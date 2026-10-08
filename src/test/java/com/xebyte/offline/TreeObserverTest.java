package com.xebyte.offline;

import com.xebyte.core.tree.TreeObserver;
import com.xebyte.core.tree.DirtyQueue;
import ghidra.framework.model.DomainObject;
import ghidra.framework.model.DomainObjectChangeRecord;
import ghidra.framework.model.DomainObjectChangedEvent;
import ghidra.framework.model.DomainObjectEvent;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.util.FunctionChangeRecord;
import ghidra.program.util.ProgramChangeRecord;
import ghidra.program.util.ProgramEvent;
import ghidra.util.task.TaskMonitor;
import org.junit.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Event→address translation for {@link TreeObserver}. No decompile, no
 * disk — the observer must stay EDT-safe.
 */
public class TreeObserverTest {

    @Test
    public void functionAddedDirtiesEntry() {
        Address entry = addr("00100000");
        Function func = mock(Function.class);
        when(func.getEntryPoint()).thenReturn(entry);
        ProgramChangeRecord rec = new ProgramChangeRecord(
                ProgramEvent.FUNCTION_ADDED, entry, entry, func, null, func);

        TreeObserver.Hint hint = TreeObserver.translate(event(rec), program());
        assertEquals(Set.of("00100000"), hint.addresses());
        assertFalse(hint.needsReconcile());
    }

    @Test
    public void functionRemovedYieldsAddressEvenWhenGoneFromProgram() {
        // THE BUG: looking up by address after FUNCTION_REMOVED returns null
        // and the removal is silently dropped. Address must come off the record.
        Address entry = addr("00100abc");
        Function gone = mock(Function.class);
        when(gone.getEntryPoint()).thenReturn(entry);

        FunctionManager fm = mock(FunctionManager.class);
        when(fm.getFunctionAt(any())).thenReturn(null);
        when(fm.getFunctionContaining(any())).thenReturn(null);
        Program program = mock(Program.class);
        when(program.getFunctionManager()).thenReturn(fm);

        ProgramChangeRecord rec = new ProgramChangeRecord(
                ProgramEvent.FUNCTION_REMOVED, entry, entry, gone, gone, null);

        TreeObserver.Hint hint = TreeObserver.translate(event(rec), program);
        assertEquals(Set.of("00100abc"), hint.addresses());
        assertFalse(hint.needsReconcile());
    }

    @Test
    public void functionBodyChangedDirtiesEntry() {
        Address entry = addr("00200000");
        Function func = mock(Function.class);
        when(func.getEntryPoint()).thenReturn(entry);
        ProgramChangeRecord rec = new ProgramChangeRecord(
                ProgramEvent.FUNCTION_BODY_CHANGED, entry, entry, func, null, null);

        TreeObserver.Hint hint = TreeObserver.translate(event(rec), program());
        assertEquals(Set.of("00200000"), hint.addresses());
    }

    @Test
    public void signatureChangeAlsoDirtiesCallers() {
        Address entry = addr("00100000");
        Address callerEntry = addr("00100100");
        Function callee = mock(Function.class);
        Function caller = mock(Function.class);
        when(callee.getEntryPoint()).thenReturn(entry);
        when(caller.getEntryPoint()).thenReturn(callerEntry);
        when(callee.getCallingFunctions(any(TaskMonitor.class)))
                .thenReturn(Set.of(caller));

        FunctionChangeRecord rec = new FunctionChangeRecord(
                callee, FunctionChangeRecord.FunctionChangeType.PARAMETERS_CHANGED);
        assertTrue("PARAMETERS_CHANGED must count as signature",
                rec.isFunctionSignatureChange());

        // FunctionChangeRecord's event type is FUNCTION_CHANGED (set by ctor).
        // Build an event that carries it.
        DomainObjectChangedEvent ev = event(rec);
        TreeObserver.Hint hint = TreeObserver.translate(ev, program());
        assertTrue(hint.addresses().contains("00100000"));
        assertTrue(
                "signature change must dirty callers: " + hint.addresses(),
                hint.addresses().contains("00100100"));
    }

    @Test
    public void symbolRenamedDirtiesContainingFunction() {
        Address at = addr("00100040");
        Address entry = addr("00100000");
        Function containing = mock(Function.class);
        when(containing.getEntryPoint()).thenReturn(entry);

        FunctionManager fm = mock(FunctionManager.class);
        when(fm.getFunctionContaining(at)).thenReturn(containing);
        Program program = mock(Program.class);
        when(program.getFunctionManager()).thenReturn(fm);

        ProgramChangeRecord rec = new ProgramChangeRecord(
                ProgramEvent.SYMBOL_RENAMED, at, at, null, "old", "new");

        TreeObserver.Hint hint = TreeObserver.translate(event(rec), program);
        assertEquals(Set.of("00100000"), hint.addresses());
    }

    @Test
    public void commentChangedDirtiesContainingFunction() {
        Address at = addr("00100010");
        Address entry = addr("00100000");
        Function containing = mock(Function.class);
        when(containing.getEntryPoint()).thenReturn(entry);

        FunctionManager fm = mock(FunctionManager.class);
        when(fm.getFunctionContaining(at)).thenReturn(containing);
        Program program = mock(Program.class);
        when(program.getFunctionManager()).thenReturn(fm);

        ProgramChangeRecord rec = new ProgramChangeRecord(
                ProgramEvent.COMMENT_CHANGED, at, at, null, null, "note");

        TreeObserver.Hint hint = TreeObserver.translate(event(rec), program);
        assertEquals(Set.of("00100000"), hint.addresses());
    }

    @Test
    public void codeAddedDirtiesOverlappingFunctions() {
        Address start = addr("00100000");
        Address end = addr("00100100");
        Address entryA = addr("00100000");
        Address entryB = addr("00100080");
        Function a = mock(Function.class);
        Function b = mock(Function.class);
        when(a.getEntryPoint()).thenReturn(entryA);
        when(b.getEntryPoint()).thenReturn(entryB);

        FunctionManager fm = mock(FunctionManager.class);
        // Prefer the containing fallback — AddressSet construction with mock
        // addresses is unreliable offline. Overlap intent is the same.
        when(fm.getFunctionContaining(start)).thenReturn(a);
        when(fm.getFunctionContaining(end)).thenReturn(b);
        when(fm.getFunctionsOverlapping(any()))
                .thenThrow(new RuntimeException("force fallback"));

        Program program = mock(Program.class);
        when(program.getFunctionManager()).thenReturn(fm);

        ProgramChangeRecord rec = new ProgramChangeRecord(
                ProgramEvent.CODE_ADDED, start, end, null, null, null);

        TreeObserver.Hint hint = TreeObserver.translate(event(rec), program);
        assertTrue(hint.addresses().contains("00100000"));
        assertTrue(hint.addresses().contains("00100080"));
    }

    @Test
    public void restoredSetsNeedsReconcileAndEnumeratesNothing() {
        DomainObjectChangeRecord restored =
                new DomainObjectChangeRecord(DomainObjectEvent.RESTORED);
        // Mix in a FUNCTION_ADDED — RESTORED must still win without enumerating.
        Address entry = addr("00100000");
        ProgramChangeRecord added = new ProgramChangeRecord(
                ProgramEvent.FUNCTION_ADDED, entry, entry, null, null, null);

        TreeObserver.Hint hint = TreeObserver.translate(
                event(restored, added), program());
        assertTrue(hint.needsReconcile());
        assertTrue(
                "RESTORED must not enumerate: " + hint.addresses(),
                hint.addresses().isEmpty());
    }

    @Test
    public void boundCollapseIsOwnedByDirtyQueue() {
        // Observer yields addresses; DirtyQueue collapses storms. Pin the
        // contract that translate itself does not invent needsReconcile for
        // a large batch of ordinary records.
        List<DomainObjectChangeRecord> records = new ArrayList<>();
        for (int i = 0; i < 50; i++) {
            Address a = addr(String.format("%08x", 0x100000 + i));
            records.add(new ProgramChangeRecord(
                    ProgramEvent.FUNCTION_ADDED, a, a, null, null, null));
        }
        DomainObjectChangedEvent ev = new DomainObjectChangedEvent(
                mock(DomainObject.class), records);
        TreeObserver.Hint hint = TreeObserver.translate(ev, program());
        assertFalse(hint.needsReconcile());
        assertEquals(50, hint.addresses().size());
        assertEquals(DirtyQueue.ADDRESS_BOUND, 2000);
    }

    /**
     * Found in a live RE session: renaming a function updated its own block, but its
     * callers' bodies (which print the callee's name) stayed stale until some unrelated
     * full reconcile minutes later.
     */
    @Test
    public void aRenamedFunctionDirtiesEveryCaller() {
        Address entry = addr("00100000");
        Address callSite = addr("00100208");
        Function callee = function("00100000");
        Function caller = function("00100200");
        FunctionManager fm = mock(FunctionManager.class);
        when(fm.getFunctionContaining(entry)).thenReturn(callee);
        when(fm.getFunctionContaining(callSite)).thenReturn(caller);
        Program program = program(fm, entry, callSite);

        ProgramChangeRecord rec = new ProgramChangeRecord(
                ProgramEvent.SYMBOL_RENAMED, entry, entry, null, "old", "new");
        TreeObserver.Hint hint = TreeObserver.translate(event(rec), program);
        assertEquals(Set.of("00100000", "00100200"), hint.addresses());
        assertEquals("the old name is handed on for the tree search",
                Set.of("old"), hint.retiredNames());
    }

    /** A label or global used in several functions lives in no function at all. */
    @Test
    public void aRenamedGlobalDirtiesEveryFunctionThatReferencesIt() {
        Address global = addr("20004410");
        Address useA = addr("00100010");
        Address useB = addr("00100410");
        Function a = function("00100000");
        Function b = function("00100400");
        FunctionManager fm = mock(FunctionManager.class);
        when(fm.getFunctionContaining(global)).thenReturn(null);
        when(fm.getFunctionContaining(useA)).thenReturn(a);
        when(fm.getFunctionContaining(useB)).thenReturn(b);
        Program program = program(fm, global, useA, useB);

        ProgramChangeRecord rec = new ProgramChangeRecord(
                ProgramEvent.SYMBOL_RENAMED, global, global, null, "DAT_20004410", "g_scan");
        TreeObserver.Hint hint = TreeObserver.translate(event(rec), program);
        assertEquals(Set.of("00100000", "00100400"), hint.addresses());
        assertFalse(hint.needsReconcile());
    }

    /** Typing a literal-pool word changes how every function loading it decompiles. */
    @Test
    public void dataDefinedOutsideAFunctionDirtiesItsReaders() {
        Address word = addr("080164a0");
        Address load = addr("08016402");
        Function reader = function("08016400");
        FunctionManager fm = mock(FunctionManager.class);
        when(fm.getFunctionContaining(word)).thenReturn(null);
        when(fm.getFunctionContaining(load)).thenReturn(reader);
        when(fm.getFunctionsOverlapping(any())).thenThrow(new RuntimeException("force fallback"));
        Program program = program(fm, word, load);

        ProgramChangeRecord rec = new ProgramChangeRecord(
                ProgramEvent.CODE_ADDED, word, word, null, null, null);
        TreeObserver.Hint hint = TreeObserver.translate(event(rec), program);
        assertEquals(Set.of("08016400"), hint.addresses());
    }

    @Test
    public void aSymbolUsedEverywhereAsksForAFullReconcileInsteadOfEnumerating() {
        Address global = addr("20000000");
        Address[] uses = new Address[DirtyQueue.ADDRESS_BOUND + 1];
        for (int i = 0; i < uses.length; i++) {
            uses[i] = addr(String.format("%08x", 0x100000 + i * 4));
        }
        Program program = program(mock(FunctionManager.class), global, uses);

        ProgramChangeRecord rec = new ProgramChangeRecord(
                ProgramEvent.SYMBOL_RENAMED, global, global, null, "a", "b");
        assertTrue(TreeObserver.translate(event(rec), program).needsReconcile());
    }

    /**
     * Marking flash read-only turns every literal-pool load into a constant, in functions
     * no record names and without changing a fingerprint: only a resweep fixes the tree.
     */
    @Test
    public void aMemoryMapChangeMakesTheDecompTreeStale() {
        Address start = addr("08005000");
        ProgramChangeRecord rec = new ProgramChangeRecord(
                ProgramEvent.MEMORY_BLOCK_CHANGED, start, start, null, null, null);
        TreeObserver.Hint hint = TreeObserver.translate(event(rec), program());
        assertTrue(hint.staleReason(), hint.staleReason().contains("resweep"));
        assertTrue(hint.addresses().isEmpty());
    }

    // -------------------------------------------------------------------------

    private static Function function(String entryHex) {
        Function f = mock(Function.class);
        Address entry = addr(entryHex);
        when(f.getEntryPoint()).thenReturn(entry);
        return f;
    }

    /** A program whose only references point at {@code target}, one from each of {@code froms}. */
    private static Program program(FunctionManager fm, Address target, Address... froms) {
        Program program = mock(Program.class);
        when(program.getFunctionManager()).thenReturn(fm);
        ReferenceManager rm = mock(ReferenceManager.class);
        when(program.getReferenceManager()).thenReturn(rm);
        List<Reference> refs = new ArrayList<>();
        for (Address from : froms) {
            Reference r = mock(Reference.class);
            when(r.getFromAddress()).thenReturn(from);
            refs.add(r);
        }
        java.util.Iterator<Reference> it = refs.iterator();
        ReferenceIterator ri = mock(ReferenceIterator.class);
        when(ri.iterator()).thenReturn(ri);
        when(ri.hasNext()).thenAnswer(inv -> it.hasNext());
        when(ri.next()).thenAnswer(inv -> it.next());
        when(rm.getReferencesTo(target)).thenReturn(ri);
        return program;
    }

    private static Program program() {
        Program program = mock(Program.class);
        FunctionManager fm = mock(FunctionManager.class);
        when(program.getFunctionManager()).thenReturn(fm);
        return program;
    }

    private static Address addr(String hex) {
        Address a = mock(Address.class);
        when(a.toString(false)).thenReturn(hex);
        return a;
    }

    private static DomainObjectChangedEvent event(DomainObjectChangeRecord... records) {
        return new DomainObjectChangedEvent(
                mock(DomainObject.class), List.of(records));
    }
}
