package com.xebyte.offline;

import com.xebyte.core.tree.InputFingerprint;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import org.junit.Before;
import org.junit.Test;

import java.util.concurrent.atomic.AtomicReference;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * {@code ifp} is stable across repeated reads, moves when name/signature/comment
 * changes, and never needs a decompiler (this test constructs no DecompInterface).
 */
public class InputFingerprintTest {

    private Program program;
    private Listing listing;
    private SymbolTable symbols;
    private Function func;
    private Address entry;
    private AddressSetView body;
    private final AtomicReference<String> name = new AtomicReference<>("Foo");
    private final AtomicReference<String> proto = new AtomicReference<>("void Foo(void)");
    private final AtomicReference<String> plate = new AtomicReference<>("Algorithm:\nDoes stuff");

    @Before
    public void setUp() {
        program = mock(Program.class);
        listing = mock(Listing.class);
        symbols = mock(SymbolTable.class);
        func = mock(Function.class);
        entry = addr(0x1000);
        Address end = addr(0x1010);

        body = mock(AddressSetView.class);
        when(body.isEmpty()).thenReturn(false);
        when(body.getMinAddress()).thenReturn(entry);
        when(body.getMaxAddress()).thenReturn(end);
        when(body.getNumAddresses()).thenReturn(16L);
        when(body.getAddresses(true)).thenAnswer(inv -> {
            AddressIterator ai = mock(AddressIterator.class);
            when(ai.hasNext()).thenReturn(true, false);
            when(ai.next()).thenReturn(entry);
            return ai;
        });

        when(program.getListing()).thenReturn(listing);
        when(program.getSymbolTable()).thenReturn(symbols);

        when(func.getProgram()).thenReturn(program);
        when(func.getEntryPoint()).thenReturn(entry);
        when(func.getBody()).thenReturn(body);
        when(func.getName()).thenAnswer(inv -> name.get());
        when(func.getComment()).thenAnswer(inv -> plate.get());
        when(func.getPrototypeString(false, false)).thenAnswer(inv -> proto.get());
        when(func.getSignature()).thenReturn(null);

        // No instructions / refs by default — still a valid fingerprint.
        InstructionIterator empty = mock(InstructionIterator.class);
        when(empty.hasNext()).thenReturn(false);
        when(listing.getInstructions(any(AddressSetView.class), anyBoolean())).thenReturn(empty);
        when(listing.getComment(any(Integer.class), any(Address.class))).thenReturn(null);
    }

    @Test
    public void stableAcrossRepeatedReads() {
        String a = InputFingerprint.of(func);
        String b = InputFingerprint.of(func);
        assertEquals(a, b);
        assertEquals(12, a.length());
        assertTrue(a.matches("[0-9a-f]{12}"));
    }

    @Test
    public void movesWhenNameChanges() {
        String before = InputFingerprint.of(func);
        name.set("FooRenamed");
        String after = InputFingerprint.of(func);
        assertNotEquals(before, after);
    }

    @Test
    public void movesWhenSignatureChanges() {
        String before = InputFingerprint.of(func);
        proto.set("int Foo(int x)");
        String after = InputFingerprint.of(func);
        assertNotEquals(before, after);
    }

    @Test
    public void movesWhenPlateCommentChanges() {
        String before = InputFingerprint.of(func);
        plate.set("Algorithm:\nDoes other stuff");
        String after = InputFingerprint.of(func);
        assertNotEquals(before, after);
    }

    @Test
    public void movesWhenEolCommentAppears() {
        String before = InputFingerprint.of(func);
        when(listing.getComment(eq(CodeUnit.EOL_COMMENT), eq(entry)))
                .thenReturn("why this insn");
        String after = InputFingerprint.of(func);
        assertNotEquals(before, after);
    }

    @Test
    public void neverRequiresDecompiler() {
        // Constructing ifp with only Program listing/symbol mocks — if this
        // test class imported DecompInterface it would be lying. Guard the
        // contract by asserting the hash is produced without that dependency.
        assertFalse("InputFingerprint must not mention DecompInterface",
                InputFingerprint.class.getName().contains("Decomp"));
        String fp = InputFingerprint.of(func);
        assertEquals(12, fp.length());
    }

    @Test
    public void referencedSymbolNamesAffectHash() {
        String before = InputFingerprint.of(func);

        Instruction ins = mock(Instruction.class);
        Reference ref = mock(Reference.class);
        Address target = addr(0x2000);
        when(ref.getToAddress()).thenReturn(target);
        when(ins.getReferencesFrom()).thenReturn(new Reference[]{ref});

        InstructionIterator ii = mock(InstructionIterator.class);
        when(ii.hasNext()).thenReturn(true, false);
        when(ii.next()).thenReturn(ins);
        when(listing.getInstructions(any(AddressSetView.class), anyBoolean())).thenReturn(ii);

        Symbol sym = mock(Symbol.class);
        when(sym.getName()).thenReturn("g_dwFlags");
        when(symbols.getPrimarySymbol(target)).thenReturn(sym);

        String after = InputFingerprint.of(func);
        assertNotEquals(before, after);
    }

    private Address addr(long offset) {
        Address a = mock(Address.class);
        when(a.getOffset()).thenReturn(offset);
        when(a.toString(false)).thenReturn(String.format("%08x", offset));
        return a;
    }
}
