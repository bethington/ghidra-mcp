package com.xebyte.core.tree;

import com.xebyte.core.AddressKeys;
import ghidra.framework.model.DomainObjectChangeRecord;
import ghidra.framework.model.DomainObjectChangedEvent;
import ghidra.framework.model.DomainObjectEvent;
import ghidra.framework.model.DomainObjectListener;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.util.FunctionChangeRecord;
import ghidra.program.util.ProgramChangeRecord;
import ghidra.program.util.ProgramEvent;
import ghidra.util.task.TaskMonitor;

import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Set;

/**
 * Translates program change events into dirty tree addresses.
 *
 * <p>Events land on the EDT in GUI mode (DomainObjectChangeSupport batches
 * through a GhidraSwingTimer). This listener does <em>no</em> decompile, file
 * IO, or locking — blocking here stalls every other listener, including
 * AutoAnalysisManager's scheduler. It only maps records to entry addresses and
 * hands them to {@link DirtyQueue}.
 *
 * <p>Holds the tree id, never a {@link Program}: the registry deliberately
 * never pins a ProgramDB, and a listener field that did would break close.
 *
 * @since 7.2.0
 */
public final class TreeObserver implements DomainObjectListener {

    private final String treeId;
    private final DirtyQueue queue;

    public TreeObserver(String treeId, DirtyQueue queue) {
        this.treeId = Objects.requireNonNull(treeId, "treeId");
        this.queue = Objects.requireNonNull(queue, "queue");
    }

    public String treeId() {
        return treeId;
    }

    @Override
    public void domainObjectChanged(DomainObjectChangedEvent ev) {
        if (ev == null) {
            return;
        }
        // Source is the live Program for this callback only — never stored.
        Object src = ev.getSource();
        Program program = src instanceof Program p ? p : null;

        // CLOSED: drop our listener so a disposed Program cannot keep us alive.
        if (ev.contains(DomainObjectEvent.CLOSED)) {
            TreeRegistry.getInstance().noteClosing(treeId, program);
            TreeRegistry.getInstance().detachObserver(treeId);
            return;
        }
        if (ev.contains(DomainObjectEvent.SAVED) && program != null) {
            TreeRegistry.getInstance().noteSaved(treeId, program.getModificationNumber());
        }

        Hint hint = translate(ev, program);
        if (hint.staleReason() != null) {
            TreeRegistry.getInstance().markStale(treeId, hint.staleReason());
        }
        if (!hint.introducedNames().isEmpty()) {
            TreeRegistry.getInstance().noteIntroducedNames(treeId, hint.introducedNames());
        }
        if (!hint.retiredNames().isEmpty()) {
            queue.markRetiredNames(treeId, hint.retiredNames());
        }
        if (hint.needsReconcile()) {
            queue.markNeedsReconcile(treeId);
            return;
        }
        if (!hint.addresses().isEmpty()) {
            queue.markDirty(treeId, hint.addresses());
        }
    }

    /**
     * Pure event→address mapping. Public so offline tests can drive every
     * ProgramEvent without a live DomainObjectListener dispatch.
     */
    public static Hint translate(DomainObjectChangedEvent ev, Program program) {
        Set<String> dirty = new LinkedHashSet<>();
        Set<String> retired = new LinkedHashSet<>();
        Set<String> introduced = new LinkedHashSet<>();
        if (ev == null) {
            return Hint.none();
        }
        // Undo/redo and bulk restore replace the detailed stream with one
        // RESTORED — enumerating is impossible; the reconciler must re-diff.
        if (ev.contains(DomainObjectEvent.RESTORED)) {
            return Hint.fullReconcile();
        }

        FunctionManager fm = program != null ? program.getFunctionManager() : null;

        // A memory-map change (a block made read-only, mapped or removed) changes how the
        // decompiler treats every load from that range, in functions no record names and
        // without changing any input fingerprint: only a resweep brings the tree back.
        for (DomainObjectChangeRecord rec : ev) {
            var type = rec == null ? null : rec.getEventType();
            if (type == ProgramEvent.MEMORY_BLOCK_CHANGED || type == ProgramEvent.MEMORY_BLOCK_ADDED
                    || type == ProgramEvent.MEMORY_BLOCK_REMOVED || type == ProgramEvent.MEMORY_BLOCK_MOVED
                    || type == ProgramEvent.MEMORY_BLOCK_SPLIT || type == ProgramEvent.MEMORY_BLOCKS_JOINED) {
                return Hint.stale("the memory map changed; every function may decompile "
                        + "differently, so resweep (decompile_tree_run action=start)");
            }
        }

        for (DomainObjectChangeRecord rec : ev) {
            if (rec == null || rec.getEventType() == null) {
                continue;
            }
            var type = rec.getEventType();

            if (type == ProgramEvent.FUNCTION_REMOVED) {
                // Function is ALREADY gone from the program. A lookup by address
                // returns null and the removal would be silently dropped — the
                // bug class this stage exists to kill. Take the address off the
                // record itself.
                String hex = entryHexFromRecord(rec, false, fm);
                if (hex != null) {
                    dirty.add(hex);
                }
                continue;
            }

            if (type == ProgramEvent.FUNCTION_ADDED
                    || type == ProgramEvent.FUNCTION_BODY_CHANGED
                    || type == ProgramEvent.FUNCTION_CHANGED) {
                String hex = entryHexFromRecord(rec, true, fm);
                if (hex != null) {
                    dirty.add(hex);
                }
                // Signature rewrite changes call expressions in every caller.
                if (rec instanceof FunctionChangeRecord fcr
                        && fcr.isFunctionSignatureChange()) {
                    addCallers(fcr.getFunction(), dirty);
                }
                continue;
            }

            if (type == ProgramEvent.COMMENT_CHANGED) {
                addContaining(fm, startOf(rec), dirty);
                continue;
            }

            // A name is printed wherever the symbol is used, not only where it lives: a
            // renamed function appears in every caller's body, a renamed label or global in
            // every function that references it.
            if (type == ProgramEvent.SYMBOL_RENAMED
                    || type == ProgramEvent.SYMBOL_SCOPE_CHANGED
                    || type == ProgramEvent.SYMBOL_ADDED
                    || type == ProgramEvent.SYMBOL_REMOVED
                    || type == ProgramEvent.SYMBOL_PRIMARY_STATE_CHANGED) {
                Address at = startOf(rec);
                addContaining(fm, at, dirty);
                // A function's name also shows in its callees' blocks (callers, xrefs).
                Function renamed = fm != null && at != null ? fm.getFunctionAt(at) : null;
                if (renamed != null) {
                    addCallees(renamed, dirty);
                }
                if (type == ProgramEvent.SYMBOL_RENAMED
                        && rec.getOldValue() instanceof String oldName && !oldName.isBlank()) {
                    retired.add(oldName);
                }
                if (type == ProgramEvent.SYMBOL_RENAMED
                        && rec.getNewValue() instanceof String newName && !newName.isBlank()) {
                    introduced.add(newName);
                }
                if (!addReferencers(program, fm, at, dirty)) {
                    return new Hint(Set.of(), true, retired, introduced);
                }
                continue;
            }

            // A new reference changes what its function's code resolves to, and the target
            // function's callers and xrefs.
            if (type == ProgramEvent.REFERENCE_ADDED || type == ProgramEvent.REFERENCE_REMOVED
                    || type == ProgramEvent.REFERENCE_TYPE_CHANGED) {
                addContaining(fm, startOf(rec), dirty);
                for (Object value : new Object[] {rec.getNewValue(), rec.getOldValue()}) {
                    if (value instanceof Reference ref) {
                        addContaining(fm, ref.getToAddress(), dirty);
                    }
                }
                continue;
            }

            if (type == ProgramEvent.FUNCTION_TAG_APPLIED || type == ProgramEvent.FUNCTION_TAG_UNAPPLIED) {
                String hex = entryHexFromRecord(rec, true, fm);
                if (hex != null) {
                    dirty.add(hex);
                }
                continue;
            }
            // A tag definition renamed or deleted shows in every block carrying it; the input
            // fingerprint includes tags, so a full pass finds them.
            if (type == ProgramEvent.FUNCTION_TAG_CHANGED || type == ProgramEvent.FUNCTION_TAG_DELETED) {
                return new Hint(Set.of(), true, retired, introduced);
            }

            if (type == ProgramEvent.CODE_ADDED || type == ProgramEvent.CODE_REMOVED) {
                Address start = startOf(rec);
                addOverlapping(fm, start, endOf(rec), dirty);
                // Data defined or cleared outside any function (a typed global, a literal-pool
                // word) changes how every function reading it decompiles.
                if (start != null && fm != null && fm.getFunctionContaining(start) == null
                        && !addReferencers(program, fm, start, dirty)) {
                    return new Hint(Set.of(), true, retired, introduced);
                }
            }
            if (dirty.size() > DirtyQueue.ADDRESS_BOUND) {
                return new Hint(Set.of(), true, retired, introduced);
            }
        }
        return new Hint(dirty, false, retired, introduced);
    }

    /**
     * Prefer the record's own address/function — never require a live listing
     * hit. {@code lookupOk} allows a containing-function fallback for events
     * where the function still exists (not FUNCTION_REMOVED).
     */
    private static String entryHexFromRecord(
            DomainObjectChangeRecord rec, boolean lookupOk, FunctionManager fm) {
        if (rec instanceof FunctionChangeRecord fcr) {
            Function f = fcr.getFunction();
            if (f != null && f.getEntryPoint() != null) {
                return AddressKeys.of(f);
            }
        }
        if (rec instanceof ProgramChangeRecord pcr) {
            Address start = pcr.getStart();
            if (start != null) {
                return AddressKeys.of(start, fm != null ? fm.getProgram() : null);
            }
            Object obj = pcr.getObject();
            if (obj instanceof Function f && f.getEntryPoint() != null) {
                return AddressKeys.of(f);
            }
            Object neu = pcr.getNewValue();
            if (neu instanceof Function f && f.getEntryPoint() != null) {
                return AddressKeys.of(f);
            }
            Object old = pcr.getOldValue();
            if (old instanceof Function f && f.getEntryPoint() != null) {
                return AddressKeys.of(f);
            }
        }
        if (lookupOk && fm != null) {
            Address start = startOf(rec);
            if (start != null) {
                Function f = fm.getFunctionContaining(start);
                if (f != null && f.getEntryPoint() != null) {
                    return AddressKeys.of(f);
                }
            }
        }
        return null;
    }

    private static void addCallers(Function func, Set<String> dirty) {
        if (func == null) {
            return;
        }
        try {
            Set<Function> callers = func.getCallingFunctions(TaskMonitor.DUMMY);
            if (callers == null) {
                return;
            }
            for (Function caller : callers) {
                if (caller != null && caller.getEntryPoint() != null) {
                    dirty.add(AddressKeys.of(caller));
                }
            }
        } catch (Exception ignored) {
            // Best-effort on the EDT — a failed caller walk must not throw.
        }
    }

    private static void addCallees(Function func, Set<String> dirty) {
        try {
            for (Function callee : func.getCalledFunctions(TaskMonitor.DUMMY)) {
                if (callee != null && callee.getEntryPoint() != null && !callee.isExternal()) {
                    dirty.add(AddressKeys.of(callee));
                }
            }
        } catch (Exception ignored) {
            // Best-effort on the EDT.
        }
    }

    /**
     * Every function holding a reference to {@code at}. False when there are more than the
     * queue would track anyway, so the caller asks for a full reconcile rather than
     * enumerating them on the event thread.
     */
    private static boolean addReferencers(
            Program program, FunctionManager fm, Address at, Set<String> dirty) {
        if (program == null || fm == null || at == null) {
            return true;
        }
        try {
            int seen = 0;
            for (Reference ref : program.getReferenceManager().getReferencesTo(at)) {
                if (++seen > DirtyQueue.ADDRESS_BOUND) {
                    return false;
                }
                addContaining(fm, ref.getFromAddress(), dirty);
            }
        } catch (Exception ignored) {
            // Best-effort on the EDT — a failed reference walk must not throw.
        }
        return true;
    }

    private static void addContaining(FunctionManager fm, Address at, Set<String> dirty) {
        if (fm == null || at == null) {
            return;
        }
        Function f = fm.getFunctionContaining(at);
        if (f != null && f.getEntryPoint() != null) {
            dirty.add(AddressKeys.of(f));
        }
    }

    private static void addOverlapping(
            FunctionManager fm, Address start, Address end, Set<String> dirty) {
        if (fm == null || start == null) {
            return;
        }
        Address stop = end != null ? end : start;
        try {
            AddressSet range = new AddressSet(start, stop);
            Iterator<Function> it = fm.getFunctionsOverlapping(range);
            if (it != null) {
                while (it.hasNext()) {
                    Function f = it.next();
                    if (f != null && f.getEntryPoint() != null) {
                        dirty.add(AddressKeys.of(f));
                    }
                }
                return;
            }
        } catch (Exception ignored) {
            // Mocked addresses in offline tests (and exotic spaces) can refuse
            // AddressSet construction — degrade to the endpoints.
        }
        addContaining(fm, start, dirty);
        if (end != null && !end.equals(start)) {
            addContaining(fm, end, dirty);
        }
    }

    private static Address startOf(DomainObjectChangeRecord rec) {
        return rec instanceof ProgramChangeRecord pcr ? pcr.getStart() : null;
    }

    private static Address endOf(DomainObjectChangeRecord rec) {
        return rec instanceof ProgramChangeRecord pcr ? pcr.getEnd() : null;
    }

    /**
     * Translation result — addresses to dirty, or a full-reconcile flag — plus the names
     * symbols were renamed away from, which the drain looks for in the tree's bodies, and
     * the names they were renamed to, which a discarded session would leave behind.
     */
    public record Hint(Set<String> addresses, boolean needsReconcile, Set<String> retiredNames,
            Set<String> introducedNames, String staleReason) {

        public Hint(Set<String> addresses, boolean needsReconcile, Set<String> retiredNames,
                Set<String> introducedNames) {
            this(addresses, needsReconcile, retiredNames, introducedNames, null);
        }

        /** Nothing a reconcile can fix: the tree needs a resweep. */
        static Hint stale(String reason) {
            return new Hint(Set.of(), false, Set.of(), Set.of(), reason);
        }

        public Hint {
            addresses = addresses == null ? Set.of() : Set.copyOf(addresses);
            retiredNames = retiredNames == null ? Set.of() : Set.copyOf(retiredNames);
            introducedNames = introducedNames == null ? Set.of() : Set.copyOf(introducedNames);
        }

        static Hint none() {
            return new Hint(Set.of(), false, Set.of(), Set.of());
        }

        static Hint of(Set<String> addresses) {
            return new Hint(addresses, false, Set.of(), Set.of());
        }

        /** RESTORED / bound-collapse — reconciler re-diffs; do not enumerate. */
        static Hint fullReconcile() {
            return new Hint(Set.of(), true, Set.of(), Set.of());
        }
    }
}
