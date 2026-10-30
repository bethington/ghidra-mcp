package com.xebyte.core.tree;

import com.xebyte.core.AddressKeys;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/**
 * Which blocks a change of the memory map can change, so a full reconcile re-decompiles them
 * although their input fingerprints match.
 *
 * <p>The decompiler reads the memory map as well as the function: a load from a read-only
 * block folds to a constant, one from a volatile block never does, and a reference into a
 * block that moved prints another address. None of that moves a fingerprint. The map the tree
 * was decompiled against is compared with the live one address by address, and the functions
 * holding references into what changed are the ones that can decompile differently. A block
 * renamed, split or joined changes nothing at any address and costs nothing; one moved, added
 * or removed changes every reference into its old and new range; one whose permissions or
 * initialisation changed affects only the data references into it, since a call or jump
 * decompiles the same whatever the target block allows.
 *
 * <p>Functions that moved themselves (an image base change, a code block moved) have new
 * keys, which the reconcile's address diff already re-decompiles; only blocks keeping their
 * key are counted here.
 */
public final class MemoryMapChange {

    /**
     * The blocks to re-decompile, or why the change cannot be followed block by block: the
     * old map does not parse, or it reaches more blocks than a reconcile takes on.
     */
    public record Affected(Set<String> keys, String unresolved) {
        public static final Affected NONE = new Affected(Set.of(), null);

        public Affected {
            keys = keys == null ? Set.of() : Set.copyOf(keys);
        }
    }

    private MemoryMapChange() {
    }

    /**
     * What changed between {@code before} ({@link DecompTree.Session#memoryMapOf}) and the
     * program's live map, as the keys among {@code keeping} whose functions reference it.
     */
    public static Affected since(String before, Program program, Set<String> keeping) {
        String live = DecompTree.Session.memoryMapOf(program);
        if (before == null || before.equals(live)) {
            return Affected.NONE;
        }
        Map<String, AddressSet> was = parse(before, program);
        Map<String, AddressSet> now = parse(live, program);
        if (was == null || now == null) {
            return new Affected(Set.of(), "the memory map changed and the one the tree was "
                    + "decompiled against cannot be read back; resweep (decompile_tree_run action=start)");
        }
        AddressSet mappedWas = union(was);
        AddressSet relocated = mappedWas.xor(union(now));
        AddressSet retyped = new AddressSet();
        Set<String> attributes = new LinkedHashSet<>(was.keySet());
        attributes.addAll(now.keySet());
        for (String attr : attributes) {
            retyped.add(was.getOrDefault(attr, new AddressSet()).xor(now.getOrDefault(attr, new AddressSet())));
        }
        retyped = retyped.subtract(relocated);

        Set<String> keys = new LinkedHashSet<>();
        if (!referencers(program, relocated, false, keeping, keys)
                || !referencers(program, retyped, true, keeping, keys)) {
            return new Affected(Set.of(), "the memory map changed under more than "
                    + DirtyQueue.ADDRESS_BOUND + " functions that reference it; resweep "
                    + "(decompile_tree_run action=start)");
        }
        return new Affected(keys, null);
    }

    /**
     * Each block's addresses by its permissions and initialisation. Null when an entry does
     * not parse; an entry whose address space no longer exists is skipped, since nothing live
     * can reference it.
     */
    static Map<String, AddressSet> parse(String map, Program program) {
        Map<String, AddressSet> out = new LinkedHashMap<>();
        for (String entry : map.split(";")) {
            if (entry.isEmpty()) {
                continue;
            }
            int at = entry.lastIndexOf('@');
            int colon = entry.lastIndexOf(':');
            int dash = at < 0 ? -1 : entry.indexOf('-', at);
            if (at < 0 || dash < 0 || colon < dash) {
                return null;
            }
            Address start = program.getAddressFactory().getAddress(entry.substring(at + 1, dash));
            Address end = program.getAddressFactory().getAddress(entry.substring(dash + 1, colon));
            if (start == null || end == null) {
                continue;
            }
            if (!start.getAddressSpace().equals(end.getAddressSpace()) || start.compareTo(end) > 0) {
                return null;
            }
            out.computeIfAbsent(entry.substring(colon + 1), k -> new AddressSet()).add(start, end);
        }
        return out;
    }

    private static AddressSet union(Map<String, AddressSet> sets) {
        AddressSet all = new AddressSet();
        sets.values().forEach(all::add);
        return all;
    }

    /** False once more than {@link DirtyQueue#ADDRESS_BOUND} keys are affected. */
    private static boolean referencers(Program program, AddressSet changed, boolean dataOnly,
            Set<String> keeping, Set<String> keys) {
        if (changed.isEmpty()) {
            return true;
        }
        ReferenceManager refs = program.getReferenceManager();
        FunctionManager fm = program.getFunctionManager();
        AddressIterator targets = refs.getReferenceDestinationIterator(changed, true);
        while (targets.hasNext()) {
            for (Reference ref : refs.getReferencesTo(targets.next())) {
                if (dataOnly && ref.getReferenceType().isFlow()) {
                    continue;
                }
                Function f = fm.getFunctionContaining(ref.getFromAddress());
                if (f == null) {
                    continue;
                }
                String key = AddressKeys.of(f);
                if (keeping.contains(key) && keys.add(key) && keys.size() > DirtyQueue.ADDRESS_BOUND) {
                    return false;
                }
            }
        }
        return true;
    }
}
