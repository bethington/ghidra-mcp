package com.xebyte.core.partition;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.data.AbstractStringDataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.util.task.TaskMonitor;

import java.util.ArrayList;
import java.util.BitSet;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * Shared state for one cascade run: the function pool, and the analyses every
 * partitioner would otherwise rebuild.
 *
 * <p>The literal index and the call graph each cost a full pass over every
 * instruction in the program. Five partitioners building their own would cost five
 * passes to answer one question, which is the entire reason this is a context
 * object rather than loose arguments.
 *
 * <p>Both are built lazily, because the cascade skips strategies whose probe fails
 * and a skipped strategy must not pay for an analysis it never uses.
 *
 * @since 7.2.0
 */
public final class PartitionContext {

    /** Below this, a constant is an ordinary small integer rather than an address. */
    private static final long LITERAL_ADDRESS_FLOOR = 0x40000000L;

    private final Program program;
    private final List<Function> functions;
    private final Map<Address, Integer> indexOf;
    private final BitSet assigned;

    private LiteralIndex literals;
    private CallGraph callGraph;

    public PartitionContext(Program program) {
        this.program = program;
        this.functions = new ArrayList<>();
        Listing listing = program.getListing();
        FunctionIterator it = program.getFunctionManager().getFunctions(true);
        while (it.hasNext()) {
            Function f = it.next();
            // Externals have no body and thunks are one jump; neither can be
            // grouped by anything they reference, and both would dilute coverage.
            if (f.isExternal() || f.isThunk()) continue;
            if (listing.getInstructionAt(f.getEntryPoint()) == null) continue;
            functions.add(f);
        }
        this.indexOf = new HashMap<>();
        for (int i = 0; i < functions.size(); i++) {
            indexOf.put(functions.get(i).getEntryPoint(), i);
        }
        this.assigned = new BitSet(functions.size());
    }

    /**
     * Count why {@link #size()} may be zero — used by {@code /partition_program}
     * to name the {@code .pdata}-without-disassembly case instead of blaming thunks.
     */
    public static EligibilityScan scanEligibility(Program program) {
        Listing listing = program.getListing();
        int total = 0;
        int externalOrThunk = 0;
        int noInstruction = 0;
        int eligible = 0;
        FunctionIterator it = program.getFunctionManager().getFunctions(true);
        while (it.hasNext()) {
            Function f = it.next();
            total++;
            if (f.isExternal() || f.isThunk()) {
                externalOrThunk++;
                continue;
            }
            if (listing.getInstructionAt(f.getEntryPoint()) == null) {
                noInstruction++;
                continue;
            }
            eligible++;
        }
        return new EligibilityScan(total, externalOrThunk, noInstruction, eligible);
    }

    /** Partition eligibility breakdown for one program. */
    public record EligibilityScan(
            int totalFunctions,
            int externalOrThunk,
            int noInstructionAtEntry,
            int eligible) {
    }

    public Program program() {
        return program;
    }

    /** Every eligible function, in address order. Indices into this list are the currency. */
    public List<Function> functions() {
        return Collections.unmodifiableList(functions);
    }

    public int size() {
        return functions.size();
    }

    public boolean isAssigned(int i) {
        return assigned.get(i);
    }

    public int assignedCount() {
        return assigned.cardinality();
    }

    /** Indices still unclaimed, in address order — what the next partitioner sees. */
    public List<Integer> unassigned() {
        List<Integer> out = new ArrayList<>();
        for (int i = 0; i < functions.size(); i++) {
            if (!assigned.get(i)) out.add(i);
        }
        return out;
    }

    public void markAssigned(Iterable<Integer> indices) {
        for (int i : indices) assigned.set(i);
    }

    public Integer indexOf(Address entry) {
        return indexOf.get(entry);
    }

    public synchronized LiteralIndex literals() {
        if (literals == null) literals = buildLiteralIndex();
        return literals;
    }

    public synchronized CallGraph callGraph() {
        if (callGraph == null) callGraph = buildCallGraph();
        return callGraph;
    }

    /**
     * Per-function referenced literals: string addresses, string word tokens, and
     * high constants.
     *
     * <p>These are one signal, not three. A linker concatenates {@code .rodata} in
     * the same object order as {@code .text}, so an object's code and its constants
     * advance together — measured at 634x tighter than a shuffled baseline on a PE
     * driver. MMIO register addresses and rare magic numbers cluster for the same
     * reason. What separates a useful literal from a useless one is rarity, which is
     * why the tokens are kept for TF-IDF rather than counted here.
     */
    private LiteralIndex buildLiteralIndex() {
        int n = functions.size();
        long[] medianStringAddr = new long[n];
        List<Set<String>> tokens = new ArrayList<>(n);
        List<Set<Long>> pages = new ArrayList<>(n);
        List<List<String>> rawStrings = new ArrayList<>(n);

        ReferenceManager rm = program.getReferenceManager();
        Listing listing = program.getListing();

        for (int i = 0; i < n; i++) {
            List<Long> stringAddrs = new ArrayList<>();
            Set<String> tok = new HashSet<>();
            Set<Long> pg = new TreeSet<>();
            List<String> raw = new ArrayList<>();

            InstructionIterator ii = listing.getInstructions(functions.get(i).getBody(), true);
            while (ii.hasNext()) {
                Instruction ins = ii.next();
                for (int oi = 0; oi < ins.getNumOperands(); oi++) {
                    for (Object o : ins.getOpObjects(oi)) {
                        if (o instanceof Scalar s) addPage(pg, s.getUnsignedValue());
                    }
                }
                for (Reference r : ins.getReferencesFrom()) {
                    Address to = r.getToAddress();
                    Data d = listing.getDataAt(to);
                    if (d == null) continue;
                    if (d.getDataType() instanceof AbstractStringDataType) {
                        stringAddrs.add(to.getOffset());
                        Object v = d.getValue();
                        if (v != null) {
                            String s = v.toString().trim();
                            if (!s.isEmpty() && s.length() <= 256) {
                                raw.add(s);
                                for (String w : s.split("[^A-Za-z0-9_]+")) {
                                    if (w.length() >= 4 && w.length() <= 24 && !w.matches("\\d+")) {
                                        tok.add(w.toLowerCase());
                                    }
                                }
                            }
                        }
                    } else if (d.getLength() == 4) {
                        // ARM literal pool: the peripheral address is data, not an operand.
                        Object v = d.getValue();
                        if (v instanceof Address a) addPage(pg, a.getOffset());
                        else if (v instanceof Scalar s) addPage(pg, s.getUnsignedValue());
                    }
                }
            }
            if (stringAddrs.isEmpty()) {
                medianStringAddr[i] = -1;
            } else {
                Collections.sort(stringAddrs);
                medianStringAddr[i] = stringAddrs.get(stringAddrs.size() / 2);
            }
            tokens.add(tok);
            pages.add(pg);
            rawStrings.add(raw);
        }
        return new LiteralIndex(medianStringAddr, tokens, pages, rawStrings);
    }

    private static void addPage(Set<Long> into, long value) {
        // 0xFFFFFFFF is -1 in disguise and appears everywhere; it is not an address.
        if (value >= LITERAL_ADDRESS_FLOOR && value < 0xFFFFFFFFL) {
            into.add(value >>> 24);
        }
    }

    private CallGraph buildCallGraph() {
        int n = functions.size();
        List<Set<Integer>> callees = new ArrayList<>(n);
        List<Set<Integer>> callers = new ArrayList<>(n);
        for (int i = 0; i < n; i++) {
            callees.add(new HashSet<>());
            callers.add(new HashSet<>());
        }
        for (int i = 0; i < n; i++) {
            for (Function cf : functions.get(i).getCalledFunctions(TaskMonitor.DUMMY)) {
                Integer j = indexOf.get(cf.getEntryPoint());
                if (j == null || j == i) continue;
                callees.get(i).add(j);
                callers.get(j).add(i);
            }
        }
        return new CallGraph(callers, callees);
    }

    /** Referenced-literal facts, one entry per function index. */
    public record LiteralIndex(
            long[] medianStringAddress,
            List<Set<String>> stringTokens,
            List<Set<Long>> highPages,
            List<List<String>> rawStrings) {

        public int functionsWithStrings() {
            int c = 0;
            for (long v : medianStringAddress) if (v >= 0) c++;
            return c;
        }

        public int functionsWithPages() {
            int c = 0;
            for (Set<Long> p : highPages) if (!p.isEmpty()) c++;
            return c;
        }
    }

    /** Intra-program call edges, by function index. */
    public record CallGraph(List<Set<Integer>> callers, List<Set<Integer>> callees) {
    }
}
