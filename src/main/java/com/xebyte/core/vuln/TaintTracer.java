package com.xebyte.core.vuln;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.util.task.TaskMonitor;

import java.util.*;

/**
 * Backward inter-procedural taint tracer. Stateful per scan: owns a
 * DecompInterface (or reuses a shared one) and caches HighFunctions and
 * per-function tainted-buffer roots. AutoCloseable — use try-with-resources.
 */
public final class TaintTracer implements AutoCloseable {

    static final int DECOMP_TIMEOUT_S = 12;
    static final int INTRA_STEP_CAP   = 64;
    static final int CALLER_FANOUT_CAP = 16;

    private final Program program;
    private final SinkCatalog catalog;
    private final DecompInterface decomp;
    private final boolean ownsDecomp;
    private final Map<Function, HighFunction> hfCache = new HashMap<>();
    private final Map<HighFunction, Set<Varnode>> rootsCache = new IdentityHashMap<>();

    public TaintTracer(Program program, SinkCatalog catalog) {
        this(program, catalog, openOwn(program), true);
    }

    public TaintTracer(Program program, SinkCatalog catalog, DecompInterface shared) {
        this(program, catalog, shared, false);
    }

    private TaintTracer(Program p, SinkCatalog c, DecompInterface d, boolean owns) {
        this.program = p; this.catalog = c; this.decomp = d; this.ownsDecomp = owns;
    }

    private static DecompInterface openOwn(Program program) {
        try {
            DecompInterface d = new DecompInterface();
            d.openProgram(program);
            d.setSimplificationStyle("decompile");
            return d;
        } catch (Exception e) {
            return null;
        }
    }

    @Override public void close() {
        if (ownsDecomp && decomp != null) {
            try { decomp.dispose(); } catch (Exception ignored) {}
        }
    }

    public int functionsVisited() { return hfCache.size(); }

    /** Decompile via cache. Returns null on failure (counted as a miss). */
    public HighFunction decompile(Function f) {
        if (f == null) return null;
        if (hfCache.containsKey(f)) return hfCache.get(f);
        HighFunction hf = null;
        if (decomp != null) {
            try {
                DecompileResults r = decomp.decompileFunction(f, DECOMP_TIMEOUT_S, TaskMonitor.DUMMY);
                if (r != null && r.decompileCompleted()) hf = r.getHighFunction();
            } catch (Exception ignored) {}
        }
        hfCache.put(f, hf); // cache nulls too (don't retry)
        return hf;
    }

    /**
     * Varnodes in {@code hf} that are catalog-source output buffers: the
     * out_arg varnode of any source call site, and the output varnode of any
     * source call with returnIsOutput=true. Cached per HighFunction.
     */
    public Set<Varnode> taintedBufferRoots(HighFunction hf) {
        Set<Varnode> cached = rootsCache.get(hf);
        if (cached != null) return cached;
        Set<Varnode> roots = new LinkedHashSet<>();
        FunctionManager fm = program.getFunctionManager();
        var ops = hf.getPcodeOps();
        while (ops.hasNext()) {
            PcodeOp op = ops.next();
            int oc = op.getOpcode();
            if (oc != PcodeOp.CALL && oc != PcodeOp.CALLIND) continue;
            Function callee = resolveCallee(op, fm);
            if (callee == null) continue;
            for (CatalogEntry e : catalog.resolve(callee)) {
                if (!"source".equals(e.kind())) continue;
                Integer outIdx = e.arg("out_arg");
                if (outIdx != null) {
                    Varnode v = PcodeQuery.argVarnode(op, outIdx);
                    if (v != null) roots.add(v);
                }
                if (e.returnIsOutput() && op.getOutput() != null) {
                    roots.add(op.getOutput());
                }
            }
        }
        rootsCache.put(hf, roots);
        return roots;
    }

    public Function resolveCallee(PcodeOp op, FunctionManager fm) {
        if (op.getNumInputs() == 0) return null;
        Varnode tgt = op.getInput(0);
        if (tgt != null && tgt.isAddress()) {
            Function f = fm.getFunctionAt(tgt.getAddress());
            if (f != null && f.isThunk()) {
                Function real = f.getThunkedFunction(true);
                if (real != null) return real;
            }
            return f;
        }
        // CALLIND fallback via references — same approach as VulnAnalysisService.resolveCallee
        if (op.getSeqnum() != null) {
            ReferenceManager rm = program.getReferenceManager();
            for (Reference ref : rm.getReferencesFrom(op.getSeqnum().getTarget())) {
                if (ref.getReferenceType().isCall()) {
                    Function f = fm.getFunctionAt(ref.getToAddress());
                    if (f != null) return f;
                }
            }
        }
        return null;
    }

    // ---- trace() — implemented in Task 3 ----
    public TaintResult trace(HighFunction startHf, PcodeOp sinkCall, int argIdx,
            int maxCallDepth, int maxFunctions) {
        throw new UnsupportedOperationException("Task 3");
    }
}
