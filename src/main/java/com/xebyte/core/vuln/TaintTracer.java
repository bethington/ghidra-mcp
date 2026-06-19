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

    // ---- trace() — backward inter-procedural walk ----

    /**
     * One worklist frame. {@code seen} is the per-function varnode visited
     * set: intra-function forks SHARE the parent's set (bounding loop-carried
     * phi cycles); inter-procedural enqueues get a fresh set.
     */
    private record Frame(HighFunction hf, Varnode v, int depth,
            List<TaintStep> path, Set<Function> onPath, Set<Varnode> seen) {}

    /** Longest dead-end path with its own terminal reason (kept paired). */
    private record Dead(List<TaintStep> path, String reason) {}

    public TaintResult trace(HighFunction startHf, PcodeOp sinkCall, int argIdx,
            int maxCallDepth, int maxFunctions) {
        int depthCap = Math.max(1, Math.min(maxCallDepth, 10));
        int fnCap = Math.max(1, Math.min(maxFunctions, 256));

        Varnode start = PcodeQuery.argVarnode(sinkCall, argIdx);
        if (start == null) return new TaintResult(null, List.of(), "no_arg", 0, 0);
        hfCache.putIfAbsent(startHf.getFunction(), startHf);

        Deque<Frame> work = new ArrayDeque<>();
        work.add(new Frame(startHf, start, 0, new ArrayList<>(),
            new LinkedHashSet<>(Set.of(startHf.getFunction())),
            new LinkedHashSet<>()));

        Dead best = new Dead(List.of(), "no_path");
        int maxDepthReached = 0;

        FunctionManager fm = program.getFunctionManager();
        ReferenceManager rm = program.getReferenceManager();

        while (!work.isEmpty()) {
            Frame fr = work.poll();
            maxDepthReached = Math.max(maxDepthReached, fr.depth);
            String fnName = fr.hf.getFunction() != null ? fr.hf.getFunction().getName() : "?";

            // ---- intra-function backward walk to a boundary ----
            Varnode cur = fr.v;
            Set<Varnode> seen = fr.seen();
            List<TaintStep> path = new ArrayList<>(fr.path);
            int steps = 0;
            while (cur != null && steps++ < INTRA_STEP_CAP) {
                if (!seen.add(cur)) {
                    // Already visited in this function (loop-carried phi or
                    // diamond join) — treat as a cycle terminal.
                    if (path.size() >= best.path().size())
                        best = new Dead(List.copyOf(path), "cycle");
                    cur = null; break;
                }
                if (cur.isConstant()) {
                    if (path.size() >= best.path().size())
                        best = new Dead(List.copyOf(path), "constant");
                    cur = null; break;
                }
                PcodeOp def = cur.getDef();
                if (def == null) {
                    // Parameter? → cross to callers. Else: terminal "input".
                    HighVariable hv = cur.getHigh();
                    HighSymbol sym = hv != null ? hv.getSymbol() : null;
                    if (sym != null && sym.isParameter()) {
                        int slot = sym.getCategoryIndex();
                        path.add(step(fnName, sinkAddr(def, fr.hf), "param",
                            "param_" + slot + " → callers"));
                        if (fr.depth >= depthCap) {
                            if (path.size() >= best.path().size())
                                best = new Dead(List.copyOf(path), "call_depth");
                        } else {
                            enqueueCallers(work, fr, slot, path, fm, rm, fnCap);
                        }
                    } else {
                        if (path.size() >= best.path().size())
                            best = new Dead(List.copyOf(path), "input");
                    }
                    cur = null; break;
                }
                int oc = def.getOpcode();
                if (oc == PcodeOp.CALL || oc == PcodeOp.CALLIND) {
                    Function callee = resolveCallee(def, fm);
                    path.add(step(fnName, opAddr(def), "call_return",
                        callee != null ? callee.getName() : "<indirect>"));
                    String term = null;
                    if (callee != null) {
                        for (CatalogEntry e : catalog.resolve(callee)) {
                            if ("source".equals(e.kind())) {
                                return new TaintResult(e, path, "source",
                                    functionsVisited(), maxDepthReached);
                            }
                        }
                        if (fr.depth >= depthCap || fr.onPath.contains(callee)
                                || functionsVisited() >= fnCap) {
                            term = fr.onPath.contains(callee) ? "recursion"
                                : (fr.depth >= depthCap ? "call_depth" : "budget");
                        } else {
                            HighFunction chf = decompile(callee);
                            if (chf == null) term = "decompile_failed";
                            else enqueueReturns(work, fr, chf, callee, path);
                        }
                    } else {
                        term = "indirect_call";
                    }
                    if (term != null && path.size() >= best.path().size())
                        best = new Dead(List.copyOf(path), term);
                    cur = null; break;
                }
                if (oc == PcodeOp.LOAD) {
                    Varnode laddr = def.getNumInputs() > 1 ? def.getInput(1) : null;
                    CatalogEntry hit = loadFromTaintedBuffer(fr.hf, laddr);
                    path.add(step(fnName, opAddr(def), "load",
                        hit != null ? "address derives from " + hit.id() + " out-buffer"
                                    : "address provenance unknown"));
                    if (hit != null) {
                        return new TaintResult(hit, path, "tainted_load",
                            functionsVisited(), maxDepthReached);
                    }
                    if (path.size() >= best.path().size())
                        best = new Dead(List.copyOf(path), "load_unknown_provenance");
                    cur = null; break;
                }
                // transparent ops — record and continue through input(s)
                path.add(step(fnName, opAddr(def), "op", PcodeQuery.mnemonic(def)));
                switch (oc) {
                    case PcodeOp.COPY: case PcodeOp.CAST:
                    case PcodeOp.INT_ZEXT: case PcodeOp.INT_SEXT:
                    case PcodeOp.INDIRECT:
                        cur = def.getInput(0); break;
                    case PcodeOp.PTRSUB: case PcodeOp.PTRADD:
                    case PcodeOp.INT_ADD: case PcodeOp.INT_SUB: case PcodeOp.INT_MULT:
                    case PcodeOp.MULTIEQUAL:
                        // follow the first non-constant input; fork the rest.
                        // Forked frames share `seen` so loop-carried inputs are
                        // visited at most once across the whole function.
                        Varnode next = null;
                        for (int i = 0; i < def.getNumInputs(); i++) {
                            Varnode in = def.getInput(i);
                            if (in == null || in.isConstant()) continue;
                            if (next == null) next = in;
                            else if (!seen.contains(in))
                                work.add(new Frame(fr.hf, in, fr.depth,
                                    new ArrayList<>(path), fr.onPath, seen));
                        }
                        cur = next; break;
                    default:
                        if (path.size() >= best.path().size())
                            best = new Dead(List.copyOf(path), "op_" + PcodeQuery.mnemonic(def));
                        cur = null;
                }
            }
        }
        return new TaintResult(null, best.path(), best.reason(),
            functionsVisited(), maxDepthReached);
    }

    private void enqueueCallers(Deque<Frame> work, Frame fr, int slot,
            List<TaintStep> path, FunctionManager fm, ReferenceManager rm, int fnCap) {
        Function self = fr.hf.getFunction();
        var refs = rm.getReferencesTo(self.getEntryPoint());
        int taken = 0;
        while (refs.hasNext() && taken < CALLER_FANOUT_CAP) {
            var ref = refs.next();
            if (!ref.getReferenceType().isCall()) continue;
            Function caller = fm.getFunctionContaining(ref.getFromAddress());
            if (caller == null || fr.onPath.contains(caller)) continue;
            if (functionsVisited() >= fnCap) break;
            HighFunction chf = decompile(caller);
            if (chf == null) continue;
            // find the CALL op at this site to read its arg[slot]
            PcodeOp callOp = null;
            var it = chf.getPcodeOps(ref.getFromAddress());
            while (it != null && it.hasNext()) {
                PcodeOp op = it.next();
                if (op.getOpcode() == PcodeOp.CALL || op.getOpcode() == PcodeOp.CALLIND) {
                    callOp = op; break;
                }
            }
            if (callOp == null) continue;
            Varnode arg = PcodeQuery.argVarnode(callOp, slot);
            if (arg == null) continue;
            Set<Function> on = new LinkedHashSet<>(fr.onPath); on.add(caller);
            List<TaintStep> p = new ArrayList<>(path);
            p.add(step(caller.getName(), ref.getFromAddress().toString(),
                "caller_arg", "arg" + slot + " at call to " + self.getName()));
            work.add(new Frame(chf, arg, fr.depth + 1, p, on, new LinkedHashSet<>()));
            taken++;
        }
    }

    private void enqueueReturns(Deque<Frame> work, Frame fr, HighFunction chf,
            Function callee, List<TaintStep> path) {
        Set<Function> on = new LinkedHashSet<>(fr.onPath); on.add(callee);
        var ops = chf.getPcodeOps();
        while (ops.hasNext()) {
            PcodeOp op = ops.next();
            if (op.getOpcode() != PcodeOp.RETURN) continue;
            // RETURN input(0) is the indirect target; value (if any) is input(1).
            if (op.getNumInputs() < 2) continue;
            Varnode rv = op.getInput(1);
            if (rv == null) continue;
            List<TaintStep> p = new ArrayList<>(path);
            p.add(step(callee.getName(), opAddr(op), "into_callee_return",
                "RETURN value of " + callee.getName()));
            work.add(new Frame(chf, rv, fr.depth + 1, p, on, new LinkedHashSet<>()));
        }
    }

    private CatalogEntry loadFromTaintedBuffer(HighFunction hf, Varnode addr) {
        if (addr == null) return null;
        Set<Varnode> roots = taintedBufferRoots(hf);
        if (roots.isEmpty()) return null;
        // Walk addr's intra-function def chain; if any base input is (or
        // COPY/CAST-derives from) a root, it's tainted.
        Deque<Varnode> w = new ArrayDeque<>(); w.push(addr);
        Set<Varnode> seen = new HashSet<>();
        int steps = 0;
        while (!w.isEmpty() && steps++ < INTRA_STEP_CAP) {
            Varnode v = w.pop();
            if (!seen.add(v)) continue;
            if (roots.contains(v)) return rootEntryFor(hf, v);
            PcodeOp d = v.getDef();
            if (d == null) continue;
            switch (d.getOpcode()) {
                case PcodeOp.COPY: case PcodeOp.CAST: case PcodeOp.INDIRECT:
                case PcodeOp.INT_ZEXT: case PcodeOp.INT_SEXT:
                    w.push(d.getInput(0)); break;
                case PcodeOp.PTRADD: case PcodeOp.PTRSUB:
                case PcodeOp.INT_ADD: case PcodeOp.INT_SUB:
                    for (int i = 0; i < d.getNumInputs(); i++)
                        if (d.getInput(i) != null) w.push(d.getInput(i));
                    break;
                default: // LOAD/CALL/etc — stop this branch
            }
        }
        return null;
    }

    private CatalogEntry rootEntryFor(HighFunction hf, Varnode root) {
        // Re-scan to find which source produced this root (cheap; small set).
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
                Integer oi = e.arg("out_arg");
                if (oi != null && PcodeQuery.argVarnode(op, oi) == root) return e;
                if (e.returnIsOutput() && op.getOutput() == root) return e;
            }
        }
        return null;
    }

    private static TaintStep step(String fn, String addr, String kind, String detail) {
        return new TaintStep(fn, addr == null ? "" : addr, kind, detail);
    }
    private static String opAddr(PcodeOp op) {
        return (op != null && op.getSeqnum() != null && op.getSeqnum().getTarget() != null)
            ? op.getSeqnum().getTarget().toString() : "";
    }
    private static String sinkAddr(PcodeOp op, HighFunction hf) {
        if (op != null) return opAddr(op);
        return hf.getFunction() != null && hf.getFunction().getEntryPoint() != null
            ? hf.getFunction().getEntryPoint().toString() : "";
    }
}
