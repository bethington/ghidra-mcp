package com.xebyte.core.vuln;

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Static PCode query helpers shared by all VulnDetectors. Intra-function only:
 * walks stop at CALL/CALLIND/CALLOTHER, MULTIEQUAL (phi), constants, and inputs
 * (no def). Mirrors the termination rules of AnalysisService.analyze_dataflow.
 */
public final class PcodeQuery {
    private PcodeQuery() {}

    /** 0-based call argument: input(0) is the call target, args start at input(1). */
    public static Varnode argVarnode(PcodeOp call, int idx) {
        if (call == null || idx < 0) return null;
        int slot = idx + 1;
        return slot < call.getNumInputs() ? call.getInput(slot) : null;
    }

    /**
     * True iff the backward def-chain from {@code v} reaches only constants
     * through transparent ops (COPY/CAST/INT_ZEXT/INT_SEXT/PTRSUB/PTRADD/INT_ADD/MULTIEQUAL).
     * A MULTIEQUAL (phi) is transparent iff all its inputs prove constant; loop-carried
     * back-edges are bounded by the seen-set so the walk always terminates.
     * False on any input (no-def), CALL*, LOAD, or step exhaustion.
     */
    public static boolean reachesConstantOnly(Varnode v, int maxSteps) {
        if (v == null) return false;
        Deque<Varnode> work = new ArrayDeque<>();
        Set<Varnode> seen = new LinkedHashSet<>();
        work.push(v);
        int steps = 0;
        while (!work.isEmpty()) {
            if (steps++ >= maxSteps) return false;
            Varnode cur = work.pop();
            if (!seen.add(cur)) continue;
            if (cur.isConstant()) continue;
            PcodeOp def = cur.getDef();
            if (def == null) return false;
            switch (def.getOpcode()) {
                case PcodeOp.COPY:
                case PcodeOp.CAST:
                case PcodeOp.INT_ZEXT:
                case PcodeOp.INT_SEXT:
                    work.push(def.getInput(0));
                    break;
                case PcodeOp.INDIRECT:
                    // INDIRECT(prev, iop) — call/store may-alias barrier. Transparent
                    // through input(0) per Ghidra's own ShowConstantUse semantics;
                    // input(1) is an iop-ref constant and must NOT be walked.
                    work.push(def.getInput(0));
                    break;
                case PcodeOp.PTRSUB:
                case PcodeOp.PTRADD:
                case PcodeOp.INT_ADD:
                case PcodeOp.INT_SUB:
                case PcodeOp.INT_MULT:
                case PcodeOp.MULTIEQUAL:
                    // A phi of constants is constant. Loop-carried phis are
                    // bounded by the seen-set (the back-edge input is skipped).
                    for (int i = 0; i < def.getNumInputs(); i++) work.push(def.getInput(i));
                    break;
                default:
                    return false;
            }
        }
        return true;
    }

    /**
     * Transitive set of producing PcodeOps reachable backward from {@code v},
     * stopping at constants, inputs, CALL/CALLIND/CALLOTHER, MULTIEQUAL, or
     * {@code maxSteps}. Includes every visited def op (boundary ops are included
     * but not recursed past).
     */
    public static Set<PcodeOp> definingOps(Varnode v, int maxSteps) {
        Set<PcodeOp> ops = new LinkedHashSet<>();
        if (v == null) return ops;
        Deque<Varnode> work = new ArrayDeque<>();
        Set<Varnode> seen = new LinkedHashSet<>();
        work.push(v);
        int steps = 0;
        while (!work.isEmpty() && steps++ < maxSteps) {
            Varnode cur = work.pop();
            if (!seen.add(cur) || cur.isConstant()) continue;
            PcodeOp def = cur.getDef();
            if (def == null) continue;
            int oc = def.getOpcode();
            if (oc == PcodeOp.CALL || oc == PcodeOp.CALLIND || oc == PcodeOp.CALLOTHER
                    || oc == PcodeOp.MULTIEQUAL) {
                ops.add(def);
                continue;
            }
            ops.add(def);
            if (oc == PcodeOp.INDIRECT) {
                // Only the prior-value input is meaningful for backward provenance.
                Varnode prev = def.getInput(0);
                if (prev != null) work.push(prev);
            } else {
                for (int i = 0; i < def.getNumInputs(); i++) {
                    Varnode in = def.getInput(i);
                    if (in != null) work.push(in);
                }
            }
        }
        return ops;
    }

    /** True iff any op in the def chain of {@code v} is a CALL/CALLIND. */
    public static boolean defChainHasCall(Varnode v, int maxSteps) {
        for (PcodeOp op : definingOps(v, maxSteps)) {
            int oc = op.getOpcode();
            if (oc == PcodeOp.CALL || oc == PcodeOp.CALLIND) return true;
        }
        return false;
    }

    /** True iff {@code v}'s backward walk reaches a no-def (function input/parameter). */
    public static boolean defChainHasInput(Varnode v, int maxSteps) {
        if (v == null) return false;
        Deque<Varnode> work = new ArrayDeque<>();
        Set<Varnode> seen = new LinkedHashSet<>();
        work.push(v);
        int steps = 0;
        while (!work.isEmpty() && steps++ < maxSteps) {
            Varnode cur = work.pop();
            if (!seen.add(cur) || cur.isConstant()) continue;
            PcodeOp def = cur.getDef();
            if (def == null) return true;
            int oc = def.getOpcode();
            if (oc == PcodeOp.CALL || oc == PcodeOp.CALLIND || oc == PcodeOp.CALLOTHER
                    || oc == PcodeOp.MULTIEQUAL) continue;
            if (oc == PcodeOp.INDIRECT) {
                Varnode prev = def.getInput(0);
                if (prev != null) work.push(prev);
                continue;
            }
            for (int i = 0; i < def.getNumInputs(); i++) {
                Varnode in = def.getInput(i);
                if (in != null) work.push(in);
            }
        }
        return false;
    }

    /**
     * Coarse "has a bound check on this size" test for Phase 1: true iff some
     * INT_LESS/INT_SLESS/INT_LESSEQUAL/INT_SLESSEQUAL/INT_EQUAL in {@code hf}
     * reads {@code v} or a varnode whose def is in {@code definingOps(v)}.
     * Not a CFG-dominance check (deferred to Phase 2).
     */
    public static boolean hasDominatingCompare(Varnode v, HighFunction hf, int maxSteps) {
        if (v == null || hf == null) return false;
        Set<PcodeOp> defs = definingOps(v, maxSteps);
        var it = hf.getPcodeOps();
        while (it.hasNext()) {
            PcodeOp op = it.next();
            switch (op.getOpcode()) {
                case PcodeOp.INT_LESS:
                case PcodeOp.INT_SLESS:
                case PcodeOp.INT_LESSEQUAL:
                case PcodeOp.INT_SLESSEQUAL:
                case PcodeOp.INT_EQUAL:
                    for (int i = 0; i < op.getNumInputs(); i++) {
                        Varnode in = op.getInput(i);
                        if (in == null) continue;
                        if (in.equals(v)) return true;
                        PcodeOp d = in.getDef();
                        if (d != null && defs.contains(d)) return true;
                    }
                    break;
                default:
            }
        }
        return false;
    }

    /**
     * Best-effort byte size of the buffer {@code dst} points at. Returns the
     * pointed-to / array DataType length when known; -1 when unknown.
     */
    public static int destBufferSize(Varnode dst, HighFunction hf) {
        if (dst == null) return -1;
        HighVariable hv = dst.getHigh();
        if (hv == null) return -1;
        // Prefer the SYMBOL's declared type — for `char buf[64]` the use-site
        // HighVariable type is `char*`, but HighSymbol.getDataType() is `char[64]`.
        HighSymbol sym = hv.getSymbol();
        DataType declared = (sym != null) ? sym.getDataType() : null;
        int len = sizeOf(declared);
        if (len > 0) return len;
        // Fallback: HighVariable's use-site type. Unwrap one Pointer; if the
        // pointed-to type is a primitive (≤ pointer width), we don't know the
        // buffer extent — return unknown rather than the element size.
        DataType dt = hv.getDataType();
        if (dt instanceof Pointer p && p.getDataType() != null) {
            int inner = sizeOf(p.getDataType());
            int ptrSize = (hf != null) ? hf.getFunction().getProgram()
                    .getDefaultPointerSize() : 8;
            return inner > ptrSize ? inner : -1;
        }
        return sizeOf(dt);
    }

    private static int sizeOf(DataType dt) {
        if (dt == null) return -1;
        int len = dt.getLength();
        return len > 0 ? len : -1;
    }

    /** Human label for evidence lines. */
    public static String describe(Varnode v) {
        if (v == null) return "<null>";
        if (v.isConstant()) return "0x" + Long.toHexString(v.getOffset());
        HighVariable hv = v.getHigh();
        if (hv != null && hv.getName() != null) return hv.getName();
        return v.toString();
    }

    public static String mnemonic(PcodeOp op) {
        try { return op != null ? op.getMnemonic() : "<null>"; }
        catch (Exception e) { return "op#" + (op != null ? op.getOpcode() : -1); }
    }
}
