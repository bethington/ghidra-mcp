package com.xebyte.core.vuln.detectors;

import com.xebyte.core.vuln.*;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import java.util.*;

/** Flags allocator size derived from non-constant INT_MULT/INT_ADD without an overflow guard. */
public final class IntegerOverflowAllocDetector implements VulnDetector {
    private static final int MAX_STEPS = 48;

    @Override public String id()           { return "integer_overflow_alloc"; }
    @Override public String description()  { return "Allocator size is INT_MULT/INT_ADD of a non-constant input with no observed overflow check."; }
    @Override public Set<String> sinkClasses() { return Set.of("alloc"); }

    @Override
    public List<Finding> scan(HighFunction hf, List<SinkCallSite> sites) {
        List<Finding> out = new ArrayList<>();
        String fn = hf.getFunction() != null ? hf.getFunction().getName() : "<unknown>";
        for (SinkCallSite s : sites) {
            if (!"alloc".equals(s.entry().vulnClass())) continue;
            Integer idx = s.entry().arg("size_arg");
            if (idx == null) continue;
            Varnode size = PcodeQuery.argVarnode(s.call(), idx);
            if (size == null || size.isConstant()) continue;

            PcodeOp risky = null;
            for (PcodeOp op : PcodeQuery.definingOps(size, MAX_STEPS)) {
                int oc = op.getOpcode();
                if (oc != PcodeOp.INT_MULT && oc != PcodeOp.INT_ADD) continue;
                boolean allConst = true;
                for (int i = 0; i < op.getNumInputs(); i++) {
                    Varnode in = op.getInput(i);
                    if (in == null || !in.isConstant()) { allConst = false; break; }
                }
                if (!allConst) { risky = op; break; }
            }
            if (risky == null) continue;
            if (PcodeQuery.hasDominatingCompare(size, hf, MAX_STEPS)) continue;

            out.add(new Finding(id(), "alloc", s.callAddr().toString(), fn,
                s.entry().id(), "medium",
                List.of("size = " + PcodeQuery.describe(size),
                        PcodeQuery.mnemonic(risky) + " on non-constant input feeds allocator"),
                "Allocator size derived via " + PcodeQuery.mnemonic(risky)
                    + " without an overflow check at " + s.callAddr()));
        }
        return out;
    }
}
