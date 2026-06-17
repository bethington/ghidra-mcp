package com.xebyte.core.vuln.detectors;

import com.xebyte.core.vuln.*;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.Varnode;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/** Flags copies into a bounded destination without an adequate length guard. */
public final class UnboundedCopyDetector implements VulnDetector {
    private static final int MAX_STEPS = 48;

    @Override public String id()           { return "unbounded_copy"; }
    @Override public String description()  { return "memcpy/strcpy-family call writes into a bounded buffer without a dominating size check or with a non-constant length."; }
    @Override public Set<String> sinkClasses() { return Set.of("copy"); }

    @Override
    public List<Finding> scan(HighFunction hf, List<SinkCallSite> sites) {
        List<Finding> out = new ArrayList<>();
        String fn = hf.getFunction() != null ? hf.getFunction().getName() : "<unknown>";
        for (SinkCallSite s : sites) {
            if (!"copy".equals(s.entry().vulnClass())) continue;
            Integer dstIdx = s.entry().arg("dst_arg");
            if (dstIdx == null) continue;
            Varnode dst = PcodeQuery.argVarnode(s.call(), dstIdx);
            int destSize = PcodeQuery.destBufferSize(dst, hf);
            if (destSize <= 0) continue;

            Integer sizeIdx = s.entry().arg("size_arg");
            if (sizeIdx == null) {
                Varnode src = PcodeQuery.argVarnode(s.call(), dstIdx + 1);
                if (src != null && !PcodeQuery.reachesConstantOnly(src, MAX_STEPS)) {
                    out.add(finding(s, fn, "high",
                        List.of("dest size = " + destSize + " bytes",
                                "src = " + PcodeQuery.describe(src) + " (unbounded, non-constant)"),
                        "Unbounded string copy into " + destSize + "-byte buffer via " + s.entry().id()));
                }
                continue;
            }

            Varnode size = PcodeQuery.argVarnode(s.call(), sizeIdx);
            if (size == null) continue;
            if (size.isConstant()) {
                long k = size.getOffset();
                if (k <= destSize) continue;
                out.add(finding(s, fn, "high",
                    List.of("dest size = " + destSize + " bytes", "length constant = " + k),
                    "Constant-length copy of " + k + " bytes into " + destSize + "-byte buffer via " + s.entry().id()));
                continue;
            }
            if (PcodeQuery.hasDominatingCompare(size, hf, MAX_STEPS)) continue;
            out.add(finding(s, fn, "medium",
                List.of("dest size = " + destSize + " bytes",
                        "length = " + PcodeQuery.describe(size) + " (non-constant, no observed bound check)"),
                "Length-unchecked copy into " + destSize + "-byte buffer via " + s.entry().id()));
        }
        return out;
    }

    private Finding finding(SinkCallSite s, String fn, String conf, List<String> ev, String why) {
        return new Finding(id(), "copy", s.callAddr().toString(), fn, s.entry().id(), conf, ev, why);
    }
}
