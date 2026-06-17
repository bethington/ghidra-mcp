package com.xebyte.core.vuln.detectors;

import com.xebyte.core.vuln.*;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.Varnode;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/** Flags non-constant format-argument reaching a format sink. */
public final class FormatStringDetector implements VulnDetector {
    private static final int MAX_STEPS = 32;

    @Override public String id()           { return "format_string"; }
    @Override public String description()  { return "Non-constant value reaches the format-string argument of a printf/scanf/syslog-family sink."; }
    @Override public Set<String> sinkClasses() { return Set.of("format"); }

    @Override
    public List<Finding> scan(HighFunction hf, List<SinkCallSite> sites) {
        List<Finding> out = new ArrayList<>();
        String fn = hf.getFunction() != null ? hf.getFunction().getName() : "<unknown>";
        for (SinkCallSite s : sites) {
            if (!sinkClasses().contains(s.entry().vulnClass())) continue;
            Integer idx = s.entry().arg("fmt_arg");
            if (idx == null) continue;
            Varnode fmt = PcodeQuery.argVarnode(s.call(), idx);
            if (fmt == null) continue;
            if (PcodeQuery.reachesConstantOnly(fmt, MAX_STEPS)) continue;
            boolean fromInput = PcodeQuery.defChainHasInput(fmt, MAX_STEPS)
                             || PcodeQuery.defChainHasCall(fmt, MAX_STEPS);
            String conf = fromInput ? "high" : "medium";
            out.add(new Finding(id(), "format", s.callAddr().toString(), fn,
                s.entry().id(), conf,
                List.of("fmt_arg = " + PcodeQuery.describe(fmt) + " (non-constant)"),
                "Non-constant format string reaches " + s.entry().id() + " at " + s.callAddr()));
        }
        return out;
    }
}
