package com.xebyte.core.vuln.detectors;

import com.xebyte.core.vuln.*;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.Varnode;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/** Flags non-constant command argument reaching an exec sink. */
public final class CommandInjectionDetector implements VulnDetector {
    private static final int MAX_STEPS = 32;

    @Override public String id()           { return "command_injection"; }
    @Override public String description()  { return "Non-constant value reaches the command argument of system/popen/exec*/CreateProcess*/ShellExecute*."; }
    @Override public Set<String> sinkClasses() { return Set.of("exec"); }

    @Override
    public List<Finding> scan(HighFunction hf, List<SinkCallSite> sites) {
        List<Finding> out = new ArrayList<>();
        String fn = hf.getFunction() != null ? hf.getFunction().getName() : "<unknown>";
        for (SinkCallSite s : sites) {
            if (!sinkClasses().contains(s.entry().vulnClass())) continue;
            Integer idx = s.entry().arg("cmd_arg");
            if (idx == null) continue;
            Varnode cmd = PcodeQuery.argVarnode(s.call(), idx);
            if (cmd == null) continue;
            if (PcodeQuery.reachesConstantOnly(cmd, MAX_STEPS)) continue;
            boolean fromInput = PcodeQuery.defChainHasInput(cmd, MAX_STEPS)
                             || PcodeQuery.defChainHasCall(cmd, MAX_STEPS);
            String conf = fromInput ? "high" : "medium";
            out.add(new Finding(id(), "exec", s.callAddr().toString(), fn,
                s.entry().id(), conf,
                List.of("cmd_arg = " + PcodeQuery.describe(cmd) + " (non-constant)"),
                "Non-constant command reaches " + s.entry().id() + " at " + s.callAddr()));
        }
        return out;
    }
}
