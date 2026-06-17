package com.xebyte.core.vuln.detectors;

import com.xebyte.core.vuln.*;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.Varnode;
import java.util.ArrayList;
import java.util.List;

/**
 * Shared logic for detectors that flag a non-constant value reaching a
 * single-arg sink (format string, command injection). Subclasses supply
 * id/description/sinkClasses, the catalog arg-role key, and the vuln class
 * label written into the Finding.
 */
abstract class AbstractNonConstArgDetector implements VulnDetector {
    static final int MAX_STEPS = 32;

    /** Catalog arg-role key (e.g. "fmt_arg", "cmd_arg"). */
    protected abstract String argRole();
    /** vulnClass string written into emitted Findings (e.g. "format", "exec"). */
    protected abstract String findingClass();
    /** Noun used in evidence/why text (e.g. "format string", "command"). */
    protected abstract String argNoun();

    @Override
    public final List<Finding> scan(HighFunction hf, List<SinkCallSite> sites) {
        List<Finding> out = new ArrayList<>();
        String fn = hf.getFunction() != null ? hf.getFunction().getName() : "<unknown>";
        var classes = sinkClasses();
        for (SinkCallSite s : sites) {
            if (!classes.contains(s.entry().vulnClass())) continue;
            Integer idx = s.entry().arg(argRole());
            if (idx == null) continue;
            Varnode arg = PcodeQuery.argVarnode(s.call(), idx);
            if (arg == null) continue;
            if (PcodeQuery.reachesConstantOnly(arg, MAX_STEPS)) continue;
            boolean fromInput = PcodeQuery.defChainHasInput(arg, MAX_STEPS)
                             || PcodeQuery.defChainHasCall(arg, MAX_STEPS);
            String conf = fromInput ? "high" : "medium";
            out.add(new Finding(id(), findingClass(), s.callAddr().toString(), fn,
                s.entry().id(), conf,
                List.of(argRole() + " = " + PcodeQuery.describe(arg) + " (non-constant)"),
                "Non-constant " + argNoun() + " reaches " + s.entry().id() + " at " + s.callAddr()));
        }
        return out;
    }
}
