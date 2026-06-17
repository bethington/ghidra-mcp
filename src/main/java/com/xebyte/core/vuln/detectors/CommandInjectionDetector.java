package com.xebyte.core.vuln.detectors;

import java.util.Set;

/** Flags non-constant command argument reaching an exec sink. */
public final class CommandInjectionDetector extends AbstractNonConstArgDetector {
    @Override public String id()              { return "command_injection"; }
    @Override public String description()     { return "Non-constant value reaches the command argument of system/popen/exec*/CreateProcess*/ShellExecute*."; }
    @Override public Set<String> sinkClasses() { return Set.of("exec"); }
    @Override protected String argRole()      { return "cmd_arg"; }
    @Override protected String findingClass() { return "exec"; }
    @Override protected String argNoun()      { return "command"; }
}
