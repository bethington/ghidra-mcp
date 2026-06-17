package com.xebyte.core.vuln.detectors;

import java.util.Set;

/** Flags non-constant format-argument reaching a format sink. */
public final class FormatStringDetector extends AbstractNonConstArgDetector {
    @Override public String id()              { return "format_string"; }
    @Override public String description()     { return "Non-constant value reaches the format-string argument of a printf/scanf/syslog-family sink."; }
    @Override public Set<String> sinkClasses() { return Set.of("format"); }
    @Override protected String argRole()      { return "fmt_arg"; }
    @Override protected String findingClass() { return "format"; }
    @Override protected String argNoun()      { return "format string"; }
}
