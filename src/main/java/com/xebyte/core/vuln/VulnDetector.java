package com.xebyte.core.vuln;

import ghidra.program.model.pcode.HighFunction;
import java.util.List;
import java.util.Set;

/**
 * One intra-function vulnerability pattern matcher. The service pre-resolves
 * every CALL in the HighFunction against the catalog and passes only the
 * SinkCallSites whose entry.vulnClass() ∈ sinkClasses() to scan(...).
 */
public interface VulnDetector {
    /** Stable id, snake_case (e.g. "format_string"). */
    String id();
    /** Human one-liner shown by list_vuln_detectors. */
    String description();
    /** Catalog vulnClass values this detector consumes (e.g. {"format"}). */
    Set<String> sinkClasses();
    /** Run the detector over the pre-resolved call sites. Never returns null. */
    List<Finding> scan(HighFunction hf, List<SinkCallSite> sites);
}
