package com.xebyte.core.vuln;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.PcodeOp;

/**
 * A CALL/CALLIND site whose callee resolved to a catalog entry.
 * Valid only within the scan() call that created it: {@code call} is a
 * {@link ghidra.program.model.pcode.PcodeOp} owned by a single decompile
 * result and becomes stale if the HighFunction is recomputed.
 */
public record SinkCallSite(PcodeOp call, CatalogEntry entry, Function callee, Address callAddr) {}
