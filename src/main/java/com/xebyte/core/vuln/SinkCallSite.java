package com.xebyte.core.vuln;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.PcodeOp;

/** A CALL/CALLIND site whose callee resolved to a catalog entry. */
public record SinkCallSite(PcodeOp call, CatalogEntry entry, Function callee, Address callAddr) {}
