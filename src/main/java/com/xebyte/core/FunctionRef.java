package com.xebyte.core;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

/** A function reference that can be a name or hex address. Must be resolved against a Program. */
public record FunctionRef(String value) {
    /** Resolve to a Function: tries address first, then exact name, then case-insensitive. */
    public Function resolve(Program program) {
        if (value == null || value.isEmpty()) return null;
        // Try as address
        try {
            var addr = program.getAddressFactory().getAddress(value);
            if (addr != null) {
                Function func = ServiceUtils.getFunctionForAddress(program, addr);
                if (func != null) return func;
            }
        } catch (Exception ignored) {}
        // Exact name match
        for (Function func : program.getFunctionManager().getFunctions(true))
            if (func.getName().equals(value)) return func;
        // Case-insensitive name match
        for (Function func : program.getFunctionManager().getFunctions(true))
            if (func.getName().equalsIgnoreCase(value)) return func;
        return null;
    }
}
