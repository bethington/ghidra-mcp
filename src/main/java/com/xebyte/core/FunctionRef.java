package com.xebyte.core;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;

/**
 * Type-safe function reference that accepts either an address (hex) or a
 * function name.  Resolution order:
 * <ol>
 *   <li>Parse as hex address → {@code getFunctionAt(addr)}</li>
 *   <li>Exact name match (case-sensitive)</li>
 *   <li>Case-insensitive name match</li>
 * </ol>
 *
 * Constructed from a String by {@link AnnotationScanner}'s type-converting
 * argument resolver.
 */
public record FunctionRef(String value) {

    /**
     * Resolve this reference to a Function in the given program.
     *
     * @return the resolved Function, or {@code null} if not found
     */
    public Function resolve(Program program) {
        if (value == null || value.isBlank()) return null;

        // 1. Try as address (at or containing)
        try {
            Address addr = program.getAddressFactory().getAddress(value);
            if (addr != null) {
                Function func = program.getFunctionManager().getFunctionAt(addr);
                if (func != null) return func;
                func = program.getFunctionManager().getFunctionContaining(addr);
                if (func != null) return func;
            }
        } catch (Exception ignored) {
            // Not a valid address — try as name
        }

        // 2. Exact name match via symbol table
        for (Symbol sym : program.getSymbolTable().getSymbols(value)) {
            if (sym.getSymbolType() == SymbolType.FUNCTION) {
                Function func = program.getFunctionManager().getFunctionAt(sym.getAddress());
                if (func != null) return func;
            }
        }

        // 3. Case-insensitive scan
        String lower = value.toLowerCase();
        FunctionIterator iter = program.getFunctionManager().getFunctions(true);
        while (iter.hasNext()) {
            Function func = iter.next();
            if (func.getName().toLowerCase().equals(lower)) {
                return func;
            }
        }

        return null;
    }

    /**
     * Resolve or throw an error suitable for returning in a Response.
     */
    public Function resolveOrError(Program program) {
        Function func = resolve(program);
        if (func == null) {
            throw new IllegalArgumentException(
                "No function found for '" + value + "' (tried address, exact name, case-insensitive name)");
        }
        return func;
    }

    @Override
    public String toString() {
        return value;
    }
}
