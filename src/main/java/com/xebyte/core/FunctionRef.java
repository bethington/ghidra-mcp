package com.xebyte.core;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;

/**
 * Unified function reference that resolves a {@link Function} from either
 * a name or an address string, using a multi-step resolution chain:
 *
 * <ol>
 *   <li>Try parsing as hex address → {@code getFunctionAt(addr)}</li>
 *   <li>Fallback → {@code getFunctionContaining(addr)}</li>
 *   <li>Symbol table lookup by exact name</li>
 *   <li>Case-insensitive name fallback</li>
 * </ol>
 *
 * <p>Usage:
 * <pre>{@code
 *   FunctionRef ref = FunctionRef.of(userInput);
 *   Function func = ref.resolve(program);
 *   // or with custom error handling:
 *   FunctionRef.Result result = ref.tryResolve(program);
 * }</pre>
 *
 * <p>Replaces duplicated resolution patterns across FunctionService,
 * AnalysisService, XrefCallGraphService, and CommentService.
 *
 * @since 4.3.0
 */
public final class FunctionRef {

    /** Immutable result of a resolution attempt. */
    public record Result(Function function, String error) {
        public boolean isSuccess() { return function != null; }

        /** Get the resolved function or throw IllegalStateException. */
        public Function orThrow() {
            if (function == null) {
                throw new IllegalStateException(error);
            }
            return function;
        }
    }

    private final String ref;

    private FunctionRef(String ref) {
        this.ref = ref;
    }

    /**
     * Create a FunctionRef from a user-supplied string (address or name).
     *
     * @param ref hex address (e.g., "0x00401000", "401000") or function name
     * @return a FunctionRef instance
     * @throws IllegalArgumentException if ref is null or blank
     */
    public static FunctionRef of(String ref) {
        if (ref == null || ref.isBlank()) {
            throw new IllegalArgumentException("Function reference must not be null or blank");
        }
        return new FunctionRef(ref.trim());
    }

    /**
     * Create a FunctionRef from separate name and address params, preferring
     * whichever is non-null. This mirrors the common endpoint pattern where
     * callers provide either {@code function_name} or {@code function_address}.
     *
     * @param name    function name (may be null)
     * @param address function address (may be null)
     * @return a FunctionRef for whichever is provided (address preferred)
     * @throws IllegalArgumentException if both are null/blank
     */
    public static FunctionRef ofNameOrAddress(String name, String address) {
        if (address != null && !address.isBlank()) {
            return new FunctionRef(address.trim());
        }
        if (name != null && !name.isBlank()) {
            return new FunctionRef(name.trim());
        }
        throw new IllegalArgumentException(
            "Either function_name or function_address must be provided");
    }

    /**
     * Resolve the function through the full resolution chain.
     *
     * @param program the Ghidra program to search
     * @return the resolved Function, never null
     * @throws IllegalStateException if the function cannot be resolved
     */
    public Function resolve(Program program) {
        return tryResolve(program).orThrow();
    }

    /**
     * Attempt to resolve the function, returning a Result with either
     * the function or an error message.
     *
     * @param program the Ghidra program to search
     * @return a Result containing the function or error description
     */
    public Result tryResolve(Program program) {
        if (program == null) {
            return new Result(null, "No program is open");
        }

        FunctionManager fm = program.getFunctionManager();

        // --- Step 1: Try as hex address ---
        Function func = resolveByAddress(program, fm);
        if (func != null) {
            return new Result(func, null);
        }

        // --- Step 2: Try as function name via symbol table (efficient) ---
        func = resolveBySymbolTable(program, fm);
        if (func != null) {
            return new Result(func, null);
        }

        // --- Step 3: Case-insensitive name fallback (linear scan) ---
        func = resolveByCaseInsensitiveName(fm);
        if (func != null) {
            return new Result(func, null);
        }

        return new Result(null,
            "Function not found: '" + ref + "' (tried as address, exact name, and case-insensitive name)");
    }

    /**
     * Resolve by parsing as a hex address, with getFunctionContaining fallback.
     */
    private Function resolveByAddress(Program program, FunctionManager fm) {
        Address addr;
        try {
            addr = ServiceUtils.parseAddress(program, ref);
        } catch (Exception e) {
            return null; // Not a valid address — will try name resolution
        }
        if (addr == null) {
            return null;
        }

        Function func = fm.getFunctionAt(addr);
        if (func != null) {
            return func;
        }

        // Fallback: address might be inside the function body
        return fm.getFunctionContaining(addr);
    }

    /**
     * Resolve by exact name via the SymbolTable (O(1) hash lookup).
     */
    private Function resolveBySymbolTable(Program program, FunctionManager fm) {
        SymbolTable symbolTable = program.getSymbolTable();
        SymbolIterator symbols = symbolTable.getSymbols(ref);
        while (symbols.hasNext()) {
            Symbol symbol = symbols.next();
            if (symbol.getSymbolType() == SymbolType.FUNCTION) {
                Function func = fm.getFunctionAt(symbol.getAddress());
                if (func != null) {
                    return func;
                }
            }
        }
        return null;
    }

    /**
     * Resolve by case-insensitive name match (linear scan, last resort).
     */
    private Function resolveByCaseInsensitiveName(FunctionManager fm) {
        for (Function func : fm.getFunctions(true)) {
            if (func.getName().equalsIgnoreCase(ref)) {
                return func;
            }
        }
        return null;
    }

    /** Returns the original reference string. */
    public String raw() {
        return ref;
    }

    @Override
    public String toString() {
        return "FunctionRef[" + ref + "]";
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof FunctionRef other && ref.equals(other.ref);
    }

    @Override
    public int hashCode() {
        return ref.hashCode();
    }
}
