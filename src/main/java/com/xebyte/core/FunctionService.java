package com.xebyte.core;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighFunctionDBUtil.ReturnCommitOption;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;

import java.util.*;
import javax.swing.SwingUtilities;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Service for function-related operations: decompilation, renaming, prototype management,
 * variable typing, and function creation/deletion.
 * Extracted from GhidraMCPPlugin as part of v4.0.0 refactor.
 */
public class FunctionService {

    private static final int DECOMPILE_TIMEOUT_SECONDS = 60;  // Increased from 30s to 60s for large functions

    private final ProgramProvider programProvider;
    private final ThreadingStrategy threadingStrategy;

    public FunctionService(ProgramProvider programProvider, ThreadingStrategy threadingStrategy) {
        this.programProvider = programProvider;
        this.threadingStrategy = threadingStrategy;
    }

    // ========================================================================
    // Program resolution helper
    // ========================================================================

    /**
     * Resolve a program by name, returning [program, Response.Err].
     * If program is null, the second element contains a Response.Err.
     */
    private Object[] getProgramOrError(String programName) {
        Program program = programProvider.resolveProgram(programName);
        if (program == null) {
            String msg = (programName != null && !programName.trim().isEmpty())
                ? "Program not found: " + programName
                : "No program currently loaded";
            return new Object[]{null, Response.err(msg)};
        }
        return new Object[]{program, null};
    }

    // ========================================================================
    // Inner classes
    // ========================================================================

    /**
     * Class to hold the result of a prototype setting operation.
     */
    public static class PrototypeResult {
        private final boolean success;
        private final String errorMessage;

        public PrototypeResult(boolean success, String errorMessage) {
            this.success = success;
            this.errorMessage = errorMessage;
        }

        public boolean isSuccess() {
            return success;
        }

        public String getErrorMessage() {
            return errorMessage;
        }
    }

    /** Suggest a concrete type for an undefined Ghidra type based on size. */
    public static String suggestType(String typeName) {
        if ("undefined1".equals(typeName)) return "byte";
        if ("undefined2".equals(typeName)) return "ushort";
        if ("undefined4".equals(typeName)) return "uint";
        if ("undefined8".equals(typeName)) return "ulonglong";
        return "uint";
    }

    /** Suggest a Hungarian notation prefix for a resolved type. */
    public static String suggestHungarianPrefix(String typeName) {
        if (typeName == null) return "";
        String base = typeName.replace("*", "").replace("[]", "").trim();
        if (typeName.contains("*")) {
            if ("char".equals(base)) return "sz";
            if ("wchar_t".equals(base)) return "wsz";
            if ("void".equals(base)) return "p";
            return "p";
        }
        if (typeName.contains("[")) {
            if ("byte".equals(base) || "undefined1".equals(base)) return "ab";
            if ("ushort".equals(base)) return "aw";
            if ("uint".equals(base)) return "ad";
            return "a";
        }
        switch (base) {
            case "byte": case "uchar": return "b";
            case "char": return "c";
            case "bool": case "BOOL": return "f";
            case "short": case "int16_t": return "n";
            case "ushort": case "uint16_t": case "WORD": case "wchar_t": return "w";
            case "int": case "int32_t": case "long": return "n";
            case "uint": case "uint32_t": case "ulong": case "DWORD": case "dword": return "dw";
            case "longlong": case "int64_t": return "ll";
            case "ulonglong": case "uint64_t": case "QWORD": return "qw";
            case "float": return "fl";
            case "double": return "d";
            case "void": return "";
            case "HANDLE": return "h";
            default: return "";
        }
    }

    // ========================================================================
    // Decompilation methods
    // ========================================================================

    /**
     * Decompile a function by its name.
     */
    public Response decompileFunctionByName(String name) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) return Response.err("No program loaded");
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            if (func.getName().equals(name)) {
                DecompileResults result =
                    decomp.decompileFunction(func, DECOMPILE_TIMEOUT_SECONDS, new ConsoleTaskMonitor());
                if (result != null && result.decompileCompleted()) {
                    return Response.text(result.getDecompiledFunction().getC());
                } else {
                    return Response.err("Decompilation failed");
                }
            }
        }
        return Response.err("Function not found");
    }

    /**
     * Decompile a function at the given address.
     * If programName is provided, uses that program instead of the current one.
     */
    @McpTool(value = "/decompile_function", description = "Decompile a function by name or address and return the decompiled C code")

    public Response decompileFunctionByAddress(

            @Param(value = "address") String addressStr,

            @Param(value = "program", required = false) String programName,

            @Param(value = "timeoutSeconds", type = "integer") int timeoutSeconds) {
        Object[] result = getProgramOrError(programName);
        Program program = (Program) result[0];
        if (program == null) return (Response) result[1];
        if (addressStr == null || addressStr.isEmpty()) return Response.err("Address is required");

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = ServiceUtils.getFunctionForAddress(program, addr);
            if (func == null) return Response.err("No function found at or containing address " + addressStr);

            DecompInterface decomp = new DecompInterface();
            decomp.openProgram(program);
            DecompileResults decompResult = decomp.decompileFunction(func, timeoutSeconds, new ConsoleTaskMonitor());

            if (decompResult == null) {
                return Response.err("Decompiler returned null result for function at " + addressStr);
            }

            if (!decompResult.decompileCompleted()) {
                String errorMsg = decompResult.getErrorMessage();
                return Response.err("Decompilation did not complete. " +
                       (errorMsg != null ? "Reason: " + errorMsg : "Function may be too complex or have invalid code flow."));
            }

            if (decompResult.getDecompiledFunction() == null) {
                return Response.err("Decompiler completed but returned null decompiled function.");
            }

            return Response.text(decompResult.getDecompiledFunction().getC());
        } catch (Throwable e) {
            String msg = e.getMessage() != null ? e.getMessage() : e.toString();
            return Response.err("Error decompiling function: " + msg);
        }
    }

    // Backward compatible overloads for internal callers
    public Response decompileFunctionByAddress(String addressStr, String programName) {
        return decompileFunctionByAddress(addressStr, programName, DECOMPILE_TIMEOUT_SECONDS);
    }

    public Response decompileFunctionByAddress(String addressStr) {
        return decompileFunctionByAddress(addressStr, null, DECOMPILE_TIMEOUT_SECONDS);
    }

    /**
     * Decompile a function and return the results (with retry logic).
     */
    public DecompileResults decompileFunction(Function func, Program program) {
        return decompileFunctionWithRetry(func, program, 3);  // 3 retries for stability
    }

    /**
     * Decompile function with retry logic for stability (FIX #3).
     * Complex functions with SEH + alloca may fail initially but succeed on retry.
     * @param func Function to decompile
     * @param program Current program
     * @param maxRetries Maximum number of retry attempts
     * @return Decompilation results or null if all retries exhausted
     */
    public DecompileResults decompileFunctionWithRetry(Function func, Program program, int maxRetries) {
        DecompInterface decomp = null;

        for (int attempt = 1; attempt <= maxRetries; attempt++) {
            try {
                decomp = new DecompInterface();
                decomp.openProgram(program);
                decomp.setSimplificationStyle("decompile");

                // On retry attempts, flush cache first and increase timeout
                if (attempt > 1) {
                    Msg.info(this, "Decompilation attempt " + attempt + " for function " + func.getName());
                    decomp.flushCache();

                    // Increase timeout on retries for complex functions
                    int timeoutSecs = DECOMPILE_TIMEOUT_SECONDS * attempt;
                    DecompileResults results = decomp.decompileFunction(func, timeoutSecs, new ConsoleTaskMonitor());

                    if (results != null && results.decompileCompleted()) {
                        Msg.info(this, "Decompilation succeeded on attempt " + attempt);
                        return results;
                    }

                    String errorMsg = (results != null) ? results.getErrorMessage() : "Unknown error";
                    Msg.warn(this, "Decompilation attempt " + attempt + " failed: " + errorMsg);
                } else {
                    // First attempt - use normal timeout
                    DecompileResults results = decomp.decompileFunction(func, DECOMPILE_TIMEOUT_SECONDS, new ConsoleTaskMonitor());

                    if (results != null && results.decompileCompleted()) {
                        return results;
                    }

                    String errorMsg = (results != null) ? results.getErrorMessage() : "Unknown error";
                    Msg.warn(this, "Decompilation attempt " + attempt + " failed: " + errorMsg);
                }

            } catch (Exception e) {
                Msg.warn(this, "Decompilation attempt " + attempt + " threw exception: " + e.getMessage());
            } finally {
                if (decomp != null) {
                    decomp.dispose();
                    decomp = null;
                }
            }

            // Small delay between retries to allow Ghidra to stabilize
            if (attempt < maxRetries) {
                try {
                    Thread.sleep(100);  // 100ms delay
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                }
            }
        }

        Msg.error(this, "Could not decompile function after " + maxRetries + " attempts: " + func.getName());
        return null;
    }

    /**
     * Batch decompile multiple functions by name.
     */
    @McpTool(value = "/batch_decompile", description = "Decompile multiple functions at once for bulk analysis")

    public Response batchDecompileFunctions(

            @Param(value = "functions") String functionsParam) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) {
            return Response.err("No program loaded");
        }

        if (functionsParam == null || functionsParam.trim().isEmpty()) {
            return Response.err("Functions parameter is required");
        }

        try {
            String[] functionNames = functionsParam.split(",");
            StringBuilder result = new StringBuilder();
            result.append("{");

            FunctionManager funcManager = program.getFunctionManager();
            final int MAX_FUNCTIONS = 20; // Limit to prevent overload

            for (int i = 0; i < functionNames.length && i < MAX_FUNCTIONS; i++) {
                String funcName = functionNames[i].trim();
                if (funcName.isEmpty()) continue;

                if (i > 0) result.append(", ");
                result.append("\"").append(ServiceUtils.escapeJson(funcName)).append("\": ");

                // Find function by name
                Function function = null;
                SymbolTable symbolTable = program.getSymbolTable();
                SymbolIterator symbols = symbolTable.getSymbols(funcName);

                while (symbols.hasNext()) {
                    Symbol symbol = symbols.next();
                    if (symbol.getSymbolType() == SymbolType.FUNCTION) {
                        function = funcManager.getFunctionAt(symbol.getAddress());
                        break;
                    }
                }

                if (function == null) {
                    result.append("\"Error: Function not found\"");
                    continue;
                }

                // Decompile the function
                try {
                    DecompInterface decompiler = new DecompInterface();
                    decompiler.openProgram(program);
                    DecompileResults decompResults = decompiler.decompileFunction(function, 30, null);

                    if (decompResults != null && decompResults.decompileCompleted()) {
                        String decompCode = decompResults.getDecompiledFunction().getC();
                        result.append("\"").append(ServiceUtils.escapeJson(decompCode)).append("\"");
                    } else {
                        result.append("\"Error: Decompilation failed\"");
                    }

                    decompiler.dispose();
                } catch (Exception e) {
                    result.append("\"Error: ").append(ServiceUtils.escapeJson(e.getMessage())).append("\"");
                }
            }

            result.append("}");
            return Response.text(result.toString());
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    /**
     * Force a fresh decompilation of a function (flushing cached results).
     */
    // No @McpTool — GUI plugin registers this with GET/POST fallback
    public Response forceDecompile(String functionAddrStr) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) {
            return Response.err("No program loaded");
        }

        if (functionAddrStr == null || functionAddrStr.isEmpty()) {
            return Response.err("Function address is required");
        }

        final StringBuilder resultMsg = new StringBuilder();
        final AtomicBoolean success = new AtomicBoolean(false);

        try {
            threadingStrategy.executeRead(() -> {
                try {
                    Address addr = program.getAddressFactory().getAddress(functionAddrStr);
                    if (addr == null) {
                        resultMsg.append("Error: Invalid function address: ").append(functionAddrStr);
                        return null;
                    }

                    Function func = program.getFunctionManager().getFunctionAt(addr);
                    if (func == null) {
                        resultMsg.append("Error: No function found at address ").append(functionAddrStr);
                        return null;
                    }

                    // Create new decompiler interface
                    DecompInterface decompiler = new DecompInterface();
                    decompiler.openProgram(program);

                    try {
                        // Flush cached results to force fresh decompilation
                        decompiler.flushCache();
                        DecompileResults results = decompiler.decompileFunction(func, DECOMPILE_TIMEOUT_SECONDS, new ConsoleTaskMonitor());

                        if (results == null || !results.decompileCompleted()) {
                            String errorMsg = results != null ? results.getErrorMessage() : "Unknown error";
                            resultMsg.append("Error: Decompilation did not complete for function ").append(func.getName());
                            if (errorMsg != null && !errorMsg.isEmpty()) {
                                resultMsg.append(". Reason: ").append(errorMsg);
                            }
                            return null;
                        }

                        // Check if decompiled function is null (can happen even when decompileCompleted returns true)
                        if (results.getDecompiledFunction() == null) {
                            resultMsg.append("Error: Decompiler completed but returned null decompiled function for ").append(func.getName()).append(".\n");
                            resultMsg.append("This can happen with functions that have:\n");
                            resultMsg.append("- Invalid control flow or unreachable code\n");
                            resultMsg.append("- Large NOP sleds or padding\n");
                            resultMsg.append("- External calls to unknown addresses\n");
                            resultMsg.append("- Stack frame issues\n");
                            resultMsg.append("Consider using get_disassembly() instead for this function.");
                            return null;
                        }

                        // Get the decompiled C code
                        String decompiledCode = results.getDecompiledFunction().getC();

                        success.set(true);
                        resultMsg.append("Success: Forced redecompilation of ").append(func.getName()).append("\n\n");
                        resultMsg.append(decompiledCode);

                        Msg.info(this, "Forced decompilation for function: " + func.getName());

                    } finally {
                        decompiler.dispose();
                    }

                } catch (Throwable e) {
                    String msg = e.getMessage() != null ? e.getMessage() : e.toString();
                    resultMsg.append("Error: ").append(msg);
                    Msg.error(this, "Error forcing decompilation", e);
                }
                return null;
            });
        } catch (Throwable e) {
            String msg = e.getMessage() != null ? e.getMessage() : e.toString();
            resultMsg.append("Error: Failed to execute on Swing thread: ").append(msg);
            Msg.error(this, "Failed to execute force decompile on Swing thread", e);
        }

        String text = resultMsg.length() > 0 ? resultMsg.toString() : "Error: Unknown failure";
        if (text.startsWith("Error:")) {
            return Response.err(text.substring(7).trim());
        }
        return Response.text(text);
    }

    // ========================================================================
    // Disassembly
    // ========================================================================

    /**
     * Get assembly code for a function.
     * If programName is provided, uses that program instead of the current one.
     */
    @SuppressWarnings("deprecation")
    @McpTool(value = "/disassemble_function", description = "Get assembly code (address: instruction; comment) for a function")

    public Response disassembleFunction(

            @Param(value = "address") String addressStr,

            @Param(value = "program", required = false) String programName,

            @Param(value = "filter_mnemonics", required = false, description = "Comma-separated mnemonics to filter by (e.g. 'CALL,JMP')") String filterMnemonics) {
        Object[] result = getProgramOrError(programName);
        Program program = (Program) result[0];
        if (program == null) return (Response) result[1];
        if (addressStr == null || addressStr.isEmpty()) return Response.err("Address is required");

        // Parse mnemonic filter
        Set<String> mnemonicFilter = null;
        if (filterMnemonics != null && !filterMnemonics.isEmpty()) {
            mnemonicFilter = new HashSet<>();
            for (String m : filterMnemonics.split(",")) {
                mnemonicFilter.add(m.trim().toUpperCase());
            }
        }

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = ServiceUtils.getFunctionForAddress(program, addr);
            if (func == null) return Response.err("No function found at or containing address " + addressStr);

            StringBuilder sb = new StringBuilder();
            Listing listing = program.getListing();
            Address start = func.getEntryPoint();
            Address end = func.getBody().getMaxAddress();

            InstructionIterator instructions = listing.getInstructions(start, true);
            while (instructions.hasNext()) {
                Instruction instr = instructions.next();
                if (instr.getAddress().compareTo(end) > 0) break;

                // Apply mnemonic filter if specified
                if (mnemonicFilter != null && !mnemonicFilter.contains(instr.getMnemonicString().toUpperCase())) {
                    continue;
                }

                String comment = listing.getComment(CodeUnit.EOL_COMMENT, instr.getAddress());
                comment = (comment != null) ? "; " + comment : "";

                sb.append(String.format("%s: %s %s\n",
                    instr.getAddress(),
                    instr.toString(),
                    comment));
            }

            return Response.text(sb.toString());
        } catch (Exception e) {
            return Response.err("Error disassembling function: " + e.getMessage());
        }
    }

    // Backward compatible overload for internal callers
    public Response disassembleFunction(String addressStr) {
        return disassembleFunction(addressStr, null, null);
    }

    // ========================================================================
    // Function lookup
    // ========================================================================

    /**
     * Get function by address.
     */
    @McpTool(value = "/get_function_by_address", description = "Get a function by its address")

    public Response getFunctionByAddress(

            @Param(value = "address") String addressStr,

            @Param(value = "program", required = false) String programName) {
        Object[] programResult = getProgramOrError(programName);
        Program program = (Program) programResult[0];
        if (program == null) return (Response) programResult[1];
        if (addressStr == null || addressStr.isEmpty()) return Response.err("Address is required");

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            if (addr == null) return Response.err("Invalid address: " + addressStr);

            Function func = program.getFunctionManager().getFunctionAt(addr);
            if (func == null) {
                func = program.getFunctionManager().getFunctionContaining(addr);
            }

            if (func == null) return Response.err("No function found at or containing address " + addressStr);

            return Response.text(String.format("Function: %s at %s\nSignature: %s\nEntry: %s\nBody: %s - %s",
                func.getName(),
                func.getEntryPoint(),
                func.getSignature(),
                func.getEntryPoint(),
                func.getBody().getMinAddress(),
                func.getBody().getMaxAddress()));
        } catch (Exception e) {
            return Response.err("Error getting function: " + e.getMessage());
        }
    }

    // Backward compatibility overload
    public Response getFunctionByAddress(String addressStr) {
        return getFunctionByAddress(addressStr, null);
    }

    // ========================================================================
    // Rename methods
    // ========================================================================

    /**
     * Rename a function by its name.
     */
    @McpTool(value = "/rename_function", description = "Rename a function by its current name to a new user-defined name", method = McpTool.Method.POST)

    public Response renameFunction(

            @Param(value = "oldName") String oldName,

            @Param(value = "newName") String newName) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) {
            return Response.err("No program loaded");
        }

        if (oldName == null || oldName.isEmpty()) {
            return Response.err("Old function name is required");
        }

        if (newName == null || newName.isEmpty()) {
            return Response.err("New function name is required");
        }

        final StringBuilder resultMsg = new StringBuilder();
        final AtomicBoolean successFlag = new AtomicBoolean(false);

        try {
            threadingStrategy.executeWrite(program, "Rename function via HTTP", () -> {
                boolean found = false;
                for (Function func : program.getFunctionManager().getFunctions(true)) {
                    if (func.getName().equals(oldName)) {
                        found = true;
                        func.setName(newName, SourceType.USER_DEFINED);
                        successFlag.set(true);
                        resultMsg.append("Success: Renamed function '").append(oldName)
                                .append("' to '").append(newName).append("'");
                        break;
                    }
                }

                if (!found) {
                    resultMsg.append("Error: Function '").append(oldName).append("' not found");
                }
                return null;
            });

            // Force event processing to ensure changes propagate
            if (successFlag.get()) {
                program.flushEvents();
                try {
                    Thread.sleep(50);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
        } catch (Exception e) {
            resultMsg.append("Error: Failed to execute rename on Swing thread: ").append(e.getMessage());
            Msg.error(this, "Failed to execute rename on Swing thread", e);
        }

        String text = resultMsg.length() > 0 ? resultMsg.toString() : "Error: Unknown failure";
        if (text.startsWith("Error:")) {
            return Response.err(text.substring(7).trim());
        }
        return Response.text(text);
    }

    /**
     * Rename a variable in a function.
     */
    @McpTool(value = "/rename_variable", description = "Rename variable", method = McpTool.Method.POST)

    public Response renameVariableInFunction(

            @Param(value = "functionName") String functionName,

            @Param(value = "oldName") String oldVarName,

            @Param(value = "newName") String newVarName) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) return Response.err("No program loaded");

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);

        Function func = null;
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            if (f.getName().equals(functionName)) {
                func = f;
                break;
            }
        }

        if (func == null) {
            return Response.err("Function not found");
        }

        DecompileResults result = decomp.decompileFunction(func, DECOMPILE_TIMEOUT_SECONDS, new ConsoleTaskMonitor());
        if (result == null || !result.decompileCompleted()) {
            return Response.err("Decompilation failed");
        }

        HighFunction highFunction = result.getHighFunction();
        if (highFunction == null) {
            return Response.err("Decompilation failed (no high function)");
        }

        LocalSymbolMap localSymbolMap = highFunction.getLocalSymbolMap();
        if (localSymbolMap == null) {
            return Response.err("Decompilation failed (no local symbol map)");
        }

        HighSymbol highSymbol = null;
        Iterator<HighSymbol> symbols = localSymbolMap.getSymbols();
        while (symbols.hasNext()) {
            HighSymbol symbol = symbols.next();
            String symbolName = symbol.getName();

            if (symbolName.equals(oldVarName)) {
                highSymbol = symbol;
            }
            if (symbolName.equals(newVarName)) {
                return Response.err("A variable with name '" + newVarName + "' already exists in this function");
            }
        }

        if (highSymbol == null) {
            return Response.err("Variable not found");
        }

        boolean commitRequired = checkFullCommit(highSymbol, highFunction);

        final HighSymbol finalHighSymbol = highSymbol;
        final HighFunction finalHighFunction = highFunction;
        final Function finalFunction = func;
        AtomicBoolean successFlag = new AtomicBoolean(false);

        try {
            threadingStrategy.executeWrite(program, "Rename variable", () -> {
                if (commitRequired) {
                    HighFunctionDBUtil.commitParamsToDatabase(finalHighFunction, false,
                        ReturnCommitOption.NO_COMMIT, finalFunction.getSignatureSource());
                }
                HighFunctionDBUtil.updateDBVariable(
                    finalHighSymbol,
                    newVarName,
                    null,
                    SourceType.USER_DEFINED
                );
                successFlag.set(true);
                return null;
            });
        } catch (Exception e) {
            String errorMsg = "Failed to execute rename on Swing thread: " + e.getMessage();
            Msg.error(this, errorMsg, e);
            return Response.err(errorMsg);
        }
        return successFlag.get() ? Response.text("Variable renamed") : Response.err("Failed to rename variable");
    }

    /**
     * Copied from AbstractDecompilerAction.checkFullCommit, it's protected.
     * Compare the given HighFunction's idea of the prototype with the Function's idea.
     * Return true if there is a difference. If a specific symbol is being changed,
     * it can be passed in to check whether or not the prototype is being affected.
     * @param highSymbol (if not null) is the symbol being modified
     * @param hfunction is the given HighFunction
     * @return true if there is a difference (and a full commit is required)
     */
    public static boolean checkFullCommit(HighSymbol highSymbol, HighFunction hfunction) {
        if (highSymbol != null && !highSymbol.isParameter()) {
            return false;
        }
        Function function = hfunction.getFunction();
        Parameter[] parameters = function.getParameters();
        LocalSymbolMap localSymbolMap = hfunction.getLocalSymbolMap();
        int numParams = localSymbolMap.getNumParams();
        if (numParams != parameters.length) {
            return true;
        }

        for (int i = 0; i < numParams; i++) {
            HighSymbol param = localSymbolMap.getParamSymbol(i);
            if (param.getCategoryIndex() != i) {
                return true;
            }
            VariableStorage storage = param.getStorage();
            // Don't compare using the equals method so that DynamicVariableStorage can match
            if (0 != storage.compareTo(parameters[i].getVariableStorage())) {
                return true;
            }
        }

        return false;
    }

    /**
     * Rename a function by its address.
     */
    @McpTool(value = "/rename_function_by_address", description = "Rename a function by its address", method = McpTool.Method.POST)

    public Response renameFunctionByAddress(

            @Param(value = "function_address") String functionAddrStr,

            @Param(value = "new_name") String newName) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) {
            return Response.err("No program loaded");
        }

        if (functionAddrStr == null || functionAddrStr.isEmpty()) {
            return Response.err("Function address is required");
        }

        if (newName == null || newName.isEmpty()) {
            return Response.err("New function name is required");
        }

        final StringBuilder resultMsg = new StringBuilder();
        final AtomicBoolean success = new AtomicBoolean(false);

        try {
            threadingStrategy.executeWrite(program, "Rename function by address", () -> {
                Address addr = program.getAddressFactory().getAddress(functionAddrStr);
                if (addr == null) {
                    resultMsg.append("Error: Invalid address: ").append(functionAddrStr);
                    return null;
                }

                Function func = ServiceUtils.getFunctionForAddress(program, addr);
                if (func == null) {
                    resultMsg.append("Error: No function found at address ").append(functionAddrStr);
                    return null;
                }

                String oldName = func.getName();
                func.setName(newName, SourceType.USER_DEFINED);
                success.set(true);
                resultMsg.append("Success: Renamed function at ").append(functionAddrStr)
                        .append(" from '").append(oldName).append("' to '").append(newName).append("'");
                return null;
            });
        } catch (Exception e) {
            resultMsg.append("Error: Failed to execute rename on Swing thread: ").append(e.getMessage());
            Msg.error(this, "Failed to execute rename function on Swing thread", e);
        }

        String text = resultMsg.length() > 0 ? resultMsg.toString() : "Error: Unknown failure";
        if (text.startsWith("Error:")) {
            return Response.err(text.substring(7).trim());
        }
        return Response.text(text);
    }

    // ========================================================================
    // Prototype / Signature methods
    // ========================================================================

    /** MCP endpoint wrapper — converts PrototypeResult to Response. */
    @McpTool(value = "/set_function_prototype", description = "Set a function's prototype and optionally its calling convention", method = McpTool.Method.POST)
    public Response setFunctionPrototypeEndpoint(
            @Param(value = "function_address", description = "Function address in hex") String functionAddrStr,
            @Param(value = "prototype", description = "C-style function prototype") String prototype,
            @Param(value = "calling_convention", required = false, description = "Calling convention name") String callingConvention) {
        PrototypeResult result = setFunctionPrototype(functionAddrStr, prototype, callingConvention);
        if (result.isSuccess()) return Response.text("Success");
        return Response.err(result.getErrorMessage());
    }

    /**
     * Set a function's prototype with proper error handling using ApplyFunctionSignatureCmd.
     */
    public PrototypeResult setFunctionPrototype(String functionAddrStr, String prototype) {
        return setFunctionPrototype(functionAddrStr, prototype, null);
    }

    /**
     * Set a function's prototype with calling convention support.
     */
    public PrototypeResult setFunctionPrototype(String functionAddrStr, String prototype, String callingConvention) {
        // Input validation
        Program program = programProvider.getCurrentProgram();
        if (program == null) return new PrototypeResult(false, "No program loaded");
        if (functionAddrStr == null || functionAddrStr.isEmpty()) {
            return new PrototypeResult(false, "Function address is required");
        }
        if (prototype == null || prototype.isEmpty()) {
            return new PrototypeResult(false, "Function prototype is required");
        }

        // v3.0.1: Extract inline calling convention from prototype string if present
        // Handles cases like "void __cdecl MyFunc(int x)" -> prototype="void MyFunc(int x)", cc="__cdecl"
        String cleanPrototype = prototype;
        String resolvedConvention = callingConvention;
        String[] knownConventions = {"__cdecl", "__stdcall", "__thiscall", "__fastcall", "__vectorcall"};
        for (String cc : knownConventions) {
            if (cleanPrototype.contains(cc)) {
                cleanPrototype = cleanPrototype.replace(cc, "").replaceAll("\\s+", " ").trim();
                if (resolvedConvention == null || resolvedConvention.isEmpty()) {
                    resolvedConvention = cc;
                }
                Msg.info(this, "Extracted calling convention '" + cc + "' from prototype string");
                break;
            }
        }
        final String finalPrototype = cleanPrototype;
        final String finalConvention = resolvedConvention;

        final StringBuilder errorMessage = new StringBuilder();
        final AtomicBoolean success = new AtomicBoolean(false);

        try {
            threadingStrategy.executeRead(() -> {
                applyFunctionPrototype(program, functionAddrStr, finalPrototype, finalConvention, success, errorMessage);
                return null;
            });
        } catch (Exception e) {
            String msg = "Failed to set function prototype on Swing thread: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
        }

        return new PrototypeResult(success.get(), errorMessage.toString());
    }

    /**
     * Helper method that applies the function prototype within a transaction.
     * v3.0.1: Preserves existing plate comment across prototype changes.
     */
    void applyFunctionPrototype(Program program, String functionAddrStr, String prototype,
                                       String callingConvention, AtomicBoolean success, StringBuilder errorMessage) {
        try {
            // Get the address and function
            Address addr = program.getAddressFactory().getAddress(functionAddrStr);
            Function func = ServiceUtils.getFunctionForAddress(program, addr);

            if (func == null) {
                String msg = "Could not find function at address: " + functionAddrStr;
                errorMessage.append(msg);
                Msg.error(this, msg);
                return;
            }

            Msg.info(this, "Setting prototype for function " + func.getName() + ": " + prototype);

            // v3.0.1: Save existing plate comment before prototype change (which may wipe it)
            String savedPlateComment = func.getComment();

            // Use ApplyFunctionSignatureCmd to parse and apply the signature
            parseFunctionSignatureAndApply(program, addr, prototype, callingConvention, success, errorMessage);

            // v3.0.1: Restore plate comment if it was wiped by prototype change
            if (savedPlateComment != null && !savedPlateComment.isEmpty()) {
                String currentComment = func.getComment();
                if (currentComment == null || currentComment.isEmpty() ||
                    currentComment.startsWith("Setting prototype:")) {
                    int txRestore = program.startTransaction("Restore plate comment after prototype");
                    try {
                        func.setComment(savedPlateComment);
                        Msg.info(this, "Restored plate comment after prototype change for " + func.getName());
                    } finally {
                        program.endTransaction(txRestore, true);
                    }
                }
            }

        } catch (Exception e) {
            String msg = "Error setting function prototype: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
        }
    }

    /**
     * Parse and apply the function signature with error handling.
     */
    void parseFunctionSignatureAndApply(Program program, Address addr, String prototype,
                                              String callingConvention, AtomicBoolean success, StringBuilder errorMessage) {
        // Use ApplyFunctionSignatureCmd to parse and apply the signature
        int txProto = program.startTransaction("Set function prototype");
        boolean signatureApplied = false;
        try {
            // Get data type manager
            DataTypeManager dtm = program.getDataTypeManager();

            // Create function signature parser without DataTypeManagerService
            // to prevent UI dialogs from popping up (pass null instead of dtms)
            ghidra.app.util.parser.FunctionSignatureParser parser =
                new ghidra.app.util.parser.FunctionSignatureParser(dtm, null);

            // Parse the prototype into a function signature
            ghidra.program.model.data.FunctionDefinitionDataType sig = parser.parse(null, prototype);

            if (sig == null) {
                String msg = "Failed to parse function prototype";
                errorMessage.append(msg);
                Msg.error(this, msg);
                return;
            }

            // Create and apply the command
            ghidra.app.cmd.function.ApplyFunctionSignatureCmd cmd =
                new ghidra.app.cmd.function.ApplyFunctionSignatureCmd(
                    addr, sig, SourceType.USER_DEFINED);

            // Apply the command to the program
            boolean cmdResult = cmd.applyTo(program, new ConsoleTaskMonitor());

            if (cmdResult) {
                signatureApplied = true;
                Msg.info(this, "Successfully applied function signature");
            } else {
                String msg = "Command failed: " + cmd.getStatusMsg();
                errorMessage.append(msg);
                Msg.error(this, msg);
            }
        } catch (Exception e) {
            String msg = "Error applying function signature: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
        } finally {
            program.endTransaction(txProto, signatureApplied);
        }

        // Apply calling convention in a SEPARATE transaction after signature is committed
        // This ensures the calling convention isn't overridden by ApplyFunctionSignatureCmd
        if (signatureApplied && callingConvention != null && !callingConvention.isEmpty()) {
            int txConv = program.startTransaction("Set calling convention");
            boolean conventionApplied = false;
            try {
                conventionApplied = applyCallingConvention(program, addr, callingConvention, errorMessage);
                if (conventionApplied) {
                    success.set(true);
                } else {
                    success.set(false);  // Fail if calling convention couldn't be applied
                }
            } catch (Exception e) {
                String msg = "Error in calling convention transaction: " + e.getMessage();
                errorMessage.append(msg);
                Msg.error(this, msg, e);
                success.set(false);
            } finally {
                program.endTransaction(txConv, conventionApplied);
            }
        } else if (signatureApplied) {
            success.set(true);
        }
    }

    /**
     * Apply a calling convention to a function at the given address.
     */
    public boolean applyCallingConvention(Program program, Address addr, String callingConvention, StringBuilder errorMessage) {
        try {
            Function func = ServiceUtils.getFunctionForAddress(program, addr);
            if (func == null) {
                errorMessage.append("Could not find function to set calling convention");
                return false;
            }

            // Get the program's calling convention manager
            ghidra.program.model.lang.CompilerSpec compilerSpec = program.getCompilerSpec();
            ghidra.program.model.lang.PrototypeModel callingConv = null;

            // Get all available calling conventions
            ghidra.program.model.lang.PrototypeModel[] available = compilerSpec.getCallingConventions();

            // Try to find matching calling convention by name
            String targetName = callingConvention.toLowerCase();
            for (ghidra.program.model.lang.PrototypeModel model : available) {
                String modelName = model.getName().toLowerCase();
                if (modelName.equals(targetName) ||
                    modelName.equals("__" + targetName) ||
                    modelName.replace("__", "").equals(targetName.replace("__", ""))) {
                    callingConv = model;
                    break;
                }
            }

            if (callingConv != null) {
                func.setCallingConvention(callingConv.getName());
                Msg.info(this, "Set calling convention to: " + callingConv.getName());
                return true;  // Successfully applied
            } else {
                String msg = "Unknown calling convention: " + callingConvention + ". ";

                // List available calling conventions for debugging
                StringBuilder availList = new StringBuilder("Available calling conventions: ");
                for (ghidra.program.model.lang.PrototypeModel model : available) {
                    availList.append(model.getName()).append(", ");
                }
                String availMsg = availList.toString();
                msg += availMsg;

                errorMessage.append(msg);
                Msg.warn(this, msg);
                Msg.info(this, availMsg);

                return false;  // Convention not found
            }

        } catch (Exception e) {
            String msg = "Error setting calling convention: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
            return false;
        }
    }

    // ========================================================================
    // Variable type methods
    // ========================================================================

    /**
     * Set a local variable's type using HighFunctionDBUtil.updateDBVariable.
     */
    @McpTool(value = "/set_local_variable_type", description = "Set a local variable's type", method = McpTool.Method.POST)

    public Response setLocalVariableType(

            @Param(value = "function_address") String functionAddrStr,

            @Param(value = "variable_name") String variableName,

            @Param(value = "new_type") String newType) {
        // Input validation
        Program program = programProvider.getCurrentProgram();
        if (program == null) {
            return Response.err("No program loaded");
        }

        if (functionAddrStr == null || functionAddrStr.isEmpty()) {
            return Response.err("Function address is required");
        }

        if (variableName == null || variableName.isEmpty()) {
            return Response.err("Variable name is required");
        }

        if (newType == null || newType.isEmpty()) {
            return Response.err("New type is required");
        }

        final StringBuilder resultMsg = new StringBuilder();
        final AtomicBoolean success = new AtomicBoolean(false);

        try {
            threadingStrategy.executeRead(() -> {
                try {
                    // Find the function
                    Address addr = program.getAddressFactory().getAddress(functionAddrStr);
                    if (addr == null) {
                        resultMsg.append("Error: Invalid address: ").append(functionAddrStr);
                        return null;
                    }

                    Function func = ServiceUtils.getFunctionForAddress(program, addr);
                    if (func == null) {
                        resultMsg.append("Error: No function found at address ").append(functionAddrStr);
                        return null;
                    }

                    DecompileResults results = decompileFunction(func, program);
                    if (results == null || !results.decompileCompleted()) {
                        resultMsg.append("Error: Decompilation failed for function at ").append(functionAddrStr);
                        return null;
                    }

                    ghidra.program.model.pcode.HighFunction highFunction = results.getHighFunction();
                    if (highFunction == null) {
                        resultMsg.append("Error: No high function available");
                        return null;
                    }

                    // Find the symbol by name
                    HighSymbol symbol = findSymbolByName(highFunction, variableName);
                    if (symbol == null) {
                        // PRIORITY 2 FIX: Provide helpful diagnostic information
                        resultMsg.append("Error: Variable '").append(variableName)
                                .append("' not found in decompiled function. ");

                        // List available variables for user guidance
                        List<String> availableNames = new ArrayList<>();
                        Iterator<HighSymbol> symbols = highFunction.getLocalSymbolMap().getSymbols();
                        while (symbols.hasNext()) {
                            availableNames.add(symbols.next().getName());
                        }

                        if (!availableNames.isEmpty()) {
                            resultMsg.append("Available variables: ")
                                    .append(String.join(", ", availableNames))
                                    .append(". ");
                        }

                        // Check if variable exists in low-level API but not high-level (phantom variable)
                        Variable[] lowLevelVars = func.getLocalVariables();
                        boolean isPhantomVariable = false;
                        for (Variable v : lowLevelVars) {
                            if (v.getName().equals(variableName)) {
                                isPhantomVariable = true;
                                break;
                            }
                        }

                        if (isPhantomVariable) {
                            resultMsg.append("NOTE: Variable '").append(variableName)
                                    .append("' exists in stack frame but not in decompiled code. ")
                                    .append("This is a phantom variable created by Ghidra's stack analysis ")
                                    .append("that was optimized away during decompilation. ")
                                    .append("You cannot set the type of phantom variables. ")
                                    .append("Only variables visible in the decompiled code can be typed.");
                        }

                        return null;
                    }

                    // Get high variable -- may be null for EBP-pinned / SSA-only symbols.
                    // updateDBVariable works without a HighVariable (rename path proves this),
                    // so we skip the null guard and fall through to updateVariableType directly.
                    HighVariable highVar = symbol.getHighVariable();
                    String oldType = highVar != null
                        ? highVar.getDataType().getName()
                        : symbol.getDataType().getName();

                    // Find the data type
                    DataTypeManager dtm = program.getDataTypeManager();
                    DataType dataType = ServiceUtils.resolveDataType(dtm, newType);

                    if (dataType == null) {
                        resultMsg.append("Error: Could not resolve data type: ").append(newType);
                        return null;
                    }

                    // Apply the type change in a transaction
                    StringBuilder errorDetails = new StringBuilder();
                    if (updateVariableType(program, symbol, dataType, success, errorDetails)) {
                        resultMsg.append("Success: Changed type of variable '").append(variableName)
                                .append("' from '").append(oldType).append("' to '")
                                .append(dataType.getName()).append("'")
                                .append(". WARNING: Type changes trigger re-decompilation which may create new SSA variables. ")
                                .append("Call get_function_variables after all type changes to discover any new variables.");
                    } else {
                        // Provide detailed error message including storage location
                        String storageInfo = "unknown";
                        try {
                            storageInfo = symbol.getStorage().toString();
                        } catch (Exception e) {
                            // If we can't get storage, continue without it
                        }

                        resultMsg.append("Error: Failed to update variable type for '").append(variableName).append("'");
                        resultMsg.append(" (Storage: ").append(storageInfo).append(")");

                        if (errorDetails.length() > 0) {
                            resultMsg.append(". Details: ").append(errorDetails.toString());
                        }

                        // Add helpful guidance for known limitations
                        if (storageInfo.startsWith("Stack[-") && storageInfo.contains(":4")) {
                            resultMsg.append(". Note: Stack-based local variables with 4-byte size may have type-setting limitations in Ghidra's API");
                        }
                    }

                } catch (Exception e) {
                    resultMsg.append("Error: ").append(e.getMessage());
                    Msg.error(this, "Error setting variable type", e);
                }
                return null;
            });
        } catch (Exception e) {
            resultMsg.append("Error: Failed to execute on Swing thread: ").append(e.getMessage());
            Msg.error(this, "Failed to execute set variable type on Swing thread", e);
        }

        String text = resultMsg.length() > 0 ? resultMsg.toString() : "Error: Unknown failure";
        if (text.startsWith("Error:")) {
            return Response.err(text.substring(7).trim());
        }
        return Response.text(text);
    }

    /**
     * Find a high symbol by name in the given high function.
     */
    HighSymbol findSymbolByName(ghidra.program.model.pcode.HighFunction highFunction, String variableName) {
        Iterator<HighSymbol> symbols = highFunction.getLocalSymbolMap().getSymbols();
        while (symbols.hasNext()) {
            HighSymbol s = symbols.next();
            if (s.getName().equals(variableName)) {
                return s;
            }
        }
        return null;
    }

    /**
     * Apply the type update in a transaction.
     */
    boolean updateVariableType(Program program, HighSymbol symbol, DataType dataType,
                                       AtomicBoolean success, StringBuilder errorDetails) {
        int tx = program.startTransaction("Set variable type");
        boolean result = false;
        String storageInfo = "unknown";

        try {
            // Get storage information for detailed logging
            try {
                storageInfo = symbol.getStorage().toString();
            } catch (Exception e) {
                // If we can't get storage, continue without it
            }

            // Log variable storage information for debugging
            Msg.info(this, "Attempting to set type for variable: " + symbol.getName() +
                          ", storage: " + storageInfo + ", new type: " + dataType.getName());

            // Use HighFunctionDBUtil to update the variable with the new type
            HighFunctionDBUtil.updateDBVariable(
                symbol,                // The high symbol to modify
                symbol.getName(),      // Keep original name
                dataType,              // The new data type
                SourceType.USER_DEFINED // Mark as user-defined
            );

            success.set(true);
            result = true;
            Msg.info(this, "Successfully set variable type using HighFunctionDBUtil");

        } catch (ghidra.util.exception.DuplicateNameException e) {
            String msg = "Variable name conflict: " + e.getMessage();
            Msg.error(this, msg, e);
            if (errorDetails != null) {
                errorDetails.append(msg).append(" (Storage: ").append(storageInfo).append(")");
            }
        } catch (ghidra.util.exception.InvalidInputException e) {
            String msg;

            // FIX: Detect register-based storage and provide helpful error message
            if (storageInfo.contains("ESP:") || storageInfo.contains("EDI:") ||
                storageInfo.contains("EAX:") || storageInfo.contains("EBX:") ||
                storageInfo.contains("ECX:") || storageInfo.contains("EDX:") ||
                storageInfo.contains("ESI:") || storageInfo.contains("EBP:")) {

                msg = "Cannot set type for register-based variable '" + symbol.getName() +
                      "' at storage location: " + storageInfo + ". " +
                      "Register variables (ESP/EDI/EAX/etc) are decompiler temporaries and cannot have types set via API. " +
                      "Workaround: Manually retype this variable in Ghidra's decompiler UI (right-click -> Retype Variable). " +
                      "Ghidra limitation: " + e.getMessage();
            } else {
                msg = "Invalid input for variable type update: " + e.getMessage() +
                      " (Storage: " + storageInfo + ")";
            }

            Msg.error(this, msg, e);
            if (errorDetails != null) {
                errorDetails.append(msg);
            }
        } catch (IllegalArgumentException e) {
            String msg = "Illegal argument: " + e.getMessage();
            Msg.error(this, msg, e);
            if (errorDetails != null) {
                errorDetails.append(msg).append(" (Storage: ").append(storageInfo).append(")");
            }
        } catch (Exception e) {
            // Generic catch-all for unexpected exceptions
            String msg = "Unexpected error setting variable type: " + e.getClass().getName() + ": " + e.getMessage();
            Msg.error(this, msg, e);
            e.printStackTrace();  // Full stack trace for debugging
            if (errorDetails != null) {
                errorDetails.append(msg).append(" (Storage: ").append(storageInfo).append(")");
            }
        } finally {
            program.endTransaction(tx, success.get());
        }
        return result;
    }

    // ========================================================================
    // Function attribute methods
    // ========================================================================

    /**
     * Set a function's "No Return" attribute.
     *
     * This method controls whether Ghidra treats a function as non-returning (like exit(), abort(), etc.).
     * When a function is marked as non-returning:
     * - Call sites are treated as terminators (CALL_TERMINATOR)
     * - Decompiler doesn't show code execution continuing after the call
     * - Control flow analysis treats the call like a RET instruction
     *
     * @param functionAddrStr The function address in hex format (e.g., "0x401000")
     * @param noReturn true to mark as non-returning, false to mark as returning
     * @return Success or error Response
     */
    @McpTool(value = "/set_function_no_return", description = "Set a function's \"No Return\" attribute to control flow analysis", method = McpTool.Method.POST)

    public Response setFunctionNoReturn(

            @Param(value = "function_address") String functionAddrStr,

            @Param(value = "no_return", type = "boolean", defaultValue = "true") boolean noReturn) {
        // Input validation
        Program program = programProvider.getCurrentProgram();
        if (program == null) {
            return Response.err("No program loaded");
        }

        if (functionAddrStr == null || functionAddrStr.isEmpty()) {
            return Response.err("Function address is required");
        }

        final StringBuilder resultMsg = new StringBuilder();
        final AtomicBoolean success = new AtomicBoolean(false);

        try {
            threadingStrategy.executeWrite(program, "Set function no return", () -> {
                Address addr = program.getAddressFactory().getAddress(functionAddrStr);
                if (addr == null) {
                    resultMsg.append("Error: Invalid address: ").append(functionAddrStr);
                    return null;
                }

                Function func = ServiceUtils.getFunctionForAddress(program, addr);
                if (func == null) {
                    resultMsg.append("Error: No function found at address ").append(functionAddrStr);
                    return null;
                }

                String oldState = func.hasNoReturn() ? "non-returning" : "returning";

                // Set the no-return attribute
                func.setNoReturn(noReturn);

                String newState = noReturn ? "non-returning" : "returning";
                success.set(true);

                resultMsg.append("Success: Set function '").append(func.getName())
                        .append("' at ").append(functionAddrStr)
                        .append(" from ").append(oldState)
                        .append(" to ").append(newState);

                Msg.info(this, "Set no-return=" + noReturn + " for function " + func.getName() + " at " + functionAddrStr);
                return null;
            });
        } catch (Exception e) {
            resultMsg.append("Error: Failed to execute on Swing thread: ").append(e.getMessage());
            Msg.error(this, "Failed to execute set no-return on Swing thread", e);
        }

        String text = resultMsg.length() > 0 ? resultMsg.toString() : "Error: Unknown failure";
        if (text.startsWith("Error:")) {
            return Response.err(text.substring(7).trim());
        }
        return Response.text(text);
    }

    /**
     * Clear instruction-level flow override at a specific address.
     *
     * This method clears flow overrides that are set on individual instructions (like CALL_TERMINATOR).
     * Flow overrides can be set at:
     * 1. Function level (via setNoReturn) - affects all call sites globally
     * 2. Instruction level (per call site) - takes precedence over function-level settings
     *
     * Use this method to:
     * - Clear CALL_TERMINATOR overrides on specific CALL instructions
     * - Remove incorrect flow analysis overrides
     * - Allow execution to continue after a call that was marked as non-returning
     *
     * After clearing the override, Ghidra will re-analyze the instruction using default flow rules.
     *
     * @param instructionAddrStr The instruction address in hex format (e.g., "0x6fb5c8b9")
     * @return Success or error Response
     */
    @McpTool(value = "/clear_instruction_flow_override", description = "Clear a flow override on an instruction at the given address", method = McpTool.Method.POST)

    public Response clearInstructionFlowOverride(

            @Param(value = "address") String instructionAddrStr) {
        // Input validation
        Program program = programProvider.getCurrentProgram();
        if (program == null) {
            return Response.err("No program loaded");
        }

        if (instructionAddrStr == null || instructionAddrStr.isEmpty()) {
            return Response.err("Instruction address is required");
        }

        final StringBuilder resultMsg = new StringBuilder();
        final AtomicBoolean success = new AtomicBoolean(false);

        try {
            threadingStrategy.executeWrite(program, "Clear instruction flow override", () -> {
                Address addr = program.getAddressFactory().getAddress(instructionAddrStr);
                if (addr == null) {
                    resultMsg.append("Error: Invalid address: ").append(instructionAddrStr);
                    return null;
                }

                // Get the instruction at the address
                Listing listing = program.getListing();
                ghidra.program.model.listing.Instruction instruction = listing.getInstructionAt(addr);

                if (instruction == null) {
                    resultMsg.append("Error: No instruction found at address ").append(instructionAddrStr);
                    return null;
                }

                // Get the current flow override type (if any)
                ghidra.program.model.listing.FlowOverride oldOverride = instruction.getFlowOverride();

                // Clear the flow override by setting to NONE
                instruction.setFlowOverride(ghidra.program.model.listing.FlowOverride.NONE);

                success.set(true);
                resultMsg.append("Success: Cleared flow override at ").append(instructionAddrStr);
                resultMsg.append(" (was: ").append(oldOverride.toString()).append(", now: NONE)");

                // Get the instruction's mnemonic for logging
                String mnemonic = instruction.getMnemonicString();
                Msg.info(this, "Cleared flow override for instruction '" + mnemonic + "' at " + instructionAddrStr +
                         " (previous override: " + oldOverride + ")");
                return null;
            });
        } catch (Exception e) {
            resultMsg.append("Error: Failed to execute on Swing thread: ").append(e.getMessage());
            Msg.error(this, "Failed to execute clear flow override on Swing thread", e);
        }

        String text = resultMsg.length() > 0 ? resultMsg.toString() : "Error: Unknown failure";
        if (text.startsWith("Error:")) {
            return Response.err(text.substring(7).trim());
        }
        return Response.text(text);
    }

    /**
     * Set custom storage for a local variable or parameter (v1.7.0).
     *
     * This allows overriding Ghidra's automatic variable storage detection.
     * Useful for cases where registers are reused or compiler optimizations confuse the decompiler.
     *
     * @param functionAddrStr Function address containing the variable
     * @param variableName Name of the variable to modify
     * @param storageSpec Storage specification (e.g., "Stack[-0x10]:4", "EBP:4", "EAX:4")
     * @return Success or error Response
     */
    @McpTool(value = "/set_variable_storage", description = "Set custom storage for a local variable or parameter (v1.7.0)", method = McpTool.Method.POST)

    public Response setVariableStorage(

            @Param(value = "function_address") String functionAddrStr,

            @Param(value = "variable_name") String variableName,

            @Param(value = "storage") String storageSpec) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) {
            return Response.err("No program loaded");
        }

        if (functionAddrStr == null || functionAddrStr.isEmpty()) {
            return Response.err("Function address is required");
        }
        if (variableName == null || variableName.isEmpty()) {
            return Response.err("Variable name is required");
        }
        if (storageSpec == null || storageSpec.isEmpty()) {
            return Response.err("Storage specification is required");
        }

        final StringBuilder resultMsg = new StringBuilder();
        final AtomicBoolean success = new AtomicBoolean(false);

        try {
            threadingStrategy.executeWrite(program, "Set variable storage", () -> {
                Address addr = program.getAddressFactory().getAddress(functionAddrStr);
                if (addr == null) {
                    resultMsg.append("Error: Invalid function address: ").append(functionAddrStr);
                    return null;
                }

                Function func = program.getFunctionManager().getFunctionAt(addr);
                if (func == null) {
                    resultMsg.append("Error: No function found at address ").append(functionAddrStr);
                    return null;
                }

                // Find the variable
                Variable targetVar = null;
                for (Variable var : func.getAllVariables()) {
                    if (var.getName().equals(variableName)) {
                        targetVar = var;
                        break;
                    }
                }

                if (targetVar == null) {
                    resultMsg.append("Error: Variable '").append(variableName).append("' not found in function ").append(func.getName());
                    return null;
                }

                String oldStorage = targetVar.getVariableStorage().toString();

                // Ghidra's variable storage API has limited programmatic access
                // The proper way to change variable storage is through the decompiler UI
                resultMsg.append("Note: Programmatic variable storage control is limited in Ghidra.\n\n");
                resultMsg.append("Current variable information:\n");
                resultMsg.append("  Variable: ").append(variableName).append("\n");
                resultMsg.append("  Function: ").append(func.getName()).append(" @ ").append(functionAddrStr).append("\n");
                resultMsg.append("  Current storage: ").append(oldStorage).append("\n");
                resultMsg.append("  Requested storage: ").append(storageSpec).append("\n\n");
                resultMsg.append("To change variable storage:\n");
                resultMsg.append("1. Open the function in Ghidra's Decompiler window\n");
                resultMsg.append("2. Right-click on the variable '").append(variableName).append("'\n");
                resultMsg.append("3. Select 'Edit Data Type' or 'Retype Variable'\n");
                resultMsg.append("4. Manually adjust the storage location\n\n");
                resultMsg.append("Alternative approach:\n");
                resultMsg.append("- Use run_script() to execute a custom Ghidra script\n");
                resultMsg.append("- The script can use high-level Pcode/HighVariable API\n");
                resultMsg.append("- See FixEBPRegisterReuse.java for an example\n");

                success.set(true);
                Msg.info(this, "Variable storage query for: " + variableName + " in " + func.getName() +
                         " (current: " + oldStorage + ", requested: " + storageSpec + ")");
                return null;
            });
        } catch (Exception e) {
            resultMsg.append("Error: Failed to execute on Swing thread: ").append(e.getMessage());
            Msg.error(this, "Failed to execute set variable storage on Swing thread", e);
        }

        String text = resultMsg.length() > 0 ? resultMsg.toString() : "Error: Unknown failure";
        if (text.startsWith("Error:")) {
            return Response.err(text.substring(7).trim());
        }
        return Response.text(text);
    }

    // ========================================================================
    // Function variables query
    // ========================================================================

    /**
     * Get detailed information about a function's variables (parameters and locals).
     */
    // No @McpTool — GUI plugin registers this with function_address→name resolution
    public Response getFunctionVariables(String functionName, String programName) {
        Object[] programResult = getProgramOrError(programName);
        Program program = (Program) programResult[0];
        if (program == null) {
            return (Response) programResult[1];
        }

        if (functionName == null || functionName.isEmpty()) {
            return Response.err("Function name is required");
        }

        final Program finalProgram = program;
        final StringBuilder result = new StringBuilder();
        final AtomicReference<String> errorMsg = new AtomicReference<>(null);

        try {
            threadingStrategy.executeRead(() -> {
                try {
                    // Find function by name
                    Function func = null;
                    for (Function f : finalProgram.getFunctionManager().getFunctions(true)) {
                        if (f.getName().equals(functionName)) {
                            func = f;
                            break;
                        }
                    }

                    if (func == null) {
                        errorMsg.set("Function not found: " + functionName);
                        return null;
                    }

                    // FIX: Force decompiler cache refresh to get current variable states after type changes
                    // This ensures get_function_variables returns fresh data matching actual decompilation
                    try {
                        DecompInterface tempDecomp = new DecompInterface();
                        tempDecomp.openProgram(finalProgram);
                        tempDecomp.flushCache();
                        tempDecomp.decompileFunction(func, DECOMPILE_TIMEOUT_SECONDS, new ConsoleTaskMonitor());
                        tempDecomp.dispose();
                    } catch (Exception e) {
                        Msg.warn(this, "Failed to refresh decompiler cache for getFunctionVariables: " + e.getMessage());
                        // Continue anyway - better to return potentially stale data than fail completely
                    }

                    result.append("{");
                    result.append("\"function_name\": \"").append(func.getName()).append("\", ");
                    result.append("\"function_address\": \"").append(func.getEntryPoint().toString()).append("\", ");

                    // Get parameters
                    result.append("\"parameters\": [");
                    Parameter[] params = func.getParameters();
                    for (int i = 0; i < params.length; i++) {
                        if (i > 0) result.append(", ");
                        Parameter param = params[i];
                        result.append("{");
                        result.append("\"name\": \"").append(param.getName()).append("\", ");
                        result.append("\"type\": \"").append(param.getDataType().getName()).append("\", ");
                        result.append("\"ordinal\": ").append(param.getOrdinal()).append(", ");
                        result.append("\"storage\": \"").append(param.getVariableStorage().toString()).append("\"");
                        result.append("}");
                    }
                    result.append("], ");

                    // Get local variables and detect phantom variables
                    result.append("\"locals\": [");
                    Variable[] locals = func.getLocalVariables();

                    // Decompile to get HighFunction for phantom detection
                    DecompileResults decompResults = decompileFunction(func, finalProgram);
                    java.util.Set<String> decompVarNames = new java.util.HashSet<>();
                    if (decompResults != null && decompResults.decompileCompleted()) {
                        ghidra.program.model.pcode.HighFunction highFunc = decompResults.getHighFunction();
                        if (highFunc != null) {
                            java.util.Iterator<ghidra.program.model.pcode.HighSymbol> symbols =
                                highFunc.getLocalSymbolMap().getSymbols();
                            while (symbols.hasNext()) {
                                decompVarNames.add(symbols.next().getName());
                            }
                        }
                    }

                    for (int i = 0; i < locals.length; i++) {
                        if (i > 0) result.append(", ");
                        Variable local = locals[i];
                        boolean isPhantom = !decompVarNames.contains(local.getName());

                        result.append("{");
                        result.append("\"name\": \"").append(local.getName()).append("\", ");
                        result.append("\"type\": \"").append(local.getDataType().getName()).append("\", ");
                        result.append("\"storage\": \"").append(local.getVariableStorage().toString()).append("\", ");
                        result.append("\"is_phantom\": ").append(isPhantom).append(", ");
                        result.append("\"in_decompiled_code\": ").append(!isPhantom);
                        result.append("}");
                    }
                    result.append("]");
                    result.append("}");
                } catch (Exception e) {
                    errorMsg.set(e.getMessage());
                    Msg.error(this, "Error getting function variables", e);
                }
                return null;
            });

            if (errorMsg.get() != null) {
                return Response.err(errorMsg.get());
            }
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }

        return Response.text(result.toString());
    }

    // Backward compatibility overload
    @SuppressWarnings("deprecation")
    public Response getFunctionVariables(String functionName) {
        return getFunctionVariables(functionName, null);
    }

    // ========================================================================
    // Batch operations
    // ========================================================================

    /**
     * v1.5.0: Batch rename function and all its components atomically.
     */
    @SuppressWarnings("deprecation")
    @McpTool(value = "/batch_rename_function_components", description = "Rename function and all its components atomically (v1.5.0)", method = McpTool.Method.POST)

    public Response batchRenameFunctionComponents(

            @Param(value = "function_address") String functionAddress,

            @Param(value = "function_name") String functionName,

            @Param(value = "parameter_renames", type = "object") Map<String, String> parameterRenames,

            @Param(value = "local_renames", type = "object") Map<String, String> localRenames,

            @Param(value = "returnType") String returnType) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) {
            return Response.err("No program loaded");
        }

        final StringBuilder result = new StringBuilder();
        result.append("{");
        final AtomicBoolean success = new AtomicBoolean(false);
        final AtomicReference<Integer> paramsRenamed = new AtomicReference<>(0);
        final AtomicReference<Integer> localsRenamed = new AtomicReference<>(0);

        try {
            threadingStrategy.executeWrite(program, "Batch Rename Function Components", () -> {
                Address addr = program.getAddressFactory().getAddress(functionAddress);
                if (addr == null) {
                    result.append("\"error\": \"Invalid address: ").append(functionAddress).append("\"");
                    return null;
                }

                Function func = program.getFunctionManager().getFunctionAt(addr);
                if (func == null) {
                    result.append("\"error\": \"No function at address: ").append(functionAddress).append("\"");
                    return null;
                }

                // Rename function
                if (functionName != null && !functionName.isEmpty()) {
                    func.setName(functionName, SourceType.USER_DEFINED);
                }

                // Rename parameters
                if (parameterRenames != null && !parameterRenames.isEmpty()) {
                    Parameter[] params = func.getParameters();
                    for (Parameter param : params) {
                        String newName = parameterRenames.get(param.getName());
                        if (newName != null && !newName.isEmpty()) {
                            param.setName(newName, SourceType.USER_DEFINED);
                            paramsRenamed.getAndSet(paramsRenamed.get() + 1);
                        }
                    }
                }

                // Rename local variables
                if (localRenames != null && !localRenames.isEmpty()) {
                    Variable[] locals = func.getLocalVariables();
                    for (Variable local : locals) {
                        String newName = localRenames.get(local.getName());
                        if (newName != null && !newName.isEmpty()) {
                            local.setName(newName, SourceType.USER_DEFINED);
                            localsRenamed.getAndSet(localsRenamed.get() + 1);
                        }
                    }
                }

                // Set return type if provided
                if (returnType != null && !returnType.isEmpty()) {
                    DataTypeManager dtm = program.getDataTypeManager();
                    DataType dt = dtm.getDataType(returnType);
                    if (dt != null) {
                        func.setReturnType(dt, SourceType.USER_DEFINED);
                    }
                }

                success.set(true);
                return null;
            });

            if (success.get()) {
                result.append("\"success\": true, ");
                result.append("\"function_renamed\": ").append(functionName != null).append(", ");
                result.append("\"parameters_renamed\": ").append(paramsRenamed.get()).append(", ");
                result.append("\"locals_renamed\": ").append(localsRenamed.get());
            }
        } catch (Exception e) {
            result.append("\"error\": \"").append(e.getMessage().replace("\"", "\\\"")).append("\"");
        }

        result.append("}");
        return Response.text(result.toString());
    }

    // ========================================================================
    // Function creation / deletion
    // ========================================================================

    /**
     * Delete a function at the given address.
     */
    @McpTool(value = "/delete_function", description = "Delete a function at the specified address", method = McpTool.Method.POST)

    public Response deleteFunctionAtAddress(

            @Param(value = "address") String addressStr) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) {
            return Response.err("No program loaded");
        }
        if (addressStr == null || addressStr.isEmpty()) {
            return Response.err("address parameter required");
        }

        final StringBuilder result = new StringBuilder();
        final AtomicReference<String> errorMsg = new AtomicReference<>();

        try {
            threadingStrategy.executeWrite(program, "Delete function at address", () -> {
                Address addr = program.getAddressFactory().getAddress(addressStr);
                if (addr == null) {
                    errorMsg.set("Invalid address: " + addressStr);
                    return null;
                }

                Function func = program.getFunctionManager().getFunctionAt(addr);
                if (func == null) {
                    errorMsg.set("No function found at address " + addressStr);
                    return null;
                }

                String funcName = func.getName();
                long bodySize = func.getBody().getNumAddresses();
                program.getFunctionManager().removeFunction(addr);

                result.append("{");
                result.append("\"success\": true, ");
                result.append("\"address\": \"").append(addr).append("\", ");
                result.append("\"deleted_function\": \"").append(funcName.replace("\"", "\\\"")).append("\", ");
                result.append("\"body_size\": ").append(bodySize).append(", ");
                result.append("\"message\": \"Function '").append(funcName.replace("\"", "\\\""))
                      .append("' deleted at ").append(addr).append("\"");
                result.append("}");
                return null;
            });

            if (errorMsg.get() != null) {
                return Response.err(errorMsg.get());
            }
        } catch (Throwable e) {
            String msg = e.getMessage() != null ? e.getMessage() : e.toString();
            return Response.err("Failed to execute on Swing thread: " + msg);
        }

        return result.length() > 0 ? Response.text(result.toString()) : Response.err("Unknown failure");
    }

    /**
     * Create a function at the given address.
     */
    @McpTool(value = "/create_function", description = "Create a function at the specified address (v1.9.4)", method = McpTool.Method.POST)

    public Response createFunctionAtAddress(

            @Param(value = "address") String addressStr,

            @Param(value = "name") String name,

            @Param(value = "disassembleFirst", type = "boolean") boolean disassembleFirst) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) {
            return Response.err("No program loaded");
        }

        if (addressStr == null || addressStr.isEmpty()) {
            return Response.err("address parameter required");
        }

        final StringBuilder result = new StringBuilder();
        final AtomicReference<String> errorMsg = new AtomicReference<>();

        try {
            threadingStrategy.executeWrite(program, "Create function at address", () -> {
                Address addr = program.getAddressFactory().getAddress(addressStr);
                if (addr == null) {
                    errorMsg.set("Invalid address: " + addressStr);
                    return null;
                }

                // Check if a function already exists at this address
                Function existing = program.getFunctionManager().getFunctionAt(addr);
                if (existing != null) {
                    errorMsg.set("Function already exists at " + addressStr + ": " + existing.getName());
                    return null;
                }

                // Optionally disassemble first
                if (disassembleFirst) {
                    if (program.getListing().getInstructionAt(addr) == null) {
                        AddressSet addrSet = new AddressSet(addr, addr);
                        ghidra.app.cmd.disassemble.DisassembleCommand disCmd =
                            new ghidra.app.cmd.disassemble.DisassembleCommand(addrSet, null, true);
                        if (!disCmd.applyTo(program, ghidra.util.task.TaskMonitor.DUMMY)) {
                            errorMsg.set("Failed to disassemble at " + addressStr + ": " + disCmd.getStatusMsg());
                            return null;
                        }
                    }
                }

                // Create the function using CreateFunctionCmd
                ghidra.app.cmd.function.CreateFunctionCmd cmd =
                    new ghidra.app.cmd.function.CreateFunctionCmd(addr);
                if (!cmd.applyTo(program, ghidra.util.task.TaskMonitor.DUMMY)) {
                    errorMsg.set("Failed to create function at " + addressStr + ": " + cmd.getStatusMsg());
                    return null;
                }

                Function func = program.getFunctionManager().getFunctionAt(addr);
                if (func == null) {
                    errorMsg.set("Function creation reported success but function not found at " + addressStr);
                    return null;
                }

                // Optionally rename the function
                if (name != null && !name.isEmpty()) {
                    func.setName(name, SourceType.USER_DEFINED);
                }

                String funcName = func.getName();
                result.append("{");
                result.append("\"success\": true, ");
                result.append("\"address\": \"").append(addr).append("\", ");
                result.append("\"function_name\": \"").append(funcName.replace("\"", "\\\"")).append("\", ");
                result.append("\"entry_point\": \"").append(func.getEntryPoint()).append("\", ");
                result.append("\"body_size\": ").append(func.getBody().getNumAddresses()).append(", ");
                result.append("\"message\": \"Function created successfully at ").append(addr).append("\"");
                result.append("}");
                return null;
            });

            if (errorMsg.get() != null) {
                return Response.err(errorMsg.get());
            }
        } catch (Throwable e) {
            String msg = e.getMessage() != null ? e.getMessage() : e.toString();
            return Response.err("Failed to execute on Swing thread: " + msg);
        }

        return result.length() > 0 ? Response.text(result.toString()) : Response.err("Unknown failure");
    }

    // ========================================================================
    // Disassembly
    // ========================================================================

    /**
     * Disassemble a range of bytes at a specific address range.
     * Useful for disassembling hidden code after clearing flow overrides.
     *
     * @param startAddress Starting address in hex format (e.g., "0x6fb4ca14")
     * @param endAddress Optional ending address in hex format (exclusive)
     * @param length Optional length in bytes (alternative to endAddress)
     * @param restrictToExecuteMemory If true, restricts disassembly to executable memory (default: true)
     * @return JSON result with disassembly status
     */
    @McpTool(value = "/disassemble_bytes", description = "Disassemble a range of undefined bytes at a specific address (v1.7.1)", method = McpTool.Method.POST)

    public Response disassembleBytes(

            @Param(value = "start_address") String startAddress,

            @Param(value = "end_address") String endAddress,

            @Param(value = "length", type = "integer") Integer length,

            @Param(value = "restrictToExecuteMemory", type = "boolean") boolean restrictToExecuteMemory) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) {
            return Response.err("No program loaded");
        }

        if (startAddress == null || startAddress.isEmpty()) {
            return Response.err("start_address parameter required");
        }

        final StringBuilder result = new StringBuilder();
        final AtomicReference<String> errorMsg = new AtomicReference<>();

        try {
            Msg.debug(this, "disassembleBytes: Starting disassembly at " + startAddress +
                     (length != null ? " with length " + length : "") +
                     (endAddress != null ? " to " + endAddress : ""));

            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Disassemble Bytes");
                boolean success = false;

                try {
                    // Parse start address
                    Address start = program.getAddressFactory().getAddress(startAddress);
                    if (start == null) {
                        errorMsg.set("Invalid start address: " + startAddress);
                        return;
                    }

                    // Determine end address
                    Address end;
                    if (endAddress != null && !endAddress.isEmpty()) {
                        // Use explicit end address (exclusive)
                        end = program.getAddressFactory().getAddress(endAddress);
                        if (end == null) {
                            errorMsg.set("Invalid end address: " + endAddress);
                            return;
                        }
                        // Make end address inclusive for AddressSet
                        try {
                            end = end.subtract(1);
                        } catch (Exception e) {
                            errorMsg.set("End address calculation failed: " + e.getMessage());
                            return;
                        }
                    } else if (length != null && length > 0) {
                        // Use length to calculate end address
                        try {
                            end = start.add(length - 1);
                        } catch (Exception e) {
                            errorMsg.set("End address calculation from length failed: " + e.getMessage());
                            return;
                        }
                    } else {
                        // Auto-detect length (scan until we hit existing code/data)
                        Listing listing = program.getListing();
                        Address current = start;
                        int maxBytes = 100; // Safety limit
                        int count = 0;

                        while (count < maxBytes) {
                            CodeUnit cu = listing.getCodeUnitAt(current);

                            // Stop if we hit an existing instruction
                            if (cu instanceof Instruction) {
                                break;
                            }

                            // Stop if we hit defined data
                            if (cu instanceof Data && ((Data) cu).isDefined()) {
                                break;
                            }

                            count++;
                            try {
                                current = current.add(1);
                            } catch (Exception e) {
                                break;
                            }
                        }

                        if (count == 0) {
                            errorMsg.set("No undefined bytes found at address (already disassembled or defined data)");
                            return;
                        }

                        // end is now one past the last undefined byte
                        try {
                            end = current.subtract(1);
                        } catch (Exception e) {
                            end = current;
                        }
                    }

                    // Create address set
                    AddressSet addressSet = new AddressSet(start, end);
                    long numBytes = addressSet.getNumAddresses();

                    // Execute disassembly
                    DisassembleCommand cmd =
                        new DisassembleCommand(addressSet, null, restrictToExecuteMemory);

                    // Prevent auto-analysis cascade
                    cmd.setSeedContext(null);
                    cmd.setInitialContext(null);

                    if (cmd.applyTo(program, ghidra.util.task.TaskMonitor.DUMMY)) {
                        // Success - build result
                        Msg.debug(this, "disassembleBytes: Successfully disassembled " + numBytes + " byte(s) from " + start + " to " + end);
                        result.append("{");
                        result.append("\"success\": true, ");
                        result.append("\"start_address\": \"").append(start).append("\", ");
                        result.append("\"end_address\": \"").append(end).append("\", ");
                        result.append("\"bytes_disassembled\": ").append(numBytes).append(", ");
                        result.append("\"message\": \"Successfully disassembled ").append(numBytes).append(" byte(s)\"");
                        result.append("}");
                        success = true;
                    } else {
                        errorMsg.set("Disassembly failed: " + cmd.getStatusMsg());
                        Msg.error(this, "disassembleBytes: Disassembly command failed - " + cmd.getStatusMsg());
                    }

                } catch (Throwable e) {
                    String msg = e.getMessage() != null ? e.getMessage() : e.toString();
                    errorMsg.set("Exception during disassembly: " + msg);
                    Msg.error(this, "disassembleBytes: Exception during disassembly", e);
                } finally {
                    program.endTransaction(tx, success);
                }
            });

            Msg.debug(this, "disassembleBytes: invokeAndWait completed");

            if (errorMsg.get() != null) {
                Msg.error(this, "disassembleBytes: Returning error response - " + errorMsg.get());
                return Response.err(errorMsg.get());
            }
        } catch (Throwable e) {
            String msg = e.getMessage() != null ? e.getMessage() : e.toString();
            Msg.error(this, "disassembleBytes: Exception in outer try block", e);
            return Response.err(msg);
        }

        String response = result.toString();
        Msg.debug(this, "disassembleBytes: Returning success response, length=" + response.length());
        return Response.text(response);
    }

    // ========================================================================
    // Batch Variable Rename
    // ========================================================================

    /**
     * Batch rename variables with partial success reporting and fallback.
     * Falls back to individual operations if batch operations fail due to decompilation issues.
     *
     * @param functionAddress The address of the function containing the variables
     * @param variableRenames Map of old variable names to new names
     * @param forceIndividual If true, skip batch mode and use individual renames
     * @return JSON result with rename status
     */
    @McpTool(value = "/batch_rename_variables", description = "Batch rename variables", method = McpTool.Method.POST)

    public Response batchRenameVariables(

            @Param(value = "function_address") String functionAddress,

            @Param(value = "force_individual", type = "object", defaultValue = "false") Map<String, String> variableRenames,

            @Param(value = "variable_renames", type = "boolean") boolean forceIndividual) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) {
            return Response.err("No program loaded");
        }

        final StringBuilder result = new StringBuilder();
        result.append("{");
        final AtomicBoolean success = new AtomicBoolean(false);
        final AtomicInteger variablesRenamed = new AtomicInteger(0);
        final AtomicInteger variablesFailed = new AtomicInteger(0);
        final List<String> errors = new ArrayList<>();
        final AtomicReference<Function> funcRef = new AtomicReference<>(null);

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Batch Rename Variables");
                // Suppress events during batch operation to prevent re-analysis on each rename
                int eventTx = program.startTransaction("Suppress Events");
                program.flushEvents();

                try {
                    Address addr = program.getAddressFactory().getAddress(functionAddress);
                    if (addr == null) {
                        result.append("\"error\": \"Invalid address: ").append(functionAddress).append("\"");
                        return;
                    }

                    Function func = program.getFunctionManager().getFunctionAt(addr);
                    funcRef.set(func);
                    if (func == null) {
                        result.append("\"error\": \"No function at address: ").append(functionAddress).append("\"");
                        return;
                    }

                    if (variableRenames != null && !variableRenames.isEmpty()) {
                        // Use decompiler to access SSA variables (the ones that appear in decompiled code)
                        DecompInterface decomp = new DecompInterface();
                        decomp.openProgram(program);

                        DecompileResults decompResult = decomp.decompileFunction(func, DECOMPILE_TIMEOUT_SECONDS, new ConsoleTaskMonitor());
                        if (decompResult != null && decompResult.decompileCompleted()) {
                            HighFunction highFunction = decompResult.getHighFunction();
                            if (highFunction != null) {
                                LocalSymbolMap localSymbolMap = highFunction.getLocalSymbolMap();
                                if (localSymbolMap != null) {
                                    // Check for name conflicts first
                                    Set<String> existingNames = new HashSet<>();
                                    Iterator<HighSymbol> checkSymbols = localSymbolMap.getSymbols();
                                    while (checkSymbols.hasNext()) {
                                        existingNames.add(checkSymbols.next().getName());
                                    }

                                    // Validate no conflicts
                                    for (Map.Entry<String, String> entry : variableRenames.entrySet()) {
                                        String newName = entry.getValue();
                                        if (!entry.getKey().equals(newName) && existingNames.contains(newName)) {
                                            variablesFailed.incrementAndGet();
                                            errors.add("Variable name '" + newName + "' already exists in function");
                                        }
                                    }

                                    // Commit parameters if needed
                                    boolean commitRequired = false;
                                    Iterator<HighSymbol> symbols = localSymbolMap.getSymbols();
                                    if (symbols.hasNext()) {
                                        HighSymbol firstSymbol = symbols.next();
                                        commitRequired = checkFullCommit(firstSymbol, highFunction);
                                    }

                                    if (commitRequired) {
                                        HighFunctionDBUtil.commitParamsToDatabase(highFunction, false,
                                            ReturnCommitOption.NO_COMMIT, func.getSignatureSource());
                                    }

                                    // PATH 1: Rename SSA variables from LocalSymbolMap (decompiler variables)
                                    Set<String> renamedVars = new HashSet<>();
                                    Iterator<HighSymbol> renameSymbols = localSymbolMap.getSymbols();
                                    while (renameSymbols.hasNext()) {
                                        HighSymbol symbol = renameSymbols.next();
                                        String oldName = symbol.getName();
                                        String newName = variableRenames.get(oldName);

                                        if (newName != null && !newName.isEmpty() && !oldName.equals(newName)) {
                                            try {
                                                HighFunctionDBUtil.updateDBVariable(
                                                    symbol,
                                                    newName,
                                                    null,
                                                    SourceType.USER_DEFINED
                                                );
                                                variablesRenamed.incrementAndGet();
                                                renamedVars.add(oldName);
                                            } catch (Exception e) {
                                                variablesFailed.incrementAndGet();
                                                errors.add("Failed to rename SSA variable " + oldName + " to " + newName + ": " + e.getMessage());
                                            }
                                        }
                                    }

                                    // PATH 2: Rename storage-based variables from Function.getAllVariables()
                                    try {
                                        Variable[] allVars = func.getAllVariables();
                                        for (Variable var : allVars) {
                                            String oldName = var.getName();
                                            String newName = variableRenames.get(oldName);

                                            if (newName != null && !newName.isEmpty() && !oldName.equals(newName) && !renamedVars.contains(oldName)) {
                                                try {
                                                    var.setName(newName, SourceType.USER_DEFINED);
                                                    variablesRenamed.incrementAndGet();
                                                    renamedVars.add(oldName);
                                                } catch (Exception e) {
                                                    variablesFailed.incrementAndGet();
                                                    errors.add("Failed to rename storage variable " + oldName + " to " + newName + ": " + e.getMessage());
                                                }
                                            }
                                        }
                                    } catch (Exception e) {
                                        Msg.warn(this, "Storage variable rename encountered error: " + e.getMessage());
                                    }
                                } else {
                                    errors.add("Failed to get LocalSymbolMap from decompiler");
                                }
                            } else {
                                errors.add("Failed to get HighFunction from decompiler");
                            }
                        } else {
                            errors.add("Decompilation failed or did not complete");
                        }

                        decomp.dispose();
                    }

                    success.set(true);
                } catch (Exception e) {
                    // If batch operation fails, try individual operations as fallback
                    Msg.warn(this, "Batch rename variables failed, attempting individual operations: " + e.getMessage());
                    try {
                        program.endTransaction(eventTx, false);
                        program.endTransaction(tx, false);

                        // Try individual operations
                        Response individualResult = batchRenameVariablesIndividual(functionAddress, variableRenames);
                        result.append("\"fallback_used\": true, ");
                        if (individualResult instanceof Response.Text t) {
                            result.append(t.content());
                        } else if (individualResult instanceof Response.Err err) {
                            result.append("\"error\": \"").append(err.message().replace("\"", "\\\"")).append("\"");
                        }
                        return;
                    } catch (Exception fallbackE) {
                        result.append("\"error\": \"Batch operation failed and fallback also failed: ").append(e.getMessage()).append("\"");
                        Msg.error(this, "Both batch and individual rename operations failed", e);
                    }
                } finally {
                    if (!result.toString().contains("\"fallback_used\"")) {
                        // End event suppression transaction
                        program.endTransaction(eventTx, success.get());
                        program.flushEvents();
                        program.endTransaction(tx, success.get());

                        // Invalidate decompiler cache after successful renames
                        if (success.get() && variablesRenamed.get() > 0 && funcRef.get() != null) {
                            try {
                                DecompInterface tempDecomp = new DecompInterface();
                                tempDecomp.openProgram(program);
                                tempDecomp.flushCache();
                                tempDecomp.decompileFunction(funcRef.get(), DECOMPILE_TIMEOUT_SECONDS, new ConsoleTaskMonitor());
                                tempDecomp.dispose();
                                Msg.info(this, "Invalidated decompiler cache after renaming " + variablesRenamed.get() + " variables");
                            } catch (Exception cacheEx) {
                                Msg.warn(this, "Failed to invalidate decompiler cache: " + cacheEx.getMessage());
                            }
                        }
                    }
                }
            });

            if (success.get() && !result.toString().contains("\"fallback_used\"")) {
                result.append("\"success\": true, ");
                result.append("\"method\": \"batch\", ");
                result.append("\"variables_renamed\": ").append(variablesRenamed.get()).append(", ");
                result.append("\"variables_failed\": ").append(variablesFailed.get());
                if (!errors.isEmpty()) {
                    result.append(", \"errors\": [");
                    for (int i = 0; i < errors.size(); i++) {
                        if (i > 0) result.append(", ");
                        result.append("\"").append(errors.get(i).replace("\"", "\\\"")).append("\"");
                    }
                    result.append("]");
                }
            }
        } catch (Exception e) {
            result.append("\"error\": \"").append(e.getMessage().replace("\"", "\\\"")).append("\"");
        }

        result.append("}");
        return Response.text(result.toString());
    }

    /**
     * Individual variable renaming using HighFunctionDBUtil (fallback method).
     * This method uses decompilation but is more reliable for persistence.
     */
    public Response batchRenameVariablesIndividual(String functionAddress, Map<String, String> variableRenames) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) {
            return Response.err("No program loaded");
        }

        final StringBuilder result = new StringBuilder();
        final AtomicInteger variablesRenamed = new AtomicInteger(0);
        final AtomicInteger variablesFailed = new AtomicInteger(0);
        final List<String> errors = new ArrayList<>();

        // Get function name for individual operations
        final String[] functionName = new String[1];
        try {
            SwingUtilities.invokeAndWait(() -> {
                Address addr = program.getAddressFactory().getAddress(functionAddress);
                if (addr != null) {
                    Function func = program.getFunctionManager().getFunctionAt(addr);
                    if (func != null) {
                        functionName[0] = func.getName();
                    }
                }
            });
        } catch (Exception e) {
            return Response.err("Failed to get function name: " + e.getMessage());
        }

        if (functionName[0] == null) {
            return Response.err("Could not find function at address: " + functionAddress);
        }

        // Process each variable individually using the reliable method
        for (Map.Entry<String, String> entry : variableRenames.entrySet()) {
            String oldName = entry.getKey();
            String newName = entry.getValue();

            try {
                Response renameResult = renameVariableInFunction(functionName[0], oldName, newName);
                if (renameResult instanceof Response.Text t && t.content().equals("Variable renamed")) {
                    variablesRenamed.incrementAndGet();
                } else {
                    variablesFailed.incrementAndGet();
                    String msg = renameResult instanceof Response.Err err ? err.message()
                               : renameResult instanceof Response.Text t2 ? t2.content()
                               : "Unknown error";
                    errors.add("Failed to rename '" + oldName + "' to '" + newName + "': " + msg);
                }
            } catch (Exception e) {
                variablesFailed.incrementAndGet();
                errors.add("Exception renaming '" + oldName + "' to '" + newName + "': " + e.getMessage());
            }
        }

        result.append("\"success\": true, ");
        result.append("\"method\": \"individual\", ");
        result.append("\"variables_renamed\": ").append(variablesRenamed.get()).append(", ");
        result.append("\"variables_failed\": ").append(variablesFailed.get());
        if (!errors.isEmpty()) {
            result.append(", \"errors\": [");
            for (int i = 0; i < errors.size(); i++) {
                if (i > 0) result.append(", ");
                result.append("\"").append(errors.get(i).replace("\"", "\\\"")).append("\"");
            }
            result.append("]");
        }

        return Response.text(result.toString());
    }

    /**
     * Validate that batch operations actually persisted by checking current state.
     */
    public Response validateBatchOperationResults(String functionAddress, Map<String, String> expectedRenames, Map<String, String> expectedTypes) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) {
            return Response.err("No program loaded");
        }

        final StringBuilder result = new StringBuilder();
        result.append("{");

        try {
            SwingUtilities.invokeAndWait(() -> {
                try {
                    Address addr = program.getAddressFactory().getAddress(functionAddress);
                    if (addr == null) {
                        result.append("\"error\": \"Invalid address: ").append(functionAddress).append("\"");
                        return;
                    }

                    Function func = program.getFunctionManager().getFunctionAt(addr);
                    if (func == null) {
                        result.append("\"error\": \"No function at address: ").append(functionAddress).append("\"");
                        return;
                    }

                    int renamesValidated = 0;
                    int typesValidated = 0;
                    List<String> validationErrors = new ArrayList<>();

                    // Validate renames
                    if (expectedRenames != null) {
                        for (Parameter param : func.getParameters()) {
                            String expectedName = expectedRenames.get(param.getName());
                            if (expectedName != null) {
                                validationErrors.add("Parameter rename not persisted: expected '" + expectedName + "', found '" + param.getName() + "'");
                            } else if (expectedRenames.containsValue(param.getName())) {
                                renamesValidated++;
                            }
                        }

                        for (Variable local : func.getLocalVariables()) {
                            String expectedName = expectedRenames.get(local.getName());
                            if (expectedName != null) {
                                validationErrors.add("Local variable rename not persisted: expected '" + expectedName + "', found '" + local.getName() + "'");
                            } else if (expectedRenames.containsValue(local.getName())) {
                                renamesValidated++;
                            }
                        }
                    }

                    // Validate types
                    if (expectedTypes != null) {
                        DataTypeManager dtm = program.getDataTypeManager();

                        for (Parameter param : func.getParameters()) {
                            String expectedType = expectedTypes.get(param.getName());
                            if (expectedType != null) {
                                DataType currentType = param.getDataType();
                                DataType expectedDataType = dtm.getDataType(expectedType);
                                if (expectedDataType != null && currentType != null &&
                                    currentType.getName().equals(expectedDataType.getName())) {
                                    typesValidated++;
                                } else {
                                    validationErrors.add("Parameter type not persisted for '" + param.getName() +
                                                       "': expected '" + expectedType + "', found '" +
                                                       (currentType != null ? currentType.getName() : "null") + "'");
                                }
                            }
                        }

                        for (Variable local : func.getLocalVariables()) {
                            String expectedType = expectedTypes.get(local.getName());
                            if (expectedType != null) {
                                DataType currentType = local.getDataType();
                                DataType expectedDataType = dtm.getDataType(expectedType);
                                if (expectedDataType != null && currentType != null &&
                                    currentType.getName().equals(expectedDataType.getName())) {
                                    typesValidated++;
                                } else {
                                    validationErrors.add("Local variable type not persisted for '" + local.getName() +
                                                       "': expected '" + expectedType + "', found '" +
                                                       (currentType != null ? currentType.getName() : "null") + "'");
                                }
                            }
                        }
                    }

                    result.append("\"success\": true, ");
                    result.append("\"renames_validated\": ").append(renamesValidated).append(", ");
                    result.append("\"types_validated\": ").append(typesValidated);
                    if (!validationErrors.isEmpty()) {
                        result.append(", \"validation_errors\": [");
                        for (int i = 0; i < validationErrors.size(); i++) {
                            if (i > 0) result.append(", ");
                            result.append("\"").append(validationErrors.get(i).replace("\"", "\\\"")).append("\"");
                        }
                        result.append("]");
                    }

                } catch (Exception e) {
                    result.append("\"error\": \"").append(e.getMessage().replace("\"", "\\\"")).append("\"");
                    Msg.error(this, "Error validating batch operations", e);
                }
            });
        } catch (Exception e) {
            result.append("\"error\": \"").append(e.getMessage().replace("\"", "\\\"")).append("\"");
        }

        result.append("}");
        return Response.text(result.toString());
    }
}
