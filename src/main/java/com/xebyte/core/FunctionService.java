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
@McpToolGroup(value = "function", description = "Decompile, rename, prototype, variables, batch rename, create/delete functions")
public class FunctionService {

    private static final int DECOMPILE_TIMEOUT_SECONDS = 60;  // Increased from 30s to 60s for large functions

    // Shorter cap for the no-retry scoring/analysis path. Keeps EDT-holding
    // decompiles under Ghidra's 20-second Swing deadlock threshold so internal
    // task-manager jobs (GTreeRestoreTreeStateTask, TableUpdateJob) can run
    // between calls. Chosen so that handlers with up to 4 sequential no-retry
    // decompiles (e.g. /analyze_for_documentation -> nested
    // /analyze_function_completeness -> validateParameterTypeQuality fallback)
    // still finish under the 60s client-side HTTP timeout:
    //   4 * 12s = 48s < 60s client timeout. 12s also stays under the 20s
    //   Swing deadlock threshold per decompile. Pathological functions that
    //   need >12s are treated as "too complex to score" — an acceptable
    //   trade since they also pin the HTTP thread pool under any longer cap.
    private static final int NO_RETRY_DECOMPILE_TIMEOUT_SECONDS = 12;

    private final ProgramProvider programProvider;
    private final ThreadingStrategy threadingStrategy;

    public FunctionService(ProgramProvider programProvider, ThreadingStrategy threadingStrategy) {
        this.programProvider = programProvider;
        this.threadingStrategy = threadingStrategy;
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

    // ========================================================================
    // Decompilation methods
    // ========================================================================

    /**
     * Decompile a function by its name.
     */
    public Response decompileFunctionByName(String name, String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();
        DecompInterface decomp = null;
        try {
            decomp = new DecompInterface();
            decomp.openProgram(program);
            for (Function func : program.getFunctionManager().getFunctions(true)) {
                if (func.getName().equals(name)) {
                    DecompileResults result =
                        decomp.decompileFunction(func, DECOMPILE_TIMEOUT_SECONDS, new ConsoleTaskMonitor());
                    if (result != null && result.decompileCompleted()) {
                        return Response.text(result.getDecompiledFunction().getC());
                    } else {
                        return Response.text("Decompilation failed");
                    }
                }
            }
        } finally {
            if (decomp != null) {
                try { decomp.dispose(); } catch (Exception ignored) {}
            }
        }
        return Response.text("Function not found");
    }

    public Response decompileFunctionByName(String name) {
        return decompileFunctionByName(name, null);
    }

    /**
     * Decompile a function at the given address.
     * If programName is provided, uses that program instead of the current one.
     */
    @McpTool(path = "/decompile_function", description = "Decompile function at address to pseudocode. On programs with multiple address spaces (e.g., embedded targets), prefix addresses with the space name (mem:1000) to avoid ambiguous resolution.", category = "function")
    public Response decompileFunctionByAddress(
            @Param(value = "address", paramType = "address",
                   description = "Address in the program. Accepts 0x<hex> (default space) or <space>:<hex> "
                               + "(e.g., mem:1000, code:ff00). Note: some programs — particularly "
                               + "embedded/microcontroller targets — are not address-space-agnostic; "
                               + "use get_address_spaces to discover spaces before assuming a plain hex "
                               + "address is unambiguous.") String addressStr,
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName,
            @Param(value = "timeout", defaultValue = "60", description = "Decompile timeout in seconds") int timeoutSeconds) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();
        if (addressStr == null || addressStr.isEmpty()) return Response.err("Address or function name is required");

        DecompInterface decomp = null;
        try {
            Function func = ServiceUtils.resolveFunction(program, addressStr);
            if (func == null) return Response.err("No function found for " + addressStr);

            decomp = new DecompInterface();
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
        } finally {
            if (decomp != null) {
                try { decomp.dispose(); } catch (Exception ignored) {}
            }
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
     * Single-attempt decompile with no retry escalation. For scoring/analysis
     * code paths where a clean miss is fine and we cannot afford the 60→120→180s
     * escalation of the retry wrapper (which leaked DecompInterface contexts
     * when abandoned by upstream timeouts). Worst case:
     * {@link #NO_RETRY_DECOMPILE_TIMEOUT_SECONDS} per call, sized so that
     * handlers with up to 4 sequential calls still finish under the 60s client
     * timeout. No retry.
     */
    public DecompileResults decompileFunctionNoRetry(Function func, Program program) {
        DecompInterface decomp = null;
        try {
            decomp = new DecompInterface();
            decomp.openProgram(program);
            decomp.setSimplificationStyle("decompile");
            return decomp.decompileFunction(func, NO_RETRY_DECOMPILE_TIMEOUT_SECONDS, new ConsoleTaskMonitor());
        } catch (Exception e) {
            Msg.warn(this, "Single-attempt decompile failed for " + func.getName() + ": " + e.getMessage());
            return null;
        } finally {
            if (decomp != null) {
                try { decomp.dispose(); } catch (Exception ignored) {}
            }
        }
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
        @McpTool(path = "/batch_decompile", description = "Decompile multiple functions at once. Accepts comma-separated function names or addresses.", category = "function")
    public Response batchDecompileFunctions(
            @Param(value = "functions", description = "Comma-separated function references (names or addresses)") String functionsParam,
            @Param(value = "program", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        if (functionsParam == null || functionsParam.trim().isEmpty()) {
            return Response.err("Functions parameter is required");
        }

        try {
            String[] functionRefs = functionsParam.split(",");
            Map<String, Object> resultMap = new LinkedHashMap<>();
            final int MAX_FUNCTIONS = 20; // Limit to prevent overload

            for (int i = 0; i < functionRefs.length && i < MAX_FUNCTIONS; i++) {
                String funcRef = functionRefs[i].trim();
                if (funcRef.isEmpty()) continue;

                Function function = ServiceUtils.resolveFunction(program, funcRef);

                if (function == null) {
                    resultMap.put(funcRef, "Error: Function not found");
                    continue;
                }

                // Decompile the function
                DecompInterface decompiler = null;
                try {
                    decompiler = new DecompInterface();
                    decompiler.openProgram(program);
                    DecompileResults decompResults = decompiler.decompileFunction(function, 30, null);

                    if (decompResults != null && decompResults.decompileCompleted()) {
                        String decompCode = decompResults.getDecompiledFunction().getC();
                        resultMap.put(funcRef, decompCode);
                    } else {
                        resultMap.put(funcRef, "Error: Decompilation failed");
                    }
                } catch (Exception e) {
                    resultMap.put(funcRef, "Error: " + e.getMessage());
                } finally {
                    if (decompiler != null) {
                        try { decompiler.dispose(); } catch (Exception ignored) {}
                    }
                }
            }

            return Response.ok(resultMap);
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    public Response batchDecompileFunctions(String functionsParam) {
        return batchDecompileFunctions(functionsParam, null);
    }

    /**
     * Force a fresh decompilation of a function (flushing cached results).
     */
    @McpTool(path = "/force_decompile", description = "Force decompiler cache refresh for function. On programs with multiple address spaces (e.g., embedded targets), prefix addresses with the space name (mem:1000) to avoid ambiguous resolution.", category = "function")
    public Response forceDecompile(
            @Param(value = "address", paramType = "address",
                   description = "Address in the program. Accepts 0x<hex> (default space) or <space>:<hex> "
                               + "(e.g., mem:1000, code:ff00). Note: some programs — particularly "
                               + "embedded/microcontroller targets — are not address-space-agnostic; "
                               + "use get_address_spaces to discover spaces before assuming a plain hex "
                               + "address is unambiguous.") String functionAddrStr,
            @Param(value = "program", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        if (functionAddrStr == null || functionAddrStr.isEmpty()) {
            return Response.err("Function address is required");
        }

        final StringBuilder resultMsg = new StringBuilder();
        final AtomicBoolean success = new AtomicBoolean(false);

        // Resolve address before entering threading lambda
        Address addr = ServiceUtils.parseAddress(program, functionAddrStr);
        if (addr == null) return Response.err(ServiceUtils.getLastParseError());

        try {
            threadingStrategy.executeRead(() -> {
                try {
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

    public Response forceDecompile(String functionAddrStr) {
        return forceDecompile(functionAddrStr, null);
    }

    // ========================================================================
    // Disassembly
    // ========================================================================

    /**
     * Get assembly code for a function.
     * If programName is provided, uses that program instead of the current one.
     */
    @McpTool(path = "/disassemble_function", description = "Get assembly listing of function. On programs with multiple address spaces (e.g., embedded targets), prefix addresses with the space name (mem:1000) to avoid ambiguous resolution.", category = "function")
    public Response disassembleFunction(
            @Param(value = "address", paramType = "address",
                   description = "Address in the program. Accepts 0x<hex> (default space) or <space>:<hex> "
                               + "(e.g., mem:1000, code:ff00). Note: some programs — particularly "
                               + "embedded/microcontroller targets — are not address-space-agnostic; "
                               + "use get_address_spaces to discover spaces before assuming a plain hex "
                               + "address is unambiguous.") String addressStr,
            @Param(value = "program", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();
        if (addressStr == null || addressStr.isEmpty()) return Response.err("Address is required");

        try {
            Address addr = ServiceUtils.parseAddress(program, addressStr);
            if (addr == null) return Response.err(ServiceUtils.getLastParseError());
            Function func = ServiceUtils.getFunctionForAddress(program, addr);
            if (func == null) return Response.err("No function found at or containing address " + addressStr);

            StringBuilder sb = new StringBuilder();
            Listing listing = program.getListing();
            Address start = func.getEntryPoint();
            Address end = func.getBody().getMaxAddress();

            InstructionIterator instructions = listing.getInstructions(start, true);
            while (instructions.hasNext()) {
                Instruction instr = instructions.next();
                if (instr.getAddress().compareTo(end) > 0) {
                    break; // Stop if we've gone past the end of the function
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
        return disassembleFunction(addressStr, null);
    }

    // ========================================================================
    // Function lookup
    // ========================================================================

    /**
     * Get function by address.
     */
    @McpTool(path = "/get_function_by_address", description = "Get function info at a specific address. On programs with multiple address spaces (e.g., embedded targets), prefix addresses with the space name (mem:1000) to avoid ambiguous resolution.", category = "function")
    public Response getFunctionByAddress(
            @Param(value = "address", paramType = "address",
                   description = "Address in the program. Accepts 0x<hex> (default space) or <space>:<hex> "
                               + "(e.g., mem:1000, code:ff00). Note: some programs — particularly "
                               + "embedded/microcontroller targets — are not address-space-agnostic; "
                               + "use get_address_spaces to discover spaces before assuming a plain hex "
                               + "address is unambiguous.") String addressStr,
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();
        if (addressStr == null || addressStr.isEmpty()) return Response.text("Address or function name is required");

        try {
            Function func = ServiceUtils.resolveFunction(program, addressStr);
            if (func == null) return Response.text("No function found for " + addressStr);

            return Response.text(String.format("Function: %s at %s\nSignature: %s\nEntry: %s\nBody: %s - %s",
                func.getName(),
                func.getEntryPoint(),
                func.getSignature(),
                func.getEntryPoint(),
                func.getBody().getMinAddress(),
                func.getBody().getMaxAddress()));
        } catch (Exception e) {
            return Response.text("Error getting function: " + e.getMessage());
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
    @McpTool(path = "/rename_function", method = "POST", description = "Rename function by old and new name", category = "function")
    public Response renameFunction(
            @Param(value = "oldName", source = ParamSource.BODY) String oldName,
            @Param(value = "newName", source = ParamSource.BODY) String newName,
            @Param(value = "program", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

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
        if (successFlag.get()) {
            List<String> nameWarnings = NamingConventions.validateFunctionName(newName, false);
            if (nameWarnings.isEmpty()) {
                return Response.ok(JsonHelper.mapOf("status", "success", "message", text));
            } else {
                return Response.ok(JsonHelper.mapOf("status", "success", "message", text, "warnings", nameWarnings));
            }
        }
        return Response.err(text.startsWith("Error: ") ? text.substring(7) : text);
    }

    public Response renameFunction(String oldName, String newName) {
        return renameFunction(oldName, newName, null);
    }

    /**
     * Rename a variable in a function.
     */
    @McpTool(path = "/rename_variable", method = "POST", description = "Rename a variable in a function. Accepts functionName or function_address; address is more stable after recent renames.", category = "function")
    public Response renameVariableInFunction(
            @Param(value = "functionName", source = ParamSource.BODY, defaultValue = "") String functionName,
            @Param(value = "function_address", paramType = "address", source = ParamSource.BODY, defaultValue = "") String functionAddress,
            @Param(value = "oldName", source = ParamSource.BODY) String oldVarName,
            @Param(value = "newName", source = ParamSource.BODY) String newVarName,
            @Param(value = "program", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        if ((functionName == null || functionName.isEmpty()) && (functionAddress == null || functionAddress.isEmpty())) {
            return Response.err("Function name or address is required");
        }

        DecompInterface decomp = new DecompInterface();
        try {
            decomp.openProgram(program);

            String functionRef = (functionAddress != null && !functionAddress.isEmpty()) ? functionAddress : functionName;
            Function func = ServiceUtils.resolveFunction(program, functionRef);
            if (func == null) {
                return Response.err("Function not found: " + functionRef);
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
                return Response.err("Variable not found: " + oldVarName);
            }

            boolean commitRequired = checkFullCommit(highSymbol, highFunction);

            final HighSymbol finalHighSymbol = highSymbol;
            final HighFunction finalHighFunction = highFunction;
            final Function finalFunction = func;
            AtomicBoolean successFlag = new AtomicBoolean(false);

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

            if (successFlag.get()) {
                String varType = finalHighSymbol.getDataType().getName();
                String hungarianWarning = NamingConventions.validateHungarianPrefix(newVarName, varType);
                if (hungarianWarning != null) {
                    return Response.ok(JsonHelper.mapOf("status", "success", "message", "Variable renamed", "warnings", List.of(hungarianWarning)));
                }
                return Response.text("Variable renamed");
            }
        } catch (Exception e) {
            String errorMsg = "Failed to execute rename on Swing thread: " + e.getMessage();
            Msg.error(this, errorMsg, e);
            return Response.err(errorMsg);
        } finally {
            decomp.dispose();
        }
        return Response.text("Failed to rename variable");
    }

    public Response renameVariableInFunction(String functionName, String oldVarName, String newVarName) {
        return renameVariableInFunction(functionName, null, oldVarName, newVarName, null);
    }

    public Response renameVariableInFunction(String functionName, String oldVarName, String newVarName, String programName) {
        return renameVariableInFunction(functionName, null, oldVarName, newVarName, programName);
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
    @McpTool(path = "/rename_function_by_address", method = "POST", description = "Rename function at specific address. On programs with multiple address spaces (e.g., embedded targets), prefix addresses with the space name (mem:1000) to avoid ambiguous resolution.", category = "function")
    public Response renameFunctionByAddress(
            @Param(value = "function_address", paramType = "address", source = ParamSource.BODY,
                   description = "Address in the program. Accepts 0x<hex> (default space) or <space>:<hex> "
                               + "(e.g., mem:1000, code:ff00). Note: some programs — particularly "
                               + "embedded/microcontroller targets — are not address-space-agnostic; "
                               + "use get_address_spaces to discover spaces before assuming a plain hex "
                               + "address is unambiguous.") String functionAddrStr,
            @Param(value = "new_name", source = ParamSource.BODY) String newName,
            @Param(value = "program", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        if (functionAddrStr == null || functionAddrStr.isEmpty()) {
            return Response.err("Function address or name is required");
        }

        if (newName == null || newName.isEmpty()) {
            return Response.err("New function name is required");
        }

        Function targetFunc = ServiceUtils.resolveFunction(program, functionAddrStr);
        if (targetFunc == null) {
            return Response.err("No function found for " + functionAddrStr);
        }

        // ---- Q1-Q5 validator gate (defense in depth) ----------------------
        // Hard-reject names that fail verb-tier specificity (Q2/Q4) or
        // collide via token-subset with another function in this program
        // (Q3/Q4). Auto-generated names are exempt — the model may
        // legitimately restore one in rare recovery flows.
        if (!ServiceUtils.isAutoGeneratedName(newName)) {
            NamingConventions.NameQualityResult quality =
                    NamingConventions.checkFunctionNameQuality(newName);
            if (!quality.ok) {
                return Response.ok(JsonHelper.mapOf(
                        "status", "rejected",
                        "error", "name_quality",
                        "issue", quality.issue,
                        "rejected_name", newName,
                        "message", quality.message,
                        "suggestion", quality.suggestion
                ));
            }
            // Token-subset collision check against every function in the
            // program. Iteration is read-only and fast enough for in-line
            // execution even on 5k-function binaries.
            List<String> existingNames = new ArrayList<>();
            for (Function f : program.getFunctionManager().getFunctions(true)) {
                if (f == targetFunc) continue;
                String n = f.getName();
                if (n != null && !n.isEmpty()) existingNames.add(n);
            }
            String collidesWith =
                    NamingConventions.findTokenSubsetCollision(newName, existingNames);
            if (collidesWith != null) {
                return Response.ok(JsonHelper.mapOf(
                        "status", "rejected",
                        "error", "name_collision",
                        "issue", "token_subset_duplicate",
                        "rejected_name", newName,
                        "conflicts_with", collidesWith,
                        "message", "Token-subset collision: '" + newName + "' shares the same token set "
                                + "as existing function '" + collidesWith + "' in this program. "
                                + "Names that differ only by an added/removed trailing token are usually "
                                + "a sign that the function needs a more meaningful distinguisher.",
                        "suggestion", "Pick a name with a distinguishing token that captures *why* this "
                                + "function differs from '" + collidesWith + "' (e.g., add 'Broadcast', "
                                + "'Local', 'ByIndex', 'ForPlayer', 'WithRetry', ...) rather than just "
                                + "trimming/extending '" + collidesWith + "'."
                ));
            }
        }

        final StringBuilder resultMsg = new StringBuilder();
        final AtomicBoolean success = new AtomicBoolean(false);

        try {
            threadingStrategy.executeWrite(program, "Rename function by address", () -> {
                String oldName = targetFunc.getName();
                targetFunc.setName(newName, SourceType.USER_DEFINED);
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
        if (success.get()) {
            List<String> nameWarnings = NamingConventions.validateFunctionName(newName, false);
            if (nameWarnings.isEmpty()) {
                return Response.ok(JsonHelper.mapOf("status", "success", "message", text));
            } else {
                return Response.ok(JsonHelper.mapOf("status", "success", "message", text,
                        "warnings", nameWarnings));
            }
        }
        return Response.err(text.startsWith("Error: ") ? text.substring(7) : text);
    }

    public Response renameFunctionByAddress(String functionAddrStr, String newName) {
        return renameFunctionByAddress(functionAddrStr, newName, null);
    }

    // ========================================================================
    // Prototype / Signature methods
    // ========================================================================

    /**
     * Set a function's prototype with proper error handling using ApplyFunctionSignatureCmd.
     */
    public PrototypeResult setFunctionPrototype(String functionAddrStr, String prototype) {
        return setFunctionPrototype(functionAddrStr, prototype, null, null);
    }

    /**
     * Set a function's prototype with calling convention support (backward compatible).
     */
    public PrototypeResult setFunctionPrototype(String functionAddrStr, String prototype, String callingConvention) {
        return setFunctionPrototype(functionAddrStr, prototype, callingConvention, null);
    }

    /**
     * Set a function's prototype with calling convention and program name support.
     */
    public PrototypeResult setFunctionPrototype(String functionAddrStr, String prototype, String callingConvention, String programName) {
        // Input validation
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return new PrototypeResult(false, pe.error().toJson());
        Program program = pe.program();
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
     * Endpoint wrapper for setFunctionPrototype that converts PrototypeResult to Response.
     */
    @McpTool(path = "/set_function_prototype", method = "POST", description = "Set function prototype (return type, parameter types, calling convention) by address. NOTE: the function name in the prototype string is used only for parsing — it does NOT rename the function. To rename, call rename_function_by_address separately. On programs with multiple address spaces (e.g., embedded targets), prefix addresses with the space name (mem:1000) to avoid ambiguous resolution.", category = "function")
    public Response setFunctionPrototypeEndpoint(
            @Param(value = "function_address", paramType = "address", source = ParamSource.BODY,
                   description = "Address in the program. Accepts 0x<hex> (default space) or <space>:<hex> "
                               + "(e.g., mem:1000, code:ff00). Note: some programs — particularly "
                               + "embedded/microcontroller targets — are not address-space-agnostic; "
                               + "use get_address_spaces to discover spaces before assuming a plain hex "
                               + "address is unambiguous.") String functionAddress,
            @Param(value = "prototype", source = ParamSource.BODY) String prototype,
            @Param(value = "calling_convention", source = ParamSource.BODY, defaultValue = "") String callingConvention,
            @Param(value = "program", description = "Target program name", defaultValue = "") String programName) {
        PrototypeResult result = setFunctionPrototype(functionAddress, prototype, callingConvention, programName);
        if (result.isSuccess()) {
            String msg = "Successfully set prototype for function at " + functionAddress;
            if (callingConvention != null && !callingConvention.isEmpty()) {
                msg += " with " + callingConvention + " calling convention";
            }
            // Warn about __thiscall ECX auto-param limitation
            String cc = callingConvention != null ? callingConvention : "";
            boolean protoHasThiscall = prototype != null && (prototype.contains("__thiscall") || cc.contains("__thiscall"));
            if (protoHasThiscall && prototype != null && !prototype.contains("void *this") && !prototype.contains("void * this")) {
                msg += "\n\nWARNING: __thiscall ECX auto-parameter 'this' cannot be retyped via API. "
                     + "Ghidra accepts the prototype but the decompiler will still show 'this' as void*. "
                     + "Document the intended type in the plate comment Parameters section instead.";
            }
            if (!result.getErrorMessage().isEmpty()) {
                msg += "\n\nWarnings/Debug Info:\n" + result.getErrorMessage();
            }
            return Response.text(msg);
        } else {
            return Response.text("Failed to set function prototype: " + result.getErrorMessage());
        }
    }

    /**
     * Helper method that applies the function prototype within a transaction.
     * v3.0.1: Preserves existing plate comment across prototype changes.
     */
    void applyFunctionPrototype(Program program, String functionAddrStr, String prototype,
                                       String callingConvention, AtomicBoolean success, StringBuilder errorMessage) {
        try {
            // Get the address and function
            Address addr = ServiceUtils.parseAddress(program, functionAddrStr);
            if (addr == null) {
                String msg = ServiceUtils.getLastParseError();
                errorMessage.append(msg);
                Msg.error(this, msg);
                return;
            }
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
    @McpTool(path = "/set_local_variable_type", method = "POST", description = "Set the data type of a local variable. On programs with multiple address spaces (e.g., embedded targets), prefix addresses with the space name (mem:1000) to avoid ambiguous resolution.", category = "function")
    public Response setLocalVariableType(
            @Param(value = "function_address", paramType = "address", source = ParamSource.BODY,
                   description = "Address in the program. Accepts 0x<hex> (default space) or <space>:<hex> "
                               + "(e.g., mem:1000, code:ff00). Note: some programs — particularly "
                               + "embedded/microcontroller targets — are not address-space-agnostic; "
                               + "use get_address_spaces to discover spaces before assuming a plain hex "
                               + "address is unambiguous.") String functionAddrStr,
            @Param(value = "variable_name", source = ParamSource.BODY) String variableName,
            @Param(value = "new_type", source = ParamSource.BODY) String newType,
            @Param(value = "program", defaultValue = "") String programName) {
        // Input validation
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        if (functionAddrStr == null || functionAddrStr.isEmpty()) {
            return Response.err("Function address is required");
        }

        if (variableName == null || variableName.isEmpty()) {
            return Response.err("Variable name is required");
        }

        if (newType == null || newType.isEmpty()) {
            return Response.err("New type is required");
        }

        // Reject undefined -> undefined (no improvement)
        if (newType.startsWith("undefined")) {
            return Response.err("Rejected: new type '" + newType + "' is still undefined. "
                    + "Resolve to a concrete type: byte, ushort, int, uint, void *, etc.");
        }

        // Resolve address before entering threading lambda
        Address addr = ServiceUtils.parseAddress(program, functionAddrStr);
        if (addr == null) return Response.err(ServiceUtils.getLastParseError());

        final StringBuilder resultMsg = new StringBuilder();
        final AtomicBoolean success = new AtomicBoolean(false);

        try {
            threadingStrategy.executeRead(() -> {
                try {
                    // Find the function
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

                        // SSA churn hint: when the failed name follows the
                        // <prefix><digit>+ pattern of a Ghidra SSA temporary
                        // (iVar5, psVar7, puVar2, ...) and there is a similar
                        // name in the available list with a *different* digit,
                        // the most likely cause is that a previous
                        // set_local_variable_type call retyped a variable in
                        // the same function and re-decompilation renumbered
                        // SSA temporaries. Recommend the atomic batch tool
                        // explicitly rather than leaving the worker to guess.
                        if (variableName.matches("^[a-z]+Var\\d+$")) {
                            String prefix = variableName.replaceAll("\\d+$", "");
                            boolean hasSamePrefix = availableNames.stream()
                                    .anyMatch(n -> n.startsWith(prefix) && n.matches("^[a-z]+Var\\d+$"));
                            if (hasSamePrefix) {
                                resultMsg.append("Hint: this looks like SSA-renumber drift from a previous ")
                                        .append("set_local_variable_type call in the same function. ")
                                        .append("Use set_variables for ALL variable type+rename changes in one ")
                                        .append("atomic call to avoid this — individual set_local_variable_type ")
                                        .append("calls trigger re-decompilation that renumbers SSA temporaries. ");
                            }
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
                        // Provide actionable hint for pointer types
                        if (newType.endsWith("*")) {
                            String baseTypeName = newType.substring(0, newType.length() - 1).trim();
                            if (!baseTypeName.isEmpty() && !baseTypeName.equals("void")) {
                                resultMsg.append(". Hint: struct '").append(baseTypeName)
                                    .append("' does not exist. Create it first with create_struct(name=\"")
                                    .append(baseTypeName).append("\", fields=[...]), then retry set_local_variable_type.");
                            }
                        }
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
        if (success.get()) {
            return Response.ok(JsonHelper.mapOf("status", "success", "message", text));
        }
        return Response.err(text.startsWith("Error: ") ? text.substring(7) : text);
    }

    public Response setLocalVariableType(String functionAddrStr, String variableName, String newType) {
        return setLocalVariableType(functionAddrStr, variableName, newType, null);
    }

    /**
     * Endpoint wrapper for set_parameter_type (delegates to setLocalVariableType).
     */
    @McpTool(path = "/set_parameter_type", method = "POST", description = "Set the data type of a function parameter. On programs with multiple address spaces (e.g., embedded targets), prefix addresses with the space name (mem:1000) to avoid ambiguous resolution.", category = "function")
    public Response setParameterTypeEndpoint(
            @Param(value = "function_address", paramType = "address", source = ParamSource.BODY,
                   description = "Address in the program. Accepts 0x<hex> (default space) or <space>:<hex> "
                               + "(e.g., mem:1000, code:ff00). Note: some programs — particularly "
                               + "embedded/microcontroller targets — are not address-space-agnostic; "
                               + "use get_address_spaces to discover spaces before assuming a plain hex "
                               + "address is unambiguous.") String functionAddress,
            @Param(value = "parameter_name", source = ParamSource.BODY) String parameterName,
            @Param(value = "new_type", source = ParamSource.BODY) String newType,
            @Param(value = "program", description = "Target program name", defaultValue = "") String programName) {
        return setLocalVariableType(functionAddress, parameterName, newType, programName);
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
     * @return Success or error message
     */
    @McpTool(path = "/set_function_no_return", method = "POST", description = "Mark function as no-return. On programs with multiple address spaces (e.g., embedded targets), prefix addresses with the space name (mem:1000) to avoid ambiguous resolution.", category = "function")
    public Response setFunctionNoReturn(
            @Param(value = "function_address", paramType = "address", source = ParamSource.BODY,
                   description = "Address in the program. Accepts 0x<hex> (default space) or <space>:<hex> "
                               + "(e.g., mem:1000, code:ff00). Note: some programs — particularly "
                               + "embedded/microcontroller targets — are not address-space-agnostic; "
                               + "use get_address_spaces to discover spaces before assuming a plain hex "
                               + "address is unambiguous.") String functionAddrStr,
            @Param(value = "no_return", source = ParamSource.BODY) boolean noReturn,
            @Param(value = "program", defaultValue = "") String programName) {
        // Input validation
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        if (functionAddrStr == null || functionAddrStr.isEmpty()) {
            return Response.err("Function address is required");
        }

        // Resolve address before entering threading lambda
        Address addr = ServiceUtils.parseAddress(program, functionAddrStr);
        if (addr == null) return Response.err(ServiceUtils.getLastParseError());

        final StringBuilder resultMsg = new StringBuilder();
        final AtomicBoolean success = new AtomicBoolean(false);

        try {
            threadingStrategy.executeWrite(program, "Set function no return", () -> {

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
        if (success.get()) {
            return Response.ok(JsonHelper.mapOf("status", "success", "message", text));
        }
        return Response.err(text.startsWith("Error: ") ? text.substring(7) : text);
    }

    public Response setFunctionNoReturn(String functionAddrStr, boolean noReturn) {
        return setFunctionNoReturn(functionAddrStr, noReturn, null);
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
     * @return Success or error message
     */
    @McpTool(path = "/clear_instruction_flow_override", method = "POST", description = "Clear flow override at address. On programs with multiple address spaces (e.g., embedded targets), prefix addresses with the space name (mem:1000) to avoid ambiguous resolution.", category = "function")
    public Response clearInstructionFlowOverride(
            @Param(value = "address", paramType = "address", source = ParamSource.BODY,
                   description = "Address in the program. Accepts 0x<hex> (default space) or <space>:<hex> "
                               + "(e.g., mem:1000, code:ff00). Note: some programs — particularly "
                               + "embedded/microcontroller targets — are not address-space-agnostic; "
                               + "use get_address_spaces to discover spaces before assuming a plain hex "
                               + "address is unambiguous.") String instructionAddrStr,
            @Param(value = "program", defaultValue = "") String programName) {
        // Input validation
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        if (instructionAddrStr == null || instructionAddrStr.isEmpty()) {
            return Response.err("Instruction address is required");
        }

        // Resolve address before entering threading lambda
        Address addr = ServiceUtils.parseAddress(program, instructionAddrStr);
        if (addr == null) return Response.err(ServiceUtils.getLastParseError());

        final StringBuilder resultMsg = new StringBuilder();
        final AtomicBoolean success = new AtomicBoolean(false);

        try {
            threadingStrategy.executeWrite(program, "Clear instruction flow override", () -> {

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
        if (success.get()) {
            return Response.ok(JsonHelper.mapOf("status", "success", "message", text));
        }
        return Response.err(text.startsWith("Error: ") ? text.substring(7) : text);
    }

    public Response clearInstructionFlowOverride(String instructionAddrStr) {
        return clearInstructionFlowOverride(instructionAddrStr, null);
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
     * @return Success or error message
     */
    @McpTool(path = "/set_variable_storage", method = "POST", description = "Set variable storage location. On programs with multiple address spaces (e.g., embedded targets), prefix addresses with the space name (mem:1000) to avoid ambiguous resolution.", category = "function")
    public Response setVariableStorage(
            @Param(value = "function_address", paramType = "address", source = ParamSource.BODY,
                   description = "Address in the program. Accepts 0x<hex> (default space) or <space>:<hex> "
                               + "(e.g., mem:1000, code:ff00). Note: some programs — particularly "
                               + "embedded/microcontroller targets — are not address-space-agnostic; "
                               + "use get_address_spaces to discover spaces before assuming a plain hex "
                               + "address is unambiguous.") String functionAddrStr,
            @Param(value = "variable_name", source = ParamSource.BODY) String variableName,
            @Param(value = "storage", source = ParamSource.BODY) String storageSpec,
            @Param(value = "program", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        if (functionAddrStr == null || functionAddrStr.isEmpty()) {
            return Response.err("Function address is required");
        }
        if (variableName == null || variableName.isEmpty()) {
            return Response.err("Variable name is required");
        }
        if (storageSpec == null || storageSpec.isEmpty()) {
            return Response.err("Storage specification is required");
        }

        // Resolve address before entering threading lambda
        Address addr = ServiceUtils.parseAddress(program, functionAddrStr);
        if (addr == null) return Response.err(ServiceUtils.getLastParseError());

        final StringBuilder resultMsg = new StringBuilder();
        final AtomicBoolean success = new AtomicBoolean(false);

        try {
            threadingStrategy.executeWrite(program, "Set variable storage", () -> {

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
        if (success.get()) {
            return Response.text(text);
        }
        return Response.err(text.startsWith("Error: ") ? text.substring(7) : text);
    }

    public Response setVariableStorage(String functionAddrStr, String variableName, String storageSpec) {
        return setVariableStorage(functionAddrStr, variableName, storageSpec, null);
    }

    // ========================================================================
    // Function variables query
    // ========================================================================

    /**
     * Get detailed information about a function's variables (parameters and locals).
     */
    @McpTool(path = "/get_function_variables", description = "List all variables in a function. Accepts function_name (by name) or address (by address). If both are given, address takes precedence. Useful when the function was recently renamed — use address to avoid name-lookup race conditions.", category = "function")
    public Response getFunctionVariables(
            @Param(value = "function_name", description = "Function name (ignored if address is provided)", defaultValue = "") String functionName,
            @Param(value = "address", description = "Function address (hex, e.g. 6fc583f0). If provided, overrides function_name lookup.", defaultValue = "") String address,
            @Param(value = "program", defaultValue = "") String programName,
            @Param(value = "limit", description = "Max local variables to return (default 200, 0 = unlimited)", defaultValue = "200") String limitStr,
            @Param(value = "filter", description = "Filter locals: 'all' (default), 'needs_work' (only needs_type or needs_rename), 'named' (only non-generic names)", defaultValue = "all") String filter) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        if ((functionName == null || functionName.isEmpty()) && (address == null || address.isEmpty())) {
            return Response.err("Either function_name or address is required");
        }

        final int limit = (limitStr != null && !limitStr.isEmpty()) ? Integer.parseInt(limitStr) : 200;
        final String filterMode = (filter != null && !filter.isEmpty()) ? filter : "all";

        final Program finalProgram = program;
        final AtomicReference<Map<String, Object>> resultData = new AtomicReference<>(null);
        final AtomicReference<String> errorMsg = new AtomicReference<>(null);

        try {
            threadingStrategy.executeRead(() -> {
                try {
                    // Find function — address lookup takes precedence over name scan
                    Function func = null;
                    if (address != null && !address.isEmpty()) {
                        Address addr = ServiceUtils.parseAddress(finalProgram, address);
                        if (addr != null) {
                            func = ServiceUtils.getFunctionForAddress(finalProgram, addr);
                        }
                        if (func == null) {
                            errorMsg.set("No function at address: " + address);
                            return null;
                        }
                    } else {
                        for (Function f : finalProgram.getFunctionManager().getFunctions(true)) {
                            if (f.getName().equals(functionName)) {
                                func = f;
                                break;
                            }
                        }
                    }

                    if (func == null) {
                        errorMsg.set("Function not found: " + functionName);
                        return null;
                    }

                    // Use shared decompileFunction (uses existing cache, no forced flush)
                    // The old forced cache flush + re-decompile added 5-30s latency per call.
                    // Fresh data is ensured by decompileFunction's internal caching.
                    DecompileResults decompResults = decompileFunction(func, finalProgram);

                    Map<String, Object> data = new LinkedHashMap<>();
                    data.put("function_name", func.getName());
                    data.put("function_address", func.getEntryPoint().toString());

                    // Get parameters with pre-analysis hints
                    List<Map<String, Object>> paramsList = new ArrayList<>();
                    Parameter[] params = func.getParameters();
                    for (Parameter param : params) {
                        Map<String, Object> paramMap = new LinkedHashMap<>();
                        String pTypeName = param.getDataType().getName();
                        boolean pNeedsType = pTypeName.startsWith("undefined");
                        boolean pNeedsRename = param.getName().startsWith("param_");
                        paramMap.put("name", param.getName());
                        paramMap.put("type", pTypeName);
                        paramMap.put("ordinal", param.getOrdinal());
                        paramMap.put("storage", param.getVariableStorage().toString());
                        paramMap.put("needs_type", pNeedsType);
                        paramMap.put("needs_rename", pNeedsRename);
                        if (pNeedsType) {
                            paramMap.put("suggested_type", suggestType(pTypeName));
                        }
                        if (!pNeedsType) {
                            paramMap.put("suggested_prefix", suggestHungarianPrefix(pTypeName));
                        }
                        paramsList.add(paramMap);
                    }
                    data.put("parameters", paramsList);

                    // Get local variables and detect phantom variables
                    List<Map<String, Object>> localsList = new ArrayList<>();
                    Variable[] locals = func.getLocalVariables();

                    // Use existing decompilation results for phantom detection (no second decompile)
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

                    int totalLocals = locals.length;
                    int filteredOut = 0;
                    int truncated = 0;

                    for (Variable local : locals) {
                        boolean isPhantom = !decompVarNames.contains(local.getName());
                        String lTypeName = local.getDataType().getName();
                        boolean lNeedsType = lTypeName.startsWith("undefined");
                        boolean lNeedsRename = local.getName().startsWith("local_") ||
                            local.getName().matches(".*Var\\d+");

                        // Apply filter
                        if ("needs_work".equals(filterMode)) {
                            if (isPhantom || (!lNeedsType && !lNeedsRename)) {
                                filteredOut++;
                                continue;
                            }
                        } else if ("named".equals(filterMode)) {
                            if (isPhantom || lNeedsRename) {
                                filteredOut++;
                                continue;
                            }
                        }

                        // Apply limit (0 = unlimited)
                        if (limit > 0 && localsList.size() >= limit) {
                            truncated++;
                            continue;
                        }

                        Map<String, Object> localMap = new LinkedHashMap<>();
                        localMap.put("name", local.getName());
                        localMap.put("type", lTypeName);
                        localMap.put("storage", local.getVariableStorage().toString());
                        localMap.put("is_phantom", isPhantom);
                        localMap.put("needs_type", lNeedsType && !isPhantom);
                        localMap.put("needs_rename", lNeedsRename && !isPhantom);
                        if (lNeedsType && !isPhantom) {
                            localMap.put("suggested_type", suggestType(lTypeName));
                        }
                        if (!lNeedsType && !isPhantom) {
                            localMap.put("suggested_prefix", suggestHungarianPrefix(lTypeName));
                        }
                        localsList.add(localMap);
                    }
                    data.put("locals", localsList);
                    data.put("total_locals", totalLocals);
                    if (filteredOut > 0) data.put("filtered_out", filteredOut);
                    if (truncated > 0) data.put("truncated", truncated);

                    resultData.set(data);
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

        if (resultData.get() != null) {
            return Response.ok(resultData.get());
        }
        return Response.err("Unknown error");
    }

    // Backward compatibility overload
    public Response getFunctionVariables(String functionName) {
        return getFunctionVariables(functionName, null, null, null, null);
    }

    /** Suggest a concrete type for an undefined Ghidra type based on size. */
    static String suggestType(String typeName) {
        if ("undefined1".equals(typeName)) return "byte";
        if ("undefined2".equals(typeName)) return "ushort";
        if ("undefined4".equals(typeName)) return "uint";
        if ("undefined8".equals(typeName)) return "ulonglong";
        return "uint"; // fallback for other undefined variants
    }

    /** Suggest a Hungarian notation prefix for a resolved type. */
    static String suggestHungarianPrefix(String typeName) {
        if (typeName == null) return "";
        String base = typeName.replace("*", "").replace("[]", "").trim();
        // Pointer types
        if (typeName.contains("*")) {
            if ("char".equals(base)) return "sz";
            if ("wchar_t".equals(base)) return "wsz";
            if ("void".equals(base)) return "p";
            return "p"; // generic pointer
        }
        // Array types
        if (typeName.contains("[")) {
            if ("byte".equals(base) || "undefined1".equals(base)) return "ab";
            if ("ushort".equals(base)) return "aw";
            if ("uint".equals(base)) return "ad";
            return "a";
        }
        // Scalar types
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
    // Batch operations
    // ========================================================================

    /**
     * v1.5.0: Batch rename function and all its components atomically.
     */
    @McpTool(path = "/batch_rename_function_components", method = "POST", description = "Rename function and components atomically. On programs with multiple address spaces (e.g., embedded targets), prefix addresses with the space name (mem:1000) to avoid ambiguous resolution.", category = "function")
    public Response batchRenameFunctionComponents(
            @Param(value = "function_address", paramType = "address", source = ParamSource.BODY,
                   description = "Address in the program. Accepts 0x<hex> (default space) or <space>:<hex> "
                               + "(e.g., mem:1000, code:ff00). Note: some programs — particularly "
                               + "embedded/microcontroller targets — are not address-space-agnostic; "
                               + "use get_address_spaces to discover spaces before assuming a plain hex "
                               + "address is unambiguous.") String functionAddress,
            @Param(value = "function_name", source = ParamSource.BODY, defaultValue = "") String functionName,
            @Param(value = "parameter_renames", source = ParamSource.BODY) Map<String, String> parameterRenames,
            @Param(value = "local_renames", source = ParamSource.BODY) Map<String, String> localRenames,
            @Param(value = "return_type", source = ParamSource.BODY, defaultValue = "") String returnType,
            @Param(value = "program", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        // Resolve address before entering threading lambda
        Address addr = ServiceUtils.parseAddress(program, functionAddress);
        if (addr == null) return Response.err(ServiceUtils.getLastParseError());

        final AtomicBoolean success = new AtomicBoolean(false);
        final AtomicInteger paramsRenamed = new AtomicInteger(0);
        final AtomicInteger localsRenamed = new AtomicInteger(0);
        final AtomicReference<String> errorRef = new AtomicReference<>(null);

        try {
            threadingStrategy.executeWrite(program, "Batch Rename Function Components", () -> {

                Function func = program.getFunctionManager().getFunctionAt(addr);
                if (func == null) {
                    errorRef.set("No function at address: " + functionAddress);
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
                            paramsRenamed.incrementAndGet();
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
                            localsRenamed.incrementAndGet();
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

            if (errorRef.get() != null) {
                return Response.err(errorRef.get());
            }

            if (success.get()) {
                return Response.ok(JsonHelper.mapOf(
                    "success", true,
                    "function_renamed", functionName != null,
                    "parameters_renamed", paramsRenamed.get(),
                    "locals_renamed", localsRenamed.get()
                ));
            }
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }

        return Response.err("Unknown failure");
    }

    public Response batchRenameFunctionComponents(String functionAddress, String functionName,
                                                Map<String, String> parameterRenames,
                                                Map<String, String> localRenames,
                                                String returnType) {
        return batchRenameFunctionComponents(functionAddress, functionName, parameterRenames, localRenames, returnType, null);
    }

    // ========================================================================
    // Function creation / deletion
    // ========================================================================

    /**
     * Delete a function at the given address.
     */
    @McpTool(path = "/delete_function", method = "POST", description = "Delete function at address. On programs with multiple address spaces (e.g., embedded targets), prefix addresses with the space name (mem:1000) to avoid ambiguous resolution.", category = "function")
    public Response deleteFunctionAtAddress(
            @Param(value = "address", paramType = "address", source = ParamSource.BODY,
                   description = "Address in the program. Accepts 0x<hex> (default space) or <space>:<hex> "
                               + "(e.g., mem:1000, code:ff00). Note: some programs — particularly "
                               + "embedded/microcontroller targets — are not address-space-agnostic; "
                               + "use get_address_spaces to discover spaces before assuming a plain hex "
                               + "address is unambiguous.") String addressStr,
            @Param(value = "program", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();
        if (addressStr == null || addressStr.isEmpty()) {
            return Response.err("address parameter required");
        }

        // Resolve address before entering threading lambda
        Address addr = ServiceUtils.parseAddress(program, addressStr);
        if (addr == null) return Response.err(ServiceUtils.getLastParseError());

        final AtomicReference<Map<String, Object>> resultData = new AtomicReference<>(null);
        final AtomicReference<String> errorMsg = new AtomicReference<>();

        try {
            threadingStrategy.executeWrite(program, "Delete function at address", () -> {

                Function func = program.getFunctionManager().getFunctionAt(addr);
                if (func == null) {
                    errorMsg.set("No function found at address " + addressStr);
                    return null;
                }

                String funcName = func.getName();
                long bodySize = func.getBody().getNumAddresses();
                program.getFunctionManager().removeFunction(addr);

                Map<String, Object> delResult = new LinkedHashMap<>();
                delResult.put("success", true);
                delResult.putAll(ServiceUtils.addressToJson(addr, program));
                delResult.put("deleted_function", funcName);
                delResult.put("body_size", bodySize);
                delResult.put("message", "Function '" + funcName + "' deleted at " + addr);
                resultData.set(delResult);
                return null;
            });

            if (errorMsg.get() != null) {
                return Response.err(errorMsg.get());
            }
        } catch (Throwable e) {
            String msg = e.getMessage() != null ? e.getMessage() : e.toString();
            return Response.err("Failed to execute on Swing thread: " + msg);
        }

        if (resultData.get() != null) {
            return Response.ok(resultData.get());
        }
        return Response.err("Unknown failure");
    }

    public Response deleteFunctionAtAddress(String addressStr) {
        return deleteFunctionAtAddress(addressStr, null);
    }

    /**
     * Create a function at the given address.
     */
    @McpTool(path = "/create_function", method = "POST", description = "Create function at address. On programs with multiple address spaces (e.g., embedded targets), prefix addresses with the space name (mem:1000) to avoid ambiguous resolution.", category = "function")
    public Response createFunctionAtAddress(
            @Param(value = "address", paramType = "address", source = ParamSource.BODY,
                   description = "Address in the program. Accepts 0x<hex> (default space) or <space>:<hex> "
                               + "(e.g., mem:1000, code:ff00). Note: some programs — particularly "
                               + "embedded/microcontroller targets — are not address-space-agnostic; "
                               + "use get_address_spaces to discover spaces before assuming a plain hex "
                               + "address is unambiguous.") String addressStr,
            @Param(value = "name", source = ParamSource.BODY, defaultValue = "") String name,
            @Param(value = "disassemble_first", source = ParamSource.BODY, defaultValue = "true") boolean disassembleFirst,
            @Param(value = "program", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        if (addressStr == null || addressStr.isEmpty()) {
            return Response.err("address parameter required");
        }

        // Resolve address before entering threading lambda
        Address addr = ServiceUtils.parseAddress(program, addressStr);
        if (addr == null) return Response.err(ServiceUtils.getLastParseError());

        final AtomicReference<Map<String, Object>> resultData = new AtomicReference<>(null);
        final AtomicReference<String> errorMsg = new AtomicReference<>();

        try {
            threadingStrategy.executeWrite(program, "Create function at address", () -> {

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

                Map<String, Object> createResult = new LinkedHashMap<>();
                createResult.put("success", true);
                createResult.putAll(ServiceUtils.addressToJson(addr, program));
                createResult.put("function_name", func.getName());
                Address ep = func.getEntryPoint();
                createResult.put("entry_point", ep.toString(false));
                if (ServiceUtils.getPhysicalSpaceCount(program) > 1) {
                    createResult.put("entry_point_full", ep.toString());
                    createResult.put("entry_point_space", ep.getAddressSpace().getName());
                }
                createResult.put("body_size", func.getBody().getNumAddresses());
                createResult.put("message", "Function created successfully at " + addr);
                resultData.set(createResult);
                return null;
            });

            if (errorMsg.get() != null) {
                return Response.err(errorMsg.get());
            }
        } catch (Throwable e) {
            String msg = e.getMessage() != null ? e.getMessage() : e.toString();
            return Response.err("Failed to execute on Swing thread: " + msg);
        }

        if (resultData.get() != null) {
            Map<String, Object> data = resultData.get();
            // Validate function name if one was provided
            if (name != null && !name.isEmpty()) {
                List<String> nameWarnings = NamingConventions.validateFunctionName(name, false);
                if (!nameWarnings.isEmpty()) {
                    data.put("warnings", nameWarnings);
                }
            }
            return Response.ok(data);
        }
        return Response.err("Unknown failure");
    }

    public Response createFunctionAtAddress(String addressStr, String name, boolean disassembleFirst) {
        return createFunctionAtAddress(addressStr, name, disassembleFirst, null);
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
    @McpTool(path = "/disassemble_bytes", method = "POST", description = "Disassemble a range of bytes. On programs with multiple address spaces (e.g., embedded targets), prefix addresses with the space name (mem:1000) to avoid ambiguous resolution.", category = "function")
    public Response disassembleBytes(
            @Param(value = "start_address", paramType = "address", source = ParamSource.BODY,
                   description = "Address in the program. Accepts 0x<hex> (default space) or <space>:<hex> "
                               + "(e.g., mem:1000, code:ff00). Note: some programs — particularly "
                               + "embedded/microcontroller targets — are not address-space-agnostic; "
                               + "use get_address_spaces to discover spaces before assuming a plain hex "
                               + "address is unambiguous.") String startAddress,
            @Param(value = "end_address", paramType = "address", source = ParamSource.BODY, defaultValue = "",
                   description = "Address in the program. Accepts 0x<hex> (default space) or <space>:<hex> "
                               + "(e.g., mem:1000, code:ff00). Note: some programs — particularly "
                               + "embedded/microcontroller targets — are not address-space-agnostic; "
                               + "use get_address_spaces to discover spaces before assuming a plain hex "
                               + "address is unambiguous.") String endAddress,
            @Param(value = "length", source = ParamSource.BODY, defaultValue = "0") Integer length,
            @Param(value = "restrict_to_execute_memory", source = ParamSource.BODY, defaultValue = "true") boolean restrictToExecuteMemory,
            @Param(value = "program", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        if (startAddress == null || startAddress.isEmpty()) {
            return Response.err("start_address parameter required");
        }

        // Resolve addresses before entering SwingUtilities lambda
        Address start = ServiceUtils.parseAddress(program, startAddress);
        if (start == null) return Response.err(ServiceUtils.getLastParseError());

        Address parsedEnd = null;
        if (endAddress != null && !endAddress.isEmpty()) {
            parsedEnd = ServiceUtils.parseAddress(program, endAddress);
            if (parsedEnd == null) return Response.err(ServiceUtils.getLastParseError());
        }
        final Address resolvedEnd = parsedEnd;

        final AtomicReference<Map<String, Object>> resultData = new AtomicReference<>(null);
        final AtomicReference<String> errorMsg = new AtomicReference<>();

        try {
            Msg.debug(this, "disassembleBytes: Starting disassembly at " + startAddress +
                     (length != null ? " with length " + length : "") +
                     (endAddress != null ? " to " + endAddress : ""));

            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Disassemble Bytes");
                boolean success = false;

                try {
                    // Determine end address
                    Address end;
                    if (resolvedEnd != null) {
                        // Make end address inclusive for AddressSet
                        try {
                            end = resolvedEnd.subtract(1);
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
                        resultData.set(JsonHelper.mapOf(
                            "success", true,
                            "start_address", start.toString(),
                            "end_address", end.toString(),
                            "bytes_disassembled", numBytes,
                            "message", "Successfully disassembled " + numBytes + " byte(s)"
                        ));
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

        if (resultData.get() != null) {
            Msg.debug(this, "disassembleBytes: Returning success response");
            return Response.ok(resultData.get());
        }
        return Response.err("Unknown failure");
    }

    public Response disassembleBytes(String startAddress, String endAddress, Integer length,
                                   boolean restrictToExecuteMemory) {
        return disassembleBytes(startAddress, endAddress, length, restrictToExecuteMemory, null);
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
    @McpTool(path = "/rename_variables", method = "POST", description = "Rename multiple variables atomically. On programs with multiple address spaces (e.g., embedded targets), prefix addresses with the space name (mem:1000) to avoid ambiguous resolution.", category = "function")
    public Response batchRenameVariables(
            @Param(value = "function_address", paramType = "address", source = ParamSource.BODY,
                   description = "Address in the program. Accepts 0x<hex> (default space) or <space>:<hex> "
                               + "(e.g., mem:1000, code:ff00). Note: some programs — particularly "
                               + "embedded/microcontroller targets — are not address-space-agnostic; "
                               + "use get_address_spaces to discover spaces before assuming a plain hex "
                               + "address is unambiguous.") String functionAddress,
            @Param(value = "variable_renames", source = ParamSource.BODY) Map<String, String> variableRenames,
            @Param(value = "force_individual", source = ParamSource.BODY, defaultValue = "false") boolean forceIndividual,
            @Param(value = "program", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        // Resolve address before entering SwingUtilities lambda
        Address addr = ServiceUtils.parseAddress(program, functionAddress);
        if (addr == null) return Response.err(ServiceUtils.getLastParseError());

        final AtomicBoolean success = new AtomicBoolean(false);
        final AtomicInteger variablesRenamed = new AtomicInteger(0);
        final AtomicInteger variablesFailed = new AtomicInteger(0);
        final List<String> errors = new ArrayList<>();
        final List<String> warnings = new ArrayList<>();
        final AtomicReference<Function> funcRef = new AtomicReference<>(null);
        final AtomicReference<String> fallbackResult = new AtomicReference<>(null);
        final AtomicReference<String> errorRef = new AtomicReference<>(null);

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Batch Rename Variables");
                // Suppress events during batch operation to prevent re-analysis on each rename
                int eventTx = program.startTransaction("Suppress Events");
                program.flushEvents();

                try {

                    Function func = program.getFunctionManager().getFunctionAt(addr);
                    funcRef.set(func);
                    if (func == null) {
                        errorRef.set("No function at address: " + functionAddress);
                        return;
                    }

                    if (variableRenames != null && !variableRenames.isEmpty()) {
                        // Use decompiler to access SSA variables (the ones that appear in decompiled code)
                        DecompInterface decomp = null;
                        try {
                            decomp = new DecompInterface();
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
                                        // hungarianWarnings collected into shared 'warnings' list
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
                                                    // Validate Hungarian prefix against type
                                                    String varType = symbol.getDataType().getName();
                                                    String hw = NamingConventions.validateHungarianPrefix(newName, varType);
                                                    if (hw != null) warnings.add(hw);
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
                        } finally {
                            if (decomp != null) {
                                try { decomp.dispose(); } catch (Exception ignored) {}
                            }
                        }
                    }

                    success.set(true);
                } catch (Exception e) {
                    // If batch operation fails, try individual operations as fallback
                    Msg.warn(this, "Batch rename variables failed, attempting individual operations: " + e.getMessage());
                    try {
                        // Try individual operations (transactions will be closed in finally)
                        Response individualResult = batchRenameVariablesIndividual(functionAddress, variableRenames, programName);
                        fallbackResult.set(individualResult.toJson());
                    } catch (Exception fallbackE) {
                        errorRef.set("Batch operation failed and fallback also failed: " + e.getMessage());
                        Msg.error(this, "Both batch and individual rename operations failed", e);
                    }
                } finally {
                    // ALWAYS close transactions — nested transactions must be closed inner-first
                    program.endTransaction(eventTx, success.get());
                    program.flushEvents();
                    program.endTransaction(tx, success.get());

                    // Invalidate decompiler cache after successful renames
                    if (success.get() && variablesRenamed.get() > 0 && funcRef.get() != null) {
                        try {
                            DecompInterface tempDecomp = null;
                            try {
                                tempDecomp = new DecompInterface();
                                tempDecomp.openProgram(program);
                                tempDecomp.flushCache();
                                tempDecomp.decompileFunction(funcRef.get(), DECOMPILE_TIMEOUT_SECONDS, new ConsoleTaskMonitor());
                            } finally {
                                if (tempDecomp != null) {
                                    try { tempDecomp.dispose(); } catch (Exception ignored) {}
                                }
                            }
                            Msg.info(this, "Invalidated decompiler cache after renaming " + variablesRenamed.get() + " variables");
                        } catch (Exception cacheEx) {
                            Msg.warn(this, "Failed to invalidate decompiler cache: " + cacheEx.getMessage());
                        }
                    }
                }
            });

            // Return fallback result if used
            if (fallbackResult.get() != null) {
                return Response.text(fallbackResult.get());
            }

            if (errorRef.get() != null) {
                return Response.err(errorRef.get());
            }

            if (success.get()) {
                Map<String, Object> resultMap = new LinkedHashMap<>();
                resultMap.put("success", true);
                resultMap.put("method", "batch");
                resultMap.put("variables_renamed", variablesRenamed.get());
                resultMap.put("variables_failed", variablesFailed.get());
                if (!errors.isEmpty()) {
                    resultMap.put("errors", errors);
                }
                if (!warnings.isEmpty()) {
                    resultMap.put("warnings", warnings);
                }
                return Response.ok(resultMap);
            }

            return Response.err("Unknown failure");
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    public Response batchRenameVariables(String functionAddress, Map<String, String> variableRenames, boolean forceIndividual) {
        return batchRenameVariables(functionAddress, variableRenames, forceIndividual, null);
    }

    @McpTool(path = "/set_variables", method = "POST",
            description = "Set types and names for multiple variables atomically. Types are applied first, then renames, in a single transaction. "
                        + "Hungarian prefix validation is enforced: the new name's prefix must match the type. "
                        + "On programs with multiple address spaces, prefix addresses with the space name.",
            category = "function")
    public Response setVariables(
            @Param(value = "function_address", paramType = "address", source = ParamSource.BODY,
                   description = "Function entry point address") String functionAddress,
            @Param(value = "variables", source = ParamSource.BODY,
                   description = "JSON object mapping old variable names to {name, type} objects. "
                               + "Both fields optional: omit 'type' to rename only, omit 'name' to retype only. "
                               + "Example: {\"local_8\": {\"name\": \"dwFlags\", \"type\": \"uint\"}, \"local_c\": {\"type\": \"int\"}}") String variablesJson,
            @Param(value = "program") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        Address addr = ServiceUtils.parseAddress(program, functionAddress);
        if (addr == null) return Response.err(ServiceUtils.getLastParseError());

        // Parse the variables JSON into a map of oldName -> {name?, type?}.
        // Tolerant of three worker shapes:
        //   1. {"local_8": {"name": "dwFlags", "type": "uint"}}  (canonical)
        //   2. {"local_8": "dwFlags"}                              (rename-only)
        //   3. {"local_8": ["dwFlags", "uint"]}                    (positional)
        // Anything else gets a structured error explaining the canonical shape
        // — workers in production logs hit the cast at oldName→ArrayList /
        //   oldName→String paths and the cryptic "cannot be cast" message
        //   was unrecoverable.
        Map<String, Map<String, String>> variables;
        try {
            Object rawParsed;
            // variablesJson can arrive as either a JSON-encoded string OR an
            // already-parsed object/array. parseJson handles the string case;
            // for non-string raw input we already have it.
            try {
                rawParsed = JsonHelper.parseJson(variablesJson);
            } catch (Exception ignored) {
                rawParsed = variablesJson;
            }
            if (!(rawParsed instanceof Map)) {
                return Response.err("variables must be a JSON object mapping oldName to "
                        + "{name?, type?}. Got: " + rawParsed.getClass().getSimpleName()
                        + ". Example: {\"local_8\": {\"name\": \"dwFlags\", \"type\": \"uint\"}, "
                        + "\"local_c\": {\"type\": \"int\"}}");
            }
            @SuppressWarnings("unchecked")
            Map<String, Object> raw = (Map<String, Object>) rawParsed;
            variables = new LinkedHashMap<>();
            for (Map.Entry<String, Object> entry : raw.entrySet()) {
                Object value = entry.getValue();
                Map<String, String> spec = new LinkedHashMap<>();
                if (value instanceof Map<?, ?> mapVal) {
                    if (mapVal.containsKey("name")) spec.put("name", String.valueOf(mapVal.get("name")));
                    if (mapVal.containsKey("type")) spec.put("type", String.valueOf(mapVal.get("type")));
                } else if (value instanceof String strVal) {
                    // Shape 2: {"local_8": "dwFlags"} — rename-only shorthand.
                    if (!strVal.isEmpty()) spec.put("name", strVal);
                } else if (value instanceof List<?> listVal) {
                    // Shape 3: {"local_8": ["dwFlags", "uint"]} — positional.
                    if (listVal.size() >= 1 && listVal.get(0) != null) {
                        spec.put("name", String.valueOf(listVal.get(0)));
                    }
                    if (listVal.size() >= 2 && listVal.get(1) != null) {
                        spec.put("type", String.valueOf(listVal.get(1)));
                    }
                } else if (value != null) {
                    return Response.err("variables['" + entry.getKey() + "'] must be an object "
                            + "({\"name\": ..., \"type\": ...}), a string (rename-only), or a "
                            + "[name, type] array. Got: " + value.getClass().getSimpleName()
                            + ". Example: {\"" + entry.getKey() + "\": {\"name\": \"dwFlags\", \"type\": \"uint\"}}");
                }
                variables.put(entry.getKey(), spec);
            }
        } catch (Exception e) {
            return Response.err("Invalid variables JSON: " + e.getMessage()
                    + ". Expected: {\"local_8\": {\"name\": \"dwFlags\", \"type\": \"uint\"}}");
        }

        // Empty variables map is a no-op success — matches set_global's convention.
        // Workers reach this state when their analysis concludes nothing needs
        // changing; rejecting forces error-handling that the worker can't recover
        // from. Returning a success-shaped no-op lets the worker move on.
        if (variables.isEmpty()) {
            return Response.ok(JsonHelper.mapOf(
                "success", true,
                "types_set", 0,
                "names_set", 0,
                "failed", 0,
                "message", "No variables to set (empty payload)"));
        }

        final AtomicInteger typesSet = new AtomicInteger(0);
        final AtomicInteger namesSet = new AtomicInteger(0);
        final AtomicInteger failed = new AtomicInteger(0);
        final List<String> warnings = new ArrayList<>();
        final List<String> errors = new ArrayList<>();
        final AtomicReference<String> errorRef = new AtomicReference<>(null);

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Set Variables");
                try {
                    Function func = program.getFunctionManager().getFunctionAt(addr);
                    if (func == null) {
                        errorRef.set("No function at address: " + functionAddress);
                        return;
                    }

                    // Phase 1: Set types
                    for (Map.Entry<String, Map<String, String>> entry : variables.entrySet()) {
                        String oldName = entry.getKey();
                        String newType = entry.getValue().get("type");
                        if (newType == null) continue;

                        // Find the variable
                        Variable target = null;
                        for (Variable v : func.getLocalVariables()) {
                            if (v.getName().equals(oldName)) { target = v; break; }
                        }
                        if (target == null) {
                            for (Parameter p : func.getParameters()) {
                                if (p.getName().equals(oldName)) { target = p; break; }
                            }
                        }
                        if (target == null) {
                            errors.add("Variable not found: " + oldName);
                            failed.incrementAndGet();
                            continue;
                        }

                        // Reject undefined -> undefined
                        String oldType = target.getDataType().getName();
                        if (NamingConventions.isUndefinedToUndefined(oldType, newType)) {
                            errors.add("Rejected: " + oldName + " type " + oldType + " -> " + newType + " (still undefined)");
                            failed.incrementAndGet();
                            continue;
                        }

                        try {
                            DataType dt = ServiceUtils.resolveDataType(program.getDataTypeManager(), newType);
                            if (dt == null) {
                                errors.add("Unknown type '" + newType + "' for " + oldName);
                                failed.incrementAndGet();
                                continue;
                            }
                            target.setDataType(dt, SourceType.USER_DEFINED);
                            typesSet.incrementAndGet();
                        } catch (Exception e) {
                            errors.add("Failed to set type on " + oldName + ": " + e.getMessage());
                            failed.incrementAndGet();
                        }
                    }

                    // Phase 2: Decompile to get fresh SSA variables for renaming
                    DecompInterface decomp = null;
                    try {
                        decomp = new DecompInterface();
                        decomp.openProgram(program);
                        DecompileResults decompResult = decomp.decompileFunction(func, DECOMPILE_TIMEOUT_SECONDS, new ConsoleTaskMonitor());
                        if (decompResult == null || !decompResult.decompileCompleted()) {
                            errors.add("Decompilation failed after type changes; renames skipped");
                            return;
                        }
                        HighFunction highFunction = decompResult.getHighFunction();
                        if (highFunction == null) {
                            errors.add("No HighFunction after decompile; renames skipped");
                            return;
                        }

                        // Commit params if needed
                        LocalSymbolMap localSymbolMap = highFunction.getLocalSymbolMap();
                        Iterator<HighSymbol> checkSymbols = localSymbolMap.getSymbols();
                        if (checkSymbols.hasNext()) {
                            HighSymbol first = checkSymbols.next();
                            if (checkFullCommit(first, highFunction)) {
                                HighFunctionDBUtil.commitParamsToDatabase(highFunction, false,
                                        ReturnCommitOption.NO_COMMIT, func.getSignatureSource());
                            }
                        }

                        // Phase 3a: Rename via HighSymbol (decompiler-visible variables).
                        // This is the primary path for SSA temporaries (iVar*, psVar*, etc.)
                        // and for register-backed parameters/locals.
                        Set<String> renamedHere = new HashSet<>();
                        Iterator<HighSymbol> symbols = localSymbolMap.getSymbols();
                        while (symbols.hasNext()) {
                            HighSymbol symbol = symbols.next();
                            String currentName = symbol.getName();
                            Map<String, String> spec = variables.get(currentName);
                            if (spec == null || !spec.containsKey("name")) continue;

                            String newName = spec.get("name");
                            if (newName == null || newName.isEmpty() || newName.equals(currentName)) continue;

                            // Validate Hungarian prefix against actual type
                            String actualType = symbol.getDataType().getName();
                            String hungarianWarning = NamingConventions.validateHungarianPrefix(newName, actualType);
                            if (hungarianWarning != null) {
                                warnings.add(hungarianWarning);
                            }

                            try {
                                HighFunctionDBUtil.updateDBVariable(symbol, newName, null, SourceType.USER_DEFINED);
                                namesSet.incrementAndGet();
                                renamedHere.add(currentName);
                            } catch (Exception e) {
                                errors.add("Failed to rename " + currentName + " -> " + newName + ": " + e.getMessage());
                                failed.incrementAndGet();
                            }
                        }

                        // Phase 3b: Storage-based fallback. Stack-frame-only variables
                        // (local_4, local_148, etc.) are not promoted to HighSymbol
                        // form — they live only in func.getAllVariables(). Without
                        // this fallback, a worker calling set_variables with
                        // {local_4: {name: nStackDepth, ...}} sees types_set++ but
                        // names_set silently stays at zero, then fails subsequent
                        // calls with "Variable not found: nStackDepth".
                        try {
                            for (Variable lowVar : func.getAllVariables()) {
                                String oldName = lowVar.getName();
                                if (renamedHere.contains(oldName)) continue;
                                Map<String, String> spec = variables.get(oldName);
                                if (spec == null || !spec.containsKey("name")) continue;
                                String newName = spec.get("name");
                                if (newName == null || newName.isEmpty() || newName.equals(oldName)) continue;
                                try {
                                    lowVar.setName(newName, SourceType.USER_DEFINED);
                                    namesSet.incrementAndGet();
                                    renamedHere.add(oldName);
                                } catch (Exception e) {
                                    errors.add("Failed to rename storage variable " + oldName + " -> " + newName + ": " + e.getMessage());
                                    failed.incrementAndGet();
                                }
                            }
                        } catch (Exception e) {
                            Msg.warn(this, "set_variables storage-rename fallback encountered error: " + e.getMessage());
                        }

                        // Phase 3c: Caller-visibility — surface any rename specs
                        // that matched neither path so workers can tell at a
                        // glance that part of their request didn't apply.
                        for (Map.Entry<String, Map<String, String>> e : variables.entrySet()) {
                            String oldName = e.getKey();
                            Map<String, String> spec = e.getValue();
                            if (!spec.containsKey("name")) continue;
                            String requestedNew = spec.get("name");
                            if (requestedNew == null || requestedNew.isEmpty() || requestedNew.equals(oldName)) continue;
                            if (!renamedHere.contains(oldName)) {
                                errors.add("Rename spec for '" + oldName + "' matched no high-level or storage variable; "
                                        + "name unchanged. Re-fetch with get_function_variables before retrying.");
                                failed.incrementAndGet();
                            }
                        }
                    } finally {
                        if (decomp != null) {
                            try { decomp.dispose(); } catch (Exception ignored) {}
                        }
                    }
                } catch (Exception e) {
                    errorRef.set(e.getMessage());
                } finally {
                    program.endTransaction(tx, errorRef.get() == null);
                }
            });
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }

        if (errorRef.get() != null) return Response.err(errorRef.get());

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("success", true);
        result.put("types_set", typesSet.get());
        result.put("names_set", namesSet.get());
        result.put("failed", failed.get());
        if (!warnings.isEmpty()) result.put("warnings", warnings);
        if (!errors.isEmpty()) result.put("errors", errors);
        return Response.ok(result);
    }

    /**
     * Individual variable renaming using HighFunctionDBUtil (fallback method).
     * This method uses decompilation but is more reliable for persistence.
     */
    public Response batchRenameVariablesIndividual(String functionAddress, Map<String, String> variableRenames, String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        // Resolve address before entering SwingUtilities lambda
        Address addr = ServiceUtils.parseAddress(program, functionAddress);
        if (addr == null) return Response.err(ServiceUtils.getLastParseError());

        final AtomicInteger variablesRenamed = new AtomicInteger(0);
        final AtomicInteger variablesFailed = new AtomicInteger(0);
        final List<String> errors = new ArrayList<>();

        // Get function name for individual operations
        final String[] functionName = new String[1];
        try {
            SwingUtilities.invokeAndWait(() -> {
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
                Response renameResult = renameVariableInFunction(functionName[0], oldName, newName, programName);
                String resultText = renameResult.toJson();
                if (resultText.equals("Variable renamed")) {
                    variablesRenamed.incrementAndGet();
                } else {
                    variablesFailed.incrementAndGet();
                    errors.add("Failed to rename '" + oldName + "' to '" + newName + "': " + resultText);
                }
            } catch (Exception e) {
                variablesFailed.incrementAndGet();
                errors.add("Exception renaming '" + oldName + "' to '" + newName + "': " + e.getMessage());
            }
        }

        Map<String, Object> resultMap = new LinkedHashMap<>();
        resultMap.put("success", true);
        resultMap.put("method", "individual");
        resultMap.put("variables_renamed", variablesRenamed.get());
        resultMap.put("variables_failed", variablesFailed.get());
        if (!errors.isEmpty()) {
            resultMap.put("errors", errors);
        }
        return Response.ok(resultMap);
    }

    public Response batchRenameVariablesIndividual(String functionAddress, Map<String, String> variableRenames) {
        return batchRenameVariablesIndividual(functionAddress, variableRenames, null);
    }

    /**
     * Validate that batch operations actually persisted by checking current state.
     */
    public Response validateBatchOperationResults(String functionAddress, Map<String, String> expectedRenames, Map<String, String> expectedTypes, String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        // Resolve address before entering SwingUtilities lambda
        Address addr = ServiceUtils.parseAddress(program, functionAddress);
        if (addr == null) return Response.err(ServiceUtils.getLastParseError());

        final AtomicReference<Map<String, Object>> resultData = new AtomicReference<>(null);
        final AtomicReference<String> errorRef = new AtomicReference<>(null);

        try {
            SwingUtilities.invokeAndWait(() -> {
                try {

                    Function func = program.getFunctionManager().getFunctionAt(addr);
                    if (func == null) {
                        errorRef.set("No function at address: " + functionAddress);
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

                    Map<String, Object> data = new LinkedHashMap<>();
                    data.put("success", true);
                    data.put("renames_validated", renamesValidated);
                    data.put("types_validated", typesValidated);
                    if (!validationErrors.isEmpty()) {
                        data.put("validation_errors", validationErrors);
                    }
                    resultData.set(data);

                } catch (Exception e) {
                    errorRef.set(e.getMessage());
                    Msg.error(this, "Error validating batch operations", e);
                }
            });
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }

        if (errorRef.get() != null) {
            return Response.err(errorRef.get());
        }
        if (resultData.get() != null) {
            return Response.ok(resultData.get());
        }
        return Response.err("Unknown failure");
    }

    public Response validateBatchOperationResults(String functionAddress, Map<String, String> expectedRenames, Map<String, String> expectedTypes) {
        return validateBatchOperationResults(functionAddress, expectedRenames, expectedTypes, null);
    }
}
