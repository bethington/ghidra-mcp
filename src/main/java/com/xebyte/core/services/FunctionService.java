/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.xebyte.core.services;

import com.google.gson.JsonObject;
import com.xebyte.core.JsonHelper;
import com.xebyte.core.ProgramProvider;
import com.xebyte.core.Response;
import com.xebyte.core.ThreadingStrategy;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Shared service for function analysis endpoints.
 *
 * Handles decompile, disassemble, call graph (callees/callers), function variables,
 * analyze_function_complete, force_decompile, and find_next_undefined_function.
 */
public class FunctionService extends BaseService {

    private static final int DECOMPILE_TIMEOUT_SECONDS = 60;

    public FunctionService(ProgramProvider programProvider, ThreadingStrategy threadingStrategy) {
        super(programProvider, threadingStrategy);
    }

    // =========================================================================
    // GETTER ENDPOINTS
    // =========================================================================

    /**
     * Get function info at a specific address.
     * Endpoint: /get_function_by_address
     */
    public Response getFunctionByAddress(String addressStr, String programName) {
        Program program = resolveProgram(programName);
        if (program == null) {
            return programNotFoundError(programName);
        }

        Address addr = parseAddress(program, addressStr);
        if (addr == null) {
            return Response.err("Invalid address: " + addressStr);
        }

        Function func = program.getFunctionManager().getFunctionAt(addr);
        if (func == null) {
            func = program.getFunctionManager().getFunctionContaining(addr);
        }

        if (func == null) {
            return Response.err("No function found at address: " + addressStr);
        }

        Map<String, String> info = new LinkedHashMap<>();
        info.put("name", func.getName());
        info.put("address", func.getEntryPoint().toString());
        info.put("signature", func.getSignature().getPrototypeString());
        info.put("calling_convention", func.getCallingConventionName());
        return Response.ok(info);
    }

    // =========================================================================
    // DECOMPILE / DISASSEMBLE ENDPOINTS
    // =========================================================================

    /**
     * Decompile a function by address or name.
     * Endpoint: /decompile_function
     */
    public Response decompileFunction(String addressStr, String name, String programName) {
        Program program = resolveProgram(programName);
        if (program == null) {
            return programNotFoundError(programName);
        }

        Function func = resolveFunction(program, addressStr, name);
        if (func == null) {
            return Response.err("Function not found");
        }

        try {
            DecompInterface decompiler = new DecompInterface();
            decompiler.openProgram(program);

            DecompileResults results = decompiler.decompileFunction(func, DECOMPILE_TIMEOUT_SECONDS, monitor);

            if (results == null || !results.decompileCompleted()) {
                String errorMsg = results != null ? results.getErrorMessage() : "Unknown error";
                return Response.err("Decompilation failed - " + errorMsg);
            }

            String decompiled = results.getDecompiledFunction().getC();
            decompiler.dispose();

            return decompiled != null ? Response.text(decompiled) : Response.err("No decompiled output");

        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    /**
     * Disassemble a function at an address.
     * Endpoint: /disassemble_function
     */
    public Response disassembleFunction(String addressStr, String programName) {
        Program program = resolveProgram(programName);
        if (program == null) {
            return programNotFoundError(programName);
        }

        Address addr = parseAddress(program, addressStr);
        if (addr == null) {
            return Response.err("Invalid address: " + addressStr);
        }

        Function func = program.getFunctionManager().getFunctionAt(addr);
        if (func == null) {
            func = program.getFunctionManager().getFunctionContaining(addr);
        }

        if (func == null) {
            return Response.err("No function found at address: " + addressStr);
        }

        List<String> lines = new ArrayList<>();
        Listing listing = program.getListing();
        InstructionIterator iter = listing.getInstructions(func.getBody(), true);

        while (iter.hasNext()) {
            Instruction inst = iter.next();
            String comment = inst.getComment(CodeUnit.EOL_COMMENT);
            String line = inst.getAddress() + ": " + inst.toString();
            if (comment != null && !comment.isEmpty()) {
                line += " ; " + comment;
            }
            lines.add(line);
        }

        return Response.text(String.join("\n", lines));
    }

    /**
     * Force re-decompilation of a function (bypasses cache).
     * Endpoint: /force_decompile
     */
    public Response forceDecompile(String address, String name, String programName) {
        Program program = resolveProgram(programName);
        if (program == null) {
            return programNotFoundError(programName);
        }

        Function func = resolveFunction(program, address, name);
        if (func == null) {
            return Response.err("Function not found");
        }

        DecompInterface decompiler = new DecompInterface();
        try {
            decompiler.openProgram(program);
            DecompileResults results = decompiler.decompileFunction(func, DECOMPILE_TIMEOUT_SECONDS, monitor);

            if (results == null || !results.decompileCompleted()) {
                return Response.err("Decompilation failed");
            }

            String code = results.getDecompiledFunction().getC();
            return code != null ? Response.text(code) : Response.err("No decompiled code available");
        } finally {
            decompiler.dispose();
        }
    }

    // =========================================================================
    // CALL GRAPH ENDPOINTS
    // =========================================================================

    /**
     * Get all functions called by a function (callees).
     * Endpoint: /get_function_callees
     */
    public Response getFunctionCallees(String functionName, int offset, int limit, String programName) {
        Program program = resolveProgram(programName);
        if (program == null) {
            return programNotFoundError(programName);
        }

        if (functionName == null || functionName.isEmpty()) {
            return Response.err("Function name is required");
        }

        Function func = findFunctionByName(program, functionName);
        if (func == null) {
            return Response.err("Function not found: " + functionName);
        }

        Set<Function> callees = new LinkedHashSet<>();
        ReferenceManager refMgr = program.getReferenceManager();
        FunctionManager funcMgr = program.getFunctionManager();
        InstructionIterator instrs = program.getListing().getInstructions(func.getBody(), true);

        while (instrs.hasNext()) {
            Instruction instr = instrs.next();
            if (instr.getFlowType().isCall()) {
                for (Reference ref : refMgr.getReferencesFrom(instr.getAddress())) {
                    if (ref.getReferenceType().isCall()) {
                        Function target = funcMgr.getFunctionAt(ref.getToAddress());
                        if (target != null) {
                            callees.add(target);
                        }
                    }
                }
            }
        }

        List<String> results = callees.stream()
            .map(f -> f.getName() + " @ " + f.getEntryPoint())
            .collect(Collectors.toList());

        return paginateList(results, offset, limit);
    }

    /**
     * Get all functions that call a function (callers).
     * Endpoint: /get_function_callers
     */
    public Response getFunctionCallers(String functionName, int offset, int limit, String programName) {
        Program program = resolveProgram(programName);
        if (program == null) {
            return programNotFoundError(programName);
        }

        if (functionName == null || functionName.isEmpty()) {
            return Response.err("Function name is required");
        }

        Function func = findFunctionByName(program, functionName);
        if (func == null) {
            return Response.err("Function not found: " + functionName);
        }

        Set<Function> callers = new LinkedHashSet<>();
        ReferenceManager refMgr = program.getReferenceManager();
        FunctionManager funcMgr = program.getFunctionManager();
        ReferenceIterator refs = refMgr.getReferencesTo(func.getEntryPoint());

        while (refs.hasNext()) {
            Reference ref = refs.next();
            if (ref.getReferenceType().isCall()) {
                Function caller = funcMgr.getFunctionContaining(ref.getFromAddress());
                if (caller != null) {
                    callers.add(caller);
                }
            }
        }

        List<String> results = callers.stream()
            .map(f -> f.getName() + " @ " + f.getEntryPoint())
            .collect(Collectors.toList());

        return paginateList(results, offset, limit);
    }

    // =========================================================================
    // VARIABLE ENDPOINTS
    // =========================================================================

    /**
     * Get all variables (parameters and locals) for a function.
     * Endpoint: /get_function_variables
     */
    public Response getFunctionVariables(String functionName, String programName) {
        Program program = resolveProgram(programName);
        if (program == null) {
            return programNotFoundError(programName);
        }

        if (functionName == null || functionName.isEmpty()) {
            return Response.err("Function name is required");
        }

        Function func = findFunctionByName(program, functionName);
        if (func == null) {
            return Response.err("Function not found: " + functionName);
        }

        List<JsonObject> params = new ArrayList<>();
        for (Parameter p : func.getParameters()) {
            JsonObject pObj = new JsonObject();
            pObj.addProperty("name", p.getName());
            pObj.addProperty("type", p.getDataType().getName());
            pObj.addProperty("ordinal", p.getOrdinal());
            pObj.addProperty("storage", p.getVariableStorage().toString());
            params.add(pObj);
        }

        List<JsonObject> locals = new ArrayList<>();
        for (Variable v : func.getLocalVariables()) {
            JsonObject vObj = new JsonObject();
            vObj.addProperty("name", v.getName());
            vObj.addProperty("type", v.getDataType().getName());
            vObj.addProperty("storage", v.getVariableStorage().toString());
            locals.add(vObj);
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("function", func.getName());
        result.put("parameters", params);
        result.put("locals", locals);
        return Response.ok(result);
    }

    // =========================================================================
    // COMPOSITE / SEARCH ENDPOINTS
    // =========================================================================

    /**
     * Comprehensive function analysis in a single call.
     * Endpoint: /analyze_function_complete
     */
    public Response analyzeFunctionComplete(String name, boolean includeXrefs, boolean includeCallees,
                                            boolean includeCallers, boolean includeDisasm,
                                            boolean includeVariables, String programName) {
        Program program = resolveProgram(programName);
        if (program == null) {
            return programNotFoundError(programName);
        }

        Function func = findFunctionByName(program, name);
        if (func == null) {
            return Response.err("Function not found: " + name);
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("name", func.getName());
        result.put("address", func.getEntryPoint().toString());
        result.put("signature", func.getSignature().getPrototypeString());

        // Decompiled code
        Response decompResponse = decompileFunction(null, name, programName);
        result.put("decompiled_code", extractText(decompResponse));

        // Xrefs
        if (includeXrefs) {
            List<Object> xrefs = new ArrayList<>();
            ReferenceManager refMgr = program.getReferenceManager();
            int count = 0;
            for (Reference ref : refMgr.getReferencesTo(func.getEntryPoint())) {
                Map<String, String> xrefEntry = new LinkedHashMap<>();
                xrefEntry.put("from", ref.getFromAddress().toString());
                xrefEntry.put("type", ref.getReferenceType().toString());
                xrefs.add(xrefEntry);
                if (++count >= 50) break;
            }
            result.put("xrefs", xrefs);
        }

        // Callees
        if (includeCallees) {
            result.put("callees", extractLines(getFunctionCallees(name, 0, 50, programName)));
        }

        // Callers
        if (includeCallers) {
            result.put("callers", extractLines(getFunctionCallers(name, 0, 50, programName)));
        }

        // Disassembly
        if (includeDisasm) {
            Response disasmResponse = disassembleFunction(func.getEntryPoint().toString(), programName);
            result.put("disassembly", extractText(disasmResponse));
        }

        // Variables
        if (includeVariables) {
            Response varsResponse = getFunctionVariables(name, programName);
            if (varsResponse instanceof Response.Ok(var data)) {
                result.put("variables", data);
            }
        }

        return Response.ok(result);
    }

    /**
     * Find the next undefined/unnamed function based on criteria.
     * Endpoint: /find_next_undefined_function
     */
    public Response findNextUndefinedFunction(String startAddress, String criteria,
                                              String pattern, String direction, String programName) {
        Program program = resolveProgram(programName);
        if (program == null) {
            return programNotFoundError(programName);
        }

        FunctionManager fm = program.getFunctionManager();
        Address startAddr = null;

        if (startAddress != null && !startAddress.isEmpty()) {
            startAddr = parseAddress(program, startAddress);
        }

        if (startAddr == null) {
            startAddr = program.getMinAddress();
        }

        String searchPattern = (pattern != null && !pattern.isEmpty()) ? pattern : "FUN_";
        boolean ascending = !"descending".equalsIgnoreCase(direction);

        FunctionIterator funcIter = fm.getFunctions(startAddr, ascending);
        while (funcIter.hasNext()) {
            Function func = funcIter.next();
            String funcName = func.getName();

            if (funcName.contains(searchPattern)) {
                Map<String, Object> found = new LinkedHashMap<>();
                found.put("found", true);
                found.put("name", funcName);
                found.put("address", func.getEntryPoint().toString());
                found.put("signature", func.getSignature().getPrototypeString());
                return Response.ok(found);
            }
        }

        return Response.ok(Map.of("found", false));
    }

    // =========================================================================
    // Internal helpers
    // =========================================================================

    /**
     * Find a function by name (linear scan).
     */
    private Function findFunctionByName(Program program, String name) {
        if (name == null || name.isEmpty()) return null;
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            if (f.getName().equals(name)) {
                return f;
            }
        }
        return null;
    }

    /**
     * Resolve a function by address first, then by name.
     */
    private Function resolveFunction(Program program, String addressStr, String name) {
        Function func = null;

        if (addressStr != null && !addressStr.isEmpty()) {
            Address addr = parseAddress(program, addressStr);
            if (addr != null) {
                func = program.getFunctionManager().getFunctionAt(addr);
                if (func == null) {
                    func = program.getFunctionManager().getFunctionContaining(addr);
                }
            }
        }

        if (func == null && name != null && !name.isEmpty()) {
            func = findFunctionByName(program, name);
        }

        return func;
    }

    /** Extract text content from a Response, returning error message if not text/ok. */
    private String extractText(Response response) {
        return switch (response) {
            case Response.Text(var content) -> content;
            case Response.Err(var message) -> "Error: " + message;
            case Response.Ok(var data) -> data.toString();
        };
    }

    /** Extract newline-delimited text as a list of non-empty strings. */
    private List<String> extractLines(Response response) {
        String text = extractText(response);
        if (text == null || text.isEmpty()) return List.of();
        return Arrays.stream(text.split("\n"))
            .filter(line -> !line.isEmpty())
            .collect(Collectors.toList());
    }
}
