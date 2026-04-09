package com.xebyte.core;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

import java.util.*;

/**
 * Service for cross-reference and call graph operations: xrefs to/from, function callees/callers,
 * call graph traversal, cycle detection, path finding, and bulk xref analysis.
 * Extracted from GhidraMCPPlugin as part of v4.0.0 refactor.
 */
@McpToolGroup(value = "xref", description = "Cross-references, call graphs, incoming/outgoing calls, data refs")
public class XrefCallGraphService {

    private final ProgramProvider programProvider;
    private final ThreadingStrategy threadingStrategy;

    public XrefCallGraphService(ProgramProvider programProvider, ThreadingStrategy threadingStrategy) {
        this.programProvider = programProvider;
        this.threadingStrategy = threadingStrategy;
    }

    // -----------------------------------------------------------------------
    // Xref Methods
    // -----------------------------------------------------------------------

    /**
     * Get all references to a specific address (xref to)
     */
    @McpTool(path = "/get_xrefs_to", description = "Get cross-references to an address. On programs with multiple address spaces (e.g., embedded targets), prefix addresses with the space name (mem:1000) to avoid ambiguous resolution.", category = "xref")
    public Response getXrefsTo(
            @Param(value = "address", paramType = "address",
                   description = "Address in the program. Accepts 0x<hex> (default space) or <space>:<hex> "
                               + "(e.g., mem:1000, code:ff00). Note: some programs — particularly "
                               + "embedded/microcontroller targets — are not address-space-agnostic; "
                               + "use get_address_spaces to discover spaces before assuming a plain hex "
                               + "address is unambiguous.") String addressStr,
            @Param(value = "offset", defaultValue = "0") int offset,
            @Param(value = "limit", defaultValue = "100") int limit,
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();
        if (addressStr == null || addressStr.isEmpty()) return Response.err("Address is required");

        try {
            Address addr = ServiceUtils.parseAddress(program, addressStr);
            if (addr == null) return Response.err(ServiceUtils.getLastParseError());
            ReferenceManager refManager = program.getReferenceManager();

            ReferenceIterator refIter = refManager.getReferencesTo(addr);

            List<String> refs = new ArrayList<>();
            while (refIter.hasNext()) {
                Reference ref = refIter.next();
                Address fromAddr = ref.getFromAddress();
                RefType refType = ref.getReferenceType();

                Function fromFunc = program.getFunctionManager().getFunctionContaining(fromAddr);
                String funcInfo = (fromFunc != null) ? " in " + fromFunc.getName() : "";

                refs.add(String.format("From %s%s [%s]", fromAddr, funcInfo, refType.getName()));
            }

            // Return meaningful message if no references found
            if (refs.isEmpty()) {
                return Response.text("No references found to address: " + addressStr);
            }

            return Response.text(ServiceUtils.paginateList(refs, offset, limit));
        } catch (Exception e) {
            return Response.err("Error getting references to address: " + e.getMessage());
        }
    }

    /**
     * Get all references from a specific address (xref from)
     */
    @McpTool(path = "/get_xrefs_from", description = "Get cross-references from an address. On programs with multiple address spaces (e.g., embedded targets), prefix addresses with the space name (mem:1000) to avoid ambiguous resolution.", category = "xref")
    public Response getXrefsFrom(
            @Param(value = "address", paramType = "address",
                   description = "Address in the program. Accepts 0x<hex> (default space) or <space>:<hex> "
                               + "(e.g., mem:1000, code:ff00). Note: some programs — particularly "
                               + "embedded/microcontroller targets — are not address-space-agnostic; "
                               + "use get_address_spaces to discover spaces before assuming a plain hex "
                               + "address is unambiguous.") String addressStr,
            @Param(value = "offset", defaultValue = "0") int offset,
            @Param(value = "limit", defaultValue = "100") int limit,
            @Param(value = "program", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();
        if (addressStr == null || addressStr.isEmpty()) return Response.err("Address is required");

        try {
            Address addr = ServiceUtils.parseAddress(program, addressStr);
            if (addr == null) return Response.err(ServiceUtils.getLastParseError());
            ReferenceManager refManager = program.getReferenceManager();

            Reference[] references = refManager.getReferencesFrom(addr);

            List<String> refs = new ArrayList<>();
            for (Reference ref : references) {
                Address toAddr = ref.getToAddress();
                RefType refType = ref.getReferenceType();

                String targetInfo = "";
                Function toFunc = program.getFunctionManager().getFunctionAt(toAddr);
                if (toFunc != null) {
                    targetInfo = " to function " + toFunc.getName();
                } else {
                    Data data = program.getListing().getDataAt(toAddr);
                    if (data != null) {
                        targetInfo = " to data " + (data.getLabel() != null ? data.getLabel() : data.getPathName());
                    }
                }

                refs.add(String.format("To %s%s [%s]", toAddr, targetInfo, refType.getName()));
            }

            // Return meaningful message if no references found
            if (refs.isEmpty()) {
                return Response.text("No references found from address: " + addressStr);
            }

            return Response.text(ServiceUtils.paginateList(refs, offset, limit));
        } catch (Exception e) {
            return Response.err("Error getting references from address: " + e.getMessage());
        }
    }

    /**
     * Get all references to a specific function by name
     */
    @McpTool(path = "/get_function_xrefs", description = "Get cross-references to a function. Accepts function name or address (pass address as 'address' param, or as 'name').", category = "xref")
    public Response getFunctionXrefs(
            @Param(value = "name", defaultValue = "", description = "Function name") String functionName,
            @Param(value = "address", defaultValue = "", description = "Function entry-point address (hex) — alternative to name") String address,
            @Param(value = "offset", defaultValue = "0") int offset,
            @Param(value = "limit", defaultValue = "100") int limit,
            @Param(value = "program", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        try {
            FunctionRef.Result resolved = FunctionRef.ofNameOrAddress(functionName, address).tryResolve(program);
            if (!resolved.isSuccess()) return Response.text("No references found to function: " + functionName);
            Function function = resolved.function();

            List<String> refs = new ArrayList<>();
            FunctionManager funcManager = program.getFunctionManager();
            Address entryPoint = function.getEntryPoint();
            ReferenceIterator refIter = program.getReferenceManager().getReferencesTo(entryPoint);

            while (refIter.hasNext()) {
                Reference ref = refIter.next();
                Address fromAddr = ref.getFromAddress();
                RefType refType = ref.getReferenceType();

                Function fromFunc = funcManager.getFunctionContaining(fromAddr);
                String funcInfo = (fromFunc != null) ? " in " + fromFunc.getName() : "";

                refs.add(String.format("From %s%s [%s]", fromAddr, funcInfo, refType.getName()));
            }

            if (refs.isEmpty()) {
                return Response.text("No references found to function: " + functionName);
            }

            return Response.text(ServiceUtils.paginateList(refs, offset, limit));
        } catch (Exception e) {
            return Response.err("Error getting function references: " + e.getMessage());
        }
    }

    // -----------------------------------------------------------------------
    // Jump Target Methods
    // -----------------------------------------------------------------------

    /**
     * Get all jump target addresses from a function's disassembly
     */
    public Response getFunctionJumpTargets(String functionName, int offset, int limit) {
        return getFunctionJumpTargets(functionName, null, offset, limit, null);
    }

    @McpTool(path = "/get_function_jump_targets", description = "Get jump targets within a function. Accepts function name or address.", category = "xref")
    public Response getFunctionJumpTargets(
            @Param(value = "name", defaultValue = "", description = "Function name") String functionName,
            @Param(value = "address", defaultValue = "", description = "Function entry-point address (hex) — alternative to name") String address,
            @Param(value = "offset", defaultValue = "0") int offset,
            @Param(value = "limit", defaultValue = "100") int limit,
            @Param(value = "program", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        StringBuilder sb = new StringBuilder();
        FunctionManager functionManager = program.getFunctionManager();

        // Find the function by name or address
        FunctionRef.Result resolved = FunctionRef.ofNameOrAddress(functionName, address).tryResolve(program);
        if (!resolved.isSuccess()) {
            return Response.text("Function not found: " + functionName);
        }
        Function function = resolved.function();

        AddressSetView functionBody = function.getBody();
        Listing listing = program.getListing();
        Set<Address> jumpTargets = new HashSet<>();

        // Iterate through all instructions in the function
        InstructionIterator instructions = listing.getInstructions(functionBody, true);
        while (instructions.hasNext()) {
            Instruction instr = instructions.next();

            // Check if this is a jump instruction
            if (instr.getFlowType().isJump()) {
                // Get all reference addresses from this instruction
                Reference[] references = instr.getReferencesFrom();
                for (Reference ref : references) {
                    Address targetAddr = ref.getToAddress();
                    // Only include targets within the function or program space
                    if (targetAddr != null && program.getMemory().contains(targetAddr)) {
                        jumpTargets.add(targetAddr);
                    }
                }

                // Also check for fall-through addresses for conditional jumps
                if (instr.getFlowType().isConditional()) {
                    Address fallThroughAddr = instr.getFallThrough();
                    if (fallThroughAddr != null) {
                        jumpTargets.add(fallThroughAddr);
                    }
                }
            }
        }

        // Convert to sorted list and apply pagination
        List<Address> sortedTargets = new ArrayList<>(jumpTargets);
        Collections.sort(sortedTargets);

        int count = 0;
        int skipped = 0;

        for (Address target : sortedTargets) {
            if (count >= limit) break;

            if (skipped < offset) {
                skipped++;
                continue;
            }

            if (sb.length() > 0) {
                sb.append("\n");
            }

            // Add context about what's at this address
            String context = "";
            Function targetFunc = functionManager.getFunctionContaining(target);
            if (targetFunc != null) {
                context = " (in " + targetFunc.getName() + ")";
            } else {
                // Check if there's a label at this address
                Symbol symbol = program.getSymbolTable().getPrimarySymbol(target);
                if (symbol != null) {
                    context = " (" + symbol.getName() + ")";
                }
            }

            sb.append(target.toString()).append(context);
            count++;
        }

        if (sb.length() == 0) {
            return Response.text("No jump targets found in function: " + functionName);
        }

        return Response.text(sb.toString());
    }

    // -----------------------------------------------------------------------
    // Callee/Caller Methods
    // -----------------------------------------------------------------------

    /**
     * Get all functions called by the specified function (callees)
     */
    @McpTool(path = "/get_function_callees", description = "Get functions called by a function. Accepts function name or address.", category = "xref")
    public Response getFunctionCallees(
            @Param(value = "name", defaultValue = "", description = "Function name") String functionName,
            @Param(value = "address", defaultValue = "", description = "Function entry-point address (hex) — alternative to name") String address,
            @Param(value = "offset", defaultValue = "0") int offset,
            @Param(value = "limit", defaultValue = "100") int limit,
            @Param(value = "program", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        StringBuilder sb = new StringBuilder();
        FunctionManager functionManager = program.getFunctionManager();

        // Find the function by name or address
        FunctionRef.Result resolved = FunctionRef.ofNameOrAddress(functionName, address).tryResolve(program);
        if (!resolved.isSuccess()) {
            return Response.text("Function not found: " + functionName);
        }
        Function function = resolved.function();

        Set<Function> callees = new HashSet<>();
        AddressSetView functionBody = function.getBody();
        Listing listing = program.getListing();
        ReferenceManager refManager = program.getReferenceManager();

        // Iterate through all instructions in the function
        InstructionIterator instructions = listing.getInstructions(functionBody, true);
        while (instructions.hasNext()) {
            Instruction instr = instructions.next();

            // Check if this is a call instruction
            if (instr.getFlowType().isCall()) {
                // Get all reference addresses from this instruction
                Reference[] references = refManager.getReferencesFrom(instr.getAddress());
                for (Reference ref : references) {
                    if (ref.getReferenceType().isCall()) {
                        Address targetAddr = ref.getToAddress();
                        Function targetFunc = functionManager.getFunctionAt(targetAddr);
                        if (targetFunc != null) {
                            callees.add(targetFunc);
                        }
                    }
                }
            }
        }

        // Convert to sorted list and apply pagination
        List<Function> sortedCallees = new ArrayList<>(callees);
        sortedCallees.sort((f1, f2) -> f1.getName().compareTo(f2.getName()));

        int count = 0;
        int skipped = 0;

        for (Function callee : sortedCallees) {
            if (count >= limit) break;

            if (skipped < offset) {
                skipped++;
                continue;
            }

            if (sb.length() > 0) {
                sb.append("\n");
            }

            sb.append(String.format("%s @ %s", callee.getName(), callee.getEntryPoint()));
            count++;
        }

        if (sb.length() == 0) {
            return Response.text("No callees found for function: " + functionName);
        }

        return Response.text(sb.toString());
    }

    /**
     * Get all functions that call the specified function (callers)
     */
    @McpTool(path = "/get_function_callers", description = "Get functions calling a function. Accepts function name or address.", category = "xref")
    public Response getFunctionCallers(
            @Param(value = "name", defaultValue = "", description = "Function name") String functionName,
            @Param(value = "address", defaultValue = "", description = "Function entry-point address (hex) — alternative to name") String address,
            @Param(value = "offset", defaultValue = "0") int offset,
            @Param(value = "limit", defaultValue = "100") int limit,
            @Param(value = "program", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        StringBuilder sb = new StringBuilder();
        FunctionManager functionManager = program.getFunctionManager();

        // Find the function by name or address
        Function targetFunction = null;
        FunctionRef.Result resolved = FunctionRef.ofNameOrAddress(functionName, address).tryResolve(program);
        if (!resolved.isSuccess()) {
            return Response.text("Function not found: " + functionName);
        }
        targetFunction = resolved.function();

        Set<Function> callers = new HashSet<>();
        ReferenceManager refManager = program.getReferenceManager();

        // Get all references to this function's entry point
        ReferenceIterator refIter = refManager.getReferencesTo(targetFunction.getEntryPoint());
        while (refIter.hasNext()) {
            Reference ref = refIter.next();
            if (ref.getReferenceType().isCall()) {
                Address fromAddr = ref.getFromAddress();
                Function callerFunc = functionManager.getFunctionContaining(fromAddr);
                if (callerFunc != null) {
                    callers.add(callerFunc);
                }
            }
        }

        // Convert to sorted list and apply pagination
        List<Function> sortedCallers = new ArrayList<>(callers);
        sortedCallers.sort((f1, f2) -> f1.getName().compareTo(f2.getName()));

        int count = 0;
        int skipped = 0;

        for (Function caller : sortedCallers) {
            if (count >= limit) break;

            if (skipped < offset) {
                skipped++;
                continue;
            }

            if (sb.length() > 0) {
                sb.append("\n");
            }

            sb.append(String.format("%s @ %s", caller.getName(), caller.getEntryPoint()));
            count++;
        }

        if (sb.length() == 0) {
            return Response.text("No callers found for function: " + functionName);
        }

        return Response.text(sb.toString());
    }

    // -----------------------------------------------------------------------
    // Call Graph Methods
    // -----------------------------------------------------------------------

    /**
     * Get a call graph subgraph centered on the specified function
     */
    @McpTool(path = "/get_function_call_graph", description = "Traverse call graph from a function. Accepts function name or address.", category = "xref")
    public Response getFunctionCallGraph(
            @Param(value = "name", defaultValue = "", description = "Function name") String functionName,
            @Param(value = "address", defaultValue = "", description = "Function entry-point address (hex) — alternative to name") String address,
            @Param(value = "depth", defaultValue = "2", description = "Traversal depth") int depth,
            @Param(value = "direction", defaultValue = "both", description = "Traversal direction (both/callers/callees)") String direction,
            @Param(value = "program", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        StringBuilder sb = new StringBuilder();
        FunctionManager functionManager = program.getFunctionManager();

        // Find the function by name or address
        Function rootFunction = null;
        FunctionRef.Result resolved = FunctionRef.ofNameOrAddress(functionName, address).tryResolve(program);
        if (!resolved.isSuccess()) {
            return Response.text("Function not found: " + functionName);
        }
        rootFunction = resolved.function();

        Set<String> visited = new HashSet<>();
        Map<String, Set<String>> callGraph = new HashMap<>();

        // Build call graph based on direction
        if ("callees".equals(direction) || "both".equals(direction)) {
            buildCallGraphCallees(rootFunction, depth, visited, callGraph, functionManager, program);
        }

        if ("callers".equals(direction) || "both".equals(direction)) {
            visited.clear(); // Reset for callers traversal
            buildCallGraphCallers(rootFunction, depth, visited, callGraph, functionManager, program);
        }

        // Format output as edges
        for (Map.Entry<String, Set<String>> entry : callGraph.entrySet()) {
            String caller = entry.getKey();
            for (String callee : entry.getValue()) {
                if (sb.length() > 0) {
                    sb.append("\n");
                }
                sb.append(caller).append(" -> ").append(callee);
            }
        }

        if (sb.length() == 0) {
            return Response.text("No call graph relationships found for function: " + functionName);
        }

        return Response.text(sb.toString());
    }

    /**
     * Helper method to build call graph for callees (what this function calls)
     */
    private void buildCallGraphCallees(Function function, int depth, Set<String> visited,
                                     Map<String, Set<String>> callGraph, FunctionManager functionManager,
                                     Program program) {
        if (depth <= 0 || visited.contains(function.getName())) {
            return;
        }

        visited.add(function.getName());
        Set<String> callees = new HashSet<>();

        // Find callees of this function
        AddressSetView functionBody = function.getBody();
        Listing listing = program.getListing();
        ReferenceManager refManager = program.getReferenceManager();

        InstructionIterator instructions = listing.getInstructions(functionBody, true);
        while (instructions.hasNext()) {
            Instruction instr = instructions.next();

            if (instr.getFlowType().isCall()) {
                Reference[] references = refManager.getReferencesFrom(instr.getAddress());
                for (Reference ref : references) {
                    if (ref.getReferenceType().isCall()) {
                        Address targetAddr = ref.getToAddress();
                        Function targetFunc = functionManager.getFunctionAt(targetAddr);
                        if (targetFunc != null) {
                            callees.add(targetFunc.getName());
                            // Recursively build graph for callees
                            buildCallGraphCallees(targetFunc, depth - 1, visited, callGraph, functionManager, program);
                        }
                    }
                }
            }
        }

        if (!callees.isEmpty()) {
            callGraph.put(function.getName(), callees);
        }
    }

    /**
     * Helper method to build call graph for callers (what calls this function)
     */
    private void buildCallGraphCallers(Function function, int depth, Set<String> visited,
                                     Map<String, Set<String>> callGraph, FunctionManager functionManager,
                                     Program program) {
        if (depth <= 0 || visited.contains(function.getName())) {
            return;
        }

        visited.add(function.getName());
        ReferenceManager refManager = program.getReferenceManager();

        // Find callers of this function
        ReferenceIterator refIter = refManager.getReferencesTo(function.getEntryPoint());
        while (refIter.hasNext()) {
            Reference ref = refIter.next();
            if (ref.getReferenceType().isCall()) {
                Address fromAddr = ref.getFromAddress();
                Function callerFunc = functionManager.getFunctionContaining(fromAddr);
                if (callerFunc != null) {
                    String callerName = callerFunc.getName();
                    callGraph.computeIfAbsent(callerName, k -> new HashSet<>()).add(function.getName());
                    // Recursively build graph for callers
                    buildCallGraphCallers(callerFunc, depth - 1, visited, callGraph, functionManager, program);
                }
            }
        }
    }

    /**
     * Get the complete call graph for the entire program
     */
    @McpTool(path = "/get_full_call_graph", description = "Get entire program call graph", category = "xref")
    public Response getFullCallGraph(
            @Param(value = "format", defaultValue = "edges", description = "Output format (edges or adjacency)") String format,
            @Param(value = "limit", defaultValue = "1000") int limit,
            @Param(value = "program", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        StringBuilder sb = new StringBuilder();
        FunctionManager functionManager = program.getFunctionManager();
        ReferenceManager refManager = program.getReferenceManager();
        Listing listing = program.getListing();

        Map<String, Set<String>> callGraph = new HashMap<>();
        int relationshipCount = 0;

        // Build complete call graph
        for (Function function : functionManager.getFunctions(true)) {
            if (relationshipCount >= limit) {
                break;
            }

            String functionName = function.getName();
            Set<String> callees = new HashSet<>();

            // Find all functions called by this function
            AddressSetView functionBody = function.getBody();
            InstructionIterator instructions = listing.getInstructions(functionBody, true);

            while (instructions.hasNext() && relationshipCount < limit) {
                Instruction instr = instructions.next();

                if (instr.getFlowType().isCall()) {
                    Reference[] references = refManager.getReferencesFrom(instr.getAddress());
                    for (Reference ref : references) {
                        if (ref.getReferenceType().isCall()) {
                            Address targetAddr = ref.getToAddress();
                            Function targetFunc = functionManager.getFunctionAt(targetAddr);
                            if (targetFunc != null) {
                                callees.add(targetFunc.getName());
                                relationshipCount++;
                                if (relationshipCount >= limit) {
                                    break;
                                }
                            }
                        }
                    }
                }
            }

            if (!callees.isEmpty()) {
                callGraph.put(functionName, callees);
            }
        }

        // Format output based on requested format
        if ("dot".equals(format)) {
            sb.append("digraph CallGraph {\n");
            sb.append("  rankdir=TB;\n");
            sb.append("  node [shape=box];\n");
            for (Map.Entry<String, Set<String>> entry : callGraph.entrySet()) {
                String caller = entry.getKey().replace("\"", "\\\"");
                for (String callee : entry.getValue()) {
                    callee = callee.replace("\"", "\\\"");
                    sb.append("  \"").append(caller).append("\" -> \"").append(callee).append("\";\n");
                }
            }
            sb.append("}");
        } else if ("mermaid".equals(format)) {
            sb.append("graph TD\n");
            for (Map.Entry<String, Set<String>> entry : callGraph.entrySet()) {
                String caller = entry.getKey().replace(" ", "_");
                for (String callee : entry.getValue()) {
                    callee = callee.replace(" ", "_");
                    sb.append("  ").append(caller).append(" --> ").append(callee).append("\n");
                }
            }
        } else if ("adjacency".equals(format)) {
            for (Map.Entry<String, Set<String>> entry : callGraph.entrySet()) {
                if (sb.length() > 0) {
                    sb.append("\n");
                }
                sb.append(entry.getKey()).append(": ");
                sb.append(String.join(", ", entry.getValue()));
            }
        } else { // Default "edges" format
            for (Map.Entry<String, Set<String>> entry : callGraph.entrySet()) {
                String caller = entry.getKey();
                for (String callee : entry.getValue()) {
                    if (sb.length() > 0) {
                        sb.append("\n");
                    }
                    sb.append(caller).append(" -> ").append(callee);
                }
            }
        }

        if (sb.length() == 0) {
            return Response.text("No call relationships found in the program");
        }

        return Response.text(sb.toString());
    }

    // -----------------------------------------------------------------------
    // Call Graph Analysis Methods
    // -----------------------------------------------------------------------

    /**
     * Enhanced call graph analysis with cycle detection and path finding
     * Provides advanced graph algorithms for understanding function relationships
     */
    @McpTool(path = "/analyze_call_graph", description = "Analyze call graph paths between functions", category = "xref")
    public Response analyzeCallGraph(
            @Param(value = "start_function", description = "Start function name") String startFunction,
            @Param(value = "end_function", description = "End function name") String endFunction,
            @Param(value = "analysis_type", defaultValue = "summary", description = "Analysis type (summary/paths/cycles)") String analysisType,
            @Param(value = "program", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        try {
            FunctionManager functionManager = program.getFunctionManager();
            ReferenceManager refManager = program.getReferenceManager();

            // Build adjacency list representation of call graph
            Map<String, Set<String>> callGraph = new LinkedHashMap<>();
            Map<String, String> functionAddresses = new LinkedHashMap<>();

            for (Function func : functionManager.getFunctions(true)) {
                if (func.isThunk()) continue;

                String funcName = func.getName();
                functionAddresses.put(funcName, func.getEntryPoint().toString());
                Set<String> callees = new HashSet<>();

                Listing listing = program.getListing();
                InstructionIterator instrIter = listing.getInstructions(func.getBody(), true);

                while (instrIter.hasNext()) {
                    Instruction instr = instrIter.next();
                    if (instr.getFlowType().isCall()) {
                        for (Reference ref : refManager.getReferencesFrom(instr.getAddress())) {
                            if (ref.getReferenceType().isCall()) {
                                Function calledFunc = functionManager.getFunctionAt(ref.getToAddress());
                                if (calledFunc != null && !calledFunc.isThunk()) {
                                    callees.add(calledFunc.getName());
                                }
                            }
                        }
                    }
                }

                if (!callees.isEmpty()) {
                    callGraph.put(funcName, callees);
                }
            }

            if ("cycles".equals(analysisType)) {
                // Detect cycles in the call graph using DFS
                List<List<String>> cycles = findCycles(callGraph);

                List<Map<String, Object>> cyclesList = new ArrayList<>();
                for (int i = 0; i < Math.min(cycles.size(), 20); i++) {
                    List<String> cycle = cycles.get(i);
                    cyclesList.add(JsonHelper.mapOf(
                        "length", cycle.size(),
                        "path", cycle
                    ));
                }
                if (cycles.size() > 20) {
                    cyclesList.add(JsonHelper.mapOf("note", (cycles.size() - 20) + " additional cycles omitted"));
                }

                return Response.ok(JsonHelper.mapOf(
                    "analysis_type", "cycle_detection",
                    "cycles_found", cycles.size(),
                    "cycles", cyclesList
                ));

            } else if ("path".equals(analysisType) && startFunction != null && endFunction != null) {
                // Find shortest path between two functions using BFS
                List<String> path = findShortestPath(callGraph, startFunction, endFunction);

                if (path != null) {
                    return Response.ok(JsonHelper.mapOf(
                        "analysis_type", "path_finding",
                        "start_function", startFunction,
                        "end_function", endFunction,
                        "path_found", true,
                        "path_length", path.size() - 1,
                        "path", path
                    ));
                } else {
                    return Response.ok(JsonHelper.mapOf(
                        "analysis_type", "path_finding",
                        "start_function", startFunction,
                        "end_function", endFunction,
                        "path_found", false,
                        "message", "No path exists between the specified functions"
                    ));
                }

            } else if ("strongly_connected".equals(analysisType)) {
                // Find strongly connected components using Kosaraju's algorithm
                List<Set<String>> sccs = findStronglyConnectedComponents(callGraph);

                // Filter to only non-trivial SCCs (size > 1)
                List<Set<String>> nonTrivialSCCs = new ArrayList<>();
                for (Set<String> scc : sccs) {
                    if (scc.size() > 1) {
                        nonTrivialSCCs.add(scc);
                    }
                }

                List<Map<String, Object>> componentsList = new ArrayList<>();
                for (int i = 0; i < Math.min(nonTrivialSCCs.size(), 20); i++) {
                    Set<String> scc = nonTrivialSCCs.get(i);
                    List<String> funcNames = new ArrayList<>();
                    int j = 0;
                    for (String func : scc) {
                        if (j >= 10) break;
                        funcNames.add(func);
                        j++;
                    }
                    if (scc.size() > 10) {
                        funcNames.add("..." + (scc.size() - 10) + " more");
                    }
                    componentsList.add(JsonHelper.mapOf(
                        "size", scc.size(),
                        "functions", funcNames
                    ));
                }

                return Response.ok(JsonHelper.mapOf(
                    "analysis_type", "strongly_connected_components",
                    "total_sccs", sccs.size(),
                    "non_trivial_sccs", nonTrivialSCCs.size(),
                    "components", componentsList
                ));

            } else if ("entry_points".equals(analysisType)) {
                // Find functions that are never called (potential entry points)
                Set<String> allFunctions = new HashSet<>(functionAddresses.keySet());
                Set<String> calledFunctions = new HashSet<>();
                for (Set<String> callees : callGraph.values()) {
                    calledFunctions.addAll(callees);
                }

                Set<String> entryPoints = new HashSet<>(allFunctions);
                entryPoints.removeAll(calledFunctions);

                List<Map<String, Object>> entryPointsList = new ArrayList<>();
                int idx = 0;
                for (String ep : entryPoints) {
                    if (idx >= 50) {
                        entryPointsList.add(JsonHelper.mapOf("note", (entryPoints.size() - 50) + " more entry points"));
                        break;
                    }
                    entryPointsList.add(JsonHelper.mapOf(
                        "name", ep,
                        "address", functionAddresses.getOrDefault(ep, "unknown")
                    ));
                    idx++;
                }

                return Response.ok(JsonHelper.mapOf(
                    "analysis_type", "entry_point_detection",
                    "total_functions", allFunctions.size(),
                    "entry_points_found", entryPoints.size(),
                    "entry_points", entryPointsList
                ));

            } else if ("leaf_functions".equals(analysisType)) {
                // Find functions that don't call any other functions
                Set<String> leafFunctions = new HashSet<>(functionAddresses.keySet());
                leafFunctions.removeAll(callGraph.keySet());

                List<Map<String, Object>> leafFunctionsList = new ArrayList<>();
                int idx = 0;
                for (String lf : leafFunctions) {
                    if (idx >= 50) {
                        leafFunctionsList.add(JsonHelper.mapOf("note", (leafFunctions.size() - 50) + " more leaf functions"));
                        break;
                    }
                    leafFunctionsList.add(JsonHelper.mapOf(
                        "name", lf,
                        "address", functionAddresses.getOrDefault(lf, "unknown")
                    ));
                    idx++;
                }

                return Response.ok(JsonHelper.mapOf(
                    "analysis_type", "leaf_function_detection",
                    "leaf_functions_found", leafFunctions.size(),
                    "leaf_functions", leafFunctionsList
                ));

            } else {
                // Default: summary statistics
                int totalEdges = 0;
                int maxOutDegree = 0;
                String maxOutDegreeFunc = "";
                Map<String, Integer> inDegree = new HashMap<>();

                for (Map.Entry<String, Set<String>> entry : callGraph.entrySet()) {
                    totalEdges += entry.getValue().size();
                    if (entry.getValue().size() > maxOutDegree) {
                        maxOutDegree = entry.getValue().size();
                        maxOutDegreeFunc = entry.getKey();
                    }
                    for (String callee : entry.getValue()) {
                        inDegree.put(callee, inDegree.getOrDefault(callee, 0) + 1);
                    }
                }

                int maxInDegree = 0;
                String maxInDegreeFunc = "";
                for (Map.Entry<String, Integer> entry : inDegree.entrySet()) {
                    if (entry.getValue() > maxInDegree) {
                        maxInDegree = entry.getValue();
                        maxInDegreeFunc = entry.getKey();
                    }
                }

                return Response.ok(JsonHelper.mapOf(
                    "analysis_type", "summary",
                    "total_functions", functionAddresses.size(),
                    "functions_with_calls", callGraph.size(),
                    "total_call_edges", totalEdges,
                    "max_out_degree", JsonHelper.mapOf("function", maxOutDegreeFunc, "calls", maxOutDegree),
                    "max_in_degree", JsonHelper.mapOf("function", maxInDegreeFunc, "called_by", maxInDegree),
                    "available_analyses", Arrays.asList("cycles", "path", "strongly_connected", "entry_points", "leaf_functions")
                ));
            }

        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    // -----------------------------------------------------------------------
    // Graph Algorithm Helpers
    // -----------------------------------------------------------------------

    /**
     * Find cycles in directed graph using DFS
     */
    private List<List<String>> findCycles(Map<String, Set<String>> graph) {
        List<List<String>> cycles = new ArrayList<>();
        Set<String> visited = new HashSet<>();
        Set<String> recStack = new HashSet<>();
        Map<String, String> parent = new HashMap<>();

        for (String node : graph.keySet()) {
            if (!visited.contains(node)) {
                findCyclesDFS(node, graph, visited, recStack, parent, cycles);
            }
        }

        return cycles;
    }

    private void findCyclesDFS(String node, Map<String, Set<String>> graph, Set<String> visited,
                               Set<String> recStack, Map<String, String> parent, List<List<String>> cycles) {
        visited.add(node);
        recStack.add(node);

        Set<String> neighbors = graph.getOrDefault(node, Collections.emptySet());
        for (String neighbor : neighbors) {
            if (!visited.contains(neighbor)) {
                parent.put(neighbor, node);
                findCyclesDFS(neighbor, graph, visited, recStack, parent, cycles);
            } else if (recStack.contains(neighbor)) {
                // Found a cycle - reconstruct it
                List<String> cycle = new ArrayList<>();
                cycle.add(neighbor);
                String current = node;
                while (current != null && !current.equals(neighbor)) {
                    cycle.add(0, current);
                    current = parent.get(current);
                }
                cycle.add(0, neighbor);
                if (cycles.size() < 100) { // Limit cycles
                    cycles.add(cycle);
                }
            }
        }

        recStack.remove(node);
    }

    /**
     * Find shortest path using BFS
     */
    private List<String> findShortestPath(Map<String, Set<String>> graph, String start, String end) {
        if (start.equals(end)) {
            return Arrays.asList(start);
        }

        Queue<String> queue = new LinkedList<>();
        Map<String, String> parent = new HashMap<>();
        Set<String> visited = new HashSet<>();

        queue.add(start);
        visited.add(start);

        while (!queue.isEmpty()) {
            String current = queue.poll();
            Set<String> neighbors = graph.getOrDefault(current, Collections.emptySet());

            for (String neighbor : neighbors) {
                if (!visited.contains(neighbor)) {
                    visited.add(neighbor);
                    parent.put(neighbor, current);

                    if (neighbor.equals(end)) {
                        // Reconstruct path
                        List<String> path = new ArrayList<>();
                        String node = end;
                        while (node != null) {
                            path.add(0, node);
                            node = parent.get(node);
                        }
                        return path;
                    }

                    queue.add(neighbor);
                }
            }
        }

        return null; // No path found
    }

    /**
     * Find strongly connected components using Kosaraju's algorithm
     */
    private List<Set<String>> findStronglyConnectedComponents(Map<String, Set<String>> graph) {
        // Step 1: Fill vertices in stack according to finishing times
        Stack<String> stack = new Stack<>();
        Set<String> visited = new HashSet<>();

        // Get all nodes
        Set<String> allNodes = new HashSet<>(graph.keySet());
        for (Set<String> neighbors : graph.values()) {
            allNodes.addAll(neighbors);
        }

        for (String node : allNodes) {
            if (!visited.contains(node)) {
                fillOrder(node, graph, visited, stack);
            }
        }

        // Step 2: Create reversed graph
        Map<String, Set<String>> reversedGraph = new HashMap<>();
        for (Map.Entry<String, Set<String>> entry : graph.entrySet()) {
            for (String neighbor : entry.getValue()) {
                reversedGraph.computeIfAbsent(neighbor, k -> new HashSet<>()).add(entry.getKey());
            }
        }

        // Step 3: Process vertices in order of decreasing finish time
        visited.clear();
        List<Set<String>> sccs = new ArrayList<>();

        while (!stack.isEmpty()) {
            String node = stack.pop();
            if (!visited.contains(node)) {
                Set<String> scc = new HashSet<>();
                dfsCollect(node, reversedGraph, visited, scc);
                sccs.add(scc);
            }
        }

        return sccs;
    }

    private void fillOrder(String node, Map<String, Set<String>> graph, Set<String> visited, Stack<String> stack) {
        visited.add(node);
        Set<String> neighbors = graph.getOrDefault(node, Collections.emptySet());
        for (String neighbor : neighbors) {
            if (!visited.contains(neighbor)) {
                fillOrder(neighbor, graph, visited, stack);
            }
        }
        stack.push(node);
    }

    private void dfsCollect(String node, Map<String, Set<String>> graph, Set<String> visited, Set<String> component) {
        visited.add(node);
        component.add(node);
        Set<String> neighbors = graph.getOrDefault(node, Collections.emptySet());
        for (String neighbor : neighbors) {
            if (!visited.contains(neighbor)) {
                dfsCollect(neighbor, graph, visited, component);
            }
        }
    }

    // -----------------------------------------------------------------------
    // Bulk Xref Methods
    // -----------------------------------------------------------------------

    /**
     * Retrieve xrefs for multiple addresses in one call
     */
    public Response getBulkXrefs(Object addressesObj) {
        return getBulkXrefs(addressesObj, null);
    }

    @McpTool(path = "/get_bulk_xrefs", method = "POST", description = "Batch cross-reference retrieval", category = "xref")
    public Response getBulkXrefs(
            @Param(value = "addresses", source = ParamSource.BODY) Object addressesObj,
            @Param(value = "program", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        try {
            List<String> addresses = new ArrayList<>();

            // Parse addresses array
            if (addressesObj instanceof List) {
                for (Object addr : (List<?>) addressesObj) {
                    if (addr != null) {
                        addresses.add(addr.toString());
                    }
                }
            } else if (addressesObj instanceof String) {
                // Handle comma-separated string
                String[] parts = ((String) addressesObj).split(",");
                for (String part : parts) {
                    addresses.add(part.trim());
                }
            }

            ReferenceManager refMgr = program.getReferenceManager();
            Map<String, Object> resultMap = new LinkedHashMap<>();

            for (String addrStr : addresses) {
                List<Map<String, Object>> refsList = new ArrayList<>();

                try {
                    Address addr = ServiceUtils.parseAddress(program, addrStr);
                    if (addr != null) {
                        ReferenceIterator refIter = refMgr.getReferencesTo(addr);

                        while (refIter.hasNext()) {
                            Reference ref = refIter.next();
                            Address fromAddr = ref.getFromAddress();
                            Map<String, Object> refItem = new LinkedHashMap<>();
                            refItem.put("from", fromAddr.toString(false));
                            if (ServiceUtils.getPhysicalSpaceCount(program) > 1) {
                                refItem.put("from_full", fromAddr.toString());
                                refItem.put("from_space", fromAddr.getAddressSpace().getName());
                            }
                            refItem.put("type", ref.getReferenceType().getName());
                            refsList.add(refItem);
                        }
                    }
                } catch (Exception e) {
                    // Address parsing failed, return empty array
                }

                resultMap.put(addrStr, refsList);
            }

            return Response.ok(resultMap);
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    /**
     * Assembly pattern analysis - get assembly context around xref source addresses
     */
    public Response getAssemblyContext(Object xrefSourcesObj, int contextInstructions,
                                      Object includePatternsObj) {
        return getAssemblyContext(xrefSourcesObj, contextInstructions, includePatternsObj, null);
    }

    @McpTool(path = "/get_assembly_context", method = "POST", description = "Get assembly pattern context for xref sources", category = "xref")
    public Response getAssemblyContext(
            @Param(value = "xref_sources", source = ParamSource.BODY) Object xrefSourcesObj,
            @Param(value = "context_instructions", source = ParamSource.BODY, defaultValue = "5") int contextInstructions,
            @Param(value = "include_patterns", source = ParamSource.BODY) Object includePatternsObj,
            @Param(value = "program", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        try {
            List<String> xrefSources = new ArrayList<>();

            if (xrefSourcesObj instanceof List) {
                for (Object addr : (List<?>) xrefSourcesObj) {
                    if (addr != null) {
                        xrefSources.add(addr.toString());
                    }
                }
            } else if (xrefSourcesObj instanceof String s) {
                for (String part : s.split(",")) {
                    String trimmed = part.trim();
                    if (!trimmed.isEmpty()) {
                        xrefSources.add(trimmed);
                    }
                }
            }

            Listing listing = program.getListing();
            Map<String, Object> resultMap = new LinkedHashMap<>();

            for (String addrStr : xrefSources) {
                try {
                    Address addr = ServiceUtils.parseAddress(program, addrStr);
                    if (addr != null) {
                        Instruction instr = listing.getInstructionAt(addr);

                        if (instr != null) {
                            // Get context before
                            List<String> contextBefore = new ArrayList<>();
                            Address prevAddr = addr;
                            for (int i = 0; i < contextInstructions; i++) {
                                Instruction prevInstr = listing.getInstructionBefore(prevAddr);
                                if (prevInstr == null) break;
                                prevAddr = prevInstr.getAddress();
                                contextBefore.add(prevAddr + ": " + prevInstr.toString());
                            }

                            // Get context after
                            List<String> contextAfter = new ArrayList<>();
                            Address nextAddr = addr;
                            for (int i = 0; i < contextInstructions; i++) {
                                Instruction nextInstr = listing.getInstructionAfter(nextAddr);
                                if (nextInstr == null) break;
                                nextAddr = nextInstr.getAddress();
                                contextAfter.add(nextAddr + ": " + nextInstr.toString());
                            }

                            // Detect patterns
                            String mnemonic = instr.getMnemonicString().toUpperCase();

                            List<String> patterns = new ArrayList<>();
                            if (mnemonic.equals("MOV") || mnemonic.equals("LEA")) {
                                patterns.add("data_access");
                            }
                            if (mnemonic.equals("CMP") || mnemonic.equals("TEST")) {
                                patterns.add("comparison");
                            }
                            if (mnemonic.equals("IMUL") || mnemonic.equals("SHL") || mnemonic.equals("SHR")) {
                                patterns.add("arithmetic");
                            }
                            if (mnemonic.equals("PUSH") || mnemonic.equals("POP")) {
                                patterns.add("stack_operation");
                            }
                            if (mnemonic.startsWith("J") || mnemonic.equals("CALL")) {
                                patterns.add("control_flow");
                            }

                            resultMap.put(addrStr, JsonHelper.mapOf(
                                "address", addrStr,
                                "instruction", instr.toString(),
                                "context_before", contextBefore,
                                "context_after", contextAfter,
                                "mnemonic", mnemonic,
                                "patterns_detected", patterns
                            ));
                        } else {
                            resultMap.put(addrStr, JsonHelper.mapOf(
                                "address", addrStr,
                                "error", "No instruction at address"
                            ));
                        }
                    }
                } catch (Exception e) {
                    resultMap.put(addrStr, JsonHelper.mapOf(
                        "error", e.getMessage()
                    ));
                }
            }

            return Response.ok(resultMap);
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }
}
