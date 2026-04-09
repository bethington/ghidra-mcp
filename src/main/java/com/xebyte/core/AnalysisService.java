package com.xebyte.core;

import ghidra.app.decompiler.DecompileResults;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Symbol;

import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TaskMonitor;

import javax.swing.SwingUtilities;
import java.lang.reflect.InvocationTargetException;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Pattern;

/**
 * Service for analysis operations: control flow analysis, function completeness,
 * similarity detection, memory inspection, and enhanced search.
 * Extracted from GhidraMCPPlugin as part of v4.0.0 refactor.
 */
@McpToolGroup(value = "analysis", description = "Completeness analysis, control flow, similarity, crypto detection, memory inspection")
public class AnalysisService {

    private static final int MAX_FIELD_EXAMPLES = 50;
    private static final int MAX_FIELD_OFFSET = 65536;

    private final ProgramProvider programProvider;
    private final ThreadingStrategy threadingStrategy;
    private final FunctionService functionService;

    public AnalysisService(ProgramProvider programProvider, ThreadingStrategy threadingStrategy, FunctionService functionService) {
        this.programProvider = programProvider;
        this.threadingStrategy = threadingStrategy;
        this.functionService = functionService;
    }

    // ========================================================================
    // Function classification utility
    // ========================================================================

    /**
     * Classify a function's type for documentation workflow routing.
     * Returns one of: "thunk", "leaf", "wrapper", "worker", "api_export", "stub".
     */
    public static String classifyFunction(Function func, Program program) {
        // Check for thunk (single JMP instruction or Ghidra-tagged thunk)
        if (func.isThunk()) return "thunk";

        InstructionIterator instrIter = program.getListing().getInstructions(func.getBody(), true);
        int instrCount = 0;
        String firstMnemonic = null;
        while (instrIter.hasNext()) {
            ghidra.program.model.listing.Instruction instr = instrIter.next();
            if (instrCount == 0) firstMnemonic = instr.getMnemonicString();
            instrCount++;
        }

        // Single-JMP stub (not tagged by Ghidra but functionally a thunk)
        if (instrCount == 1 && "JMP".equals(firstMnemonic)) return "thunk";

        // Stub: 1-3 instructions (NOP/RET patterns)
        if (instrCount <= 3) return "stub";

        // Check for exported ordinal (API export)
        Symbol sym = func.getSymbol();
        if (sym != null && sym.isExternalEntryPoint()) return "api_export";

        // Check callees
        Set<Function> callees = func.getCalledFunctions(null);
        boolean hasCallees = callees != null && !callees.isEmpty();

        // Leaf: no calls to other functions
        if (!hasCallees) return "leaf";

        // Wrapper: exactly 1 callee and <= 15 instructions
        if (callees.size() == 1 && instrCount <= 15) return "wrapper";

        // Default: worker (has callees and significant body)
        return "worker";
    }

    // ========================================================================
    // Inner classes
    // ========================================================================

    /**
     * Helper class to store function metrics for similarity comparison
     */
    private static class FunctionMetrics {
        int basicBlockCount = 0;
        int instructionCount = 0;
        int callCount = 0;
        int cyclomaticComplexity = 0;
        int edgeCount = 0;
        Set<String> calledFunctions = new HashSet<>();
    }

    /**
     * Score result containing both raw and effective scores.
     * Effective score excludes unfixable deductions (void* on generic functions, phantoms).
     */
    private static class CompletenessScoreResult {
        final double score;
        final double effectiveScore;
        final int unfixableDeductions;
        final double fixablePenalty;
        final double structuralPenalty;
        final double maxAchievableScore;
        final List<Map<String, Object>> deductionBreakdown;

        CompletenessScoreResult(double score, double effectiveScore, int unfixableDeductions,
                                double fixablePenalty, double structuralPenalty,
                                double maxAchievableScore, List<Map<String, Object>> deductionBreakdown) {
            this.score = score;
            this.effectiveScore = effectiveScore;
            this.unfixableDeductions = unfixableDeductions;
            this.fixablePenalty = fixablePenalty;
            this.structuralPenalty = structuralPenalty;
            this.maxAchievableScore = maxAchievableScore;
            this.deductionBreakdown = deductionBreakdown;
        }
    }

    // ========================================================================
    // Public endpoint methods
    // ========================================================================

    @McpTool(path = "/list_analyzers", description = "List available analyzers", category = "analysis")
    public Response listAnalyzers(
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        try {
            Options options = program.getOptions(Program.ANALYSIS_PROPERTIES);
            List<String> names = options.getOptionNames();
            List<Map<String, Object>> entries = new ArrayList<>();
            for (String name : names) {
                try {
                    boolean enabled = options.getBoolean(name, false);
                    entries.add(JsonHelper.mapOf("name", name, "enabled", enabled));
                } catch (Exception ignored) {
                    // Not a boolean option -- skip non-analyzer properties
                }
            }
            return Response.ok(JsonHelper.mapOf("analyzers", entries, "count", entries.size()));
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    /**
     * Trigger auto-analysis on the current or named program.
     */
    @McpTool(path = "/run_analysis", method = "POST", description = "Trigger auto-analysis on program", category = "analysis")
    public Response runAnalysis(
            @Param(value = "program", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        try {
            long start = System.currentTimeMillis();
            int before = program.getFunctionManager().getFunctionCount();

            AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
            int txId = program.startTransaction("Run Auto Analysis");
            boolean success = false;
            try {
                mgr.initializeOptions();
                mgr.reAnalyzeAll(program.getMemory().getLoadedAndInitializedAddressSet());
                mgr.startAnalysis(TaskMonitor.DUMMY);
                success = true;
            } finally {
                program.endTransaction(txId, success);
            }

            long duration = System.currentTimeMillis() - start;
            int after = program.getFunctionManager().getFunctionCount();
            return Response.ok(JsonHelper.mapOf(
                "success", true,
                "duration_ms", duration,
                "total_functions", after,
                "new_functions", after - before,
                "program", program.getName()
            ));
        } catch (Exception e) {
            return Response.err("Analysis failed: " + e.getMessage());
        }
    }

    public Response analyzeDataRegion(String startAddressStr, int maxScanBytes,
                                    boolean includeXrefMap, boolean includeAssemblyPatterns,
                                    boolean includeBoundaryDetection) {
        return analyzeDataRegion(startAddressStr, maxScanBytes, includeXrefMap, includeAssemblyPatterns, includeBoundaryDetection, null);
    }

    @McpTool(path = "/analyze_data_region", method = "POST", description = "Comprehensive data region analysis. On programs with multiple address spaces (e.g., embedded targets), prefix addresses with the space name (mem:1000) to avoid ambiguous resolution.", category = "analysis")
    public Response analyzeDataRegion(
            @Param(value = "address", paramType = "address", source = ParamSource.BODY,
                   description = "Address in the program. Accepts 0x<hex> (default space) or <space>:<hex> "
                               + "(e.g., mem:1000, code:ff00). Note: some programs — particularly "
                               + "embedded/microcontroller targets — are not address-space-agnostic; "
                               + "use get_address_spaces to discover spaces before assuming a plain hex "
                               + "address is unambiguous.") String startAddressStr,
            @Param(value = "max_scan_bytes", source = ParamSource.BODY, defaultValue = "1024") int maxScanBytes,
            @Param(value = "include_xref_map", source = ParamSource.BODY, defaultValue = "true") boolean includeXrefMap,
            @Param(value = "include_assembly_patterns", source = ParamSource.BODY, defaultValue = "true") boolean includeAssemblyPatterns,
            @Param(value = "include_boundary_detection", source = ParamSource.BODY, defaultValue = "true") boolean includeBoundaryDetection,
            @Param(value = "program", description = "Target program name", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        try {
            Address startAddr = ServiceUtils.parseAddress(program, startAddressStr);
            if (startAddr == null) {
                return Response.err(ServiceUtils.getLastParseError());
            }

            ReferenceManager refMgr = program.getReferenceManager();
            Listing listing = program.getListing();

            // Scan byte-by-byte for xrefs and boundary detection
            Address endAddr = startAddr;
            Set<String> uniqueXrefs = new HashSet<>();
            int byteCount = 0;
            Map<String, List<String>> xrefMap = new LinkedHashMap<>();

            for (int i = 0; i < maxScanBytes; i++) {
                Address scanAddr = startAddr.add(i);

                // Check for boundary: Named symbol that isn't DAT_
                Symbol[] symbols = program.getSymbolTable().getSymbols(scanAddr);
                if (includeBoundaryDetection && symbols.length > 0) {
                    for (Symbol sym : symbols) {
                        String name = sym.getName();
                        if (!name.startsWith("DAT_") && !name.equals(startAddr.toString())) {
                            endAddr = scanAddr.subtract(1);
                            byteCount = i;
                            break;
                        }
                    }
                    if (byteCount > 0) break;
                }

                // Get xrefs for this byte
                ReferenceIterator refIter = refMgr.getReferencesTo(scanAddr);
                List<String> refsAtThisByte = new ArrayList<>();

                while (refIter.hasNext()) {
                    Reference ref = refIter.next();
                    String fromAddr = ref.getFromAddress().toString();
                    refsAtThisByte.add(fromAddr);
                    uniqueXrefs.add(fromAddr);
                }

                if (includeXrefMap && !refsAtThisByte.isEmpty()) {
                    xrefMap.put(scanAddr.toString(), refsAtThisByte);
                }

                endAddr = scanAddr;
                byteCount = i + 1;
            }

            // Get current name and type
            Data data = listing.getDataAt(startAddr);
            String currentName = (data != null && data.getLabel() != null) ?
                                data.getLabel() : "DAT_" + startAddr.toString(false);
            String currentType = (data != null) ?
                                data.getDataType().getName() : "undefined";

            // STRING DETECTION: Read memory content to check for strings
            boolean isLikelyString = false;
            String detectedString = null;
            int suggestedStringLength = 0;

            try {
                Memory memory = program.getMemory();
                byte[] bytes = new byte[Math.min(byteCount, 256)];
                int bytesRead = memory.getBytes(startAddr, bytes);

                int printableCount = 0;
                int nullTerminatorIndex = -1;
                int consecutivePrintable = 0;
                int maxConsecutivePrintable = 0;

                for (int i = 0; i < bytesRead; i++) {
                    char c = (char) (bytes[i] & 0xFF);

                    if (c >= 0x20 && c <= 0x7E) {
                        printableCount++;
                        consecutivePrintable++;
                        if (consecutivePrintable > maxConsecutivePrintable) {
                            maxConsecutivePrintable = consecutivePrintable;
                        }
                    } else {
                        consecutivePrintable = 0;
                    }

                    if (c == 0x00 && nullTerminatorIndex == -1) {
                        nullTerminatorIndex = i;
                    }
                }

                double printableRatio = (double) printableCount / bytesRead;

                isLikelyString = (printableRatio >= 0.6) ||
                                (maxConsecutivePrintable >= 4 && nullTerminatorIndex > 0);

                if (isLikelyString && nullTerminatorIndex > 0) {
                    detectedString = new String(bytes, 0, nullTerminatorIndex, StandardCharsets.US_ASCII);
                    suggestedStringLength = nullTerminatorIndex + 1;
                } else if (isLikelyString && printableRatio >= 0.8) {
                    int endIdx = bytesRead;
                    for (int i = bytesRead - 1; i >= 0; i--) {
                        if ((bytes[i] & 0xFF) >= 0x20 && (bytes[i] & 0xFF) <= 0x7E) {
                            endIdx = i + 1;
                            break;
                        }
                    }
                    detectedString = new String(bytes, 0, endIdx, StandardCharsets.US_ASCII);
                    suggestedStringLength = endIdx;
                }
            } catch (Exception e) {
                // String detection failed, continue with normal classification
            }

            // Classify data type hint (enhanced with string detection)
            String classification = "PRIMITIVE";
            if (isLikelyString) {
                classification = "STRING";
            } else if (uniqueXrefs.size() > 3) {
                classification = "ARRAY";
            } else if (uniqueXrefs.size() > 1) {
                classification = "STRUCTURE";
            }

            // Build result map
            Map<String, Object> resultMap = new LinkedHashMap<>();
            resultMap.put("start_address", startAddr.toString());
            resultMap.put("end_address", endAddr.toString());
            resultMap.put("byte_span", byteCount);
            if (includeXrefMap) {
                resultMap.put("xref_map", xrefMap);
            }
            resultMap.put("unique_xref_addresses", new ArrayList<>(uniqueXrefs));
            resultMap.put("xref_count", uniqueXrefs.size());
            resultMap.put("classification_hint", classification);
            resultMap.put("stride_detected", 1);
            resultMap.put("current_name", currentName);
            resultMap.put("current_type", currentType);
            resultMap.put("is_likely_string", isLikelyString);
            resultMap.put("detected_string", detectedString);
            resultMap.put("suggested_string_type", detectedString != null ? "char[" + suggestedStringLength + "]" : null);

            return Response.ok(resultMap);
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    /**
     * 3. DETECT_ARRAY_BOUNDS - Array/table size detection
     */
    public Response detectArrayBounds(String addressStr, boolean analyzeLoopBounds,
                                    boolean analyzeIndexing, int maxScanRange) {
        return detectArrayBounds(addressStr, analyzeLoopBounds, analyzeIndexing, maxScanRange, null);
    }

    @McpTool(path = "/detect_array_bounds", method = "POST", description = "Detect array/table size from context. On programs with multiple address spaces (e.g., embedded targets), prefix addresses with the space name (mem:1000) to avoid ambiguous resolution.", category = "analysis")
    public Response detectArrayBounds(
            @Param(value = "address", paramType = "address", source = ParamSource.BODY,
                   description = "Address in the program. Accepts 0x<hex> (default space) or <space>:<hex> "
                               + "(e.g., mem:1000, code:ff00). Note: some programs — particularly "
                               + "embedded/microcontroller targets — are not address-space-agnostic; "
                               + "use get_address_spaces to discover spaces before assuming a plain hex "
                               + "address is unambiguous.") String addressStr,
            @Param(value = "analyze_loop_bounds", source = ParamSource.BODY, defaultValue = "true") boolean analyzeLoopBounds,
            @Param(value = "analyze_indexing", source = ParamSource.BODY, defaultValue = "true") boolean analyzeIndexing,
            @Param(value = "max_scan_range", source = ParamSource.BODY, defaultValue = "2048") int maxScanRange,
            @Param(value = "program", description = "Target program name", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        try {
            Address addr = ServiceUtils.parseAddress(program, addressStr);
            if (addr == null) {
                return Response.err(ServiceUtils.getLastParseError());
            }

            ReferenceManager refMgr = program.getReferenceManager();

            // Scan for xrefs to detect array bounds
            int estimatedSize = 0;
            Address scanAddr = addr;

            for (int i = 0; i < maxScanRange; i++) {
                ReferenceIterator refIter = refMgr.getReferencesTo(scanAddr);
                if (refIter.hasNext()) {
                    estimatedSize = i + 1;
                }

                // Check for boundary symbol
                Symbol[] symbols = program.getSymbolTable().getSymbols(scanAddr);
                if (symbols.length > 0 && i > 0) {
                    for (Symbol sym : symbols) {
                        if (!sym.getName().startsWith("DAT_")) {
                            break;  // Found boundary
                        }
                    }
                }

                scanAddr = scanAddr.add(1);
            }

            Map<String, Object> arrayResult = new LinkedHashMap<>();
            arrayResult.putAll(ServiceUtils.addressToJson(addr, program));
            arrayResult.put("estimated_size", estimatedSize);
            arrayResult.put("stride", 1);
            arrayResult.put("element_count", estimatedSize);
            arrayResult.put("confidence", "medium");
            arrayResult.put("detection_method", "xref_analysis");
            return Response.ok(arrayResult);
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    /**
     * GET_FIELD_ACCESS_CONTEXT - Get assembly/decompilation context for specific field offsets
     */
    public Response getFieldAccessContext(String structAddressStr, int fieldOffset, int numExamples) {
        return getFieldAccessContext(structAddressStr, fieldOffset, numExamples, null);
    }

    @McpTool(path = "/get_field_access_context", method = "POST", description = "Get assembly context for struct field offsets. On programs with multiple address spaces (e.g., embedded targets), prefix addresses with the space name (mem:1000) to avoid ambiguous resolution.", category = "analysis")
    public Response getFieldAccessContext(
            @Param(value = "struct_address", paramType = "address", source = ParamSource.BODY,
                   description = "Address in the program. Accepts 0x<hex> (default space) or <space>:<hex> "
                               + "(e.g., mem:1000, code:ff00). Note: some programs — particularly "
                               + "embedded/microcontroller targets — are not address-space-agnostic; "
                               + "use get_address_spaces to discover spaces before assuming a plain hex "
                               + "address is unambiguous.") String structAddressStr,
            @Param(value = "field_offset", source = ParamSource.BODY, defaultValue = "0") int fieldOffset,
            @Param(value = "num_examples", source = ParamSource.BODY, defaultValue = "5") int numExamples,
            @Param(value = "program", description = "Target program name", defaultValue = "") String programName) {
        // MAJOR FIX #7: Validate input parameters
        if (fieldOffset < 0 || fieldOffset > MAX_FIELD_OFFSET) {
            return Response.err("Field offset must be between 0 and " + MAX_FIELD_OFFSET);
        }
        if (numExamples < 1 || numExamples > MAX_FIELD_EXAMPLES) {
            return Response.err("numExamples must be between 1 and " + MAX_FIELD_EXAMPLES);
        }

        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program resolvedProgram = pe.program();

        // Resolve address before entering SwingUtilities lambda
        Address structAddr = ServiceUtils.parseAddress(resolvedProgram, structAddressStr);
        if (structAddr == null) return Response.err(ServiceUtils.getLastParseError());

        final AtomicReference<Response> result = new AtomicReference<>();

        // CRITICAL FIX #1: Thread safety - wrap in SwingUtilities.invokeAndWait
        try {
            SwingUtilities.invokeAndWait(() -> {
                try {
                    Program program = resolvedProgram;

                    // Calculate field address with overflow protection
                    Address fieldAddr;
                    try {
                        fieldAddr = structAddr.add(fieldOffset);
                    } catch (Exception e) {
                        result.set(Response.err("Field offset overflow: " + fieldOffset));
                        return;
                    }

                    Msg.info(this, "Getting field access context for " + fieldAddr + " (offset " + fieldOffset + ")");

                    // Get xrefs to the field address (or nearby addresses)
                    ReferenceManager refMgr = program.getReferenceManager();
                    ReferenceIterator refIter = refMgr.getReferencesTo(fieldAddr);

                    List<Map<String, Object>> examples = new ArrayList<>();
                    int exampleCount = 0;

                    while (refIter.hasNext() && exampleCount < numExamples) {
                        Reference ref = refIter.next();
                        Address fromAddr = ref.getFromAddress();

                        Map<String, Object> example = new LinkedHashMap<>();
                        example.put("access_address", fromAddr.toString());
                        example.put("ref_type", ref.getReferenceType().getName());

                        // Get assembly context with null check
                        Listing listing = program.getListing();
                        Instruction instr = listing.getInstructionAt(fromAddr);
                        example.put("assembly", instr != null ? instr.toString() : "");

                        // Get function context with null check
                        Function func = program.getFunctionManager().getFunctionContaining(fromAddr);
                        example.put("function_name", func != null ? func.getName() : "");
                        example.put("function_address", func != null ? func.getEntryPoint().toString() : "");

                        examples.add(example);
                        exampleCount++;
                    }

                    Msg.info(this, "Found " + exampleCount + " field access examples");
                    result.set(Response.ok(JsonHelper.mapOf(
                        "struct_address", structAddressStr,
                        "field_offset", fieldOffset,
                        "field_address", fieldAddr.toString(),
                        "examples", examples
                    )));

                } catch (Exception e) {
                    Msg.error(this, "Error in getFieldAccessContext", e);
                    result.set(Response.err(e.getMessage()));
                }
            });
        } catch (InvocationTargetException | InterruptedException e) {
            Msg.error(this, "Thread synchronization error in getFieldAccessContext", e);
            return Response.err("Thread synchronization error: " + e.getMessage());
        }

        return result.get();
    }

    /**
     * 7. INSPECT_MEMORY_CONTENT - Memory content inspection with string detection
     */
    public Response inspectMemoryContent(String addressStr, int length, boolean detectStrings) {
        return inspectMemoryContent(addressStr, length, detectStrings, null);
    }

    @McpTool(path = "/inspect_memory_content", description = "Inspect memory with string detection. On programs with multiple address spaces (e.g., embedded targets), prefix addresses with the space name (mem:1000) to avoid ambiguous resolution.", category = "analysis")
    public Response inspectMemoryContent(
            @Param(value = "address", paramType = "address",
                   description = "Address in the program. Accepts 0x<hex> (default space) or <space>:<hex> "
                               + "(e.g., mem:1000, code:ff00). Note: some programs — particularly "
                               + "embedded/microcontroller targets — are not address-space-agnostic; "
                               + "use get_address_spaces to discover spaces before assuming a plain hex "
                               + "address is unambiguous.") String addressStr,
            @Param(value = "length", defaultValue = "64", description = "Bytes to read") int length,
            @Param(value = "detect_strings", defaultValue = "true", description = "Auto-detect strings") boolean detectStrings,
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        try {
            Address addr = ServiceUtils.parseAddress(program, addressStr);
            if (addr == null) {
                return Response.err(ServiceUtils.getLastParseError());
            }

            Memory memory = program.getMemory();
            int MAX_READ_BYTES = 16 * 1024 * 1024; // 16 MB safety limit
            if (length <= 0 || length > MAX_READ_BYTES) {
                return Response.err("length must be between 1 and " + MAX_READ_BYTES + " bytes");
            }
            byte[] bytes = new byte[length];
            int bytesRead = memory.getBytes(addr, bytes);

            // Build hex dump
            StringBuilder hexDump = new StringBuilder();
            StringBuilder asciiRepr = new StringBuilder();

            for (int i = 0; i < bytesRead; i++) {
                if (i > 0 && i % 16 == 0) {
                    hexDump.append("\\n");
                    asciiRepr.append("\\n");
                }

                hexDump.append(String.format("%02X ", bytes[i] & 0xFF));

                // ASCII representation (printable chars only)
                char c = (char) (bytes[i] & 0xFF);
                if (c >= 0x20 && c <= 0x7E) {
                    asciiRepr.append(c);
                } else if (c == 0x00) {
                    asciiRepr.append("\\0");
                } else {
                    asciiRepr.append(".");
                }
            }

            // String detection heuristics
            boolean likelyString = false;
            int printableCount = 0;
            int nullTerminatorIndex = -1;
            int consecutivePrintable = 0;
            int maxConsecutivePrintable = 0;

            for (int i = 0; i < bytesRead; i++) {
                char c = (char) (bytes[i] & 0xFF);

                if (c >= 0x20 && c <= 0x7E) {
                    printableCount++;
                    consecutivePrintable++;
                    if (consecutivePrintable > maxConsecutivePrintable) {
                        maxConsecutivePrintable = consecutivePrintable;
                    }
                } else {
                    consecutivePrintable = 0;
                }

                if (c == 0x00 && nullTerminatorIndex == -1) {
                    nullTerminatorIndex = i;
                }
            }

            double printableRatio = (double) printableCount / bytesRead;

            // String detection criteria
            if (detectStrings) {
                likelyString = (printableRatio >= 0.6) ||
                              (maxConsecutivePrintable >= 4 && nullTerminatorIndex > 0);
            }

            // Detect potential string content
            String detectedString = null;
            int stringLength = 0;
            if (likelyString && nullTerminatorIndex > 0) {
                detectedString = new String(bytes, 0, nullTerminatorIndex, StandardCharsets.US_ASCII);
                stringLength = nullTerminatorIndex + 1;
            } else if (likelyString && printableRatio >= 0.8) {
                int endIdx = bytesRead;
                for (int i = bytesRead - 1; i >= 0; i--) {
                    if ((bytes[i] & 0xFF) >= 0x20 && (bytes[i] & 0xFF) <= 0x7E) {
                        endIdx = i + 1;
                        break;
                    }
                }
                detectedString = new String(bytes, 0, endIdx, StandardCharsets.US_ASCII);
                stringLength = endIdx;
            }

            Map<String, Object> resultMap = new LinkedHashMap<>();
            resultMap.put("address", addressStr);
            resultMap.put("bytes_read", bytesRead);
            resultMap.put("hex_dump", hexDump.toString().trim());
            resultMap.put("ascii_repr", asciiRepr.toString().trim());
            resultMap.put("printable_count", printableCount);
            resultMap.put("printable_ratio", Math.round(printableRatio * 100.0) / 100.0);
            resultMap.put("null_terminator_at", nullTerminatorIndex);
            resultMap.put("max_consecutive_printable", maxConsecutivePrintable);
            resultMap.put("is_likely_string", likelyString);
            resultMap.put("detected_string", detectedString);
            resultMap.put("suggested_type", detectedString != null ? "char[" + stringLength + "]" : null);
            resultMap.put("string_length", stringLength);

            return Response.ok(resultMap);
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    /**
     * Detect cryptographic constants in the binary (AES S-boxes, SHA constants, etc.)
     */
    public Response detectCryptoConstants() {
        return detectCryptoConstants(null);
    }

    @McpTool(path = "/detect_crypto_constants", description = "Detect crypto algorithm constants", category = "malware")
    public Response detectCryptoConstants(
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();

        try {
            // This is a placeholder implementation
            List<Map<String, Object>> results = new ArrayList<>();
            results.add(JsonHelper.mapOf(
                "algorithm", "Crypto Detection",
                "status", "Not yet implemented",
                "note", "This endpoint requires advanced pattern matching against known crypto constants"
            ));
            return Response.ok(results);
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    /**
     * Search for byte patterns with optional wildcards
     */
    public Response searchBytePatterns(String pattern, String mask) {
        return searchBytePatterns(pattern, mask, null);
    }

    @McpTool(path = "/search_byte_patterns", description = "Search for byte patterns with masks", category = "analysis")
    public Response searchBytePatterns(
            @Param(value = "pattern", description = "Hex byte pattern") String pattern,
            @Param(value = "mask", description = "Pattern mask (omit or leave empty for exact match)", defaultValue = "") String mask,
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        if (pattern == null || pattern.trim().isEmpty()) {
            return Response.err("Pattern is required");
        }

        try {
            // Parse hex pattern (e.g., "E8 ?? ?? ?? ??" or "E8????????")
            String cleanPattern = pattern.trim().toUpperCase().replaceAll("\\s+", "");

            // Convert pattern to byte array and mask
            int patternLen = cleanPattern.replace("?", "").length() / 2 + cleanPattern.replace("?", "").length() % 2;
            if (cleanPattern.contains("?")) {
                patternLen = cleanPattern.length() / 2;
            }

            byte[] patternBytes = new byte[patternLen];
            byte[] maskBytes = new byte[patternLen];

            int byteIndex = 0;
            for (int i = 0; i < cleanPattern.length(); i += 2) {
                if (cleanPattern.charAt(i) == '?' || (i + 1 < cleanPattern.length() && cleanPattern.charAt(i + 1) == '?')) {
                    patternBytes[byteIndex] = 0;
                    maskBytes[byteIndex] = 0;
                } else {
                    String hexByte = cleanPattern.substring(i, Math.min(i + 2, cleanPattern.length()));
                    patternBytes[byteIndex] = (byte) Integer.parseInt(hexByte, 16);
                    maskBytes[byteIndex] = (byte) 0xFF;
                }
                byteIndex++;
            }

            // Search memory for pattern
            Memory memory = program.getMemory();
            List<Map<String, Object>> matches = new ArrayList<>();
            final int MAX_MATCHES = 1000;

            for (MemoryBlock block : memory.getBlocks()) {
                if (!block.isInitialized()) continue;

                Address blockStart = block.getStart();
                long blockSize = block.getSize();

                byte[] blockData = new byte[(int) Math.min(blockSize, Integer.MAX_VALUE)];
                try {
                    block.getBytes(blockStart, blockData);
                } catch (Exception e) {
                    continue;
                }

                for (int i = 0; i <= blockData.length - patternBytes.length; i++) {
                    boolean matchFound = true;
                    for (int j = 0; j < patternBytes.length; j++) {
                        if (maskBytes[j] != 0 && blockData[i + j] != patternBytes[j]) {
                            matchFound = false;
                            break;
                        }
                    }

                    if (matchFound) {
                        Address matchAddr = blockStart.add(i);
                        matches.add(ServiceUtils.addressToJson(matchAddr, program));

                        if (matches.size() >= MAX_MATCHES) {
                            matches.add(JsonHelper.mapOf("note", "Limited to " + MAX_MATCHES + " matches"));
                            break;
                        }
                    }
                }

                if (matches.size() >= MAX_MATCHES) break;
            }

            if (matches.isEmpty()) {
                matches.add(JsonHelper.mapOf("note", "No matches found"));
            }

            return Response.ok(matches);
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    /**
     * Find functions structurally similar to the target function
     * Uses basic block count, instruction count, call count, and cyclomatic complexity
     */
    public Response findSimilarFunctions(String targetFunction, double threshold) {
        return findSimilarFunctions(targetFunction, threshold, null);
    }

    @McpTool(path = "/find_similar_functions", description = "Find structurally similar functions", category = "analysis")
    public Response findSimilarFunctions(
            @Param(value = "target_function", description = "Function name") String targetFunction,
            @Param(value = "threshold", defaultValue = "0.8", description = "Similarity threshold") double threshold,
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        if (targetFunction == null || targetFunction.trim().isEmpty()) {
            return Response.err("Target function name is required");
        }

        try {
            FunctionManager functionManager = program.getFunctionManager();

            // Find the target function by name or address
            FunctionRef.Result resolved = FunctionRef.of(targetFunction).tryResolve(program);
            if (!resolved.isSuccess()) {
                return Response.err("Function not found: " + targetFunction);
            }
            Function targetFunc = resolved.function();

            // Calculate metrics for target function
            BasicBlockModel blockModel = new BasicBlockModel(program);
            FunctionMetrics targetMetrics = calculateFunctionMetrics(targetFunc, blockModel, program);

            // Find similar functions
            List<Map<String, Object>> similarFunctions = new ArrayList<>();

            for (Function func : functionManager.getFunctions(true)) {
                if (func.getName().equals(targetFunction)) continue;
                if (func.isThunk()) continue;

                FunctionMetrics funcMetrics = calculateFunctionMetrics(func, blockModel, program);
                double similarity = calculateSimilarity(targetMetrics, funcMetrics);

                if (similarity >= threshold) {
                    Map<String, Object> simItem = new LinkedHashMap<>();
                    simItem.put("name", func.getName());
                    simItem.putAll(ServiceUtils.addressToJson(func.getEntryPoint(), program));
                    simItem.put("similarity", Math.round(similarity * 1000.0) / 1000.0);
                    simItem.put("basic_blocks", funcMetrics.basicBlockCount);
                    simItem.put("instructions", funcMetrics.instructionCount);
                    simItem.put("calls", funcMetrics.callCount);
                    simItem.put("complexity", funcMetrics.cyclomaticComplexity);
                    similarFunctions.add(simItem);
                }
            }

            // Sort by similarity descending
            similarFunctions.sort((a, b) -> Double.compare((Double)b.get("similarity"), (Double)a.get("similarity")));

            // Limit results
            if (similarFunctions.size() > 50) {
                similarFunctions = similarFunctions.subList(0, 50);
            }

            return Response.ok(JsonHelper.mapOf(
                "target_function", targetFunction,
                "target_metrics", JsonHelper.mapOf(
                    "basic_blocks", targetMetrics.basicBlockCount,
                    "instructions", targetMetrics.instructionCount,
                    "calls", targetMetrics.callCount,
                    "complexity", targetMetrics.cyclomaticComplexity
                ),
                "threshold", threshold,
                "matches_found", similarFunctions.size(),
                "similar_functions", similarFunctions
            ));
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    /**
     * Analyze function control flow complexity
     * Calculates cyclomatic complexity, basic blocks, edges, and detailed metrics
     */
    public Response analyzeControlFlow(String functionName) {
        return analyzeControlFlow(functionName, null);
    }

    @McpTool(path = "/analyze_control_flow", description = "Analyze function control flow complexity", category = "analysis")
    public Response analyzeControlFlow(
            @Param(value = "function_name", description = "Function name") String functionName,
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        if (functionName == null || functionName.trim().isEmpty()) {
            return Response.err("Function name is required");
        }

        try {
            FunctionManager functionManager = program.getFunctionManager();

            // Find the function by name or address
            FunctionRef.Result resolved = FunctionRef.of(functionName).tryResolve(program);
            if (!resolved.isSuccess()) {
                return Response.err("Function not found: " + functionName);
            }
            Function func = resolved.function();

            BasicBlockModel blockModel = new BasicBlockModel(program);
            Listing listing = program.getListing();

            // Collect detailed metrics
            int basicBlockCount = 0;
            int edgeCount = 0;
            int conditionalBranches = 0;
            int unconditionalJumps = 0;
            int loops = 0;
            int instructionCount = 0;
            int callCount = 0;
            int returnCount = 0;
            List<Map<String, Object>> blocks = new ArrayList<>();
            Set<Address> blockEntries = new HashSet<>();

            // First pass: collect all block entry points
            CodeBlockIterator blockIter = blockModel.getCodeBlocksContaining(func.getBody(), TaskMonitor.DUMMY);
            while (blockIter.hasNext()) {
                CodeBlock block = blockIter.next();
                blockEntries.add(block.getFirstStartAddress());
            }

            // Second pass: detailed analysis
            blockIter = blockModel.getCodeBlocksContaining(func.getBody(), TaskMonitor.DUMMY);
            while (blockIter.hasNext()) {
                CodeBlock block = blockIter.next();
                basicBlockCount++;

                Map<String, Object> blockInfo = new LinkedHashMap<>();
                blockInfo.putAll(ServiceUtils.addressToJson(block.getFirstStartAddress(), program));
                blockInfo.put("size", block.getNumAddresses());

                // Count edges and detect loops
                int outEdges = 0;
                boolean hasBackEdge = false;

                CodeBlockReferenceIterator destIter = block.getDestinations(TaskMonitor.DUMMY);
                while (destIter.hasNext()) {
                    CodeBlockReference ref = destIter.next();
                    outEdges++;
                    edgeCount++;
                    Address destAddr = ref.getDestinationAddress();

                    // Detect back edges (loops)
                    if (destAddr.compareTo(block.getFirstStartAddress()) < 0 &&
                        blockEntries.contains(destAddr)) {
                        hasBackEdge = true;
                    }
                }

                if (hasBackEdge) loops++;
                blockInfo.put("successors", outEdges);
                blockInfo.put("is_loop_header", hasBackEdge);

                // Classify block type
                if (outEdges == 0) {
                    blockInfo.put("type", "exit");
                } else if (outEdges == 1) {
                    blockInfo.put("type", "sequential");
                } else if (outEdges == 2) {
                    blockInfo.put("type", "conditional");
                    conditionalBranches++;
                } else {
                    blockInfo.put("type", "switch");
                }

                blocks.add(blockInfo);
            }

            // Count instructions by type
            InstructionIterator instrIter = listing.getInstructions(func.getBody(), true);
            while (instrIter.hasNext()) {
                Instruction instr = instrIter.next();
                instructionCount++;

                if (instr.getFlowType().isCall()) {
                    callCount++;
                } else if (instr.getFlowType().isTerminal()) {
                    returnCount++;
                } else if (instr.getFlowType().isJump()) {
                    if (!instr.getFlowType().isConditional()) {
                        unconditionalJumps++;
                    }
                }
            }

            // Calculate cyclomatic complexity: M = E - N + 2P
            int cyclomaticComplexity = edgeCount - basicBlockCount + 2;
            if (cyclomaticComplexity < 1) cyclomaticComplexity = 1;

            // Complexity rating
            String complexityRating;
            if (cyclomaticComplexity <= 5) {
                complexityRating = "low";
            } else if (cyclomaticComplexity <= 10) {
                complexityRating = "moderate";
            } else if (cyclomaticComplexity <= 20) {
                complexityRating = "high";
            } else if (cyclomaticComplexity <= 50) {
                complexityRating = "very_high";
            } else {
                complexityRating = "extreme";
            }

            // Truncate block details if too many
            List<Map<String, Object>> blockDetails = blocks.size() > 100 ? new ArrayList<>(blocks.subList(0, 100)) : blocks;
            if (blocks.size() > 100) {
                blockDetails.add(JsonHelper.mapOf("note", (blocks.size() - 100) + " additional blocks truncated"));
            }

            Address ep = func.getEntryPoint();
            Map<String, Object> cfResult = new LinkedHashMap<>();
            cfResult.put("function_name", functionName);
            cfResult.put("entry_point", ep.toString(false));
            if (ServiceUtils.getPhysicalSpaceCount(program) > 1) {
                cfResult.put("entry_point_full", ep.toString());
                cfResult.put("entry_point_space", ep.getAddressSpace().getName());
            }
            cfResult.put("size_bytes", func.getBody().getNumAddresses());
            cfResult.put("metrics", JsonHelper.mapOf(
                "cyclomatic_complexity", cyclomaticComplexity,
                "complexity_rating", complexityRating,
                "basic_blocks", basicBlockCount,
                "edges", edgeCount,
                "instructions", instructionCount,
                "conditional_branches", conditionalBranches,
                "unconditional_jumps", unconditionalJumps,
                "loops_detected", loops,
                "calls", callCount,
                "returns", returnCount
            ));
            cfResult.put("basic_block_details", blockDetails);
            return Response.ok(cfResult);
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    /**
     * Find potentially unreachable code blocks
     */
    public Response findDeadCode(String functionName) {
        return findDeadCode(functionName, null);
    }

    @McpTool(path = "/find_dead_code", description = "Identify unreachable code blocks", category = "analysis")
    public Response findDeadCode(
            @Param(value = "function_name", description = "Function name") String functionName,
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();

        if (functionName == null || functionName.trim().isEmpty()) {
            return Response.err("Function name is required");
        }

        try {
            // Placeholder implementation
            List<Map<String, Object>> results = new ArrayList<>();
            results.add(JsonHelper.mapOf(
                "function_name", functionName,
                "status", "Not yet implemented",
                "note", "This endpoint requires reachability analysis via control flow graph"
            ));
            return Response.ok(results);
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    /**
     * Analyze function documentation completeness
     */
    public Response analyzeFunctionCompleteness(String functionAddress) {
        return analyzeFunctionCompleteness(functionAddress, false, null);
    }

    public Response analyzeFunctionCompleteness(String functionAddress, boolean compact) {
        return analyzeFunctionCompleteness(functionAddress, compact, null);
    }

    /**
     * Analyze function documentation completeness.
     * @param compact When true, returns only scores and issue counts (no arrays, no recommendations).
     *                Reduces response from ~20KB to ~300 bytes.
     */
    @McpTool(path = "/analyze_function_completeness", description = "Check function documentation completeness. On programs with multiple address spaces (e.g., embedded targets), prefix addresses with the space name (mem:1000) to avoid ambiguous resolution.", category = "analysis")
    public Response analyzeFunctionCompleteness(
            @Param(value = "function_address", paramType = "address",
                   description = "Address in the program. Accepts 0x<hex> (default space) or <space>:<hex> "
                               + "(e.g., mem:1000, code:ff00). Note: some programs — particularly "
                               + "embedded/microcontroller targets — are not address-space-agnostic; "
                               + "use get_address_spaces to discover spaces before assuming a plain hex "
                               + "address is unambiguous.") String functionAddress,
            @Param(value = "compact", defaultValue = "false", description = "Compact output") boolean compact,
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        // Resolve address before entering SwingUtilities lambda
        Address addr = ServiceUtils.parseAddress(program, functionAddress);
        if (addr == null) return Response.err(ServiceUtils.getLastParseError());

        final AtomicReference<Map<String, Object>> resultData = new AtomicReference<>();
        final AtomicReference<String> errorMsg = new AtomicReference<>(null);

        try {
            // EDT-safe: if already on EDT (e.g. called from analyzeForDocumentation),
            // run directly to avoid nested invokeAndWait deadlock.
            Runnable completenessWork = () -> {
                try {
                    Function func = program.getFunctionManager().getFunctionAt(addr);
                    if (func == null) {
                        errorMsg.set("No function at address: " + functionAddress);
                        return;
                    }

                    // Classify function using shared utility
                    String classification = classifyFunction(func, program);
                    boolean isThunk = "thunk".equals(classification);
                    boolean isStub = "stub".equals(classification);
                    int instructionCount = getInstructionCount(func, program);
                    String decompiledCodeForContext = null;
                    boolean isCompilerHelper = looksLikeCompilerRuntimeHelper(func, null, instructionCount, isThunk, isStub);

                    Map<String, Object> data = new LinkedHashMap<>();
                    data.put("function_name", func.getName());
                    data.put("classification", classification);
                    data.put("is_thunk", isThunk);
                    data.put("has_custom_name", !ServiceUtils.isAutoGeneratedName(func.getName()));
                    data.put("has_prototype", func.getSignature() != null);
                    data.put("has_calling_convention", func.getCallingConvention() != null);
                    data.put("is_stub", isStub);
                    data.put("is_compiler_helper", isCompilerHelper);
                    data.put("documentation_profile", isCompilerHelper ? "compiler_helper" : classification);

                    // v3.0.1: Check if return type is unresolved (undefined)
                    String returnTypeName = func.getReturnType().getName();
                    boolean returnTypeUndefined = returnTypeName.startsWith("undefined");
                    data.put("return_type", returnTypeName);
                    data.put("return_type_resolved", !returnTypeUndefined);

                    // Enhanced plate comment validation
                    String plateComment = func.getComment();
                    boolean hasPlateComment = plateComment != null && !plateComment.isEmpty();
                    data.put("has_plate_comment", hasPlateComment);

                    // Validate plate comment structure and content
                    List<String> plateCommentIssues = new ArrayList<>();
                    if (hasPlateComment) {
                        validatePlateCommentStructure(plateComment, plateCommentIssues, func, isThunk, isCompilerHelper);
                    }

                    if (compact) {
                        data.put("plate_issues", plateCommentIssues.size());
                    } else {
                        data.put("plate_comment_issues", plateCommentIssues);
                    }

                    // Check for undefined variables (both names and types)
                    // PRIORITY 1 FIX: Use decompilation-based variable detection to avoid phantom variables
                    // v3.2.0: For thunk functions (single JMP), all decompiler variables belong to the
                    // callee body, not this function. Mark them all as unfixable at the thunk level.
                    List<String> undefinedVars = new ArrayList<>();
                    List<String> phantomVars = new ArrayList<>();
                    int unfixableUndefinedCount = 0;
                    boolean decompilationAvailable = false;

                    // Build set of variable names from low-level Variable API (hoisted for use in Hungarian check)
                    java.util.Set<String> localVarNames = new java.util.HashSet<>();
                    for (Variable local : func.getLocalVariables()) {
                        localVarNames.add(local.getName());
                    }

                    // Try to use decompilation-based detection (high-level API)
                    DecompileResults decompResults = functionService.decompileFunction(func, program);
                    if (decompResults != null && decompResults.decompileCompleted()) {
                        decompilationAvailable = true;
                        ghidra.program.model.pcode.HighFunction highFunction = decompResults.getHighFunction();

                        if (highFunction != null) {
                            // Check parameters (same as before, from Function API)
                            for (Parameter param : func.getParameters()) {
                                // Check for generic parameter names
                                if (param.getName().startsWith("param_")) {
                                    undefinedVars.add(param.getName() + " (generic name)");
                                }
                                // Check for undefined data types
                                String typeName = param.getDataType().getName();
                                if (typeName.startsWith("undefined")) {
                                    undefinedVars.add(param.getName() + " (type: " + typeName + ")");
                                    // Detect type-rename ordering violation on parameters
                                    if (!param.getName().startsWith("param_")) {
                                        String impliedType = inferTypeFromHungarianPrefix(param.getName());
                                        if (impliedType != null) {
                                            undefinedVars.add(param.getName() + " (WORKFLOW: renamed with '" + impliedType +
                                                "' prefix but type is still " + typeName +
                                                " — fix: set_function_prototype() with correct param type, then rename)");
                                        }
                                    }
                                }
                            }

                            // Check locals from HIGH-LEVEL decompiled symbol map (not low-level stack frame)
                            // This avoids phantom variables that exist in stack analysis but not decompilation
                            java.util.Set<String> checkedVarNames = new java.util.HashSet<>();

                            // v3.2.0: For thunks with no real locals, skip local variable checks entirely.
                            // The decompiler projects the callee body's variables through the thunk view,
                            // but these are display artifacts -- the thunk has no actual locals to fix.
                            boolean thunkWithNoLocals = isThunk && localVarNames.isEmpty();

                            Iterator<ghidra.program.model.pcode.HighSymbol> symbols = highFunction.getLocalSymbolMap().getSymbols();
                            while (symbols.hasNext()) {
                                ghidra.program.model.pcode.HighSymbol symbol = symbols.next();
                                String name = symbol.getName();
                                String typeName = symbol.getDataType().getName();
                                checkedVarNames.add(name);

                                // v3.0.1: Skip phantom decompiler artifacts (extraout_*, in_*)
                                // These cannot be renamed or typed -- exclude from scoring
                                if (name.startsWith("extraout_") || name.startsWith("in_")) {
                                    phantomVars.add(name + " (type: " + typeName + ", phantom)");
                                    continue;
                                }

                                // v3.2.0: Thunks with no real locals -- all decompiler variables are
                                // body-projected artifacts. Skip entirely (don't penalize at all).
                                if (thunkWithNoLocals) {
                                    continue;
                                }

                                // v3.2.0: For thunks with some locals, or register-only vars
                                boolean isRegisterOnly = isThunk || !localVarNames.contains(name);

                                // Check for generic local names (local_XX or XVar patterns)
                                if (name.startsWith("local_") ||
                                    name.matches(".*Var\\d+") ||  // pvVar1, iVar2, etc.
                                    name.matches("(i|u|d|f|p|b)Var\\d+")) {  // specific type patterns
                                    undefinedVars.add(name + " (generic name)");
                                    if (isRegisterOnly) unfixableUndefinedCount++;
                                }

                                // Check for undefined data types (decompiler display type)
                                if (typeName.startsWith("undefined")) {
                                    undefinedVars.add(name + " (type: " + typeName + ")");
                                    if (isRegisterOnly) unfixableUndefinedCount++;

                                    // Detect type-rename ordering violation: variable has a meaningful
                                    // Hungarian prefix implying a resolved type, but actual type is still undefined.
                                    // This means the AI renamed before setting the type — a workflow error.
                                    if (!name.startsWith("local_") && !name.startsWith("param_") &&
                                        !name.matches(".*Var\\d+") && !name.startsWith("extraout_") &&
                                        !name.startsWith("in_")) {
                                        // Variable was renamed (not auto-generated) but type is still undefined
                                        String impliedType = inferTypeFromHungarianPrefix(name);
                                        if (impliedType != null) {
                                            String fixAction = isRegisterOnly
                                                ? " — fix: type may be register-only, try set_local_variable_type('" + name + "', '" + impliedType.split("/")[0] + "'), on failure use PRE_COMMENT"
                                                : " — fix: set_local_variable_type('" + name + "', '" + impliedType.split("/")[0] + "')";
                                            undefinedVars.add(name + " (WORKFLOW: renamed with '" + impliedType +
                                                "' prefix but type is still " + typeName + fixAction + ")");
                                        }
                                    }

                                    // Detect large byte-array buffers that likely need struct definitions
                                    java.util.regex.Matcher arrayMatcher = java.util.regex.Pattern.compile("undefined1\\[(\\d+)\\]").matcher(typeName);
                                    if (arrayMatcher.matches()) {
                                        int arraySize = Integer.parseInt(arrayMatcher.group(1));
                                        if (arraySize > 8) {
                                            String bufferHint = name.toLowerCase();
                                            boolean suggestStruct = bufferHint.contains("context") || bufferHint.contains("buffer") ||
                                                bufferHint.contains("record") || bufferHint.contains("info") ||
                                                bufferHint.contains("data") || bufferHint.contains("callback") ||
                                                bufferHint.contains("param") || bufferHint.contains("state");
                                            if (suggestStruct) {
                                                undefinedVars.add(name + " (STRUCT: " + arraySize + "-byte buffer with struct-like name — create struct with create_struct(), then set_local_variable_type('" + name + "', 'YourStructName'))");
                                            } else if (arraySize >= 16) {
                                                // Large buffers always suggest struct even without name hints
                                                undefinedVars.add(name + " (STRUCT: " + arraySize + "-byte buffer — likely needs struct definition via create_struct())");
                                            }
                                        }
                                    }
                                }
                            }

                            // v3.0.1: Cross-check storage types from low-level Variable API
                            // The decompiler may show resolved types (e.g. "short *") while the
                            // actual storage type is still "undefined4". Catch these mismatches.
                            for (Variable local : func.getLocalVariables()) {
                                String localName = local.getName();
                                String storageName = local.getDataType().getName();
                                // Only check variables that exist in decompiled code (not stack phantoms)
                                if (checkedVarNames.contains(localName) && storageName.startsWith("undefined")) {
                                    String flag = localName + " (storage type: " + storageName + ", decompiler shows resolved type)";
                                    if (!undefinedVars.contains(flag)) {
                                        undefinedVars.add(flag);
                                    }
                                }
                            }
                            // Also check register-based HighSymbols whose storage type may be undefined
                            // These may not appear in func.getLocalVariables() at all
                            Iterator<ghidra.program.model.pcode.HighSymbol> storageCheckSymbols = highFunction.getLocalSymbolMap().getSymbols();
                            while (storageCheckSymbols.hasNext()) {
                                ghidra.program.model.pcode.HighSymbol sym = storageCheckSymbols.next();
                                String symName = sym.getName();
                                if (symName.startsWith("extraout_") || symName.startsWith("in_")) continue;
                                ghidra.program.model.pcode.HighVariable highVar = sym.getHighVariable();
                                if (highVar != null) {
                                    // Get the representative varnode to check actual storage
                                    ghidra.program.model.pcode.Varnode rep = highVar.getRepresentative();
                                    if (rep != null && rep.getSize() > 0) {
                                        // Check if the HighVariable's declared type differs from what Ghidra stores
                                        DataType highType = highVar.getDataType();
                                        DataType symType = sym.getDataType();
                                        // If symbol storage reports undefined but decompiler infers a type
                                        if (symType != null && symType.getName().startsWith("undefined") &&
                                            highType != null && !highType.getName().startsWith("undefined")) {
                                            String flag = symName + " (storage type: " + symType.getName() + ", decompiler shows: " + highType.getName() + ")";
                                            if (!undefinedVars.stream().anyMatch(v -> v.startsWith(symName + " "))) {
                                                undefinedVars.add(flag);
                                                // v3.1.1: Track as unfixable if register-only (not in func.getLocalVariables())
                                                if (!localVarNames.contains(symName)) {
                                                    unfixableUndefinedCount++;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // Fallback to low-level API if decompilation failed (with warning in output)
                    if (!decompilationAvailable) {
                        // Check parameters
                        for (Parameter param : func.getParameters()) {
                            if (param.getName().startsWith("param_")) {
                                undefinedVars.add(param.getName() + " (generic name)");
                            }
                            String typeName = param.getDataType().getName();
                            if (typeName.startsWith("undefined")) {
                                undefinedVars.add(param.getName() + " (type: " + typeName + ")");
                            }
                        }

                        // Use low-level API with phantom variable warning
                        for (Variable local : func.getLocalVariables()) {
                            if (local.getName().startsWith("local_")) {
                                undefinedVars.add(local.getName() + " (generic name, may be phantom variable)");
                            }
                            String typeName = local.getDataType().getName();
                            if (typeName.startsWith("undefined")) {
                                undefinedVars.add(local.getName() + " (type: " + typeName + ", may be phantom variable)");
                            }
                        }
                    }

                    data.put("decompilation_available", decompilationAvailable);

                    // Bulk stack-array heuristic: functions with a very high count of
                    // generic locals (e.g., data table initializers with 1,000+ decomposed
                    // array slots) are impractical to fix via individual API calls.
                    // Reclassify the excess above a reasonable threshold as structural.
                    int BULK_UNDEFINED_THRESHOLD = 100;
                    int BULK_FIXABLE_ALLOWANCE = 20; // still count first 20 as fixable
                    int totalFixableUndefined = undefinedVars.size() - unfixableUndefinedCount;
                    if (totalFixableUndefined > BULK_UNDEFINED_THRESHOLD) {
                        int reclassified = totalFixableUndefined - BULK_FIXABLE_ALLOWANCE;
                        unfixableUndefinedCount += reclassified;
                        data.put("bulk_array_reclassified", reclassified);
                    }

                    if (compact) {
                        data.put("undefined_count", undefinedVars.size());
                        data.put("phantom_count", phantomVars.size());
                    } else {
                        data.put("undefined_variables", undefinedVars);

                        // v3.0.1: Report phantom variables separately (not counted in scoring)
                        data.put("phantom_variables", phantomVars);
                    }

                    // Check Hungarian notation compliance
                    // v3.2.0: Track unfixable Hungarian violations (register-only/thunk variables)
                    List<String> hungarianViolations = new ArrayList<>();
                    int unfixableHungarianCount = 0;
                    boolean funcIsThiscall = false;
                    try {
                        funcIsThiscall = "__thiscall".equals(func.getCallingConventionName());
                    } catch (Exception ignored) {}

                    for (Parameter param : func.getParameters()) {
                        int prevSize = hungarianViolations.size();
                        validateHungarianNotation(param.getName(), param.getDataType().getName(), false, true, hungarianViolations);
                        // __thiscall ECX this auto-param: any violation is structural (can't retype via API)
                        if (hungarianViolations.size() > prevSize && funcIsThiscall
                                && "this".equals(param.getName()) && param.isAutoParameter()) {
                            unfixableHungarianCount += (hungarianViolations.size() - prevSize);
                        }
                    }

                    // Use decompilation-based locals if available, otherwise fallback to low-level API
                    if (decompilationAvailable && decompResults != null && decompResults.getHighFunction() != null) {
                        ghidra.program.model.pcode.HighFunction highFunction = decompResults.getHighFunction();
                        Iterator<ghidra.program.model.pcode.HighSymbol> symbols = highFunction.getLocalSymbolMap().getSymbols();
                        while (symbols.hasNext()) {
                            ghidra.program.model.pcode.HighSymbol symbol = symbols.next();
                            int prevSize = hungarianViolations.size();
                            validateHungarianNotation(symbol.getName(), symbol.getDataType().getName(), false, false, hungarianViolations);
                            // If a new violation was added and the variable is register-only or thunk-owned, it's unfixable
                            if (hungarianViolations.size() > prevSize && (isThunk || !localVarNames.contains(symbol.getName()))) {
                                unfixableHungarianCount += (hungarianViolations.size() - prevSize);
                            }
                        }
                    } else {
                        // Fallback to low-level API
                        for (Variable local : func.getLocalVariables()) {
                            validateHungarianNotation(local.getName(), local.getDataType().getName(), false, false, hungarianViolations);
                        }
                    }

                    // Enhanced validation: Check parameter type quality
                    // Pass existing decompilation to avoid redundant re-decompile (which can silently fail)
                    List<String> typeQualityIssues = new ArrayList<>();
                    ghidra.program.model.pcode.HighFunction hf = (decompilationAvailable && decompResults != null) ? decompResults.getHighFunction() : null;
                    validateParameterTypeQuality(func, typeQualityIssues, hf);

                    if (compact) {
                        data.put("hungarian_violations", hungarianViolations.size());
                        data.put("type_quality_issues", typeQualityIssues.size());
                    } else {
                        data.put("hungarian_notation_violations", hungarianViolations);
                        data.put("type_quality_issues", typeQualityIssues);
                    }

                    // NEW: Check for unrenamed DAT_* globals, LAB_* labels, and undocumented Ordinal calls in decompiled code
                    List<String> unrenamedGlobals = new ArrayList<>();
                    List<String> unrenamedLabels = new ArrayList<>();
                    List<String> undocumentedOrdinals = new ArrayList<>();
                    int inlineCommentCount = 0;
                    int codeLineCount = 0;

                    if (decompilationAvailable && decompResults != null) {
                        String decompiledCode = decompResults.getDecompiledFunction().getC();
                        if (decompiledCode != null) {
                            decompiledCodeForContext = decompiledCode;
                            if (!isCompilerHelper) {
                                isCompilerHelper = looksLikeCompilerRuntimeHelper(func, decompiledCodeForContext, instructionCount, isThunk, isStub);
                                data.put("is_compiler_helper", isCompilerHelper);
                                data.put("documentation_profile", isCompilerHelper ? "compiler_helper" : classification);
                            }
                            // Count lines of code and inline comments
                            // We need to distinguish between:
                            // 1. Plate comments (before function body) - don't count
                            // 2. Body comments (inside function braces) - count these
                            String[] lines = decompiledCode.split("\n");
                            boolean inFunctionBody = false;
                            boolean inPlateComment = false;
                            int braceDepth = 0;

                            for (String line : lines) {
                                String trimmed = line.trim();

                                // Track plate comment block (before function signature)
                                if (!inFunctionBody && trimmed.startsWith("/*")) {
                                    inPlateComment = true;
                                }
                                if (inPlateComment && trimmed.endsWith("*/")) {
                                    inPlateComment = false;
                                    continue;
                                }
                                if (inPlateComment) continue;

                                // Track function body by counting braces
                                for (char c : trimmed.toCharArray()) {
                                    if (c == '{') {
                                        braceDepth++;
                                        inFunctionBody = true;
                                    } else if (c == '}') {
                                        braceDepth--;
                                    }
                                }

                                // Count code lines (non-empty, non-comment lines inside function)
                                if (inFunctionBody && !trimmed.isEmpty() &&
                                    !trimmed.startsWith("/*") && !trimmed.startsWith("*") && !trimmed.startsWith("//")) {
                                    codeLineCount++;
                                }

                                // Count comments inside function body
                                // This includes both standalone comment lines and trailing comments
                                if (inFunctionBody && trimmed.contains("/*")) {
                                    // Exclude WARNING comments from decompiler (they're not user-added)
                                    if (!trimmed.contains("WARNING:")) {
                                        inlineCommentCount++;
                                    }
                                }
                                // Also count // style comments
                                if (inFunctionBody && trimmed.contains("//")) {
                                    inlineCommentCount++;
                                }
                            }

                            // Find DAT_* references (unrenamed globals)
                            java.util.regex.Pattern datPattern = java.util.regex.Pattern.compile("DAT_[0-9a-fA-F]+");
                            java.util.regex.Matcher datMatcher = datPattern.matcher(decompiledCode);
                            java.util.Set<String> foundDats = new java.util.HashSet<>();
                            while (datMatcher.find()) {
                                foundDats.add(datMatcher.group());
                            }
                            unrenamedGlobals.addAll(foundDats);

                            // Find undocumented Ordinal calls in the function body
                            // v3.2.0: Use callee-based detection instead of text scanning.
                            // This correctly counts only functions THIS function calls (not callers
                            // mentioned in the plate comment) and excludes self-referencing artifacts
                            // from unresolved IAT indirect jumps.
                            java.util.Set<String> calleeOrdinals = new java.util.HashSet<>();
                            for (Function callee : func.getCalledFunctions(new ConsoleTaskMonitor())) {
                                if (callee.getName().startsWith("Ordinal_")) {
                                    calleeOrdinals.add(callee.getName());
                                }
                            }

                            // For each callee ordinal, check if it has a nearby comment in the decompiled body
                            int bodyStart = decompiledCode.indexOf('{');
                            String bodyCode = bodyStart >= 0 ? decompiledCode.substring(bodyStart) : decompiledCode;

                            // Find LAB_* references (unrenamed labels within function body)
                            java.util.regex.Pattern labPattern = java.util.regex.Pattern.compile("LAB_[0-9a-fA-F]+");
                            java.util.regex.Matcher labMatcher = labPattern.matcher(bodyCode);
                            java.util.Set<String> foundLabs = new java.util.HashSet<>();
                            while (labMatcher.find()) {
                                foundLabs.add(labMatcher.group());
                            }
                            unrenamedLabels.addAll(foundLabs);

                            for (String ordinal : calleeOrdinals) {
                                java.util.regex.Pattern ordinalPattern = java.util.regex.Pattern.compile(java.util.regex.Pattern.quote(ordinal));
                                java.util.regex.Matcher ordinalMatcher = ordinalPattern.matcher(bodyCode);
                                boolean documented = false;
                                while (ordinalMatcher.find()) {
                                    int pos = ordinalMatcher.start();
                                    int lineStart = bodyCode.lastIndexOf('\n', pos);
                                    int lineEnd = bodyCode.indexOf('\n', pos);
                                    if (lineEnd == -1) lineEnd = bodyCode.length();
                                    String currentLine = bodyCode.substring(Math.max(0, lineStart + 1), lineEnd);
                                    if (currentLine.contains("/*") || currentLine.contains("//")) {
                                        documented = true;
                                        break;
                                    }
                                    if (lineStart > 0) {
                                        int prevLineStart = bodyCode.lastIndexOf('\n', lineStart - 1);
                                        String prevLine = bodyCode.substring(Math.max(0, prevLineStart + 1), lineStart).trim();
                                        if ((prevLine.contains("/*") || prevLine.contains("//")) && prevLine.contains(ordinal)) {
                                            documented = true;
                                            break;
                                        }
                                    }
                                }
                                if (!documented) {
                                    undocumentedOrdinals.add(ordinal);
                                }
                            }
                        }
                    }

                    // Count disassembly EOL comments and detect undocumented magic numbers
                    int disasmCommentCount = 0;
                    List<String> undocumentedMagicNumbers = new ArrayList<>();
                    ghidra.program.model.listing.InstructionIterator disasmIter =
                        program.getListing().getInstructions(func.getBody(), true);
                    while (disasmIter.hasNext()) {
                        ghidra.program.model.listing.Instruction instr = disasmIter.next();
                        String eolComment = program.getListing().getComment(
                            ghidra.program.model.listing.CodeUnit.EOL_COMMENT, instr.getAddress());
                        boolean hasComment = eolComment != null && !eolComment.isEmpty();
                        if (hasComment) {
                            disasmCommentCount++;
                        }

                        // Detect magic number constants in instruction operands
                        if (!hasComment) {
                            for (int opIdx = 0; opIdx < instr.getNumOperands(); opIdx++) {
                                int opType = instr.getOperandType(opIdx);
                                // Check for scalar (immediate) operand
                                if ((opType & ghidra.program.model.lang.OperandType.SCALAR) != 0) {
                                    ghidra.program.model.scalar.Scalar scalar = instr.getScalar(opIdx);
                                    if (scalar != null) {
                                        long val = scalar.getUnsignedValue();
                                        // Flag non-trivial constants: skip 0, 1, -1, small powers of 2
                                        if (val > 1 && val != 0xFFFFFFFFL && val != 2 && val != 4 && val != 8 && val != 16) {
                                            String hex = String.format("0x%X", val);
                                            undocumentedMagicNumbers.add(hex + " at " + instr.getAddress().toString());
                                            break; // one finding per instruction is enough
                                        }
                                    }
                                }
                            }
                        }
                    }
                    // Include disassembly comments in total for density calculation
                    int totalCommentCount = inlineCommentCount + disasmCommentCount;

                    // Detect unresolved struct field accesses in decompiled code
                    // Patterns: *(type *)(var + 0xNN), var[0xNN], *(int *)(param + 0xNN)
                    List<String> unresolvedStructAccesses = new ArrayList<>();
                    if (decompiledCodeForContext != null) {
                        int bodyStart2 = decompiledCodeForContext.indexOf('{');
                        String bodyForStruct = bodyStart2 >= 0 ? decompiledCodeForContext.substring(bodyStart2) : decompiledCodeForContext;
                        // Match raw hex offset dereferences: *(type *)(expr + 0xNN) or *(expr + 0xNN)
                        java.util.regex.Pattern rawOffsetPattern = java.util.regex.Pattern.compile(
                            "\\*\\s*\\([^)]*\\)\\s*\\([^)]+\\+\\s*(0x[0-9a-fA-F]+)\\)");
                        java.util.regex.Matcher rawMatcher = rawOffsetPattern.matcher(bodyForStruct);
                        java.util.Set<String> seenOffsets = new java.util.HashSet<>();
                        while (rawMatcher.find()) {
                            String offset = rawMatcher.group(1);
                            if (seenOffsets.add(offset)) {
                                unresolvedStructAccesses.add("raw offset dereference at +" + offset);
                            }
                        }
                    }

                    if (compact) {
                        data.put("globals_unrenamed", unrenamedGlobals.size());
                        data.put("labels_unrenamed", unrenamedLabels.size());
                        data.put("ordinals_undocumented", undocumentedOrdinals.size());
                        data.put("magic_numbers_undocumented", undocumentedMagicNumbers.size());
                        data.put("struct_accesses_unresolved", unresolvedStructAccesses.size());
                    } else {
                        data.put("unrenamed_globals", unrenamedGlobals);
                        data.put("unrenamed_labels", unrenamedLabels);
                        data.put("undocumented_ordinals", undocumentedOrdinals);
                        data.put("undocumented_magic_numbers", undocumentedMagicNumbers);
                        data.put("unresolved_struct_accesses", unresolvedStructAccesses);
                    }

                    data.put("inline_comment_count", inlineCommentCount);
                    data.put("disasm_comment_count", disasmCommentCount);
                    data.put("code_line_count", codeLineCount);

                    // Calculate comment density using total comments (decompiler + disassembly)
                    double commentDensity = codeLineCount > 0 ? (totalCommentCount * 10.0 / codeLineCount) : 0;
                    data.put("comment_density", Math.round(commentDensity * 100.0) / 100.0);

                    CompletenessScoreResult scoreResult = calculateCompletenessScore(func, undefinedVars.size(), plateCommentIssues.size(), hungarianViolations.size(), typeQualityIssues.size(), unrenamedGlobals.size(), unrenamedLabels.size(), undocumentedOrdinals.size(), undocumentedMagicNumbers.size(), unresolvedStructAccesses.size(), commentDensity, typeQualityIssues, phantomVars.size(), codeLineCount, unfixableUndefinedCount, unfixableHungarianCount, isThunk, isStub, isCompilerHelper);
                    data.put("completeness_score", scoreResult.score);
                    data.put("effective_score", scoreResult.effectiveScore);
                    data.put("all_deductions_unfixable", scoreResult.score < 100.0 && scoreResult.effectiveScore >= 100.0);
                    data.put("fixable_deductions", scoreResult.fixablePenalty);
                    data.put("structural_deductions", scoreResult.structuralPenalty);
                    data.put("max_achievable_score", scoreResult.maxAchievableScore);

                    if (compact) {
                        data.put("deduction_count", scoreResult.deductionBreakdown.size());
                    } else {
                        data.put("deduction_breakdown", scoreResult.deductionBreakdown);
                    }

                    // PROP-0002: Report whether function has renameable variables (not register-only SSA)
                    data.put("has_renameable_variables", !localVarNames.isEmpty());

                    if (!compact) {
                        // Generate workflow-aligned recommendations (skipped in compact mode -- AI has these in its prompt)
                        List<String> recommendations = generateWorkflowRecommendations(
                            func, undefinedVars, plateCommentIssues, hungarianViolations, typeQualityIssues,
                            unrenamedGlobals, unrenamedLabels, undocumentedOrdinals, undocumentedMagicNumbers, unresolvedStructAccesses,
                            commentDensity, scoreResult, codeLineCount, isThunk, isStub, isCompilerHelper
                        );

                        List<Map<String, Object>> remediationActions = generateRemediationActions(
                            func, undefinedVars, plateCommentIssues, hungarianViolations, typeQualityIssues,
                            unrenamedGlobals, unrenamedLabels, undocumentedOrdinals, undocumentedMagicNumbers, unresolvedStructAccesses,
                            commentDensity, scoreResult, isThunk, isStub, isCompilerHelper
                        );

                        data.put("recommendations", recommendations);
                        data.put("remediation_actions", remediationActions);
                    }

                    resultData.set(data);
                } catch (Exception e) {
                    errorMsg.set(e.getMessage());
                }
            };

            if (SwingUtilities.isEventDispatchThread()) {
                completenessWork.run();
            } else {
                SwingUtilities.invokeAndWait(completenessWork);
            }

            if (errorMsg.get() != null) {
                return Response.err(errorMsg.get());
            }
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }

        return Response.ok(resultData.get());
    }

    @McpTool(path = "/batch_analyze_completeness", method = "POST", description = "Analyze completeness for multiple functions", category = "analysis")
    @SuppressWarnings("unchecked")
    public Response batchAnalyzeCompleteness(
            @Param(value = "addresses", source = ParamSource.BODY) Object addressesObj,
            @Param(value = "program", description = "Target program name", defaultValue = "") String programName) {
        List<String> addresses;
        if (addressesObj instanceof List<?> list) {
            addresses = list.stream().map(String::valueOf).collect(java.util.stream.Collectors.toList());
        } else if (addressesObj instanceof String s) {
            addresses = new ArrayList<>();
            for (String part : s.split(",")) {
                String trimmed = part.trim();
                if (!trimmed.isEmpty()) {
                    addresses.add(trimmed);
                }
            }
        } else {
            return Response.err("Missing required parameter: addresses (JSON array of hex addresses)");
        }
        if (addresses.isEmpty()) {
            return Response.err("Missing required parameter: addresses (JSON array of hex addresses)");
        }
        StringBuilder sb = new StringBuilder();
        sb.append("{\"results\": [");
        for (int i = 0; i < addresses.size(); i++) {
            if (i > 0) sb.append(", ");
            sb.append(analyzeFunctionCompleteness(addresses.get(i), false, programName).toJson());
        }
        sb.append("], \"count\": ").append(addresses.size()).append("}");
        return Response.text(sb.toString());
    }

    /**
     * v1.5.0: Find next undefined function needing analysis
     */
    @McpTool(path = "/find_next_undefined_function", description = "Find next function needing analysis. On programs with multiple address spaces (e.g., embedded targets), prefix addresses with the space name (mem:1000) to avoid ambiguous resolution.", category = "analysis")
    public Response findNextUndefinedFunction(
            @Param(value = "start_address", paramType = "address",
                   description = "Address in the program. Accepts 0x<hex> (default space) or <space>:<hex> "
                               + "(e.g., mem:1000, code:ff00). Note: some programs — particularly "
                               + "embedded/microcontroller targets — are not address-space-agnostic; "
                               + "use get_address_spaces to discover spaces before assuming a plain hex "
                               + "address is unambiguous.") String startAddress,
            @Param(value = "criteria", description = "Search criteria") String criteria,
            @Param(value = "pattern", description = "Name pattern filter") String pattern,
            @Param(value = "direction", description = "Search direction") String direction,
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        // Resolve address before entering SwingUtilities lambda
        final Address startAddr;
        if (startAddress != null && !startAddress.isEmpty()) {
            startAddr = ServiceUtils.parseAddress(program, startAddress);
            if (startAddr == null) return Response.err(ServiceUtils.getLastParseError());
        } else {
            startAddr = program.getMinAddress();
        }

        final AtomicReference<Response> responseRef = new AtomicReference<>(null);
        final AtomicReference<String> errorMsg = new AtomicReference<>(null);

        try {
            SwingUtilities.invokeAndWait(() -> {
                try {
                    FunctionManager funcMgr = program.getFunctionManager();
                    Address start = startAddr;

                    String searchPattern = pattern; // null means match all auto-generated names
                    boolean ascending = !"descending".equals(direction);

                    FunctionIterator iter = ascending ?
                        funcMgr.getFunctions(start, true) :
                        funcMgr.getFunctions(start, false);

                    Function found = null;
                    while (iter.hasNext()) {
                        Function func = iter.next();
                        boolean matches = (searchPattern != null)
                            ? func.getName().startsWith(searchPattern)
                            : ServiceUtils.isAutoGeneratedName(func.getName());
                        if (matches) {
                            found = func;
                            break;
                        }
                    }

                    if (found != null) {
                        responseRef.set(Response.ok(JsonHelper.mapOf(
                            "found", true,
                            "function_name", found.getName(),
                            "function_address", found.getEntryPoint().toString(),
                            "xref_count", found.getSymbol().getReferenceCount()
                        )));
                    } else {
                        responseRef.set(Response.ok(JsonHelper.mapOf("found", false)));
                    }
                } catch (Exception e) {
                    errorMsg.set(e.getMessage());
                }
            });

            if (errorMsg.get() != null) {
                return Response.err(errorMsg.get());
            }
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }

        return responseRef.get();
    }

    // Backward compatibility overload
    public Response findNextUndefinedFunction(String startAddress, String criteria,
                                            String pattern, String direction) {
        return findNextUndefinedFunction(startAddress, criteria, pattern, direction, null);
    }

    /**
     * Comprehensive function analysis combining decompilation, xrefs, callees, callers, disassembly, and variables
     */
    @McpTool(path = "/analyze_function_complete", description = "Comprehensive single-call function analysis. Requires function name — if you only have an address, call get_function_by_address first.", category = "analysis")
    public Response analyzeFunctionComplete(
            @Param(value = "name", description = "Function name (not an address — use get_function_by_address to resolve an address to a name first)") String name,
            @Param(value = "include_xrefs", defaultValue = "true") boolean includeXrefs,
            @Param(value = "include_callees", defaultValue = "true") boolean includeCallees,
            @Param(value = "include_callers", defaultValue = "true") boolean includeCallers,
            @Param(value = "include_disasm", defaultValue = "true") boolean includeDisasm,
            @Param(value = "include_variables", defaultValue = "true") boolean includeVariables,
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        final AtomicReference<Map<String, Object>> resultData = new AtomicReference<>();
        final AtomicReference<String> errorMsg = new AtomicReference<>(null);

        try {
            SwingUtilities.invokeAndWait(() -> {
                try {
                    Function func = null;
                    FunctionManager funcMgr = program.getFunctionManager();

                    // Find function by name
                    for (Function f : funcMgr.getFunctions(true)) {
                        if (f.getName().equals(name)) {
                            func = f;
                            break;
                        }
                    }

                    if (func == null) {
                        errorMsg.set("Function not found: " + name);
                        return;
                    }

                    // Build structured data for Gson serialization
                    Map<String, Object> data = new LinkedHashMap<>();
                    data.put("name", func.getName());
                    data.putAll(ServiceUtils.addressToJson(func.getEntryPoint(), program));
                    data.put("classification", classifyFunction(func, program));
                    data.put("signature", func.getSignature().toString());

                    // v3.0.1: Flag undefined return type
                    String retTypeName = func.getReturnType().getName();
                    if (retTypeName.startsWith("undefined")) {
                        data.put("return_type_resolved", false);
                        data.put("return_type_warning", "Return type is '" + retTypeName
                              + "' -- verify EAX at RET. Do not trust decompiler void display.");
                    } else {
                        data.put("return_type_resolved", true);
                    }

                    // v3.0.1: Include decompiled code (previously only in headless version)
                    DecompileResults decompResults = functionService.decompileFunction(func, program);
                    if (decompResults != null && decompResults.decompileCompleted() &&
                        decompResults.getDecompiledFunction() != null) {
                        String decompiledCode = decompResults.getDecompiledFunction().getC();
                        if (decompiledCode != null) {
                            data.put("decompiled_code", decompiledCode);
                        }
                    }

                    // Include xrefs
                    if (includeXrefs) {
                        List<Map<String, Object>> xrefList = new ArrayList<>();
                        ReferenceIterator refs = program.getReferenceManager().getReferencesTo(func.getEntryPoint());
                        int refCount = 0;
                        while (refs.hasNext() && refCount < 100) {
                            Reference ref = refs.next();
                            Address fromAddr = ref.getFromAddress();
                            Map<String, Object> xrefItem = new LinkedHashMap<>();
                            xrefItem.put("from", fromAddr.toString(false));
                            if (ServiceUtils.getPhysicalSpaceCount(program) > 1) {
                                xrefItem.put("from_full", fromAddr.toString());
                                xrefItem.put("from_space", fromAddr.getAddressSpace().getName());
                            }
                            xrefList.add(xrefItem);
                            refCount++;
                        }
                        data.put("xrefs", xrefList);
                        data.put("xref_count", refCount);
                    }

                    // Include callees
                    if (includeCallees) {
                        Set<Function> calledFuncs = func.getCalledFunctions(null);
                        List<String> calleeNames = new ArrayList<>();
                        for (Function called : calledFuncs) {
                            calleeNames.add(called.getName());
                        }
                        data.put("callees", calleeNames);

                        // v3.0.1: Wrapper return propagation hint
                        // If function has exactly 1 callee and <=15 instructions, check callee return type
                        if (calleeNames.size() == 1 && retTypeName.startsWith("undefined")) {
                            Function callee = calledFuncs.iterator().next();
                            String calleeRetType = callee.getReturnType().getName();
                            if (!calleeRetType.equals("void") && !calleeRetType.startsWith("undefined")) {
                                // Count instructions to confirm wrapper pattern
                                Listing tmpListing = program.getListing();
                                InstructionIterator tmpIter = tmpListing.getInstructions(func.getBody(), true);
                                int instrTotal = 0;
                                while (tmpIter.hasNext()) { tmpIter.next(); instrTotal++; }
                                if (instrTotal <= 15) {
                                    data.put("wrapper_hint", "Callee '" + callee.getName()
                                          + "' returns " + calleeRetType
                                          + ". This wrapper likely returns the same type -- verify EAX is not clobbered before RET.");
                                }
                            }
                        }
                    }

                    // Include callers
                    if (includeCallers) {
                        List<String> callerNames = new ArrayList<>();
                        Set<Function> callingFuncs = func.getCallingFunctions(null);
                        for (Function caller : callingFuncs) {
                            callerNames.add(caller.getName());
                        }
                        data.put("callers", callerNames);
                    }

                    // Include disassembly
                    if (includeDisasm) {
                        List<Map<String, Object>> disasmList = new ArrayList<>();
                        Listing listing = program.getListing();
                        AddressSetView body = func.getBody();
                        InstructionIterator instrIter = listing.getInstructions(body, true);
                        int instrCount = 0;
                        while (instrIter.hasNext() && instrCount < 100) {
                            Instruction instr = instrIter.next();
                            Map<String, Object> instrItem = new LinkedHashMap<>();
                            instrItem.putAll(ServiceUtils.addressToJson(instr.getAddress(), program));
                            instrItem.put("mnemonic", instr.getMnemonicString());
                            disasmList.add(instrItem);
                            instrCount++;
                        }
                        data.put("disassembly", disasmList);
                    }

                    // Include variables (v3.0.1: use HighFunction for locals to capture register-based vars)
                    if (includeVariables) {
                        List<Map<String, Object>> paramList = new ArrayList<>();
                        Parameter[] params = func.getParameters();
                        for (Parameter param : params) {
                            paramList.add(JsonHelper.mapOf(
                                "name", param.getName(),
                                "type", param.getDataType().getName(),
                                "storage", param.getVariableStorage().toString()
                            ));
                        }
                        data.put("parameters", paramList);

                        List<Map<String, Object>> localList = new ArrayList<>();

                        // Use HighFunction symbol map for locals (captures register-based and SSA variables)
                        if (decompResults != null && decompResults.decompileCompleted()) {
                            ghidra.program.model.pcode.HighFunction highFunc = decompResults.getHighFunction();
                            if (highFunc != null) {
                                java.util.Iterator<ghidra.program.model.pcode.HighSymbol> symbols =
                                    highFunc.getLocalSymbolMap().getSymbols();
                                while (symbols.hasNext()) {
                                    ghidra.program.model.pcode.HighSymbol sym = symbols.next();
                                    String symName = sym.getName();
                                    boolean isPhantom = symName.startsWith("extraout_") || symName.startsWith("in_");
                                    // Get storage location from HighVariable
                                    String storageStr = "";
                                    ghidra.program.model.pcode.HighVariable highVar = sym.getHighVariable();
                                    if (highVar != null && highVar.getRepresentative() != null) {
                                        ghidra.program.model.pcode.Varnode rep = highVar.getRepresentative();
                                        if (rep.getAddress() != null) {
                                            storageStr = rep.getAddress().toString() + ":" + rep.getSize();
                                        }
                                    }
                                    localList.add(JsonHelper.mapOf(
                                        "name", symName,
                                        "type", sym.getDataType().getName(),
                                        "storage", storageStr,
                                        "is_phantom", isPhantom,
                                        "in_decompiled_code", true
                                    ));
                                }
                            }
                        }

                        // Fallback: if decompilation unavailable, use low-level API
                        if (decompResults == null || !decompResults.decompileCompleted()) {
                            Variable[] locals = func.getLocalVariables();
                            for (Variable local : locals) {
                                localList.add(JsonHelper.mapOf(
                                    "name", local.getName(),
                                    "type", local.getDataType().getName(),
                                    "storage", local.getVariableStorage().toString(),
                                    "is_phantom", false,
                                    "in_decompiled_code", false
                                ));
                            }
                        }
                        data.put("locals", localList);
                    }

                    resultData.set(data);
                } catch (Exception e) {
                    errorMsg.set(e.getMessage());
                }
            });

            if (errorMsg.get() != null) {
                return Response.err(errorMsg.get());
            }
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }

        return Response.ok(resultData.get());
    }

    // Backward compatibility overload
    public Response analyzeFunctionComplete(String name, boolean includeXrefs, boolean includeCallees,
                                          boolean includeCallers, boolean includeDisasm, boolean includeVariables) {
        return analyzeFunctionComplete(name, includeXrefs, includeCallees, includeCallers, includeDisasm, includeVariables, null);
    }

    /**
     * NEW v1.6.0: Enhanced function search with filtering and sorting
     */
    @McpTool(path = "/search_functions_enhanced", description = "Advanced function search with filtering", category = "analysis")
    public Response searchFunctionsEnhanced(
            @Param(value = "name_pattern", description = "Name pattern (omit to match all)", defaultValue = "") String namePattern,
            @Param(value = "min_xrefs", description = "Minimum xref count filter (omit for no minimum)", defaultValue = "") Integer minXrefs,
            @Param(value = "max_xrefs", description = "Maximum xref count filter (omit for no maximum)", defaultValue = "") Integer maxXrefs,
            @Param(value = "calling_convention", description = "Calling convention filter (omit for any)", defaultValue = "") String callingConvention,
            @Param(value = "has_custom_name", description = "Filter by whether function has a user-defined name (omit for any)", defaultValue = "") Boolean hasCustomName,
            @Param(value = "regex", defaultValue = "false", description = "Use regex matching") boolean regex,
            @Param(value = "sort_by", defaultValue = "address", description = "Sort field") String sortBy,
            @Param(value = "offset", defaultValue = "0") int offset,
            @Param(value = "limit", defaultValue = "100") int limit,
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        final AtomicReference<Response> responseRef = new AtomicReference<>(null);
        final AtomicReference<String> errorMsg = new AtomicReference<>(null);

        try {
            SwingUtilities.invokeAndWait(() -> {
                try {
                    List<Map<String, Object>> matches = new ArrayList<>();
                    Pattern pattern = null;
                    if (regex && namePattern != null) {
                        try {
                            pattern = Pattern.compile(namePattern);
                        } catch (Exception e) {
                            errorMsg.set("Invalid regex pattern: " + e.getMessage());
                            return;
                        }
                    }

                    FunctionManager funcMgr = program.getFunctionManager();

                    for (Function func : funcMgr.getFunctions(true)) {
                        // Filter by name pattern
                        if (namePattern != null && !namePattern.isEmpty()) {
                            if (regex) {
                                if (!pattern.matcher(func.getName()).find()) {
                                    continue;
                                }
                            } else {
                                if (!func.getName().contains(namePattern)) {
                                    continue;
                                }
                            }
                        }

                        // Filter by custom name
                        if (hasCustomName != null) {
                            boolean isCustom = !ServiceUtils.isAutoGeneratedName(func.getName());
                            if (hasCustomName != isCustom) {
                                continue;
                            }
                        }

                        // Get xref count for filtering and sorting
                        int xrefCount = func.getSymbol().getReferenceCount();

                        // Filter by xref count
                        if (minXrefs != null && xrefCount < minXrefs) {
                            continue;
                        }
                        if (maxXrefs != null && xrefCount > maxXrefs) {
                            continue;
                        }

                        // Create match entry
                        Map<String, Object> match = new LinkedHashMap<>();
                        match.put("name", func.getName());
                        match.putAll(ServiceUtils.addressToJson(func.getEntryPoint(), program));
                        match.put("xref_count", xrefCount);
                        matches.add(match);
                    }

                    // Sort results
                    if ("name".equals(sortBy)) {
                        matches.sort((a, b) -> ((String)a.get("name")).compareTo((String)b.get("name")));
                    } else if ("xref_count".equals(sortBy)) {
                        matches.sort((a, b) -> Integer.compare((Integer)b.get("xref_count"), (Integer)a.get("xref_count")));
                    } else {
                        // Default: sort by address
                        matches.sort((a, b) -> ((String)a.get("address")).compareTo((String)b.get("address")));
                    }

                    // Apply pagination
                    int total = matches.size();
                    int endIndex = Math.min(offset + limit, total);
                    List<Map<String, Object>> page = matches.subList(Math.min(offset, total), endIndex);

                    responseRef.set(Response.ok(JsonHelper.mapOf(
                        "total", total,
                        "offset", offset,
                        "limit", limit,
                        "results", page
                    )));

                } catch (Exception e) {
                    errorMsg.set(e.getMessage());
                }
            });

            if (errorMsg.get() != null) {
                return Response.err(errorMsg.get());
            }
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }

        return responseRef.get();
    }

    // ========================================================================
    // Private helper methods
    // ========================================================================

    /**
     * Calculate structural metrics for a function
     */
    private FunctionMetrics calculateFunctionMetrics(Function func, BasicBlockModel blockModel, Program program) {
        FunctionMetrics metrics = new FunctionMetrics();

        try {
            // Count basic blocks and edges
            CodeBlockIterator blockIter = blockModel.getCodeBlocksContaining(func.getBody(), TaskMonitor.DUMMY);
            while (blockIter.hasNext()) {
                CodeBlock block = blockIter.next();
                metrics.basicBlockCount++;

                // Count outgoing edges for complexity calculation
                CodeBlockReferenceIterator destIter = block.getDestinations(TaskMonitor.DUMMY);
                while (destIter.hasNext()) {
                    destIter.next();
                    metrics.edgeCount++;
                }
            }

            // Cyclomatic complexity = E - N + 2P (where P=1 for single function)
            metrics.cyclomaticComplexity = metrics.edgeCount - metrics.basicBlockCount + 2;
            if (metrics.cyclomaticComplexity < 1) metrics.cyclomaticComplexity = 1;

            // Count instructions and calls
            Listing listing = program.getListing();
            InstructionIterator instrIter = listing.getInstructions(func.getBody(), true);
            ReferenceManager refManager = program.getReferenceManager();

            while (instrIter.hasNext()) {
                Instruction instr = instrIter.next();
                metrics.instructionCount++;

                if (instr.getFlowType().isCall()) {
                    metrics.callCount++;
                    // Track which functions are called
                    for (Reference ref : refManager.getReferencesFrom(instr.getAddress())) {
                        if (ref.getReferenceType().isCall()) {
                            Function calledFunc = program.getFunctionManager().getFunctionAt(ref.getToAddress());
                            if (calledFunc != null) {
                                metrics.calledFunctions.add(calledFunc.getName());
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            // Return partial metrics on error
        }

        return metrics;
    }

    /**
     * Calculate similarity score between two functions (0.0 to 1.0)
     */
    private double calculateSimilarity(FunctionMetrics a, FunctionMetrics b) {
        // Weight different metrics
        double blockSim = 1.0 - Math.abs(a.basicBlockCount - b.basicBlockCount) /
                          (double) Math.max(Math.max(a.basicBlockCount, b.basicBlockCount), 1);
        double instrSim = 1.0 - Math.abs(a.instructionCount - b.instructionCount) /
                          (double) Math.max(Math.max(a.instructionCount, b.instructionCount), 1);
        double callSim = 1.0 - Math.abs(a.callCount - b.callCount) /
                         (double) Math.max(Math.max(a.callCount, b.callCount), 1);
        double complexitySim = 1.0 - Math.abs(a.cyclomaticComplexity - b.cyclomaticComplexity) /
                               (double) Math.max(Math.max(a.cyclomaticComplexity, b.cyclomaticComplexity), 1);

        // Jaccard similarity for called functions
        double calledFuncSim = 0.0;
        if (!a.calledFunctions.isEmpty() || !b.calledFunctions.isEmpty()) {
            Set<String> intersection = new HashSet<>(a.calledFunctions);
            intersection.retainAll(b.calledFunctions);
            Set<String> union = new HashSet<>(a.calledFunctions);
            union.addAll(b.calledFunctions);
            calledFuncSim = union.isEmpty() ? 0.0 : (double) intersection.size() / union.size();
        }

        // Weighted average (structure matters more than exact counts)
        return 0.25 * blockSim + 0.20 * instrSim + 0.15 * callSim +
               0.20 * complexitySim + 0.20 * calledFuncSim;
    }

    private CompletenessScoreResult calculateCompletenessScore(Function func, int undefinedCount, int plateCommentIssueCount, int hungarianViolationCount, int typeQualityIssueCount, int unrenamedGlobalsCount, int unrenamedLabelsCount, int undocumentedOrdinalsCount, int undocumentedMagicNumbersCount, int unresolvedStructAccessesCount, double commentDensity, List<String> typeQualityIssues, int phantomCount, int codeLineCount, int unfixableUndefinedCount, int unfixableHungarianCount, boolean isThunk, boolean isStub, boolean isCompilerHelper) {
        double fixablePenalty = 0.0;
        double structuralPenalty = 0.0;
        List<Map<String, Object>> breakdown = new ArrayList<>();

        // --- Identity tier (binary deductions, ~65% of score budget) ---

        if (ServiceUtils.isAutoGeneratedName(func.getName())) {
            fixablePenalty += 30;
            breakdown.add(deductionItem("auto_name", 30.0, true, 1, "Function still has an auto-generated name"));
        } else if (func.getName().matches(".*_[0-9a-fA-F]{6,}$")) {
            fixablePenalty += 20;
            breakdown.add(deductionItem("address_suffix_name", 20.0, true, 1,
                    "Function name ends with address suffix (e.g., _6FD93C30) — strip suffix and verify name"));
        }

        if (func.getSignature() == null) {
            fixablePenalty += 15;
            breakdown.add(deductionItem("missing_signature", 15.0, true, 1, "Missing function prototype/signature"));
        }

        if (func.getCallingConvention() == null) {
            fixablePenalty += 5;
            breakdown.add(deductionItem("missing_calling_convention", 5.0, true, 1, "Missing calling convention"));
        }

        // Plate comment quality tiers (sliding scale, not binary)
        String plateComment = func.getComment();
        if (plateComment == null || plateComment.isEmpty()) {
            double penalty = isCompilerHelper ? 15.0 : 35.0;
            fixablePenalty += penalty;
            breakdown.add(deductionItem("missing_plate_comment", penalty, true, 1, "Missing plate comment"));
        } else {
            String[] plateLines = plateComment.split("\n");
            if (plateLines.length < 5) {
                // Stub plate comment (very short)
                fixablePenalty += 25;
                breakdown.add(deductionItem("plate_comment_stub", 25.0, true, 1,
                        "Plate comment is a stub (" + plateLines.length + " lines, minimum 5)"));
            } else if (plateCommentIssueCount >= 2) {
                // Present but missing multiple required sections
                fixablePenalty += 15;
                breakdown.add(deductionItem("plate_comment_incomplete", 15.0, true, plateCommentIssueCount,
                        "Plate comment missing " + plateCommentIssueCount + " required sections"));
            } else if (plateCommentIssueCount == 1) {
                // Present but missing one section
                fixablePenalty += 8;
                breakdown.add(deductionItem("plate_comment_minor", 8.0, true, 1,
                        "Plate comment missing 1 required section"));
            }
            // plateCommentIssueCount == 0 → no deduction (fully complete plate)
        }

        if (func.getReturnType().getName().startsWith("undefined")) {
            fixablePenalty += 15;
            breakdown.add(deductionItem("undefined_return_type", 15.0, true, 1, "Return type is unresolved"));
        }

        // --- Variable-level tier (per-count with log-scaled budgets) ---

        int fixableUndefinedCount = Math.max(0, undefinedCount - unfixableUndefinedCount);
        if (fixableUndefinedCount > 0) {
            double penalty = logScaledPenalty(25.0, fixableUndefinedCount, 10);
            fixablePenalty += penalty;
            breakdown.add(deductionItem("undefined_variables", penalty, true, fixableUndefinedCount,
                    "Variables with generic names or unresolved types"));
        }
        if (unfixableUndefinedCount > 0) {
            double penalty = logScaledPenalty(15.0, unfixableUndefinedCount, 8);
            structuralPenalty += penalty;
            breakdown.add(deductionItem("undefined_variables_structural", penalty, false, unfixableUndefinedCount,
                    "Register-only/thunk-projected variables not fixable via API"));
        }

        // plate_comment_issues merged into tiered plate scoring above

        int fixableHungarianCount = Math.max(0, hungarianViolationCount - unfixableHungarianCount);
        if (fixableHungarianCount > 0) {
            double penalty = logScaledPenalty(10.0, fixableHungarianCount, 8);
            fixablePenalty += penalty;
            breakdown.add(deductionItem("hungarian_violations", penalty, true, fixableHungarianCount,
                    "Variables violate naming convention for their data types"));
        }
        if (unfixableHungarianCount > 0) {
            double penalty = logScaledPenalty(5.0, unfixableHungarianCount, 5);
            structuralPenalty += penalty;
            breakdown.add(deductionItem("hungarian_violations_structural", penalty, false, unfixableHungarianCount,
                    "Hungarian mismatch on non-renameable register-only/thunk variables"));
        }

        boolean isExternalEntry = func.getProgram().getSymbolTable().isExternalEntryPoint(func.getEntryPoint());
        int structuralTypeIssues = 0;
        int prefixTypeMismatchCount = 0;
        int undocumentedParamCount = 0;
        int localTypeIssueCount = 0;

        for (String issue : typeQualityIssues) {
            if (issue.contains("Generic void*") && (isExternalEntry || isThunk || isCompilerHelper)) {
                structuralTypeIssues++;
            } else if (issue.contains("Unresolved this pointer: __thiscall")) {
                // __thiscall ECX auto-param cannot be retyped via API — always structural
                structuralTypeIssues++;
            } else if (issue.contains("Prefix-type mismatch")) {
                prefixTypeMismatchCount++;
            } else if (issue.contains("Undocumented parameter")) {
                undocumentedParamCount++;
            } else if (issue.startsWith("Generic void* local:") || issue.startsWith("Generic int* local:") ||
                       issue.startsWith("Local prefix-type mismatch:")) {
                localTypeIssueCount++;
            }
        }
        int fullTypeIssues = Math.max(0, typeQualityIssueCount - structuralTypeIssues - prefixTypeMismatchCount - undocumentedParamCount - localTypeIssueCount);
        if (fullTypeIssues > 0) {
            double penalty = logScaledPenalty(10.0, fullTypeIssues, 3);
            fixablePenalty += penalty;
            breakdown.add(deductionItem("type_quality", penalty, true, fullTypeIssues,
                    "Type quality problems requiring better struct/pointer typing"));
        }
        if (prefixTypeMismatchCount > 0) {
            double penalty = logScaledPenalty(5.0, prefixTypeMismatchCount, 4);
            fixablePenalty += penalty;
            breakdown.add(deductionItem("prefix_type_mismatch", penalty, true, prefixTypeMismatchCount,
                    "Parameter name prefix suggests pointer but type is scalar"));
        }
        if (undocumentedParamCount > 0) {
            double penalty = logScaledPenalty(5.0, undocumentedParamCount, 5);
            fixablePenalty += penalty;
            breakdown.add(deductionItem("undocumented_params", penalty, true, undocumentedParamCount,
                    "Parameters not listed in plate comment Parameters section"));
        }
        if (localTypeIssueCount > 0) {
            double penalty = logScaledPenalty(10.0, localTypeIssueCount, 5);
            fixablePenalty += penalty;
            breakdown.add(deductionItem("local_type_quality", penalty, true, localTypeIssueCount,
                    "Local variables with generic void*/int* types need struct typing"));
        }
        if (structuralTypeIssues > 0) {
            double penalty = logScaledPenalty(5.0, structuralTypeIssues, 3);
            structuralPenalty += penalty;
            breakdown.add(deductionItem("type_quality_structural", penalty, false, structuralTypeIssues,
                    "Generic void* acceptable in compiler helpers/thunks/exports"));
        }

        // --- Polish tier (per-count with log-scaled budgets) ---

        if (unrenamedGlobalsCount > 0) {
            double penalty = logScaledPenalty(8.0, unrenamedGlobalsCount, 5);
            fixablePenalty += penalty;
            breakdown.add(deductionItem("unrenamed_globals", penalty, true, unrenamedGlobalsCount,
                    "DAT_* globals should be renamed"));
        }

        if (unrenamedLabelsCount > 0) {
            double penalty = logScaledPenalty(5.0, unrenamedLabelsCount, 5);
            fixablePenalty += penalty;
            breakdown.add(deductionItem("unrenamed_labels", penalty, true, unrenamedLabelsCount,
                    "LAB_* labels should be renamed where meaningful"));
        }

        if (undocumentedOrdinalsCount > 0) {
            double penalty = logScaledPenalty(5.0, undocumentedOrdinalsCount, 5);
            fixablePenalty += penalty;
            breakdown.add(deductionItem("undocumented_ordinals", penalty, true, undocumentedOrdinalsCount,
                    "Ordinal calls should have inline documentation"));
        }

        if (undocumentedMagicNumbersCount > 0 && codeLineCount > 10 && !isThunk && !isStub) {
            double penalty = logScaledPenalty(5.0, undocumentedMagicNumbersCount, 10);
            fixablePenalty += penalty;
            breakdown.add(deductionItem("undocumented_magic_numbers", penalty, true, undocumentedMagicNumbersCount,
                    "Hex/numeric constants in instructions without EOL comments"));
        }

        if (unresolvedStructAccessesCount > 0 && !isThunk && !isStub) {
            double penalty = logScaledPenalty(5.0, unresolvedStructAccessesCount, 5);
            fixablePenalty += penalty;
            breakdown.add(deductionItem("unresolved_struct_accesses", penalty, true, unresolvedStructAccessesCount,
                    "Raw pointer+offset dereferences that should use struct field names"));
        }

        if (commentDensity < 1.0 && func.getComment() != null && codeLineCount > 10 && !isThunk && !isStub && !isCompilerHelper) {
            fixablePenalty += 5.0;
            breakdown.add(deductionItem("low_comment_density", 5.0, true, 1,
                    "Inline/disassembly comments are sparse for function complexity"));
        }

        double totalPenalty = fixablePenalty + structuralPenalty;
        double rawScore = Math.max(0.0, 100.0 - totalPenalty);
        double maxAchievableScore = Math.max(0.0, Math.min(100.0, 100.0 - structuralPenalty));
        // effectiveScore: only fixable deductions count. Structural deductions are fully forgiven.
        // When fixablePenalty == 0, effective score is 100% regardless of structural penalties.
        double effectiveScore = Math.max(0.0, Math.min(100.0, 100.0 - fixablePenalty));

        return new CompletenessScoreResult(rawScore, effectiveScore, (int) structuralPenalty,
                fixablePenalty, structuralPenalty, maxAchievableScore, breakdown);
    }
    private List<String> generateWorkflowRecommendations(
            Function func,
            List<String> undefinedVars,
            List<String> plateCommentIssues,
            List<String> hungarianViolations,
            List<String> typeQualityIssues,
            List<String> unrenamedGlobals,
            List<String> unrenamedLabels,
            List<String> undocumentedOrdinals,
            List<String> undocumentedMagicNumbers,
            List<String> unresolvedStructAccesses,
            double commentDensity,
            CompletenessScoreResult scoreResult,
            int codeLineCount,
            boolean isThunk,
            boolean isStub,
            boolean isCompilerHelper) {

        List<String> recommendations = new ArrayList<>();

        // If 100% complete (raw), return early
        if (scoreResult.score >= 100.0) {
            recommendations.add("Function is fully documented - no further action needed.");
            return recommendations;
        }

        // If all deductions are unfixable, report that and skip the full workflow
        if (scoreResult.effectiveScore >= 100.0) {
            recommendations.add("All remaining deductions are unfixable (void* on exported functions, phantom variables). No further action needed.");
            return recommendations;
        }

        if (isCompilerHelper) {
            recommendations.add("COMPILER/CRT HELPER PROFILE - Use compact documentation requirements:");
            recommendations.add("1. Prioritize Purpose, Origin, Parameters, and callback/ABI behavior.");
            recommendations.add("2. Skip long algorithm narratives unless helper has real game logic.");
            recommendations.add("3. Treat generic void* callback signatures as potentially structural for CRT helpers.");
        }
        // CRITICAL: Undefined return type
        if (func.getReturnType().getName().startsWith("undefined")) {
            recommendations.add("UNDEFINED RETURN TYPE - Do not trust decompiler display. Verify EAX at RET instruction:");
            recommendations.add("1. Current return type: " + func.getReturnType().getName() + " (unresolved)");
            recommendations.add("2. Check disassembly: what value is in EAX at each RET instruction?");
            recommendations.add("3. For wrappers: if callee returns non-void and EAX is not clobbered before RET, the wrapper returns the same type");
            recommendations.add("4. Use set_function_prototype() to set the correct return type (void, int, uint, etc.)");
        }

        // CRITICAL: Unnamed DAT_* Globals (highest priority)
        if (!unrenamedGlobals.isEmpty()) {
            recommendations.add("UNRENAMED DAT_* GLOBALS DETECTED - Must rename before documentation is complete:");
            recommendations.add("1. Found " + unrenamedGlobals.size() + " DAT_* reference(s): " + String.join(", ", unrenamedGlobals.subList(0, Math.min(5, unrenamedGlobals.size()))));
            recommendations.add("2. Use rename_or_label() or rename_data() to give meaningful names to each global");
            recommendations.add("3. Apply Hungarian notation with g_ prefix: g_dwPlayerCount, g_pCurrentGame, g_abEncryptionKey");
            recommendations.add("4. If global is a structure, apply type with apply_data_type() first, then rename");
            recommendations.add("5. Consult KNOWN_ORDINALS.md and existing codebase for naming conventions");
        }

        // UNRENAMED LAB_* LABELS (auto-generated goto targets)
        if (!unrenamedLabels.isEmpty()) {
            recommendations.add("UNRENAMED LAB_* LABELS DETECTED - Rename auto-generated labels to descriptive names:");
            recommendations.add("1. Found " + unrenamedLabels.size() + " LAB_* label(s): " + String.join(", ", unrenamedLabels.subList(0, Math.min(5, unrenamedLabels.size()))));
            recommendations.add("2. Use rename_label() to give meaningful names (e.g., LAB_6fd71a3c -> exitEarly, LAB_6fd71a50 -> processNextItem)");
            recommendations.add("3. Skip labels that are simple fall-through targets with no external xrefs");
        }

        // CRITICAL: Undocumented Ordinal Calls
        if (!undocumentedOrdinals.isEmpty()) {
            recommendations.add("UNDOCUMENTED ORDINAL CALLS - Add inline comments for each:");
            recommendations.add("1. Found " + undocumentedOrdinals.size() + " Ordinal call(s) without comments: " + String.join(", ", undocumentedOrdinals.subList(0, Math.min(5, undocumentedOrdinals.size()))));
            recommendations.add("2. Consult docs/KNOWN_ORDINALS.md for Ordinal mappings (Storm.dll, Fog.dll ordinals documented)");
            recommendations.add("3. Use set_decompiler_comment() or batch_set_comments() to add inline comment explaining the call");
            recommendations.add("4. Format: /* Ordinal_123 = StorageFunctionName - brief description */");
        }

        // UNDOCUMENTED MAGIC NUMBERS in disassembly
        if (!undocumentedMagicNumbers.isEmpty()) {
            recommendations.add("UNDOCUMENTED MAGIC NUMBERS - Add EOL comments for hex/numeric constants:");
            recommendations.add("1. Found " + undocumentedMagicNumbers.size() + " instruction(s) with undocumented constants: "
                    + String.join(", ", undocumentedMagicNumbers.subList(0, Math.min(5, undocumentedMagicNumbers.size()))));
            recommendations.add("2. Use batch_set_comments() with EOL_COMMENTs to explain each constant");
            recommendations.add("3. Common patterns: struct offsets (document field name), enum values, bit masks, array sizes");
        }

        // UNRESOLVED STRUCT FIELD ACCESSES
        if (!unresolvedStructAccesses.isEmpty()) {
            recommendations.add("UNRESOLVED STRUCT FIELD ACCESSES - Apply struct types to eliminate raw offsets:");
            recommendations.add("1. Found " + unresolvedStructAccesses.size() + " raw pointer+offset dereference(s): "
                    + String.join(", ", unresolvedStructAccesses.subList(0, Math.min(5, unresolvedStructAccesses.size()))));
            recommendations.add("2. Use search_data_types() to find existing struct definitions");
            recommendations.add("3. If no struct exists, use create_struct() with fields matching the observed offsets");
            recommendations.add("4. Apply struct type to variables with set_local_variable_type() or set_function_prototype()");
        }

        // CRITICAL: Undefined Type Audit (FUNCTION_DOC_WORKFLOW_V4.md Mandatory Undefined Type Audit)
        if (!undefinedVars.isEmpty()) {
            recommendations.add("UNDEFINED TYPES DETECTED - Follow FUNCTION_DOC_WORKFLOW_V4.md 'Mandatory Undefined Type Audit' section:");
            recommendations.add("1. Type Resolution: Apply type normalization before renaming:");
            recommendations.add("   - undefined1 -> byte (8-bit integer)");
            recommendations.add("   - undefined2 -> ushort/short (16-bit integer)");
            recommendations.add("   - undefined4 -> uint/int/float/pointer (32-bit - check usage context)");
            recommendations.add("   - undefined8 -> double/ulonglong/longlong (64-bit)");
            recommendations.add("   - undefined1[N] -> byte[N] (byte array for XMM spills, buffers)");
            recommendations.add("2. Use set_local_variable_type() with lowercase builtin types (uint, ushort, byte) NOT uppercase Windows types (UINT, USHORT, BYTE)");
            recommendations.add("3. CRITICAL: Check disassembly with get_disassembly() for assembly-only undefined types:");
            recommendations.add("   - Stack temporaries: [EBP + local_offset] not in get_function_variables()");
            recommendations.add("   - XMM register spills: undefined1[16] at stack locations");
            recommendations.add("   - Intermediate calculation results not appearing in decompiled view");
            recommendations.add("4. After resolving ALL undefined types, rename variables with Hungarian notation using rename_variables()");
        }

        // Plate Comment Issues
        if (!plateCommentIssues.isEmpty()) {
            recommendations.add("PLATE COMMENT ISSUES - Follow FUNCTION_DOC_WORKFLOW_V4.md 'Plate Comment Creation' section:");
            for (String issue : plateCommentIssues) {
                if (issue.contains("Missing Algorithm section")) {
                    recommendations.add("1. Add Algorithm section with numbered steps describing operations (validation, function calls, error handling)");
                } else if (issue.contains("no numbered steps")) {
                    recommendations.add("2. Add numbered steps in Algorithm section (1., 2., 3., etc.)");
                } else if (issue.contains("Missing Parameters section")) {
                    recommendations.add("3. Add Parameters section documenting all parameters with types and purposes (include IMPLICIT keyword for undocumented register params)");
                } else if (issue.contains("Missing Returns section")) {
                    recommendations.add("4. Add Returns section explaining return values, success codes, error conditions, NULL/zero cases");
                } else if (issue.contains("lines (minimum 10 required)")) {
                    recommendations.add("5. Expand plate comment to minimum 10 lines with comprehensive documentation");
                }
            }
            recommendations.add("Use set_plate_comment() to create/update plate comment following docs/prompts/PLATE_COMMENT_FORMAT_GUIDE.md");
        }

        // Hungarian Notation Violations
        if (!hungarianViolations.isEmpty()) {
            boolean hasReverseMismatch = hungarianViolations.stream().anyMatch(v -> v.contains("REVERSE MISMATCH"));
            if (hasReverseMismatch) {
                recommendations.add("REVERSE MISMATCH DETECTED - Variable name prefix implies a different type than Ghidra shows:");
                for (String violation : hungarianViolations) {
                    if (violation.contains("REVERSE MISMATCH")) {
                        recommendations.add("  - " + violation);
                    }
                }
                recommendations.add("FIX THE TYPE, NOT THE NAME. The human-assigned name is correct; the decompiler-inferred type is wrong.");
            }
            recommendations.add("HUNGARIAN NOTATION VIOLATIONS - Follow FUNCTION_DOC_WORKFLOW_V4.md 'Local Variable Renaming' section and docs/HUNGARIAN_NOTATION.md:");
            recommendations.add("1. Verify type-to-prefix mapping matches Ghidra type:");
            recommendations.add("   - byte -> b/by | char -> c/ch | bool -> f | short -> n/s | ushort -> w");
            recommendations.add("   - int -> n/i | uint -> dw | long -> l | ulong -> dw");
            recommendations.add("   - longlong -> ll | ulonglong -> qw | float -> fl | double -> d");
            recommendations.add("   - void* -> p | typed pointers -> p+StructName (pUnitAny)");
            recommendations.add("   - byte[N] -> ab | ushort[N] -> aw | uint[N] -> ad");
            recommendations.add("   - char* -> sz/lpsz | wchar_t* -> wsz");
            recommendations.add("2. First set correct type with set_local_variable_type() using lowercase builtin");
            recommendations.add("3. Then rename with rename_variables() using correct Hungarian prefix");
            recommendations.add("4. For globals, add g_ prefix before type prefix: g_dwProcessId, g_abEncryptionKey");
        }

        // Type Quality Issues
        if (!typeQualityIssues.isEmpty()) {
            recommendations.add("TYPE QUALITY ISSUES - Follow FUNCTION_DOC_WORKFLOW_V4.md 'Structure Identification' section:");
            for (String issue : typeQualityIssues) {
                if (issue.contains("Unresolved this pointer")) {
                    recommendations.add("UNRESOLVED THIS POINTER - __thiscall function has void* this:");
                    recommendations.add("1. " + issue);
                    recommendations.add("2. Analyze xrefs to identify the class/vtable this function belongs to");
                    recommendations.add("3. Create struct with create_struct() if no existing type matches");
                    recommendations.add("4. Use set_function_prototype() to replace void* with the struct pointer type");
                } else if (issue.contains("PLATE CONFIRMED")) {
                    recommendations.add("PLATE-CONFIRMED TYPE FIX NEEDED - Plate comment proves parameter is a pointer:");
                    recommendations.add("1. " + issue);
                    recommendations.add("2. The plate comment explicitly describes this as a pointer — change the type NOW");
                    recommendations.add("3. Use set_function_prototype() to upgrade from int/uint to void* (or specific struct*)");
                } else if (issue.contains("Plate-type contradiction")) {
                    recommendations.add("PLATE-TYPE CONTRADICTION - Plate comment disagrees with actual Ghidra type:");
                    recommendations.add("1. " + issue);
                    recommendations.add("2. Either fix the type with set_function_prototype() to match plate, or correct plate comment");
                } else if (issue.contains("Generic void*")) {
                    recommendations.add("1. Replace generic void* parameters with specific structure types using set_function_prototype()");
                    recommendations.add("   Example: void ProcessData(void* pData) -> void ProcessData(UnitAny* pUnit)");
                } else if (issue.contains("Generic int* parameter")) {
                    recommendations.add("GENERIC INT* PARAMETER - p-prefix parameter typed as int* instead of struct pointer:");
                    recommendations.add("1. " + issue);
                    recommendations.add("2. Identify the actual struct type from usage context (field accesses, callees)");
                    recommendations.add("3. Use set_function_prototype() to change int* to the correct struct pointer type");
                } else if (issue.startsWith("Generic void* local:")) {
                    recommendations.add("GENERIC VOID* LOCAL VARIABLE - needs typed struct pointer:");
                    recommendations.add("1. " + issue);
                    recommendations.add("2. Identify the struct type from field accesses and cast patterns in the decompiled code");
                    recommendations.add("3. Use set_local_variable_type() to change void* to the correct struct pointer type");
                } else if (issue.startsWith("Generic int* local:")) {
                    recommendations.add("GENERIC INT* LOCAL VARIABLE - p-prefix local typed as int* instead of struct pointer:");
                    recommendations.add("1. " + issue);
                    recommendations.add("2. Identify the actual struct type from usage context (field accesses, callees)");
                    recommendations.add("3. Use set_local_variable_type() to change int* to the correct struct pointer type");
                } else if (issue.startsWith("Local prefix-type mismatch:")) {
                    recommendations.add("LOCAL PREFIX-TYPE MISMATCH - Local variable name suggests pointer but type is scalar:");
                    recommendations.add("1. " + issue);
                    recommendations.add("2. Fix the type with set_local_variable_type() to use correct pointer type");
                    recommendations.add("3. Then verify Hungarian prefix still matches the new type");
                } else if (issue.contains("Undocumented parameter")) {
                    recommendations.add("UNDOCUMENTED PARAMETER - Plate comment missing parameter description:");
                    recommendations.add("1. " + issue);
                    recommendations.add("2. Add a line to the plate comment Parameters section: paramName — description");
                    recommendations.add("3. Use set_plate_comment() to update the plate comment");
                } else if (issue.contains("State-based type name")) {
                    recommendations.add("2. Rename state-based type names to identity-based names:");
                    recommendations.add("   BAD: InitializedGameObject, AllocatedBuffer, ProcessedData");
                    recommendations.add("   GOOD: GameObject, Buffer, DataRecord");
                    recommendations.add("   Use create_struct() with identity-based name, document legacy name in comments");
                } else if (issue.contains("Type duplication")) {
                    recommendations.add("3. Consolidate duplicate types - use identity-based version, delete state-based variant");
                } else if (issue.contains("Prefix-type mismatch")) {
                    recommendations.add("PREFIX-TYPE MISMATCH - Parameter name suggests pointer but type is scalar:");
                    recommendations.add("1. " + issue);
                    recommendations.add("2. Fix the type FIRST with set_function_prototype() to use correct pointer type");
                    recommendations.add("3. Then verify Hungarian prefix still matches the new type");
                }
            }
        }

        // Inline Comment Density Check (skip for small functions <= 10 code lines, and for thunks)
        if (commentDensity < 0.67 && codeLineCount > 10 && !isThunk && !isStub && !isCompilerHelper) { // Less than 1 comment per 15 lines
            recommendations.add("LOW INLINE COMMENT DENSITY - Add more explanatory comments:");
            recommendations.add("1. Current density: " + String.format("%.2f", commentDensity) + " comments per 10 lines (target: 0.67+)");
            recommendations.add("2. Add inline comments for:");
            recommendations.add("   - Complex calculations or magic numbers");
            recommendations.add("   - Non-obvious conditional branches");
            recommendations.add("   - Ordinal/DLL calls explaining their purpose");
            recommendations.add("   - Structure field accesses explaining data meaning");
            recommendations.add("   - Error handling paths explaining expected failures");
            recommendations.add("3. Use set_decompiler_comment() for individual comments or batch_set_comments() for multiple");
        }

        // General Workflow Guidance -- only show if there are fixable issues
        if (scoreResult.fixablePenalty > 0.0) {
            if (isCompilerHelper) {
                recommendations.add("HELPER WORKFLOW (compact):");
                recommendations.add("1. Confirm helper identity and ABI semantics.");
                recommendations.add("2. Ensure function name/prototype are accurate and stable across versions.");
                recommendations.add("3. Add concise plate comment with Purpose/Origin/Parameters/Returns.");
                recommendations.add("4. Re-score and stop when only structural deductions remain.");
            } else {
                recommendations.add("COMPLETE WORKFLOW (FUNCTION_DOC_WORKFLOW_V4.md):");
                recommendations.add("1. Initialize: get_current_selection() + analyze_function_complete() -- gather decompiled code, xrefs, callees, callers, disassembly, variables");
                recommendations.add("2. Classify: Leaf/Worker/Thunk/Init/Callback/Public API/Internal utility");
                recommendations.add("3. Mandatory Undefined Type Audit: examine BOTH decompiled code and disassembly for undefined types");
                recommendations.add("4. Verify Decompiler vs Assembly: loops, type casts, pointer arithmetic, conditionals, early exits");
                recommendations.add("5. Control Flow + Loop Mapping: return points, loop headers/bounds/stride, error paths");
                recommendations.add("6. Structure Identification: search_data_types() or create_struct(), memory model docs");
                recommendations.add("7. Rename + Prototype: rename_function_by_address() (PascalCase) + set_function_prototype()");
                recommendations.add("8. Local Variable Renaming: set_local_variable_type() then rename_variables() with Hungarian notation");
                recommendations.add("9. Global Data: rename_or_label() with g_ prefix for DAT_*/s_* references");
                recommendations.add("10. Plate Comment: set_plate_comment() per PLATE_COMMENT_FORMAT_GUIDE.md (Algorithm, Parameters, Returns, Structure Layout, Magic Numbers)");
                recommendations.add("11. Inline Comments: PRE_COMMENTs + EOL_COMMENTs via batch_set_comments()");
                recommendations.add("12. Verify: analyze_function_completeness() once -- accept phantom/void* deductions");
            }
        }

        return recommendations;
    }

    /**
     * Log-scaled penalty: smoothly approaches budget as count increases, hard-capped at budget.
     * At count == threshold the full budget is consumed; below threshold it scales logarithmically.
     */
    private double logScaledPenalty(double budget, int count, int threshold) {
        if (count <= 0) return 0.0;
        if (count >= threshold) return budget;
        return Math.min(budget, budget * Math.log(1.0 + count) / Math.log(1.0 + threshold));
    }

    private Map<String, Object> deductionItem(String category, double points, boolean fixable, int count, String description) {
        return JsonHelper.mapOf(
                "category", category,
                "points", points,
                "fixable", fixable,
                "count", count,
                "description", description
        );
    }

    private int getInstructionCount(Function func, Program program) {
        int count = 0;
        InstructionIterator instrIter = program.getListing().getInstructions(func.getBody(), true);
        while (instrIter.hasNext()) {
            instrIter.next();
            count++;
        }
        return count;
    }

    private boolean looksLikeCompilerRuntimeHelper(Function func, String decompiledCode, int instructionCount,
                                                   boolean isThunk, boolean isStub) {
        String name = func.getName().toLowerCase(Locale.ROOT);
        if (name.contains("arrayunwind") || name.contains("eh_") || name.contains("seh_") ||
            name.contains("msvcrt") || name.contains("guard_check") || name.contains("security_cookie")) {
            return true;
        }

        if (decompiledCode != null) {
            String code = decompiledCode.toLowerCase(Locale.ROOT);
            if (code.contains("library function") || code.contains("visual studio") || code.contains("__arrayunwind") ||
                code.contains("__seh_prolog") || code.contains("__seh_epilog")) {
                return true;
            }
        }

        if (isThunk || isStub) {
            return false;
        }

        return instructionCount <= 20 && func.getName().startsWith("FUN_") && func.getParameterCount() >= 3;
    }

    private List<Map<String, Object>> generateRemediationActions(
            Function func,
            List<String> undefinedVars,
            List<String> plateCommentIssues,
            List<String> hungarianViolations,
            List<String> typeQualityIssues,
            List<String> unrenamedGlobals,
            List<String> unrenamedLabels,
            List<String> undocumentedOrdinals,
            List<String> undocumentedMagicNumbers,
            List<String> unresolvedStructAccesses,
            double commentDensity,
            CompletenessScoreResult scoreResult,
            boolean isThunk,
            boolean isStub,
            boolean isCompilerHelper) {

        List<Map<String, Object>> actions = new ArrayList<>();

        if (scoreResult.fixablePenalty <= 0.0) {
            return actions;
        }

        if (ServiceUtils.isAutoGeneratedName(func.getName())) {
            actions.add(JsonHelper.mapOf(
                    "issue_type", "auto_name",
                    "priority", "high",
                    "tool", "rename_function_by_address",
                    "params_template", JsonHelper.mapOf("function_address", func.getEntryPoint().toString(), "new_name", "<PascalCaseName>"),
                    "evidence", Collections.singletonList(func.getName()),
                    "estimated_gain", 30
            ));
        }

        if (!undefinedVars.isEmpty()) {
            List<String> evidence = new ArrayList<>(undefinedVars.subList(0, Math.min(5, undefinedVars.size())));
            actions.add(JsonHelper.mapOf(
                    "issue_type", "undefined_variables",
                    "priority", "high",
                    "tool", "set_local_variable_type",
                    "params_template", JsonHelper.mapOf("function_address", func.getEntryPoint().toString(), "variable_name", "<var>", "new_type", "<resolved_type>"),
                    "evidence", evidence,
                    "estimated_gain", Math.min(25, undefinedVars.size() * (isCompilerHelper ? 2 : 5))
            ));
        }

        if (!hungarianViolations.isEmpty()) {
            List<String> evidence = new ArrayList<>(hungarianViolations.subList(0, Math.min(5, hungarianViolations.size())));
            actions.add(JsonHelper.mapOf(
                    "issue_type", "hungarian_violations",
                    "priority", "medium",
                    "tool", "rename_variables",
                    "params_template", JsonHelper.mapOf("function_address", func.getEntryPoint().toString(), "variable_renames", JsonHelper.mapOf("<old_name>", "<new_name>")),
                    "evidence", evidence,
                    "estimated_gain", Math.min(15, hungarianViolations.size() * (isCompilerHelper ? 1 : 3))
            ));
        }

        if (!plateCommentIssues.isEmpty()) {
            actions.add(JsonHelper.mapOf(
                    "issue_type", "plate_comment",
                    "priority", "medium",
                    "tool", "set_plate_comment",
                    "params_template", JsonHelper.mapOf("function_address", func.getEntryPoint().toString(), "comment", "<plate_comment_text>"),
                    "evidence", new ArrayList<>(plateCommentIssues.subList(0, Math.min(5, plateCommentIssues.size()))),
                    "estimated_gain", Math.min(20, plateCommentIssues.size() * (isCompilerHelper ? 2 : 5))
            ));
        }

        boolean hasFixableTypeIssues = false;
        boolean hasStructuralVoidStar = false;
        boolean hasLocalTypeIssues = false;
        boolean isExternalEntry = func.getProgram().getSymbolTable().isExternalEntryPoint(func.getEntryPoint());
        for (String issue : typeQualityIssues) {
            if (issue.contains("Generic void*") && (isExternalEntry || isThunk || isCompilerHelper)) {
                hasStructuralVoidStar = true;
            } else if (issue.startsWith("Generic void* local:") || issue.startsWith("Generic int* local:") ||
                       issue.startsWith("Local prefix-type mismatch:")) {
                hasLocalTypeIssues = true;
            } else {
                hasFixableTypeIssues = true;
            }
        }

        if (hasFixableTypeIssues) {
            actions.add(JsonHelper.mapOf(
                    "issue_type", "type_quality",
                    "priority", "high",
                    "tool", "set_function_prototype",
                    "params_template", JsonHelper.mapOf("function_address", func.getEntryPoint().toString(), "prototype", "<return_type> <name>(<typed_params>)"),
                    "evidence", new ArrayList<>(typeQualityIssues.subList(0, Math.min(5, typeQualityIssues.size()))),
                    "estimated_gain", 15
            ));
        } else if (hasStructuralVoidStar) {
            actions.add(JsonHelper.mapOf(
                    "issue_type", "type_quality_structural",
                    "priority", "low",
                    "tool", "none",
                    "params_template", JsonHelper.mapOf(),
                    "evidence", Collections.singletonList("Generic void* appears structural for helper/thunk/export"),
                    "estimated_gain", 0
            ));
        }
        if (hasLocalTypeIssues) {
            List<String> localIssues = new ArrayList<>();
            for (String issue : typeQualityIssues) {
                if (issue.startsWith("Generic void* local:") || issue.startsWith("Generic int* local:") ||
                    issue.startsWith("Local prefix-type mismatch:")) {
                    localIssues.add(issue);
                }
            }
            actions.add(JsonHelper.mapOf(
                    "issue_type", "local_type_quality",
                    "priority", "high",
                    "tool", "set_local_variable_type",
                    "params_template", JsonHelper.mapOf("function_address", func.getEntryPoint().toString(), "name", "<variable_name>", "data_type", "<StructName> *"),
                    "evidence", new ArrayList<>(localIssues.subList(0, Math.min(5, localIssues.size()))),
                    "estimated_gain", (int) Math.min(20, localIssues.size() * 10)
            ));
        }

        if (!unrenamedGlobals.isEmpty()) {
            actions.add(JsonHelper.mapOf(
                    "issue_type", "unrenamed_globals",
                    "priority", "high",
                    "tool", "rename_or_label",
                    "params_template", JsonHelper.mapOf("address", "<global_address>", "name", "g_<typedName>"),
                    "evidence", new ArrayList<>(unrenamedGlobals.subList(0, Math.min(5, unrenamedGlobals.size()))),
                    "estimated_gain", Math.min(20, unrenamedGlobals.size() * 3)
            ));
        }

        if (!unrenamedLabels.isEmpty()) {
            actions.add(JsonHelper.mapOf(
                    "issue_type", "unrenamed_labels",
                    "priority", "low",
                    "tool", "rename_label",
                    "params_template", JsonHelper.mapOf("address", "<label_address>", "old_name", "LAB_xxxxxxxx", "new_name", "<descriptive_label>"),
                    "evidence", new ArrayList<>(unrenamedLabels.subList(0, Math.min(5, unrenamedLabels.size()))),
                    "estimated_gain", Math.min(10, unrenamedLabels.size() * 2)
            ));
        }

        if (!undocumentedOrdinals.isEmpty()) {
            actions.add(JsonHelper.mapOf(
                    "issue_type", "undocumented_ordinals",
                    "priority", "medium",
                    "tool", "set_decompiler_comment",
                    "params_template", JsonHelper.mapOf("address", "<call_site>", "comment", "Ordinal_<n> = <resolved_name>"),
                    "evidence", new ArrayList<>(undocumentedOrdinals.subList(0, Math.min(5, undocumentedOrdinals.size()))),
                    "estimated_gain", Math.min(10, undocumentedOrdinals.size() * 2)
            ));
        }

        if (!undocumentedMagicNumbers.isEmpty() && !isThunk && !isStub) {
            actions.add(JsonHelper.mapOf(
                    "issue_type", "undocumented_magic_numbers",
                    "priority", "medium",
                    "tool", "batch_set_comments",
                    "params_template", JsonHelper.mapOf("function_address", func.getEntryPoint().toString(), "eol_comments", Collections.singletonList(JsonHelper.mapOf("address", "<instr_address>", "comment", "<constant_meaning>"))),
                    "evidence", new ArrayList<>(undocumentedMagicNumbers.subList(0, Math.min(5, undocumentedMagicNumbers.size()))),
                    "estimated_gain", (int) Math.min(10, undocumentedMagicNumbers.size() * 2)
            ));
        }

        if (!unresolvedStructAccesses.isEmpty() && !isThunk && !isStub) {
            actions.add(JsonHelper.mapOf(
                    "issue_type", "unresolved_struct_accesses",
                    "priority", "high",
                    "tool", "create_struct",
                    "params_template", JsonHelper.mapOf("name", "<StructName>", "fields", Collections.singletonList(JsonHelper.mapOf("name", "<field_name>", "type", "<field_type>", "offset", "<hex_offset>"))),
                    "evidence", new ArrayList<>(unresolvedStructAccesses.subList(0, Math.min(5, unresolvedStructAccesses.size()))),
                    "estimated_gain", (int) Math.min(10, unresolvedStructAccesses.size() * 2)
            ));
        }

        if (commentDensity < 0.67 && !isThunk && !isStub && !isCompilerHelper) {
            actions.add(JsonHelper.mapOf(
                    "issue_type", "inline_comment_density",
                    "priority", "low",
                    "tool", "batch_set_comments",
                    "params_template", JsonHelper.mapOf("function_address", func.getEntryPoint().toString(), "decompiler_comments", Collections.singletonList(JsonHelper.mapOf("address", "<address>", "comment", "<explanation>"))),
                    "evidence", Collections.singletonList("comment_density=" + String.format("%.2f", commentDensity)),
                    "estimated_gain", 5
            ));
        }

        return actions;
    }

    /**
     * Infer what type a Hungarian-prefixed variable name implies.
     * Returns a human-readable type description, or null if the name doesn't have a recognizable prefix.
     */
    private String inferTypeFromHungarianPrefix(String varName) {
        if (varName == null || varName.length() < 2) return null;

        // Check two-char prefixes first (dw, sz, fl, ll, qw, by, ch, ab, aw, ad)
        if (varName.length() >= 3) {
            String prefix2 = varName.substring(0, 2);
            char third = varName.charAt(2);
            if (Character.isUpperCase(third) || third == '_') {
                switch (prefix2) {
                    case "dw": return "uint/dword";
                    case "sz": return "char*/string";
                    case "fl": return "float";
                    case "ll": return "longlong";
                    case "qw": return "ulonglong";
                    case "by": return "byte";
                    case "ch": return "char";
                    case "ab": return "byte[]";
                    case "aw": return "ushort[]";
                    case "ad": return "uint[]";
                    case "ld": return "float10";
                }
            }
        }

        // Check single-char prefixes (p, n, i, b, f, w, l, d, s, h)
        char first = varName.charAt(0);
        char second = varName.charAt(1);
        if (Character.isUpperCase(second)) {
            switch (first) {
                case 'p': return "pointer";
                case 'n': return "int";
                case 'i': return "int";
                case 'b': return "byte/bool";
                case 'f': return "bool/flag";
                case 'w': return "ushort/word";
                case 'l': return "long";
                case 'd': return "double";
                case 's': return "short";
                case 'h': return "HANDLE";
            }
        }
        // g_ prefix for globals
        if (varName.startsWith("g_") && varName.length() > 3) {
            return inferTypeFromHungarianPrefix(varName.substring(2));
        }

        return null;
    }

    /**
     * Search the DataTypeManager for struct/class types matching a variable name.
     * Strips the p-prefix (e.g., pUnit → Unit) and tries multiple common naming conventions.
     * Returns the matching DataType name if found, or null.
     */
    private String findMatchingStructType(DataTypeManager dtm, String varName) {
        if (varName == null || varName.length() < 2) return null;

        // Strip p-prefix for pointer-named variables
        String baseName = varName;
        if (varName.startsWith("p") && varName.length() > 1 && Character.isUpperCase(varName.charAt(1))) {
            baseName = varName.substring(1);
        }
        // Strip g_ prefix for globals
        if (baseName.startsWith("g_") && baseName.length() > 2) {
            baseName = baseName.substring(2);
            // Also strip further p-prefix: g_pUnit → Unit
            if (baseName.startsWith("p") && baseName.length() > 1 && Character.isUpperCase(baseName.charAt(1))) {
                baseName = baseName.substring(1);
            }
        }

        if (baseName.length() < 2) return null;

        // Try exact name and common suffixed variants in root category
        String[] candidates = {
            baseName,            // Unit
            baseName + "Any",    // UnitAny (Diablo 2 convention)
            baseName + "Data",   // UnitData
            baseName + "Info",   // UnitInfo
            baseName + "Rec",    // UnitRec
            baseName + "Record", // UnitRecord
            baseName + "Struct", // UnitStruct
            baseName + "Ctx",    // UnitCtx
            baseName + "Context",// UnitContext
            baseName + "Hdr",    // UnitHdr
            baseName + "Header", // UnitHeader
            baseName + "Tbl",    // UnitTbl
            baseName + "Table",  // UnitTable
        };

        for (String candidate : candidates) {
            DataType dt = dtm.getDataType("/" + candidate);
            if (dt != null && (dt instanceof ghidra.program.model.data.Structure ||
                              dt instanceof ghidra.program.model.data.TypeDef)) {
                return candidate;
            }
        }

        // Fallback: search ALL categories for structs matching candidate names
        // This catches structs in subcategories like /windows/UnitAny
        for (String candidate : candidates) {
            DataType dt = ServiceUtils.findDataTypeByNameInAllCategories(dtm, candidate);
            if (dt != null && (dt instanceof ghidra.program.model.data.Structure ||
                              dt instanceof ghidra.program.model.data.TypeDef)) {
                return candidate;
            }
        }

        // Last resort: case-insensitive search across all data types for baseName prefix match
        // e.g., pUnit → any struct whose name starts with "Unit" (but only if exactly one match)
        String lowerBase = baseName.toLowerCase(Locale.ROOT);
        String singleMatch = null;
        int matchCount = 0;
        Iterator<DataType> allTypes = dtm.getAllDataTypes();
        while (allTypes.hasNext()) {
            DataType dt = allTypes.next();
            if (dt instanceof ghidra.program.model.data.Structure) {
                String dtName = dt.getName().toLowerCase(Locale.ROOT);
                if (dtName.startsWith(lowerBase) || dtName.equals(lowerBase)) {
                    singleMatch = dt.getName();
                    matchCount++;
                    if (matchCount > 1) break; // Ambiguous — don't guess
                }
            }
        }
        if (matchCount == 1) {
            return singleMatch;
        }

        return null;
    }

    /**
     * Validate Hungarian notation compliance for variables
     */
    private void validateHungarianNotation(String varName, String typeName, boolean isGlobal, boolean isParameter, List<String> violations) {
        // Skip generic/default names - they're already caught by undefined variable check
        if (varName.startsWith("param_") || varName.startsWith("local_") ||
            varName.startsWith("iVar") || varName.startsWith("uVar") ||
            varName.startsWith("dVar") || varName.startsWith("fVar") ||
            varName.startsWith("in_") || varName.startsWith("extraout_")) {
            return;
        }

        // Skip undefined types - they're already caught by undefined type check
        if (typeName.startsWith("undefined")) {
            return;
        }

        // Normalize type name (remove array brackets, pointer stars, etc.)
        String baseTypeName = typeName.replaceAll("\\[.*\\]", "").replaceAll("\\s*\\*", "").trim();

        // Get expected prefix for this type
        String expectedPrefix = getExpectedHungarianPrefix(baseTypeName, typeName.contains("*"), typeName.contains("["));

        if (expectedPrefix == null) {
            // Unknown type or structure type - skip validation
            return;
        }

        // For global variables, expect g_ prefix before type prefix
        String fullExpectedPrefix = isGlobal ? "g_" + expectedPrefix : expectedPrefix;

        // Check if variable name starts with expected prefix
        boolean hasCorrectPrefix = false;

        // For types with multiple valid prefixes (e.g., byte can be 'b' or 'by')
        if (expectedPrefix.contains("|")) {
            String[] validPrefixes = expectedPrefix.split("\\|");
            for (String prefix : validPrefixes) {
                String fullPrefix = isGlobal ? "g_" + prefix : prefix;
                if (varName.startsWith(fullPrefix)) {
                    hasCorrectPrefix = true;
                    break;
                }
            }
        } else {
            hasCorrectPrefix = varName.startsWith(fullExpectedPrefix);
        }

        if (!hasCorrectPrefix) {
            // PROP-0001: Allow p-prefix on int/uint/undefined4 parameters (pointer-passed-as-int pattern
            // common in game DLLs where ordinal exports receive all params as int)
            if (isParameter && !isGlobal && varName.length() > 1 && varName.startsWith("p") &&
                Character.isUpperCase(varName.charAt(1)) &&
                (baseTypeName.equals("int") || baseTypeName.equals("uint") || baseTypeName.equals("undefined4") || baseTypeName.equals("dword"))) {
                return; // Valid: pointer-semantic parameter typed as int
            }

            // Detect reverse mismatch: name prefix implies a specific type but actual type differs.
            // Case 1: scalar prefix on pointer-typed variable (e.g., nItemGuid typed as void*)
            // Case 2: semantic prefix on generic primitive (e.g., bForceNoDrop typed as int — should be BOOL)
            if (varName.length() > 1 && Character.isUpperCase(varName.charAt(1))) {
                String prefixImplied = inferTypeFromHungarianPrefix(varName);
                if (prefixImplied != null && !prefixImplied.equals("pointer")) {
                    boolean isGenericPrimitive = baseTypeName.equals("int") || baseTypeName.equals("uint") ||
                        baseTypeName.equals("undefined4") || baseTypeName.equals("dword");
                    boolean typeConflict = typeName.contains("*") || isGenericPrimitive;
                    if (typeConflict) {
                        String suggestedType = prefixImplied.split("/")[0];
                        // Don't flag if the prefix-implied type matches the actual type
                        if (!baseTypeName.equals(suggestedType) && !baseTypeName.equals(prefixImplied)) {
                            violations.add(varName + " (REVERSE MISMATCH: name prefix implies " + prefixImplied +
                                " but type is " + typeName +
                                " — fix TYPE to " + suggestedType +
                                " via set_function_prototype() or set_local_variable_type())");
                            return;
                        }
                    }
                }
            }

            violations.add(varName + " (type: " + typeName + ", expected prefix: " + fullExpectedPrefix + ")");
        }
    }

    /**
     * Get expected Hungarian notation prefix for a given type
     */
    private String getExpectedHungarianPrefix(String typeName, boolean isPointer, boolean isArray) {
        // Handle arrays
        if (isArray) {
            if (typeName.equals("byte")) return "ab";
            if (typeName.equals("ushort")) return "aw";
            if (typeName.equals("uint")) return "ad";
            if (typeName.equals("char")) return "sz";
            return null; // Unknown array type
        }

        // Handle pointers
        if (isPointer) {
            if (typeName.equals("void")) return "p";
            if (typeName.equals("char")) return "sz|lpsz";
            if (typeName.equals("wchar_t")) return "wsz";
            return "p"; // Typed pointers generally use 'p' prefix
        }

        // Handle basic types
        switch (typeName) {
            case "byte": return "b|by";
            case "char": return "c|ch";
            case "bool": return "f";
            case "short": return "n|s";
            case "ushort": case "word": return "w";
            case "int": return "n|i";
            case "uint": case "dword": return "dw";
            case "long": return "l";
            case "ulong": return "dw";
            case "longlong": return "ll";
            case "ulonglong": case "qword": return "qw";
            case "float": return "fl";
            case "double": return "d";
            case "float10": return "ld";
            case "HANDLE": return "h";
            case "BOOL": return "f";
            default:
                // Unknown type (might be structure or custom type)
                return null;
        }
    }

    /**
     * Validate parameter type quality (enhanced completeness check)
     * Checks for: generic void*, int*, state-based type names, missing structures, type duplication
     * @param func Function to validate
     * @param issues List to append detected issues to
     * @param existingHighFunction Pre-decompiled HighFunction (avoids redundant decompilation); may be null
     */
    private void validateParameterTypeQuality(Function func, List<String> issues, ghidra.program.model.pcode.HighFunction existingHighFunction) {
        Program program = func.getProgram();
        DataTypeManager dtm = program.getDataTypeManager();

        // State-based type name prefixes to flag
        String[] statePrefixes = {"Initialized", "Allocated", "Created", "Updated",
                                  "Processed", "Deleted", "Modified", "Constructed",
                                  "Freed", "Destroyed", "Copied", "Cloned"};

        // Parse plate comment parameter descriptions for cross-validation
        String plateComment = func.getComment();
        Map<String, String> plateParamDescriptions = new java.util.HashMap<>();
        if (plateComment != null) {
            boolean inParams = false;
            for (String line : plateComment.split("\n")) {
                String trimmed = line.trim();
                if (trimmed.startsWith("Parameters:") || trimmed.equals("Parameters")) {
                    inParams = true;
                    continue;
                }
                if (inParams && (trimmed.startsWith("Returns:") || trimmed.startsWith("Algorithm:") || trimmed.isEmpty())) {
                    if (trimmed.startsWith("Returns:") || trimmed.startsWith("Algorithm:")) inParams = false;
                    continue;
                }
                if (inParams) {
                    // Match patterns like "pGame — Game session pointer" or "pGame - description"
                    java.util.regex.Matcher m = java.util.regex.Pattern.compile(
                        "^[*\\s]*([a-zA-Z_]\\w*)\\s*[—\\-–:]\\s*(.+)").matcher(trimmed);
                    if (m.find()) {
                        plateParamDescriptions.put(m.group(1), m.group(2).trim().toLowerCase(Locale.ROOT));
                    }
                }
            }
        }

        // Check for __thiscall with unresolved void* this pointer
        try {
            String callingConv = func.getCallingConventionName();
            if ("__thiscall".equals(callingConv)) {
                Parameter autoParam = func.getParameter(0); // 'this' is first param in thiscall
                if (autoParam != null) {
                    DataType thisType = autoParam.getDataType();
                    if (thisType instanceof Pointer) {
                        Pointer thisPtr = (Pointer) thisType;
                        DataType pointedTo = thisPtr.getDataType();
                        if (pointedTo != null && pointedTo.getName().equals("void")) {
                            issues.add("Unresolved this pointer: __thiscall function has void* this — " +
                                "STRUCTURAL: ECX auto-param cannot be retyped via API. " +
                                "Document the intended type in the plate comment Parameters section instead.");
                        }
                    }
                }
            }
        } catch (Exception e) {
            // getCallingConventionName may throw if not set
        }

        for (Parameter param : func.getParameters()) {
            DataType paramType = param.getDataType();
            String typeName = paramType.getName();

            // Check 1: Generic void* pointers (should use specific types)
            if (paramType instanceof Pointer) {
                Pointer ptrType = (Pointer) paramType;
                DataType pointedTo = ptrType.getDataType();
                if (pointedTo != null && pointedTo.getName().equals("void")) {
                    String matchedStruct = findMatchingStructType(dtm, param.getName());
                    if (matchedStruct != null) {
                        issues.add("Generic void* parameter: " + param.getName() +
                                  " — struct '" + matchedStruct + "' exists in program, use set_function_prototype() to change to " + matchedStruct + "*");
                    } else {
                        issues.add("Generic void* parameter: " + param.getName() +
                                  " (should use specific structure type)");
                    }
                }
            }

            // Check 1a: Generic int* pointers with p-prefix names (should be struct pointers)
            // e.g., pUnit typed as int* but plate says "Unit receiving drops" → should be UnitAny*
            if (paramType instanceof Pointer) {
                Pointer ptrType = (Pointer) paramType;
                DataType pointedTo = ptrType.getDataType();
                if (pointedTo != null && (pointedTo.getName().equals("int") || pointedTo.getName().equals("uint")) &&
                    param.getName().length() > 1 && param.getName().startsWith("p") &&
                    Character.isUpperCase(param.getName().charAt(1))) {
                    String matchedStruct = findMatchingStructType(dtm, param.getName());
                    if (matchedStruct != null) {
                        issues.add("Generic int* parameter: " + param.getName() +
                                  " — struct '" + matchedStruct + "' exists in program, use set_function_prototype() to change to " + matchedStruct + "*");
                    } else {
                        issues.add("Generic int* parameter: " + param.getName() +
                                  " (p-prefix suggests typed struct pointer, not int* — create struct with create_struct() then apply)");
                    }
                }
            }

            // Check 1b: Hungarian prefix-type mismatch (p-prefix on non-pointer types)
            // Detects parameters named like pointers (pGame, pUnit) but typed as int/uint/dword
            String paramName = param.getName();
            if (paramName.length() > 1 && paramName.startsWith("p") &&
                Character.isUpperCase(paramName.charAt(1)) &&
                !(paramType instanceof Pointer)) {
                String pTypeName = paramType.getName();
                if (pTypeName.equals("int") || pTypeName.equals("uint") ||
                    pTypeName.equals("dword") || pTypeName.startsWith("undefined")) {
                    // Check if plate comment confirms pointer semantics
                    String plateDesc = plateParamDescriptions.get(paramName);
                    boolean plateConfirmsPointer = plateDesc != null &&
                        (plateDesc.contains("pointer") || plateDesc.contains("ptr") ||
                         plateDesc.contains("address") || plateDesc.contains("handle"));
                    String matchedStruct = findMatchingStructType(dtm, paramName);
                    if (plateConfirmsPointer) {
                        String fixSuffix = matchedStruct != null
                            ? " — fix: set_function_prototype() to change type to " + matchedStruct + "*"
                            : " — fix: set_function_prototype() to change type to void* or specific struct pointer";
                        issues.add("Prefix-type mismatch (PLATE CONFIRMED): " + paramName +
                            " has p prefix and plate says '" + plateDesc +
                            "' but type is " + pTypeName + fixSuffix);
                    } else {
                        String fixSuffix = matchedStruct != null
                            ? " (struct '" + matchedStruct + "' exists — change type to " + matchedStruct + "*)"
                            : " (should be a pointer type — create struct with create_struct() if needed)";
                        issues.add("Prefix-type mismatch: " + paramName +
                            " has p prefix (pointer) but type is " + pTypeName + fixSuffix);
                    }
                }
            }

            // Check 1c: Plate comment vs actual type cross-validation
            String plateDesc = plateParamDescriptions.get(paramName);
            if (plateDesc != null) {
                boolean plateSaysPointer = plateDesc.contains("pointer") || plateDesc.contains("ptr") ||
                    plateDesc.contains("address") || plateDesc.contains("handle");
                boolean actualIsPointer = paramType instanceof Pointer;
                // Plate says pointer but type is scalar
                if (plateSaysPointer && !actualIsPointer && !paramName.startsWith("p")) {
                    issues.add("Plate-type contradiction: " + paramName +
                        " — plate says '" + plateDesc + "' (pointer) but actual type is " + typeName +
                        " — update type or correct plate comment");
                }
            }

            // Check 2: State-based type names (bad practice)
            for (String prefix : statePrefixes) {
                if (typeName.startsWith(prefix)) {
                    issues.add("State-based type name: " + typeName +
                              " on parameter " + param.getName() +
                              " (should use identity-based name)");
                    break;
                }
            }

            // Check 3: Check for similar type names (potential duplicates)
            if (paramType instanceof Pointer) {
                String baseType = typeName.replace(" *", "").trim();
                // Check for types with similar base names
                for (String prefix : statePrefixes) {
                    if (baseType.startsWith(prefix)) {
                        String identityName = baseType.substring(prefix.length());
                        // Check if identity-based version exists
                        DataType identityType = dtm.getDataType("/" + identityName);
                        if (identityType != null) {
                            issues.add("Type duplication: " + baseType + " and " + identityName +
                                      " exist (consider consolidating to " + identityName + ")");
                        }
                    }
                }
            }
        }

        // Check 4: Plate parameter completeness — verify all function params are documented
        if (!plateParamDescriptions.isEmpty()) {
            for (Parameter param : func.getParameters()) {
                String pName = param.getName();
                if (!plateParamDescriptions.containsKey(pName) &&
                    !pName.equals("this") && !pName.startsWith("param_")) {
                    issues.add("Undocumented parameter: " + pName +
                        " is not listed in plate comment Parameters section");
                }
            }
        }

        // Check 5: Local variable type quality — detect generic void*/int* on named locals
        // Uses pre-decompiled HighFunction when available (avoids redundant decompile that can silently fail)
        try {
            ghidra.program.model.pcode.HighFunction highFunction = existingHighFunction;
            if (highFunction == null) {
                // Fallback: decompile if caller didn't provide pre-decompiled result
                DecompileResults decompResults = functionService.decompileFunction(func, program);
                if (decompResults != null && decompResults.decompileCompleted()) {
                    highFunction = decompResults.getHighFunction();
                }
            }
            if (highFunction != null) {
                    Iterator<ghidra.program.model.pcode.HighSymbol> symbols = highFunction.getLocalSymbolMap().getSymbols();
                    while (symbols.hasNext()) {
                        ghidra.program.model.pcode.HighSymbol symbol = symbols.next();
                        String localName = symbol.getName();
                        DataType localType = symbol.getDataType();

                        // Skip auto-generated names and phantom variables
                        if (localName.startsWith("local_") || localName.startsWith("extraout_") ||
                            localName.startsWith("in_") || localName.matches(".*Var\\d+")) {
                            continue;
                        }

                        // Check 5a: Local void* with meaningful name
                        if (localType instanceof Pointer) {
                            Pointer ptrType = (Pointer) localType;
                            DataType pointedTo = ptrType.getDataType();
                            if (pointedTo != null && pointedTo.getName().equals("void") &&
                                localName.length() > 1 && localName.startsWith("p") &&
                                Character.isUpperCase(localName.charAt(1))) {
                                String matchedStruct = findMatchingStructType(dtm, localName);
                                if (matchedStruct != null) {
                                    issues.add("Generic void* local: " + localName +
                                              " — struct '" + matchedStruct + "' exists, use set_local_variable_type('" +
                                              localName + "', '" + matchedStruct + " *')");
                                } else {
                                    issues.add("Generic void* local: " + localName +
                                              " (p-prefix suggests typed struct pointer — create struct with create_struct() then set_local_variable_type())");
                                }
                            }
                        }

                        // Check 5b: Local int*/uint* with p-prefix name
                        if (localType instanceof Pointer) {
                            Pointer ptrType = (Pointer) localType;
                            DataType pointedTo = ptrType.getDataType();
                            if (pointedTo != null && (pointedTo.getName().equals("int") || pointedTo.getName().equals("uint")) &&
                                localName.length() > 1 && localName.startsWith("p") &&
                                Character.isUpperCase(localName.charAt(1))) {
                                String matchedStruct = findMatchingStructType(dtm, localName);
                                if (matchedStruct != null) {
                                    issues.add("Generic int* local: " + localName +
                                              " — struct '" + matchedStruct + "' exists, use set_local_variable_type('" +
                                              localName + "', '" + matchedStruct + " *')");
                                } else {
                                    issues.add("Generic int* local: " + localName +
                                              " (p-prefix suggests typed struct pointer, not int* — create struct then set_local_variable_type())");
                                }
                            }
                        }

                        // Check 5c: Local p-prefix with scalar type (should be pointer)
                        if (localName.length() > 1 && localName.startsWith("p") &&
                            Character.isUpperCase(localName.charAt(1)) &&
                            !(localType instanceof Pointer)) {
                            String localTypeName = localType.getName();
                            if (localTypeName.equals("int") || localTypeName.equals("uint") ||
                                localTypeName.equals("dword") || localTypeName.startsWith("undefined")) {
                                String matchedStruct = findMatchingStructType(dtm, localName);
                                if (matchedStruct != null) {
                                    issues.add("Local prefix-type mismatch: " + localName +
                                              " has p prefix but type is " + localTypeName +
                                              " — struct '" + matchedStruct + "' exists, use set_local_variable_type('" +
                                              localName + "', '" + matchedStruct + " *')");
                                } else {
                                    issues.add("Local prefix-type mismatch: " + localName +
                                              " has p prefix but type is " + localTypeName +
                                              " (should be a pointer type)");
                                }
                            }
                        }
                    }
            }
        } catch (Exception e) {
            // Decompilation may fail for some functions — skip local checks
        }
    }

    /**
     * Validate plate comment structure and content quality
     */
    private void validatePlateCommentStructure(String plateComment, List<String> issues,
                                               Function func, boolean isThunk, boolean isCompilerHelper) {
        if (plateComment == null || plateComment.isEmpty()) {
            issues.add("Plate comment is empty");
            return;
        }

        // v3.2.0: Thunks only require: identifies as thunk/stub + references body address.
        if (isThunk) {
            String lower = plateComment.toLowerCase();
            if (!lower.contains("thunk") && !lower.contains("stub") && !lower.contains("forwarding") && !lower.contains("jmp")) {
                issues.add("Thunk plate comment should identify function as a forwarding stub");
            }
            return;
        }

        // Compiler/CRT helpers use a compact plate-comment profile.
        String[] lines = plateComment.split("\n");
        if (isCompilerHelper) {
            String lower = plateComment.toLowerCase(Locale.ROOT);
            if (lines.length < 5) {
                issues.add("Plate comment has only " + lines.length + " lines (minimum 5 required for compiler helpers)");
            }
            if (!lower.contains("purpose:") && !lower.contains("origin:")) {
                issues.add("Compiler helper comment should include Purpose or Origin context");
            }
            if (!lower.contains("parameters:")) {
                issues.add("Missing Parameters section");
            }
            return;
        }

        // --- High-value check 1: Summary line ---
        // First non-empty line should be a meaningful description (>20 chars)
        String summaryLine = null;
        for (String line : lines) {
            String trimmed = line.trim();
            if (!trimmed.isEmpty()) {
                summaryLine = trimmed;
                break;
            }
        }
        if (summaryLine == null || summaryLine.length() < 20) {
            issues.add("Summary line missing or too short (need >20 chars describing what the function does)");
        }

        // Check minimum line count
        if (lines.length < 10) {
            issues.add("Plate comment has only " + lines.length + " lines (minimum 10 required)");
        }

        // Check for required sections
        boolean hasAlgorithm = false;
        boolean hasParameters = false;
        boolean hasReturns = false;
        boolean hasSource = false;
        boolean hasNumberedSteps = false;
        int algorithmLineIdx = -1;
        int parametersLineIdx = -1;
        int returnsLineIdx = -1;
        int nextSectionAfterAlgo = -1;
        int nextSectionAfterParams = -1;
        int nextSectionAfterReturns = -1;

        for (int i = 0; i < lines.length; i++) {
            String trimmed = lines[i].trim();

            if (trimmed.startsWith("Algorithm:") || trimmed.equals("Algorithm")) {
                hasAlgorithm = true;
                algorithmLineIdx = i;
                if (parametersLineIdx >= 0 && nextSectionAfterParams < 0) nextSectionAfterParams = i;
                if (returnsLineIdx >= 0 && nextSectionAfterReturns < 0) nextSectionAfterReturns = i;
            }
            if (trimmed.matches("^\\d+\\.\\s+.*")) {
                hasNumberedSteps = true;
            }
            if (trimmed.startsWith("Parameters:") || trimmed.equals("Parameters")) {
                hasParameters = true;
                parametersLineIdx = i;
                if (algorithmLineIdx >= 0 && nextSectionAfterAlgo < 0) nextSectionAfterAlgo = i;
                if (returnsLineIdx >= 0 && nextSectionAfterReturns < 0) nextSectionAfterReturns = i;
            }
            if (trimmed.startsWith("Returns:") || trimmed.equals("Returns")) {
                hasReturns = true;
                returnsLineIdx = i;
                if (algorithmLineIdx >= 0 && nextSectionAfterAlgo < 0) nextSectionAfterAlgo = i;
                if (parametersLineIdx >= 0 && nextSectionAfterParams < 0) nextSectionAfterParams = i;
            }
            if (trimmed.startsWith("Source:") || trimmed.startsWith("Source file:")) {
                hasSource = true;
                if (algorithmLineIdx >= 0 && nextSectionAfterAlgo < 0) nextSectionAfterAlgo = i;
                if (parametersLineIdx >= 0 && nextSectionAfterParams < 0) nextSectionAfterParams = i;
                if (returnsLineIdx >= 0 && nextSectionAfterReturns < 0) nextSectionAfterReturns = i;
            }
            // Any other section header ends the previous section
            if (trimmed.endsWith(":") && trimmed.length() > 1 && !trimmed.startsWith("//")) {
                if (algorithmLineIdx >= 0 && nextSectionAfterAlgo < 0 && i > algorithmLineIdx) nextSectionAfterAlgo = i;
                if (parametersLineIdx >= 0 && nextSectionAfterParams < 0 && i > parametersLineIdx) nextSectionAfterParams = i;
                if (returnsLineIdx >= 0 && nextSectionAfterReturns < 0 && i > returnsLineIdx) nextSectionAfterReturns = i;
            }
        }

        if (!hasAlgorithm) {
            issues.add("Missing Algorithm section");
        }
        if (hasAlgorithm && !hasNumberedSteps) {
            issues.add("Algorithm section exists but has no numbered steps");
        }
        if (!hasParameters) {
            issues.add("Missing Parameters section");
        }
        if (!hasReturns) {
            issues.add("Missing Returns section");
        }

        // --- Medium-value check 1: Algorithm step substance ---
        // Each numbered step should have >10 chars of content (not just "1. Init")
        if (hasAlgorithm && hasNumberedSteps) {
            int algoEnd = nextSectionAfterAlgo > 0 ? nextSectionAfterAlgo : lines.length;
            int shallowSteps = 0;
            int totalSteps = 0;
            for (int i = algorithmLineIdx + 1; i < algoEnd; i++) {
                String trimmed = lines[i].trim();
                if (trimmed.matches("^\\d+\\.\\s+.*")) {
                    totalSteps++;
                    // Extract the text after "N. "
                    String stepText = trimmed.replaceFirst("^\\d+\\.\\s+", "");
                    if (stepText.length() < 10) {
                        shallowSteps++;
                    }
                }
            }
            if (totalSteps > 0 && shallowSteps > totalSteps / 2) {
                issues.add("Algorithm has " + shallowSteps + "/" + totalSteps
                        + " shallow steps (<10 chars each); steps should describe behavior, not just label it");
            }
        }

        // --- High-value check 2: Parameter count cross-validation ---
        // --- Medium-value check 2: Parameter entries have type+description ---
        if (hasParameters && func != null) {
            int sigParamCount = func.getParameterCount();
            int endIdx = nextSectionAfterParams > 0 ? nextSectionAfterParams : lines.length;
            int docParamCount = 0;
            int shallowParams = 0;
            for (int i = parametersLineIdx + 1; i < endIdx; i++) {
                String trimmed = lines[i].trim();
                if (trimmed.isEmpty()) continue;
                // Parameter entries typically start with the param name followed by colon or dash
                // e.g. "  nExpansionMode: int - data source flag" or "  param_1 (int) - ..."
                if (trimmed.matches("^\\w+\\s*[:(-].*") || trimmed.matches("^\\w+\\s*\\(.*")) {
                    docParamCount++;
                    // Check substance: after the param name and separator, is there a real description?
                    // Strip "paramName: type - " or "paramName (type) - " prefix to get description
                    String afterName = trimmed.replaceFirst("^\\w+\\s*[:(-]\\s*", "");
                    // Also strip a type token if present (e.g., "int - desc" -> "desc")
                    String desc = afterName.replaceFirst("^\\w+\\*?\\s*[-)]\\s*", "");
                    if (desc.length() < 5) {
                        shallowParams++;
                    }
                }
            }
            if (sigParamCount > 0 && docParamCount > 0 && Math.abs(sigParamCount - docParamCount) > 1) {
                issues.add("Parameter count mismatch: signature has " + sigParamCount
                        + " params but plate comment documents " + docParamCount);
            }
            if (docParamCount > 0 && shallowParams > docParamCount / 2) {
                issues.add("" + shallowParams + "/" + docParamCount
                        + " parameter entries lack meaningful descriptions (need type + what the param is for)");
            }
        }

        // --- High-value check 3: Returns section cross-validates with return type ---
        if (hasReturns && func != null) {
            String returnType = func.getReturnType().getName();
            int endIdx = nextSectionAfterReturns > 0 ? nextSectionAfterReturns : lines.length;
            StringBuilder returnsContent = new StringBuilder();
            for (int i = returnsLineIdx; i < endIdx; i++) {
                returnsContent.append(lines[i].trim()).append(" ");
            }
            String returnsText = returnsContent.toString().toLowerCase();
            boolean isVoidReturn = returnType.equals("void");
            boolean docSaysVoid = returnsText.contains("void") || returnsText.contains("no return value")
                    || returnsText.contains("nothing");
            boolean docSaysNonVoid = returnsText.contains("returns the") || returnsText.contains("return value")
                    || returnsText.matches(".*returns?\\s+\\w+.*");

            if (isVoidReturn && !docSaysVoid && docSaysNonVoid) {
                issues.add("Returns section claims a return value but function return type is void");
            } else if (!isVoidReturn && docSaysVoid && !returnsText.contains(returnType.toLowerCase())) {
                issues.add("Returns section says void/nothing but function return type is " + returnType);
            }
        }

        // --- High-value check 4: Source file reference ---
        if (!hasSource) {
            issues.add("Missing Source file reference (e.g., Source: ..\\Source\\D2Common\\DATATBLS\\DataTbls.cpp)");
        }
    }

    /**
     * Composite endpoint for RE documentation workflow.
     * Returns decompiled code + classification + callees + variables with pre-analysis + compact completeness
     * in a single response, using only one decompilation.
     */
    @McpTool(path = "/analyze_for_documentation", description = "Composite analysis for RE documentation workflow. On programs with multiple address spaces (e.g., embedded targets), prefix addresses with the space name (mem:1000) to avoid ambiguous resolution.", category = "analysis")
    public Response analyzeForDocumentation(
            @Param(value = "function_address", paramType = "address",
                   description = "Address in the program. Accepts 0x<hex> (default space) or <space>:<hex> "
                               + "(e.g., mem:1000, code:ff00). Note: some programs — particularly "
                               + "embedded/microcontroller targets — are not address-space-agnostic; "
                               + "use get_address_spaces to discover spaces before assuming a plain hex "
                               + "address is unambiguous.") String functionAddress,
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        // Resolve address before entering SwingUtilities lambda
        Address addr = ServiceUtils.parseAddress(program, functionAddress);
        if (addr == null) return Response.err(ServiceUtils.getLastParseError());

        final AtomicReference<Map<String, Object>> resultData = new AtomicReference<>();
        final AtomicReference<String> errorMsg = new AtomicReference<>(null);

        try {
            SwingUtilities.invokeAndWait(() -> {
                try {
                    // Resolve function by address
                    Function func = program.getFunctionManager().getFunctionAt(addr);
                    if (func == null) {
                        func = program.getFunctionManager().getFunctionContaining(addr);
                    }
                    if (func == null) {
                        errorMsg.set("No function at address: " + functionAddress);
                        return;
                    }

                    // Build structured data
                    Map<String, Object> data = new LinkedHashMap<>();

                    // Basic info
                    data.put("name", func.getName());
                    data.putAll(ServiceUtils.addressToJson(func.getEntryPoint(), program));
                    data.put("signature", func.getSignature().toString());

                    // Classification
                    String classification = classifyFunction(func, program);
                    data.put("classification", classification);

                    // Return type analysis
                    String retTypeName = func.getReturnType().getName();
                    data.put("return_type", retTypeName);
                    data.put("return_type_resolved", !retTypeName.startsWith("undefined"));

                    // Decompile (single decompilation reused for code + variables)
                    DecompileResults decompResults = functionService.decompileFunction(func, program);
                    if (decompResults != null && decompResults.decompileCompleted() &&
                        decompResults.getDecompiledFunction() != null) {
                        String decompiledCode = decompResults.getDecompiledFunction().getC();
                        if (decompiledCode != null) {
                            data.put("decompiled_code", decompiledCode);
                        }
                    }

                    // Callees with ordinal and documentation status
                    List<Map<String, Object>> calleeList = new ArrayList<>();
                    Set<Function> calledFuncs = func.getCalledFunctions(null);
                    int ordinalCalleeCount = 0;
                    for (Function called : calledFuncs) {
                        String calleeName = called.getName();
                        boolean isUndocumented = calleeName.startsWith("FUN_") || calleeName.startsWith("thunk_FUN_");
                        boolean isOrdinal = calleeName.startsWith("Ordinal_") || calleeName.startsWith("thunk_Ordinal_");
                        if (isOrdinal) ordinalCalleeCount++;
                        Map<String, Object> calleeEntry = new LinkedHashMap<>();
                        calleeEntry.put("name", calleeName);
                        if (isUndocumented) calleeEntry.put("undocumented", true);
                        if (isOrdinal) calleeEntry.put("is_ordinal", true);
                        if (called.isThunk()) calleeEntry.put("is_thunk", true);
                        calleeList.add(calleeEntry);
                    }
                    data.put("callees", calleeList);
                    data.put("callee_count", calleeList.size());
                    data.put("ordinal_callee_count", ordinalCalleeCount);

                    // Wrapper hint
                    if (calleeList.size() == 1 && retTypeName.startsWith("undefined")) {
                        Function callee = calledFuncs.iterator().next();
                        String calleeRetType = callee.getReturnType().getName();
                        if (!calleeRetType.equals("void") && !calleeRetType.startsWith("undefined")) {
                            data.put("wrapper_hint", "Callee '" + callee.getName()
                                  + "' returns " + calleeRetType);
                        }
                    }

                    // Parameters with pre-analysis
                    List<Map<String, Object>> paramList = new ArrayList<>();
                    Parameter[] params = func.getParameters();
                    for (Parameter param : params) {
                        String pName = param.getName();
                        String pType = param.getDataType().getName();
                        String pStorage = param.getVariableStorage().toString();
                        boolean needsType = pType.startsWith("undefined");
                        boolean needsRename = pName.matches("param_\\d+");
                        Map<String, Object> paramEntry = new LinkedHashMap<>();
                        paramEntry.put("name", pName);
                        paramEntry.put("type", pType);
                        paramEntry.put("storage", pStorage);
                        paramEntry.put("needs_type", needsType);
                        paramEntry.put("needs_rename", needsRename);
                        if (needsType) {
                            paramEntry.put("suggested_type", FunctionService.suggestType(pType));
                            paramEntry.put("suggested_prefix", FunctionService.suggestHungarianPrefix(FunctionService.suggestType(pType)));
                        } else {
                            paramEntry.put("suggested_prefix", FunctionService.suggestHungarianPrefix(pType));
                        }
                        paramList.add(paramEntry);
                    }
                    data.put("parameters", paramList);

                    // Local variables with pre-analysis (from HighFunction)
                    List<Map<String, Object>> localList = new ArrayList<>();
                    if (decompResults != null && decompResults.decompileCompleted()) {
                        HighFunction highFunc = decompResults.getHighFunction();
                        if (highFunc != null) {
                            Iterator<HighSymbol> symbols = highFunc.getLocalSymbolMap().getSymbols();
                            while (symbols.hasNext()) {
                                HighSymbol sym = symbols.next();
                                String symName = sym.getName();
                                String symType = sym.getDataType().getName();
                                boolean isPhantom = symName.startsWith("extraout_") || symName.startsWith("in_");
                                String storageStr = "";
                                HighVariable highVar = sym.getHighVariable();
                                if (highVar != null && highVar.getRepresentative() != null) {
                                    Varnode rep = highVar.getRepresentative();
                                    if (rep.getAddress() != null) {
                                        storageStr = rep.getAddress().toString() + ":" + rep.getSize();
                                    }
                                }
                                boolean needsType = !isPhantom && symType.startsWith("undefined");
                                boolean needsRename = !isPhantom && symName.matches("local_[0-9a-fA-F]+|[a-zA-Z]Var\\d+");
                                Map<String, Object> localEntry = new LinkedHashMap<>();
                                localEntry.put("name", symName);
                                localEntry.put("type", symType);
                                localEntry.put("storage", storageStr);
                                localEntry.put("is_phantom", isPhantom);
                                if (needsType) {
                                    localEntry.put("needs_type", true);
                                    localEntry.put("suggested_type", FunctionService.suggestType(symType));
                                }
                                if (needsRename) {
                                    localEntry.put("needs_rename", true);
                                    String prefix = needsType ? FunctionService.suggestHungarianPrefix(FunctionService.suggestType(symType))
                                                             : FunctionService.suggestHungarianPrefix(symType);
                                    localEntry.put("suggested_prefix", prefix);
                                }
                                localList.add(localEntry);
                            }
                        }
                    }
                    data.put("locals", localList);

                    // DAT global count (unrenamed globals referenced)
                    int datGlobalCount = 0;
                    ReferenceIterator refIter = program.getReferenceManager().getReferenceIterator(func.getBody().getMinAddress());
                    while (refIter.hasNext()) {
                        Reference ref = refIter.next();
                        if (!func.getBody().contains(ref.getFromAddress())) continue;
                        Address toAddr = ref.getToAddress();
                        Symbol sym = program.getSymbolTable().getPrimarySymbol(toAddr);
                        if (sym != null && sym.getName().startsWith("DAT_")) {
                            datGlobalCount++;
                        }
                    }
                    data.put("dat_global_count", datGlobalCount);

                    // Compact completeness score
                    Response completenessResponse = analyzeFunctionCompleteness(func.getEntryPoint().toString(), true);
                    if (completenessResponse instanceof Response.Ok ok) {
                        data.put("completeness", ok.data());
                    }

                    resultData.set(data);
                } catch (Exception e) {
                    errorMsg.set(e.getMessage());
                }
            });

            if (errorMsg.get() != null) {
                return Response.err(errorMsg.get());
            }
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }

        return Response.ok(resultData.get());
    }

    /**
     * Find gaps of undefined/unanalyzed bytes in executable memory not covered by any function body.
     */
    @McpTool(path = "/find_code_gaps",
             description = "Find gaps of undefined/unanalyzed bytes in executable memory not covered by any "
                         + "function body. Useful for discovering missed functions in firmware and embedded "
                         + "binaries. Reports each contiguous uncovered range with its size, content type, "
                         + "and the nearest functions on each side.",
             category = "analysis")
    public Response findCodeGaps(
            @Param(value = "min_size", defaultValue = "1",
                   description = "Minimum gap size in addressable units to report (increase to filter alignment padding)") int minSize,
            @Param(value = "offset", defaultValue = "0") int offset,
            @Param(value = "limit", defaultValue = "100") int limit,
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        final AtomicReference<Response> responseRef = new AtomicReference<>(null);
        final AtomicReference<String> errorMsg = new AtomicReference<>(null);

        try {
            SwingUtilities.invokeAndWait(() -> {
                try {
                    FunctionManager funcMgr = program.getFunctionManager();
                    Listing listing = program.getListing();
                    Memory memory = program.getMemory();

                    // Union of all function bodies
                    AddressSet functionUnion = new AddressSet();
                    for (Function f : funcMgr.getFunctions(true)) {
                        functionUnion.add(f.getBody());
                    }

                    // Executable, non-external memory blocks
                    AddressSet execMemory = new AddressSet();
                    for (MemoryBlock block : memory.getBlocks()) {
                        if (block.isExecute() && !block.isExternalBlock()) {
                            execMemory.add(block.getStart(), block.getEnd());
                        }
                    }

                    // Gaps = executable memory not covered by any function body
                    AddressSet gapSet = execMemory.subtract(functionUnion);

                    List<Map<String, Object>> gaps = new ArrayList<>();
                    boolean multiSpace = ServiceUtils.getPhysicalSpaceCount(program) > 1;

                    AddressRangeIterator rangeIter = gapSet.getAddressRanges();
                    while (rangeIter.hasNext()) {
                        AddressRange range = rangeIter.next();
                        long size = range.getLength();
                        if (size < minSize) continue;

                        Address gapStart = range.getMinAddress();
                        Address gapEnd   = range.getMaxAddress();

                        AddressSet thisGap = new AddressSet(gapStart, gapEnd);
                        boolean hasUndefined     = listing.getUndefinedDataAt(gapStart) != null;
                        boolean hasInstructions  = listing.getInstructions(thisGap, true).hasNext();

                        FunctionIterator bIter = funcMgr.getFunctions(gapStart, false);
                        Function before = bIter.hasNext() ? bIter.next() : null;

                        Address nextAddr = gapEnd.next();
                        Function after = null;
                        if (nextAddr != null) {
                            FunctionIterator aIter = funcMgr.getFunctions(nextAddr, true);
                            if (aIter.hasNext()) after = aIter.next();
                        }

                        Map<String, Object> gap = new java.util.LinkedHashMap<>();
                        gap.put("start", gapStart.toString(false));
                        gap.put("end",   gapEnd.toString(false));
                        if (multiSpace) {
                            gap.put("start_full",    gapStart.toString());
                            gap.put("end_full",      gapEnd.toString());
                            gap.put("address_space", gapStart.getAddressSpace().getName());
                        }
                        gap.put("size",                    size);
                        gap.put("has_undefined_bytes",     hasUndefined);
                        gap.put("has_orphaned_instructions", hasInstructions);
                        gap.put("before_function",         before != null ? before.getName() : null);
                        gap.put("before_function_address", before != null ? before.getEntryPoint().toString(false) : null);
                        gap.put("after_function",          after != null ? after.getName() : null);
                        gap.put("after_function_address",  after != null ? after.getEntryPoint().toString(false) : null);
                        gaps.add(gap);
                    }

                    int total    = gaps.size();
                    int endIndex = Math.min(offset + limit, total);
                    List<Map<String, Object>> page = gaps.subList(Math.min(offset, total), endIndex);

                    responseRef.set(Response.ok(JsonHelper.mapOf(
                        "total",  total,
                        "offset", offset,
                        "limit",  limit,
                        "gaps",   page
                    )));

                } catch (Exception e) {
                    errorMsg.set(e.getMessage());
                }
            });

            if (errorMsg.get() != null) {
                return Response.err(errorMsg.get());
            }
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }

        return responseRef.get();
    }
}















