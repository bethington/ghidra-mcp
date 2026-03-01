package com.xebyte.core;

import ghidra.app.decompiler.DecompileResults;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
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
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TaskMonitor;

import javax.swing.SwingUtilities;
import java.lang.reflect.InvocationTargetException;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Service for analysis operations: control flow analysis, function completeness,
 * similarity detection, memory inspection, and enhanced search.
 * Extracted from GhidraMCPPlugin as part of v4.0.0 refactor.
 */
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
    // Program resolution helper
    // ========================================================================

    private Object[] getProgramOrError(String programName) {
        Program program = null;
        if (programName != null && !programName.isEmpty()) {
            program = programProvider.resolveProgram(programName);
        } else {
            program = programProvider.getCurrentProgram();
        }
        if (program == null) {
            String available = "";
            Program[] all = programProvider.getAllOpenPrograms();
            if (all != null && all.length > 0) {
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < all.length; i++) {
                    if (i > 0) sb.append(", ");
                    sb.append(all[i].getName());
                }
                available = " Available programs: " + sb;
            }
            String error = programName != null && !programName.isEmpty()
                    ? ServiceUtils.programNotFoundError(programName) + available
                    : "No program loaded." + available;
            return new Object[]{null, error};
        }
        return new Object[]{program, null};
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

        CompletenessScoreResult(double score, double effectiveScore, int unfixableDeductions) {
            this.score = score;
            this.effectiveScore = effectiveScore;
            this.unfixableDeductions = unfixableDeductions;
        }
    }

    // ========================================================================
    // Public endpoint methods
    // ========================================================================

    public String listAnalyzers(String programName) {
        Object[] programResult = getProgramOrError(programName);
        Program program = (Program) programResult[0];
        if (program == null) return (String) programResult[1];

        try {
            Options options = program.getOptions(Program.ANALYSIS_PROPERTIES);
            List<String> names = options.getOptionNames();
            List<String> entries = new ArrayList<>();
            for (String name : names) {
                try {
                    boolean enabled = options.getBoolean(name, false);
                    entries.add("{\"name\": \"" + ServiceUtils.escapeJson(name) + "\", \"enabled\": " + enabled + "}");
                } catch (Exception ignored) {
                    // Not a boolean option -- skip non-analyzer properties
                }
            }
            StringBuilder sb = new StringBuilder("{\"analyzers\": [");
            for (int i = 0; i < entries.size(); i++) {
                if (i > 0) sb.append(", ");
                sb.append(entries.get(i));
            }
            sb.append("], \"count\": ").append(entries.size()).append("}");
            return sb.toString();
        } catch (Exception e) {
            return "{\"error\": \"" + ServiceUtils.escapeJson(e.getMessage()) + "\"}";
        }
    }

    /**
     * Trigger auto-analysis on the current or named program.
     */
    public String runAnalysis(String programName) {
        Object[] programResult = getProgramOrError(programName);
        Program program = (Program) programResult[0];
        if (program == null) return (String) programResult[1];

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
            return "{\"success\": true, \"duration_ms\": " + duration +
                   ", \"total_functions\": " + after +
                   ", \"new_functions\": " + (after - before) +
                   ", \"program\": \"" + ServiceUtils.escapeJson(program.getName()) + "\"}";
        } catch (Exception e) {
            return "{\"error\": \"Analysis failed: " + ServiceUtils.escapeJson(e.getMessage()) + "\"}";
        }
    }

    public String analyzeDataRegion(String startAddressStr, int maxScanBytes,
                                    boolean includeXrefMap, boolean includeAssemblyPatterns,
                                    boolean includeBoundaryDetection) {
        return analyzeDataRegion(startAddressStr, maxScanBytes, includeXrefMap, includeAssemblyPatterns, includeBoundaryDetection, null);
    }

    public String analyzeDataRegion(String startAddressStr, int maxScanBytes,
                                    boolean includeXrefMap, boolean includeAssemblyPatterns,
                                    boolean includeBoundaryDetection, String programName) {
        Object[] programResult = getProgramOrError(programName);
        Program program = (Program) programResult[0];
        if (program == null) return (String) programResult[1];

        try {
            Address startAddr = program.getAddressFactory().getAddress(startAddressStr);
            if (startAddr == null) {
                return "{\"error\": \"Invalid address: " + startAddressStr + "\"}";
            }

            ReferenceManager refMgr = program.getReferenceManager();
            Listing listing = program.getListing();

            // Scan byte-by-byte for xrefs and boundary detection
            Address currentAddr = startAddr;
            Address endAddr = startAddr;
            Set<String> uniqueXrefs = new HashSet<>();
            int byteCount = 0;
            StringBuilder xrefMapJson = new StringBuilder();
            xrefMapJson.append("\"xref_map\": {");
            boolean firstXrefEntry = true;

            for (int i = 0; i < maxScanBytes; i++) {
                Address scanAddr = startAddr.add(i);

                // Check for boundary: Named symbol that isn't DAT_
                Symbol[] symbols = program.getSymbolTable().getSymbols(scanAddr);
                if (includeBoundaryDetection && symbols.length > 0) {
                    for (Symbol sym : symbols) {
                        String name = sym.getName();
                        if (!name.startsWith("DAT_") && !name.equals(startAddr.toString())) {
                            // Found a named boundary
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
                    if (!firstXrefEntry) xrefMapJson.append(",");
                    firstXrefEntry = false;

                    xrefMapJson.append("\"").append(scanAddr.toString()).append("\": [");
                    for (int j = 0; j < refsAtThisByte.size(); j++) {
                        if (j > 0) xrefMapJson.append(",");
                        xrefMapJson.append("\"").append(refsAtThisByte.get(j)).append("\"");
                    }
                    xrefMapJson.append("]");
                }

                endAddr = scanAddr;
                byteCount = i + 1;
            }
            xrefMapJson.append("}");

            // Get current name and type
            Data data = listing.getDataAt(startAddr);
            String currentName = (data != null && data.getLabel() != null) ?
                                data.getLabel() : "DAT_" + startAddr.toString().replace(":", "");
            String currentType = (data != null) ?
                                data.getDataType().getName() : "undefined";

            // STRING DETECTION: Read memory content to check for strings
            boolean isLikelyString = false;
            String detectedString = null;
            int suggestedStringLength = 0;

            try {
                Memory memory = program.getMemory();
                byte[] bytes = new byte[Math.min(byteCount, 256)]; // Read up to 256 bytes
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

                // String detection criteria
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

            // Build final JSON response
            StringBuilder result = new StringBuilder();
            result.append("{");
            result.append("\"start_address\": \"").append(startAddr.toString()).append("\",");
            result.append("\"end_address\": \"").append(endAddr.toString()).append("\",");
            result.append("\"byte_span\": ").append(byteCount).append(",");

            if (includeXrefMap) {
                result.append(xrefMapJson.toString()).append(",");
            }

            result.append("\"unique_xref_addresses\": [");
            int idx = 0;
            for (String xref : uniqueXrefs) {
                if (idx++ > 0) result.append(",");
                result.append("\"").append(xref).append("\"");
            }
            result.append("],");

            result.append("\"xref_count\": ").append(uniqueXrefs.size()).append(",");
            result.append("\"classification_hint\": \"").append(classification).append("\",");
            result.append("\"stride_detected\": 1,");
            result.append("\"current_name\": \"").append(currentName).append("\",");
            result.append("\"current_type\": \"").append(currentType).append("\",");

            // Add string detection results
            result.append("\"is_likely_string\": ").append(isLikelyString).append(",");
            if (detectedString != null) {
                result.append("\"detected_string\": \"").append(ServiceUtils.escapeJson(detectedString)).append("\",");
                result.append("\"suggested_string_type\": \"char[").append(suggestedStringLength).append("]\"");
            } else {
                result.append("\"detected_string\": null,");
                result.append("\"suggested_string_type\": null");
            }

            result.append("}");

            return result.toString();
        } catch (Exception e) {
            return "{\"error\": \"" + ServiceUtils.escapeJson(e.getMessage()) + "\"}";
        }
    }

    /**
     * 3. DETECT_ARRAY_BOUNDS - Array/table size detection
     */
    public String detectArrayBounds(String addressStr, boolean analyzeLoopBounds,
                                    boolean analyzeIndexing, int maxScanRange) {
        return detectArrayBounds(addressStr, analyzeLoopBounds, analyzeIndexing, maxScanRange, null);
    }

    public String detectArrayBounds(String addressStr, boolean analyzeLoopBounds,
                                    boolean analyzeIndexing, int maxScanRange, String programName) {
        Object[] programResult = getProgramOrError(programName);
        Program program = (Program) programResult[0];
        if (program == null) return (String) programResult[1];

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            if (addr == null) {
                return "{\"error\": \"Invalid address: " + addressStr + "\"}";
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

            StringBuilder result = new StringBuilder();
            result.append("{");
            result.append("\"address\": \"").append(addr.toString()).append("\",");
            result.append("\"estimated_size\": ").append(estimatedSize).append(",");
            result.append("\"stride\": 1,");
            result.append("\"element_count\": ").append(estimatedSize).append(",");
            result.append("\"confidence\": \"medium\",");
            result.append("\"detection_method\": \"xref_analysis\"");
            result.append("}");

            return result.toString();
        } catch (Exception e) {
            return "{\"error\": \"" + ServiceUtils.escapeJson(e.getMessage()) + "\"}";
        }
    }

    /**
     * GET_FIELD_ACCESS_CONTEXT - Get assembly/decompilation context for specific field offsets
     */
    public String getFieldAccessContext(String structAddressStr, int fieldOffset, int numExamples) {
        return getFieldAccessContext(structAddressStr, fieldOffset, numExamples, null);
    }

    public String getFieldAccessContext(String structAddressStr, int fieldOffset, int numExamples, String programName) {
        // MAJOR FIX #7: Validate input parameters
        if (fieldOffset < 0 || fieldOffset > MAX_FIELD_OFFSET) {
            return "{\"error\": \"Field offset must be between 0 and " + MAX_FIELD_OFFSET + "\"}";
        }
        if (numExamples < 1 || numExamples > MAX_FIELD_EXAMPLES) {
            return "{\"error\": \"numExamples must be between 1 and " + MAX_FIELD_EXAMPLES + "\"}";
        }

        Object[] programResult = getProgramOrError(programName);
        Program resolvedProgram = (Program) programResult[0];
        if (resolvedProgram == null) return (String) programResult[1];

        final AtomicReference<String> result = new AtomicReference<>();

        // CRITICAL FIX #1: Thread safety - wrap in SwingUtilities.invokeAndWait
        try {
            SwingUtilities.invokeAndWait(() -> {
                try {
                    Program program = resolvedProgram;

                    Address structAddr = program.getAddressFactory().getAddress(structAddressStr);
                    if (structAddr == null) {
                        result.set("{\"error\": \"Invalid address: " + structAddressStr + "\"}");
                        return;
                    }

                    // Calculate field address with overflow protection
                    Address fieldAddr;
                    try {
                        fieldAddr = structAddr.add(fieldOffset);
                    } catch (Exception e) {
                        result.set("{\"error\": \"Field offset overflow: " + fieldOffset + "\"}");
                        return;
                    }

                    Msg.info(this, "Getting field access context for " + fieldAddr + " (offset " + fieldOffset + ")");

                    // Get xrefs to the field address (or nearby addresses)
                    ReferenceManager refMgr = program.getReferenceManager();
                    ReferenceIterator refIter = refMgr.getReferencesTo(fieldAddr);

                    StringBuilder json = new StringBuilder();
                    json.append("{");
                    json.append("\"struct_address\": \"").append(structAddressStr).append("\",");
                    json.append("\"field_offset\": ").append(fieldOffset).append(",");
                    json.append("\"field_address\": \"").append(fieldAddr.toString()).append("\",");
                    json.append("\"examples\": [");

                    int exampleCount = 0;
                    boolean first = true;

                    while (refIter.hasNext() && exampleCount < numExamples) {
                        Reference ref = refIter.next();
                        Address fromAddr = ref.getFromAddress();

                        if (!first) json.append(",");
                        first = false;

                        json.append("{");
                        json.append("\"access_address\": \"").append(fromAddr.toString()).append("\",");
                        json.append("\"ref_type\": \"").append(ref.getReferenceType().getName()).append("\",");

                        // Get assembly context with null check
                        Listing listing = program.getListing();
                        Instruction instr = listing.getInstructionAt(fromAddr);
                        if (instr != null) {
                            json.append("\"assembly\": \"").append(ServiceUtils.escapeJson(instr.toString())).append("\",");
                        } else {
                            json.append("\"assembly\": \"\",");
                        }

                        // Get function context with null check
                        Function func = program.getFunctionManager().getFunctionContaining(fromAddr);
                        if (func != null) {
                            json.append("\"function_name\": \"").append(ServiceUtils.escapeJson(func.getName())).append("\",");
                            json.append("\"function_address\": \"").append(func.getEntryPoint().toString()).append("\"");
                        } else {
                            json.append("\"function_name\": \"\",");
                            json.append("\"function_address\": \"\"");
                        }

                        json.append("}");
                        exampleCount++;
                    }

                    json.append("]");
                    json.append("}");

                    Msg.info(this, "Found " + exampleCount + " field access examples");
                    result.set(json.toString());

                } catch (Exception e) {
                    Msg.error(this, "Error in getFieldAccessContext", e);
                    result.set("{\"error\": \"" + ServiceUtils.escapeJson(e.getMessage()) + "\"}");
                }
            });
        } catch (InvocationTargetException | InterruptedException e) {
            Msg.error(this, "Thread synchronization error in getFieldAccessContext", e);
            return "{\"error\": \"Thread synchronization error: " + ServiceUtils.escapeJson(e.getMessage()) + "\"}";
        }

        return result.get();
    }

    /**
     * 7. INSPECT_MEMORY_CONTENT - Memory content inspection with string detection
     */
    public String inspectMemoryContent(String addressStr, int length, boolean detectStrings) {
        return inspectMemoryContent(addressStr, length, detectStrings, null);
    }

    public String inspectMemoryContent(String addressStr, int length, boolean detectStrings, String programName) {
        Object[] programResult = getProgramOrError(programName);
        Program program = (Program) programResult[0];
        if (program == null) return (String) programResult[1];

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            if (addr == null) {
                return "{\"error\": \"Invalid address: " + addressStr + "\"}";
            }

            Memory memory = program.getMemory();
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

            // String detection criteria:
            // - At least 60% printable characters OR
            // - At least 4 consecutive printable chars followed by null terminator
            if (detectStrings) {
                likelyString = (printableRatio >= 0.6) ||
                              (maxConsecutivePrintable >= 4 && nullTerminatorIndex > 0);
            }

            // Detect potential string content
            String detectedString = null;
            int stringLength = 0;
            if (likelyString && nullTerminatorIndex > 0) {
                detectedString = new String(bytes, 0, nullTerminatorIndex, StandardCharsets.US_ASCII);
                stringLength = nullTerminatorIndex + 1; // Include null terminator
            } else if (likelyString && printableRatio >= 0.8) {
                // String without null terminator (might be fixed-length string)
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

            // Build JSON response
            StringBuilder result = new StringBuilder();
            result.append("{");
            result.append("\"address\": \"").append(addressStr).append("\",");
            result.append("\"bytes_read\": ").append(bytesRead).append(",");
            result.append("\"hex_dump\": \"").append(hexDump.toString().trim()).append("\",");
            result.append("\"ascii_repr\": \"").append(asciiRepr.toString().trim()).append("\",");
            result.append("\"printable_count\": ").append(printableCount).append(",");
            result.append("\"printable_ratio\": ").append(String.format("%.2f", printableRatio)).append(",");
            result.append("\"null_terminator_at\": ").append(nullTerminatorIndex).append(",");
            result.append("\"max_consecutive_printable\": ").append(maxConsecutivePrintable).append(",");
            result.append("\"is_likely_string\": ").append(likelyString).append(",");

            if (detectedString != null) {
                result.append("\"detected_string\": \"").append(ServiceUtils.escapeJson(detectedString)).append("\",");
                result.append("\"suggested_type\": \"char[").append(stringLength).append("]\",");
                result.append("\"string_length\": ").append(stringLength);
            } else {
                result.append("\"detected_string\": null,");
                result.append("\"suggested_type\": null,");
                result.append("\"string_length\": 0");
            }

            result.append("}");

            return result.toString();
        } catch (Exception e) {
            return "{\"error\": \"" + ServiceUtils.escapeJson(e.getMessage()) + "\"}";
        }
    }

    /**
     * Detect cryptographic constants in the binary (AES S-boxes, SHA constants, etc.)
     */
    public String detectCryptoConstants() {
        return detectCryptoConstants(null);
    }

    public String detectCryptoConstants(String programName) {
        Object[] programResult = getProgramOrError(programName);
        Program program = (Program) programResult[0];
        if (program == null) return (String) programResult[1];

        try {
            final StringBuilder result = new StringBuilder();
            result.append("[\n");

            // This is a placeholder implementation
            // Full implementation would search for known crypto constants like:
            // - AES S-boxes (0x63, 0x7c, 0x77, 0x7b, 0xf2, ...)
            // - SHA constants (0x67452301, 0xefcdab89, ...)
            // - DES constants, RC4 initialization vectors, etc.

            result.append("  {\"algorithm\": \"Crypto Detection\", \"status\": \"Not yet implemented\", ");
            result.append("\"note\": \"This endpoint requires advanced pattern matching against known crypto constants\"}\n");
            result.append("]");

            return result.toString();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Search for byte patterns with optional wildcards
     */
    public String searchBytePatterns(String pattern, String mask) {
        return searchBytePatterns(pattern, mask, null);
    }

    public String searchBytePatterns(String pattern, String mask, String programName) {
        Object[] programResult = getProgramOrError(programName);
        Program program = (Program) programResult[0];
        if (program == null) return (String) programResult[1];

        if (pattern == null || pattern.trim().isEmpty()) {
            return "Error: Pattern is required";
        }

        try {
            final StringBuilder result = new StringBuilder();
            result.append("[\n");

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
                    maskBytes[byteIndex] = 0; // Don't check this byte
                } else {
                    String hexByte = cleanPattern.substring(i, Math.min(i + 2, cleanPattern.length()));
                    patternBytes[byteIndex] = (byte) Integer.parseInt(hexByte, 16);
                    maskBytes[byteIndex] = (byte) 0xFF; // Check this byte
                }
                byteIndex++;
            }

            // Search memory for pattern
            Memory memory = program.getMemory();
            int matchCount = 0;
            final int MAX_MATCHES = 1000; // Limit results

            for (MemoryBlock block : memory.getBlocks()) {
                if (!block.isInitialized()) continue;

                Address blockStart = block.getStart();
                long blockSize = block.getSize();

                // Read block data
                byte[] blockData = new byte[(int) Math.min(blockSize, Integer.MAX_VALUE)];
                try {
                    block.getBytes(blockStart, blockData);
                } catch (Exception e) {
                    continue; // Skip blocks we can't read
                }

                // Search for pattern in block
                for (int i = 0; i <= blockData.length - patternBytes.length; i++) {
                    boolean match = true;
                    for (int j = 0; j < patternBytes.length; j++) {
                        if (maskBytes[j] != 0 && blockData[i + j] != patternBytes[j]) {
                            match = false;
                            break;
                        }
                    }

                    if (match) {
                        if (matchCount > 0) result.append(",\n");
                        Address matchAddr = blockStart.add(i);
                        result.append("  {\"address\": \"").append(matchAddr).append("\"}");
                        matchCount++;

                        if (matchCount >= MAX_MATCHES) {
                            result.append(",\n  {\"note\": \"Limited to ").append(MAX_MATCHES).append(" matches\"}");
                            break;
                        }
                    }
                }

                if (matchCount >= MAX_MATCHES) break;
            }

            if (matchCount == 0) {
                result.append("  {\"note\": \"No matches found\"}");
            }

            result.append("\n]");
            return result.toString();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Find functions structurally similar to the target function
     * Uses basic block count, instruction count, call count, and cyclomatic complexity
     */
    public String findSimilarFunctions(String targetFunction, double threshold) {
        return findSimilarFunctions(targetFunction, threshold, null);
    }

    public String findSimilarFunctions(String targetFunction, double threshold, String programName) {
        Object[] programResult = getProgramOrError(programName);
        Program program = (Program) programResult[0];
        if (program == null) return (String) programResult[1];

        if (targetFunction == null || targetFunction.trim().isEmpty()) {
            return "Error: Target function name is required";
        }

        try {
            FunctionManager functionManager = program.getFunctionManager();
            Function targetFunc = null;

            // Find the target function
            for (Function f : functionManager.getFunctions(true)) {
                if (f.getName().equals(targetFunction)) {
                    targetFunc = f;
                    break;
                }
            }

            if (targetFunc == null) {
                return "{\"error\": \"Function not found: " + ServiceUtils.escapeJson(targetFunction) + "\"}";
            }

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
                    Map<String, Object> match = new LinkedHashMap<>();
                    match.put("name", func.getName());
                    match.put("address", func.getEntryPoint().toString());
                    match.put("similarity", Math.round(similarity * 1000.0) / 1000.0);
                    match.put("basic_blocks", funcMetrics.basicBlockCount);
                    match.put("instructions", funcMetrics.instructionCount);
                    match.put("calls", funcMetrics.callCount);
                    match.put("complexity", funcMetrics.cyclomaticComplexity);
                    similarFunctions.add(match);
                }
            }

            // Sort by similarity descending
            similarFunctions.sort((a, b) -> Double.compare((Double)b.get("similarity"), (Double)a.get("similarity")));

            // Limit results
            if (similarFunctions.size() > 50) {
                similarFunctions = similarFunctions.subList(0, 50);
            }

            // Build JSON response
            StringBuilder result = new StringBuilder();
            result.append("{\n");
            result.append("  \"target_function\": \"").append(ServiceUtils.escapeJson(targetFunction)).append("\",\n");
            result.append("  \"target_metrics\": {\n");
            result.append("    \"basic_blocks\": ").append(targetMetrics.basicBlockCount).append(",\n");
            result.append("    \"instructions\": ").append(targetMetrics.instructionCount).append(",\n");
            result.append("    \"calls\": ").append(targetMetrics.callCount).append(",\n");
            result.append("    \"complexity\": ").append(targetMetrics.cyclomaticComplexity).append("\n");
            result.append("  },\n");
            result.append("  \"threshold\": ").append(threshold).append(",\n");
            result.append("  \"matches_found\": ").append(similarFunctions.size()).append(",\n");
            result.append("  \"similar_functions\": [\n");

            for (int i = 0; i < similarFunctions.size(); i++) {
                Map<String, Object> match = similarFunctions.get(i);
                result.append("    {");
                result.append("\"name\": \"").append(ServiceUtils.escapeJson((String)match.get("name"))).append("\", ");
                result.append("\"address\": \"").append(match.get("address")).append("\", ");
                result.append("\"similarity\": ").append(match.get("similarity")).append(", ");
                result.append("\"basic_blocks\": ").append(match.get("basic_blocks")).append(", ");
                result.append("\"instructions\": ").append(match.get("instructions")).append(", ");
                result.append("\"calls\": ").append(match.get("calls")).append(", ");
                result.append("\"complexity\": ").append(match.get("complexity"));
                result.append("}");
                if (i < similarFunctions.size() - 1) result.append(",");
                result.append("\n");
            }

            result.append("  ]\n");
            result.append("}");

            return result.toString();
        } catch (Exception e) {
            return "{\"error\": \"" + ServiceUtils.escapeJson(e.getMessage()) + "\"}";
        }
    }

    /**
     * Analyze function control flow complexity
     * Calculates cyclomatic complexity, basic blocks, edges, and detailed metrics
     */
    public String analyzeControlFlow(String functionName) {
        return analyzeControlFlow(functionName, null);
    }

    public String analyzeControlFlow(String functionName, String programName) {
        Object[] programResult = getProgramOrError(programName);
        Program program = (Program) programResult[0];
        if (program == null) return (String) programResult[1];

        if (functionName == null || functionName.trim().isEmpty()) {
            return "{\"error\": \"Function name is required\"}";
        }

        try {
            FunctionManager functionManager = program.getFunctionManager();
            Function func = null;

            // Find the function by name
            for (Function f : functionManager.getFunctions(true)) {
                if (f.getName().equals(functionName)) {
                    func = f;
                    break;
                }
            }

            if (func == null) {
                return "{\"error\": \"Function not found: " + ServiceUtils.escapeJson(functionName) + "\"}";
            }

            BasicBlockModel blockModel = new BasicBlockModel(program);
            Listing listing = program.getListing();
            ReferenceManager refManager = program.getReferenceManager();

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
                blockInfo.put("address", block.getFirstStartAddress().toString());
                blockInfo.put("size", block.getNumAddresses());

                // Count edges and detect loops
                int outEdges = 0;
                boolean hasBackEdge = false;
                List<String> successors = new ArrayList<>();

                CodeBlockReferenceIterator destIter = block.getDestinations(TaskMonitor.DUMMY);
                while (destIter.hasNext()) {
                    CodeBlockReference ref = destIter.next();
                    outEdges++;
                    edgeCount++;
                    Address destAddr = ref.getDestinationAddress();
                    successors.add(destAddr.toString());

                    // Detect back edges (loops) - destination is before current block
                    if (destAddr.compareTo(block.getFirstStartAddress()) < 0 &&
                        blockEntries.contains(destAddr)) {
                        hasBackEdge = true;
                    }
                }

                if (hasBackEdge) loops++;
                blockInfo.put("successors", successors.size());
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
                    if (instr.getFlowType().isConditional()) {
                        // Already counted above
                    } else {
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

            // Build JSON response
            StringBuilder result = new StringBuilder();
            result.append("{\n");
            result.append("  \"function_name\": \"").append(ServiceUtils.escapeJson(functionName)).append("\",\n");
            result.append("  \"entry_point\": \"").append(func.getEntryPoint().toString()).append("\",\n");
            result.append("  \"size_bytes\": ").append(func.getBody().getNumAddresses()).append(",\n");
            result.append("  \"metrics\": {\n");
            result.append("    \"cyclomatic_complexity\": ").append(cyclomaticComplexity).append(",\n");
            result.append("    \"complexity_rating\": \"").append(complexityRating).append("\",\n");
            result.append("    \"basic_blocks\": ").append(basicBlockCount).append(",\n");
            result.append("    \"edges\": ").append(edgeCount).append(",\n");
            result.append("    \"instructions\": ").append(instructionCount).append(",\n");
            result.append("    \"conditional_branches\": ").append(conditionalBranches).append(",\n");
            result.append("    \"unconditional_jumps\": ").append(unconditionalJumps).append(",\n");
            result.append("    \"loops_detected\": ").append(loops).append(",\n");
            result.append("    \"calls\": ").append(callCount).append(",\n");
            result.append("    \"returns\": ").append(returnCount).append("\n");
            result.append("  },\n");
            result.append("  \"basic_block_details\": [\n");

            for (int i = 0; i < Math.min(blocks.size(), 100); i++) {
                Map<String, Object> block = blocks.get(i);
                result.append("    {");
                result.append("\"address\": \"").append(block.get("address")).append("\", ");
                result.append("\"size\": ").append(block.get("size")).append(", ");
                result.append("\"type\": \"").append(block.get("type")).append("\", ");
                result.append("\"successors\": ").append(block.get("successors")).append(", ");
                result.append("\"is_loop_header\": ").append(block.get("is_loop_header"));
                result.append("}");
                if (i < Math.min(blocks.size(), 100) - 1) result.append(",");
                result.append("\n");
            }

            if (blocks.size() > 100) {
                result.append("    {\"note\": \"").append(blocks.size() - 100).append(" additional blocks truncated\"}\n");
            }

            result.append("  ]\n");
            result.append("}");

            return result.toString();
        } catch (Exception e) {
            return "{\"error\": \"" + ServiceUtils.escapeJson(e.getMessage()) + "\"}";
        }
    }

    /**
     * Find potentially unreachable code blocks
     */
    public String findDeadCode(String functionName) {
        return findDeadCode(functionName, null);
    }

    public String findDeadCode(String functionName, String programName) {
        Object[] programResult = getProgramOrError(programName);
        Program program = (Program) programResult[0];
        if (program == null) return (String) programResult[1];

        if (functionName == null || functionName.trim().isEmpty()) {
            return "Error: Function name is required";
        }

        try {
            final StringBuilder result = new StringBuilder();
            result.append("[\n");

            // Placeholder implementation
            // Full implementation would analyze control flow to find unreachable blocks

            result.append("  {\"function_name\": \"").append(ServiceUtils.escapeJson(functionName)).append("\", ");
            result.append("\"status\": \"Not yet implemented\", ");
            result.append("\"note\": \"This endpoint requires reachability analysis via control flow graph\"}\n");
            result.append("]");

            return result.toString();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Analyze function documentation completeness
     */
    public String analyzeFunctionCompleteness(String functionAddress) {
        return analyzeFunctionCompleteness(functionAddress, false, null);
    }

    public String analyzeFunctionCompleteness(String functionAddress, boolean compact) {
        return analyzeFunctionCompleteness(functionAddress, compact, null);
    }

    /**
     * Analyze function documentation completeness.
     * @param compact When true, returns only scores and issue counts (no arrays, no recommendations).
     *                Reduces response from ~20KB to ~300 bytes.
     */
    public String analyzeFunctionCompleteness(String functionAddress, boolean compact, String programName) {
        Object[] programResult = getProgramOrError(programName);
        Program program = (Program) programResult[0];
        if (program == null) return (String) programResult[1];

        final StringBuilder result = new StringBuilder();
        final AtomicReference<String> errorMsg = new AtomicReference<>(null);

        try {
            SwingUtilities.invokeAndWait(() -> {
                try {
                    Address addr = program.getAddressFactory().getAddress(functionAddress);
                    if (addr == null) {
                        errorMsg.set("Invalid address: " + functionAddress);
                        return;
                    }

                    Function func = program.getFunctionManager().getFunctionAt(addr);
                    if (func == null) {
                        errorMsg.set("No function at address: " + functionAddress);
                        return;
                    }

                    // Classify function using shared utility
                    String classification = classifyFunction(func, program);
                    boolean isThunk = "thunk".equals(classification);

                    result.append("{");
                    result.append("\"function_name\": \"").append(func.getName()).append("\", ");
                    result.append("\"classification\": \"").append(classification).append("\", ");
                    result.append("\"is_thunk\": ").append(isThunk).append(", ");
                    result.append("\"has_custom_name\": ").append(!ServiceUtils.isAutoGeneratedName(func.getName())).append(", ");
                    result.append("\"has_prototype\": ").append(func.getSignature() != null).append(", ");
                    result.append("\"has_calling_convention\": ").append(func.getCallingConvention() != null).append(", ");

                    // v3.0.1: Check if return type is unresolved (undefined)
                    String returnTypeName = func.getReturnType().getName();
                    boolean returnTypeUndefined = returnTypeName.startsWith("undefined");
                    result.append("\"return_type\": \"").append(ServiceUtils.escapeJson(returnTypeName)).append("\", ");
                    result.append("\"return_type_resolved\": ").append(!returnTypeUndefined).append(", ");

                    // Enhanced plate comment validation
                    String plateComment = func.getComment();
                    boolean hasPlateComment = plateComment != null && !plateComment.isEmpty();
                    result.append("\"has_plate_comment\": ").append(hasPlateComment).append(", ");

                    // Validate plate comment structure and content
                    List<String> plateCommentIssues = new ArrayList<>();
                    if (hasPlateComment) {
                        validatePlateCommentStructure(plateComment, plateCommentIssues, isThunk);
                    }

                    if (compact) {
                        result.append("\"plate_issues\": ").append(plateCommentIssues.size()).append(", ");
                    } else {
                        result.append("\"plate_comment_issues\": [");
                        for (int i = 0; i < plateCommentIssues.size(); i++) {
                            if (i > 0) result.append(", ");
                            result.append("\"").append(ServiceUtils.escapeJson(plateCommentIssues.get(i))).append("\"");
                        }
                        result.append("], ");
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

                    result.append("\"decompilation_available\": ").append(decompilationAvailable).append(", ");

                    if (compact) {
                        result.append("\"undefined_count\": ").append(undefinedVars.size()).append(", ");
                        result.append("\"phantom_count\": ").append(phantomVars.size()).append(", ");
                    } else {
                        result.append("\"undefined_variables\": [");
                        for (int i = 0; i < undefinedVars.size(); i++) {
                            if (i > 0) result.append(", ");
                            result.append("\"").append(undefinedVars.get(i)).append("\"");
                        }
                        result.append("], ");

                        // v3.0.1: Report phantom variables separately (not counted in scoring)
                        result.append("\"phantom_variables\": [");
                        for (int i = 0; i < phantomVars.size(); i++) {
                            if (i > 0) result.append(", ");
                            result.append("\"").append(ServiceUtils.escapeJson(phantomVars.get(i))).append("\"");
                        }
                        result.append("], ");
                    }

                    // Check Hungarian notation compliance
                    // PRIORITY 1 FIX: Use same decompilation-based detection for consistency
                    // v3.2.0: Track unfixable Hungarian violations (register-only/thunk variables)
                    List<String> hungarianViolations = new ArrayList<>();
                    int unfixableHungarianCount = 0;
                    for (Parameter param : func.getParameters()) {
                        validateHungarianNotation(param.getName(), param.getDataType().getName(), false, true, hungarianViolations);
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
                    List<String> typeQualityIssues = new ArrayList<>();
                    validateParameterTypeQuality(func, typeQualityIssues);

                    if (compact) {
                        result.append("\"hungarian_violations\": ").append(hungarianViolations.size()).append(", ");
                        result.append("\"type_quality_issues\": ").append(typeQualityIssues.size()).append(", ");
                    } else {
                        result.append("\"hungarian_notation_violations\": [");
                        for (int i = 0; i < hungarianViolations.size(); i++) {
                            if (i > 0) result.append(", ");
                            result.append("\"").append(ServiceUtils.escapeJson(hungarianViolations.get(i))).append("\"");
                        }
                        result.append("], ");

                        result.append("\"type_quality_issues\": [");
                        for (int i = 0; i < typeQualityIssues.size(); i++) {
                            if (i > 0) result.append(", ");
                            result.append("\"").append(ServiceUtils.escapeJson(typeQualityIssues.get(i))).append("\"");
                        }
                        result.append("], ");
                    }

                    // NEW: Check for unrenamed DAT_* globals and undocumented Ordinal calls in decompiled code
                    List<String> unrenamedGlobals = new ArrayList<>();
                    List<String> undocumentedOrdinals = new ArrayList<>();
                    int inlineCommentCount = 0;
                    int codeLineCount = 0;

                    if (decompilationAvailable && decompResults != null) {
                        String decompiledCode = decompResults.getDecompiledFunction().getC();
                        if (decompiledCode != null) {
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

                    // Count disassembly EOL comments within function body
                    int disasmCommentCount = 0;
                    ghidra.program.model.listing.InstructionIterator disasmIter =
                        program.getListing().getInstructions(func.getBody(), true);
                    while (disasmIter.hasNext()) {
                        ghidra.program.model.listing.Instruction instr = disasmIter.next();
                        String eolComment = program.getListing().getComment(
                            ghidra.program.model.listing.CodeUnit.EOL_COMMENT, instr.getAddress());
                        if (eolComment != null && !eolComment.isEmpty()) {
                            disasmCommentCount++;
                        }
                    }
                    // Include disassembly comments in total for density calculation
                    int totalCommentCount = inlineCommentCount + disasmCommentCount;

                    if (compact) {
                        result.append("\"globals_unrenamed\": ").append(unrenamedGlobals.size()).append(", ");
                        result.append("\"ordinals_undocumented\": ").append(undocumentedOrdinals.size()).append(", ");
                    } else {
                        result.append("\"unrenamed_globals\": [");
                        for (int i = 0; i < unrenamedGlobals.size(); i++) {
                            if (i > 0) result.append(", ");
                            result.append("\"").append(ServiceUtils.escapeJson(unrenamedGlobals.get(i))).append("\"");
                        }
                        result.append("], ");

                        result.append("\"undocumented_ordinals\": [");
                        for (int i = 0; i < undocumentedOrdinals.size(); i++) {
                            if (i > 0) result.append(", ");
                            result.append("\"").append(ServiceUtils.escapeJson(undocumentedOrdinals.get(i))).append("\"");
                        }
                        result.append("], ");
                    }

                    result.append("\"inline_comment_count\": ").append(inlineCommentCount).append(", ");
                    result.append("\"disasm_comment_count\": ").append(disasmCommentCount).append(", ");
                    result.append("\"code_line_count\": ").append(codeLineCount).append(", ");

                    // Calculate comment density using total comments (decompiler + disassembly)
                    double commentDensity = codeLineCount > 0 ? (totalCommentCount * 10.0 / codeLineCount) : 0;
                    result.append("\"comment_density\": ").append(String.format("%.2f", commentDensity)).append(", ");

                    CompletenessScoreResult scoreResult = calculateCompletenessScore(func, undefinedVars.size(), plateCommentIssues.size(), hungarianViolations.size(), typeQualityIssues.size(), unrenamedGlobals.size(), undocumentedOrdinals.size(), commentDensity, typeQualityIssues, phantomVars.size(), codeLineCount, unfixableUndefinedCount, unfixableHungarianCount, isThunk);
                    result.append("\"completeness_score\": ").append(scoreResult.score).append(", ");
                    result.append("\"effective_score\": ").append(scoreResult.effectiveScore).append(", ");
                    result.append("\"all_deductions_unfixable\": ").append(scoreResult.score < 100.0 && scoreResult.effectiveScore >= 100.0).append(", ");

                    // PROP-0002: Report whether function has renameable variables (not register-only SSA)
                    if (compact) {
                        // In compact mode, this is the last field — no trailing comma
                        result.append("\"has_renameable_variables\": ").append(!localVarNames.isEmpty());
                    } else {
                        result.append("\"has_renameable_variables\": ").append(!localVarNames.isEmpty()).append(", ");
                    }

                    if (!compact) {
                        // Generate workflow-aligned recommendations (skipped in compact mode — AI has these in its prompt)
                        List<String> recommendations = generateWorkflowRecommendations(
                            func, undefinedVars, plateCommentIssues, hungarianViolations, typeQualityIssues,
                            unrenamedGlobals, undocumentedOrdinals, commentDensity, scoreResult, codeLineCount, isThunk
                        );

                        result.append("\"recommendations\": [");
                        for (int i = 0; i < recommendations.size(); i++) {
                            if (i > 0) result.append(", ");
                            result.append("\"").append(ServiceUtils.escapeJson(recommendations.get(i))).append("\"");
                        }
                        result.append("]");
                    }

                    result.append("}");
                } catch (Exception e) {
                    errorMsg.set(e.getMessage());
                }
            });

            if (errorMsg.get() != null) {
                return "{\"error\": \"" + errorMsg.get().replace("\"", "\\\"") + "\"}";
            }
        } catch (Exception e) {
            return "{\"error\": \"" + e.getMessage().replace("\"", "\\\"") + "\"}";
        }

        return result.toString();
    }

    /**
     * v1.5.0: Find next undefined function needing analysis
     */
    @SuppressWarnings("deprecation")
    public String findNextUndefinedFunction(String startAddress, String criteria,
                                            String pattern, String direction, String programName) {
        Object[] programResult = getProgramOrError(programName);
        Program program = (Program) programResult[0];
        if (program == null) {
            return "{\"error\": \"" + ServiceUtils.escapeJson((String) programResult[1]) + "\"}";
        }

        final Program finalProgram = program;
        final StringBuilder result = new StringBuilder();
        final AtomicReference<String> errorMsg = new AtomicReference<>(null);

        try {
            SwingUtilities.invokeAndWait(() -> {
                try {
                    FunctionManager funcMgr = finalProgram.getFunctionManager();
                    Address start = startAddress != null ?
                        finalProgram.getAddressFactory().getAddress(startAddress) :
                        finalProgram.getMinAddress();

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
                        result.append("{");
                        result.append("\"found\": true, ");
                        result.append("\"function_name\": \"").append(found.getName()).append("\", ");
                        result.append("\"function_address\": \"").append(found.getEntryPoint().toString()).append("\", ");
                        result.append("\"xref_count\": ").append(found.getSymbol().getReferenceCount());
                        result.append("}");
                    } else {
                        result.append("{\"found\": false}");
                    }
                } catch (Exception e) {
                    errorMsg.set(e.getMessage());
                }
            });

            if (errorMsg.get() != null) {
                return "{\"error\": \"" + errorMsg.get().replace("\"", "\\\"") + "\"}";
            }
        } catch (Exception e) {
            return "{\"error\": \"" + e.getMessage().replace("\"", "\\\"") + "\"}";
        }

        return result.toString();
    }

    // Backward compatibility overload
    public String findNextUndefinedFunction(String startAddress, String criteria,
                                            String pattern, String direction) {
        return findNextUndefinedFunction(startAddress, criteria, pattern, direction, null);
    }

    /**
     * Comprehensive function analysis combining decompilation, xrefs, callees, callers, disassembly, and variables
     */
    public String analyzeFunctionComplete(String name, boolean includeXrefs, boolean includeCallees,
                                          boolean includeCallers, boolean includeDisasm, boolean includeVariables,
                                          String programName) {
        Object[] programResult = getProgramOrError(programName);
        Program program = (Program) programResult[0];
        if (program == null) {
            return "{\"error\": \"" + ServiceUtils.escapeJson((String) programResult[1]) + "\"}";
        }

        final Program finalProgram = program;

        final StringBuilder result = new StringBuilder();
        final AtomicReference<String> errorMsg = new AtomicReference<>(null);

        try {
            SwingUtilities.invokeAndWait(() -> {
                try {
                    Function func = null;
                    FunctionManager funcMgr = finalProgram.getFunctionManager();

                    // Find function by name
                    for (Function f : funcMgr.getFunctions(true)) {
                        if (f.getName().equals(name)) {
                            func = f;
                            break;
                        }
                    }

                    if (func == null) {
                        result.append("{\"error\": \"Function not found: ").append(name).append("\"}");
                        return;
                    }

                    result.append("{");
                    result.append("\"name\": \"").append(func.getName()).append("\", ");
                    result.append("\"address\": \"").append(func.getEntryPoint().toString()).append("\", ");
                    result.append("\"classification\": \"").append(classifyFunction(func, finalProgram)).append("\", ");
                    result.append("\"signature\": \"").append(func.getSignature().toString().replace("\"", "\\\"")).append("\"");

                    // v3.0.1: Flag undefined return type
                    String retTypeName = func.getReturnType().getName();
                    if (retTypeName.startsWith("undefined")) {
                        result.append(", \"return_type_resolved\": false");
                        result.append(", \"return_type_warning\": \"Return type is '").append(ServiceUtils.escapeJson(retTypeName))
                              .append("' — verify EAX at RET. Do not trust decompiler void display.\"");
                    } else {
                        result.append(", \"return_type_resolved\": true");
                    }

                    // v3.0.1: Include decompiled code (previously only in headless version)
                    DecompileResults decompResults = functionService.decompileFunction(func, finalProgram);
                    if (decompResults != null && decompResults.decompileCompleted() &&
                        decompResults.getDecompiledFunction() != null) {
                        String decompiledCode = decompResults.getDecompiledFunction().getC();
                        if (decompiledCode != null) {
                            result.append(", \"decompiled_code\": \"").append(ServiceUtils.escapeJson(decompiledCode)).append("\"");
                        }
                    }

                    // Include xrefs
                    if (includeXrefs) {
                        result.append(", \"xrefs\": [");
                        ReferenceIterator refs = finalProgram.getReferenceManager().getReferencesTo(func.getEntryPoint());
                        int refCount = 0;
                        while (refs.hasNext() && refCount < 100) {
                            Reference ref = refs.next();
                            if (refCount > 0) result.append(", ");
                            result.append("{\"from\": \"").append(ref.getFromAddress().toString()).append("\"}");
                            refCount++;
                        }
                        result.append("], \"xref_count\": ").append(refCount);
                    }

                    // Include callees
                    if (includeCallees) {
                        result.append(", \"callees\": [");
                        Set<Function> calledFuncs = func.getCalledFunctions(null);
                        int calleeCount = 0;
                        for (Function called : calledFuncs) {
                            if (calleeCount > 0) result.append(", ");
                            result.append("\"").append(called.getName()).append("\"");
                            calleeCount++;
                        }
                        result.append("]");

                        // v3.0.1: Wrapper return propagation hint
                        // If function has exactly 1 callee and <=15 instructions, check callee return type
                        if (calleeCount == 1 && retTypeName.startsWith("undefined")) {
                            Function callee = calledFuncs.iterator().next();
                            String calleeRetType = callee.getReturnType().getName();
                            if (!calleeRetType.equals("void") && !calleeRetType.startsWith("undefined")) {
                                // Count instructions to confirm wrapper pattern
                                Listing tmpListing = finalProgram.getListing();
                                InstructionIterator tmpIter = tmpListing.getInstructions(func.getBody(), true);
                                int instrTotal = 0;
                                while (tmpIter.hasNext()) { tmpIter.next(); instrTotal++; }
                                if (instrTotal <= 15) {
                                    result.append(", \"wrapper_hint\": \"Callee '").append(ServiceUtils.escapeJson(callee.getName()))
                                          .append("' returns ").append(ServiceUtils.escapeJson(calleeRetType))
                                          .append(". This wrapper likely returns the same type — verify EAX is not clobbered before RET.\"");
                                }
                            }
                        }
                    }

                    // Include callers
                    if (includeCallers) {
                        result.append(", \"callers\": [");
                        Set<Function> callingFuncs = func.getCallingFunctions(null);
                        int callerCount = 0;
                        for (Function caller : callingFuncs) {
                            if (callerCount > 0) result.append(", ");
                            result.append("\"").append(caller.getName()).append("\"");
                            callerCount++;
                        }
                        result.append("]");
                    }

                    // Include disassembly
                    if (includeDisasm) {
                        result.append(", \"disassembly\": [");
                        Listing listing = finalProgram.getListing();
                        AddressSetView body = func.getBody();
                        InstructionIterator instrIter = listing.getInstructions(body, true);
                        int instrCount = 0;
                        while (instrIter.hasNext() && instrCount < 100) {
                            Instruction instr = instrIter.next();
                            if (instrCount > 0) result.append(", ");
                            result.append("{\"address\": \"").append(instr.getAddress().toString()).append("\", ");
                            result.append("\"mnemonic\": \"").append(instr.getMnemonicString()).append("\"}");
                            instrCount++;
                        }
                        result.append("]");
                    }

                    // Include variables (v3.0.1: use HighFunction for locals to capture register-based vars)
                    if (includeVariables) {
                        result.append(", \"parameters\": [");
                        Parameter[] params = func.getParameters();
                        for (int i = 0; i < params.length; i++) {
                            if (i > 0) result.append(", ");
                            result.append("{\"name\": \"").append(ServiceUtils.escapeJson(params[i].getName())).append("\", ");
                            result.append("\"type\": \"").append(ServiceUtils.escapeJson(params[i].getDataType().getName())).append("\", ");
                            result.append("\"storage\": \"").append(ServiceUtils.escapeJson(params[i].getVariableStorage().toString())).append("\"}");
                        }
                        result.append("], \"locals\": [");

                        // Use HighFunction symbol map for locals (captures register-based and SSA variables)
                        boolean firstLocal = true;
                        if (decompResults != null && decompResults.decompileCompleted()) {
                            ghidra.program.model.pcode.HighFunction highFunc = decompResults.getHighFunction();
                            if (highFunc != null) {
                                java.util.Iterator<ghidra.program.model.pcode.HighSymbol> symbols =
                                    highFunc.getLocalSymbolMap().getSymbols();
                                while (symbols.hasNext()) {
                                    ghidra.program.model.pcode.HighSymbol sym = symbols.next();
                                    if (!firstLocal) result.append(", ");
                                    firstLocal = false;
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
                                    result.append("{\"name\": \"").append(ServiceUtils.escapeJson(symName)).append("\", ");
                                    result.append("\"type\": \"").append(ServiceUtils.escapeJson(sym.getDataType().getName())).append("\", ");
                                    result.append("\"storage\": \"").append(ServiceUtils.escapeJson(storageStr)).append("\", ");
                                    result.append("\"is_phantom\": ").append(isPhantom).append(", ");
                                    result.append("\"in_decompiled_code\": true}");
                                }
                            }
                        }

                        // Fallback: if decompilation unavailable, use low-level API
                        if (decompResults == null || !decompResults.decompileCompleted()) {
                            Variable[] locals = func.getLocalVariables();
                            for (int i = 0; i < locals.length; i++) {
                                if (!firstLocal) result.append(", ");
                                firstLocal = false;
                                result.append("{\"name\": \"").append(ServiceUtils.escapeJson(locals[i].getName())).append("\", ");
                                result.append("\"type\": \"").append(ServiceUtils.escapeJson(locals[i].getDataType().getName())).append("\", ");
                                result.append("\"storage\": \"").append(ServiceUtils.escapeJson(locals[i].getVariableStorage().toString())).append("\", ");
                                result.append("\"is_phantom\": false, ");
                                result.append("\"in_decompiled_code\": false}");
                            }
                        }
                        result.append("]");
                    }

                    result.append("}");
                } catch (Exception e) {
                    errorMsg.set(e.getMessage());
                }
            });

            if (errorMsg.get() != null) {
                return "{\"error\": \"" + errorMsg.get().replace("\"", "\\\"") + "\"}";
            }
        } catch (Exception e) {
            return "{\"error\": \"" + e.getMessage().replace("\"", "\\\"") + "\"}";
        }

        return result.toString();
    }

    // Backward compatibility overload
    public String analyzeFunctionComplete(String name, boolean includeXrefs, boolean includeCallees,
                                          boolean includeCallers, boolean includeDisasm, boolean includeVariables) {
        return analyzeFunctionComplete(name, includeXrefs, includeCallees, includeCallers, includeDisasm, includeVariables, null);
    }

    /**
     * NEW v1.6.0: Enhanced function search with filtering and sorting
     */
    public String searchFunctionsEnhanced(String namePattern, Integer minXrefs, Integer maxXrefs,
                                          String callingConvention, Boolean hasCustomName, boolean regex,
                                          String sortBy, int offset, int limit, String programName) {
        Object[] programResult = getProgramOrError(programName);
        Program program = (Program) programResult[0];
        if (program == null) {
            return "{\"error\": \"" + ServiceUtils.escapeJson((String) programResult[1]) + "\"}";
        }

        final StringBuilder result = new StringBuilder();
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
                            result.append("{\"error\": \"Invalid regex pattern: ").append(e.getMessage()).append("\"}");
                            return;
                        }
                    }

                    FunctionManager funcMgr = program.getFunctionManager();
                    ReferenceManager refMgr = program.getReferenceManager();

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
                        Map<String, Object> match = new HashMap<>();
                        match.put("name", func.getName());
                        match.put("address", func.getEntryPoint().toString());
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

                    // Build JSON result
                    result.append("{\"total\": ").append(total).append(", ");
                    result.append("\"offset\": ").append(offset).append(", ");
                    result.append("\"limit\": ").append(limit).append(", ");
                    result.append("\"results\": [");

                    for (int i = 0; i < page.size(); i++) {
                        if (i > 0) result.append(", ");
                        Map<String, Object> match = page.get(i);
                        result.append("{\"name\": \"").append(match.get("name")).append("\", ");
                        result.append("\"address\": \"").append(match.get("address")).append("\", ");
                        result.append("\"xref_count\": ").append(match.get("xref_count")).append("}");
                    }

                    result.append("]}");

                } catch (Exception e) {
                    errorMsg.set(e.getMessage());
                }
            });

            if (errorMsg.get() != null) {
                return "{\"error\": \"" + errorMsg.get().replace("\"", "\\\"") + "\"}";
            }
        } catch (Exception e) {
            return "{\"error\": \"" + e.getMessage().replace("\"", "\\\"") + "\"}";
        }

        return result.toString();
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

    private CompletenessScoreResult calculateCompletenessScore(Function func, int undefinedCount, int plateCommentIssueCount, int hungarianViolationCount, int typeQualityIssueCount, int unrenamedGlobalsCount, int undocumentedOrdinalsCount, double commentDensity, List<String> typeQualityIssues, int phantomCount, int codeLineCount, int unfixableUndefinedCount, int unfixableHungarianCount, boolean isThunk) {
        double score = 100.0;
        double unfixablePenalty = 0.0;

        if (ServiceUtils.isAutoGeneratedName(func.getName())) score -= 30;
        if (func.getSignature() == null) score -= 20;
        if (func.getCallingConvention() == null) score -= 10;
        if (func.getComment() == null) score -= 20;
        // v3.0.1: Penalize undefined return type (must be resolved to void, int, uint, etc.)
        if (func.getReturnType().getName().startsWith("undefined")) score -= 15;
        score -= (undefinedCount * 5);
        score -= (plateCommentIssueCount * 5);
        score -= (hungarianViolationCount * 3);
        score -= (typeQualityIssueCount * 15);

        score -= (unrenamedGlobalsCount * 3);
        score -= (undocumentedOrdinalsCount * 2);

        if (commentDensity < 1.0 && func.getComment() != null && codeLineCount > 10 && !isThunk) {
            score -= 5;
        }

        // Calculate unfixable penalty: void* on ordinal exports (params arrive as int, void*
        // is the best we can do without caller-side analysis), phantom vars,
        // register-only SSA variables, and thunk-owned callee variables
        boolean isExternalEntry = func.getProgram().getSymbolTable()
                .isExternalEntryPoint(func.getEntryPoint());
        for (String issue : typeQualityIssues) {
            if (issue.contains("Generic void*") && (isExternalEntry || isThunk)) {
                unfixablePenalty += 15;
            }
        }
        // Register-only SSA variables (not in func.getLocalVariables()) cannot be renamed
        // or retyped via Ghidra's API -- each deduction is 5 points
        unfixablePenalty += (unfixableUndefinedCount * 5);
        // v3.2.0: Hungarian violations on register-only/thunk variables are also unfixable
        unfixablePenalty += (unfixableHungarianCount * 3);

        double rawScore = Math.max(0, score);
        double effectiveScore = Math.min(100.0, rawScore + unfixablePenalty);

        return new CompletenessScoreResult(rawScore, effectiveScore, (int) unfixablePenalty);
    }

    /**
     * Generate workflow-aligned recommendations based on FUNCTION_DOC_WORKFLOW_V5.md
     */
    private List<String> generateWorkflowRecommendations(
            Function func,
            List<String> undefinedVars,
            List<String> plateCommentIssues,
            List<String> hungarianViolations,
            List<String> typeQualityIssues,
            List<String> unrenamedGlobals,
            List<String> undocumentedOrdinals,
            double commentDensity,
            CompletenessScoreResult scoreResult,
            int codeLineCount,
            boolean isThunk) {

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

        // CRITICAL: Undocumented Ordinal Calls
        if (!undocumentedOrdinals.isEmpty()) {
            recommendations.add("UNDOCUMENTED ORDINAL CALLS - Add inline comments for each:");
            recommendations.add("1. Found " + undocumentedOrdinals.size() + " Ordinal call(s) without comments: " + String.join(", ", undocumentedOrdinals.subList(0, Math.min(5, undocumentedOrdinals.size()))));
            recommendations.add("2. Consult docs/KNOWN_ORDINALS.md for Ordinal mappings (Storm.dll, Fog.dll ordinals documented)");
            recommendations.add("3. Use set_decompiler_comment() or batch_set_comments() to add inline comment explaining the call");
            recommendations.add("4. Format: /* Ordinal_123 = StorageFunctionName - brief description */");
        }

        // CRITICAL: Undefined Type Audit (FUNCTION_DOC_WORKFLOW_V5.md Step 3: Type Audit)
        if (!undefinedVars.isEmpty()) {
            recommendations.add("UNDEFINED TYPES DETECTED - Follow FUNCTION_DOC_WORKFLOW_V5.md Step 3 'Type Audit + Variable Renaming' section:");
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
            recommendations.add("PLATE COMMENT ISSUES - Follow FUNCTION_DOC_WORKFLOW_V5.md Step 6 'Plate Comment + Inline Comments' section:");
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
            recommendations.add("HUNGARIAN NOTATION VIOLATIONS - Follow FUNCTION_DOC_WORKFLOW_V5.md Step 3 'Type Audit + Variable Renaming' and docs/HUNGARIAN_NOTATION.md:");
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
            recommendations.add("TYPE QUALITY ISSUES - Follow FUNCTION_DOC_WORKFLOW_V5.md Step 4 'Structures' section:");
            for (String issue : typeQualityIssues) {
                if (issue.contains("Generic void*")) {
                    recommendations.add("1. Replace generic void* parameters with specific structure types using set_function_prototype()");
                    recommendations.add("   Example: void ProcessData(void* pData) -> void ProcessData(UnitAny* pUnit)");
                } else if (issue.contains("State-based type name")) {
                    recommendations.add("2. Rename state-based type names to identity-based names:");
                    recommendations.add("   BAD: InitializedGameObject, AllocatedBuffer, ProcessedData");
                    recommendations.add("   GOOD: GameObject, Buffer, DataRecord");
                    recommendations.add("   Use create_struct() with identity-based name, document legacy name in comments");
                } else if (issue.contains("Type duplication")) {
                    recommendations.add("3. Consolidate duplicate types - use identity-based version, delete state-based variant");
                }
            }
        }

        // Inline Comment Density Check (skip for small functions <= 10 code lines, and for thunks)
        if (commentDensity < 0.67 && codeLineCount > 10 && !isThunk) { // Less than 1 comment per 15 lines
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
        if (scoreResult.effectiveScore < 100.0) {
            recommendations.add("COMPLETE WORKFLOW (FUNCTION_DOC_WORKFLOW_V5.md):");
            recommendations.add("1. Initialize: get_current_selection() + analyze_function_complete() in parallel, classify function");
            recommendations.add("2. Rename + Prototype: rename_function_by_address() (PascalCase) + set_function_prototype() in parallel");
            recommendations.add("3. Type Audit + Variables: set_local_variable_type() then rename_variables() with Hungarian notation");
            recommendations.add("4. Structures: search_data_types() or create_struct() if field-offset patterns found (skip if none)");
            recommendations.add("5. Globals: rename_or_label() with g_ prefix for DAT_*/s_* references (skip if none)");
            recommendations.add("6. Comments: batch_set_comments() with plate_comment + PRE_COMMENTs + EOL_COMMENTs in ONE call");
            recommendations.add("7. Verify: analyze_function_completeness() once -- accept phantom/void* deductions");
        }

        return recommendations;
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
     * Checks for: generic void*, state-based type names, missing structures, type duplication
     */
    private void validateParameterTypeQuality(Function func, List<String> issues) {
        Program program = func.getProgram();
        DataTypeManager dtm = program.getDataTypeManager();

        // State-based type name prefixes to flag
        String[] statePrefixes = {"Initialized", "Allocated", "Created", "Updated",
                                  "Processed", "Deleted", "Modified", "Constructed",
                                  "Freed", "Destroyed", "Copied", "Cloned"};

        for (Parameter param : func.getParameters()) {
            DataType paramType = param.getDataType();
            String typeName = paramType.getName();

            // Check 1: Generic void* pointers (should use specific types)
            if (paramType instanceof Pointer) {
                Pointer ptrType = (Pointer) paramType;
                DataType pointedTo = ptrType.getDataType();
                if (pointedTo != null && pointedTo.getName().equals("void")) {
                    issues.add("Generic void* parameter: " + param.getName() +
                              " (should use specific structure type)");
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
    }

    /**
     * Validate plate comment structure and content quality
     */
    private void validatePlateCommentStructure(String plateComment, List<String> issues, boolean isThunk) {
        if (plateComment == null || plateComment.isEmpty()) {
            issues.add("Plate comment is empty");
            return;
        }

        // v3.2.0: Thunks only require: identifies as thunk/stub + references body address.
        // No minimum line count, Algorithm, or Returns sections needed for forwarding stubs.
        if (isThunk) {
            String lower = plateComment.toLowerCase();
            if (!lower.contains("thunk") && !lower.contains("stub") && !lower.contains("forwarding") && !lower.contains("jmp")) {
                issues.add("Thunk plate comment should identify function as a forwarding stub");
            }
            return;
        }

        // Check minimum line count
        String[] lines = plateComment.split("\n");
        if (lines.length < 10) {
            issues.add("Plate comment has only " + lines.length + " lines (minimum 10 required)");
        }

        // Check for required sections based on PLATE_COMMENT_FORMAT_GUIDE.md
        boolean hasAlgorithm = false;
        boolean hasParameters = false;
        boolean hasReturns = false;
        boolean hasNumberedSteps = false;

        for (String line : lines) {
            String trimmed = line.trim();

            // Check for Algorithm section with numbered steps
            if (trimmed.startsWith("Algorithm:") || trimmed.equals("Algorithm")) {
                hasAlgorithm = true;
            }

            // Check for numbered steps (1., 2., etc.)
            if (trimmed.matches("^\\d+\\.\\s+.*")) {
                hasNumberedSteps = true;
            }

            // Check for Parameters section
            if (trimmed.startsWith("Parameters:") || trimmed.equals("Parameters")) {
                hasParameters = true;
            }

            // Check for Returns section
            if (trimmed.startsWith("Returns:") || trimmed.equals("Returns")) {
                hasReturns = true;
            }
        }

        // Add issues for missing required sections
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
    }

    /**
     * Composite endpoint for RE documentation workflow.
     * Returns decompiled code + classification + callees + variables with pre-analysis + compact completeness
     * in a single response, using only one decompilation.
     */
    public String analyzeForDocumentation(String functionAddress, String programName) {
        Object[] programResult = getProgramOrError(programName);
        Program program = (Program) programResult[0];
        if (program == null) {
            return "{\"error\": \"" + ServiceUtils.escapeJson((String) programResult[1]) + "\"}";
        }

        final Program finalProgram = program;
        final StringBuilder result = new StringBuilder();
        final AtomicReference<String> errorMsg = new AtomicReference<>(null);

        try {
            SwingUtilities.invokeAndWait(() -> {
                try {
                    // Resolve function by address
                    Address addr = finalProgram.getAddressFactory().getAddress(functionAddress);
                    if (addr == null) {
                        result.append("{\"error\": \"Invalid address: ").append(functionAddress).append("\"}");
                        return;
                    }
                    Function func = finalProgram.getFunctionManager().getFunctionAt(addr);
                    if (func == null) {
                        func = finalProgram.getFunctionManager().getFunctionContaining(addr);
                    }
                    if (func == null) {
                        result.append("{\"error\": \"No function at address: ").append(functionAddress).append("\"}");
                        return;
                    }

                    result.append("{");

                    // Basic info
                    result.append("\"name\": \"").append(ServiceUtils.escapeJson(func.getName())).append("\", ");
                    result.append("\"address\": \"").append(func.getEntryPoint().toString()).append("\", ");
                    result.append("\"signature\": \"").append(ServiceUtils.escapeJson(func.getSignature().toString())).append("\", ");

                    // Classification
                    String classification = classifyFunction(func, finalProgram);
                    result.append("\"classification\": \"").append(classification).append("\", ");

                    // Return type analysis
                    String retTypeName = func.getReturnType().getName();
                    result.append("\"return_type\": \"").append(ServiceUtils.escapeJson(retTypeName)).append("\", ");
                    result.append("\"return_type_resolved\": ").append(!retTypeName.startsWith("undefined")).append(", ");

                    // Decompile (single decompilation reused for code + variables)
                    DecompileResults decompResults = functionService.decompileFunction(func, finalProgram);
                    if (decompResults != null && decompResults.decompileCompleted() &&
                        decompResults.getDecompiledFunction() != null) {
                        String decompiledCode = decompResults.getDecompiledFunction().getC();
                        if (decompiledCode != null) {
                            result.append("\"decompiled_code\": \"").append(ServiceUtils.escapeJson(decompiledCode)).append("\", ");
                        }
                    }

                    // Callees with ordinal and documentation status
                    result.append("\"callees\": [");
                    Set<Function> calledFuncs = func.getCalledFunctions(null);
                    int calleeIdx = 0;
                    int ordinalCalleeCount = 0;
                    for (Function called : calledFuncs) {
                        if (calleeIdx > 0) result.append(", ");
                        String calleeName = called.getName();
                        boolean isUndocumented = calleeName.startsWith("FUN_") || calleeName.startsWith("thunk_FUN_");
                        boolean isOrdinal = calleeName.startsWith("Ordinal_") || calleeName.startsWith("thunk_Ordinal_");
                        if (isOrdinal) ordinalCalleeCount++;
                        result.append("{\"name\": \"").append(ServiceUtils.escapeJson(calleeName)).append("\"");
                        if (isUndocumented) result.append(", \"undocumented\": true");
                        if (isOrdinal) result.append(", \"is_ordinal\": true");
                        if (called.isThunk()) result.append(", \"is_thunk\": true");
                        result.append("}");
                        calleeIdx++;
                    }
                    result.append("], ");
                    result.append("\"callee_count\": ").append(calleeIdx).append(", ");
                    result.append("\"ordinal_callee_count\": ").append(ordinalCalleeCount).append(", ");

                    // Wrapper hint
                    if (calleeIdx == 1 && retTypeName.startsWith("undefined")) {
                        Function callee = calledFuncs.iterator().next();
                        String calleeRetType = callee.getReturnType().getName();
                        if (!calleeRetType.equals("void") && !calleeRetType.startsWith("undefined")) {
                            result.append("\"wrapper_hint\": \"Callee '").append(ServiceUtils.escapeJson(callee.getName()))
                                  .append("' returns ").append(ServiceUtils.escapeJson(calleeRetType)).append("\", ");
                        }
                    }

                    // Parameters with pre-analysis
                    result.append("\"parameters\": [");
                    Parameter[] params = func.getParameters();
                    for (int i = 0; i < params.length; i++) {
                        if (i > 0) result.append(", ");
                        String pName = params[i].getName();
                        String pType = params[i].getDataType().getName();
                        String pStorage = params[i].getVariableStorage().toString();
                        boolean needsType = pType.startsWith("undefined");
                        boolean needsRename = pName.matches("param_\\d+");
                        result.append("{\"name\": \"").append(ServiceUtils.escapeJson(pName)).append("\", ");
                        result.append("\"type\": \"").append(ServiceUtils.escapeJson(pType)).append("\", ");
                        result.append("\"storage\": \"").append(ServiceUtils.escapeJson(pStorage)).append("\", ");
                        result.append("\"needs_type\": ").append(needsType).append(", ");
                        result.append("\"needs_rename\": ").append(needsRename);
                        if (needsType) {
                            result.append(", \"suggested_type\": \"").append(FunctionService.suggestType(pType)).append("\"");
                            result.append(", \"suggested_prefix\": \"").append(FunctionService.suggestHungarianPrefix(FunctionService.suggestType(pType))).append("\"");
                        } else {
                            result.append(", \"suggested_prefix\": \"").append(FunctionService.suggestHungarianPrefix(pType)).append("\"");
                        }
                        result.append("}");
                    }
                    result.append("], ");

                    // Local variables with pre-analysis (from HighFunction)
                    result.append("\"locals\": [");
                    boolean firstLocal = true;
                    if (decompResults != null && decompResults.decompileCompleted()) {
                        HighFunction highFunc = decompResults.getHighFunction();
                        if (highFunc != null) {
                            Iterator<HighSymbol> symbols = highFunc.getLocalSymbolMap().getSymbols();
                            while (symbols.hasNext()) {
                                HighSymbol sym = symbols.next();
                                if (!firstLocal) result.append(", ");
                                firstLocal = false;
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
                                result.append("{\"name\": \"").append(ServiceUtils.escapeJson(symName)).append("\", ");
                                result.append("\"type\": \"").append(ServiceUtils.escapeJson(symType)).append("\", ");
                                result.append("\"storage\": \"").append(ServiceUtils.escapeJson(storageStr)).append("\", ");
                                result.append("\"is_phantom\": ").append(isPhantom);
                                if (needsType) {
                                    result.append(", \"needs_type\": true");
                                    result.append(", \"suggested_type\": \"").append(FunctionService.suggestType(symType)).append("\"");
                                }
                                if (needsRename) {
                                    result.append(", \"needs_rename\": true");
                                    String prefix = needsType ? FunctionService.suggestHungarianPrefix(FunctionService.suggestType(symType))
                                                             : FunctionService.suggestHungarianPrefix(symType);
                                    result.append(", \"suggested_prefix\": \"").append(prefix).append("\"");
                                }
                                result.append("}");
                            }
                        }
                    }
                    result.append("], ");

                    // DAT global count (unrenamed globals referenced)
                    int datGlobalCount = 0;
                    ReferenceIterator refIter = finalProgram.getReferenceManager().getReferenceIterator(func.getBody().getMinAddress());
                    while (refIter.hasNext()) {
                        Reference ref = refIter.next();
                        if (!func.getBody().contains(ref.getFromAddress())) continue;
                        Address toAddr = ref.getToAddress();
                        Symbol sym = finalProgram.getSymbolTable().getPrimarySymbol(toAddr);
                        if (sym != null && sym.getName().startsWith("DAT_")) {
                            datGlobalCount++;
                        }
                    }
                    result.append("\"dat_global_count\": ").append(datGlobalCount).append(", ");

                    // Compact completeness score
                    String completenessJson = analyzeFunctionCompleteness(func.getEntryPoint().toString(), true);
                    // Strip outer braces and embed inline
                    if (completenessJson.startsWith("{") && completenessJson.endsWith("}")) {
                        result.append("\"completeness\": ").append(completenessJson);
                    }

                    result.append("}");
                } catch (Exception e) {
                    errorMsg.set(e.getMessage());
                }
            });

            if (errorMsg.get() != null) {
                return "{\"error\": \"" + ServiceUtils.escapeJson(errorMsg.get()) + "\"}";
            }
        } catch (Exception e) {
            return "{\"error\": \"" + ServiceUtils.escapeJson(e.getMessage()) + "\"}";
        }

        return result.toString();
    }
}
