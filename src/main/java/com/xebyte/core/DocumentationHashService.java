package com.xebyte.core;

import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.listing.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;

import javax.swing.SwingUtilities;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
/**
 * Service for function hashing, documentation export/import, and cross-version matching.
 * Extracted from GhidraMCPPlugin as part of v4.0.0 refactor.
 */
@McpToolGroup("dochash")
public class DocumentationHashService {

    private final ProgramProvider programProvider;
    private final ThreadingStrategy threadingStrategy;
    private final BinaryComparisonService binaryComparisonService;
    private FunctionService functionService;
    private CommentService commentService;
    private AnalysisService analysisService;

    public DocumentationHashService(ProgramProvider programProvider, ThreadingStrategy threadingStrategy,
                                     BinaryComparisonService binaryComparisonService) {
        this.programProvider = programProvider;
        this.threadingStrategy = threadingStrategy;
        this.binaryComparisonService = binaryComparisonService;
    }

    /**
     * Set the FunctionService (needed for decompilation in getFunctionDocumentation).
     */
    public void setFunctionService(FunctionService functionService) {
        this.functionService = functionService;
    }

    /** Set CommentService (needed for batch_apply_documentation). */
    public void setCommentService(CommentService commentService) {
        this.commentService = commentService;
    }

    /** Set AnalysisService (needed for batch_apply_documentation completeness step). */
    public void setAnalysisService(AnalysisService analysisService) {
        this.analysisService = analysisService;
    }

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

    // -----------------------------------------------------------------------
    // Function Hash Methods
    // -----------------------------------------------------------------------

    /**
     * Compute a normalized opcode hash for a function.
     * The hash normalizes:
     * - Absolute addresses (call targets, jump targets, data refs) are replaced with placeholders
     * - Register-based operations are preserved
     * - Instruction mnemonics and operand types are included
     *
     * This allows matching identical functions that are located at different addresses.
     */
    @McpTool(value = "/get_function_hash", description = "Compute a normalized opcode hash for a function")

    public Response getFunctionHash(

            @Param(value = "address") FunctionRef funcRef,

            @Param(value = "program", required = false) String programName) {
        Object[] programResult = getProgramOrError(programName);
        Program program = (Program) programResult[0];
        if (program == null) {
            return Response.err((String) programResult[1]);
        }
        if (funcRef == null) return Response.err("Function name or address is required");

        try {
            Function func = funcRef.resolve(program);
            if (func == null) {
                return Response.err("No function found: " + funcRef.value());
            }
            Address addr = func.getEntryPoint();

            String hash = computeNormalizedFunctionHash(program, func);
            int instructionCount = countFunctionInstructions(program, func);
            long functionSize = func.getBody().getNumAddresses();

            StringBuilder json = new StringBuilder();
            json.append("{");
            json.append("\"function_name\": \"").append(ServiceUtils.escapeJson(func.getName())).append("\", ");
            json.append("\"address\": \"").append(addr.toString()).append("\", ");
            json.append("\"hash\": \"").append(hash).append("\", ");
            json.append("\"instruction_count\": ").append(instructionCount).append(", ");
            json.append("\"size_bytes\": ").append(functionSize).append(", ");
            json.append("\"has_custom_name\": ").append(!ServiceUtils.isAutoGeneratedName(func.getName())).append(", ");
            json.append("\"program\": \"").append(ServiceUtils.escapeJson(program.getName())).append("\"");
            json.append("}");

            return Response.text(json.toString());
        } catch (Exception e) {
            return Response.err("Failed to compute hash: " + e.getMessage());
        }
    }

    // Backward compatibility overload
    public Response getFunctionHash(String functionAddress) {
        return getFunctionHash(new FunctionRef(functionAddress), null);
    }

    /**
     * Compute a normalized hash from function instructions.
     * This ignores absolute addresses but preserves the logical structure.
     */
    private String computeNormalizedFunctionHash(Program program, Function func) {
        StringBuilder normalized = new StringBuilder();
        Listing listing = program.getListing();
        AddressSetView functionBody = func.getBody();
        InstructionIterator instructions = listing.getInstructions(functionBody, true);

        Address funcStart = func.getEntryPoint();

        while (instructions.hasNext()) {
            Instruction instr = instructions.next();

            // Add mnemonic
            normalized.append(instr.getMnemonicString()).append(" ");

            // Process each operand
            int numOperands = instr.getNumOperands();
            for (int i = 0; i < numOperands; i++) {
                int opType = instr.getOperandType(i);

                // Check if this operand contains an address reference
                boolean isAddressRef = (opType & OperandType.ADDRESS) != 0 ||
                                       (opType & OperandType.CODE) != 0 ||
                                       (opType & OperandType.DATA) != 0;

                if (isAddressRef) {
                    // For address references, use relative offset from function start if within function,
                    // otherwise use a generic placeholder
                    Reference[] refs = instr.getOperandReferences(i);
                    if (refs.length > 0) {
                        Address targetAddr = refs[0].getToAddress();
                        if (functionBody.contains(targetAddr)) {
                            // Internal reference - use relative offset
                            long relOffset = targetAddr.subtract(funcStart);
                            normalized.append("REL+").append(relOffset);
                        } else {
                            // External reference - use generic marker with reference type
                            RefType refType = refs[0].getReferenceType();
                            if (refType.isCall()) {
                                normalized.append("CALL_EXT");
                            } else if (refType.isData()) {
                                normalized.append("DATA_EXT");
                            } else {
                                normalized.append("EXT_REF");
                            }
                        }
                    } else {
                        normalized.append("ADDR");
                    }
                } else if ((opType & OperandType.REGISTER) != 0) {
                    // Keep register names as-is (they're part of the function's logic)
                    normalized.append(instr.getDefaultOperandRepresentation(i));
                } else if ((opType & OperandType.SCALAR) != 0) {
                    // For small constants (likely magic numbers or offsets), keep the value
                    // For large constants (likely addresses), normalize
                    Object[] opObjects = instr.getOpObjects(i);
                    if (opObjects.length > 0 && opObjects[0] instanceof Scalar) {
                        Scalar scalar = (Scalar) opObjects[0];
                        long value = scalar.getValue();
                        // Keep small constants (< 0x10000), normalize large ones
                        if (Math.abs(value) < 0x10000) {
                            normalized.append("IMM:").append(value);
                        } else {
                            normalized.append("IMM_LARGE");
                        }
                    } else {
                        normalized.append(instr.getDefaultOperandRepresentation(i));
                    }
                } else {
                    // Other operand types - use default representation
                    normalized.append(instr.getDefaultOperandRepresentation(i));
                }

                if (i < numOperands - 1) {
                    normalized.append(",");
                }
            }

            normalized.append(";");
        }

        // Compute SHA-256 hash of the normalized representation
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(normalized.toString().getBytes(StandardCharsets.UTF_8));
            StringBuilder hexString = new StringBuilder();
            for (byte b : hashBytes) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (java.security.NoSuchAlgorithmException e) {
            // Fallback to simple string hash
            return Integer.toHexString(normalized.toString().hashCode());
        }
    }

    /**
     * Count instructions in a function
     */
    private int countFunctionInstructions(Program program, Function func) {
        Listing listing = program.getListing();
        AddressSetView functionBody = func.getBody();
        InstructionIterator instructions = listing.getInstructions(functionBody, true);
        int count = 0;
        while (instructions.hasNext()) {
            instructions.next();
            count++;
        }
        return count;
    }

    // -----------------------------------------------------------------------
    // Bulk Function Hash Methods
    // -----------------------------------------------------------------------

    /**
     * Get hashes for multiple functions efficiently
     */
    @McpTool(value = "/get_bulk_function_hashes", description = "Get normalized opcode hashes for multiple functions efficiently")

    public Response getBulkFunctionHashes(

            @Param(value = "offset", type = "integer", required = false, defaultValue = "0") int offset,

            @Param(value = "limit", type = "integer", required = false, defaultValue = "100") int limit,

            @Param(value = "filter", required = false) String filter,

            @Param(value = "program", required = false) String programName) {
        Object[] programResult = getProgramOrError(programName);
        Program program = (Program) programResult[0];
        if (program == null) {
            return Response.err((String) programResult[1]);
        }

        try {
            StringBuilder json = new StringBuilder();
            json.append("{\"program\": \"").append(ServiceUtils.escapeJson(program.getName())).append("\", ");
            json.append("\"functions\": [");

            FunctionManager funcMgr = program.getFunctionManager();
            int total = 0;
            int skipped = 0;
            int added = 0;

            for (Function func : funcMgr.getFunctions(true)) {
                // Apply filter
                boolean isDocumented = !ServiceUtils.isAutoGeneratedName(func.getName()) &&
                                       !func.getName().startsWith("switch");

                if ("documented".equals(filter) && !isDocumented) continue;
                if ("undocumented".equals(filter) && isDocumented) continue;

                total++;

                if (skipped < offset) {
                    skipped++;
                    continue;
                }

                if (added >= limit) continue; // Still counting total

                if (added > 0) json.append(", ");

                String hash = computeNormalizedFunctionHash(program, func);
                int instructionCount = countFunctionInstructions(program, func);

                json.append("{");
                json.append("\"name\": \"").append(ServiceUtils.escapeJson(func.getName())).append("\", ");
                json.append("\"address\": \"").append(func.getEntryPoint().toString()).append("\", ");
                json.append("\"hash\": \"").append(hash).append("\", ");
                json.append("\"instruction_count\": ").append(instructionCount).append(", ");
                json.append("\"has_custom_name\": ").append(isDocumented);
                json.append("}");

                added++;
            }

            json.append("], ");
            json.append("\"offset\": ").append(offset).append(", ");
            json.append("\"limit\": ").append(limit).append(", ");
            json.append("\"returned\": ").append(added).append(", ");
            json.append("\"total_matching\": ").append(total).append("}");

            return Response.text(json.toString());
        } catch (Exception e) {
            return Response.err("Failed to get bulk hashes: " + e.getMessage());
        }
    }

    // Backward compatibility overload
    public Response getBulkFunctionHashes(int offset, int limit, String filter) {
        return getBulkFunctionHashes(offset, limit, filter, null);
    }

    // -----------------------------------------------------------------------
    // Function Documentation Export/Import
    // -----------------------------------------------------------------------

    /**
     * Export all documentation for a function (for use in cross-binary propagation)
     */
    @McpTool(value = "/get_function_documentation", description = "Export all documentation for a function (for cross-binary propagation)")

    public Response getFunctionDocumentation(

            @Param(value = "address") FunctionRef funcRef) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) {
            return Response.err("No program loaded");
        }
        if (funcRef == null) return Response.err("Function name or address is required");

        try {
            Function func = funcRef.resolve(program);
            if (func == null) {
                return Response.err("No function found: " + funcRef.value());
            }
            Address addr = func.getEntryPoint();

            // Compute hash for matching
            String hash = computeNormalizedFunctionHash(program, func);

            StringBuilder json = new StringBuilder();
            json.append("{");
            json.append("\"hash\": \"").append(hash).append("\", ");
            json.append("\"source_program\": \"").append(ServiceUtils.escapeJson(program.getName())).append("\", ");
            json.append("\"source_address\": \"").append(addr.toString()).append("\", ");
            json.append("\"function_name\": \"").append(ServiceUtils.escapeJson(func.getName())).append("\", ");

            // Return type and calling convention
            json.append("\"return_type\": \"").append(ServiceUtils.escapeJson(func.getReturnType().getName())).append("\", ");
            json.append("\"calling_convention\": \"").append(func.getCallingConventionName() != null ? ServiceUtils.escapeJson(func.getCallingConventionName()) : "").append("\", ");

            // Plate comment
            String plateComment = func.getComment();
            json.append("\"plate_comment\": ").append(plateComment != null ? "\"" + ServiceUtils.escapeJson(plateComment) + "\"" : "null").append(", ");

            // Parameters
            json.append("\"parameters\": [");
            Parameter[] params = func.getParameters();
            for (int i = 0; i < params.length; i++) {
                if (i > 0) json.append(", ");
                Parameter p = params[i];
                json.append("{");
                json.append("\"ordinal\": ").append(p.getOrdinal()).append(", ");
                json.append("\"name\": \"").append(ServiceUtils.escapeJson(p.getName())).append("\", ");
                json.append("\"type\": \"").append(ServiceUtils.escapeJson(p.getDataType().getName())).append("\", ");
                json.append("\"comment\": ").append(p.getComment() != null ? "\"" + ServiceUtils.escapeJson(p.getComment()) + "\"" : "null");
                json.append("}");
            }
            json.append("], ");

            // Local variables (from decompilation if available)
            json.append("\"local_variables\": [");
            DecompileResults decompResults = functionService.decompileFunction(func, program);
            boolean first = true;
            if (decompResults != null && decompResults.decompileCompleted()) {
                ghidra.program.model.pcode.HighFunction highFunc = decompResults.getHighFunction();
                if (highFunc != null) {
                    Iterator<ghidra.program.model.pcode.HighSymbol> symbols = highFunc.getLocalSymbolMap().getSymbols();
                    while (symbols.hasNext()) {
                        ghidra.program.model.pcode.HighSymbol sym = symbols.next();
                        if (sym.isParameter()) continue; // Skip parameters, handled above

                        if (!first) json.append(", ");
                        first = false;

                        json.append("{");
                        json.append("\"name\": \"").append(ServiceUtils.escapeJson(sym.getName())).append("\", ");
                        json.append("\"type\": \"").append(ServiceUtils.escapeJson(sym.getDataType().getName())).append("\", ");
                        // Try to get storage info for matching
                        ghidra.program.model.pcode.HighVariable highVar = sym.getHighVariable();
                        if (highVar != null && highVar.getRepresentative() != null) {
                            // Use Varnode's toString() which gives address/register info
                            json.append("\"storage\": \"").append(ServiceUtils.escapeJson(highVar.getRepresentative().toString())).append("\"");
                        } else {
                            json.append("\"storage\": null");
                        }
                        json.append("}");
                    }
                }
            }
            json.append("], ");

            // Inline comments (EOL and PRE comments within function body)
            json.append("\"comments\": [");
            AddressSetView functionBody = func.getBody();
            Listing listing = program.getListing();
            first = true;
            Address funcStart = func.getEntryPoint();

            for (Address cAddr : functionBody.getAddresses(true)) {
                String eolComment = listing.getComment(CodeUnit.EOL_COMMENT, cAddr);
                String preComment = listing.getComment(CodeUnit.PRE_COMMENT, cAddr);

                if (eolComment != null || preComment != null) {
                    if (!first) json.append(", ");
                    first = false;

                    long relOffset = cAddr.subtract(funcStart);
                    json.append("{");
                    json.append("\"relative_offset\": ").append(relOffset).append(", ");
                    json.append("\"eol_comment\": ").append(eolComment != null ? "\"" + ServiceUtils.escapeJson(eolComment) + "\"" : "null").append(", ");
                    json.append("\"pre_comment\": ").append(preComment != null ? "\"" + ServiceUtils.escapeJson(preComment) + "\"" : "null");
                    json.append("}");
                }
            }
            json.append("], ");

            // Labels within function
            json.append("\"labels\": [");
            first = true;
            SymbolTable symTable = program.getSymbolTable();
            for (Address lAddr : functionBody.getAddresses(true)) {
                Symbol[] symbols = symTable.getSymbols(lAddr);
                for (Symbol sym : symbols) {
                    if (sym.getSymbolType() == SymbolType.LABEL && !sym.getName().equals(func.getName())) {
                        if (!first) json.append(", ");
                        first = false;

                        long relOffset = lAddr.subtract(funcStart);
                        json.append("{");
                        json.append("\"relative_offset\": ").append(relOffset).append(", ");
                        json.append("\"name\": \"").append(ServiceUtils.escapeJson(sym.getName())).append("\"");
                        json.append("}");
                    }
                }
            }
            json.append("], ");

            // Completeness score - simplified version without full analysis
            List<String> undefinedVars = new ArrayList<>();
            for (Parameter param : func.getParameters()) {
                if (param.getName().startsWith("param_")) {
                    undefinedVars.add(param.getName());
                }
                if (param.getDataType().getName().startsWith("undefined")) {
                    undefinedVars.add(param.getName());
                }
            }

            double completenessScore = calculateSimpleCompletenessScore(func);
            json.append("\"completeness_score\": ").append(completenessScore);

            json.append("}");
            return Response.text(json.toString());

        } catch (Exception e) {
            return Response.err("Failed to export documentation: " + e.getMessage());
        }
    }

    /**
     * Simple completeness score calculation for documentation export.
     * A simplified version that doesn't require the full analysis infrastructure.
     */
    private double calculateSimpleCompletenessScore(Function func) {
        double score = 100.0;

        if (ServiceUtils.isAutoGeneratedName(func.getName())) score -= 30;
        if (func.getComment() == null) score -= 20;

        // Check parameters
        for (Parameter param : func.getParameters()) {
            if (param.getName().startsWith("param_")) {
                score -= 5;
            }
            if (param.getDataType().getName().startsWith("undefined")) {
                score -= 5;
            }
        }

        return Math.max(0, score);
    }

    /**
     * Apply documentation from a source function to a target function.
     * Expects JSON body with: target_address, source_documentation (from getFunctionDocumentation)
     */
    @SuppressWarnings("deprecation")
    @McpTool(value = "/apply_function_documentation", description = "Apply documentation to a target function from exported documentation", method = McpTool.Method.POST)

    public Response applyFunctionDocumentation(
            @Param(value = "_body", description = "Full JSON body as string") String jsonBody) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) {
            return Response.err("No program loaded");
        }

        try {
            Map<String, Object> body = JsonHelper.parseMap(jsonBody);
            String targetAddress = JsonHelper.getString(body, "target_address");
            String functionName = JsonHelper.getString(body, "function_name");
            String returnType = JsonHelper.getString(body, "return_type");
            String callingConvention = JsonHelper.getString(body, "calling_convention");
            String plateComment = JsonHelper.getString(body, "plate_comment");

            if (targetAddress == null || targetAddress.isEmpty()) {
                return Response.err("target_address is required");
            }

            Address addr = program.getAddressFactory().getAddress(targetAddress);
            if (addr == null) {
                return Response.err("Invalid target address: " + targetAddress);
            }

            Function func = program.getFunctionManager().getFunctionAt(addr);
            if (func == null) {
                return Response.err("No function at target address: " + targetAddress);
            }

            final AtomicBoolean success = new AtomicBoolean(false);
            final AtomicReference<String> errorMsg = new AtomicReference<>(null);
            final AtomicInteger changesApplied = new AtomicInteger(0);

            try {
                SwingUtilities.invokeAndWait(() -> {
                    int tx = program.startTransaction("Apply Function Documentation");
                    try {
                        // Apply function name
                        if (functionName != null && !functionName.isEmpty() && !functionName.equals(func.getName())) {
                            try {
                                func.setName(functionName, SourceType.USER_DEFINED);
                                changesApplied.incrementAndGet();
                            } catch (Exception e) {
                                Msg.warn(this, "Could not set function name: " + e.getMessage());
                            }
                        }

                        // Apply plate comment
                        if (plateComment != null && !plateComment.isEmpty()) {
                            func.setComment(plateComment);
                            changesApplied.incrementAndGet();
                        }

                        // Apply calling convention
                        if (callingConvention != null && !callingConvention.isEmpty()) {
                            try {
                                func.setCallingConvention(callingConvention);
                                changesApplied.incrementAndGet();
                            } catch (Exception e) {
                                Msg.warn(this, "Could not set calling convention: " + e.getMessage());
                            }
                        }

                        // Apply return type
                        if (returnType != null && !returnType.isEmpty()) {
                            DataType dt = ServiceUtils.findDataTypeByNameInAllCategories(program.getDataTypeManager(), returnType);
                            if (dt != null) {
                                try {
                                    func.setReturnType(dt, SourceType.USER_DEFINED);
                                    changesApplied.incrementAndGet();
                                } catch (Exception e) {
                                    Msg.warn(this, "Could not set return type: " + e.getMessage());
                                }
                            }
                        }

                        // Apply parameter names and types from JSON array
                        Object paramsObj = body.get("parameters");
                        if (paramsObj instanceof List<?> paramsList) {
                            applyParameterDocumentation(func, program, paramsList, changesApplied);
                        }

                        // Apply comments from JSON array
                        Object commentsObj = body.get("comments");
                        if (commentsObj instanceof List<?> commentsList) {
                            applyCommentsDocumentation(func, program, commentsList, changesApplied);
                        }

                        // Apply labels from JSON array
                        Object labelsObj = body.get("labels");
                        if (labelsObj instanceof List<?> labelsList) {
                            applyLabelsDocumentation(func, program, labelsList, changesApplied);
                        }

                        success.set(true);
                    } catch (Exception e) {
                        errorMsg.set(e.getMessage());
                    } finally {
                        program.endTransaction(tx, success.get());
                    }
                });
            } catch (Exception e) {
                return Response.err("Failed to apply documentation: " + e.getMessage());
            }

            if (success.get()) {
                Map<String, Object> out = new java.util.LinkedHashMap<>();
                out.put("success", true);
                out.put("changes_applied", changesApplied.get());
                out.put("function", func.getName());
                out.put("address", addr.toString());
                return Response.text(JsonHelper.toJson(out));
            } else {
                return Response.err(errorMsg.get() != null ? errorMsg.get() : "Unknown error");
            }

        } catch (Exception e) {
            return Response.err("Failed to parse documentation JSON: " + e.getMessage());
        }
    }

    /**
     * v4.0.0: Apply all documentation to a function in a single call.
     * Orchestrates: optional goto (no-op in service/GUI-only) -> rename -> prototype -> variable types -> variable renames -> comments -> optional completeness score.
     */
    @SuppressWarnings("unchecked")
    @McpTool(value = "/batch_apply_documentation", description = "Apply documentation in one call (rename, prototype, variable types/renames, comments)", method = McpTool.Method.POST)
    public Response batchApplyDocumentation(
            @Param(value = "_body", description = "JSON body: address, name, prototype, calling_convention, variable_types, variable_renames, plate_comment, decompiler_comments, disassembly_comments, goto, score") String jsonBody) {
        if (jsonBody == null || jsonBody.isBlank()) {
            return Response.err("JSON body is required");
        }
        Map<String, Object> params = JsonHelper.parseMap(jsonBody);
        String address = JsonHelper.getString(params, "address");
        if (address != null) address = address.trim();
        if (address == null || address.isEmpty()) {
            return Response.err("address parameter is required");
        }

        Program program = programProvider.getCurrentProgram();
        if (program == null) {
            return Response.err("No program loaded");
        }

        // Use address string directly; FunctionRef not yet available at this commit
        Map<String, Object> steps = new java.util.LinkedHashMap<>();
        java.util.List<String> errors = new java.util.ArrayList<>();

        // Step 1: Goto (optional) — no-op in service; GUI can register a separate handler that does goto then calls this
        Object gotoParam = params.get("goto");
        boolean doGoto = gotoParam instanceof Boolean && (Boolean) gotoParam;
        if (doGoto) {
            steps.put("goto", Map.of("skipped", true, "note", "GUI-only; use plugin endpoint for navigation"));
        }

        // Step 2: Rename function (optional)
        String name = JsonHelper.getString(params, "name");
        if (name != null && !name.isEmpty() && functionService != null) {
            Response renameResp = functionService.renameFunctionByAddress(new FunctionRef(address), name);
            boolean renameOk = !(renameResp instanceof Response.Err);
            Map<String, Object> step = new java.util.LinkedHashMap<>();
            step.put("success", renameOk);
            if (renameResp instanceof Response.Err e) {
                step.put("error", e.message());
                errors.add("rename: " + e.message());
            }
            steps.put("rename", step);
        }

        // Step 3: Set prototype (optional)
        String prototype = JsonHelper.getString(params, "prototype");
        if (prototype != null && !prototype.isEmpty() && functionService != null) {
            String callingConvention = JsonHelper.getString(params, "calling_convention");
            FunctionService.PrototypeResult protoResult = functionService.setFunctionPrototype(address, prototype, callingConvention);
            Map<String, Object> step = new java.util.LinkedHashMap<>();
            step.put("success", protoResult.isSuccess());
            if (!protoResult.isSuccess()) {
                step.put("error", protoResult.getErrorMessage());
                errors.add("prototype: " + protoResult.getErrorMessage());
            }
            steps.put("prototype", step);
        }

        // Step 4: Set variable types (optional)
        Object varTypesObj = params.get("variable_types");
        if (varTypesObj instanceof Map && functionService != null) {
            Map<String, Object> varTypes = (Map<String, Object>) varTypesObj;
            int setCount = 0, failCount = 0;
            java.util.List<String> typeErrors = new java.util.ArrayList<>();
            for (Map.Entry<String, Object> entry : varTypes.entrySet()) {
                Response typeResp = functionService.setLocalVariableType(new FunctionRef(address), entry.getKey(), entry.getValue().toString());
                boolean ok = !(typeResp instanceof Response.Err);
                if (ok) setCount++; else {
                    failCount++;
                    typeErrors.add(entry.getKey() + ": " + (typeResp instanceof Response.Err e ? e.message() : "failed"));
                }
            }
            Map<String, Object> step = new java.util.LinkedHashMap<>();
            step.put("success", failCount == 0);
            step.put("set", setCount);
            step.put("failed", failCount);
            if (!typeErrors.isEmpty()) {
                step.put("errors", new java.util.ArrayList<>(typeErrors));
                errors.addAll(typeErrors);
            }
            steps.put("variable_types", step);
        }

        // Step 5: Rename variables (optional)
        Object varRenamesObj = params.get("variable_renames");
        if (varRenamesObj instanceof Map && functionService != null) {
            Map<String, String> varRenames = new java.util.LinkedHashMap<>();
            for (Map.Entry<String, Object> e : ((Map<String, Object>) varRenamesObj).entrySet()) {
                varRenames.put(e.getKey(), e.getValue().toString());
            }
            Response renameVarsResp = functionService.batchRenameVariables(new FunctionRef(address), varRenames, true);
            boolean renameOk = renameVarsResp instanceof Response.Text t && t.content().contains("\"success\": true");
            steps.put("variable_renames", Map.of("success", renameOk));
            if (!renameOk && renameVarsResp instanceof Response.Err err) {
                errors.add("variable_renames: " + err.message());
            }
        }

        // Step 6: Set comments (optional)
        String plateComment = JsonHelper.getString(params, "plate_comment");
        java.util.List<Map<String, String>> decompComments = ServiceUtils.convertToMapList(params.get("decompiler_comments"));
        java.util.List<Map<String, String>> disasmComments = ServiceUtils.convertToMapList(params.get("disassembly_comments"));
        boolean hasComments = (plateComment != null && !plateComment.isEmpty()) ||
            (decompComments != null && !decompComments.isEmpty()) ||
            (disasmComments != null && !disasmComments.isEmpty());
        if (hasComments && commentService != null) {
            Response commentResp = commentService.batchSetComments(new FunctionRef(address), decompComments, disasmComments, plateComment);
            boolean commentOk = commentResp instanceof Response.Text t && t.content().contains("\"success\": true");
            steps.put("comments", Map.of("success", commentOk));
            if (!commentOk && commentResp instanceof Response.Err err) {
                errors.add("comments: " + err.message());
            }
        }

        // Step 7: Completeness score (optional)
        Object scoreParam = params.get("score");
        boolean doScore = !(scoreParam instanceof Boolean) || (Boolean) scoreParam;
        Map<String, Object> result = new java.util.LinkedHashMap<>();
        result.put("address", address);
        result.put("steps", steps);
        result.put("errors", errors);
        if (doScore && analysisService != null) {
            Response scoreResp = analysisService.analyzeFunctionCompleteness(address);
            if (scoreResp instanceof Response.Text t) {
                String scoreStr = t.content();
                if (scoreStr != null && !scoreStr.isBlank() && scoreStr.startsWith("{")) {
                    result.put("completeness", JsonHelper.parseMap(scoreStr));
                }
            }
        }

        return Response.text(JsonHelper.toJson(result));
    }

    /**
     * Apply parameter documentation from parsed JSON array (list of maps with ordinal, name, type).
     */
    @SuppressWarnings("unchecked")
    private void applyParameterDocumentation(Function func, Program program, List<?> paramsList, AtomicInteger changesApplied) {
        if (paramsList == null) return;
        Parameter[] params = func.getParameters();
        for (Object item : paramsList) {
            if (!(item instanceof Map)) continue;
            Map<String, Object> entry = (Map<String, Object>) item;
            try {
                Object ordObj = entry.get("ordinal");
                int ordinal = ordObj instanceof Number n ? n.intValue() : -1;
                String name = JsonHelper.getString(entry, "name");
                String typeName = JsonHelper.getString(entry, "type");
                if (ordinal < 0 || name == null || typeName == null || ordinal >= params.length) continue;

                Parameter param = params[ordinal];
                if (!name.startsWith("param_") && !name.equals(param.getName())) {
                    try {
                        param.setName(name, SourceType.USER_DEFINED);
                        changesApplied.incrementAndGet();
                    } catch (Exception e) {
                        Msg.warn(this, "Could not set parameter name: " + e.getMessage());
                    }
                }
                if (!typeName.startsWith("undefined") && !typeName.equals(param.getDataType().getName())) {
                    DataType dt = ServiceUtils.findDataTypeByNameInAllCategories(program.getDataTypeManager(), typeName);
                    if (dt != null) {
                        try {
                            param.setDataType(dt, SourceType.USER_DEFINED);
                            changesApplied.incrementAndGet();
                        } catch (Exception e) {
                            Msg.warn(this, "Could not set parameter type: " + e.getMessage());
                        }
                    }
                }
            } catch (Exception e) {
                // Skip this parameter
            }
        }
    }

    /**
     * Apply inline comments from parsed JSON array (list of maps with relative_offset, eol_comment, pre_comment).
     */
    @SuppressWarnings("unchecked")
    private void applyCommentsDocumentation(Function func, Program program, List<?> commentsList, AtomicInteger changesApplied) {
        if (commentsList == null) return;
        Address funcStart = func.getEntryPoint();
        Listing listing = program.getListing();
        for (Object item : commentsList) {
            if (!(item instanceof Map)) continue;
            Map<String, Object> entry = (Map<String, Object>) item;
            try {
                Object offsetObj = entry.get("relative_offset");
                long relOffset = offsetObj instanceof Number n ? n.longValue() : -1;
                if (relOffset < 0) continue;
                String eolComment = JsonHelper.getString(entry, "eol_comment");
                String preComment = JsonHelper.getString(entry, "pre_comment");

                Address commentAddr = funcStart.add(relOffset);
                CodeUnit cu = listing.getCodeUnitAt(commentAddr);
                if (cu != null) {
                    if (eolComment != null && !eolComment.isEmpty()) {
                        cu.setComment(CodeUnit.EOL_COMMENT, eolComment);
                        changesApplied.incrementAndGet();
                    }
                    if (preComment != null && !preComment.isEmpty()) {
                        cu.setComment(CodeUnit.PRE_COMMENT, preComment);
                        changesApplied.incrementAndGet();
                    }
                }
            } catch (Exception e) {
                // Skip this comment
            }
        }
    }

    /**
     * Apply labels from parsed JSON array (list of maps with relative_offset, name).
     */
    @SuppressWarnings("unchecked")
    private void applyLabelsDocumentation(Function func, Program program, List<?> labelsList, AtomicInteger changesApplied) {
        if (labelsList == null) return;
        Address funcStart = func.getEntryPoint();
        SymbolTable symTable = program.getSymbolTable();
        for (Object item : labelsList) {
            if (!(item instanceof Map)) continue;
            Map<String, Object> entry = (Map<String, Object>) item;
            try {
                Object offsetObj = entry.get("relative_offset");
                long relOffset = offsetObj instanceof Number n ? n.longValue() : -1;
                String labelName = JsonHelper.getString(entry, "name");
                if (relOffset < 0 || labelName == null || labelName.isEmpty()) continue;

                Address labelAddr = funcStart.add(relOffset);
                Symbol existing = symTable.getPrimarySymbol(labelAddr);
                if (existing == null || existing.getSymbolType() != SymbolType.LABEL ||
                    !existing.getName().equals(labelName)) {
                    try {
                        symTable.createLabel(labelAddr, labelName, SourceType.USER_DEFINED);
                        changesApplied.incrementAndGet();
                    } catch (Exception e) {
                        Msg.warn(this, "Could not create label: " + e.getMessage());
                    }
                }
            } catch (Exception e) {
                // Skip this label
            }
        }
    }

    // -----------------------------------------------------------------------
    // Cross-Version Matching Tools
    // -----------------------------------------------------------------------

    /**
     * Compare documentation status across all open programs.
     * Returns documented/undocumented function counts for each program.
     */
    @McpTool(value = "/compare_programs_documentation", description = "Compare documentation status across all open programs")

    public Response compareProgramsDocumentation() {
        StringBuilder result = new StringBuilder();
        result.append("{\"programs\": [");

        try {
            Program[] allPrograms = programProvider.getAllOpenPrograms();
            Program currentProgram = programProvider.getCurrentProgram();

            if (allPrograms == null || allPrograms.length == 0) {
                return Response.err("No programs are open");
            }

            boolean first = true;
            for (Program prog : allPrograms) {
                if (!first) result.append(", ");
                first = false;

                int documented = 0;
                int undocumented = 0;
                int total = 0;

                FunctionManager funcMgr = prog.getFunctionManager();
                for (Function func : funcMgr.getFunctions(true)) {
                    total++;
                    if (ServiceUtils.isAutoGeneratedName(func.getName())) {
                        undocumented++;
                    } else {
                        documented++;
                    }
                }

                double docPercent = total > 0 ? (documented * 100.0 / total) : 0;

                result.append("{");
                result.append("\"name\": \"").append(ServiceUtils.escapeJson(prog.getName())).append("\", ");
                result.append("\"path\": \"").append(ServiceUtils.escapeJson(prog.getDomainFile().getPathname())).append("\", ");
                result.append("\"is_current\": ").append(prog == currentProgram).append(", ");
                result.append("\"total_functions\": ").append(total).append(", ");
                result.append("\"documented\": ").append(documented).append(", ");
                result.append("\"undocumented\": ").append(undocumented).append(", ");
                result.append("\"documentation_percent\": ").append(String.format("%.1f", docPercent));
                result.append("}");
            }

            result.append("], \"count\": ").append(allPrograms.length).append("}");

        } catch (Exception e) {
            return Response.err(e.getMessage());
        }

        return Response.text(result.toString());
    }

    /**
     * Find undocumented (FUN_*) functions that reference a given string address.
     * This filters get_xrefs_to results to only return FUN_* functions.
     */
    @McpTool(value = "/find_undocumented_by_string", description = "Find undocumented (FUN_*) functions that reference a given string address")

    public Response findUndocumentedByString(

            @Param(value = "address") String stringAddress,

            @Param(value = "program", required = false) String programName) {
        if (stringAddress == null || stringAddress.isEmpty()) {
            return Response.err("String address is required");
        }

        Object[] programResult = getProgramOrError(programName);
        Program program = (Program) programResult[0];
        if (program == null) {
            return Response.err((String) programResult[1]);
        }

        StringBuilder result = new StringBuilder();
        result.append("{\"string_address\": \"").append(stringAddress).append("\", ");
        result.append("\"undocumented_functions\": [");

        try {
            Address addr = program.getAddressFactory().getAddress(stringAddress);
            if (addr == null) {
                return Response.err("Invalid address format: " + stringAddress);
            }

            ReferenceManager refMgr = program.getReferenceManager();
            FunctionManager funcMgr = program.getFunctionManager();

            // Get references to this address
            ReferenceIterator refIter = refMgr.getReferencesTo(addr);

            Set<String> seenFunctions = new HashSet<>();
            boolean first = true;
            int undocCount = 0;
            int docCount = 0;

            while (refIter.hasNext()) {
                Reference ref = refIter.next();
                Address fromAddr = ref.getFromAddress();

                // Find the function containing this reference
                Function func = funcMgr.getFunctionContaining(fromAddr);
                if (func != null) {
                    String funcName = func.getName();

                    // Only add each function once
                    if (!seenFunctions.contains(funcName)) {
                        seenFunctions.add(funcName);

                        if (ServiceUtils.isAutoGeneratedName(funcName)) {
                            if (!first) result.append(", ");
                            first = false;
                            undocCount++;

                            result.append("{");
                            result.append("\"name\": \"").append(ServiceUtils.escapeJson(funcName)).append("\", ");
                            result.append("\"address\": \"").append(func.getEntryPoint().toString()).append("\", ");
                            result.append("\"ref_address\": \"").append(fromAddr.toString()).append("\", ");
                            result.append("\"ref_type\": \"").append(ref.getReferenceType().getName()).append("\"");
                            result.append("}");
                        } else {
                            docCount++;
                        }
                    }
                }
            }

            result.append("], ");
            result.append("\"undocumented_count\": ").append(undocCount).append(", ");
            result.append("\"documented_count\": ").append(docCount).append(", ");
            result.append("\"total_referencing_functions\": ").append(seenFunctions.size());
            result.append("}");

        } catch (Exception e) {
            return Response.err(e.getMessage());
        }

        return Response.text(result.toString());
    }

    /**
     * Generate a report of all strings matching a pattern (e.g., ".cpp") and their referencing FUN_* functions.
     * This helps identify undocumented functions that can be matched using string anchors.
     */
    @McpTool(value = "/batch_string_anchor_report", description = "Generate a report of source file strings and their undocumented functions")

    public Response batchStringAnchorReport(

            @Param(value = "pattern", required = false) String pattern,

            @Param(value = "program", required = false) String programName) {
        Object[] programResult = getProgramOrError(programName);
        Program program = (Program) programResult[0];
        if (program == null) {
            return Response.err((String) programResult[1]);
        }

        StringBuilder result = new StringBuilder();
        result.append("{\"pattern\": \"").append(ServiceUtils.escapeJson(pattern)).append("\", ");
        result.append("\"anchors\": [");

        try {
            Listing listing = program.getListing();
            ReferenceManager refMgr = program.getReferenceManager();
            FunctionManager funcMgr = program.getFunctionManager();

            int anchorCount = 0;
            int totalUndocumented = 0;
            boolean firstAnchor = true;

            // Iterate through all defined strings in the program
            DataIterator dataIter = listing.getDefinedData(true);
            while (dataIter.hasNext()) {
                Data data = dataIter.next();

                // Check if this is a string type
                if (data.getDataType() instanceof StringDataType ||
                    data.getDataType().getName().toLowerCase().contains("string")) {

                    Object value = data.getValue();
                    if (value instanceof String) {
                        String strValue = (String) value;

                        // Check if string matches the pattern
                        if (strValue.toLowerCase().contains(pattern.toLowerCase())) {
                            Address strAddr = data.getAddress();

                            // Find FUN_* functions referencing this string
                            ReferenceIterator refIter = refMgr.getReferencesTo(strAddr);
                            Set<String> undocFuncs = new LinkedHashSet<>();
                            Set<String> docFuncs = new LinkedHashSet<>();

                            while (refIter.hasNext()) {
                                Reference ref = refIter.next();
                                Function func = funcMgr.getFunctionContaining(ref.getFromAddress());
                                if (func != null) {
                                    String funcName = func.getName();
                                    if (ServiceUtils.isAutoGeneratedName(funcName)) {
                                        undocFuncs.add(funcName + "@" + func.getEntryPoint().toString());
                                    } else {
                                        docFuncs.add(funcName);
                                    }
                                }
                            }

                            // Only include strings that have at least one referencing function
                            if (!undocFuncs.isEmpty() || !docFuncs.isEmpty()) {
                                if (!firstAnchor) result.append(", ");
                                firstAnchor = false;
                                anchorCount++;
                                totalUndocumented += undocFuncs.size();

                                result.append("{");
                                result.append("\"string\": \"").append(ServiceUtils.escapeJson(strValue)).append("\", ");
                                result.append("\"address\": \"").append(strAddr.toString()).append("\", ");
                                result.append("\"undocumented\": [");

                                boolean firstFunc = true;
                                for (String funcInfo : undocFuncs) {
                                    if (!firstFunc) result.append(", ");
                                    firstFunc = false;
                                    String[] parts = funcInfo.split("@");
                                    result.append("{\"name\": \"").append(parts[0]).append("\", ");
                                    result.append("\"address\": \"").append(parts[1]).append("\"}");
                                }

                                result.append("], \"documented\": [");

                                firstFunc = true;
                                for (String funcName : docFuncs) {
                                    if (!firstFunc) result.append(", ");
                                    firstFunc = false;
                                    result.append("\"").append(ServiceUtils.escapeJson(funcName)).append("\"");
                                }

                                result.append("], ");
                                result.append("\"undocumented_count\": ").append(undocFuncs.size()).append(", ");
                                result.append("\"documented_count\": ").append(docFuncs.size());
                                result.append("}");
                            }
                        }
                    }
                }
            }

            result.append("], ");
            result.append("\"total_anchors\": ").append(anchorCount).append(", ");
            result.append("\"total_undocumented_functions\": ").append(totalUndocumented);
            result.append("}");

        } catch (Exception e) {
            return Response.err(e.getMessage());
        }

        return Response.text(result.toString());
    }

    // -----------------------------------------------------------------------
    // Fuzzy Matching & Diff Handlers (delegates to BinaryComparisonService)
    // -----------------------------------------------------------------------

    /**
     * Get the function signature (feature vector) for a function at the given address.
     */
    @McpTool(value = "/get_function_signature", description = "Get a function's feature signature for fuzzy matching")

    public Response handleGetFunctionSignature(

            @Param(value = "address") FunctionRef funcRef,

            @Param(value = "program", required = false) String programName) {
        Object[] programResult = getProgramOrError(programName);
        Program program = (Program) programResult[0];
        if (program == null) return Response.err((String) programResult[1]);
        if (funcRef == null) return Response.err("Function name or address is required");

        try {
            Function func = funcRef.resolve(program);
            if (func == null) return Response.err("No function found: " + funcRef.value());

            BinaryComparisonService.FunctionSignature sig =
                BinaryComparisonService.computeFunctionSignature(program, func, new ConsoleTaskMonitor());
            return Response.text(sig.toJson());
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    /**
     * Find functions in target program similar to the source function.
     */
    @McpTool(value = "/find_similar_functions_fuzzy", description = "Find functions in a target binary that are similar to a given source function")

    public Response handleFindSimilarFunctionsFuzzy(

            @Param(value = "address") FunctionRef funcRef,

            @Param(value = "source_program") String sourceProgramName,

            @Param(value = "targetProgramName") String targetProgramName,

            @Param(value = "threshold", type = "number") double threshold,

            @Param(value = "limit", type = "integer", required = false, defaultValue = "100") int limit) {
        // Source program: use sourceProgramName if given, otherwise current program
        Object[] srcResult = getProgramOrError(sourceProgramName);
        Program srcProgram = (Program) srcResult[0];
        if (srcProgram == null) return Response.err((String) srcResult[1]);
        if (funcRef == null) return Response.err("Function name or address is required");

        // Target program is required
        if (targetProgramName == null || targetProgramName.trim().isEmpty()) {
            return Response.err("target_program parameter is required");
        }
        Object[] tgtResult = getProgramOrError(targetProgramName);
        Program tgtProgram = (Program) tgtResult[0];
        if (tgtProgram == null) return Response.err((String) tgtResult[1]);

        try {
            Function srcFunc = funcRef.resolve(srcProgram);
            if (srcFunc == null) return Response.err("No function found: " + funcRef.value());

            return Response.text(BinaryComparisonService.findSimilarFunctionsJson(
                srcProgram, srcFunc, tgtProgram, threshold, limit, new ConsoleTaskMonitor()));
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    /**
     * Bulk fuzzy match: find best match for each source function in target program.
     */
    @McpTool(value = "/bulk_fuzzy_match", description = "Find the best fuzzy match for each source function in a target binary")

    public Response handleBulkFuzzyMatch(

            @Param(value = "source_program") String sourceProgramName,

            @Param(value = "target_program") String targetProgramName,

            @Param(value = "threshold", type = "number") double threshold,

            @Param(value = "offset", type = "integer", required = false, defaultValue = "0") int offset,

            @Param(value = "limit", type = "integer", required = false, defaultValue = "100") int limit,

            @Param(value = "filter", required = false) String filter) {
        if (sourceProgramName == null || sourceProgramName.trim().isEmpty()) {
            return Response.err("source_program parameter is required");
        }
        Object[] srcResult = getProgramOrError(sourceProgramName);
        Program srcProgram = (Program) srcResult[0];
        if (srcProgram == null) return Response.err((String) srcResult[1]);

        if (targetProgramName == null || targetProgramName.trim().isEmpty()) {
            return Response.err("target_program parameter is required");
        }
        Object[] tgtResult = getProgramOrError(targetProgramName);
        Program tgtProgram = (Program) tgtResult[0];
        if (tgtProgram == null) return Response.err((String) tgtResult[1]);

        try {
            return Response.text(BinaryComparisonService.bulkFuzzyMatchJson(
                srcProgram, tgtProgram, threshold, offset, limit, filter, new ConsoleTaskMonitor()));
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    /**
     * Compute a structured diff between two functions.
     */
    @McpTool(value = "/diff_functions", description = "Compute a structured diff between two functions")

    public Response handleDiffFunctions(

            @Param(value = "address_a") FunctionRef funcRefA,

            @Param(value = "address_b") FunctionRef funcRefB,

            @Param(value = "program_a") String programAName,

            @Param(value = "program_b") String programBName) {
        // Program A
        Object[] resultA = getProgramOrError(programAName);
        Program progA = (Program) resultA[0];
        if (progA == null) return Response.err((String) resultA[1]);
        if (funcRefA == null) return Response.err("Function A name or address is required");
        if (funcRefB == null) return Response.err("Function B name or address is required");

        // Program B defaults to Program A if not specified
        Program progB;
        if (programBName == null || programBName.trim().isEmpty()) {
            progB = progA;
        } else {
            Object[] resultB = getProgramOrError(programBName);
            progB = (Program) resultB[0];
            if (progB == null) return Response.err((String) resultB[1]);
        }

        try {
            Function funcA = funcRefA.resolve(progA);
            if (funcA == null) return Response.err("No function found for A: " + funcRefA.value());

            Function funcB = funcRefB.resolve(progB);
            if (funcB == null) return Response.err("No function found for B: " + funcRefB.value());

            return Response.text(BinaryComparisonService.diffFunctionsJson(progA, funcA, progB, funcB, new ConsoleTaskMonitor()));
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }
}
