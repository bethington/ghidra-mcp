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
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Service for function hashing, documentation export/import, and cross-version matching.
 * Extracted from GhidraMCPPlugin as part of v4.0.0 refactor.
 */
public class DocumentationHashService {

    private final ProgramProvider programProvider;
    private final ThreadingStrategy threadingStrategy;
    private final BinaryComparisonService binaryComparisonService;
    private FunctionService functionService;

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
    public String getFunctionHash(String functionAddress, String programName) {
        Object[] programResult = getProgramOrError(programName);
        Program program = (Program) programResult[0];
        if (program == null) {
            return "{\"error\": \"" + ServiceUtils.escapeJson((String) programResult[1]) + "\"}";
        }

        try {
            Address addr = program.getAddressFactory().getAddress(functionAddress);
            if (addr == null) {
                return "{\"error\": \"Invalid address: " + functionAddress + "\"}";
            }

            Function func = program.getFunctionManager().getFunctionAt(addr);
            if (func == null) {
                return "{\"error\": \"No function at address: " + functionAddress + "\"}";
            }

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

            return json.toString();
        } catch (Exception e) {
            return "{\"error\": \"Failed to compute hash: " + ServiceUtils.escapeJson(e.getMessage()) + "\"}";
        }
    }

    // Backward compatibility overload
    public String getFunctionHash(String functionAddress) {
        return getFunctionHash(functionAddress, null);
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
    public String getBulkFunctionHashes(int offset, int limit, String filter, String programName) {
        Object[] programResult = getProgramOrError(programName);
        Program program = (Program) programResult[0];
        if (program == null) {
            return "{\"error\": \"" + ServiceUtils.escapeJson((String) programResult[1]) + "\"}";
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

            return json.toString();
        } catch (Exception e) {
            return "{\"error\": \"Failed to get bulk hashes: " + ServiceUtils.escapeJson(e.getMessage()) + "\"}";
        }
    }

    // Backward compatibility overload
    public String getBulkFunctionHashes(int offset, int limit, String filter) {
        return getBulkFunctionHashes(offset, limit, filter, null);
    }

    // -----------------------------------------------------------------------
    // Function Documentation Export/Import
    // -----------------------------------------------------------------------

    /**
     * Export all documentation for a function (for use in cross-binary propagation)
     */
    public String getFunctionDocumentation(String functionAddress) {
        return getFunctionDocumentation(functionAddress, null);
    }

    public String getFunctionDocumentation(String functionAddress, String programName) {
        Object[] programResult = getProgramOrError(programName);
        Program program = (Program) programResult[0];
        if (program == null) {
            return "{\"error\": \"" + ServiceUtils.escapeJson((String) programResult[1]) + "\"}";
        }

        try {
            Address addr = program.getAddressFactory().getAddress(functionAddress);
            if (addr == null) {
                return "{\"error\": \"Invalid address: " + functionAddress + "\"}";
            }

            Function func = program.getFunctionManager().getFunctionAt(addr);
            if (func == null) {
                return "{\"error\": \"No function at address: " + functionAddress + "\"}";
            }

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
            return json.toString();

        } catch (Exception e) {
            return "{\"error\": \"Failed to export documentation: " + ServiceUtils.escapeJson(e.getMessage()) + "\"}";
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
    public String applyFunctionDocumentation(String jsonBody) {
        return applyFunctionDocumentation(jsonBody, null);
    }

    @SuppressWarnings("deprecation")
    public String applyFunctionDocumentation(String jsonBody, String programName) {
        Object[] programResult = getProgramOrError(programName);
        Program program = (Program) programResult[0];
        if (program == null) {
            return "{\"error\": \"" + ServiceUtils.escapeJson((String) programResult[1]) + "\"}";
        }

        try {
            // Parse JSON manually (simple parsing for this format)
            String targetAddress = ServiceUtils.extractJsonString(jsonBody, "target_address");
            String functionName = ServiceUtils.extractJsonString(jsonBody, "function_name");
            String returnType = ServiceUtils.extractJsonString(jsonBody, "return_type");
            String callingConvention = ServiceUtils.extractJsonString(jsonBody, "calling_convention");
            String plateComment = ServiceUtils.extractJsonString(jsonBody, "plate_comment");

            if (targetAddress == null) {
                return "{\"error\": \"target_address is required\"}";
            }

            Address addr = program.getAddressFactory().getAddress(targetAddress);
            if (addr == null) {
                return "{\"error\": \"Invalid target address: " + targetAddress + "\"}";
            }

            Function func = program.getFunctionManager().getFunctionAt(addr);
            if (func == null) {
                return "{\"error\": \"No function at target address: " + targetAddress + "\"}";
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
                        String paramsJson = ServiceUtils.extractJsonArray(jsonBody, "parameters");
                        if (paramsJson != null) {
                            applyParameterDocumentation(func, program, paramsJson, changesApplied);
                        }

                        // Apply comments from JSON array
                        String commentsJson = ServiceUtils.extractJsonArray(jsonBody, "comments");
                        if (commentsJson != null) {
                            applyCommentsDocumentation(func, program, commentsJson, changesApplied);
                        }

                        // Apply labels from JSON array
                        String labelsJson = ServiceUtils.extractJsonArray(jsonBody, "labels");
                        if (labelsJson != null) {
                            applyLabelsDocumentation(func, program, labelsJson, changesApplied);
                        }

                        success.set(true);
                    } catch (Exception e) {
                        errorMsg.set(e.getMessage());
                    } finally {
                        program.endTransaction(tx, success.get());
                    }
                });
            } catch (Exception e) {
                return "{\"error\": \"Failed to apply documentation: " + ServiceUtils.escapeJson(e.getMessage()) + "\"}";
            }

            if (success.get()) {
                return "{\"success\": true, \"changes_applied\": " + changesApplied.get() +
                       ", \"function\": \"" + ServiceUtils.escapeJson(func.getName()) + "\", " +
                       "\"address\": \"" + addr.toString() + "\"}";
            } else {
                return "{\"error\": \"" + (errorMsg.get() != null ? ServiceUtils.escapeJson(errorMsg.get()) : "Unknown error") + "\"}";
            }

        } catch (Exception e) {
            return "{\"error\": \"Failed to parse documentation JSON: " + ServiceUtils.escapeJson(e.getMessage()) + "\"}";
        }
    }

    /**
     * Apply parameter documentation from JSON
     */
    private void applyParameterDocumentation(Function func, Program program, String paramsJson, AtomicInteger changesApplied) {
        // Parse simple array format: [{"ordinal": 0, "name": "...", "type": "..."}, ...]
        Pattern p = Pattern.compile(
            "\\{\\s*\"ordinal\"\\s*:\\s*(\\d+).*?\"name\"\\s*:\\s*\"([^\"]*)\".*?\"type\"\\s*:\\s*\"([^\"]*)\"");
        Matcher m = p.matcher(paramsJson);

        Parameter[] params = func.getParameters();
        while (m.find()) {
            try {
                int ordinal = Integer.parseInt(m.group(1));
                String name = m.group(2);
                String typeName = m.group(3);

                if (ordinal < params.length) {
                    Parameter param = params[ordinal];

                    // Set name if different and not generic
                    if (!name.startsWith("param_") && !name.equals(param.getName())) {
                        try {
                            param.setName(name, SourceType.USER_DEFINED);
                            changesApplied.incrementAndGet();
                        } catch (Exception e) {
                            Msg.warn(this, "Could not set parameter name: " + e.getMessage());
                        }
                    }

                    // Set type if different
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
                }
            } catch (Exception e) {
                // Skip this parameter
            }
        }
    }

    /**
     * Apply inline comments from JSON
     */
    private void applyCommentsDocumentation(Function func, Program program, String commentsJson, AtomicInteger changesApplied) {
        // Parse: [{"relative_offset": 0, "eol_comment": "...", "pre_comment": "..."}, ...]
        Pattern p = Pattern.compile(
            "\\{\\s*\"relative_offset\"\\s*:\\s*(\\d+)");
        Matcher m = p.matcher(commentsJson);

        Address funcStart = func.getEntryPoint();
        Listing listing = program.getListing();

        while (m.find()) {
            try {
                long relOffset = Long.parseLong(m.group(1));
                Address commentAddr = funcStart.add(relOffset);

                // Extract comments for this entry
                int entryStart = m.start();
                int entryEnd = commentsJson.indexOf('}', entryStart);
                if (entryEnd < 0) continue;
                String entry = commentsJson.substring(entryStart, entryEnd + 1);

                String eolComment = ServiceUtils.extractJsonString(entry, "eol_comment");
                String preComment = ServiceUtils.extractJsonString(entry, "pre_comment");

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
     * Apply labels from JSON
     */
    private void applyLabelsDocumentation(Function func, Program program, String labelsJson, AtomicInteger changesApplied) {
        // Parse: [{"relative_offset": 0, "name": "..."}, ...]
        Pattern p = Pattern.compile(
            "\\{\\s*\"relative_offset\"\\s*:\\s*(\\d+).*?\"name\"\\s*:\\s*\"([^\"]*)\"");
        Matcher m = p.matcher(labelsJson);

        Address funcStart = func.getEntryPoint();
        SymbolTable symTable = program.getSymbolTable();

        while (m.find()) {
            try {
                long relOffset = Long.parseLong(m.group(1));
                String labelName = m.group(2);

                Address labelAddr = funcStart.add(relOffset);

                // Check if label already exists
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
    public String compareProgramsDocumentation() {
        return compareProgramsDocumentation(null);
    }

    public String compareProgramsDocumentation(String programName) {
        StringBuilder result = new StringBuilder();
        result.append("{\"programs\": [");

        try {
            Program[] allPrograms = programProvider.getAllOpenPrograms();
            Object[] programResult = getProgramOrError(programName);
            Program currentProgram = (Program) programResult[0];

            if (allPrograms == null || allPrograms.length == 0) {
                return "{\"error\": \"No programs are open\"}";
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
            return "{\"error\": \"" + ServiceUtils.escapeJson(e.getMessage()) + "\"}";
        }

        return result.toString();
    }

    /**
     * Find undocumented (FUN_*) functions that reference a given string address.
     * This filters get_xrefs_to results to only return FUN_* functions.
     */
    public String findUndocumentedByString(String stringAddress, String programName) {
        if (stringAddress == null || stringAddress.isEmpty()) {
            return "{\"error\": \"String address is required\"}";
        }

        Object[] programResult = getProgramOrError(programName);
        Program program = (Program) programResult[0];
        if (program == null) {
            return "{\"error\": \"" + ServiceUtils.escapeJson((String) programResult[1]) + "\"}";
        }

        StringBuilder result = new StringBuilder();
        result.append("{\"string_address\": \"").append(stringAddress).append("\", ");
        result.append("\"undocumented_functions\": [");

        try {
            Address addr = program.getAddressFactory().getAddress(stringAddress);
            if (addr == null) {
                return "{\"error\": \"Invalid address format: " + stringAddress + "\"}";
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
            return "{\"error\": \"" + ServiceUtils.escapeJson(e.getMessage()) + "\"}";
        }

        return result.toString();
    }

    /**
     * Generate a report of all strings matching a pattern (e.g., ".cpp") and their referencing FUN_* functions.
     * This helps identify undocumented functions that can be matched using string anchors.
     */
    public String batchStringAnchorReport(String pattern, String programName) {
        Object[] programResult = getProgramOrError(programName);
        Program program = (Program) programResult[0];
        if (program == null) {
            return "{\"error\": \"" + ServiceUtils.escapeJson((String) programResult[1]) + "\"}";
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
            return "{\"error\": \"" + ServiceUtils.escapeJson(e.getMessage()) + "\"}";
        }

        return result.toString();
    }

    // -----------------------------------------------------------------------
    // Fuzzy Matching & Diff Handlers (delegates to BinaryComparisonService)
    // -----------------------------------------------------------------------

    /**
     * Get the function signature (feature vector) for a function at the given address.
     */
    public String handleGetFunctionSignature(String addressStr, String programName) {
        Object[] programResult = getProgramOrError(programName);
        Program program = (Program) programResult[0];
        if (program == null) return (String) programResult[1];

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            if (addr == null) return "{\"error\": \"Invalid address: " + addressStr + "\"}";

            Function func = program.getFunctionManager().getFunctionAt(addr);
            if (func == null) return "{\"error\": \"No function at address: " + addressStr + "\"}";

            BinaryComparisonService.FunctionSignature sig =
                BinaryComparisonService.computeFunctionSignature(program, func, new ConsoleTaskMonitor());
            return sig.toJson();
        } catch (Exception e) {
            return "{\"error\": \"" + ServiceUtils.escapeJson(e.getMessage()) + "\"}";
        }
    }

    /**
     * Find functions in target program similar to the source function.
     */
    public String handleFindSimilarFunctionsFuzzy(String addressStr, String sourceProgramName,
            String targetProgramName, double threshold, int limit) {
        // Source program: use sourceProgramName if given, otherwise current program
        Object[] srcResult = getProgramOrError(sourceProgramName);
        Program srcProgram = (Program) srcResult[0];
        if (srcProgram == null) return (String) srcResult[1];

        // Target program is required
        if (targetProgramName == null || targetProgramName.trim().isEmpty()) {
            return "{\"error\": \"target_program parameter is required\"}";
        }
        Object[] tgtResult = getProgramOrError(targetProgramName);
        Program tgtProgram = (Program) tgtResult[0];
        if (tgtProgram == null) return (String) tgtResult[1];

        try {
            Address addr = srcProgram.getAddressFactory().getAddress(addressStr);
            if (addr == null) return "{\"error\": \"Invalid address: " + addressStr + "\"}";

            Function srcFunc = srcProgram.getFunctionManager().getFunctionAt(addr);
            if (srcFunc == null) return "{\"error\": \"No function at address: " + addressStr + "\"}";

            return BinaryComparisonService.findSimilarFunctionsJson(
                srcProgram, srcFunc, tgtProgram, threshold, limit, new ConsoleTaskMonitor());
        } catch (Exception e) {
            return "{\"error\": \"" + ServiceUtils.escapeJson(e.getMessage()) + "\"}";
        }
    }

    /**
     * Bulk fuzzy match: find best match for each source function in target program.
     */
    public String handleBulkFuzzyMatch(String sourceProgramName, String targetProgramName,
            double threshold, int offset, int limit, String filter) {
        if (sourceProgramName == null || sourceProgramName.trim().isEmpty()) {
            return "{\"error\": \"source_program parameter is required\"}";
        }
        Object[] srcResult = getProgramOrError(sourceProgramName);
        Program srcProgram = (Program) srcResult[0];
        if (srcProgram == null) return (String) srcResult[1];

        if (targetProgramName == null || targetProgramName.trim().isEmpty()) {
            return "{\"error\": \"target_program parameter is required\"}";
        }
        Object[] tgtResult = getProgramOrError(targetProgramName);
        Program tgtProgram = (Program) tgtResult[0];
        if (tgtProgram == null) return (String) tgtResult[1];

        try {
            return BinaryComparisonService.bulkFuzzyMatchJson(
                srcProgram, tgtProgram, threshold, offset, limit, filter, new ConsoleTaskMonitor());
        } catch (Exception e) {
            return "{\"error\": \"" + ServiceUtils.escapeJson(e.getMessage()) + "\"}";
        }
    }

    /**
     * Compute a structured diff between two functions.
     */
    public String handleDiffFunctions(String addressA, String addressB, String programAName, String programBName) {
        // Program A
        Object[] resultA = getProgramOrError(programAName);
        Program progA = (Program) resultA[0];
        if (progA == null) return (String) resultA[1];

        // Program B defaults to Program A if not specified
        Program progB;
        if (programBName == null || programBName.trim().isEmpty()) {
            progB = progA;
        } else {
            Object[] resultB = getProgramOrError(programBName);
            progB = (Program) resultB[0];
            if (progB == null) return (String) resultB[1];
        }

        try {
            Address addrA = progA.getAddressFactory().getAddress(addressA);
            if (addrA == null) return "{\"error\": \"Invalid address_a: " + addressA + "\"}";

            Address addrB = progB.getAddressFactory().getAddress(addressB);
            if (addrB == null) return "{\"error\": \"Invalid address_b: " + addressB + "\"}";

            Function funcA = progA.getFunctionManager().getFunctionAt(addrA);
            if (funcA == null) return "{\"error\": \"No function at address_a: " + addressA + "\"}";

            Function funcB = progB.getFunctionManager().getFunctionAt(addrB);
            if (funcB == null) return "{\"error\": \"No function at address_b: " + addressB + "\"}";

            return BinaryComparisonService.diffFunctionsJson(progA, funcA, progB, funcB, new ConsoleTaskMonitor());
        } catch (Exception e) {
            return "{\"error\": \"" + ServiceUtils.escapeJson(e.getMessage()) + "\"}";
        }
    }
}
