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

import com.xebyte.core.BinaryComparisonService;
import com.xebyte.core.ProgramProvider;
import com.xebyte.core.Response;
import com.xebyte.core.ThreadingStrategy;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Shared service for function hashing, fuzzy matching, and diff operations.
 *
 * Provides normalized opcode hashing for exact matching, delegates to
 * {@link BinaryComparisonService} for fuzzy similarity and structured diffs.
 * Used by both GhidraMCPPlugin (GUI) and HeadlessEndpointHandler.
 */
public class ComparisonService extends BaseService {

    public ComparisonService(ProgramProvider programProvider, ThreadingStrategy threadingStrategy) {
        super(programProvider, threadingStrategy);
    }

    // =========================================================================
    // PUBLIC METHODS
    // =========================================================================

    /**
     * Compute normalized hash for a single function.
     */
    public Response getFunctionHash(String addressStr, String programName) {
        Program program = resolveProgram(programName);
        if (program == null) {
            return programNotFoundError(programName);
        }

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            if (addr == null) {
                return Response.err("Invalid address: " + addressStr);
            }

            Function func = program.getFunctionManager().getFunctionAt(addr);
            if (func == null) {
                return Response.err("No function at address: " + addressStr);
            }

            String hash = computeNormalizedFunctionHash(program, func);
            int instructionCount = countFunctionInstructions(program, func);
            boolean hasCustomName = !func.getName().startsWith("FUN_") &&
                                   !func.getName().startsWith("thunk_");

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("function_name", func.getName());
            result.put("address", addr.toString());
            result.put("hash", hash);
            result.put("instruction_count", instructionCount);
            result.put("has_custom_name", hasCustomName);
            result.put("program", program.getName());

            return Response.ok(result);
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    /**
     * Get hashes for multiple functions with pagination and filtering.
     */
    public Response getBulkFunctionHashes(int offset, int limit, String filter, String programName) {
        Program program = resolveProgram(programName);
        if (program == null) {
            return programNotFoundError(programName);
        }

        try {
            FunctionManager funcMgr = program.getFunctionManager();
            int total = 0;
            int skipped = 0;
            int added = 0;
            List<Map<String, Object>> functions = new ArrayList<>();

            for (Function func : funcMgr.getFunctions(true)) {
                boolean isDocumented = !func.getName().startsWith("FUN_") &&
                                       !func.getName().startsWith("thunk_") &&
                                       !func.getName().startsWith("switch");

                if ("documented".equals(filter) && !isDocumented) continue;
                if ("undocumented".equals(filter) && isDocumented) continue;

                total++;

                if (skipped < offset) {
                    skipped++;
                    continue;
                }

                if (added >= limit) continue;

                String hash = computeNormalizedFunctionHash(program, func);
                int instructionCount = countFunctionInstructions(program, func);

                Map<String, Object> entry = new LinkedHashMap<>();
                entry.put("name", func.getName());
                entry.put("address", func.getEntryPoint().toString());
                entry.put("hash", hash);
                entry.put("instruction_count", instructionCount);
                entry.put("has_custom_name", isDocumented);
                functions.add(entry);

                added++;
            }

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("program", program.getName());
            result.put("functions", functions);
            result.put("offset", offset);
            result.put("limit", limit);
            result.put("returned", added);
            result.put("total_matching", total);

            return Response.ok(result);
        } catch (Exception e) {
            return Response.err("Failed to get bulk hashes: " + e.getMessage());
        }
    }

    /**
     * Get function signature (feature vector) for fuzzy matching.
     */
    public Response getFunctionSignature(String addressStr, String programName) {
        Program program = resolveProgram(programName);
        if (program == null) return programNotFoundError(programName);

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            if (addr == null) return Response.err("Invalid address: " + addressStr);

            Function func = program.getFunctionManager().getFunctionAt(addr);
            if (func == null) return Response.err("No function at address: " + addressStr);

            BinaryComparisonService.FunctionSignature sig =
                BinaryComparisonService.computeFunctionSignature(program, func, monitor);
            return Response.text(sig.toJson());
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    /**
     * Find functions in target program similar to a source function.
     */
    public Response findSimilarFunctionsFuzzy(String addressStr, String sourceProgramName,
            String targetProgramName, double threshold, int limit) {
        Program srcProgram = resolveProgram(sourceProgramName);
        if (srcProgram == null) return programNotFoundError(sourceProgramName);

        if (targetProgramName == null || targetProgramName.trim().isEmpty()) {
            return Response.err("target_program parameter is required");
        }
        Program tgtProgram = resolveProgram(targetProgramName);
        if (tgtProgram == null) return programNotFoundError(targetProgramName);

        try {
            Address addr = srcProgram.getAddressFactory().getAddress(addressStr);
            if (addr == null) return Response.err("Invalid address: " + addressStr);

            Function srcFunc = srcProgram.getFunctionManager().getFunctionAt(addr);
            if (srcFunc == null) return Response.err("No function at address: " + addressStr);

            return Response.text(BinaryComparisonService.findSimilarFunctionsJson(
                srcProgram, srcFunc, tgtProgram, threshold, limit, monitor));
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    /**
     * Bulk fuzzy match: best match per source function in target program.
     */
    public Response bulkFuzzyMatch(String sourceProgramName, String targetProgramName,
            double threshold, int offset, int limit, String filter) {
        if (sourceProgramName == null || sourceProgramName.trim().isEmpty()) {
            return Response.err("source_program parameter is required");
        }
        Program srcProgram = resolveProgram(sourceProgramName);
        if (srcProgram == null) return programNotFoundError(sourceProgramName);

        if (targetProgramName == null || targetProgramName.trim().isEmpty()) {
            return Response.err("target_program parameter is required");
        }
        Program tgtProgram = resolveProgram(targetProgramName);
        if (tgtProgram == null) return programNotFoundError(targetProgramName);

        try {
            return Response.text(BinaryComparisonService.bulkFuzzyMatchJson(
                srcProgram, tgtProgram, threshold, offset, limit, filter, monitor));
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    /**
     * Structured diff between two functions (optionally from different programs).
     */
    public Response diffFunctions(String addressA, String addressB,
            String programAName, String programBName) {
        Program progA = resolveProgram(programAName);
        if (progA == null) return programNotFoundError(programAName);

        Program progB;
        if (programBName == null || programBName.trim().isEmpty()) {
            progB = progA;
        } else {
            progB = resolveProgram(programBName);
            if (progB == null) return programNotFoundError(programBName);
        }

        try {
            Address addrA = progA.getAddressFactory().getAddress(addressA);
            if (addrA == null) return Response.err("Invalid address_a: " + addressA);

            Address addrB = progB.getAddressFactory().getAddress(addressB);
            if (addrB == null) return Response.err("Invalid address_b: " + addressB);

            Function funcA = progA.getFunctionManager().getFunctionAt(addrA);
            if (funcA == null) return Response.err("No function at address_a: " + addressA);

            Function funcB = progB.getFunctionManager().getFunctionAt(addrB);
            if (funcB == null) return Response.err("No function at address_b: " + addressB);

            return Response.text(BinaryComparisonService.diffFunctionsJson(progA, funcA, progB, funcB, monitor));
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    // =========================================================================
    // PRIVATE HELPERS
    // =========================================================================

    /**
     * Compute a normalized opcode hash for function matching.
     * Normalizes addresses and large immediates so that functions compiled to
     * different base addresses still hash identically when structurally equivalent.
     */
    private String computeNormalizedFunctionHash(Program program, Function func) {
        StringBuilder normalized = new StringBuilder();
        Listing listing = program.getListing();
        AddressSetView functionBody = func.getBody();
        InstructionIterator instructions = listing.getInstructions(functionBody, true);

        while (instructions.hasNext()) {
            Instruction instr = instructions.next();
            normalized.append(instr.getMnemonicString()).append(":");

            int numOperands = instr.getNumOperands();
            for (int i = 0; i < numOperands; i++) {
                Object[] opObjects = instr.getOpObjects(i);
                if (opObjects.length > 0 && opObjects[0] instanceof ghidra.program.model.address.Address) {
                    ghidra.program.model.address.Address targetAddr = (ghidra.program.model.address.Address) opObjects[0];
                    if (functionBody.contains(targetAddr)) {
                        normalized.append("LOCAL");
                    } else {
                        Function targetFunc = program.getFunctionManager().getFunctionAt(targetAddr);
                        if (targetFunc != null) {
                            normalized.append("CALL_EXT");
                        } else {
                            normalized.append("DATA_EXT");
                        }
                    }
                } else if (opObjects.length > 0 && opObjects[0] instanceof ghidra.program.model.scalar.Scalar) {
                    ghidra.program.model.scalar.Scalar scalar = (ghidra.program.model.scalar.Scalar) opObjects[0];
                    long value = scalar.getValue();
                    if (Math.abs(value) < 0x10000) {
                        normalized.append("IMM:").append(value);
                    } else {
                        normalized.append("IMM_LARGE");
                    }
                } else {
                    normalized.append(instr.getDefaultOperandRepresentation(i));
                }

                if (i < numOperands - 1) {
                    normalized.append(",");
                }
            }
            normalized.append(";");
        }

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
        } catch (NoSuchAlgorithmException e) {
            return Integer.toHexString(normalized.toString().hashCode());
        }
    }

    /**
     * Count instructions in a function body.
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
}
