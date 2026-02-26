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

import com.xebyte.core.ProgramProvider;
import com.xebyte.core.Response;
import com.xebyte.core.ThreadingStrategy;
import ghidra.app.services.AnalyzerType;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.util.task.TaskMonitor;

import java.util.*;

/**
 * Read-only analysis service for byte pattern search, data region analysis,
 * array bound detection, assembly context retrieval, and structure field usage.
 *
 * All methods are read-only and do not require write transactions.
 */
public class AnalysisService extends BaseService {

    public AnalysisService(ProgramProvider programProvider, ThreadingStrategy threadingStrategy) {
        super(programProvider, threadingStrategy);
    }

    /**
     * Search memory for hex byte patterns with wildcards (??)
     */
    public Response searchBytePatterns(String pattern, String mask) {
        Program program = resolveProgram(null);
        if (program == null) {
            return programNotFoundError(null);
        }

        if (pattern == null || pattern.trim().isEmpty()) {
            return Response.err("Pattern is required");
        }

        try {
            // Parse hex pattern (e.g., "E8 ?? ?? ?? ??" or "E8????????")
            String cleanPattern = pattern.trim().toUpperCase().replaceAll("\\s+", "");

            // Convert pattern to byte array and mask
            int patternLen = cleanPattern.length() / 2;
            byte[] patternBytes = new byte[patternLen];
            byte[] maskBytes = new byte[patternLen];

            int byteIndex = 0;
            for (int i = 0; i < cleanPattern.length() && byteIndex < patternLen; i += 2) {
                if (cleanPattern.charAt(i) == '?' ||
                    (i + 1 < cleanPattern.length() && cleanPattern.charAt(i + 1) == '?')) {
                    patternBytes[byteIndex] = 0;
                    maskBytes[byteIndex] = 0;
                } else {
                    String hexByte = cleanPattern.substring(i, Math.min(i + 2, cleanPattern.length()));
                    patternBytes[byteIndex] = (byte) Integer.parseInt(hexByte, 16);
                    maskBytes[byteIndex] = (byte) 0xFF;
                }
                byteIndex++;
            }

            Memory memory = program.getMemory();
            List<Object> matches = new ArrayList<>();
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
                    boolean found = true;
                    for (int j = 0; j < patternBytes.length; j++) {
                        if (maskBytes[j] != 0 && blockData[i + j] != patternBytes[j]) {
                            found = false;
                            break;
                        }
                    }

                    if (found) {
                        Address matchAddr = blockStart.add(i);
                        matches.add(Map.of("address", matchAddr.toString()));

                        if (matches.size() >= MAX_MATCHES) {
                            matches.add(Map.of("note", "Limited to " + MAX_MATCHES + " matches"));
                            break;
                        }
                    }
                }

                if (matches.size() >= MAX_MATCHES) break;
            }

            if (matches.isEmpty()) {
                matches.add(Map.of("note", "No matches found"));
            }

            return Response.ok(matches);
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    /**
     * Analyze a data region comprehensively
     */
    public Response analyzeDataRegion(String startAddressStr, int maxScanBytes,
                                      boolean includeXrefMap, boolean includeAssemblyPatterns,
                                      boolean includeBoundaryDetection) {
        Program program = resolveProgram(null);
        if (program == null) {
            return programNotFoundError(null);
        }

        try {
            Address startAddr = program.getAddressFactory().getAddress(startAddressStr);
            if (startAddr == null) {
                return Response.err("Invalid address: " + startAddressStr);
            }

            ReferenceManager refMgr = program.getReferenceManager();
            Listing listing = program.getListing();

            Address endAddr = startAddr;
            Set<String> uniqueXrefs = new HashSet<>();
            int byteCount = 0;
            Map<String, List<String>> xrefMap = includeXrefMap ? new LinkedHashMap<>() : null;

            for (int i = 0; i < maxScanBytes; i++) {
                Address scanAddr = startAddr.add(i);

                if (includeBoundaryDetection) {
                    Symbol[] symbols = program.getSymbolTable().getSymbols(scanAddr);
                    if (symbols.length > 0 && i > 0) {
                        boolean hitBoundary = false;
                        for (Symbol sym : symbols) {
                            String name = sym.getName();
                            if (!name.startsWith("DAT_") && !name.equals(startAddr.toString())) {
                                endAddr = scanAddr.subtract(1);
                                byteCount = i;
                                hitBoundary = true;
                                break;
                            }
                        }
                        if (hitBoundary) break;
                    }
                }

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
                                data.getLabel() : "DAT_" + startAddr.toString().replace(":", "");
            String currentType = (data != null) ?
                                data.getDataType().getName() : "undefined";

            String classification = "PRIMITIVE";
            if (uniqueXrefs.size() > 3) {
                classification = "ARRAY";
            } else if (uniqueXrefs.size() > 1) {
                classification = "STRUCTURE";
            }

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("start_address", startAddr.toString());
            result.put("end_address", endAddr.toString());
            result.put("byte_span", byteCount);
            if (includeXrefMap) {
                result.put("xref_map", xrefMap);
            }
            result.put("unique_xref_addresses", new ArrayList<>(uniqueXrefs));
            result.put("xref_count", uniqueXrefs.size());
            result.put("classification_hint", classification);
            result.put("current_name", currentName);
            result.put("current_type", currentType);

            return Response.ok(result);
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    /**
     * Detect array bounds based on xref analysis
     */
    public Response detectArrayBounds(String addressStr, boolean analyzeLoopBounds,
                                      boolean analyzeIndexing, int maxScanRange) {
        Program program = resolveProgram(null);
        if (program == null) {
            return programNotFoundError(null);
        }

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            if (addr == null) {
                return Response.err("Invalid address: " + addressStr);
            }

            ReferenceManager refMgr = program.getReferenceManager();
            int estimatedSize = 0;
            Address scanAddr = addr;

            for (int i = 0; i < maxScanRange; i++) {
                ReferenceIterator refIter = refMgr.getReferencesTo(scanAddr);
                if (refIter.hasNext()) {
                    estimatedSize = i + 1;
                }

                Symbol[] symbols = program.getSymbolTable().getSymbols(scanAddr);
                if (symbols.length > 0 && i > 0) {
                    for (Symbol sym : symbols) {
                        if (!sym.getName().startsWith("DAT_")) {
                            break;
                        }
                    }
                }

                scanAddr = scanAddr.add(1);
            }

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("address", addr.toString());
            result.put("estimated_size", estimatedSize);
            result.put("stride", 1);
            result.put("element_count", estimatedSize);
            result.put("confidence", "medium");
            result.put("detection_method", "xref_analysis");

            return Response.ok(result);
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    /**
     * Get assembly context around xref sources
     */
    public Response getAssemblyContext(String xrefSourcesStr, int contextInstructions, String includePatterns) {
        Program program = resolveProgram(null);
        if (program == null) {
            return programNotFoundError(null);
        }

        try {
            String[] addresses = xrefSourcesStr.split(",");
            Listing listing = program.getListing();
            Map<String, Object> result = new LinkedHashMap<>();

            for (String addrStr : addresses) {
                addrStr = addrStr.trim();
                if (addrStr.isEmpty()) continue;

                Map<String, Object> entry = new LinkedHashMap<>();
                try {
                    Address addr = program.getAddressFactory().getAddress(addrStr);
                    if (addr != null) {
                        Instruction instr = listing.getInstructionAt(addr);
                        entry.put("address", addrStr);

                        if (instr != null) {
                            entry.put("instruction", instr.toString());

                            List<String> contextBefore = new ArrayList<>();
                            Address prevAddr = addr;
                            for (int i = 0; i < contextInstructions; i++) {
                                Instruction prevInstr = listing.getInstructionBefore(prevAddr);
                                if (prevInstr == null) break;
                                prevAddr = prevInstr.getAddress();
                                contextBefore.add(prevAddr + ": " + prevInstr.toString());
                            }
                            entry.put("context_before", contextBefore);

                            List<String> contextAfter = new ArrayList<>();
                            Address nextAddr = addr;
                            for (int i = 0; i < contextInstructions; i++) {
                                Instruction nextInstr = listing.getInstructionAfter(nextAddr);
                                if (nextInstr == null) break;
                                nextAddr = nextInstr.getAddress();
                                contextAfter.add(nextAddr + ": " + nextInstr.toString());
                            }
                            entry.put("context_after", contextAfter);

                            entry.put("mnemonic", instr.getMnemonicString());
                        } else {
                            entry.put("error", "No instruction at address");
                        }
                    } else {
                        entry.put("error", "Invalid address");
                    }
                } catch (Exception e) {
                    entry.put("error", e.getMessage());
                }

                result.put(addrStr, entry);
            }

            return Response.ok(result);
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    /**
     * Analyze how structure fields are accessed
     */
    public Response analyzeStructFieldUsage(String addressStr, String structName, int maxFunctions) {
        Program program = resolveProgram(null);
        if (program == null) {
            return programNotFoundError(null);
        }

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            if (addr == null) {
                return Response.err("Invalid address: " + addressStr);
            }

            ReferenceManager refMgr = program.getReferenceManager();
            ReferenceIterator refIter = refMgr.getReferencesTo(addr);

            List<String> referencingFunctions = new ArrayList<>();
            Set<String> uniqueFuncs = new HashSet<>();

            while (refIter.hasNext() && uniqueFuncs.size() < maxFunctions) {
                Reference ref = refIter.next();
                Address fromAddr = ref.getFromAddress();
                Function func = program.getFunctionManager().getFunctionContaining(fromAddr);
                if (func != null && !uniqueFuncs.contains(func.getName())) {
                    uniqueFuncs.add(func.getName());
                    referencingFunctions.add(func.getName() + " @ " + func.getEntryPoint());
                }
            }

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("struct_address", addr.toString());
            result.put("struct_name", structName);
            result.put("functions_analyzed", referencingFunctions.size());
            result.put("referencing_functions", referencingFunctions);

            return Response.ok(result);
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    /**
     * Get field access context for a structure field
     */
    public Response getFieldAccessContext(String structAddressStr, int fieldOffset, int numExamples) {
        Program program = resolveProgram(null);
        if (program == null) {
            return programNotFoundError(null);
        }

        try {
            Address structAddr = program.getAddressFactory().getAddress(structAddressStr);
            if (structAddr == null) {
                return Response.err("Invalid address: " + structAddressStr);
            }

            Address fieldAddr = structAddr.add(fieldOffset);
            ReferenceManager refMgr = program.getReferenceManager();
            ReferenceIterator refIter = refMgr.getReferencesTo(fieldAddr);

            List<Map<String, String>> examples = new ArrayList<>();
            Listing listing = program.getListing();

            while (refIter.hasNext() && examples.size() < numExamples) {
                Reference ref = refIter.next();
                Address fromAddr = ref.getFromAddress();
                Instruction instr = listing.getInstructionAt(fromAddr);
                Function func = program.getFunctionManager().getFunctionContaining(fromAddr);

                Map<String, String> example = new LinkedHashMap<>();
                example.put("from_address", fromAddr.toString());
                example.put("ref_type", ref.getReferenceType().getName());
                if (instr != null) {
                    example.put("instruction", instr.toString());
                }
                if (func != null) {
                    example.put("function", func.getName());
                }
                examples.add(example);
            }

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("struct_address", structAddr.toString());
            result.put("field_offset", fieldOffset);
            result.put("field_address", fieldAddr.toString());
            result.put("examples", examples);

            return Response.ok(result);
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    /**
     * List all registered analyzers and their enabled/disabled state.
     * Endpoint: /list_analyzers
     */
    public Response listAnalyzers(String programName) {
        Program program = resolveProgram(programName);
        if (program == null) return programNotFoundError(programName);

        try {
            Options options = program.getOptions(Program.ANALYSIS_PROPERTIES);
            List<String> names = options.getOptionNames();
            List<Map<String, Object>> entries = new ArrayList<>();
            for (String name : names) {
                try {
                    boolean enabled = options.getBoolean(name, false);
                    entries.add(Map.of("name", name, "enabled", enabled));
                } catch (Exception ignored) {}
            }
            return Response.ok(Map.of("analyzers", entries, "count", entries.size()));
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    /**
     * Trigger auto-analysis on the current or named program.
     * Endpoint: /run_analysis
     */
    public Response runAnalysis(String programName) {
        Program program = resolveProgram(programName);
        if (program == null) return programNotFoundError(programName);

        try {
            return threadingStrategy.executeWrite(program, "Run Auto Analysis", () -> {
                long start = System.currentTimeMillis();
                int before = program.getFunctionManager().getFunctionCount();

                ghidra.app.plugin.core.analysis.AutoAnalysisManager mgr =
                    ghidra.app.plugin.core.analysis.AutoAnalysisManager.getAnalysisManager(program);
                mgr.initializeOptions();
                mgr.reAnalyzeAll(program.getMemory().getLoadedAndInitializedAddressSet());
                mgr.startAnalysis(TaskMonitor.DUMMY);

                long duration = System.currentTimeMillis() - start;
                int after = program.getFunctionManager().getFunctionCount();
                Map<String, Object> result = new LinkedHashMap<>();
                result.put("success", true);
                result.put("duration_ms", duration);
                result.put("total_functions", after);
                result.put("new_functions", after - before);
                result.put("program", program.getName());
                return Response.ok(result);
            });
        } catch (Exception e) {
            return Response.err("Analysis failed: " + e.getMessage());
        }
    }
}
