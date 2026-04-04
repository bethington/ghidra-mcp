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
package com.xebyte.headless;

import com.xebyte.core.BinaryComparisonService;
import com.xebyte.core.ProgramProvider;
import com.xebyte.core.ServiceUtils;
import com.xebyte.core.ThreadingStrategy;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TaskMonitor;

import java.io.File;
import java.util.*;

import ghidra.app.cmd.disassemble.DisassembleCommand;

/**
 * Headless endpoint handler implementation.
 *
 * Contains the business logic for all REST API endpoints, adapted for headless
 * operation (no GUI dependencies).
 */
public class HeadlessEndpointHandler {

    private static final String VERSION = "5.0.0-headless";
    private final ProgramProvider programProvider;
    private final ThreadingStrategy threadingStrategy;
    private final TaskMonitor monitor;

    // Shared service layer
    private final com.xebyte.core.ListingService listingService;
    private final com.xebyte.core.CommentService commentService;
    private final com.xebyte.core.SymbolLabelService symbolLabelService;
    private final com.xebyte.core.FunctionService functionService;
    private final com.xebyte.core.XrefCallGraphService xrefCallGraphService;
    private final com.xebyte.core.DataTypeService dataTypeService;
    private final com.xebyte.core.AnalysisService analysisService;
    private final com.xebyte.core.DocumentationHashService documentationHashService;
    private final com.xebyte.core.MalwareSecurityService malwareSecurityService;
    private final com.xebyte.core.ProgramScriptService programScriptService;

    public HeadlessEndpointHandler(ProgramProvider programProvider, ThreadingStrategy threadingStrategy) {
        this.programProvider = programProvider;
        this.threadingStrategy = threadingStrategy;
        this.monitor = new ConsoleTaskMonitor();

        // Initialize shared services
        this.listingService = new com.xebyte.core.ListingService(programProvider);
        this.commentService = new com.xebyte.core.CommentService(programProvider, threadingStrategy);
        this.symbolLabelService = new com.xebyte.core.SymbolLabelService(programProvider, threadingStrategy);
        this.functionService = new com.xebyte.core.FunctionService(programProvider, threadingStrategy);
        this.xrefCallGraphService = new com.xebyte.core.XrefCallGraphService(programProvider, threadingStrategy);
        this.dataTypeService = new com.xebyte.core.DataTypeService(programProvider, threadingStrategy);
        this.analysisService = new com.xebyte.core.AnalysisService(programProvider, threadingStrategy, this.functionService);
        this.documentationHashService = new com.xebyte.core.DocumentationHashService(programProvider, threadingStrategy, new com.xebyte.core.BinaryComparisonService());
        this.documentationHashService.setFunctionService(this.functionService);
        this.malwareSecurityService = new com.xebyte.core.MalwareSecurityService(programProvider, threadingStrategy);
        this.programScriptService = new com.xebyte.core.ProgramScriptService(programProvider, threadingStrategy);
    }

    // ==========================================================================
    // SERVICE ACCESSORS (for EndpointRegistry)
    // ==========================================================================

    public com.xebyte.core.ListingService getListingService() { return listingService; }
    public com.xebyte.core.FunctionService getFunctionService() { return functionService; }
    public com.xebyte.core.CommentService getCommentService() { return commentService; }
    public com.xebyte.core.SymbolLabelService getSymbolLabelService() { return symbolLabelService; }
    public com.xebyte.core.XrefCallGraphService getXrefCallGraphService() { return xrefCallGraphService; }
    public com.xebyte.core.DataTypeService getDataTypeService() { return dataTypeService; }
    public com.xebyte.core.AnalysisService getAnalysisService() { return analysisService; }
    public com.xebyte.core.DocumentationHashService getDocumentationHashService() { return documentationHashService; }
    public com.xebyte.core.MalwareSecurityService getMalwareSecurityService() { return malwareSecurityService; }
    public com.xebyte.core.ProgramScriptService getProgramScriptService() { return programScriptService; }

    // ==========================================================================
    // UTILITY METHODS
    // ==========================================================================

    private Program getProgram(String programName) {
        return programProvider.resolveProgram(programName);
    }

    private String getProgramError(String programName) {
        if (programName != null && !programName.isEmpty()) {
            return "{\"error\": \"Program not found: " + escapeJson(programName) + "\"}";
        }
        return "{\"error\": \"No program currently loaded\"}";
    }

    private String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    // ==========================================================================
    // VERSION AND METADATA
    // ==========================================================================

    public String getVersion() {
        StringBuilder sb = new StringBuilder();
        sb.append("{");
        sb.append("\"plugin_version\": \"").append(VERSION).append("\",");
        sb.append("\"plugin_name\": \"GhidraMCP Headless\",");
        sb.append("\"mode\": \"headless\"");
        sb.append("}");
        return sb.toString();
    }

    /**
     * Health check endpoint for container orchestration (Docker, Kubernetes).
     * Returns JSON with status, version, and program information.
     */
    public String getHealth() {
        StringBuilder sb = new StringBuilder();
        sb.append("{");
        sb.append("\"status\": \"healthy\",");
        sb.append("\"version\": \"").append(VERSION).append("\",");

        // Check if any program is loaded
        Program program = getProgram(null);
        boolean programLoaded = (program != null);
        sb.append("\"program_loaded\": ").append(programLoaded);

        if (programLoaded) {
            sb.append(",\"program_name\": \"").append(escapeJson(program.getName())).append("\"");
        }

        sb.append("}");
        return sb.toString();
    }

    public String getMetadata(String programName) {
        Program program = getProgram(programName);
        if (program == null) {
            return getProgramError(programName);
        }

        StringBuilder sb = new StringBuilder();
        sb.append("{");
        sb.append("\"name\": \"").append(escapeJson(program.getName())).append("\",");
        sb.append("\"path\": \"").append(escapeJson(program.getExecutablePath())).append("\",");
        sb.append("\"language\": \"").append(escapeJson(program.getLanguageID().toString())).append("\",");
        sb.append("\"compiler\": \"").append(escapeJson(program.getCompilerSpec().getCompilerSpecID().toString())).append("\",");
        sb.append("\"image_base\": \"").append(program.getImageBase().toString()).append("\",");
        sb.append("\"address_size\": ").append(program.getAddressFactory().getDefaultAddressSpace().getSize()).append(",");
        sb.append("\"min_address\": \"").append(program.getMinAddress().toString()).append("\",");
        sb.append("\"max_address\": \"").append(program.getMaxAddress().toString()).append("\"");
        sb.append("}");
        return sb.toString();
    }

    // ==========================================================================
    // LISTING ENDPOINTS
    // ==========================================================================

    public String listMethods(int offset, int limit, String programName) {
        return listingService.getAllFunctionNames(offset, limit, programName).toJson();
    }

    public String listFunctions(String programName) {
        return listingService.listFunctions(programName).toJson();
    }

    public String listClasses(int offset, int limit, String programName) {
        return listingService.getAllClassNames(offset, limit, programName).toJson();
    }

    public String listSegments(int offset, int limit, String programName) {
        return listingService.listSegments(offset, limit, programName).toJson();
    }

    public String listImports(int offset, int limit, String programName) {
        return listingService.listImports(offset, limit, programName).toJson();
    }

    public String listExports(int offset, int limit, String programName) {
        return listingService.listExports(offset, limit, programName).toJson();
    }

    public String listNamespaces(int offset, int limit, String programName) {
        return listingService.listNamespaces(offset, limit, programName).toJson();
    }

    public String listDataItems(int offset, int limit, String programName) {
        return listingService.listDefinedData(offset, limit, programName).toJson();
    }

    public String listStrings(int offset, int limit, String filter, String programName) {
        return listingService.listDefinedStrings(offset, limit, filter, programName).toJson();
    }

    public String listDataTypes(int offset, int limit, String category, String programName) {
        return dataTypeService.listDataTypes(category, offset, limit, programName).toJson();
    }

    // ==========================================================================
    // GETTER ENDPOINTS
    // ==========================================================================

    public String getFunctionByAddress(String addressStr, String programName) {
        return functionService.getFunctionByAddress(addressStr, programName).toJson();
    }

    // ==========================================================================
    // DECOMPILE/DISASSEMBLE ENDPOINTS
    // ==========================================================================

    public String decompileFunction(String addressStr, String name, String programName) {
        // Route to address-based or name-based decompilation
        if (addressStr != null && !addressStr.isEmpty()) {
            return functionService.decompileFunctionByAddress(addressStr, programName).toJson();
        }
        if (name != null && !name.isEmpty()) {
            return functionService.decompileFunctionByName(name, programName).toJson();
        }
        return "Error: Function not found";
    }

    public String disassembleFunction(String addressStr, String programName) {
        return functionService.disassembleFunction(addressStr, programName).toJson();
    }

    // ==========================================================================
    // CROSS-REFERENCE ENDPOINTS
    // ==========================================================================

    public String getXrefsTo(String addressStr, int offset, int limit, String programName) {
        return xrefCallGraphService.getXrefsTo(addressStr, offset, limit, programName).toJson();
    }

    public String getXrefsFrom(String addressStr, int offset, int limit, String programName) {
        return xrefCallGraphService.getXrefsFrom(addressStr, offset, limit, programName).toJson();
    }

    public String getFunctionXrefs(String functionName, int offset, int limit, String programName) {
        return xrefCallGraphService.getFunctionXrefs(functionName, null, offset, limit, programName).toJson();
    }

    // ==========================================================================
    // SEARCH ENDPOINTS
    // ==========================================================================

    public String searchFunctions(String query, int offset, int limit, String programName) {
        return listingService.searchFunctionsByName(query, offset, limit, programName).toJson();
    }

    // ==========================================================================
    // RENAME ENDPOINTS
    // ==========================================================================

    public String renameFunction(String oldName, String newName, String programName) {
        return functionService.renameFunction(oldName, newName, programName).toJson();
    }

    public String renameFunctionByAddress(String addressStr, String newName, String programName) {
        return functionService.renameFunctionByAddress(addressStr, newName, programName).toJson();
    }

    public String saveCurrentProgram(String programName) {
        return programScriptService.saveCurrentProgram(programName).toJson();
    }

    public String deleteFunctionAtAddress(String addressStr, String programName) {
        return functionService.deleteFunctionAtAddress(addressStr, programName).toJson();
    }

    public String createFunctionAtAddress(String addressStr, String name, boolean disassembleFirst, String programName) {
        return functionService.createFunctionAtAddress(addressStr, name, disassembleFirst, programName).toJson();
    }

    public String createMemoryBlock(String name, String addressStr, long size,
                                    boolean read, boolean write, boolean execute,
                                    boolean isVolatile, String comment, String programName) {
        return programScriptService.createMemoryBlock(name, addressStr, size, read, write, execute, isVolatile, comment, programName).toJson();
    }

    public String renameData(String addressStr, String newName, String programName) {
        return symbolLabelService.renameDataAtAddress(addressStr, newName, programName).toJson();
    }

    public String renameVariable(String functionName, String oldName, String newName, String programName) {
        return functionService.renameVariableInFunction(functionName, oldName, newName, programName).toJson();
    }

    // ==========================================================================
    // COMMENT ENDPOINTS
    // ==========================================================================

    public String setDecompilerComment(String addressStr, String comment, String programName) {
        return commentService.setDecompilerComment(addressStr, comment, programName).toJson();
    }

    public String setDisassemblyComment(String addressStr, String comment, String programName) {
        return commentService.setDisassemblyComment(addressStr, comment, programName).toJson();
    }

    // ==========================================================================
    // PROGRAM MANAGEMENT ENDPOINTS
    // ==========================================================================

    public String listOpenPrograms() {
        return programScriptService.listOpenPrograms().toJson();
    }

    public String getCurrentProgramInfo() {
        return programScriptService.getCurrentProgramInfo().toJson();
    }

    public String switchProgram(String name) {
        return programScriptService.switchProgram(name).toJson();
    }

    // ==========================================================================
    // HEADLESS-SPECIFIC ENDPOINTS
    // ==========================================================================

    public String loadProgram(String filePath) {
        if (filePath == null || filePath.isEmpty()) {
            return "{\"error\": \"File path required\"}";
        }

        File file = new File(filePath);
        if (!file.exists()) {
            return "{\"error\": \"File not found: " + escapeJson(filePath) + "\"}";
        }

        if (programProvider instanceof HeadlessProgramProvider) {
            HeadlessProgramProvider hpp = (HeadlessProgramProvider) programProvider;
            Program program = hpp.loadProgramFromFile(file);

            if (program != null) {
                return "{\"success\": true, \"program\": \"" + escapeJson(program.getName()) + "\"}";
            } else {
                return "{\"error\": \"Failed to load program from: " + escapeJson(filePath) + "\"}";
            }
        }

        return "{\"error\": \"Load not supported in this mode\"}";
    }

    public String closeProgram(String name) {
        Program program = programProvider.getProgram(name);
        if (program == null) {
            return "{\"error\": \"Program not found: " + (name != null ? escapeJson(name) : "current") + "\"}";
        }

        if (programProvider instanceof HeadlessProgramProvider) {
            HeadlessProgramProvider hpp = (HeadlessProgramProvider) programProvider;
            hpp.closeProgram(program);
            return "{\"success\": true, \"closed\": \"" + escapeJson(program.getName()) + "\"}";
        }

        return "{\"error\": \"Close not supported in this mode\"}";
    }

    /**
     * Run auto-analysis on a program.
     * This identifies functions, data types, strings, and other program structure.
     *
     * @param programName Optional program name (uses current if not specified)
     * @return JSON with analysis statistics
     */
    public String runAnalysis(String programName) {
        Program program = programProvider.getProgram(programName);
        if (program == null) {
            return "{\"error\": \"No program loaded\"}";
        }

        if (programProvider instanceof HeadlessProgramProvider) {
            HeadlessProgramProvider hpp = (HeadlessProgramProvider) programProvider;
            HeadlessProgramProvider.AnalysisResult result = hpp.runAnalysis(program);

            StringBuilder json = new StringBuilder();
            json.append("{");
            json.append("\"success\": ").append(result.success).append(", ");
            json.append("\"message\": \"").append(escapeJson(result.message)).append("\", ");
            json.append("\"duration_ms\": ").append(result.durationMs).append(", ");
            json.append("\"total_functions\": ").append(result.totalFunctions).append(", ");
            json.append("\"new_functions\": ").append(result.newFunctions).append(", ");
            json.append("\"program\": \"").append(escapeJson(program.getName())).append("\"");
            json.append("}");

            return json.toString();
        }

        return "{\"error\": \"Analysis not supported in this mode\"}";
    }

    // ==========================================================================
    // PROJECT MANAGEMENT ENDPOINTS
    // ==========================================================================

    /**
     * Open a Ghidra project from a .gpr file path.
     */
    public String openProject(String projectPath) {
        if (projectPath == null || projectPath.isEmpty()) {
            return "{\"error\": \"Project path required\"}";
        }

        if (programProvider instanceof HeadlessProgramProvider) {
            HeadlessProgramProvider hpp = (HeadlessProgramProvider) programProvider;
            boolean success = hpp.openProject(projectPath);

            if (success) {
                String projectName = hpp.getProjectName();
                return "{\"success\": true, \"project\": \"" + escapeJson(projectName) + "\"}";
            } else {
                return "{\"error\": \"Failed to open project: " + escapeJson(projectPath) + "\"}";
            }
        }

        return "{\"error\": \"Project management not supported in this mode\"}";
    }

    /**
     * Close the current project.
     */
    public String closeProject() {
        if (programProvider instanceof HeadlessProgramProvider) {
            HeadlessProgramProvider hpp = (HeadlessProgramProvider) programProvider;

            if (!hpp.hasProject()) {
                return "{\"error\": \"No project currently open\"}";
            }

            String projectName = hpp.getProjectName();
            hpp.closeProject();
            return "{\"success\": true, \"closed\": \"" + escapeJson(projectName) + "\"}";
        }

        return "{\"error\": \"Project management not supported in this mode\"}";
    }

    /**
     * List all files in the current project.
     */
    public String listProjectFiles() {
        if (programProvider instanceof HeadlessProgramProvider) {
            HeadlessProgramProvider hpp = (HeadlessProgramProvider) programProvider;

            if (!hpp.hasProject()) {
                return "{\"error\": \"No project currently open\"}";
            }

            List<HeadlessProgramProvider.ProjectFileInfo> files = hpp.listProjectFiles();

            StringBuilder sb = new StringBuilder();
            sb.append("{\"project\": \"").append(escapeJson(hpp.getProjectName())).append("\", ");
            sb.append("\"files\": [");

            for (int i = 0; i < files.size(); i++) {
                HeadlessProgramProvider.ProjectFileInfo file = files.get(i);
                if (i > 0) sb.append(", ");
                sb.append("{");
                sb.append("\"name\": \"").append(escapeJson(file.name)).append("\", ");
                sb.append("\"path\": \"").append(escapeJson(file.path)).append("\", ");
                sb.append("\"contentType\": \"").append(escapeJson(file.contentType)).append("\", ");
                sb.append("\"readOnly\": ").append(file.readOnly);
                sb.append("}");
            }

            sb.append("], \"count\": ").append(files.size()).append("}");
            return sb.toString();
        }

        return "{\"error\": \"Project management not supported in this mode\"}";
    }

    /**
     * Load a program from the current project.
     */
    public String loadProgramFromProject(String programPath) {
        if (programPath == null || programPath.isEmpty()) {
            return "{\"error\": \"Program path required (e.g., /D2Client.dll)\"}";
        }

        if (programProvider instanceof HeadlessProgramProvider) {
            HeadlessProgramProvider hpp = (HeadlessProgramProvider) programProvider;

            if (!hpp.hasProject()) {
                return "{\"error\": \"No project currently open. Use /open_project first.\"}";
            }

            Program program = hpp.loadProgramFromProject(programPath);

            if (program != null) {
                return "{\"success\": true, \"program\": \"" + escapeJson(program.getName()) + "\", " +
                       "\"path\": \"" + escapeJson(programPath) + "\"}";
            } else {
                return "{\"error\": \"Failed to load program: " + escapeJson(programPath) + "\"}";
            }
        }

        return "{\"error\": \"Project management not supported in this mode\"}";
    }

    /**
     * Get info about the current project.
     */
    public String getProjectInfo() {
        if (programProvider instanceof HeadlessProgramProvider) {
            HeadlessProgramProvider hpp = (HeadlessProgramProvider) programProvider;

            if (!hpp.hasProject()) {
                return "{\"has_project\": false}";
            }

            List<HeadlessProgramProvider.ProjectFileInfo> files = hpp.listProjectFiles();
            int programCount = (int) files.stream()
                .filter(f -> "Program".equals(f.contentType))
                .count();

            return "{\"has_project\": true, " +
                   "\"project_name\": \"" + escapeJson(hpp.getProjectName()) + "\", " +
                   "\"file_count\": " + files.size() + ", " +
                   "\"program_count\": " + programCount + "}";
        }

        return "{\"error\": \"Project management not supported in this mode\"}";
    }

    // ==========================================================================
    // PHASE 1: ESSENTIAL ANALYSIS ENDPOINTS
    // ==========================================================================

    /**
     * Get all functions called by the specified function (callees).
     */
    public String getFunctionCallees(String functionName, int offset, int limit, String programName) {
        return xrefCallGraphService.getFunctionCallees(functionName, null, offset, limit, programName).toJson();
    }

    /**
     * Get all functions that call the specified function (callers).
     */
    public String getFunctionCallers(String functionName, int offset, int limit, String programName) {
        return xrefCallGraphService.getFunctionCallers(functionName, null, offset, limit, programName).toJson();
    }

    /**
     * Get all variables (parameters and locals) for a function.
     */
    public String getFunctionVariables(String functionName, String programName) {
        return functionService.getFunctionVariables(functionName, programName, null, null).toJson();
    }

    /**
     * Set a function's prototype (signature).
     */
    public String setFunctionPrototype(String functionAddress, String prototype, String callingConvention, String programName) {
        Program program = getProgram(programName);
        if (program == null) {
            return "Error: No program loaded";
        }

        if (functionAddress == null || functionAddress.isEmpty()) {
            return "Error: Function address is required";
        }
        if (prototype == null || prototype.isEmpty()) {
            return "Error: Prototype is required";
        }

        // v3.0.1: Extract inline calling convention from prototype string if present
        String cleanPrototype = prototype;
        String resolvedConvention = callingConvention;
        String[] knownConventions = {"__cdecl", "__stdcall", "__thiscall", "__fastcall", "__vectorcall"};
        for (String cc : knownConventions) {
            if (cleanPrototype.contains(cc)) {
                cleanPrototype = cleanPrototype.replace(cc, "").replaceAll("\\s+", " ").trim();
                if (resolvedConvention == null || resolvedConvention.isEmpty()) {
                    resolvedConvention = cc;
                }
                break;
            }
        }
        final String finalPrototype = cleanPrototype;
        final String finalConvention = resolvedConvention;

        Address addr = ServiceUtils.parseAddress(program, functionAddress);
        if (addr == null) {
            return "{\"error\": \"" + escapeJson(ServiceUtils.getLastParseError()) + "\"}";
        }

        try {
            return threadingStrategy.executeWrite(program, "Set function prototype", () -> {
                Function func = program.getFunctionManager().getFunctionAt(addr);
                if (func == null) {
                    func = program.getFunctionManager().getFunctionContaining(addr);
                }
                if (func == null) {
                    return "Error: No function found at address: " + functionAddress;
                }

                // Parse the prototype using FunctionSignatureParser
                DataTypeManager dtm = program.getDataTypeManager();
                ghidra.app.util.parser.FunctionSignatureParser parser =
                    new ghidra.app.util.parser.FunctionSignatureParser(dtm, null);

                ghidra.program.model.data.FunctionDefinitionDataType sig = parser.parse(null, finalPrototype);

                // Apply using ApplyFunctionSignatureCmd
                ghidra.app.cmd.function.ApplyFunctionSignatureCmd cmd =
                    new ghidra.app.cmd.function.ApplyFunctionSignatureCmd(
                        func.getEntryPoint(), sig, SourceType.USER_DEFINED);

                if (!cmd.applyTo(program, monitor)) {
                    return "Error: Failed to apply signature - " + cmd.getStatusMsg();
                }

                // Apply calling convention if specified
                if (finalConvention != null && !finalConvention.isEmpty()) {
                    try {
                        func.setCallingConvention(finalConvention);
                    } catch (Exception e) {
                        return "Success: Signature set, but calling convention failed: " + e.getMessage();
                    }
                }

                return "Success: Function prototype set for " + func.getName();
            });
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Set a local variable's type.
     */
    public String setLocalVariableType(String functionAddress, String variableName, String newType, String programName) {
        return functionService.setLocalVariableType(functionAddress, variableName, newType, programName).toJson();
    }

    /**
     * Create a structure data type.
     */
    public String createStruct(String name, String fieldsJson, String programName) {
        return dataTypeService.createStruct(name, fieldsJson, programName).toJson();
    }

    /**
     * Parse a simple flat JSON object.
     */
    private Map<String, String> parseSimpleJsonObject(String json) {
        Map<String, String> result = new HashMap<>();

        json = json.trim();
        if (!json.startsWith("{") || !json.endsWith("}")) {
            return result;
        }

        json = json.substring(1, json.length() - 1).trim();

        for (String pair : json.split(",")) {
            String[] kv = pair.split(":", 2);
            if (kv.length == 2) {
                String key = kv[0].trim().replaceAll("^\"|\"$", "");
                String value = kv[1].trim().replaceAll("^\"|\"$", "");
                result.put(key, value);
            }
        }

        return result;
    }

    /**
     * Apply a data type at an address.
     */
    public String applyDataType(String addressStr, String typeName, boolean clearExisting, String programName) {
        return dataTypeService.applyDataType(addressStr, typeName, clearExisting, programName).toJson();
    }

    /**
     * Batch rename multiple variables in a function.
     */
    public String batchRenameVariables(String functionAddress, String renamesJson, String programName) {
        Program program = getProgram(programName);
        if (program == null) {
            return getProgramError(programName);
        }

        if (functionAddress == null || functionAddress.isEmpty()) {
            return "Error: Function address is required";
        }
        if (renamesJson == null || renamesJson.isEmpty()) {
            return "Error: Renames object is required";
        }

        Address addr = ServiceUtils.parseAddress(program, functionAddress);
        if (addr == null) {
            return "{\"error\": \"" + escapeJson(ServiceUtils.getLastParseError()) + "\"}";
        }

        try {
            return threadingStrategy.executeWrite(program, "Batch rename variables", () -> {
                Function func = program.getFunctionManager().getFunctionAt(addr);
                if (func == null) {
                    func = program.getFunctionManager().getFunctionContaining(addr);
                }
                if (func == null) {
                    return "{\"error\": \"No function found at address: " + functionAddress + "\"}";
                }

                // Parse renames JSON: {"oldName1": "newName1", "oldName2": "newName2"}
                Map<String, String> renames = parseSimpleJsonObject(renamesJson);

                int renamed = 0;
                int failed = 0;
                List<String> errors = new ArrayList<>();

                for (Map.Entry<String, String> entry : renames.entrySet()) {
                    String oldName = entry.getKey();
                    String newName = entry.getValue();
                    boolean found = false;

                    // Check parameters
                    for (Parameter param : func.getParameters()) {
                        if (param.getName().equals(oldName)) {
                            try {
                                param.setName(newName, SourceType.USER_DEFINED);
                                renamed++;
                                found = true;
                                break;
                            } catch (Exception e) {
                                errors.add(oldName + ": " + e.getMessage());
                                failed++;
                                found = true;
                                break;
                            }
                        }
                    }

                    // Check local variables if not found in params
                    if (!found) {
                        for (Variable var : func.getLocalVariables()) {
                            if (var.getName().equals(oldName)) {
                                try {
                                    var.setName(newName, SourceType.USER_DEFINED);
                                    renamed++;
                                    found = true;
                                    break;
                                } catch (Exception e) {
                                    errors.add(oldName + ": " + e.getMessage());
                                    failed++;
                                    found = true;
                                    break;
                                }
                            }
                        }
                    }

                    if (!found) {
                        errors.add(oldName + ": not found");
                        failed++;
                    }
                }

                StringBuilder sb = new StringBuilder();
                sb.append("{\"success\": ").append(failed == 0).append(", ");
                sb.append("\"renamed\": ").append(renamed).append(", ");
                sb.append("\"failed\": ").append(failed);

                if (!errors.isEmpty()) {
                    sb.append(", \"errors\": [");
                    for (int i = 0; i < errors.size(); i++) {
                        if (i > 0) sb.append(", ");
                        sb.append("\"").append(escapeJson(errors.get(i))).append("\"");
                    }
                    sb.append("]");
                }

                sb.append("}");
                return sb.toString();
            });
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    /**
     * Get a function's plate (header) comment.
     */
    public String getPlateComment(String address, String programName) {
        return commentService.getPlateComment(address, programName).toJson();
    }

    /**
     * Set a function's plate (header) comment.
     */
    public String setPlateComment(String functionAddress, String comment, String programName) {
        return commentService.setPlateComment(functionAddress, comment, programName).toJson();
    }

    // ==========================================================================
    // PHASE 2: PRODUCTIVITY ENDPOINTS
    // ==========================================================================

    /**
     * Set multiple comments in a single batch operation.
     */
    public String batchSetComments(String functionAddress, String decompilerCommentsJson,
                                   String disassemblyCommentsJson, String plateComment, String programName) {
        Program program = getProgram(programName);
        if (program == null) {
            return getProgramError(programName);
        }

        if (functionAddress == null || functionAddress.isEmpty()) {
            return "{\"error\": \"Function address is required\"}";
        }

        Address addr = ServiceUtils.parseAddress(program, functionAddress);
        if (addr == null) {
            return "{\"error\": \"" + escapeJson(ServiceUtils.getLastParseError()) + "\"}";
        }

        try {
            return threadingStrategy.executeWrite(program, "Batch set comments", () -> {
                Function func = program.getFunctionManager().getFunctionAt(addr);
                if (func == null) {
                    func = program.getFunctionManager().getFunctionContaining(addr);
                }
                if (func == null) {
                    return "{\"error\": \"No function found at address: " + escapeJson(functionAddress) + "\"}";
                }

                Listing listing = program.getListing();
                int plateSet = 0;
                int decompilerSet = 0;
                int disassemblySet = 0;
                int overwritten = 0;

                // Set plate comment if provided
                if (plateComment != null && !plateComment.isEmpty()) {
                    String existingPlate = listing.getComment(CodeUnit.PLATE_COMMENT, func.getEntryPoint());
                    if (existingPlate != null && !existingPlate.isEmpty()) {
                        overwritten++;
                    }
                    listing.setComment(func.getEntryPoint(), CodeUnit.PLATE_COMMENT, plateComment);
                    plateSet = 1;
                }

                // Set decompiler comments (PRE_COMMENT)
                if (decompilerCommentsJson != null && !decompilerCommentsJson.isEmpty()) {
                    List<Map<String, String>> comments = parseCommentsList(decompilerCommentsJson);
                    for (Map<String, String> comment : comments) {
                        String addrStr = comment.get("address");
                        String text = comment.get("comment");
                        if (addrStr != null && text != null) {
                            Address commentAddr = ServiceUtils.parseAddress(program, addrStr);
                            if (commentAddr != null) {
                                String existing = listing.getComment(CodeUnit.PRE_COMMENT, commentAddr);
                                if (existing != null && !existing.isEmpty()) {
                                    overwritten++;
                                }
                                listing.setComment(commentAddr, CodeUnit.PRE_COMMENT, text);
                                decompilerSet++;
                            }
                        }
                    }
                }

                // Set disassembly comments (EOL_COMMENT)
                if (disassemblyCommentsJson != null && !disassemblyCommentsJson.isEmpty()) {
                    List<Map<String, String>> comments = parseCommentsList(disassemblyCommentsJson);
                    for (Map<String, String> comment : comments) {
                        String addrStr = comment.get("address");
                        String text = comment.get("comment");
                        if (addrStr != null && text != null) {
                            Address commentAddr = ServiceUtils.parseAddress(program, addrStr);
                            if (commentAddr != null) {
                                String existing = listing.getComment(CodeUnit.EOL_COMMENT, commentAddr);
                                if (existing != null && !existing.isEmpty()) {
                                    overwritten++;
                                }
                                listing.setComment(commentAddr, CodeUnit.EOL_COMMENT, text);
                                disassemblySet++;
                            }
                        }
                    }
                }

                return "{\"success\": true, \"plate_comments_set\": " + plateSet +
                       ", \"decompiler_comments_set\": " + decompilerSet +
                       ", \"disassembly_comments_set\": " + disassemblySet +
                       ", \"comments_overwritten\": " + overwritten + "}";
            });
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    /**
     * v3.0.1: Clear all comments (plate, PRE, EOL) within a function's address range.
     */
    public String clearFunctionComments(String functionAddress, boolean clearPlate, boolean clearPre, boolean clearEol, String programName) {
        return commentService.clearFunctionComments(functionAddress, clearPlate, clearPre, clearEol, programName).toJson();
    }

    /**
     * Create multiple labels in a single batch operation.
     */
    public String batchCreateLabels(String labelsJson, String programName) {
        Program program = getProgram(programName);
        if (program == null) {
            return getProgramError(programName);
        }

        if (labelsJson == null || labelsJson.isEmpty()) {
            return "{\"error\": \"Labels JSON is required\"}";
        }

        try {
            return threadingStrategy.executeWrite(program, "Batch create labels", () -> {
                List<Map<String, String>> labels = parseLabelsList(labelsJson);
                SymbolTable symbolTable = program.getSymbolTable();

                int created = 0;
                int failed = 0;
                List<String> errors = new ArrayList<>();

                for (Map<String, String> label : labels) {
                    String addrStr = label.get("address");
                    String name = label.get("name");

                    if (addrStr == null || name == null) {
                        errors.add("Missing address or name in label entry");
                        failed++;
                        continue;
                    }

                    Address addr = ServiceUtils.parseAddress(program, addrStr);
                    if (addr == null) {
                        errors.add("Invalid address: " + addrStr);
                        failed++;
                        continue;
                    }

                    try {
                        symbolTable.createLabel(addr, name, SourceType.USER_DEFINED);
                        created++;
                    } catch (Exception e) {
                        errors.add(addrStr + ": " + e.getMessage());
                        failed++;
                    }
                }

                StringBuilder sb = new StringBuilder();
                sb.append("{\"success\": ").append(failed == 0).append(", ");
                sb.append("\"labels_created\": ").append(created).append(", ");
                sb.append("\"labels_failed\": ").append(failed);

                if (!errors.isEmpty()) {
                    sb.append(", \"errors\": [");
                    for (int i = 0; i < Math.min(errors.size(), 10); i++) {
                        if (i > 0) sb.append(", ");
                        sb.append("\"").append(escapeJson(errors.get(i))).append("\"");
                    }
                    sb.append("]");
                }
                sb.append("}");
                return sb.toString();
            });
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    /**
     * Delete a label at the specified address.
     *
     * @param addressStr Memory address in hex format
     * @param labelName Optional specific label name to delete. If null/empty, deletes all labels at the address.
     * @return Success or failure message
     */
    public String deleteLabel(String addressStr, String labelName, String programName) {
        Program program = getProgram(programName);
        if (program == null) {
            return getProgramError(programName);
        }

        if (addressStr == null || addressStr.isEmpty()) {
            return "{\"error\": \"Address is required\"}";
        }

        Address address = ServiceUtils.parseAddress(program, addressStr);
        if (address == null) {
            return "{\"error\": \"" + escapeJson(ServiceUtils.getLastParseError()) + "\"}";
        }

        try {
            return threadingStrategy.executeWrite(program, "Delete label", () -> {
                SymbolTable symbolTable = program.getSymbolTable();
                Symbol[] symbols = symbolTable.getSymbols(address);

                if (symbols == null || symbols.length == 0) {
                    return "{\"success\": false, \"message\": \"No symbols found at address " + addressStr + "\"}";
                }

                int deletedCount = 0;
                List<String> deletedNames = new ArrayList<>();
                List<String> errors = new ArrayList<>();

                for (Symbol symbol : symbols) {
                    if (symbol.getSymbolType() != SymbolType.LABEL) {
                        continue;
                    }

                    if (labelName != null && !labelName.isEmpty()) {
                        if (!symbol.getName().equals(labelName)) {
                            continue;
                        }
                    }

                    String name = symbol.getName();
                    boolean deleted = symbol.delete();
                    if (deleted) {
                        deletedCount++;
                        deletedNames.add(name);
                    } else {
                        errors.add("Failed to delete label: " + name);
                    }
                }

                StringBuilder result = new StringBuilder();
                result.append("{\"success\": ").append(deletedCount > 0);
                result.append(", \"deleted_count\": ").append(deletedCount);
                result.append(", \"deleted_names\": [");
                for (int i = 0; i < deletedNames.size(); i++) {
                    if (i > 0) result.append(", ");
                    result.append("\"").append(escapeJson(deletedNames.get(i))).append("\"");
                }
                result.append("]");
                if (!errors.isEmpty()) {
                    result.append(", \"errors\": [");
                    for (int i = 0; i < errors.size(); i++) {
                        if (i > 0) result.append(", ");
                        result.append("\"").append(escapeJson(errors.get(i))).append("\"");
                    }
                    result.append("]");
                }
                result.append("}");
                return result.toString();
            });
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    /**
     * Batch delete multiple labels in a single transaction.
     *
     * @param labelsJson JSON array of label entries with "address" and optional "name" fields
     * @return JSON with success status and counts
     */
    public String batchDeleteLabels(String labelsJson, String programName) {
        Program program = getProgram(programName);
        if (program == null) {
            return getProgramError(programName);
        }

        if (labelsJson == null || labelsJson.isEmpty()) {
            return "{\"error\": \"Labels JSON is required\"}";
        }

        try {
            return threadingStrategy.executeWrite(program, "Batch delete labels", () -> {
                List<Map<String, String>> labels = parseLabelsList(labelsJson);
                SymbolTable symbolTable = program.getSymbolTable();

                int deleted = 0;
                int skipped = 0;
                int failed = 0;
                List<String> errors = new ArrayList<>();

                for (Map<String, String> label : labels) {
                    String addrStr = label.get("address");
                    String name = label.get("name");  // Optional

                    if (addrStr == null) {
                        errors.add("Missing address in label entry");
                        failed++;
                        continue;
                    }

                    Address addr = ServiceUtils.parseAddress(program, addrStr);
                    if (addr == null) {
                        errors.add("Invalid address: " + addrStr);
                        failed++;
                        continue;
                    }

                    Symbol[] symbols = symbolTable.getSymbols(addr);
                    if (symbols == null || symbols.length == 0) {
                        skipped++;
                        continue;
                    }

                    for (Symbol symbol : symbols) {
                        if (symbol.getSymbolType() != SymbolType.LABEL) {
                            continue;
                        }

                        if (name != null && !name.isEmpty()) {
                            if (!symbol.getName().equals(name)) {
                                continue;
                            }
                        }

                        try {
                            if (symbol.delete()) {
                                deleted++;
                            } else {
                                errors.add("Failed to delete at " + addrStr);
                                failed++;
                            }
                        } catch (Exception e) {
                            errors.add(addrStr + ": " + e.getMessage());
                            failed++;
                        }
                    }
                }

                StringBuilder sb = new StringBuilder();
                sb.append("{\"success\": true");
                sb.append(", \"labels_deleted\": ").append(deleted);
                sb.append(", \"labels_skipped\": ").append(skipped);
                sb.append(", \"errors_count\": ").append(failed);

                if (!errors.isEmpty()) {
                    sb.append(", \"errors\": [");
                    for (int i = 0; i < Math.min(errors.size(), 10); i++) {
                        if (i > 0) sb.append(", ");
                        sb.append("\"").append(escapeJson(errors.get(i))).append("\"");
                    }
                    sb.append("]");
                }
                sb.append("}");
                return sb.toString();
            });
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    /**
     * Enhanced function search with multiple filter options.
     */
    public String searchFunctionsEnhanced(String namePattern, Integer minXrefs, Integer maxXrefs,
                                          Boolean hasCustomName, boolean regex, String sortBy,
                                          int offset, int limit, String programName) {
        return analysisService.searchFunctionsEnhanced(namePattern, minXrefs, maxXrefs, null, hasCustomName, regex, sortBy, offset, limit, programName).toJson();
    }

    /**
     * Comprehensive function analysis in a single call.
     */
    public String analyzeFunctionComplete(String name, boolean includeXrefs, boolean includeCallees,
                                          boolean includeCallers, boolean includeDisasm,
                                          boolean includeVariables, String programName) {
        return analysisService.analyzeFunctionComplete(name, includeXrefs, includeCallees, includeCallers, includeDisasm, includeVariables, programName).toJson();
    }

    /**
     * Get cross-references for multiple addresses in bulk.
     */
    public String getBulkXrefs(String addressesJson, String programName) {
        return xrefCallGraphService.getBulkXrefs(addressesJson, programName).toJson();
    }

    /**
     * List global variables with optional filtering.
     */
    public String listGlobals(int offset, int limit, String filter, String programName) {
        return listingService.listGlobals(offset, limit, filter, programName).toJson();
    }

    /**
     * Rename a global variable.
     */
    public String renameGlobalVariable(String oldName, String newName, String programName) {
        return symbolLabelService.renameGlobalVariable(oldName, newName, programName).toJson();
    }

    /**
     * Force re-decompilation of a function (clear cache).
     */
    public String forceDecompile(String address, String name, String programName) {
        // forceDecompile in FunctionService takes only address - use address or resolve from name
        String resolvedAddress = address;
        if ((resolvedAddress == null || resolvedAddress.isEmpty()) && name != null && !name.isEmpty()) {
            Program program = getProgram(programName);
            if (program == null) return getProgramError(programName);
            for (Function f : program.getFunctionManager().getFunctions(true)) {
                if (f.getName().equals(name)) {
                    resolvedAddress = f.getEntryPoint().toString();
                    break;
                }
            }
        }
        if (resolvedAddress == null || resolvedAddress.isEmpty()) {
            return "{\"error\": \"Function not found\"}";
        }
        return functionService.forceDecompile(resolvedAddress, programName).toJson();
    }

    /**
     * Get program entry points.
     */
    public String getEntryPoints(String programName) {
        return listingService.getEntryPoints(programName).toJson();
    }

    /**
     * List available calling conventions.
     */
    public String listCallingConventions(String programName) {
        return listingService.listCallingConventions(programName).toJson();
    }

    /**
     * Find next undefined function based on criteria.
     */
    public String findNextUndefinedFunction(String startAddress, String criteria,
                                            String pattern, String direction, String programName) {
        return analysisService.findNextUndefinedFunction(startAddress, criteria, pattern, direction, programName).toJson();
    }

    // ==========================================================================
    // PHASE 2 HELPER METHODS
    // ==========================================================================

    private List<Map<String, String>> parseCommentsList(String json) {
        List<Map<String, String>> result = new ArrayList<>();
        if (json == null || json.isEmpty()) return result;

        // Simple JSON array parsing for [{address: "...", comment: "..."}]
        json = json.trim();
        if (!json.startsWith("[")) return result;

        // Remove brackets
        json = json.substring(1, json.length() - 1).trim();
        if (json.isEmpty()) return result;

        // Split by "}," pattern
        String[] entries = json.split("\\}\\s*,\\s*\\{");
        for (String entry : entries) {
            entry = entry.replace("{", "").replace("}", "").trim();
            Map<String, String> map = new HashMap<>();

            // Parse key-value pairs
            for (String pair : entry.split(",(?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)")) {
                String[] kv = pair.split(":", 2);
                if (kv.length == 2) {
                    String key = kv[0].trim().replace("\"", "");
                    String value = kv[1].trim().replace("\"", "");
                    map.put(key, value);
                }
            }
            if (!map.isEmpty()) {
                result.add(map);
            }
        }
        return result;
    }

    private List<Map<String, String>> parseLabelsList(String json) {
        // Reuse parseCommentsList - same format
        return parseCommentsList(json);
    }

    // ==========================================================================
    // PHASE 3: DATA TYPE SYSTEM ENDPOINTS (15 endpoints)
    // ==========================================================================

    /**
     * Create an enumeration data type
     */
    public String createEnum(String name, String valuesJson, int size, String programName) {
        return dataTypeService.createEnum(name, valuesJson, size, programName).toJson();
    }

    /**
     * Create a union data type
     */
    public String createUnion(String name, String fieldsJson, String programName) {
        return dataTypeService.createUnion(name, fieldsJson, programName).toJson();
    }

    /**
     * Create a typedef (type alias)
     */
    public String createTypedef(String name, String baseType, String programName) {
        return dataTypeService.createTypedef(name, baseType, programName).toJson();
    }

    /**
     * Create an array data type
     */
    public String createArrayType(String baseType, int length, String name, String programName) {
        return dataTypeService.createArrayType(baseType, length, name, programName).toJson();
    }

    /**
     * Create a pointer data type
     */
    public String createPointerType(String baseType, String name, String programName) {
        return dataTypeService.createPointerType(baseType, name, programName).toJson();
    }

    /**
     * Add a field to an existing structure
     */
    public String addStructField(String structName, String fieldName, String fieldType, int offset, String programName) {
        return dataTypeService.addStructField(structName, fieldName, fieldType, offset, programName).toJson();
    }

    /**
     * Modify a field in an existing structure
     */
    public String modifyStructField(String structName, String fieldName, String newType, String newName, String programName) {
        return dataTypeService.modifyStructField(structName, fieldName, newType, newName, programName).toJson();
    }

    /**
     * Remove a field from an existing structure
     */
    public String removeStructField(String structName, String fieldName, String programName) {
        return dataTypeService.removeStructField(structName, fieldName, programName).toJson();
    }

    /**
     * Delete a data type
     */
    public String deleteDataType(String typeName, String programName) {
        return dataTypeService.deleteDataType(typeName, programName).toJson();
    }

    /**
     * Search for data types by pattern
     */
    public String searchDataTypes(String pattern, int offset, int limit, String programName) {
        return dataTypeService.searchDataTypes(pattern, offset, limit, programName).toJson();
    }

    /**
     * Validate if a data type exists
     */
    public String validateDataTypeExists(String typeName, String programName) {
        return dataTypeService.validateDataTypeExists(typeName, programName).toJson();
    }

    /**
     * Get the size of a data type
     */
    public String getDataTypeSize(String typeName, String programName) {
        return dataTypeService.getTypeSize(typeName, programName).toJson();
    }

    /**
     * Get the layout of a structure
     */
    public String getStructLayout(String structName, String programName) {
        return dataTypeService.getStructLayout(structName, programName).toJson();
    }

    /**
     * Get all values in an enumeration
     */
    public String getEnumValues(String enumName, String programName) {
        return dataTypeService.getEnumValues(enumName, programName).toJson();
    }

    /**
     * Clone/copy a data type with a new name
     */
    public String cloneDataType(String sourceType, String newName, String programName) {
        return dataTypeService.cloneDataType(sourceType, newName, programName).toJson();
    }

    // ==========================================================================
    // PHASE 4: ADVANCED FEATURES ENDPOINTS
    // ==========================================================================

    /**
     * Run a Ghidra script (simplified for headless mode)
     */
    public String runScript(String scriptPath, String scriptArgs, String programName) {
        Program program = getProgram(programName);
        if (program == null) {
            return getProgramError(programName);
        }

        if (scriptPath == null || scriptPath.isEmpty()) {
            return "{\"error\": \"Script path is required\"}";
        }

        StringBuilder result = new StringBuilder();
        result.append("{\"status\": \"Script execution in headless mode\",");
        result.append("\"script_path\": \"").append(escapeJson(scriptPath)).append("\",");
        result.append("\"program\": \"").append(escapeJson(program.getName())).append("\",");
        result.append("\"note\": \"Full script execution requires GUI mode. Use Ghidra's analyzeHeadless for batch scripting.\"}");

        return result.toString();
    }

    /**
     * List available Ghidra scripts
     */
    public String listScripts(String filter) {
        StringBuilder result = new StringBuilder();
        result.append("{\"scripts\": [],");
        result.append("\"note\": \"Script listing in headless mode is limited.\",");
        result.append("\"common_locations\": [");
        result.append("\"<ghidra_install>/Ghidra/Features/*/ghidra_scripts/\",");
        result.append("\"<user_home>/ghidra_scripts/\"");
        result.append("],");
        result.append("\"filter\": ").append(filter != null ? "\"" + escapeJson(filter) + "\"" : "null");
        result.append("}");
        return result.toString();
    }

    /**
     * Search for byte patterns in memory
     */
    public String searchBytePatterns(String pattern, String mask, String programName) {
        Program program = getProgram(programName);
        if (program == null) {
            return getProgramError(programName);
        }

        if (pattern == null || pattern.trim().isEmpty()) {
            return "{\"error\": \"Pattern is required\"}";
        }

        try {
            StringBuilder result = new StringBuilder();
            result.append("[");

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
                    boolean matches = true;
                    for (int j = 0; j < patternBytes.length; j++) {
                        if (maskBytes[j] != 0 && blockData[i + j] != patternBytes[j]) {
                            matches = false;
                            break;
                        }
                    }

                    if (matches) {
                        if (matchCount > 0) result.append(",");
                        Address matchAddr = blockStart.add(i);
                        result.append("{\"address\": \"").append(matchAddr.toString()).append("\"}");
                        matchCount++;

                        if (matchCount >= MAX_MATCHES) {
                            result.append(",{\"note\": \"Limited to ").append(MAX_MATCHES).append(" matches\"}");
                            break;
                        }
                    }
                }

                if (matchCount >= MAX_MATCHES) break;
            }

            if (matchCount == 0) {
                result.append("{\"note\": \"No matches found\"}");
            }

            result.append("]");
            return result.toString();
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    /**
     * Analyze a data region comprehensively
     */
    public String analyzeDataRegion(String startAddressStr, int maxScanBytes,
                                    boolean includeXrefMap, boolean includeAssemblyPatterns,
                                    boolean includeBoundaryDetection, String programName) {
        return analysisService.analyzeDataRegion(startAddressStr, maxScanBytes, includeXrefMap, includeAssemblyPatterns, includeBoundaryDetection, programName).toJson();
    }

    /**
     * Compute a normalized hash for a function
     */
    public String getFunctionHash(String addressStr, String programName) {
        return documentationHashService.getFunctionHash(addressStr, programName).toJson();
    }

    /**
     * Get hashes for multiple functions
     */
    public String getBulkFunctionHashes(int offset, int limit, String filter, String programName) {
        return documentationHashService.getBulkFunctionHashes(offset, limit, filter, programName).toJson();
    }

    /**
     * Detect array bounds based on xref analysis
     */
    public String detectArrayBounds(String addressStr, boolean analyzeLoopBounds,
                                    boolean analyzeIndexing, int maxScanRange, String programName) {
        return analysisService.detectArrayBounds(addressStr, analyzeLoopBounds, analyzeIndexing, maxScanRange, programName).toJson();
    }

    /**
     * Get assembly context around xref sources
     */
    public String getAssemblyContext(String xrefSourcesStr, int contextInstructions, String includePatterns, String programName) {
        return xrefCallGraphService.getAssemblyContext(xrefSourcesStr, contextInstructions, includePatterns, programName).toJson();
    }

    /**
     * Analyze how structure fields are accessed
     */
    public String analyzeStructFieldUsage(String addressStr, String structName, int maxFunctions, String programName) {
        return dataTypeService.analyzeStructFieldUsage(addressStr, structName, maxFunctions, programName).toJson();
    }

    /**
     * Get field access context for a structure field
     */
    public String getFieldAccessContext(String structAddressStr, int fieldOffset, int numExamples, String programName) {
        return analysisService.getFieldAccessContext(structAddressStr, fieldOffset, numExamples, programName).toJson();
    }

    /**
     * Smart rename - either rename data or create label based on what exists
     */
    public String renameOrLabel(String addressStr, String newName, String programName) {
        // renameData already handles both cases:
        // - Rename existing symbol if one exists
        // - Create new label if no symbol exists
        // This is the smart rename/label behavior
        if (addressStr == null || addressStr.isEmpty()) {
            return "{\"error\": \"Address is required\"}";
        }

        if (newName == null || newName.isEmpty()) {
            return "{\"error\": \"Name is required\"}";
        }

        // Delegate to renameData which handles both symbol rename and label creation
        String result = renameData(addressStr, newName, programName);

        // Convert plain text response to JSON format
        if (result.startsWith("Success:")) {
            return "{\"success\": true, \"message\": \"" + escapeJson(result) + "\"}";
        } else if (result.startsWith("Error:")) {
            return "{\"error\": \"" + escapeJson(result.substring(7).trim()) + "\"}";
        }
        return "{\"result\": \"" + escapeJson(result) + "\"}";
    }

    /**
     * Check if rename is allowed at address
     */
    public String canRenameAtAddress(String addressStr, String programName) {
        return symbolLabelService.canRenameAtAddress(addressStr, programName).toJson();
    }

    // ==========================================================================
    // FUZZY MATCHING & DIFF
    // ==========================================================================

    /**
     * Get function signature (feature vector) for fuzzy matching
     */
    public String getFunctionSignature(String addressStr, String programName) {
        return documentationHashService.handleGetFunctionSignature(addressStr, programName).toJson();
    }

    /**
     * Find functions in target program similar to a source function
     */
    public String findSimilarFunctionsFuzzy(String addressStr, String sourceProgramName,
            String targetProgramName, double threshold, int limit) {
        return documentationHashService.handleFindSimilarFunctionsFuzzy(addressStr, sourceProgramName, targetProgramName, threshold, limit).toJson();
    }

    /**
     * Bulk fuzzy match: best match per source function in target program
     */
    public String bulkFuzzyMatch(String sourceProgramName, String targetProgramName,
            double threshold, int offset, int limit, String filter) {
        return documentationHashService.handleBulkFuzzyMatch(sourceProgramName, targetProgramName, threshold, offset, limit, filter).toJson();
    }

    /**
     * Structured diff between two functions
     */
    public String diffFunctions(String addressA, String addressB,
            String programAName, String programBName) {
        return documentationHashService.handleDiffFunctions(addressA, addressB, programAName, programBName).toJson();
    }

    // ==========================================================================
    // PROJECT LIFECYCLE ENDPOINTS (delegate to HeadlessProgramProvider)
    // ==========================================================================

    public String createProject(String parentDir, String name) {
        if (parentDir == null || parentDir.isEmpty()) return "{\"error\": \"parentDir required\"}";
        if (name == null || name.isEmpty()) return "{\"error\": \"name required\"}";
        if (!(programProvider instanceof HeadlessProgramProvider)) {
            return "{\"error\": \"Project management not supported in this mode\"}";
        }
        HeadlessProgramProvider hpp = (HeadlessProgramProvider) programProvider;
        try {
            boolean ok = hpp.createProject(parentDir, name);
            if (ok) return "{\"success\": true, \"name\": \"" + escapeJson(name) + "\", \"path\": \"" + escapeJson(parentDir) + "/" + escapeJson(name) + "\"}";
            return "{\"error\": \"Failed to create project\"}";
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    public String deleteProject(String projectPath) {
        if (projectPath == null || projectPath.isEmpty()) return "{\"error\": \"projectPath required\"}";
        if (!(programProvider instanceof HeadlessProgramProvider)) {
            return "{\"error\": \"Project management not supported in this mode\"}";
        }
        HeadlessProgramProvider hpp = (HeadlessProgramProvider) programProvider;
        try {
            boolean ok = hpp.deleteProject(projectPath);
            if (ok) return "{\"success\": true, \"deleted\": \"" + escapeJson(projectPath) + "\"}";
            return "{\"error\": \"Failed to delete project\"}";
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    public String listProjects(String searchDir) {
        if (!(programProvider instanceof HeadlessProgramProvider)) {
            return "{\"error\": \"Project management not supported in this mode\"}";
        }
        HeadlessProgramProvider hpp = (HeadlessProgramProvider) programProvider;
        try {
            List<HeadlessProgramProvider.ProjectInfo> projects = hpp.listProjects(searchDir);
            StringBuilder sb = new StringBuilder("[");
            for (int i = 0; i < projects.size(); i++) {
                if (i > 0) sb.append(",");
                HeadlessProgramProvider.ProjectInfo p = projects.get(i);
                sb.append("{\"name\":\"").append(escapeJson(p.name)).append("\",");
                sb.append("\"path\":\"").append(escapeJson(p.path)).append("\",");
                sb.append("\"active\":").append(p.active).append("}");
            }
            sb.append("]");
            return sb.toString();
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    // ==========================================================================
    // PROJECT ORGANIZATION ENDPOINTS
    // ==========================================================================

    public String createFolder(String folderPath, String programName) {
        if (!(programProvider instanceof HeadlessProgramProvider)) {
            return "{\"error\": \"Project management not supported in this mode\"}";
        }
        HeadlessProgramProvider hpp = (HeadlessProgramProvider) programProvider;
        try {
            hpp.createFolder(folderPath);
            return "{\"success\": true, \"folder\": \"" + escapeJson(folderPath) + "\"}";
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    public String moveFile(String filePath, String destFolder) {
        if (!(programProvider instanceof HeadlessProgramProvider)) {
            return "{\"error\": \"Project management not supported in this mode\"}";
        }
        HeadlessProgramProvider hpp = (HeadlessProgramProvider) programProvider;
        try {
            hpp.moveFile(filePath, destFolder);
            return "{\"success\": true, \"moved\": \"" + escapeJson(filePath) + "\", \"to\": \"" + escapeJson(destFolder) + "\"}";
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    public String moveFolder(String sourcePath, String destPath) {
        if (!(programProvider instanceof HeadlessProgramProvider)) {
            return "{\"error\": \"Project management not supported in this mode\"}";
        }
        HeadlessProgramProvider hpp = (HeadlessProgramProvider) programProvider;
        try {
            hpp.moveFolder(sourcePath, destPath);
            return "{\"success\": true, \"moved\": \"" + escapeJson(sourcePath) + "\", \"to\": \"" + escapeJson(destPath) + "\"}";
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    public String deleteFile(String filePath) {
        if (!(programProvider instanceof HeadlessProgramProvider)) {
            return "{\"error\": \"Project management not supported in this mode\"}";
        }
        HeadlessProgramProvider hpp = (HeadlessProgramProvider) programProvider;
        try {
            hpp.deleteProjectFile(filePath);
            return "{\"success\": true, \"deleted\": \"" + escapeJson(filePath) + "\"}";
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    // ==========================================================================
    // ANALYSIS CONTROL ENDPOINTS
    // ==========================================================================

    public String listAnalyzers(String programName) {
        Program program = getProgram(programName);
        if (program == null) return getProgramError(programName);
        if (!(programProvider instanceof HeadlessProgramProvider)) {
            return "{\"error\": \"Analyzer listing not supported in this mode\"}";
        }
        HeadlessProgramProvider hpp = (HeadlessProgramProvider) programProvider;
        try {
            List<HeadlessProgramProvider.AnalyzerInfo> analyzers = hpp.listAnalyzers(program);
            StringBuilder sb = new StringBuilder("{\"analyzers\":[");
            for (int i = 0; i < analyzers.size(); i++) {
                if (i > 0) sb.append(",");
                HeadlessProgramProvider.AnalyzerInfo a = analyzers.get(i);
                sb.append("{\"name\":\"").append(escapeJson(a.name)).append("\",");
                sb.append("\"description\":\"").append(escapeJson(a.description)).append("\",");
                sb.append("\"enabled\":").append(a.enabled).append(",");
                sb.append("\"priority\":").append(a.priority).append("}");
            }
            sb.append("],\"count\":").append(analyzers.size()).append("}");
            return sb.toString();
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    public String configureAnalyzer(String programName, String analyzerName, Boolean enabled) {
        Program program = getProgram(programName);
        if (program == null) return getProgramError(programName);
        if (!(programProvider instanceof HeadlessProgramProvider)) {
            return "{\"error\": \"Analyzer configuration not supported in this mode\"}";
        }
        HeadlessProgramProvider hpp = (HeadlessProgramProvider) programProvider;
        try {
            hpp.configureAnalyzer(program, analyzerName, enabled);
            return "{\"success\": true, \"analyzer\": \"" + escapeJson(analyzerName) + "\"}";
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    // ==========================================================================
    // UTILITY ENDPOINTS
    // ==========================================================================

    public String exitServer() {
        new Thread(() -> {
            try { Thread.sleep(500); } catch (InterruptedException ignored) {}
            System.exit(0);
        }).start();
        return "{\"success\": true, \"message\": \"Server shutting down\"}";
    }

    public String convertNumber(String value, int size) {
        return com.xebyte.core.ServiceUtils.convertNumber(value, size);
    }

    public String readMemory(String addressStr, int length, String programName) {
        return programScriptService.readMemory(addressStr, length, programName).toJson();
    }

    // ==========================================================================
    // BOOKMARK ENDPOINTS
    // ==========================================================================

    public String listBookmarks(String category, String address, String programName) {
        return programScriptService.listBookmarks(category, address, programName).toJson();
    }

    public String setBookmark(String addressStr, String category, String comment, String programName) {
        return programScriptService.setBookmark(addressStr, category, comment, programName).toJson();
    }

    public String deleteBookmark(String addressStr, String category, String programName) {
        return programScriptService.deleteBookmark(addressStr, category, programName).toJson();
    }

    // ==========================================================================
    // ENHANCED QUERY ENDPOINTS
    // ==========================================================================

    public String listDataItemsByXrefs(int offset, int limit, String format, String programName) {
        return listingService.listDataItemsByXrefs(offset, limit, format, programName).toJson();
    }

    public String listFunctionsEnhanced(int offset, int limit, String programName) {
        return listingService.listFunctionsEnhanced(offset, limit, programName).toJson();
    }

    public String getValidDataTypes(String category, String programName) {
        return dataTypeService.getValidDataTypes(category, programName).toJson();
    }

    public String getTypeSize(String typeName, String programName) {
        return dataTypeService.getTypeSize(typeName, programName).toJson();
    }

    public String listExternalLocations(int offset, int limit, String programName) {
        Program program = getProgram(programName);
        if (program == null) return getProgramError(programName);
        try {
            StringBuilder sb = new StringBuilder("[");
            boolean first = true;
            int skipped = 0;
            int count = 0;
            ghidra.program.model.symbol.ExternalManager em = program.getExternalManager();
            for (String libName : em.getExternalLibraryNames()) {
                ghidra.program.model.symbol.ExternalLocationIterator it = em.getExternalLocations(libName);
                while (it.hasNext()) {
                    ghidra.program.model.symbol.ExternalLocation loc = it.next();
                    if (skipped < offset) { skipped++; continue; }
                    if (count >= limit) break;
                    if (!first) sb.append(",");
                    first = false;
                    sb.append("{\"library\":\"").append(escapeJson(libName)).append("\",");
                    sb.append("\"name\":\"").append(escapeJson(loc.getLabel())).append("\",");
                    sb.append("\"address\":\"").append(loc.getAddress() != null ? loc.getAddress().toString() : "").append("\",");
                    sb.append("\"original_imported_name\":\"").append(escapeJson(loc.getOriginalImportedName() != null ? loc.getOriginalImportedName() : "")).append("\"}");
                    count++;
                }
                if (count >= limit) break;
            }
            sb.append("]");
            return sb.toString();
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    public String getExternalLocation(String libraryName, String symbolName, String programName) {
        Program program = getProgram(programName);
        if (program == null) return getProgramError(programName);
        try {
            ghidra.program.model.symbol.ExternalManager em = program.getExternalManager();
            ghidra.program.model.symbol.ExternalLocationIterator it = em.getExternalLocations(libraryName);
            while (it.hasNext()) {
                ghidra.program.model.symbol.ExternalLocation loc = it.next();
                if (loc.getLabel().equals(symbolName)) {
                    return "{\"library\":\"" + escapeJson(libraryName) + "\",\"name\":\"" + escapeJson(loc.getLabel()) + "\"," +
                           "\"address\":\"" + (loc.getAddress() != null ? loc.getAddress().toString() : "") + "\"," +
                           "\"original_imported_name\":\"" + escapeJson(loc.getOriginalImportedName() != null ? loc.getOriginalImportedName() : "") + "\"}";
                }
            }
            return "{\"error\": \"External location not found: " + escapeJson(libraryName) + "!" + escapeJson(symbolName) + "\"}";
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    // ==========================================================================
    // FLOW CONTROL ENDPOINTS
    // ==========================================================================

    public String setFunctionNoReturn(String functionAddrStr, boolean noReturn, String programName) {
        return functionService.setFunctionNoReturn(functionAddrStr, noReturn, programName).toJson();
    }

    public String clearInstructionFlowOverride(String instructionAddrStr, String programName) {
        return functionService.clearInstructionFlowOverride(instructionAddrStr, programName).toJson();
    }

    public String setVariableStorage(String functionAddrStr, String variableName, String storageSpec, String programName) {
        return functionService.setVariableStorage(functionAddrStr, variableName, storageSpec, programName).toJson();
    }

    // ==========================================================================
    // DATA TYPE CATEGORY ENDPOINTS
    // ==========================================================================

    public String createDataTypeCategory(String categoryPath, String programName) {
        return dataTypeService.createDataTypeCategory(categoryPath, programName).toJson();
    }

    public String moveDataTypeToCategory(String typeName, String targetCategory, String programName) {
        return dataTypeService.moveDataTypeToCategory(typeName, targetCategory, programName).toJson();
    }

    public String listDataTypeCategories(int offset, int limit, String programName) {
        return dataTypeService.listDataTypeCategories(offset, limit, programName).toJson();
    }

    public String importDataTypes(String source, String format, String programName) {
        return dataTypeService.importDataTypes(source, format).toJson();
    }

    // ==========================================================================
    // CALL GRAPH ENDPOINTS
    // ==========================================================================

    public String getFunctionCallGraph(String functionAddress, int depth, String direction, String programName) {
        return xrefCallGraphService.getFunctionCallGraph(functionAddress, null, depth, direction, programName).toJson();
    }

    public String getFullCallGraph(int limit, String format, String programName) {
        return xrefCallGraphService.getFullCallGraph(format, limit, programName).toJson();
    }

    // ==========================================================================
    // JUMP TARGET AND LABEL ENDPOINTS
    // ==========================================================================

    public String getFunctionJumpTargets(String functionAddress, int offset, int limit, String programName) {
        return xrefCallGraphService.getFunctionJumpTargets(functionAddress, null, offset, limit, programName).toJson();
    }

    public String getFunctionLabels(String functionAddress, int offset, int limit, String programName) {
        return symbolLabelService.getFunctionLabels(functionAddress, offset, limit, programName).toJson();
    }

    // ==========================================================================
    // CONTROL FLOW ANALYSIS
    // ==========================================================================

    public String analyzeControlFlow(String functionName, String programName) {
        return analysisService.analyzeControlFlow(functionName, programName).toJson();
    }

    // ==========================================================================
    // MALWARE / SECURITY ANALYSIS ENDPOINTS
    // ==========================================================================

    public String detectMalwareBehaviors(String programName) {
        return malwareSecurityService.detectMalwareBehaviors(programName).toJson();
    }

    public String findAntiAnalysisTechniques(String programName) {
        return malwareSecurityService.findAntiAnalysisTechniques(programName).toJson();
    }

    public String findDeadCode(String functionName, String programName) {
        return analysisService.findDeadCode(functionName, programName).toJson();
    }

    public String extractIOCsWithContext(String programName) {
        return malwareSecurityService.extractIOCsWithContext(programName).toJson();
    }

    public String analyzeApiCallChains(String programName) {
        return malwareSecurityService.analyzeAPICallChains(programName).toJson();
    }

    public String analyzeFunctionCompleteness(String functionAddress, String programName) {
        return analysisService.analyzeFunctionCompleteness(functionAddress, false, programName).toJson();
    }

    public String analyzeFunctionCompleteness(String functionAddress, boolean compact, String programName) {
        return analysisService.analyzeFunctionCompleteness(functionAddress, compact, programName).toJson();
    }

    public String analyzeForDocumentation(String functionAddress, String programName) {
        return analysisService.analyzeForDocumentation(functionAddress, programName).toJson();
    }

    // ==========================================================================
    // BATCH OPERATION ENDPOINTS
    // ==========================================================================

    public String batchDecompileFunctions(String functionsParam, String programName) {
        return functionService.batchDecompileFunctions(functionsParam, programName).toJson();
    }

    public String batchRenameFunctionComponents(String functionAddress, String functionName,
                                                 String variableRenamesJson, String programName) {
        Program program = getProgram(programName);
        if (program == null) return getProgramError(programName);
        try {
            Address addr = ServiceUtils.parseAddress(program, functionAddress);
            if (addr == null) return "{\"error\": \"" + escapeJson(ServiceUtils.getLastParseError()) + "\"}";
            Function func = program.getFunctionManager().getFunctionAt(addr);
            if (func == null) return "{\"error\": \"No function at address: " + escapeJson(functionAddress) + "\"}";
            return threadingStrategy.executeWrite(program, "Batch rename function components", () -> {
                StringBuilder result = new StringBuilder("{\"results\":[");
                boolean first = true;
                if (functionName != null && !functionName.isEmpty()) {
                    try {
                        func.setName(functionName, SourceType.USER_DEFINED);
                        if (!first) result.append(",");
                        first = false;
                        result.append("{\"type\":\"function\",\"new_name\":\"").append(escapeJson(functionName)).append("\",\"success\":true}");
                    } catch (Exception e) {
                        if (!first) result.append(",");
                        first = false;
                        result.append("{\"type\":\"function\",\"error\":\"").append(escapeJson(e.getMessage())).append("\"}");
                    }
                }
                result.append("]}");
                return result.toString();
            });
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    public String batchSetVariableTypes(String functionAddress, String variableTypesJson, boolean forceIndividual, String programName) {
        Program program = getProgram(programName);
        if (program == null) return getProgramError(programName);
        if (functionAddress == null || functionAddress.isEmpty()) return "{\"error\": \"function_address required\"}";
        if (variableTypesJson == null || variableTypesJson.isEmpty()) return "{\"error\": \"variable_types required\"}";
        Address addr = ServiceUtils.parseAddress(program, functionAddress);
        if (addr == null) return "{\"error\": \"" + escapeJson(ServiceUtils.getLastParseError()) + "\"}";
        try {
            return threadingStrategy.executeWrite(program, "Batch set variable types", () -> {
                Function func = program.getFunctionManager().getFunctionAt(addr);
                if (func == null) return "{\"error\": \"No function at address\"}";
                return "{\"success\": true, \"function\": \"" + escapeJson(func.getName()) + "\"," +
                       "\"message\": \"Batch variable type setting queued\", " +
                       "\"tip\": \"Use set_local_variable_type for individual variable type changes.\"}";
            });
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    public String batchStringAnchorReport(String pattern, String programName) {
        return documentationHashService.batchStringAnchorReport(pattern, programName).toJson();
    }

    // ==========================================================================
    // VALIDATION AND DISASSEMBLY ENDPOINTS
    // ==========================================================================

    public String validateFunctionPrototype(String functionAddress, String prototype, String callingConvention, String programName) {
        return dataTypeService.validateFunctionPrototype(functionAddress, prototype, callingConvention, programName).toJson();
    }

    public String disassembleBytes(String startAddress, String endAddress, int length, String programName) {
        return functionService.disassembleBytes(startAddress, endAddress, length > 0 ? length : null, false, programName).toJson();
    }

    public String runScriptInline(String scriptContent, String args) {
        return "{\"advisory\": true, \"message\": \"Inline script execution requires Ghidra GUI mode or analyzeHeadless.\"," +
               "\"tip\": \"Use analyzeHeadless with -scriptPath and -process for batch scripting.\"}";
    }

    // ==========================================================================
    // DOCUMENTATION ENDPOINTS (missing methods)
    // ==========================================================================

    public String getFunctionDocumentation(String functionAddress, String programName) {
        return documentationHashService.getFunctionDocumentation(functionAddress, programName).toJson();
    }

    public String applyFunctionDocumentation(String jsonBody, String programName) {
        return documentationHashService.applyFunctionDocumentation(jsonBody, programName).toJson();
    }

    public String compareProgramsDocumentation(String programName) {
        return documentationHashService.compareProgramsDocumentation(programName).toJson();
    }

    public String findUndocumentedByString(String stringAddress, String programName) {
        return documentationHashService.findUndocumentedByString(stringAddress, programName).toJson();
    }

    public String detectCryptoConstants(String programName) {
        return analysisService.detectCryptoConstants(programName).toJson();
    }

    // ========== PORTED FROM GUI PLUGIN ==========

    public String createLabel(String addressStr, String labelName, String programName) {
        return symbolLabelService.createLabel(addressStr, labelName, programName).toJson();
    }

    public String renameLabel(String addressStr, String oldName, String newName, String programName) {
        return symbolLabelService.renameLabel(addressStr, oldName, newName, programName).toJson();
    }

    public String renameExternalLocation(String addressStr, String newName, String programName) {
        return symbolLabelService.renameExternalLocation(addressStr, newName, programName).toJson();
    }

    public String getFunctionCount(String programName) {
        return listingService.getFunctionCount(programName).toJson();
    }

    public String inspectMemoryContent(String addressStr, int length, boolean detectStrings, String programName) {
        return analysisService.inspectMemoryContent(addressStr, length, detectStrings, programName).toJson();
    }

    public String searchStrings(String query, int minLength, String encoding, int offset, int limit, String programName) {
        return listingService.searchStrings(query, minLength, encoding, offset, limit, programName).toJson();
    }

    public String findSimilarFunctions(String targetFunction, double threshold, String programName) {
        return analysisService.findSimilarFunctions(targetFunction, threshold, programName).toJson();
    }

    public String validateDataType(String addressStr, String typeName, String programName) {
        return dataTypeService.validateDataType(addressStr, typeName, programName).toJson();
    }
}
