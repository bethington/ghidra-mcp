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
import com.xebyte.core.ThreadingStrategy;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighParam;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TaskMonitor;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.stream.Collectors;

import ghidra.program.model.mem.Memory;
import ghidra.program.model.address.AddressSetView;

/**
 * Headless endpoint handler implementation.
 *
 * Contains the business logic for all REST API endpoints, adapted for headless
 * operation (no GUI dependencies).
 */
public class HeadlessEndpointHandler {

    private static final String VERSION = "1.9.4-headless";
    private static final int DECOMPILE_TIMEOUT_SECONDS = 60;

    private final ProgramProvider programProvider;
    private final ThreadingStrategy threadingStrategy;
    private final TaskMonitor monitor;

    public HeadlessEndpointHandler(ProgramProvider programProvider, ThreadingStrategy threadingStrategy) {
        this.programProvider = programProvider;
        this.threadingStrategy = threadingStrategy;
        this.monitor = new ConsoleTaskMonitor();
    }

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

    private String paginateList(List<String> items, int offset, int limit) {
        if (items.isEmpty()) {
            return "";
        }
        int start = Math.max(0, offset);
        int end = Math.min(items.size(), start + limit);
        if (start >= items.size()) {
            return "";
        }
        return String.join("\n", items.subList(start, end));
    }

    private String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    private Address parseAddress(Program program, String addressStr) {
        if (addressStr == null || addressStr.isEmpty()) {
            return null;
        }
        return program.getAddressFactory().getAddress(addressStr);
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

    public String getMetadata() {
        Program program = getProgram(null);
        if (program == null) {
            return "{\"error\": \"No program loaded\"}";
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
        Program program = getProgram(programName);
        if (program == null) {
            return getProgramError(programName);
        }

        List<String> names = new ArrayList<>();
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            names.add(f.getName());
        }
        return paginateList(names, offset, limit);
    }

    public String listFunctions(String programName) {
        Program program = getProgram(programName);
        if (program == null) {
            return getProgramError(programName);
        }

        List<String> lines = new ArrayList<>();
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            lines.add(f.getName() + " @ " + f.getEntryPoint().toString());
        }
        return String.join("\n", lines);
    }

    public String listClasses(int offset, int limit, String programName) {
        Program program = getProgram(programName);
        if (program == null) {
            return getProgramError(programName);
        }

        Set<String> classNames = new HashSet<>();
        for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
            Namespace ns = symbol.getParentNamespace();
            if (ns != null && !ns.isGlobal()) {
                classNames.add(ns.getName());
            }
        }
        List<String> sorted = new ArrayList<>(classNames);
        Collections.sort(sorted);
        return paginateList(sorted, offset, limit);
    }

    public String listSegments(int offset, int limit, String programName) {
        Program program = getProgram(programName);
        if (program == null) {
            return getProgramError(programName);
        }

        List<String> lines = new ArrayList<>();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            lines.add(String.format("%s: %s - %s", block.getName(), block.getStart(), block.getEnd()));
        }
        return paginateList(lines, offset, limit);
    }

    public String listImports(int offset, int limit, String programName) {
        Program program = getProgram(programName);
        if (program == null) {
            return getProgramError(programName);
        }

        List<String> lines = new ArrayList<>();
        for (Symbol symbol : program.getSymbolTable().getExternalSymbols()) {
            lines.add(symbol.getName() + " -> " + symbol.getAddress());
        }
        return paginateList(lines, offset, limit);
    }

    public String listExports(int offset, int limit, String programName) {
        Program program = getProgram(programName);
        if (program == null) {
            return getProgramError(programName);
        }

        SymbolTable table = program.getSymbolTable();
        List<String> lines = new ArrayList<>();
        SymbolIterator iter = table.getAllSymbols(true);
        while (iter.hasNext()) {
            Symbol symbol = iter.next();
            if (symbol.isExternalEntryPoint()) {
                lines.add(symbol.getName() + " @ " + symbol.getAddress());
            }
        }
        return paginateList(lines, offset, limit);
    }

    public String listNamespaces(int offset, int limit, String programName) {
        Program program = getProgram(programName);
        if (program == null) {
            return getProgramError(programName);
        }

        Set<String> namespaces = new HashSet<>();
        for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
            Namespace ns = symbol.getParentNamespace();
            while (ns != null && !ns.isGlobal()) {
                namespaces.add(ns.getName(true));
                ns = ns.getParentNamespace();
            }
        }
        List<String> sorted = new ArrayList<>(namespaces);
        Collections.sort(sorted);
        return paginateList(sorted, offset, limit);
    }

    public String listDataItems(int offset, int limit, String programName) {
        Program program = getProgram(programName);
        if (program == null) {
            return getProgramError(programName);
        }

        List<String> lines = new ArrayList<>();
        Listing listing = program.getListing();
        DataIterator dataIterator = listing.getDefinedData(true);
        int count = 0;
        int skipped = 0;

        while (dataIterator.hasNext() && count < limit) {
            Data data = dataIterator.next();
            if (skipped < offset) {
                skipped++;
                continue;
            }

            String name = data.getLabel();
            if (name == null || name.isEmpty()) {
                name = "DAT_" + data.getAddress().toString();
            }
            String type = data.getDataType().getName();
            lines.add(name + " @ " + data.getAddress() + " [" + type + "]");
            count++;
        }
        return String.join("\n", lines);
    }

    public String listStrings(int offset, int limit, String filter, String programName) {
        Program program = getProgram(programName);
        if (program == null) {
            return getProgramError(programName);
        }

        List<String> lines = new ArrayList<>();
        Listing listing = program.getListing();
        DataIterator dataIterator = listing.getDefinedData(true);

        while (dataIterator.hasNext()) {
            Data data = dataIterator.next();
            DataType dt = data.getDataType();

            if (dt instanceof StringDataType || dt instanceof TerminatedStringDataType ||
                dt instanceof UnicodeDataType || dt.getName().toLowerCase().contains("string")) {

                Object value = data.getValue();
                String strValue = value != null ? value.toString() : "";

                if (filter == null || filter.isEmpty() || strValue.contains(filter)) {
                    lines.add(data.getAddress() + ": \"" + escapeJson(strValue) + "\"");
                }
            }
        }

        return paginateList(lines, offset, limit);
    }

    public String listDataTypes(int offset, int limit, String category, String programName) {
        Program program = getProgram(programName);
        if (program == null) {
            return getProgramError(programName);
        }

        List<String> lines = new ArrayList<>();
        DataTypeManager dtm = program.getDataTypeManager();

        java.util.Iterator<DataType> dtIterator = dtm.getAllDataTypes();
        while (dtIterator.hasNext()) {
            DataType dt = dtIterator.next();
            String catPath = dt.getCategoryPath().toString();

            if (category == null || category.isEmpty() ||
                catPath.toLowerCase().contains(category.toLowerCase())) {
                lines.add(dt.getName() + " [" + dt.getLength() + " bytes] " + catPath);
            }
        }

        Collections.sort(lines);
        return paginateList(lines, offset, limit);
    }

    // ==========================================================================
    // GETTER ENDPOINTS
    // ==========================================================================

    public String getFunctionByAddress(String addressStr, String programName) {
        Program program = getProgram(programName);
        if (program == null) {
            return getProgramError(programName);
        }

        Address addr = parseAddress(program, addressStr);
        if (addr == null) {
            return "{\"error\": \"Invalid address: " + addressStr + "\"}";
        }

        Function func = program.getFunctionManager().getFunctionAt(addr);
        if (func == null) {
            func = program.getFunctionManager().getFunctionContaining(addr);
        }

        if (func == null) {
            return "{\"error\": \"No function found at address: " + addressStr + "\"}";
        }

        StringBuilder sb = new StringBuilder();
        sb.append("{");
        sb.append("\"name\": \"").append(escapeJson(func.getName())).append("\",");
        sb.append("\"address\": \"").append(func.getEntryPoint().toString()).append("\",");
        sb.append("\"signature\": \"").append(escapeJson(func.getSignature().getPrototypeString())).append("\",");
        sb.append("\"calling_convention\": \"").append(escapeJson(func.getCallingConventionName())).append("\"");
        sb.append("}");
        return sb.toString();
    }

    // ==========================================================================
    // DECOMPILE/DISASSEMBLE ENDPOINTS
    // ==========================================================================

    public String decompileFunction(String addressStr, String name, String programName) {
        Program program = getProgram(programName);
        if (program == null) {
            return getProgramError(programName);
        }

        Function func = null;

        // Try by address first
        if (addressStr != null && !addressStr.isEmpty()) {
            Address addr = parseAddress(program, addressStr);
            if (addr != null) {
                func = program.getFunctionManager().getFunctionAt(addr);
                if (func == null) {
                    func = program.getFunctionManager().getFunctionContaining(addr);
                }
            }
        }

        // Try by name if no address or not found
        if (func == null && name != null && !name.isEmpty()) {
            for (Function f : program.getFunctionManager().getFunctions(true)) {
                if (f.getName().equals(name)) {
                    func = f;
                    break;
                }
            }
        }

        if (func == null) {
            return "Error: Function not found";
        }

        try {
            DecompInterface decompiler = new DecompInterface();
            decompiler.openProgram(program);

            DecompileResults results = decompiler.decompileFunction(func, DECOMPILE_TIMEOUT_SECONDS, monitor);

            if (results == null || !results.decompileCompleted()) {
                String errorMsg = results != null ? results.getErrorMessage() : "Unknown error";
                return "Error: Decompilation failed - " + errorMsg;
            }

            String decompiled = results.getDecompiledFunction().getC();
            decompiler.dispose();

            return decompiled != null ? decompiled : "Error: No decompiled output";

        } catch (Exception e) {
            Msg.error(this, "Decompilation error", e);
            return "Error: " + e.getMessage();
        }
    }

    public String disassembleFunction(String addressStr, String programName) {
        Program program = getProgram(programName);
        if (program == null) {
            return getProgramError(programName);
        }

        Address addr = parseAddress(program, addressStr);
        if (addr == null) {
            return "Error: Invalid address: " + addressStr;
        }

        Function func = program.getFunctionManager().getFunctionAt(addr);
        if (func == null) {
            func = program.getFunctionManager().getFunctionContaining(addr);
        }

        if (func == null) {
            return "Error: No function found at address: " + addressStr;
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

        return String.join("\n", lines);
    }

    // ==========================================================================
    // CROSS-REFERENCE ENDPOINTS
    // ==========================================================================

    public String getXrefsTo(String addressStr, int offset, int limit, String programName) {
        Program program = getProgram(programName);
        if (program == null) {
            return getProgramError(programName);
        }

        Address addr = parseAddress(program, addressStr);
        if (addr == null) {
            return "{\"error\": \"Invalid address: " + addressStr + "\"}";
        }

        List<String> lines = new ArrayList<>();
        ReferenceManager refMgr = program.getReferenceManager();
        ReferenceIterator refs = refMgr.getReferencesTo(addr);

        int count = 0;
        int skipped = 0;
        while (refs.hasNext() && count < limit) {
            Reference ref = refs.next();
            if (skipped < offset) {
                skipped++;
                continue;
            }

            lines.add(ref.getFromAddress() + " -> " + addr + " [" + ref.getReferenceType() + "]");
            count++;
        }

        return String.join("\n", lines);
    }

    public String getXrefsFrom(String addressStr, int offset, int limit, String programName) {
        Program program = getProgram(programName);
        if (program == null) {
            return getProgramError(programName);
        }

        Address addr = parseAddress(program, addressStr);
        if (addr == null) {
            return "{\"error\": \"Invalid address: " + addressStr + "\"}";
        }

        List<String> lines = new ArrayList<>();
        ReferenceManager refMgr = program.getReferenceManager();
        Reference[] refs = refMgr.getReferencesFrom(addr);

        int end = Math.min(refs.length, offset + limit);
        for (int i = offset; i < end; i++) {
            Reference ref = refs[i];
            lines.add(addr + " -> " + ref.getToAddress() + " [" + ref.getReferenceType() + "]");
        }

        return String.join("\n", lines);
    }

    public String getFunctionXrefs(String functionName, int offset, int limit, String programName) {
        Program program = getProgram(programName);
        if (program == null) {
            return getProgramError(programName);
        }

        Function func = null;
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            if (f.getName().equals(functionName)) {
                func = f;
                break;
            }
        }

        if (func == null) {
            return "{\"error\": \"Function not found: " + functionName + "\"}";
        }

        return getXrefsTo(func.getEntryPoint().toString(), offset, limit, programName);
    }

    // ==========================================================================
    // SEARCH ENDPOINTS
    // ==========================================================================

    public String searchFunctions(String query, int offset, int limit, String programName) {
        Program program = getProgram(programName);
        if (program == null) {
            return getProgramError(programName);
        }

        if (query == null || query.isEmpty()) {
            return "{\"error\": \"Query parameter required\"}";
        }

        List<String> matches = new ArrayList<>();
        String lowerQuery = query.toLowerCase();

        for (Function f : program.getFunctionManager().getFunctions(true)) {
            if (f.getName().toLowerCase().contains(lowerQuery)) {
                matches.add(f.getName() + " @ " + f.getEntryPoint());
            }
        }

        return paginateList(matches, offset, limit);
    }

    // ==========================================================================
    // RENAME ENDPOINTS
    // ==========================================================================

    public String renameFunction(String oldName, String newName) {
        Program program = getProgram(null);
        if (program == null) {
            return "Error: No program loaded";
        }

        if (oldName == null || oldName.isEmpty()) {
            return "Error: Old function name is required";
        }
        if (newName == null || newName.isEmpty()) {
            return "Error: New function name is required";
        }

        try {
            return threadingStrategy.executeWrite(program, "Rename function", () -> {
                for (Function func : program.getFunctionManager().getFunctions(true)) {
                    if (func.getName().equals(oldName)) {
                        func.setName(newName, SourceType.USER_DEFINED);
                        return "Success: Renamed function '" + oldName + "' to '" + newName + "'";
                    }
                }
                return "Error: Function '" + oldName + "' not found";
            });
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    public String renameFunctionByAddress(String addressStr, String newName) {
        Program program = getProgram(null);
        if (program == null) {
            return "Error: No program loaded";
        }

        if (addressStr == null || addressStr.isEmpty()) {
            return "Error: Function address is required";
        }
        if (newName == null || newName.isEmpty()) {
            return "Error: New function name is required";
        }

        Address addr = parseAddress(program, addressStr);
        if (addr == null) {
            return "Error: Invalid address: " + addressStr;
        }

        try {
            return threadingStrategy.executeWrite(program, "Rename function by address", () -> {
                Function func = program.getFunctionManager().getFunctionAt(addr);
                if (func == null) {
                    func = program.getFunctionManager().getFunctionContaining(addr);
                }
                if (func == null) {
                    return "Error: No function found at address: " + addressStr;
                }

                String oldName = func.getName();
                func.setName(newName, SourceType.USER_DEFINED);
                return "Success: Renamed function '" + oldName + "' to '" + newName + "'";
            });
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    public String saveCurrentProgram() {
        Program program = getProgram(null);
        if (program == null) {
            return "{\"error\": \"No program loaded\"}";
        }
        try {
            return threadingStrategy.executeWrite(program, "Save program", () -> {
                ghidra.framework.model.DomainFile df = program.getDomainFile();
                if (df == null) {
                    return "{\"error\": \"Program has no domain file\"}";
                }
                df.save(TaskMonitor.DUMMY);
                return "{\"success\": true, \"program\": \"" + escapeJson(program.getName()) +
                       "\", \"message\": \"Program saved successfully\"}";
            });
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    public String deleteFunctionAtAddress(String addressStr) {
        Program program = getProgram(null);
        if (program == null) {
            return "{\"error\": \"No program loaded\"}";
        }
        if (addressStr == null || addressStr.isEmpty()) {
            return "{\"error\": \"address parameter required\"}";
        }

        Address addr = parseAddress(program, addressStr);
        if (addr == null) {
            return "{\"error\": \"Invalid address: " + addressStr + "\"}";
        }

        Function func = program.getFunctionManager().getFunctionAt(addr);
        if (func == null) {
            return "{\"error\": \"No function found at address " + addressStr + "\"}";
        }

        String funcName = func.getName();
        long bodySize = func.getBody().getNumAddresses();

        try {
            return threadingStrategy.executeWrite(program, "Delete function at address", () -> {
                program.getFunctionManager().removeFunction(addr);
                return "{" +
                    "\"success\": true, " +
                    "\"address\": \"" + addr + "\", " +
                    "\"deleted_function\": \"" + escapeJson(funcName) + "\", " +
                    "\"body_size\": " + bodySize + ", " +
                    "\"message\": \"Function '" + escapeJson(funcName) + "' deleted at " + addr + "\"" +
                    "}";
            });
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    public String createFunctionAtAddress(String addressStr, String name, boolean disassembleFirst) {
        Program program = getProgram(null);
        if (program == null) {
            return "{\"error\": \"No program loaded\"}";
        }

        if (addressStr == null || addressStr.isEmpty()) {
            return "{\"error\": \"address parameter required\"}";
        }

        Address addr = parseAddress(program, addressStr);
        if (addr == null) {
            return "{\"error\": \"Invalid address: " + addressStr + "\"}";
        }

        Function existing = program.getFunctionManager().getFunctionAt(addr);
        if (existing != null) {
            return "{\"error\": \"Function already exists at " + addressStr + ": " + existing.getName() + "\"}";
        }

        try {
            return threadingStrategy.executeWrite(program, "Create function at address", () -> {
                // Optionally disassemble first
                if (disassembleFirst) {
                    if (program.getListing().getInstructionAt(addr) == null) {
                        ghidra.program.model.address.AddressSet addrSet =
                            new ghidra.program.model.address.AddressSet(addr, addr);
                        ghidra.app.cmd.disassemble.DisassembleCommand disCmd =
                            new ghidra.app.cmd.disassemble.DisassembleCommand(addrSet, null, true);
                        if (!disCmd.applyTo(program, TaskMonitor.DUMMY)) {
                            return "{\"error\": \"Failed to disassemble at " + addressStr + ": " + disCmd.getStatusMsg() + "\"}";
                        }
                    }
                }

                ghidra.app.cmd.function.CreateFunctionCmd cmd =
                    new ghidra.app.cmd.function.CreateFunctionCmd(addr);
                if (!cmd.applyTo(program, TaskMonitor.DUMMY)) {
                    return "{\"error\": \"Failed to create function at " + addressStr + ": " + cmd.getStatusMsg() + "\"}";
                }

                Function func = program.getFunctionManager().getFunctionAt(addr);
                if (func == null) {
                    return "{\"error\": \"Function creation reported success but function not found at " + addressStr + "\"}";
                }

                if (name != null && !name.isEmpty()) {
                    func.setName(name, SourceType.USER_DEFINED);
                }

                String funcName = func.getName();
                return "{" +
                    "\"success\": true, " +
                    "\"address\": \"" + addr + "\", " +
                    "\"function_name\": \"" + escapeJson(funcName) + "\", " +
                    "\"entry_point\": \"" + func.getEntryPoint() + "\", " +
                    "\"body_size\": " + func.getBody().getNumAddresses() + ", " +
                    "\"message\": \"Function created successfully at " + addr + "\"" +
                    "}";
            });
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    public String createMemoryBlock(String name, String addressStr, long size,
                                    boolean read, boolean write, boolean execute,
                                    boolean isVolatile, String comment) {
        Program program = getProgram(null);
        if (program == null) {
            return "{\"error\": \"No program loaded\"}";
        }
        if (name == null || name.isEmpty()) {
            return "{\"error\": \"name parameter required\"}";
        }
        if (addressStr == null || addressStr.isEmpty()) {
            return "{\"error\": \"address parameter required\"}";
        }
        if (size <= 0) {
            return "{\"error\": \"size must be positive\"}";
        }

        Address addr = parseAddress(program, addressStr);
        if (addr == null) {
            return "{\"error\": \"Invalid address: " + addressStr + "\"}";
        }

        try {
            return threadingStrategy.executeWrite(program, "Create memory block", () -> {
                MemoryBlock block = program.getMemory().createUninitializedBlock(
                    name, addr, size, false);

                block.setRead(read);
                block.setWrite(write);
                block.setExecute(execute);
                block.setVolatile(isVolatile);
                if (comment != null && !comment.isEmpty()) {
                    block.setComment(comment);
                }

                return "{" +
                    "\"success\": true, " +
                    "\"name\": \"" + escapeJson(name) + "\", " +
                    "\"start\": \"" + block.getStart() + "\", " +
                    "\"end\": \"" + block.getEnd() + "\", " +
                    "\"size\": " + block.getSize() + ", " +
                    "\"permissions\": \"" + (read ? "r" : "-") + (write ? "w" : "-") + (execute ? "x" : "-") + "\", " +
                    "\"volatile\": " + isVolatile + ", " +
                    "\"message\": \"Memory block '" + escapeJson(name) + "' created at " + addr + "\"" +
                    "}";
            });
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    public String renameData(String addressStr, String newName) {
        Program program = getProgram(null);
        if (program == null) {
            return "Error: No program loaded";
        }

        if (addressStr == null || addressStr.isEmpty()) {
            return "Error: Address is required";
        }
        if (newName == null || newName.isEmpty()) {
            return "Error: New name is required";
        }

        Address addr = parseAddress(program, addressStr);
        if (addr == null) {
            return "Error: Invalid address: " + addressStr;
        }

        try {
            return threadingStrategy.executeWrite(program, "Rename data", () -> {
                SymbolTable symTable = program.getSymbolTable();
                Symbol symbol = symTable.getPrimarySymbol(addr);

                if (symbol != null) {
                    symbol.setName(newName, SourceType.USER_DEFINED);
                    return "Success: Renamed data at " + addressStr + " to '" + newName + "'";
                } else {
                    symTable.createLabel(addr, newName, SourceType.USER_DEFINED);
                    return "Success: Created label '" + newName + "' at " + addressStr;
                }
            });
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    public String renameVariable(String functionName, String oldName, String newName) {
        Program program = getProgram(null);
        if (program == null) {
            return "Error: No program loaded";
        }

        if (functionName == null || functionName.isEmpty()) {
            return "Error: Function name is required";
        }
        if (oldName == null || oldName.isEmpty()) {
            return "Error: Old variable name is required";
        }
        if (newName == null || newName.isEmpty()) {
            return "Error: New variable name is required";
        }

        Function func = null;
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            if (f.getName().equals(functionName)) {
                func = f;
                break;
            }
        }

        if (func == null) {
            return "Error: Function '" + functionName + "' not found";
        }

        final Function targetFunc = func;

        try {
            return threadingStrategy.executeWrite(program, "Rename variable", () -> {
                // Check parameters
                for (Parameter param : targetFunc.getParameters()) {
                    if (param.getName().equals(oldName)) {
                        param.setName(newName, SourceType.USER_DEFINED);
                        return "Success: Renamed parameter '" + oldName + "' to '" + newName + "'";
                    }
                }

                // Check local variables
                for (Variable var : targetFunc.getLocalVariables()) {
                    if (var.getName().equals(oldName)) {
                        var.setName(newName, SourceType.USER_DEFINED);
                        return "Success: Renamed local variable '" + oldName + "' to '" + newName + "'";
                    }
                }

                return "Error: Variable '" + oldName + "' not found in function '" + functionName + "'";
            });
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // ==========================================================================
    // COMMENT ENDPOINTS
    // ==========================================================================

    public String setDecompilerComment(String addressStr, String comment) {
        Program program = getProgram(null);
        if (program == null) {
            return "Error: No program loaded";
        }

        Address addr = parseAddress(program, addressStr);
        if (addr == null) {
            return "Error: Invalid address: " + addressStr;
        }

        try {
            return threadingStrategy.executeWrite(program, "Set decompiler comment", () -> {
                Listing listing = program.getListing();
                listing.setComment(addr, CodeUnit.PRE_COMMENT, comment);
                return "Success: Set decompiler comment at " + addressStr;
            });
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    public String setDisassemblyComment(String addressStr, String comment) {
        Program program = getProgram(null);
        if (program == null) {
            return "Error: No program loaded";
        }

        Address addr = parseAddress(program, addressStr);
        if (addr == null) {
            return "Error: Invalid address: " + addressStr;
        }

        try {
            return threadingStrategy.executeWrite(program, "Set disassembly comment", () -> {
                Listing listing = program.getListing();
                listing.setComment(addr, CodeUnit.EOL_COMMENT, comment);
                return "Success: Set disassembly comment at " + addressStr;
            });
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // ==========================================================================
    // PROGRAM MANAGEMENT ENDPOINTS
    // ==========================================================================

    public String listOpenPrograms() {
        Program[] programs = programProvider.getAllOpenPrograms();
        Program current = programProvider.getCurrentProgram();

        StringBuilder sb = new StringBuilder();
        sb.append("{\"programs\": [");

        for (int i = 0; i < programs.length; i++) {
            if (i > 0) sb.append(", ");
            Program p = programs[i];
            sb.append("{");
            sb.append("\"name\": \"").append(escapeJson(p.getName())).append("\",");
            sb.append("\"is_current\": ").append(p == current);
            sb.append("}");
        }

        sb.append("], \"count\": ").append(programs.length);
        if (current != null) {
            sb.append(", \"current_program\": \"").append(escapeJson(current.getName())).append("\"");
        }
        sb.append("}");

        return sb.toString();
    }

    public String getCurrentProgramInfo() {
        Program program = getProgram(null);
        if (program == null) {
            return "{\"error\": \"No program loaded\"}";
        }

        return getMetadata();
    }

    public String switchProgram(String name) {
        if (name == null || name.isEmpty()) {
            return "{\"error\": \"Program name required\"}";
        }

        Program program = programProvider.getProgram(name);
        if (program == null) {
            return "{\"error\": \"Program not found: " + escapeJson(name) + "\"}";
        }

        programProvider.setCurrentProgram(program);
        return "{\"success\": true, \"current_program\": \"" + escapeJson(program.getName()) + "\"}";
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
        Program program = getProgram(programName);
        if (program == null) {
            return getProgramError(programName);
        }

        if (functionName == null || functionName.isEmpty()) {
            return "{\"error\": \"Function name is required\"}";
        }

        Function func = null;
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            if (f.getName().equals(functionName)) {
                func = f;
                break;
            }
        }

        if (func == null) {
            return "{\"error\": \"Function not found: " + escapeJson(functionName) + "\"}";
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
     * Get all functions that call the specified function (callers).
     */
    public String getFunctionCallers(String functionName, int offset, int limit, String programName) {
        Program program = getProgram(programName);
        if (program == null) {
            return getProgramError(programName);
        }

        if (functionName == null || functionName.isEmpty()) {
            return "{\"error\": \"Function name is required\"}";
        }

        Function func = null;
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            if (f.getName().equals(functionName)) {
                func = f;
                break;
            }
        }

        if (func == null) {
            return "{\"error\": \"Function not found: " + escapeJson(functionName) + "\"}";
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

    /**
     * Get all variables (parameters and locals) for a function.
     */
    public String getFunctionVariables(String functionName, String programName) {
        Program program = getProgram(programName);
        if (program == null) {
            return getProgramError(programName);
        }

        if (functionName == null || functionName.isEmpty()) {
            return "{\"error\": \"Function name is required\"}";
        }

        Function func = null;
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            if (f.getName().equals(functionName)) {
                func = f;
                break;
            }
        }

        if (func == null) {
            return "{\"error\": \"Function not found: " + escapeJson(functionName) + "\"}";
        }

        StringBuilder sb = new StringBuilder();
        sb.append("{\"function\": \"").append(escapeJson(func.getName())).append("\", ");
        sb.append("\"parameters\": [");

        Parameter[] params = func.getParameters();
        for (int i = 0; i < params.length; i++) {
            if (i > 0) sb.append(", ");
            Parameter p = params[i];
            sb.append("{");
            sb.append("\"name\": \"").append(escapeJson(p.getName())).append("\", ");
            sb.append("\"type\": \"").append(escapeJson(p.getDataType().getName())).append("\", ");
            sb.append("\"ordinal\": ").append(p.getOrdinal()).append(", ");
            sb.append("\"storage\": \"").append(escapeJson(p.getVariableStorage().toString())).append("\"");
            sb.append("}");
        }

        sb.append("], \"locals\": [");

        Variable[] locals = func.getLocalVariables();
        for (int i = 0; i < locals.length; i++) {
            if (i > 0) sb.append(", ");
            Variable v = locals[i];
            sb.append("{");
            sb.append("\"name\": \"").append(escapeJson(v.getName())).append("\", ");
            sb.append("\"type\": \"").append(escapeJson(v.getDataType().getName())).append("\", ");
            sb.append("\"storage\": \"").append(escapeJson(v.getVariableStorage().toString())).append("\"");
            sb.append("}");
        }

        sb.append("]}");
        return sb.toString();
    }

    /**
     * Set a function's prototype (signature).
     */
    public String setFunctionPrototype(String functionAddress, String prototype, String callingConvention) {
        Program program = getProgram(null);
        if (program == null) {
            return "Error: No program loaded";
        }

        if (functionAddress == null || functionAddress.isEmpty()) {
            return "Error: Function address is required";
        }
        if (prototype == null || prototype.isEmpty()) {
            return "Error: Prototype is required";
        }

        Address addr = parseAddress(program, functionAddress);
        if (addr == null) {
            return "Error: Invalid address: " + functionAddress;
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

                ghidra.program.model.data.FunctionDefinitionDataType sig = parser.parse(null, prototype);

                // Apply using ApplyFunctionSignatureCmd
                ghidra.app.cmd.function.ApplyFunctionSignatureCmd cmd =
                    new ghidra.app.cmd.function.ApplyFunctionSignatureCmd(
                        func.getEntryPoint(), sig, SourceType.USER_DEFINED);

                if (!cmd.applyTo(program, monitor)) {
                    return "Error: Failed to apply signature - " + cmd.getStatusMsg();
                }

                // Apply calling convention if specified
                if (callingConvention != null && !callingConvention.isEmpty()) {
                    try {
                        func.setCallingConvention(callingConvention);
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
    public String setLocalVariableType(String functionAddress, String variableName, String newType) {
        Program program = getProgram(null);
        if (program == null) {
            return "Error: No program loaded";
        }

        if (functionAddress == null || functionAddress.isEmpty()) {
            return "Error: Function address is required";
        }
        if (variableName == null || variableName.isEmpty()) {
            return "Error: Variable name is required";
        }
        if (newType == null || newType.isEmpty()) {
            return "Error: New type is required";
        }

        Address addr = parseAddress(program, functionAddress);
        if (addr == null) {
            return "Error: Invalid address: " + functionAddress;
        }

        try {
            return threadingStrategy.executeWrite(program, "Set variable type", () -> {
                Function func = program.getFunctionManager().getFunctionAt(addr);
                if (func == null) {
                    func = program.getFunctionManager().getFunctionContaining(addr);
                }
                if (func == null) {
                    return "Error: No function found at address: " + functionAddress;
                }

                // Find the data type
                DataType dataType = findDataType(program.getDataTypeManager(), newType);
                if (dataType == null) {
                    return "Error: Data type not found: " + newType;
                }

                // Check parameters first
                for (Parameter param : func.getParameters()) {
                    if (param.getName().equals(variableName)) {
                        param.setDataType(dataType, SourceType.USER_DEFINED);
                        return "Success: Set type of parameter '" + variableName + "' to '" + newType + "'";
                    }
                }

                // Check local variables
                for (Variable var : func.getLocalVariables()) {
                    if (var.getName().equals(variableName)) {
                        var.setDataType(dataType, SourceType.USER_DEFINED);
                        return "Success: Set type of local '" + variableName + "' to '" + newType + "'";
                    }
                }

                return "Error: Variable '" + variableName + "' not found in function";
            });
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Find a data type by name in the data type manager.
     */
    private DataType findDataType(DataTypeManager dtm, String typeName) {
        // First try exact match
        java.util.Iterator<DataType> iter = dtm.getAllDataTypes();
        while (iter.hasNext()) {
            DataType dt = iter.next();
            if (dt.getName().equals(typeName)) {
                return dt;
            }
        }

        // Try built-in types
        DataTypeManager builtIn = ghidra.program.model.data.BuiltInDataTypeManager.getDataTypeManager();
        iter = builtIn.getAllDataTypes();
        while (iter.hasNext()) {
            DataType dt = iter.next();
            if (dt.getName().equals(typeName) || dt.getName().equalsIgnoreCase(typeName)) {
                return dt;
            }
        }

        // Handle common aliases
        switch (typeName.toLowerCase()) {
            case "int": return new IntegerDataType();
            case "uint": return new UnsignedIntegerDataType();
            case "short": return new ShortDataType();
            case "ushort": return new UnsignedShortDataType();
            case "long": return new LongDataType();
            case "ulong": return new UnsignedLongDataType();
            case "byte": return new ByteDataType();
            case "ubyte": return new UnsignedCharDataType();
            case "char": return new CharDataType();
            case "uchar": return new UnsignedCharDataType();
            case "float": return new FloatDataType();
            case "double": return new DoubleDataType();
            case "void": return new VoidDataType();
            case "bool": return new BooleanDataType();
            case "dword": return new DWordDataType();
            case "word": return new WordDataType();
            case "qword": return new QWordDataType();
        }

        // Handle pointer types
        if (typeName.endsWith("*")) {
            String baseTypeName = typeName.substring(0, typeName.length() - 1).trim();
            DataType baseType = findDataType(dtm, baseTypeName);
            if (baseType != null) {
                return dtm.getPointer(baseType);
            }
        }

        return null;
    }

    /**
     * Create a structure data type.
     */
    public String createStruct(String name, String fieldsJson) {
        Program program = getProgram(null);
        if (program == null) {
            return "Error: No program loaded";
        }

        if (name == null || name.isEmpty()) {
            return "Error: Structure name is required";
        }
        if (fieldsJson == null || fieldsJson.isEmpty()) {
            return "Error: Fields array is required";
        }

        try {
            return threadingStrategy.executeWrite(program, "Create structure", () -> {
                DataTypeManager dtm = program.getDataTypeManager();

                // Check if struct already exists
                java.util.Iterator<DataType> iter = dtm.getAllDataTypes();
                while (iter.hasNext()) {
                    DataType dt = iter.next();
                    if (dt.getName().equals(name) && dt instanceof Structure) {
                        return "Error: Structure '" + name + "' already exists";
                    }
                }

                // Create new structure
                StructureDataType struct = new StructureDataType(name, 0);

                // Parse fields JSON: [{"name": "field1", "type": "int"}, ...]
                List<Map<String, String>> fields = parseFieldsJson(fieldsJson);

                for (Map<String, String> field : fields) {
                    String fieldName = field.get("name");
                    String fieldType = field.get("type");

                    if (fieldName == null || fieldType == null) {
                        continue;
                    }

                    DataType fieldDataType = findDataType(dtm, fieldType);
                    if (fieldDataType == null) {
                        return "Error: Unknown field type: " + fieldType;
                    }

                    struct.add(fieldDataType, fieldName, null);
                }

                // Add to data type manager
                dtm.addDataType(struct, null);

                return "Success: Created structure '" + name + "' with " + fields.size() + " fields";
            });
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Parse a simple JSON array of field objects.
     */
    private List<Map<String, String>> parseFieldsJson(String json) {
        List<Map<String, String>> fields = new ArrayList<>();

        json = json.trim();
        if (!json.startsWith("[") || !json.endsWith("]")) {
            return fields;
        }

        json = json.substring(1, json.length() - 1).trim();
        if (json.isEmpty()) {
            return fields;
        }

        // Simple parsing - split by }, {
        int depth = 0;
        StringBuilder current = new StringBuilder();

        for (int i = 0; i < json.length(); i++) {
            char c = json.charAt(i);

            if (c == '{') {
                depth++;
                if (depth == 1) {
                    current = new StringBuilder();
                    continue;
                }
            } else if (c == '}') {
                depth--;
                if (depth == 0) {
                    // Parse the object
                    Map<String, String> field = parseSimpleJsonObject("{" + current.toString() + "}");
                    if (!field.isEmpty()) {
                        fields.add(field);
                    }
                    continue;
                }
            }

            if (depth > 0) {
                current.append(c);
            }
        }

        return fields;
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
    public String applyDataType(String addressStr, String typeName, boolean clearExisting) {
        Program program = getProgram(null);
        if (program == null) {
            return "Error: No program loaded";
        }

        if (addressStr == null || addressStr.isEmpty()) {
            return "Error: Address is required";
        }
        if (typeName == null || typeName.isEmpty()) {
            return "Error: Type name is required";
        }

        Address addr = parseAddress(program, addressStr);
        if (addr == null) {
            return "Error: Invalid address: " + addressStr;
        }

        try {
            return threadingStrategy.executeWrite(program, "Apply data type", () -> {
                DataTypeManager dtm = program.getDataTypeManager();
                DataType dataType = findDataType(dtm, typeName);

                if (dataType == null) {
                    return "Error: Data type not found: " + typeName;
                }

                Listing listing = program.getListing();

                if (clearExisting) {
                    // Clear existing data/code
                    listing.clearCodeUnits(addr, addr.add(dataType.getLength() - 1), false);
                }

                // Create the data
                try {
                    listing.createData(addr, dataType);
                    return "Success: Applied '" + typeName + "' at " + addressStr;
                } catch (Exception e) {
                    return "Error: Failed to apply data type - " + e.getMessage();
                }
            });
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Batch rename multiple variables in a function.
     */
    public String batchRenameVariables(String functionAddress, String renamesJson) {
        Program program = getProgram(null);
        if (program == null) {
            return "Error: No program loaded";
        }

        if (functionAddress == null || functionAddress.isEmpty()) {
            return "Error: Function address is required";
        }
        if (renamesJson == null || renamesJson.isEmpty()) {
            return "Error: Renames object is required";
        }

        Address addr = parseAddress(program, functionAddress);
        if (addr == null) {
            return "Error: Invalid address: " + functionAddress;
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
     * Set a function's plate (header) comment.
     */
    public String setPlateComment(String functionAddress, String comment) {
        Program program = getProgram(null);
        if (program == null) {
            return "Error: No program loaded";
        }

        if (functionAddress == null || functionAddress.isEmpty()) {
            return "Error: Function address is required";
        }
        if (comment == null) {
            return "Error: Comment is required";
        }

        Address addr = parseAddress(program, functionAddress);
        if (addr == null) {
            return "Error: Invalid address: " + functionAddress;
        }

        try {
            return threadingStrategy.executeWrite(program, "Set plate comment", () -> {
                Function func = program.getFunctionManager().getFunctionAt(addr);
                if (func == null) {
                    func = program.getFunctionManager().getFunctionContaining(addr);
                }
                if (func == null) {
                    return "Error: No function found at address: " + functionAddress;
                }

                // Set plate comment at function entry point
                Listing listing = program.getListing();
                listing.setComment(func.getEntryPoint(), CodeUnit.PLATE_COMMENT, comment);

                return "Success: Set plate comment for " + func.getName();
            });
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // ==========================================================================
    // PHASE 2: PRODUCTIVITY ENDPOINTS
    // ==========================================================================

    /**
     * Set multiple comments in a single batch operation.
     */
    public String batchSetComments(String functionAddress, String decompilerCommentsJson,
                                   String disassemblyCommentsJson, String plateComment) {
        Program program = getProgram(null);
        if (program == null) {
            return "{\"error\": \"No program loaded\"}";
        }

        if (functionAddress == null || functionAddress.isEmpty()) {
            return "{\"error\": \"Function address is required\"}";
        }

        Address addr = parseAddress(program, functionAddress);
        if (addr == null) {
            return "{\"error\": \"Invalid address: " + escapeJson(functionAddress) + "\"}";
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

                // Set plate comment if provided
                if (plateComment != null && !plateComment.isEmpty()) {
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
                            Address commentAddr = parseAddress(program, addrStr);
                            if (commentAddr != null) {
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
                            Address commentAddr = parseAddress(program, addrStr);
                            if (commentAddr != null) {
                                listing.setComment(commentAddr, CodeUnit.EOL_COMMENT, text);
                                disassemblySet++;
                            }
                        }
                    }
                }

                return "{\"success\": true, \"plate_comments_set\": " + plateSet +
                       ", \"decompiler_comments_set\": " + decompilerSet +
                       ", \"disassembly_comments_set\": " + disassemblySet + "}";
            });
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    /**
     * Create multiple labels in a single batch operation.
     */
    public String batchCreateLabels(String labelsJson) {
        Program program = getProgram(null);
        if (program == null) {
            return "{\"error\": \"No program loaded\"}";
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

                    Address addr = parseAddress(program, addrStr);
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
    public String deleteLabel(String addressStr, String labelName) {
        Program program = getProgram(null);
        if (program == null) {
            return "{\"error\": \"No program loaded\"}";
        }

        if (addressStr == null || addressStr.isEmpty()) {
            return "{\"error\": \"Address is required\"}";
        }

        try {
            return threadingStrategy.executeWrite(program, "Delete label", () -> {
                Address address = parseAddress(program, addressStr);
                if (address == null) {
                    return "{\"error\": \"Invalid address: " + addressStr + "\"}";
                }

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
    public String batchDeleteLabels(String labelsJson) {
        Program program = getProgram(null);
        if (program == null) {
            return "{\"error\": \"No program loaded\"}";
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

                    Address addr = parseAddress(program, addrStr);
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
        Program program = getProgram(programName);
        if (program == null) {
            return getProgramError(programName);
        }

        FunctionManager fm = program.getFunctionManager();
        ReferenceManager refMgr = program.getReferenceManager();
        List<FunctionInfo> results = new ArrayList<>();

        FunctionIterator funcIter = fm.getFunctions(true);
        while (funcIter.hasNext()) {
            Function func = funcIter.next();
            String name = func.getName();

            // Filter by name pattern
            if (namePattern != null && !namePattern.isEmpty()) {
                boolean matches;
                if (regex) {
                    try {
                        matches = name.matches(namePattern);
                    } catch (Exception e) {
                        matches = false;
                    }
                } else {
                    matches = name.toLowerCase().contains(namePattern.toLowerCase());
                }
                if (!matches) continue;
            }

            // Filter by custom name
            if (hasCustomName != null) {
                boolean isCustom = !name.startsWith("FUN_");
                if (hasCustomName && !isCustom) continue;
                if (!hasCustomName && isCustom) continue;
            }

            // Count xrefs
            int xrefCount = 0;
            for (Reference ref : refMgr.getReferencesTo(func.getEntryPoint())) {
                xrefCount++;
            }

            // Filter by xref count
            if (minXrefs != null && xrefCount < minXrefs) continue;
            if (maxXrefs != null && xrefCount > maxXrefs) continue;

            results.add(new FunctionInfo(name, func.getEntryPoint().toString(), xrefCount));
        }

        // Sort results
        if ("xref_count".equalsIgnoreCase(sortBy)) {
            results.sort((a, b) -> Integer.compare(b.xrefCount, a.xrefCount));
        } else if ("name".equalsIgnoreCase(sortBy)) {
            results.sort((a, b) -> a.name.compareToIgnoreCase(b.name));
        } else {
            // Default: sort by address
            results.sort((a, b) -> a.address.compareTo(b.address));
        }

        // Build JSON response with pagination
        StringBuilder sb = new StringBuilder();
        sb.append("{\"total\": ").append(results.size());
        sb.append(", \"offset\": ").append(offset);
        sb.append(", \"limit\": ").append(limit);
        sb.append(", \"results\": [");

        int start = Math.max(0, offset);
        int end = Math.min(results.size(), start + limit);
        for (int i = start; i < end; i++) {
            if (i > start) sb.append(", ");
            FunctionInfo fi = results.get(i);
            sb.append("{\"name\": \"").append(escapeJson(fi.name)).append("\"");
            sb.append(", \"address\": \"").append(fi.address).append("\"");
            sb.append(", \"xref_count\": ").append(fi.xrefCount).append("}");
        }

        sb.append("]}");
        return sb.toString();
    }

    /**
     * Comprehensive function analysis in a single call.
     */
    public String analyzeFunctionComplete(String name, boolean includeXrefs, boolean includeCallees,
                                          boolean includeCallers, boolean includeDisasm,
                                          boolean includeVariables, String programName) {
        Program program = getProgram(programName);
        if (program == null) {
            return getProgramError(programName);
        }

        FunctionManager fm = program.getFunctionManager();
        Function func = null;
        for (Function f : fm.getFunctions(true)) {
            if (f.getName().equals(name)) {
                func = f;
                break;
            }
        }
        if (func == null) {
            return "{\"error\": \"Function not found: " + escapeJson(name) + "\"}";
        }

        StringBuilder sb = new StringBuilder();
        sb.append("{");

        // Basic info
        sb.append("\"name\": \"").append(escapeJson(func.getName())).append("\"");
        sb.append(", \"address\": \"").append(func.getEntryPoint()).append("\"");
        sb.append(", \"signature\": \"").append(escapeJson(func.getSignature().getPrototypeString())).append("\"");

        // Decompiled code
        String decompiled = decompileFunction(null, name, programName);
        sb.append(", \"decompiled_code\": \"").append(escapeJson(decompiled)).append("\"");

        // Xrefs
        if (includeXrefs) {
            sb.append(", \"xrefs\": [");
            ReferenceManager refMgr = program.getReferenceManager();
            int count = 0;
            for (Reference ref : refMgr.getReferencesTo(func.getEntryPoint())) {
                if (count > 0) sb.append(", ");
                sb.append("{\"from\": \"").append(ref.getFromAddress()).append("\"");
                sb.append(", \"type\": \"").append(ref.getReferenceType()).append("\"}");
                if (++count >= 50) break;
            }
            sb.append("]");
        }

        // Callees
        if (includeCallees) {
            String callees = getFunctionCallees(name, 0, 50, programName);
            sb.append(", \"callees\": [");
            String[] lines = callees.split("\n");
            boolean first = true;
            for (String line : lines) {
                if (line.isEmpty() || line.contains("error")) continue;
                if (!first) sb.append(", ");
                sb.append("\"").append(escapeJson(line)).append("\"");
                first = false;
            }
            sb.append("]");
        }

        // Callers
        if (includeCallers) {
            String callers = getFunctionCallers(name, 0, 50, programName);
            sb.append(", \"callers\": [");
            String[] lines = callers.split("\n");
            boolean first = true;
            for (String line : lines) {
                if (line.isEmpty() || line.contains("error")) continue;
                if (!first) sb.append(", ");
                sb.append("\"").append(escapeJson(line)).append("\"");
                first = false;
            }
            sb.append("]");
        }

        // Disassembly
        if (includeDisasm) {
            String disasm = disassembleFunction(func.getEntryPoint().toString(), programName);
            sb.append(", \"disassembly\": \"").append(escapeJson(disasm)).append("\"");
        }

        // Variables
        if (includeVariables) {
            String vars = getFunctionVariables(name, programName);
            sb.append(", \"variables\": ").append(vars);
        }

        sb.append("}");
        return sb.toString();
    }

    /**
     * Get cross-references for multiple addresses in bulk.
     */
    public String getBulkXrefs(String addressesJson) {
        Program program = getProgram(null);
        if (program == null) {
            return getProgramError(null);
        }

        if (addressesJson == null || addressesJson.isEmpty()) {
            return "{\"error\": \"Addresses JSON array is required\"}";
        }

        List<String> addresses = parseStringArray(addressesJson);
        if (addresses.isEmpty()) {
            return "{\"error\": \"No valid addresses in input\"}";
        }

        ReferenceManager refMgr = program.getReferenceManager();
        StringBuilder sb = new StringBuilder();
        sb.append("{");

        boolean first = true;
        for (String addrStr : addresses) {
            Address addr = parseAddress(program, addrStr);
            if (addr == null) continue;

            if (!first) sb.append(", ");
            sb.append("\"").append(addrStr).append("\": [");

            int count = 0;
            for (Reference ref : refMgr.getReferencesTo(addr)) {
                if (count > 0) sb.append(", ");
                sb.append("{\"from\": \"").append(ref.getFromAddress()).append("\"");
                sb.append(", \"type\": \"").append(ref.getReferenceType()).append("\"}");
                if (++count >= 20) break;
            }
            sb.append("]");
            first = false;
        }

        sb.append("}");
        return sb.toString();
    }

    /**
     * List global variables with optional filtering.
     */
    public String listGlobals(int offset, int limit, String filter, String programName) {
        Program program = getProgram(programName);
        if (program == null) {
            return getProgramError(programName);
        }

        SymbolTable symbolTable = program.getSymbolTable();
        List<String> results = new ArrayList<>();

        SymbolIterator symbols = symbolTable.getAllSymbols(true);
        while (symbols.hasNext()) {
            Symbol sym = symbols.next();
            // Only include global symbols (not in functions)
            if (sym.isGlobal() && !sym.getName().startsWith("FUN_") &&
                !sym.getName().startsWith("LAB_") && !sym.getName().startsWith("DAT_")) {

                String name = sym.getName();

                // Apply filter if provided
                if (filter != null && !filter.isEmpty()) {
                    if (!name.toLowerCase().contains(filter.toLowerCase())) {
                        continue;
                    }
                }

                String entry = name + " @ " + sym.getAddress();
                results.add(entry);
            }
        }

        return paginateList(results, offset, limit);
    }

    /**
     * Rename a global variable.
     */
    public String renameGlobalVariable(String oldName, String newName) {
        Program program = getProgram(null);
        if (program == null) {
            return "Error: No program loaded";
        }

        if (oldName == null || oldName.isEmpty()) {
            return "Error: Old name is required";
        }
        if (newName == null || newName.isEmpty()) {
            return "Error: New name is required";
        }

        try {
            return threadingStrategy.executeWrite(program, "Rename global variable", () -> {
                SymbolTable symbolTable = program.getSymbolTable();
                List<Symbol> symbols = symbolTable.getGlobalSymbols(oldName);

                if (symbols.isEmpty()) {
                    return "Error: Global variable not found: " + oldName;
                }

                Symbol sym = symbols.get(0);
                sym.setName(newName, SourceType.USER_DEFINED);

                return "Success: Renamed " + oldName + " to " + newName;
            });
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Force re-decompilation of a function (clear cache).
     */
    public String forceDecompile(String address, String name, String programName) {
        Program program = getProgram(programName);
        if (program == null) {
            return getProgramError(programName);
        }

        Function func = null;
        FunctionManager fm = program.getFunctionManager();

        if (name != null && !name.isEmpty()) {
            for (Function f : fm.getFunctions(true)) {
                if (f.getName().equals(name)) {
                    func = f;
                    break;
                }
            }
        } else if (address != null && !address.isEmpty()) {
            Address addr = parseAddress(program, address);
            if (addr != null) {
                func = fm.getFunctionAt(addr);
                if (func == null) {
                    func = fm.getFunctionContaining(addr);
                }
            }
        }

        if (func == null) {
            return "{\"error\": \"Function not found\"}";
        }

        // Create a fresh decompiler to force re-decompilation
        DecompInterface decompiler = new DecompInterface();
        try {
            decompiler.openProgram(program);
            DecompileResults results = decompiler.decompileFunction(func, DECOMPILE_TIMEOUT_SECONDS, monitor);

            if (results == null || !results.decompileCompleted()) {
                return "{\"error\": \"Decompilation failed\"}";
            }

            String code = results.getDecompiledFunction().getC();
            return code != null ? code : "{\"error\": \"No decompiled code available\"}";
        } finally {
            decompiler.dispose();
        }
    }

    /**
     * Get program entry points.
     */
    public String getEntryPoints(String programName) {
        Program program = getProgram(programName);
        if (program == null) {
            return getProgramError(programName);
        }

        SymbolTable symbolTable = program.getSymbolTable();
        StringBuilder sb = new StringBuilder();
        sb.append("{\"entry_points\": [");

        ghidra.program.model.address.AddressIterator addresses = symbolTable.getExternalEntryPointIterator();
        boolean first = true;
        while (addresses.hasNext()) {
            Address addr = addresses.next();
            Symbol sym = symbolTable.getPrimarySymbol(addr);
            String name = (sym != null) ? sym.getName() : "entry_" + addr;
            if (!first) sb.append(", ");
            sb.append("{\"name\": \"").append(escapeJson(name)).append("\"");
            sb.append(", \"address\": \"").append(addr).append("\"}");
            first = false;
        }

        sb.append("]}");
        return sb.toString();
    }

    /**
     * List available calling conventions.
     */
    public String listCallingConventions(String programName) {
        Program program = getProgram(programName);
        if (program == null) {
            return getProgramError(programName);
        }

        FunctionManager fm = program.getFunctionManager();
        StringBuilder sb = new StringBuilder();
        sb.append("{\"calling_conventions\": [");

        Collection<String> conventions = fm.getCallingConventionNames();
        boolean first = true;
        for (String convention : conventions) {
            if (!first) sb.append(", ");
            sb.append("\"").append(escapeJson(convention)).append("\"");
            first = false;
        }

        sb.append("]}");
        return sb.toString();
    }

    /**
     * Find next undefined function based on criteria.
     */
    public String findNextUndefinedFunction(String startAddress, String criteria,
                                            String pattern, String direction, String programName) {
        Program program = getProgram(programName);
        if (program == null) {
            return getProgramError(programName);
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
            String name = func.getName();

            if (name.contains(searchPattern)) {
                StringBuilder sb = new StringBuilder();
                sb.append("{\"found\": true");
                sb.append(", \"name\": \"").append(escapeJson(name)).append("\"");
                sb.append(", \"address\": \"").append(func.getEntryPoint()).append("\"");
                sb.append(", \"signature\": \"").append(escapeJson(func.getSignature().getPrototypeString())).append("\"");
                sb.append("}");
                return sb.toString();
            }
        }

        return "{\"found\": false}";
    }

    // ==========================================================================
    // PHASE 2 HELPER METHODS
    // ==========================================================================

    private static class FunctionInfo {
        String name;
        String address;
        int xrefCount;

        FunctionInfo(String name, String address, int xrefCount) {
            this.name = name;
            this.address = address;
            this.xrefCount = xrefCount;
        }
    }

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

    private List<String> parseStringArray(String json) {
        List<String> result = new ArrayList<>();
        if (json == null || json.isEmpty()) return result;

        json = json.trim();
        if (!json.startsWith("[")) return result;

        // Remove brackets
        json = json.substring(1, json.length() - 1).trim();
        if (json.isEmpty()) return result;

        // Split by comma
        String[] items = json.split(",");
        for (String item : items) {
            item = item.trim().replace("\"", "");
            if (!item.isEmpty()) {
                result.add(item);
            }
        }
        return result;
    }

    // ==========================================================================
    // PHASE 3: DATA TYPE SYSTEM ENDPOINTS (15 endpoints)
    // ==========================================================================

    /**
     * Create an enumeration data type
     */
    public String createEnum(String name, String valuesJson, int size) {
        Program program = getProgram(null);
        if (program == null) {
            return getProgramError(null);
        }

        if (name == null || name.isEmpty()) {
            return "{\"error\": \"Enumeration name is required\"}";
        }

        if (valuesJson == null || valuesJson.isEmpty()) {
            return "{\"error\": \"Values JSON is required\"}";
        }

        if (size != 1 && size != 2 && size != 4 && size != 8) {
            return "{\"error\": \"Invalid size. Must be 1, 2, 4, or 8 bytes\"}";
        }

        try {
            return threadingStrategy.executeWrite(program, "Create Enumeration: " + name, () -> {
                Map<String, Long> values = parseEnumValuesJson(valuesJson);

                if (values.isEmpty()) {
                    return "{\"error\": \"No valid enum values provided\"}";
                }

                DataTypeManager dtm = program.getDataTypeManager();

                // Check if enum already exists
                DataType existingType = dtm.getDataType("/" + name);
                if (existingType != null) {
                    return "{\"error\": \"Enumeration with name '" + name + "' already exists\"}";
                }

                ghidra.program.model.data.EnumDataType enumDt =
                    new ghidra.program.model.data.EnumDataType(name, size);

                for (Map.Entry<String, Long> entry : values.entrySet()) {
                    enumDt.add(entry.getKey(), entry.getValue());
                }

                dtm.addDataType(enumDt, null);

                return "{\"success\": true, \"message\": \"Created enumeration '" + name +
                       "' with " + values.size() + " values, size: " + size + " bytes\"}";
            });
        } catch (Exception e) {
            return "{\"error\": \"Error creating enumeration: " + escapeJson(e.getMessage()) + "\"}";
        }
    }

    /**
     * Create a union data type
     */
    public String createUnion(String name, String fieldsJson) {
        Program program = getProgram(null);
        if (program == null) {
            return getProgramError(null);
        }

        if (name == null || name.isEmpty()) {
            return "{\"error\": \"Union name is required\"}";
        }

        if (fieldsJson == null || fieldsJson.isEmpty()) {
            return "{\"error\": \"Fields JSON is required\"}";
        }

        try {
            return threadingStrategy.executeWrite(program, "Create Union: " + name, () -> {
                DataTypeManager dtm = program.getDataTypeManager();
                ghidra.program.model.data.UnionDataType union =
                    new ghidra.program.model.data.UnionDataType(name);

                List<Map<String, String>> fields = parseFieldsList(fieldsJson);

                if (fields.isEmpty()) {
                    return "{\"error\": \"No valid fields provided\"}";
                }

                int addedCount = 0;
                for (Map<String, String> field : fields) {
                    String fieldName = field.get("name");
                    String fieldType = field.get("type");

                    if (fieldName != null && fieldType != null) {
                        DataType dt = resolveDataType(dtm, fieldType);
                        if (dt != null) {
                            union.add(dt, fieldName, null);
                            addedCount++;
                        }
                    }
                }

                dtm.addDataType(union, DataTypeConflictHandler.REPLACE_HANDLER);

                return "{\"success\": true, \"message\": \"Union '" + name +
                       "' created with " + addedCount + " fields\"}";
            });
        } catch (Exception e) {
            return "{\"error\": \"Error creating union: " + escapeJson(e.getMessage()) + "\"}";
        }
    }

    /**
     * Create a typedef (type alias)
     */
    public String createTypedef(String name, String baseType) {
        Program program = getProgram(null);
        if (program == null) {
            return getProgramError(null);
        }

        if (name == null || name.isEmpty()) {
            return "{\"error\": \"Typedef name is required\"}";
        }

        if (baseType == null || baseType.isEmpty()) {
            return "{\"error\": \"Base type is required\"}";
        }

        try {
            return threadingStrategy.executeWrite(program, "Create Typedef: " + name, () -> {
                DataTypeManager dtm = program.getDataTypeManager();
                DataType base = null;

                // Handle pointer syntax (e.g., "UnitAny *")
                if (baseType.endsWith(" *") || baseType.endsWith("*")) {
                    String baseTypeName = baseType.replace(" *", "").replace("*", "").trim();
                    DataType baseDataType = findDataTypeByName(dtm, baseTypeName);
                    if (baseDataType != null) {
                        base = new PointerDataType(baseDataType);
                    } else {
                        return "{\"error\": \"Base type not found for pointer: " + baseTypeName + "\"}";
                    }
                } else {
                    base = resolveDataType(dtm, baseType);
                }

                if (base == null) {
                    return "{\"error\": \"Base type not found: " + baseType + "\"}";
                }

                TypedefDataType typedef = new TypedefDataType(name, base);
                dtm.addDataType(typedef, DataTypeConflictHandler.REPLACE_HANDLER);

                return "{\"success\": true, \"message\": \"Typedef '" + name +
                       "' created as alias for '" + baseType + "'\"}";
            });
        } catch (Exception e) {
            return "{\"error\": \"Error creating typedef: " + escapeJson(e.getMessage()) + "\"}";
        }
    }

    /**
     * Create an array data type
     */
    public String createArrayType(String baseType, int length, String name) {
        Program program = getProgram(null);
        if (program == null) {
            return getProgramError(null);
        }

        if (baseType == null || baseType.isEmpty()) {
            return "{\"error\": \"Base type is required\"}";
        }

        if (length <= 0) {
            return "{\"error\": \"Array length must be positive\"}";
        }

        try {
            return threadingStrategy.executeWrite(program, "Create Array Type", () -> {
                DataTypeManager dtm = program.getDataTypeManager();
                DataType baseDataType = resolveDataType(dtm, baseType);

                if (baseDataType == null) {
                    return "{\"error\": \"Base data type not found: " + baseType + "\"}";
                }

                ArrayDataType arrayType = new ArrayDataType(baseDataType, length, baseDataType.getLength());

                if (name != null && !name.isEmpty()) {
                    arrayType.setName(name);
                }

                DataType addedType = dtm.addDataType(arrayType, DataTypeConflictHandler.REPLACE_HANDLER);

                return "{\"success\": true, \"message\": \"Created array type: " +
                       addedType.getName() + " (" + baseType + "[" + length + "])\"}";
            });
        } catch (Exception e) {
            return "{\"error\": \"Error creating array type: " + escapeJson(e.getMessage()) + "\"}";
        }
    }

    /**
     * Create a pointer data type
     */
    public String createPointerType(String baseType, String name) {
        Program program = getProgram(null);
        if (program == null) {
            return getProgramError(null);
        }

        if (baseType == null || baseType.isEmpty()) {
            return "{\"error\": \"Base type is required\"}";
        }

        try {
            return threadingStrategy.executeWrite(program, "Create Pointer Type", () -> {
                DataTypeManager dtm = program.getDataTypeManager();
                DataType baseDataType = null;

                if ("void".equals(baseType)) {
                    baseDataType = dtm.getDataType("/void");
                    if (baseDataType == null) {
                        baseDataType = VoidDataType.dataType;
                    }
                } else {
                    baseDataType = resolveDataType(dtm, baseType);
                }

                if (baseDataType == null) {
                    return "{\"error\": \"Base data type not found: " + baseType + "\"}";
                }

                PointerDataType pointerType = new PointerDataType(baseDataType);

                if (name != null && !name.isEmpty()) {
                    pointerType.setName(name);
                }

                DataType addedType = dtm.addDataType(pointerType, DataTypeConflictHandler.REPLACE_HANDLER);

                return "{\"success\": true, \"message\": \"Created pointer type: " +
                       addedType.getName() + " (" + baseType + "*)\"}";
            });
        } catch (Exception e) {
            return "{\"error\": \"Error creating pointer type: " + escapeJson(e.getMessage()) + "\"}";
        }
    }

    /**
     * Add a field to an existing structure
     */
    public String addStructField(String structName, String fieldName, String fieldType, int offset) {
        Program program = getProgram(null);
        if (program == null) {
            return getProgramError(null);
        }

        if (structName == null || structName.isEmpty()) {
            return "{\"error\": \"Structure name is required\"}";
        }

        if (fieldName == null || fieldName.isEmpty()) {
            return "{\"error\": \"Field name is required\"}";
        }

        if (fieldType == null || fieldType.isEmpty()) {
            return "{\"error\": \"Field type is required\"}";
        }

        try {
            return threadingStrategy.executeWrite(program, "Add Struct Field", () -> {
                DataTypeManager dtm = program.getDataTypeManager();
                DataType dataType = findDataTypeByName(dtm, structName);

                if (dataType == null) {
                    return "{\"error\": \"Structure not found: " + structName + "\"}";
                }

                if (!(dataType instanceof Structure)) {
                    return "{\"error\": \"Data type '" + structName + "' is not a structure\"}";
                }

                Structure struct = (Structure) dataType;
                DataType newFieldType = resolveDataType(dtm, fieldType);

                if (newFieldType == null) {
                    return "{\"error\": \"Field data type not found: " + fieldType + "\"}";
                }

                if (offset >= 0) {
                    struct.insertAtOffset(offset, newFieldType, newFieldType.getLength(), fieldName, null);
                } else {
                    struct.add(newFieldType, fieldName, null);
                }

                return "{\"success\": true, \"message\": \"Added field '" + fieldName +
                       "' to structure '" + structName + "'\"}";
            });
        } catch (Exception e) {
            return "{\"error\": \"Error adding struct field: " + escapeJson(e.getMessage()) + "\"}";
        }
    }

    /**
     * Modify a field in an existing structure
     */
    public String modifyStructField(String structName, String fieldName, String newType, String newName) {
        Program program = getProgram(null);
        if (program == null) {
            return getProgramError(null);
        }

        if (structName == null || structName.isEmpty()) {
            return "{\"error\": \"Structure name is required\"}";
        }

        if (fieldName == null || fieldName.isEmpty()) {
            return "{\"error\": \"Field name is required\"}";
        }

        try {
            return threadingStrategy.executeWrite(program, "Modify Struct Field", () -> {
                DataTypeManager dtm = program.getDataTypeManager();
                DataType dataType = findDataTypeByName(dtm, structName);

                if (dataType == null) {
                    return "{\"error\": \"Structure not found: " + structName + "\"}";
                }

                if (!(dataType instanceof Structure)) {
                    return "{\"error\": \"Data type '" + structName + "' is not a structure\"}";
                }

                Structure struct = (Structure) dataType;
                DataTypeComponent[] components = struct.getDefinedComponents();
                DataTypeComponent targetComponent = null;

                for (DataTypeComponent component : components) {
                    if (fieldName.equals(component.getFieldName())) {
                        targetComponent = component;
                        break;
                    }
                }

                if (targetComponent == null) {
                    return "{\"error\": \"Field '" + fieldName + "' not found in structure '" + structName + "'\"}";
                }

                if (newType != null && !newType.isEmpty()) {
                    DataType newDataType = resolveDataType(dtm, newType);
                    if (newDataType == null) {
                        return "{\"error\": \"New data type not found: " + newType + "\"}";
                    }
                    struct.replace(targetComponent.getOrdinal(), newDataType, newDataType.getLength());
                }

                if (newName != null && !newName.isEmpty()) {
                    targetComponent = struct.getComponent(targetComponent.getOrdinal());
                    targetComponent.setFieldName(newName);
                }

                return "{\"success\": true, \"message\": \"Modified field '" + fieldName +
                       "' in structure '" + structName + "'\"}";
            });
        } catch (Exception e) {
            return "{\"error\": \"Error modifying struct field: " + escapeJson(e.getMessage()) + "\"}";
        }
    }

    /**
     * Remove a field from an existing structure
     */
    public String removeStructField(String structName, String fieldName) {
        Program program = getProgram(null);
        if (program == null) {
            return getProgramError(null);
        }

        if (structName == null || structName.isEmpty()) {
            return "{\"error\": \"Structure name is required\"}";
        }

        if (fieldName == null || fieldName.isEmpty()) {
            return "{\"error\": \"Field name is required\"}";
        }

        try {
            return threadingStrategy.executeWrite(program, "Remove Struct Field", () -> {
                DataTypeManager dtm = program.getDataTypeManager();
                DataType dataType = findDataTypeByName(dtm, structName);

                if (dataType == null) {
                    return "{\"error\": \"Structure not found: " + structName + "\"}";
                }

                if (!(dataType instanceof Structure)) {
                    return "{\"error\": \"Data type '" + structName + "' is not a structure\"}";
                }

                Structure struct = (Structure) dataType;
                DataTypeComponent[] components = struct.getDefinedComponents();
                int targetOrdinal = -1;

                for (DataTypeComponent component : components) {
                    if (fieldName.equals(component.getFieldName())) {
                        targetOrdinal = component.getOrdinal();
                        break;
                    }
                }

                if (targetOrdinal == -1) {
                    return "{\"error\": \"Field '" + fieldName + "' not found in structure '" + structName + "'\"}";
                }

                struct.delete(targetOrdinal);

                return "{\"success\": true, \"message\": \"Removed field '" + fieldName +
                       "' from structure '" + structName + "'\"}";
            });
        } catch (Exception e) {
            return "{\"error\": \"Error removing struct field: " + escapeJson(e.getMessage()) + "\"}";
        }
    }

    /**
     * Delete a data type
     */
    public String deleteDataType(String typeName) {
        Program program = getProgram(null);
        if (program == null) {
            return getProgramError(null);
        }

        if (typeName == null || typeName.isEmpty()) {
            return "{\"error\": \"Type name is required\"}";
        }

        try {
            return threadingStrategy.executeWrite(program, "Delete Data Type", () -> {
                DataTypeManager dtm = program.getDataTypeManager();
                DataType dataType = findDataTypeByName(dtm, typeName);

                if (dataType == null) {
                    return "{\"error\": \"Data type not found: " + typeName + "\"}";
                }

                boolean deleted = dtm.remove(dataType, null);
                if (deleted) {
                    return "{\"success\": true, \"message\": \"Data type '" + typeName + "' deleted\"}";
                } else {
                    return "{\"error\": \"Failed to delete data type '" + typeName + "'\"}";
                }
            });
        } catch (Exception e) {
            return "{\"error\": \"Error deleting data type: " + escapeJson(e.getMessage()) + "\"}";
        }
    }

    /**
     * Search for data types by pattern
     */
    public String searchDataTypes(String pattern, int offset, int limit) {
        Program program = getProgram(null);
        if (program == null) {
            return getProgramError(null);
        }

        if (pattern == null || pattern.isEmpty()) {
            return "{\"error\": \"Search pattern is required\"}";
        }

        List<String> matches = new ArrayList<>();
        DataTypeManager dtm = program.getDataTypeManager();

        Iterator<DataType> allTypes = dtm.getAllDataTypes();
        while (allTypes.hasNext()) {
            DataType dt = allTypes.next();
            String name = dt.getName();
            String path = dt.getPathName();

            if (name.toLowerCase().contains(pattern.toLowerCase()) ||
                path.toLowerCase().contains(pattern.toLowerCase())) {
                matches.add(name + " | Size: " + dt.getLength() + " | Path: " + path);
            }
        }

        Collections.sort(matches);
        return paginateList(matches, offset, limit);
    }

    /**
     * Validate if a data type exists
     */
    public String validateDataTypeExists(String typeName) {
        Program program = getProgram(null);
        if (program == null) {
            return "{\"error\": \"No program loaded\"}";
        }

        if (typeName == null || typeName.isEmpty()) {
            return "{\"error\": \"Type name is required\"}";
        }

        try {
            DataTypeManager dtm = program.getDataTypeManager();
            DataType dt = findDataTypeByName(dtm, typeName);

            StringBuilder sb = new StringBuilder();
            sb.append("{\"exists\": ").append(dt != null);
            sb.append(", \"type_name\": \"").append(escapeJson(typeName)).append("\"");
            if (dt != null) {
                sb.append(", \"category\": \"").append(escapeJson(dt.getCategoryPath().getPath())).append("\"");
                sb.append(", \"size\": ").append(dt.getLength());
            }
            sb.append("}");
            return sb.toString();

        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    /**
     * Get the size of a data type
     */
    public String getDataTypeSize(String typeName) {
        Program program = getProgram(null);
        if (program == null) {
            return getProgramError(null);
        }

        if (typeName == null || typeName.isEmpty()) {
            return "{\"error\": \"Type name is required\"}";
        }

        DataTypeManager dtm = program.getDataTypeManager();
        DataType dataType = findDataTypeByName(dtm, typeName);

        if (dataType == null) {
            return "{\"error\": \"Data type not found: " + typeName + "\"}";
        }

        StringBuilder sb = new StringBuilder();
        sb.append("{\"type_name\": \"").append(escapeJson(dataType.getName())).append("\"");
        sb.append(", \"size\": ").append(dataType.getLength());
        sb.append(", \"alignment\": ").append(dataType.getAlignment());
        sb.append(", \"path\": \"").append(escapeJson(dataType.getPathName())).append("\"");
        sb.append("}");
        return sb.toString();
    }

    /**
     * Get the layout of a structure
     */
    public String getStructLayout(String structName) {
        Program program = getProgram(null);
        if (program == null) {
            return getProgramError(null);
        }

        if (structName == null || structName.isEmpty()) {
            return "{\"error\": \"Struct name is required\"}";
        }

        DataTypeManager dtm = program.getDataTypeManager();
        DataType dataType = findDataTypeByName(dtm, structName);

        if (dataType == null) {
            return "{\"error\": \"Structure not found: " + structName + "\"}";
        }

        if (!(dataType instanceof Structure)) {
            return "{\"error\": \"Data type is not a structure: " + structName + "\"}";
        }

        Structure struct = (Structure) dataType;
        StringBuilder sb = new StringBuilder();

        sb.append("{\"name\": \"").append(escapeJson(struct.getName())).append("\"");
        sb.append(", \"size\": ").append(struct.getLength());
        sb.append(", \"alignment\": ").append(struct.getAlignment());
        sb.append(", \"fields\": [");

        DataTypeComponent[] components = struct.getDefinedComponents();
        for (int i = 0; i < components.length; i++) {
            if (i > 0) sb.append(", ");
            DataTypeComponent comp = components[i];
            sb.append("{\"offset\": ").append(comp.getOffset());
            sb.append(", \"size\": ").append(comp.getLength());
            sb.append(", \"type\": \"").append(escapeJson(comp.getDataType().getName())).append("\"");
            sb.append(", \"name\": \"").append(escapeJson(comp.getFieldName() != null ? comp.getFieldName() : "(unnamed)")).append("\"");
            sb.append("}");
        }

        sb.append("]}");
        return sb.toString();
    }

    /**
     * Get all values in an enumeration
     */
    public String getEnumValues(String enumName) {
        Program program = getProgram(null);
        if (program == null) {
            return getProgramError(null);
        }

        if (enumName == null || enumName.isEmpty()) {
            return "{\"error\": \"Enum name is required\"}";
        }

        DataTypeManager dtm = program.getDataTypeManager();
        DataType dataType = findDataTypeByName(dtm, enumName);

        if (dataType == null) {
            return "{\"error\": \"Enumeration not found: " + enumName + "\"}";
        }

        if (!(dataType instanceof ghidra.program.model.data.Enum)) {
            return "{\"error\": \"Data type is not an enumeration: " + enumName + "\"}";
        }

        ghidra.program.model.data.Enum enumType = (ghidra.program.model.data.Enum) dataType;
        StringBuilder sb = new StringBuilder();

        sb.append("{\"name\": \"").append(escapeJson(enumType.getName())).append("\"");
        sb.append(", \"size\": ").append(enumType.getLength());
        sb.append(", \"values\": [");

        String[] names = enumType.getNames();
        for (int i = 0; i < names.length; i++) {
            if (i > 0) sb.append(", ");
            String valueName = names[i];
            long value = enumType.getValue(valueName);
            sb.append("{\"name\": \"").append(escapeJson(valueName)).append("\"");
            sb.append(", \"value\": ").append(value);
            sb.append("}");
        }

        sb.append("]}");
        return sb.toString();
    }

    /**
     * Clone/copy a data type with a new name
     */
    public String cloneDataType(String sourceType, String newName) {
        Program program = getProgram(null);
        if (program == null) {
            return getProgramError(null);
        }

        if (sourceType == null || sourceType.isEmpty()) {
            return "{\"error\": \"Source type is required\"}";
        }

        if (newName == null || newName.isEmpty()) {
            return "{\"error\": \"New name is required\"}";
        }

        try {
            return threadingStrategy.executeWrite(program, "Clone Data Type", () -> {
                DataTypeManager dtm = program.getDataTypeManager();
                DataType source = findDataTypeByName(dtm, sourceType);

                if (source == null) {
                    return "{\"error\": \"Source data type not found: " + sourceType + "\"}";
                }

                DataType cloned = source.copy(dtm);
                cloned.setName(newName);

                dtm.addDataType(cloned, DataTypeConflictHandler.REPLACE_HANDLER);

                return "{\"success\": true, \"message\": \"Cloned '" + sourceType +
                       "' as '" + newName + "'\"}";
            });
        } catch (Exception e) {
            return "{\"error\": \"Error cloning data type: " + escapeJson(e.getMessage()) + "\"}";
        }
    }

    // ==========================================================================
    // PHASE 3 HELPER METHODS
    // ==========================================================================

    /**
     * Parse enum values from JSON format {"NAME1": value1, "NAME2": value2}
     */
    private Map<String, Long> parseEnumValuesJson(String valuesJson) {
        Map<String, Long> values = new LinkedHashMap<>();

        try {
            String content = valuesJson.trim();
            if (content.startsWith("{")) {
                content = content.substring(1);
            }
            if (content.endsWith("}")) {
                content = content.substring(0, content.length() - 1);
            }

            String[] pairs = content.split(",");

            for (String pair : pairs) {
                String[] keyValue = pair.split(":");
                if (keyValue.length == 2) {
                    String key = keyValue[0].trim().replace("\"", "");
                    String valueStr = keyValue[1].trim();

                    try {
                        Long value = Long.parseLong(valueStr);
                        values.put(key, value);
                    } catch (NumberFormatException e) {
                        // Skip invalid values
                    }
                }
            }
        } catch (Exception e) {
            // Return empty map on parse error
        }

        return values;
    }

    /**
     * Parse fields list from JSON format [{"name": "...", "type": "..."}, ...]
     */
    private List<Map<String, String>> parseFieldsList(String json) {
        List<Map<String, String>> result = new ArrayList<>();
        if (json == null || json.isEmpty()) return result;

        json = json.trim();
        if (!json.startsWith("[")) return result;

        json = json.substring(1, json.length() - 1).trim();
        if (json.isEmpty()) return result;

        String[] entries = json.split("\\}\\s*,\\s*\\{");
        for (String entry : entries) {
            entry = entry.replace("{", "").replace("}", "").trim();
            Map<String, String> map = new HashMap<>();

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

    /**
     * Find a data type by name in all categories
     */
    private DataType findDataTypeByName(DataTypeManager dtm, String typeName) {
        // First try direct lookup
        DataType dt = dtm.getDataType("/" + typeName);
        if (dt != null) return dt;

        // Search in all categories
        Iterator<DataType> iter = dtm.getAllDataTypes();
        while (iter.hasNext()) {
            DataType dataType = iter.next();
            if (dataType.getName().equals(typeName)) {
                return dataType;
            }
        }

        return null;
    }

    /**
     * Resolve a data type by name, handling builtin types, arrays, and pointers
     */
    private DataType resolveDataType(DataTypeManager dtm, String typeName) {
        // First try direct lookup in root category
        DataType builtinType = dtm.getDataType("/" + typeName);
        if (builtinType != null) {
            return builtinType;
        }

        // Try lowercase version (handles "UINT" → "/uint")
        DataType builtinTypeLower = dtm.getDataType("/" + typeName.toLowerCase());
        if (builtinTypeLower != null) {
            return builtinTypeLower;
        }

        // Search all categories
        DataType dataType = findDataTypeByName(dtm, typeName);
        if (dataType != null) {
            return dataType;
        }

        // Handle array syntax: "type[count]"
        if (typeName.contains("[") && typeName.endsWith("]")) {
            int bracketPos = typeName.indexOf('[');
            String baseTypeName = typeName.substring(0, bracketPos);
            String countStr = typeName.substring(bracketPos + 1, typeName.length() - 1);

            try {
                int count = Integer.parseInt(countStr);
                DataType baseType = resolveDataType(dtm, baseTypeName);

                if (baseType != null && count > 0) {
                    return new ArrayDataType(baseType, count, baseType.getLength());
                }
            } catch (NumberFormatException e) {
                return null;
            }
        }

        // Handle pointer syntax: "type*"
        if (typeName.endsWith("*")) {
            String baseTypeName = typeName.substring(0, typeName.length() - 1).trim();

            if (baseTypeName.equals("void") || baseTypeName.isEmpty()) {
                DataType voidType = dtm.getDataType("/void");
                return new PointerDataType(voidType != null ? voidType : VoidDataType.dataType);
            }

            DataType baseType = resolveDataType(dtm, baseTypeName);
            if (baseType != null) {
                return new PointerDataType(baseType);
            }

            // Default to void* if base type not found
            DataType voidType = dtm.getDataType("/void");
            return new PointerDataType(voidType != null ? voidType : VoidDataType.dataType);
        }

        return null;
    }

    // ==========================================================================
    // PHASE 4: ADVANCED FEATURES ENDPOINTS
    // ==========================================================================

    /**
     * Run a Ghidra script (simplified for headless mode)
     */
    public String runScript(String scriptPath, String scriptArgs) {
        Program program = getProgram(null);
        if (program == null) {
            return "{\"error\": \"No program loaded\"}";
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
    public String searchBytePatterns(String pattern, String mask) {
        Program program = getProgram(null);
        if (program == null) {
            return "{\"error\": \"No program loaded\"}";
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
                                    boolean includeBoundaryDetection) {
        Program program = getProgram(null);
        if (program == null) {
            return "{\"error\": \"No program loaded\"}";
        }

        try {
            Address startAddr = program.getAddressFactory().getAddress(startAddressStr);
            if (startAddr == null) {
                return "{\"error\": \"Invalid address: " + startAddressStr + "\"}";
            }

            ReferenceManager refMgr = program.getReferenceManager();
            Listing listing = program.getListing();

            Address endAddr = startAddr;
            Set<String> uniqueXrefs = new HashSet<>();
            int byteCount = 0;
            StringBuilder xrefMapJson = new StringBuilder();
            xrefMapJson.append("\"xref_map\": {");
            boolean firstXrefEntry = true;

            for (int i = 0; i < maxScanBytes; i++) {
                Address scanAddr = startAddr.add(i);

                // Check for boundary
                if (includeBoundaryDetection) {
                    Symbol[] symbols = program.getSymbolTable().getSymbols(scanAddr);
                    if (symbols.length > 0 && i > 0) {
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
                }

                // Get xrefs
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

            // Classify
            String classification = "PRIMITIVE";
            if (uniqueXrefs.size() > 3) {
                classification = "ARRAY";
            } else if (uniqueXrefs.size() > 1) {
                classification = "STRUCTURE";
            }

            // Build result
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
            result.append("\"current_name\": \"").append(escapeJson(currentName)).append("\",");
            result.append("\"current_type\": \"").append(escapeJson(currentType)).append("\"");
            result.append("}");

            return result.toString();
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    /**
     * Compute a normalized hash for a function
     */
    public String getFunctionHash(String addressStr, String programName) {
        Program program = getProgram(programName);
        if (program == null) {
            return getProgramError(programName);
        }

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            if (addr == null) {
                return "{\"error\": \"Invalid address: " + addressStr + "\"}";
            }

            Function func = program.getFunctionManager().getFunctionAt(addr);
            if (func == null) {
                return "{\"error\": \"No function at address: " + addressStr + "\"}";
            }

            String hash = computeNormalizedFunctionHash(program, func);
            int instructionCount = countFunctionInstructions(program, func);
            boolean hasCustomName = !func.getName().startsWith("FUN_") &&
                                   !func.getName().startsWith("thunk_");

            StringBuilder result = new StringBuilder();
            result.append("{");
            result.append("\"function_name\": \"").append(escapeJson(func.getName())).append("\",");
            result.append("\"address\": \"").append(addr.toString()).append("\",");
            result.append("\"hash\": \"").append(hash).append("\",");
            result.append("\"instruction_count\": ").append(instructionCount).append(",");
            result.append("\"has_custom_name\": ").append(hasCustomName).append(",");
            result.append("\"program\": \"").append(escapeJson(program.getName())).append("\"");
            result.append("}");

            return result.toString();
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    /**
     * Get hashes for multiple functions
     */
    public String getBulkFunctionHashes(int offset, int limit, String filter, String programName) {
        Program program = getProgram(programName);
        if (program == null) {
            return getProgramError(programName);
        }

        try {
            StringBuilder json = new StringBuilder();
            json.append("{\"program\": \"").append(escapeJson(program.getName())).append("\", ");
            json.append("\"functions\": [");

            FunctionManager funcMgr = program.getFunctionManager();
            int total = 0;
            int skipped = 0;
            int added = 0;

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

                if (added > 0) json.append(", ");

                String hash = computeNormalizedFunctionHash(program, func);
                int instructionCount = countFunctionInstructions(program, func);

                json.append("{");
                json.append("\"name\": \"").append(escapeJson(func.getName())).append("\", ");
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
            return "{\"error\": \"Failed to get bulk hashes: " + escapeJson(e.getMessage()) + "\"}";
        }
    }

    /**
     * Detect array bounds based on xref analysis
     */
    public String detectArrayBounds(String addressStr, boolean analyzeLoopBounds,
                                    boolean analyzeIndexing, int maxScanRange) {
        Program program = getProgram(null);
        if (program == null) {
            return "{\"error\": \"No program loaded\"}";
        }

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            if (addr == null) {
                return "{\"error\": \"Invalid address: " + addressStr + "\"}";
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
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    /**
     * Get assembly context around xref sources
     */
    public String getAssemblyContext(String xrefSourcesStr, int contextInstructions, String includePatterns) {
        Program program = getProgram(null);
        if (program == null) {
            return "{\"error\": \"No program loaded\"}";
        }

        StringBuilder json = new StringBuilder();
        json.append("{");

        try {
            // Parse comma-separated addresses
            String[] addresses = xrefSourcesStr.split(",");
            Listing listing = program.getListing();
            boolean first = true;

            for (String addrStr : addresses) {
                addrStr = addrStr.trim();
                if (addrStr.isEmpty()) continue;

                if (!first) json.append(",");
                first = false;

                json.append("\"").append(addrStr).append("\": {");

                try {
                    Address addr = program.getAddressFactory().getAddress(addrStr);
                    if (addr != null) {
                        Instruction instr = listing.getInstructionAt(addr);
                        json.append("\"address\": \"").append(addrStr).append("\",");

                        if (instr != null) {
                            json.append("\"instruction\": \"").append(escapeJson(instr.toString())).append("\",");

                            // Get context before
                            json.append("\"context_before\": [");
                            Address prevAddr = addr;
                            for (int i = 0; i < contextInstructions; i++) {
                                Instruction prevInstr = listing.getInstructionBefore(prevAddr);
                                if (prevInstr == null) break;
                                prevAddr = prevInstr.getAddress();
                                if (i > 0) json.append(",");
                                json.append("\"").append(prevAddr).append(": ").append(escapeJson(prevInstr.toString())).append("\"");
                            }
                            json.append("],");

                            // Get context after
                            json.append("\"context_after\": [");
                            Address nextAddr = addr;
                            for (int i = 0; i < contextInstructions; i++) {
                                Instruction nextInstr = listing.getInstructionAfter(nextAddr);
                                if (nextInstr == null) break;
                                nextAddr = nextInstr.getAddress();
                                if (i > 0) json.append(",");
                                json.append("\"").append(nextAddr).append(": ").append(escapeJson(nextInstr.toString())).append("\"");
                            }
                            json.append("],");

                            json.append("\"mnemonic\": \"").append(instr.getMnemonicString()).append("\"");
                        } else {
                            json.append("\"error\": \"No instruction at address\"");
                        }
                    } else {
                        json.append("\"error\": \"Invalid address\"");
                    }
                } catch (Exception e) {
                    json.append("\"error\": \"").append(escapeJson(e.getMessage())).append("\"");
                }

                json.append("}");
            }
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }

        json.append("}");
        return json.toString();
    }

    /**
     * Analyze how structure fields are accessed
     */
    public String analyzeStructFieldUsage(String addressStr, String structName, int maxFunctions) {
        Program program = getProgram(null);
        if (program == null) {
            return "{\"error\": \"No program loaded\"}";
        }

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            if (addr == null) {
                return "{\"error\": \"Invalid address: " + addressStr + "\"}";
            }

            // Get xrefs to understand usage
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

            StringBuilder result = new StringBuilder();
            result.append("{");
            result.append("\"struct_address\": \"").append(addr.toString()).append("\",");
            result.append("\"struct_name\": ").append(structName != null ? "\"" + escapeJson(structName) + "\"" : "null").append(",");
            result.append("\"functions_analyzed\": ").append(referencingFunctions.size()).append(",");
            result.append("\"referencing_functions\": [");
            for (int i = 0; i < referencingFunctions.size(); i++) {
                if (i > 0) result.append(",");
                result.append("\"").append(escapeJson(referencingFunctions.get(i))).append("\"");
            }
            result.append("]");
            result.append("}");

            return result.toString();
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    /**
     * Get field access context for a structure field
     */
    public String getFieldAccessContext(String structAddressStr, int fieldOffset, int numExamples) {
        Program program = getProgram(null);
        if (program == null) {
            return "{\"error\": \"No program loaded\"}";
        }

        try {
            Address structAddr = program.getAddressFactory().getAddress(structAddressStr);
            if (structAddr == null) {
                return "{\"error\": \"Invalid address: " + structAddressStr + "\"}";
            }

            Address fieldAddr = structAddr.add(fieldOffset);
            ReferenceManager refMgr = program.getReferenceManager();
            ReferenceIterator refIter = refMgr.getReferencesTo(fieldAddr);

            List<String> examples = new ArrayList<>();
            Listing listing = program.getListing();

            while (refIter.hasNext() && examples.size() < numExamples) {
                Reference ref = refIter.next();
                Address fromAddr = ref.getFromAddress();
                Instruction instr = listing.getInstructionAt(fromAddr);
                Function func = program.getFunctionManager().getFunctionContaining(fromAddr);

                StringBuilder example = new StringBuilder();
                example.append("{\"from_address\": \"").append(fromAddr.toString()).append("\"");
                example.append(", \"ref_type\": \"").append(ref.getReferenceType().getName()).append("\"");
                if (instr != null) {
                    example.append(", \"instruction\": \"").append(escapeJson(instr.toString())).append("\"");
                }
                if (func != null) {
                    example.append(", \"function\": \"").append(escapeJson(func.getName())).append("\"");
                }
                example.append("}");
                examples.add(example.toString());
            }

            StringBuilder result = new StringBuilder();
            result.append("{");
            result.append("\"struct_address\": \"").append(structAddr.toString()).append("\",");
            result.append("\"field_offset\": ").append(fieldOffset).append(",");
            result.append("\"field_address\": \"").append(fieldAddr.toString()).append("\",");
            result.append("\"examples\": [");
            for (int i = 0; i < examples.size(); i++) {
                if (i > 0) result.append(",");
                result.append(examples.get(i));
            }
            result.append("]");
            result.append("}");

            return result.toString();
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    /**
     * Smart rename - either rename data or create label based on what exists
     */
    public String renameOrLabel(String addressStr, String newName) {
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
        String result = renameData(addressStr, newName);

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
    public String canRenameAtAddress(String addressStr) {
        Program program = getProgram(null);
        if (program == null) {
            return "{\"error\": \"No program loaded\"}";
        }

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            if (addr == null) {
                return "{\"can_rename\": false, \"error\": \"Invalid address\"}";
            }

            StringBuilder result = new StringBuilder();
            result.append("{\"can_rename\": true");

            // Check if it's a function
            Function func = program.getFunctionManager().getFunctionAt(addr);
            if (func != null) {
                result.append(", \"type\": \"function\"");
                result.append(", \"suggested_operation\": \"rename_function\"");
                result.append(", \"current_name\": \"").append(escapeJson(func.getName())).append("\"");
                result.append("}");
                return result.toString();
            }

            // Check if it's defined data
            Data data = program.getListing().getDefinedDataAt(addr);
            if (data != null) {
                result.append(", \"type\": \"defined_data\"");
                result.append(", \"suggested_operation\": \"rename_data\"");
                Symbol symbol = program.getSymbolTable().getPrimarySymbol(addr);
                if (symbol != null) {
                    result.append(", \"current_name\": \"").append(escapeJson(symbol.getName())).append("\"");
                }
                result.append("}");
                return result.toString();
            }

            // Undefined - can create label
            result.append(", \"type\": \"undefined\"");
            result.append(", \"suggested_operation\": \"create_label\"");
            result.append("}");
            return result.toString();
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    // ==========================================================================
    // PHASE 4 HELPER METHODS
    // ==========================================================================

    /**
     * Compute a normalized opcode hash for function matching
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
                    // Normalize addresses
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

        // Compute SHA-256 hash
        try {
            java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(normalized.toString().getBytes(StandardCharsets.UTF_8));
            StringBuilder hexString = new StringBuilder();
            for (byte b : hashBytes) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (java.security.NoSuchAlgorithmException e) {
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

    // ==========================================================================
    // FUZZY MATCHING & DIFF
    // ==========================================================================

    /**
     * Get function signature (feature vector) for fuzzy matching
     */
    public String getFunctionSignature(String addressStr, String programName) {
        Program program = getProgram(programName);
        if (program == null) return getProgramError(programName);

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            if (addr == null) return "{\"error\": \"Invalid address: " + addressStr + "\"}";

            Function func = program.getFunctionManager().getFunctionAt(addr);
            if (func == null) return "{\"error\": \"No function at address: " + addressStr + "\"}";

            BinaryComparisonService.FunctionSignature sig =
                BinaryComparisonService.computeFunctionSignature(program, func, monitor);
            return sig.toJson();
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    /**
     * Find functions in target program similar to a source function
     */
    public String findSimilarFunctionsFuzzy(String addressStr, String sourceProgramName,
            String targetProgramName, double threshold, int limit) {
        Program srcProgram = getProgram(sourceProgramName);
        if (srcProgram == null) return getProgramError(sourceProgramName);

        if (targetProgramName == null || targetProgramName.trim().isEmpty()) {
            return "{\"error\": \"target_program parameter is required\"}";
        }
        Program tgtProgram = getProgram(targetProgramName);
        if (tgtProgram == null) return getProgramError(targetProgramName);

        try {
            Address addr = srcProgram.getAddressFactory().getAddress(addressStr);
            if (addr == null) return "{\"error\": \"Invalid address: " + addressStr + "\"}";

            Function srcFunc = srcProgram.getFunctionManager().getFunctionAt(addr);
            if (srcFunc == null) return "{\"error\": \"No function at address: " + addressStr + "\"}";

            return BinaryComparisonService.findSimilarFunctionsJson(
                srcProgram, srcFunc, tgtProgram, threshold, limit, monitor);
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    /**
     * Bulk fuzzy match: best match per source function in target program
     */
    public String bulkFuzzyMatch(String sourceProgramName, String targetProgramName,
            double threshold, int offset, int limit, String filter) {
        if (sourceProgramName == null || sourceProgramName.trim().isEmpty()) {
            return "{\"error\": \"source_program parameter is required\"}";
        }
        Program srcProgram = getProgram(sourceProgramName);
        if (srcProgram == null) return getProgramError(sourceProgramName);

        if (targetProgramName == null || targetProgramName.trim().isEmpty()) {
            return "{\"error\": \"target_program parameter is required\"}";
        }
        Program tgtProgram = getProgram(targetProgramName);
        if (tgtProgram == null) return getProgramError(targetProgramName);

        try {
            return BinaryComparisonService.bulkFuzzyMatchJson(
                srcProgram, tgtProgram, threshold, offset, limit, filter, monitor);
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    /**
     * Structured diff between two functions
     */
    public String diffFunctions(String addressA, String addressB,
            String programAName, String programBName) {
        Program progA = getProgram(programAName);
        if (progA == null) return getProgramError(programAName);

        Program progB;
        if (programBName == null || programBName.trim().isEmpty()) {
            progB = progA;
        } else {
            progB = getProgram(programBName);
            if (progB == null) return getProgramError(programBName);
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

            return BinaryComparisonService.diffFunctionsJson(progA, funcA, progB, funcB, monitor);
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }
}
