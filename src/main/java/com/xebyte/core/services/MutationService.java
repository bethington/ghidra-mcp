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
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.task.TaskMonitor;

import java.util.*;

/**
 * Shared service for write (mutation) operations.
 *
 * Handles rename, create, delete, and type-change operations on functions,
 * variables, data labels, and memory blocks. All write operations use
 * {@link ThreadingStrategy#executeWrite} for proper transaction management.
 */
public class MutationService extends BaseService {

    public MutationService(ProgramProvider programProvider, ThreadingStrategy threadingStrategy) {
        super(programProvider, threadingStrategy);
    }

    // =========================================================================
    // FUNCTION RENAME / DELETE / CREATE
    // =========================================================================

    /**
     * Find a function by name and rename it.
     * Endpoint: /rename_function
     */
    public Response renameFunction(String oldName, String newName) {
        Program program = resolveProgram(null);
        if (program == null) return programNotFoundError(null);
        if (oldName == null || oldName.isEmpty()) return Response.err("Old function name is required");
        if (newName == null || newName.isEmpty()) return Response.err("New function name is required");

        try {
            return threadingStrategy.executeWrite(program, "Rename function", () -> {
                for (Function func : program.getFunctionManager().getFunctions(true)) {
                    if (func.getName().equals(oldName)) {
                        func.setName(newName, SourceType.USER_DEFINED);
                        Map<String, Object> result = new LinkedHashMap<>();
                        result.put("status", "success");
                        result.put("message", "Renamed function '" + oldName + "' to '" + newName + "'");
                        return Response.ok(result);
                    }
                }
                return Response.err("Function '" + oldName + "' not found");
            });
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    /**
     * Find a function at or containing an address and rename it.
     * Endpoint: /rename_function_by_address
     */
    public Response renameFunctionByAddress(String addressStr, String newName) {
        Program program = resolveProgram(null);
        if (program == null) return programNotFoundError(null);
        if (addressStr == null || addressStr.isEmpty()) return Response.err("Function address is required");
        if (newName == null || newName.isEmpty()) return Response.err("New function name is required");

        Address addr = parseAddress(program, addressStr);
        if (addr == null) return Response.err("Invalid address: " + addressStr);

        try {
            return threadingStrategy.executeWrite(program, "Rename function by address", () -> {
                Function func = program.getFunctionManager().getFunctionAt(addr);
                if (func == null) {
                    func = program.getFunctionManager().getFunctionContaining(addr);
                }
                if (func == null) {
                    return Response.err("No function found at address: " + addressStr);
                }

                String oldName = func.getName();
                func.setName(newName, SourceType.USER_DEFINED);
                Map<String, Object> result = new LinkedHashMap<>();
                result.put("status", "success");
                result.put("message", "Renamed function '" + oldName + "' to '" + newName + "'");
                return Response.ok(result);
            });
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    /**
     * Save the current program's domain file.
     * Endpoint: /save_program
     */
    public Response saveCurrentProgram() {
        Program program = resolveProgram(null);
        if (program == null) return programNotFoundError(null);

        try {
            ghidra.framework.model.DomainFile df = program.getDomainFile();
            if (df == null) {
                return Response.err("Program has no domain file");
            }
            // Save outside of a transaction — df.save() needs exclusive lock
            // which cannot be acquired while a transaction is active.
            df.save(TaskMonitor.DUMMY);
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("success", true);
            result.put("program", program.getName());
            result.put("message", "Program saved successfully");
            return Response.ok(result);
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    /**
     * Remove a function at the given address.
     * Endpoint: /delete_function
     */
    public Response deleteFunctionAtAddress(String addressStr) {
        Program program = resolveProgram(null);
        if (program == null) return programNotFoundError(null);
        if (addressStr == null || addressStr.isEmpty()) return Response.err("address parameter required");

        Address addr = parseAddress(program, addressStr);
        if (addr == null) return Response.err("Invalid address: " + addressStr);

        Function func = program.getFunctionManager().getFunctionAt(addr);
        if (func == null) return Response.err("No function found at address " + addressStr);

        String funcName = func.getName();
        long bodySize = func.getBody().getNumAddresses();

        try {
            return threadingStrategy.executeWrite(program, "Delete function at address", () -> {
                program.getFunctionManager().removeFunction(addr);
                Map<String, Object> result = new LinkedHashMap<>();
                result.put("success", true);
                result.put("address", addr.toString());
                result.put("deleted_function", funcName);
                result.put("body_size", bodySize);
                result.put("message", "Function '" + funcName + "' deleted at " + addr);
                return Response.ok(result);
            });
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    /**
     * Create a function at the given address, optionally disassembling first.
     * Endpoint: /create_function
     */
    public Response createFunctionAtAddress(String addressStr, String name, boolean disassembleFirst) {
        Program program = resolveProgram(null);
        if (program == null) return programNotFoundError(null);
        if (addressStr == null || addressStr.isEmpty()) return Response.err("address parameter required");

        Address addr = parseAddress(program, addressStr);
        if (addr == null) return Response.err("Invalid address: " + addressStr);

        Function existing = program.getFunctionManager().getFunctionAt(addr);
        if (existing != null) {
            return Response.err("Function already exists at " + addressStr + ": " + existing.getName());
        }

        try {
            return threadingStrategy.executeWrite(program, "Create function at address", () -> {
                if (disassembleFirst) {
                    if (program.getListing().getInstructionAt(addr) == null) {
                        ghidra.program.model.address.AddressSet addrSet =
                            new ghidra.program.model.address.AddressSet(addr, addr);
                        ghidra.app.cmd.disassemble.DisassembleCommand disCmd =
                            new ghidra.app.cmd.disassemble.DisassembleCommand(addrSet, null, true);
                        if (!disCmd.applyTo(program, TaskMonitor.DUMMY)) {
                            return Response.err("Failed to disassemble at " + addressStr +
                                   ": " + disCmd.getStatusMsg());
                        }
                    }
                }

                ghidra.app.cmd.function.CreateFunctionCmd cmd =
                    new ghidra.app.cmd.function.CreateFunctionCmd(addr);
                if (!cmd.applyTo(program, TaskMonitor.DUMMY)) {
                    return Response.err("Failed to create function at " + addressStr +
                           ": " + cmd.getStatusMsg());
                }

                Function func = program.getFunctionManager().getFunctionAt(addr);
                if (func == null) {
                    return Response.err("Function creation reported success but function not found at " +
                           addressStr);
                }

                if (name != null && !name.isEmpty()) {
                    func.setName(name, SourceType.USER_DEFINED);
                }

                Map<String, Object> result = new LinkedHashMap<>();
                result.put("success", true);
                result.put("address", addr.toString());
                result.put("function_name", func.getName());
                result.put("entry_point", func.getEntryPoint().toString());
                result.put("body_size", func.getBody().getNumAddresses());
                result.put("message", "Function created successfully at " + addr);
                return Response.ok(result);
            });
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    // =========================================================================
    // MEMORY BLOCK CREATION
    // =========================================================================

    /**
     * Create an uninitialized memory block.
     * Endpoint: /create_memory_block
     */
    public Response createMemoryBlock(String name, String addressStr, long size,
                                    boolean read, boolean write, boolean execute,
                                    boolean isVolatile, String comment) {
        Program program = resolveProgram(null);
        if (program == null) return programNotFoundError(null);
        if (name == null || name.isEmpty()) return Response.err("name parameter required");
        if (addressStr == null || addressStr.isEmpty()) return Response.err("address parameter required");
        if (size <= 0) return Response.err("size must be positive");

        Address addr = parseAddress(program, addressStr);
        if (addr == null) return Response.err("Invalid address: " + addressStr);

        try {
            return threadingStrategy.executeWrite(program, "Create memory block", () -> {
                ghidra.program.model.mem.MemoryBlock block =
                    program.getMemory().createUninitializedBlock(name, addr, size, false);

                block.setRead(read);
                block.setWrite(write);
                block.setExecute(execute);
                block.setVolatile(isVolatile);
                if (comment != null && !comment.isEmpty()) {
                    block.setComment(comment);
                }

                Map<String, Object> result = new LinkedHashMap<>();
                result.put("success", true);
                result.put("name", name);
                result.put("start", block.getStart().toString());
                result.put("end", block.getEnd().toString());
                result.put("size", block.getSize());
                result.put("permissions",
                    (read ? "r" : "-") + (write ? "w" : "-") + (execute ? "x" : "-"));
                result.put("volatile", isVolatile);
                result.put("message", "Memory block '" + name + "' created at " + addr);
                return Response.ok(result);
            });
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    // =========================================================================
    // DATA / LABEL RENAME
    // =========================================================================

    /**
     * Rename the primary symbol at an address, or create a label if none exists.
     * Endpoint: /rename_data
     */
    public Response renameData(String addressStr, String newName) {
        Program program = resolveProgram(null);
        if (program == null) return programNotFoundError(null);
        if (addressStr == null || addressStr.isEmpty()) return Response.err("Address is required");
        if (newName == null || newName.isEmpty()) return Response.err("New name is required");

        Address addr = parseAddress(program, addressStr);
        if (addr == null) return Response.err("Invalid address: " + addressStr);

        try {
            return threadingStrategy.executeWrite(program, "Rename data", () -> {
                SymbolTable symTable = program.getSymbolTable();
                Symbol symbol = symTable.getPrimarySymbol(addr);

                Map<String, Object> result = new LinkedHashMap<>();
                result.put("status", "success");
                if (symbol != null) {
                    symbol.setName(newName, SourceType.USER_DEFINED);
                    result.put("message", "Renamed data at " + addressStr + " to '" + newName + "'");
                } else {
                    symTable.createLabel(addr, newName, SourceType.USER_DEFINED);
                    result.put("message", "Created label '" + newName + "' at " + addressStr);
                }
                return Response.ok(result);
            });
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    /**
     * Delegate to {@link #renameData} and return the result directly.
     * Endpoint: /rename_or_label
     */
    public Response renameOrLabel(String addressStr, String newName) {
        if (addressStr == null || addressStr.isEmpty()) return Response.err("Address is required");
        if (newName == null || newName.isEmpty()) return Response.err("Name is required");

        return renameData(addressStr, newName);
    }

    /**
     * Read-only check: determine what exists at an address and suggest a rename operation.
     * Endpoint: /can_rename_at_address
     */
    public Response canRenameAtAddress(String addressStr) {
        Program program = resolveProgram(null);
        if (program == null) return programNotFoundError(null);

        try {
            Address addr = parseAddress(program, addressStr);
            if (addr == null) {
                Map<String, Object> result = new LinkedHashMap<>();
                result.put("can_rename", false);
                result.put("error", "Invalid address");
                return Response.ok(result);
            }

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("can_rename", true);

            Function func = program.getFunctionManager().getFunctionAt(addr);
            if (func != null) {
                result.put("type", "function");
                result.put("suggested_operation", "rename_function");
                result.put("current_name", func.getName());
                return Response.ok(result);
            }

            Data data = program.getListing().getDefinedDataAt(addr);
            if (data != null) {
                result.put("type", "defined_data");
                result.put("suggested_operation", "rename_data");
                Symbol symbol = program.getSymbolTable().getPrimarySymbol(addr);
                if (symbol != null) {
                    result.put("current_name", symbol.getName());
                }
                return Response.ok(result);
            }

            result.put("type", "undefined");
            result.put("suggested_operation", "create_label");
            return Response.ok(result);
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    // =========================================================================
    // VARIABLE RENAME / TYPE CHANGE
    // =========================================================================

    /**
     * Rename a parameter or local variable in a function (found by name).
     * Endpoint: /rename_variable
     */
    public Response renameVariable(String functionName, String oldName, String newName) {
        Program program = resolveProgram(null);
        if (program == null) return programNotFoundError(null);
        if (functionName == null || functionName.isEmpty()) return Response.err("Function name is required");
        if (oldName == null || oldName.isEmpty()) return Response.err("Old variable name is required");
        if (newName == null || newName.isEmpty()) return Response.err("New variable name is required");

        Function func = null;
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            if (f.getName().equals(functionName)) {
                func = f;
                break;
            }
        }

        if (func == null) return Response.err("Function '" + functionName + "' not found");

        final Function targetFunc = func;

        try {
            return threadingStrategy.executeWrite(program, "Rename variable", () -> {
                for (Parameter param : targetFunc.getParameters()) {
                    if (param.getName().equals(oldName)) {
                        param.setName(newName, SourceType.USER_DEFINED);
                        Map<String, Object> result = new LinkedHashMap<>();
                        result.put("status", "success");
                        result.put("message", "Renamed parameter '" + oldName + "' to '" + newName + "'");
                        return Response.ok(result);
                    }
                }

                for (Variable var : targetFunc.getLocalVariables()) {
                    if (var.getName().equals(oldName)) {
                        var.setName(newName, SourceType.USER_DEFINED);
                        Map<String, Object> result = new LinkedHashMap<>();
                        result.put("status", "success");
                        result.put("message", "Renamed local variable '" + oldName + "' to '" + newName + "'");
                        return Response.ok(result);
                    }
                }

                return Response.err("Variable '" + oldName + "' not found in function '" + functionName + "'");
            });
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    /**
     * Rename multiple variables in a single transaction.
     * Endpoint: /batch_rename_variables
     *
     * @param functionAddress  Entry point address of the function
     * @param renames          Pre-parsed map of old name to new name
     */
    public Response batchRenameVariables(String functionAddress, Map<String, String> renames) {
        Program program = resolveProgram(null);
        if (program == null) return programNotFoundError(null);
        if (functionAddress == null || functionAddress.isEmpty()) return Response.err("Function address is required");
        if (renames == null || renames.isEmpty()) return Response.err("Renames map is required");

        Address addr = parseAddress(program, functionAddress);
        if (addr == null) return Response.err("Invalid address: " + functionAddress);

        try {
            return threadingStrategy.executeWrite(program, "Batch rename variables", () -> {
                Function func = program.getFunctionManager().getFunctionAt(addr);
                if (func == null) {
                    func = program.getFunctionManager().getFunctionContaining(addr);
                }
                if (func == null) {
                    return Response.err("No function found at address: " + functionAddress);
                }

                int renamed = 0;
                int failed = 0;
                List<String> errors = new ArrayList<>();

                for (Map.Entry<String, String> entry : renames.entrySet()) {
                    String oldName = entry.getKey();
                    String newName = entry.getValue();
                    boolean found = false;

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

                Map<String, Object> result = new LinkedHashMap<>();
                result.put("success", failed == 0);
                result.put("renamed", renamed);
                result.put("failed", failed);
                if (!errors.isEmpty()) {
                    result.put("errors", errors);
                }
                return Response.ok(result);
            });
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    // =========================================================================
    // FUNCTION PROTOTYPE / VARIABLE TYPE
    // =========================================================================

    /**
     * Parse and apply a function signature, then optionally set the calling convention.
     * Endpoint: /set_function_prototype
     */
    public Response setFunctionPrototype(String functionAddress, String prototype, String callingConvention) {
        Program program = resolveProgram(null);
        if (program == null) return programNotFoundError(null);
        if (functionAddress == null || functionAddress.isEmpty()) return Response.err("Function address is required");
        if (prototype == null || prototype.isEmpty()) return Response.err("Prototype is required");

        Address addr = parseAddress(program, functionAddress);
        if (addr == null) return Response.err("Invalid address: " + functionAddress);

        try {
            return threadingStrategy.executeWrite(program, "Set function prototype", () -> {
                Function func = program.getFunctionManager().getFunctionAt(addr);
                if (func == null) {
                    func = program.getFunctionManager().getFunctionContaining(addr);
                }
                if (func == null) {
                    return Response.err("No function found at address: " + functionAddress);
                }

                DataTypeManager dtm = program.getDataTypeManager();
                ghidra.app.util.parser.FunctionSignatureParser parser =
                    new ghidra.app.util.parser.FunctionSignatureParser(dtm, null);

                FunctionDefinitionDataType sig = parser.parse(null, prototype);

                ghidra.app.cmd.function.ApplyFunctionSignatureCmd cmd =
                    new ghidra.app.cmd.function.ApplyFunctionSignatureCmd(
                        func.getEntryPoint(), sig, SourceType.USER_DEFINED);

                if (!cmd.applyTo(program, monitor)) {
                    return Response.err("Failed to apply signature - " + cmd.getStatusMsg());
                }

                if (callingConvention != null && !callingConvention.isEmpty()) {
                    try {
                        func.setCallingConvention(callingConvention);
                    } catch (Exception e) {
                        Map<String, Object> result = new LinkedHashMap<>();
                        result.put("status", "success");
                        result.put("message", "Signature set, but calling convention failed: " + e.getMessage());
                        return Response.ok(result);
                    }
                }

                Map<String, Object> result = new LinkedHashMap<>();
                result.put("status", "success");
                result.put("message", "Function prototype set for " + func.getName());
                return Response.ok(result);
            });
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    /**
     * Change the data type of a parameter or local variable.
     * Endpoint: /set_local_variable_type
     */
    public Response setLocalVariableType(String functionAddress, String variableName, String newType) {
        Program program = resolveProgram(null);
        if (program == null) return programNotFoundError(null);
        if (functionAddress == null || functionAddress.isEmpty()) return Response.err("Function address is required");
        if (variableName == null || variableName.isEmpty()) return Response.err("Variable name is required");
        if (newType == null || newType.isEmpty()) return Response.err("New type is required");

        Address addr = parseAddress(program, functionAddress);
        if (addr == null) return Response.err("Invalid address: " + functionAddress);

        try {
            return threadingStrategy.executeWrite(program, "Set variable type", () -> {
                Function func = program.getFunctionManager().getFunctionAt(addr);
                if (func == null) {
                    func = program.getFunctionManager().getFunctionContaining(addr);
                }
                if (func == null) {
                    return Response.err("No function found at address: " + functionAddress);
                }

                DataType dataType = findDataType(program.getDataTypeManager(), newType);
                if (dataType == null) {
                    return Response.err("Data type not found: " + newType);
                }

                for (Parameter param : func.getParameters()) {
                    if (param.getName().equals(variableName)) {
                        param.setDataType(dataType, SourceType.USER_DEFINED);
                        Map<String, Object> result = new LinkedHashMap<>();
                        result.put("status", "success");
                        result.put("message", "Set type of parameter '" + variableName + "' to '" + newType + "'");
                        return Response.ok(result);
                    }
                }

                for (Variable var : func.getLocalVariables()) {
                    if (var.getName().equals(variableName)) {
                        var.setDataType(dataType, SourceType.USER_DEFINED);
                        Map<String, Object> result = new LinkedHashMap<>();
                        result.put("status", "success");
                        result.put("message", "Set type of local '" + variableName + "' to '" + newType + "'");
                        return Response.ok(result);
                    }
                }

                return Response.err("Variable '" + variableName + "' not found in function");
            });
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    // =========================================================================
    // Internal helpers
    // =========================================================================

    /**
     * Look up a data type by name with fallbacks to built-in types and common aliases.
     * Handles pointer types (names ending with {@code *}) recursively.
     */
    private DataType findDataType(DataTypeManager dtm, String typeName) {
        Iterator<DataType> iter = dtm.getAllDataTypes();
        while (iter.hasNext()) {
            DataType dt = iter.next();
            if (dt.getName().equals(typeName)) {
                return dt;
            }
        }

        DataTypeManager builtIn = BuiltInDataTypeManager.getDataTypeManager();
        iter = builtIn.getAllDataTypes();
        while (iter.hasNext()) {
            DataType dt = iter.next();
            if (dt.getName().equals(typeName) || dt.getName().equalsIgnoreCase(typeName)) {
                return dt;
            }
        }

        switch (typeName.toLowerCase()) {
            case "int":    return new IntegerDataType();
            case "uint":   return new UnsignedIntegerDataType();
            case "short":  return new ShortDataType();
            case "ushort": return new UnsignedShortDataType();
            case "long":   return new LongDataType();
            case "ulong":  return new UnsignedLongDataType();
            case "byte":   return new ByteDataType();
            case "ubyte":  return new UnsignedCharDataType();
            case "char":   return new CharDataType();
            case "uchar":  return new UnsignedCharDataType();
            case "float":  return new FloatDataType();
            case "double": return new DoubleDataType();
            case "void":   return new VoidDataType();
            case "bool":   return new BooleanDataType();
            case "dword":  return new DWordDataType();
            case "word":   return new WordDataType();
            case "qword":  return new QWordDataType();
            default:       break;
        }

        if (typeName.endsWith("*")) {
            String baseTypeName = typeName.substring(0, typeName.length() - 1).trim();
            DataType baseType = findDataType(dtm, baseTypeName);
            if (baseType != null) {
                return dtm.getPointer(baseType);
            }
        }

        return null;
    }
}
