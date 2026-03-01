package com.xebyte.core;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;

import javax.swing.SwingUtilities;
import java.lang.reflect.InvocationTargetException;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Pattern;

/**
 * Service for data type operations: list, create, modify, validate, and analyze data types.
 * Extracted from GhidraMCPPlugin as part of v4.0.0 refactor.
 */
public class DataTypeService {

    private final ProgramProvider programProvider;
    private final ThreadingStrategy threadingStrategy;

    // Constants from GhidraMCPPlugin
    private static final int MAX_FUNCTIONS_TO_ANALYZE = 100;
    private static final int MIN_FUNCTIONS_TO_ANALYZE = 1;
    private static final int MAX_STRUCT_FIELDS = 256;
    private static final int MAX_FIELD_EXAMPLES = 50;
    private static final int DECOMPILE_TIMEOUT_SECONDS = 60;
    private static final int MIN_TOKEN_LENGTH = 3;
    private static final int MAX_FIELD_OFFSET = 65536;

    // C language keywords to filter from field name suggestions
    private static final Set<String> C_KEYWORDS = Set.of(
        "if", "else", "for", "while", "do", "switch", "case", "default",
        "break", "continue", "return", "goto", "int", "void", "char",
        "float", "double", "long", "short", "struct", "union", "enum",
        "typedef", "sizeof", "const", "static", "extern", "auto", "register",
        "signed", "unsigned", "volatile", "inline", "restrict"
    );

    public DataTypeService(ProgramProvider programProvider, ThreadingStrategy threadingStrategy) {
        this.programProvider = programProvider;
        this.threadingStrategy = threadingStrategy;
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
            return new Object[]{null, Response.err(error)};
        }
        return new Object[]{program, null};
    }

    // -----------------------------------------------------------------------
    // Helper Classes
    // -----------------------------------------------------------------------

    /**
     * Helper class for field definitions
     */
    private static class FieldDefinition {
        String name;
        String type;
        int offset;

        FieldDefinition(String name, String type, int offset) {
            this.name = name;
            this.type = type;
            this.offset = offset;
        }
    }

    /**
     * Helper class to track field usage information
     */
    private static class FieldUsageInfo {
        int accessCount = 0;
        Set<String> suggestedNames = new HashSet<>();
        Set<String> usagePatterns = new HashSet<>();

        String getSuggestedNamesJson() {
            StringBuilder json = new StringBuilder("[");
            boolean first = true;
            for (String name : suggestedNames) {
                if (!first) json.append(",");
                first = false;
                json.append("\"").append(name).append("\"");
            }
            json.append("]");
            return json.toString();
        }

        String getUsagePatternsJson() {
            StringBuilder json = new StringBuilder("[");
            boolean first = true;
            for (String pattern : usagePatterns) {
                if (!first) json.append(",");
                first = false;
                json.append("\"").append(pattern).append("\"");
            }
            json.append("]");
            return json.toString();
        }
    }

    // -----------------------------------------------------------------------
    // Data Type Listing and Query Methods
    // -----------------------------------------------------------------------

    /**
     * List all data types available in the program with optional category filtering
     */
    @McpTool(value = "/list_data_types", description = "List all data types available in the program with optional category filtering")

    public Response listDataTypes(

            @Param(value = "category") String category,

            @Param(value = "offset", type = "integer", required = false, defaultValue = "0") int offset,

            @Param(value = "limit", type = "integer", required = false, defaultValue = "100") int limit,

            @Param(value = "program", required = false) String programName) {
        Object[] programResult = getProgramOrError(programName);
        Program program = (Program) programResult[0];
        if (program == null) {
            return (Response) programResult[1];
        }

        DataTypeManager dtm = program.getDataTypeManager();
        List<String> dataTypes = new ArrayList<>();

        // Get all data types from the manager
        Iterator<DataType> allTypes = dtm.getAllDataTypes();
        while (allTypes.hasNext()) {
            DataType dt = allTypes.next();

            // Apply category/type filter if specified
            if (category != null && !category.isEmpty()) {
                String dtCategory = getCategoryName(dt);
                String dtTypeName = getDataTypeName(dt);

                // Check both category path AND data type name
                boolean matches = dtCategory.toLowerCase().contains(category.toLowerCase()) ||
                                dtTypeName.toLowerCase().contains(category.toLowerCase());

                if (!matches) {
                    continue;
                }
            }

            // Format: name | category | size | path
            String categoryName = getCategoryName(dt);
            int size = dt.getLength();
            String sizeStr = (size > 0) ? String.valueOf(size) : "variable";

            dataTypes.add(String.format("%s | %s | %s bytes | %s",
                dt.getName(), categoryName, sizeStr, dt.getPathName()));
        }

        // Apply pagination
        String result = ServiceUtils.paginateList(dataTypes, offset, limit);

        if (result.isEmpty()) {
            return Response.text("No data types found" + (category != null ? " for category: " + category : ""));
        }

        return Response.text(result);
    }

    // Backward compatibility overload
    public Response listDataTypes(String category, int offset, int limit) {
        return listDataTypes(category, offset, limit, null);
    }

    /**
     * Helper method to get category name for a data type
     */
    public String getCategoryName(DataType dt) {
        if (dt.getCategoryPath() == null) {
            return "builtin";
        }
        String categoryPath = dt.getCategoryPath().getPath();
        if (categoryPath.isEmpty() || categoryPath.equals("/")) {
            return "builtin";
        }

        // Extract the last part of the category path
        String[] parts = categoryPath.split("/");
        return parts[parts.length - 1].toLowerCase();
    }

    /**
     * Helper method to get the type classification of a data type
     * Returns: struct, enum, typedef, pointer, array, union, function, or primitive
     */
    public String getDataTypeName(DataType dt) {
        if (dt instanceof Structure) {
            return "struct";
        } else if (dt instanceof Union) {
            return "union";
        } else if (dt instanceof ghidra.program.model.data.Enum) {
            return "enum";
        } else if (dt instanceof TypeDef) {
            return "typedef";
        } else if (dt instanceof Pointer) {
            return "pointer";
        } else if (dt instanceof Array) {
            return "array";
        } else if (dt instanceof FunctionDefinition) {
            return "function";
        } else {
            return "primitive";
        }
    }

    /**
     * Search for data types by pattern
     */
    @McpTool(value = "/search_data_types", description = "Search for data types by pattern matching against type names")

    public Response searchDataTypes(

            @Param(value = "pattern", required = false) String pattern,

            @Param(value = "offset", type = "integer", required = false, defaultValue = "0") int offset,

            @Param(value = "limit", type = "integer", required = false, defaultValue = "100") int limit) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) return Response.err("No program loaded");
        if (pattern == null || pattern.isEmpty()) return Response.err("Search pattern is required");

        List<String> matches = new ArrayList<>();
        DataTypeManager dtm = program.getDataTypeManager();

        Iterator<DataType> allTypes = dtm.getAllDataTypes();
        while (allTypes.hasNext()) {
            DataType dt = allTypes.next();
            String name = dt.getName();
            String path = dt.getPathName();

            if (name.toLowerCase().contains(pattern.toLowerCase()) ||
                path.toLowerCase().contains(pattern.toLowerCase())) {
                matches.add(String.format("%s | Size: %d | Path: %s",
                           name, dt.getLength(), path));
            }
        }

        Collections.sort(matches);
        return Response.text(ServiceUtils.paginateList(matches, offset, limit));
    }

    /**
     * Get the size of a data type
     */
    @McpTool(value = "/get_type_size", description = "Get type size")

    public Response getTypeSize(

            @Param(value = "type_name") String typeName) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) return Response.err("No program loaded");
        if (typeName == null || typeName.isEmpty()) return Response.err("Type name is required");

        DataTypeManager dtm = program.getDataTypeManager();
        DataType dataType = ServiceUtils.findDataTypeByNameInAllCategories(dtm, typeName);

        if (dataType == null) {
            return Response.err("Data type not found: " + typeName);
        }

        int size = dataType.getLength();
        return Response.text(String.format("Type: %s\nSize: %d bytes\nAlignment: %d\nPath: %s",
                            dataType.getName(),
                            size,
                            dataType.getAlignment(),
                            dataType.getPathName()));
    }

    /**
     * Get the layout of a structure
     */
    @McpTool(value = "/get_struct_layout", description = "Get the detailed field layout of a structure data type")

    public Response getStructLayout(

            @Param(value = "struct_name") String structName) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) return Response.err("No program loaded");
        if (structName == null || structName.isEmpty()) return Response.err("Struct name is required");

        DataTypeManager dtm = program.getDataTypeManager();
        DataType dataType = ServiceUtils.findDataTypeByNameInAllCategories(dtm, structName);

        if (dataType == null) {
            return Response.err("Structure not found: " + structName);
        }

        if (!(dataType instanceof Structure)) {
            return Response.err("Data type is not a structure: " + structName);
        }

        Structure struct = (Structure) dataType;
        StringBuilder result = new StringBuilder();

        result.append("Structure: ").append(struct.getName()).append("\n");
        result.append("Size: ").append(struct.getLength()).append(" bytes\n");
        result.append("Alignment: ").append(struct.getAlignment()).append("\n\n");
        result.append("Layout:\n");
        result.append("Offset | Size | Type | Name\n");
        result.append("-------|------|------|-----\n");

        for (DataTypeComponent component : struct.getDefinedComponents()) {
            result.append(String.format("%6d | %4d | %-20s | %s\n",
                component.getOffset(),
                component.getLength(),
                component.getDataType().getName(),
                component.getFieldName() != null ? component.getFieldName() : "(unnamed)"));
        }

        return Response.text(result.toString());
    }

    /**
     * Get all values in an enumeration
     */
    @McpTool(value = "/get_enum_values", description = "Get all values and names in an enumeration")

    public Response getEnumValues(

            @Param(value = "enum_name") String enumName) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) return Response.err("No program loaded");
        if (enumName == null || enumName.isEmpty()) return Response.err("Enum name is required");

        DataTypeManager dtm = program.getDataTypeManager();
        DataType dataType = ServiceUtils.findDataTypeByNameInAllCategories(dtm, enumName);

        if (dataType == null) {
            return Response.err("Enumeration not found: " + enumName);
        }

        if (!(dataType instanceof ghidra.program.model.data.Enum)) {
            return Response.err("Data type is not an enumeration: " + enumName);
        }

        ghidra.program.model.data.Enum enumType = (ghidra.program.model.data.Enum) dataType;
        StringBuilder result = new StringBuilder();

        result.append("Enumeration: ").append(enumType.getName()).append("\n");
        result.append("Size: ").append(enumType.getLength()).append(" bytes\n\n");
        result.append("Values:\n");
        result.append("Name | Value\n");
        result.append("-----|------\n");

        String[] names = enumType.getNames();
        for (String valueName : names) {
            long value = enumType.getValue(valueName);
            result.append(String.format("%-20s | %d (0x%X)\n", valueName, value, value));
        }

        return Response.text(result.toString());
    }

    /**
     * v1.5.0: Get valid Ghidra data type strings
     */
    @McpTool(value = "/get_valid_data_types", description = "Get list of valid Ghidra data type strings (v1.5.0)")

    public Response getValidDataTypes(

            @Param(value = "category") String category) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) {
            return Response.err("No program loaded");
        }

        Map<String, Object> resultMap = new LinkedHashMap<>();
        final AtomicReference<String> errorMsg = new AtomicReference<>(null);

        try {
            SwingUtilities.invokeAndWait(() -> {
                try {
                    // Common builtin types
                    List<String> builtinTypes = List.of(
                        "void", "byte", "char", "short", "int", "long", "longlong",
                        "float", "double", "pointer", "bool",
                        "undefined", "undefined1", "undefined2", "undefined4", "undefined8",
                        "uchar", "ushort", "uint", "ulong", "ulonglong",
                        "sbyte", "sword", "sdword", "sqword",
                        "word", "dword", "qword"
                    );

                    List<String> windowsTypes = List.of(
                        "BOOL", "BOOLEAN", "BYTE", "CHAR", "DWORD", "QWORD", "WORD",
                        "HANDLE", "HMODULE", "HWND", "LPVOID", "PVOID",
                        "LPCSTR", "LPSTR", "LPCWSTR", "LPWSTR",
                        "SIZE_T", "ULONG", "USHORT"
                    );

                    resultMap.put("builtin_types", builtinTypes);
                    resultMap.put("windows_types", windowsTypes);
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

        return Response.ok(resultMap);
    }

    /**
     * NEW v1.6.0: Check if data type exists in type manager
     */
    @McpTool(value = "/validate_data_type_exists", description = "Check if a data type exists in Ghidra before attempting type operations")

    public Response validateDataTypeExists(

            @Param(value = "type_name") String typeName) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) {
            return Response.err("No program loaded");
        }

        Map<String, Object> resultMap = new LinkedHashMap<>();
        final AtomicReference<String> errorMsg = new AtomicReference<>(null);

        try {
            SwingUtilities.invokeAndWait(() -> {
                try {
                    DataTypeManager dtm = program.getDataTypeManager();
                    DataType dt = dtm.getDataType(typeName);

                    resultMap.put("exists", dt != null);
                    if (dt != null) {
                        resultMap.put("category", dt.getCategoryPath().getPath());
                        resultMap.put("size", dt.getLength());
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

        return Response.ok(resultMap);
    }

    // -----------------------------------------------------------------------
    // Data Type Creation Methods
    // -----------------------------------------------------------------------

    /**
     * Create a new structure data type with specified fields
     */
    @SuppressWarnings("deprecation")
    @McpTool(value = "/create_struct", description = "Create a new structure data type with specified fields", method = McpTool.Method.POST)

    public Response createStruct(

            @Param(value = "name") String name,

            @Param(value = "fields") String fieldsJson) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) {
            return Response.err("No program loaded");
        }

        if (name == null || name.isEmpty()) {
            return Response.err("Structure name is required");
        }

        if (fieldsJson == null || fieldsJson.isEmpty()) {
            return Response.err("Fields JSON is required");
        }

        final StringBuilder resultMsg = new StringBuilder();
        final AtomicBoolean successFlag = new AtomicBoolean(false);

        try {
            // Parse the fields JSON (simplified parsing for basic structure)
            // Expected format: [{"name":"field1","type":"int"},{"name":"field2","type":"char"}]
            List<FieldDefinition> fields = parseFieldsJson(fieldsJson);

            if (fields.isEmpty()) {
                return Response.err("No valid fields provided");
            }

            DataTypeManager dtm = program.getDataTypeManager();

            // Check if struct already exists
            DataType existingType = dtm.getDataType("/" + name);
            if (existingType != null) {
                return Response.err("Structure with name '" + name + "' already exists");
            }

            // Pre-resolve all field types before entering the transaction
            Map<FieldDefinition, DataType> resolvedTypes = new java.util.LinkedHashMap<>();
            for (FieldDefinition field : fields) {
                DataType fieldType = ServiceUtils.resolveDataType(dtm, field.type);
                if (fieldType == null) {
                    return Response.err("Unknown field type: " + field.type);
                }
                resolvedTypes.put(field, fieldType);
            }

            // Determine if any fields have explicit offsets
            boolean hasOffsets = fields.stream().anyMatch(f -> f.offset >= 0);

            // Calculate required struct size from field offsets
            int requiredSize = 0;
            if (hasOffsets) {
                for (Map.Entry<FieldDefinition, DataType> entry : resolvedTypes.entrySet()) {
                    int off = entry.getKey().offset;
                    int len = entry.getValue().getLength();
                    if (off >= 0 && off + len > requiredSize) {
                        requiredSize = off + len;
                    }
                }
            }
            final int structInitSize = requiredSize;

            // Create the structure on Swing EDT thread (required for transactions)
            SwingUtilities.invokeAndWait(() -> {
                int txId = program.startTransaction("Create Structure: " + name);
                try {
                    ghidra.program.model.data.StructureDataType struct =
                        new ghidra.program.model.data.StructureDataType(name, structInitSize);

                    for (Map.Entry<FieldDefinition, DataType> entry : resolvedTypes.entrySet()) {
                        FieldDefinition field = entry.getKey();
                        DataType fieldType = entry.getValue();

                        if (field.offset >= 0 && hasOffsets) {
                            // Place field at explicit offset
                            struct.replaceAtOffset(field.offset, fieldType,
                                fieldType.getLength(), field.name, "");
                        } else {
                            // Append to end
                            struct.add(fieldType, fieldType.getLength(), field.name, "");
                        }
                    }

                    // Add the structure to the data type manager
                    DataType createdStruct = dtm.addDataType(struct, null);

                    successFlag.set(true);
                    resultMsg.append("Successfully created structure '").append(name).append("' with ")
                            .append(fields.size()).append(" fields, total size: ")
                            .append(createdStruct.getLength()).append(" bytes");

                } catch (Throwable e) {
                    String msg = e.getMessage() != null ? e.getMessage() : e.toString();
                    resultMsg.append("Error creating structure: ").append(msg);
                    Msg.error(this, "Error creating structure", e);
                }
                finally {
                    program.endTransaction(txId, successFlag.get());
                }
            });

            // Force event processing to ensure changes propagate
            if (successFlag.get()) {
                program.flushEvents();
                try {
                    Thread.sleep(50);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }

        } catch (Throwable e) {
            String msg = e.getMessage() != null ? e.getMessage() : e.toString();
            return Response.err(msg);
        }

        String msg = resultMsg.length() > 0 ? resultMsg.toString() : "Unknown failure";
        if (successFlag.get()) {
            return Response.text(msg);
        } else {
            return Response.err(msg);
        }
    }

    /**
     * Create a new enumeration data type with name-value pairs
     */
    @McpTool(value = "/create_enum", description = "Create a new enumeration data type with name-value pairs", method = McpTool.Method.POST)

    public Response createEnum(

            @Param(value = "name") String name,

            @Param(value = "values") String valuesJson,

            @Param(value = "size", type = "integer") int size) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) {
            return Response.err("No program loaded");
        }

        if (name == null || name.isEmpty()) {
            return Response.err("Enumeration name is required");
        }

        if (valuesJson == null || valuesJson.isEmpty()) {
            return Response.err("Values JSON is required");
        }

        if (size != 1 && size != 2 && size != 4 && size != 8) {
            return Response.err("Invalid size. Must be 1, 2, 4, or 8 bytes");
        }

        try {
            // Parse the values JSON
            Map<String, Long> values = parseValuesJson(valuesJson);

            if (values.isEmpty()) {
                return Response.err("No valid enum values provided");
            }

            DataTypeManager dtm = program.getDataTypeManager();

            // Check if enum already exists
            DataType existingType = dtm.getDataType("/" + name);
            if (existingType != null) {
                return Response.err("Enumeration with name '" + name + "' already exists");
            }

            // Create the enumeration
            int txId = program.startTransaction("Create Enumeration: " + name);
            try {
                ghidra.program.model.data.EnumDataType enumDt =
                    new ghidra.program.model.data.EnumDataType(name, size);

                for (Map.Entry<String, Long> entry : values.entrySet()) {
                    enumDt.add(entry.getKey(), entry.getValue());
                }

                // Add the enumeration to the data type manager
                dtm.addDataType(enumDt, null);

                program.endTransaction(txId, true);

                return Response.text("Successfully created enumeration '" + name + "' with " + values.size() +
                       " values, size: " + size + " bytes");

            } catch (Exception e) {
                program.endTransaction(txId, false);
                return Response.err("Error creating enumeration: " + e.getMessage());
            }

        } catch (Exception e) {
            return Response.err("Error parsing values JSON: " + e.getMessage());
        }
    }

    /**
     * Create a union data type with simplified approach for testing
     */
    public Response createUnionSimple(String name, Object fieldsObj) {
        // Even simpler test - don't access any Ghidra APIs
        if (name == null || name.isEmpty()) return Response.err("Union name is required");
        if (fieldsObj == null) return Response.err("Fields are required");

        return Response.text("Union endpoint test successful - name: " + name);
    }

    /**
     * Create a union data type directly from fields object
     */
    @SuppressWarnings("unchecked")
    public Response createUnionDirect(String name, Object fieldsObj) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) return Response.err("No program loaded");
        if (name == null || name.isEmpty()) return Response.err("Union name is required");
        if (fieldsObj == null) return Response.err("Fields are required");

        AtomicBoolean success = new AtomicBoolean(false);
        StringBuilder result = new StringBuilder();

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Create union");
                try {
                    DataTypeManager dtm = program.getDataTypeManager();
                    UnionDataType union = new UnionDataType(name);

                    // Handle fields object directly (should be a List of Maps)
                    if (fieldsObj instanceof java.util.List) {
                        java.util.List<Object> fieldsList = (java.util.List<Object>) fieldsObj;

                        for (Object fieldObj : fieldsList) {
                            if (fieldObj instanceof java.util.Map) {
                                java.util.Map<String, Object> fieldMap = (java.util.Map<String, Object>) fieldObj;

                                String fieldName = (String) fieldMap.get("name");
                                String fieldType = (String) fieldMap.get("type");

                                if (fieldName != null && fieldType != null) {
                                    DataType dt = ServiceUtils.findDataTypeByNameInAllCategories(dtm, fieldType);
                                    if (dt != null) {
                                        union.add(dt, fieldName, null);
                                        result.append("Added field: ").append(fieldName).append(" (").append(fieldType).append(")\n");
                                    } else {
                                        result.append("Warning: Data type not found for field ").append(fieldName).append(": ").append(fieldType).append("\n");
                                    }
                                }
                            }
                        }
                    } else {
                        result.append("Invalid fields format - expected list of field objects");
                        return;
                    }

                    dtm.addDataType(union, DataTypeConflictHandler.REPLACE_HANDLER);
                    result.append("Union '").append(name).append("' created successfully with ").append(union.getNumComponents()).append(" fields");
                    success.set(true);
                } catch (Exception e) {
                    result.append("Error creating union: ").append(e.getMessage());
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            result.append("Failed to execute union creation on Swing thread: ").append(e.getMessage());
        }

        if (success.get()) {
            return Response.text(result.toString());
        } else {
            return Response.err(result.toString());
        }
    }

    /**
     * Create a union data type (legacy method)
     */
    @McpTool(value = "/create_union", description = "Create a union data type with specified fields", method = McpTool.Method.POST)

    public Response createUnion(

            @Param(value = "name") String name,

            @Param(value = "fields") String fieldsJson) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) return Response.err("No program loaded");
        if (name == null || name.isEmpty()) return Response.err("Union name is required");
        if (fieldsJson == null || fieldsJson.isEmpty()) return Response.err("Fields JSON is required");

        AtomicBoolean success = new AtomicBoolean(false);
        StringBuilder result = new StringBuilder();

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Create union");
                try {
                    DataTypeManager dtm = program.getDataTypeManager();
                    UnionDataType union = new UnionDataType(name);

                    // Parse fields from JSON using the same method as structs
                    List<FieldDefinition> fields = parseFieldsJson(fieldsJson);

                    if (fields.isEmpty()) {
                        result.append("No valid fields provided");
                        return;
                    }

                    // Process each field for the union (use resolveDataType like structs do)
                    for (FieldDefinition field : fields) {
                        DataType dt = ServiceUtils.resolveDataType(dtm, field.type);
                        if (dt != null) {
                            union.add(dt, field.name, null);
                            result.append("Added field: ").append(field.name).append(" (").append(field.type).append(")\n");
                        } else {
                            result.append("Warning: Data type not found for field ").append(field.name).append(": ").append(field.type).append("\n");
                        }
                    }

                    dtm.addDataType(union, DataTypeConflictHandler.REPLACE_HANDLER);
                    result.append("Union '").append(name).append("' created successfully with ").append(union.getNumComponents()).append(" fields");
                    success.set(true);
                } catch (Exception e) {
                    result.append("Error creating union: ").append(e.getMessage());
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            result.append("Failed to execute union creation on Swing thread: ").append(e.getMessage());
        }

        if (success.get()) {
            return Response.text(result.toString());
        } else {
            return Response.err(result.toString());
        }
    }

    /**
     * Create a typedef (type alias)
     */
    @McpTool(value = "/create_typedef", description = "Create a typedef (type alias) data type", method = McpTool.Method.POST)

    public Response createTypedef(

            @Param(value = "name") String name,

            @Param(value = "base_type") String baseType) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) return Response.err("No program loaded");
        if (name == null || name.isEmpty()) return Response.err("Typedef name is required");
        if (baseType == null || baseType.isEmpty()) return Response.err("Base type is required");

        AtomicBoolean success = new AtomicBoolean(false);
        StringBuilder result = new StringBuilder();

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Create typedef");
                try {
                    DataTypeManager dtm = program.getDataTypeManager();
                    DataType base = null;

                    // Handle pointer syntax (e.g., "UnitAny *")
                    if (baseType.endsWith(" *") || baseType.endsWith("*")) {
                        String baseTypeName = baseType.replace(" *", "").replace("*", "").trim();
                        DataType baseDataType = ServiceUtils.findDataTypeByNameInAllCategories(dtm, baseTypeName);
                        if (baseDataType != null) {
                            base = new PointerDataType(baseDataType);
                        } else {
                            result.append("Base type not found for pointer: ").append(baseTypeName);
                            return;
                        }
                    } else {
                        // Regular type lookup
                        base = ServiceUtils.findDataTypeByNameInAllCategories(dtm, baseType);
                    }

                    if (base == null) {
                        result.append("Base type not found: ").append(baseType);
                        return;
                    }

                    TypedefDataType typedef = new TypedefDataType(name, base);
                    dtm.addDataType(typedef, DataTypeConflictHandler.REPLACE_HANDLER);

                    result.append("Typedef '").append(name).append("' created as alias for '").append(baseType).append("'");
                    success.set(true);
                } catch (Exception e) {
                    result.append("Error creating typedef: ").append(e.getMessage());
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            result.append("Failed to execute typedef creation on Swing thread: ").append(e.getMessage());
        }

        if (success.get()) {
            return Response.text(result.toString());
        } else {
            return Response.err(result.toString());
        }
    }

    /**
     * Clone/copy a data type with a new name
     */
    @McpTool(value = "/clone_data_type", description = "Clone an existing data type with a new name", method = McpTool.Method.POST)

    public Response cloneDataType(

            @Param(value = "source_type") String sourceType,

            @Param(value = "new_name") String newName) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) return Response.err("No program loaded");
        if (sourceType == null || sourceType.isEmpty()) return Response.err("Source type is required");
        if (newName == null || newName.isEmpty()) return Response.err("New name is required");

        AtomicBoolean success = new AtomicBoolean(false);
        StringBuilder result = new StringBuilder();

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Clone data type");
                try {
                    DataTypeManager dtm = program.getDataTypeManager();
                    DataType source = ServiceUtils.findDataTypeByNameInAllCategories(dtm, sourceType);

                    if (source == null) {
                        result.append("Source type not found: ").append(sourceType);
                        return;
                    }

                    DataType cloned = source.clone(dtm);
                    cloned.setName(newName);

                    dtm.addDataType(cloned, DataTypeConflictHandler.REPLACE_HANDLER);
                    result.append("Data type '").append(sourceType).append("' cloned as '").append(newName).append("'");
                    success.set(true);
                } catch (Exception e) {
                    result.append("Error cloning data type: ").append(e.getMessage());
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            result.append("Failed to execute data type cloning on Swing thread: ").append(e.getMessage());
        }

        if (success.get()) {
            return Response.text(result.toString());
        } else {
            return Response.err(result.toString());
        }
    }

    /**
     * Create an array data type
     */
    @McpTool(value = "/create_array_type", description = "Create an array data type", method = McpTool.Method.POST)

    public Response createArrayType(

            @Param(value = "base_type") String baseType,

            @Param(value = "length", type = "integer", defaultValue = "1") int length,

            @Param(value = "name") String name) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) return Response.err("No program loaded");
        if (baseType == null || baseType.isEmpty()) return Response.err("Base type is required");
        if (length <= 0) return Response.err("Array length must be positive");

        AtomicBoolean success = new AtomicBoolean(false);
        StringBuilder result = new StringBuilder();

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Create array type");
                try {
                    DataTypeManager dtm = program.getDataTypeManager();
                    DataType baseDataType = ServiceUtils.resolveDataType(dtm, baseType);

                    if (baseDataType == null) {
                        result.append("Base data type not found: ").append(baseType);
                        return;
                    }

                    ArrayDataType arrayType = new ArrayDataType(baseDataType, length, baseDataType.getLength());

                    if (name != null && !name.isEmpty()) {
                        arrayType.setName(name);
                    }

                    DataType addedType = dtm.addDataType(arrayType, DataTypeConflictHandler.REPLACE_HANDLER);

                    result.append("Successfully created array type: ").append(addedType.getName())
                          .append(" (").append(baseType).append("[").append(length).append("])");
                    success.set(true);

                } catch (Exception e) {
                    result.append("Error creating array type: ").append(e.getMessage());
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            result.append("Failed to execute array type creation on Swing thread: ").append(e.getMessage());
        }

        if (success.get()) {
            return Response.text(result.toString());
        } else {
            return Response.err(result.toString());
        }
    }

    /**
     * Create a pointer data type
     */
    @McpTool(value = "/create_pointer_type", description = "Create a pointer data type wrapping a base type", method = McpTool.Method.POST)

    public Response createPointerType(

            @Param(value = "base_type") String baseType,

            @Param(value = "name") String name) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) return Response.err("No program loaded");
        if (baseType == null || baseType.isEmpty()) return Response.err("Base type is required");

        AtomicBoolean success = new AtomicBoolean(false);
        StringBuilder result = new StringBuilder();

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Create pointer type");
                try {
                    DataTypeManager dtm = program.getDataTypeManager();
                    DataType baseDataType = null;

                    if ("void".equals(baseType)) {
                        baseDataType = dtm.getDataType("/void");
                        if (baseDataType == null) {
                            baseDataType = VoidDataType.dataType;
                        }
                    } else {
                        baseDataType = ServiceUtils.resolveDataType(dtm, baseType);
                    }

                    if (baseDataType == null) {
                        result.append("Base data type not found: ").append(baseType);
                        return;
                    }

                    PointerDataType pointerType = new PointerDataType(baseDataType);

                    if (name != null && !name.isEmpty()) {
                        pointerType.setName(name);
                    }

                    DataType addedType = dtm.addDataType(pointerType, DataTypeConflictHandler.REPLACE_HANDLER);

                    result.append("Successfully created pointer type: ").append(addedType.getName())
                          .append(" (").append(baseType).append("*)");
                    success.set(true);

                } catch (Exception e) {
                    result.append("Error creating pointer type: ").append(e.getMessage());
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            result.append("Failed to execute pointer type creation on Swing thread: ").append(e.getMessage());
        }

        if (success.get()) {
            return Response.text(result.toString());
        } else {
            return Response.err(result.toString());
        }
    }

    /**
     * Create a function signature data type
     */
    @McpTool(value = "/create_function_signature", description = "Create function signature", method = McpTool.Method.POST)

    public Response createFunctionSignature(

            @Param(value = "name") String name,

            @Param(value = "return_type") String returnType,

            @Param(value = "parametersJson") String parametersJson) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) return Response.err("No program loaded");
        if (name == null || name.isEmpty()) return Response.err("Function name is required");
        if (returnType == null || returnType.isEmpty()) return Response.err("Return type is required");

        AtomicBoolean success = new AtomicBoolean(false);
        StringBuilder result = new StringBuilder();

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Create function signature");
                try {
                    DataTypeManager dtm = program.getDataTypeManager();

                    // Resolve return type
                    DataType returnDataType = ServiceUtils.resolveDataType(dtm, returnType);
                    if (returnDataType == null) {
                        result.append("Return type not found: ").append(returnType);
                        return;
                    }

                    // Create function definition
                    FunctionDefinitionDataType funcDef = new FunctionDefinitionDataType(name);
                    funcDef.setReturnType(returnDataType);

                    // Parse parameters if provided
                    if (parametersJson != null && !parametersJson.isEmpty()) {
                        try {
                            // Simple JSON parsing for parameters
                            String[] paramPairs = parametersJson.replace("[", "").replace("]", "")
                                                               .replace("{", "").replace("}", "")
                                                               .split(",");

                            for (String paramPair : paramPairs) {
                                if (paramPair.trim().isEmpty()) continue;

                                String[] parts = paramPair.split(":");
                                if (parts.length >= 2) {
                                    String paramType = parts[1].replace("\"", "").trim();
                                    DataType paramDataType = ServiceUtils.resolveDataType(dtm, paramType);
                                    if (paramDataType != null) {
                                        funcDef.setArguments(new ParameterDefinition[] {
                                            new ParameterDefinitionImpl(null, paramDataType, null)
                                        });
                                    }
                                }
                            }
                        } catch (Exception e) {
                            // If JSON parsing fails, continue without parameters
                            result.append("Warning: Could not parse parameters, continuing without them. ");
                        }
                    }

                    DataType addedFuncDef = dtm.addDataType(funcDef, DataTypeConflictHandler.REPLACE_HANDLER);

                    result.append("Successfully created function signature: ").append(addedFuncDef.getName());
                    success.set(true);

                } catch (Exception e) {
                    result.append("Error creating function signature: ").append(e.getMessage());
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            result.append("Failed to execute function signature creation on Swing thread: ").append(e.getMessage());
        }

        if (success.get()) {
            return Response.text(result.toString());
        } else {
            return Response.err(result.toString());
        }
    }

    // -----------------------------------------------------------------------
    // Data Type Modification Methods
    // -----------------------------------------------------------------------

    /**
     * Apply a specific data type at the given memory address
     */
    @McpTool(value = "/apply_data_type", description = "Apply a specific data type at the given memory address", method = McpTool.Method.POST)

    public Response applyDataType(

            @Param(value = "address") String addressStr,

            @Param(value = "type_name") String typeName,

            @Param(value = "clearExisting", type = "boolean") boolean clearExisting) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) {
            return Response.err("No program loaded");
        }

        if (addressStr == null || addressStr.isEmpty()) {
            return Response.err("Address is required");
        }

        if (typeName == null || typeName.isEmpty()) {
            return Response.err("Data type name is required");
        }

        try {
            Address address = program.getAddressFactory().getAddress(addressStr);
            if (address == null) {
                return Response.err("Invalid address: " + addressStr);
            }

            DataTypeManager dtm = program.getDataTypeManager();
            DataType dataType = ServiceUtils.resolveDataType(dtm, typeName);

            if (dataType == null) {
                return Response.err("Unknown data type: " + typeName + ". " +
                       "For arrays, use syntax 'basetype[count]' (e.g., 'dword[10]'). " +
                       "Or create the type first using create_struct, create_enum, or mcp_ghidra_create_array_type.");
            }

            Listing listing = program.getListing();

            // Check if address is in a valid memory block
            if (!program.getMemory().contains(address)) {
                return Response.err("Address is not in program memory: " + addressStr);
            }

            int txId = program.startTransaction("Apply Data Type: " + typeName);
            try {
                // Clear existing code/data if requested
                if (clearExisting) {
                    CodeUnit existingCU = listing.getCodeUnitAt(address);
                    if (existingCU != null) {
                        listing.clearCodeUnits(address,
                            address.add(Math.max(dataType.getLength() - 1, 0)), false);
                    }
                }

                // Apply the data type
                Data data = listing.createData(address, dataType);

                program.endTransaction(txId, true);

                // Validate size matches expectation
                int expectedSize = dataType.getLength();
                int actualSize = (data != null) ? data.getLength() : 0;

                if (actualSize != expectedSize) {
                    Msg.warn(this, String.format("Size mismatch: expected %d bytes but applied %d bytes at %s",
                                                 expectedSize, actualSize, addressStr));
                }

                StringBuilder resultText = new StringBuilder();
                resultText.append("Successfully applied data type '").append(typeName).append("' at ")
                       .append(addressStr).append(" (size: ").append(actualSize).append(" bytes)");

                // Add value information if available
                if (data != null && data.getValue() != null) {
                    resultText.append("\nValue: ").append(data.getValue().toString());
                }

                return Response.text(resultText.toString());

            } catch (Exception e) {
                program.endTransaction(txId, false);
                return Response.err("Error applying data type: " + e.getMessage());
            }

        } catch (Exception e) {
            return Response.err("Error processing request: " + e.getMessage());
        }
    }

    /**
     * Delete a data type from the program
     */
    @McpTool(value = "/delete_data_type", description = "Delete a data type from the program", method = McpTool.Method.POST)

    public Response deleteDataType(

            @Param(value = "type_name") String typeName) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) return Response.err("No program loaded");
        if (typeName == null || typeName.isEmpty()) return Response.err("Type name is required");

        AtomicBoolean success = new AtomicBoolean(false);
        StringBuilder result = new StringBuilder();

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Delete data type");
                try {
                    DataTypeManager dtm = program.getDataTypeManager();
                    DataType dataType = ServiceUtils.findDataTypeByNameInAllCategories(dtm, typeName);

                    if (dataType == null) {
                        result.append("Data type not found: ").append(typeName);
                        return;
                    }

                    // Check if type is in use (simplified check)
                    // Note: Ghidra will prevent deletion if type is in use during remove operation

                    boolean deleted = dtm.remove(dataType, null);
                    if (deleted) {
                        result.append("Data type '").append(typeName).append("' deleted successfully");
                        success.set(true);
                    } else {
                        result.append("Failed to delete data type '").append(typeName).append("'");
                    }

                } catch (Exception e) {
                    result.append("Error deleting data type: ").append(e.getMessage());
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            result.append("Failed to execute data type deletion on Swing thread: ").append(e.getMessage());
        }

        if (success.get()) {
            return Response.text(result.toString());
        } else {
            return Response.err(result.toString());
        }
    }

    /**
     * Modify a field in an existing structure
     */
    @McpTool(value = "/modify_struct_field", description = "Modify a field in an existing structure", method = McpTool.Method.POST)

    public Response modifyStructField(

            @Param(value = "struct_name") String structName,

            @Param(value = "field_name") String fieldName,

            @Param(value = "new_type") String newType,

            @Param(value = "new_name") String newName) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) return Response.err("No program loaded");
        if (structName == null || structName.isEmpty()) return Response.err("Structure name is required");
        if (fieldName == null || fieldName.isEmpty()) return Response.err("Field name is required");

        AtomicBoolean success = new AtomicBoolean(false);
        StringBuilder result = new StringBuilder();

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Modify struct field");
                try {
                    DataTypeManager dtm = program.getDataTypeManager();
                    DataType dataType = ServiceUtils.findDataTypeByNameInAllCategories(dtm, structName);

                    if (dataType == null) {
                        result.append("Structure not found: ").append(structName);
                        return;
                    }

                    if (!(dataType instanceof Structure)) {
                        result.append("Data type '").append(structName).append("' is not a structure");
                        return;
                    }

                    Structure struct = (Structure) dataType;
                    DataTypeComponent[] components = struct.getDefinedComponents();
                    DataTypeComponent targetComponent = null;

                    // Find the field to modify
                    for (DataTypeComponent component : components) {
                        if (fieldName.equals(component.getFieldName())) {
                            targetComponent = component;
                            break;
                        }
                    }

                    if (targetComponent == null) {
                        result.append("Field '").append(fieldName).append("' not found in structure '").append(structName).append("'");
                        return;
                    }

                    // If new type is specified, change the field type
                    if (newType != null && !newType.isEmpty()) {
                        DataType newDataType = ServiceUtils.resolveDataType(dtm, newType);
                        if (newDataType == null) {
                            result.append("New data type not found: ").append(newType);
                            return;
                        }
                        struct.replace(targetComponent.getOrdinal(), newDataType, newDataType.getLength());
                    }

                    // If new name is specified, change the field name
                    if (newName != null && !newName.isEmpty()) {
                        targetComponent = struct.getComponent(targetComponent.getOrdinal()); // Refresh component
                        targetComponent.setFieldName(newName);
                    }

                    result.append("Successfully modified field '").append(fieldName).append("' in structure '").append(structName).append("'");
                    success.set(true);

                } catch (Exception e) {
                    result.append("Error modifying struct field: ").append(e.getMessage());
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            result.append("Failed to execute struct field modification on Swing thread: ").append(e.getMessage());
        }

        if (success.get()) {
            return Response.text(result.toString());
        } else {
            return Response.err(result.toString());
        }
    }

    /**
     * Add a new field to an existing structure
     */
    @McpTool(value = "/add_struct_field", description = "Add a new field to an existing structure", method = McpTool.Method.POST)

    public Response addStructField(

            @Param(value = "struct_name") String structName,

            @Param(value = "field_name") String fieldName,

            @Param(value = "fieldType") String fieldType,

            @Param(value = "offset", type = "integer", required = false, defaultValue = "0") int offset) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) return Response.err("No program loaded");
        if (structName == null || structName.isEmpty()) return Response.err("Structure name is required");
        if (fieldName == null || fieldName.isEmpty()) return Response.err("Field name is required");
        if (fieldType == null || fieldType.isEmpty()) return Response.err("Field type is required");

        AtomicBoolean success = new AtomicBoolean(false);
        StringBuilder result = new StringBuilder();

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Add struct field");
                try {
                    DataTypeManager dtm = program.getDataTypeManager();
                    DataType dataType = ServiceUtils.findDataTypeByNameInAllCategories(dtm, structName);

                    if (dataType == null) {
                        result.append("Structure not found: ").append(structName);
                        return;
                    }

                    if (!(dataType instanceof Structure)) {
                        result.append("Data type '").append(structName).append("' is not a structure");
                        return;
                    }

                    Structure struct = (Structure) dataType;
                    DataType newFieldType = ServiceUtils.resolveDataType(dtm, fieldType);
                    if (newFieldType == null) {
                        result.append("Field data type not found: ").append(fieldType);
                        return;
                    }

                    if (offset >= 0) {
                        // Add at specific offset
                        struct.insertAtOffset(offset, newFieldType, newFieldType.getLength(), fieldName, null);
                    } else {
                        // Add at end
                        struct.add(newFieldType, fieldName, null);
                    }

                    result.append("Successfully added field '").append(fieldName).append("' to structure '").append(structName).append("'");
                    success.set(true);

                } catch (Exception e) {
                    result.append("Error adding struct field: ").append(e.getMessage());
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            result.append("Failed to execute struct field addition on Swing thread: ").append(e.getMessage());
        }

        if (success.get()) {
            return Response.text(result.toString());
        } else {
            return Response.err(result.toString());
        }
    }

    /**
     * Remove a field from an existing structure
     */
    @McpTool(value = "/remove_struct_field", description = "Remove a field from an existing structure", method = McpTool.Method.POST)

    public Response removeStructField(

            @Param(value = "struct_name") String structName,

            @Param(value = "field_name") String fieldName) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) return Response.err("No program loaded");
        if (structName == null || structName.isEmpty()) return Response.err("Structure name is required");
        if (fieldName == null || fieldName.isEmpty()) return Response.err("Field name is required");

        AtomicBoolean success = new AtomicBoolean(false);
        StringBuilder result = new StringBuilder();

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Remove struct field");
                try {
                    DataTypeManager dtm = program.getDataTypeManager();
                    DataType dataType = ServiceUtils.findDataTypeByNameInAllCategories(dtm, structName);

                    if (dataType == null) {
                        result.append("Structure not found: ").append(structName);
                        return;
                    }

                    if (!(dataType instanceof Structure)) {
                        result.append("Data type '").append(structName).append("' is not a structure");
                        return;
                    }

                    Structure struct = (Structure) dataType;
                    DataTypeComponent[] components = struct.getDefinedComponents();
                    int targetOrdinal = -1;

                    // Find the field to remove
                    for (DataTypeComponent component : components) {
                        if (fieldName.equals(component.getFieldName())) {
                            targetOrdinal = component.getOrdinal();
                            break;
                        }
                    }

                    if (targetOrdinal == -1) {
                        result.append("Field '").append(fieldName).append("' not found in structure '").append(structName).append("'");
                        return;
                    }

                    struct.delete(targetOrdinal);
                    result.append("Successfully removed field '").append(fieldName).append("' from structure '").append(structName).append("'");
                    success.set(true);

                } catch (Exception e) {
                    result.append("Error removing struct field: ").append(e.getMessage());
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            result.append("Failed to execute struct field removal on Swing thread: ").append(e.getMessage());
        }

        if (success.get()) {
            return Response.text(result.toString());
        } else {
            return Response.err(result.toString());
        }
    }

    /**
     * Move a data type to a different category
     */
    @McpTool(value = "/move_data_type_to_category", description = "Move an existing data type to a different category", method = McpTool.Method.POST)

    public Response moveDataTypeToCategory(

            @Param(value = "type_name") String typeName,

            @Param(value = "category_path") String categoryPath) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) return Response.err("No program loaded");
        if (typeName == null || typeName.isEmpty()) return Response.err("Type name is required");
        if (categoryPath == null || categoryPath.isEmpty()) return Response.err("Category path is required");

        AtomicBoolean success = new AtomicBoolean(false);
        StringBuilder result = new StringBuilder();

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Move data type to category");
                try {
                    DataTypeManager dtm = program.getDataTypeManager();
                    DataType dataType = ServiceUtils.findDataTypeByNameInAllCategories(dtm, typeName);

                    if (dataType == null) {
                        result.append("Data type not found: ").append(typeName);
                        return;
                    }

                    CategoryPath catPath = new CategoryPath(categoryPath);
                    Category category = dtm.createCategory(catPath);

                    // Move the data type
                    dataType.setCategoryPath(catPath);

                    result.append("Successfully moved data type '").append(typeName)
                          .append("' to category '").append(categoryPath).append("'");
                    success.set(true);

                } catch (Exception e) {
                    result.append("Error moving data type: ").append(e.getMessage());
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            result.append("Failed to execute data type move on Swing thread: ").append(e.getMessage());
        }

        if (success.get()) {
            return Response.text(result.toString());
        } else {
            return Response.err(result.toString());
        }
    }

    // -----------------------------------------------------------------------
    // Data Type Validation Methods
    // -----------------------------------------------------------------------

    /**
     * Validate if a data type fits at a given address
     */
    @McpTool(value = "/validate_data_type", description = "Validate whether a data type can be applied at a specific memory address")

    public Response validateDataType(

            @Param(value = "address") String addressStr,

            @Param(value = "type_name") String typeName) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) return Response.err("No program loaded");
        if (addressStr == null || addressStr.isEmpty()) return Response.err("Address is required");
        if (typeName == null || typeName.isEmpty()) return Response.err("Type name is required");

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            DataTypeManager dtm = program.getDataTypeManager();
            DataType dataType = ServiceUtils.findDataTypeByNameInAllCategories(dtm, typeName);

            if (dataType == null) {
                return Response.err("Data type not found: " + typeName);
            }

            StringBuilder result = new StringBuilder();
            result.append("Validation for type '").append(typeName).append("' at address ").append(addressStr).append(":\n\n");

            // Check if memory is available
            Memory memory = program.getMemory();
            int typeSize = dataType.getLength();
            Address endAddr = addr.add(typeSize - 1);

            if (!memory.contains(addr) || !memory.contains(endAddr)) {
                result.append("FAIL: Memory range not available\n");
                result.append("   Required: ").append(addr).append(" - ").append(endAddr).append("\n");
                return Response.text(result.toString());
            }

            result.append("PASS: Memory range available\n");
            result.append("   Range: ").append(addr).append(" - ").append(endAddr).append(" (").append(typeSize).append(" bytes)\n");

            // Check alignment
            long alignment = dataType.getAlignment();
            if (alignment > 1 && addr.getOffset() % alignment != 0) {
                result.append("WARN: Alignment warning: Address not aligned to ").append(alignment).append("-byte boundary\n");
            } else {
                result.append("PASS: Proper alignment\n");
            }

            // Check if there's existing data
            Data existingData = program.getListing().getDefinedDataAt(addr);
            if (existingData != null) {
                result.append("WARN: Existing data: ").append(existingData.getDataType().getName()).append("\n");
            } else {
                result.append("PASS: No conflicting data\n");
            }

            return Response.text(result.toString());
        } catch (Exception e) {
            return Response.err("Error validating data type: " + e.getMessage());
        }
    }

    /**
     * NEW v1.6.0: Validate function prototype before applying
     */
    @McpTool(value = "/validate_function_prototype", description = "Validate a function prototype before applying it")

    public Response validateFunctionPrototype(

            @Param(value = "function_address") String functionAddress,

            @Param(value = "prototype") String prototype,

            @Param(value = "calling_convention") String callingConvention) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) {
            return Response.err("No program loaded");
        }

        Map<String, Object> resultMap = new LinkedHashMap<>();
        final AtomicReference<String> errorMsg = new AtomicReference<>(null);

        try {
            SwingUtilities.invokeAndWait(() -> {
                try {
                    Address addr = program.getAddressFactory().getAddress(functionAddress);
                    if (addr == null) {
                        resultMap.put("valid", false);
                        resultMap.put("error", "Invalid address: " + functionAddress);
                        return;
                    }

                    Function func = program.getFunctionManager().getFunctionAt(addr);
                    if (func == null) {
                        resultMap.put("valid", false);
                        resultMap.put("error", "No function at address: " + functionAddress);
                        return;
                    }

                    // Basic validation - check if prototype string is parseable
                    if (prototype == null || prototype.trim().isEmpty()) {
                        resultMap.put("valid", false);
                        resultMap.put("error", "Empty prototype");
                        return;
                    }

                    // Check for common issues
                    List<String> warnings = new ArrayList<>();

                    // Check for return type
                    if (!prototype.contains("(")) {
                        resultMap.put("valid", false);
                        resultMap.put("error", "Invalid prototype format - missing parentheses");
                        return;
                    }

                    // Validate calling convention if provided
                    if (callingConvention != null && !callingConvention.isEmpty()) {
                        String[] validConventions = {"__cdecl", "__stdcall", "__fastcall", "__thiscall", "default"};
                        boolean validConv = false;
                        for (String valid : validConventions) {
                            if (callingConvention.equalsIgnoreCase(valid)) {
                                validConv = true;
                                break;
                            }
                        }
                        if (!validConv) {
                            warnings.add("Unknown calling convention: " + callingConvention);
                        }
                    }

                    resultMap.put("valid", true);
                    if (!warnings.isEmpty()) {
                        resultMap.put("warnings", warnings);
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

        return Response.ok(resultMap);
    }

    /**
     * Import data types (placeholder)
     */
    @McpTool(value = "/import_data_types", description = "Import data types from an external source file", method = McpTool.Method.POST)

    public Response importDataTypes(

            @Param(value = "source") String source,

            @Param(value = "format", required = false) String format) {
        // This is a placeholder for import functionality
        // In a real implementation, you would parse the source based on format
        return Response.text("Import functionality not yet implemented. Source: " + source + ", Format: " + format);
    }

    // -----------------------------------------------------------------------
    // Data Type Category Methods
    // -----------------------------------------------------------------------

    /**
     * Create a new data type category
     */
    @McpTool(value = "/create_data_type_category", description = "Create a new category (folder) in the data type manager", method = McpTool.Method.POST)

    public Response createDataTypeCategory(

            @Param(value = "category_path") String categoryPath) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) return Response.err("No program loaded");
        if (categoryPath == null || categoryPath.isEmpty()) return Response.err("Category path is required");

        try {
            DataTypeManager dtm = program.getDataTypeManager();
            CategoryPath catPath = new CategoryPath(categoryPath);
            Category category = dtm.createCategory(catPath);

            return Response.text("Successfully created category: " + category.getCategoryPathName());
        } catch (Exception e) {
            return Response.err("Error creating category: " + e.getMessage());
        }
    }

    /**
     * List all data type categories
     */
    @McpTool(value = "/list_data_type_categories", description = "List all data type categories (folders) in the program")

    public Response listDataTypeCategories(

            @Param(value = "offset", type = "integer", required = false, defaultValue = "0") int offset,

            @Param(value = "limit", type = "integer", required = false, defaultValue = "100") int limit) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) return Response.err("No program loaded");

        try {
            DataTypeManager dtm = program.getDataTypeManager();
            List<String> categories = new ArrayList<>();

            // Get all categories recursively
            addCategoriesRecursively(dtm.getRootCategory(), categories, "");

            return Response.text(ServiceUtils.paginateList(categories, offset, limit));
        } catch (Exception e) {
            return Response.err("Error listing categories: " + e.getMessage());
        }
    }

    /**
     * Helper method to recursively add categories
     */
    private void addCategoriesRecursively(Category category, List<String> categories, String parentPath) {
        for (Category subCategory : category.getCategories()) {
            String fullPath = parentPath.isEmpty() ?
                            subCategory.getName() :
                            parentPath + "/" + subCategory.getName();
            categories.add(fullPath);
            addCategoriesRecursively(subCategory, categories, fullPath);
        }
    }

    // -----------------------------------------------------------------------
    // Data Type Analysis Methods
    // -----------------------------------------------------------------------

    /**
     * ANALYZE_STRUCT_FIELD_USAGE - Analyze how structure fields are accessed in decompiled code
     *
     * This method decompiles all functions that reference a structure and extracts usage patterns
     * for each field, including variable names, access types, and purposes.
     *
     * @param addressStr Address of the structure instance
     * @param structName Name of the structure type (optional - can be inferred if null)
     * @param maxFunctionsToAnalyze Maximum number of referencing functions to analyze
     * @return Response with field usage analysis
     */
    @SuppressWarnings("deprecation")
    @McpTool(value = "/analyze_struct_field_usage", description = "Analyze how structure fields are accessed in decompiled code", method = McpTool.Method.POST)

    public Response analyzeStructFieldUsage(

            @Param(value = "address") String addressStr,

            @Param(value = "struct_name") String structName,

            @Param(value = "maxFunctionsToAnalyze", type = "integer") int maxFunctionsToAnalyze) {
        // CRITICAL FIX #3: Validate input parameters
        if (maxFunctionsToAnalyze < MIN_FUNCTIONS_TO_ANALYZE || maxFunctionsToAnalyze > MAX_FUNCTIONS_TO_ANALYZE) {
            return Response.err("maxFunctionsToAnalyze must be between " + MIN_FUNCTIONS_TO_ANALYZE +
                   " and " + MAX_FUNCTIONS_TO_ANALYZE);
        }

        final AtomicReference<Response> result = new AtomicReference<>();

        // CRITICAL FIX #1: Thread safety - wrap in SwingUtilities.invokeAndWait
        try {
            SwingUtilities.invokeAndWait(() -> {
                try {
                    Program program = programProvider.getCurrentProgram();
                    if (program == null) {
                        result.set(Response.err("No program loaded"));
                        return;
                    }

                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    if (addr == null) {
                        result.set(Response.err("Invalid address: " + addressStr));
                        return;
                    }

                    // Get data at address to determine structure
                    Data data = program.getListing().getDataAt(addr);
                    DataType dataType = (data != null) ? data.getDataType() : null;

                    if (dataType == null || !(dataType instanceof Structure)) {
                        result.set(Response.err("No structure data type found at " + addressStr));
                        return;
                    }

                    Structure struct = (Structure) dataType;

                    // MAJOR FIX #5: Validate structure size
                    DataTypeComponent[] components = struct.getComponents();
                    if (components.length > MAX_STRUCT_FIELDS) {
                        result.set(Response.err("Structure too large (" + components.length +
                                   " fields). Maximum " + MAX_STRUCT_FIELDS + " fields supported."));
                        return;
                    }

                    String actualStructName = (structName != null && !structName.isEmpty()) ? structName : struct.getName();

                    // Get all xrefs to this address
                    ReferenceManager refMgr = program.getReferenceManager();
                    ReferenceIterator refIter = refMgr.getReferencesTo(addr);

                    Set<Function> functionsToAnalyze = new HashSet<>();
                    while (refIter.hasNext() && functionsToAnalyze.size() < maxFunctionsToAnalyze) {
                        Reference ref = refIter.next();
                        Function func = program.getFunctionManager().getFunctionContaining(ref.getFromAddress());
                        if (func != null) {
                            functionsToAnalyze.add(func);
                        }
                    }

                    // Decompile all functions and analyze field usage
                    Map<Integer, FieldUsageInfo> fieldUsageMap = new HashMap<>();
                    DecompInterface decomp = null;

                    // CRITICAL FIX #2: Resource management with try-finally
                    try {
                        decomp = new DecompInterface();
                        decomp.openProgram(program);

                        long analysisStart = System.currentTimeMillis();
                        Msg.info(this, "Analyzing struct at " + addressStr + " with " + functionsToAnalyze.size() + " functions");

                        for (Function func : functionsToAnalyze) {
                            try {
                                DecompileResults results = decomp.decompileFunction(func, DECOMPILE_TIMEOUT_SECONDS,
                                                                                   new ConsoleTaskMonitor());
                                if (results != null && results.decompileCompleted()) {
                                    String decompiledCode = results.getDecompiledFunction().getC();
                                    analyzeFieldUsageInCode(decompiledCode, struct, fieldUsageMap, addr.toString());
                                } else {
                                    Msg.warn(this, "Failed to decompile function: " + func.getName());
                                }
                            } catch (Exception e) {
                                // Continue with other functions if one fails
                                Msg.error(this, "Error decompiling function " + func.getName() + ": " + e.getMessage());
                            }
                        }

                        long analysisTime = System.currentTimeMillis() - analysisStart;
                        Msg.info(this, "Field analysis completed in " + analysisTime + "ms, found " +
                                 fieldUsageMap.size() + " fields with usage data");

                    } finally {
                        // CRITICAL FIX #2: Always dispose of DecompInterface
                        if (decomp != null) {
                            decomp.dispose();
                        }
                    }

                    // Build JSON response with field analysis
                    StringBuilder json = new StringBuilder();
                    json.append("{");
                    json.append("\"struct_address\": \"").append(addressStr).append("\",");
                    json.append("\"struct_name\": \"").append(ServiceUtils.escapeJson(actualStructName)).append("\",");
                    json.append("\"struct_size\": ").append(struct.getLength()).append(",");
                    json.append("\"functions_analyzed\": ").append(functionsToAnalyze.size()).append(",");
                    json.append("\"field_usage\": {");

                    boolean first = true;
                    for (int i = 0; i < components.length; i++) {
                        DataTypeComponent component = components[i];
                        int offset = component.getOffset();

                        if (!first) json.append(",");
                        first = false;

                        json.append("\"").append(offset).append("\": {");
                        json.append("\"field_name\": \"").append(ServiceUtils.escapeJson(component.getFieldName())).append("\",");
                        json.append("\"field_type\": \"").append(ServiceUtils.escapeJson(component.getDataType().getName())).append("\",");
                        json.append("\"offset\": ").append(offset).append(",");
                        json.append("\"size\": ").append(component.getLength()).append(",");

                        FieldUsageInfo usageInfo = fieldUsageMap.get(offset);
                        if (usageInfo != null) {
                            json.append("\"access_count\": ").append(usageInfo.accessCount).append(",");
                            json.append("\"suggested_names\": ").append(usageInfo.getSuggestedNamesJson()).append(",");
                            json.append("\"usage_patterns\": ").append(usageInfo.getUsagePatternsJson());
                        } else {
                            json.append("\"access_count\": 0,");
                            json.append("\"suggested_names\": [],");
                            json.append("\"usage_patterns\": []");
                        }

                        json.append("}");
                    }

                    json.append("}");
                    json.append("}");

                    result.set(Response.text(json.toString()));
                } catch (Exception e) {
                    result.set(Response.err(e.getMessage()));
                }
            });
        } catch (InvocationTargetException | InterruptedException e) {
            Msg.error(this, "Thread synchronization error in analyzeStructFieldUsage", e);
            return Response.err("Thread synchronization error: " + e.getMessage());
        }

        return result.get();
    }

    /**
     * Analyze decompiled code to extract field usage patterns
     * MAJOR FIX #4: Improved pattern matching with word boundaries and keyword filtering
     */
    private void analyzeFieldUsageInCode(String code, Structure struct, Map<Integer, FieldUsageInfo> fieldUsageMap, String baseAddr) {
        String[] lines = code.split("\\n");

        for (String line : lines) {
            // Skip empty lines and comments
            String trimmedLine = line.trim();
            if (trimmedLine.isEmpty() || trimmedLine.startsWith("//") || trimmedLine.startsWith("/*")) {
                continue;
            }

            // Look for field access patterns
            for (DataTypeComponent component : struct.getComponents()) {
                String fieldName = component.getFieldName();
                int offset = component.getOffset();
                boolean fieldMatched = false;

                // IMPROVED: Use word boundary matching for field names
                Pattern fieldPattern = Pattern.compile("\\b" + Pattern.quote(fieldName) + "\\b");
                if (fieldPattern.matcher(line).find()) {
                    fieldMatched = true;
                }

                // IMPROVED: Use word boundary for offset matching (e.g., "+4" but not "+40")
                Pattern offsetPattern = Pattern.compile("\\+\\s*" + offset + "\\b");
                if (offsetPattern.matcher(line).find()) {
                    fieldMatched = true;
                }

                if (fieldMatched) {
                    FieldUsageInfo info = fieldUsageMap.computeIfAbsent(offset, k -> new FieldUsageInfo());
                    info.accessCount++;

                    // IMPROVED: Detect usage patterns with better regex
                    // Conditional check: if (field == ...) or if (field != ...)
                    if (line.matches(".*\\bif\\s*\\(.*\\b" + Pattern.quote(fieldName) + "\\b.*(==|!=|<|>|<=|>=).*")) {
                        info.usagePatterns.add("conditional_check");
                    }

                    // Increment/decrement: field++ or field--
                    if (line.matches(".*\\b" + Pattern.quote(fieldName) + "\\s*(\\+\\+|--).*") ||
                        line.matches(".*(\\+\\+|--)\\s*\\b" + Pattern.quote(fieldName) + "\\b.*")) {
                        info.usagePatterns.add("increment_decrement");
                    }

                    // Assignment: variable = field or field = value
                    if (line.matches(".*\\b\\w+\\s*=\\s*.*\\b" + Pattern.quote(fieldName) + "\\b.*") ||
                        line.matches(".*\\b" + Pattern.quote(fieldName) + "\\s*=.*")) {
                        info.usagePatterns.add("assignment");
                    }

                    // Array access: field[index]
                    if (line.matches(".*\\b" + Pattern.quote(fieldName) + "\\s*\\[.*\\].*")) {
                        info.usagePatterns.add("array_access");
                    }

                    // Pointer dereference: ptr->field or struct.field
                    if (line.matches(".*->\\s*\\b" + Pattern.quote(fieldName) + "\\b.*") ||
                        line.matches(".*\\.\\s*\\b" + Pattern.quote(fieldName) + "\\b.*")) {
                        info.usagePatterns.add("pointer_dereference");
                    }

                    // IMPROVED: Extract variable names with C keyword filtering
                    String[] tokens = line.split("\\W+");
                    for (String token : tokens) {
                        if (token.length() >= MIN_TOKEN_LENGTH &&
                            !token.equals(fieldName) &&
                            !C_KEYWORDS.contains(token.toLowerCase()) &&
                            Character.isLetter(token.charAt(0)) &&
                            !token.matches("\\d+")) {  // Filter out numbers
                            info.suggestedNames.add(token);
                        }
                    }
                }
            }
        }
    }

    /**
     * SUGGEST_FIELD_NAMES - AI-assisted field name suggestions based on usage patterns
     *
     * @param structAddressStr Address of the structure instance
     * @param structSize Size of the structure in bytes (0 for auto-detect)
     * @return Response with field name suggestions
     */
    @SuppressWarnings("deprecation")
    @McpTool(value = "/suggest_field_names", description = "Get AI-assisted field name suggestions for a structure at an address", method = McpTool.Method.POST)

    public Response suggestFieldNames(

            @Param(value = "struct_address") String structAddressStr,

            @Param(value = "structSize", type = "integer") int structSize) {
        // Validate input parameters
        if (structSize < 0 || structSize > MAX_FIELD_OFFSET) {
            return Response.err("structSize must be between 0 and " + MAX_FIELD_OFFSET);
        }

        final AtomicReference<Response> result = new AtomicReference<>();

        // CRITICAL FIX #1: Thread safety - wrap in SwingUtilities.invokeAndWait
        try {
            SwingUtilities.invokeAndWait(() -> {
                try {
                    Program program = programProvider.getCurrentProgram();
                    if (program == null) {
                        result.set(Response.err("No program loaded"));
                        return;
                    }

                    Address addr = program.getAddressFactory().getAddress(structAddressStr);
                    if (addr == null) {
                        result.set(Response.err("Invalid address: " + structAddressStr));
                        return;
                    }

                    Msg.info(this, "Generating field name suggestions for structure at " + structAddressStr);

                    // Get data at address
                    Data data = program.getListing().getDataAt(addr);
                    DataType dataType = (data != null) ? data.getDataType() : null;

                    if (dataType == null || !(dataType instanceof Structure)) {
                        result.set(Response.err("No structure data type found at " + structAddressStr));
                        return;
                    }

                    Structure struct = (Structure) dataType;

                    // MAJOR FIX #5: Validate structure size
                    DataTypeComponent[] components = struct.getComponents();
                    if (components.length > MAX_STRUCT_FIELDS) {
                        result.set(Response.err("Structure too large: " + components.length +
                                   " fields (max " + MAX_STRUCT_FIELDS + ")"));
                        return;
                    }

                    StringBuilder json = new StringBuilder();
                    json.append("{");
                    json.append("\"struct_address\": \"").append(structAddressStr).append("\",");
                    json.append("\"struct_name\": \"").append(ServiceUtils.escapeJson(struct.getName())).append("\",");
                    json.append("\"struct_size\": ").append(struct.getLength()).append(",");
                    json.append("\"suggestions\": [");

                    boolean first = true;
                    for (DataTypeComponent component : components) {
                        if (!first) json.append(",");
                        first = false;

                        json.append("{");
                        json.append("\"offset\": ").append(component.getOffset()).append(",");
                        json.append("\"current_name\": \"").append(ServiceUtils.escapeJson(component.getFieldName())).append("\",");
                        json.append("\"field_type\": \"").append(ServiceUtils.escapeJson(component.getDataType().getName())).append("\",");

                        // Generate suggestions based on type and patterns
                        List<String> suggestions = generateFieldNameSuggestions(component);

                        // Ensure we always have fallback suggestions
                        if (suggestions.isEmpty()) {
                            suggestions.add(component.getFieldName() + "Value");
                            suggestions.add(component.getFieldName() + "Data");
                        }

                        json.append("\"suggested_names\": [");
                        for (int i = 0; i < suggestions.size(); i++) {
                            if (i > 0) json.append(",");
                            json.append("\"").append(ServiceUtils.escapeJson(suggestions.get(i))).append("\"");
                        }
                        json.append("],");

                        json.append("\"confidence\": \"medium\"");  // Placeholder confidence level
                        json.append("}");
                    }

                    json.append("]");
                    json.append("}");

                    Msg.info(this, "Generated suggestions for " + components.length + " fields");
                    result.set(Response.text(json.toString()));

                } catch (Exception e) {
                    Msg.error(this, "Error in suggestFieldNames", e);
                    result.set(Response.err(e.getMessage()));
                }
            });
        } catch (InvocationTargetException | InterruptedException e) {
            Msg.error(this, "Thread synchronization error in suggestFieldNames", e);
            return Response.err("Thread synchronization error: " + e.getMessage());
        }

        return result.get();
    }

    /**
     * Generate field name suggestions based on data type and patterns
     */
    private List<String> generateFieldNameSuggestions(DataTypeComponent component) {
        List<String> suggestions = new ArrayList<>();
        String typeName = component.getDataType().getName().toLowerCase();
        String currentName = component.getFieldName();

        // Hungarian notation suggestions based on type
        if (typeName.contains("pointer") || typeName.startsWith("p")) {
            suggestions.add("p" + capitalizeFirst(currentName));
            suggestions.add("lp" + capitalizeFirst(currentName));
        } else if (typeName.contains("dword")) {
            suggestions.add("dw" + capitalizeFirst(currentName));
        } else if (typeName.contains("word")) {
            suggestions.add("w" + capitalizeFirst(currentName));
        } else if (typeName.contains("byte") || typeName.contains("char")) {
            suggestions.add("b" + capitalizeFirst(currentName));
            suggestions.add("sz" + capitalizeFirst(currentName));
        } else if (typeName.contains("int")) {
            suggestions.add("n" + capitalizeFirst(currentName));
            suggestions.add("i" + capitalizeFirst(currentName));
        }

        // Add generic suggestions
        suggestions.add(currentName + "Value");
        suggestions.add(currentName + "Data");

        return suggestions;
    }

    /**
     * 6. APPLY_DATA_CLASSIFICATION - Atomic type application
     */
    @SuppressWarnings("unchecked")
    @McpTool(value = "/apply_data_classification", description = "Apply data type classification at an address with naming and comments in one atomic call", method = McpTool.Method.POST)

    public Response applyDataClassification(

            @Param(value = "address") String addressStr,

            @Param(value = "classification") String classification,

            @Param(value = "name") String name,

            @Param(value = "comment") String comment,

            @Param(value = "typeDefinitionObj", type = "object") Object typeDefinitionObj) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) return Response.err("No program loaded");

        final AtomicReference<Response> responseRef = new AtomicReference<>();
        final AtomicReference<String> typeApplied = new AtomicReference<>("none");
        final List<String> operations = new ArrayList<>();

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            if (addr == null) {
                return Response.err("Invalid address: " + addressStr);
            }

            // Parse type_definition from the object
            final Map<String, Object> typeDef;
            if (typeDefinitionObj instanceof Map) {
                typeDef = (Map<String, Object>) typeDefinitionObj;
            } else if (typeDefinitionObj == null) {
                typeDef = null;
            } else {
                // Received something unexpected - log it for debugging
                return Response.err("type_definition must be a JSON object/dict, got: " +
                       typeDefinitionObj.getClass().getSimpleName() +
                       " with value: " + String.valueOf(typeDefinitionObj));
            }

            final String finalClassification = classification;
            final String finalName = name;
            final String finalComment = comment;

            // Atomic transaction for all operations
            SwingUtilities.invokeAndWait(() -> {
                int txId = program.startTransaction("Apply Data Classification");
                boolean success = false;

                try {
                    DataTypeManager dtm = program.getDataTypeManager();
                    Listing listing = program.getListing();
                    DataType dataTypeToApply = null;

                    // 1. CREATE/RESOLVE DATA TYPE based on classification
                    if ("PRIMITIVE".equals(finalClassification)) {
                        // CRITICAL FIX: Require type_definition for PRIMITIVE classification
                        if (typeDef == null) {
                            throw new IllegalArgumentException(
                                "PRIMITIVE classification requires type_definition parameter. " +
                                "Example: type_definition='{\"type\": \"dword\"}' or type_definition={\"type\": \"dword\"}");
                        }
                        if (!typeDef.containsKey("type")) {
                            throw new IllegalArgumentException(
                                "PRIMITIVE classification requires 'type' field in type_definition. " +
                                "Received: " + typeDef.keySet() + ". " +
                                "Example: {\"type\": \"dword\"}");
                        }

                        String typeStr = (String) typeDef.get("type");
                        dataTypeToApply = ServiceUtils.resolveDataType(dtm, typeStr);
                        if (dataTypeToApply != null) {
                            typeApplied.set(typeStr);
                            operations.add("resolved_primitive_type");
                        } else {
                            throw new IllegalArgumentException("Failed to resolve primitive type: " + typeStr);
                        }
                    }
                    else if ("STRUCTURE".equals(finalClassification)) {
                        // CRITICAL FIX: Require type_definition for STRUCTURE classification
                        if (typeDef == null || !typeDef.containsKey("name") || !typeDef.containsKey("fields")) {
                            throw new IllegalArgumentException(
                                "STRUCTURE classification requires type_definition with 'name' and 'fields'. " +
                                "Example: {\"name\": \"MyStruct\", \"fields\": [{\"name\": \"field1\", \"type\": \"dword\"}]}");
                        }

                        String structName2 = (String) typeDef.get("name");
                        Object fieldsObj = typeDef.get("fields");

                        // Check if structure already exists
                        DataType existing = dtm.getDataType("/" + structName2);
                        if (existing != null) {
                            dataTypeToApply = existing;
                            typeApplied.set(structName2);
                            operations.add("found_existing_structure");
                        } else {
                            // Create new structure
                            StructureDataType struct = new StructureDataType(structName2, 0);

                            // Parse fields
                            if (fieldsObj instanceof List) {
                                List<Map<String, Object>> fieldsList = (List<Map<String, Object>>) fieldsObj;
                                for (Map<String, Object> field : fieldsList) {
                                    String fieldName = (String) field.get("name");
                                    String fieldType = (String) field.get("type");

                                    DataType fieldDataType = ServiceUtils.resolveDataType(dtm, fieldType);
                                    if (fieldDataType != null) {
                                        struct.add(fieldDataType, fieldDataType.getLength(), fieldName, "");
                                    }
                                }
                            }

                            dataTypeToApply = dtm.addDataType(struct, null);
                            typeApplied.set(structName2);
                            operations.add("created_structure");
                        }
                    }
                    else if ("ARRAY".equals(finalClassification)) {
                        // CRITICAL FIX: Require type_definition for ARRAY classification
                        if (typeDef == null) {
                            throw new IllegalArgumentException(
                                "ARRAY classification requires type_definition with 'element_type' or 'element_struct', and 'count'. " +
                                "Example: {\"element_type\": \"dword\", \"count\": 64}");
                        }

                        DataType elementType = null;
                        int count = 1;

                        // Support element_type or element_struct
                        if (typeDef.containsKey("element_type")) {
                            String elementTypeStr = (String) typeDef.get("element_type");
                            elementType = ServiceUtils.resolveDataType(dtm, elementTypeStr);
                            if (elementType == null) {
                                throw new IllegalArgumentException("Failed to resolve array element type: " + elementTypeStr);
                            }
                        } else if (typeDef.containsKey("element_struct")) {
                            String structName2 = (String) typeDef.get("element_struct");
                            elementType = dtm.getDataType("/" + structName2);
                            if (elementType == null) {
                                throw new IllegalArgumentException("Failed to find struct for array element: " + structName2);
                            }
                        } else {
                            throw new IllegalArgumentException(
                                "ARRAY type_definition must contain 'element_type' or 'element_struct'");
                        }

                        if (typeDef.containsKey("count")) {
                            Object countObj = typeDef.get("count");
                            if (countObj instanceof Integer) {
                                count = (Integer) countObj;
                            } else if (countObj instanceof String) {
                                count = Integer.parseInt((String) countObj);
                            }
                        } else {
                            throw new IllegalArgumentException("ARRAY type_definition must contain 'count' field");
                        }

                        if (count <= 0) {
                            throw new IllegalArgumentException("Array count must be positive, got: " + count);
                        }

                        ArrayDataType arrayType = new ArrayDataType(elementType, count, elementType.getLength());
                        dataTypeToApply = arrayType;
                        typeApplied.set(elementType.getName() + "[" + count + "]");
                        operations.add("created_array");
                    }
                    else if ("STRING".equals(finalClassification)) {
                        if (typeDef != null && typeDef.containsKey("type")) {
                            String typeStr = (String) typeDef.get("type");
                            dataTypeToApply = ServiceUtils.resolveDataType(dtm, typeStr);
                            if (dataTypeToApply != null) {
                                typeApplied.set(typeStr);
                                operations.add("resolved_string_type");
                            }
                        }
                    }

                    // 2. APPLY DATA TYPE
                    if (dataTypeToApply != null) {
                        // Clear existing code/data
                        CodeUnit existingCU = listing.getCodeUnitAt(addr);
                        if (existingCU != null) {
                            listing.clearCodeUnits(addr,
                                addr.add(Math.max(dataTypeToApply.getLength() - 1, 0)), false);
                        }

                        listing.createData(addr, dataTypeToApply);
                        operations.add("applied_type");
                    }

                    // 3. RENAME (if name provided)
                    if (finalName != null && !finalName.isEmpty()) {
                        Data data = listing.getDefinedDataAt(addr);
                        if (data != null) {
                            SymbolTable symTable = program.getSymbolTable();
                            Symbol symbol = symTable.getPrimarySymbol(addr);
                            if (symbol != null) {
                                symbol.setName(finalName, SourceType.USER_DEFINED);
                            } else {
                                symTable.createLabel(addr, finalName, SourceType.USER_DEFINED);
                            }
                            operations.add("renamed");
                        }
                    }

                    // 4. SET COMMENT (if provided)
                    if (finalComment != null && !finalComment.isEmpty()) {
                        // CRITICAL FIX: Unescape newlines before setting comment
                        String unescapedComment = finalComment.replace("\\n", "\n")
                                                             .replace("\\t", "\t")
                                                             .replace("\\r", "\r");
                        listing.setComment(addr, CodeUnit.PRE_COMMENT, unescapedComment);
                        operations.add("commented");
                    }

                    success = true;

                } catch (Exception e) {
                    responseRef.set(Response.err(e.getMessage()));
                } finally {
                    program.endTransaction(txId, success);
                }
            });

            // Build result if no error
            if (responseRef.get() != null) {
                return responseRef.get();
            }

            Map<String, Object> resultMap = new LinkedHashMap<>();
            resultMap.put("success", true);
            resultMap.put("address", addressStr);
            resultMap.put("classification", classification);
            if (name != null) {
                resultMap.put("name", name);
            }
            resultMap.put("type_applied", typeApplied.get());
            resultMap.put("operations_performed", operations);

            return Response.ok(resultMap);

        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    // -----------------------------------------------------------------------
    // JSON Parsing Helpers (for struct/union field definitions)
    // -----------------------------------------------------------------------

    /**
     * Parse fields JSON into FieldDefinition objects using robust JSON parsing
     * Supports array format: [{"name":"field1","type":"uint"}, {"name":"field2","type":"void*"}]
     */
    private List<FieldDefinition> parseFieldsJson(String fieldsJson) {
        List<FieldDefinition> fields = new ArrayList<>();

        if (fieldsJson == null || fieldsJson.isEmpty()) {
            Msg.error(this, "Fields JSON is null or empty");
            return fields;
        }

        try {
            // Trim and validate JSON array
            String json = fieldsJson.trim();
            if (!json.startsWith("[")) {
                Msg.error(this, "Fields JSON must be an array starting with [, got: " + json.substring(0, Math.min(50, json.length())));
                return fields;
            }
            if (!json.endsWith("]")) {
                Msg.error(this, "Fields JSON must be an array ending with ]");
                return fields;
            }

            // Remove outer brackets
            json = json.substring(1, json.length() - 1).trim();

            // Parse field objects using proper bracket/brace matching
            List<String> fieldJsons = parseFieldJsonArray(json);
            Msg.info(this, "Found " + fieldJsons.size() + " field objects to parse");

            for (String fieldJson : fieldJsons) {
                FieldDefinition field = parseFieldJsonObject(fieldJson);
                if (field != null && field.name != null && field.type != null) {
                    fields.add(field);
                    Msg.info(this, "  Parsed field: " + field.name + " (" + field.type + ")");
                } else {
                    Msg.warn(this, "  Field missing required fields (name/type): " + fieldJson.substring(0, Math.min(50, fieldJson.length())));
                }
            }

            if (fields.isEmpty()) {
                Msg.error(this, "No valid fields parsed from JSON");
            } else {
                Msg.info(this, "Successfully parsed " + fields.size() + " field(s)");
            }

        } catch (Exception e) {
            Msg.error(this, "Exception parsing fields JSON: " + e.getMessage());
            e.printStackTrace();
        }

        return fields;
    }

    /**
     * Parse a JSON array string by properly matching braces
     * Returns list of individual JSON object content strings (without outer braces)
     */
    private List<String> parseFieldJsonArray(String json) {
        List<String> items = new ArrayList<>();

        int braceDepth = 0;
        int start = -1;
        boolean inString = false;
        boolean escapeNext = false;

        for (int i = 0; i < json.length(); i++) {
            char c = json.charAt(i);

            // Handle escape sequences
            if (escapeNext) {
                escapeNext = false;
                continue;
            }

            if (c == '\\') {
                escapeNext = true;
                continue;
            }

            // Track if we're inside a string
            if (c == '"' && !escapeNext) {
                inString = !inString;
                continue;
            }

            // Only count braces outside of strings
            if (!inString) {
                if (c == '{') {
                    if (braceDepth == 0) {
                        start = i + 1; // Start after the opening brace
                    }
                    braceDepth++;
                } else if (c == '}') {
                    braceDepth--;
                    if (braceDepth == 0 && start >= 0) {
                        // Extract object content (between braces)
                        String item = json.substring(start, i).trim();
                        if (!item.isEmpty()) {
                            items.add(item);
                        }
                        start = -1;
                    }
                }
            }
        }

        return items;
    }

    /**
     * Parse a single JSON object string (content between braces) into a FieldDefinition
     * Format: "name":"fieldname","type":"typename","offset":0
     */
    private FieldDefinition parseFieldJsonObject(String objectJson) {
        if (objectJson == null || objectJson.isEmpty()) {
            return null;
        }

        String name = null;
        String type = null;
        int offset = -1;

        try {
            // Parse key-value pairs while respecting quotes and escapes
            Map<String, String> keyValues = parseJsonKeyValues(objectJson);

            if (keyValues.containsKey("name")) {
                name = keyValues.get("name");
            }
            if (keyValues.containsKey("type")) {
                type = keyValues.get("type");
            }
            if (keyValues.containsKey("offset")) {
                try {
                    offset = Integer.parseInt(keyValues.get("offset"));
                } catch (NumberFormatException e) {
                    // Keep offset as -1
                }
            }

        } catch (Exception e) {
            Msg.error(this, "Error parsing JSON object: " + e.getMessage());
        }

        return new FieldDefinition(name, type, offset);
    }

    /**
     * Parse JSON key-value pairs from a string like: "name":"value","type":"typename"
     * Properly handles quoted strings and escapes
     */
    private Map<String, String> parseJsonKeyValues(String json) {
        Map<String, String> pairs = new LinkedHashMap<>();

        // Find all "key":"value" or "key":value patterns
        int i = 0;
        while (i < json.length()) {
            // Skip whitespace and commas
            while (i < json.length() && (Character.isWhitespace(json.charAt(i)) || json.charAt(i) == ',')) {
                i++;
            }

            if (i >= json.length()) break;

            // Expect opening quote for key
            if (json.charAt(i) != '"') {
                i++;
                continue;
            }

            // Parse key (quoted string)
            i++; // Skip opening quote
            int keyStart = i;
            boolean escapeNext = false;
            while (i < json.length()) {
                char c = json.charAt(i);
                if (escapeNext) {
                    escapeNext = false;
                } else if (c == '\\') {
                    escapeNext = true;
                } else if (c == '"') {
                    break;
                }
                i++;
            }
            String key = json.substring(keyStart, i).replace("\\\"", "\"");
            i++; // Skip closing quote

            // Skip whitespace and colon
            while (i < json.length() && (Character.isWhitespace(json.charAt(i)) || json.charAt(i) == ':')) {
                i++;
            }

            if (i >= json.length()) break;

            // Parse value (can be quoted string or number)
            String value;
            if (json.charAt(i) == '"') {
                // Quoted string value
                i++; // Skip opening quote
                int valueStart = i;
                escapeNext = false;
                while (i < json.length()) {
                    char c = json.charAt(i);
                    if (escapeNext) {
                        escapeNext = false;
                    } else if (c == '\\') {
                        escapeNext = true;
                    } else if (c == '"') {
                        break;
                    }
                    i++;
                }
                value = json.substring(valueStart, i).replace("\\\"", "\"");
                i++; // Skip closing quote
            } else {
                // Unquoted value (number, boolean, etc)
                int valueStart = i;
                while (i < json.length() && json.charAt(i) != ',' && json.charAt(i) != '}') {
                    i++;
                }
                value = json.substring(valueStart, i).trim();
            }

            pairs.put(key, value);
        }

        return pairs;
    }

    /**
     * Parse values JSON into name-value pairs (for enum creation)
     */
    private Map<String, Long> parseValuesJson(String valuesJson) {
        Map<String, Long> values = new LinkedHashMap<>();

        try {
            // Remove outer braces and whitespace
            String content = valuesJson.trim();
            if (content.startsWith("{")) {
                content = content.substring(1);
            }
            if (content.endsWith("}")) {
                content = content.substring(0, content.length() - 1);
            }

            // Split by commas (simple parsing)
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

    // -----------------------------------------------------------------------
    // String Utility Helpers
    // -----------------------------------------------------------------------

    /**
     * Helper to capitalize first letter
     */
    private String capitalizeFirst(String str) {
        if (str == null || str.isEmpty()) return str;
        return Character.toUpperCase(str.charAt(0)) + str.substring(1);
    }
}
