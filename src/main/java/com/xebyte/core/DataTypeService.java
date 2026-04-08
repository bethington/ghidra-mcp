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
@McpToolGroup(value = "datatype", description = "Struct/enum/union CRUD, apply data types, type conflicts, validation")
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
    }

    // -----------------------------------------------------------------------
    // Data Type Listing and Query Methods
    // -----------------------------------------------------------------------

    /**
     * List all data types available in the program with optional category filtering
     */
    @McpTool(path = "/list_data_types", description = "List all data types with optional category filter", category = "datatype")
    public Response listDataTypes(
            @Param(value = "category", description = "Category filter") String category,
            @Param(value = "offset", defaultValue = "0") int offset,
            @Param(value = "limit", defaultValue = "100") int limit,
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

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
    @McpTool(path = "/search_data_types", description = "Search data types by pattern", category = "datatype")
    public Response searchDataTypes(
            @Param(value = "pattern", description = "Search pattern") String pattern,
            @Param(value = "offset", defaultValue = "0") int offset,
            @Param(value = "limit", defaultValue = "100") int limit,
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();
        if (pattern == null || pattern.isEmpty()) return Response.text("Search pattern is required");

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

    // Backward compatibility overload
    public Response searchDataTypes(String pattern, int offset, int limit) {
        return searchDataTypes(pattern, offset, limit, null);
    }

    /**
     * Get the size of a data type
     */
    @McpTool(path = "/get_type_size", description = "Get data type size and info", category = "datatype")
    public Response getTypeSize(
            @Param(value = "type_name", description = "Data type name") String typeName,
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();
        if (typeName == null || typeName.isEmpty()) return Response.text("Type name is required");

        DataTypeManager dtm = program.getDataTypeManager();
        DataType dataType = ServiceUtils.findDataTypeByNameInAllCategories(dtm, typeName);

        if (dataType == null) {
            return Response.text("Data type not found: " + typeName);
        }

        int size = dataType.getLength();
        return Response.text(String.format("Type: %s\nSize: %d bytes\nAlignment: %d\nPath: %s",
                            dataType.getName(),
                            size,
                            dataType.getAlignment(),
                            dataType.getPathName()));
    }

    // Backward compatibility overload
    public Response getTypeSize(String typeName) {
        return getTypeSize(typeName, null);
    }

    /**
     * Get the layout of a structure
     */
    @McpTool(path = "/get_struct_layout", description = "Get structure field layout", category = "datatype")
    public Response getStructLayout(
            @Param(value = "struct_name", description = "Structure name") String structName,
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();
        if (structName == null || structName.isEmpty()) return Response.text("Struct name is required");

        DataTypeManager dtm = program.getDataTypeManager();
        DataType dataType = ServiceUtils.findDataTypeByNameInAllCategories(dtm, structName);

        if (dataType == null) {
            return Response.text("Structure not found: " + structName);
        }

        if (!(dataType instanceof Structure)) {
            return Response.text("Data type is not a structure: " + structName);
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

    // Backward compatibility overload
    public Response getStructLayout(String structName) {
        return getStructLayout(structName, null);
    }

    /**
     * Get all values in an enumeration
     */
    @McpTool(path = "/get_enum_values", description = "Get enum member values", category = "datatype")
    public Response getEnumValues(
            @Param(value = "enum_name", description = "Enum name") String enumName,
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();
        if (enumName == null || enumName.isEmpty()) return Response.text("Enum name is required");

        DataTypeManager dtm = program.getDataTypeManager();
        DataType dataType = ServiceUtils.findDataTypeByNameInAllCategories(dtm, enumName);

        if (dataType == null) {
            return Response.text("Enumeration not found: " + enumName);
        }

        if (!(dataType instanceof ghidra.program.model.data.Enum)) {
            return Response.text("Data type is not an enumeration: " + enumName);
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

    // Backward compatibility overload
    public Response getEnumValues(String enumName) {
        return getEnumValues(enumName, null);
    }

    /**
     * v1.5.0: Get valid Ghidra data type strings
     */
    @McpTool(path = "/get_valid_data_types", description = "List valid Ghidra data type strings", category = "datatype")
    public Response getValidDataTypes(
            @Param(value = "category", description = "Category filter") String category,
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        final AtomicReference<Response> responseRef = new AtomicReference<>(null);

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

                    responseRef.set(Response.ok(JsonHelper.mapOf(
                        "builtin_types", builtinTypes,
                        "windows_types", windowsTypes
                    )));
                } catch (Exception e) {
                    responseRef.set(Response.err(e.getMessage()));
                }
            });

            if (responseRef.get() != null) {
                return responseRef.get();
            }
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }

        return Response.err("Unknown failure");
    }

    // Backward compatibility overload
    public Response getValidDataTypes(String category) {
        return getValidDataTypes(category, null);
    }

    /**
     * NEW v1.6.0: Check if data type exists in type manager
     */
    @McpTool(path = "/validate_data_type_exists", description = "Check if a data type exists", category = "datatype")
    public Response validateDataTypeExists(
            @Param(value = "type_name", description = "Data type name") String typeName,
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        final AtomicReference<Response> responseRef = new AtomicReference<>(null);

        try {
            SwingUtilities.invokeAndWait(() -> {
                try {
                    DataTypeManager dtm = program.getDataTypeManager();
                    DataType dt = dtm.getDataType(typeName);

                    if (dt != null) {
                        responseRef.set(Response.ok(JsonHelper.mapOf(
                            "exists", true,
                            "category", dt.getCategoryPath().getPath(),
                            "size", dt.getLength()
                        )));
                    } else {
                        responseRef.set(Response.ok(JsonHelper.mapOf(
                            "exists", false
                        )));
                    }
                } catch (Exception e) {
                    responseRef.set(Response.err(e.getMessage()));
                }
            });

            if (responseRef.get() != null) {
                return responseRef.get();
            }
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }

        return Response.err("Unknown failure");
    }

    // Backward compatibility overload
    public Response validateDataTypeExists(String typeName) {
        return validateDataTypeExists(typeName, null);
    }

    // -----------------------------------------------------------------------
    // Data Type Creation Methods
    // -----------------------------------------------------------------------

    /**
     * Create a new structure data type with specified fields
     */
    @McpTool(path = "/create_struct", method = "POST", description = "Create a structure data type", category = "datatype")
    public Response createStruct(
            @Param(value = "name", source = ParamSource.BODY) String name,
            @Param(value = "fields", source = ParamSource.BODY, fieldsJson = true) String fieldsJson,
            @Param(value = "program", description = "Target program name", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        if (name == null || name.isEmpty()) {
            return Response.text("Structure name is required");
        }

        if (fieldsJson == null || fieldsJson.isEmpty()) {
            return Response.text("Fields JSON is required");
        }

        final StringBuilder resultMsg = new StringBuilder();
        final AtomicBoolean successFlag = new AtomicBoolean(false);

        try {
            // Parse the fields JSON (simplified parsing for basic structure)
            // Expected format: [{"name":"field1","type":"int"},{"name":"field2","type":"char"}]
            List<FieldDefinition> fields = parseFieldsJson(fieldsJson);

            if (fields.isEmpty()) {
                return Response.text("No valid fields provided");
            }

            DataTypeManager dtm = program.getDataTypeManager();

            // Check if struct already exists
            DataType existingType = dtm.getDataType("/" + name);
            if (existingType != null) {
                return Response.text("Structure with name '" + name + "' already exists");
            }

            // Pre-resolve all field types before entering the transaction
            Map<FieldDefinition, DataType> resolvedTypes = new java.util.LinkedHashMap<>();
            for (FieldDefinition field : fields) {
                DataType fieldType = ServiceUtils.resolveDataType(dtm, field.type);
                if (fieldType == null) {
                    return Response.text("Unknown field type: " + field.type);
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

        return resultMsg.length() > 0 ? Response.text(resultMsg.toString()) : Response.err("Unknown failure");
    }

    // Backward compatibility overload
    public Response createStruct(String name, String fieldsJson) {
        return createStruct(name, fieldsJson, null);
    }

    /**
     * Create a new enumeration data type with name-value pairs
     */
    @McpTool(path = "/create_enum", method = "POST", description = "Create an enum data type", category = "datatype")
    public Response createEnum(
            @Param(value = "name", source = ParamSource.BODY) String name,
            @Param(value = "values", source = ParamSource.BODY, fieldsJson = true) String valuesJson,
            @Param(value = "size", source = ParamSource.BODY, defaultValue = "4") int size,
            @Param(value = "program", description = "Target program name", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        if (name == null || name.isEmpty()) {
            return Response.text("Enumeration name is required");
        }

        if (valuesJson == null || valuesJson.isEmpty()) {
            return Response.text("Values JSON is required. " +
                "Expected format: {\"NAME\": 0, \"NAME2\": 1} or {\"NAME\": \"0\", \"NAME2\": \"1\"}");
        }

        if (size != 1 && size != 2 && size != 4 && size != 8) {
            return Response.text("Invalid size. Must be 1, 2, 4, or 8 bytes");
        }

        try {
            // Parse the values JSON (supports int, string, and hex formats)
            Map<String, Long> values = parseValuesJson(valuesJson);

            if (values.isEmpty()) {
                return Response.text("No valid enum values could be parsed from: " + valuesJson +
                    ". Expected format: {\"NAME\": 0, \"NAME2\": 1} or {\"NAME\": \"0\", \"NAME2\": \"1\"} " +
                    "or {\"NAME\": \"0xFF\"}. Values must be integers (not floats or arbitrary strings).");
            }

            DataTypeManager dtm = program.getDataTypeManager();

            // Check if enum already exists
            DataType existingType = dtm.getDataType("/" + name);
            if (existingType != null) {
                return Response.text("Enumeration with name '" + name + "' already exists");
            }

            // Create the enumeration
            int txId = program.startTransaction("Create Enumeration: " + name);
            boolean txSuccess = false;
            try {
                ghidra.program.model.data.EnumDataType enumDt =
                    new ghidra.program.model.data.EnumDataType(name, size);

                for (Map.Entry<String, Long> entry : values.entrySet()) {
                    enumDt.add(entry.getKey(), entry.getValue());
                }

                // Add the enumeration to the data type manager
                dtm.addDataType(enumDt, null);

                txSuccess = true;

                // Validate enum member naming (UPPERCASE_SNAKE_CASE)
                List<String> enumWarnings = new ArrayList<>();
                for (String memberName : values.keySet()) {
                    enumWarnings.addAll(NamingConventions.validateEnumMemberName(memberName));
                }

                Map<String, Object> resultMap = new LinkedHashMap<>();
                resultMap.put("status", "success");
                resultMap.put("message", "Successfully created enumeration '" + name + "' with " + values.size() +
                               " values, size: " + size + " bytes");
                if (!enumWarnings.isEmpty()) {
                    resultMap.put("warnings", enumWarnings);
                }
                return Response.ok(resultMap);

            } catch (Exception e) {
                return Response.err("Error creating enumeration: " + e.getMessage());
            } finally {
                program.endTransaction(txId, txSuccess);
            }

        } catch (Exception e) {
            return Response.err("Error parsing values JSON: " + e.getMessage());
        }
    }

    // Backward compatibility overload
    public Response createEnum(String name, String valuesJson, int size) {
        return createEnum(name, valuesJson, size, null);
    }

    /**
     * Create a union data type with simplified approach for testing
     */
    public Response createUnionSimple(String name, Object fieldsObj) {
        // Even simpler test - don't access any Ghidra APIs
        if (name == null || name.isEmpty()) return Response.text("Union name is required");
        if (fieldsObj == null) return Response.text("Fields are required");

        return Response.text("Union endpoint test successful - name: " + name);
    }

    /**
     * Create a union data type directly from fields object
     */
    @SuppressWarnings("unchecked")
    public Response createUnionDirect(String name, Object fieldsObj, String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();
        if (name == null || name.isEmpty()) return Response.text("Union name is required");
        if (fieldsObj == null) return Response.text("Fields are required");

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

        return Response.text(result.toString());
    }

    // Backward compatibility overload
    public Response createUnionDirect(String name, Object fieldsObj) {
        return createUnionDirect(name, fieldsObj, null);
    }

    /**
     * Create a union data type (legacy method)
     */
    @McpTool(path = "/create_union", method = "POST", description = "Create a union data type", category = "datatype")
    public Response createUnion(
            @Param(value = "name", source = ParamSource.BODY) String name,
            @Param(value = "fields", source = ParamSource.BODY, fieldsJson = true) String fieldsJson,
            @Param(value = "program", description = "Target program name", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();
        if (name == null || name.isEmpty()) return Response.text("Union name is required");
        if (fieldsJson == null || fieldsJson.isEmpty()) return Response.text("Fields JSON is required");

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

        return Response.text(result.toString());
    }

    // Backward compatibility overload
    public Response createUnion(String name, String fieldsJson) {
        return createUnion(name, fieldsJson, null);
    }

    /**
     * Create a typedef (type alias)
     */
    @McpTool(path = "/create_typedef", method = "POST", description = "Create a typedef alias", category = "datatype")
    public Response createTypedef(
            @Param(value = "name", source = ParamSource.BODY) String name,
            @Param(value = "base_type", source = ParamSource.BODY) String baseType,
            @Param(value = "program", description = "Target program name", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();
        if (name == null || name.isEmpty()) return Response.text("Typedef name is required");
        if (baseType == null || baseType.isEmpty()) return Response.text("Base type is required");

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

        return Response.text(result.toString());
    }

    // Backward compatibility overload
    public Response createTypedef(String name, String baseType) {
        return createTypedef(name, baseType, null);
    }

    /**
     * Clone/copy a data type with a new name
     */
    @McpTool(path = "/clone_data_type", method = "POST", description = "Clone a data type with new name", category = "datatype")
    public Response cloneDataType(
            @Param(value = "source_type", source = ParamSource.BODY) String sourceType,
            @Param(value = "new_name", source = ParamSource.BODY) String newName,
            @Param(value = "program", description = "Target program name", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();
        if (sourceType == null || sourceType.isEmpty()) return Response.text("Source type is required");
        if (newName == null || newName.isEmpty()) return Response.text("New name is required");

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

        return Response.text(result.toString());
    }

    // Backward compatibility overload
    public Response cloneDataType(String sourceType, String newName) {
        return cloneDataType(sourceType, newName, null);
    }

    /**
     * Create an array data type
     */
    @McpTool(path = "/create_array_type", method = "POST", description = "Create an array data type", category = "datatype")
    public Response createArrayType(
            @Param(value = "base_type", source = ParamSource.BODY) String baseType,
            @Param(value = "length", source = ParamSource.BODY, defaultValue = "1") int length,
            @Param(value = "name", source = ParamSource.BODY, defaultValue = "") String name,
            @Param(value = "program", description = "Target program name", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();
        if (baseType == null || baseType.isEmpty()) return Response.text("Base type is required");
        if (length <= 0) return Response.text("Array length must be positive");

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

        return Response.text(result.toString());
    }

    // Backward compatibility overload
    public Response createArrayType(String baseType, int length, String name) {
        return createArrayType(baseType, length, name, null);
    }

    /**
     * Create a pointer data type
     */
    @McpTool(path = "/create_pointer_type", method = "POST", description = "Create a pointer data type", category = "datatype")
    public Response createPointerType(
            @Param(value = "base_type", source = ParamSource.BODY) String baseType,
            @Param(value = "name", source = ParamSource.BODY, defaultValue = "") String name,
            @Param(value = "program", description = "Target program name", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();
        if (baseType == null || baseType.isEmpty()) return Response.text("Base type is required");

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

        return Response.text(result.toString());
    }

    // Backward compatibility overload
    public Response createPointerType(String baseType, String name) {
        return createPointerType(baseType, name, null);
    }

    /**
     * Create a function signature data type
     */
    @McpTool(path = "/create_function_signature", method = "POST", description = "Create a function signature data type", category = "datatype")
    public Response createFunctionSignature(
            @Param(value = "name", source = ParamSource.BODY) String name,
            @Param(value = "return_type", source = ParamSource.BODY) String returnType,
            @Param(value = "parameters", source = ParamSource.BODY) String parametersJson,
            @Param(value = "program", description = "Target program name", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();
        if (name == null || name.isEmpty()) return Response.text("Function name is required");
        if (returnType == null || returnType.isEmpty()) return Response.text("Return type is required");

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

        return Response.text(result.toString());
    }

    // Backward compatibility overload
    public Response createFunctionSignature(String name, String returnType, String parametersJson) {
        return createFunctionSignature(name, returnType, parametersJson, null);
    }

    // -----------------------------------------------------------------------
    // Data Type Modification Methods
    // -----------------------------------------------------------------------

    /**
     * Apply a specific data type at the given memory address
     */
    @McpTool(path = "/apply_data_type", method = "POST", description = "Apply data type at address. On programs with multiple address spaces (e.g., embedded targets), prefix addresses with the space name (mem:1000) to avoid ambiguous resolution.", category = "datatype")
    public Response applyDataType(
            @Param(value = "address", paramType = "address", source = ParamSource.BODY,
                   description = "Address in the program. Accepts 0x<hex> (default space) or <space>:<hex> "
                               + "(e.g., mem:1000, code:ff00). Note: some programs — particularly "
                               + "embedded/microcontroller targets — are not address-space-agnostic; "
                               + "use get_address_spaces to discover spaces before assuming a plain hex "
                               + "address is unambiguous.") String addressStr,
            @Param(value = "type_name", source = ParamSource.BODY) String typeName,
            @Param(value = "clear_existing", source = ParamSource.BODY, defaultValue = "true") boolean clearExisting,
            @Param(value = "program", description = "Target program name", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        if (addressStr == null || addressStr.isEmpty()) {
            return Response.text("Address is required");
        }

        if (typeName == null || typeName.isEmpty()) {
            return Response.text("Data type name is required");
        }

        try {
            Address address = ServiceUtils.parseAddress(program, addressStr);
            if (address == null) {
                return Response.text(ServiceUtils.getLastParseError());
            }

            DataTypeManager dtm = program.getDataTypeManager();
            DataType dataType = ServiceUtils.resolveDataType(dtm, typeName);

            if (dataType == null) {
                return Response.text("ERROR: Unknown data type: " + typeName + ". " +
                       "For arrays, use syntax 'basetype[count]' (e.g., 'dword[10]'). " +
                       "Or create the type first using create_struct, create_enum, or mcp_ghidra_create_array_type.");
            }

            Listing listing = program.getListing();

            // Check if address is in a valid memory block
            if (!program.getMemory().contains(address)) {
                return Response.text("Address is not in program memory: " + addressStr);
            }

            int txId = program.startTransaction("Apply Data Type: " + typeName);
            boolean txSuccess = false;
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

                txSuccess = true;

                // Validate size matches expectation
                int expectedSize = dataType.getLength();
                int actualSize = (data != null) ? data.getLength() : 0;

                if (actualSize != expectedSize) {
                    Msg.warn(this, String.format("Size mismatch: expected %d bytes but applied %d bytes at %s",
                                                 expectedSize, actualSize, addressStr));
                }

                String resultText = "Successfully applied data type '" + typeName + "' at " +
                               addressStr + " (size: " + actualSize + " bytes)";

                // Add value information if available
                if (data != null && data.getValue() != null) {
                    resultText += "\nValue: " + data.getValue().toString();
                }

                return Response.text(resultText);

            } catch (Exception e) {
                return Response.err("Error applying data type: " + e.getMessage());
            } finally {
                program.endTransaction(txId, txSuccess);
            }

        } catch (Exception e) {
            return Response.err("Error processing request: " + e.getMessage());
        }
    }

    // Backward compatibility overload
    public Response applyDataType(String addressStr, String typeName, boolean clearExisting) {
        return applyDataType(addressStr, typeName, clearExisting, null);
    }

    /**
     * Delete a data type from the program
     */
    @McpTool(path = "/delete_data_type", method = "POST", description = "Delete a data type", category = "datatype")
    public Response deleteDataType(
            @Param(value = "type_name", source = ParamSource.BODY) String typeName,
            @Param(value = "program", description = "Target program name", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();
        if (typeName == null || typeName.isEmpty()) return Response.text("Type name is required");

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

        return Response.text(result.toString());
    }

    // Backward compatibility overload
    public Response deleteDataType(String typeName) {
        return deleteDataType(typeName, null);
    }

    /**
     * Modify a field in an existing structure
     */
    @McpTool(path = "/modify_struct_field", method = "POST", description = "Modify a field in a structure. Fields can be identified by name or by offset (for unnamed fields).", category = "datatype")
    public Response modifyStructField(
            @Param(value = "struct_name", source = ParamSource.BODY) String structName,
            @Param(value = "field_name", source = ParamSource.BODY, defaultValue = "",
                   description = "Field name to modify. For unnamed fields, use 'offset:N' (e.g., 'offset:16') to identify by byte offset.") String fieldName,
            @Param(value = "new_type", source = ParamSource.BODY, defaultValue = "") String newType,
            @Param(value = "new_name", source = ParamSource.BODY, defaultValue = "") String newName,
            @Param(value = "program", description = "Target program name", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();
        if (structName == null || structName.isEmpty()) return Response.text("Structure name is required");
        if ((fieldName == null || fieldName.isEmpty()) && (newName == null || newName.isEmpty())) {
            return Response.text("Field name or offset is required");
        }

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
                    DataTypeComponent targetComponent = null;

                    // Support offset-based lookup: "offset:16" or "offset:0x10"
                    if (fieldName != null && fieldName.startsWith("offset:")) {
                        try {
                            String offsetStr = fieldName.substring(7).trim();
                            int targetOffset = offsetStr.startsWith("0x") || offsetStr.startsWith("0X")
                                    ? Integer.parseInt(offsetStr.substring(2), 16)
                                    : Integer.parseInt(offsetStr);
                            targetComponent = struct.getComponentAt(targetOffset);
                            if (targetComponent == null) {
                                result.append("No field at offset ").append(targetOffset).append(" in structure '").append(structName).append("'");
                                return;
                            }
                        } catch (NumberFormatException e) {
                            result.append("Invalid offset format: ").append(fieldName).append(". Use 'offset:16' or 'offset:0x10'");
                            return;
                        }
                    } else {
                        // Find by field name
                        DataTypeComponent[] components = struct.getDefinedComponents();
                        for (DataTypeComponent component : components) {
                            if (fieldName != null && fieldName.equals(component.getFieldName())) {
                                targetComponent = component;
                                break;
                            }
                        }
                    }

                    if (targetComponent == null) {
                        result.append("Field '").append(fieldName).append("' not found in structure '").append(structName)
                                .append("'. For unnamed fields, use 'offset:N' (e.g., 'offset:16' or 'offset:0x10')");
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

                    // If new name is specified, auto-fix Hungarian prefix and change the field name
                    if (newName != null && !newName.isEmpty()) {
                        targetComponent = struct.getComponent(targetComponent.getOrdinal()); // Refresh component
                        String fieldTypeName = targetComponent.getDataType().getName();
                        String fixedName = NamingConventions.autoFixFieldPrefix(newName, fieldTypeName);
                        targetComponent.setFieldName(fixedName);
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

        return Response.text(result.toString());
    }

    // Backward compatibility overload
    public Response modifyStructField(String structName, String fieldName, String newType, String newName) {
        return modifyStructField(structName, fieldName, newType, newName, null);
    }

    /**
     * Add a new field to an existing structure
     */
    @McpTool(path = "/add_struct_field", method = "POST", description = "Add a field to a structure", category = "datatype")
    public Response addStructField(
            @Param(value = "struct_name", source = ParamSource.BODY) String structName,
            @Param(value = "field_name", source = ParamSource.BODY) String fieldName,
            @Param(value = "field_type", source = ParamSource.BODY) String fieldType,
            @Param(value = "offset", source = ParamSource.BODY, defaultValue = "-1") int offset,
            @Param(value = "program", description = "Target program name", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();
        if (structName == null || structName.isEmpty()) return Response.text("Structure name is required");
        if (fieldName == null || fieldName.isEmpty()) return Response.text("Field name is required");
        if (fieldType == null || fieldType.isEmpty()) return Response.text("Field type is required");

        // Auto-fix Hungarian prefix
        fieldName = NamingConventions.autoFixFieldPrefix(fieldName, fieldType);

        AtomicBoolean success = new AtomicBoolean(false);
        StringBuilder result = new StringBuilder();
        final String finalFieldName = fieldName;

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
                        // Overlay at specific offset (replace undefined padding, do NOT shift fields)
                        if (offset < struct.getLength()) {
                            struct.replaceAtOffset(offset, newFieldType, newFieldType.getLength(), finalFieldName, null);
                        } else {
                            // At or beyond current struct size — grow to fit, then place
                            int needed = offset + newFieldType.getLength() - struct.getLength();
                            if (needed > 0) {
                                struct.growStructure(needed);
                            }
                            struct.replaceAtOffset(offset, newFieldType, newFieldType.getLength(), finalFieldName, null);
                        }
                    } else {
                        // Add at end
                        struct.add(newFieldType, finalFieldName, null);
                    }

                    result.append("Successfully added field '").append(finalFieldName).append("' to structure '").append(structName).append("'");
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

        return Response.text(result.toString());
    }

    // Backward compatibility overload
    public Response addStructField(String structName, String fieldName, String fieldType, int offset) {
        return addStructField(structName, fieldName, fieldType, offset, null);
    }

    /**
     * Remove a field from an existing structure
     */
    @McpTool(path = "/remove_struct_field", method = "POST", description = "Remove a field from a structure", category = "datatype")
    public Response removeStructField(
            @Param(value = "struct_name", source = ParamSource.BODY) String structName,
            @Param(value = "field_name", source = ParamSource.BODY) String fieldName,
            @Param(value = "program", description = "Target program name", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();
        if (structName == null || structName.isEmpty()) return Response.text("Structure name is required");
        if (fieldName == null || fieldName.isEmpty()) return Response.text("Field name is required");

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

        return Response.text(result.toString());
    }

    // Backward compatibility overload
    public Response removeStructField(String structName, String fieldName) {
        return removeStructField(structName, fieldName, null);
    }

    /**
     * Move a data type to a different category
     */
    @McpTool(path = "/move_data_type_to_category", method = "POST", description = "Move data type to category", category = "datatype")
    public Response moveDataTypeToCategory(
            @Param(value = "type_name", source = ParamSource.BODY) String typeName,
            @Param(value = "category_path", source = ParamSource.BODY) String categoryPath,
            @Param(value = "program", description = "Target program name", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();
        if (typeName == null || typeName.isEmpty()) return Response.text("Type name is required");
        if (categoryPath == null || categoryPath.isEmpty()) return Response.text("Category path is required");

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

        return Response.text(result.toString());
    }

    // Backward compatibility overload
    public Response moveDataTypeToCategory(String typeName, String categoryPath) {
        return moveDataTypeToCategory(typeName, categoryPath, null);
    }

    // -----------------------------------------------------------------------
    // Data Type Validation Methods
    // -----------------------------------------------------------------------

    /**
     * Validate if a data type fits at a given address
     */
    @McpTool(path = "/validate_data_type", description = "Validate data type applicability at address. On programs with multiple address spaces (e.g., embedded targets), prefix addresses with the space name (mem:1000) to avoid ambiguous resolution.", category = "datatype")
    public Response validateDataType(
            @Param(value = "address", paramType = "address",
                   description = "Address in the program. Accepts 0x<hex> (default space) or <space>:<hex> "
                               + "(e.g., mem:1000, code:ff00). Note: some programs — particularly "
                               + "embedded/microcontroller targets — are not address-space-agnostic; "
                               + "use get_address_spaces to discover spaces before assuming a plain hex "
                               + "address is unambiguous.") String addressStr,
            @Param(value = "type_name", description = "Data type name") String typeName,
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();
        if (addressStr == null || addressStr.isEmpty()) return Response.text("Address is required");
        if (typeName == null || typeName.isEmpty()) return Response.text("Type name is required");

        try {
            Address addr = ServiceUtils.parseAddress(program, addressStr);
            if (addr == null) return Response.text(ServiceUtils.getLastParseError());
            DataTypeManager dtm = program.getDataTypeManager();
            DataType dataType = ServiceUtils.findDataTypeByNameInAllCategories(dtm, typeName);

            if (dataType == null) {
                return Response.text("Data type not found: " + typeName);
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

    // Backward compatibility overload
    public Response validateDataType(String addressStr, String typeName) {
        return validateDataType(addressStr, typeName, null);
    }

    /**
     * NEW v1.6.0: Validate function prototype before applying
     */
    @McpTool(path = "/validate_function_prototype", description = "Validate prototype before applying. On programs with multiple address spaces (e.g., embedded targets), prefix addresses with the space name (mem:1000) to avoid ambiguous resolution.", category = "datatype")
    public Response validateFunctionPrototype(
            @Param(value = "function_address", paramType = "address",
                   description = "Address in the program. Accepts 0x<hex> (default space) or <space>:<hex> "
                               + "(e.g., mem:1000, code:ff00). Note: some programs — particularly "
                               + "embedded/microcontroller targets — are not address-space-agnostic; "
                               + "use get_address_spaces to discover spaces before assuming a plain hex "
                               + "address is unambiguous.") String functionAddress,
            @Param(value = "prototype", description = "Function prototype") String prototype,
            @Param(value = "calling_convention", description = "Calling convention") String callingConvention,
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        // Resolve address before entering SwingUtilities lambda
        Address addr = ServiceUtils.parseAddress(program, functionAddress);
        if (addr == null) return Response.err(ServiceUtils.getLastParseError());

        final AtomicReference<Response> responseRef = new AtomicReference<>(null);

        try {
            SwingUtilities.invokeAndWait(() -> {
                try {
                    Function func = program.getFunctionManager().getFunctionAt(addr);
                    if (func == null) {
                        responseRef.set(Response.ok(JsonHelper.mapOf(
                            "valid", false,
                            "error", "No function at address: " + functionAddress
                        )));
                        return;
                    }

                    // Basic validation - check if prototype string is parseable
                    if (prototype == null || prototype.trim().isEmpty()) {
                        responseRef.set(Response.ok(JsonHelper.mapOf(
                            "valid", false,
                            "error", "Empty prototype"
                        )));
                        return;
                    }

                    // Check for common issues
                    List<String> warnings = new ArrayList<>();

                    // Check for return type
                    if (!prototype.contains("(")) {
                        responseRef.set(Response.ok(JsonHelper.mapOf(
                            "valid", false,
                            "error", "Invalid prototype format - missing parentheses"
                        )));
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

                    if (!warnings.isEmpty()) {
                        responseRef.set(Response.ok(JsonHelper.mapOf(
                            "valid", true,
                            "warnings", warnings
                        )));
                    } else {
                        responseRef.set(Response.ok(JsonHelper.mapOf(
                            "valid", true
                        )));
                    }
                } catch (Exception e) {
                    responseRef.set(Response.ok(JsonHelper.mapOf(
                        "valid", false,
                        "error", e.getMessage()
                    )));
                }
            });

            if (responseRef.get() != null) {
                return responseRef.get();
            }
        } catch (Exception e) {
            return Response.ok(JsonHelper.mapOf(
                "valid", false,
                "error", e.getMessage()
            ));
        }

        return Response.ok(JsonHelper.mapOf("valid", false, "error", "Unknown failure"));
    }

    // Backward compatibility overload
    public Response validateFunctionPrototype(String functionAddress, String prototype, String callingConvention) {
        return validateFunctionPrototype(functionAddress, prototype, callingConvention, null);
    }

    /**
     * Import data types (placeholder)
     */
    @McpTool(path = "/import_data_types", method = "POST", description = "Import data types from C source", category = "datatype")
    public Response importDataTypes(
            @Param(value = "source", source = ParamSource.BODY) String source,
            @Param(value = "format", source = ParamSource.BODY, defaultValue = "c") String format) {
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
    @McpTool(path = "/create_data_type_category", method = "POST", description = "Create a new data type category", category = "datatype")
    public Response createDataTypeCategory(
            @Param(value = "category_path", source = ParamSource.BODY) String categoryPath,
            @Param(value = "program", description = "Target program name", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();
        if (categoryPath == null || categoryPath.isEmpty()) return Response.text("Category path is required");

        try {
            DataTypeManager dtm = program.getDataTypeManager();
            CategoryPath catPath = new CategoryPath(categoryPath);
            Category category = dtm.createCategory(catPath);

            return Response.ok(JsonHelper.mapOf(
                "status", "success",
                "message", "Successfully created category: " + category.getCategoryPathName()
            ));
        } catch (Exception e) {
            return Response.err("Error creating category: " + e.getMessage());
        }
    }

    // Backward compatibility overload
    public Response createDataTypeCategory(String categoryPath) {
        return createDataTypeCategory(categoryPath, null);
    }

    /**
     * List all data type categories
     */
    @McpTool(path = "/list_data_type_categories", description = "List all data type categories", category = "datatype")
    public Response listDataTypeCategories(
            @Param(value = "offset", defaultValue = "0") int offset,
            @Param(value = "limit", defaultValue = "100") int limit,
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

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

    // Backward compatibility overload
    public Response listDataTypeCategories(int offset, int limit) {
        return listDataTypeCategories(offset, limit, null);
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
    @McpTool(path = "/analyze_struct_field_usage", method = "POST", description = "Analyze structure field access patterns. On programs with multiple address spaces (e.g., embedded targets), prefix addresses with the space name (mem:1000) to avoid ambiguous resolution.", category = "datatype")
    public Response analyzeStructFieldUsage(
            @Param(value = "address", paramType = "address", source = ParamSource.BODY,
                   description = "Address in the program. Accepts 0x<hex> (default space) or <space>:<hex> "
                               + "(e.g., mem:1000, code:ff00). Note: some programs — particularly "
                               + "embedded/microcontroller targets — are not address-space-agnostic; "
                               + "use get_address_spaces to discover spaces before assuming a plain hex "
                               + "address is unambiguous.") String addressStr,
            @Param(value = "struct_name", source = ParamSource.BODY) String structName,
            @Param(value = "max_functions", source = ParamSource.BODY, defaultValue = "10") int maxFunctionsToAnalyze,
            @Param(value = "program", description = "Target program name", defaultValue = "") String programName) {
        // CRITICAL FIX #3: Validate input parameters
        if (maxFunctionsToAnalyze < MIN_FUNCTIONS_TO_ANALYZE || maxFunctionsToAnalyze > MAX_FUNCTIONS_TO_ANALYZE) {
            return Response.err("maxFunctionsToAnalyze must be between " + MIN_FUNCTIONS_TO_ANALYZE +
                   " and " + MAX_FUNCTIONS_TO_ANALYZE);
        }

        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        // Resolve address before entering SwingUtilities lambda
        Address addr = ServiceUtils.parseAddress(program, addressStr);
        if (addr == null) return Response.err(ServiceUtils.getLastParseError());

        final AtomicReference<Response> responseRef = new AtomicReference<>();

        // CRITICAL FIX #1: Thread safety - wrap in SwingUtilities.invokeAndWait
        try {
            SwingUtilities.invokeAndWait(() -> {
                try {
                    // Get data at address to determine structure
                    Data data = program.getListing().getDataAt(addr);
                    DataType dataType = (data != null) ? data.getDataType() : null;

                    if (dataType == null || !(dataType instanceof Structure)) {
                        responseRef.set(Response.err("No structure data type found at " + addressStr));
                        return;
                    }

                    Structure struct = (Structure) dataType;

                    // MAJOR FIX #5: Validate structure size
                    DataTypeComponent[] components = struct.getComponents();
                    if (components.length > MAX_STRUCT_FIELDS) {
                        responseRef.set(Response.err("Structure too large (" + components.length +
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

                    // Build response with field analysis
                    Map<String, Object> fieldUsage = new LinkedHashMap<>();
                    for (int i = 0; i < components.length; i++) {
                        DataTypeComponent component = components[i];
                        int offset = component.getOffset();

                        Map<String, Object> fieldInfo = new LinkedHashMap<>();
                        fieldInfo.put("field_name", component.getFieldName());
                        fieldInfo.put("field_type", component.getDataType().getName());
                        fieldInfo.put("offset", offset);
                        fieldInfo.put("size", component.getLength());

                        FieldUsageInfo usageInfo = fieldUsageMap.get(offset);
                        if (usageInfo != null) {
                            fieldInfo.put("access_count", usageInfo.accessCount);
                            fieldInfo.put("suggested_names", new ArrayList<>(usageInfo.suggestedNames));
                            fieldInfo.put("usage_patterns", new ArrayList<>(usageInfo.usagePatterns));
                        } else {
                            fieldInfo.put("access_count", 0);
                            fieldInfo.put("suggested_names", new ArrayList<>());
                            fieldInfo.put("usage_patterns", new ArrayList<>());
                        }

                        fieldUsage.put(String.valueOf(offset), fieldInfo);
                    }

                    responseRef.set(Response.ok(JsonHelper.mapOf(
                        "struct_address", addressStr,
                        "struct_name", actualStructName,
                        "struct_size", struct.getLength(),
                        "functions_analyzed", functionsToAnalyze.size(),
                        "field_usage", fieldUsage
                    )));
                } catch (Exception e) {
                    responseRef.set(Response.err(e.getMessage()));
                }
            });
        } catch (InvocationTargetException | InterruptedException e) {
            Msg.error(this, "Thread synchronization error in analyzeStructFieldUsage", e);
            return Response.err("Thread synchronization error: " + e.getMessage());
        }

        return responseRef.get();
    }

    // Backward compatibility overload
    public Response analyzeStructFieldUsage(String addressStr, String structName, int maxFunctionsToAnalyze) {
        return analyzeStructFieldUsage(addressStr, structName, maxFunctionsToAnalyze, null);
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
    @McpTool(path = "/suggest_field_names", method = "POST", description = "AI-assisted field name suggestions. On programs with multiple address spaces (e.g., embedded targets), prefix addresses with the space name (mem:1000) to avoid ambiguous resolution.", category = "datatype")
    public Response suggestFieldNames(
            @Param(value = "struct_address", paramType = "address", source = ParamSource.BODY,
                   description = "Address in the program. Accepts 0x<hex> (default space) or <space>:<hex> "
                               + "(e.g., mem:1000, code:ff00). Note: some programs — particularly "
                               + "embedded/microcontroller targets — are not address-space-agnostic; "
                               + "use get_address_spaces to discover spaces before assuming a plain hex "
                               + "address is unambiguous.") String structAddressStr,
            @Param(value = "struct_size", source = ParamSource.BODY, defaultValue = "0") int structSize,
            @Param(value = "program", description = "Target program name", defaultValue = "") String programName) {
        // Validate input parameters
        if (structSize < 0 || structSize > MAX_FIELD_OFFSET) {
            return Response.err("structSize must be between 0 and " + MAX_FIELD_OFFSET);
        }

        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        // Resolve address before entering SwingUtilities lambda
        Address addr = ServiceUtils.parseAddress(program, structAddressStr);
        if (addr == null) return Response.err(ServiceUtils.getLastParseError());

        final AtomicReference<Response> responseRef = new AtomicReference<>();

        // CRITICAL FIX #1: Thread safety - wrap in SwingUtilities.invokeAndWait
        try {
            SwingUtilities.invokeAndWait(() -> {
                try {
                    Msg.info(this, "Generating field name suggestions for structure at " + structAddressStr);

                    // Get data at address
                    Data data = program.getListing().getDataAt(addr);
                    DataType dataType = (data != null) ? data.getDataType() : null;

                    if (dataType == null || !(dataType instanceof Structure)) {
                        responseRef.set(Response.err("No structure data type found at " + structAddressStr));
                        return;
                    }

                    Structure struct = (Structure) dataType;

                    // MAJOR FIX #5: Validate structure size
                    DataTypeComponent[] components = struct.getComponents();
                    if (components.length > MAX_STRUCT_FIELDS) {
                        responseRef.set(Response.err("Structure too large: " + components.length +
                                   " fields (max " + MAX_STRUCT_FIELDS + ")"));
                        return;
                    }

                    List<Map<String, Object>> suggestions = new ArrayList<>();
                    for (DataTypeComponent component : components) {
                        Map<String, Object> suggestion = new LinkedHashMap<>();
                        suggestion.put("offset", component.getOffset());
                        suggestion.put("current_name", component.getFieldName());
                        suggestion.put("field_type", component.getDataType().getName());

                        // Generate suggestions based on type and patterns
                        List<String> nameSuggestions = generateFieldNameSuggestions(component);

                        // Ensure we always have fallback suggestions
                        if (nameSuggestions.isEmpty()) {
                            nameSuggestions.add(component.getFieldName() + "Value");
                            nameSuggestions.add(component.getFieldName() + "Data");
                        }

                        suggestion.put("suggested_names", nameSuggestions);
                        suggestion.put("confidence", "medium");  // Placeholder confidence level
                        suggestions.add(suggestion);
                    }

                    Msg.info(this, "Generated suggestions for " + components.length + " fields");
                    responseRef.set(Response.ok(JsonHelper.mapOf(
                        "struct_address", structAddressStr,
                        "struct_name", struct.getName(),
                        "struct_size", struct.getLength(),
                        "suggestions", suggestions
                    )));

                } catch (Exception e) {
                    Msg.error(this, "Error in suggestFieldNames", e);
                    responseRef.set(Response.err(e.getMessage()));
                }
            });
        } catch (InvocationTargetException | InterruptedException e) {
            Msg.error(this, "Thread synchronization error in suggestFieldNames", e);
            return Response.err("Thread synchronization error: " + e.getMessage());
        }

        return responseRef.get();
    }

    // Backward compatibility overload
    public Response suggestFieldNames(String structAddressStr, int structSize) {
        return suggestFieldNames(structAddressStr, structSize, null);
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
    @McpTool(path = "/apply_data_classification", method = "POST", description = "Atomic type application with classification. On programs with multiple address spaces (e.g., embedded targets), prefix addresses with the space name (mem:1000) to avoid ambiguous resolution.", category = "datatype")
    @SuppressWarnings("unchecked")
    public Response applyDataClassification(
            @Param(value = "address", paramType = "address", source = ParamSource.BODY,
                   description = "Address in the program. Accepts 0x<hex> (default space) or <space>:<hex> "
                               + "(e.g., mem:1000, code:ff00). Note: some programs — particularly "
                               + "embedded/microcontroller targets — are not address-space-agnostic; "
                               + "use get_address_spaces to discover spaces before assuming a plain hex "
                               + "address is unambiguous.") String addressStr,
            @Param(value = "classification", source = ParamSource.BODY) String classification,
            @Param(value = "name", source = ParamSource.BODY, defaultValue = "") String name,
            @Param(value = "comment", source = ParamSource.BODY, defaultValue = "") String comment,
            @Param(value = "type_definition", source = ParamSource.BODY) Object typeDefinitionObj,
            @Param(value = "program", description = "Target program name", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        final AtomicReference<Response> responseRef = new AtomicReference<>(null);
        final AtomicReference<String> typeApplied = new AtomicReference<>("none");
        final List<String> operations = new ArrayList<>();

        try {
            Address addr = ServiceUtils.parseAddress(program, addressStr);
            if (addr == null) {
                return Response.err(ServiceUtils.getLastParseError());
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

                        String structName = (String) typeDef.get("name");
                        Object fieldsObj = typeDef.get("fields");

                        // Check if structure already exists
                        DataType existing = dtm.getDataType("/" + structName);
                        if (existing != null) {
                            dataTypeToApply = existing;
                            typeApplied.set(structName);
                            operations.add("found_existing_structure");
                        } else {
                            // Create new structure
                            StructureDataType struct = new StructureDataType(structName, 0);

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
                            typeApplied.set(structName);
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
                            String structName = (String) typeDef.get("element_struct");
                            elementType = dtm.getDataType("/" + structName);
                            if (elementType == null) {
                                throw new IllegalArgumentException("Failed to find struct for array element: " + structName);
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
            if (responseRef.get() == null) {
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
            }

            return responseRef.get();

        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    // Backward compatibility overload
    public Response applyDataClassification(String addressStr, String classification,
                                           String name, String comment,
                                           Object typeDefinitionObj) {
        return applyDataClassification(addressStr, classification, name, comment, typeDefinitionObj, null);
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

            // Accept common alternative key names for flexibility
            name = firstOf(keyValues, "name", "field_name", "fieldName", "field");
            type = firstOf(keyValues, "type", "field_type", "fieldType", "data_type", "dataType");
            String offsetStr = firstOf(keyValues, "offset", "field_offset", "fieldOffset", "off");
            if (offsetStr != null) {
                try {
                    offset = Integer.parseInt(offsetStr);
                } catch (NumberFormatException e) {
                    // Keep offset as -1
                }
            }

        } catch (Exception e) {
            Msg.error(this, "Error parsing JSON object: " + e.getMessage());
        }

        // Auto-fix Hungarian prefix on field name
        if (name != null && type != null) {
            name = NamingConventions.autoFixFieldPrefix(name, type);
        }

        return new FieldDefinition(name, type, offset);
    }

    /** Return the value for the first matching key, or null. */
    private static String firstOf(Map<String, String> map, String... keys) {
        for (String key : keys) {
            String val = map.get(key);
            if (val != null) return val;
        }
        return null;
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
    /**
     * Parse enum values from JSON string. Accepts multiple formats:
     * - {"NAME": 0, "NAME2": 1}          (standard int values)
     * - {"NAME": "0", "NAME2": "1"}      (string values — auto-converted)
     * - {"NAME": 0.0, "NAME2": 1.0}      (Gson-parsed doubles — auto-converted)
     * - {"NAME": "0x1F"}                  (hex string values)
     *
     * Returns empty map with logged error on parse failure.
     */
    private Map<String, Long> parseValuesJson(String valuesJson) {
        Map<String, Long> values = new LinkedHashMap<>();

        try {
            Map<String, Object> parsed = JsonHelper.parseJson(valuesJson);

            for (Map.Entry<String, Object> entry : parsed.entrySet()) {
                String key = entry.getKey();
                Object val = entry.getValue();
                Long numValue = null;

                if (val instanceof Number n) {
                    numValue = n.longValue();
                } else if (val instanceof String s) {
                    String trimmed = s.trim();
                    try {
                        if (trimmed.startsWith("0x") || trimmed.startsWith("0X")) {
                            numValue = Long.parseLong(trimmed.substring(2), 16);
                        } else {
                            numValue = Long.parseLong(trimmed);
                        }
                    } catch (NumberFormatException e) {
                        Msg.warn(this, "Enum value parse error for '" + key + "': '" + s +
                                 "' is not a valid integer. Expected integer, hex string (0x...), or numeric string.");
                    }
                } else if (val != null) {
                    Msg.warn(this, "Enum value type error for '" + key + "': unexpected type " +
                             val.getClass().getSimpleName() + ". Expected integer or string.");
                }

                if (numValue != null) {
                    values.put(key, numValue);
                }
            }
        } catch (Exception e) {
            Msg.error(this, "Failed to parse enum values JSON: " + e.getMessage() +
                      ". Expected format: {\"NAME\": 0, \"NAME2\": 1} or {\"NAME\": \"0\", \"NAME2\": \"1\"}");
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
