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
    @McpTool(path = "/create_struct", method = "POST", description = "Create a structure data type. Body fields must be a JSON array of objects; each object needs name and type, with optional offset. Example fields: [{\"name\":\"dwId\",\"type\":\"uint\",\"offset\":0},{\"name\":\"pNext\",\"type\":\"void *\",\"offset\":4}]. Type may be any resolvable Ghidra data type or existing struct name. Set replace_placeholder=true to delete a 1-byte demangler/placeholder type with the same name before creating. To change size of an existing struct in place, use resize_struct; for atomic delete+recreate, use recreate_struct (see docs/STRUCT_RESIZE_WORKFLOW.md).", category = "datatype")
    public Response createStruct(
            @Param(value = "name", source = ParamSource.BODY,
                   description = "New structure type name, for example UnitAny or SkillTableEntry") String name,
            @Param(value = "fields", source = ParamSource.BODY, fieldsJson = true,
                   description = "JSON array of field objects. Required keys: name, type. Optional key: offset as a decimal byte offset. Alternate keys are accepted: field_name/fieldName, field_type/fieldType/data_type/dataType, field_offset/fieldOffset/off. Example: [{\"name\":\"dwId\",\"type\":\"uint\",\"offset\":0},{\"name\":\"pNext\",\"type\":\"void *\",\"offset\":4}]") String fieldsJson,
            @Param(value = "replace_placeholder", source = ParamSource.BODY, defaultValue = "false",
                   description = "If true and a same-named type exists with size <= 1 byte (typical /Demangler stub), delete it first then create the struct.") boolean replacePlaceholder,
            @Param(value = "program", description = "Target program name", defaultValue = "") String programName) {
        if (name == null || name.isEmpty()) {
            return Response.text("Structure name is required");
        }

        if (fieldsJson == null || fieldsJson.isEmpty()) {
            return Response.text(badFieldsFormatHint("Fields JSON is required"));
        }

        // Cheap up-front shape check (issue #167): give the model a clear
        // "what was expected vs what you sent" message before we even try
        // to parse, so a C-struct or CSV attempt fails loudly with a
        // concrete fix instead of a generic "No valid fields provided".
        String fieldsTrimmed = fieldsJson.trim();
        if (!fieldsTrimmed.startsWith("[") || !fieldsTrimmed.endsWith("]")) {
            return Response.text(badFieldsFormatHint(
                    "fields parameter must be a JSON array (got: "
                            + fieldsTrimmed.substring(0, Math.min(60, fieldsTrimmed.length()))
                            + "...)"));
        }

        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        final StringBuilder resultMsg = new StringBuilder();
        final AtomicBoolean successFlag = new AtomicBoolean(false);

        try {
            // Parse the fields JSON (simplified parsing for basic structure)
            // Expected format: [{"name":"field1","type":"int"},{"name":"field2","type":"char"}]
            List<FieldDefinition> fields = parseFieldsJson(fieldsJson);

            if (fields.isEmpty()) {
                return Response.text(badFieldsFormatHint(
                        "No valid fields parsed — every field must have name and type"));
            }

            DataTypeManager dtm = program.getDataTypeManager();

            // Check if struct already exists
            DataType existingType = ServiceUtils.findDataTypeByNameInAllCategories(dtm, name);
            if (existingType != null) {
                if (replacePlaceholder && existingType.getLength() <= 1) {
                    if (!deletePlaceholderType(program, existingType, name, new StringBuilder())) {
                        return Response.text("Failed to remove 1-byte placeholder '"
                                + existingType.getPathName() + "' before create_struct");
                    }
                } else {
                    return Response.text("Structure with name '" + name + "' already exists"
                            + " (" + existingType.getPathName() + ", " + existingType.getLength()
                            + " bytes). Use replace_placeholder=true for 1-byte stubs, or resolve_duplicate_type.");
                }
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
            final boolean hasOffsetsFinal = hasOffsets;

            // Create the structure under the injected threading strategy so the
            // mutation runs on the EDT (GUI) or under the global write lock
            // (headless) with transaction commit/rollback handled centrally.
            try {
                threadingStrategy.executeWrite(program, "Create Structure: " + name, () -> {
                    ghidra.program.model.data.StructureDataType struct =
                        new ghidra.program.model.data.StructureDataType(name, structInitSize);

                    for (Map.Entry<FieldDefinition, DataType> entry : resolvedTypes.entrySet()) {
                        FieldDefinition field = entry.getKey();
                        DataType fieldType = entry.getValue();

                        if (field.offset >= 0 && hasOffsetsFinal) {
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
                    return null;
                });
            } catch (Exception e) {
                String msg = e.getMessage() != null ? e.getMessage() : e.toString();
                Msg.error(this, "Error creating structure", e);
                return Response.err("Error creating structure: " + msg);
            }

            // executeWrite already flushed events; keep the post-create settle.
            if (successFlag.get()) {
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
        return createStruct(name, fieldsJson, false, null);
    }

    public Response createStruct(String name, String fieldsJson, String programName) {
        return createStruct(name, fieldsJson, false, programName);
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

            // Create the enumeration under the injected threading strategy so the
            // mutation runs on the EDT (GUI) or under the global write lock (headless)
            // with transaction commit/rollback handled centrally.
            try {
                return threadingStrategy.executeWrite(program, "Create Enumeration: " + name, () -> {
                    ghidra.program.model.data.EnumDataType enumDt =
                        new ghidra.program.model.data.EnumDataType(name, size);

                    for (Map.Entry<String, Long> entry : values.entrySet()) {
                        enumDt.add(entry.getKey(), entry.getValue());
                    }

                    // Add the enumeration to the data type manager
                    dtm.addDataType(enumDt, null);

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
                });
            } catch (Exception e) {
                return Response.err("Error creating enumeration: " + e.getMessage());
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
            threadingStrategy.executeWrite(program, "Create union", () -> {
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
                    return null;
                }

                dtm.addDataType(union, DataTypeConflictHandler.REPLACE_HANDLER);
                result.append("Union '").append(name).append("' created successfully with ").append(union.getNumComponents()).append(" fields");
                success.set(true);
                return null;
            });
        } catch (Exception e) {
            result.append("Error creating union: ").append(e.getMessage());
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
            threadingStrategy.executeWrite(program, "Create union", () -> {
                DataTypeManager dtm = program.getDataTypeManager();
                UnionDataType union = new UnionDataType(name);

                // Parse fields from JSON using the same method as structs
                List<FieldDefinition> fields = parseFieldsJson(fieldsJson);

                if (fields.isEmpty()) {
                    result.append(badFieldsFormatHint(
                            "No valid fields parsed — every field must have name and type"));
                    return null;
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
                return null;
            });
        } catch (Exception e) {
            result.append("Error creating union: ").append(e.getMessage());
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
            threadingStrategy.executeWrite(program, "Create typedef", () -> {
                DataTypeManager dtm = program.getDataTypeManager();
                DataType base = null;

                // Delegate to resolveDataType which handles pointer chains (int**),
                // arrays (type[N]), well-known C types, and DTM lookups recursively.
                base = ServiceUtils.resolveDataType(dtm, baseType);
                if (base == null) {
                    result.append("Could not resolve base type: ").append(baseType);
                    return null;
                }

                TypedefDataType typedef = new TypedefDataType(name, base);
                dtm.addDataType(typedef, DataTypeConflictHandler.REPLACE_HANDLER);

                result.append("Typedef '").append(name).append("' created as alias for '").append(baseType).append("'");
                success.set(true);
                return null;
            });
        } catch (Exception e) {
            result.append("Error creating typedef: ").append(e.getMessage());
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
            threadingStrategy.executeWrite(program, "Clone data type", () -> {
                DataTypeManager dtm = program.getDataTypeManager();
                DataType source = ServiceUtils.findDataTypeByNameInAllCategories(dtm, sourceType);

                if (source == null) {
                    result.append("Source type not found: ").append(sourceType);
                    return null;
                }

                DataType cloned = source.clone(dtm);
                cloned.setName(newName);

                dtm.addDataType(cloned, DataTypeConflictHandler.REPLACE_HANDLER);
                result.append("Data type '").append(sourceType).append("' cloned as '").append(newName).append("'");
                success.set(true);
                return null;
            });
        } catch (Exception e) {
            result.append("Error cloning data type: ").append(e.getMessage());
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
            threadingStrategy.executeWrite(program, "Create array type", () -> {
                DataTypeManager dtm = program.getDataTypeManager();
                DataType baseDataType = ServiceUtils.resolveDataType(dtm, baseType);

                if (baseDataType == null) {
                    result.append("Base data type not found: ").append(baseType);
                    return null;
                }

                ArrayDataType arrayType = new ArrayDataType(baseDataType, length, baseDataType.getLength());

                if (name != null && !name.isEmpty()) {
                    arrayType.setName(name);
                }

                DataType addedType = dtm.addDataType(arrayType, DataTypeConflictHandler.REPLACE_HANDLER);

                result.append("Successfully created array type: ").append(addedType.getName())
                      .append(" (").append(baseType).append("[").append(length).append("])");
                success.set(true);
                return null;
            });
        } catch (Exception e) {
            result.append("Error creating array type: ").append(e.getMessage());
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
            threadingStrategy.executeWrite(program, "Create pointer type", () -> {
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
                    return null;
                }

                PointerDataType pointerType = new PointerDataType(baseDataType);

                if (name != null && !name.isEmpty()) {
                    pointerType.setName(name);
                }

                DataType addedType = dtm.addDataType(pointerType, DataTypeConflictHandler.REPLACE_HANDLER);

                result.append("Successfully created pointer type: ").append(addedType.getName())
                      .append(" (").append(baseType).append("*)");
                success.set(true);
                return null;
            });
        } catch (Exception e) {
            result.append("Error creating pointer type: ").append(e.getMessage());
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
            threadingStrategy.executeWrite(program, "Create function signature", () -> {
                DataTypeManager dtm = program.getDataTypeManager();

                // Resolve return type
                DataType returnDataType = ServiceUtils.resolveDataType(dtm, returnType);
                if (returnDataType == null) {
                    result.append("Return type not found: ").append(returnType);
                    return null;
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

                        List<ParameterDefinition> params = new ArrayList<>();
                        for (String paramPair : paramPairs) {
                            if (paramPair.trim().isEmpty()) continue;

                            String[] parts = paramPair.split(":");
                            if (parts.length >= 2) {
                                String paramType = parts[1].replace("\"", "").trim();
                                DataType paramDataType = ServiceUtils.resolveDataType(dtm, paramType);
                                if (paramDataType != null) {
                                    params.add(new ParameterDefinitionImpl(null, paramDataType, null));
                                }
                            }
                        }
                        if (!params.isEmpty()) {
                            funcDef.setArguments(params.toArray(new ParameterDefinition[0]));
                        }
                    } catch (Exception e) {
                        // If JSON parsing fails, continue without parameters
                        result.append("Warning: Could not parse parameters, continuing without them. ");
                    }
                }

                DataType addedFuncDef = dtm.addDataType(funcDef, DataTypeConflictHandler.REPLACE_HANDLER);

                result.append("Successfully created function signature: ").append(addedFuncDef.getName());
                success.set(true);
                return null;
            });
        } catch (Exception e) {
            result.append("Error creating function signature: ").append(e.getMessage());
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
            @Param(value = "program", description = "Target program name", defaultValue = "") String programName,
            @Param(value = "strict_mode", source = ParamSource.BODY, defaultValue = "",
                   description = "Optional per-call override for naming enforcement: 'enforce' / 'warn' / 'off'. Omit to use the project/global setting.")
                    String strictModeArg) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        if (addressStr == null || addressStr.isEmpty()) {
            return Response.text("Address is required");
        }

        if (typeName == null || typeName.isEmpty()) {
            return Response.text("Data type name is required");
        }

        try (AutoCloseable scopedMode = NamingPolicy.getInstance().scopedRequestMode(strictModeArg)) {
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
            List<String> enforcementWarnings = new ArrayList<>();

            // Check if address is in a valid memory block
            if (!program.getMemory().contains(address)) {
                return Response.text("Address is not in program memory: " + addressStr);
            }

            // Hungarian-vs-name cross-check (option A enforcement gate).
            // When the address already has a `g_*` named symbol, applying a
            // type that contradicts the name's Hungarian prefix produces a
            // silently-lying global (e.g., `g_dwActiveQuestState` typed as
            // `byte`). This is the only escape hatch around `set_global`'s
            // upfront validation, so we close it here too. Only fires on
            // the type-mismatch issue — other name issues (missing g_,
            // short descriptor, etc.) belong to the rename path's gate
            // and would be over-zealous to re-check on type writes against
            // grandfathered names.
            SymbolTable preCheckSymTable = program.getSymbolTable();
            Symbol preCheckSym = preCheckSymTable.getPrimarySymbol(address);
            if (preCheckSym != null) {
                String existingName = preCheckSym.getName();
                if (existingName != null && existingName.startsWith("g_")) {
                    NamingConventions.GlobalNameResult preCheckResult =
                            NamingConventions.checkGlobalNameQuality(existingName, typeName);
                    if (!preCheckResult.ok && "prefix_type_mismatch".equals(preCheckResult.issue)) {
                        Map<String, Object> rejection = JsonHelper.mapOf(
                                "status", "rejected",
                                "error", "prefix_type_mismatch",
                                "address", addressStr,
                                "current_name", existingName,
                                "rejected_type", typeName,
                                "message", preCheckResult.message,
                                "suggestion", "Either rename the global to match '" + typeName
                                        + "' first (use rename_data / rename_global_variable), "
                                        + "or apply the type+name change atomically with set_global "
                                        + "to avoid the silently-lying-name state."
                        );
                        if (NamingPolicy.getInstance().isStrictNamingEnforcement()) {
                            return Response.ok(rejection);
                        }
                        enforcementWarnings.add(disabledGlobalEnforcementWarning(rejection));
                    }
                }
            }

            // Apply the data type under the injected threading strategy so the
            // mutation runs on the EDT (GUI) or under the global write lock (headless)
            // with transaction commit/rollback handled centrally.
            try {
                return threadingStrategy.executeWrite(program, "Apply Data Type: " + typeName, () -> {
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
                    for (String warning : enforcementWarnings) {
                        resultText += "\nWarning: " + warning;
                    }

                    return Response.text(resultText);
                });
            } catch (Exception e) {
                return Response.err("Error applying data type: " + e.getMessage());
            }

        } catch (Exception e) {
            return Response.err("Error processing request: " + e.getMessage());
        }
    }

    /** Four-arg overload preserving the pre-v5.11.2 signature. */
    public Response applyDataType(String addressStr, String typeName, boolean clearExisting,
                                   String programName) {
        return applyDataType(addressStr, typeName, clearExisting, programName, null);
    }

    // Backward compatibility overload
    public Response applyDataType(String addressStr, String typeName, boolean clearExisting) {
        return applyDataType(addressStr, typeName, clearExisting, null, null);
    }

    /**
     * Delete a data type from the program
     */
    @McpTool(path = "/delete_data_type", method = "POST",
            description = "Delete a data type by name. Fails if the type is referenced; use resolve_duplicate_type first to remove unused /Demangler 1-byte stubs when a full type exists.",
            category = "datatype")
    public Response deleteDataType(
            @Param(value = "type_name", source = ParamSource.BODY) String typeName,
            @Param(value = "resolve_demangler_duplicate", source = ParamSource.BODY, defaultValue = "false",
                   description = "If delete fails, attempt resolve_duplicate_type to remove a /Demangler size-1 stub when a larger same-named type exists.") boolean resolveDemanglerDuplicate,
            @Param(value = "program", description = "Target program name", defaultValue = "") String programName) {
        if (typeName == null || typeName.isEmpty()) return Response.text("Type name is required");

        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        AtomicBoolean success = new AtomicBoolean(false);
        StringBuilder result = new StringBuilder();

        try {
            threadingStrategy.executeWrite(program, "Delete data type", () -> {
                DataTypeManager dtm = program.getDataTypeManager();
                DataType dataType = ServiceUtils.findDataTypeByNameInAllCategories(dtm, typeName);

                if (dataType == null) {
                    result.append("Data type not found: ").append(typeName);
                    return null;
                }

                // Check if type is in use (simplified check)
                // Note: Ghidra will prevent deletion if type is in use during remove operation

                boolean deleted = dtm.remove(dataType, null);
                if (deleted) {
                    result.append("Data type '").append(typeName).append("' deleted successfully");
                    success.set(true);
                } else {
                    result.append("Failed to delete data type '").append(typeName)
                            .append("' (may be in use). Try resolve_duplicate_type if a /Demangler 1-byte stub blocks a full struct.");
                }
                return null;
            });
        } catch (Exception e) {
            result.append("Error deleting data type: ").append(e.getMessage());
        }

        if (!success.get() && resolveDemanglerDuplicate) {
            Response resolved = resolveDuplicateType(typeName, true, programName);
            return Response.text(result.toString() + "\n" + resolved.toJson());
        }

        return Response.text(result.toString());
    }

    // Backward compatibility overload
    public Response deleteDataType(String typeName) {
        return deleteDataType(typeName, false, null);
    }

    public Response deleteDataType(String typeName, String programName) {
        return deleteDataType(typeName, false, programName);
    }

    /**
     * Modify a field in an existing structure
     */
    @McpTool(path = "/modify_struct_field", method = "POST", description = "Modify a field in a structure. Fields can be identified by name or by offset (for unnamed fields). For layout size changes (grow/shrink padding), use resize_struct instead of manual delete+create.", category = "datatype")
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
            threadingStrategy.executeWrite(program, "Modify struct field", () -> {
                DataTypeManager dtm = program.getDataTypeManager();
                DataType dataType = ServiceUtils.findDataTypeByNameInAllCategories(dtm, structName);

                if (dataType == null) {
                    result.append("Structure not found: ").append(structName);
                    return null;
                }

                if (!(dataType instanceof Structure)) {
                    result.append("Data type '").append(structName).append("' is not a structure");
                    return null;
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
                            return null;
                        }
                    } catch (NumberFormatException e) {
                        result.append("Invalid offset format: ").append(fieldName).append(". Use 'offset:16' or 'offset:0x10'");
                        return null;
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
                    return null;
                }

                // If new type is specified, change the field type
                if (newType != null && !newType.isEmpty()) {
                    DataType newDataType = ServiceUtils.resolveDataType(dtm, newType);
                    if (newDataType == null) {
                        result.append("New data type not found: ").append(newType);
                        return null;
                    }
                    struct.replace(targetComponent.getOrdinal(), newDataType, newDataType.getLength());
                }

                // If new name is specified, apply the configured field naming policy.
                if (newName != null && !newName.isEmpty()) {
                    targetComponent = struct.getComponent(targetComponent.getOrdinal()); // Refresh component
                    String fieldTypeName = targetComponent.getDataType().getName();
                    String fixedName = NamingConventions.applyStructFieldNamingPolicy(newName, fieldTypeName);
                    targetComponent.setFieldName(fixedName);
                }

                result.append("Successfully modified field '").append(fieldName).append("' in structure '").append(structName).append("'");
                success.set(true);
                return null;
            });
        } catch (Exception e) {
            result.append("Error modifying struct field: ").append(e.getMessage());
        }

        return Response.text(result.toString());
    }

    // Backward compatibility overload
    public Response modifyStructField(String structName, String fieldName, String newType, String newName) {
        return modifyStructField(structName, fieldName, newType, newName, null);
    }

    /**
     * Alias for {@link #modifyStructField} when only the field type changes.
     */
    @McpTool(path = "/modify_struct_field_type", method = "POST",
            description = "Set a structure field's type by name or offset (offset:N). Same as modify_struct_field with new_type only.",
            category = "datatype")
    public Response modifyStructFieldType(
            @Param(value = "struct_name", source = ParamSource.BODY) String structName,
            @Param(value = "field_name", source = ParamSource.BODY,
                   description = "Field name or offset:N (e.g. offset:0x88).") String fieldName,
            @Param(value = "new_type", source = ParamSource.BODY) String newType,
            @Param(value = "program", defaultValue = "") String programName) {
        return modifyStructField(structName, fieldName, newType, "", programName);
    }

    /**
     * Embed a structure by value at a field offset (not a pointer). Common for nested MSVC-style subobjects.
     */
    @McpTool(path = "/embed_struct_field", method = "POST",
            description = "Replace a structure field with an embedded struct type by value (e.g. Rectangle inside LayoutNode). Uses modify_struct_field internally.",
            category = "datatype")
    public Response embedStructField(
            @Param(value = "parent_struct", source = ParamSource.BODY) String parentStruct,
            @Param(value = "field_name", source = ParamSource.BODY, defaultValue = "",
                   description = "Field name or offset:N.") String fieldName,
            @Param(value = "embedded_struct", source = ParamSource.BODY,
                   description = "Existing structure type to embed by value.") String embeddedStruct,
            @Param(value = "program", defaultValue = "") String programName) {
        if (embeddedStruct == null || embeddedStruct.isEmpty()) {
            return Response.text("embedded_struct is required");
        }
        return modifyStructField(parentStruct, fieldName, embeddedStruct, "", programName);
    }

    /**
     * Grow or shrink an existing structure without delete+recreate.
     */
    @McpTool(path = "/resize_struct", method = "POST",
            description = "Grow or shrink an existing structure by total byte size. Defined fields whose end offset fits within new_size are preserved; growth pads with undefined filler. Refuses shrink that would clip defined fields unless force=true. See docs/STRUCT_RESIZE_WORKFLOW.md.",
            category = "datatype")
    public Response resizeStruct(
            @Param(value = "name", source = ParamSource.BODY) String name,
            @Param(value = "new_size", source = ParamSource.BODY) int newSize,
            @Param(value = "preserve_fields", source = ParamSource.BODY, defaultValue = "true",
                   description = "When true (default), keep defined fields that still fit; when false with force, trailing layout may be cleared before resize.") boolean preserveFields,
            @Param(value = "force", source = ParamSource.BODY, defaultValue = "false",
                   description = "Allow shrink even when defined fields extend past new_size (clips trailing layout).") boolean force,
            @Param(value = "program", defaultValue = "") String programName) {

        if (name == null || name.isEmpty()) {
            return Response.err("name is required");
        }
        if (newSize <= 0) {
            return Response.err("new_size must be positive");
        }

        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        AtomicBoolean success = new AtomicBoolean(false);
        StringBuilder result = new StringBuilder();
        final int[] oldLenOut = new int[1];

        try {
            threadingStrategy.executeWrite(program, "Resize structure: " + name, () -> {
                DataTypeManager dtm = program.getDataTypeManager();
                DataType dataType = ServiceUtils.findDataTypeByNameInAllCategories(dtm, name);
                if (dataType == null) {
                    result.append("Structure not found: ").append(name);
                    return null;
                }
                if (!(dataType instanceof Structure)) {
                    result.append("Data type '").append(name).append("' is not a structure");
                    return null;
                }

                Structure struct = (Structure) dataType;
                oldLenOut[0] = struct.getLength();
                String clipError = validateStructResize(struct, newSize, force);
                if (clipError != null) {
                    result.append(clipError);
                    return null;
                }

                if (!preserveFields && force && newSize < oldLenOut[0]) {
                    clearStructComponentsFromOffset(struct, newSize);
                }

                struct.setLength(newSize);
                success.set(true);
                result.append("Resized '").append(name).append("' from ")
                        .append(oldLenOut[0]).append(" to ").append(struct.getLength()).append(" bytes");
                return null;
            });
        } catch (IllegalArgumentException e) {
            result.append("Resize failed: ").append(e.getMessage())
                    .append(". Use force=true or recreate_struct with an explicit fields array.");
        } catch (Exception e) {
            result.append("Error resizing structure: ").append(e.getMessage());
        }

        if (success.get()) {
            return Response.ok(JsonHelper.mapOf(
                    "status", "success",
                    "name", name,
                    "old_size", oldLenOut[0],
                    "new_size", newSize,
                    "message", result.toString()));
        }
        return result.length() > 0 ? Response.err(result.toString()) : Response.err("Failed to resize structure");
    }

    /**
     * Replace a structure: remove placeholder or existing type (when allowed), then create with fields.
     * Not a single transaction; the delete and create are committed separately.
     */
    @McpTool(path = "/recreate_struct", method = "POST",
            description = "Replace a structure in one step: optionally remove an existing same-named type, then create with fields JSON (same shape as create_struct). Use when resize_struct cannot apply or you are rebuilding layout from get_struct_layout export. Set force=true to delete a non-stub type that is not referenced.",
            category = "datatype")
    public Response recreateStruct(
            @Param(value = "name", source = ParamSource.BODY) String name,
            @Param(value = "fields", source = ParamSource.BODY, fieldsJson = true) String fieldsJson,
            @Param(value = "size", source = ParamSource.BODY, defaultValue = "0",
                   description = "Optional minimum total size in bytes after create; grows with undefined padding when larger than implied field layout.") int size,
            @Param(value = "replace_placeholder", source = ParamSource.BODY, defaultValue = "true",
                   description = "Delete a 1-byte placeholder/Demangler stub before recreate (default true).") boolean replacePlaceholder,
            @Param(value = "force", source = ParamSource.BODY, defaultValue = "false",
                   description = "Delete an existing full-sized struct before recreate (fails if referenced).") boolean force,
            @Param(value = "program", defaultValue = "") String programName) {

        if (name == null || name.isEmpty()) {
            return Response.err("name is required");
        }
        if (fieldsJson == null || fieldsJson.isEmpty()) {
            return Response.err(badFieldsFormatHint("fields JSON is required"));
        }

        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        DataTypeManager dtm = program.getDataTypeManager();
        DataType existing = ServiceUtils.findDataTypeByNameInAllCategories(dtm, name);

        // recreate_struct is inherently multi-step (delete -> create -> resize across
        // separate transactions). To avoid permanently destroying the original type when
        // a later step fails, capture a restorable deep copy BEFORE any destructive delete
        // and re-add it if the create does not succeed.
        DataType originalBackup = null;
        boolean deletedOriginal = false;

        if (existing != null) {
            boolean stub = existing.getLength() <= 1;
            boolean demangler = isDemanglerPlaceholder(existing);
            if (stub && (replacePlaceholder || demangler)) {
                originalBackup = existing.copy(dtm);
                StringBuilder stubMsg = new StringBuilder();
                if (!deletePlaceholderType(program, existing, name, stubMsg)) {
                    return Response.err("Could not remove placeholder before recreate: " + stubMsg);
                }
                deletedOriginal = true;
            } else if (force) {
                originalBackup = existing.copy(dtm);
                AtomicBoolean deleted = new AtomicBoolean(false);
                StringBuilder delMsg = new StringBuilder();
                try {
                    threadingStrategy.executeWrite(program, "Recreate struct delete", () -> {
                        deleted.set(dtm.remove(existing, null));
                        if (deleted.get()) {
                            delMsg.append("Removed existing type before recreate");
                        } else {
                            delMsg.append("Could not delete '").append(name)
                                    .append("' (may be in use)");
                        }
                        return null;
                    });
                } catch (Exception e) {
                    return Response.err("Delete before recreate failed: " + e.getMessage());
                }
                if (!deleted.get()) {
                    return Response.err(delMsg.toString());
                }
                deletedOriginal = true;
            } else {
                return Response.err("Structure '" + name + "' already exists ("
                        + existing.getLength() + " bytes at " + existing.getPathName()
                        + "). Use resize_struct, replace_placeholder for 1-byte stubs, or force=true.");
            }
        }

        Response created = createStruct(name, fieldsJson, false, programName);

        // Verify the create actually landed; if not, restore the original we deleted so the
        // operation is net-zero rather than destructive.
        boolean structPresent =
                ServiceUtils.findDataTypeByNameInAllCategories(dtm, name) instanceof Structure;
        if (!structPresent) {
            String createErr = (created instanceof Response.Err)
                    ? ((Response.Err) created).message()
                    : "create_struct did not produce a structure";
            if (deletedOriginal && originalBackup != null) {
                final DataType restore = originalBackup;
                try {
                    threadingStrategy.executeWrite(program,
                            "Restore struct after failed recreate", () -> {
                        dtm.addDataType(restore, null);
                        return null;
                    });
                    return Response.err("recreate_struct failed to create '" + name
                            + "'; the original type was restored unchanged. Cause: " + createErr);
                } catch (Exception e) {
                    return Response.err("recreate_struct failed to create '" + name
                            + "' AND could not restore the original ("
                            + restore.getPathName() + "): " + e.getMessage()
                            + ". Original create error: " + createErr);
                }
            }
            return created;
        }

        if (size <= 0) {
            return created;
        }

        Response resized = resizeStruct(name, size, true, true, programName);

        if (resized instanceof Response.Err) {
            return Response.err("Created struct but post-create resize failed: "
                    + ((Response.Err) resized).message());
        }
        return resized;
    }

    /**
     * Remove a 1-byte /Demangler placeholder when a full same-named type exists.
     */
    @McpTool(path = "/resolve_duplicate_type", method = "POST",
            description = "Find duplicate data types by simple name; delete unused /Demangler size-1 stubs when a larger canonical type exists. Helps fix 'Can't resolve datatype' and create_struct already exists on placeholders.",
            category = "datatype")
    public Response resolveDuplicateType(
            @Param(value = "type_name", source = ParamSource.BODY) String typeName,
            @Param(value = "delete_demangler_stub", source = ParamSource.BODY, defaultValue = "true",
                   description = "Delete /Demangler/* stubs (size <= 1) when a larger type with the same name exists.") boolean deleteDemanglerStub,
            @Param(value = "program", defaultValue = "") String programName) {

        if (typeName == null || typeName.isEmpty()) {
            return Response.text("type_name is required");
        }

        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        DataTypeManager dtm = program.getDataTypeManager();
        List<DataType> matches = findAllTypesBySimpleName(dtm, typeName);
        if (matches.isEmpty()) {
            return Response.text("No data type named '" + typeName + "'");
        }

        List<DataType> demanglerStubs = new ArrayList<>();
        List<DataType> canonical = new ArrayList<>();
        for (DataType dt : matches) {
            if (isDemanglerPlaceholder(dt)) {
                demanglerStubs.add(dt);
            } else {
                canonical.add(dt);
            }
        }

        StringBuilder report = new StringBuilder();
        report.append("Found ").append(matches.size()).append(" type(s) named '").append(typeName).append("': ");
        for (DataType dt : matches) {
            report.append(dt.getPathName()).append(" (").append(dt.getLength()).append(" B); ");
        }

        if (demanglerStubs.isEmpty()) {
            if (canonical.size() <= 1) {
                return Response.text(report + "No /Demangler 1-byte stub to resolve.");
            }
            return Response.text(report + "Multiple canonical types — pick one manually or delete orphans with delete_data_type.");
        }

        if (canonical.isEmpty()) {
            return Response.text(report + "Only demangler stub(s) present — use delete_data_type or create_struct with replace_placeholder=true.");
        }

        if (!deleteDemanglerStub) {
            return Response.text(report + "Demangler stub(s) present; set delete_demangler_stub=true to remove.");
        }

        int removed = 0;
        for (DataType stub : demanglerStubs) {
            StringBuilder stubMsg = new StringBuilder();
            if (deletePlaceholderType(program, stub, typeName, stubMsg)) {
                removed++;
                report.append("Deleted ").append(stub.getPathName()).append(". ");
            } else {
                report.append("Could not delete ").append(stub.getPathName()).append(": ")
                        .append(stubMsg).append(" ");
            }
        }

        DataType best = canonical.stream().max(Comparator.comparingInt(DataType::getLength)).orElse(canonical.get(0));
        report.append("Prefer canonical type ").append(best.getPathName())
                .append(" (").append(best.getLength()).append(" B).");

        if (removed > 0) {
            return Response.ok(JsonHelper.mapOf(
                    "status", "success",
                    "removed", removed,
                    "message", report.toString(),
                    "canonical_path", best.getPathName()));
        }
        return Response.text(report.toString());
    }

    static List<DataType> findAllTypesBySimpleName(DataTypeManager dtm, String typeName) {
        List<DataType> matches = new ArrayList<>();
        Iterator<DataType> all = dtm.getAllDataTypes();
        while (all.hasNext()) {
            DataType dt = all.next();
            if (typeName.equals(dt.getName())) {
                matches.add(dt);
            }
        }
        return matches;
    }

    static boolean isDemanglerPlaceholder(DataType dt) {
        if (dt == null) {
            return false;
        }
        String path = dt.getCategoryPath() != null ? dt.getCategoryPath().getPath() : null;
        return isDemanglerPlaceholder(dt.getLength(), path);
    }

    static boolean isDemanglerPlaceholder(int length, String categoryPath) {
        if (length > 1) {
            return false;
        }
        return categoryPath != null && categoryPath.contains("/Demangler");
    }

    /** Highest byte offset covered by any defined component (0 if empty). */
    static int structDefinedByteExtent(Structure struct) {
        int max = 0;
        for (DataTypeComponent component : struct.getDefinedComponents()) {
            max = Math.max(max, component.getEndOffset());
        }
        return max;
    }

    /**
     * @return error message when shrink would clip defined fields and force is false; null if OK
     */
    static String validateStructResize(Structure struct, int newSize, boolean force) {
        return validateStructResize(structDefinedByteExtent(struct), struct.getName(), newSize, force);
    }

    static String validateStructResize(int definedByteExtent, String structName, int newSize, boolean force) {
        if (newSize <= 0) {
            return "new_size must be positive";
        }
        if (newSize < definedByteExtent && !force) {
            return "Cannot shrink '" + structName + "' to " + newSize
                    + " bytes: defined fields extend to " + definedByteExtent
                    + " bytes. Set force=true to clip, or use recreate_struct with a new fields array.";
        }
        return null;
    }

    /** Delete components starting at {@code fromOffset} (highest ordinal first). */
    static void clearStructComponentsFromOffset(Structure struct, int fromOffset) {
        for (int i = struct.getNumComponents() - 1; i >= 0; i--) {
            DataTypeComponent component = struct.getComponent(i);
            if (component != null && component.getOffset() >= fromOffset) {
                struct.delete(i);
            }
        }
    }

    boolean deletePlaceholderType(Program program, DataType dataType, String logicalName,
                                         StringBuilder result) {
        AtomicBoolean success = new AtomicBoolean(false);
        try {
            threadingStrategy.executeWrite(program, "Delete placeholder type " + logicalName, () -> {
                DataTypeManager dtm = program.getDataTypeManager();
                boolean deleted = dtm.remove(dataType, null);
                if (deleted) {
                    result.append("Removed placeholder '").append(dataType.getPathName()).append("'");
                    success.set(true);
                } else {
                    result.append("Could not remove '").append(dataType.getPathName())
                            .append("' (in use or locked)");
                }
                return null;
            });
        } catch (Exception e) {
            result.append("Error: ").append(e.getMessage());
        }
        return success.get();
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

        // Apply configured struct-field naming policy.
        fieldName = NamingConventions.applyStructFieldNamingPolicy(fieldName, fieldType);

        AtomicBoolean success = new AtomicBoolean(false);
        StringBuilder result = new StringBuilder();
        final String finalFieldName = fieldName;

        try {
            threadingStrategy.executeWrite(program, "Add struct field", () -> {
                DataTypeManager dtm = program.getDataTypeManager();
                DataType dataType = ServiceUtils.findDataTypeByNameInAllCategories(dtm, structName);

                if (dataType == null) {
                    result.append("Structure not found: ").append(structName);
                    return null;
                }

                if (!(dataType instanceof Structure)) {
                    result.append("Data type '").append(structName).append("' is not a structure");
                    return null;
                }

                Structure struct = (Structure) dataType;
                DataType newFieldType = ServiceUtils.resolveDataType(dtm, fieldType);
                if (newFieldType == null) {
                    result.append("Field data type not found: ").append(fieldType);
                    return null;
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
                return null;
            });
        } catch (Exception e) {
            result.append("Error adding struct field: ").append(e.getMessage());
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
            threadingStrategy.executeWrite(program, "Remove struct field", () -> {
                DataTypeManager dtm = program.getDataTypeManager();
                DataType dataType = ServiceUtils.findDataTypeByNameInAllCategories(dtm, structName);

                if (dataType == null) {
                    result.append("Structure not found: ").append(structName);
                    return null;
                }

                if (!(dataType instanceof Structure)) {
                    result.append("Data type '").append(structName).append("' is not a structure");
                    return null;
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
                    return null;
                }

                struct.delete(targetOrdinal);
                result.append("Successfully removed field '").append(fieldName).append("' from structure '").append(structName).append("'");
                success.set(true);
                return null;
            });
        } catch (Exception e) {
            result.append("Error removing struct field: ").append(e.getMessage());
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
            threadingStrategy.executeWrite(program, "Move data type to category", () -> {
                DataTypeManager dtm = program.getDataTypeManager();
                DataType dataType = ServiceUtils.findDataTypeByNameInAllCategories(dtm, typeName);

                if (dataType == null) {
                    result.append("Data type not found: ").append(typeName);
                    return null;
                }

                CategoryPath catPath = new CategoryPath(categoryPath);
                Category category = dtm.createCategory(catPath);

                // Move the data type
                dataType.setCategoryPath(catPath);

                result.append("Successfully moved data type '").append(typeName)
                      .append("' to category '").append(categoryPath).append("'");
                success.set(true);
                return null;
            });
        } catch (Exception e) {
            result.append("Error moving data type: ").append(e.getMessage());
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
            return threadingStrategy.executeWrite(program, "Create category " + categoryPath, () -> {
                DataTypeManager dtm = program.getDataTypeManager();
                CategoryPath catPath = new CategoryPath(categoryPath);
                Category category = dtm.createCategory(catPath);

                return Response.ok(JsonHelper.mapOf(
                    "status", "success",
                    "message", "Successfully created category: " + category.getCategoryPathName()
                ));
            });
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
                        decomp = ServiceUtils.createConfiguredDecompiler(program);

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
            try {
                threadingStrategy.executeWrite(program, "Apply Data Classification", () -> {
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

                    return null;
                });
            } catch (Exception e) {
                responseRef.set(Response.err(e.getMessage()));
            }

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
    /**
     * Build a multi-line error message that explains what the {@code fields}
     * parameter is supposed to look like. Used by {@code create_struct} and
     * {@code create_struct_with_fields} so an agent that sends a C-style
     * struct, CSV, or anything else that isn't a JSON array gets back a
     * concrete corrected example on its first wrong attempt.
     *
     * Closes issue #167 — agents were trying multiple formats before giving
     * up because the prior error ("No valid fields provided") gave them no
     * path to the right shape.
     */
    private static String badFieldsFormatHint(String reason) {
        return reason + ". Expected a JSON array of objects, each with "
                + "name (string) and type (string), with optional offset (decimal byte). "
                + "Example: "
                + "[{\"name\":\"dwId\",\"type\":\"uint\",\"offset\":0},"
                + "{\"name\":\"pNext\",\"type\":\"void *\",\"offset\":4}]. "
                + "type may be any resolvable Ghidra data type "
                + "(uint, byte, ushort, char *, void *, MyStruct *, ...). "
                + "Do NOT pass a C-style struct definition or CSV — only JSON.";
    }

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

        // Apply configured struct-field naming policy.
        if (name != null && type != null) {
            name = NamingConventions.applyStructFieldNamingPolicy(name, type);
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

    // -----------------------------------------------------------------------
    // Global Variable Documentation Tools (v5.7.0)
    // -----------------------------------------------------------------------
    //
    // Per the Q1-Q8 design conversation 2026-04-25, "properly documented
    // global" means:
    //   1. Has a meaningful name (g_ prefix + Hungarian + descriptor)
    //   2. Has a real type (not undefined1/2/4/8)
    //   3. Bytes at the address are formatted as that type (length matches;
    //      ASCII null-terminated runs are string types, not raw char[])
    //   4. Has a non-empty plate comment with a meaningful one-line summary
    //
    // audit_global is the read-only inspector — returns the global's current
    // state and the list of issues blocking it from being "fully documented."
    //
    // set_global is the canonical atomic writer — applies type, sets array
    // length when applicable, renames, and writes the plate comment in one
    // transaction. Replaces the 4-tool chain (apply_data_type → rename_data
    // → batch_set_comments → maybe create_label) so partial application is
    // structurally impossible.

    /**
     * Audit a single global at the given address — public static helper
     * shared by audit_global (per-address) and audit_globals_in_function
     * (per-function bulk auditor). Returns the same map shape from both
     * call sites so the model can union-process results.
     */
    public static Map<String, Object> auditGlobalAt(Program program, Address addr) {
        Listing listing = program.getListing();
        SymbolTable symTable = program.getSymbolTable();

        Symbol primary = symTable.getPrimarySymbol(addr);
        String name = primary != null ? primary.getName() : "";
        Data data = listing.getDefinedDataAt(addr);
        String typeName = "";
        int length = 0;
        boolean hasUndefinedType = false;
        boolean lengthMismatch = false;
        if (data != null) {
            DataType dt = data.getDataType();
            if (dt != null) {
                typeName = dt.getName();
                hasUndefinedType = typeName.startsWith("undefined");
                int declared = dt.getLength();
                length = data.getLength();
                if (declared > 0 && length != declared) lengthMismatch = true;
            }
        }
        String plateComment = listing.getComment(ghidra.program.model.listing.CodeUnit.PLATE_COMMENT, addr);
        if (plateComment == null) plateComment = "";

        ReferenceManager refMgr = program.getReferenceManager();
        int xrefCount = 0;
        ReferenceIterator iter = refMgr.getReferencesTo(addr);
        while (iter.hasNext()) { iter.next(); xrefCount++; }

        List<String> issues = new ArrayList<>();

        // Code-address guard: any address that is code (has an Instruction
        // at it, OR has a Function defined at it) is not a data global.
        // /list_globals iterates symbols and skips SymbolType.FUNCTION,
        // but two patterns slip through:
        //   1. A LABEL on the same address as a function entry
        //      (function_entry case — getFunctionAt(addr) != null)
        //   2. A LABEL on a code address where Ghidra has NOT created a
        //      Function yet — FLIRT/FID matches like "FID_conflict:__time32"
        //      are the canonical example. getFunctionAt(addr) returns null
        //      here because there's no Function symbol, only a label sitting
        //      on top of an Instruction.
        // Without this guard, audit_global reports `untyped` (no defined
        // data) on every code address and the worker burns a turn
        // confirming-and-skipping. Production log showed CRT helpers
        // (AcquireStreamLock, ConvertFileTimeToUnixTime32, FID_conflict:*,
        // etc.) eating the entire run.
        boolean hasFunction = program.getFunctionManager().getFunctionAt(addr) != null;
        boolean hasInstruction = listing.getInstructionAt(addr) != null;
        if (hasFunction || hasInstruction) {
            return JsonHelper.mapOf(
                    "address", addr.toString(),
                    "name", name,
                    "type", typeName,
                    "length", length,
                    "plate_comment", plateComment,
                    "xref_count", xrefCount,
                    "issues", issues,
                    "fully_documented", true,
                    "is_code_address", true,
                    "is_function_entry", hasFunction
            );
        }

        // OS-canonical labels (TIB/PEB/KUSER) are fully exempt from the
        // audit — the Microsoft name + the OS-applied type are canonical,
        // and asking the user to write a plate comment for "ExceptionList"
        // is wrong. Mark the response so callers (worker, scorer) know
        // why the issue list is empty.
        boolean osCanonical = NamingConventions.isOsCanonicalGlobalName(name);
        if (osCanonical) {
            return JsonHelper.mapOf(
                    "address", addr.toString(),
                    "name", name,
                    "type", typeName,
                    "length", length,
                    "plate_comment", plateComment,
                    "xref_count", xrefCount,
                    "issues", issues,
                    "fully_documented", true,
                    "os_canonical", true
            );
        }

        // Per-issue severity tracker. Hard + medium count toward
        // `fully_documented`; soft are surfaced for human review but
        // don't block "completion." Mirrors the function-side rubric
        // where structural deductions are forgiven in `effective_score`.
        Map<String, String> severityByIssue = new java.util.LinkedHashMap<>();

        boolean autoGen = NamingConventions.isAutoGeneratedGlobalName(name) || name.isEmpty();
        if (autoGen) {
            issues.add("generic_name");
            severityByIssue.put("generic_name", "hard");
        } else {
            // IDA reserved prefix (sub_, loc_, byte_, etc.) — hard issue,
            // breaks downstream tools that rely on these as "untouched"
            // sentinels.
            if (NamingConventions.hasIdaReservedPrefix(name)) {
                issues.add("ida_reserved_prefix");
                severityByIssue.put("ida_reserved_prefix", "hard");
            }
            NamingConventions.GlobalNameResult q =
                    NamingConventions.checkGlobalNameQuality(name, typeName.isEmpty() ? null : typeName);
            if (!q.ok) {
                String code = "name_" + q.issue;
                issues.add(code);
                // missing_g_prefix / prefix_type_mismatch / etc. are all
                // hard — they violate the project naming convention and
                // were already gated by checkGlobalNameQuality at write
                // time (set_global rejects them).
                severityByIssue.put(code, "hard");
            } else {
                // Name passed the quality check. Check the descriptor
                // portion for low-information generic words.
                // Strip g_ + Hungarian prefix to isolate the descriptor.
                String descriptor = extractDescriptorPart(name);
                if (descriptor != null && NamingConventions.isGenericDescriptor(descriptor)) {
                    issues.add("generic_descriptor");
                    severityByIssue.put("generic_descriptor", "soft");
                }
            }
        }

        if (data == null || hasUndefinedType) {
            issues.add("untyped");
            severityByIssue.put("untyped", "hard");
        }

        if (data != null) {
            if (lengthMismatch) {
                issues.add("unformatted_bytes_length_mismatch");
                severityByIssue.put("unformatted_bytes_length_mismatch", "medium");
            }
            if (!typeName.isEmpty() && (typeName.equals("char") || typeName.equals("byte"))) {
                if (looksLikeUnappliedStringAt(program, addr)) {
                    issues.add("unformatted_bytes_should_be_string");
                    severityByIssue.put("unformatted_bytes_should_be_string", "medium");
                }
            }
            // Array with no documented length AND > 1 xref → soft signal
            // ("you typed it as an array but didn't say how many elements").
            DataType dt = data.getDataType();
            if (dt instanceof ghidra.program.model.data.Array
                    && ((ghidra.program.model.data.Array) dt).getNumElements() <= 1
                    && xrefCount > 1) {
                issues.add("bytes_size_unknown");
                severityByIssue.put("bytes_size_unknown", "soft");
            }
        }

        String trimmedComment = plateComment.trim();
        if (trimmedComment.isEmpty()) {
            issues.add("missing_plate_comment");
            severityByIssue.put("missing_plate_comment", "hard");
        } else {
            String[] plateIssue = NamingConventions.checkGlobalPlateComment(plateComment);
            if (plateIssue != null) {
                issues.add(plateIssue[0]);
                severityByIssue.put(plateIssue[0], "medium");
            }
            // Xref-summary missing — when xref_count > 5, we expect the
            // plate to mention writers/readers somehow. Heuristic: look
            // for "Set by", "Read by", "Used by", or "Modified by".
            // Medium severity — community treats this as the substance
            // of global doc, but it's not always required for terse globals.
            if (xrefCount > 5) {
                String lowerPlate = plateComment.toLowerCase();
                boolean hasXrefSummary = lowerPlate.contains("set by")
                        || lowerPlate.contains("read by")
                        || lowerPlate.contains("used by")
                        || lowerPlate.contains("modified by")
                        || lowerPlate.contains("written by")
                        || lowerPlate.contains("called by");
                if (!hasXrefSummary) {
                    issues.add("xref_summary_missing");
                    severityByIssue.put("xref_summary_missing", "medium");
                }
            }
            // Bitfield decomposition expected — name pattern signal:
            // descriptors containing Flags/Bits/Mask/State/Mode + integer
            // type → plate should have a Bitfield: section or bit-list.
            if (!typeName.isEmpty() && isIntegerLikeType(typeName)) {
                String lowerName = name.toLowerCase();
                boolean looksBitfieldy = lowerName.contains("flags")
                        || lowerName.contains("bits")
                        || lowerName.contains("mask")
                        || lowerName.contains("state")
                        || lowerName.contains("mode");
                if (looksBitfieldy) {
                    String lowerPlate = plateComment.toLowerCase();
                    boolean hasBitfieldSection = lowerPlate.contains("bitfield")
                            || lowerPlate.contains("0x0001")
                            || lowerPlate.contains("0x01")
                            || lowerPlate.contains("bit ");
                    if (!hasBitfieldSection) {
                        issues.add("bitfield_undocumented");
                        severityByIssue.put("bitfield_undocumented", "medium");
                    }
                }
            }
            // Callback signature missing — pfn-prefixed globals or
            // function-pointer types should have plate text describing
            // the callback signature / call sites.
            boolean isFunctionPointer = name.startsWith("g_pfn")
                    || name.toLowerCase().contains("callback")
                    || (typeName.contains("(*") && typeName.contains(")"));
            if (isFunctionPointer) {
                String lowerPlate = plateComment.toLowerCase();
                boolean hasCallSig = lowerPlate.contains("called by")
                        || lowerPlate.contains("invoked")
                        || lowerPlate.contains("signature")
                        || lowerPlate.contains("callback")
                        || lowerPlate.contains("returns")
                        || lowerPlate.contains("(") /* arg list in plate */;
                if (!hasCallSig) {
                    issues.add("callback_signature_missing");
                    severityByIssue.put("callback_signature_missing", "medium");
                }
            }
            // Plate-line wrap check (soft) — Ghidra's listing column clips
            // pre-comment lines past ~80 chars with a truncation ellipsis,
            // so an unwrapped `Set by: A, B, C, ... 19 names` line displays
            // as `Set by: A, B, C, Pro.` even though the stored text is
            // intact. Reading the plate in the listing (the most common
            // surface) becomes lossy. Surface this as a soft issue so the
            // worker hard-wraps long lines on the next visit; doesn't
            // block completion. Helper + threshold live in
            // NamingConventions so the offline test suite covers them.
            int maxLineLen = NamingConventions.longestPlateLineLength(plateComment);
            if (maxLineLen > NamingConventions.PLATE_LINE_CLIP_THRESHOLD) {
                issues.add("plate_line_too_long");
                severityByIssue.put("plate_line_too_long", "soft");
            }
        }

        // Severity-aware completion check (Q1=A): soft issues never block
        // `fully_documented`. The worker treats anything with no hard +
        // medium issues as "completed", letting it move on while the
        // soft warnings remain visible to a human reviewer. Mirrors the
        // function rubric where structural deductions are forgiven in
        // `effective_score`.
        int hardCount = 0, mediumCount = 0, softCount = 0;
        for (String code : issues) {
            String sev = severityByIssue.get(code);
            if ("hard".equals(sev)) hardCount++;
            else if ("medium".equals(sev)) mediumCount++;
            else if ("soft".equals(sev)) softCount++;
        }
        boolean fullyDocumented = (hardCount == 0 && mediumCount == 0);

        // Applicable-axes hint — tells the worker which axes are
        // semantically relevant for THIS global so the model knows
        // which sections to write in the plate. Helps avoid the
        // "filler N/A" anti-pattern: skip axes flagged false.
        Map<String, Boolean> applicableAxes = new java.util.LinkedHashMap<>();
        applicableAxes.put("xref_summary", xrefCount > 5);
        boolean isIntType = !typeName.isEmpty() && isIntegerLikeType(typeName);
        String lowerName = name.toLowerCase();
        applicableAxes.put("bitfield_decomp",
                isIntType && (lowerName.contains("flags") || lowerName.contains("bits")
                        || lowerName.contains("mask") || lowerName.contains("state")
                        || lowerName.contains("mode")));
        applicableAxes.put("callback_sig",
                name.startsWith("g_pfn") || lowerName.contains("callback")
                        || (typeName.contains("(*") && typeName.contains(")")));
        applicableAxes.put("value_semantics",
                isIntType || (!typeName.isEmpty() && typeName.contains("*")));

        return JsonHelper.mapOf(
                "address", addr.toString(),
                "name", name,
                "type", typeName,
                "length", length,
                "plate_comment", plateComment,
                "xref_count", xrefCount,
                "issues", issues,
                "severity_summary", JsonHelper.mapOf(
                        "hard", hardCount,
                        "medium", mediumCount,
                        "soft", softCount
                ),
                "applicable_axes", applicableAxes,
                "fully_documented", fullyDocumented
        );
    }

    /** Strip g_ + Hungarian prefix off a global name to isolate the
     *  descriptor portion for `generic_descriptor` checking. Returns
     *  null when the name doesn't follow the project convention well
     *  enough to safely identify the descriptor. */
    private static String extractDescriptorPart(String name) {
        if (name == null || !name.startsWith("g_") || name.length() < 4) return null;
        String afterG = name.substring(2);
        // Strip a 1-4 char lowercase Hungarian prefix that ends at the
        // first uppercase letter (where the descriptor starts).
        int i = 0;
        while (i < afterG.length() && i < 5 && Character.isLowerCase(afterG.charAt(i))) {
            i++;
        }
        if (i == 0 || i >= afterG.length()) return null;
        return afterG.substring(i);
    }

    /** Whether {@code typeName} represents an integer-like type that
     *  could plausibly be a bitfield. Used by the bitfield-undocumented
     *  heuristic. */
    private static boolean isIntegerLikeType(String typeName) {
        if (typeName == null || typeName.isEmpty()) return false;
        String t = typeName.toLowerCase();
        return t.equals("uint") || t.equals("int") || t.equals("dword")
                || t.equals("word") || t.equals("ushort") || t.equals("short")
                || t.equals("byte") || t.equals("uchar") || t.equals("char")
                || t.equals("ulong") || t.equals("long")
                || t.equals("uint32_t") || t.equals("int32_t")
                || t.equals("uint16_t") || t.equals("int16_t")
                || t.equals("uint8_t") || t.equals("int8_t");
    }

    /** Static variant of looksLikeUnappliedString — package-visible for the
     * static auditGlobalAt helper to reuse. */
    static boolean looksLikeUnappliedStringAt(Program program, Address addr) {
        try {
            Memory mem = program.getMemory();
            int printable = 0;
            for (int i = 0; i < 64; i++) {
                byte b = mem.getByte(addr.add(i));
                if (b == 0) {
                    return printable >= 4;
                }
                if (b < 0x20 || b > 0x7E) return false;
                printable++;
            }
        } catch (Exception ignored) {
        }
        return false;
    }

    @McpTool(path = "/audit_global", method = "GET",
            description = "Audit a global variable's documentation state. Returns name, type, length, plate comment, xref count, and list of issues. Use this before set_global so you know exactly what's missing.",
            category = "datatype")
    public Response auditGlobal(
            @Param(value = "address", paramType = "address",
                   description = "Address of the global. Accepts 0x<hex> (default space) or <space>:<hex>.") String addressStr,
            @Param(value = "program", description = "Target program name", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        if (addressStr == null || addressStr.isEmpty()) {
            return Response.err("address is required");
        }
        Address addr = ServiceUtils.parseAddress(program, addressStr);
        if (addr == null) return Response.err(ServiceUtils.getLastParseError());

        return Response.ok(auditGlobalAt(program, addr));
    }

    @McpTool(path = "/audit_globals_in_function", method = "GET",
            description = "Audit every global variable referenced from within a function in one call. Walks the function's instructions, collects unique data references, and returns the per-global audit (same shape as audit_global) plus a summary of how many are fully documented vs have issues. The killer per-function pre-flight tool — start every doc pass with this when the function has global xrefs.",
            category = "datatype")
    public Response auditGlobalsInFunction(
            @Param(value = "address", paramType = "address",
                   description = "Address of the function (NOT a global address). Accepts 0x<hex> (default space) or <space>:<hex>.") String addressStr,
            @Param(value = "program", description = "Target program name", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        if (addressStr == null || addressStr.isEmpty()) {
            return Response.err("address is required");
        }
        Address funcAddr = ServiceUtils.parseAddress(program, addressStr);
        if (funcAddr == null) return Response.err(ServiceUtils.getLastParseError());

        Function func = ServiceUtils.resolveFunction(program, addressStr);
        if (func == null) {
            return Response.err("No function found at " + addressStr);
        }

        // Walk instructions, gather unique data-reference targets.
        // Skip targets that resolve to other functions (those are call/jump
        // refs to code, not data globals).
        Listing listing = program.getListing();
        ReferenceManager refMgr = program.getReferenceManager();
        InstructionIterator instrIter = listing.getInstructions(func.getBody(), true);

        Set<Address> globalAddrs = new java.util.LinkedHashSet<>();
        while (instrIter.hasNext()) {
            Instruction instr = instrIter.next();
            for (Reference ref : refMgr.getReferencesFrom(instr.getAddress())) {
                if (ref.getReferenceType().isFlow()) continue;
                if (ref.getReferenceType().isCall()) continue;
                if (ref.getReferenceType().isJump()) continue;
                Address target = ref.getToAddress();
                if (target == null) continue;
                // Skip if the target is a function entry — those are imports
                // / external calls already covered by call refs but with a
                // data-style ref type.
                if (program.getFunctionManager().getFunctionAt(target) != null) continue;
                // Only include targets that live in the program's memory and
                // sit outside the function's own body (locals are stack refs,
                // not globals).
                if (!program.getMemory().contains(target)) continue;
                if (func.getBody().contains(target)) continue;
                globalAddrs.add(target);
            }
        }

        List<Map<String, Object>> globals = new ArrayList<>();
        int fullyDocumented = 0;
        int withIssues = 0;
        Map<String, Integer> issueHistogram = new java.util.LinkedHashMap<>();
        for (Address gAddr : globalAddrs) {
            Map<String, Object> audit = auditGlobalAt(program, gAddr);
            globals.add(audit);
            @SuppressWarnings("unchecked")
            List<String> auditIssues = (List<String>) audit.get("issues");
            if (auditIssues == null || auditIssues.isEmpty()) {
                fullyDocumented++;
            } else {
                withIssues++;
                for (String issue : auditIssues) {
                    issueHistogram.merge(issue, 1, Integer::sum);
                }
            }
        }

        return Response.ok(JsonHelper.mapOf(
                "function", JsonHelper.mapOf(
                        "address", funcAddr.toString(),
                        "name", func.getName()
                ),
                "globals", globals,
                "summary", JsonHelper.mapOf(
                        "total", globalAddrs.size(),
                        "fully_documented", fullyDocumented,
                        "with_issues", withIssues,
                        "issue_histogram", issueHistogram
                )
        ));
    }

    @McpTool(path = "/set_global", method = "POST",
            description = "Atomically apply name + type + plate-comment + array length to a global variable. Single-transaction; rejects on validation failure with no partial write. Replaces the 4-tool chain (apply_data_type → rename_data → batch_set_comments → create_label).",
            category = "datatype")
    public Response setGlobal(
            @Param(value = "address", paramType = "address", source = ParamSource.BODY,
                   description = "Address of the global. Accepts 0x<hex> (default space) or <space>:<hex>.") String addressStr,
            @Param(value = "name", source = ParamSource.BODY,
                   description = "New name. Must follow g_ + Hungarian + descriptor convention (e.g., g_dwActiveQuestState, g_pUnitList).") String newName,
            @Param(value = "type_name", source = ParamSource.BODY,
                   description = "Ghidra data type to apply (e.g., uint, byte, UnitAny *, char *, MyStruct). Use create_struct/create_array_type first if the type doesn't exist. Pass empty to leave type unchanged.") String typeName,
            @Param(value = "array_length", source = ParamSource.BODY, defaultValue = "0",
                   description = "If >0, applied as an array of array_length elements of type_name. Required when documenting an array of fixed length (e.g., a 100-entry data table).") int arrayLength,
            @Param(value = "plate_comment", source = ParamSource.BODY,
                   description = "Plate comment for the address. First line must be a meaningful one-line summary (≥4 words). Optional sectioned details (Used by:, Layout:, Source:, Bitfield:) follow when applicable. Pass empty to leave plate comment unchanged.") String plateComment,
            @Param(value = "program", description = "Target program name", defaultValue = "") String programName,
            @Param(value = "strict_mode", source = ParamSource.BODY, defaultValue = "",
                   description = "Optional per-call override for naming enforcement: 'enforce' / 'warn' / 'off'. Omit to use the project/global setting.")
                    String strictModeArg) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        if (addressStr == null || addressStr.isEmpty()) return Response.err("address is required");
        Address addr = ServiceUtils.parseAddress(program, addressStr);
        if (addr == null) return Response.err(ServiceUtils.getLastParseError());

        try (AutoCloseable scopedMode = NamingPolicy.getInstance().scopedRequestMode(strictModeArg)) {
        // Pre-flight validation. Strict naming enforcement preserves the
        // no-partial-write behavior for name-quality failures; when disabled,
        // the write proceeds and reports the same issue as a warning.
        List<String> enforcementWarnings = new ArrayList<>();
        if (newName != null && !newName.isEmpty()) {
            String typeForCheck = (typeName != null && !typeName.isEmpty()) ? typeName : null;
            // If type isn't being set, fall back to whatever's already at the address.
            if (typeForCheck == null) {
                Data existing = program.getListing().getDefinedDataAt(addr);
                if (existing != null && existing.getDataType() != null) {
                    typeForCheck = existing.getDataType().getName();
                }
            }
            NamingConventions.GlobalNameResult quality =
                    NamingConventions.checkGlobalNameQuality(newName, typeForCheck);
            if (!quality.ok) {
                Map<String, Object> rejection = JsonHelper.mapOf(
                        "status", "rejected",
                        "error", "name_quality",
                        "issue", quality.issue,
                        "rejected_name", newName,
                        "address", addressStr,
                        "message", quality.message,
                        "suggestion", quality.suggestion
                );
                if (NamingPolicy.getInstance().isStrictNamingEnforcement()) {
                    return Response.ok(rejection);
                }
                enforcementWarnings.add(disabledGlobalEnforcementWarning(rejection));
            }
        }

        // Use the shared helper so audit_global and set_global agree on rule.
        String[] plateIssue = NamingConventions.checkGlobalPlateComment(plateComment);
        if (plateIssue != null) {
            return Response.ok(JsonHelper.mapOf(
                    "status", "rejected",
                    "error", plateIssue[0],
                    "first_line", plateIssue[1],
                    "message", "Plate-comment first line must be a >=4-word summary describing what the global represents.",
                    "suggestion", "Replace with a one-liner like 'Bitmap of currently-active quests for the player' or 'Pointer to the head of the linked unit list.'"
            ));
        }

        DataType resolvedType = null;
        if (typeName != null && !typeName.isEmpty()) {
            DataTypeManager dtm = program.getDataTypeManager();
            resolvedType = ServiceUtils.resolveDataType(dtm, typeName);
            if (resolvedType == null) {
                // Build a more actionable suggestion based on the shape of
                // the type the worker passed. Two common patterns hit
                // unknown_type frequently in production logs:
                //   1. Array shorthand baked into type_name ("double[0x100]")
                //      — should be split into type_name="double" + array_length=256.
                //   2. Function-pointer literal ("void (__cdecl **)()")
                //      — needs a typedef created via create_typedef first,
                //      or use a simpler "void *" for opaque pointers.
                String suggestion = "Use create_struct, create_enum, or "
                        + "create_array_type to define the type first; or use an "
                        + "existing builtin (uint, byte, char *, etc.).";
                if (typeName.matches(".+\\[\\s*0?[xX]?[0-9a-fA-F]+\\s*\\]")) {
                    int lb = typeName.indexOf('[');
                    int rb = typeName.indexOf(']', lb);
                    String elemType = typeName.substring(0, lb).trim();
                    String lenStr = typeName.substring(lb + 1, rb).trim();
                    suggestion = "Type '" + typeName + "' looks like an array shorthand. "
                            + "Split it into type_name=\"" + elemType + "\" and "
                            + "array_length=" + lenStr + " (decimal); set_global will "
                            + "build the array for you. The DataTypeManager doesn't "
                            + "store array shorthand as named types.";
                } else if (typeName.contains("(") && typeName.contains(")")
                        && (typeName.contains("*") || typeName.contains("__cdecl")
                            || typeName.contains("__stdcall") || typeName.contains("__fastcall"))) {
                    suggestion = "Type '" + typeName + "' looks like a function-pointer "
                            + "literal. The DataTypeManager doesn't accept inline function "
                            + "signatures; create a named typedef first via "
                            + "create_typedef(name=\"PFnSomething\", base_type=\"void *\") "
                            + "(or a more specific signature via create_function_signature), "
                            + "then pass that name as type_name. For opaque function "
                            + "pointers, \"void *\" is acceptable.";
                }
                return Response.ok(JsonHelper.mapOf(
                        "status", "rejected",
                        "error", "unknown_type",
                        "type_name", typeName,
                        "message", "Type '" + typeName + "' is not in the program's data type manager.",
                        "suggestion", suggestion
                ));
            }
            if (resolvedType.getName().startsWith("undefined")) {
                return Response.ok(JsonHelper.mapOf(
                        "status", "rejected",
                        "error", "undefined_type_rejected",
                        "type_name", typeName,
                        "message", "set_global rejects undefined* types — globals must have a real type.",
                        "suggestion", "Pick a concrete type (uint/byte/ushort for primitives, a struct or pointer-to-struct for composite data)."
                ));
            }
        }

        // Array bounds checks. Arrays without a concrete element type silently
        // dropped before; negatives flipped to zero; overflow on element_size *
        // array_length could exceed the address space. Reject all three up-front
        // so callers get an actionable error instead of a misleading "success".
        if (arrayLength < 0) {
            return Response.ok(JsonHelper.mapOf(
                    "status", "rejected",
                    "error", "invalid_array_length",
                    "array_length", arrayLength,
                    "message", "array_length must be >= 0.",
                    "suggestion", "Pass 0 (or omit) for a single value; pass a positive integer for a fixed-length array."
            ));
        }
        if (arrayLength > 0 && resolvedType == null) {
            return Response.ok(JsonHelper.mapOf(
                    "status", "rejected",
                    "error", "array_length_requires_type",
                    "array_length", arrayLength,
                    "type_name", typeName == null ? "" : typeName,
                    "message", "array_length can only be applied when type_name resolves to a concrete element type.",
                    "suggestion", "Provide a non-empty type_name together with array_length, or omit array_length to leave the existing layout untouched."
            ));
        }
        if (arrayLength > 0 && resolvedType != null) {
            int elementLen = resolvedType.getLength();
            if (elementLen <= 0) {
                return Response.ok(JsonHelper.mapOf(
                        "status", "rejected",
                        "error", "invalid_element_size",
                        "type_name", typeName,
                        "element_length", elementLen,
                        "message", "Element type has non-positive size; cannot form an array.",
                        "suggestion", "Use a sized type (e.g., uint, byte, a fully-defined struct) as the array element."
                ));
            }
            // Overflow guard: element_size * array_length must fit in int and
            // stay within a sane upper bound (16 MiB caps any one global).
            long totalLen = (long) elementLen * arrayLength;
            final int MAX_TOTAL = 16 * 1024 * 1024;
            if (totalLen > MAX_TOTAL) {
                return Response.ok(JsonHelper.mapOf(
                        "status", "rejected",
                        "error", "array_too_large",
                        "array_length", arrayLength,
                        "element_length", elementLen,
                        "total_bytes", totalLen,
                        "max_bytes", MAX_TOTAL,
                        "message", "array_length * element_size exceeds the 16 MiB single-global cap.",
                        "suggestion", "Split into multiple smaller arrays, or increase the cap if this is intentional."
                ));
            }
        }

        // Single transaction: type → array → name → plate comment.
        final List<String> applied = new ArrayList<>();
        final AtomicReference<String> errorMsg = new AtomicReference<>();
        final AtomicBoolean success = new AtomicBoolean(false);
        final DataType finalType = resolvedType;

        try {
            threadingStrategy.executeWrite(program, "set_global at " + addressStr, () -> {
                Listing listing = program.getListing();

                if (finalType != null) {
                    // Clear existing data at the address before re-applying.
                    int totalLen = arrayLength > 0
                            ? finalType.getLength() * arrayLength
                            : finalType.getLength();
                    if (totalLen > 0) {
                        try {
                            listing.clearCodeUnits(addr, addr.add(totalLen - 1), false);
                        } catch (Exception ignored) {
                            // best-effort clear; createData below will surface a real error
                        }
                    }
                    if (arrayLength > 0) {
                        ArrayDataType arrayType = new ArrayDataType(finalType, arrayLength, finalType.getLength());
                        listing.createData(addr, arrayType);
                    } else {
                        listing.createData(addr, finalType);
                    }
                    applied.add("type");
                    if (arrayLength > 0) applied.add("array_length=" + arrayLength);
                }

                if (newName != null && !newName.isEmpty()) {
                    SymbolTable symTable = program.getSymbolTable();
                    Symbol existing = symTable.getPrimarySymbol(addr);
                    if (existing != null) {
                        // Idempotent on name: if the address already has the
                        // requested name, skip setName (Ghidra throws
                        // DuplicateNameException for same-name reassignment).
                        // Workers re-running set_global on a partially-applied
                        // global hit this when the name landed in a previous
                        // attempt but the type or plate comment didn't.
                        if (newName.equals(existing.getName())) {
                            applied.add("name=already_set");
                        } else {
                            existing.setName(newName, SourceType.USER_DEFINED);
                            applied.add("name");
                        }
                    } else {
                        symTable.createLabel(addr, newName, SourceType.USER_DEFINED);
                        applied.add("name");
                    }
                }

                if (plateComment != null && !plateComment.trim().isEmpty()) {
                    listing.setComment(addr, ghidra.program.model.listing.CodeUnit.PLATE_COMMENT, plateComment);
                    applied.add("plate_comment");
                }

                success.set(true);
                return null;
            });
        } catch (Exception e) {
            errorMsg.set(e.getMessage() != null ? e.getMessage() : e.getClass().getName());
            Msg.error(this, "set_global error", e);
        }

        if (success.get()) {
            Map<String, Object> result = JsonHelper.mapOf(
                    "status", "success",
                    "address", addr.toString(),
                    "applied", applied
            );
            if (!enforcementWarnings.isEmpty()) {
                result.put("warnings", enforcementWarnings);
            }
            return Response.ok(result);
        }
        return Response.err(errorMsg.get() != null ? errorMsg.get() : "Unknown failure");
        } catch (Exception e) {
            // try-with-resources close() is declared as throws Exception;
            // re-wrap since the body never raises a checked exception.
            throw new RuntimeException(e);
        }
    }

    private static String disabledGlobalEnforcementWarning(Map<String, Object> rejection) {
        Object issue = rejection.containsKey("issue") ? rejection.get("issue") : rejection.get("error");
        return "Strict naming enforcement disabled: would have rejected "
                + rejection.get("error") + "/" + issue + " - "
                + rejection.get("message");
    }
}
