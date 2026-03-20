package com.xebyte.core;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.Msg;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Shared static utility methods used by all service classes.
 * All methods are stateless and thread-safe.
 */
public final class ServiceUtils {

    private ServiceUtils() {} // Prevent instantiation

    // ========================================================================
    // JSON Encoding/Decoding
    // ========================================================================

    /**
     * Escape a string for safe inclusion in JSON values.
     * Handles quotes, backslashes, and control characters.
     * @deprecated Use {@link JsonHelper#toJson(Object)} instead — Gson handles escaping automatically.
     */
    @Deprecated
    public static String escapeJson(String str) {
        if (str == null) return "";
        return str.replace("\\", "\\\\")
                  .replace("\"", "\\\"")
                  .replace("\n", "\\n")
                  .replace("\r", "\\r")
                  .replace("\t", "\\t");
    }

    /**
     * Unescape JSON string escape sequences: \n -> newline, \" -> quote, \\ -> backslash, etc.
     */
    public static String unescapeJsonString(String s) {
        if (s == null || s.isEmpty()) return s;
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\\' && i + 1 < s.length()) {
                char next = s.charAt(i + 1);
                switch (next) {
                    case 'n':  sb.append('\n'); i++; break;
                    case 'r':  sb.append('\r'); i++; break;
                    case 't':  sb.append('\t'); i++; break;
                    case '"':  sb.append('"');  i++; break;
                    case '\\': sb.append('\\'); i++; break;
                    case '/':  sb.append('/');  i++; break;
                    case 'u':
                        if (i + 5 < s.length()) {
                            try {
                                int cp = Integer.parseInt(s.substring(i + 2, i + 6), 16);
                                sb.append((char) cp);
                                i += 5;
                            } catch (NumberFormatException e) {
                                sb.append(c);
                            }
                        } else {
                            sb.append(c);
                        }
                        break;
                    default:
                        sb.append(c);
                        break;
                }
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    /**
     * Serialize a List of objects to a JSON array string.
     * @deprecated Use {@link JsonHelper#toJson(Object)} instead.
     */
    @Deprecated
    public static String serializeListToJson(List<?> list) {
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < list.size(); i++) {
            if (i > 0) sb.append(",");
            Object item = list.get(i);
            if (item instanceof String) {
                sb.append("\"").append(escapeJson((String) item)).append("\"");
            } else if (item instanceof Number) {
                sb.append(item);
            } else if (item instanceof Map) {
                sb.append(serializeMapToJson((Map<?, ?>) item));
            } else if (item instanceof List) {
                sb.append(serializeListToJson((List<?>) item));
            } else {
                sb.append("\"").append(escapeJson(item.toString())).append("\"");
            }
        }
        sb.append("]");
        return sb.toString();
    }

    /**
     * Serialize a Map to a JSON object string.
     * @deprecated Use {@link JsonHelper#toJson(Object)} instead.
     */
    @Deprecated
    public static String serializeMapToJson(Map<?, ?> map) {
        StringBuilder sb = new StringBuilder("{");
        boolean first = true;
        for (Map.Entry<?, ?> entry : map.entrySet()) {
            if (!first) sb.append(",");
            first = false;
            sb.append("\"").append(escapeJson(entry.getKey().toString())).append("\":");
            Object value = entry.getValue();
            if (value instanceof String) {
                sb.append("\"").append(escapeJson((String) value)).append("\"");
            } else if (value instanceof Number) {
                sb.append(value);
            } else if (value instanceof Map) {
                sb.append(serializeMapToJson((Map<?, ?>) value));
            } else if (value instanceof List) {
                sb.append(serializeListToJson((List<?>) value));
            } else if (value instanceof Boolean) {
                sb.append(value);
            } else if (value == null) {
                sb.append("null");
            } else {
                sb.append("\"").append(escapeJson(value.toString())).append("\"");
            }
        }
        sb.append("}");
        return sb.toString();
    }

    /**
     * Extract a JSON string value by key using regex.
     */
    public static String extractJsonString(String json, String key) {
        String pattern = "\"" + key + "\"\\s*:\\s*\"([^\"]*)\"";
        Pattern p = Pattern.compile(pattern);
        Matcher m = p.matcher(json);
        if (m.find()) {
            return m.group(1).replace("\\\"", "\"").replace("\\n", "\n");
        }
        // Check for null value
        pattern = "\"" + key + "\"\\s*:\\s*null";
        if (json.matches(".*" + pattern + ".*")) {
            return null;
        }
        return null;
    }

    /**
     * Extract a JSON array as a string by key using bracket matching.
     */
    public static String extractJsonArray(String json, String key) {
        int startIdx = json.indexOf("\"" + key + "\"");
        if (startIdx < 0) return null;

        int arrayStart = json.indexOf('[', startIdx);
        if (arrayStart < 0) return null;

        int depth = 1;
        int arrayEnd = arrayStart + 1;
        while (arrayEnd < json.length() && depth > 0) {
            char c = json.charAt(arrayEnd);
            if (c == '[') depth++;
            else if (c == ']') depth--;
            arrayEnd++;
        }

        return json.substring(arrayStart, arrayEnd);
    }

    // ========================================================================
    // Numeric/Boolean Parsing
    // ========================================================================

    /**
     * Parse an integer from a string, returning defaultValue if null or invalid.
     */
    public static int parseIntOrDefault(String val, int defaultValue) {
        if (val == null) return defaultValue;
        try {
            return Integer.parseInt(val);
        } catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    /**
     * Parse a double from a string, returning defaultValue if null or invalid.
     */
    public static double parseDoubleOrDefault(String val, double defaultValue) {
        if (val == null) return defaultValue;
        try {
            return Double.parseDouble(val);
        } catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    /**
     * Parse a boolean from an Object (Boolean, String, or null), returning defaultValue if unrecognized.
     */
    public static boolean parseBoolOrDefault(Object obj, boolean defaultValue) {
        if (obj == null) return defaultValue;
        if (obj instanceof Boolean) return (Boolean) obj;
        if (obj instanceof String) return Boolean.parseBoolean((String) obj);
        return defaultValue;
    }

    // ========================================================================
    // Collection Utilities
    // ========================================================================

    /**
     * Convert a list of strings into a newline-delimited string, applying offset and limit.
     */
    public static String paginateList(List<String> items, int offset, int limit) {
        int start = Math.max(0, offset);
        int end = Math.min(items.size(), offset + limit);

        if (start >= items.size()) {
            return "";
        }
        List<String> sub = items.subList(start, end);
        return String.join("\n", sub);
    }

    /**
     * Safely downcast a List&lt;Object&gt; to List&lt;Map&lt;String,String&gt;&gt;.
     */
    @SuppressWarnings("unchecked")
    public static List<Map<String, String>> convertToMapList(Object obj) {
        if (obj == null) {
            return null;
        }

        if (obj instanceof List) {
            List<Object> objList = (List<Object>) obj;
            List<Map<String, String>> result = new ArrayList<>();

            for (Object item : objList) {
                if (item instanceof Map) {
                    result.add((Map<String, String>) item);
                }
            }

            return result;
        }

        return null;
    }

    // ========================================================================
    // String Utilities
    // ========================================================================

    /**
     * Escape non-ASCII characters to \\xHH hex notation.
     */
    public static String escapeNonAscii(String input) {
        if (input == null) return "";
        StringBuilder sb = new StringBuilder();
        for (char c : input.toCharArray()) {
            if (c >= 32 && c < 127) {
                sb.append(c);
            } else {
                sb.append("\\x");
                sb.append(Integer.toHexString(c & 0xFF));
            }
        }
        return sb.toString();
    }

    /**
     * Escape special characters in a string for display.
     */
    public static String escapeString(String input) {
        if (input == null) return "";

        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            if (c >= 32 && c < 127) {
                sb.append(c);
            } else if (c == '\n') {
                sb.append("\\n");
            } else if (c == '\r') {
                sb.append("\\r");
            } else if (c == '\t') {
                sb.append("\\t");
            } else {
                sb.append(String.format("\\x%02x", (int) c & 0xFF));
            }
        }
        return sb.toString();
    }

    /**
     * Check if a string meets quality criteria: 4+ chars, 80%+ printable ASCII.
     */
    public static boolean isQualityString(String str) {
        if (str == null || str.length() < 4) {
            return false;
        }

        int printableCount = 0;
        for (int i = 0; i < str.length(); i++) {
            char c = str.charAt(i);
            if ((c >= 32 && c < 127) || c == '\n' || c == '\r' || c == '\t') {
                printableCount++;
            }
        }

        double printableRatio = (double) printableCount / str.length();
        return printableRatio >= 0.80;
    }

    /**
     * Check if a Data item represents string data based on its type name.
     */
    public static boolean isStringData(Data data) {
        if (data == null) return false;

        DataType dt = data.getDataType();
        String typeName = dt.getName().toLowerCase();
        return typeName.contains("string") || typeName.contains("char") || typeName.equals("unicode");
    }

    // ========================================================================
    // Function Utilities
    // ========================================================================

    // ========================================================================
    // Number Conversion
    // ========================================================================

    /**
     * Convert a number to different representations (decimal, hex, binary, octal).
     * Supports hex (0x), binary (0b), octal (0), and decimal input formats.
     *
     * @param text The number string to convert
     * @param size The byte size for masking (1, 2, 4, or 8)
     * @return Formatted string with all representations, or an error message
     */
    public static String convertNumber(String text, int size) {
        if (text == null || text.isEmpty()) {
            return "Error: No number provided";
        }

        try {
            long value;
            String inputType;

            // Determine input format and parse
            if (text.startsWith("0x") || text.startsWith("0X")) {
                value = Long.parseUnsignedLong(text.substring(2), 16);
                inputType = "hexadecimal";
            } else if (text.startsWith("0b") || text.startsWith("0B")) {
                value = Long.parseUnsignedLong(text.substring(2), 2);
                inputType = "binary";
            } else if (text.startsWith("0") && text.length() > 1 && text.matches("0[0-7]+")) {
                value = Long.parseUnsignedLong(text, 8);
                inputType = "octal";
            } else {
                value = Long.parseUnsignedLong(text);
                inputType = "decimal";
            }

            StringBuilder result = new StringBuilder();
            result.append("Input: ").append(text).append(" (").append(inputType).append(")\n");
            result.append("Size: ").append(size).append(" bytes\n\n");

            // Handle different sizes with proper masking
            long mask = (size == 8) ? -1L : (1L << (size * 8)) - 1L;
            long maskedValue = value & mask;

            result.append("Decimal (unsigned): ").append(Long.toUnsignedString(maskedValue)).append("\n");

            // Signed representation for appropriate sizes
            if (size <= 8) {
                long signedValue = maskedValue;
                if (size < 8) {
                    // Sign extend for smaller sizes
                    long signBit = 1L << (size * 8 - 1);
                    if ((maskedValue & signBit) != 0) {
                        signedValue = maskedValue | (~mask);
                    }
                }
                result.append("Decimal (signed): ").append(signedValue).append("\n");
            }

            result.append("Hexadecimal: 0x").append(Long.toHexString(maskedValue).toUpperCase()).append("\n");
            result.append("Binary: 0b").append(Long.toBinaryString(maskedValue)).append("\n");
            result.append("Octal: 0").append(Long.toOctalString(maskedValue)).append("\n");

            // Add size-specific hex representation
            String hexFormat = String.format("%%0%dX", size * 2);
            result.append("Hex (").append(size).append(" bytes): 0x").append(String.format(hexFormat, maskedValue)).append("\n");

            return result.toString();

        } catch (NumberFormatException e) {
            return "Error: Invalid number format: " + text;
        } catch (Exception e) {
            return "Error converting number: " + e.getMessage();
        }
    }

    /**
     * Check if a function name is auto-generated (not user-assigned).
     * Covers FUN_, Ordinal_, and thunk variants of both.
     */
    public static boolean isAutoGeneratedName(String name) {
        return name.startsWith("FUN_") || name.startsWith("Ordinal_") ||
               name.startsWith("thunk_FUN_") || name.startsWith("thunk_Ordinal_");
    }

    /**
     * Get a function at the given address, falling back to the function containing the address.
     */
    public static Function getFunctionForAddress(Program program, Address addr) {
        Function func = program.getFunctionManager().getFunctionAt(addr);
        if (func == null) {
            func = program.getFunctionManager().getFunctionContaining(addr);
        }
        return func;
    }

    /**
     * Resolve a function by either address or name.
     * Resolution order:
     * 1. Try parsing as an address → getFunctionAt → getFunctionContaining
     * 2. If address resolution fails, try exact name match via SymbolTable
     * Returns null if no function is found.
     */
    public static Function resolveFunction(Program program, String functionRef) {
        if (functionRef == null || functionRef.trim().isEmpty()) return null;
        functionRef = functionRef.trim();

        // Try as address first
        try {
            Address addr = program.getAddressFactory().getAddress(functionRef);
            if (addr != null) {
                Function func = getFunctionForAddress(program, addr);
                if (func != null) return func;
            }
        } catch (Exception e) {
            // Not a valid address — fall through to name resolution
        }

        // Try as exact function name via symbol table
        FunctionManager funcManager = program.getFunctionManager();
        SymbolTable symbolTable = program.getSymbolTable();
        SymbolIterator symbols = symbolTable.getSymbols(functionRef);
        while (symbols.hasNext()) {
            Symbol symbol = symbols.next();
            if (symbol.getSymbolType() == SymbolType.FUNCTION) {
                Function func = funcManager.getFunctionAt(symbol.getAddress());
                if (func != null) return func;
            }
        }

        return null;
    }

    // ========================================================================
    // Program Resolution
    // ========================================================================

    /**
     * Generate a JSON error response for when a program cannot be found.
     * @deprecated Use {@link #getProgramOrError(ProgramProvider, String)} instead.
     */
    @Deprecated
    public static String programNotFoundError(String programName) {
        if (programName == null || programName.isEmpty()) {
            return "{\"error\": \"No program is currently open\"}";
        }
        return "{\"error\": \"Program not found: " + escapeJson(programName) + "\"}";
    }

    /**
     * Type-safe result from program resolution.
     * Replaces the Object[] {Program, String} pattern used across all services.
     */
    public record ProgramOrError(Program program, Response error) {
        public boolean hasError() { return program == null; }
    }

    /**
     * Resolve the target program by name, or the current program if name is null/empty.
     * Returns a ProgramOrError with either a valid Program or a Response.Err.
     */
    public static ProgramOrError getProgramOrError(ProgramProvider provider, String programName) {
        Program program = null;
        if (programName != null && !programName.isEmpty()) {
            program = provider.resolveProgram(programName);
        } else {
            program = provider.getCurrentProgram();
        }
        if (program == null) {
            String available = "";
            Program[] all = provider.getAllOpenPrograms();
            if (all != null && all.length > 0) {
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < all.length; i++) {
                    if (i > 0) sb.append(", ");
                    sb.append(all[i].getName());
                }
                available = " Available programs: " + sb;
            }
            String msg = programName != null && !programName.isEmpty()
                    ? "Program not found: " + programName + available
                    : "No program loaded." + available;
            return new ProgramOrError(null, Response.err(msg));
        }
        return new ProgramOrError(program, null);
    }

    // ========================================================================
    // Data Type Resolution
    // ========================================================================

    /**
     * Maps common C type names to Ghidra built-in DataType instances.
     */
    public static DataType resolveWellKnownType(String typeName) {
        switch (typeName.toLowerCase()) {
            case "int":        return IntegerDataType.dataType;
            case "uint":       return UnsignedIntegerDataType.dataType;
            case "short":      return ShortDataType.dataType;
            case "ushort":     return UnsignedShortDataType.dataType;
            case "long":       return LongDataType.dataType;
            case "ulong":      return UnsignedLongDataType.dataType;
            case "longlong":
            case "long long":  return LongLongDataType.dataType;
            case "char":       return CharDataType.dataType;
            case "uchar":      return UnsignedCharDataType.dataType;
            case "float":      return FloatDataType.dataType;
            case "double":     return DoubleDataType.dataType;
            case "bool":
            case "boolean":    return BooleanDataType.dataType;
            case "void":       return VoidDataType.dataType;
            case "byte":       return ByteDataType.dataType;
            case "sbyte":      return SignedByteDataType.dataType;
            case "word":       return WordDataType.dataType;
            case "dword":      return DWordDataType.dataType;
            case "qword":      return QWordDataType.dataType;
            case "int8_t":
            case "int8":       return SignedByteDataType.dataType;
            case "uint8_t":
            case "uint8":      return ByteDataType.dataType;
            case "int16_t":
            case "int16":      return ShortDataType.dataType;
            case "uint16_t":
            case "uint16":     return UnsignedShortDataType.dataType;
            case "int32_t":
            case "int32":      return IntegerDataType.dataType;
            case "uint32_t":
            case "uint32":     return UnsignedIntegerDataType.dataType;
            case "int64_t":
            case "int64":      return LongLongDataType.dataType;
            case "uint64_t":
            case "uint64":     return UnsignedLongLongDataType.dataType;
            case "size_t":     return UnsignedIntegerDataType.dataType;
            case "unsigned int": return UnsignedIntegerDataType.dataType;
            case "unsigned short": return UnsignedShortDataType.dataType;
            case "unsigned long": return UnsignedLongDataType.dataType;
            case "unsigned char": return UnsignedCharDataType.dataType;
            case "signed char": return SignedByteDataType.dataType;
            default:           return null;
        }
    }

    /**
     * Resolves a data type by name, handling common types, pointer types, and array types.
     * @param dtm The data type manager
     * @param typeName The type name to resolve
     * @return The resolved DataType, or null if not found
     */
    public static DataType resolveDataType(DataTypeManager dtm, String typeName) {
        // ZERO: Map common C type names to Ghidra built-in DataType instances
        DataType wellKnown = resolveWellKnownType(typeName);
        if (wellKnown != null) {
            Msg.info(ServiceUtils.class, "Resolved well-known type: " + typeName + " -> " + wellKnown.getName());
            return wellKnown;
        }

        // FIRST: Try Ghidra builtin types in root category
        DataType builtinType = dtm.getDataType("/" + typeName);
        if (builtinType != null) {
            Msg.info(ServiceUtils.class, "Found builtin data type: " + builtinType.getPathName());
            return builtinType;
        }

        // SECOND: Try lowercase version of builtin types
        DataType builtinTypeLower = dtm.getDataType("/" + typeName.toLowerCase());
        if (builtinTypeLower != null) {
            Msg.info(ServiceUtils.class, "Found builtin data type (lowercase): " + builtinTypeLower.getPathName());
            return builtinTypeLower;
        }

        // THIRD: Search all categories as fallback
        DataType dataType = findDataTypeByNameInAllCategories(dtm, typeName);
        if (dataType != null) {
            Msg.info(ServiceUtils.class, "Found data type in categories: " + dataType.getPathName());
            return dataType;
        }

        // Check for array syntax: "type[count]"
        if (typeName.contains("[") && typeName.endsWith("]")) {
            int bracketPos = typeName.indexOf('[');
            String baseTypeName = typeName.substring(0, bracketPos);
            String countStr = typeName.substring(bracketPos + 1, typeName.length() - 1);

            try {
                int count = Integer.parseInt(countStr);
                DataType baseType = resolveDataType(dtm, baseTypeName);

                if (baseType != null && count > 0) {
                    ArrayDataType arrayType = new ArrayDataType(baseType, count, baseType.getLength());
                    Msg.info(ServiceUtils.class, "Auto-created array type: " + typeName +
                            " (base: " + baseType.getName() + ", count: " + count +
                            ", total size: " + arrayType.getLength() + " bytes)");
                    return arrayType;
                } else if (baseType == null) {
                    Msg.error(ServiceUtils.class, "Cannot create array: base type '" + baseTypeName + "' not found");
                    return null;
                }
            } catch (NumberFormatException e) {
                Msg.error(ServiceUtils.class, "Invalid array count in type: " + typeName);
                return null;
            }
        }

        // Check for C-style pointer types (type*)
        if (typeName.endsWith("*")) {
            String baseTypeName = typeName.substring(0, typeName.length() - 1).trim();

            if (baseTypeName.equals("void") || baseTypeName.isEmpty()) {
                Msg.info(ServiceUtils.class, "Creating void* pointer type");
                return new PointerDataType(dtm.getDataType("/void"));
            }

            DataType baseType = resolveDataType(dtm, baseTypeName);
            if (baseType != null) {
                Msg.info(ServiceUtils.class, "Creating pointer type: " + typeName +
                        " (base: " + baseType.getName() + ")");
                return new PointerDataType(baseType);
            }

            Msg.warn(ServiceUtils.class, "Base type not found for " + typeName + ", defaulting to void*");
            return new PointerDataType(dtm.getDataType("/void"));
        }

        // Check for Windows-style pointer types (PXXX)
        if (typeName.startsWith("P") && typeName.length() > 1) {
            String baseTypeName = typeName.substring(1);

            if (baseTypeName.equals("VOID")) {
                return new PointerDataType(dtm.getDataType("/void"));
            }

            DataType baseType = findDataTypeByNameInAllCategories(dtm, baseTypeName);
            if (baseType != null) {
                return new PointerDataType(baseType);
            }

            Msg.warn(ServiceUtils.class, "Base type not found for " + typeName + ", defaulting to void*");
            return new PointerDataType(dtm.getDataType("/void"));
        }

        // Handle common built-in types via DTM path lookup
        switch (typeName.toLowerCase()) {
            case "int":
            case "long":
                return dtm.getDataType("/int");
            case "uint":
            case "unsigned int":
            case "unsigned long":
            case "dword":
                return dtm.getDataType("/uint");
            case "short":
                return dtm.getDataType("/short");
            case "ushort":
            case "unsigned short":
            case "word":
                return dtm.getDataType("/ushort");
            case "char":
            case "byte":
                return dtm.getDataType("/char");
            case "uchar":
            case "unsigned char":
                return dtm.getDataType("/uchar");
            case "longlong":
            case "__int64":
                return dtm.getDataType("/longlong");
            case "ulonglong":
            case "unsigned __int64":
                return dtm.getDataType("/ulonglong");
            case "bool":
            case "boolean":
                return dtm.getDataType("/bool");
            case "float":
                return dtm.getDataType("/dword");
            case "double":
                return dtm.getDataType("/double");
            case "void":
                return dtm.getDataType("/void");
            default:
                DataType directType = dtm.getDataType("/" + typeName);
                if (directType != null) {
                    return directType;
                }
                Msg.error(ServiceUtils.class, "Unknown type: " + typeName);
                return null;
        }
    }

    /**
     * Find a data type by name in all categories/folders of the data type manager.
     */
    public static DataType findDataTypeByNameInAllCategories(DataTypeManager dtm, String typeName) {
        DataType result = searchByNameInAllCategories(dtm, typeName);
        if (result != null) {
            return result;
        }
        return searchByNameInAllCategories(dtm, typeName.toLowerCase());
    }

    /**
     * Search for a data type by name across all categories.
     */
    public static DataType searchByNameInAllCategories(DataTypeManager dtm, String name) {
        Iterator<DataType> allTypes = dtm.getAllDataTypes();
        while (allTypes.hasNext()) {
            DataType dt = allTypes.next();
            if (dt.getName().equals(name)) {
                return dt;
            }
            if (dt.getName().equalsIgnoreCase(name)) {
                return dt;
            }
        }
        return null;
    }
}
