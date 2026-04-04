package com.xebyte.core;

import java.util.*;

/**
 * Declarative endpoint registry that maps HTTP paths to service method calls.
 * Shared between GUI ({@code GhidraMCPPlugin}) and headless ({@code GhidraMCPHeadlessServer}) modes.
 *
 * <p>Only includes endpoints whose handler logic lives entirely in the service layer.
 * GUI-only endpoints ({@code /get_current_address}, {@code /get_current_function},
 * {@code /get_current_selection}, {@code /tool/*}, {@code /exit_ghidra},
 * {@code /check_connection}, {@code /health}, {@code /get_version}) stay inline.
 *
 * <p>Usage:
 * <pre>{@code
 *   EndpointRegistry registry = new EndpointRegistry(listing, function, ...);
 *   for (EndpointDef ep : registry.getEndpoints()) {
 *       server.createContext(ep.path(), safeHandler(exchange -> {
 *           Map<String,String> q = parseQueryParams(exchange);
 *           Map<String,Object> b = ep.method().equals("POST") ? parseJsonParams(exchange) : Map.of();
 *           String json = ep.handler().handle(q, b).toJson();
 *           sendResponse(exchange, json);
 *       }));
 *   }
 * }</pre>
 */
public class EndpointRegistry {

    private final List<EndpointDef> endpoints = new ArrayList<>();

    // Service references
    private final ListingService listingService;
    private final FunctionService functionService;
    private final CommentService commentService;
    private final SymbolLabelService symbolLabelService;
    private final XrefCallGraphService xrefCallGraphService;
    private final DataTypeService dataTypeService;
    private final AnalysisService analysisService;
    private final DocumentationHashService documentationHashService;
    private final MalwareSecurityService malwareSecurityService;
    private final ProgramScriptService programScriptService;

    public EndpointRegistry(ListingService listingService,
                            FunctionService functionService,
                            CommentService commentService,
                            SymbolLabelService symbolLabelService,
                            XrefCallGraphService xrefCallGraphService,
                            DataTypeService dataTypeService,
                            AnalysisService analysisService,
                            DocumentationHashService documentationHashService,
                            MalwareSecurityService malwareSecurityService,
                            ProgramScriptService programScriptService) {
        this.listingService = listingService;
        this.functionService = functionService;
        this.commentService = commentService;
        this.symbolLabelService = symbolLabelService;
        this.xrefCallGraphService = xrefCallGraphService;
        this.dataTypeService = dataTypeService;
        this.analysisService = analysisService;
        this.documentationHashService = documentationHashService;
        this.malwareSecurityService = malwareSecurityService;
        this.programScriptService = programScriptService;
        registerEndpoints();
    }

    /** Returns an unmodifiable view of all registered endpoints. */
    /** Returns an unmodifiable view of all registered endpoints. */
    public List<EndpointDef> getEndpoints() {
        return Collections.unmodifiableList(endpoints);
    }

    /**
     * Generate a JSON schema string describing all registered endpoints.
     * Used by the {@code /mcp/schema} endpoint for dynamic tool discovery.
     */
    public String generateSchema() {
        StringBuilder sb = new StringBuilder();
        sb.append("{\"tools\": [");
        boolean first = true;
        for (EndpointDef ep : endpoints) {
            if (first) first = false; else sb.append(", ");
            sb.append(ep.schemaJson());
        }
        sb.append("], \"count\": ").append(endpoints.size()).append("}");
        return sb.toString();
    }

    // ======================================================================
    // Registration helpers
    // ======================================================================

    private void get(String path, EndpointDef.EndpointHandler handler) {
        endpoints.add(new EndpointDef(path, "GET", handler));
    }

    private void get(String path, String desc, List<EndpointDef.ParamDef> params,
                     EndpointDef.EndpointHandler handler) {
        endpoints.add(new EndpointDef(path, "GET", handler, desc, params));
    }

    private void post(String path, EndpointDef.EndpointHandler handler) {
        endpoints.add(new EndpointDef(path, "POST", handler));
    }

    private void post(String path, String desc, List<EndpointDef.ParamDef> params,
                      EndpointDef.EndpointHandler handler) {
        endpoints.add(new EndpointDef(path, "POST", handler, desc, params));
    }

    // --- Schema builder helpers ---

    private static List<EndpointDef.ParamDef> params(EndpointDef.ParamDef... defs) {
        return List.of(defs);
    }

    private static EndpointDef.ParamDef qStr(String name, String desc) {
        return new EndpointDef.ParamDef(name, "string", "query", false, null, desc);
    }

    private static EndpointDef.ParamDef qStr(String name) {
        return qStr(name, "");
    }

    private static EndpointDef.ParamDef qInt(String name, int def, String desc) {
        return new EndpointDef.ParamDef(name, "integer", "query", false, String.valueOf(def), desc);
    }

    private static EndpointDef.ParamDef qInt(String name, int def) {
        return qInt(name, def, "");
    }

    private static EndpointDef.ParamDef qBool(String name, boolean def, String desc) {
        return new EndpointDef.ParamDef(name, "boolean", "query", false, String.valueOf(def), desc);
    }

    private static EndpointDef.ParamDef qBool(String name, boolean def) {
        return qBool(name, def, "");
    }

    private static EndpointDef.ParamDef qDbl(String name, double def) {
        return new EndpointDef.ParamDef(name, "number", "query", false, String.valueOf(def), "");
    }

    private static EndpointDef.ParamDef qDbl(String name, double def, String desc) {
        return new EndpointDef.ParamDef(name, "number", "query", false, String.valueOf(def), desc);
    }

    private static EndpointDef.ParamDef qNullInt(String name) {
        return new EndpointDef.ParamDef(name, "integer", "query", false, null, "");
    }

    private static EndpointDef.ParamDef qNullBool(String name) {
        return new EndpointDef.ParamDef(name, "boolean", "query", false, null, "");
    }

    private static EndpointDef.ParamDef bStr(String name, String desc) {
        return new EndpointDef.ParamDef(name, "string", "body", true, null, desc);
    }

    private static EndpointDef.ParamDef bStr(String name) {
        return bStr(name, "");
    }

    private static EndpointDef.ParamDef bStrOpt(String name, String def) {
        return new EndpointDef.ParamDef(name, "string", "body", false, def, "");
    }

    private static EndpointDef.ParamDef bStrOpt(String name) {
        return new EndpointDef.ParamDef(name, "string", "body", false, null, "");
    }

    private static EndpointDef.ParamDef bInt(String name, int def) {
        return new EndpointDef.ParamDef(name, "integer", "body", false, String.valueOf(def), "");
    }

    private static EndpointDef.ParamDef bLong(String name, long def) {
        return new EndpointDef.ParamDef(name, "integer", "body", false, String.valueOf(def), "");
    }

    private static EndpointDef.ParamDef bBool(String name, boolean def) {
        return new EndpointDef.ParamDef(name, "boolean", "body", false, String.valueOf(def), "");
    }

    private static EndpointDef.ParamDef bBool(String name) {
        return new EndpointDef.ParamDef(name, "boolean", "body", false, null, "");
    }

    private static EndpointDef.ParamDef bBoolReq(String name) {
        return new EndpointDef.ParamDef(name, "boolean", "body", true, null, "");
    }

    private static EndpointDef.ParamDef bJson(String name, String desc) {
        return new EndpointDef.ParamDef(name, "json", "body", true, null, desc);
    }

    private static EndpointDef.ParamDef bJson(String name) {
        return bJson(name, "");
    }

    private static EndpointDef.ParamDef bObj(String name, String desc) {
        return new EndpointDef.ParamDef(name, "object", "body", false, null, desc);
    }

    private static EndpointDef.ParamDef bObj(String name) {
        return new EndpointDef.ParamDef(name, "object", "body", false, null, "");
    }

    private static EndpointDef.ParamDef bArr(String name, String desc) {
        return new EndpointDef.ParamDef(name, "array", "body", true, null, desc);
    }

    private static EndpointDef.ParamDef bArr(String name) {
        return new EndpointDef.ParamDef(name, "array", "body", true, null, "");
    }

    // Program param is always from query, always optional
    private static EndpointDef.ParamDef pProg() {
        return new EndpointDef.ParamDef("program", "string", "query", false, null, "Target program name");
    }

    // ======================================================================
    // Parameter extraction — query string (Map<String,String>)
    // ======================================================================

    private static String str(Map<String, String> q, String key) {
        return q.get(key);
    }

    private static String str(Map<String, String> q, String key, String def) {
        return q.getOrDefault(key, def);
    }

    private static int num(Map<String, String> q, String key, int def) {
        String v = q.get(key);
        if (v == null || v.isEmpty()) return def;
        try { return Integer.parseInt(v); } catch (NumberFormatException e) { return def; }
    }

    private static boolean bool(Map<String, String> q, String key) {
        return "true".equalsIgnoreCase(q.get(key));
    }

    private static boolean bool(Map<String, String> q, String key, boolean def) {
        String v = q.get(key);
        if (v == null || v.isEmpty()) return def;
        return "true".equalsIgnoreCase(v);
    }

    private static double dbl(Map<String, String> q, String key, double def) {
        String v = q.get(key);
        if (v == null || v.isEmpty()) return def;
        try { return Double.parseDouble(v); } catch (NumberFormatException e) { return def; }
    }

    private static Integer nullableInt(Map<String, String> q, String key) {
        String v = q.get(key);
        if (v == null || v.isEmpty()) return null;
        try { return Integer.parseInt(v); } catch (NumberFormatException e) { return null; }
    }

    private static Boolean nullableBool(Map<String, String> q, String key) {
        String v = q.get(key);
        if (v == null || v.isEmpty()) return null;
        return Boolean.parseBoolean(v);
    }

    // ======================================================================
    // Parameter extraction — JSON body (Map<String,Object>)
    // ======================================================================

    private static String bodyStr(Map<String, Object> b, String key) {
        Object v = b.get(key);
        return v != null ? String.valueOf(v) : null;
    }

    private static String bodyStr(Map<String, Object> b, String key, String def) {
        Object v = b.get(key);
        return v != null ? String.valueOf(v) : def;
    }

    private static int bodyInt(Map<String, Object> b, String key, int def) {
        return JsonHelper.getInt(b.get(key), def);
    }

    private static long bodyLong(Map<String, Object> b, String key, long def) {
        Object v = b.get(key);
        if (v == null) return def;
        if (v instanceof Number) return ((Number) v).longValue();
        try { return Long.parseLong(String.valueOf(v)); } catch (NumberFormatException e) { return def; }
    }

    private static boolean bodyBool(Map<String, Object> b, String key) {
        return bodyBool(b, key, false);
    }

    private static boolean bodyBool(Map<String, Object> b, String key, boolean def) {
        Object v = b.get(key);
        if (v == null) return def;
        if (v instanceof Boolean bb) return bb;
        return "true".equalsIgnoreCase(String.valueOf(v));
    }

    /**
     * Convert body fields Object to a serialized JSON string for fields/values params.
     * Handles String pass-through, List serialization, and Map serialization.
     */
    private static String bodyFieldsJson(Map<String, Object> b, String key) {
        Object obj = b.get(key);
        if (obj == null) return null;
        if (obj instanceof String s) return s;
        if (obj instanceof List<?> list) return ServiceUtils.serializeListToJson(list);
        if (obj instanceof Map<?, ?> map) return ServiceUtils.serializeMapToJson(map);
        return obj.toString();
    }

    /**
     * Convert body object to a List of Map for batch label/comment operations.
     */
    @SuppressWarnings("unchecked")
    private static List<Map<String, String>> bodyMapList(Map<String, Object> b, String key) {
        return ServiceUtils.convertToMapList(b.get(key));
    }

    /**
     * Extract a Map<String,String> from the body, handling String (JSON parse) or Map.
     */
    @SuppressWarnings("unchecked")
    private static Map<String, String> bodyStringMap(Map<String, Object> b, String key) {
        Object obj = b.get(key);
        if (obj instanceof Map) return (Map<String, String>) obj;
        if (obj instanceof String s) {
            Map<String, String> result = new HashMap<>();
            Map<String, Object> parsed = JsonHelper.parseJson(s);
            parsed.forEach((k, v) -> result.put(k, v != null ? String.valueOf(v) : null));
            return result;
        }
        return new HashMap<>();
    }

    // ======================================================================
    // Endpoint Registration
    // ======================================================================

    private void registerEndpoints() {
        registerListingEndpoints();
        registerFunctionEndpoints();
        registerCommentEndpoints();
        registerSymbolLabelEndpoints();
        registerXrefCallGraphEndpoints();
        registerDataTypeEndpoints();
        registerAnalysisEndpoints();
        registerDocumentationHashEndpoints();
        registerMalwareSecurityEndpoints();
        registerProgramScriptEndpoints();
    }

    // ======================================================================
    // LISTING ENDPOINTS
    // ======================================================================

    private void registerListingEndpoints() {

        get("/list_methods", "List all function names with pagination",
            params(qInt("offset", 0), qInt("limit", 100), pProg()),
            (q, b) -> listingService.getAllFunctionNames(num(q, "offset", 0), num(q, "limit", 100), str(q, "program")));

        get("/list_classes", "List class and namespace names with pagination",
            params(qInt("offset", 0), qInt("limit", 100), pProg()),
            (q, b) -> listingService.getAllClassNames(num(q, "offset", 0), num(q, "limit", 100), str(q, "program")));

        get("/list_segments", "List memory blocks/segments",
            params(qInt("offset", 0), qInt("limit", 100), pProg()),
            (q, b) -> listingService.listSegments(num(q, "offset", 0), num(q, "limit", 100), str(q, "program")));

        get("/list_imports", "List external/imported symbols",
            params(qInt("offset", 0), qInt("limit", 100), pProg()),
            (q, b) -> listingService.listImports(num(q, "offset", 0), num(q, "limit", 100), str(q, "program")));

        get("/list_exports", "List exported entry points",
            params(qInt("offset", 0), qInt("limit", 100), pProg()),
            (q, b) -> listingService.listExports(num(q, "offset", 0), num(q, "limit", 100), str(q, "program")));

        get("/list_namespaces", "List namespace hierarchy",
            params(qInt("offset", 0), qInt("limit", 100), pProg()),
            (q, b) -> listingService.listNamespaces(num(q, "offset", 0), num(q, "limit", 100), str(q, "program")));

        get("/list_data_items", "List defined data items",
            params(qInt("offset", 0), qInt("limit", 100), pProg()),
            (q, b) -> listingService.listDefinedData(num(q, "offset", 0), num(q, "limit", 100), str(q, "program")));

        get("/list_data_items_by_xrefs", "List data items sorted by cross-reference count",
            params(qInt("offset", 0), qInt("limit", 100), qStr("format", "Output format (text or json)"), pProg()),
            (q, b) -> listingService.listDataItemsByXrefs(num(q, "offset", 0), num(q, "limit", 100),
                str(q, "format", "text"), str(q, "program")));

        get("/list_functions", "List all functions (no pagination)",
            params(pProg()),
            (q, b) -> listingService.listFunctions(str(q, "program")));

        get("/list_functions_enhanced", "List functions with thunk/external flags as JSON",
            params(qInt("offset", 0), qInt("limit", 10000), pProg()),
            (q, b) -> listingService.listFunctionsEnhanced(num(q, "offset", 0), num(q, "limit", 10000), str(q, "program")));

        get("/list_calling_conventions", "List available calling conventions",
            params(pProg()),
            (q, b) -> listingService.listCallingConventions(str(q, "program")));

        get("/list_strings", "List defined strings with optional filter",
            params(qInt("offset", 0), qInt("limit", 100), qStr("filter", "Substring filter"), pProg()),
            (q, b) -> listingService.listDefinedStrings(num(q, "offset", 0), num(q, "limit", 100),
                str(q, "filter"), str(q, "program")));

        get("/list_globals", "List global symbols with optional filter",
            params(qInt("offset", 0), qInt("limit", 100), qStr("filter", "Substring filter"), pProg()),
            (q, b) -> listingService.listGlobals(num(q, "offset", 0), num(q, "limit", 100),
                str(q, "filter"), str(q, "program")));

        get("/get_entry_points", "Get program entry points",
            params(pProg()),
            (q, b) -> listingService.getEntryPoints(str(q, "program")));

        get("/get_function_count", "Get total function count",
            params(pProg()),
            (q, b) -> listingService.getFunctionCount(str(q, "program")));

        get("/search_strings", "Search strings by regex pattern",
            params(qStr("search_term", "Regex search pattern"), qInt("min_length", 4), qStr("encoding", "String encoding"), qInt("offset", 0), qInt("limit", 100), pProg()),
            (q, b) -> listingService.searchStrings(str(q, "search_term"), num(q, "min_length", 4),
                str(q, "encoding"), num(q, "offset", 0), num(q, "limit", 100), str(q, "program")));

        get("/list_external_locations", "List external symbol locations",
            params(qInt("offset", 0), qInt("limit", 100), pProg()),
            (q, b) -> listingService.listExternalLocations(num(q, "offset", 0), num(q, "limit", 100), str(q, "program")));

        get("/get_external_location", "Get external location details by address or DLL name",
            params(qStr("address"), qStr("dll_name"), pProg()),
            (q, b) -> listingService.getExternalLocationDetails(str(q, "address"), str(q, "dll_name"), str(q, "program")));

        get("/convert_number", "Convert number between hex/decimal/binary formats",
            params(qStr("text", "Number to convert"), qInt("size", 4, "Size in bytes")),
            (q, b) -> Response.text(ServiceUtils.convertNumber(str(q, "text"), num(q, "size", 4))));

        get("/search_functions", "Search functions by name pattern",
            params(qStr("name_pattern", "Search pattern"), qInt("offset", 0), qInt("limit", 100), pProg()),
            (q, b) -> listingService.searchFunctionsByName(str(q, "name_pattern"), num(q, "offset", 0),
                num(q, "limit", 100), str(q, "program")));
    }

    // ======================================================================
    // FUNCTION ENDPOINTS
    // ======================================================================

    private void registerFunctionEndpoints() {

        get("/get_function_by_address", "Get function info at a specific address",
            params(qStr("address", "Function address in hex"), pProg()),
            (q, b) -> functionService.getFunctionByAddress(str(q, "address"), str(q, "program")));

        get("/decompile_function", "Decompile function at address to pseudocode",
            params(qStr("address", "Function address in hex"), qInt("timeout", 60, "Decompile timeout in seconds"), pProg()),
            (q, b) -> functionService.decompileFunctionByAddress(str(q, "address"), str(q, "program"),
                num(q, "timeout", 60)));

        get("/disassemble_function", "Get assembly listing of function",
            params(qStr("address", "Function address in hex"), pProg()),
            (q, b) -> functionService.disassembleFunction(str(q, "address"), str(q, "program")));

        get("/force_decompile", "Force decompiler cache refresh for function",
            params(qStr("address", "Function address in hex"), pProg()),
            (q, b) -> functionService.forceDecompile(str(q, "address"), str(q, "program")));

        get("/batch_decompile", "Decompile multiple functions at once",
            params(qStr("functions", "Comma-separated function names"), pProg()),
            (q, b) -> functionService.batchDecompileFunctions(str(q, "functions"), str(q, "program")));

        post("/rename_function", "Rename function by old and new name",
            params(bStr("oldName"), bStr("newName"), pProg()),
            (q, b) -> functionService.renameFunction(bodyStr(b, "oldName"), bodyStr(b, "newName"), str(q, "program")));

        post("/rename_function_by_address", "Rename function at specific address",
            params(bStr("function_address"), bStr("new_name"), pProg()),
            (q, b) -> functionService.renameFunctionByAddress(bodyStr(b, "function_address"), bodyStr(b, "new_name"), str(q, "program")));

        post("/rename_variable", "Rename a variable in a function",
            params(bStr("functionName"), bStr("oldName"), bStr("newName"), pProg()),
            (q, b) -> functionService.renameVariableInFunction(bodyStr(b, "functionName"), bodyStr(b, "oldName"),
                bodyStr(b, "newName"), str(q, "program")));

        post("/set_function_prototype", "Set function prototype with calling convention",
            params(bStr("function_address"), bStr("prototype"), bStrOpt("calling_convention"), pProg()),
            (q, b) -> {
            String functionAddress = bodyStr(b, "function_address");
            String prototype = bodyStr(b, "prototype");
            String callingConvention = bodyStr(b, "calling_convention");
            FunctionService.PrototypeResult result = functionService.setFunctionPrototype(
                functionAddress, prototype, callingConvention, str(q, "program"));
            if (result.isSuccess()) {
                String msg = "Successfully set prototype for function at " + functionAddress;
                if (callingConvention != null && !callingConvention.isEmpty()) {
                    msg += " with " + callingConvention + " calling convention";
                }
                if (!result.getErrorMessage().isEmpty()) {
                    msg += "\n\nWarnings/Debug Info:\n" + result.getErrorMessage();
                }
                return Response.text(msg);
            } else {
                return Response.text("Failed to set function prototype: " + result.getErrorMessage());
            }
        });

        post("/set_local_variable_type", "Set the data type of a local variable",
            params(bStr("function_address"), bStr("variable_name"), bStr("new_type"), pProg()),
            (q, b) -> functionService.setLocalVariableType(bodyStr(b, "function_address"),
                bodyStr(b, "variable_name"), bodyStr(b, "new_type"), str(q, "program")));

        post("/set_parameter_type", "Set the data type of a function parameter",
            params(bStr("function_address"), bStr("parameter_name"), bStr("new_type"), pProg()),
            (q, b) -> functionService.setLocalVariableType(bodyStr(b, "function_address"),
                bodyStr(b, "parameter_name"), bodyStr(b, "new_type"), str(q, "program")));

        post("/set_function_no_return", "Mark function as no-return",
            params(bStr("function_address"), bBool("no_return"), pProg()),
            (q, b) -> functionService.setFunctionNoReturn(bodyStr(b, "function_address"),
                bodyBool(b, "no_return"), str(q, "program")));

        post("/clear_instruction_flow_override", "Clear flow override at address",
            params(bStr("address"), pProg()),
            (q, b) -> functionService.clearInstructionFlowOverride(bodyStr(b, "address"), str(q, "program")));

        post("/set_variable_storage", "Set variable storage location",
            params(bStr("function_address"), bStr("variable_name"), bStr("storage"), pProg()),
            (q, b) -> functionService.setVariableStorage(bodyStr(b, "function_address"),
                bodyStr(b, "variable_name"), bodyStr(b, "storage"), str(q, "program")));

        get("/get_function_variables", "List all variables in a function",
            params(qStr("function_name", "Function name"), pProg()),
            (q, b) -> functionService.getFunctionVariables(str(q, "function_name"), str(q, "program"), null, null));

        post("/batch_rename_function_components", "Rename function and components atomically",
            params(bStr("function_address"), bStrOpt("function_name"), bObj("parameter_renames"),
                bObj("local_renames"), bStrOpt("return_type"), pProg()),
            (q, b) -> {
            @SuppressWarnings("unchecked")
            Map<String, String> parameterRenames = b.get("parameter_renames") instanceof Map ?
                (Map<String, String>) b.get("parameter_renames") : null;
            @SuppressWarnings("unchecked")
            Map<String, String> localRenames = b.get("local_renames") instanceof Map ?
                (Map<String, String>) b.get("local_renames") : null;
            return functionService.batchRenameFunctionComponents(
                bodyStr(b, "function_address"), bodyStr(b, "function_name"),
                parameterRenames, localRenames, bodyStr(b, "return_type"), str(q, "program"));
        });

        post("/rename_variables", "Rename multiple variables atomically",
            params(bStr("function_address"), bObj("variable_renames"), bBool("force_individual"), pProg()),
            (q, b) -> functionService.batchRenameVariables(bodyStr(b, "function_address"),
                bodyStringMap(b, "variable_renames"),
                bodyBool(b, "force_individual"), str(q, "program")));

        post("/batch_rename_variables", "Backward-compatible alias for /rename_variables",
            params(bStr("function_address"), bObj("variable_renames"), bBool("force_individual"), pProg()),
            (q, b) -> functionService.batchRenameVariables(bodyStr(b, "function_address"),
                bodyStringMap(b, "variable_renames"),
                bodyBool(b, "force_individual"), str(q, "program")));

        post("/delete_function", "Delete function at address",
            params(bStr("address"), pProg()),
            (q, b) -> functionService.deleteFunctionAtAddress(bodyStr(b, "address"), str(q, "program")));

        post("/create_function", "Create function at address",
            params(bStr("address"), bStrOpt("name"), bBool("disassemble_first"), pProg()),
            (q, b) -> functionService.createFunctionAtAddress(bodyStr(b, "address"), bodyStr(b, "name"),
                bodyBool(b, "disassemble_first", true), str(q, "program")));

        post("/disassemble_bytes", "Disassemble a range of bytes",
            params(bStr("start_address"), bStrOpt("end_address"), bInt("length", 0),
                bBool("restrict_to_execute_memory"), pProg()),
            (q, b) -> {
            Integer length = b.get("length") != null ? JsonHelper.getInt(b.get("length"), 0) : null;
            if (length != null && length == 0) length = null;
            return functionService.disassembleBytes(bodyStr(b, "start_address"), bodyStr(b, "end_address"),
                length, bodyBool(b, "restrict_to_execute_memory", true), str(q, "program"));
        });
    }

    // ======================================================================
    // COMMENT ENDPOINTS
    // ======================================================================

    private void registerCommentEndpoints() {

        post("/set_decompiler_comment", "Set decompiler PRE_COMMENT at address",
            params(bStr("address"), bStr("comment"), pProg()),
            (q, b) -> commentService.setDecompilerComment(bodyStr(b, "address"), bodyStr(b, "comment"), str(q, "program")));

        post("/set_disassembly_comment", "Set disassembly EOL_COMMENT at address",
            params(bStr("address"), bStr("comment"), pProg()),
            (q, b) -> commentService.setDisassemblyComment(bodyStr(b, "address"), bodyStr(b, "comment"), str(q, "program")));

        get("/get_plate_comment", "Get function header/plate comment",
            params(qStr("address", "Function address"), pProg()),
            (q, b) -> commentService.getPlateComment(str(q, "address"), str(q, "program")));

        post("/set_plate_comment", "Set function header/plate comment",
            params(bStr("address"), bStr("comment"), pProg()),
            (q, b) -> commentService.setPlateComment(bodyStr(b, "address"), bodyStr(b, "comment"), str(q, "program")));

        post("/batch_set_comments", "Set multiple comments in one operation",
            params(bStr("address"), bArr("decompiler_comments"), bArr("disassembly_comments"),
                bStrOpt("plate_comment"), pProg()),
            (q, b) -> commentService.batchSetComments(bodyStr(b, "address"),
                bodyMapList(b, "decompiler_comments"), bodyMapList(b, "disassembly_comments"),
                bodyStr(b, "plate_comment"), str(q, "program")));

        post("/clear_function_comments", "Clear all comments within a function",
            params(bStr("address"), bBool("clear_plate"), bBool("clear_pre"), bBool("clear_eol"), pProg()),
            (q, b) -> commentService.clearFunctionComments(bodyStr(b, "address"),
                bodyBool(b, "clear_plate", true), bodyBool(b, "clear_pre", true),
                bodyBool(b, "clear_eol", true), str(q, "program")));
    }

    // ======================================================================
    // SYMBOL / LABEL ENDPOINTS
    // ======================================================================

    private void registerSymbolLabelEndpoints() {

        post("/rename_data", "Rename data at address",
            params(bStr("address"), bStr("newName"), pProg()),
            (q, b) -> symbolLabelService.renameDataAtAddress(bodyStr(b, "address"), bodyStr(b, "newName"), str(q, "program")));

        post("/rename_label", "Rename a label at address",
            params(bStr("address"), bStr("old_name"), bStr("new_name"), pProg()),
            (q, b) -> symbolLabelService.renameLabel(bodyStr(b, "address"), bodyStr(b, "old_name"),
                bodyStr(b, "new_name"), str(q, "program")));

        post("/rename_external_location", "Rename external location",
            params(bStr("address"), bStr("new_name"), pProg()),
            (q, b) -> symbolLabelService.renameExternalLocation(bodyStr(b, "address"), bodyStr(b, "new_name"), str(q, "program")));

        post("/rename_global_variable", "Rename a global variable",
            params(bStr("old_name"), bStr("new_name"), pProg()),
            (q, b) -> symbolLabelService.renameGlobalVariable(bodyStr(b, "old_name"), bodyStr(b, "new_name"), str(q, "program")));

        post("/create_label", "Create a label at address",
            params(bStr("address"), bStr("name"), pProg()),
            (q, b) -> symbolLabelService.createLabel(bodyStr(b, "address"), bodyStr(b, "name"), str(q, "program")));

        post("/batch_create_labels", "Create multiple labels at once",
            params(bArr("labels"), pProg()),
            (q, b) -> symbolLabelService.batchCreateLabels(bodyMapList(b, "labels"), str(q, "program")));

        post("/rename_or_label", "Rename or create label at address",
            params(bStr("address"), bStr("name"), pProg()),
            (q, b) -> symbolLabelService.renameOrLabel(bodyStr(b, "address"), bodyStr(b, "name"), str(q, "program")));

        post("/delete_label", "Delete a label at address",
            params(bStr("address"), bStr("name"), pProg()),
            (q, b) -> symbolLabelService.deleteLabel(bodyStr(b, "address"), bodyStr(b, "name"), str(q, "program")));

        post("/batch_delete_labels", "Delete multiple labels at once",
            params(bArr("labels"), pProg()),
            (q, b) -> symbolLabelService.batchDeleteLabels(bodyMapList(b, "labels"), str(q, "program")));

        get("/can_rename_at_address", "Check if address supports rename",
            params(qStr("address", "Address to check"), pProg()),
            (q, b) -> symbolLabelService.canRenameAtAddress(str(q, "address"), str(q, "program")));

        get("/get_function_labels", "Get labels within a function body",
            params(qStr("name", "Function name"), qInt("offset", 0), qInt("limit", 20), pProg()),
            (q, b) -> symbolLabelService.getFunctionLabels(str(q, "name"), num(q, "offset", 0),
                num(q, "limit", 20), str(q, "program")));
    }

    // ======================================================================
    // XREF / CALL GRAPH ENDPOINTS
    // ======================================================================

    private void registerXrefCallGraphEndpoints() {

        get("/get_xrefs_to", "Get cross-references to an address",
            params(qStr("address", "Target address"), qInt("offset", 0), qInt("limit", 100), pProg()),
            (q, b) -> xrefCallGraphService.getXrefsTo(str(q, "address"), num(q, "offset", 0),
                num(q, "limit", 100), str(q, "program")));

        get("/get_xrefs_from", "Get cross-references from an address",
            params(qStr("address", "Source address"), qInt("offset", 0), qInt("limit", 100), pProg()),
            (q, b) -> xrefCallGraphService.getXrefsFrom(str(q, "address"), num(q, "offset", 0),
                num(q, "limit", 100), str(q, "program")));

        get("/get_function_xrefs", "Get cross-references to a function",
            params(qStr("name", "Function name"), qStr("address", "Function address (alternative to name)"), qInt("offset", 0), qInt("limit", 100), pProg()),
            (q, b) -> xrefCallGraphService.getFunctionXrefs(str(q, "name"), str(q, "address"), num(q, "offset", 0),
                num(q, "limit", 100), str(q, "program")));

        get("/get_function_jump_targets", "Get jump targets within a function",
            params(qStr("name", "Function name"), qStr("address", "Function address (alternative to name)"), qInt("offset", 0), qInt("limit", 100), pProg()),
            (q, b) -> xrefCallGraphService.getFunctionJumpTargets(str(q, "name"), str(q, "address"), num(q, "offset", 0),
                num(q, "limit", 100), str(q, "program")));

        get("/get_function_callees", "Get functions called by a function",
            params(qStr("name", "Function name"), qStr("address", "Function address (alternative to name)"), qInt("offset", 0), qInt("limit", 100), pProg()),
            (q, b) -> xrefCallGraphService.getFunctionCallees(str(q, "name"), str(q, "address"), num(q, "offset", 0),
                num(q, "limit", 100), str(q, "program")));

        get("/get_function_callers", "Get functions calling a function",
            params(qStr("name", "Function name"), qStr("address", "Function address (alternative to name)"), qInt("offset", 0), qInt("limit", 100), pProg()),
            (q, b) -> xrefCallGraphService.getFunctionCallers(str(q, "name"), str(q, "address"), num(q, "offset", 0),
                num(q, "limit", 100), str(q, "program")));

        get("/get_function_call_graph", "Traverse call graph from a function",
            params(qStr("name", "Function name"), qStr("address", "Function address (alternative to name)"),
                qInt("depth", 2, "Traversal depth"),
                qStr("direction", "Traversal direction (both/callers/callees)"), pProg()),
            (q, b) -> xrefCallGraphService.getFunctionCallGraph(str(q, "name"), str(q, "address"), num(q, "depth", 2),
                str(q, "direction", "both"), str(q, "program")));

        get("/get_full_call_graph", "Get entire program call graph",
            params(qStr("format", "Output format (edges or adjacency)"), qInt("limit", 1000), pProg()),
            (q, b) -> xrefCallGraphService.getFullCallGraph(str(q, "format", "edges"),
                num(q, "limit", 1000), str(q, "program")));

        get("/analyze_call_graph", "Analyze call graph paths between functions",
            params(qStr("start_function", "Start function name"), qStr("end_function", "End function name"),
                qStr("analysis_type", "Analysis type (summary/paths/cycles)"), pProg()),
            (q, b) -> xrefCallGraphService.analyzeCallGraph(str(q, "start_function"), str(q, "end_function"),
                str(q, "analysis_type", "summary"), str(q, "program")));

        post("/get_bulk_xrefs", "Batch cross-reference retrieval",
            params(bArr("addresses"), pProg()),
            (q, b) -> xrefCallGraphService.getBulkXrefs(b.get("addresses"), str(q, "program")));

        post("/get_assembly_context", "Get assembly pattern context for xref sources",
            params(bArr("xref_sources"), bInt("context_instructions", 5), bArr("include_patterns"), pProg()),
            (q, b) -> xrefCallGraphService.getAssemblyContext(b.get("xref_sources"),
                bodyInt(b, "context_instructions", 5), b.get("include_patterns"), str(q, "program")));
    }

    // ======================================================================
    // DATA TYPE ENDPOINTS
    // ======================================================================

    private void registerDataTypeEndpoints() {

        get("/list_data_types", "List all data types with optional category filter",
            params(qStr("category", "Category filter"), qInt("offset", 0), qInt("limit", 100), pProg()),
            (q, b) -> dataTypeService.listDataTypes(str(q, "category"), num(q, "offset", 0),
                num(q, "limit", 100), str(q, "program")));

        get("/search_data_types", "Search data types by pattern",
            params(qStr("pattern", "Search pattern"), qInt("offset", 0), qInt("limit", 100), pProg()),
            (q, b) -> dataTypeService.searchDataTypes(str(q, "pattern"), num(q, "offset", 0),
                num(q, "limit", 100), str(q, "program")));

        get("/get_type_size", "Get data type size and info",
            params(qStr("type_name", "Data type name"), pProg()),
            (q, b) -> dataTypeService.getTypeSize(str(q, "type_name"), str(q, "program")));

        get("/get_struct_layout", "Get structure field layout",
            params(qStr("struct_name", "Structure name"), pProg()),
            (q, b) -> dataTypeService.getStructLayout(str(q, "struct_name"), str(q, "program")));

        get("/get_enum_values", "Get enum member values",
            params(qStr("enum_name", "Enum name"), pProg()),
            (q, b) -> dataTypeService.getEnumValues(str(q, "enum_name"), str(q, "program")));

        get("/get_valid_data_types", "List valid Ghidra data type strings",
            params(qStr("category", "Category filter"), pProg()),
            (q, b) -> dataTypeService.getValidDataTypes(str(q, "category"), str(q, "program")));

        get("/validate_data_type_exists", "Check if a data type exists",
            params(qStr("type_name", "Data type name"), pProg()),
            (q, b) -> dataTypeService.validateDataTypeExists(str(q, "type_name"), str(q, "program")));

        get("/validate_data_type", "Validate data type applicability at address",
            params(qStr("address", "Target address"), qStr("type_name", "Data type name"), pProg()),
            (q, b) -> dataTypeService.validateDataType(str(q, "address"), str(q, "type_name"), str(q, "program")));

        get("/validate_function_prototype", "Validate prototype before applying",
            params(qStr("function_address", "Function address"), qStr("prototype", "Function prototype"),
                qStr("calling_convention", "Calling convention"), pProg()),
            (q, b) -> dataTypeService.validateFunctionPrototype(str(q, "function_address"),
                str(q, "prototype"), str(q, "calling_convention"), str(q, "program")));

        get("/list_data_type_categories", "List all data type categories",
            params(qInt("offset", 0), qInt("limit", 100), pProg()),
            (q, b) -> dataTypeService.listDataTypeCategories(num(q, "offset", 0), num(q, "limit", 100), str(q, "program")));

        post("/create_struct", "Create a structure data type",
            params(bStr("name"), bJson("fields"), pProg()),
            (q, b) -> dataTypeService.createStruct(bodyStr(b, "name"), bodyFieldsJson(b, "fields"), str(q, "program")));

        post("/create_enum", "Create an enum data type",
            params(bStr("name"), bJson("values"), bInt("size", 4), pProg()),
            (q, b) -> dataTypeService.createEnum(bodyStr(b, "name"), bodyFieldsJson(b, "values"),
                bodyInt(b, "size", 4), str(q, "program")));

        post("/create_union", "Create a union data type",
            params(bStr("name"), bJson("fields"), pProg()),
            (q, b) -> dataTypeService.createUnion(bodyStr(b, "name"), bodyFieldsJson(b, "fields"), str(q, "program")));

        post("/create_typedef", "Create a typedef alias",
            params(bStr("name"), bStr("base_type"), pProg()),
            (q, b) -> dataTypeService.createTypedef(bodyStr(b, "name"), bodyStr(b, "base_type"), str(q, "program")));

        post("/clone_data_type", "Clone a data type with new name",
            params(bStr("source_type"), bStr("new_name"), pProg()),
            (q, b) -> dataTypeService.cloneDataType(bodyStr(b, "source_type"), bodyStr(b, "new_name"), str(q, "program")));

        post("/create_array_type", "Create an array data type",
            params(bStr("base_type"), bInt("length", 1), bStrOpt("name"), pProg()),
            (q, b) -> dataTypeService.createArrayType(bodyStr(b, "base_type"), bodyInt(b, "length", 1),
                bodyStr(b, "name"), str(q, "program")));

        post("/create_pointer_type", "Create a pointer data type",
            params(bStr("base_type"), bStrOpt("name"), pProg()),
            (q, b) -> dataTypeService.createPointerType(bodyStr(b, "base_type"), bodyStr(b, "name"), str(q, "program")));

        post("/create_function_signature", "Create a function signature data type",
            params(bStr("name"), bStr("return_type"), bStr("parameters"), pProg()),
            (q, b) -> {
            Object parametersObj = b.get("parameters");
            String parametersJson = (parametersObj instanceof String) ? (String) parametersObj :
                                   (parametersObj != null ? parametersObj.toString() : null);
            return dataTypeService.createFunctionSignature(bodyStr(b, "name"), bodyStr(b, "return_type"),
                parametersJson, str(q, "program"));
        });

        post("/apply_data_type", "Apply data type at address",
            params(bStr("address"), bStr("type_name"), bBool("clear_existing"), pProg()),
            (q, b) -> dataTypeService.applyDataType(bodyStr(b, "address"), bodyStr(b, "type_name"),
                bodyBool(b, "clear_existing", true), str(q, "program")));

        post("/delete_data_type", "Delete a data type",
            params(bStr("type_name"), pProg()),
            (q, b) -> dataTypeService.deleteDataType(bodyStr(b, "type_name"), str(q, "program")));

        post("/modify_struct_field", "Modify a field in a structure",
            params(bStr("struct_name"), bStr("field_name"), bStrOpt("new_type"), bStrOpt("new_name"), pProg()),
            (q, b) -> dataTypeService.modifyStructField(bodyStr(b, "struct_name"), bodyStr(b, "field_name"),
                bodyStr(b, "new_type"), bodyStr(b, "new_name"), str(q, "program")));

        post("/add_struct_field", "Add a field to a structure",
            params(bStr("struct_name"), bStr("field_name"), bStr("field_type"), bInt("offset", -1), pProg()),
            (q, b) -> dataTypeService.addStructField(bodyStr(b, "struct_name"), bodyStr(b, "field_name"),
                bodyStr(b, "field_type"), bodyInt(b, "offset", -1), str(q, "program")));

        post("/remove_struct_field", "Remove a field from a structure",
            params(bStr("struct_name"), bStr("field_name"), pProg()),
            (q, b) -> dataTypeService.removeStructField(bodyStr(b, "struct_name"), bodyStr(b, "field_name"), str(q, "program")));

        post("/import_data_types", "Import data types from C source",
            params(bStr("source"), bStr("format")),
            (q, b) -> dataTypeService.importDataTypes(bodyStr(b, "source"), bodyStr(b, "format", "c")));

        post("/create_data_type_category", "Create a new data type category",
            params(bStr("category_path"), pProg()),
            (q, b) -> dataTypeService.createDataTypeCategory(bodyStr(b, "category_path"), str(q, "program")));

        post("/move_data_type_to_category", "Move data type to category",
            params(bStr("type_name"), bStr("category_path"), pProg()),
            (q, b) -> dataTypeService.moveDataTypeToCategory(bodyStr(b, "type_name"), bodyStr(b, "category_path"), str(q, "program")));

        post("/analyze_struct_field_usage", "Analyze structure field access patterns",
            params(bStr("address"), bStr("struct_name"), bInt("max_functions", 10), pProg()),
            (q, b) -> dataTypeService.analyzeStructFieldUsage(bodyStr(b, "address"), bodyStr(b, "struct_name"),
                bodyInt(b, "max_functions", 10), str(q, "program")));

        post("/get_field_access_context", "Get assembly context for struct field offsets",
            params(bStr("struct_address"), bInt("field_offset", 0), bInt("num_examples", 5), pProg()),
            (q, b) -> analysisService.getFieldAccessContext(bodyStr(b, "struct_address"),
                bodyInt(b, "field_offset", 0), bodyInt(b, "num_examples", 5), str(q, "program")));

        post("/suggest_field_names", "AI-assisted field name suggestions",
            params(bStr("struct_address"), bInt("struct_size", 0), pProg()),
            (q, b) -> dataTypeService.suggestFieldNames(bodyStr(b, "struct_address"), bodyInt(b, "struct_size", 0), str(q, "program")));

        post("/apply_data_classification", "Atomic type application with classification",
            params(bStr("address"), bStr("classification"), bStrOpt("name"), bStrOpt("comment"),
                bObj("type_definition"), pProg()),
            (q, b) -> dataTypeService.applyDataClassification(bodyStr(b, "address"), bodyStr(b, "classification"),
                bodyStr(b, "name"), bodyStr(b, "comment"), b.get("type_definition"), str(q, "program")));
    }

    // ======================================================================
    // ANALYSIS ENDPOINTS
    // ======================================================================

    private void registerAnalysisEndpoints() {

        get("/list_analyzers", "List available analyzers",
            params(pProg()),
            (q, b) -> analysisService.listAnalyzers(str(q, "program")));

        post("/run_analysis", "Trigger auto-analysis on program",
            params(bStr("program")),
            (q, b) -> analysisService.runAnalysis(bodyStr(b, "program")));

        post("/analyze_data_region", "Comprehensive data region analysis",
            params(bStr("address"), bInt("max_scan_bytes", 1024), bBool("include_xref_map"),
                bBool("include_assembly_patterns"), bBool("include_boundary_detection"), pProg()),
            (q, b) -> analysisService.analyzeDataRegion(bodyStr(b, "address"),
                bodyInt(b, "max_scan_bytes", 1024),
                bodyBool(b, "include_xref_map", true),
                bodyBool(b, "include_assembly_patterns", true),
                bodyBool(b, "include_boundary_detection", true),
                str(q, "program")));

        post("/detect_array_bounds", "Detect array/table size from context",
            params(bStr("address"), bBool("analyze_loop_bounds"), bBool("analyze_indexing"),
                bInt("max_scan_range", 2048), pProg()),
            (q, b) -> analysisService.detectArrayBounds(bodyStr(b, "address"),
                bodyBool(b, "analyze_loop_bounds", true),
                bodyBool(b, "analyze_indexing", true),
                bodyInt(b, "max_scan_range", 2048),
                str(q, "program")));

        get("/inspect_memory_content", "Inspect memory with string detection",
            params(qStr("address", "Start address"), qInt("length", 64, "Bytes to read"),
                qBool("detect_strings", true, "Auto-detect strings"), pProg()),
            (q, b) -> analysisService.inspectMemoryContent(str(q, "address"), num(q, "length", 64),
                bool(q, "detect_strings", true), str(q, "program")));

        get("/search_byte_patterns", "Search for byte patterns with masks",
            params(qStr("pattern", "Hex byte pattern"), qStr("mask", "Pattern mask"), pProg()),
            (q, b) -> analysisService.searchBytePatterns(str(q, "pattern"), str(q, "mask"), str(q, "program")));

        get("/find_similar_functions", "Find structurally similar functions",
            params(qStr("target_function", "Function name"), qDbl("threshold", 0.8, "Similarity threshold"), pProg()),
            (q, b) -> analysisService.findSimilarFunctions(str(q, "target_function"),
                dbl(q, "threshold", 0.8), str(q, "program")));

        get("/analyze_control_flow", "Analyze function control flow complexity",
            params(qStr("function_name", "Function name"), pProg()),
            (q, b) -> analysisService.analyzeControlFlow(str(q, "function_name"), str(q, "program")));

        get("/find_dead_code", "Identify unreachable code blocks",
            params(qStr("function_name", "Function name"), pProg()),
            (q, b) -> analysisService.findDeadCode(str(q, "function_name"), str(q, "program")));

        get("/analyze_function_completeness", "Check function documentation completeness",
            params(qStr("function_address", "Function address"), qBool("compact", false, "Compact output"), pProg()),
            (q, b) -> analysisService.analyzeFunctionCompleteness(str(q, "function_address"),
                bool(q, "compact"), str(q, "program")));

        get("/analyze_for_documentation", "Composite analysis for RE documentation workflow",
            params(qStr("function_address", "Function address"), pProg()),
            (q, b) -> analysisService.analyzeForDocumentation(str(q, "function_address"), str(q, "program")));

        post("/batch_analyze_completeness", "Analyze completeness for multiple functions",
            params(bArr("addresses"), pProg()),
            (q, b) -> {
            @SuppressWarnings("unchecked")
            List<String> addresses = (List<String>) b.get("addresses");
            if (addresses == null || addresses.isEmpty()) {
                return Response.err("Missing required parameter: addresses (JSON array of hex addresses)");
            }
            StringBuilder sb = new StringBuilder();
            sb.append("{\"results\": [");
            for (int i = 0; i < addresses.size(); i++) {
                if (i > 0) sb.append(", ");
                sb.append(analysisService.analyzeFunctionCompleteness(addresses.get(i)).toJson());
            }
            sb.append("], \"count\": ").append(addresses.size()).append("}");
            return Response.text(sb.toString());
        });

        get("/find_next_undefined_function", "Find next function needing analysis",
            params(qStr("start_address", "Starting address"), qStr("criteria", "Search criteria"),
                qStr("pattern", "Name pattern filter"), qStr("direction", "Search direction"), pProg()),
            (q, b) -> analysisService.findNextUndefinedFunction(str(q, "start_address"), str(q, "criteria"),
                str(q, "pattern"), str(q, "direction"), str(q, "program")));

        get("/find_code_gaps", "Find gaps of undefined bytes between functions in executable memory",
            params(qInt("min_size", 1), qInt("offset", 0), qInt("limit", 100), pProg()),
            (q, b) -> analysisService.findCodeGaps(num(q, "min_size", 1), num(q, "offset", 0),
                num(q, "limit", 100), str(q, "program")));

        get("/analyze_function_complete", "Comprehensive single-call function analysis",
            params(qStr("name", "Function name"), qBool("include_xrefs", true), qBool("include_callees", true),
                qBool("include_callers", true), qBool("include_disasm", true),
                qBool("include_variables", true), pProg()),
            (q, b) -> analysisService.analyzeFunctionComplete(str(q, "name"),
                bool(q, "include_xrefs", true), bool(q, "include_callees", true),
                bool(q, "include_callers", true), bool(q, "include_disasm", true),
                bool(q, "include_variables", true), str(q, "program")));

        get("/search_functions_enhanced", "Advanced function search with filtering",
            params(qStr("name_pattern", "Name pattern"), qNullInt("min_xrefs"), qNullInt("max_xrefs"),
                qStr("calling_convention", "Calling convention filter"), qNullBool("has_custom_name"),
                qBool("regex", false, "Use regex matching"), qStr("sort_by", "Sort field"),
                qInt("offset", 0), qInt("limit", 100), pProg()),
            (q, b) -> analysisService.searchFunctionsEnhanced(str(q, "name_pattern"),
                nullableInt(q, "min_xrefs"), nullableInt(q, "max_xrefs"),
                str(q, "calling_convention"), nullableBool(q, "has_custom_name"),
                bool(q, "regex"), str(q, "sort_by", "address"),
                num(q, "offset", 0), num(q, "limit", 100), str(q, "program")));
    }

    // ======================================================================
    // DOCUMENTATION / HASH ENDPOINTS
    // ======================================================================

    private void registerDocumentationHashEndpoints() {

        get("/get_function_hash", "Compute normalized opcode hash for function",
            params(qStr("address", "Function address"), pProg()),
            (q, b) -> documentationHashService.getFunctionHash(str(q, "address"), str(q, "program")));

        get("/get_bulk_function_hashes", "Get hashes for multiple or all functions",
            params(qInt("offset", 0), qInt("limit", 100), qStr("filter", "Name filter"), pProg()),
            (q, b) -> documentationHashService.getBulkFunctionHashes(num(q, "offset", 0), num(q, "limit", 100),
                str(q, "filter"), str(q, "program")));

        get("/get_function_documentation", "Export all documentation for a function",
            params(qStr("address", "Function address"), pProg()),
            (q, b) -> documentationHashService.getFunctionDocumentation(str(q, "address"), str(q, "program")));

        post("/apply_function_documentation", "Import documentation to a target function",
            params(bStr("json_body"), pProg()),
            (q, b) -> {
            String jsonBody = bodyStr(b, "json_body");
            if (jsonBody == null) {
                jsonBody = JsonHelper.toJson(b);
            }
            return documentationHashService.applyFunctionDocumentation(jsonBody, str(q, "program"));
        });

        get("/compare_programs_documentation", "Compare documented vs undocumented counts",
            params(pProg()),
            (q, b) -> documentationHashService.compareProgramsDocumentation(str(q, "program")));

        get("/find_undocumented_by_string", "Find FUN_* functions referencing a string",
            params(qStr("address", "String address"), pProg()),
            (q, b) -> documentationHashService.findUndocumentedByString(str(q, "address"), str(q, "program")));

        get("/batch_string_anchor_report", "Report of source file strings and their FUN_* functions",
            params(qStr("pattern", "File pattern (e.g. .cpp)"), pProg()),
            (q, b) -> documentationHashService.batchStringAnchorReport(str(q, "pattern", ".cpp"), str(q, "program")));

        get("/get_function_signature", "Get function signature for cross-binary comparison",
            params(qStr("address", "Function address"), pProg()),
            (q, b) -> documentationHashService.handleGetFunctionSignature(str(q, "address"), str(q, "program")));

        get("/find_similar_functions_fuzzy", "Cross-binary fuzzy function matching",
            params(qStr("address", "Function address"), qStr("source_program", "Source program name"),
                qStr("target_program", "Target program name"), qDbl("threshold", 0.7, "Similarity threshold"),
                qInt("limit", 20)),
            (q, b) -> documentationHashService.handleFindSimilarFunctionsFuzzy(str(q, "address"),
                str(q, "source_program"), str(q, "target_program"),
                dbl(q, "threshold", 0.7), num(q, "limit", 20)));

        get("/bulk_fuzzy_match", "Bulk cross-binary function matching",
            params(qStr("source_program", "Source program name"), qStr("target_program", "Target program name"),
                qDbl("threshold", 0.7, "Similarity threshold"), qInt("offset", 0), qInt("limit", 50),
                qStr("filter", "Name filter")),
            (q, b) -> documentationHashService.handleBulkFuzzyMatch(str(q, "source_program"), str(q, "target_program"),
                dbl(q, "threshold", 0.7), num(q, "offset", 0), num(q, "limit", 50), str(q, "filter")));

        get("/diff_functions", "Compute structured diff between two functions",
            params(qStr("address_a", "First function address"), qStr("address_b", "Second function address"),
                qStr("program_a", "First program name"), qStr("program_b", "Second program name")),
            (q, b) -> documentationHashService.handleDiffFunctions(str(q, "address_a"), str(q, "address_b"),
                str(q, "program_a"), str(q, "program_b")));
    }

    // ======================================================================
    // MALWARE / SECURITY ENDPOINTS
    // ======================================================================

    private void registerMalwareSecurityEndpoints() {

        get("/find_anti_analysis_techniques", "Detect anti-analysis and anti-debug techniques",
            params(pProg()),
            (q, b) -> malwareSecurityService.findAntiAnalysisTechniques(str(q, "program")));

        get("/analyze_api_call_chains", "Detect suspicious API call patterns",
            params(pProg()),
            (q, b) -> malwareSecurityService.analyzeAPICallChains(str(q, "program")));

        get("/extract_iocs_with_context", "Enhanced IOC extraction with context",
            params(pProg()),
            (q, b) -> malwareSecurityService.extractIOCsWithContext(str(q, "program")));

        get("/detect_malware_behaviors", "Detect common malware behaviors",
            params(pProg()),
            (q, b) -> malwareSecurityService.detectMalwareBehaviors(str(q, "program")));

        get("/detect_crypto_constants", "Detect crypto algorithm constants",
            params(pProg()),
            (q, b) -> analysisService.detectCryptoConstants(str(q, "program")));
    }

    // ======================================================================
    // PROGRAM / SCRIPT ENDPOINTS
    // ======================================================================

    private void registerProgramScriptEndpoints() {

        get("/get_metadata", "Get program metadata",
            params(pProg()),
            (q, b) -> programScriptService.getMetadata(str(q, "program")));

        get("/save_program", "Save current program",
            params(pProg()),
            (q, b) -> programScriptService.saveCurrentProgram(str(q, "program")));

        get("/list_open_programs", "List all open programs",
            params(),
            (q, b) -> programScriptService.listOpenPrograms());

        get("/get_address_spaces", "List all physical address spaces in the program",
            params(pProg()),
            (q, b) -> programScriptService.getAddressSpaces(str(q, "program")));

        get("/get_current_program_info", "Get detailed info about the active program",
            params(pProg()),
            (q, b) -> programScriptService.getCurrentProgramInfo(str(q, "program")));

        get("/switch_program", "Switch MCP context to a different program",
            params(qStr("program", "Program name to switch to")),
            (q, b) -> programScriptService.switchProgram(str(q, "program")));

        get("/list_project_files", "List files in the current project",
            params(qStr("folder", "Project folder path")),
            (q, b) -> programScriptService.listProjectFiles(str(q, "folder")));

        get("/open_program", "Open a program from the current project",
            params(qStr("path", "Program path in project"), qBool("auto_analyze", false, "Run auto-analysis")),
            (q, b) -> programScriptService.openProgramFromProject(str(q, "path"), bool(q, "auto_analyze")));

        post("/run_script", "Execute a Ghidra script by path",
            params(bStr("script_path"), bStrOpt("args"), pProg()),
            (q, b) -> programScriptService.runGhidraScript(bodyStr(b, "script_path"), bodyStr(b, "args"), str(q, "program")));

        post("/run_script_inline", "Execute inline Ghidra script code",
            params(bStr("code"), bStrOpt("args")),
            (q, b) -> programScriptService.runGhidraScript(bodyStr(b, "code"), bodyStr(b, "args")));

        post("/run_ghidra_script", "Execute script with output capture and timeout",
            params(bStr("script_name"), bStrOpt("args"), bInt("timeout_seconds", 300),
                bBool("capture_output"), pProg()),
            (q, b) -> programScriptService.runGhidraScriptWithCapture(bodyStr(b, "script_name"), bodyStr(b, "args"),
                bodyInt(b, "timeout_seconds", 300), bodyBool(b, "capture_output", true), str(q, "program")));

        get("/list_scripts", "List available Ghidra scripts",
            params(qStr("filter", "Script name filter")),
            (q, b) -> programScriptService.listGhidraScripts(str(q, "filter")));

        get("/read_memory", "Read raw memory bytes",
            params(qStr("address", "Start address"), qInt("length", 16, "Number of bytes"), pProg()),
            (q, b) -> programScriptService.readMemory(str(q, "address"), num(q, "length", 16), str(q, "program")));

        post("/create_memory_block", "Create a new memory block",
            params(bStr("name"), bStr("address"), bLong("size", 0), bBool("read"), bBool("write"),
                bBool("execute"), bBool("volatile"), bStrOpt("comment"), pProg()),
            (q, b) -> programScriptService.createMemoryBlock(bodyStr(b, "name"), bodyStr(b, "address"),
                bodyLong(b, "size", 0),
                bodyBool(b, "read", true), bodyBool(b, "write", true),
                bodyBool(b, "execute", false), bodyBool(b, "volatile", false),
                bodyStr(b, "comment"), str(q, "program")));

        post("/set_bookmark", "Create or update a bookmark",
            params(bStr("address"), bStrOpt("category"), bStrOpt("comment"), pProg()),
            (q, b) -> programScriptService.setBookmark(bodyStr(b, "address"), bodyStr(b, "category"),
                bodyStr(b, "comment"), str(q, "program")));

        get("/list_bookmarks", "List bookmarks with optional filter",
            params(qStr("category", "Category filter"), qStr("address", "Address filter"), pProg()),
            (q, b) -> programScriptService.listBookmarks(str(q, "category"), str(q, "address"), str(q, "program")));

        post("/delete_bookmark", "Delete a bookmark",
            params(bStr("address"), bStrOpt("category"), pProg()),
            (q, b) -> programScriptService.deleteBookmark(bodyStr(b, "address"), bodyStr(b, "category"), str(q, "program")));
    }
}
