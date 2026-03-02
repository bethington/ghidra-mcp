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
    public List<EndpointDef> getEndpoints() {
        return Collections.unmodifiableList(endpoints);
    }

    // ======================================================================
    // Registration helpers
    // ======================================================================

    private void get(String path, EndpointDef.EndpointHandler handler) {
        endpoints.add(new EndpointDef(path, "GET", handler));
    }

    private void post(String path, EndpointDef.EndpointHandler handler) {
        endpoints.add(new EndpointDef(path, "POST", handler));
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

        // /list_methods — paginated function names
        get("/list_methods", (q, b) ->
            listingService.getAllFunctionNames(num(q, "offset", 0), num(q, "limit", 100), str(q, "program")));

        // /list_classes — paginated class/namespace names
        get("/list_classes", (q, b) ->
            listingService.getAllClassNames(num(q, "offset", 0), num(q, "limit", 100), str(q, "program")));

        // /list_segments — memory block listing
        get("/list_segments", (q, b) ->
            listingService.listSegments(num(q, "offset", 0), num(q, "limit", 100), str(q, "program")));

        // /list_imports — external symbol listing
        get("/list_imports", (q, b) ->
            listingService.listImports(num(q, "offset", 0), num(q, "limit", 100), str(q, "program")));

        // /list_exports — entry point listing
        get("/list_exports", (q, b) ->
            listingService.listExports(num(q, "offset", 0), num(q, "limit", 100), str(q, "program")));

        // /list_namespaces — namespace listing
        get("/list_namespaces", (q, b) ->
            listingService.listNamespaces(num(q, "offset", 0), num(q, "limit", 100), str(q, "program")));

        // /list_data_items — defined data listing
        get("/list_data_items", (q, b) ->
            listingService.listDefinedData(num(q, "offset", 0), num(q, "limit", 100), str(q, "program")));

        // /list_data_items_by_xrefs — data items sorted by reference count
        get("/list_data_items_by_xrefs", (q, b) ->
            listingService.listDataItemsByXrefs(num(q, "offset", 0), num(q, "limit", 100),
                str(q, "format", "text"), str(q, "program")));

        // /list_functions — all functions (no pagination)
        get("/list_functions", (q, b) ->
            listingService.listFunctions(str(q, "program")));

        // /list_functions_enhanced — JSON with thunk/external flags
        get("/list_functions_enhanced", (q, b) ->
            listingService.listFunctionsEnhanced(num(q, "offset", 0), num(q, "limit", 10000), str(q, "program")));

        // /list_calling_conventions — available calling conventions
        get("/list_calling_conventions", (q, b) ->
            listingService.listCallingConventions(str(q, "program")));

        // /list_strings — defined string listing
        get("/list_strings", (q, b) ->
            listingService.listDefinedStrings(num(q, "offset", 0), num(q, "limit", 100),
                str(q, "filter"), str(q, "program")));

        // /list_globals — global symbols
        get("/list_globals", (q, b) ->
            listingService.listGlobals(num(q, "offset", 0), num(q, "limit", 100),
                str(q, "filter"), str(q, "program")));

        // /get_entry_points — program entry points
        get("/get_entry_points", (q, b) ->
            listingService.getEntryPoints(str(q, "program")));

        // /get_function_count — total function count
        get("/get_function_count", (q, b) ->
            listingService.getFunctionCount(str(q, "program")));

        // /search_strings — regex string search
        get("/search_strings", (q, b) ->
            listingService.searchStrings(str(q, "query"), num(q, "min_length", 4),
                str(q, "encoding"), num(q, "offset", 0), num(q, "limit", 100), str(q, "program")));

        // /list_external_locations — external symbol locations
        get("/list_external_locations", (q, b) ->
            listingService.listExternalLocations(num(q, "offset", 0), num(q, "limit", 100), str(q, "program")));

        // /get_external_location — external location details
        get("/get_external_location", (q, b) ->
            listingService.getExternalLocationDetails(str(q, "address"), str(q, "dll_name"), str(q, "program")));

        // /convert_number — number format conversion
        get("/convert_number", (q, b) ->
            Response.text(ServiceUtils.convertNumber(str(q, "text"), num(q, "size", 4))));

        // /search_functions — search functions by name
        get("/search_functions", (q, b) ->
            listingService.searchFunctionsByName(str(q, "query"), num(q, "offset", 0),
                num(q, "limit", 100), str(q, "program")));
    }

    // ======================================================================
    // FUNCTION ENDPOINTS
    // ======================================================================

    private void registerFunctionEndpoints() {

        // /get_function_by_address — get function info at address
        get("/get_function_by_address", (q, b) ->
            functionService.getFunctionByAddress(str(q, "address"), str(q, "program")));

        // /decompile_function — decompile function at address
        get("/decompile_function", (q, b) ->
            functionService.decompileFunctionByAddress(str(q, "address"), str(q, "program"),
                num(q, "timeout", 60)));

        // /disassemble_function — disassemble function at address
        get("/disassemble_function", (q, b) ->
            functionService.disassembleFunction(str(q, "address"), str(q, "program")));

        // /force_decompile — force decompiler cache refresh
        get("/force_decompile", (q, b) ->
            functionService.forceDecompile(str(q, "address"), str(q, "program")));

        // /batch_decompile — decompile multiple functions
        get("/batch_decompile", (q, b) ->
            functionService.batchDecompileFunctions(str(q, "functions"), str(q, "program")));

        // /rename_function — rename function by old/new name (POST, form-encoded)
        post("/rename_function", (q, b) ->
            functionService.renameFunction(bodyStr(b, "oldName"), bodyStr(b, "newName"), str(q, "program")));

        // /rename_function_by_address — rename function at address (POST, form-encoded)
        post("/rename_function_by_address", (q, b) ->
            functionService.renameFunctionByAddress(bodyStr(b, "function_address"), bodyStr(b, "new_name"), str(q, "program")));

        // /rename_variable — rename a variable in a function (POST, form-encoded)
        post("/rename_variable", (q, b) ->
            functionService.renameVariableInFunction(bodyStr(b, "functionName"), bodyStr(b, "oldName"),
                bodyStr(b, "newName"), str(q, "program")));

        // /set_function_prototype — set function prototype with calling convention (POST, JSON)
        post("/set_function_prototype", (q, b) -> {
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

        // /set_local_variable_type — set the type of a local variable (POST, form-encoded)
        post("/set_local_variable_type", (q, b) ->
            functionService.setLocalVariableType(bodyStr(b, "function_address"),
                bodyStr(b, "variable_name"), bodyStr(b, "new_type"), str(q, "program")));

        // /set_function_no_return — mark function as no-return (POST, form-encoded)
        post("/set_function_no_return", (q, b) ->
            functionService.setFunctionNoReturn(bodyStr(b, "function_address"),
                bodyBool(b, "no_return"), str(q, "program")));

        // /clear_instruction_flow_override — clear flow override (POST, form-encoded)
        post("/clear_instruction_flow_override", (q, b) ->
            functionService.clearInstructionFlowOverride(bodyStr(b, "address"), str(q, "program")));

        // /set_variable_storage — set variable storage location (POST, form-encoded)
        post("/set_variable_storage", (q, b) ->
            functionService.setVariableStorage(bodyStr(b, "function_address"),
                bodyStr(b, "variable_name"), bodyStr(b, "storage"), str(q, "program")));

        // /get_function_variables — list all variables in a function
        get("/get_function_variables", (q, b) ->
            functionService.getFunctionVariables(str(q, "function_name"), str(q, "program")));

        // /batch_rename_function_components — rename function and components atomically (POST, JSON)
        post("/batch_rename_function_components", (q, b) -> {
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

        // /batch_rename_variables — rename multiple variables atomically (POST, JSON)
        post("/batch_rename_variables", (q, b) ->
            functionService.batchRenameVariables(bodyStr(b, "function_address"),
                bodyStringMap(b, "variable_renames"),
                bodyBool(b, "force_individual"), str(q, "program")));

        // /delete_function — delete function at address (POST, JSON)
        post("/delete_function", (q, b) ->
            functionService.deleteFunctionAtAddress(bodyStr(b, "address"), str(q, "program")));

        // /create_function — create function at address (POST, JSON)
        post("/create_function", (q, b) ->
            functionService.createFunctionAtAddress(bodyStr(b, "address"), bodyStr(b, "name"),
                bodyBool(b, "disassemble_first", true), str(q, "program")));

        // /disassemble_bytes — disassemble a range of bytes (POST, JSON)
        post("/disassemble_bytes", (q, b) -> {
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

        // /set_decompiler_comment — set PRE_COMMENT at address (POST, form-encoded)
        post("/set_decompiler_comment", (q, b) ->
            commentService.setDecompilerComment(bodyStr(b, "address"), bodyStr(b, "comment"), str(q, "program")));

        // /set_disassembly_comment — set EOL_COMMENT at address (POST, form-encoded)
        post("/set_disassembly_comment", (q, b) ->
            commentService.setDisassemblyComment(bodyStr(b, "address"), bodyStr(b, "comment"), str(q, "program")));

        // /get_plate_comment — get function header/plate comment
        get("/get_plate_comment", (q, b) ->
            commentService.getPlateComment(str(q, "address"), str(q, "program")));

        // /set_plate_comment — set function header/plate comment (POST, form-encoded)
        post("/set_plate_comment", (q, b) ->
            commentService.setPlateComment(bodyStr(b, "function_address"), bodyStr(b, "comment"), str(q, "program")));

        // /batch_set_comments — set multiple comments in one operation (POST, JSON)
        post("/batch_set_comments", (q, b) ->
            commentService.batchSetComments(bodyStr(b, "function_address"),
                bodyMapList(b, "decompiler_comments"), bodyMapList(b, "disassembly_comments"),
                bodyStr(b, "plate_comment"), str(q, "program")));

        // /clear_function_comments — clear all comments within a function (POST, JSON)
        post("/clear_function_comments", (q, b) ->
            commentService.clearFunctionComments(bodyStr(b, "function_address"),
                bodyBool(b, "clear_plate", true), bodyBool(b, "clear_pre", true),
                bodyBool(b, "clear_eol", true), str(q, "program")));
    }

    // ======================================================================
    // SYMBOL / LABEL ENDPOINTS
    // ======================================================================

    private void registerSymbolLabelEndpoints() {

        // /rename_data — rename data at address (POST, form-encoded)
        post("/rename_data", (q, b) ->
            symbolLabelService.renameDataAtAddress(bodyStr(b, "address"), bodyStr(b, "newName"), str(q, "program")));

        // /rename_label — rename a label at address (POST, form-encoded)
        post("/rename_label", (q, b) ->
            symbolLabelService.renameLabel(bodyStr(b, "address"), bodyStr(b, "old_name"),
                bodyStr(b, "new_name"), str(q, "program")));

        // /rename_external_location — rename external location (POST, form-encoded)
        post("/rename_external_location", (q, b) ->
            symbolLabelService.renameExternalLocation(bodyStr(b, "address"), bodyStr(b, "new_name"), str(q, "program")));

        // /rename_global_variable — rename a global variable (POST, form-encoded)
        post("/rename_global_variable", (q, b) ->
            symbolLabelService.renameGlobalVariable(bodyStr(b, "old_name"), bodyStr(b, "new_name"), str(q, "program")));

        // /create_label — create a label at address (POST, form-encoded)
        post("/create_label", (q, b) ->
            symbolLabelService.createLabel(bodyStr(b, "address"), bodyStr(b, "name"), str(q, "program")));

        // /batch_create_labels — create multiple labels (POST, JSON)
        post("/batch_create_labels", (q, b) ->
            symbolLabelService.batchCreateLabels(bodyMapList(b, "labels"), str(q, "program")));

        // /rename_or_label — rename or create label at address (POST, form-encoded)
        post("/rename_or_label", (q, b) ->
            symbolLabelService.renameOrLabel(bodyStr(b, "address"), bodyStr(b, "name"), str(q, "program")));

        // /delete_label — delete a label at address (POST, form-encoded)
        post("/delete_label", (q, b) ->
            symbolLabelService.deleteLabel(bodyStr(b, "address"), bodyStr(b, "name"), str(q, "program")));

        // /batch_delete_labels — delete multiple labels (POST, JSON)
        post("/batch_delete_labels", (q, b) ->
            symbolLabelService.batchDeleteLabels(bodyMapList(b, "labels"), str(q, "program")));

        // /can_rename_at_address — check if address supports rename
        get("/can_rename_at_address", (q, b) ->
            symbolLabelService.canRenameAtAddress(str(q, "address"), str(q, "program")));

        // /get_function_labels — labels within a function body
        get("/get_function_labels", (q, b) ->
            symbolLabelService.getFunctionLabels(str(q, "name"), num(q, "offset", 0),
                num(q, "limit", 20), str(q, "program")));
    }

    // ======================================================================
    // XREF / CALL GRAPH ENDPOINTS
    // ======================================================================

    private void registerXrefCallGraphEndpoints() {

        // /get_xrefs_to — references to an address
        get("/get_xrefs_to", (q, b) ->
            xrefCallGraphService.getXrefsTo(str(q, "address"), num(q, "offset", 0),
                num(q, "limit", 100), str(q, "program")));

        // /get_xrefs_from — references from an address
        get("/get_xrefs_from", (q, b) ->
            xrefCallGraphService.getXrefsFrom(str(q, "address"), num(q, "offset", 0),
                num(q, "limit", 100), str(q, "program")));

        // /get_function_xrefs — references to a function by name
        get("/get_function_xrefs", (q, b) ->
            xrefCallGraphService.getFunctionXrefs(str(q, "name"), num(q, "offset", 0),
                num(q, "limit", 100), str(q, "program")));

        // /get_function_jump_targets — jump targets within a function
        get("/get_function_jump_targets", (q, b) ->
            xrefCallGraphService.getFunctionJumpTargets(str(q, "name"), num(q, "offset", 0),
                num(q, "limit", 100), str(q, "program")));

        // /get_function_callees — functions called by a function
        get("/get_function_callees", (q, b) ->
            xrefCallGraphService.getFunctionCallees(str(q, "name"), num(q, "offset", 0),
                num(q, "limit", 100), str(q, "program")));

        // /get_function_callers — functions calling a function
        get("/get_function_callers", (q, b) ->
            xrefCallGraphService.getFunctionCallers(str(q, "name"), num(q, "offset", 0),
                num(q, "limit", 100), str(q, "program")));

        // /get_function_call_graph — call graph traversal
        get("/get_function_call_graph", (q, b) ->
            xrefCallGraphService.getFunctionCallGraph(str(q, "name"), num(q, "depth", 2),
                str(q, "direction", "both"), str(q, "program")));

        // /get_full_call_graph — entire program call graph
        get("/get_full_call_graph", (q, b) ->
            xrefCallGraphService.getFullCallGraph(str(q, "format", "edges"),
                num(q, "limit", 1000), str(q, "program")));

        // /analyze_call_graph — call graph path analysis
        get("/analyze_call_graph", (q, b) ->
            xrefCallGraphService.analyzeCallGraph(str(q, "start_function"), str(q, "end_function"),
                str(q, "analysis_type", "summary"), str(q, "program")));

        // /get_bulk_xrefs — batch xref retrieval (POST, JSON)
        post("/get_bulk_xrefs", (q, b) ->
            xrefCallGraphService.getBulkXrefs(b.get("addresses"), str(q, "program")));

        // /get_assembly_context — assembly pattern analysis (POST, JSON)
        post("/get_assembly_context", (q, b) ->
            xrefCallGraphService.getAssemblyContext(b.get("xref_sources"),
                bodyInt(b, "context_instructions", 5), b.get("include_patterns"), str(q, "program")));
    }

    // ======================================================================
    // DATA TYPE ENDPOINTS
    // ======================================================================

    private void registerDataTypeEndpoints() {

        // /list_data_types — list all data types with optional category filter
        get("/list_data_types", (q, b) ->
            dataTypeService.listDataTypes(str(q, "category"), num(q, "offset", 0),
                num(q, "limit", 100), str(q, "program")));

        // /search_data_types — search data types by pattern
        get("/search_data_types", (q, b) ->
            dataTypeService.searchDataTypes(str(q, "pattern"), num(q, "offset", 0),
                num(q, "limit", 100), str(q, "program")));

        // /get_type_size — get data type size/info
        get("/get_type_size", (q, b) ->
            dataTypeService.getTypeSize(str(q, "type_name"), str(q, "program")));

        // /get_struct_layout — get structure field layout
        get("/get_struct_layout", (q, b) ->
            dataTypeService.getStructLayout(str(q, "struct_name"), str(q, "program")));

        // /get_enum_values — get enum member values
        get("/get_enum_values", (q, b) ->
            dataTypeService.getEnumValues(str(q, "enum_name"), str(q, "program")));

        // /get_valid_data_types — list valid Ghidra data type strings
        get("/get_valid_data_types", (q, b) ->
            dataTypeService.getValidDataTypes(str(q, "category"), str(q, "program")));

        // /validate_data_type_exists — check if a data type exists
        get("/validate_data_type_exists", (q, b) ->
            dataTypeService.validateDataTypeExists(str(q, "type_name"), str(q, "program")));

        // /validate_data_type — validate data type applicability at address
        get("/validate_data_type", (q, b) ->
            dataTypeService.validateDataType(str(q, "address"), str(q, "type_name"), str(q, "program")));

        // /validate_function_prototype — validate prototype before applying
        get("/validate_function_prototype", (q, b) ->
            dataTypeService.validateFunctionPrototype(str(q, "function_address"),
                str(q, "prototype"), str(q, "calling_convention"), str(q, "program")));

        // /list_data_type_categories — list all data type categories
        get("/list_data_type_categories", (q, b) ->
            dataTypeService.listDataTypeCategories(num(q, "offset", 0), num(q, "limit", 100), str(q, "program")));

        // /create_struct — create a structure data type (POST, JSON)
        post("/create_struct", (q, b) ->
            dataTypeService.createStruct(bodyStr(b, "name"), bodyFieldsJson(b, "fields"), str(q, "program")));

        // /create_enum — create an enum data type (POST, JSON)
        post("/create_enum", (q, b) ->
            dataTypeService.createEnum(bodyStr(b, "name"), bodyFieldsJson(b, "values"),
                bodyInt(b, "size", 4), str(q, "program")));

        // /create_union — create a union data type (POST, JSON)
        post("/create_union", (q, b) ->
            dataTypeService.createUnion(bodyStr(b, "name"), bodyFieldsJson(b, "fields"), str(q, "program")));

        // /create_typedef — create a typedef (POST, JSON)
        post("/create_typedef", (q, b) ->
            dataTypeService.createTypedef(bodyStr(b, "name"), bodyStr(b, "base_type"), str(q, "program")));

        // /clone_data_type — clone a data type with new name (POST, JSON)
        post("/clone_data_type", (q, b) ->
            dataTypeService.cloneDataType(bodyStr(b, "source_type"), bodyStr(b, "new_name"), str(q, "program")));

        // /create_array_type — create an array data type (POST, JSON)
        post("/create_array_type", (q, b) ->
            dataTypeService.createArrayType(bodyStr(b, "base_type"), bodyInt(b, "length", 1),
                bodyStr(b, "name"), str(q, "program")));

        // /create_pointer_type — create a pointer data type (POST, form-encoded)
        post("/create_pointer_type", (q, b) ->
            dataTypeService.createPointerType(bodyStr(b, "base_type"), bodyStr(b, "name"), str(q, "program")));

        // /create_function_signature — create a function signature data type (POST, JSON)
        post("/create_function_signature", (q, b) -> {
            Object parametersObj = b.get("parameters");
            String parametersJson = (parametersObj instanceof String) ? (String) parametersObj :
                                   (parametersObj != null ? parametersObj.toString() : null);
            return dataTypeService.createFunctionSignature(bodyStr(b, "name"), bodyStr(b, "return_type"),
                parametersJson, str(q, "program"));
        });

        // /apply_data_type — apply data type at address (POST, JSON)
        post("/apply_data_type", (q, b) ->
            dataTypeService.applyDataType(bodyStr(b, "address"), bodyStr(b, "type_name"),
                bodyBool(b, "clear_existing", true), str(q, "program")));

        // /delete_data_type — delete a data type (POST, JSON)
        post("/delete_data_type", (q, b) ->
            dataTypeService.deleteDataType(bodyStr(b, "type_name"), str(q, "program")));

        // /modify_struct_field — modify a field in a structure (POST, JSON)
        post("/modify_struct_field", (q, b) ->
            dataTypeService.modifyStructField(bodyStr(b, "struct_name"), bodyStr(b, "field_name"),
                bodyStr(b, "new_type"), bodyStr(b, "new_name"), str(q, "program")));

        // /add_struct_field — add a field to a structure (POST, JSON)
        post("/add_struct_field", (q, b) ->
            dataTypeService.addStructField(bodyStr(b, "struct_name"), bodyStr(b, "field_name"),
                bodyStr(b, "field_type"), bodyInt(b, "offset", -1), str(q, "program")));

        // /remove_struct_field — remove a field from a structure (POST, JSON)
        post("/remove_struct_field", (q, b) ->
            dataTypeService.removeStructField(bodyStr(b, "struct_name"), bodyStr(b, "field_name"), str(q, "program")));

        // /import_data_types — import data types from source (POST, JSON)
        post("/import_data_types", (q, b) ->
            dataTypeService.importDataTypes(bodyStr(b, "source"), bodyStr(b, "format", "c")));

        // /create_data_type_category — create a new data type category (POST, form-encoded)
        post("/create_data_type_category", (q, b) ->
            dataTypeService.createDataTypeCategory(bodyStr(b, "category_path"), str(q, "program")));

        // /move_data_type_to_category — move data type to category (POST, form-encoded)
        post("/move_data_type_to_category", (q, b) ->
            dataTypeService.moveDataTypeToCategory(bodyStr(b, "type_name"), bodyStr(b, "category_path"), str(q, "program")));

        // /analyze_struct_field_usage — analyze structure field access patterns (POST, JSON)
        post("/analyze_struct_field_usage", (q, b) ->
            dataTypeService.analyzeStructFieldUsage(bodyStr(b, "address"), bodyStr(b, "struct_name"),
                bodyInt(b, "max_functions", 10), str(q, "program")));

        // /get_field_access_context — assembly/decompilation context for field offsets (POST, JSON)
        post("/get_field_access_context", (q, b) ->
            analysisService.getFieldAccessContext(bodyStr(b, "struct_address"),
                bodyInt(b, "field_offset", 0), bodyInt(b, "num_examples", 5), str(q, "program")));

        // /suggest_field_names — AI-assisted field name suggestions (POST, JSON)
        post("/suggest_field_names", (q, b) ->
            dataTypeService.suggestFieldNames(bodyStr(b, "struct_address"), bodyInt(b, "struct_size", 0), str(q, "program")));

        // /apply_data_classification — atomic type application (POST, JSON)
        post("/apply_data_classification", (q, b) ->
            dataTypeService.applyDataClassification(bodyStr(b, "address"), bodyStr(b, "classification"),
                bodyStr(b, "name"), bodyStr(b, "comment"), b.get("type_definition"), str(q, "program")));
    }

    // ======================================================================
    // ANALYSIS ENDPOINTS
    // ======================================================================

    private void registerAnalysisEndpoints() {

        // /list_analyzers — list available analyzers
        get("/list_analyzers", (q, b) ->
            analysisService.listAnalyzers(str(q, "program")));

        // /run_analysis — trigger auto-analysis (POST, form-encoded)
        post("/run_analysis", (q, b) ->
            analysisService.runAnalysis(bodyStr(b, "program")));

        // /analyze_data_region — comprehensive data region analysis (POST, JSON)
        post("/analyze_data_region", (q, b) ->
            analysisService.analyzeDataRegion(bodyStr(b, "address"),
                bodyInt(b, "max_scan_bytes", 1024),
                bodyBool(b, "include_xref_map", true),
                bodyBool(b, "include_assembly_patterns", true),
                bodyBool(b, "include_boundary_detection", true),
                str(q, "program")));

        // /detect_array_bounds — array/table size detection (POST, JSON)
        post("/detect_array_bounds", (q, b) ->
            analysisService.detectArrayBounds(bodyStr(b, "address"),
                bodyBool(b, "analyze_loop_bounds", true),
                bodyBool(b, "analyze_indexing", true),
                bodyInt(b, "max_scan_range", 2048),
                str(q, "program")));

        // /inspect_memory_content — memory inspection with string detection
        get("/inspect_memory_content", (q, b) ->
            analysisService.inspectMemoryContent(str(q, "address"), num(q, "length", 64),
                bool(q, "detect_strings", true), str(q, "program")));

        // /search_byte_patterns — search for byte patterns with masks
        get("/search_byte_patterns", (q, b) ->
            analysisService.searchBytePatterns(str(q, "pattern"), str(q, "mask"), str(q, "program")));

        // /find_similar_functions — find structurally similar functions
        get("/find_similar_functions", (q, b) ->
            analysisService.findSimilarFunctions(str(q, "target_function"),
                dbl(q, "threshold", 0.8), str(q, "program")));

        // /analyze_control_flow — function control flow complexity analysis
        get("/analyze_control_flow", (q, b) ->
            analysisService.analyzeControlFlow(str(q, "function_name"), str(q, "program")));

        // /find_dead_code — identify unreachable code blocks
        get("/find_dead_code", (q, b) ->
            analysisService.findDeadCode(str(q, "function_name"), str(q, "program")));

        // /analyze_function_completeness — check function documentation completeness
        get("/analyze_function_completeness", (q, b) ->
            analysisService.analyzeFunctionCompleteness(str(q, "function_address"),
                bool(q, "compact"), str(q, "program")));

        // /analyze_for_documentation — composite endpoint for RE documentation workflow
        get("/analyze_for_documentation", (q, b) ->
            analysisService.analyzeForDocumentation(str(q, "function_address"), str(q, "program")));

        // /batch_analyze_completeness — analyze completeness for multiple functions (POST, JSON)
        post("/batch_analyze_completeness", (q, b) -> {
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

        // /find_next_undefined_function — find next function needing analysis
        get("/find_next_undefined_function", (q, b) ->
            analysisService.findNextUndefinedFunction(str(q, "start_address"), str(q, "criteria"),
                str(q, "pattern"), str(q, "direction"), str(q, "program")));

        // /analyze_function_complete — comprehensive single-call analysis
        get("/analyze_function_complete", (q, b) ->
            analysisService.analyzeFunctionComplete(str(q, "name"),
                bool(q, "include_xrefs", true), bool(q, "include_callees", true),
                bool(q, "include_callers", true), bool(q, "include_disasm", true),
                bool(q, "include_variables", true), str(q, "program")));

        // /search_functions_enhanced — advanced search with filtering
        get("/search_functions_enhanced", (q, b) ->
            analysisService.searchFunctionsEnhanced(str(q, "name_pattern"),
                nullableInt(q, "min_xrefs"), nullableInt(q, "max_xrefs"),
                str(q, "calling_convention"), nullableBool(q, "has_custom_name"),
                bool(q, "regex"), str(q, "sort_by", "address"),
                num(q, "offset", 0), num(q, "limit", 100), str(q, "program")));
    }

    // ======================================================================
    // DOCUMENTATION / HASH ENDPOINTS
    // ======================================================================

    private void registerDocumentationHashEndpoints() {

        // /get_function_hash — compute normalized opcode hash
        get("/get_function_hash", (q, b) ->
            documentationHashService.getFunctionHash(str(q, "address"), str(q, "program")));

        // /get_bulk_function_hashes — get hashes for multiple/all functions
        get("/get_bulk_function_hashes", (q, b) ->
            documentationHashService.getBulkFunctionHashes(num(q, "offset", 0), num(q, "limit", 100),
                str(q, "filter"), str(q, "program")));

        // /get_function_documentation — export all documentation for a function
        get("/get_function_documentation", (q, b) ->
            documentationHashService.getFunctionDocumentation(str(q, "address"), str(q, "program")));

        // /apply_function_documentation — import documentation to a target function (POST, raw body)
        // NOTE: This endpoint reads the raw request body as JSON text.
        // The registry handler will receive the body as a Map, so callers must pass the
        // raw JSON string via bodyStr(b, "json_body") or reconstruct it.
        post("/apply_function_documentation", (q, b) -> {
            String jsonBody = bodyStr(b, "json_body");
            if (jsonBody == null) {
                // Fallback: re-serialize the body map to JSON for callers that pass structured data
                jsonBody = JsonHelper.toJson(b);
            }
            return documentationHashService.applyFunctionDocumentation(jsonBody, str(q, "program"));
        });

        // /compare_programs_documentation — compare documented vs undocumented counts
        get("/compare_programs_documentation", (q, b) ->
            documentationHashService.compareProgramsDocumentation(str(q, "program")));

        // /find_undocumented_by_string — find FUN_* functions referencing a string
        get("/find_undocumented_by_string", (q, b) ->
            documentationHashService.findUndocumentedByString(str(q, "address"), str(q, "program")));

        // /batch_string_anchor_report — report of source file strings and their FUN_* functions
        get("/batch_string_anchor_report", (q, b) ->
            documentationHashService.batchStringAnchorReport(str(q, "pattern", ".cpp"), str(q, "program")));

        // /get_function_signature — get function signature for cross-binary comparison
        get("/get_function_signature", (q, b) ->
            documentationHashService.handleGetFunctionSignature(str(q, "address"), str(q, "program")));

        // /find_similar_functions_fuzzy — cross-binary fuzzy function matching
        get("/find_similar_functions_fuzzy", (q, b) ->
            documentationHashService.handleFindSimilarFunctionsFuzzy(str(q, "address"),
                str(q, "source_program"), str(q, "target_program"),
                dbl(q, "threshold", 0.7), num(q, "limit", 20)));

        // /bulk_fuzzy_match — bulk cross-binary function matching
        get("/bulk_fuzzy_match", (q, b) ->
            documentationHashService.handleBulkFuzzyMatch(str(q, "source_program"), str(q, "target_program"),
                dbl(q, "threshold", 0.7), num(q, "offset", 0), num(q, "limit", 50), str(q, "filter")));

        // /diff_functions — compute structured diff between two functions
        get("/diff_functions", (q, b) ->
            documentationHashService.handleDiffFunctions(str(q, "address_a"), str(q, "address_b"),
                str(q, "program_a"), str(q, "program_b")));
    }

    // ======================================================================
    // MALWARE / SECURITY ENDPOINTS
    // ======================================================================

    private void registerMalwareSecurityEndpoints() {

        // /find_anti_analysis_techniques — detect anti-analysis/anti-debug techniques
        get("/find_anti_analysis_techniques", (q, b) ->
            malwareSecurityService.findAntiAnalysisTechniques(str(q, "program")));

        // /analyze_api_call_chains — detect suspicious API call patterns
        get("/analyze_api_call_chains", (q, b) ->
            malwareSecurityService.analyzeAPICallChains(str(q, "program")));

        // /extract_iocs_with_context — enhanced IOC extraction with context
        get("/extract_iocs_with_context", (q, b) ->
            malwareSecurityService.extractIOCsWithContext(str(q, "program")));

        // /detect_malware_behaviors — detect common malware behaviors
        get("/detect_malware_behaviors", (q, b) ->
            malwareSecurityService.detectMalwareBehaviors(str(q, "program")));

        // /detect_crypto_constants — detect crypto algorithm constants
        get("/detect_crypto_constants", (q, b) ->
            analysisService.detectCryptoConstants(str(q, "program")));
    }

    // ======================================================================
    // PROGRAM / SCRIPT ENDPOINTS
    // ======================================================================

    private void registerProgramScriptEndpoints() {

        // /get_metadata — program metadata
        get("/get_metadata", (q, b) ->
            programScriptService.getMetadata(str(q, "program")));

        // /save_program — save current program
        get("/save_program", (q, b) ->
            programScriptService.saveCurrentProgram(str(q, "program")));

        // /list_open_programs — list all open programs
        get("/list_open_programs", (q, b) ->
            programScriptService.listOpenPrograms());

        // /get_current_program_info — detailed info about the active program
        get("/get_current_program_info", (q, b) ->
            programScriptService.getCurrentProgramInfo(str(q, "program")));

        // /switch_program — switch MCP context to a different program
        get("/switch_program", (q, b) ->
            programScriptService.switchProgram(str(q, "name")));

        // /list_project_files — list files in the current project
        get("/list_project_files", (q, b) ->
            programScriptService.listProjectFiles(str(q, "folder")));

        // /open_program — open a program from the current project
        get("/open_program", (q, b) ->
            programScriptService.openProgramFromProject(str(q, "path"), bool(q, "auto_analyze")));

        // /run_script — execute a Ghidra script (POST, form-encoded)
        post("/run_script", (q, b) ->
            programScriptService.runGhidraScript(bodyStr(b, "script_path"), bodyStr(b, "args"), str(q, "program")));

        // /run_script_inline — execute inline Ghidra script code (POST, JSON)
        // NOTE: This endpoint has special class-rewriting logic that stays inline in the plugin.
        // The registry version delegates to ProgramScriptService which may not have
        // the same OSGi class-name rewriting. Callers should verify behavior.
        post("/run_script_inline", (q, b) ->
            programScriptService.runGhidraScript(bodyStr(b, "code"), bodyStr(b, "args")));

        // /run_ghidra_script — execute script with capture and timeout (POST, JSON)
        post("/run_ghidra_script", (q, b) ->
            programScriptService.runGhidraScriptWithCapture(bodyStr(b, "script_name"), bodyStr(b, "args"),
                bodyInt(b, "timeout_seconds", 300), bodyBool(b, "capture_output", true), str(q, "program")));

        // /list_scripts — list available Ghidra scripts
        get("/list_scripts", (q, b) ->
            programScriptService.listGhidraScripts(str(q, "filter")));

        // /read_memory — read raw memory bytes
        get("/read_memory", (q, b) ->
            programScriptService.readMemory(str(q, "address"), num(q, "length", 16), str(q, "program")));

        // /create_memory_block — create a new memory block (POST, JSON)
        post("/create_memory_block", (q, b) ->
            programScriptService.createMemoryBlock(bodyStr(b, "name"), bodyStr(b, "address"),
                bodyLong(b, "size", 0),
                bodyBool(b, "read", true), bodyBool(b, "write", true),
                bodyBool(b, "execute", false), bodyBool(b, "volatile", false),
                bodyStr(b, "comment"), str(q, "program")));

        // /set_bookmark — create or update a bookmark (POST, JSON)
        post("/set_bookmark", (q, b) ->
            programScriptService.setBookmark(bodyStr(b, "address"), bodyStr(b, "category"),
                bodyStr(b, "comment"), str(q, "program")));

        // /list_bookmarks — list bookmarks, optionally filtered
        get("/list_bookmarks", (q, b) ->
            programScriptService.listBookmarks(str(q, "category"), str(q, "address"), str(q, "program")));

        // /delete_bookmark — delete a bookmark (POST, JSON)
        post("/delete_bookmark", (q, b) ->
            programScriptService.deleteBookmark(bodyStr(b, "address"), bodyStr(b, "category"), str(q, "program")));
    }
}
