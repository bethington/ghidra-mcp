package com.xebyte.core;

import com.google.gson.JsonObject;
import com.xebyte.VersionInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.services.CodeViewerService;
import ghidra.app.services.ProgramManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.data.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import com.xebyte.core.services.CommentService;
import com.xebyte.core.services.FunctionService;
import com.xebyte.core.services.ListingService;
import com.xebyte.core.services.AnalysisService;
import com.xebyte.core.services.ComparisonService;
import com.xebyte.core.services.DataTypeService;
import com.xebyte.core.services.MutationService;
import com.xebyte.core.services.SymbolService;
import com.sun.net.httpserver.Headers;
import javax.swing.SwingUtilities;
import java.io.*;
import java.lang.reflect.InvocationTargetException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Pattern;
import java.util.function.Supplier;

/**
 * Owns all HTTP endpoint registrations and handler methods.
 * Created by ServerManager; has no lifecycle logic of its own.
 */
public class EndpointRouter {

    private final MultiToolProgramProvider programProvider;
    private final Supplier<PluginTool> activeToolSupplier;
    private final ListingService listingService;
    private final CommentService commentService;
    private final SymbolService symbolService;
    private final FunctionService functionService;
    private final MutationService mutationService;
    private final DataTypeService dataTypeService;
    private final AnalysisService analysisService;
    private final ComparisonService comparisonService;

    private static final int MAX_STRUCT_FIELDS = 256;
    private static final int DECOMPILE_TIMEOUT_SECONDS = 60;  // Increased from 30s to 60s for large functions
    private static final int MAX_FIELD_OFFSET = 65536;

    public EndpointRouter(
            MultiToolProgramProvider programProvider,
            Supplier<PluginTool> activeToolSupplier,
            ListingService listingService,
            CommentService commentService,
            SymbolService symbolService,
            FunctionService functionService,
            MutationService mutationService,
            DataTypeService dataTypeService,
            AnalysisService analysisService,
            ComparisonService comparisonService) {
        this.programProvider = programProvider;
        this.activeToolSupplier = activeToolSupplier;
        this.listingService = listingService;
        this.commentService = commentService;
        this.symbolService = symbolService;
        this.functionService = functionService;
        this.mutationService = mutationService;
        this.dataTypeService = dataTypeService;
        this.analysisService = analysisService;
        this.comparisonService = comparisonService;
    }

    private PluginTool getActiveTool() {
        return activeToolSupplier.get();
    }

    public Program getCurrentProgram() {
        return programProvider.getCurrentProgram();
    }

    public Program getProgram(String programName) {
        return programProvider.getProgram(programName);
    }

    // ==================================================================================
    // Functional interfaces for endpoint registration helpers
    // ==================================================================================

    @FunctionalInterface interface PageFn   { Response apply(int offset, int limit, String prog) throws Exception; }
    @FunctionalInterface interface PageFn1  { Response apply(String p, int offset, int limit, String prog) throws Exception; }
    @FunctionalInterface interface PageFn1R { Response apply(int offset, int limit, String p, String prog) throws Exception; }
    @FunctionalInterface interface Fn0      { Response apply() throws Exception; }
    @FunctionalInterface interface Fn1      { Response apply(String p1) throws Exception; }
    @FunctionalInterface interface Fn2      { Response apply(String p1, String p2) throws Exception; }
    @FunctionalInterface interface Fn3      { Response apply(String p1, String p2, String p3) throws Exception; }

    // Wraps a checked-exception lambda into an IOException-only Handler for safeHandler.
    private UdsHttpServer.Handler checked(CheckedHandler h) {
        return ex -> { try { h.handle(ex); } catch (IOException e) { throw e; } catch (Exception e) { throw new IOException(e); } };
    }
    @FunctionalInterface interface CheckedHandler { void handle(UdsHttpExchange ex) throws Exception; }

    // GET: paginated (offset, limit, program)
    private void getPage(UdsHttpServer s, String path, PageFn fn) {
        s.createContext(path, safeHandler(checked(ex -> {
            Map<String,String> q = parseQueryParams(ex);
            sendResponse(ex, fn.apply(parseIntOrDefault(q.get("offset"),0), parseIntOrDefault(q.get("limit"),100), q.get("program")));
        })));
    }
    // GET: paginated with 1 leading param (param, offset, limit, program)
    private void getPage1(UdsHttpServer s, String path, String pName, PageFn1 fn) {
        s.createContext(path, safeHandler(checked(ex -> {
            Map<String,String> q = parseQueryParams(ex);
            sendResponse(ex, fn.apply(q.get(pName), parseIntOrDefault(q.get("offset"),0), parseIntOrDefault(q.get("limit"),100), q.get("program")));
        })));
    }
    // GET: paginated with 1 trailing param before program (offset, limit, param, program)
    private void getPage1r(UdsHttpServer s, String path, String pName, PageFn1R fn) {
        s.createContext(path, safeHandler(checked(ex -> {
            Map<String,String> q = parseQueryParams(ex);
            sendResponse(ex, fn.apply(parseIntOrDefault(q.get("offset"),0), parseIntOrDefault(q.get("limit"),100), q.get(pName), q.get("program")));
        })));
    }
    // GET: no params
    private void get0(UdsHttpServer s, String path, Fn0 fn) {
        s.createContext(path, safeHandler(checked(ex -> sendResponse(ex, fn.apply()))));
    }
    // GET: 1 query param
    private void get1(UdsHttpServer s, String path, String p1, Fn1 fn) {
        s.createContext(path, safeHandler(checked(ex -> sendResponse(ex, fn.apply(parseQueryParams(ex).get(p1))))));
    }
    // GET: 2 query params
    private void get2(UdsHttpServer s, String path, String p1, String p2, Fn2 fn) {
        s.createContext(path, safeHandler(checked(ex -> {
            Map<String,String> q = parseQueryParams(ex);
            sendResponse(ex, fn.apply(q.get(p1), q.get(p2)));
        })));
    }
    // POST: 2 form params
    private void post2(UdsHttpServer s, String path, String p1, String p2, Fn2 fn) {
        s.createContext(path, safeHandler(checked(ex -> {
            Map<String,String> p = parsePostParams(ex);
            sendResponse(ex, fn.apply(p.get(p1), p.get(p2)));
        })));
    }
    // POST: 3 form params
    private void post3(UdsHttpServer s, String path, String p1, String p2, String p3, Fn3 fn) {
        s.createContext(path, safeHandler(checked(ex -> {
            Map<String,String> p = parsePostParams(ex);
            sendResponse(ex, fn.apply(p.get(p1), p.get(p2), p.get(p3)));
        })));
    }
    // POST: 1 form param
    private void post1(UdsHttpServer s, String path, String p1, Fn1 fn) {
        s.createContext(path, safeHandler(checked(ex -> sendResponse(ex, fn.apply(parsePostParams(ex).get(p1))))));
    }
    // GET: 3 query params
    private void get3(UdsHttpServer s, String path, String p1, String p2, String p3, Fn3 fn) {
        s.createContext(path, safeHandler(checked(ex -> {
            Map<String,String> q = parseQueryParams(ex);
            sendResponse(ex, fn.apply(q.get(p1), q.get(p2), q.get(p3)));
        })));
    }
    // POST JSON: 1 string param
    private void json1(UdsHttpServer s, String path, String p1, Fn1 fn) {
        s.createContext(path, safeHandler(checked(ex -> sendResponse(ex, fn.apply((String) parseJsonParams(ex).get(p1))))));
    }
    // POST JSON: 2 string params
    private void json2(UdsHttpServer s, String path, String p1, String p2, Fn2 fn) {
        s.createContext(path, safeHandler(checked(ex -> {
            Map<String,Object> j = parseJsonParams(ex);
            sendResponse(ex, fn.apply((String) j.get(p1), (String) j.get(p2)));
        })));
    }
    // POST JSON: 3 string params
    private void json3(UdsHttpServer s, String path, String p1, String p2, String p3, Fn3 fn) {
        s.createContext(path, safeHandler(checked(ex -> {
            Map<String,Object> j = parseJsonParams(ex);
            sendResponse(ex, fn.apply((String) j.get(p1), (String) j.get(p2), (String) j.get(p3)));
        })));
    }

    // Functional interfaces for additional patterns
    @FunctionalInterface interface PageFn0  { Response apply(int offset, int limit) throws Exception; }
    @FunctionalInterface interface PageFn1NP { Response apply(String p, int offset, int limit) throws Exception; }
    @FunctionalInterface interface Fn4      { Response apply(String p1, String p2, String p3, String p4) throws Exception; }

    // GET: paginated (offset, limit) — no program param
    private void getPageNP(UdsHttpServer s, String path, PageFn0 fn) {
        s.createContext(path, safeHandler(checked(ex -> {
            Map<String,String> q = parseQueryParams(ex);
            sendResponse(ex, fn.apply(parseIntOrDefault(q.get("offset"),0), parseIntOrDefault(q.get("limit"),100)));
        })));
    }
    // GET: paginated with 1 leading param (param, offset, limit) — no program param
    private void getPage1NP(UdsHttpServer s, String path, String pName, PageFn1NP fn) {
        s.createContext(path, safeHandler(checked(ex -> {
            Map<String,String> q = parseQueryParams(ex);
            sendResponse(ex, fn.apply(q.get(pName), parseIntOrDefault(q.get("offset"),0), parseIntOrDefault(q.get("limit"),100)));
        })));
    }
    // GET: 4 query params
    private void get4(UdsHttpServer s, String path, String p1, String p2, String p3, String p4, Fn4 fn) {
        s.createContext(path, safeHandler(checked(ex -> {
            Map<String,String> q = parseQueryParams(ex);
            sendResponse(ex, fn.apply(q.get(p1), q.get(p2), q.get(p3), q.get(p4)));
        })));
    }
    // POST JSON: 4 string params
    private void json4(UdsHttpServer s, String path, String p1, String p2, String p3, String p4, Fn4 fn) {
        s.createContext(path, safeHandler(checked(ex -> {
            Map<String,Object> j = parseJsonParams(ex);
            sendResponse(ex, fn.apply((String) j.get(p1), (String) j.get(p2), (String) j.get(p3), (String) j.get(p4)));
        })));
    }

    /** POST JSON body → handler receives Map&lt;String,Object&gt; → response. Single place for param parsing. */
    @FunctionalInterface
    private interface JsonHandler { Response apply(Map<String, Object> params) throws Exception; }
    private void jsonPost(UdsHttpServer s, String path, JsonHandler fn) {
        s.createContext(path, safeHandler(checked(ex -> sendResponse(ex, fn.apply(parseJsonParams(ex))))));
    }

    /** GET query params → handler receives Map&lt;String,String&gt; → response. */
    @FunctionalInterface
    private interface QueryHandler { Response apply(Map<String, String> params) throws Exception; }
    private void getWithQuery(UdsHttpServer s, String path, QueryHandler fn) {
        s.createContext(path, safeHandler(checked(ex -> sendResponse(ex, fn.apply(parseQueryParams(ex))))));
    }

    // ==================================================================================
    // Declarative endpoint table — sealed interface with one record per helper pattern
    // ==================================================================================

    sealed interface Ep {
        String path();

        // GET patterns
        record Get0(String path, Fn0 fn) implements Ep {}
        record Get1(String path, String p1, Fn1 fn) implements Ep {}
        record Get2(String path, String p1, String p2, Fn2 fn) implements Ep {}
        record Get3(String path, String p1, String p2, String p3, Fn3 fn) implements Ep {}
        record Get4(String path, String p1, String p2, String p3, String p4, Fn4 fn) implements Ep {}
        record GetPage(String path, PageFn fn) implements Ep {}
        record GetPage1(String path, String pName, PageFn1 fn) implements Ep {}
        record GetPage1R(String path, String pName, PageFn1R fn) implements Ep {}
        record GetPageNP(String path, PageFn0 fn) implements Ep {}
        record GetPage1NP(String path, String pName, PageFn1NP fn) implements Ep {}
        record GetQuery(String path, QueryHandler fn) implements Ep {}

        // POST patterns
        record Post1(String path, String p1, Fn1 fn) implements Ep {}
        record Post2(String path, String p1, String p2, Fn2 fn) implements Ep {}
        record Post3(String path, String p1, String p2, String p3, Fn3 fn) implements Ep {}
        record Json1(String path, String p1, Fn1 fn) implements Ep {}
        record Json2(String path, String p1, String p2, Fn2 fn) implements Ep {}
        record Json3(String path, String p1, String p2, String p3, Fn3 fn) implements Ep {}
        record Json4(String path, String p1, String p2, String p3, String p4, Fn4 fn) implements Ep {}
        record JsonPost(String path, JsonHandler fn) implements Ep {}
    }


    private void register(UdsHttpServer s, Ep ep) {
        switch (ep) {
            case Ep.Get0(var path, var fn)                                     -> get0(s, path, fn);
            case Ep.Get1(var path, var p1, var fn)                             -> get1(s, path, p1, fn);
            case Ep.Get2(var path, var p1, var p2, var fn)                     -> get2(s, path, p1, p2, fn);
            case Ep.Get3(var path, var p1, var p2, var p3, var fn)             -> get3(s, path, p1, p2, p3, fn);
            case Ep.Get4(var path, var p1, var p2, var p3, var p4, var fn)     -> get4(s, path, p1, p2, p3, p4, fn);
            case Ep.GetPage(var path, var fn)                                  -> getPage(s, path, fn);
            case Ep.GetPage1(var path, var pn, var fn)                         -> getPage1(s, path, pn, fn);
            case Ep.GetPage1R(var path, var pn, var fn)                        -> getPage1r(s, path, pn, fn);
            case Ep.GetPageNP(var path, var fn)                                -> getPageNP(s, path, fn);
            case Ep.GetPage1NP(var path, var pn, var fn)                       -> getPage1NP(s, path, pn, fn);
            case Ep.GetQuery(var path, var fn)                                 -> getWithQuery(s, path, fn);
            case Ep.Post1(var path, var p1, var fn)                            -> post1(s, path, p1, fn);
            case Ep.Post2(var path, var p1, var p2, var fn)                    -> post2(s, path, p1, p2, fn);
            case Ep.Post3(var path, var p1, var p2, var p3, var fn)            -> post3(s, path, p1, p2, p3, fn);
            case Ep.Json1(var path, var p1, var fn)                            -> json1(s, path, p1, fn);
            case Ep.Json2(var path, var p1, var p2, var fn)                    -> json2(s, path, p1, p2, fn);
            case Ep.Json3(var path, var p1, var p2, var p3, var fn)            -> json3(s, path, p1, p2, p3, fn);
            case Ep.Json4(var path, var p1, var p2, var p3, var p4, var fn)    -> json4(s, path, p1, p2, p3, p4, fn);
            case Ep.JsonPost(var path, var fn)                                 -> jsonPost(s, path, fn);
        }
    }

    // ParamReader-style helpers for JSON/query maps (optional params with defaults)
    private static int getInt(Map<String, ?> map, String key, int defaultValue) {
        Object v = map != null ? map.get(key) : null;
        if (v == null) return defaultValue;
        if (v instanceof Number) return ((Number) v).intValue();
        try { return Integer.parseInt(v.toString()); } catch (NumberFormatException e) { return defaultValue; }
    }
    private static double getDouble(Map<String, ?> map, String key, double defaultValue) {
        Object v = map != null ? map.get(key) : null;
        if (v == null) return defaultValue;
        if (v instanceof Number) return ((Number) v).doubleValue();
        try { return Double.parseDouble(v.toString()); } catch (NumberFormatException e) { return defaultValue; }
    }
    private static boolean getBool(Map<String, ?> map, String key, boolean defaultValue) {
        Object v = map != null ? map.get(key) : null;
        if (v == null) return defaultValue;
        if (v instanceof Boolean) return (Boolean) v;
        return Boolean.parseBoolean(v.toString());
    }
    private static String getStr(Map<String, ?> map, String key) {
        Object v = map != null ? map.get(key) : null;
        return v != null ? v.toString() : null;
    }

    /** Coerce a parsed JSON value (String, List, Map) to a JSON string for service methods that accept raw JSON. */
    private static String coerceToJsonString(Object obj) {
        if (obj == null) return null;
        if (obj instanceof String) return (String) obj;
        return JsonHelper.toJson(obj);
    }

    public void registerAll(UdsHttpServer server) {
        for (Ep ep : endpointTable()) {
            register(server, ep);
        }

        // Complex handlers that don't fit any Ep pattern
        server.createContext("/run_script_inline", safeHandler(exchange -> {
            Map<String, Object> params = parseJsonParams(exchange);
            String code = (String) params.get("code");
            String scriptArgs = (String) params.get("args");

            if (code == null || code.isEmpty()) {
                sendResponse(exchange, errorJson("code parameter is required"));
                return;
            }

            // Generate a unique class name per invocation to avoid OSGi class cache collisions
            String uid = Long.toHexString(System.nanoTime());
            String userClass = null;
            java.util.regex.Matcher m = java.util.regex.Pattern
                .compile("public\\s+class\\s+(\\w+)").matcher(code);
            if (m.find()) {
                userClass = m.group(1);
            }
            String className = "Mcp_" + uid;
            String rewrittenCode = userClass != null
                ? code.replace("class " + userClass, "class " + className)
                : "import ghidra.app.script.GhidraScript;\npublic class " + className
                  + " extends GhidraScript {\n  public void run() throws Exception {\n"
                  + code + "\n  }\n}\n";

            File scriptDir = new File(System.getProperty("user.home"), "ghidra_scripts");
            scriptDir.mkdirs();
            File tempScript = new File(scriptDir, className + ".java");
            try {
                java.nio.file.Files.writeString(tempScript.toPath(), rewrittenCode);
                sendResponse(exchange, runGhidraScript(tempScript.getAbsolutePath(), scriptArgs));
            } finally {
                if (!tempScript.delete()) tempScript.deleteOnExit();
                File classFile = new File(scriptDir, className + ".class");
                if (classFile.exists() && !classFile.delete()) classFile.deleteOnExit();
            }
        }));

        server.createContext("/analyze_function_completeness", safeHandler(exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String functionAddress = qparams.get("function_address");

            Program program = getCurrentProgram();
            if (program != null && functionAddress != null && !functionAddress.isEmpty()) {
                try {
                    Address addr = program.getAddressFactory().getAddress(functionAddress);
                    if (addr != null) {
                        Function func = program.getFunctionManager().getFunctionAt(addr);
                        if (func != null) {
                            DecompInterface tempDecomp = new DecompInterface();
                            tempDecomp.openProgram(program);
                            tempDecomp.flushCache();
                            tempDecomp.decompileFunction(func, DECOMPILE_TIMEOUT_SECONDS, new ConsoleTaskMonitor());
                            tempDecomp.dispose();
                            Msg.info(this, "Refreshed decompiler cache before completeness analysis for " + func.getName());
                        }
                    }
                } catch (Exception e) {
                    Msg.warn(this, "Failed to refresh cache before completeness analysis: " + e.getMessage());
                }
            }
            sendResponse(exchange, analyzeFunctionCompleteness(functionAddress));
        }));

        server.createContext("/exit_ghidra", safeHandler(exchange -> {
            saveCurrentProgram();
            sendResponse(exchange, Response.ok(Map.of("success", true, "message", "Saving and exiting Ghidra")));
            new Thread(() -> {
                try { Thread.sleep(500); } catch (InterruptedException ignored) {}
                SwingUtilities.invokeLater(() -> {
                    PluginTool t = getActiveTool();
                    if (t != null) t.close();
                });
            }).start();
        }));

        server.createContext("/apply_function_documentation", safeHandler(checked(exchange -> {
            String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            sendResponse(exchange, applyFunctionDocumentation(body));
        })));
    }

    private List<Ep> endpointTable() {
        return List.of(
            new Ep.GetPage("/list_methods", listingService::listMethods),
            new Ep.GetPage("/list_classes", listingService::listClasses),
            new Ep.GetPage("/list_segments", listingService::listSegments),
            new Ep.GetPage("/list_imports", listingService::listImports),
            new Ep.GetPage("/list_exports", listingService::listExports),
            new Ep.GetPage("/list_namespaces", listingService::listNamespaces),
            new Ep.GetPage("/list_data_items", listingService::listDataItems),
            new Ep.GetPage1R("/list_data_items_by_xrefs", "format", listingService::listDataItemsByXrefs),
            new Ep.GetPage("/list_functions", listingService::listFunctions),
            new Ep.GetQuery("/list_functions_enhanced", q ->
                listFunctionsEnhanced(getInt(q, "offset", 0), getInt(q, "limit", 10000), getStr(q, "program"))),
            new Ep.GetQuery("/get_function_call_graph", q ->
                getFunctionCallGraph(getStr(q, "name"), getInt(q, "depth", 2),
                    getStr(q, "direction") != null ? getStr(q, "direction") : "both", getStr(q, "program"))),
            new Ep.GetQuery("/get_full_call_graph", q ->
                getFullCallGraph(getStr(q, "format") != null ? getStr(q, "format") : "edges",
                    getInt(q, "limit", 1000), getStr(q, "program"))),
            new Ep.GetQuery("/analyze_call_graph", q ->
                analyzeCallGraph(getStr(q, "start_function"), getStr(q, "end_function"),
                    getStr(q, "analysis_type") != null ? getStr(q, "analysis_type") : "summary", getStr(q, "program"))),
            new Ep.Post2("/rename_function", "oldName", "newName", mutationService::renameFunction),
            new Ep.Post2("/rename_data", "address", "newName", mutationService::renameData),
            new Ep.Post3("/rename_variable", "functionName", "oldName", "newName", mutationService::renameVariable),
            new Ep.GetPage1("/search_functions", "query", symbolService::searchFunctions),
            new Ep.Get2("/get_function_by_address", "address", "program", functionService::getFunctionByAddress),
            new Ep.Get0("/get_current_address", this::getCurrentAddress),
            new Ep.Get0("/get_current_function", this::getCurrentFunction),
            new Ep.Get3("/decompile_function", "address", "name", "program", functionService::decompileFunction),
            new Ep.Get2("/disassemble_function", "address", "program", functionService::disassembleFunction),
            new Ep.Post2("/set_decompiler_comment", "address", "comment", commentService::setDecompilerComment),
            new Ep.Post2("/set_disassembly_comment", "address", "comment", commentService::setDisassemblyComment),
            new Ep.Post2("/rename_function_by_address", "function_address", "new_name", mutationService::renameFunctionByAddress),
            new Ep.Json3("/set_function_prototype", "function_address", "prototype", "calling_convention", mutationService::setFunctionPrototype),
            new Ep.Get0("/list_calling_conventions", () -> symbolService.listCallingConventions(null)),
            new Ep.Post3("/set_local_variable_type", "function_address", "variable_name", "new_type", mutationService::setLocalVariableType),
            new Ep.Post2("/set_function_no_return", "function_address", "no_return", this::setFunctionNoReturn),
            new Ep.Post1("/clear_instruction_flow_override", "address", this::clearInstructionFlowOverride),
            new Ep.Post3("/set_variable_storage", "function_address", "variable_name", "storage", this::setVariableStorage),
            new Ep.Post2("/run_script", "script_path", "args", this::runGhidraScript),
            new Ep.Get1("/list_scripts", "filter", this::listGhidraScripts),
            new Ep.Post3("/force_decompile", "function_address", "name", "program", functionService::forceDecompile),
            new Ep.GetPage1("/get_xrefs_to", "address", symbolService::getXrefsTo),
            new Ep.GetPage1("/get_xrefs_from", "address", symbolService::getXrefsFrom),
            new Ep.GetPage1("/get_function_xrefs", "name", symbolService::getFunctionXrefs),
            new Ep.GetPage1NP("/get_function_labels", "name", this::getFunctionLabels),
            new Ep.GetPage1NP("/get_function_jump_targets", "name", this::getFunctionJumpTargets),
            new Ep.Post3("/rename_label", "address", "old_name", "new_name", this::renameLabel),
            new Ep.GetPage("/list_external_locations", this::listExternalLocations),
            new Ep.Get3("/get_external_location", "address", "dll_name", "program", this::getExternalLocationDetails),
            new Ep.Post2("/rename_external_location", "address", "new_name", this::renameExternalLocation),
            new Ep.Post2("/create_label", "address", "name", this::createLabel),
            new Ep.JsonPost("/batch_create_labels", p -> symbolService.batchCreateLabels(convertToMapList(p.get("labels")))),
            new Ep.Post2("/rename_or_label", "address", "name", mutationService::renameOrLabel),
            new Ep.Post2("/delete_label", "address", "name", symbolService::deleteLabel),
            new Ep.JsonPost("/batch_delete_labels", p -> symbolService.batchDeleteLabels(convertToMapList(p.get("labels")))),
            new Ep.GetPage1("/get_function_callees", "name", functionService::getFunctionCallees),
            new Ep.GetPage1("/get_function_callers", "name", functionService::getFunctionCallers),
            new Ep.GetPage1R("/list_data_types", "category", listingService::listDataTypes),
            new Ep.JsonPost("/create_struct", p ->
                dataTypeService.createStruct(getStr(p, "name"), coerceToJsonString(p.get("fields")))),
            new Ep.JsonPost("/create_enum", p ->
                dataTypeService.createEnum(getStr(p, "name"), coerceToJsonString(p.get("values")), getInt(p, "size", 4))),
            new Ep.JsonPost("/apply_data_type", p ->
                dataTypeService.applyDataType(getStr(p, "address"), getStr(p, "type_name"), getBool(p, "clear_existing", true))),
            new Ep.GetPage1R("/list_strings", "filter", listingService::listStrings),
            new Ep.Get0("/check_connection", this::checkConnection),
            new Ep.Get0("/get_version", this::getVersion),
            new Ep.Get0("/get_metadata", this::getMetadata),
            new Ep.GetQuery("/convert_number", q -> convertNumber(getStr(q, "text"), getInt(q, "size", 4))),
            new Ep.GetPage1R("/list_globals", "filter", symbolService::listGlobals),
            new Ep.Post2("/rename_global_variable", "old_name", "new_name", symbolService::renameGlobalVariable),
            new Ep.Get0("/get_entry_points", () -> symbolService.getEntryPoints(null)),
            new Ep.JsonPost("/create_union", p ->
                dataTypeService.createUnion(getStr(p, "name"), coerceToJsonString(p.get("fields")))),
            new Ep.Get1("/get_type_size", "type_name", this::getTypeSize),
            new Ep.Get1("/get_struct_layout", "struct_name", dataTypeService::getStructLayout),
            new Ep.GetPage1NP("/search_data_types", "pattern", dataTypeService::searchDataTypes),
            new Ep.Get1("/get_enum_values", "enum_name", dataTypeService::getEnumValues),
            new Ep.Json2("/create_typedef", "name", "base_type", dataTypeService::createTypedef),
            new Ep.Json2("/clone_data_type", "source_type", "new_name", dataTypeService::cloneDataType),
            new Ep.Json2("/import_data_types", "source", "format", this::importDataTypes),
            new Ep.Json1("/delete_data_type", "type_name", dataTypeService::deleteDataType),
            new Ep.Json4("/modify_struct_field", "struct_name", "field_name", "new_type", "new_name", dataTypeService::modifyStructField),
            new Ep.JsonPost("/add_struct_field", p ->
                dataTypeService.addStructField(getStr(p, "struct_name"), getStr(p, "field_name"),
                    getStr(p, "field_type"), getInt(p, "offset", -1))),
            new Ep.Post2("/remove_struct_field", "struct_name", "field_name", dataTypeService::removeStructField),
            new Ep.JsonPost("/create_array_type", p ->
                dataTypeService.createArrayType(getStr(p, "base_type"), getInt(p, "length", 1), getStr(p, "name"))),
            new Ep.Post2("/create_pointer_type", "base_type", "name", dataTypeService::createPointerType),
            new Ep.Post1("/create_data_type_category", "category_path", this::createDataTypeCategory),
            new Ep.Post2("/move_data_type_to_category", "type_name", "category_path", this::moveDataTypeToCategory),
            new Ep.GetPageNP("/list_data_type_categories", this::listDataTypeCategories),
            new Ep.Json1("/delete_function", "address", mutationService::deleteFunctionAtAddress),
            new Ep.JsonPost("/create_function", p ->
                mutationService.createFunctionAtAddress(getStr(p, "address"), getStr(p, "name"),
                    getBool(p, "disassemble_first", true))),
            new Ep.JsonPost("/create_function_signature", p ->
                createFunctionSignature(getStr(p, "name"), getStr(p, "return_type"),
                    coerceToJsonString(p.get("parameters")))),
            new Ep.GetQuery("/read_memory", q ->
                readMemory(getStr(q, "address"), getInt(q, "length", 16), getStr(q, "program"))),
            new Ep.JsonPost("/create_memory_block", p -> {
                long size = p.get("size") != null ? ((Number) p.get("size")).longValue() : 0;
                return mutationService.createMemoryBlock(getStr(p, "name"), getStr(p, "address"), size,
                    getBool(p, "read", true), getBool(p, "write", true), getBool(p, "execute", false),
                    getBool(p, "volatile", false), getStr(p, "comment"));
            }),
            new Ep.JsonPost("/get_bulk_xrefs", p -> {
                Object addressesObj = p.get("addresses");
                List<String> addresses = new ArrayList<>();
                if (addressesObj instanceof List) {
                    for (Object addr : (List<?>) addressesObj) {
                        if (addr != null) addresses.add(addr.toString());
                    }
                } else if (addressesObj instanceof String) {
                    for (String part : ((String) addressesObj).split(",")) {
                        addresses.add(part.trim());
                    }
                }
                return symbolService.getBulkXrefs(addresses, null);
            }),
            new Ep.JsonPost("/analyze_data_region", p ->
                analysisService.analyzeDataRegion(getStr(p, "address"), getInt(p, "max_scan_bytes", 1024),
                    getBool(p, "include_xref_map", true), getBool(p, "include_assembly_patterns", true),
                    getBool(p, "include_boundary_detection", true))),
            new Ep.JsonPost("/detect_array_bounds", p ->
                analysisService.detectArrayBounds(getStr(p, "address"), getBool(p, "analyze_loop_bounds", true),
                    getBool(p, "analyze_indexing", true), getInt(p, "max_scan_range", 2048))),
            new Ep.JsonPost("/get_assembly_context", p ->
                analysisService.getAssemblyContext(objectToCommaSeparated(p.get("xref_sources")),
                    getInt(p, "context_instructions", 5), objectToCommaSeparated(p.get("include_patterns")))),
            new Ep.JsonPost("/apply_data_classification", p ->
                applyDataClassification(getStr(p, "address"), getStr(p, "classification"), getStr(p, "name"),
                    getStr(p, "comment"), p.get("type_definition"))),
            new Ep.JsonPost("/analyze_struct_field_usage", p ->
                analysisService.analyzeStructFieldUsage(getStr(p, "address"), getStr(p, "struct_name"), getInt(p, "max_functions", 10))),
            new Ep.JsonPost("/get_field_access_context", p ->
                analysisService.getFieldAccessContext(getStr(p, "struct_address"), getInt(p, "field_offset", 0), getInt(p, "num_examples", 5))),
            new Ep.JsonPost("/suggest_field_names", p ->
                suggestFieldNames(getStr(p, "struct_address"), getInt(p, "struct_size", 0))),
            new Ep.GetQuery("/inspect_memory_content", q ->
                inspectMemoryContent(getStr(q, "address"), getInt(q, "length", 64), getBool(q, "detect_strings", true))),
            new Ep.Get0("/detect_crypto_constants", this::detectCryptoConstants),
            new Ep.GetQuery("/get_function_count", q -> listingService.getFunctionCount(getStr(q, "program"))),
            new Ep.GetQuery("/search_strings", q ->
                listingService.searchStrings(getStr(q, "query"), getInt(q, "min_length", 4),
                    getStr(q, "encoding"), getInt(q, "offset", 0), getInt(q, "limit", 100), getStr(q, "program"))),
            new Ep.GetQuery("/list_analyzers", q -> analysisService.listAnalyzers(getStr(q, "program"))),
            new Ep.Post1("/run_analysis", "program", analysisService::runAnalysis),
            new Ep.Get2("/search_byte_patterns", "pattern", "mask", analysisService::searchBytePatterns),
            new Ep.GetQuery("/find_similar_functions", q ->
                findSimilarFunctions(getStr(q, "target_function"), getDouble(q, "threshold", 0.8))),
            new Ep.Get1("/analyze_control_flow", "function_name", this::analyzeControlFlow),
            new Ep.Get0("/find_anti_analysis_techniques", this::findAntiAnalysisTechniques),
            new Ep.Get1("/batch_decompile", "functions", this::batchDecompileFunctions),
            new Ep.Get1("/find_dead_code", "function_name", this::findDeadCode),
            new Ep.Get0("/decrypt_strings_auto", this::autoDecryptStrings),
            new Ep.Get0("/analyze_api_call_chains", this::analyzeAPICallChains),
            new Ep.Get0("/extract_iocs_with_context", this::extractIOCsWithContext),
            new Ep.Get0("/detect_malware_behaviors", this::detectMalwareBehaviors),
            new Ep.JsonPost("/batch_set_comments", p ->
                commentService.batchSetComments(getStr(p, "function_address"),
                    convertToMapList(p.get("decompiler_comments")), convertToMapList(p.get("disassembly_comments")),
                    getStr(p, "plate_comment"))),
            new Ep.JsonPost("/clear_function_comments", p ->
                commentService.clearFunctionComments(getStr(p, "function_address"),
                    getBool(p, "clear_plate", true), getBool(p, "clear_pre", true), getBool(p, "clear_eol", true))),
            new Ep.Post2("/set_plate_comment", "function_address", "comment", commentService::setPlateComment),
            new Ep.Get2("/get_function_variables", "function_name", "program", functionService::getFunctionVariables),
            new Ep.JsonPost("/batch_rename_function_components", p -> {
                @SuppressWarnings("unchecked")
                Map<String, String> paramRenames = (Map<String, String>) p.get("parameter_renames");
                @SuppressWarnings("unchecked")
                Map<String, String> localRenames = (Map<String, String>) p.get("local_renames");
                return batchRenameFunctionComponents(getStr(p, "function_address"), getStr(p, "function_name"),
                    paramRenames, localRenames, getStr(p, "return_type"));
            }),
            new Ep.Get1("/get_valid_data_types", "category", this::getValidDataTypes),
            new Ep.Get2("/validate_data_type", "address", "type_name", this::validateDataType),
            new Ep.Get1("/get_data_type_size", "type_name", dataTypeService::getDataTypeSize),
            new Ep.GetQuery("/find_next_undefined_function", q ->
                functionService.findNextUndefinedFunction(getStr(q, "start_address"), getStr(q, "criteria"),
                    getStr(q, "pattern"), getStr(q, "direction"), getStr(q, "program"))),
            new Ep.JsonPost("/batch_set_variable_types", p -> {
                @SuppressWarnings("unchecked")
                Map<String, String> variableTypes = p.get("variable_types") instanceof Map
                    ? (Map<String, String>) p.get("variable_types") : new HashMap<>();
                return batchSetVariableTypesOptimized(getStr(p, "function_address"), variableTypes);
            }),
            new Ep.JsonPost("/batch_rename_variables", p -> {
                @SuppressWarnings("unchecked")
                Map<String, String> variableRenames = p.get("variable_renames") instanceof Map
                    ? (Map<String, String>) p.get("variable_renames") : new HashMap<>();
                return mutationService.batchRenameVariables(getStr(p, "function_address"), variableRenames);
            }),
            new Ep.Get3("/validate_function_prototype", "function_address", "prototype", "calling_convention", this::validateFunctionPrototype),
            new Ep.Get1("/validate_data_type_exists", "type_name", this::validateDataTypeExists),
            new Ep.Get1("/can_rename_at_address", "address", mutationService::canRenameAtAddress),
            new Ep.GetQuery("/analyze_function_complete", q ->
                functionService.analyzeFunctionComplete(getStr(q, "name"),
                    !"false".equalsIgnoreCase(getStr(q, "include_xrefs")),
                    !"false".equalsIgnoreCase(getStr(q, "include_callees")),
                    !"false".equalsIgnoreCase(getStr(q, "include_callers")),
                    !"false".equalsIgnoreCase(getStr(q, "include_disasm")),
                    !"false".equalsIgnoreCase(getStr(q, "include_variables")),
                    getStr(q, "program"))),
            new Ep.GetQuery("/search_functions_enhanced", q -> {
                String minX = getStr(q, "min_xrefs");
                String maxX = getStr(q, "max_xrefs");
                String hcn = getStr(q, "has_custom_name");
                Integer minXrefs = minX != null ? Integer.parseInt(minX) : null;
                Integer maxXrefs = maxX != null ? Integer.parseInt(maxX) : null;
                Boolean hasCustomName = hcn != null ? Boolean.parseBoolean(hcn) : null;
                return symbolService.searchFunctionsEnhanced(getStr(q, "name_pattern"), minXrefs, maxXrefs,
                    getStr(q, "calling_convention"), hasCustomName, getBool(q, "regex", false),
                    getStr(q, "sort_by") != null ? getStr(q, "sort_by") : "address",
                    getInt(q, "offset", 0), getInt(q, "limit", 100), getStr(q, "program"));
            }),
            new Ep.JsonPost("/disassemble_bytes", p -> {
                Integer length = p.get("length") != null ? ((Number) p.get("length")).intValue() : null;
                return disassembleBytes(getStr(p, "start_address"), getStr(p, "end_address"), length, getBool(p, "restrict_to_execute_memory", true));
            }),
            new Ep.JsonPost("/run_ghidra_script", p ->
                runGhidraScriptWithCapture(getStr(p, "script_name"), getStr(p, "args"),
                    getInt(p, "timeout_seconds", 300), getBool(p, "capture_output", true))),
            new Ep.Json3("/set_bookmark", "address", "category", "comment", this::setBookmark),
            new Ep.Get2("/list_bookmarks", "category", "address", this::listBookmarks),
            new Ep.Json2("/delete_bookmark", "address", "category", this::deleteBookmark),
            new Ep.Get0("/save_program", mutationService::saveCurrentProgram),
            new Ep.Get0("/list_open_programs", this::listOpenPrograms),
            new Ep.Get0("/get_current_program_info", this::getCurrentProgramInfo),
            new Ep.Get1("/switch_program", "name", this::switchProgram),
            new Ep.Get1("/list_project_files", "folder", this::listProjectFiles),
            new Ep.Get1("/open_program", "path", this::openProgramFromProject),
            new Ep.Get2("/get_function_hash", "address", "program", comparisonService::getFunctionHash),
            new Ep.GetPage1R("/get_bulk_function_hashes", "filter", comparisonService::getBulkFunctionHashes),
            new Ep.Get1("/get_function_documentation", "address", this::getFunctionDocumentation),
            new Ep.Get0("/compare_programs_documentation", this::compareProgramsDocumentation),
            new Ep.Get2("/find_undocumented_by_string", "address", "program", this::findUndocumentedByString),
            new Ep.Get2("/batch_string_anchor_report", "pattern", "program", this::batchStringAnchorReport),
            new Ep.Get2("/get_function_signature", "address", "program", comparisonService::getFunctionSignature),
            new Ep.GetQuery("/find_similar_functions_fuzzy", q ->
                comparisonService.findSimilarFunctionsFuzzy(getStr(q, "address"), getStr(q, "source_program"),
                    getStr(q, "target_program"), getDouble(q, "threshold", 0.7), getInt(q, "limit", 20))),
            new Ep.GetQuery("/bulk_fuzzy_match", q ->
                comparisonService.bulkFuzzyMatch(getStr(q, "source_program"), getStr(q, "target_program"),
                    getDouble(q, "threshold", 0.7), getInt(q, "offset", 0), getInt(q, "limit", 50), getStr(q, "filter"))),
            new Ep.Get4("/diff_functions", "address_a", "address_b", "program_a", "program_b", comparisonService::diffFunctions)
        );
    }


    /**
     * Get current address selected in Ghidra GUI
     */
    private Response getCurrentAddress() {
        CodeViewerService service = getActiveTool().getService(CodeViewerService.class);
        if (service == null) return errorJson("Code viewer service not available");

        ProgramLocation location = service.getCurrentLocation();
        if (location == null) return errorJson("No current location");
        JsonObject _jo1 = new JsonObject();
        _jo1.addProperty("address", location.getAddress().toString());
        return new Response.Ok(_jo1);
    }

    /**
     * Get current function selected in Ghidra GUI
     */
    private Response getCurrentFunction() {
        CodeViewerService service = getActiveTool().getService(CodeViewerService.class);
        if (service == null) return errorJson("Code viewer service not available");

        ProgramLocation location = service.getCurrentLocation();
        if (location == null) return errorJson("No current location");

        Program program = getCurrentProgram();
        if (program == null) return errorJson("No program loaded");

        Function func = program.getFunctionManager().getFunctionContaining(location.getAddress());
        if (func == null) return errorJson("No function at current location: " + location.getAddress());

        JsonObject _jo2 = new JsonObject();
        _jo2.addProperty("name", func.getName());
        _jo2.addProperty("address", func.getEntryPoint().toString());
        _jo2.addProperty("signature", func.getSignature().toString());
        return new Response.Ok(_jo2);
    }

    /**
     * List all functions with enhanced metadata including thunk/external flags.
     * Returns JSON array for easy parsing.
     */
    private Response listFunctionsEnhanced(int offset, int limit, String programName) {
        Object[] programResult = getProgramOrError(programName);
        Program program = (Program) programResult[0];
        if (program == null) return (Response) programResult[1];

        var functions = new ArrayList<>();
        int skipped = 0;
        int count = 0;

        for (Function func : program.getFunctionManager().getFunctions(true)) {
            if (skipped < offset) {
                skipped++;
                continue;
            }
            if (count >= limit) break;

            final var f = func;
            JsonObject _jo3 = new JsonObject();
            _jo3.addProperty("name", f.getName());
            _jo3.addProperty("address", f.getEntryPoint().toString());
            _jo3.addProperty("isThunk", f.isThunk());
            _jo3.addProperty("isExternal", f.isExternal());
            functions.add(_jo3);
            count++;
        }

        var result = new java.util.LinkedHashMap<String, Object>();
        result.put("functions", functions);
        result.put("count", count);
        result.put("offset", offset);
        result.put("limit", limit);
        return Response.ok(result);
    }

    /**
     * Gets a function at the given address or containing the address
     * @return the function or null if not found
     */
    private Function getFunctionForAddress(Program program, Address addr) {
        Function func = program.getFunctionManager().getFunctionAt(addr);
        if (func == null) {
            func = program.getFunctionManager().getFunctionContaining(addr);
        }
        return func;
    }

    /**
     * Set a local variable's type using HighFunctionDBUtil.updateDBVariable
     */
    private Response setLocalVariableType(String functionAddrStr, String variableName, String newType) {
        // Input validation
        Program program = getCurrentProgram();
        if (program == null) {
            return Response.err("No program loaded");
        }

        if (functionAddrStr == null || functionAddrStr.isEmpty()) {
            return Response.err("Function address is required");
        }

        if (variableName == null || variableName.isEmpty()) {
            return Response.err("Variable name is required");
        }

        if (newType == null || newType.isEmpty()) {
            return Response.err("New type is required");
        }

        final StringBuilder resultMsg = new StringBuilder();
        final AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {
                try {
                    // Find the function
                    Address addr = program.getAddressFactory().getAddress(functionAddrStr);
                    if (addr == null) {
                        resultMsg.append("Error: Invalid address: ").append(functionAddrStr);
                        return;
                    }

                    Function func = getFunctionForAddress(program, addr);
                    if (func == null) {
                        resultMsg.append("Error: No function found at address ").append(functionAddrStr);
                        return;
                    }

                    DecompileResults results = decompileFunction(func, program);
                    if (results == null || !results.decompileCompleted()) {
                        resultMsg.append("Error: Decompilation failed for function at ").append(functionAddrStr);
                        return;
                    }

                    ghidra.program.model.pcode.HighFunction highFunction = results.getHighFunction();
                    if (highFunction == null) {
                        resultMsg.append("Error: No high function available");
                        return;
                    }

                    // Find the symbol by name
                    HighSymbol symbol = findSymbolByName(highFunction, variableName);
                    if (symbol == null) {
                        // PRIORITY 2 FIX: Provide helpful diagnostic information
                        resultMsg.append("Error: Variable '").append(variableName)
                                .append("' not found in decompiled function. ");

                        // List available variables for user guidance
                        List<String> availableNames = new ArrayList<>();
                        Iterator<HighSymbol> symbols = highFunction.getLocalSymbolMap().getSymbols();
                        while (symbols.hasNext()) {
                            availableNames.add(symbols.next().getName());
                        }

                        if (!availableNames.isEmpty()) {
                            resultMsg.append("Available variables: ")
                                    .append(String.join(", ", availableNames))
                                    .append(". ");
                        }

                        // Check if variable exists in low-level API but not high-level (phantom variable)
                        Variable[] lowLevelVars = func.getLocalVariables();
                        boolean isPhantomVariable = false;
                        for (Variable v : lowLevelVars) {
                            if (v.getName().equals(variableName)) {
                                isPhantomVariable = true;
                                break;
                            }
                        }

                        if (isPhantomVariable) {
                            resultMsg.append("NOTE: Variable '").append(variableName)
                                    .append("' exists in stack frame but not in decompiled code. ")
                                    .append("This is a phantom variable created by Ghidra's stack analysis ")
                                    .append("that was optimized away during decompilation. ")
                                    .append("You cannot set the type of phantom variables. ")
                                    .append("Only variables visible in the decompiled code can be typed.");
                        }

                        return;
                    }

                    // Get high variable
                    HighVariable highVar = symbol.getHighVariable();
                    if (highVar == null) {
                        resultMsg.append("Error: No HighVariable found for symbol: ").append(variableName);
                        return;
                    }

                    String oldType = highVar.getDataType().getName();

                    // Find the data type
                    DataTypeManager dtm = program.getDataTypeManager();
                    DataType dataType = resolveDataType(dtm, newType);

                    if (dataType == null) {
                        resultMsg.append("Error: Could not resolve data type: ").append(newType);
                        return;
                    }

                    // Apply the type change in a transaction
                    StringBuilder errorDetails = new StringBuilder();
                    if (updateVariableType(program, symbol, dataType, success, errorDetails)) {
                        resultMsg.append("Success: Changed type of variable '").append(variableName)
                                .append("' from '").append(oldType).append("' to '")
                                .append(dataType.getName()).append("'");
                    } else {
                        // Provide detailed error message including storage location
                        String storageInfo = "unknown";
                        try {
                            storageInfo = symbol.getStorage().toString();
                        } catch (Exception e) {
                            // If we can't get storage, continue without it
                        }

                        resultMsg.append("Error: Failed to update variable type for '").append(variableName).append("'");
                        resultMsg.append(" (Storage: ").append(storageInfo).append(")");

                        if (errorDetails.length() > 0) {
                            resultMsg.append(". Details: ").append(errorDetails.toString());
                        }

                        // Add helpful guidance for known limitations
                        if (storageInfo.startsWith("Stack[-") && storageInfo.contains(":4")) {
                            resultMsg.append(". Note: Stack-based local variables with 4-byte size may have type-setting limitations in Ghidra's API");
                        }
                    }

                } catch (Exception e) {
                    resultMsg.append("Error: ").append(e.getMessage());
                    Msg.error(this, "Error setting variable type", e);
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            resultMsg.append("Error: Failed to execute on Swing thread: ").append(e.getMessage());
            Msg.error(this, "Failed to execute set variable type on Swing thread", e);
        }

        return Response.text(resultMsg.length() > 0 ? resultMsg.toString() : "Error: Unknown failure");
    }

    /**
     * Find a high symbol by name in the given high function
     */
    private HighSymbol findSymbolByName(ghidra.program.model.pcode.HighFunction highFunction, String variableName) {
        Iterator<HighSymbol> symbols = highFunction.getLocalSymbolMap().getSymbols();
        while (symbols.hasNext()) {
            HighSymbol s = symbols.next();
            if (s.getName().equals(variableName)) {
                return s;
            }
        }
        return null;
    }

    /**
     * Decompile a function and return the results (with retry logic)
     */
    private DecompileResults decompileFunction(Function func, Program program) {
        return decompileFunctionWithRetry(func, program, 3);  // 3 retries for stability
    }

    /**
     * Decompile function with retry logic for stability (FIX #3)
     * Complex functions with SEH + alloca may fail initially but succeed on retry
     * @param func Function to decompile
     * @param program Current program
     * @param maxRetries Maximum number of retry attempts
     * @return Decompilation results or null if all retries exhausted
     */
    private DecompileResults decompileFunctionWithRetry(Function func, Program program, int maxRetries) {
        DecompInterface decomp = null;

        for (int attempt = 1; attempt <= maxRetries; attempt++) {
            try {
                decomp = new DecompInterface();
                decomp.openProgram(program);
                decomp.setSimplificationStyle("decompile");

                // On retry attempts, flush cache first and increase timeout
                if (attempt > 1) {
                    Msg.info(this, "Decompilation attempt " + attempt + " for function " + func.getName());
                    decomp.flushCache();

                    // Increase timeout on retries for complex functions
                    int timeoutSeconds = DECOMPILE_TIMEOUT_SECONDS * attempt;
                    DecompileResults results = decomp.decompileFunction(func, timeoutSeconds, new ConsoleTaskMonitor());

                    if (results != null && results.decompileCompleted()) {
                        Msg.info(this, "Decompilation succeeded on attempt " + attempt);
                        return results;
                    }

                    String errorMsg = (results != null) ? results.getErrorMessage() : "Unknown error";
                    Msg.warn(this, "Decompilation attempt " + attempt + " failed: " + errorMsg);
                } else {
                    // First attempt - use normal timeout
                    DecompileResults results = decomp.decompileFunction(func, DECOMPILE_TIMEOUT_SECONDS, new ConsoleTaskMonitor());

                    if (results != null && results.decompileCompleted()) {
                        return results;
                    }

                    String errorMsg = (results != null) ? results.getErrorMessage() : "Unknown error";
                    Msg.warn(this, "Decompilation attempt " + attempt + " failed: " + errorMsg);
                }

            } catch (Exception e) {
                Msg.warn(this, "Decompilation attempt " + attempt + " threw exception: " + e.getMessage());
            } finally {
                if (decomp != null) {
                    decomp.dispose();
                    decomp = null;
                }
            }

            // Small delay between retries to allow Ghidra to stabilize
            if (attempt < maxRetries) {
                try {
                    Thread.sleep(100);  // 100ms delay
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                }
            }
        }

        Msg.error(this, "Could not decompile function after " + maxRetries + " attempts: " + func.getName());
        return null;
    }

    /**
     * Apply the type update in a transaction
     */
    private boolean updateVariableType(Program program, HighSymbol symbol, DataType dataType,
                                       AtomicBoolean success, StringBuilder errorDetails) {
        int tx = program.startTransaction("Set variable type");
        boolean result = false;
        String storageInfo = "unknown";

        try {
            // Get storage information for detailed logging
            try {
                storageInfo = symbol.getStorage().toString();
            } catch (Exception e) {
                // If we can't get storage, continue without it
            }

            // Log variable storage information for debugging
            Msg.info(this, "Attempting to set type for variable: " + symbol.getName() +
                          ", storage: " + storageInfo + ", new type: " + dataType.getName());

            // Use HighFunctionDBUtil to update the variable with the new type
            HighFunctionDBUtil.updateDBVariable(
                symbol,                // The high symbol to modify
                symbol.getName(),      // Keep original name
                dataType,              // The new data type
                SourceType.USER_DEFINED // Mark as user-defined
            );

            success.set(true);
            result = true;
            Msg.info(this, "Successfully set variable type using HighFunctionDBUtil");

        } catch (ghidra.util.exception.DuplicateNameException e) {
            String msg = "Variable name conflict: " + e.getMessage();
            Msg.error(this, msg, e);
            if (errorDetails != null) {
                errorDetails.append(msg).append(" (Storage: ").append(storageInfo).append(")");
            }
        } catch (ghidra.util.exception.InvalidInputException e) {
            String msg;

            // FIX: Detect register-based storage and provide helpful error message
            if (storageInfo.contains("ESP:") || storageInfo.contains("EDI:") ||
                storageInfo.contains("EAX:") || storageInfo.contains("EBX:") ||
                storageInfo.contains("ECX:") || storageInfo.contains("EDX:") ||
                storageInfo.contains("ESI:") || storageInfo.contains("EBP:")) {

                msg = "Cannot set type for register-based variable '" + symbol.getName() +
                      "' at storage location: " + storageInfo + ". " +
                      "Register variables (ESP/EDI/EAX/etc) are decompiler temporaries and cannot have types set via API. " +
                      "Workaround: Manually retype this variable in Ghidra's decompiler UI (right-click → Retype Variable). " +
                      "Ghidra limitation: " + e.getMessage();
            } else {
                msg = "Invalid input for variable type update: " + e.getMessage() +
                      " (Storage: " + storageInfo + ")";
            }

            Msg.error(this, msg, e);
            if (errorDetails != null) {
                errorDetails.append(msg);
            }
        } catch (IllegalArgumentException e) {
            String msg = "Illegal argument: " + e.getMessage();
            Msg.error(this, msg, e);
            if (errorDetails != null) {
                errorDetails.append(msg).append(" (Storage: ").append(storageInfo).append(")");
            }
        } catch (Exception e) {
            // Generic catch-all for unexpected exceptions
            String msg = "Unexpected error setting variable type: " + e.getClass().getName() + ": " + e.getMessage();
            Msg.error(this, msg, e);
            e.printStackTrace();  // Full stack trace for debugging
            if (errorDetails != null) {
                errorDetails.append(msg).append(" (Storage: ").append(storageInfo).append(")");
            }
        } finally {
            program.endTransaction(tx, success.get());
        }
        return result;
    }

    /**
     * Set a function's "No Return" attribute
     *
     * This method controls whether Ghidra treats a function as non-returning (like exit(), abort(), etc.).
     * When a function is marked as non-returning:
     * - Call sites are treated as terminators (CALL_TERMINATOR)
     * - Decompiler doesn't show code execution continuing after the call
     * - Control flow analysis treats the call like a RET instruction
     *
     * @param functionAddrStr The function address in hex format (e.g., "0x401000")
     * @param noReturn true to mark as non-returning, false to mark as returning
     * @return Success or error message
     */
    private Response setFunctionNoReturn(String functionAddrStr, String noReturnStr) {
        // Input validation
        Program program = getCurrentProgram();
        if (program == null) {
            return Response.err("No program loaded");
        }

        if (functionAddrStr == null || functionAddrStr.isEmpty()) {
            return Response.err("Function address is required");
        }
        boolean noReturn = noReturnStr != null && Boolean.parseBoolean(noReturnStr);

        final StringBuilder resultMsg = new StringBuilder();
        final AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Set function no return");
                try {
                    Address addr = program.getAddressFactory().getAddress(functionAddrStr);
                    if (addr == null) {
                        resultMsg.append("Error: Invalid address: ").append(functionAddrStr);
                        return;
                    }

                    Function func = getFunctionForAddress(program, addr);
                    if (func == null) {
                        resultMsg.append("Error: No function found at address ").append(functionAddrStr);
                        return;
                    }

                    String oldState = func.hasNoReturn() ? "non-returning" : "returning";

                    // Set the no-return attribute
                    func.setNoReturn(noReturn);

                    String newState = noReturn ? "non-returning" : "returning";
                    success.set(true);

                    resultMsg.append("Success: Set function '").append(func.getName())
                            .append("' at ").append(functionAddrStr)
                            .append(" from ").append(oldState)
                            .append(" to ").append(newState);

                    Msg.info(this, "Set no-return=" + noReturn + " for function " + func.getName() + " at " + functionAddrStr);

                } catch (Exception e) {
                    resultMsg.append("Error: ").append(e.getMessage());
                    Msg.error(this, "Error setting function no-return attribute", e);
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            resultMsg.append("Error: Failed to execute on Swing thread: ").append(e.getMessage());
            Msg.error(this, "Failed to execute set no-return on Swing thread", e);
        }

        return Response.text(resultMsg.length() > 0 ? resultMsg.toString() : "Error: Unknown failure");
    }

    /**
     * Clear instruction-level flow override at a specific address
     *
     * This method clears flow overrides that are set on individual instructions (like CALL_TERMINATOR).
     * Flow overrides can be set at:
     * 1. Function level (via setNoReturn) - affects all call sites globally
     * 2. Instruction level (per call site) - takes precedence over function-level settings
     *
     * Use this method to:
     * - Clear CALL_TERMINATOR overrides on specific CALL instructions
     * - Remove incorrect flow analysis overrides
     * - Allow execution to continue after a call that was marked as non-returning
     *
     * After clearing the override, Ghidra will re-analyze the instruction using default flow rules.
     *
     * @param instructionAddrStr The instruction address in hex format (e.g., "0x6fb5c8b9")
     * @return Success or error message
     */
    private Response clearInstructionFlowOverride(String instructionAddrStr) {
        // Input validation
        Program program = getCurrentProgram();
        if (program == null) {
            return Response.err("No program loaded");
        }

        if (instructionAddrStr == null || instructionAddrStr.isEmpty()) {
            return Response.err("Instruction address is required");
        }

        final StringBuilder resultMsg = new StringBuilder();
        final AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Clear instruction flow override");
                try {
                    Address addr = program.getAddressFactory().getAddress(instructionAddrStr);
                    if (addr == null) {
                        resultMsg.append("Error: Invalid address: ").append(instructionAddrStr);
                        return;
                    }

                    // Get the instruction at the address
                    Listing listing = program.getListing();
                    ghidra.program.model.listing.Instruction instruction = listing.getInstructionAt(addr);

                    if (instruction == null) {
                        resultMsg.append("Error: No instruction found at address ").append(instructionAddrStr);
                        return;
                    }

                    // Get the current flow override type (if any)
                    ghidra.program.model.listing.FlowOverride oldOverride = instruction.getFlowOverride();

                    // Clear the flow override by setting to NONE
                    instruction.setFlowOverride(ghidra.program.model.listing.FlowOverride.NONE);

                    success.set(true);
                    resultMsg.append("Success: Cleared flow override at ").append(instructionAddrStr);
                    resultMsg.append(" (was: ").append(oldOverride.toString()).append(", now: NONE)");

                    // Get the instruction's mnemonic for logging
                    String mnemonic = instruction.getMnemonicString();
                    Msg.info(this, "Cleared flow override for instruction '" + mnemonic + "' at " + instructionAddrStr +
                             " (previous override: " + oldOverride + ")");

                } catch (Exception e) {
                    resultMsg.append("Error: ").append(e.getMessage());
                    Msg.error(this, "Error clearing instruction flow override", e);
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            resultMsg.append("Error: Failed to execute on Swing thread: ").append(e.getMessage());
            Msg.error(this, "Failed to execute clear flow override on Swing thread", e);
        }

        return Response.text(resultMsg.length() > 0 ? resultMsg.toString() : "Error: Unknown failure");
    }

    /**
     * Set custom storage for a local variable or parameter (v1.7.0)
     *
     * This allows overriding Ghidra's automatic variable storage detection.
     * Useful for cases where registers are reused or compiler optimizations confuse the decompiler.
     *
     * @param functionAddrStr Function address containing the variable
     * @param variableName Name of the variable to modify
     * @param storageSpec Storage specification (e.g., "Stack[-0x10]:4", "EBP:4", "EAX:4")
     * @return Success or error message
     */
    private Response setVariableStorage(String functionAddrStr, String variableName, String storageSpec) {
        Program program = getCurrentProgram();
        if (program == null) {
            return Response.err("No program loaded");
        }

        if (functionAddrStr == null || functionAddrStr.isEmpty()) {
            return Response.err("Function address is required");
        }
        if (variableName == null || variableName.isEmpty()) {
            return Response.err("Variable name is required");
        }
        if (storageSpec == null || storageSpec.isEmpty()) {
            return Response.err("Storage specification is required");
        }

        final StringBuilder resultMsg = new StringBuilder();
        final AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Set variable storage");
                try {
                    Address addr = program.getAddressFactory().getAddress(functionAddrStr);
                    if (addr == null) {
                        resultMsg.append("Error: Invalid function address: ").append(functionAddrStr);
                        return;
                    }

                    Function func = program.getFunctionManager().getFunctionAt(addr);
                    if (func == null) {
                        resultMsg.append("Error: No function found at address ").append(functionAddrStr);
                        return;
                    }

                    // Find the variable
                    Variable targetVar = null;
                    for (Variable var : func.getAllVariables()) {
                        if (var.getName().equals(variableName)) {
                            targetVar = var;
                            break;
                        }
                    }

                    if (targetVar == null) {
                        resultMsg.append("Error: Variable '").append(variableName).append("' not found in function ").append(func.getName());
                        return;
                    }

                    String oldStorage = targetVar.getVariableStorage().toString();

                    // Ghidra's variable storage API has limited programmatic access
                    // The proper way to change variable storage is through the decompiler UI
                    resultMsg.append("Note: Programmatic variable storage control is limited in Ghidra.\n\n");
                    resultMsg.append("Current variable information:\n");
                    resultMsg.append("  Variable: ").append(variableName).append("\n");
                    resultMsg.append("  Function: ").append(func.getName()).append(" @ ").append(functionAddrStr).append("\n");
                    resultMsg.append("  Current storage: ").append(oldStorage).append("\n");
                    resultMsg.append("  Requested storage: ").append(storageSpec).append("\n\n");
                    resultMsg.append("To change variable storage:\n");
                    resultMsg.append("1. Open the function in Ghidra's Decompiler window\n");
                    resultMsg.append("2. Right-click on the variable '").append(variableName).append("'\n");
                    resultMsg.append("3. Select 'Edit Data Type' or 'Retype Variable'\n");
                    resultMsg.append("4. Manually adjust the storage location\n\n");
                    resultMsg.append("Alternative approach:\n");
                    resultMsg.append("- Use run_script() to execute a custom Ghidra script\n");
                    resultMsg.append("- The script can use high-level Pcode/HighVariable API\n");
                    resultMsg.append("- See FixEBPRegisterReuse.java for an example\n");

                    success.set(true);
                    Msg.info(this, "Variable storage query for: " + variableName + " in " + func.getName() +
                             " (current: " + oldStorage + ", requested: " + storageSpec + ")");

                } catch (Exception e) {
                    resultMsg.append("Error: ").append(e.getMessage());
                    Msg.error(this, "Error setting variable storage", e);
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            resultMsg.append("Error: Failed to execute on Swing thread: ").append(e.getMessage());
            Msg.error(this, "Failed to execute set variable storage on Swing thread", e);
        }

        return Response.text(resultMsg.length() > 0 ? resultMsg.toString() : "Error: Unknown failure");
    }

    /**
     * Run a Ghidra script programmatically (v1.7.0, fixed v2.0.1)
     *
     * Fixes: Issue #1 (args support via setScriptArgs), Issue #2 (OSGi path
     * resolution by copying to ~/ghidra_scripts/), Issue #5 (timeout protection).
     *
     * @param scriptPath Path to the script file (.java or .py), or just a filename
     * @param scriptArgs Optional space-separated arguments for the script
     * @return Script output or error message
     */
    private Response runGhidraScript(String scriptPath, String scriptArgs) {
        Program program = getCurrentProgram();
        if (program == null) {
            return errorJson("No program loaded");
        }

        final var result = new LinkedHashMap<String, Object>();
        final var scriptOutput = new StringBuilder();
        final var consoleOutput = new ByteArrayOutputStream();
        final var errorInfo = new StringBuilder();
        final AtomicBoolean success = new AtomicBoolean(false);
        final PrintStream originalOut = System.out;
        final PrintStream originalErr = System.err;
        final File[] copiedScript = {null};

        result.put("script", scriptPath);
        result.put("program", program.getName());

        try {
            SwingUtilities.invokeAndWait(() -> {
                try {
                    PrintStream captureStream = new PrintStream(consoleOutput);
                    System.setOut(captureStream);
                    System.setErr(captureStream);

                    // Resolve script file — search standard locations
                    File ghidraScriptsDir = new File(System.getProperty("user.home"), "ghidra_scripts");
                    String[] possiblePaths = {
                        scriptPath,
                        new File(ghidraScriptsDir, scriptPath).getPath(),
                        new File(ghidraScriptsDir, new File(scriptPath).getName()).getPath(),
                        "./ghidra_scripts/" + scriptPath,
                        "./ghidra_scripts/" + new File(scriptPath).getName()
                    };

                    File resolvedFile = null;
                    for (String path : possiblePaths) {
                        try {
                            File candidate = new File(path);
                            if (candidate.exists() && candidate.isFile()) {
                                resolvedFile = candidate;
                                break;
                            }
                        } catch (Exception e) {
                            // Continue
                        }
                    }

                    if (resolvedFile == null) {
                        errorInfo.append("Script file not found. Searched: ")
                            .append(Arrays.toString(possiblePaths));
                        return;
                    }

                    // Issue #2 fix: If the script is NOT already in ~/ghidra_scripts/,
                    // copy it there so Ghidra's OSGi class loader can find the source bundle.
                    File scriptFileForExecution = resolvedFile;
                    try {
                        ghidraScriptsDir.mkdirs();
                        String canonicalScriptsDir = ghidraScriptsDir.getCanonicalPath();
                        String canonicalResolved = resolvedFile.getCanonicalPath();
                        if (!canonicalResolved.startsWith(canonicalScriptsDir + File.separator)) {
                            File dest = new File(ghidraScriptsDir, resolvedFile.getName());
                            java.nio.file.Files.copy(resolvedFile.toPath(), dest.toPath(),
                                java.nio.file.StandardCopyOption.REPLACE_EXISTING);
                            scriptFileForExecution = dest;
                            copiedScript[0] = dest;
                        }
                    } catch (Exception e) {
                        // Non-fatal, script may still run from original location
                    }

                    generic.jar.ResourceFile scriptFile = new generic.jar.ResourceFile(scriptFileForExecution);
                    result.put("resolved_path", scriptFile.getAbsolutePath());

                    ghidra.app.script.GhidraScriptProvider provider = ghidra.app.script.GhidraScriptUtil.getProvider(scriptFile);
                    if (provider == null) {
                        errorInfo.append("No script provider found for: ").append(scriptFile.getName());
                        return;
                    }

                    StringWriter scriptWriter = new StringWriter();
                    PrintWriter scriptPrintWriter = new PrintWriter(scriptWriter);

                    ghidra.app.script.GhidraScript script = provider.getScriptInstance(scriptFile, scriptPrintWriter);
                    if (script == null) {
                        errorInfo.append("Failed to create script instance");
                        return;
                    }

                    ghidra.program.util.ProgramLocation location = new ghidra.program.util.ProgramLocation(program, program.getMinAddress());
                    ghidra.framework.plugintool.PluginTool pluginTool = EndpointRouter.this.getActiveTool();
                    ghidra.app.script.GhidraState scriptState = new ghidra.app.script.GhidraState(pluginTool, pluginTool.getProject(), program, location, null, null);

                    ghidra.util.task.TaskMonitor scriptMonitor = new ghidra.util.task.ConsoleTaskMonitor();
                    script.set(scriptState, scriptMonitor, scriptPrintWriter);

                    // Issue #1 + #5 fix: Parse and set script args BEFORE execution
                    String[] args = new String[0];
                    if (scriptArgs != null && !scriptArgs.trim().isEmpty()) {
                        args = scriptArgs.trim().split("\\s+");
                        script.setScriptArgs(args);
                        result.put("args", args);
                    }

                    script.runScript(scriptFile.getName(), args);

                    String output = scriptWriter.toString();
                    if (!output.isEmpty()) {
                        scriptOutput.append(output);
                    }

                    success.set(true);

                } catch (Exception e) {
                    errorInfo.append(e.getClass().getSimpleName()).append(": ").append(e.getMessage());
                    StringWriter sw = new StringWriter();
                    e.printStackTrace(new PrintWriter(sw));
                    result.put("stack_trace", sw.toString());
                    Msg.error(this, "Script execution failed: " + scriptPath, e);
                } finally {
                    System.setOut(originalOut);
                    System.setErr(originalErr);
                    if (copiedScript[0] != null) {
                        if (!copiedScript[0].delete()) {
                            copiedScript[0].deleteOnExit();
                        }
                    }
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            errorInfo.append("Failed to execute on Swing thread: ").append(e.getMessage());
            Msg.error(this, "Failed to execute on Swing thread", e);
        }

        result.put("success", success.get());
        if (scriptOutput.length() > 0) result.put("output", scriptOutput.toString());
        String captured = consoleOutput.toString();
        if (!captured.isEmpty()) result.put("console_output", captured);
        if (errorInfo.length() > 0) result.put("error", errorInfo.toString());

        return Response.ok(result);
    }

    /**
     * List available Ghidra scripts (v1.7.0)
     *
     * @param filter Optional filter string to match script names
     * @return JSON list of available scripts
     */
    private Response listGhidraScripts(String filter) {
        var response = new java.util.LinkedHashMap<String, Object>();
        response.put("note", "Script listing requires Ghidra GUI access");
        response.put("filter", filter != null ? filter : "none");
        response.put("instructions", List.of(
                "To view available scripts:",
                "1. Open Ghidra's Script Manager (Window -> Script Manager)",
                "2. Browse scripts by category",
                "3. Use the search filter at the top"
        ));
        response.put("common_script_locations", List.of(
                "<ghidra_install>/Ghidra/Features/*/ghidra_scripts/",
                "<user_home>/ghidra_scripts/"
        ));
        return Response.ok(response);
    }

    /**
     * Force decompiler reanalysis for a function (v1.7.0)
     *
     * Clears cached decompilation results and forces a fresh analysis.
    /**
     * Maps common C type names to Ghidra built-in DataType instances.
     * These types exist as Java classes but may not be in the per-program DTM.
     */
    private DataType resolveWellKnownType(String typeName) {
        switch (typeName.toLowerCase()) {
            case "int":        return ghidra.program.model.data.IntegerDataType.dataType;
            case "uint":       return ghidra.program.model.data.UnsignedIntegerDataType.dataType;
            case "short":      return ghidra.program.model.data.ShortDataType.dataType;
            case "ushort":     return ghidra.program.model.data.UnsignedShortDataType.dataType;
            case "long":       return ghidra.program.model.data.LongDataType.dataType;
            case "ulong":      return ghidra.program.model.data.UnsignedLongDataType.dataType;
            case "longlong":
            case "long long":  return ghidra.program.model.data.LongLongDataType.dataType;
            case "char":       return ghidra.program.model.data.CharDataType.dataType;
            case "uchar":      return ghidra.program.model.data.UnsignedCharDataType.dataType;
            case "float":      return ghidra.program.model.data.FloatDataType.dataType;
            case "double":     return ghidra.program.model.data.DoubleDataType.dataType;
            case "bool":
            case "boolean":    return ghidra.program.model.data.BooleanDataType.dataType;
            case "void":       return ghidra.program.model.data.VoidDataType.dataType;
            case "byte":       return ghidra.program.model.data.ByteDataType.dataType;
            case "sbyte":      return ghidra.program.model.data.SignedByteDataType.dataType;
            case "word":       return ghidra.program.model.data.WordDataType.dataType;
            case "dword":      return ghidra.program.model.data.DWordDataType.dataType;
            case "qword":      return ghidra.program.model.data.QWordDataType.dataType;
            case "int8_t":
            case "int8":       return ghidra.program.model.data.SignedByteDataType.dataType;
            case "uint8_t":
            case "uint8":      return ghidra.program.model.data.ByteDataType.dataType;
            case "int16_t":
            case "int16":      return ghidra.program.model.data.ShortDataType.dataType;
            case "uint16_t":
            case "uint16":     return ghidra.program.model.data.UnsignedShortDataType.dataType;
            case "int32_t":
            case "int32":      return ghidra.program.model.data.IntegerDataType.dataType;
            case "uint32_t":
            case "uint32":     return ghidra.program.model.data.UnsignedIntegerDataType.dataType;
            case "int64_t":
            case "int64":      return ghidra.program.model.data.LongLongDataType.dataType;
            case "uint64_t":
            case "uint64":     return ghidra.program.model.data.UnsignedLongLongDataType.dataType;
            case "size_t":     return ghidra.program.model.data.UnsignedIntegerDataType.dataType;
            case "unsigned int": return ghidra.program.model.data.UnsignedIntegerDataType.dataType;
            case "unsigned short": return ghidra.program.model.data.UnsignedShortDataType.dataType;
            case "unsigned long": return ghidra.program.model.data.UnsignedLongDataType.dataType;
            case "unsigned char": return ghidra.program.model.data.UnsignedCharDataType.dataType;
            case "signed char": return ghidra.program.model.data.SignedByteDataType.dataType;
            default:           return null;
        }
    }

    /**
     * Resolves a data type by name, handling common types and pointer types
     * @param dtm The data type manager
     * @param typeName The type name to resolve
     * @return The resolved DataType, or null if not found
     */
    private DataType resolveDataType(DataTypeManager dtm, String typeName) {
        // ZERO: Map common C type names to Ghidra built-in DataType instances
        // These types exist as Java classes but may not be registered in the per-program DTM
        DataType wellKnown = resolveWellKnownType(typeName);
        if (wellKnown != null) {
            Msg.info(this, "Resolved well-known type: " + typeName + " -> " + wellKnown.getName());
            return wellKnown;
        }

        // FIRST: Try Ghidra builtin types in root category (prioritize over Windows types)
        // This ensures we use lowercase builtin types (uint, ushort, byte) instead of
        // Windows SDK types (UINT, USHORT, BYTE) when the type name matches
        DataType builtinType = dtm.getDataType("/" + typeName);
        if (builtinType != null) {
            Msg.info(this, "Found builtin data type: " + builtinType.getPathName());
            return builtinType;
        }

        // SECOND: Try lowercase version of builtin types (handles "UINT" → "/uint")
        DataType builtinTypeLower = dtm.getDataType("/" + typeName.toLowerCase());
        if (builtinTypeLower != null) {
            Msg.info(this, "Found builtin data type (lowercase): " + builtinTypeLower.getPathName());
            return builtinTypeLower;
        }

        // THIRD: Search all categories as fallback (for Windows types, custom types, etc.)
        DataType dataType = findDataTypeByNameInAllCategories(dtm, typeName);
        if (dataType != null) {
            Msg.info(this, "Found data type in categories: " + dataType.getPathName());
            return dataType;
        }

        // Check for array syntax: "type[count]"
        if (typeName.contains("[") && typeName.endsWith("]")) {
            int bracketPos = typeName.indexOf('[');
            String baseTypeName = typeName.substring(0, bracketPos);
            String countStr = typeName.substring(bracketPos + 1, typeName.length() - 1);

            try {
                int count = Integer.parseInt(countStr);
                DataType baseType = resolveDataType(dtm, baseTypeName);  // Recursive call

                if (baseType != null && count > 0) {
                    // Create array type on-the-fly
                    ArrayDataType arrayType = new ArrayDataType(baseType, count, baseType.getLength());
                    Msg.info(this, "Auto-created array type: " + typeName +
                            " (base: " + baseType.getName() + ", count: " + count +
                            ", total size: " + arrayType.getLength() + " bytes)");
                    return arrayType;
                } else if (baseType == null) {
                    Msg.error(this, "Cannot create array: base type '" + baseTypeName + "' not found");
                    return null;
                }
            } catch (NumberFormatException e) {
                Msg.error(this, "Invalid array count in type: " + typeName);
                return null;
            }
        }

        // Check for C-style pointer types (type*)
        if (typeName.endsWith("*")) {
            String baseTypeName = typeName.substring(0, typeName.length() - 1).trim();

            // Special case for void*
            if (baseTypeName.equals("void") || baseTypeName.isEmpty()) {
                Msg.info(this, "Creating void* pointer type");
                return new PointerDataType(dtm.getDataType("/void"));
            }

            // Try to resolve the base type recursively (handles nested types)
            DataType baseType = resolveDataType(dtm, baseTypeName);
            if (baseType != null) {
                Msg.info(this, "Creating pointer type: " + typeName +
                        " (base: " + baseType.getName() + ")");
                return new PointerDataType(baseType);
            }

            // If base type not found, warn and default to void*
            Msg.warn(this, "Base type not found for " + typeName + ", defaulting to void*");
            return new PointerDataType(dtm.getDataType("/void"));
        }

        // Check for Windows-style pointer types (PXXX)
        if (typeName.startsWith("P") && typeName.length() > 1) {
            String baseTypeName = typeName.substring(1);

            // Special case for PVOID
            if (baseTypeName.equals("VOID")) {
                return new PointerDataType(dtm.getDataType("/void"));
            }

            // Try to find the base type
            DataType baseType = findDataTypeByNameInAllCategories(dtm, baseTypeName);
            if (baseType != null) {
                return new PointerDataType(baseType);
            }

            Msg.warn(this, "Base type not found for " + typeName + ", defaulting to void*");
            return new PointerDataType(dtm.getDataType("/void"));
        }

        // Handle common built-in types
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
                return dtm.getDataType("/dword");  // Use dword as 4-byte float substitute
            case "double":
                return dtm.getDataType("/double");
            case "void":
                return dtm.getDataType("/void");
            default:
                // Try as a direct path
                DataType directType = dtm.getDataType("/" + typeName);
                if (directType != null) {
                    return directType;
                }

                // Return null if type not found - let caller handle error
                Msg.error(this, "Unknown type: " + typeName);
                return null;
        }
    }
    
    /**
     * Find a data type by name in all categories/folders of the data type manager
     * This searches through all categories rather than just the root
     */
    private DataType findDataTypeByNameInAllCategories(DataTypeManager dtm, String typeName) {
        // Try exact match first
        DataType result = searchByNameInAllCategories(dtm, typeName);
        if (result != null) {
            return result;
        }

        // Try lowercase
        return searchByNameInAllCategories(dtm, typeName.toLowerCase());
    }

    /**
     * Helper method to search for a data type by name in all categories
     */
    private DataType searchByNameInAllCategories(DataTypeManager dtm, String name) {
        // Get all data types from the manager
        Iterator<DataType> allTypes = dtm.getAllDataTypes();
        while (allTypes.hasNext()) {
            DataType dt = allTypes.next();
            // Check if the name matches exactly (case-sensitive) 
            if (dt.getName().equals(name)) {
                return dt;
            }
            // For case-insensitive, we want an exact match except for case
            if (dt.getName().equalsIgnoreCase(name)) {
                return dt;
            }
        }
        return null;
    }

    /**
     * Parse query parameters from the URL, e.g. ?offset=10&limit=100
     */
    private Map<String, String> parseQueryParams(UdsHttpExchange exchange) {
        Map<String, String> result = new HashMap<>();
        String query = exchange.getRequestURI().getQuery(); // e.g. offset=10&limit=100
        if (query != null) {
            String[] pairs = query.split("&");
            for (String p : pairs) {
                String[] kv = p.split("=");
                if (kv.length == 2) {
                    // URL decode parameter values
                    try {
                        String key = URLDecoder.decode(kv[0], StandardCharsets.UTF_8);
                        String value = URLDecoder.decode(kv[1], StandardCharsets.UTF_8);
                        result.put(key, value);
                    } catch (Exception e) {
                        Msg.error(this, "Error decoding URL parameter", e);
                    }
                }
            }
        }
        return result;
    }

    /**
     * Parse post body form params, e.g. oldName=foo&newName=bar
     */
    private Map<String, String> parsePostParams(UdsHttpExchange exchange) throws IOException {
        byte[] body = exchange.getRequestBody().readAllBytes();
        String bodyStr = new String(body, StandardCharsets.UTF_8);
        Map<String, String> params = new HashMap<>();
        for (String pair : bodyStr.split("&")) {
            String[] kv = pair.split("=");
            if (kv.length == 2) {
                // URL decode parameter values
                try {
                    String key = URLDecoder.decode(kv[0], StandardCharsets.UTF_8);
                    String value = URLDecoder.decode(kv[1], StandardCharsets.UTF_8);
                    params.put(key, value);
                } catch (Exception e) {
                    Msg.error(this, "Error decoding URL parameter", e);
                }
            }
        }
        return params;
    }

    /** Parse JSON from POST request body using Gson. */
    private Map<String, Object> parseJsonParams(UdsHttpExchange exchange) throws IOException {
        return JsonHelper.parseBody(exchange.getRequestBody());
    }
    

    /**
     * Convert Object (potentially List<Object>) to List<Map<String, String>>
     * Handles the type conversion from parsed JSON arrays of objects
     */
    @SuppressWarnings("unchecked")
    private List<Map<String, String>> convertToMapList(Object obj) {
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

    /**
     * Convert a list of strings into one big newline-delimited string, applying offset & limit.
     */
    private String paginateList(List<String> items, int offset, int limit) {
        int start = Math.max(0, offset);
        int end   = Math.min(items.size(), offset + limit);

        if (start >= items.size()) {
            return ""; // no items in range
        }
        List<String> sub = items.subList(start, end);
        return String.join("\n", sub);
    }

    /**
     * Parse an integer from a string, or return defaultValue if null/invalid.
     */
    private int parseIntOrDefault(String val, int defaultValue) {
        if (val == null) return defaultValue;
        try {
            return Integer.parseInt(val);
        }
        catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    private String objectToCommaSeparated(Object obj) {
        if (obj == null) return "";
        if (obj instanceof List) {
            StringBuilder sb = new StringBuilder();
            for (Object item : (List<?>) obj) {
                if (item != null) {
                    if (sb.length() > 0) sb.append(",");
                    sb.append(item.toString());
                }
            }
            return sb.toString();
        }
        return obj.toString();
    }


    /**
     * Get a program by name with error message if not found.
     * Returns a JSON error string if the program cannot be found.
     * 
     * @param programName The name of the program to find
     * @return A 2-element array: [0] = Program (or null), [1] = error message (or null if found)
     */
    public Object[] getProgramOrError(String programName) {
        Program program = getProgram(programName);
        
        if (program == null && programName != null && !programName.trim().isEmpty()) {
            var available = new ArrayList<String>();
            for (Program p : programProvider.getAllOpenPrograms()) available.add(p.getName());
            var err = new LinkedHashMap<String, Object>();
            err.put("error", "Program not found: " + programName);
            err.put("available_programs", available);
            return new Object[] { null, Response.ok(err) };
        }

        if (program == null) {
            return new Object[] { null, errorJson("No program currently loaded") };
        }
        
        return new Object[] { program, null };
    }

    /**
     * List all currently open programs in Ghidra
     */
    private Response saveCurrentProgram() {
        Program program = getCurrentProgram();
        if (program == null) {
            return errorJson("No program loaded");
        }

        final AtomicReference<Response> result = new AtomicReference<>();
        final AtomicReference<String> errorMsg = new AtomicReference<>();

        try {
            SwingUtilities.invokeAndWait(() -> {
                try {
                    ghidra.framework.model.DomainFile df = program.getDomainFile();
                    if (df == null) {
                        errorMsg.set("Program has no domain file");
                        return;
                    }
                    df.save(new ConsoleTaskMonitor());
                    final var name = program.getName();
                    JsonObject _jo4 = new JsonObject();
                    _jo4.addProperty("success", true);
                    _jo4.addProperty("program_name", name);
                    _jo4.addProperty("message", "Program saved successfully");
                    result.set(new Response.Ok(_jo4));
                } catch (Throwable e) {
                    String msg = e.getMessage() != null ? e.getMessage() : e.toString();
                    errorMsg.set(msg);
                    Msg.error(this, "Error saving program", e);
                }
            });

            if (errorMsg.get() != null) {
                return errorJson(errorMsg.get());
            }
        } catch (Throwable e) {
            String msg = e.getMessage() != null ? e.getMessage() : e.toString();
            return errorJson(msg);
        }

        return result.get() != null ? result.get() : errorJson("Unknown failure");
    }

    private Response listOpenPrograms() {
        Program[] programs = programProvider.getAllOpenPrograms();
        Program currentProgram = programProvider.getCurrentProgram();

        var list = new ArrayList<>();
        for (Program prog : programs) {
            final var name = prog.getName();
            final var path = prog.getDomainFile().getPathname();
            final var isCurrent = prog == currentProgram;
            final var execPath = prog.getExecutablePath() != null ? prog.getExecutablePath() : "";
            final var language = prog.getLanguageID().getIdAsString();
            final var compiler = prog.getCompilerSpec().getCompilerSpecID().getIdAsString();
            final var imageBase = prog.getImageBase().toString();
            final var memSize = prog.getMemory().getSize();
            final var funcCount = prog.getFunctionManager().getFunctionCount();
            JsonObject _jo5 = new JsonObject();
            _jo5.addProperty("prog_name", name);
            _jo5.addProperty("prog_path", path);
            _jo5.addProperty("is_current", isCurrent);
            _jo5.addProperty("executable_path", execPath);
            _jo5.addProperty("language_id", language);
            _jo5.addProperty("compiler_id", compiler);
            _jo5.addProperty("image_base", imageBase);
            _jo5.addProperty("memory_size", memSize);
            _jo5.addProperty("function_count", funcCount);
            list.add(_jo5);
        }

        final var progList = list;
        final var count = programs.length;
        final var currentName = currentProgram != null ? currentProgram.getName() : "";
        JsonObject _jo6 = new JsonObject();
        _jo6.add("program_list", JsonHelper.gson().toJsonTree(progList));
        _jo6.addProperty("program_count", count);
        _jo6.addProperty("current_program", currentName);
        return new Response.Ok(_jo6);
    }

    /**
     * Get detailed information about the currently active program
     */
    private Response getCurrentProgramInfo() {
        Program program = getCurrentProgram();
        if (program == null) {
            return errorJson("No program currently loaded");
        }

        final var name = program.getName();
        final var path = program.getDomainFile().getPathname();
        final var execPath = program.getExecutablePath() != null ? program.getExecutablePath() : "";
        final var execFormat = program.getExecutableFormat();
        final var language = program.getLanguageID().getIdAsString();
        final var compiler = program.getCompilerSpec().getCompilerSpecID().getIdAsString();
        final var addrSize = program.getAddressFactory().getDefaultAddressSpace().getSize();
        final var imageBase = program.getImageBase().toString();
        final var minAddr = program.getMinAddress() != null ? program.getMinAddress().toString() : "null";
        final var maxAddr = program.getMaxAddress() != null ? program.getMaxAddress().toString() : "null";
        final var memSize = program.getMemory().getSize();
        final var funcCount = program.getFunctionManager().getFunctionCount();
        final var symCount = program.getSymbolTable().getNumSymbols();
        final var dtCount = program.getDataTypeManager().getDataTypeCount(true);
        final var creationDate = program.getCreationDate() != null ? program.getCreationDate().toString() : "unknown";
        final var memBlockCount = program.getMemory().getBlocks().length;

        JsonObject _jo7 = new JsonObject();
        _jo7.addProperty("prog_name", name);
        _jo7.addProperty("prog_path", path);
        _jo7.addProperty("executable_path", execPath);
        _jo7.addProperty("executable_format", execFormat);
        _jo7.addProperty("language_id", language);
        _jo7.addProperty("compiler_id", compiler);
        _jo7.addProperty("address_size", addrSize);
        _jo7.addProperty("image_base", imageBase);
        _jo7.addProperty("min_address", minAddr);
        _jo7.addProperty("max_address", maxAddr);
        _jo7.addProperty("memory_size", memSize);
        _jo7.addProperty("function_count", funcCount);
        _jo7.addProperty("symbol_count", symCount);
        _jo7.addProperty("data_type_count", dtCount);
        _jo7.addProperty("creation_date", creationDate);
        _jo7.addProperty("memory_block_count", memBlockCount);
        return new Response.Ok(_jo7);
    }

    /**
     * Switch MCP context to a different open program by name
     */
    private Response switchProgram(String programName) {
        if (programName == null || programName.trim().isEmpty()) {
            return errorJson("Program name is required");
        }

        // Use MultiToolProgramProvider which searches across all CodeBrowser windows
        Program targetProgram = programProvider.getProgram(programName);

        if (targetProgram == null) {
            var available = new ArrayList<String>();
            for (Program prog : programProvider.getAllOpenPrograms()) {
                available.add(prog.getName());
            }
            final var requestedName = programName;
            final var availableList = available;
            JsonObject _jo8 = new JsonObject();
            _jo8.addProperty("error", "Program not found: " + requestedName);
            _jo8.add("available_programs", JsonHelper.gson().toJsonTree(availableList));
            return new Response.Ok(_jo8);
        }

        // Switch to the target program (finds owning tool and sets it there)
        programProvider.setCurrentProgram(targetProgram);

        final var switchedTo = targetProgram.getName();
        final var switchedPath = targetProgram.getDomainFile().getPathname();
        JsonObject _jo9 = new JsonObject();
        _jo9.addProperty("success", true);
        _jo9.addProperty("switched_to", switchedTo);
        _jo9.addProperty("path", switchedPath);
        return new Response.Ok(_jo9);
    }

    /**
     * List all files in the current Ghidra project
     */
    private Response listProjectFiles(String folderPath) {
        ghidra.framework.model.Project project = getActiveTool().getProject();
        if (project == null) {
            return errorJson("No project is currently open");
        }

        ghidra.framework.model.ProjectData projectData = project.getProjectData();
        ghidra.framework.model.DomainFolder rootFolder = projectData.getRootFolder();

        // If folder path specified, navigate to it
        ghidra.framework.model.DomainFolder targetFolder = rootFolder;
        if (folderPath != null && !folderPath.trim().isEmpty() && !folderPath.equals("/")) {
            // Navigate through path segments (handles nested folders like "LoD/1.07")
            String cleanPath = folderPath.startsWith("/") ? folderPath.substring(1) : folderPath;
            String[] pathParts = cleanPath.split("/");
            for (String part : pathParts) {
                if (part.isEmpty()) continue;
                ghidra.framework.model.DomainFolder nextFolder = targetFolder.getFolder(part);
                if (nextFolder == null) {
                    return errorJson("Folder not found: " + folderPath);
                }
                targetFolder = nextFolder;
            }
        }

        // List subfolders
        var folderNames = new ArrayList<String>();
        for (ghidra.framework.model.DomainFolder sub : targetFolder.getFolders()) {
            folderNames.add(sub.getName());
        }

        // List files in folder
        var fileList = new ArrayList<>();
        for (ghidra.framework.model.DomainFile file : targetFolder.getFiles()) {
            final var fname = file.getName();
            final var fpath = file.getPathname();
            final var ftype = file.getContentType();
            final var fver = file.getVersion();
            final var fro = file.isReadOnly();
            final var fversioned = file.isVersioned();
            JsonObject _jo10 = new JsonObject();
            _jo10.addProperty("name", fname);
            _jo10.addProperty("path", fpath);
            _jo10.addProperty("content_type", ftype);
            _jo10.addProperty("version", fver);
            _jo10.addProperty("is_read_only", fro);
            _jo10.addProperty("is_versioned", fversioned);
            fileList.add(_jo10);
        }

        final var projName = project.getName();
        final var currFolder = targetFolder.getPathname();
        final var folders = folderNames;
        final var files = fileList;
        JsonObject _jo11 = new JsonObject();
        _jo11.addProperty("project_name", projName);
        _jo11.addProperty("current_folder", currFolder);
        _jo11.add("sub_folders", JsonHelper.gson().toJsonTree(folders));
        _jo11.add("project_files", JsonHelper.gson().toJsonTree(files));
        return new Response.Ok(_jo11);
    }

    /**
     * Open a program from the current project by path
     */
    private Response openProgramFromProject(String path) {
        if (path == null || path.trim().isEmpty()) {
            return errorJson("Program path is required");
        }

        ghidra.framework.model.Project project = getActiveTool().getProject();
        if (project == null) {
            return errorJson("No project is currently open");
        }

        ghidra.framework.model.ProjectData projectData = project.getProjectData();
        ghidra.framework.model.DomainFile domainFile = projectData.getFile(path);

        if (domainFile == null) {
            return errorJson("File not found in project: " + path);
        }

        // Check if already open across all tools
        for (Program prog : programProvider.getAllOpenPrograms()) {
            if (prog.getDomainFile().getPathname().equals(path)) {
                // Already open, just switch to it
                programProvider.setCurrentProgram(prog);
                final var alreadyName = prog.getName();
                final var alreadyPath = path;
                JsonObject _jo12 = new JsonObject();
                _jo12.addProperty("success", true);
                _jo12.addProperty("message", "Program already open, switched to it");
                _jo12.addProperty("name", alreadyName);
                _jo12.addProperty("prog_path", alreadyPath);
                return new Response.Ok(_jo12);
            }
        }

        // Need a ProgramManager to open new programs — find one from any tool
        ProgramManager pm = programProvider.findProgramManager();
        if (pm == null) {
            return errorJson("No CodeBrowser window available to open programs");
        }

        // Open via DomainFile overload — OPEN_CURRENT makes it the active program.
        // This bypasses the manual getDomainObject + openProgram(Program) path and
        // lets ProgramManagerPlugin handle the open lifecycle properly.
        try {
            Program program = pm.openProgram(domainFile, ProgramManager.OPEN_CURRENT);
            if (program == null) {
                return errorJson("Failed to open program: " + path);
            }

            // Auto-analyze silently if not yet analyzed, suppressing the "Analyze?" dialog
            ghidra.app.plugin.core.analysis.AutoAnalysisManager mgr =
                ghidra.app.plugin.core.analysis.AutoAnalysisManager.getAnalysisManager(program);
            if (mgr != null && !mgr.isAnalyzing()) {
                mgr.initializeOptions();
                mgr.reAnalyzeAll(program.getMemory());
                mgr.startAnalysis(ghidra.util.task.TaskMonitor.DUMMY);
            }

            final var openedName = program.getName();
            final var openedPath = path;
            final var funcCount = program.getFunctionManager().getFunctionCount();
            JsonObject _jo13 = new JsonObject();
            _jo13.addProperty("success", true);
            _jo13.addProperty("message", "Program opened successfully");
            _jo13.addProperty("name", openedName);
            _jo13.addProperty("prog_path", openedPath);
            _jo13.addProperty("function_count", funcCount);
            return new Response.Ok(_jo13);
        } catch (Exception e) {
            return errorJson("Failed to open program: " + e.getMessage());
        }
    }

    /**
     * Compute a normalized hash from function instructions.
     * This ignores absolute addresses but preserves the logical structure.
     */
    private String computeNormalizedFunctionHash(Program program, Function func) {
        StringBuilder normalized = new StringBuilder();
        Listing listing = program.getListing();
        AddressSetView functionBody = func.getBody();
        InstructionIterator instructions = listing.getInstructions(functionBody, true);

        Address funcStart = func.getEntryPoint();

        while (instructions.hasNext()) {
            Instruction instr = instructions.next();

            // Add mnemonic
            normalized.append(instr.getMnemonicString()).append(" ");

            // Process each operand
            int numOperands = instr.getNumOperands();
            for (int i = 0; i < numOperands; i++) {
                int opType = instr.getOperandType(i);

                // Check if this operand contains an address reference
                boolean isAddressRef = (opType & ghidra.program.model.lang.OperandType.ADDRESS) != 0 ||
                                       (opType & ghidra.program.model.lang.OperandType.CODE) != 0 ||
                                       (opType & ghidra.program.model.lang.OperandType.DATA) != 0;

                if (isAddressRef) {
                    // For address references, use relative offset from function start if within function,
                    // otherwise use a generic placeholder
                    Reference[] refs = instr.getOperandReferences(i);
                    if (refs.length > 0) {
                        Address targetAddr = refs[0].getToAddress();
                        if (functionBody.contains(targetAddr)) {
                            // Internal reference - use relative offset
                            long relOffset = targetAddr.subtract(funcStart);
                            normalized.append("REL+").append(relOffset);
                        } else {
                            // External reference - use generic marker with reference type
                            RefType refType = refs[0].getReferenceType();
                            if (refType.isCall()) {
                                normalized.append("CALL_EXT");
                            } else if (refType.isData()) {
                                normalized.append("DATA_EXT");
                            } else {
                                normalized.append("EXT_REF");
                            }
                        }
                    } else {
                        normalized.append("ADDR");
                    }
                } else if ((opType & ghidra.program.model.lang.OperandType.REGISTER) != 0) {
                    // Keep register names as-is (they're part of the function's logic)
                    normalized.append(instr.getDefaultOperandRepresentation(i));
                } else if ((opType & ghidra.program.model.lang.OperandType.SCALAR) != 0) {
                    // For small constants (likely magic numbers or offsets), keep the value
                    // For large constants (likely addresses), normalize
                    Object[] opObjects = instr.getOpObjects(i);
                    if (opObjects.length > 0 && opObjects[0] instanceof ghidra.program.model.scalar.Scalar) {
                        ghidra.program.model.scalar.Scalar scalar = (ghidra.program.model.scalar.Scalar) opObjects[0];
                        long value = scalar.getValue();
                        // Keep small constants (< 0x10000), normalize large ones
                        if (Math.abs(value) < 0x10000) {
                            normalized.append("IMM:").append(value);
                        } else {
                            normalized.append("IMM_LARGE");
                        }
                    } else {
                        normalized.append(instr.getDefaultOperandRepresentation(i));
                    }
                } else {
                    // Other operand types - use default representation
                    normalized.append(instr.getDefaultOperandRepresentation(i));
                }

                if (i < numOperands - 1) {
                    normalized.append(",");
                }
            }

            normalized.append(";");
        }

        // Compute SHA-256 hash of the normalized representation
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
            // Fallback to simple string hash
            return Integer.toHexString(normalized.toString().hashCode());
        }
    }

    /**
     * Export all documentation for a function (for use in cross-binary propagation)
     */
    private Response getFunctionDocumentation(String functionAddress) throws Exception {
        Program program = getCurrentProgram();
        if (program == null) {
            return errorJson("No program loaded");
        }

        Address addr = program.getAddressFactory().getAddress(functionAddress);
        if (addr == null) {
            return errorJson("Invalid address: " + functionAddress);
        }

        Function func = program.getFunctionManager().getFunctionAt(addr);
        if (func == null) {
            return errorJson("No function at address: " + functionAddress);
        }

        final var hash = computeNormalizedFunctionHash(program, func);
        final var sourceProg = program.getName();
        final var sourceAddr = addr.toString();
        final var funcName = func.getName();
        final var returnType = func.getReturnType().getName();
        final var callingConvention = func.getCallingConventionName() != null ? func.getCallingConventionName() : "";
        final var plateComment = func.getComment();

        // Parameters
        var paramList = new ArrayList<>();
        for (Parameter p : func.getParameters()) {
            final var pOrdinal = p.getOrdinal();
            final var pName = p.getName();
            final var pType = p.getDataType().getName();
            final var pComment = p.getComment();
            JsonObject _jo14 = new JsonObject();
            _jo14.addProperty("ordinal", pOrdinal);
            _jo14.addProperty("name", pName);
            _jo14.addProperty("type", pType);
            _jo14.addProperty("comment", pComment);
            paramList.add(_jo14);
        }

        // Local variables (from decompilation if available)
        var localVarList = new ArrayList<>();
        DecompileResults decompResults = decompileFunction(func, program);
        if (decompResults != null && decompResults.decompileCompleted()) {
            ghidra.program.model.pcode.HighFunction highFunc = decompResults.getHighFunction();
            if (highFunc != null) {
                Iterator<ghidra.program.model.pcode.HighSymbol> symbols = highFunc.getLocalSymbolMap().getSymbols();
                while (symbols.hasNext()) {
                    ghidra.program.model.pcode.HighSymbol sym = symbols.next();
                    if (sym.isParameter()) continue;
                    final var symName = sym.getName();
                    final var symType = sym.getDataType().getName();
                    ghidra.program.model.pcode.HighVariable highVar = sym.getHighVariable();
                    final var storage = (highVar != null && highVar.getRepresentative() != null)
                            ? highVar.getRepresentative().toString()
                            : null;
                    JsonObject _jo15 = new JsonObject();
                    _jo15.addProperty("name", symName);
                    _jo15.addProperty("type", symType);
                    _jo15.addProperty("var_storage", storage);
                    localVarList.add(_jo15);
                }
            }
        }

        // Inline comments (EOL and PRE comments within function body)
        var commentList = new ArrayList<>();
        AddressSetView functionBody = func.getBody();
        Listing listing = program.getListing();
        Address funcStart = func.getEntryPoint();
        for (Address cAddr : functionBody.getAddresses(true)) {
            String eolComment = listing.getComment(ghidra.program.model.listing.CodeUnit.EOL_COMMENT, cAddr);
            String preComment = listing.getComment(ghidra.program.model.listing.CodeUnit.PRE_COMMENT, cAddr);
            if (eolComment != null || preComment != null) {
                final var relOffset = cAddr.subtract(funcStart);
                final var eol = eolComment;
                final var pre = preComment;
                JsonObject _jo16 = new JsonObject();
                _jo16.addProperty("relative_offset", relOffset);
                _jo16.addProperty("eol_comment", eol);
                _jo16.addProperty("pre_comment", pre);
                commentList.add(_jo16);
            }
        }

        // Labels within function
        var labelList = new ArrayList<>();
        SymbolTable symTable = program.getSymbolTable();
        for (Address lAddr : functionBody.getAddresses(true)) {
            Symbol[] symbols = symTable.getSymbols(lAddr);
            for (Symbol sym : symbols) {
                if (sym.getSymbolType() == SymbolType.LABEL && !sym.getName().equals(func.getName())) {
                    final var relOffset = lAddr.subtract(funcStart);
                    final var symName = sym.getName();
                    JsonObject _jo17 = new JsonObject();
                    _jo17.addProperty("relative_offset", relOffset);
                    _jo17.addProperty("name", symName);
                    labelList.add(_jo17);
                }
            }
        }

        // Completeness score
        List<String> undefinedVars = new ArrayList<>();
        for (Parameter param : func.getParameters()) {
            if (param.getName().startsWith("param_")) {
                undefinedVars.add(param.getName());
            }
            if (param.getDataType().getName().startsWith("undefined")) {
                undefinedVars.add(param.getName());
            }
        }
        final var completenessScore = calculateCompletenessScore(func, undefinedVars.size(), 0, 0, 0, 0, 0, 0);

        final var params = paramList;
        final var localVars = localVarList;
        final var comments = commentList;
        final var labels = labelList;
        JsonObject _jo18 = new JsonObject();
        _jo18.addProperty("func_hash", hash);
        _jo18.addProperty("source_program", sourceProg);
        _jo18.addProperty("source_address", sourceAddr);
        _jo18.addProperty("function_name", funcName);
        _jo18.addProperty("return_type", returnType);
        _jo18.addProperty("calling_convention", callingConvention);
        _jo18.addProperty("plate_comment", plateComment);
        _jo18.add("parameters", JsonHelper.gson().toJsonTree(params));
        _jo18.add("local_variables", JsonHelper.gson().toJsonTree(localVars));
        _jo18.add("func_comments", JsonHelper.gson().toJsonTree(comments));
        _jo18.add("func_labels", JsonHelper.gson().toJsonTree(labels));
        _jo18.addProperty("doc_completeness_score", completenessScore);
        return new Response.Ok(_jo18);
    }

    /**
     * Apply documentation from a source function to a target function.
     * Expects JSON body with: target_address, source_documentation (from getFunctionDocumentation)
     */
    private Response applyFunctionDocumentation(String jsonBody) throws Exception {
        Program program = getCurrentProgram();
        if (program == null) {
            return errorJson("No program loaded");
        }

        // Parse JSON manually (simple parsing for this format)
        String targetAddress = extractJsonString(jsonBody, "target_address");
        String functionName = extractJsonString(jsonBody, "function_name");
        String returnType = extractJsonString(jsonBody, "return_type");
        String callingConvention = extractJsonString(jsonBody, "calling_convention");
        String plateComment = extractJsonString(jsonBody, "plate_comment");

        if (targetAddress == null) {
            return errorJson("target_address is required");
        }

        Address addr = program.getAddressFactory().getAddress(targetAddress);
        if (addr == null) {
            return errorJson("Invalid target address: " + targetAddress);
        }

        Function func = program.getFunctionManager().getFunctionAt(addr);
        if (func == null) {
            return errorJson("No function at target address: " + targetAddress);
        }

        final AtomicBoolean success = new AtomicBoolean(false);
        final AtomicReference<String> errorMsg = new AtomicReference<>(null);
        final AtomicInteger changesApplied = new AtomicInteger(0);

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Apply Function Documentation");
                try {
                    // Apply function name
                    if (functionName != null && !functionName.isEmpty() && !functionName.equals(func.getName())) {
                        try {
                            func.setName(functionName, SourceType.USER_DEFINED);
                            changesApplied.incrementAndGet();
                        } catch (Exception e) {
                            Msg.warn(this, "Could not set function name: " + e.getMessage());
                        }
                    }
                    
                    // Apply plate comment
                    if (plateComment != null && !plateComment.isEmpty()) {
                        func.setComment(plateComment);
                        changesApplied.incrementAndGet();
                    }
                    
                    // Apply calling convention
                    if (callingConvention != null && !callingConvention.isEmpty()) {
                        try {
                            func.setCallingConvention(callingConvention);
                            changesApplied.incrementAndGet();
                        } catch (Exception e) {
                            Msg.warn(this, "Could not set calling convention: " + e.getMessage());
                        }
                    }
                    
                    // Apply return type
                    if (returnType != null && !returnType.isEmpty()) {
                        DataType dt = findDataTypeByNameInAllCategories(program.getDataTypeManager(), returnType);
                        if (dt != null) {
                            try {
                                func.setReturnType(dt, SourceType.USER_DEFINED);
                                changesApplied.incrementAndGet();
                            } catch (Exception e) {
                                Msg.warn(this, "Could not set return type: " + e.getMessage());
                            }
                        }
                    }
                    
                    // Apply parameter names and types from JSON array
                    String paramsJson = extractJsonArray(jsonBody, "parameters");
                    if (paramsJson != null) {
                        applyParameterDocumentation(func, program, paramsJson, changesApplied);
                    }
                    
                    // Apply comments from JSON array
                    String commentsJson = extractJsonArray(jsonBody, "comments");
                    if (commentsJson != null) {
                        applyCommentsDocumentation(func, program, commentsJson, changesApplied);
                    }
                    
                    // Apply labels from JSON array
                    String labelsJson = extractJsonArray(jsonBody, "labels");
                    if (labelsJson != null) {
                        applyLabelsDocumentation(func, program, labelsJson, changesApplied);
                    }
                    
                    success.set(true);
                } catch (Exception e) {
                    errorMsg.set(e.getMessage());
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (Exception e) {
            return errorJson("Failed to apply documentation: " + e.getMessage());
        }

        if (success.get()) {
            final var funcName = func.getName();
            final var addrStr = addr.toString();
            final var changes = changesApplied.get();
            JsonObject _jo19 = new JsonObject();
            _jo19.addProperty("success", true);
            _jo19.addProperty("changes_applied", changes);
            _jo19.addProperty("function", funcName);
            _jo19.addProperty("address", addrStr);
            return new Response.Ok(_jo19);
        } else {
            return errorJson(errorMsg.get() != null ? errorMsg.get() : "Unknown error");
        }

    }

    /**
     * Helper to extract a string value from simple JSON
     */
    private String extractJsonString(String json, String key) {
        String pattern = "\"" + key + "\"\\s*:\\s*\"([^\"]*)\"";
        java.util.regex.Pattern p = java.util.regex.Pattern.compile(pattern);
        java.util.regex.Matcher m = p.matcher(json);
        if (m.find()) {
            return m.group(1).replace("\\\"", "\"").replace("\\n", "\n");
        }
        // Also check for null value
        pattern = "\"" + key + "\"\\s*:\\s*null";
        if (json.matches(".*" + pattern + ".*")) {
            return null;
        }
        return null;
    }

    /**
     * Helper to extract a JSON array as string
     */
    private String extractJsonArray(String json, String key) {
        String pattern = "\"" + key + "\"\\s*:\\s*\\[";
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

    /**
     * Apply parameter documentation from JSON
     */
    private void applyParameterDocumentation(Function func, Program program, String paramsJson, AtomicInteger changesApplied) {
        // Parse simple array format: [{"ordinal": 0, "name": "...", "type": "..."}, ...]
        java.util.regex.Pattern p = java.util.regex.Pattern.compile(
            "\\{\\s*\"ordinal\"\\s*:\\s*(\\d+).*?\"name\"\\s*:\\s*\"([^\"]*)\".*?\"type\"\\s*:\\s*\"([^\"]*)\"");
        java.util.regex.Matcher m = p.matcher(paramsJson);
        
        Parameter[] params = func.getParameters();
        while (m.find()) {
            try {
                int ordinal = Integer.parseInt(m.group(1));
                String name = m.group(2);
                String typeName = m.group(3);
                
                if (ordinal < params.length) {
                    Parameter param = params[ordinal];
                    
                    // Set name if different and not generic
                    if (!name.startsWith("param_") && !name.equals(param.getName())) {
                        try {
                            param.setName(name, SourceType.USER_DEFINED);
                            changesApplied.incrementAndGet();
                        } catch (Exception e) {
                            Msg.warn(this, "Could not set parameter name: " + e.getMessage());
                        }
                    }
                    
                    // Set type if different
                    if (!typeName.startsWith("undefined") && !typeName.equals(param.getDataType().getName())) {
                        DataType dt = findDataTypeByNameInAllCategories(program.getDataTypeManager(), typeName);
                        if (dt != null) {
                            try {
                                param.setDataType(dt, SourceType.USER_DEFINED);
                                changesApplied.incrementAndGet();
                            } catch (Exception e) {
                                Msg.warn(this, "Could not set parameter type: " + e.getMessage());
                            }
                        }
                    }
                }
            } catch (Exception e) {
                // Skip this parameter
            }
        }
    }

    /**
     * Apply inline comments from JSON
     */
    private void applyCommentsDocumentation(Function func, Program program, String commentsJson, AtomicInteger changesApplied) {
        // Parse: [{"relative_offset": 0, "eol_comment": "...", "pre_comment": "..."}, ...]
        java.util.regex.Pattern p = java.util.regex.Pattern.compile(
            "\\{\\s*\"relative_offset\"\\s*:\\s*(\\d+)");
        java.util.regex.Matcher m = p.matcher(commentsJson);
        
        Address funcStart = func.getEntryPoint();
        Listing listing = program.getListing();
        
        while (m.find()) {
            try {
                long relOffset = Long.parseLong(m.group(1));
                Address commentAddr = funcStart.add(relOffset);
                
                // Extract comments for this entry
                int entryStart = m.start();
                int entryEnd = commentsJson.indexOf('}', entryStart);
                if (entryEnd < 0) continue;
                String entry = commentsJson.substring(entryStart, entryEnd + 1);
                
                String eolComment = extractJsonString(entry, "eol_comment");
                String preComment = extractJsonString(entry, "pre_comment");
                
                CodeUnit cu = listing.getCodeUnitAt(commentAddr);
                if (cu != null) {
                    if (eolComment != null && !eolComment.isEmpty()) {
                        cu.setComment(ghidra.program.model.listing.CodeUnit.EOL_COMMENT, eolComment);
                        changesApplied.incrementAndGet();
                    }
                    if (preComment != null && !preComment.isEmpty()) {
                        cu.setComment(ghidra.program.model.listing.CodeUnit.PRE_COMMENT, preComment);
                        changesApplied.incrementAndGet();
                    }
                }
            } catch (Exception e) {
                // Skip this comment
            }
        }
    }

    /**
     * Apply labels from JSON
     */
    private void applyLabelsDocumentation(Function func, Program program, String labelsJson, AtomicInteger changesApplied) {
        // Parse: [{"relative_offset": 0, "name": "..."}, ...]
        java.util.regex.Pattern p = java.util.regex.Pattern.compile(
            "\\{\\s*\"relative_offset\"\\s*:\\s*(\\d+).*?\"name\"\\s*:\\s*\"([^\"]*)\"");
        java.util.regex.Matcher m = p.matcher(labelsJson);
        
        Address funcStart = func.getEntryPoint();
        SymbolTable symTable = program.getSymbolTable();
        
        while (m.find()) {
            try {
                long relOffset = Long.parseLong(m.group(1));
                String labelName = m.group(2);
                
                Address labelAddr = funcStart.add(relOffset);
                
                // Check if label already exists
                Symbol existing = symTable.getPrimarySymbol(labelAddr);
                if (existing == null || existing.getSymbolType() != SymbolType.LABEL || 
                    !existing.getName().equals(labelName)) {
                    try {
                        symTable.createLabel(labelAddr, labelName, SourceType.USER_DEFINED);
                        changesApplied.incrementAndGet();
                    } catch (Exception e) {
                        Msg.warn(this, "Could not create label: " + e.getMessage());
                    }
                }
            } catch (Exception e) {
                // Skip this label
            }
        }
    }

    /** Builds a JSON error response body. Delegates to JsonHelper for consistent format. */
    private static Response.Err errorJson(String message) {
        return new Response.Err(message != null ? message : "Unknown error");
    }

    /**
     * Wraps an HttpHandler so that any Throwable is caught and returned as a JSON error response.
     * This prevents uncaught exceptions from crashing the HTTP server and dropping connections.
     */
    private UdsHttpServer.Handler safeHandler(UdsHttpServer.Handler handler) {
        return exchange -> {
            try {
                handler.handle(exchange);
            } catch (Throwable e) {
                try {
                    String msg = e.getMessage() != null ? e.getMessage() : e.toString();
                    sendResponse(exchange, new Response.Err(msg));
                } catch (Throwable ignored) {
                    // Last resort - response already sent or exchange broken
                    Msg.error(this, "Failed to send error response", ignored);
                }
            }
        };
    }

    private void sendResponse(UdsHttpExchange exchange, Response response) throws IOException {
        String body = switch (response) {
            case Response.Ok(var data)     -> JsonHelper.toJson(data);
            case Response.Err(var message) -> JsonHelper.toJson(java.util.Map.of("error", message));
            case Response.Text(var text)   -> text;
        };
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        Headers headers = exchange.getResponseHeaders();
        headers.set("Content-Type", "text/plain; charset=utf-8");
        exchange.sendResponseHeaders(200, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
            os.flush();
        }
    }

    /**
     * Get labels within a specific function by name
     */
    public Response getFunctionLabels(String functionName, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) {
            return errorJson("No program loaded");
        }

        SymbolTable symbolTable = program.getSymbolTable();
        FunctionManager functionManager = program.getFunctionManager();

        Function function = null;
        for (Function f : functionManager.getFunctions(true)) {
            if (f.getName().equals(functionName)) {
                function = f;
                break;
            }
        }

        if (function == null) {
            return errorJson("Function not found: " + functionName);
        }

        AddressSetView functionBody = function.getBody();
        SymbolIterator symbols = symbolTable.getSymbolIterator();
        var list = new ArrayList<>();
        int count = 0;
        int skipped = 0;

        while (symbols.hasNext() && count < limit) {
            Symbol symbol = symbols.next();
            if (symbol.getSymbolType() == SymbolType.LABEL &&
                functionBody.contains(symbol.getAddress())) {

                if (skipped < offset) {
                    skipped++;
                    continue;
                }

                final var addr = symbol.getAddress().toString();
                final var name = symbol.getName();
                final var source = symbol.getSource().toString();
                JsonObject _jo20 = new JsonObject();
                _jo20.addProperty("address", addr);
                _jo20.addProperty("label_name", name);
                _jo20.addProperty("label_source", source);
                list.add(_jo20);
                count++;
            }
        }

        final var items = list;
        JsonObject _jo21 = new JsonObject();
        _jo21.add("labels", JsonHelper.gson().toJsonTree(items));
        return new Response.Ok(_jo21);
    }

    /**
     * Rename a label at the specified address
     */
    public Response renameLabel(String addressStr, String oldName, String newName) {
        Program program = getCurrentProgram();
        if (program == null) {
            return errorJson("No program loaded");
        }

        try {
            Address address = program.getAddressFactory().getAddress(addressStr);
            if (address == null) {
                return errorJson("Invalid address: " + addressStr);
            }

            SymbolTable symbolTable = program.getSymbolTable();
            Symbol[] symbols = symbolTable.getSymbols(address);

            // Find the specific symbol with the old name
            Symbol targetSymbol = null;
            for (Symbol symbol : symbols) {
                if (symbol.getName().equals(oldName) && symbol.getSymbolType() == SymbolType.LABEL) {
                    targetSymbol = symbol;
                    break;
                }
            }

            if (targetSymbol == null) {
                return errorJson("Label not found: " + oldName + " at address " + addressStr);
            }

            // Check if new name already exists at this address
            for (Symbol symbol : symbols) {
                if (symbol.getName().equals(newName) && symbol.getSymbolType() == SymbolType.LABEL) {
                    return errorJson("Label with name '" + newName + "' already exists at address " + addressStr);
                }
            }

            // Perform the rename
            int transactionId = program.startTransaction("Rename Label");
            try {
                targetSymbol.setName(newName, SourceType.USER_DEFINED);
                var result = new LinkedHashMap<String, Object>();
                result.put("status", "success");
                result.put("old_name", oldName);
                result.put("new_name", newName);
                result.put("address", addressStr);
                return new Response.Ok(result);
            } catch (Exception e) {
                return errorJson("Error renaming label: " + e.getMessage());
            } finally {
                program.endTransaction(transactionId, true);
            }

        } catch (Exception e) {
            return errorJson("Error processing request: " + e.getMessage());
        }
    }

    /**
     * Get all jump target addresses from a function's disassembly
     */
    public Response getFunctionJumpTargets(String functionName, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) {
            return errorJson("No program loaded");
        }

        FunctionManager functionManager = program.getFunctionManager();

        Function function = null;
        for (Function f : functionManager.getFunctions(true)) {
            if (f.getName().equals(functionName)) {
                function = f;
                break;
            }
        }

        if (function == null) {
            return errorJson("Function not found: " + functionName);
        }

        AddressSetView functionBody = function.getBody();
        Listing listing = program.getListing();
        Set<Address> jumpTargets = new HashSet<>();

        InstructionIterator instructions = listing.getInstructions(functionBody, true);
        while (instructions.hasNext()) {
            Instruction instr = instructions.next();
            if (instr.getFlowType().isJump()) {
                for (Reference ref : instr.getReferencesFrom()) {
                    Address targetAddr = ref.getToAddress();
                    if (targetAddr != null && program.getMemory().contains(targetAddr)) {
                        jumpTargets.add(targetAddr);
                    }
                }
                if (instr.getFlowType().isConditional()) {
                    Address fallThroughAddr = instr.getFallThrough();
                    if (fallThroughAddr != null) {
                        jumpTargets.add(fallThroughAddr);
                    }
                }
            }
        }

        List<Address> sortedTargets = new ArrayList<>(jumpTargets);
        Collections.sort(sortedTargets);

        var list = new ArrayList<>();
        int count = 0;
        int skipped = 0;

        for (Address target : sortedTargets) {
            if (count >= limit) break;
            if (skipped < offset) { skipped++; continue; }

            final var addrStr = target.toString();
            final String context;
            Function targetFunc = functionManager.getFunctionContaining(target);
            if (targetFunc != null) {
                context = targetFunc.getName();
            } else {
                Symbol symbol = program.getSymbolTable().getPrimarySymbol(target);
                context = symbol != null ? symbol.getName() : null;
            }

            JsonObject _jo22 = new JsonObject();
            _jo22.addProperty("address", addrStr);
            _jo22.addProperty("label", context);
            list.add(_jo22);
            count++;
        }

        final var items = list;
        JsonObject _jo23 = new JsonObject();
        _jo23.add("jump_targets", JsonHelper.gson().toJsonTree(items));
        return new Response.Ok(_jo23);
    }

    /**
     * Create a new label at the specified address
     */
    public Response createLabel(String addressStr, String labelName) {
        Program program = getCurrentProgram();
        if (program == null) {
            return errorJson("No program loaded");
        }

        if (addressStr == null || addressStr.isEmpty()) {
            return errorJson("Address is required");
        }

        if (labelName == null || labelName.isEmpty()) {
            return errorJson("Label name is required");
        }

        try {
            Address address = program.getAddressFactory().getAddress(addressStr);
            if (address == null) {
                return errorJson("Invalid address: " + addressStr);
            }

            SymbolTable symbolTable = program.getSymbolTable();

            // Check if a label with this name already exists at this address
            Symbol[] existingSymbols = symbolTable.getSymbols(address);
            for (Symbol symbol : existingSymbols) {
                if (symbol.getName().equals(labelName) && symbol.getSymbolType() == SymbolType.LABEL) {
                    return errorJson("Label '" + labelName + "' already exists at address " + addressStr);
                }
            }

            // Check if the label name is already used elsewhere (optional warning)
            SymbolIterator existingLabels = symbolTable.getSymbolIterator(labelName, true);
            if (existingLabels.hasNext()) {
                Symbol existingSymbol = existingLabels.next();
                if (existingSymbol.getSymbolType() == SymbolType.LABEL) {
                    // Allow creation but warn about duplicate name
                    Msg.warn(this, "Label name '" + labelName + "' already exists at address " +
                            existingSymbol.getAddress() + ". Creating duplicate at " + addressStr);
                }
            }

            // Create the label
            int transactionId = program.startTransaction("Create Label");
            try {
                Symbol newSymbol = symbolTable.createLabel(address, labelName, SourceType.USER_DEFINED);
                if (newSymbol != null) {
                    var result = new LinkedHashMap<String, Object>();
                    result.put("status", "success");
                    result.put("name", labelName);
                    result.put("address", addressStr);
                    return new Response.Ok(result);
                } else {
                    return errorJson("Failed to create label '" + labelName + "' at address " + addressStr);
                }
            } catch (Exception e) {
                return errorJson("Error creating label: " + e.getMessage());
            } finally {
                program.endTransaction(transactionId, true);
            }

        } catch (Exception e) {
            return errorJson("Error processing request: " + e.getMessage());
        }
    }

    /**
     * v1.5.1: Batch create multiple labels in a single transaction
     * Reduces API calls and prevents user interruption hooks from triggering multiple times
     *
     * @param labels List of label objects with "address" and "name" fields
     * @return result object with success status and counts
     */
    public Response batchCreateLabels(List<Map<String, String>> labels) {
        Program program = getCurrentProgram();
        if (program == null) {
            return errorJson("No program loaded");
        }

        if (labels == null || labels.isEmpty()) {
            return errorJson("No labels provided");
        }

        final AtomicInteger successCount = new AtomicInteger(0);
        final AtomicInteger skipCount = new AtomicInteger(0);
        final AtomicInteger errorCount = new AtomicInteger(0);
        final List<String> errors = new ArrayList<>();

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Batch Create Labels");
                try {
                    SymbolTable symbolTable = program.getSymbolTable();

                    for (Map<String, String> labelEntry : labels) {
                        String addressStr = labelEntry.get("address");
                        String labelName = labelEntry.get("name");

                        if (addressStr == null || addressStr.isEmpty()) {
                            errors.add("Missing address in label entry");
                            errorCount.incrementAndGet();
                            continue;
                        }

                        if (labelName == null || labelName.isEmpty()) {
                            errors.add("Missing name for address " + addressStr);
                            errorCount.incrementAndGet();
                            continue;
                        }

                        try {
                            Address address = program.getAddressFactory().getAddress(addressStr);
                            if (address == null) {
                                errors.add("Invalid address: " + addressStr);
                                errorCount.incrementAndGet();
                                continue;
                            }

                            Symbol[] existingSymbols = symbolTable.getSymbols(address);
                            boolean labelExists = false;
                            for (Symbol symbol : existingSymbols) {
                                if (symbol.getName().equals(labelName) && symbol.getSymbolType() == SymbolType.LABEL) {
                                    labelExists = true;
                                    break;
                                }
                            }

                            if (labelExists) {
                                skipCount.incrementAndGet();
                                continue;
                            }

                            Symbol newSymbol = symbolTable.createLabel(address, labelName, SourceType.USER_DEFINED);
                            if (newSymbol != null) {
                                successCount.incrementAndGet();
                            } else {
                                errors.add("Failed to create label '" + labelName + "' at " + addressStr);
                                errorCount.incrementAndGet();
                            }

                        } catch (Exception e) {
                            errors.add("Error at " + addressStr + ": " + e.getMessage());
                            errorCount.incrementAndGet();
                            Msg.error(this, "Error creating label at " + addressStr, e);
                        }
                    }

                } catch (Exception e) {
                    errors.add("Transaction error: " + e.getMessage());
                    Msg.error(this, "Error in batch create labels transaction", e);
                } finally {
                    program.endTransaction(tx, successCount.get() > 0);
                }
            });
        } catch (Exception e) {
            return errorJson(e.getMessage());
        }

        final int created = successCount.get();
        final int skipped = skipCount.get();
        final int failed = errorCount.get();
        final var errs = List.copyOf(errors);
        JsonObject _jo24 = new JsonObject();
        _jo24.addProperty("success", true);
        _jo24.addProperty("labels_created", created);
        _jo24.addProperty("labels_skipped", skipped);
        _jo24.addProperty("labels_failed", failed);
        _jo24.add("errors", JsonHelper.gson().toJsonTree(errs.isEmpty() ? null : errs));
        return new Response.Ok(_jo24);
    }

    /**
     * Delete a label at the specified address.
     *
     * @param addressStr Memory address in hex format
     * @param labelName Optional specific label name to delete. If null/empty, deletes all labels at the address.
     * @return result object with success status and deleted names
     */
    public Response deleteLabel(String addressStr, String labelName) {
        Program program = getCurrentProgram();
        if (program == null) {
            return errorJson("No program loaded");
        }

        if (addressStr == null || addressStr.isEmpty()) {
            return errorJson("Address is required");
        }

        try {
            Address address = program.getAddressFactory().getAddress(addressStr);
            if (address == null) {
                return errorJson("Invalid address: " + addressStr);
            }

            SymbolTable symbolTable = program.getSymbolTable();
            Symbol[] symbols = symbolTable.getSymbols(address);

            if (symbols == null || symbols.length == 0) {
                final var msg = "No symbols found at address " + addressStr;
                JsonObject _jo25 = new JsonObject();
                _jo25.addProperty("success", false);
                _jo25.addProperty("message", msg);
                return new Response.Ok(_jo25);
            }

            final AtomicInteger deletedCount = new AtomicInteger(0);
            final List<String> deletedNames = new ArrayList<>();
            final List<String> errors = new ArrayList<>();

            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Delete Label");
                try {
                    for (Symbol symbol : symbols) {
                        if (symbol.getSymbolType() != SymbolType.LABEL) {
                            continue;
                        }
                        if (labelName != null && !labelName.isEmpty() && !symbol.getName().equals(labelName)) {
                            continue;
                        }
                        String name = symbol.getName();
                        boolean deleted = symbol.delete();
                        if (deleted) {
                            deletedCount.incrementAndGet();
                            deletedNames.add(name);
                        } else {
                            errors.add("Failed to delete label: " + name);
                        }
                    }
                } catch (Exception e) {
                    errors.add("Error during deletion: " + e.getMessage());
                } finally {
                    program.endTransaction(tx, deletedCount.get() > 0);
                }
            });

            final boolean ok = deletedCount.get() > 0;
            final int count = deletedCount.get();
            final var names = List.copyOf(deletedNames);
            final var errs = List.copyOf(errors);
            JsonObject _jo26 = new JsonObject();
            _jo26.addProperty("success", ok);
            _jo26.addProperty("deleted_count", count);
            _jo26.add("deleted_names", JsonHelper.gson().toJsonTree(names));
            _jo26.add("errors", JsonHelper.gson().toJsonTree(errs.isEmpty() ? null : errs));
            return new Response.Ok(_jo26);

        } catch (Exception e) {
            return errorJson(e.getMessage());
        }
    }

    /**
     * Batch delete multiple labels in a single transaction.
     * Useful for cleaning up orphan labels after applying array types.
     *
     * @param labels List of label entries with "address" and optional "name" fields
     * @return result object with success status and counts
     */
    public Response batchDeleteLabels(List<Map<String, String>> labels) {
        Program program = getCurrentProgram();
        if (program == null) {
            return errorJson("No program loaded");
        }

        if (labels == null || labels.isEmpty()) {
            return errorJson("No labels provided");
        }

        final AtomicInteger deletedCount = new AtomicInteger(0);
        final AtomicInteger skippedCount = new AtomicInteger(0);
        final AtomicInteger errorCount = new AtomicInteger(0);
        final List<String> errors = new ArrayList<>();

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Batch Delete Labels");
                try {
                    SymbolTable symbolTable = program.getSymbolTable();

                    for (Map<String, String> labelEntry : labels) {
                        String addressStr = labelEntry.get("address");
                        String labelName = labelEntry.get("name");

                        if (addressStr == null || addressStr.isEmpty()) {
                            errors.add("Missing address in label entry");
                            errorCount.incrementAndGet();
                            continue;
                        }

                        try {
                            Address address = program.getAddressFactory().getAddress(addressStr);
                            if (address == null) {
                                errors.add("Invalid address: " + addressStr);
                                errorCount.incrementAndGet();
                                continue;
                            }

                            Symbol[] symbols = symbolTable.getSymbols(address);
                            if (symbols == null || symbols.length == 0) {
                                skippedCount.incrementAndGet();
                                continue;
                            }

                            for (Symbol symbol : symbols) {
                                if (symbol.getSymbolType() != SymbolType.LABEL) {
                                    continue;
                                }
                                if (labelName != null && !labelName.isEmpty() && !symbol.getName().equals(labelName)) {
                                    continue;
                                }
                                boolean deleted = symbol.delete();
                                if (deleted) {
                                    deletedCount.incrementAndGet();
                                } else {
                                    errors.add("Failed to delete at " + addressStr);
                                    errorCount.incrementAndGet();
                                }
                            }
                        } catch (Exception e) {
                            errors.add("Error at " + addressStr + ": " + e.getMessage());
                            errorCount.incrementAndGet();
                        }
                    }
                } catch (Exception e) {
                    errors.add("Transaction error: " + e.getMessage());
                } finally {
                    program.endTransaction(tx, deletedCount.get() > 0);
                }
            });
        } catch (Exception e) {
            return errorJson(e.getMessage());
        }

        final int deleted = deletedCount.get();
        final int skipped = skippedCount.get();
        final int errCount = errorCount.get();
        final var errs = errors.isEmpty() ? null : List.copyOf(errors.subList(0, Math.min(errors.size(), 10)));
        JsonObject _jo27 = new JsonObject();
        _jo27.addProperty("success", true);
        _jo27.addProperty("labels_deleted", deleted);
        _jo27.addProperty("labels_skipped", skipped);
        _jo27.addProperty("errors_count", errCount);
        _jo27.add("errors", JsonHelper.gson().toJsonTree(errs));
        return new Response.Ok(_jo27);
    }

    /**
     * Get a call graph subgraph centered on the specified function
     */
    public Response getFunctionCallGraph(String functionName, int depth, String direction, String programName) {
        Object[] programResult = getProgramOrError(programName);
        Program program = (Program) programResult[0];
        if (program == null) return (Response) programResult[1];

        FunctionManager functionManager = program.getFunctionManager();

        Function rootFunction = null;
        for (Function f : functionManager.getFunctions(true)) {
            if (f.getName().equals(functionName)) {
                rootFunction = f;
                break;
            }
        }

        if (rootFunction == null) {
            return errorJson("Function not found: " + functionName);
        }

        Set<String> visited = new HashSet<>();
        Map<String, Set<String>> callGraph = new HashMap<>();

        if ("callees".equals(direction) || "both".equals(direction)) {
            buildCallGraphCallees(rootFunction, depth, visited, callGraph, functionManager);
        }

        if ("callers".equals(direction) || "both".equals(direction)) {
            visited.clear();
            buildCallGraphCallers(rootFunction, depth, visited, callGraph, functionManager);
        }

        var edges = new ArrayList<>();
        for (Map.Entry<String, Set<String>> entry : callGraph.entrySet()) {
            final var caller = entry.getKey();
            for (String callee : entry.getValue()) {
                final var calleeName = callee;
                JsonObject _jo28 = new JsonObject();
                _jo28.addProperty("from", caller);
                _jo28.addProperty("to", calleeName);
                edges.add(_jo28);
            }
        }

        final var edgeList = edges;
        JsonObject _jo29 = new JsonObject();
        _jo29.add("call_edges", JsonHelper.gson().toJsonTree(edgeList));
        return new Response.Ok(_jo29);
    }

    /**
     * Helper method to build call graph for callees (what this function calls)
     */
    private void buildCallGraphCallees(Function function, int depth, Set<String> visited, 
                                     Map<String, Set<String>> callGraph, FunctionManager functionManager) {
        if (depth <= 0 || visited.contains(function.getName())) {
            return;
        }
        
        visited.add(function.getName());
        Set<String> callees = new HashSet<>();
        
        // Find callees of this function
        AddressSetView functionBody = function.getBody();
        Listing listing = getCurrentProgram().getListing();
        ReferenceManager refManager = getCurrentProgram().getReferenceManager();
        
        InstructionIterator instructions = listing.getInstructions(functionBody, true);
        while (instructions.hasNext()) {
            Instruction instr = instructions.next();
            
            if (instr.getFlowType().isCall()) {
                Reference[] references = refManager.getReferencesFrom(instr.getAddress());
                for (Reference ref : references) {
                    if (ref.getReferenceType().isCall()) {
                        Address targetAddr = ref.getToAddress();
                        Function targetFunc = functionManager.getFunctionAt(targetAddr);
                        if (targetFunc != null) {
                            callees.add(targetFunc.getName());
                            // Recursively build graph for callees
                            buildCallGraphCallees(targetFunc, depth - 1, visited, callGraph, functionManager);
                        }
                    }
                }
            }
        }
        
        if (!callees.isEmpty()) {
            callGraph.put(function.getName(), callees);
        }
    }

    /**
     * Helper method to build call graph for callers (what calls this function)
     */
    private void buildCallGraphCallers(Function function, int depth, Set<String> visited, 
                                     Map<String, Set<String>> callGraph, FunctionManager functionManager) {
        if (depth <= 0 || visited.contains(function.getName())) {
            return;
        }
        
        visited.add(function.getName());
        ReferenceManager refManager = getCurrentProgram().getReferenceManager();
        
        // Find callers of this function
        ReferenceIterator refIter = refManager.getReferencesTo(function.getEntryPoint());
        while (refIter.hasNext()) {
            Reference ref = refIter.next();
            if (ref.getReferenceType().isCall()) {
                Address fromAddr = ref.getFromAddress();
                Function callerFunc = functionManager.getFunctionContaining(fromAddr);
                if (callerFunc != null) {
                    String callerName = callerFunc.getName();
                    callGraph.computeIfAbsent(callerName, k -> new HashSet<>()).add(function.getName());
                    // Recursively build graph for callers
                    buildCallGraphCallers(callerFunc, depth - 1, visited, callGraph, functionManager);
                }
            }
        }
    }

    /**
     * Get the complete call graph for the entire program
     */
    public Response getFullCallGraph(String format, int limit, String programName) {
        Object[] programResult = getProgramOrError(programName);
        Program program = (Program) programResult[0];
        if (program == null) return (Response) programResult[1];

        FunctionManager functionManager = program.getFunctionManager();
        ReferenceManager refManager = program.getReferenceManager();
        Listing listing = program.getListing();

        Map<String, Set<String>> callGraph = new HashMap<>();
        int relationshipCount = 0;

        for (Function function : functionManager.getFunctions(true)) {
            if (relationshipCount >= limit) break;

            String functionName = function.getName();
            Set<String> callees = new HashSet<>();

            AddressSetView functionBody = function.getBody();
            InstructionIterator instructions = listing.getInstructions(functionBody, true);

            while (instructions.hasNext() && relationshipCount < limit) {
                Instruction instr = instructions.next();
                if (instr.getFlowType().isCall()) {
                    for (Reference ref : refManager.getReferencesFrom(instr.getAddress())) {
                        if (ref.getReferenceType().isCall()) {
                            Function targetFunc = functionManager.getFunctionAt(ref.getToAddress());
                            if (targetFunc != null) {
                                callees.add(targetFunc.getName());
                                if (++relationshipCount >= limit) break;
                            }
                        }
                    }
                }
            }

            if (!callees.isEmpty()) {
                callGraph.put(functionName, callees);
            }
        }

        if (callGraph.isEmpty()) {
            return errorJson("No call relationships found in the program");
        }

        // Text formats: return as raw string (sent verbatim by sendResponse)
        if ("dot".equals(format)) {
            StringBuilder sb = new StringBuilder();
            sb.append("digraph CallGraph {\n");
            sb.append("  rankdir=TB;\n");
            sb.append("  node [shape=box];\n");
            for (Map.Entry<String, Set<String>> entry : callGraph.entrySet()) {
                String caller = entry.getKey().replace("\"", "\\\"");
                for (String callee : entry.getValue()) {
                    sb.append("  \"").append(caller).append("\" -> \"")
                      .append(callee.replace("\"", "\\\"")).append("\";\n");
                }
            }
            sb.append("}");
            return Response.text(sb.toString());
        } else if ("mermaid".equals(format)) {
            StringBuilder sb = new StringBuilder();
            sb.append("graph TD\n");
            for (Map.Entry<String, Set<String>> entry : callGraph.entrySet()) {
                String caller = entry.getKey().replace(" ", "_");
                for (String callee : entry.getValue()) {
                    sb.append("  ").append(caller).append(" --> ")
                      .append(callee.replace(" ", "_")).append("\n");
                }
            }
            return Response.text(sb.toString());
        } else if ("adjacency".equals(format)) {
            StringBuilder sb = new StringBuilder();
            for (Map.Entry<String, Set<String>> entry : callGraph.entrySet()) {
                if (sb.length() > 0) sb.append("\n");
                sb.append(entry.getKey()).append(": ").append(String.join(", ", entry.getValue()));
            }
            return Response.text(sb.toString());
        } else {
            // Default "edges" format: return structured object
            var edges = new ArrayList<>();
            for (Map.Entry<String, Set<String>> entry : callGraph.entrySet()) {
                final var caller = entry.getKey();
                for (String callee : entry.getValue()) {
                    final var calleeName = callee;
                    JsonObject _jo30 = new JsonObject();
                    _jo30.addProperty("from", caller);
                    _jo30.addProperty("to", calleeName);
                    edges.add(_jo30);
                }
            }
            final var edgeList = edges;
            JsonObject _jo31 = new JsonObject();
            _jo31.add("call_edges", JsonHelper.gson().toJsonTree(edgeList));
            return new Response.Ok(_jo31);
        }
    }

    /**
     * Enhanced call graph analysis with cycle detection and path finding
     * Provides advanced graph algorithms for understanding function relationships
     */
    public Response analyzeCallGraph(String startFunction, String endFunction, String analysisType, String programName) {
        Object[] programResult = getProgramOrError(programName);
        Program program = (Program) programResult[0];
        if (program == null) return (Response) programResult[1];

        try {
            FunctionManager functionManager = program.getFunctionManager();
            ReferenceManager refManager = program.getReferenceManager();

            Map<String, Set<String>> callGraph = new LinkedHashMap<>();
            Map<String, String> functionAddresses = new LinkedHashMap<>();

            for (Function func : functionManager.getFunctions(true)) {
                if (func.isThunk()) continue;

                String funcName = func.getName();
                functionAddresses.put(funcName, func.getEntryPoint().toString());
                Set<String> callees = new HashSet<>();

                Listing listing = program.getListing();
                InstructionIterator instrIter = listing.getInstructions(func.getBody(), true);

                while (instrIter.hasNext()) {
                    Instruction instr = instrIter.next();
                    if (instr.getFlowType().isCall()) {
                        for (Reference ref : refManager.getReferencesFrom(instr.getAddress())) {
                            if (ref.getReferenceType().isCall()) {
                                Function calledFunc = functionManager.getFunctionAt(ref.getToAddress());
                                if (calledFunc != null && !calledFunc.isThunk()) {
                                    callees.add(calledFunc.getName());
                                }
                            }
                        }
                    }
                }

                if (!callees.isEmpty()) {
                    callGraph.put(funcName, callees);
                }
            }

            if ("cycles".equals(analysisType)) {
                List<List<String>> cycles = findCycles(callGraph);
                var cycleObjs = new ArrayList<>();
                for (int i = 0; i < Math.min(cycles.size(), 20); i++) {
                    final var path = List.copyOf(cycles.get(i));
                    JsonObject _jo32 = new JsonObject();
                    _jo32.addProperty("length", path.size());
                    _jo32.add("path_nodes", JsonHelper.gson().toJsonTree(path));
                    cycleObjs.add(_jo32);
                }
                if (cycles.size() > 20) {
                    final var note = (cycles.size() - 20) + " additional cycles omitted";
                    JsonObject _jo33 = new JsonObject();
                    _jo33.addProperty("note_message", note);
                    cycleObjs.add(_jo33);
                }
                final int total = cycles.size();
                final var cycleList = cycleObjs;
                JsonObject _jo34 = new JsonObject();
                _jo34.addProperty("analysis_type", "cycle_detection");
                _jo34.addProperty("cycles_found", total);
                _jo34.add("cycles", JsonHelper.gson().toJsonTree(cycleList));
                return new Response.Ok(_jo34);

            } else if ("path".equals(analysisType) && startFunction != null && endFunction != null) {
                List<String> path = findShortestPath(callGraph, startFunction, endFunction);
                final var start = startFunction;
                final var end = endFunction;
                if (path != null) {
                    final int pathLen = path.size() - 1;
                    final var pathList = List.copyOf(path);
                    JsonObject _jo35 = new JsonObject();
                    _jo35.addProperty("analysis_type", "path_finding");
                    _jo35.addProperty("start_function", start);
                    _jo35.addProperty("end_function", end);
                    _jo35.addProperty("path_found", true);
                    _jo35.addProperty("path_length", pathLen);
                    _jo35.add("path_nodes", JsonHelper.gson().toJsonTree(pathList));
                    return new Response.Ok(_jo35);
                } else {
                    JsonObject _jo36 = new JsonObject();
                    _jo36.addProperty("analysis_type", "path_finding");
                    _jo36.addProperty("start_function", start);
                    _jo36.addProperty("end_function", end);
                    _jo36.addProperty("path_found", false);
                    _jo36.addProperty("message", "No path exists between the specified functions");
                    return new Response.Ok(_jo36);
                }

            } else if ("strongly_connected".equals(analysisType)) {
                List<Set<String>> sccs = findStronglyConnectedComponents(callGraph);
                List<Set<String>> nonTrivialSCCs = new ArrayList<>();
                for (Set<String> scc : sccs) {
                    if (scc.size() > 1) nonTrivialSCCs.add(scc);
                }
                var components = new ArrayList<>();
                for (int i = 0; i < Math.min(nonTrivialSCCs.size(), 20); i++) {
                    Set<String> scc = nonTrivialSCCs.get(i);
                    final int sz = scc.size();
                    List<String> funcs = new ArrayList<>();
                    int j = 0;
                    for (String fn : scc) {
                        if (j++ >= 10) break;
                        funcs.add(fn);
                    }
                    if (sz > 10) funcs.add("..." + (sz - 10) + " more");
                    final var funcList = List.copyOf(funcs);
                    JsonObject _jo37 = new JsonObject();
                    _jo37.addProperty("size", sz);
                    _jo37.add("functions", JsonHelper.gson().toJsonTree(funcList));
                    components.add(_jo37);
                }
                final int totalSccs = sccs.size();
                final int nonTrivial = nonTrivialSCCs.size();
                final var compList = components;
                JsonObject _jo38 = new JsonObject();
                _jo38.addProperty("analysis_type", "strongly_connected_components");
                _jo38.addProperty("total_sccs", totalSccs);
                _jo38.addProperty("non_trivial_sccs", nonTrivial);
                _jo38.add("components", JsonHelper.gson().toJsonTree(compList));
                return new Response.Ok(_jo38);

            } else if ("entry_points".equals(analysisType)) {
                Set<String> allFunctions = new HashSet<>(functionAddresses.keySet());
                Set<String> calledFunctions = new HashSet<>();
                for (Set<String> callees : callGraph.values()) calledFunctions.addAll(callees);
                Set<String> entryPoints = new HashSet<>(allFunctions);
                entryPoints.removeAll(calledFunctions);

                var epObjs = new ArrayList<>();
                int idx = 0;
                for (String ep : entryPoints) {
                    if (idx++ >= 50) {
                        final var note = (entryPoints.size() - 50) + " more entry points";
                        JsonObject _jo39 = new JsonObject();
                        _jo39.addProperty("note_message", note);
                        epObjs.add(_jo39);
                        break;
                    }
                    final var name = ep;
                    final var addr = functionAddresses.getOrDefault(ep, "unknown");
                    JsonObject _jo40 = new JsonObject();
                    _jo40.addProperty("function_name", name);
                    _jo40.addProperty("address", addr);
                    epObjs.add(_jo40);
                }
                final int totalFuncs = allFunctions.size();
                final int epCount = entryPoints.size();
                final var epList = epObjs;
                JsonObject _jo41 = new JsonObject();
                _jo41.addProperty("analysis_type", "entry_point_detection");
                _jo41.addProperty("total_functions", totalFuncs);
                _jo41.addProperty("entry_points_found", epCount);
                _jo41.add("entry_points", JsonHelper.gson().toJsonTree(epList));
                return new Response.Ok(_jo41);

            } else if ("leaf_functions".equals(analysisType)) {
                Set<String> leafFunctions = new HashSet<>(functionAddresses.keySet());
                leafFunctions.removeAll(callGraph.keySet());

                var lfObjs = new ArrayList<>();
                int idx = 0;
                for (String lf : leafFunctions) {
                    if (idx++ >= 50) {
                        final var note = (leafFunctions.size() - 50) + " more leaf functions";
                        JsonObject _jo42 = new JsonObject();
                        _jo42.addProperty("note_message", note);
                        lfObjs.add(_jo42);
                        break;
                    }
                    final var name = lf;
                    final var addr = functionAddresses.getOrDefault(lf, "unknown");
                    JsonObject _jo43 = new JsonObject();
                    _jo43.addProperty("function_name", name);
                    _jo43.addProperty("address", addr);
                    lfObjs.add(_jo43);
                }
                final int lfCount = leafFunctions.size();
                final var lfList = lfObjs;
                JsonObject _jo44 = new JsonObject();
                _jo44.addProperty("analysis_type", "leaf_function_detection");
                _jo44.addProperty("leaf_functions_found", lfCount);
                _jo44.add("leaf_functions", JsonHelper.gson().toJsonTree(lfList));
                return new Response.Ok(_jo44);

            } else {
                // Default: summary statistics
                int totalEdges = 0;
                int maxOutDegree = 0;
                String maxOutDegreeFunc = "";
                Map<String, Integer> inDegree = new HashMap<>();

                for (Map.Entry<String, Set<String>> entry : callGraph.entrySet()) {
                    totalEdges += entry.getValue().size();
                    if (entry.getValue().size() > maxOutDegree) {
                        maxOutDegree = entry.getValue().size();
                        maxOutDegreeFunc = entry.getKey();
                    }
                    for (String callee : entry.getValue()) {
                        inDegree.put(callee, inDegree.getOrDefault(callee, 0) + 1);
                    }
                }

                int maxInDegree = 0;
                String maxInDegreeFunc = "";
                for (Map.Entry<String, Integer> entry : inDegree.entrySet()) {
                    if (entry.getValue() > maxInDegree) {
                        maxInDegree = entry.getValue();
                        maxInDegreeFunc = entry.getKey();
                    }
                }

                final int totFuncs = functionAddresses.size();
                final int funcsWithCalls = callGraph.size();
                final int totEdges = totalEdges;
                final var maxOutFunc = maxOutDegreeFunc;
                final int maxOut = maxOutDegree;
                final var maxInFunc = maxInDegreeFunc;
                final int maxIn = maxInDegree;
                JsonObject _jo_maxOut = new JsonObject();
                _jo_maxOut.addProperty("function", maxOutFunc);
                _jo_maxOut.addProperty("calls", maxOut);
                JsonObject _jo_maxIn = new JsonObject();
                _jo_maxIn.addProperty("function", maxInFunc);
                _jo_maxIn.addProperty("called_by", maxIn);
                JsonObject _jo_summary = new JsonObject();
                _jo_summary.addProperty("analysis_type", "summary");
                _jo_summary.addProperty("total_functions", totFuncs);
                _jo_summary.addProperty("functions_with_calls", funcsWithCalls);
                _jo_summary.addProperty("total_call_edges", totEdges);
                _jo_summary.add("max_out_degree", _jo_maxOut);
                _jo_summary.add("max_in_degree", _jo_maxIn);
                _jo_summary.add("available_analyses", JsonHelper.gson().toJsonTree(List.of(
                    "cycles", "path", "strongly_connected", "entry_points", "leaf_functions")));
                return new Response.Ok(_jo_summary);
            }

        } catch (Exception e) {
            return errorJson(e.getMessage());
        }
    }
    
    /**
     * Find cycles in directed graph using DFS
     */
    private List<List<String>> findCycles(Map<String, Set<String>> graph) {
        List<List<String>> cycles = new ArrayList<>();
        Set<String> visited = new HashSet<>();
        Set<String> recStack = new HashSet<>();
        Map<String, String> parent = new HashMap<>();
        
        for (String node : graph.keySet()) {
            if (!visited.contains(node)) {
                findCyclesDFS(node, graph, visited, recStack, parent, cycles);
            }
        }
        
        return cycles;
    }
    
    private void findCyclesDFS(String node, Map<String, Set<String>> graph, Set<String> visited,
                               Set<String> recStack, Map<String, String> parent, List<List<String>> cycles) {
        visited.add(node);
        recStack.add(node);
        
        Set<String> neighbors = graph.getOrDefault(node, Collections.emptySet());
        for (String neighbor : neighbors) {
            if (!visited.contains(neighbor)) {
                parent.put(neighbor, node);
                findCyclesDFS(neighbor, graph, visited, recStack, parent, cycles);
            } else if (recStack.contains(neighbor)) {
                // Found a cycle - reconstruct it
                List<String> cycle = new ArrayList<>();
                cycle.add(neighbor);
                String current = node;
                while (current != null && !current.equals(neighbor)) {
                    cycle.add(0, current);
                    current = parent.get(current);
                }
                cycle.add(0, neighbor);
                if (cycles.size() < 100) { // Limit cycles
                    cycles.add(cycle);
                }
            }
        }
        
        recStack.remove(node);
    }
    
    /**
     * Find shortest path using BFS
     */
    private List<String> findShortestPath(Map<String, Set<String>> graph, String start, String end) {
        if (start.equals(end)) {
            return Arrays.asList(start);
        }
        
        Queue<String> queue = new LinkedList<>();
        Map<String, String> parent = new HashMap<>();
        Set<String> visited = new HashSet<>();
        
        queue.add(start);
        visited.add(start);
        
        while (!queue.isEmpty()) {
            String current = queue.poll();
            Set<String> neighbors = graph.getOrDefault(current, Collections.emptySet());
            
            for (String neighbor : neighbors) {
                if (!visited.contains(neighbor)) {
                    visited.add(neighbor);
                    parent.put(neighbor, current);
                    
                    if (neighbor.equals(end)) {
                        // Reconstruct path
                        List<String> path = new ArrayList<>();
                        String node = end;
                        while (node != null) {
                            path.add(0, node);
                            node = parent.get(node);
                        }
                        return path;
                    }
                    
                    queue.add(neighbor);
                }
            }
        }
        
        return null; // No path found
    }
    
    /**
     * Find strongly connected components using Kosaraju's algorithm
     */
    private List<Set<String>> findStronglyConnectedComponents(Map<String, Set<String>> graph) {
        // Step 1: Fill vertices in stack according to finishing times
        Stack<String> stack = new Stack<>();
        Set<String> visited = new HashSet<>();
        
        // Get all nodes
        Set<String> allNodes = new HashSet<>(graph.keySet());
        for (Set<String> neighbors : graph.values()) {
            allNodes.addAll(neighbors);
        }
        
        for (String node : allNodes) {
            if (!visited.contains(node)) {
                fillOrder(node, graph, visited, stack);
            }
        }
        
        // Step 2: Create reversed graph
        Map<String, Set<String>> reversedGraph = new HashMap<>();
        for (Map.Entry<String, Set<String>> entry : graph.entrySet()) {
            for (String neighbor : entry.getValue()) {
                reversedGraph.computeIfAbsent(neighbor, k -> new HashSet<>()).add(entry.getKey());
            }
        }
        
        // Step 3: Process vertices in order of decreasing finish time
        visited.clear();
        List<Set<String>> sccs = new ArrayList<>();
        
        while (!stack.isEmpty()) {
            String node = stack.pop();
            if (!visited.contains(node)) {
                Set<String> scc = new HashSet<>();
                dfsCollect(node, reversedGraph, visited, scc);
                sccs.add(scc);
            }
        }
        
        return sccs;
    }
    
    private void fillOrder(String node, Map<String, Set<String>> graph, Set<String> visited, Stack<String> stack) {
        visited.add(node);
        Set<String> neighbors = graph.getOrDefault(node, Collections.emptySet());
        for (String neighbor : neighbors) {
            if (!visited.contains(neighbor)) {
                fillOrder(neighbor, graph, visited, stack);
            }
        }
        stack.push(node);
    }
    
    private void dfsCollect(String node, Map<String, Set<String>> graph, Set<String> visited, Set<String> component) {
        visited.add(node);
        component.add(node);
        Set<String> neighbors = graph.getOrDefault(node, Collections.emptySet());
        for (String neighbor : neighbors) {
            if (!visited.contains(neighbor)) {
                dfsCollect(neighbor, graph, visited, component);
            }
        }
    }

    /**
     * Check if the plugin is running and accessible
     */
    private Response checkConnection() {
        Program program = getCurrentProgram();
        String programName = program != null ? program.getName() : null;
        boolean loaded = program != null;
        JsonObject _jo47 = new JsonObject();
        _jo47.addProperty("connected", true);
        _jo47.addProperty("program_loaded", loaded);
        _jo47.addProperty("program_name", programName);
        return new Response.Ok(_jo47);
    }

    /**
     * Get version information about the plugin and Ghidra (v1.7.0)
     */
    private Response getVersion() {
        String pluginVersion = VersionInfo.getVersion();
        String pluginName = VersionInfo.getAppName();
        String buildTimestamp = VersionInfo.getBuildTimestamp();
        String buildNumber = VersionInfo.getBuildNumber();
        String fullVersion = VersionInfo.getFullVersion();
        String javaVersion = System.getProperty("java.version");
        int endpointCount = VersionInfo.getEndpointCount();
        JsonObject _jo48 = new JsonObject();
        _jo48.addProperty("plugin_version", pluginVersion);
        _jo48.addProperty("plugin_name", pluginName);
        _jo48.addProperty("build_timestamp", buildTimestamp);
        _jo48.addProperty("build_number", buildNumber);
        _jo48.addProperty("full_version", fullVersion);
        _jo48.addProperty("ghidra_version", "12.0.2");
        _jo48.addProperty("java_version", javaVersion);
        _jo48.addProperty("endpoint_count", endpointCount);
        return new Response.Ok(_jo48);
    }

    /**
     * Get metadata about the current program
     */
    private Response getMetadata() {
        Program program = getCurrentProgram();
        if (program == null) {
            return errorJson("No program loaded");
        }

        String programName = program.getName();
        String executablePath = program.getExecutablePath();
        String architecture = program.getLanguage().getProcessor().toString();
        String compiler = program.getCompilerSpec().getCompilerSpecID().toString();
        String language = program.getLanguage().getLanguageID().toString();
        String endian = program.getLanguage().isBigEndian() ? "Big" : "Little";
        int addressSize = program.getAddressFactory().getDefaultAddressSpace().getSize();
        String baseAddress = program.getImageBase().toString();

        long totalSize = 0;
        int blockCount = 0;
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            totalSize += block.getSize();
            blockCount++;
        }
        final long totalMemorySize = totalSize;
        final int memoryBlocks = blockCount;

        int functionCount = program.getFunctionManager().getFunctionCount();
        int symbolCount = program.getSymbolTable().getNumSymbols();

        JsonObject _jo49 = new JsonObject();
        _jo49.addProperty("program_name", programName);
        _jo49.addProperty("executable_path", executablePath);
        _jo49.addProperty("arch", architecture);
        _jo49.addProperty("comp", compiler);
        _jo49.addProperty("lang", language);
        _jo49.addProperty("endianness", endian);
        _jo49.addProperty("address_size_bits", addressSize);
        _jo49.addProperty("base_address", baseAddress);
        _jo49.addProperty("memory_block_count", memoryBlocks);
        _jo49.addProperty("total_memory_size_bytes", totalMemorySize);
        _jo49.addProperty("function_count", functionCount);
        _jo49.addProperty("symbol_count", symbolCount);
        return new Response.Ok(_jo49);
    }

    /**
     * Convert a number to different representations
     */
    private Response convertNumber(String text, int size) {
        if (text == null || text.isEmpty()) {
            return errorJson("No number provided");
        }

        try {
            long value;
            String inputType;

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

            long mask = (size == 8) ? -1L : (1L << (size * 8)) - 1L;
            long maskedValue = value & mask;

            String decimalUnsigned = Long.toUnsignedString(maskedValue);
            String hexValue = "0x" + Long.toHexString(maskedValue).toUpperCase();
            String binaryValue = "0b" + Long.toBinaryString(maskedValue);
            String octalValue = "0" + Long.toOctalString(maskedValue);
            String hexPadded = "0x" + String.format(String.format("%%0%dX", size * 2), maskedValue);

            Long decimalSigned = null;
            if (size <= 8) {
                long signedValue = maskedValue;
                if (size < 8) {
                    long signBit = 1L << (size * 8 - 1);
                    if ((maskedValue & signBit) != 0) {
                        signedValue = maskedValue | (~mask);
                    }
                }
                decimalSigned = signedValue;
            }

            final String finalInput = text;
            final String finalInputType = inputType;
            final int finalSize = size;
            final String finalDecimalUnsigned = decimalUnsigned;
            final Long finalDecimalSigned = decimalSigned;
            final String finalHex = hexValue;
            final String finalBinary = binaryValue;
            final String finalOctal = octalValue;
            final String finalHexPadded = hexPadded;

            JsonObject _jo50 = new JsonObject();
            _jo50.addProperty("input", finalInput);
            _jo50.addProperty("input_type", finalInputType);
            _jo50.addProperty("size_bytes", finalSize);
            _jo50.addProperty("decimal_unsigned", finalDecimalUnsigned);
            _jo50.addProperty("decimal_signed", finalDecimalSigned);
            _jo50.addProperty("hexadecimal", finalHex);
            _jo50.addProperty("binary", finalBinary);
            _jo50.addProperty("octal", finalOctal);
            _jo50.addProperty("hex_padded", finalHexPadded);
            return new Response.Ok(_jo50);

        } catch (NumberFormatException e) {
            return errorJson("Invalid number format: " + text);
        } catch (Exception e) {
            return errorJson("Error converting number: " + e.getMessage());
        }
    }

    /**
     * Get the size of a data type
     */
    private Response getTypeSize(String typeName) {
        Program program = getCurrentProgram();
        if (program == null) return Response.err("No program loaded");
        if (typeName == null || typeName.isEmpty()) return Response.err("Type name is required");

        DataTypeManager dtm = program.getDataTypeManager();
        DataType dataType = findDataTypeByNameInAllCategories(dtm, typeName);

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
     * Validate if a data type fits at a given address
     */
    private Response validateDataType(String addressStr, String typeName) throws Exception {
        Program program = getCurrentProgram();
        if (program == null) return errorJson("No program loaded");
        if (addressStr == null || addressStr.isEmpty()) return errorJson("Address is required");
        if (typeName == null || typeName.isEmpty()) return errorJson("Type name is required");

        Address addr = program.getAddressFactory().getAddress(addressStr);
        DataTypeManager dtm = program.getDataTypeManager();
        DataType dataType = findDataTypeByNameInAllCategories(dtm, typeName);

        if (dataType == null) {
            return errorJson("Data type not found: " + typeName);
        }

        Memory memory = program.getMemory();
        int typeSize = dataType.getLength();
        Address endAddr = addr.add(typeSize - 1);

        boolean memoryAvailable = memory.contains(addr) && memory.contains(endAddr);
        if (!memoryAvailable) {
            final String rangeStart = addr.toString();
            final String rangeEnd = endAddr.toString();
            JsonObject _jo51 = new JsonObject();
            _jo51.addProperty("address", addressStr);
            _jo51.addProperty("type_name", typeName);
            _jo51.addProperty("memory_available", false);
            _jo51.addProperty("required_range", rangeStart + " - " + rangeEnd);
            return new Response.Ok(_jo51);
        }

        long alignment = dataType.getAlignment();
        boolean aligned = alignment <= 1 || addr.getOffset() % alignment == 0;
        String alignmentWarning = aligned ? null
                : "Address not aligned to " + alignment + "-byte boundary";

        Data existingData = program.getListing().getDefinedDataAt(addr);
        String conflictingType = existingData != null ? existingData.getDataType().getName() : null;

        final String rangeStr = addr + " - " + endAddr;
        final boolean hasConflict = conflictingType != null;
        final String conflictType = conflictingType;
        final String alignWarn = alignmentWarning;

        JsonObject _jo52 = new JsonObject();
        _jo52.addProperty("address", addressStr);
        _jo52.addProperty("type_name", typeName);
        _jo52.addProperty("memory_available", true);
        _jo52.addProperty("range", rangeStr);
        _jo52.addProperty("size_bytes", typeSize);
        _jo52.addProperty("properly_aligned", aligned);
        _jo52.addProperty("alignment_warning", alignWarn);
        _jo52.addProperty("has_conflicting_data", hasConflict);
        _jo52.addProperty("conflicting_data_type", conflictType);
        return new Response.Ok(_jo52);
    }

    /**
     * Read memory at a specific address
     */
    private Response readMemory(String addressStr, int length, String programName) throws Exception {
        Object[] programResult = getProgramOrError(programName);
        Program program = (Program) programResult[0];
        if (program == null) {
            return (Response) programResult[1];
        }

        Address address = program.getAddressFactory().getAddress(addressStr);
        if (address == null) {
            return errorJson("Invalid address: " + addressStr);
        }

        Memory memory = program.getMemory();
        byte[] bytes = new byte[length];
        int bytesRead = memory.getBytes(address, bytes);

        int[] dataInts = new int[bytesRead];
        StringBuilder hexBuilder = new StringBuilder();
        for (int i = 0; i < bytesRead; i++) {
            dataInts[i] = bytes[i] & 0xFF;
            hexBuilder.append(String.format("%02x", dataInts[i]));
        }

        final String addrStr = address.toString();
        final int finalBytesRead = bytesRead;
        final int[] finalData = dataInts;
        final String hexStr = hexBuilder.toString();

        JsonObject _jo53 = new JsonObject();
        _jo53.addProperty("addr", addrStr);
        _jo53.addProperty("read_length", finalBytesRead);
        _jo53.add("data", JsonHelper.gson().toJsonTree(finalData));
        _jo53.addProperty("hex", hexStr);
        return new Response.Ok(_jo53);
    }
    
    /**
     * Import data types from various sources
     */
    private Response importDataTypes(String source, String format) {
        if (format == null || format.isEmpty()) format = "c";
        // This is a placeholder for import functionality
        // In a real implementation, you would parse the source based on format
        return Response.err("Import functionality not yet implemented. Source: " + source + ", Format: " + format);
    }


    /**
     * Create a new data type category
     */
    private Response createDataTypeCategory(String categoryPath) throws Exception {
        Program program = getCurrentProgram();
        if (program == null) return Response.err("No program loaded");
        if (categoryPath == null || categoryPath.isEmpty()) return Response.err("Category path is required");

        DataTypeManager dtm = program.getDataTypeManager();
        CategoryPath catPath = new CategoryPath(categoryPath);
        Category category = dtm.createCategory(catPath);

        return Response.text("Successfully created category: " + category.getCategoryPathName());
    }

    /**
     * Move a data type to a different category
     */
    private Response moveDataTypeToCategory(String typeName, String categoryPath) {
        Program program = getCurrentProgram();
        if (program == null) return errorJson("No program loaded");
        if (typeName == null || typeName.isEmpty()) return errorJson("Type name is required");
        if (categoryPath == null || categoryPath.isEmpty()) return errorJson("Category path is required");

        AtomicBoolean txSuccess = new AtomicBoolean(false);
        AtomicReference<Response> result = new AtomicReference<>();

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Move data type to category");
                try {
                    DataTypeManager dtm = program.getDataTypeManager();
                    DataType dataType = findDataTypeByNameInAllCategories(dtm, typeName);

                    if (dataType == null) {
                        result.set(errorJson("Data type not found: " + typeName));
                        return;
                    }

                    CategoryPath catPath = new CategoryPath(categoryPath);
                    dtm.createCategory(catPath);
                    dataType.setCategoryPath(catPath);
                    txSuccess.set(true);

                    JsonObject _jo54 = new JsonObject();
                    _jo54.addProperty("success", true);
                    _jo54.addProperty("type_name", typeName);
                    _jo54.addProperty("category", categoryPath);
                    result.set(new Response.Ok(_jo54));

                } catch (Exception e) {
                    result.set(errorJson("Error moving data type: " + e.getMessage()));
                } finally {
                    program.endTransaction(tx, txSuccess.get());
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            result.set(errorJson("Failed to execute data type move on Swing thread: " + e.getMessage()));
        }

        return result.get();
    }

    /**
     * List all data type categories
     */
    private Response listDataTypeCategories(int offset, int limit) throws Exception {
        Program program = getCurrentProgram();
        if (program == null) return Response.err("No program loaded");

        DataTypeManager dtm = program.getDataTypeManager();
        List<String> categories = new ArrayList<>();
        
        // Get all categories recursively
        addCategoriesRecursively(dtm.getRootCategory(), categories, "");
        
        return Response.text(paginateList(categories, offset, limit));
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

    /**
     * Create a function signature data type
     */
    private Response createFunctionSignature(String name, String returnType, String parametersJson) {
        Program program = getCurrentProgram();
        if (program == null) return errorJson("No program loaded");
        if (name == null || name.isEmpty()) return errorJson("Function name is required");
        if (returnType == null || returnType.isEmpty()) return errorJson("Return type is required");

        AtomicBoolean txSuccess = new AtomicBoolean(false);
        AtomicReference<Response> result = new AtomicReference<>();
        AtomicReference<String> paramWarning = new AtomicReference<>();

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Create function signature");
                try {
                    DataTypeManager dtm = program.getDataTypeManager();

                    DataType returnDataType = resolveDataType(dtm, returnType);
                    if (returnDataType == null) {
                        result.set(errorJson("Return type not found: " + returnType));
                        return;
                    }

                    FunctionDefinitionDataType funcDef = new FunctionDefinitionDataType(name);
                    funcDef.setReturnType(returnDataType);

                    if (parametersJson != null && !parametersJson.isEmpty()) {
                        try {
                            String[] paramPairs = parametersJson.replace("[", "").replace("]", "")
                                                               .replace("{", "").replace("}", "")
                                                               .split(",");
                            for (String paramPair : paramPairs) {
                                if (paramPair.trim().isEmpty()) continue;
                                String[] parts = paramPair.split(":");
                                if (parts.length >= 2) {
                                    String paramType = parts[1].replace("\"", "").trim();
                                    DataType paramDataType = resolveDataType(dtm, paramType);
                                    if (paramDataType != null) {
                                        funcDef.setArguments(new ParameterDefinition[] {
                                            new ParameterDefinitionImpl(null, paramDataType, null)
                                        });
                                    }
                                }
                            }
                        } catch (Exception e) {
                            paramWarning.set("Could not parse parameters, created without them");
                        }
                    }

                    DataType addedFuncDef = dtm.addDataType(funcDef, DataTypeConflictHandler.REPLACE_HANDLER);
                    txSuccess.set(true);

                    String addedName = addedFuncDef.getName();
                    String warning = paramWarning.get();
                    JsonObject _jo55 = new JsonObject();
                    _jo55.addProperty("success", true);
                    _jo55.addProperty("function_name", addedName);
                    _jo55.addProperty("return_type", returnType);
                    _jo55.addProperty("parameter_warning", warning);
                    result.set(new Response.Ok(_jo55));

                } catch (Exception e) {
                    result.set(errorJson("Error creating function signature: " + e.getMessage()));
                } finally {
                    program.endTransaction(tx, txSuccess.get());
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            result.set(errorJson("Failed to execute function signature creation on Swing thread: " + e.getMessage()));
        }

        return result.get();
    }

    // ==========================================================================
    // HIGH-PERFORMANCE DATA ANALYSIS METHODS (v1.3.0)
    // ==========================================================================



    /**
     * 6. APPLY_DATA_CLASSIFICATION - Atomic type application
     */
    private Response applyDataClassification(String addressStr, String classification,
                                           String name, String comment,
                                           Object typeDefinitionObj) throws Exception {
        Program program = getCurrentProgram();
        if (program == null) return errorJson("No program loaded");

        final AtomicReference<String> typeApplied = new AtomicReference<>("none");
        final List<String> operations = new ArrayList<>();
        final AtomicReference<Response> errorResult = new AtomicReference<>();

        Address addr = program.getAddressFactory().getAddress(addressStr);
        if (addr == null) {
            return errorJson("Invalid address: " + addressStr);
        }

        // Parse type_definition from the object
        @SuppressWarnings("unchecked")
        final Map<String, Object> typeDef;
        if (typeDefinitionObj instanceof Map) {
            typeDef = (Map<String, Object>) typeDefinitionObj;
        } else if (typeDefinitionObj == null) {
            typeDef = null;
        } else {
            // Received something unexpected - log it for debugging
            return errorJson("type_definition must be a JSON object/dict, got: " +
                   typeDefinitionObj.getClass().getSimpleName() +
                   " with value: " + typeDefinitionObj);
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
                    dataTypeToApply = resolveDataType(dtm, typeStr);
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
                            @SuppressWarnings("unchecked")
                            List<Map<String, Object>> fieldsList = (List<Map<String, Object>>) fieldsObj;
                            for (Map<String, Object> field : fieldsList) {
                                String fieldName = (String) field.get("name");
                                String fieldType = (String) field.get("type");

                                DataType fieldDataType = resolveDataType(dtm, fieldType);
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
                        elementType = resolveDataType(dtm, elementTypeStr);
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
                        dataTypeToApply = resolveDataType(dtm, typeStr);
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
                errorResult.set(errorJson(e.getMessage()));
            } finally {
                program.endTransaction(txId, success);
            }
        });

        if (errorResult.get() != null) {
            return errorResult.get();
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("success", true);
        result.put("address", addressStr);
        result.put("classification", classification);
        if (name != null) result.put("name", name);
        result.put("type_applied", typeApplied.get());
        result.put("operations_performed", operations);
        return new Response.Ok(result);

    }

    /**
     * SUGGEST_FIELD_NAMES - AI-assisted field name suggestions based on usage patterns
     *
     * @param structAddressStr Address of the structure instance
     * @param structSize Size of the structure in bytes (0 for auto-detect)
     * @return JSON string with field name suggestions
     */
    private Response suggestFieldNames(String structAddressStr, int structSize) {
        // Validate input parameters
        if (structSize < 0 || structSize > MAX_FIELD_OFFSET) {
            return errorJson("structSize must be between 0 and " + MAX_FIELD_OFFSET);
        }

        final AtomicReference<Response> result = new AtomicReference<>();

        // CRITICAL FIX #1: Thread safety - wrap in SwingUtilities.invokeAndWait
        try {
            SwingUtilities.invokeAndWait(() -> {
                try {
                    Program program = getCurrentProgram();
                    if (program == null) {
                        result.set(errorJson("No program loaded"));
                        return;
                    }

                    Address addr = program.getAddressFactory().getAddress(structAddressStr);
                    if (addr == null) {
                        result.set(errorJson("Invalid address: " + structAddressStr));
                        return;
                    }

                    Msg.info(this, "Generating field name suggestions for structure at " + structAddressStr);

                    // Get data at address
                    Data data = program.getListing().getDataAt(addr);
                    DataType dataType = (data != null) ? data.getDataType() : null;

                    if (dataType == null || !(dataType instanceof Structure)) {
                        result.set(errorJson("No structure data type found at " + structAddressStr));
                        return;
                    }

                    Structure struct = (Structure) dataType;

                    // MAJOR FIX #5: Validate structure size
                    DataTypeComponent[] components = struct.getComponents();
                    if (components.length > MAX_STRUCT_FIELDS) {
                        result.set(errorJson("Structure too large: " + components.length +
                                   " fields (max " + MAX_STRUCT_FIELDS + ")"));
                        return;
                    }

                    List<Map<String, Object>> suggestions = new ArrayList<>();
                    for (DataTypeComponent component : components) {
                        // Generate suggestions based on type and patterns
                        List<String> suggestedNames = generateFieldNameSuggestions(component);

                        // Ensure we always have fallback suggestions
                        if (suggestedNames.isEmpty()) {
                            suggestedNames.add(component.getFieldName() + "Value");
                            suggestedNames.add(component.getFieldName() + "Data");
                        }

                        Map<String, Object> fieldSuggestion = new LinkedHashMap<>();
                        fieldSuggestion.put("offset", component.getOffset());
                        fieldSuggestion.put("current_name", component.getFieldName());
                        fieldSuggestion.put("field_type", component.getDataType().getName());
                        fieldSuggestion.put("suggested_names", suggestedNames);
                        fieldSuggestion.put("confidence", "medium");
                        suggestions.add(fieldSuggestion);
                    }

                    Map<String, Object> response = new LinkedHashMap<>();
                    response.put("struct_address", structAddressStr);
                    response.put("struct_name", struct.getName());
                    response.put("struct_size", struct.getLength());
                    response.put("suggestions", suggestions);

                    Msg.info(this, "Generated suggestions for " + components.length + " fields");
                    result.set(Response.ok(response));

                } catch (Exception e) {
                    Msg.error(this, "Error in suggestFieldNames", e);
                    result.set(errorJson(e.getMessage()));
                }
            });
        } catch (InvocationTargetException | InterruptedException e) {
            Msg.error(this, "Thread synchronization error in suggestFieldNames", e);
            return errorJson("Thread synchronization error: " + e.getMessage());
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
     * Helper to capitalize first letter
     */
    private String capitalizeFirst(String str) {
        if (str == null || str.isEmpty()) return str;
        return Character.toUpperCase(str.charAt(0)) + str.substring(1);
    }

    /**
     * 7. INSPECT_MEMORY_CONTENT - Memory content inspection with string detection
     *
     * Reads raw memory bytes and provides hex/ASCII representation with string detection hints.
     * This helps prevent misidentification of strings as numeric data.
     */
    private Response inspectMemoryContent(String addressStr, int length, boolean detectStrings) throws Exception {
        Program program = getCurrentProgram();
        if (program == null) return errorJson("No program loaded");

        Address addr = program.getAddressFactory().getAddress(addressStr);
        if (addr == null) {
            return errorJson("Invalid address: " + addressStr);
        }

        Memory memory = program.getMemory();
        byte[] bytes = new byte[length];
        int bytesRead = memory.getBytes(addr, bytes);

        // Build hex dump
        StringBuilder hexDump = new StringBuilder();
        StringBuilder asciiRepr = new StringBuilder();

        for (int i = 0; i < bytesRead; i++) {
            if (i > 0 && i % 16 == 0) {
                hexDump.append("\\n");
                asciiRepr.append("\\n");
            }

            hexDump.append(String.format("%02X ", bytes[i] & 0xFF));

            // ASCII representation (printable chars only)
            char c = (char) (bytes[i] & 0xFF);
            if (c >= 0x20 && c <= 0x7E) {
                asciiRepr.append(c);
            } else if (c == 0x00) {
                asciiRepr.append("\\0");
            } else {
                asciiRepr.append(".");
            }
        }

        // String detection heuristics
        boolean likelyString = false;
        int printableCount = 0;
        int nullTerminatorIndex = -1;
        int consecutivePrintable = 0;
        int maxConsecutivePrintable = 0;

        for (int i = 0; i < bytesRead; i++) {
            char c = (char) (bytes[i] & 0xFF);

            if (c >= 0x20 && c <= 0x7E) {
                printableCount++;
                consecutivePrintable++;
                if (consecutivePrintable > maxConsecutivePrintable) {
                    maxConsecutivePrintable = consecutivePrintable;
                }
            } else {
                consecutivePrintable = 0;
            }

            if (c == 0x00 && nullTerminatorIndex == -1) {
                nullTerminatorIndex = i;
            }
        }

        double printableRatio = (double) printableCount / bytesRead;

        // String detection criteria:
        // - At least 60% printable characters OR
        // - At least 4 consecutive printable chars followed by null terminator
        if (detectStrings) {
            likelyString = (printableRatio >= 0.6) ||
                          (maxConsecutivePrintable >= 4 && nullTerminatorIndex > 0);
        }

        // Detect potential string content
        String detectedString = null;
        int stringLength = 0;
        if (likelyString && nullTerminatorIndex > 0) {
            detectedString = new String(bytes, 0, nullTerminatorIndex, StandardCharsets.US_ASCII);
            stringLength = nullTerminatorIndex + 1; // Include null terminator
        } else if (likelyString && printableRatio >= 0.8) {
            // String without null terminator (might be fixed-length string)
            int endIdx = bytesRead;
            for (int i = bytesRead - 1; i >= 0; i--) {
                if ((bytes[i] & 0xFF) >= 0x20 && (bytes[i] & 0xFF) <= 0x7E) {
                    endIdx = i + 1;
                    break;
                }
            }
            detectedString = new String(bytes, 0, endIdx, StandardCharsets.US_ASCII);
            stringLength = endIdx;
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("address", addressStr);
        result.put("bytes_read", bytesRead);
        result.put("hex_dump", hexDump.toString().trim());
        result.put("ascii_repr", asciiRepr.toString().trim());
        result.put("printable_count", printableCount);
        result.put("printable_ratio", Double.parseDouble(String.format("%.2f", printableRatio)));
        result.put("null_terminator_at", nullTerminatorIndex);
        result.put("max_consecutive_printable", maxConsecutivePrintable);
        result.put("is_likely_string", likelyString);
        result.put("detected_string", detectedString);
        result.put("suggested_type", detectedString != null ? "char[" + stringLength + "]" : null);
        result.put("string_length", detectedString != null ? stringLength : 0);
        return new Response.Ok(result);
    }

    // ============================================================================
    // MALWARE ANALYSIS IMPLEMENTATION METHODS
    // ============================================================================

    /**
     * Detect cryptographic constants in the binary (AES S-boxes, SHA constants, etc.)
     */
    private Response detectCryptoConstants() throws Exception {
        Program program = getCurrentProgram();
        if (program == null) {
            return errorJson("No program loaded");
        }

        // Placeholder implementation - full implementation would search for known crypto constants
        // like AES S-boxes, SHA constants, DES constants, RC4 initialization vectors, etc.
        Map<String, Object> placeholder = new LinkedHashMap<>();
        placeholder.put("algorithm", "Crypto Detection");
        placeholder.put("status", "Not yet implemented");
        placeholder.put("note", "This endpoint requires advanced pattern matching against known crypto constants");
        return new Response.Ok(List.of(placeholder));
    }

    /**
     * Find functions structurally similar to the target function
     * Uses basic block count, instruction count, call count, and cyclomatic complexity
     */
    private Response findSimilarFunctions(String targetFunction, double threshold) throws Exception {
        Program program = getCurrentProgram();
        if (program == null) {
            return errorJson("No program loaded");
        }

        if (targetFunction == null || targetFunction.trim().isEmpty()) {
            return errorJson("Target function name is required");
        }

        FunctionManager functionManager = program.getFunctionManager();
        Function targetFunc = null;
        
        // Find the target function
        for (Function f : functionManager.getFunctions(true)) {
            if (f.getName().equals(targetFunction)) {
                targetFunc = f;
                break;
            }
        }
        
        if (targetFunc == null) {
            return errorJson("Function not found: " + targetFunction);
        }

        // Calculate metrics for target function
        BasicBlockModel blockModel = new BasicBlockModel(program);
        FunctionMetrics targetMetrics = calculateFunctionMetrics(targetFunc, blockModel, program);

        // Find similar functions
        List<Map<String, Object>> similarFunctions = new ArrayList<>();

        for (Function func : functionManager.getFunctions(true)) {
            if (func.getName().equals(targetFunction)) continue;
            if (func.isThunk()) continue;

            FunctionMetrics funcMetrics = calculateFunctionMetrics(func, blockModel, program);
            double similarity = calculateSimilarity(targetMetrics, funcMetrics);

            if (similarity >= threshold) {
                Map<String, Object> match = new LinkedHashMap<>();
                match.put("name", func.getName());
                match.put("address", func.getEntryPoint().toString());
                match.put("similarity", Math.round(similarity * 1000.0) / 1000.0);
                match.put("basic_blocks", funcMetrics.basicBlockCount);
                match.put("instructions", funcMetrics.instructionCount);
                match.put("calls", funcMetrics.callCount);
                match.put("complexity", funcMetrics.cyclomaticComplexity);
                similarFunctions.add(match);
            }
        }

        // Sort by similarity descending
        similarFunctions.sort((a, b) -> Double.compare((Double)b.get("similarity"), (Double)a.get("similarity")));

        // Limit results
        if (similarFunctions.size() > 50) {
            similarFunctions = similarFunctions.subList(0, 50);
        }

        Map<String, Object> targetMetricsMap = new LinkedHashMap<>();
        targetMetricsMap.put("basic_blocks", targetMetrics.basicBlockCount);
        targetMetricsMap.put("instructions", targetMetrics.instructionCount);
        targetMetricsMap.put("calls", targetMetrics.callCount);
        targetMetricsMap.put("complexity", targetMetrics.cyclomaticComplexity);

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("target_function", targetFunction);
        result.put("target_metrics", targetMetricsMap);
        result.put("threshold", threshold);
        result.put("matches_found", similarFunctions.size());
        result.put("similar_functions", similarFunctions);
        return new Response.Ok(result);
    }
    
    /**
     * Helper class to store function metrics for similarity comparison
     */
    private static class FunctionMetrics {
        int basicBlockCount = 0;
        int instructionCount = 0;
        int callCount = 0;
        int cyclomaticComplexity = 0;
        int edgeCount = 0;
        Set<String> calledFunctions = new HashSet<>();
    }
    
    /**
     * Calculate structural metrics for a function
     */
    private FunctionMetrics calculateFunctionMetrics(Function func, BasicBlockModel blockModel, Program program) {
        FunctionMetrics metrics = new FunctionMetrics();
        
        try {
            // Count basic blocks and edges
            CodeBlockIterator blockIter = blockModel.getCodeBlocksContaining(func.getBody(), null);
            while (blockIter.hasNext()) {
                CodeBlock block = blockIter.next();
                metrics.basicBlockCount++;
                
                // Count outgoing edges for complexity calculation
                CodeBlockReferenceIterator destIter = block.getDestinations(null);
                while (destIter.hasNext()) {
                    destIter.next();
                    metrics.edgeCount++;
                }
            }
            
            // Cyclomatic complexity = E - N + 2P (where P=1 for single function)
            metrics.cyclomaticComplexity = metrics.edgeCount - metrics.basicBlockCount + 2;
            if (metrics.cyclomaticComplexity < 1) metrics.cyclomaticComplexity = 1;
            
            // Count instructions and calls
            Listing listing = program.getListing();
            InstructionIterator instrIter = listing.getInstructions(func.getBody(), true);
            ReferenceManager refManager = program.getReferenceManager();
            
            while (instrIter.hasNext()) {
                Instruction instr = instrIter.next();
                metrics.instructionCount++;
                
                if (instr.getFlowType().isCall()) {
                    metrics.callCount++;
                    // Track which functions are called
                    for (Reference ref : refManager.getReferencesFrom(instr.getAddress())) {
                        if (ref.getReferenceType().isCall()) {
                            Function calledFunc = program.getFunctionManager().getFunctionAt(ref.getToAddress());
                            if (calledFunc != null) {
                                metrics.calledFunctions.add(calledFunc.getName());
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            // Return partial metrics on error
        }
        
        return metrics;
    }
    
    /**
     * Calculate similarity score between two functions (0.0 to 1.0)
     */
    private double calculateSimilarity(FunctionMetrics a, FunctionMetrics b) {
        // Weight different metrics
        double blockSim = 1.0 - Math.abs(a.basicBlockCount - b.basicBlockCount) / 
                          (double) Math.max(Math.max(a.basicBlockCount, b.basicBlockCount), 1);
        double instrSim = 1.0 - Math.abs(a.instructionCount - b.instructionCount) / 
                          (double) Math.max(Math.max(a.instructionCount, b.instructionCount), 1);
        double callSim = 1.0 - Math.abs(a.callCount - b.callCount) / 
                         (double) Math.max(Math.max(a.callCount, b.callCount), 1);
        double complexitySim = 1.0 - Math.abs(a.cyclomaticComplexity - b.cyclomaticComplexity) / 
                               (double) Math.max(Math.max(a.cyclomaticComplexity, b.cyclomaticComplexity), 1);
        
        // Jaccard similarity for called functions
        double calledFuncSim = 0.0;
        if (!a.calledFunctions.isEmpty() || !b.calledFunctions.isEmpty()) {
            Set<String> intersection = new HashSet<>(a.calledFunctions);
            intersection.retainAll(b.calledFunctions);
            Set<String> union = new HashSet<>(a.calledFunctions);
            union.addAll(b.calledFunctions);
            calledFuncSim = union.isEmpty() ? 0.0 : (double) intersection.size() / union.size();
        }
        
        // Weighted average (structure matters more than exact counts)
        return 0.25 * blockSim + 0.20 * instrSim + 0.15 * callSim + 
               0.20 * complexitySim + 0.20 * calledFuncSim;
    }

    /**
     * Analyze function control flow complexity
     * Calculates cyclomatic complexity, basic blocks, edges, and detailed metrics
     */
    private Response analyzeControlFlow(String functionName) throws Exception {
        Program program = getCurrentProgram();
        if (program == null) {
            return errorJson("No program loaded");
        }

        if (functionName == null || functionName.trim().isEmpty()) {
            return errorJson("Function name is required");
        }

        FunctionManager functionManager = program.getFunctionManager();
        Function func = null;

        // Find the function by name
        for (Function f : functionManager.getFunctions(true)) {
            if (f.getName().equals(functionName)) {
                func = f;
                break;
            }
        }

        if (func == null) {
            return errorJson("Function not found: " + functionName);
        }
        
        BasicBlockModel blockModel = new BasicBlockModel(program);
        Listing listing = program.getListing();
        ReferenceManager refManager = program.getReferenceManager();
        
        // Collect detailed metrics
        int basicBlockCount = 0;
        int edgeCount = 0;
        int conditionalBranches = 0;
        int unconditionalJumps = 0;
        int loops = 0;
        int instructionCount = 0;
        int callCount = 0;
        int returnCount = 0;
        List<Map<String, Object>> blocks = new ArrayList<>();
        Set<Address> blockEntries = new HashSet<>();
        
        // First pass: collect all block entry points
        CodeBlockIterator blockIter = blockModel.getCodeBlocksContaining(func.getBody(), null);
        while (blockIter.hasNext()) {
            CodeBlock block = blockIter.next();
            blockEntries.add(block.getFirstStartAddress());
        }
        
        // Second pass: detailed analysis
        blockIter = blockModel.getCodeBlocksContaining(func.getBody(), null);
        while (blockIter.hasNext()) {
            CodeBlock block = blockIter.next();
            basicBlockCount++;
            
            Map<String, Object> blockInfo = new LinkedHashMap<>();
            blockInfo.put("address", block.getFirstStartAddress().toString());
            blockInfo.put("size", block.getNumAddresses());
            
            // Count edges and detect loops
            int outEdges = 0;
            boolean hasBackEdge = false;
            List<String> successors = new ArrayList<>();
            
            CodeBlockReferenceIterator destIter = block.getDestinations(null);
            while (destIter.hasNext()) {
                CodeBlockReference ref = destIter.next();
                outEdges++;
                edgeCount++;
                Address destAddr = ref.getDestinationAddress();
                successors.add(destAddr.toString());
                
                // Detect back edges (loops) - destination is before current block
                if (destAddr.compareTo(block.getFirstStartAddress()) < 0 && 
                    blockEntries.contains(destAddr)) {
                    hasBackEdge = true;
                }
            }
            
            if (hasBackEdge) loops++;
            blockInfo.put("successors", successors.size());
            blockInfo.put("is_loop_header", hasBackEdge);
            
            // Classify block type
            if (outEdges == 0) {
                blockInfo.put("type", "exit");
            } else if (outEdges == 1) {
                blockInfo.put("type", "sequential");
            } else if (outEdges == 2) {
                blockInfo.put("type", "conditional");
                conditionalBranches++;
            } else {
                blockInfo.put("type", "switch");
            }
            
            blocks.add(blockInfo);
        }
        
        // Count instructions by type
        InstructionIterator instrIter = listing.getInstructions(func.getBody(), true);
        while (instrIter.hasNext()) {
            Instruction instr = instrIter.next();
            instructionCount++;
            
            if (instr.getFlowType().isCall()) {
                callCount++;
            } else if (instr.getFlowType().isTerminal()) {
                returnCount++;
            } else if (instr.getFlowType().isJump()) {
                if (instr.getFlowType().isConditional()) {
                    // Already counted above
                } else {
                    unconditionalJumps++;
                }
            }
        }
        
        // Calculate cyclomatic complexity: M = E - N + 2P
        int cyclomaticComplexity = edgeCount - basicBlockCount + 2;
        if (cyclomaticComplexity < 1) cyclomaticComplexity = 1;

        String complexityRating;
        if (cyclomaticComplexity <= 5) {
            complexityRating = "low";
        } else if (cyclomaticComplexity <= 10) {
            complexityRating = "moderate";
        } else if (cyclomaticComplexity <= 20) {
            complexityRating = "high";
        } else if (cyclomaticComplexity <= 50) {
            complexityRating = "very_high";
        } else {
            complexityRating = "extreme";
        }

        List<Map<String, Object>> blockDetails = blocks.subList(0, Math.min(blocks.size(), 100));
        if (blocks.size() > 100) {
            Map<String, Object> truncNote = new LinkedHashMap<>();
            truncNote.put("note", (blocks.size() - 100) + " additional blocks truncated");
            blockDetails = new ArrayList<>(blockDetails);
            blockDetails.add(truncNote);
        }

        Map<String, Object> metrics = new LinkedHashMap<>();
        metrics.put("cyclomatic_complexity", cyclomaticComplexity);
        metrics.put("complexity_rating", complexityRating);
        metrics.put("basic_blocks", basicBlockCount);
        metrics.put("edges", edgeCount);
        metrics.put("instructions", instructionCount);
        metrics.put("conditional_branches", conditionalBranches);
        metrics.put("unconditional_jumps", unconditionalJumps);
        metrics.put("loops_detected", loops);
        metrics.put("calls", callCount);
        metrics.put("returns", returnCount);

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("function_name", functionName);
        result.put("entry_point", func.getEntryPoint().toString());
        result.put("size_bytes", func.getBody().getNumAddresses());
        result.put("metrics", metrics);
        result.put("basic_block_details", blockDetails);
        return new Response.Ok(result);
    }

    /**
     * Detect anti-analysis and anti-debugging techniques
     * Scans for known anti-debug APIs, timing checks, VM detection, and SEH tricks
     */
    private Response findAntiAnalysisTechniques() throws Exception {
        Program program = getCurrentProgram();
        if (program == null) {
            return errorJson("No program loaded");
        }

        // Define patterns to search for
        Map<String, String[]> antiDebugAPIs = new LinkedHashMap<>();
        antiDebugAPIs.put("debugger_detection", new String[]{
            "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
            "OutputDebugString", "DebugActiveProcess", "CloseHandle", "NtClose"
        });
        antiDebugAPIs.put("timing_checks", new String[]{
            "GetTickCount", "GetTickCount64", "QueryPerformanceCounter", 
            "GetSystemTimeAsFileTime", "timeGetTime", "NtQuerySystemTime"
        });
        antiDebugAPIs.put("process_enumeration", new String[]{
            "CreateToolhelp32Snapshot", "Process32First", "Process32Next",
            "EnumProcesses", "NtQuerySystemInformation", "OpenProcess"
        });
        antiDebugAPIs.put("vm_detection", new String[]{
            "GetSystemFirmwareTable", "EnumSystemFirmwareTable", 
            "WMI", "SMBIOS", "ACPI"
        });
        antiDebugAPIs.put("exception_based", new String[]{
            "SetUnhandledExceptionFilter", "AddVectoredExceptionHandler",
            "RtlAddVectoredExceptionHandler", "NtSetInformationThread"
        });
        antiDebugAPIs.put("memory_checks", new String[]{
            "VirtualQuery", "NtQueryVirtualMemory", "ReadProcessMemory",
            "WriteProcessMemory"
        });
        
        // Instruction patterns to detect
        String[] suspiciousInstructions = {"RDTSC", "CPUID", "INT 3", "INT 0x2d", "SIDT", "SGDT", "SLDT", "STR"};
        
        List<Map<String, Object>> findings = new ArrayList<>();
        FunctionManager functionManager = program.getFunctionManager();
        SymbolTable symbolTable = program.getSymbolTable();
        Listing listing = program.getListing();
        
        // Scan for API calls
        for (Map.Entry<String, String[]> category : antiDebugAPIs.entrySet()) {
            String categoryName = category.getKey();
            for (String apiName : category.getValue()) {
                // Search for symbols matching the API name
                SymbolIterator symbols = symbolTable.getSymbolIterator("*" + apiName + "*", true);
                while (symbols.hasNext()) {
                    Symbol sym = symbols.next();
                    // Find references to this symbol
                    ReferenceManager refManager = program.getReferenceManager();
                    ReferenceIterator refs = refManager.getReferencesTo(sym.getAddress());
                    while (refs.hasNext()) {
                        Reference ref = refs.next();
                        if (ref.getReferenceType().isCall()) {
                            Function callingFunc = functionManager.getFunctionContaining(ref.getFromAddress());
                            Map<String, Object> finding = new LinkedHashMap<>();
                            finding.put("category", categoryName);
                            finding.put("technique", apiName);
                            finding.put("address", ref.getFromAddress().toString());
                            finding.put("function", callingFunc != null ? callingFunc.getName() : "unknown");
                            finding.put("severity", getSeverity(categoryName));
                            findings.add(finding);
                        }
                    }
                }
            }
        }
        
        // Scan for suspicious instructions
        for (Function func : functionManager.getFunctions(true)) {
            InstructionIterator instrIter = listing.getInstructions(func.getBody(), true);
            while (instrIter.hasNext()) {
                Instruction instr = instrIter.next();
                String mnemonic = instr.getMnemonicString().toUpperCase();
                
                for (String suspicious : suspiciousInstructions) {
                    if (mnemonic.contains(suspicious.split(" ")[0])) {
                        Map<String, Object> finding = new LinkedHashMap<>();
                        finding.put("category", "suspicious_instruction");
                        finding.put("technique", suspicious);
                        finding.put("address", instr.getAddress().toString());
                        finding.put("function", func.getName());
                        finding.put("instruction", instr.toString());
                        finding.put("severity", "medium");
                        findings.add(finding);
                    }
                }
            }
        }
        
        // Check for PEB access patterns (common anti-debug)
        for (Function func : functionManager.getFunctions(true)) {
            InstructionIterator instrIter = listing.getInstructions(func.getBody(), true);
            boolean foundFsAccess = false;
            while (instrIter.hasNext()) {
                Instruction instr = instrIter.next();
                String instrStr = instr.toString().toUpperCase();
                // FS:[0x30] is PEB access, FS:[0x18] is TEB
                if (instrStr.contains("FS:") && (instrStr.contains("0X30") || instrStr.contains("0X18"))) {
                    if (!foundFsAccess) {
                        Map<String, Object> finding = new LinkedHashMap<>();
                        finding.put("category", "peb_teb_access");
                        finding.put("technique", "Direct PEB/TEB access");
                        finding.put("address", instr.getAddress().toString());
                        finding.put("function", func.getName());
                        finding.put("instruction", instr.toString());
                        finding.put("severity", "high");
                        finding.put("description", "Direct access to PEB/TEB can be used to detect debuggers");
                        findings.add(finding);
                        foundFsAccess = true;
                    }
                }
            }
        }
        
        // Count by category and severity
        Map<String, Integer> categoryCounts = new LinkedHashMap<>();
        Map<String, Integer> severityCounts = new LinkedHashMap<>();
        for (Map<String, Object> finding : findings) {
            String cat = (String) finding.get("category");
            String sev = (String) finding.get("severity");
            categoryCounts.put(cat, categoryCounts.getOrDefault(cat, 0) + 1);
            severityCounts.put(sev, severityCounts.getOrDefault(sev, 0) + 1);
        }

        List<Map<String, Object>> findingsList = findings.subList(0, Math.min(findings.size(), 100));
        if (findings.size() > 100) {
            Map<String, Object> truncNote = new LinkedHashMap<>();
            truncNote.put("note", (findings.size() - 100) + " additional findings truncated");
            findingsList = new ArrayList<>(findingsList);
            findingsList.add(truncNote);
        }

        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("by_category", categoryCounts);
        summary.put("by_severity", severityCounts);

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("total_findings", findings.size());
        result.put("summary", summary);
        result.put("findings", findingsList);
        return new Response.Ok(result);
    }
    
    /**
     * Helper to determine severity based on anti-analysis category
     */
    private String getSeverity(String category) {
        switch (category) {
            case "debugger_detection": return "high";
            case "timing_checks": return "medium";
            case "process_enumeration": return "medium";
            case "vm_detection": return "high";
            case "exception_based": return "high";
            case "memory_checks": return "low";
            default: return "medium";
        }
    }

    /**
     * Batch decompile multiple functions
     */
    private Response batchDecompileFunctions(String functionsParam) throws Exception {
        Program program = getCurrentProgram();
        if (program == null) {
            return errorJson("No program loaded");
        }

        if (functionsParam == null || functionsParam.trim().isEmpty()) {
            return errorJson("Functions parameter is required");
        }

        String[] functionNames = functionsParam.split(",");
        Map<String, String> result = new LinkedHashMap<>();

        FunctionManager funcManager = program.getFunctionManager();
        final int MAX_FUNCTIONS = 20; // Limit to prevent overload

        for (int i = 0; i < functionNames.length && i < MAX_FUNCTIONS; i++) {
            String funcName = functionNames[i].trim();
            if (funcName.isEmpty()) continue;

            // Find function by name
            Function function = null;
            SymbolTable symbolTable = program.getSymbolTable();
            SymbolIterator symbols = symbolTable.getSymbols(funcName);

            while (symbols.hasNext()) {
                Symbol symbol = symbols.next();
                if (symbol.getSymbolType() == SymbolType.FUNCTION) {
                    function = funcManager.getFunctionAt(symbol.getAddress());
                    break;
                }
            }

            if (function == null) {
                result.put(funcName, "Error: Function not found");
                continue;
            }

            // Decompile the function
            try {
                DecompInterface decompiler = new DecompInterface();
                decompiler.openProgram(program);
                DecompileResults decompResults = decompiler.decompileFunction(function, 30, null);

                if (decompResults != null && decompResults.decompileCompleted()) {
                    result.put(funcName, decompResults.getDecompiledFunction().getC());
                } else {
                    result.put(funcName, "Error: Decompilation failed");
                }

                decompiler.dispose();
            } catch (Exception e) {
                result.put(funcName, "Error: " + e.getMessage());
            }
        }

        return new Response.Ok(result);
    }

    /**
     * Find potentially unreachable code blocks
     */
    private Response findDeadCode(String functionName) throws Exception {
        Program program = getCurrentProgram();
        if (program == null) {
            return errorJson("No program loaded");
        }

        if (functionName == null || functionName.trim().isEmpty()) {
            return errorJson("Function name is required");
        }

        // Placeholder implementation - full implementation would analyze control flow
        // to find unreachable blocks via reachability analysis on the control flow graph
        Map<String, Object> placeholder = new LinkedHashMap<>();
        placeholder.put("function_name", functionName);
        placeholder.put("status", "Not yet implemented");
        placeholder.put("note", "This endpoint requires reachability analysis via control flow graph");
        return new Response.Ok(List.of(placeholder));
    }

    /**
     * Automatically identify and decrypt obfuscated strings
     */
    private Response autoDecryptStrings() throws Exception {
        Program program = getCurrentProgram();
        if (program == null) {
            return errorJson("No program loaded");
        }

        // Placeholder implementation - full implementation would detect and decrypt
        // XOR-encoded strings, Base64-encoded strings, ROT13, stack strings, RC4/AES encrypted strings
        Map<String, Object> placeholder = new LinkedHashMap<>();
        placeholder.put("method", "String Decryption");
        placeholder.put("status", "Not yet implemented");
        placeholder.put("note", "This endpoint requires pattern detection and decryption of various encoding schemes");
        return new Response.Ok(List.of(placeholder));
    }

    /**
     * Identify and analyze suspicious API call chains
     * Detects threat patterns like process injection, persistence, credential theft
     */
    private Response analyzeAPICallChains() throws Exception {
        Program program = getCurrentProgram();
        if (program == null) {
            return errorJson("No program loaded");
        }

        // Define threat patterns as API call sequences
        List<ThreatPattern> threatPatterns = new ArrayList<>();
        
        // Process Injection patterns
        threatPatterns.add(new ThreatPattern("process_injection_classic",
            "Classic Process Injection", "critical",
            new String[]{"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"},
            "Allocates memory in remote process, writes code, and creates thread to execute"));
        
        threatPatterns.add(new ThreatPattern("process_injection_ntapi",
            "NT API Process Injection", "critical",
            new String[]{"NtOpenProcess", "NtAllocateVirtualMemory", "NtWriteVirtualMemory", "NtCreateThreadEx"},
            "Process injection using NT native APIs"));
        
        threatPatterns.add(new ThreatPattern("process_hollowing",
            "Process Hollowing", "critical",
            new String[]{"CreateProcess", "NtUnmapViewOfSection", "VirtualAllocEx", "WriteProcessMemory", "SetThreadContext", "ResumeThread"},
            "Creates suspended process, hollows it out, and replaces with malicious code"));
        
        threatPatterns.add(new ThreatPattern("dll_injection",
            "DLL Injection", "high",
            new String[]{"OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "LoadLibrary"},
            "Injects DLL into remote process"));
        
        // Persistence patterns
        threatPatterns.add(new ThreatPattern("registry_persistence",
            "Registry Persistence", "high",
            new String[]{"RegOpenKey", "RegSetValue"},
            "Modifies registry for persistence"));
        
        threatPatterns.add(new ThreatPattern("service_persistence",
            "Service Persistence", "high",
            new String[]{"OpenSCManager", "CreateService"},
            "Creates Windows service for persistence"));
        
        threatPatterns.add(new ThreatPattern("scheduled_task",
            "Scheduled Task Persistence", "high",
            new String[]{"CoCreateInstance", "ITaskScheduler"},
            "Creates scheduled task for persistence"));
        
        // Credential theft patterns
        threatPatterns.add(new ThreatPattern("lsass_access",
            "LSASS Memory Access", "critical",
            new String[]{"OpenProcess", "ReadProcessMemory"},
            "May be accessing LSASS for credential extraction"));
        
        threatPatterns.add(new ThreatPattern("sam_access",
            "SAM Database Access", "critical",
            new String[]{"RegOpenKey", "SAM"},
            "May be accessing SAM database for password hashes"));
        
        // Network patterns
        threatPatterns.add(new ThreatPattern("socket_communication",
            "Network Communication", "medium",
            new String[]{"WSAStartup", "socket", "connect", "send", "recv"},
            "Establishes network connection"));
        
        threatPatterns.add(new ThreatPattern("http_communication",
            "HTTP Communication", "medium",
            new String[]{"InternetOpen", "InternetConnect", "HttpOpenRequest"},
            "Performs HTTP communication"));
        
        // File operations
        threatPatterns.add(new ThreatPattern("file_encryption",
            "Potential Ransomware", "critical",
            new String[]{"FindFirstFile", "FindNextFile", "CryptEncrypt"},
            "File enumeration combined with encryption"));
        
        // Analyze functions for these patterns
        FunctionManager functionManager = program.getFunctionManager();
        SymbolTable symbolTable = program.getSymbolTable();
        ReferenceManager refManager = program.getReferenceManager();
        
        List<Map<String, Object>> detectedPatterns = new ArrayList<>();
        
        // Build API call map per function
        Map<Function, Set<String>> functionAPIs = new LinkedHashMap<>();
        
        for (Function func : functionManager.getFunctions(true)) {
            if (func.isThunk()) continue;
            
            Set<String> apis = new HashSet<>();
            Listing listing = program.getListing();
            InstructionIterator instrIter = listing.getInstructions(func.getBody(), true);
            
            while (instrIter.hasNext()) {
                Instruction instr = instrIter.next();
                if (instr.getFlowType().isCall()) {
                    for (Reference ref : refManager.getReferencesFrom(instr.getAddress())) {
                        if (ref.getReferenceType().isCall()) {
                            Symbol sym = symbolTable.getPrimarySymbol(ref.getToAddress());
                            if (sym != null) {
                                apis.add(sym.getName());
                            }
                        }
                    }
                }
            }
            
            if (!apis.isEmpty()) {
                functionAPIs.put(func, apis);
            }
        }
        
        // Check each function against threat patterns
        for (Map.Entry<Function, Set<String>> entry : functionAPIs.entrySet()) {
            Function func = entry.getKey();
            Set<String> apis = entry.getValue();
            
            for (ThreatPattern pattern : threatPatterns) {
                int matchCount = 0;
                List<String> matchedAPIs = new ArrayList<>();
                
                for (String requiredAPI : pattern.apis) {
                    for (String funcAPI : apis) {
                        if (funcAPI.toLowerCase().contains(requiredAPI.toLowerCase())) {
                            matchCount++;
                            matchedAPIs.add(funcAPI);
                            break;
                        }
                    }
                }
                
                // Require at least half of the pattern APIs to match
                if (matchCount >= Math.ceil(pattern.apis.length / 2.0) && matchCount >= 2) {
                    double confidence = (double) matchCount / pattern.apis.length;
                    
                    Map<String, Object> detection = new LinkedHashMap<>();
                    detection.put("pattern_id", pattern.id);
                    detection.put("pattern_name", pattern.name);
                    detection.put("severity", pattern.severity);
                    detection.put("function", func.getName());
                    detection.put("address", func.getEntryPoint().toString());
                    detection.put("confidence", Math.round(confidence * 100.0) / 100.0);
                    detection.put("matched_apis", matchedAPIs);
                    detection.put("description", pattern.description);
                    
                    detectedPatterns.add(detection);
                }
            }
        }
        
        // Sort by severity and confidence
        detectedPatterns.sort((a, b) -> {
            int sevCompare = getSeverityRank((String)a.get("severity")) - getSeverityRank((String)b.get("severity"));
            if (sevCompare != 0) return sevCompare;
            return Double.compare((Double)b.get("confidence"), (Double)a.get("confidence"));
        });

        // Count by severity
        Map<String, Integer> sevCounts = new LinkedHashMap<>();
        for (Map<String, Object> det : detectedPatterns) {
            String sev = (String) det.get("severity");
            sevCounts.put(sev, sevCounts.getOrDefault(sev, 0) + 1);
        }

        List<Map<String, Object>> patternList = detectedPatterns.subList(0, Math.min(detectedPatterns.size(), 50));

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("total_patterns_detected", detectedPatterns.size());
        result.put("severity_summary", sevCounts);
        result.put("detected_patterns", patternList);
        return new Response.Ok(result);
    }
    
    /**
     * Helper class for threat pattern definitions
     */
    private static class ThreatPattern {
        String id;
        String name;
        String severity;
        String[] apis;
        String description;
        
        ThreatPattern(String id, String name, String severity, String[] apis, String description) {
            this.id = id;
            this.name = name;
            this.severity = severity;
            this.apis = apis;
            this.description = description;
        }
    }
    
    /**
     * Helper to rank severity for sorting
     */
    private int getSeverityRank(String severity) {
        switch (severity) {
            case "critical": return 0;
            case "high": return 1;
            case "medium": return 2;
            case "low": return 3;
            default: return 4;
        }
    }

    /**
     * Enhanced IOC extraction with context and confidence scoring
     */
    private Response extractIOCsWithContext() throws Exception {
        Program program = getCurrentProgram();
        if (program == null) {
            return Response.err("No program loaded");
        }

        List<Map<String, Object>> iocs = new ArrayList<>();
        Listing listing = program.getListing();
        FunctionManager functionManager = program.getFunctionManager();
        
        // Regex patterns for IOC extraction
        Pattern ipv4Pattern = Pattern.compile("\\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\b");
        Pattern urlPattern = Pattern.compile("https?://[\\w\\-._~:/?#\\[\\]@!$&'()*+,;=%]+", Pattern.CASE_INSENSITIVE);
        Pattern domainPattern = Pattern.compile("\\b[a-zA-Z0-9][a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9]\\.[a-zA-Z]{2,}\\b");
        Pattern emailPattern = Pattern.compile("[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}");
        Pattern registryPattern = Pattern.compile("(HKEY_[A-Z_]+|HKLM|HKCU|HKCR|HKU|HKCC)\\\\[\\w\\\\]+", Pattern.CASE_INSENSITIVE);
        Pattern filePathPattern = Pattern.compile("([a-zA-Z]:\\\\[^\"<>|*?\\n]+|\\\\\\\\[\\w.]+\\\\[^\"<>|*?\\n]+)");
        Pattern bitcoinPattern = Pattern.compile("\\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\\b");
        Pattern md5Pattern = Pattern.compile("\\b[a-fA-F0-9]{32}\\b");
        Pattern sha256Pattern = Pattern.compile("\\b[a-fA-F0-9]{64}\\b");
        
        // Scan defined strings
        DataIterator dataIter = listing.getDefinedData(true);
        while (dataIter.hasNext()) {
            Data data = dataIter.next();
            if (data.getDataType() instanceof StringDataType || 
                data.getDataType().getName().toLowerCase().contains("string")) {
                
                Object value = data.getValue();
                if (value != null) {
                    String strValue = value.toString();
                    Address addr = data.getAddress();
                    
                    // Find containing function for context
                    Function containingFunc = functionManager.getFunctionContaining(addr);
                    String funcContext = containingFunc != null ? containingFunc.getName() : "global";
                    
                    // Check each pattern
                    checkAndAddIOC(iocs, strValue, ipv4Pattern, "ipv4", addr, funcContext);
                    checkAndAddIOC(iocs, strValue, urlPattern, "url", addr, funcContext);
                    checkAndAddIOC(iocs, strValue, domainPattern, "domain", addr, funcContext);
                    checkAndAddIOC(iocs, strValue, emailPattern, "email", addr, funcContext);
                    checkAndAddIOC(iocs, strValue, registryPattern, "registry_key", addr, funcContext);
                    checkAndAddIOC(iocs, strValue, filePathPattern, "file_path", addr, funcContext);
                    checkAndAddIOC(iocs, strValue, bitcoinPattern, "bitcoin_address", addr, funcContext);
                    checkAndAddIOC(iocs, strValue, md5Pattern, "md5_hash", addr, funcContext);
                    checkAndAddIOC(iocs, strValue, sha256Pattern, "sha256_hash", addr, funcContext);
                }
            }
        }
        
        // Calculate confidence scores
        for (Map<String, Object> ioc : iocs) {
            double confidence = calculateIOCConfidence(ioc, program);
            ioc.put("confidence", Math.round(confidence * 100.0) / 100.0);
        }
        
        // Sort by confidence descending
        iocs.sort((a, b) -> Double.compare((Double)b.get("confidence"), (Double)a.get("confidence")));
        
        // Summary by type
        Map<String, Integer> typeCounts = new LinkedHashMap<>();
        for (Map<String, Object> ioc : iocs) {
            String type = (String) ioc.get("type");
            typeCounts.put(type, typeCounts.getOrDefault(type, 0) + 1);
        }

        List<Object> iocList = new ArrayList<>(iocs.subList(0, Math.min(iocs.size(), 100)));
        if (iocs.size() > 100) {
            Map<String, Object> note = new LinkedHashMap<>();
            note.put("note", (iocs.size() - 100) + " additional IOCs truncated");
            iocList.add(note);
        }

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("total_iocs", iocs.size());
        response.put("by_type", typeCounts);
        response.put("iocs", iocList);
        return new Response.Ok(response);
    }
    
    /**
     * Helper to check pattern and add IOC
     */
    private void checkAndAddIOC(List<Map<String, Object>> iocs, String value, Pattern pattern, 
                                 String type, Address address, String funcContext) {
        java.util.regex.Matcher matcher = pattern.matcher(value);
        while (matcher.find()) {
            String match = matcher.group();
            // Skip common false positives
            if (type.equals("ipv4") && (match.startsWith("0.") || match.startsWith("255."))) continue;
            if (type.equals("domain") && match.length() < 4) continue;
            
            Map<String, Object> ioc = new LinkedHashMap<>();
            ioc.put("type", type);
            ioc.put("value", match);
            ioc.put("address", address.toString());
            ioc.put("function_context", funcContext);
            iocs.add(ioc);
        }
    }
    
    /**
     * Calculate confidence score for an IOC based on context
     */
    private double calculateIOCConfidence(Map<String, Object> ioc, Program program) {
        String type = (String) ioc.get("type");
        String value = (String) ioc.get("value");
        String funcContext = (String) ioc.get("function_context");
        
        double confidence = 0.5; // Base confidence
        
        // Type-based adjustments
        switch (type) {
            case "url":
            case "ipv4":
                confidence += 0.2;
                break;
            case "registry_key":
                if (value.toLowerCase().contains("run") || value.toLowerCase().contains("services")) {
                    confidence += 0.3; // Persistence indicators
                }
                break;
            case "bitcoin_address":
                confidence += 0.4; // Strong indicator
                break;
            case "file_path":
                if (value.toLowerCase().contains("temp") || value.toLowerCase().contains("appdata")) {
                    confidence += 0.2;
                }
                break;
        }
        
        // Function context adjustments
        if (!funcContext.equals("global")) {
            confidence += 0.1; // IOC used in actual function
        }
        
        // Check for xrefs to increase confidence
        try {
            Address addr = program.getAddressFactory().getAddress((String) ioc.get("address"));
            ReferenceManager refManager = program.getReferenceManager();
            ReferenceIterator refs = refManager.getReferencesTo(addr);
            int refCount = 0;
            while (refs.hasNext() && refCount < 10) {
                refs.next();
                refCount++;
            }
            if (refCount > 0) {
                confidence += 0.1 * Math.min(refCount, 3);
            }
        } catch (Exception e) {
            // Ignore xref errors
        }
        
        return Math.min(confidence, 1.0);
    }

    /**
     * Detect common malware behaviors and techniques
     */
    private Response detectMalwareBehaviors() throws Exception {
        Program program = getCurrentProgram();
        if (program == null) {
            return Response.err("No program loaded");
        }

        List<Map<String, Object>> behaviors = new ArrayList<>();
        FunctionManager functionManager = program.getFunctionManager();
        SymbolTable symbolTable = program.getSymbolTable();
        ReferenceManager refManager = program.getReferenceManager();
        Listing listing = program.getListing();
        
        // Define behavior categories and their indicators
        Map<String, String[]> behaviorIndicators = new LinkedHashMap<>();
        
        // Code injection
        behaviorIndicators.put("code_injection", new String[]{
            "VirtualAlloc", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
            "NtWriteVirtualMemory", "RtlCreateUserThread", "QueueUserAPC"
        });
        
        // Keylogging
        behaviorIndicators.put("keylogging", new String[]{
            "SetWindowsHookEx", "GetAsyncKeyState", "GetKeyState", "RegisterRawInputDevices"
        });
        
        // Screen capture
        behaviorIndicators.put("screen_capture", new String[]{
            "GetDC", "GetWindowDC", "BitBlt", "CreateCompatibleBitmap", "GetDIBits"
        });
        
        // Privilege escalation
        behaviorIndicators.put("privilege_escalation", new String[]{
            "AdjustTokenPrivileges", "LookupPrivilegeValue", "OpenProcessToken",
            "ImpersonateLoggedOnUser", "DuplicateToken"
        });
        
        // Defense evasion
        behaviorIndicators.put("defense_evasion", new String[]{
            "NtSetInformationThread", "NtQueryInformationProcess", "GetProcAddress",
            "LoadLibrary", "VirtualProtect"
        });
        
        // Lateral movement
        behaviorIndicators.put("lateral_movement", new String[]{
            "WNetAddConnection", "NetShareEnum", "WNetEnumResource"
        });
        
        // Data exfiltration
        behaviorIndicators.put("data_exfiltration", new String[]{
            "InternetOpen", "HttpSendRequest", "FtpPutFile", "send", "WSASend"
        });
        
        // Cryptographic operations
        behaviorIndicators.put("crypto_operations", new String[]{
            "CryptAcquireContext", "CryptGenKey", "CryptEncrypt", "CryptDecrypt",
            "CryptImportKey", "CryptDeriveKey"
        });
        
        // Process manipulation
        behaviorIndicators.put("process_manipulation", new String[]{
            "TerminateProcess", "SuspendThread", "ResumeThread", "NtSuspendProcess"
        });
        
        // Check each function for behavior indicators
        for (Function func : functionManager.getFunctions(true)) {
            if (func.isThunk()) continue;
            
            Set<String> funcAPIs = new HashSet<>();
            InstructionIterator instrIter = listing.getInstructions(func.getBody(), true);
            
            while (instrIter.hasNext()) {
                Instruction instr = instrIter.next();
                if (instr.getFlowType().isCall()) {
                    for (Reference ref : refManager.getReferencesFrom(instr.getAddress())) {
                        if (ref.getReferenceType().isCall()) {
                            Symbol sym = symbolTable.getPrimarySymbol(ref.getToAddress());
                            if (sym != null) {
                                funcAPIs.add(sym.getName());
                            }
                        }
                    }
                }
            }
            
            // Check against behavior indicators
            for (Map.Entry<String, String[]> entry : behaviorIndicators.entrySet()) {
                String behaviorType = entry.getKey();
                String[] indicators = entry.getValue();
                
                List<String> matchedIndicators = new ArrayList<>();
                for (String indicator : indicators) {
                    for (String api : funcAPIs) {
                        if (api.toLowerCase().contains(indicator.toLowerCase())) {
                            matchedIndicators.add(api);
                        }
                    }
                }
                
                if (matchedIndicators.size() >= 2) {
                    Map<String, Object> behavior = new LinkedHashMap<>();
                    behavior.put("behavior_type", behaviorType);
                    behavior.put("function", func.getName());
                    behavior.put("address", func.getEntryPoint().toString());
                    behavior.put("indicators", matchedIndicators);
                    behavior.put("indicator_count", matchedIndicators.size());
                    behavior.put("severity", getBehaviorSeverity(behaviorType));
                    behaviors.add(behavior);
                }
            }
        }
        
        // Sort by severity and indicator count
        behaviors.sort((a, b) -> {
            int sevCompare = getSeverityRank((String)a.get("severity")) - getSeverityRank((String)b.get("severity"));
            if (sevCompare != 0) return sevCompare;
            return (Integer)b.get("indicator_count") - (Integer)a.get("indicator_count");
        });
        
        // Summary by behavior type
        Map<String, Integer> behaviorCounts = new LinkedHashMap<>();
        for (Map<String, Object> behavior : behaviors) {
            String type = (String) behavior.get("behavior_type");
            behaviorCounts.put(type, behaviorCounts.getOrDefault(type, 0) + 1);
        }

        List<Object> behaviorList = new ArrayList<>(behaviors.subList(0, Math.min(behaviors.size(), 100)));
        if (behaviors.size() > 100) {
            Map<String, Object> note = new LinkedHashMap<>();
            note.put("note", (behaviors.size() - 100) + " additional behaviors truncated");
            behaviorList.add(note);
        }

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("total_behaviors_detected", behaviors.size());
        response.put("by_behavior_type", behaviorCounts);
        response.put("behaviors", behaviorList);
        return new Response.Ok(response);
    }
    
    /**
     * Helper to get severity for behavior type
     */
    private String getBehaviorSeverity(String behaviorType) {
        switch (behaviorType) {
            case "code_injection":
            case "privilege_escalation":
                return "critical";
            case "keylogging":
            case "lateral_movement":
            case "data_exfiltration":
                return "high";
            case "screen_capture":
            case "defense_evasion":
            case "crypto_operations":
                return "medium";
            case "process_manipulation":
                return "medium";
            default:
                return "low";
        }
    }

    /**
     * v1.5.0: Batch rename function and all its components atomically
     */
    private Response batchRenameFunctionComponents(String functionAddress, String functionName,
                                                Map<String, String> parameterRenames,
                                                Map<String, String> localRenames,
                                                String returnType) {
        Program program = getCurrentProgram();
        if (program == null) {
            return Response.err("No program loaded");
        }

        final StringBuilder result = new StringBuilder();
        result.append("{");
        final AtomicBoolean success = new AtomicBoolean(false);
        final AtomicReference<Integer> paramsRenamed = new AtomicReference<>(0);
        final AtomicReference<Integer> localsRenamed = new AtomicReference<>(0);

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Batch Rename Function Components");
                try {
                    Address addr = program.getAddressFactory().getAddress(functionAddress);
                    if (addr == null) {
                        result.append("\"error\": \"Invalid address: ").append(functionAddress).append("\"");
                        return;
                    }

                    Function func = program.getFunctionManager().getFunctionAt(addr);
                    if (func == null) {
                        result.append("\"error\": \"No function at address: ").append(functionAddress).append("\"");
                        return;
                    }

                    // Rename function
                    if (functionName != null && !functionName.isEmpty()) {
                        func.setName(functionName, SourceType.USER_DEFINED);
                    }

                    // Rename parameters
                    if (parameterRenames != null && !parameterRenames.isEmpty()) {
                        Parameter[] params = func.getParameters();
                        for (Parameter param : params) {
                            String newName = parameterRenames.get(param.getName());
                            if (newName != null && !newName.isEmpty()) {
                                param.setName(newName, SourceType.USER_DEFINED);
                                paramsRenamed.getAndSet(paramsRenamed.get() + 1);
                            }
                        }
                    }

                    // Rename local variables
                    if (localRenames != null && !localRenames.isEmpty()) {
                        Variable[] locals = func.getLocalVariables();
                        for (Variable local : locals) {
                            String newName = localRenames.get(local.getName());
                            if (newName != null && !newName.isEmpty()) {
                                local.setName(newName, SourceType.USER_DEFINED);
                                localsRenamed.getAndSet(localsRenamed.get() + 1);
                            }
                        }
                    }

                    // Set return type if provided
                    if (returnType != null && !returnType.isEmpty()) {
                        DataTypeManager dtm = program.getDataTypeManager();
                        DataType dt = dtm.getDataType(returnType);
                        if (dt != null) {
                            func.setReturnType(dt, SourceType.USER_DEFINED);
                        }
                    }

                    success.set(true);
                } catch (Exception e) {
                    result.append("\"error\": \"").append(e.getMessage().replace("\"", "\\\"")).append("\"");
                    Msg.error(this, "Error in batch rename", e);
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });

            if (success.get()) {
                result.append("\"success\": true, ");
                result.append("\"function_renamed\": ").append(functionName != null).append(", ");
                result.append("\"parameters_renamed\": ").append(paramsRenamed.get()).append(", ");
                result.append("\"locals_renamed\": ").append(localsRenamed.get());
            }
        } catch (Exception e) {
            result.append("\"error\": \"").append(e.getMessage().replace("\"", "\\\"")).append("\"");
        }

        result.append("}");
        return Response.text(result.toString());
    }

    /**
     * v1.5.0: Get valid Ghidra data type strings
     */
    private Response getValidDataTypes(String category) {
        List<String> builtinTypes = Arrays.asList(
            "void", "byte", "char", "short", "int", "long", "longlong",
            "float", "double", "pointer", "bool",
            "undefined", "undefined1", "undefined2", "undefined4", "undefined8",
            "uchar", "ushort", "uint", "ulong", "ulonglong",
            "sbyte", "sword", "sdword", "sqword",
            "word", "dword", "qword"
        );
        List<String> windowsTypes = Arrays.asList(
            "BOOL", "BOOLEAN", "BYTE", "CHAR", "DWORD", "QWORD", "WORD",
            "HANDLE", "HMODULE", "HWND", "LPVOID", "PVOID",
            "LPCSTR", "LPSTR", "LPCWSTR", "LPWSTR",
            "SIZE_T", "ULONG", "USHORT"
        );
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("builtin_types", builtinTypes);
        response.put("windows_types", windowsTypes);
        return new Response.Ok(response);
    }

    /**
     * v1.5.0: Analyze function completeness for documentation
     */
    private Response analyzeFunctionCompleteness(String functionAddress) {
        Program program = getCurrentProgram();
        if (program == null) {
            return errorJson("No program loaded");
        }

        final AtomicReference<Map<String, Object>> resultRef = new AtomicReference<>(null);
        final AtomicReference<String> errorMsg = new AtomicReference<>(null);

        try {
            SwingUtilities.invokeAndWait(() -> {
                try {
                    Address addr = program.getAddressFactory().getAddress(functionAddress);
                    if (addr == null) {
                        errorMsg.set("Invalid address: " + functionAddress);
                        return;
                    }

                    Function func = program.getFunctionManager().getFunctionAt(addr);
                    if (func == null) {
                        errorMsg.set("No function at address: " + functionAddress);
                        return;
                    }

                    // Enhanced plate comment validation
                    String plateComment = func.getComment();
                    boolean hasPlateComment = plateComment != null && !plateComment.isEmpty();
                    List<String> plateCommentIssues = new ArrayList<>();
                    if (hasPlateComment) {
                        validatePlateCommentStructure(plateComment, plateCommentIssues);
                    }

                    // Check for undefined variables (both names and types)
                    // PRIORITY 1 FIX: Use decompilation-based variable detection to avoid phantom variables
                    List<String> undefinedVars = new ArrayList<>();
                    boolean decompilationAvailable = false;

                    // Try to use decompilation-based detection (high-level API)
                    DecompileResults decompResults = decompileFunction(func, program);
                    if (decompResults != null && decompResults.decompileCompleted()) {
                        decompilationAvailable = true;
                        ghidra.program.model.pcode.HighFunction highFunction = decompResults.getHighFunction();

                        if (highFunction != null) {
                            // Check parameters (same as before, from Function API)
                            for (Parameter param : func.getParameters()) {
                                // Check for generic parameter names
                                if (param.getName().startsWith("param_")) {
                                    undefinedVars.add(param.getName() + " (generic name)");
                                }
                                // Check for undefined data types
                                String typeName = param.getDataType().getName();
                                if (typeName.startsWith("undefined")) {
                                    undefinedVars.add(param.getName() + " (type: " + typeName + ")");
                                }
                            }

                            // Check locals from HIGH-LEVEL decompiled symbol map (not low-level stack frame)
                            // This avoids phantom variables that exist in stack analysis but not decompilation
                            Iterator<ghidra.program.model.pcode.HighSymbol> symbols = highFunction.getLocalSymbolMap().getSymbols();
                            while (symbols.hasNext()) {
                                ghidra.program.model.pcode.HighSymbol symbol = symbols.next();
                                String name = symbol.getName();
                                String typeName = symbol.getDataType().getName();

                                // Check for generic local names (local_XX or XVar patterns)
                                if (name.startsWith("local_") ||
                                    name.matches(".*Var\\d+") ||  // pvVar1, iVar2, etc.
                                    name.matches("(i|u|d|f|p|b)Var\\d+")) {  // specific type patterns
                                    undefinedVars.add(name + " (generic name)");
                                }

                                // Check for undefined data types
                                if (typeName.startsWith("undefined")) {
                                    undefinedVars.add(name + " (type: " + typeName + ")");
                                }
                            }
                        }
                    }

                    // Fallback to low-level API if decompilation failed (with warning in output)
                    if (!decompilationAvailable) {
                        // Check parameters
                        for (Parameter param : func.getParameters()) {
                            if (param.getName().startsWith("param_")) {
                                undefinedVars.add(param.getName() + " (generic name)");
                            }
                            String typeName = param.getDataType().getName();
                            if (typeName.startsWith("undefined")) {
                                undefinedVars.add(param.getName() + " (type: " + typeName + ")");
                            }
                        }

                        // Use low-level API with phantom variable warning
                        for (Variable local : func.getLocalVariables()) {
                            if (local.getName().startsWith("local_")) {
                                undefinedVars.add(local.getName() + " (generic name, may be phantom variable)");
                            }
                            String typeName = local.getDataType().getName();
                            if (typeName.startsWith("undefined")) {
                                undefinedVars.add(local.getName() + " (type: " + typeName + ", may be phantom variable)");
                            }
                        }
                    }

                    // Check Hungarian notation compliance
                    // PRIORITY 1 FIX: Use same decompilation-based detection for consistency
                    List<String> hungarianViolations = new ArrayList<>();
                    for (Parameter param : func.getParameters()) {
                        validateHungarianNotation(param.getName(), param.getDataType().getName(), false, hungarianViolations);
                    }

                    // Use decompilation-based locals if available, otherwise fallback to low-level API
                    if (decompilationAvailable && decompResults != null && decompResults.getHighFunction() != null) {
                        ghidra.program.model.pcode.HighFunction highFunction = decompResults.getHighFunction();
                        Iterator<ghidra.program.model.pcode.HighSymbol> symbols = highFunction.getLocalSymbolMap().getSymbols();
                        while (symbols.hasNext()) {
                            ghidra.program.model.pcode.HighSymbol symbol = symbols.next();
                            validateHungarianNotation(symbol.getName(), symbol.getDataType().getName(), false, hungarianViolations);
                        }
                    } else {
                        // Fallback to low-level API
                        for (Variable local : func.getLocalVariables()) {
                            validateHungarianNotation(local.getName(), local.getDataType().getName(), false, hungarianViolations);
                        }
                    }

                    // Enhanced validation: Check parameter type quality
                    List<String> typeQualityIssues = new ArrayList<>();
                    validateParameterTypeQuality(func, typeQualityIssues);

                    // NEW: Check for unrenamed DAT_* globals and undocumented Ordinal calls in decompiled code
                    List<String> unrenamedGlobals = new ArrayList<>();
                    List<String> undocumentedOrdinals = new ArrayList<>();
                    int inlineCommentCount = 0;
                    int codeLineCount = 0;

                    if (decompilationAvailable && decompResults != null) {
                        String decompiledCode = decompResults.getDecompiledFunction().getC();
                        if (decompiledCode != null) {
                            // Count lines of code and inline comments
                            // We need to distinguish between:
                            // 1. Plate comments (before function body) - don't count
                            // 2. Body comments (inside function braces) - count these
                            String[] lines = decompiledCode.split("\n");
                            boolean inFunctionBody = false;
                            boolean inPlateComment = false;
                            int braceDepth = 0;

                            for (String line : lines) {
                                String trimmed = line.trim();

                                // Track plate comment block (before function signature)
                                if (!inFunctionBody && trimmed.startsWith("/*")) {
                                    inPlateComment = true;
                                }
                                if (inPlateComment && trimmed.endsWith("*/")) {
                                    inPlateComment = false;
                                    continue;
                                }
                                if (inPlateComment) continue;

                                // Track function body by counting braces
                                for (char c : trimmed.toCharArray()) {
                                    if (c == '{') {
                                        braceDepth++;
                                        inFunctionBody = true;
                                    } else if (c == '}') {
                                        braceDepth--;
                                    }
                                }

                                // Count code lines (non-empty, non-comment lines inside function)
                                if (inFunctionBody && !trimmed.isEmpty() &&
                                    !trimmed.startsWith("/*") && !trimmed.startsWith("*") && !trimmed.startsWith("//")) {
                                    codeLineCount++;
                                }

                                // Count comments inside function body
                                // This includes both standalone comment lines and trailing comments
                                if (inFunctionBody && trimmed.contains("/*")) {
                                    // Exclude WARNING comments from decompiler (they're not user-added)
                                    if (!trimmed.contains("WARNING:")) {
                                        inlineCommentCount++;
                                    }
                                }
                                // Also count // style comments
                                if (inFunctionBody && trimmed.contains("//")) {
                                    inlineCommentCount++;
                                }
                            }

                            // Find DAT_* references (unrenamed globals)
                            java.util.regex.Pattern datPattern = java.util.regex.Pattern.compile("DAT_[0-9a-fA-F]+");
                            java.util.regex.Matcher datMatcher = datPattern.matcher(decompiledCode);
                            java.util.Set<String> foundDats = new java.util.HashSet<>();
                            while (datMatcher.find()) {
                                foundDats.add(datMatcher.group());
                            }
                            unrenamedGlobals.addAll(foundDats);

                            // Find Ordinal_XXXXX calls without nearby comments
                            java.util.regex.Pattern ordinalPattern = java.util.regex.Pattern.compile("Ordinal_\\d+");
                            java.util.regex.Matcher ordinalMatcher = ordinalPattern.matcher(decompiledCode);
                            java.util.Set<String> foundOrdinals = new java.util.HashSet<>();
                            while (ordinalMatcher.find()) {
                                String ordinal = ordinalMatcher.group();
                                // Check if there's a comment on the same line or nearby
                                int pos = ordinalMatcher.start();
                                int lineStart = decompiledCode.lastIndexOf('\n', pos);
                                int lineEnd = decompiledCode.indexOf('\n', pos);
                                if (lineEnd == -1) lineEnd = decompiledCode.length();
                                String line = decompiledCode.substring(lineStart + 1, lineEnd);
                                // If no comment on the line containing the ordinal, flag it
                                if (!line.contains("/*") && !line.contains("//")) {
                                    foundOrdinals.add(ordinal);
                                }
                            }
                            undocumentedOrdinals.addAll(foundOrdinals);
                        }
                    }

                    // Calculate comment density (comments per 10 lines of code)
                    double commentDensity = codeLineCount > 0 ? (inlineCommentCount * 10.0 / codeLineCount) : 0;

                    double completenessScore = calculateCompletenessScore(func, undefinedVars.size(), plateCommentIssues.size(), hungarianViolations.size(), typeQualityIssues.size(), unrenamedGlobals.size(), undocumentedOrdinals.size(), commentDensity);

                    // Generate workflow-aligned recommendations
                    List<String> recommendations = generateWorkflowRecommendations(
                        func, undefinedVars, plateCommentIssues, hungarianViolations, typeQualityIssues,
                        unrenamedGlobals, undocumentedOrdinals, commentDensity, completenessScore
                    );

                    Map<String, Object> r = new LinkedHashMap<>();
                    r.put("function_name", func.getName());
                    r.put("has_custom_name", !func.getName().startsWith("FUN_"));
                    r.put("has_prototype", func.getSignature() != null);
                    r.put("has_calling_convention", func.getCallingConvention() != null);
                    r.put("has_plate_comment", hasPlateComment);
                    r.put("plate_comment_issues", plateCommentIssues);
                    r.put("decompilation_available", decompilationAvailable);
                    r.put("undefined_variables", undefinedVars);
                    r.put("hungarian_notation_violations", hungarianViolations);
                    r.put("type_quality_issues", typeQualityIssues);
                    r.put("unrenamed_globals", unrenamedGlobals);
                    r.put("undocumented_ordinals", undocumentedOrdinals);
                    r.put("inline_comment_count", inlineCommentCount);
                    r.put("code_line_count", codeLineCount);
                    r.put("comment_density", Double.parseDouble(String.format("%.2f", commentDensity)));
                    r.put("completeness_score", completenessScore);
                    r.put("recommendations", recommendations);
                    resultRef.set(r);
                } catch (Exception e) {
                    errorMsg.set(e.getMessage());
                }
            });

            if (errorMsg.get() != null) {
                return errorJson(errorMsg.get());
            }
        } catch (Exception e) {
            return errorJson(e.getMessage());
        }

        return Response.ok(resultRef.get());
    }

    /**
     * Validate Hungarian notation compliance for variables
     */
    private void validateHungarianNotation(String varName, String typeName, boolean isGlobal, List<String> violations) {
        // Skip generic/default names - they're already caught by undefined variable check
        if (varName.startsWith("param_") || varName.startsWith("local_") ||
            varName.startsWith("iVar") || varName.startsWith("uVar") ||
            varName.startsWith("dVar") || varName.startsWith("fVar") ||
            varName.startsWith("in_") || varName.startsWith("extraout_")) {
            return;
        }

        // Skip undefined types - they're already caught by undefined type check
        if (typeName.startsWith("undefined")) {
            return;
        }

        // Normalize type name (remove array brackets, pointer stars, etc.)
        String baseTypeName = typeName.replaceAll("\\[.*\\]", "").replaceAll("\\s*\\*", "").trim();

        // Get expected prefix for this type
        String expectedPrefix = getExpectedHungarianPrefix(baseTypeName, typeName.contains("*"), typeName.contains("["));

        if (expectedPrefix == null) {
            // Unknown type or structure type - skip validation
            return;
        }

        // For global variables, expect g_ prefix before type prefix
        String fullExpectedPrefix = isGlobal ? "g_" + expectedPrefix : expectedPrefix;

        // Check if variable name starts with expected prefix
        boolean hasCorrectPrefix = false;

        // For types with multiple valid prefixes (e.g., byte can be 'b' or 'by')
        if (expectedPrefix.contains("|")) {
            String[] validPrefixes = expectedPrefix.split("\\|");
            for (String prefix : validPrefixes) {
                String fullPrefix = isGlobal ? "g_" + prefix : prefix;
                if (varName.startsWith(fullPrefix)) {
                    hasCorrectPrefix = true;
                    break;
                }
            }
        } else {
            hasCorrectPrefix = varName.startsWith(fullExpectedPrefix);
        }

        if (!hasCorrectPrefix) {
            violations.add(varName + " (type: " + typeName + ", expected prefix: " + fullExpectedPrefix + ")");
        }
    }

    /**
     * Get expected Hungarian notation prefix for a given type
     */
    private String getExpectedHungarianPrefix(String typeName, boolean isPointer, boolean isArray) {
        // Handle arrays
        if (isArray) {
            if (typeName.equals("byte")) return "ab";
            if (typeName.equals("ushort")) return "aw";
            if (typeName.equals("uint")) return "ad";
            if (typeName.equals("char")) return "sz";
            return null; // Unknown array type
        }

        // Handle pointers
        if (isPointer) {
            if (typeName.equals("void")) return "p";
            if (typeName.equals("char")) return "sz|lpsz";
            if (typeName.equals("wchar_t")) return "wsz";
            return "p"; // Typed pointers generally use 'p' prefix
        }

        // Handle basic types
        switch (typeName) {
            case "byte": return "b|by";
            case "char": return "c|ch";
            case "bool": return "f";
            case "short": return "n|s";
            case "ushort": return "w";
            case "int": return "n|i";
            case "uint": return "dw";
            case "long": return "l";
            case "ulong": return "dw";
            case "longlong": return "ll";
            case "ulonglong": return "qw";
            case "float": return "fl";
            case "double": return "d";
            case "float10": return "ld";
            case "HANDLE": return "h";
            default:
                // Unknown type (might be structure or custom type)
                return null;
        }
    }

    /**
     * Validate parameter type quality (enhanced completeness check)
     * Checks for: generic void*, state-based type names, missing structures, type duplication
     */
    private void validateParameterTypeQuality(Function func, List<String> issues) {
        Program program = func.getProgram();
        DataTypeManager dtm = program.getDataTypeManager();

        // State-based type name prefixes to flag
        String[] statePrefixes = {"Initialized", "Allocated", "Created", "Updated",
                                  "Processed", "Deleted", "Modified", "Constructed",
                                  "Freed", "Destroyed", "Copied", "Cloned"};

        for (Parameter param : func.getParameters()) {
            DataType paramType = param.getDataType();
            String typeName = paramType.getName();

            // Check 1: Generic void* pointers (should use specific types)
            if (paramType instanceof Pointer) {
                Pointer ptrType = (Pointer) paramType;
                DataType pointedTo = ptrType.getDataType();
                if (pointedTo != null && pointedTo.getName().equals("void")) {
                    issues.add("Generic void* parameter: " + param.getName() +
                              " (should use specific structure type)");
                }
            }

            // Check 2: State-based type names (bad practice)
            for (String prefix : statePrefixes) {
                if (typeName.startsWith(prefix)) {
                    issues.add("State-based type name: " + typeName +
                              " on parameter " + param.getName() +
                              " (should use identity-based name)");
                    break;
                }
            }

            // Check 3: Check for similar type names (potential duplicates)
            if (paramType instanceof Pointer) {
                String baseType = typeName.replace(" *", "").trim();
                // Check for types with similar base names
                for (String prefix : statePrefixes) {
                    if (baseType.startsWith(prefix)) {
                        String identityName = baseType.substring(prefix.length());
                        // Check if identity-based version exists
                        DataType identityType = dtm.getDataType("/" + identityName);
                        if (identityType != null) {
                            issues.add("Type duplication: " + baseType + " and " + identityName +
                                      " exist (consider consolidating to " + identityName + ")");
                        }
                    }
                }
            }
        }
    }

    /**
     * Validate plate comment structure and content quality
     */
    private void validatePlateCommentStructure(String plateComment, List<String> issues) {
        if (plateComment == null || plateComment.isEmpty()) {
            issues.add("Plate comment is empty");
            return;
        }

        // Check minimum line count
        String[] lines = plateComment.split("\n");
        if (lines.length < 10) {
            issues.add("Plate comment has only " + lines.length + " lines (minimum 10 required)");
        }

        // Check for required sections based on PLATE_COMMENT_FORMAT_GUIDE.md
        boolean hasAlgorithm = false;
        boolean hasParameters = false;
        boolean hasReturns = false;
        boolean hasNumberedSteps = false;

        for (String line : lines) {
            String trimmed = line.trim();

            // Check for Algorithm section with numbered steps
            if (trimmed.startsWith("Algorithm:") || trimmed.equals("Algorithm")) {
                hasAlgorithm = true;
            }

            // Check for numbered steps (1., 2., etc.)
            if (trimmed.matches("^\\d+\\.\\s+.*")) {
                hasNumberedSteps = true;
            }

            // Check for Parameters section
            if (trimmed.startsWith("Parameters:") || trimmed.equals("Parameters")) {
                hasParameters = true;
            }

            // Check for Returns section
            if (trimmed.startsWith("Returns:") || trimmed.equals("Returns")) {
                hasReturns = true;
            }
        }

        // Add issues for missing required sections
        if (!hasAlgorithm) {
            issues.add("Missing Algorithm section");
        }

        if (hasAlgorithm && !hasNumberedSteps) {
            issues.add("Algorithm section exists but has no numbered steps");
        }

        if (!hasParameters) {
            issues.add("Missing Parameters section");
        }

        if (!hasReturns) {
            issues.add("Missing Returns section");
        }
    }

    private double calculateCompletenessScore(Function func, int undefinedCount, int plateCommentIssueCount, int hungarianViolationCount, int typeQualityIssueCount, int unrenamedGlobalsCount, int undocumentedOrdinalsCount, double commentDensity) {
        double score = 100.0;

        if (func.getName().startsWith("FUN_")) score -= 30;
        if (func.getSignature() == null) score -= 20;
        if (func.getCallingConvention() == null) score -= 10;
        if (func.getComment() == null) score -= 20;
        score -= (undefinedCount * 5);
        score -= (plateCommentIssueCount * 5); // 5 points per plate comment issue
        score -= (hungarianViolationCount * 3); // 3 points per Hungarian notation violation
        score -= (typeQualityIssueCount * 15); // 15 points per type quality issue (void*, state-based names, duplicates) - HARD PENALTY to enforce identity-based naming
        
        // NEW: Penalties for unrenamed globals and undocumented ordinals
        score -= (unrenamedGlobalsCount * 3); // 3 points per DAT_* global remaining
        score -= (undocumentedOrdinalsCount * 2); // 2 points per undocumented Ordinal call
        
        // NEW: Penalty for low inline comment density (expect at least 1 comment per 10 lines)
        if (commentDensity < 1.0 && func.getComment() != null) {
            // Only penalize if function has a plate comment (meaning it's been partially documented)
            score -= 5; // Penalty for sparse inline comments
        }

        return Math.max(0, score);
    }

    /**
     * Generate workflow-aligned recommendations based on FUNCTION_DOC_WORKFLOW_V4.md
     */
    private List<String> generateWorkflowRecommendations(
            Function func,
            List<String> undefinedVars,
            List<String> plateCommentIssues,
            List<String> hungarianViolations,
            List<String> typeQualityIssues,
            List<String> unrenamedGlobals,
            List<String> undocumentedOrdinals,
            double commentDensity,
            double completenessScore) {

        List<String> recommendations = new ArrayList<>();

        // If 100% complete, return early
        if (completenessScore >= 100.0) {
            recommendations.add("Function is fully documented - no further action needed.");
            return recommendations;
        }

        // CRITICAL: Unnamed DAT_* Globals (highest priority)
        if (!unrenamedGlobals.isEmpty()) {
            recommendations.add("UNRENAMED DAT_* GLOBALS DETECTED - Must rename before documentation is complete:");
            recommendations.add("1. Found " + unrenamedGlobals.size() + " DAT_* reference(s): " + String.join(", ", unrenamedGlobals.subList(0, Math.min(5, unrenamedGlobals.size()))));
            recommendations.add("2. Use rename_or_label() or rename_data() to give meaningful names to each global");
            recommendations.add("3. Apply Hungarian notation with g_ prefix: g_dwPlayerCount, g_pCurrentGame, g_abEncryptionKey");
            recommendations.add("4. If global is a structure, apply type with apply_data_type() first, then rename");
            recommendations.add("5. Consult KNOWN_ORDINALS.md and existing codebase for naming conventions");
        }

        // CRITICAL: Undocumented Ordinal Calls
        if (!undocumentedOrdinals.isEmpty()) {
            recommendations.add("UNDOCUMENTED ORDINAL CALLS - Add inline comments for each:");
            recommendations.add("1. Found " + undocumentedOrdinals.size() + " Ordinal call(s) without comments: " + String.join(", ", undocumentedOrdinals.subList(0, Math.min(5, undocumentedOrdinals.size()))));
            recommendations.add("2. Consult docs/KNOWN_ORDINALS.md for Ordinal mappings (Storm.dll, Fog.dll ordinals documented)");
            recommendations.add("3. Use set_decompiler_comment() or batch_set_comments() to add inline comment explaining the call");
            recommendations.add("4. Format: /* Ordinal_123 = StorageFunctionName - brief description */");
        }

        // CRITICAL: Undefined Type Audit (FUNCTION_DOC_WORKFLOW_V4.md Phase 2: Type Audit)
        if (!undefinedVars.isEmpty()) {
            recommendations.add("UNDEFINED TYPES DETECTED - Follow FUNCTION_DOC_WORKFLOW_V4.md Phase 2 'Type Audit' section:");
            recommendations.add("1. Type Resolution: Apply type normalization before renaming:");
            recommendations.add("   - undefined1 -> byte (8-bit integer)");
            recommendations.add("   - undefined2 -> ushort/short (16-bit integer)");
            recommendations.add("   - undefined4 -> uint/int/float/pointer (32-bit - check usage context)");
            recommendations.add("   - undefined8 -> double/ulonglong/longlong (64-bit)");
            recommendations.add("   - undefined1[N] -> byte[N] (byte array for XMM spills, buffers)");
            recommendations.add("2. Use set_local_variable_type() with lowercase builtin types (uint, ushort, byte) NOT uppercase Windows types (UINT, USHORT, BYTE)");
            recommendations.add("3. CRITICAL: Check disassembly with get_disassembly() for assembly-only undefined types:");
            recommendations.add("   - Stack temporaries: [EBP + local_offset] not in get_function_variables()");
            recommendations.add("   - XMM register spills: undefined1[16] at stack locations");
            recommendations.add("   - Intermediate calculation results not appearing in decompiled view");
            recommendations.add("4. After resolving ALL undefined types, rename variables with Hungarian notation using rename_variables()");
        }

        // Plate Comment Issues
        if (!plateCommentIssues.isEmpty()) {
            recommendations.add("PLATE COMMENT ISSUES - Follow FUNCTION_DOC_WORKFLOW_V4.md Phase 7 'Documentation' section:");
            for (String issue : plateCommentIssues) {
                if (issue.contains("Missing Algorithm section")) {
                    recommendations.add("1. Add Algorithm section with numbered steps describing operations (validation, function calls, error handling)");
                } else if (issue.contains("no numbered steps")) {
                    recommendations.add("2. Add numbered steps in Algorithm section (1., 2., 3., etc.)");
                } else if (issue.contains("Missing Parameters section")) {
                    recommendations.add("3. Add Parameters section documenting all parameters with types and purposes (include IMPLICIT keyword for undocumented register params)");
                } else if (issue.contains("Missing Returns section")) {
                    recommendations.add("4. Add Returns section explaining return values, success codes, error conditions, NULL/zero cases");
                } else if (issue.contains("lines (minimum 10 required)")) {
                    recommendations.add("5. Expand plate comment to minimum 10 lines with comprehensive documentation");
                }
            }
            recommendations.add("Use set_plate_comment() to create/update plate comment following docs/prompts/PLATE_COMMENT_FORMAT_GUIDE.md");
        }

        // Hungarian Notation Violations
        if (!hungarianViolations.isEmpty()) {
            recommendations.add("HUNGARIAN NOTATION VIOLATIONS - Follow FUNCTION_DOC_WORKFLOW_V4.md Phase 5 'Variables' and docs/HUNGARIAN_NOTATION.md:");
            recommendations.add("1. Verify type-to-prefix mapping matches Ghidra type:");
            recommendations.add("   - byte -> b/by | char -> c/ch | bool -> f | short -> n/s | ushort -> w");
            recommendations.add("   - int -> n/i | uint -> dw | long -> l | ulong -> dw");
            recommendations.add("   - longlong -> ll | ulonglong -> qw | float -> fl | double -> d");
            recommendations.add("   - void* -> p | typed pointers -> p+StructName (pUnitAny)");
            recommendations.add("   - byte[N] -> ab | ushort[N] -> aw | uint[N] -> ad");
            recommendations.add("   - char* -> sz/lpsz | wchar_t* -> wsz");
            recommendations.add("2. First set correct type with set_local_variable_type() using lowercase builtin");
            recommendations.add("3. Then rename with rename_variables() using correct Hungarian prefix");
            recommendations.add("4. For globals, add g_ prefix before type prefix: g_dwProcessId, g_abEncryptionKey");
        }

        // Type Quality Issues
        if (!typeQualityIssues.isEmpty()) {
            recommendations.add("TYPE QUALITY ISSUES - Follow FUNCTION_DOC_WORKFLOW_V4.md Phase 3 'Structures' section:");
            for (String issue : typeQualityIssues) {
                if (issue.contains("Generic void*")) {
                    recommendations.add("1. Replace generic void* parameters with specific structure types using set_function_prototype()");
                    recommendations.add("   Example: void ProcessData(void* pData) -> void ProcessData(UnitAny* pUnit)");
                } else if (issue.contains("State-based type name")) {
                    recommendations.add("2. Rename state-based type names to identity-based names:");
                    recommendations.add("   BAD: InitializedGameObject, AllocatedBuffer, ProcessedData");
                    recommendations.add("   GOOD: GameObject, Buffer, DataRecord");
                    recommendations.add("   Use create_struct() with identity-based name, document legacy name in comments");
                } else if (issue.contains("Type duplication")) {
                    recommendations.add("3. Consolidate duplicate types - use identity-based version, delete state-based variant");
                }
            }
        }

        // Inline Comment Density Check
        if (commentDensity < 0.67) { // Less than 1 comment per 15 lines
            recommendations.add("LOW INLINE COMMENT DENSITY - Add more explanatory comments:");
            recommendations.add("1. Current density: " + String.format("%.2f", commentDensity) + " comments per 10 lines (target: 0.67+)");
            recommendations.add("2. Add inline comments for:");
            recommendations.add("   - Complex calculations or magic numbers");
            recommendations.add("   - Non-obvious conditional branches");
            recommendations.add("   - Ordinal/DLL calls explaining their purpose");
            recommendations.add("   - Structure field accesses explaining data meaning");
            recommendations.add("   - Error handling paths explaining expected failures");
            recommendations.add("3. Use set_decompiler_comment() for individual comments or batch_set_comments() for multiple");
        }

        // General Workflow Guidance
        if (completenessScore < 100.0) {
            recommendations.add("COMPLETE WORKFLOW (FUNCTION_DOC_WORKFLOW_V4.md):");
            recommendations.add("1. Initialization: Use analyze_function_complete() to gather decompiled code, xrefs, callees, callers, disassembly, variables");
            recommendations.add("2. Undefined Type Audit: Check BOTH decompiled code AND disassembly (get_disassembly()) for all undefined types");
            recommendations.add("3. Structure Identification: Create structures BEFORE renaming (create_struct, apply_data_type)");
            recommendations.add("4. Function Naming: Use rename_function_by_address() with PascalCase");
            recommendations.add("5. Prototype: Use set_function_prototype() with specific typed parameters");
            recommendations.add("6. Labels: Use batch_create_labels() for jump targets (snake_case)");
            recommendations.add("7. Variable Types: Use set_local_variable_type() with lowercase builtins");
            recommendations.add("8. Variable Renaming: Use rename_variables() with Hungarian notation");
            recommendations.add("9. Plate Comment: Use set_plate_comment() with Algorithm, Parameters, Returns sections");
            recommendations.add("10. Inline Comments: Use batch_set_comments() for decompiler and disassembly comments");
            recommendations.add("11. Verification: Re-run analyze_function_completeness() to confirm 100% score");
        }

        return recommendations;
    }



    /**
     * OPTIMIZED: Batch set variable types - simple wrapper that calls setLocalVariableType
     * sequentially with proper spacing to avoid thread issues
     */
    private Response batchSetVariableTypesOptimized(String functionAddress, Map<String, String> variableTypes) {
        if (variableTypes == null || variableTypes.isEmpty()) {
            JsonObject _jo56 = new JsonObject();
            _jo56.addProperty("success", true);
            _jo56.addProperty("method", "optimized");
            _jo56.addProperty("variables_typed", 0);
            _jo56.addProperty("variables_failed", 0);
            return new Response.Ok(_jo56);
        }

        final AtomicInteger variablesTyped = new AtomicInteger(0);
        final AtomicInteger variablesFailed = new AtomicInteger(0);
        final List<String> errors = new ArrayList<>();

        for (Map.Entry<String, String> entry : variableTypes.entrySet()) {
            String varName = entry.getKey();
            String newType = entry.getValue();

            try {
                Response resp = setLocalVariableType(functionAddress, varName, newType);
                String result = resp instanceof Response.Text t ? t.content()
                              : resp instanceof Response.Err e ? e.message()
                              : resp.toString();

                if (result.toLowerCase().contains("success")) {
                    variablesTyped.incrementAndGet();
                } else {
                    errors.add(varName + ": " + result);
                    variablesFailed.incrementAndGet();
                }

                // Small delay to allow Ghidra to process
                try {
                    Thread.sleep(50);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                }
            } catch (Exception e) {
                errors.add(varName + ": " + e.getMessage());
                variablesFailed.incrementAndGet();
            }
        }

        int typed = variablesTyped.get();
        int failed = variablesFailed.get();
        List<String> errorsCopy = new ArrayList<>(errors);
        JsonObject _jo57 = new JsonObject();
        _jo57.addProperty("success", failed == 0 && typed > 0);
        _jo57.addProperty("method", "optimized");
        _jo57.addProperty("variables_typed", typed);
        _jo57.addProperty("variables_failed", failed);
        _jo57.add("errors", JsonHelper.gson().toJsonTree(errorsCopy.isEmpty() ? null : errorsCopy));
        return new Response.Ok(_jo57);
    }


    /**
     * NEW v1.6.0: Validate function prototype before applying
     */
    private Response validateFunctionPrototype(String functionAddress, String prototype, String callingConvention) {
        Program program = getCurrentProgram();
        if (program == null) {
            return errorJson("No program loaded");
        }

        final AtomicReference<String> validationError = new AtomicReference<>(null);
        final AtomicReference<List<String>> warningsRef = new AtomicReference<>(null);
        final AtomicReference<String> exceptionMsg = new AtomicReference<>(null);

        try {
            SwingUtilities.invokeAndWait(() -> {
                try {
                    Address addr = program.getAddressFactory().getAddress(functionAddress);
                    if (addr == null) {
                        validationError.set("Invalid address: " + functionAddress);
                        return;
                    }

                    Function func = program.getFunctionManager().getFunctionAt(addr);
                    if (func == null) {
                        validationError.set("No function at address: " + functionAddress);
                        return;
                    }

                    if (prototype == null || prototype.trim().isEmpty()) {
                        validationError.set("Empty prototype");
                        return;
                    }

                    if (!prototype.contains("(")) {
                        validationError.set("Invalid prototype format - missing parentheses");
                        return;
                    }

                    List<String> warnings = new ArrayList<>();
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
                    if (!warnings.isEmpty()) warningsRef.set(warnings);
                } catch (Exception e) {
                    exceptionMsg.set(e.getMessage());
                }
            });

            if (exceptionMsg.get() != null) {
                JsonObject _jo58 = new JsonObject();
                _jo58.addProperty("valid", false);
                _jo58.addProperty("error", exceptionMsg.get());
                return new Response.Ok(_jo58);
            }
        } catch (Exception e) {
            JsonObject _jo59 = new JsonObject();
            _jo59.addProperty("valid", false);
            _jo59.addProperty("error", e.getMessage());
            return new Response.Ok(_jo59);
        }

        if (validationError.get() != null) {
            String err = validationError.get();
            JsonObject _jo60 = new JsonObject();
            _jo60.addProperty("valid", false);
            _jo60.addProperty("error", err);
            return new Response.Ok(_jo60);
        }

        List<String> warningList = warningsRef.get();
        JsonObject _jo61 = new JsonObject();
        _jo61.addProperty("valid", true);
        _jo61.add("warnings", JsonHelper.gson().toJsonTree(warningList));
        return new Response.Ok(_jo61);
    }

    /**
     * NEW v1.6.0: Check if data type exists in type manager
     */
    private Response validateDataTypeExists(String typeName) {
        Program program = getCurrentProgram();
        if (program == null) {
            return errorJson("No program loaded");
        }

        final AtomicReference<DataType> dtRef = new AtomicReference<>(null);
        final AtomicReference<String> exceptionMsg = new AtomicReference<>(null);

        try {
            SwingUtilities.invokeAndWait(() -> {
                try {
                    DataTypeManager dtm = program.getDataTypeManager();
                    dtRef.set(dtm.getDataType(typeName));
                } catch (Exception e) {
                    exceptionMsg.set(e.getMessage());
                }
            });

            if (exceptionMsg.get() != null) {
                return errorJson(exceptionMsg.get());
            }
        } catch (Exception e) {
            return errorJson(e.getMessage());
        }

        DataType dt = dtRef.get();
        if (dt != null) {
            String dtCategory = dt.getCategoryPath().getPath();
            int dtSize = dt.getLength();
            JsonObject _jo62 = new JsonObject();
            _jo62.addProperty("exists", true);
            _jo62.addProperty("category", dtCategory);
            _jo62.addProperty("size", dtSize);
            return new Response.Ok(_jo62);
        }
        JsonObject _jo63 = new JsonObject();
        _jo63.addProperty("exists", false);
        return new Response.Ok(_jo63);
    }



    /**
     * NEW v1.6.0: Comprehensive function analysis in single call
     */
    /**
     * NEW v1.7.1: Disassemble a range of bytes
     *
     * This endpoint allows disassembling undefined bytes at a specific address range.
     * Useful for disassembling hidden code after clearing flow overrides.
     *
     * @param startAddress Starting address in hex format (e.g., "0x6fb4ca14")
     * @param endAddress Optional ending address in hex format (exclusive)
     * @param length Optional length in bytes (alternative to endAddress)
     * @param restrictToExecuteMemory If true, restricts disassembly to executable memory (default: true)
     * @return JSON result with disassembly status
     */
    private Response disassembleBytes(String startAddress, String endAddress, Integer length,
                                   boolean restrictToExecuteMemory) {
        Program program = getCurrentProgram();
        if (program == null) {
            return Response.err("No program loaded");
        }

        if (startAddress == null || startAddress.isEmpty()) {
            return Response.err("start_address parameter required");
        }

        final AtomicReference<String> errorMsg = new AtomicReference<>();
        final AtomicReference<String> startAddrRef = new AtomicReference<>();
        final AtomicReference<String> endAddrRef = new AtomicReference<>();
        final AtomicLong bytesDisassembled = new AtomicLong();

        try {
            Msg.debug(this, "disassembleBytes: Starting disassembly at " + startAddress +
                     (length != null ? " with length " + length : "") +
                     (endAddress != null ? " to " + endAddress : ""));

            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Disassemble Bytes");
                boolean success = false;

                try {
                    Address start = program.getAddressFactory().getAddress(startAddress);
                    if (start == null) {
                        errorMsg.set("Invalid start address: " + startAddress);
                        return;
                    }

                    Address end;
                    if (endAddress != null && !endAddress.isEmpty()) {
                        end = program.getAddressFactory().getAddress(endAddress);
                        if (end == null) {
                            errorMsg.set("Invalid end address: " + endAddress);
                            return;
                        }
                        try {
                            end = end.subtract(1);
                        } catch (Exception e) {
                            errorMsg.set("End address calculation failed: " + e.getMessage());
                            return;
                        }
                    } else if (length != null && length > 0) {
                        try {
                            end = start.add(length - 1);
                        } catch (Exception e) {
                            errorMsg.set("End address calculation from length failed: " + e.getMessage());
                            return;
                        }
                    } else {
                        Listing listing = program.getListing();
                        Address current = start;
                        int maxBytes = 100;
                        int count = 0;

                        while (count < maxBytes) {
                            CodeUnit cu = listing.getCodeUnitAt(current);
                            if (cu instanceof Instruction) break;
                            if (cu instanceof Data && ((Data) cu).isDefined()) break;
                            count++;
                            try {
                                current = current.add(1);
                            } catch (Exception e) {
                                break;
                            }
                        }

                        if (count == 0) {
                            errorMsg.set("No undefined bytes found at address (already disassembled or defined data)");
                            return;
                        }

                        try {
                            end = current.subtract(1);
                        } catch (Exception e) {
                            end = current;
                        }
                    }

                    AddressSet addressSet = new AddressSet(start, end);
                    long numBytes = addressSet.getNumAddresses();

                    ghidra.app.cmd.disassemble.DisassembleCommand cmd =
                        new ghidra.app.cmd.disassemble.DisassembleCommand(addressSet, null, restrictToExecuteMemory);
                    cmd.setSeedContext(null);
                    cmd.setInitialContext(null);

                    if (cmd.applyTo(program, ghidra.util.task.TaskMonitor.DUMMY)) {
                        Msg.debug(this, "disassembleBytes: Successfully disassembled " + numBytes + " byte(s) from " + start + " to " + end);
                        startAddrRef.set(start.toString());
                        endAddrRef.set(end.toString());
                        bytesDisassembled.set(numBytes);
                        success = true;
                    } else {
                        errorMsg.set("Disassembly failed: " + cmd.getStatusMsg());
                        Msg.error(this, "disassembleBytes: Disassembly command failed - " + cmd.getStatusMsg());
                    }

                } catch (Throwable e) {
                    String msg = e.getMessage() != null ? e.getMessage() : e.toString();
                    errorMsg.set("Exception during disassembly: " + msg);
                    Msg.error(this, "disassembleBytes: Exception during disassembly", e);
                } finally {
                    program.endTransaction(tx, success);
                }
            });

            Msg.debug(this, "disassembleBytes: invokeAndWait completed");

            if (errorMsg.get() != null) {
                Msg.error(this, "disassembleBytes: Returning error response - " + errorMsg.get());
                return errorJson(errorMsg.get());
            }
        } catch (Throwable e) {
            String msg = e.getMessage() != null ? e.getMessage() : e.toString();
            Msg.error(this, "disassembleBytes: Exception in outer try block", e);
            return errorJson(msg);
        }

        String startStr = startAddrRef.get();
        String endStr = endAddrRef.get();
        long numBytes = bytesDisassembled.get();
        Msg.debug(this, "disassembleBytes: Returning success response");
        JsonObject _jo64 = new JsonObject();
        _jo64.addProperty("success", true);
        _jo64.addProperty("start_address", startStr);
        _jo64.addProperty("end_address", endStr);
        _jo64.addProperty("bytes_disassembled", numBytes);
        _jo64.addProperty("message", "Successfully disassembled " + numBytes + " byte(s)");
        return new Response.Ok(_jo64);
    }









    /**
     * Execute a Ghidra script and capture all output, errors, and warnings (v1.9.1)
     * This enables automatic troubleshooting by providing comprehensive error information.
     *
     * Note: Since Ghidra scripts are typically run through the GUI via Script Manager,
     * this endpoint provides script discovery and validation. Full execution with output
     * capture should be done through Ghidra's Script Manager UI or headless mode.
     */
    private Response runGhidraScriptWithCapture(String scriptName, String scriptArgs, int timeoutSeconds, boolean captureOutput) throws Exception {
        if (scriptName == null || scriptName.isEmpty()) {
            return Response.err("Script name is required");
        }

        Program program = getCurrentProgram();
        if (program == null) {
            return Response.err("No program loaded");
        }

        // Locate the script file — search Ghidra's standard script directories
        File scriptFile = null;
        String filename = scriptName;
        // If no extension, try .java and .py
        boolean hasExtension = scriptName.contains(".");

        String[] searchDirs = {
            System.getProperty("user.home") + "/ghidra_scripts",
            System.getProperty("user.dir") + "/ghidra_scripts",
            "./ghidra_scripts"
        };

        String[] extensions = hasExtension ? new String[]{""} : new String[]{".java", ".py", ""};

        for (String dirPath : searchDirs) {
            if (dirPath == null) continue;
            for (String ext : extensions) {
                File candidate = new File(dirPath, filename + ext);
                if (candidate.exists()) {
                    scriptFile = candidate;
                    break;
                }
            }
            if (scriptFile != null) break;
        }

        // Also try as absolute path
        if (scriptFile == null) {
            File candidate = new File(scriptName);
            if (candidate.exists()) {
                scriptFile = candidate;
            }
        }

        if (scriptFile == null) {
            StringBuilder searched = new StringBuilder();
            for (String dir : searchDirs) {
                if (dir != null) searched.append(dir).append(", ");
            }
            String searchedStr = searched.toString();
            JsonObject _jo65 = new JsonObject();
            _jo65.addProperty("success", false);
            _jo65.addProperty("error", "Script '" + filename + "' not found. Searched: " + searchedStr);
            return new Response.Ok(_jo65);
        }

        long startTime = System.currentTimeMillis();
        Response scriptResponse = runGhidraScript(scriptFile.getAbsolutePath(), scriptArgs);
        double executionTime = (System.currentTimeMillis() - startTime) / 1000.0;

        @SuppressWarnings("unchecked")
        Map<String, Object> scriptResult = scriptResponse instanceof Response.Ok ok
                ? (Map<String, Object>) ok.data() : Map.of();
        String output = scriptResult.getOrDefault("output", "").toString();
        boolean succeeded = Boolean.TRUE.equals(scriptResult.get("success"));
        String scriptPath = scriptFile.getAbsolutePath();
        String execTimeStr = String.format("%.2f", executionTime);
        JsonObject _jo66 = new JsonObject();
        _jo66.addProperty("success", succeeded);
        _jo66.addProperty("script_name", scriptName);
        _jo66.addProperty("script_path", scriptPath);
        _jo66.addProperty("execution_time_seconds", execTimeStr);
        _jo66.addProperty("console_output", output);
        return new Response.Ok(_jo66);

    }

    // ===================================================================================
    // BOOKMARK METHODS (v1.9.4) - Progress tracking via Ghidra bookmarks
    // ===================================================================================

    /**
     * Set a bookmark at an address with category and comment.
     * Creates or updates the bookmark if one already exists at the address with the same category.
     */
    private Response setBookmark(String addressStr, String category, String comment) throws Exception {
        Program program = getCurrentProgram();
        if (program == null) {
            return errorJson("No program loaded");
        }
        if (addressStr == null || addressStr.isEmpty()) {
            JsonObject _jo67 = new JsonObject();
            _jo67.addProperty("success", false);
            _jo67.addProperty("error", "Address is required");
            return new Response.Ok(_jo67);
        }
        if (category == null || category.isEmpty()) {
            category = "Note";
        }
        if (comment == null) {
            comment = "";
        }

        Address addr = program.getAddressFactory().getAddress(addressStr);
        if (addr == null) {
            JsonObject _jo68 = new JsonObject();
            _jo68.addProperty("success", false);
            _jo68.addProperty("error", "Invalid address: " + addressStr);
            return new Response.Ok(_jo68);
        }

        BookmarkManager bookmarkManager = program.getBookmarkManager();
        final String finalCategory = category;
        final String finalComment = comment;
        final String addrStr = addr.toString();

        int transactionId = program.startTransaction("Set bookmark at " + addressStr);
        try {
            Bookmark existing = bookmarkManager.getBookmark(addr, BookmarkType.NOTE, finalCategory);
            if (existing != null) {
                bookmarkManager.removeBookmark(existing);
            }
            bookmarkManager.setBookmark(addr, BookmarkType.NOTE, finalCategory, finalComment);
            program.endTransaction(transactionId, true);

            JsonObject _jo69 = new JsonObject();
            _jo69.addProperty("success", true);
            _jo69.addProperty("address", addrStr);
            _jo69.addProperty("category", finalCategory);
            _jo69.addProperty("comment", finalComment);
            return new Response.Ok(_jo69);

        } catch (Exception e) {
            program.endTransaction(transactionId, false);
            throw e;
        }

    }

    /**
     * List bookmarks, optionally filtered by category and/or address.
     */
    private Response listBookmarks(String category, String addressStr) throws Exception {
        Program program = getCurrentProgram();
        if (program == null) {
            return errorJson("No program loaded");
        }

        BookmarkManager bookmarkManager = program.getBookmarkManager();
        List<Map<String, Object>> bookmarks = new ArrayList<>();

        if (addressStr != null && !addressStr.isEmpty()) {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            if (addr == null) {
                JsonObject _jo70 = new JsonObject();
                _jo70.addProperty("success", false);
                _jo70.addProperty("error", "Invalid address: " + addressStr);
                return new Response.Ok(_jo70);
            }

            Bookmark[] bms = bookmarkManager.getBookmarks(addr);
            for (Bookmark bm : bms) {
                if (category == null || category.isEmpty() || bm.getCategory().equals(category)) {
                    Map<String, Object> bmMap = new LinkedHashMap<>();
                    bmMap.put("address", bm.getAddress().toString());
                    bmMap.put("category", bm.getCategory());
                    bmMap.put("comment", bm.getComment());
                    bmMap.put("type", bm.getTypeString());
                    bookmarks.add(bmMap);
                }
            }
        } else {
            BookmarkType[] types = bookmarkManager.getBookmarkTypes();
            for (BookmarkType type : types) {
                Iterator<Bookmark> iter = bookmarkManager.getBookmarksIterator(type.getTypeString());
                while (iter.hasNext()) {
                    Bookmark bm = iter.next();
                    if (category == null || category.isEmpty() || bm.getCategory().equals(category)) {
                        Map<String, Object> bmMap = new LinkedHashMap<>();
                        bmMap.put("address", bm.getAddress().toString());
                        bmMap.put("category", bm.getCategory());
                        bmMap.put("comment", bm.getComment());
                        bmMap.put("type", bm.getTypeString());
                        bookmarks.add(bmMap);
                    }
                }
            }
        }

        List<Map<String, Object>> bmList = bookmarks;
        int bmCount = bookmarks.size();
        JsonObject _jo71 = new JsonObject();
        _jo71.addProperty("success", true);
        _jo71.addProperty("count", bmCount);
        return new Response.Ok(_jo71);

    }

    /**
     * Delete a bookmark at an address with optional category filter.
     */
    private Response deleteBookmark(String addressStr, String category) throws Exception {
        Program program = getCurrentProgram();
        if (program == null) {
            return errorJson("No program loaded");
        }
        if (addressStr == null || addressStr.isEmpty()) {
            JsonObject _jo72 = new JsonObject();
            _jo72.addProperty("success", false);
            _jo72.addProperty("error", "Address is required");
            return new Response.Ok(_jo72);
        }

        Address addr = program.getAddressFactory().getAddress(addressStr);
        if (addr == null) {
            JsonObject _jo73 = new JsonObject();
            _jo73.addProperty("success", false);
            _jo73.addProperty("error", "Invalid address: " + addressStr);
            return new Response.Ok(_jo73);
        }

        BookmarkManager bookmarkManager = program.getBookmarkManager();

        int transactionId = program.startTransaction("Delete bookmark at " + addressStr);
        try {
            int deleted = 0;
            Bookmark[] bmarks = bookmarkManager.getBookmarks(addr);

            for (Bookmark bm : bmarks) {
                if (category == null || category.isEmpty() || bm.getCategory().equals(category)) {
                    bookmarkManager.removeBookmark(bm);
                    deleted++;
                }
            }

            program.endTransaction(transactionId, true);
            String addrStr = addr.toString();
            int deletedCount = deleted;
            JsonObject _jo74 = new JsonObject();
            _jo74.addProperty("success", true);
            _jo74.addProperty("deleted", deletedCount);
            _jo74.addProperty("address", addrStr);
            return new Response.Ok(_jo74);

        } catch (Exception e) {
            program.endTransaction(transactionId, false);
            throw e;
        }

    }



    /**
     * List all external locations (imports, ordinal imports, etc.)
     * Returns detailed information including library name and label
     */
    private Response listExternalLocations(int offset, int limit, String programName) {
        Object[] programResult = getProgramOrError(programName);
        Program program = (Program) programResult[0];
        if (program == null) return (Response) programResult[1];

        ExternalManager extMgr = program.getExternalManager();
        List<String> lines = new ArrayList<>();

        try {
            String[] extLibNames = extMgr.getExternalLibraryNames();
            for (String libName : extLibNames) {
                ExternalLocationIterator iter = extMgr.getExternalLocations(libName);
                while (iter.hasNext()) {
                    ExternalLocation extLoc = iter.next();
                    String locName = extLoc.getLabel();
                    String address = extLoc.getAddress().toString().replace(":", "");
                    String info = String.format("%s (%s) - %s @ %s",
                        locName, libName, extLoc.getLabel(), address);
                    lines.add(info);
                }
            }
        } catch (Exception e) {
            Msg.error(this, "Error listing external locations: " + e.getMessage());
            return errorJson(e.getMessage());
        }

        return Response.text(paginateList(lines, offset, limit));
    }
    

    /**
     * Get details of a specific external location
     */
    private Response getExternalLocationDetails(String address, String dllName, String programName) throws Exception {
        Object[] programResult = getProgramOrError(programName);
        Program program = (Program) programResult[0];
        if (program == null) return (Response) programResult[1];

        Address addr = program.getAddressFactory().getAddress(address);
        ExternalManager extMgr = program.getExternalManager();

        String foundLabel = null;
        String foundDll = null;

        if (dllName != null && !dllName.isEmpty()) {
            ExternalLocationIterator iter = extMgr.getExternalLocations(dllName);
            while (iter.hasNext()) {
                ExternalLocation extLoc = iter.next();
                if (extLoc.getAddress().equals(addr)) {
                    foundLabel = extLoc.getLabel();
                    foundDll = dllName;
                    break;
                }
            }
        } else {
            String[] libNames = extMgr.getExternalLibraryNames();
            outer:
            for (String libName : libNames) {
                ExternalLocationIterator iter = extMgr.getExternalLocations(libName);
                while (iter.hasNext()) {
                    ExternalLocation extLoc = iter.next();
                    if (extLoc.getAddress().equals(addr)) {
                        foundLabel = extLoc.getLabel();
                        foundDll = libName;
                        break outer;
                    }
                }
            }
        }

        if (foundLabel == null) {
            String errAddr = address;
            String errMsg = dllName != null && !dllName.isEmpty()
                ? "External location not found in DLL"
                : "External location not found at address " + errAddr;
            JsonObject _jo75 = new JsonObject();
            _jo75.addProperty("address", errAddr);
            _jo75.addProperty("error", errMsg);
            return new Response.Ok(_jo75);
        }

        String resultLabel = foundLabel;
        String resultDll = foundDll;
        String resultAddr = address;
        JsonObject _jo76 = new JsonObject();
        _jo76.addProperty("address", resultAddr);
        _jo76.addProperty("dll_name", resultDll);
        _jo76.addProperty("label", resultLabel);
        return new Response.Ok(_jo76);
    }
    

    /**
     * Rename an external location (e.g., change Ordinal_123 to a real function name)
     */
    private Response renameExternalLocation(String address, String newName) {
        Program program = getCurrentProgram();
        if (program == null) return errorJson("No program loaded");

        try {
            Address addr = program.getAddressFactory().getAddress(address);
            ExternalManager extMgr = program.getExternalManager();

            String[] libNames = extMgr.getExternalLibraryNames();
            for (String libName : libNames) {
                ExternalLocationIterator iter = extMgr.getExternalLocations(libName);
                while (iter.hasNext()) {
                    ExternalLocation extLoc = iter.next();
                    if (extLoc.getAddress().equals(addr)) {
                        final String finalLibName = libName;
                        final ExternalLocation finalExtLoc = extLoc;
                        final String oldName = extLoc.getLabel();

                        AtomicBoolean success = new AtomicBoolean(false);
                        AtomicReference<String> errorMsg = new AtomicReference<>();

                        try {
                            SwingUtilities.invokeAndWait(() -> {
                                int tx = program.startTransaction("Rename external location");
                                try {
                                    Namespace extLibNamespace = extMgr.getExternalLibrary(finalLibName);
                                    finalExtLoc.setName(extLibNamespace, newName, SourceType.USER_DEFINED);
                                    success.set(true);
                                    Msg.info(this, "Renamed external location: " + oldName + " -> " + newName);
                                } catch (Exception e) {
                                    errorMsg.set(e.getMessage());
                                    Msg.error(this, "Error renaming external location: " + e.getMessage());
                                } finally {
                                    program.endTransaction(tx, success.get());
                                }
                            });
                        } catch (InterruptedException e) {
                            errorMsg.set("Interrupted: " + e.getMessage());
                        } catch (InvocationTargetException e) {
                            errorMsg.set(e.getCause() != null ? e.getCause().getMessage() : e.getMessage());
                        }

                        if (success.get()) {
                            String resultDll = finalLibName;
                            JsonObject _jo77 = new JsonObject();
                            _jo77.addProperty("success", true);
                            _jo77.addProperty("old_name", oldName);
                            _jo77.addProperty("new_name", newName);
                            _jo77.addProperty("dll", resultDll);
                            return new Response.Ok(_jo77);
                        } else {
                            return errorJson(errorMsg.get() != null ? errorMsg.get() : "Unknown error");
                        }
                    }
                }
            }

            return errorJson("External location not found at address " + address);
        } catch (Exception e) {
            Msg.error(this, "Exception in renameExternalLocation: " + e.getMessage());
            return errorJson(e.getMessage());
        }
    }

    // ==================================================================================
    // CROSS-VERSION MATCHING TOOLS
    // ==================================================================================

    /**
     * Compare documentation status across all open programs.
     * Returns documented/undocumented function counts for each program.
     */
    private Response compareProgramsDocumentation() {
        try {
            PluginTool tool = this.getActiveTool();
            if (tool == null) {
                return errorJson("Tool not available");
            }

            Program[] allPrograms = programProvider.getAllOpenPrograms();
            Program currentProgram = programProvider.getCurrentProgram();

            List<Map<String, Object>> programs = new ArrayList<>();
            for (Program prog : allPrograms) {
                int documented = 0;
                int undocumented = 0;
                int total = 0;

                FunctionManager funcMgr = prog.getFunctionManager();
                for (Function func : funcMgr.getFunctions(true)) {
                    total++;
                    if (func.getName().startsWith("FUN_") || func.getName().startsWith("thunk_FUN_")) {
                        undocumented++;
                    } else {
                        documented++;
                    }
                }

                double docPercent = total > 0 ? (documented * 100.0 / total) : 0;

                Map<String, Object> entry = new LinkedHashMap<>();
                entry.put("name", prog.getName());
                entry.put("path", prog.getDomainFile().getPathname());
                entry.put("is_current", prog == currentProgram);
                entry.put("total_functions", total);
                entry.put("documented", documented);
                entry.put("undocumented", undocumented);
                entry.put("documentation_percent", Double.parseDouble(String.format("%.1f", docPercent)));
                programs.add(entry);
            }

            List<Map<String, Object>> programList = programs;
            int progCount = allPrograms.length;
            JsonObject _jo78 = new JsonObject();
            _jo78.addProperty("count", progCount);
            return new Response.Ok(_jo78);

        } catch (Exception e) {
            return errorJson(e.getMessage());
        }
    }

    /**
     * Find undocumented (FUN_*) functions that reference a given string address.
     * This filters get_xrefs_to results to only return FUN_* functions.
     */
    private Response findUndocumentedByString(String stringAddress, String programName) {
        if (stringAddress == null || stringAddress.isEmpty()) {
            return errorJson("String address is required");
        }

        Object[] programResult = getProgramOrError(programName);
        Program program = (Program) programResult[0];
        if (program == null) {
            return (Response) programResult[1];
        }

        try {
            Address addr = program.getAddressFactory().getAddress(stringAddress);
            if (addr == null) {
                return errorJson("Invalid address format: " + stringAddress);
            }

            ReferenceManager refMgr = program.getReferenceManager();
            FunctionManager funcMgr = program.getFunctionManager();

            ReferenceIterator refIter = refMgr.getReferencesTo(addr);

            Set<String> seenFunctions = new HashSet<>();
            List<Map<String, String>> undocumentedFunctions = new ArrayList<>();
            int docCount = 0;

            while (refIter.hasNext()) {
                Reference ref = refIter.next();
                Address fromAddr = ref.getFromAddress();

                Function func = funcMgr.getFunctionContaining(fromAddr);
                if (func != null) {
                    String funcName = func.getName();

                    if (!seenFunctions.contains(funcName)) {
                        seenFunctions.add(funcName);

                        if (funcName.startsWith("FUN_") || funcName.startsWith("thunk_FUN_")) {
                            Map<String, String> entry = new LinkedHashMap<>();
                            entry.put("name", funcName);
                            entry.put("address", func.getEntryPoint().toString());
                            entry.put("ref_address", fromAddr.toString());
                            entry.put("ref_type", ref.getReferenceType().getName());
                            undocumentedFunctions.add(entry);
                        } else {
                            docCount++;
                        }
                    }
                }
            }

            String strAddr = stringAddress;
            List<Map<String, String>> undocList = undocumentedFunctions;
            int undocCount = undocumentedFunctions.size();
            int documentedCount = docCount;
            int totalCount = seenFunctions.size();
            JsonObject _jo79 = new JsonObject();
            _jo79.addProperty("string_address", strAddr);
            _jo79.addProperty("undocumented_count", undocCount);
            _jo79.addProperty("documented_count", documentedCount);
            _jo79.addProperty("total_referencing_functions", totalCount);
            return new Response.Ok(_jo79);

        } catch (Exception e) {
            return errorJson(e.getMessage());
        }
    }

    /**
     * Generate a report of all strings matching a pattern (e.g., ".cpp") and their referencing FUN_* functions.
     * This helps identify undocumented functions that can be matched using string anchors.
     */
    private Response batchStringAnchorReport(String pattern, String programName) {
        if (pattern == null || pattern.isEmpty()) pattern = ".cpp";
        Object[] programResult = getProgramOrError(programName);
        Program program = (Program) programResult[0];
        if (program == null) {
            return (Response) programResult[1];
        }

        String finalPattern = pattern;
        try {
            Listing listing = program.getListing();
            ReferenceManager refMgr = program.getReferenceManager();
            FunctionManager funcMgr = program.getFunctionManager();

            List<Map<String, Object>> anchors = new ArrayList<>();
            int totalUndocumented = 0;

            DataIterator dataIter = listing.getDefinedData(true);
            while (dataIter.hasNext()) {
                Data data = dataIter.next();

                if (data.getDataType() instanceof StringDataType ||
                    data.getDataType().getName().toLowerCase().contains("string")) {

                    Object value = data.getValue();
                    if (value instanceof String) {
                        String strValue = (String) value;

                        if (strValue.toLowerCase().contains(finalPattern.toLowerCase())) {
                            Address strAddr = data.getAddress();

                            ReferenceIterator refIter = refMgr.getReferencesTo(strAddr);
                            List<Map<String, String>> undocFuncList = new ArrayList<>();
                            List<String> docFuncList = new ArrayList<>();
                            Set<String> seenUndoc = new LinkedHashSet<>();
                            Set<String> seenDoc = new LinkedHashSet<>();

                            while (refIter.hasNext()) {
                                Reference ref = refIter.next();
                                Function func = funcMgr.getFunctionContaining(ref.getFromAddress());
                                if (func != null) {
                                    String funcName = func.getName();
                                    if (funcName.startsWith("FUN_") || funcName.startsWith("thunk_FUN_")) {
                                        String key = funcName + "@" + func.getEntryPoint().toString();
                                        if (seenUndoc.add(key)) {
                                            Map<String, String> fe = new LinkedHashMap<>();
                                            fe.put("name", funcName);
                                            fe.put("address", func.getEntryPoint().toString());
                                            undocFuncList.add(fe);
                                        }
                                    } else {
                                        if (seenDoc.add(funcName)) {
                                            docFuncList.add(funcName);
                                        }
                                    }
                                }
                            }

                            if (!undocFuncList.isEmpty() || !docFuncList.isEmpty()) {
                                totalUndocumented += undocFuncList.size();

                                Map<String, Object> anchor = new LinkedHashMap<>();
                                anchor.put("string", strValue);
                                anchor.put("address", strAddr.toString());
                                anchor.put("undocumented", undocFuncList);
                                anchor.put("documented", docFuncList);
                                anchor.put("undocumented_count", undocFuncList.size());
                                anchor.put("documented_count", docFuncList.size());
                                anchors.add(anchor);
                            }
                        }
                    }
                }
            }

            List<Map<String, Object>> anchorList = anchors;
            int anchorCount = anchors.size();
            int totalUndoc = totalUndocumented;
            String patternStr = finalPattern;
            JsonObject _jo80 = new JsonObject();
            _jo80.addProperty("pattern", patternStr);
            _jo80.addProperty("total_anchors", anchorCount);
            _jo80.addProperty("total_undocumented_functions", totalUndoc);
            return new Response.Ok(_jo80);

        } catch (Exception e) {
            return errorJson(e.getMessage());
        }
    }

    // ==================== SERVER LIFECYCLE ====================

}
