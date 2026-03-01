package com.xebyte;

import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.GlobalNamespace;
import ghidra.program.model.listing.*;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighFunctionDBUtil.ReturnCommitOption;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.services.CodeViewerService;

import ghidra.app.script.GhidraScriptUtil;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraScriptProvider;
import ghidra.app.plugin.core.script.GhidraScriptMgrPlugin;

import ghidra.program.model.symbol.SourceType;

import ghidra.program.model.data.*;
import ghidra.program.model.mem.Memory;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.PointerDataType;

import ghidra.framework.options.Options;

import docking.action.DockingAction;
import docking.action.MenuData;
import docking.ActionContext;

// Block model for control flow analysis
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;

import com.xebyte.core.BinaryComparisonService;
import com.xebyte.core.FrontEndProgramProvider;
import com.xebyte.core.Response;

import ghidra.framework.main.ApplicationLevelPlugin;

import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectData;
import ghidra.framework.store.ItemCheckoutStatus;
import ghidra.framework.client.RepositoryAdapter;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.util.task.TaskMonitor;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.Headers;

import javax.swing.SwingUtilities;
import java.io.*;
import java.lang.reflect.InvocationTargetException;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Pattern;

// Load version from properties file (populated by Maven during build)
class VersionInfo {
    private static String VERSION = "4.0.0"; // Default fallback
    private static String APP_NAME = "GhidraMCP";
    private static String GHIDRA_VERSION = "unknown"; // Loaded from version.properties (Maven-filtered)
    private static String BUILD_TIMESTAMP = "dev"; // Will be replaced by Maven
    private static String BUILD_NUMBER = "0"; // Will be replaced by Maven
    private static final int ENDPOINT_COUNT = 169;
    
    static {
        try (InputStream input = GhidraMCPPlugin.class
                .getResourceAsStream("/version.properties")) {
            if (input != null) {
                Properties props = new Properties();
                props.load(input);
                VERSION = props.getProperty("app.version", "4.0.0");
                APP_NAME = props.getProperty("app.name", "GhidraMCP");
                GHIDRA_VERSION = props.getProperty("ghidra.version", "unknown");
                BUILD_TIMESTAMP = props.getProperty("build.timestamp", "dev");
                BUILD_NUMBER = props.getProperty("build.number", "0");
            }
        } catch (IOException e) {
            // Use defaults if file not found
        }
    }
    
    public static String getVersion() {
        return VERSION;
    }
    
    public static String getAppName() {
        return APP_NAME;
    }
    
    public static String getGhidraVersion() {
        return GHIDRA_VERSION;
    }
    
    public static String getBuildTimestamp() {
        return BUILD_TIMESTAMP;
    }
    
    public static String getBuildNumber() {
        return BUILD_NUMBER;
    }
    
    public static int getEndpointCount() {
        return ENDPOINT_COUNT;
    }
    
    public static String getFullVersion() {
        return VERSION + " (build " + BUILD_NUMBER + ", " + BUILD_TIMESTAMP + ")";
    }
}

@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = ghidra.framework.main.UtilityPluginPackage.NAME,
    category = PluginCategoryNames.COMMON,
    shortDescription = "GhidraMCP - HTTP server plugin",
    description = "GhidraMCP - Starts an embedded HTTP server to expose program data via REST API and MCP bridge. " +
                  "Provides 165 endpoints for reverse engineering automation. " +
                  "Port configurable via Tool Options. " +
                  "Features: function analysis, decompilation, symbol management, cross-references, label operations, " +
                  "high-performance batch data analysis, field-level structure analysis, advanced call graph analysis, " +
                  "malware analysis (IOC extraction, behavior detection, anti-analysis detection), and Ghidra script automation. " +
                  "See https://github.com/bethington/ghidra-mcp for documentation and version history."
)
public class GhidraMCPPlugin extends Plugin implements ApplicationLevelPlugin {

    // Static singleton: one HTTP server shared across all CodeBrowser windows (fixes #35)
    private static HttpServer server;
    private static int instanceCount = 0;
    private boolean ownsServer = false; // true if this instance started the server
    private static final String OPTION_CATEGORY_NAME = "GhidraMCP HTTP Server";
    private static final String PORT_OPTION_NAME = "Server Port";
    private static final int DEFAULT_PORT = 8089;

    // Field analysis constants (v1.4.0)
    private static final int MAX_FUNCTIONS_TO_ANALYZE = 100;
    private static final int MIN_FUNCTIONS_TO_ANALYZE = 1;
    private static final int MAX_STRUCT_FIELDS = 256;
    private static final int MAX_FIELD_EXAMPLES = 50;
    private static final int DECOMPILE_TIMEOUT_SECONDS = 60;  // Increased from 30s to 60s for large functions
    private static final int MIN_TOKEN_LENGTH = 3;
    private static final int MAX_FIELD_OFFSET = 65536;

    // HTTP server timeout constants (v1.6.1)
    private static final int HTTP_CONNECTION_TIMEOUT_SECONDS = 180;  // 3 minutes for connection timeout
    private static final int HTTP_IDLE_TIMEOUT_SECONDS = 300;        // 5 minutes for idle connections
    private static final int BATCH_OPERATION_CHUNK_SIZE = 20;        // Process batch operations in chunks of 20

    // Menu actions for Tools > GhidraMCP submenu
    private DockingAction startServerAction;
    private DockingAction stopServerAction;
    private DockingAction restartServerAction;
    private DockingAction serverStatusAction;

    // C language keywords to filter from field name suggestions
    private static final Set<String> C_KEYWORDS = Set.of(
        "if", "else", "for", "while", "do", "switch", "case", "default",
        "break", "continue", "return", "goto", "int", "void", "char",
        "float", "double", "long", "short", "struct", "union", "enum",
        "typedef", "sizeof", "const", "static", "extern", "auto", "register",
        "signed", "unsigned", "volatile", "inline", "restrict"
    );

    // Program provider for on-demand program access (FrontEnd mode)
    private final FrontEndProgramProvider programProvider;

    // Server authenticator for programmatic login (bypasses GUI password dialog)
    private com.xebyte.core.GhidraMCPAuthenticator authenticator;

    // Service layer for delegated operations
    private final com.xebyte.core.ListingService listingService;
    private final com.xebyte.core.CommentService commentService;
    private final com.xebyte.core.SymbolLabelService symbolLabelService;
    private final com.xebyte.core.FunctionService functionService;
    private final com.xebyte.core.XrefCallGraphService xrefCallGraphService;
    private final com.xebyte.core.DataTypeService dataTypeService;
    private final com.xebyte.core.DocumentationHashService documentationHashService;
    private final com.xebyte.core.AnalysisService analysisService;
    private final com.xebyte.core.MalwareSecurityService malwareSecurityService;
    private final com.xebyte.core.ProgramScriptService programScriptService;

    public GhidraMCPPlugin(PluginTool tool) {
        super(tool);
        instanceCount++;

        // Initialize service layer — FrontEnd mode: opens programs on-demand from project
        this.programProvider = new FrontEndProgramProvider(tool, this);
        com.xebyte.core.ThreadingStrategy threadingStrategy = new com.xebyte.headless.DirectThreadingStrategy();
        this.listingService = new com.xebyte.core.ListingService(programProvider);
        this.commentService = new com.xebyte.core.CommentService(programProvider, threadingStrategy);
        this.symbolLabelService = new com.xebyte.core.SymbolLabelService(programProvider, threadingStrategy);
        this.functionService = new com.xebyte.core.FunctionService(programProvider, threadingStrategy);
        this.xrefCallGraphService = new com.xebyte.core.XrefCallGraphService(programProvider, threadingStrategy);
        this.dataTypeService = new com.xebyte.core.DataTypeService(programProvider, threadingStrategy);
        this.documentationHashService = new com.xebyte.core.DocumentationHashService(programProvider, threadingStrategy, new com.xebyte.core.BinaryComparisonService());
        this.documentationHashService.setFunctionService(this.functionService);
        this.documentationHashService.setCommentService(this.commentService);
        this.analysisService = new com.xebyte.core.AnalysisService(programProvider, threadingStrategy, this.functionService);
        this.documentationHashService.setAnalysisService(this.analysisService);
        this.malwareSecurityService = new com.xebyte.core.MalwareSecurityService(programProvider, threadingStrategy);
        this.programScriptService = new com.xebyte.core.ProgramScriptService(programProvider, threadingStrategy);
        Msg.info(this, "============================================");
        Msg.info(this, "GhidraMCP " + VersionInfo.getFullVersion());
        Msg.info(this, "Endpoints: " + VersionInfo.getEndpointCount());
        Msg.info(this, "============================================");

        // Server authenticator: GhidraMCPAuthInitializer (ModuleInitializer) handles
        // early registration from GHIDRA_SERVER_PASSWORD env var — runs before project opens.
        // The /server/authenticate endpoint handles runtime credential updates.
        if (com.xebyte.core.GhidraMCPAuthInitializer.isRegistered()) {
            this.authenticator = com.xebyte.core.GhidraMCPAuthInitializer.getAuthenticator();
            Msg.info(this, "GhidraMCP: Server authenticator was registered at startup");
        }

        // Register the configuration option
        Options options = tool.getOptions(OPTION_CATEGORY_NAME);
        options.registerOption(PORT_OPTION_NAME, DEFAULT_PORT,
            null, // No help location for now
            "The network port number the embedded HTTP server will listen on. " +
            "Requires Ghidra restart or plugin reload to take effect after changing.");

        // Only start server if not already running (fixes #35: multi-window port collision)
        if (server != null && isServerRunning()) {
            Msg.info(this, "GhidraMCP HTTP server already running — sharing with this tool window.");
        } else {
            try {
                startServer();
                ownsServer = true;
                Msg.info(this, "GhidraMCPPlugin loaded successfully with HTTP server on port " +
                    options.getInt(PORT_OPTION_NAME, DEFAULT_PORT));
            }
            catch (IOException e) {
                Msg.error(this, "Failed to start HTTP server: " + e.getMessage(), e);
                Msg.showError(this, null, "GhidraMCP Server Error",
                    "Failed to start MCP server on port " + options.getInt(PORT_OPTION_NAME, DEFAULT_PORT) +
                    ".\n\nThe port may already be in use. Try:\n" +
                    "1. Restarting Ghidra\n" +
                    "2. Changing the port in Edit > Tool Options > GhidraMCP\n" +
                    "3. Checking if another Ghidra instance is running\n\n" +
                    "Error: " + e.getMessage());
            }
        }

        createMenuActions();
    }

    private boolean isServerRunning() {
        return server != null;
    }

    private void stopServer() {
        if (server != null) {
            Msg.info(this, "Stopping GhidraMCP HTTP server...");
            try {
                server.stop(1);
                Thread.sleep(100);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            server = null;
            Msg.info(this, "GhidraMCP HTTP server stopped.");
        }
    }

    private void updateMenuActionStates() {
        boolean running = isServerRunning();
        startServerAction.setEnabled(!running);
        stopServerAction.setEnabled(running);
        restartServerAction.setEnabled(running);
    }

    private void createMenuActions() {
        startServerAction = new DockingAction("Start Server", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                try {
                    startServer();
                    updateMenuActionStates();
                    Options options = tool.getOptions(OPTION_CATEGORY_NAME);
                    int port = options.getInt(PORT_OPTION_NAME, DEFAULT_PORT);
                    Msg.showInfo(getClass(), null, "GhidraMCP", "Server started on port " + port + ".");
                } catch (IOException e) {
                    Msg.showError(getClass(), null, "GhidraMCP", "Failed to start server: " + e.getMessage());
                }
            }
        };
        startServerAction.setMenuBarData(new MenuData(new String[]{"Tools", "GhidraMCP", "Start Server"}));

        stopServerAction = new DockingAction("Stop Server", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                stopServer();
                updateMenuActionStates();
                Msg.showInfo(getClass(), null, "GhidraMCP", "Server stopped.");
            }
        };
        stopServerAction.setMenuBarData(new MenuData(new String[]{"Tools", "GhidraMCP", "Stop Server"}));

        restartServerAction = new DockingAction("Restart Server", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                stopServer();
                try {
                    startServer();
                    updateMenuActionStates();
                    Options options = tool.getOptions(OPTION_CATEGORY_NAME);
                    int port = options.getInt(PORT_OPTION_NAME, DEFAULT_PORT);
                    Msg.showInfo(getClass(), null, "GhidraMCP", "Server restarted on port " + port + ".");
                } catch (IOException e) {
                    updateMenuActionStates();
                    Msg.showError(getClass(), null, "GhidraMCP", "Failed to restart server: " + e.getMessage());
                }
            }
        };
        restartServerAction.setMenuBarData(new MenuData(new String[]{"Tools", "GhidraMCP", "Restart Server"}));

        serverStatusAction = new DockingAction("Server Status", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                Options options = tool.getOptions(OPTION_CATEGORY_NAME);
                int port = options.getInt(PORT_OPTION_NAME, DEFAULT_PORT);
                String status = isServerRunning() ? "Running" : "Stopped";
                String message = "GhidraMCP Server Status\n\n" +
                    "Status: " + status + "\n" +
                    "Port: " + port + "\n" +
                    "Version: " + VersionInfo.getFullVersion() + "\n" +
                    "Endpoints: " + VersionInfo.getEndpointCount();
                Msg.showInfo(getClass(), null, "GhidraMCP", message);
            }
        };
        serverStatusAction.setMenuBarData(new MenuData(new String[]{"Tools", "GhidraMCP", "Server Status"}));

        tool.addAction(startServerAction);
        tool.addAction(stopServerAction);
        tool.addAction(restartServerAction);
        tool.addAction(serverStatusAction);

        updateMenuActionStates();
    }

    private void startServer() throws IOException {
        // Read the configured port
        Options options = tool.getOptions(OPTION_CATEGORY_NAME);
        int port = options.getInt(PORT_OPTION_NAME, DEFAULT_PORT);

        // Stop existing server if running (e.g., if plugin is reloaded)
        if (server != null) {
            Msg.info(this, "Stopping existing HTTP server before starting new one.");
            try {
                server.stop(0);
                // Give the server time to fully stop and release all resources
                Thread.sleep(500);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                Msg.warn(this, "Interrupted while waiting for server to stop");
            }
            server = null;
        }

        // Create new server - if port is in use, try to handle gracefully
        try {
            server = HttpServer.create(new InetSocketAddress("127.0.0.1", port), 0);
            Msg.info(this, "HTTP server created successfully on 127.0.0.1:" + port);
        } catch (java.net.BindException e) {
            Msg.error(this, "Port " + port + " is already in use. " +
                "Another instance may be running or port is not released yet. " +
                "Please wait a few seconds and restart Ghidra, or change the port in Tool Options.");
            throw e;
        } catch (IllegalArgumentException e) {
            Msg.error(this, "Cannot create HTTP server contexts - they may already exist. " +
                "Please restart Ghidra completely. Error: " + e.getMessage());
            throw new IOException("Server context creation failed", e);
        }

        // ==========================================================================
        // LISTING ENDPOINTS - All use list_ prefix with snake_case
        // ==========================================================================

        server.createContext("/list_methods", safeHandler(exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            String programName = qparams.get("program");  // Optional: target specific program
            sendResponse(exchange, getAllFunctionNames(offset, limit, programName));
        }));

        server.createContext("/list_classes", safeHandler(exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            String programName = qparams.get("program");  // Optional: target specific program
            sendResponse(exchange, getAllClassNames(offset, limit, programName));
        }));

        server.createContext("/list_segments", safeHandler(exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            String programName = qparams.get("program");  // Optional: target specific program
            sendResponse(exchange, listSegments(offset, limit, programName));
        }));

        server.createContext("/list_imports", safeHandler(exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            String programName = qparams.get("program");  // Optional: target specific program
            sendResponse(exchange, listImports(offset, limit, programName));
        }));

        server.createContext("/list_exports", safeHandler(exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            String programName = qparams.get("program");  // Optional: target specific program
            sendResponse(exchange, listExports(offset, limit, programName));
        }));

        server.createContext("/list_namespaces", safeHandler(exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            String programName = qparams.get("program");  // Optional: target specific program
            sendResponse(exchange, listNamespaces(offset, limit, programName));
        }));

        server.createContext("/list_data_items", safeHandler(exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            String programName = qparams.get("program");  // Optional: target specific program
            sendResponse(exchange, listDefinedData(offset, limit, programName));
        }));

        server.createContext("/list_data_items_by_xrefs", safeHandler(exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            String format = qparams.getOrDefault("format", "text");
            String programName = qparams.get("program");  // Optional: target specific program
            sendResponse(exchange, listDataItemsByXrefs(offset, limit, format, programName));
        }));

        server.createContext("/list_functions", safeHandler(exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String programName = qparams.get("program");  // Optional: target specific program
            sendResponse(exchange, listFunctions(programName));
        }));

        // LIST_FUNCTIONS_ENHANCED - Returns JSON with thunk/external flags
        server.createContext("/list_functions_enhanced", safeHandler(exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = Integer.parseInt(qparams.getOrDefault("offset", "0"));
            int limit = Integer.parseInt(qparams.getOrDefault("limit", "10000"));
            String programName = qparams.get("program");  // Optional: target specific program
            sendResponse(exchange, listFunctionsEnhanced(offset, limit, programName));
        }));

        // ==========================================================================
        // RENAME ENDPOINTS - All use rename_ prefix with snake_case
        // ==========================================================================

        server.createContext("/rename_function", safeHandler(exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String result = renameFunction(params.get("oldName"), params.get("newName"));
            sendResponse(exchange, result);
        }));

        server.createContext("/rename_data", safeHandler(exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String result = renameDataAtAddress(params.get("address"), params.get("newName"));
            sendResponse(exchange, result);
        }));

        server.createContext("/rename_variable", safeHandler(exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionName = params.get("functionName");
            String oldName = params.get("oldName");
            String newName = params.get("newName");
            String result = renameVariableInFunction(functionName, oldName, newName);
            sendResponse(exchange, result);
        }));

        // ==========================================================================
        // SEARCH ENDPOINTS
        // ==========================================================================

        server.createContext("/search_functions", safeHandler(exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String searchTerm = qparams.get("query");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            String programName = qparams.get("program");  // Optional: target specific program
            sendResponse(exchange, searchFunctionsByName(searchTerm, offset, limit, programName));
        }));

        // ==========================================================================
        // GETTER ENDPOINTS - All use get_ prefix with snake_case
        // ==========================================================================

        server.createContext("/get_function_by_address", safeHandler(exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            String programName = qparams.get("program");
            sendResponse(exchange, getFunctionByAddress(address, programName));
        }));

        server.createContext("/get_current_address", safeHandler(exchange -> {
            sendResponse(exchange, getCurrentAddress());
        }));

        server.createContext("/get_current_function", safeHandler(exchange -> {
            sendResponse(exchange, getCurrentFunction());
        }));

        // ==========================================================================
        // DECOMPILE/DISASSEMBLE ENDPOINTS
        // ==========================================================================

        server.createContext("/decompile_function", safeHandler(exchange -> {
            try {
                Map<String, String> qparams = parseQueryParams(exchange);
                String address = qparams.get("address");
                String programName = qparams.get("program");
                String timeoutStr = qparams.get("timeout");
                int timeout = DECOMPILE_TIMEOUT_SECONDS;
                if (timeoutStr != null && !timeoutStr.isEmpty()) {
                    try { timeout = Integer.parseInt(timeoutStr); } catch (NumberFormatException ignored) {}
                }
                sendResponse(exchange, decompileFunctionByAddress(address, programName, timeout));
            } catch (Throwable e) {
                String msg = e.getMessage() != null ? e.getMessage() : e.toString();
                sendResponse(exchange, "{\"error\": \"" + msg.replace("\"", "\\\"") + "\"}");
            }
        }));

        server.createContext("/disassemble_function", safeHandler(exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            String programName = qparams.get("program");  // Optional: target specific program
            sendResponse(exchange, disassembleFunction(address, programName));
        }));

        server.createContext("/set_decompiler_comment", safeHandler(exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String comment = params.get("comment");
            String result = setDecompilerComment(address, comment);
            sendResponse(exchange, result);
        }));

        server.createContext("/set_disassembly_comment", safeHandler(exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String comment = params.get("comment");
            String result = setDisassemblyComment(address, comment);
            sendResponse(exchange, result);
        }));

        server.createContext("/rename_function_by_address", safeHandler(exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String newName = params.get("new_name");
            String result = renameFunctionByAddress(functionAddress, newName);
            sendResponse(exchange, result);
        }));

        server.createContext("/set_function_prototype", safeHandler(exchange -> {
            Map<String, Object> params = parseJsonParams(exchange);
            String functionAddress = (String) params.get("function_address");
            String prototype = (String) params.get("prototype");
            String callingConvention = (String) params.get("calling_convention");

            // v3.0.1: Capture old prototype before applying changes
            String oldPrototype = "";
            if (functionAddress != null && !functionAddress.isEmpty()) {
                Program prog = getCurrentProgram();
                if (prog != null) {
                    Address addr = prog.getAddressFactory().getAddress(functionAddress);
                    if (addr != null) {
                        Function func = prog.getFunctionManager().getFunctionAt(addr);
                        if (func != null) {
                            oldPrototype = func.getSignature().getPrototypeString();
                        }
                    }
                }
            }

            // Call the set prototype function and get detailed result
            com.xebyte.core.FunctionService.PrototypeResult result = setFunctionPrototype(functionAddress, prototype, callingConvention);

            if (result.isSuccess()) {
                String successMsg = "Successfully set prototype for function at " + functionAddress;
                if (!oldPrototype.isEmpty()) {
                    successMsg += "\nOld prototype: " + oldPrototype;
                }
                if (callingConvention != null && !callingConvention.isEmpty()) {
                    successMsg += " with " + callingConvention + " calling convention";
                }
                if (!result.getErrorMessage().isEmpty()) {
                    successMsg += "\n\nWarnings/Debug Info:\n" + result.getErrorMessage();
                }
                sendResponse(exchange, successMsg);
            } else {
                sendResponse(exchange, "Failed to set function prototype: " + result.getErrorMessage());
            }
        }));

        server.createContext("/list_calling_conventions", safeHandler(exchange -> {
            String result = listCallingConventions();
            sendResponse(exchange, result);
        }));

        server.createContext("/set_local_variable_type", safeHandler(exchange -> {
            try {
                Map<String, String> params = parsePostParams(exchange);
                String functionAddress = params.get("function_address");
                String variableName = params.get("variable_name");
                String newType = params.get("new_type");

                // Try to set the type (with internal error handling)
                String result = setLocalVariableType(functionAddress, variableName, newType);
                sendResponse(exchange, result);
            } catch (Exception e) {
                // Catch any uncaught exceptions to prevent 500 errors
                String errorMsg = "Error: Unexpected exception in set_local_variable_type: " +
                                 e.getClass().getSimpleName() + ": " + e.getMessage();
                Msg.error(this, errorMsg, e);
                sendResponse(exchange, errorMsg);
            }
        }));

        server.createContext("/set_function_no_return", safeHandler(exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String noReturnStr = params.get("no_return");

            if (functionAddress == null || functionAddress.isEmpty()) {
                sendResponse(exchange, "Error: function_address parameter is required");
                return;
            }

            // Parse no_return as boolean (default to false if not provided or invalid)
            boolean noReturn = false;
            if (noReturnStr != null && !noReturnStr.isEmpty()) {
                noReturn = Boolean.parseBoolean(noReturnStr);
            }

            String result = setFunctionNoReturn(functionAddress, noReturn);
            sendResponse(exchange, result);
        }));

        server.createContext("/clear_instruction_flow_override", safeHandler(exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String instructionAddress = params.get("address");

            if (instructionAddress == null || instructionAddress.isEmpty()) {
                sendResponse(exchange, "Error: address parameter is required");
                return;
            }

            String result = clearInstructionFlowOverride(instructionAddress);
            sendResponse(exchange, result);
        }));

        // Variable storage control endpoint (v1.7.0)
        server.createContext("/set_variable_storage", safeHandler(exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String variableName = params.get("variable_name");
            String storageSpec = params.get("storage");

            if (functionAddress == null || functionAddress.isEmpty()) {
                sendResponse(exchange, "Error: function_address parameter is required");
                return;
            }
            if (variableName == null || variableName.isEmpty()) {
                sendResponse(exchange, "Error: variable_name parameter is required");
                return;
            }
            if (storageSpec == null || storageSpec.isEmpty()) {
                sendResponse(exchange, "Error: storage parameter is required");
                return;
            }

            String result = setVariableStorage(functionAddress, variableName, storageSpec);
            sendResponse(exchange, result);
        }));

        // Ghidra script execution endpoint (v1.7.0)
        server.createContext("/run_script", safeHandler(exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String scriptPath = params.get("script_path");
            String scriptArgs = params.get("args"); // Optional JSON arguments

            if (scriptPath == null || scriptPath.isEmpty()) {
                sendResponse(exchange, "Error: script_path parameter is required");
                return;
            }

            String result = runGhidraScript(scriptPath, scriptArgs);
            sendResponse(exchange, result);
        }));

        server.createContext("/run_script_inline", safeHandler(exchange -> {
            try {
                Map<String, Object> params = parseJsonParams(exchange);
                String code = (String) params.get("code");
                String scriptArgs = (String) params.get("args");

                if (code == null || code.isEmpty()) {
                    sendResponse(exchange, "{\"error\": \"code parameter is required\"}");
                    return;
                }

                // Generate a unique class name per invocation to avoid OSGi class cache collisions.
                // The fixed _mcp_inline_ prefix caused the bundle resolver to cache a stale
                // classloader, failing on subsequent runs with different dependencies.
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

                // Write to ~/ghidra_scripts/ so Ghidra's OSGi class loader can find the source bundle
                File scriptDir = new File(System.getProperty("user.home"), "ghidra_scripts");
                scriptDir.mkdirs();
                File tempScript = new File(scriptDir, className + ".java");
                try {
                    java.nio.file.Files.writeString(tempScript.toPath(), rewrittenCode);
                    String result = runGhidraScript(tempScript.getAbsolutePath(), scriptArgs);
                    sendResponse(exchange, result);
                } catch (Throwable e) {
                    String msg = e.getMessage() != null ? e.getMessage() : e.toString();
                    sendResponse(exchange, "{\"error\": \"" + msg.replace("\"", "\\\"") + "\"}");
                } finally {
                    // Clean up .java source and any .class file left by OSGi compiler
                    if (!tempScript.delete()) {
                        tempScript.deleteOnExit();
                    }
                    File classFile = new File(scriptDir, className + ".class");
                    if (classFile.exists() && !classFile.delete()) {
                        classFile.deleteOnExit();
                    }
                }
            } catch (Throwable e) {
                String msg = e.getMessage() != null ? e.getMessage() : e.toString();
                sendResponse(exchange, "{\"error\": \"" + msg.replace("\"", "\\\"") + "\"}");
            }
        }));

        // List available Ghidra scripts (v1.7.0)
        server.createContext("/list_scripts", safeHandler(exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String filter = qparams.get("filter"); // Optional filter

            String result = listGhidraScripts(filter);
            sendResponse(exchange, result);
        }));

        // Force decompiler reanalysis (v1.7.0, v3.0.1: aligned GET params with headless/bridge)
        server.createContext("/force_decompile", safeHandler(exchange -> {
            try {
                Map<String, String> params = parseQueryParams(exchange);
                String functionAddress = params.get("address");
                // Fallback to legacy POST parameter name for backward compatibility
                if (functionAddress == null || functionAddress.isEmpty()) {
                    Map<String, String> postParams = parsePostParams(exchange);
                    functionAddress = postParams.get("function_address");
                    if (functionAddress == null || functionAddress.isEmpty()) {
                        functionAddress = postParams.get("address");
                    }
                }

                if (functionAddress == null || functionAddress.isEmpty()) {
                    sendResponse(exchange, "{\"error\": \"address parameter is required\"}");
                    return;
                }

                String result = forceDecompile(functionAddress);
                sendResponse(exchange, result);
            } catch (Throwable e) {
                String msg = e.getMessage() != null ? e.getMessage() : e.toString();
                sendResponse(exchange, "{\"error\": \"" + msg.replace("\"", "\\\"") + "\"}");
            }
        }));

        // ==========================================================================
        // XREF ENDPOINTS - All use get_ prefix with snake_case
        // ==========================================================================

        server.createContext("/get_xrefs_to", safeHandler(exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            String programName = qparams.get("program");  // Optional: target specific program
            sendResponse(exchange, getXrefsTo(address, offset, limit, programName));
        }));

        server.createContext("/get_xrefs_from", safeHandler(exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            String programName = qparams.get("program");  // Optional: target specific program
            sendResponse(exchange, getXrefsFrom(address, offset, limit, programName));
        }));

        server.createContext("/get_function_xrefs", safeHandler(exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String name = qparams.get("name");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            String programName = qparams.get("program");  // Optional: target specific program
            sendResponse(exchange, getFunctionXrefs(name, offset, limit, programName));
        }));

        server.createContext("/get_function_labels", safeHandler(exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String name = qparams.get("name");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 20);
            sendResponse(exchange, getFunctionLabels(name, offset, limit));
        }));

        server.createContext("/get_function_jump_targets", safeHandler(exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String name = qparams.get("name");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, getFunctionJumpTargets(name, offset, limit));
        }));

        server.createContext("/rename_label", safeHandler(exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String oldName = params.get("old_name");
            String newName = params.get("new_name");
            String result = renameLabel(address, oldName, newName);
            sendResponse(exchange, result);
        }));

        // External location endpoints (v1.8.2)
        server.createContext("/list_external_locations", safeHandler(exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String programName = qparams.get("program");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, listExternalLocations(offset, limit, programName));
        }));

        server.createContext("/get_external_location", safeHandler(exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            String dllName = qparams.get("dll_name");
            String programName = qparams.get("program");
            sendResponse(exchange, getExternalLocationDetails(address, dllName, programName));
        }));

        server.createContext("/rename_external_location", safeHandler(exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String newName = params.get("new_name");
            sendResponse(exchange, renameExternalLocation(address, newName));
        }));

        server.createContext("/create_label", safeHandler(exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String name = params.get("name");
            String result = createLabel(address, name);
            sendResponse(exchange, result);
        }));

        // BATCH_CREATE_LABELS - Create multiple labels in a single operation (v1.5.1)
        server.createContext("/batch_create_labels", safeHandler(exchange -> {
            Map<String, Object> params = parseJsonParams(exchange);
            List<Map<String, String>> labels = convertToMapList(params.get("labels"));
            String result = batchCreateLabels(labels);
            sendResponse(exchange, result);
        }));

        server.createContext("/rename_or_label", safeHandler(exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String name = params.get("name");
            String result = renameOrLabel(address, name);
            sendResponse(exchange, result);
        }));

        // DELETE_LABEL - Remove a label at an address
        server.createContext("/delete_label", safeHandler(exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String name = params.get("name");  // Optional: specific label name to delete
            String result = deleteLabel(address, name);
            sendResponse(exchange, result);
        }));

        // BATCH_DELETE_LABELS - Delete multiple labels in a single operation
        server.createContext("/batch_delete_labels", safeHandler(exchange -> {
            Map<String, Object> params = parseJsonParams(exchange);
            List<Map<String, String>> labels = convertToMapList(params.get("labels"));
            String result = batchDeleteLabels(labels);
            sendResponse(exchange, result);
        }));

        // ==========================================================================
        // CALL GRAPH ENDPOINTS - All use get_ prefix with snake_case
        // ==========================================================================

        server.createContext("/get_function_callees", safeHandler(exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String name = qparams.get("name");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            String programName = qparams.get("program");  // Optional: target specific program
            sendResponse(exchange, getFunctionCallees(name, offset, limit, programName));
        }));

        server.createContext("/get_function_callers", safeHandler(exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String name = qparams.get("name");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            String programName = qparams.get("program");  // Optional: target specific program
            sendResponse(exchange, getFunctionCallers(name, offset, limit, programName));
        }));

        server.createContext("/get_function_call_graph", safeHandler(exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String name = qparams.get("name");
            int depth = parseIntOrDefault(qparams.get("depth"), 2);
            String direction = qparams.getOrDefault("direction", "both");
            String programName = qparams.get("program");  // Optional: target specific program
            sendResponse(exchange, getFunctionCallGraph(name, depth, direction, programName));
        }));

        server.createContext("/get_full_call_graph", safeHandler(exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String format = qparams.getOrDefault("format", "edges");
            int limit = parseIntOrDefault(qparams.get("limit"), 1000);
            String programName = qparams.get("program");  // Optional: target specific program
            sendResponse(exchange, getFullCallGraph(format, limit, programName));
        }));

        server.createContext("/analyze_call_graph", safeHandler(exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String startFunction = qparams.get("start_function");
            String endFunction = qparams.get("end_function");
            String analysisType = qparams.getOrDefault("analysis_type", "summary");
            String programName = qparams.get("program");
            sendResponse(exchange, analyzeCallGraph(startFunction, endFunction, analysisType, programName));
        }));

        // ==========================================================================
        // DATA TYPE ENDPOINTS
        // ==========================================================================

        server.createContext("/list_data_types", safeHandler(exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String category = qparams.get("category");
            String programName = qparams.get("program");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, listDataTypes(category, offset, limit, programName));
        }));

        server.createContext("/create_struct", safeHandler(exchange -> {
            try {
                Map<String, Object> params = parseJsonParams(exchange);
                String name = (String) params.get("name");
                Object fieldsObj = params.get("fields");
                String fieldsJson;
                if (fieldsObj instanceof String) {
                    fieldsJson = (String) fieldsObj;
                } else if (fieldsObj instanceof java.util.List) {
                    // Convert List to proper JSON array
                    fieldsJson = serializeListToJson((java.util.List<?>) fieldsObj);
                } else {
                    fieldsJson = fieldsObj != null ? fieldsObj.toString() : null;
                }
                sendResponse(exchange, createStruct(name, fieldsJson));
            } catch (Throwable e) {
                String msg = e.getMessage() != null ? e.getMessage() : e.toString();
                sendResponse(exchange, "{\"error\": \"" + msg.replace("\"", "\\\"") + "\"}");
            }
        }));

        server.createContext("/create_enum", safeHandler(exchange -> {
            Map<String, Object> params = parseJsonParams(exchange);
            String name = (String) params.get("name");
            Object valuesObj = params.get("values");
            String valuesJson;
            if (valuesObj instanceof String) {
                valuesJson = (String) valuesObj;
            } else if (valuesObj instanceof java.util.Map) {
                // Convert Map to proper JSON object
                valuesJson = serializeMapToJson((java.util.Map<?, ?>) valuesObj);
            } else {
                valuesJson = valuesObj != null ? valuesObj.toString() : null;
            }
            Object sizeObj = params.get("size");
            int size = (sizeObj instanceof Integer) ? (Integer) sizeObj :
                       parseIntOrDefault(sizeObj != null ? sizeObj.toString() : null, 4);
            sendResponse(exchange, createEnum(name, valuesJson, size));
        }));

        server.createContext("/apply_data_type", safeHandler(exchange -> {
            Map<String, Object> params = parseJsonParams(exchange);
            String address = (String) params.get("address");
            String typeName = (String) params.get("type_name");
            Object clearObj = params.get("clear_existing");
            boolean clearExisting = (clearObj instanceof Boolean) ? (Boolean) clearObj : 
                                   Boolean.parseBoolean(clearObj != null ? clearObj.toString() : "true");
            sendResponse(exchange, applyDataType(address, typeName, clearExisting));
        }));

        server.createContext("/list_strings", safeHandler(exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            String filter = qparams.get("filter");
            String programName = qparams.get("program");  // Optional: target specific program
            sendResponse(exchange, listDefinedStrings(offset, limit, filter, programName));
        }));

        // New endpoints for missing IDA functionality
        server.createContext("/check_connection", safeHandler(exchange -> {
            sendResponse(exchange, checkConnection());
        }));

        server.createContext("/get_version", safeHandler(exchange -> {
            sendResponse(exchange, getVersion());
        }));

        server.createContext("/get_metadata", safeHandler(exchange -> {
            sendResponse(exchange, getMetadata());
        }));

        server.createContext("/convert_number", safeHandler(exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String text = qparams.get("text");
            int size = parseIntOrDefault(qparams.get("size"), 4);
            sendResponse(exchange, convertNumber(text, size));
        }));

        server.createContext("/list_globals", safeHandler(exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            String filter = qparams.get("filter");
            String programName = qparams.get("program");  // Optional: target specific program
            sendResponse(exchange, listGlobals(offset, limit, filter, programName));
        }));

        server.createContext("/rename_global_variable", safeHandler(exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String oldName = params.get("old_name");
            String newName = params.get("new_name");
            String result = renameGlobalVariable(oldName, newName);
            sendResponse(exchange, result);
        }));

        server.createContext("/get_entry_points", safeHandler(exchange -> {
            sendResponse(exchange, getEntryPoints());
        }));

        // Data type analysis endpoints
        server.createContext("/create_union", safeHandler(exchange -> {
            try {
                Map<String, Object> params = parseJsonParams(exchange);
                String name = (String) params.get("name");
                Object fieldsObj = params.get("fields");
                String fieldsJson;
                if (fieldsObj instanceof String) {
                    fieldsJson = (String) fieldsObj;
                } else if (fieldsObj instanceof java.util.List) {
                    // Convert List to proper JSON array (same as create_struct)
                    fieldsJson = serializeListToJson((java.util.List<?>) fieldsObj);
                } else {
                    fieldsJson = fieldsObj != null ? fieldsObj.toString() : null;
                }
                sendResponse(exchange, createUnion(name, fieldsJson));
            } catch (Exception e) {
                sendResponse(exchange, "Union endpoint error: " + e.getMessage());
            }
        }));

        server.createContext("/get_type_size", safeHandler(exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String typeName = qparams.get("type_name");
            sendResponse(exchange, getTypeSize(typeName));
        }));

        server.createContext("/get_struct_layout", safeHandler(exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String structName = qparams.get("struct_name");
            sendResponse(exchange, getStructLayout(structName));
        }));

        server.createContext("/search_data_types", safeHandler(exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String pattern = qparams.get("pattern");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, searchDataTypes(pattern, offset, limit));
        }));

        server.createContext("/get_enum_values", safeHandler(exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String enumName = qparams.get("enum_name");
            sendResponse(exchange, getEnumValues(enumName));
        }));

        server.createContext("/create_typedef", safeHandler(exchange -> {
            Map<String, Object> params = parseJsonParams(exchange);
            String name = (String) params.get("name");
            String baseType = (String) params.get("base_type");
            sendResponse(exchange, createTypedef(name, baseType));
        }));

        server.createContext("/clone_data_type", safeHandler(exchange -> {
            Map<String, Object> params = parseJsonParams(exchange);
            String sourceType = (String) params.get("source_type");
            String newName = (String) params.get("new_name");
            sendResponse(exchange, cloneDataType(sourceType, newName));
        }));

        // Removed duplicate - see v1.5.0 VALIDATE_DATA_TYPE endpoint below

        server.createContext("/import_data_types", safeHandler(exchange -> {
            Map<String, Object> params = parseJsonParams(exchange);
            String source = (String) params.get("source");
            String format = (String) params.getOrDefault("format", "c");
            sendResponse(exchange, importDataTypes(source, format));
        }));

        // New data structure management endpoints
        server.createContext("/delete_data_type", safeHandler(exchange -> {
            Map<String, Object> params = parseJsonParams(exchange);
            String typeName = (String) params.get("type_name");
            sendResponse(exchange, deleteDataType(typeName));
        }));

        server.createContext("/modify_struct_field", safeHandler(exchange -> {
            Map<String, Object> params = parseJsonParams(exchange);
            String structName = (String) params.get("struct_name");
            String fieldName = (String) params.get("field_name");
            String newType = (String) params.get("new_type");
            String newName = (String) params.get("new_name");
            sendResponse(exchange, modifyStructField(structName, fieldName, newType, newName));
        }));

        server.createContext("/add_struct_field", safeHandler(exchange -> {
            Map<String, Object> params = parseJsonParams(exchange);
            String structName = (String) params.get("struct_name");
            String fieldName = (String) params.get("field_name");
            String fieldType = (String) params.get("field_type");
            Object offsetObj = params.get("offset");
            int offset = (offsetObj instanceof Integer) ? (Integer) offsetObj : -1;
            sendResponse(exchange, addStructField(structName, fieldName, fieldType, offset));
        }));

        server.createContext("/remove_struct_field", safeHandler(exchange -> {
            Map<String, Object> params = parseJsonParams(exchange);
            String structName = (String) params.get("struct_name");
            String fieldName = (String) params.get("field_name");
            sendResponse(exchange, removeStructField(structName, fieldName));
        }));

        server.createContext("/create_array_type", safeHandler(exchange -> {
            Map<String, Object> params = parseJsonParams(exchange);
            String baseType = (String) params.get("base_type");
            Object lengthObj = params.get("length");
            int length = (lengthObj instanceof Integer) ? (Integer) lengthObj : 1;
            String name = (String) params.get("name");
            sendResponse(exchange, createArrayType(baseType, length, name));
        }));

        server.createContext("/create_pointer_type", safeHandler(exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String baseType = params.get("base_type");
            String name = params.get("name");
            sendResponse(exchange, createPointerType(baseType, name));
        }));

        server.createContext("/create_data_type_category", safeHandler(exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String categoryPath = params.get("category_path");
            sendResponse(exchange, createDataTypeCategory(categoryPath));
        }));

        server.createContext("/move_data_type_to_category", safeHandler(exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String typeName = params.get("type_name");
            String categoryPath = params.get("category_path");
            sendResponse(exchange, moveDataTypeToCategory(typeName, categoryPath));
        }));

        server.createContext("/list_data_type_categories", safeHandler(exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, listDataTypeCategories(offset, limit));
        }));

        server.createContext("/delete_function", safeHandler(exchange -> {
            try {
                Map<String, Object> params = parseJsonParams(exchange);
                String address = (String) params.get("address");
                sendResponse(exchange, deleteFunctionAtAddress(address));
            } catch (Exception e) {
                sendResponse(exchange, "{\"error\": \"" + e.toString().replace("\"", "\\\"") + "\"}");
            }
        }));

        server.createContext("/create_function", safeHandler(exchange -> {
            try {
                Map<String, Object> params = parseJsonParams(exchange);
                String address = (String) params.get("address");
                String name = (String) params.get("name");
                Object dfObj = params.get("disassemble_first");
                boolean disassembleFirst = dfObj == null || Boolean.TRUE.equals(dfObj) ||
                    "true".equalsIgnoreCase(String.valueOf(dfObj));
                sendResponse(exchange, createFunctionAtAddress(address, name, disassembleFirst));
            } catch (Exception e) {
                sendResponse(exchange, "{\"error\": \"" + e.toString().replace("\"", "\\\"") + "\"}");
            }
        }));

        server.createContext("/create_function_signature", safeHandler(exchange -> {
            Map<String, Object> params = parseJsonParams(exchange);
            String name = (String) params.get("name");
            String returnType = (String) params.get("return_type");
            Object parametersObj = params.get("parameters");
            String parametersJson = (parametersObj instanceof String) ? (String) parametersObj : 
                                   (parametersObj != null ? parametersObj.toString() : null);
            sendResponse(exchange, createFunctionSignature(name, returnType, parametersJson));
        }));

        // Memory reading endpoint
        server.createContext("/read_memory", safeHandler(exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            String lengthStr = qparams.get("length");
            String programName = qparams.get("program");
            int length = parseIntOrDefault(lengthStr, 16);
            sendResponse(exchange, readMemory(address, length, programName));
        }));

        server.createContext("/create_memory_block", safeHandler(exchange -> {
            Map<String, Object> params = parseJsonParams(exchange);
            String name = (String) params.get("name");
            String address = (String) params.get("address");
            long size = params.get("size") != null ? ((Number) params.get("size")).longValue() : 0;
            boolean read = parseBoolOrDefault(params.get("read"), true);
            boolean write = parseBoolOrDefault(params.get("write"), true);
            boolean execute = parseBoolOrDefault(params.get("execute"), false);
            boolean isVolatile = parseBoolOrDefault(params.get("volatile"), false);
            String comment = (String) params.get("comment");
            sendResponse(exchange, createMemoryBlock(name, address, size, read, write, execute, isVolatile, comment));
        }));

        // ==========================================================================
        // HIGH-PERFORMANCE DATA ANALYSIS ENDPOINTS (v1.3.0)
        // ==========================================================================

        // 1. GET_BULK_XREFS - Batch xref retrieval
        server.createContext("/get_bulk_xrefs", safeHandler(exchange -> {
            Map<String, Object> params = parseJsonParams(exchange);
            Object addressesObj = params.get("addresses");
            String result = getBulkXrefs(addressesObj);
            sendResponse(exchange, result);
        }));

        // 2. ANALYZE_DATA_REGION - Comprehensive data region analysis
        server.createContext("/analyze_data_region", safeHandler(exchange -> {
            Map<String, Object> params = parseJsonParams(exchange);
            String address = (String) params.get("address");
            int maxScanBytes = parseIntOrDefault(String.valueOf(params.get("max_scan_bytes")), 1024);
            boolean includeXrefMap = parseBoolOrDefault(params.get("include_xref_map"), true);
            boolean includeAssemblyPatterns = parseBoolOrDefault(params.get("include_assembly_patterns"), true);
            boolean includeBoundaryDetection = parseBoolOrDefault(params.get("include_boundary_detection"), true);

            String result = analyzeDataRegion(address, maxScanBytes, includeXrefMap,
                                              includeAssemblyPatterns, includeBoundaryDetection);
            sendResponse(exchange, result);
        }));

        // 3. DETECT_ARRAY_BOUNDS - Array/table size detection
        server.createContext("/detect_array_bounds", safeHandler(exchange -> {
            Map<String, Object> params = parseJsonParams(exchange);
            String address = (String) params.get("address");
            boolean analyzeLoopBounds = parseBoolOrDefault(params.get("analyze_loop_bounds"), true);
            boolean analyzeIndexing = parseBoolOrDefault(params.get("analyze_indexing"), true);
            int maxScanRange = parseIntOrDefault(String.valueOf(params.get("max_scan_range")), 2048);

            String result = detectArrayBounds(address, analyzeLoopBounds, analyzeIndexing, maxScanRange);
            sendResponse(exchange, result);
        }));

        // 4. GET_ASSEMBLY_CONTEXT - Assembly pattern analysis
        server.createContext("/get_assembly_context", safeHandler(exchange -> {
            Map<String, Object> params = parseJsonParams(exchange);
            Object xrefSourcesObj = params.get("xref_sources");
            int contextInstructions = parseIntOrDefault(String.valueOf(params.get("context_instructions")), 5);
            Object includePatternsObj = params.get("include_patterns");

            String result = getAssemblyContext(xrefSourcesObj, contextInstructions, includePatternsObj);
            sendResponse(exchange, result);
        }));

        // 6. APPLY_DATA_CLASSIFICATION - Atomic type application
        server.createContext("/apply_data_classification", safeHandler(exchange -> {
            Map<String, Object> params = parseJsonParams(exchange);
            String address = (String) params.get("address");
            String classification = (String) params.get("classification");
            String name = (String) params.get("name");
            String comment = (String) params.get("comment");
            Object typeDefinitionObj = params.get("type_definition");

            String result = applyDataClassification(address, classification, name, comment, typeDefinitionObj);
            sendResponse(exchange, result);
        }));

        // === FIELD-LEVEL ANALYSIS ENDPOINTS (v1.4.0) ===

        // ANALYZE_STRUCT_FIELD_USAGE - Analyze how structure fields are accessed
        server.createContext("/analyze_struct_field_usage", safeHandler(exchange -> {
            Map<String, Object> params = parseJsonParams(exchange);
            String address = (String) params.get("address");
            String structName = (String) params.get("struct_name");
            int maxFunctionsToAnalyze = parseIntOrDefault(String.valueOf(params.get("max_functions")), 10);

            String result = analyzeStructFieldUsage(address, structName, maxFunctionsToAnalyze);
            sendResponse(exchange, result);
        }));

        // GET_FIELD_ACCESS_CONTEXT - Get assembly/decompilation context for specific field offsets
        server.createContext("/get_field_access_context", safeHandler(exchange -> {
            Map<String, Object> params = parseJsonParams(exchange);
            String structAddress = (String) params.get("struct_address");
            int fieldOffset = parseIntOrDefault(String.valueOf(params.get("field_offset")), 0);
            int numExamples = parseIntOrDefault(String.valueOf(params.get("num_examples")), 5);

            String result = getFieldAccessContext(structAddress, fieldOffset, numExamples);
            sendResponse(exchange, result);
        }));

        // SUGGEST_FIELD_NAMES - AI-assisted field name suggestions based on usage patterns
        server.createContext("/suggest_field_names", safeHandler(exchange -> {
            Map<String, Object> params = parseJsonParams(exchange);
            String structAddress = (String) params.get("struct_address");
            int structSize = parseIntOrDefault(String.valueOf(params.get("struct_size")), 0);

            String result = suggestFieldNames(structAddress, structSize);
            sendResponse(exchange, result);
        }));

        // 7. INSPECT_MEMORY_CONTENT - Memory content inspection with string detection
        server.createContext("/inspect_memory_content", safeHandler(exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            int length = parseIntOrDefault(qparams.get("length"), 64);
            boolean detectStrings = parseBoolOrDefault(qparams.get("detect_strings"), true);

            String result = inspectMemoryContent(address, length, detectStrings);
            sendResponse(exchange, result);
        }));

        // === MALWARE ANALYSIS ENDPOINTS ===

        // SEARCH_BYTE_PATTERNS - Search for byte patterns with masks
        server.createContext("/search_byte_patterns", safeHandler(exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String pattern = qparams.get("pattern");
            String mask = qparams.get("mask");

            String result = searchBytePatterns(pattern, mask);
            sendResponse(exchange, result);
        }));

        // FIND_SIMILAR_FUNCTIONS - Find structurally similar functions
        server.createContext("/find_similar_functions", safeHandler(exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String targetFunction = qparams.get("target_function");
            double threshold = parseDoubleOrDefault(qparams.get("threshold"), 0.8);

            String result = findSimilarFunctions(targetFunction, threshold);
            sendResponse(exchange, result);
        }));

        // ANALYZE_CONTROL_FLOW - Analyze function control flow complexity
        server.createContext("/analyze_control_flow", safeHandler(exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String functionName = qparams.get("function_name");

            String result = analyzeControlFlow(functionName);
            sendResponse(exchange, result);
        }));

        // FIND_ANTI_ANALYSIS_TECHNIQUES - Detect anti-analysis/anti-debug techniques
        server.createContext("/find_anti_analysis_techniques", safeHandler(exchange -> {
            String result = findAntiAnalysisTechniques();
            sendResponse(exchange, result);
        }));

        // BATCH_DECOMPILE - Decompile multiple functions at once
        server.createContext("/batch_decompile", safeHandler(exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String functions = qparams.get("functions");

            String result = batchDecompileFunctions(functions);
            sendResponse(exchange, result);
        }));

        // FIND_DEAD_CODE - Identify unreachable code blocks
        server.createContext("/find_dead_code", safeHandler(exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String functionName = qparams.get("function_name");

            String result = findDeadCode(functionName);
            sendResponse(exchange, result);
        }));

        // ANALYZE_API_CALL_CHAINS - Detect suspicious API call patterns
        server.createContext("/analyze_api_call_chains", safeHandler(exchange -> {
            String result = analyzeAPICallChains();
            sendResponse(exchange, result);
        }));

        // EXTRACT_IOCS_WITH_CONTEXT - Enhanced IOC extraction with context
        server.createContext("/extract_iocs_with_context", safeHandler(exchange -> {
            String result = extractIOCsWithContext();
            sendResponse(exchange, result);
        }));

        // DETECT_MALWARE_BEHAVIORS - Detect common malware behaviors
        server.createContext("/detect_malware_behaviors", safeHandler(exchange -> {
            String result = detectMalwareBehaviors();
            sendResponse(exchange, result);
        }));

        // === WORKFLOW OPTIMIZATION ENDPOINTS (v1.5.0) ===

        // BATCH_SET_COMMENTS - Set multiple comments in a single operation
        server.createContext("/batch_set_comments", safeHandler(exchange -> {
            Map<String, Object> params = parseJsonParams(exchange);
            String functionAddress = (String) params.get("function_address");

            // Convert List<Object> to List<Map<String, String>>
            List<Map<String, String>> decompilerComments = convertToMapList(params.get("decompiler_comments"));
            List<Map<String, String>> disassemblyComments = convertToMapList(params.get("disassembly_comments"));
            String plateComment = (String) params.get("plate_comment");

            String result = batchSetComments(functionAddress, decompilerComments, disassemblyComments, plateComment);
            sendResponse(exchange, result);
        }));

        // v3.0.1: Clear all comments (plate, PRE, EOL) for a function
        server.createContext("/clear_function_comments", safeHandler(exchange -> {
            Map<String, Object> params = parseJsonParams(exchange);
            String functionAddress = (String) params.get("function_address");
            Boolean clearPlate = params.containsKey("clear_plate") ? Boolean.valueOf(params.get("clear_plate").toString()) : true;
            Boolean clearPre = params.containsKey("clear_pre") ? Boolean.valueOf(params.get("clear_pre").toString()) : true;
            Boolean clearEol = params.containsKey("clear_eol") ? Boolean.valueOf(params.get("clear_eol").toString()) : true;

            String result = clearFunctionComments(functionAddress, clearPlate, clearPre, clearEol);
            sendResponse(exchange, result);
        }));

        // GET_PLATE_COMMENT - Get function header/plate comment
        server.createContext("/get_plate_comment", safeHandler(exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            String programName = qparams.get("program");

            Object[] programResult = getProgramOrError(programName);
            Program prog = (Program) programResult[0];
            if (prog == null) {
                sendResponse(exchange, (String) programResult[1]);
                return;
            }

            if (address == null || address.isEmpty()) {
                sendResponse(exchange, "{\"error\": \"address parameter is required\"}");
                return;
            }

            Address addr = prog.getAddressFactory().getAddress(address);
            if (addr == null) {
                sendResponse(exchange, "{\"error\": \"Invalid address: " + address + "\"}");
                return;
            }

            Function func = prog.getFunctionManager().getFunctionAt(addr);
            if (func == null) {
                func = prog.getFunctionManager().getFunctionContaining(addr);
            }
            if (func == null) {
                sendResponse(exchange, "{\"error\": \"No function at address: " + address + "\"}");
                return;
            }

            String comment = func.getComment();
            StringBuilder json = new StringBuilder("{");
            json.append("\"address\": \"").append(func.getEntryPoint().toString()).append("\", ");
            json.append("\"function_name\": \"").append(escapeJson(func.getName())).append("\", ");
            json.append("\"comment\": ").append(comment != null ? "\"" + escapeJson(comment) + "\"" : "null");
            json.append("}");
            sendResponse(exchange, json.toString());
        }));

        // SET_PLATE_COMMENT - Set function header/plate comment
        server.createContext("/set_plate_comment", safeHandler(exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String comment = params.get("comment");

            String result = setPlateComment(functionAddress, comment);
            sendResponse(exchange, result);
        }));

        // GET_FUNCTION_VARIABLES - List all variables in a function
        server.createContext("/get_function_variables", safeHandler(exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String functionName = qparams.get("function_name");
            String functionAddress = qparams.get("function_address");
            String programName = qparams.get("program");

            // v3.0.1: Accept function_address as alternative to function_name
            if ((functionName == null || functionName.isEmpty()) && functionAddress != null && !functionAddress.isEmpty()) {
                Object[] programResult = getProgramOrError(programName);
                Program prog = (Program) programResult[0];
                if (prog != null) {
                    Address addr = prog.getAddressFactory().getAddress(functionAddress);
                    if (addr != null) {
                        Function func = prog.getFunctionManager().getFunctionAt(addr);
                        if (func == null) {
                            func = prog.getFunctionManager().getFunctionContaining(addr);
                        }
                        if (func != null) {
                            functionName = func.getName();
                        }
                    }
                }
            }

            String result = getFunctionVariables(functionName, programName);
            sendResponse(exchange, result);
        }));

        // BATCH_RENAME_FUNCTION_COMPONENTS - Rename function and components atomically
        server.createContext("/batch_rename_function_components", safeHandler(exchange -> {
            Map<String, Object> params = parseJsonParams(exchange);
            String functionAddress = (String) params.get("function_address");
            String functionName = (String) params.get("function_name");
            @SuppressWarnings("unchecked")
            Map<String, String> parameterRenames = (Map<String, String>) params.get("parameter_renames");
            @SuppressWarnings("unchecked")
            Map<String, String> localRenames = (Map<String, String>) params.get("local_renames");
            String returnType = (String) params.get("return_type");

            String result = batchRenameFunctionComponents(functionAddress, functionName, parameterRenames, localRenames, returnType);
            sendResponse(exchange, result);
        }));

        // GET_VALID_DATA_TYPES - List valid Ghidra data type strings
        server.createContext("/get_valid_data_types", safeHandler(exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String category = qparams.get("category");

            String result = getValidDataTypes(category);
            sendResponse(exchange, result);
        }));

        // VALIDATE_DATA_TYPE - Validate data type applicability at address
        server.createContext("/validate_data_type", safeHandler(exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            String typeName = qparams.get("type_name");

            String result = validateDataType(address, typeName);
            sendResponse(exchange, result);
        }));

        // GET_DATA_TYPE_SIZE - Get the size in bytes of a data type
        server.createContext("/get_data_type_size", safeHandler(exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String typeName = qparams.get("type_name");

            if (typeName == null || typeName.isEmpty()) {
                sendResponse(exchange, "{\"error\": \"type_name parameter is required\"}");
                return;
            }

            Program program = getCurrentProgram();
            if (program == null) {
                sendResponse(exchange, "{\"error\": \"No program open\"}");
                return;
            }

            DataType dt = resolveDataType(program.getDataTypeManager(), typeName);
            if (dt == null) {
                sendResponse(exchange, "{\"error\": \"Data type not found: " + typeName + "\"}");
                return;
            }

            String category = dt.getCategoryPath().toString();
            if (category.equals("/")) {
                category = "builtin";
            }

            StringBuilder sb = new StringBuilder();
            sb.append("{\"type_name\": \"").append(dt.getName()).append("\", ");
            sb.append("\"size\": ").append(dt.getLength()).append(", ");
            sb.append("\"category\": \"").append(category.replace("\\", "\\\\").replace("\"", "\\\"")).append("\"}");
            sendResponse(exchange, sb.toString());
        }));

        // ANALYZE_FUNCTION_COMPLETENESS - Check function documentation completeness
        server.createContext("/analyze_function_completeness", safeHandler(exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String functionAddress = qparams.get("function_address");

            // FIX #4: Force decompiler cache refresh before analysis to ensure fresh data
            Program program = getCurrentProgram();
            if (program != null && functionAddress != null && !functionAddress.isEmpty()) {
                try {
                    Address addr = program.getAddressFactory().getAddress(functionAddress);
                    if (addr != null) {
                        Function func = program.getFunctionManager().getFunctionAt(addr);
                        if (func != null) {
                            // Force fresh decompilation to get current variable states
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
                    // Continue with analysis anyway
                }
            }

            String result = analyzeFunctionCompleteness(functionAddress);
            sendResponse(exchange, result);
        }));

        // BATCH_ANALYZE_COMPLETENESS - Analyze completeness for multiple functions at once
        server.createContext("/batch_analyze_completeness", safeHandler(exchange -> {
            try {
                Map<String, Object> params = parseJsonParams(exchange);
                @SuppressWarnings("unchecked")
                java.util.List<String> addresses = (java.util.List<String>) params.get("addresses");
                if (addresses == null || addresses.isEmpty()) {
                    sendResponse(exchange, "{\"error\": \"Missing required parameter: addresses (JSON array of hex addresses)\"}");
                    return;
                }

                // Refresh decompiler cache once for all functions
                Program program = getCurrentProgram();
                if (program != null) {
                    try {
                        DecompInterface tempDecomp = new DecompInterface();
                        tempDecomp.openProgram(program);
                        tempDecomp.flushCache();
                        for (String addr : addresses) {
                            Address a = program.getAddressFactory().getAddress(addr);
                            if (a != null) {
                                Function f = program.getFunctionManager().getFunctionAt(a);
                                if (f != null) {
                                    tempDecomp.decompileFunction(f, DECOMPILE_TIMEOUT_SECONDS, new ConsoleTaskMonitor());
                                }
                            }
                        }
                        tempDecomp.dispose();
                    } catch (Exception e) {
                        Msg.warn(this, "Failed to refresh cache for batch completeness: " + e.getMessage());
                    }
                }

                StringBuilder sb = new StringBuilder();
                sb.append("{\"results\": [");
                for (int i = 0; i < addresses.size(); i++) {
                    if (i > 0) sb.append(", ");
                    sb.append(analyzeFunctionCompleteness(addresses.get(i)));
                }
                sb.append("], \"count\": ").append(addresses.size()).append("}");
                sendResponse(exchange, sb.toString());
            } catch (Exception e) {
                sendResponse(exchange, "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}");
            }
        }));

        // FIND_NEXT_UNDEFINED_FUNCTION - Find next function needing analysis
        server.createContext("/find_next_undefined_function", safeHandler(exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String startAddress = qparams.get("start_address");
            String criteria = qparams.get("criteria");
            String pattern = qparams.get("pattern");
            String direction = qparams.get("direction");
            String programName = qparams.get("program");

            String result = findNextUndefinedFunction(startAddress, criteria, pattern, direction, programName);
            sendResponse(exchange, result);
        }));

        // BATCH_SET_VARIABLE_TYPES - Set types for multiple variables
        server.createContext("/batch_set_variable_types", safeHandler(exchange -> {
            try {
                Map<String, Object> params = parseJsonParams(exchange);
                String functionAddress = (String) params.get("function_address");

                // Handle variable_types as either Map or String (JSON parsing variation)
                Map<String, String> variableTypes = new HashMap<>();
                Object vtObj = params.get("variable_types");
                if (vtObj instanceof Map) {
                    @SuppressWarnings("unchecked")
                    Map<String, String> vtMap = (Map<String, String>) vtObj;
                    variableTypes = vtMap;
                } else if (vtObj instanceof String) {
                    // Parse JSON string into map
                    variableTypes = parseJsonObject((String) vtObj);
                }

                // Use optimized method
                String result = batchSetVariableTypesOptimized(functionAddress, variableTypes);
                sendResponse(exchange, result);
            } catch (Exception e) {
                // Catch any exceptions to prevent connection aborts
                String errorMsg = "{\"error\": \"" + e.getMessage().replace("\"", "\\\"") + "\", \"method\": \"optimized\"}";
                sendResponse(exchange, errorMsg);
                Msg.error(this, "Error in batch_set_variable_types endpoint", e);
            }
        }));

        // NEW v1.6.0: BATCH_RENAME_VARIABLES - Rename multiple variables atomically
        server.createContext("/batch_rename_variables", safeHandler(exchange -> {
            Map<String, Object> params = parseJsonParams(exchange);
            String functionAddress = (String) params.get("function_address");

            // Handle variable_renames as either String or Map (like create_struct does with fields)
            Object renamesObj = params.get("variable_renames");
            Map<String, String> variableRenames;
            if (renamesObj instanceof String) {
                // Parse the JSON object string into a Map
                variableRenames = parseJsonObject((String) renamesObj);
            } else if (renamesObj instanceof Map) {
                @SuppressWarnings("unchecked")
                Map<String, String> typedMap = (Map<String, String>) renamesObj;
                variableRenames = typedMap;
            } else {
                variableRenames = new HashMap<>();
            }

            boolean forceIndividual = parseBoolOrDefault(params.get("force_individual"), false);

            String result = batchRenameVariables(functionAddress, variableRenames, forceIndividual);
            sendResponse(exchange, result);
        }));

        // NEW v1.6.0: VALIDATE_FUNCTION_PROTOTYPE - Validate prototype before applying
        server.createContext("/validate_function_prototype", safeHandler(exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String functionAddress = qparams.get("function_address");
            String prototype = qparams.get("prototype");
            String callingConvention = qparams.get("calling_convention");

            String result = validateFunctionPrototype(functionAddress, prototype, callingConvention);
            sendResponse(exchange, result);
        }));

        // NEW v1.6.0: VALIDATE_DATA_TYPE_EXISTS - Check if type exists
        server.createContext("/validate_data_type_exists", safeHandler(exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String typeName = qparams.get("type_name");

            String result = validateDataTypeExists(typeName);
            sendResponse(exchange, result);
        }));

        // NEW v1.6.0: CAN_RENAME_AT_ADDRESS - Determine address type and operation
        server.createContext("/can_rename_at_address", safeHandler(exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");

            String result = canRenameAtAddress(address);
            sendResponse(exchange, result);
        }));

        // NEW v1.6.0: ANALYZE_FUNCTION_COMPLETE - Comprehensive single-call analysis
        server.createContext("/analyze_function_complete", safeHandler(exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String name = qparams.get("name");
            boolean includeXrefs = Boolean.parseBoolean(qparams.getOrDefault("include_xrefs", "true"));
            boolean includeCallees = Boolean.parseBoolean(qparams.getOrDefault("include_callees", "true"));
            boolean includeCallers = Boolean.parseBoolean(qparams.getOrDefault("include_callers", "true"));
            boolean includeDisasm = Boolean.parseBoolean(qparams.getOrDefault("include_disasm", "true"));
            boolean includeVariables = Boolean.parseBoolean(qparams.getOrDefault("include_variables", "true"));
            String programName = qparams.get("program");

            String result = analyzeFunctionComplete(name, includeXrefs, includeCallees, includeCallers, includeDisasm, includeVariables, programName);
            sendResponse(exchange, result);
        }));

        // NEW v1.6.0: SEARCH_FUNCTIONS_ENHANCED - Advanced search with filtering
        server.createContext("/search_functions_enhanced", safeHandler(exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String namePattern = qparams.get("name_pattern");
            Integer minXrefs = qparams.get("min_xrefs") != null ? Integer.parseInt(qparams.get("min_xrefs")) : null;
            Integer maxXrefs = qparams.get("max_xrefs") != null ? Integer.parseInt(qparams.get("max_xrefs")) : null;
            String callingConvention = qparams.get("calling_convention");
            Boolean hasCustomName = qparams.get("has_custom_name") != null ? Boolean.parseBoolean(qparams.get("has_custom_name")) : null;
            boolean regex = Boolean.parseBoolean(qparams.getOrDefault("regex", "false"));
            String sortBy = qparams.getOrDefault("sort_by", "address");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            String programName = qparams.get("program");

            String result = searchFunctionsEnhanced(namePattern, minXrefs, maxXrefs, callingConvention,
                hasCustomName, regex, sortBy, offset, limit, programName);
            sendResponse(exchange, result);
        }));

        // NEW v1.7.1: DISASSEMBLE_BYTES - Disassemble a range of bytes
        server.createContext("/disassemble_bytes", safeHandler(exchange -> {
            try {
                Map<String, Object> params = parseJsonParams(exchange);
                String startAddress = (String) params.get("start_address");
                String endAddress = (String) params.get("end_address");
                Integer length = params.get("length") != null ? ((Number) params.get("length")).intValue() : null;
                Object rtem = params.get("restrict_to_execute_memory");
                boolean restrictToExecuteMemory = rtem == null || Boolean.TRUE.equals(rtem) ||
                    "true".equalsIgnoreCase(String.valueOf(rtem));

                String result = disassembleBytes(startAddress, endAddress, length, restrictToExecuteMemory);
                sendResponse(exchange, result);
            } catch (Exception e) {
                sendResponse(exchange, "{\"error\": \"" + e.toString().replace("\"", "\\\"") + "\"}");
            }
        }));

        // Script execution endpoint (v1.9.1, fixed v2.0.1)
        server.createContext("/run_ghidra_script", safeHandler(exchange -> {
            try {
                Map<String, Object> params = parseJsonParams(exchange);
                String scriptName = (String) params.get("script_name");
                String scriptArgs = (String) params.get("args");
                int timeoutSeconds = params.get("timeout_seconds") != null ?
                    ((Number) params.get("timeout_seconds")).intValue() : 300;
                Object coObj = params.get("capture_output");
                boolean captureOutput = coObj == null || Boolean.TRUE.equals(coObj) ||
                    "true".equalsIgnoreCase(String.valueOf(coObj));

                String result = runGhidraScriptWithCapture(scriptName, scriptArgs, timeoutSeconds, captureOutput);
                sendResponse(exchange, result);
            } catch (Throwable e) {
                String msg = e.getMessage() != null ? e.getMessage() : e.toString();
                sendResponse(exchange, "{\"error\": \"" + msg.replace("\"", "\\\"") + "\"}");
            }
        }));

        // BOOKMARK ENDPOINTS (v1.9.4) - Progress tracking via Ghidra bookmarks
        // SET_BOOKMARK - Create or update a bookmark at an address
        server.createContext("/set_bookmark", safeHandler(exchange -> {
            Map<String, Object> params = parseJsonParams(exchange);
            String address = (String) params.get("address");
            String category = (String) params.get("category");
            String comment = (String) params.get("comment");

            String result = setBookmark(address, category, comment);
            sendResponse(exchange, result);
        }));

        // LIST_BOOKMARKS - List bookmarks, optionally filtered by category
        server.createContext("/list_bookmarks", safeHandler(exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String category = qparams.get("category");
            String address = qparams.get("address");

            String result = listBookmarks(category, address);
            sendResponse(exchange, result);
        }));

        // DELETE_BOOKMARK - Delete a bookmark at an address
        server.createContext("/delete_bookmark", safeHandler(exchange -> {
            Map<String, Object> params = parseJsonParams(exchange);
            String address = (String) params.get("address");
            String category = (String) params.get("category");

            String result = deleteBookmark(address, category);
            sendResponse(exchange, result);
        }));

        // ==================== PROGRAM MANAGEMENT ENDPOINTS ====================

        server.createContext("/save_program", safeHandler(exchange -> {
            try {
                sendResponse(exchange, saveCurrentProgram());
            } catch (Throwable e) {
                String msg = e.getMessage() != null ? e.getMessage() : e.toString();
                sendResponse(exchange, "{\"error\": \"" + msg.replace("\"", "\\\"") + "\"}");
            }
        }));

        server.createContext("/exit_ghidra", safeHandler(exchange -> {
            try {
                // Save first, then exit
                String saveResult = saveCurrentProgram();
                sendResponse(exchange, "{\"success\": true, \"message\": \"Saving and exiting Ghidra\", \"save\": " + saveResult + "}");
                // Schedule exit after response is sent
                new Thread(() -> {
                    try { Thread.sleep(500); } catch (InterruptedException ignored) {}
                    SwingUtilities.invokeLater(() -> {
                        PluginTool t = getTool();
                        if (t != null) t.close();
                    });
                }).start();
            } catch (Throwable e) {
                String msg = e.getMessage() != null ? e.getMessage() : e.toString();
                sendResponse(exchange, "{\"error\": \"" + msg.replace("\"", "\\\"") + "\"}");
            }
        }));

        // LIST_OPEN_PROGRAMS - List all currently open programs in Ghidra
        server.createContext("/list_open_programs", safeHandler(exchange -> {
            String result = listOpenPrograms();
            sendResponse(exchange, result);
        }));

        // GET_CURRENT_PROGRAM_INFO - Get detailed info about the active program
        server.createContext("/get_current_program_info", safeHandler(exchange -> {
            String result = getCurrentProgramInfo();
            sendResponse(exchange, result);
        }));

        // SWITCH_PROGRAM - Switch MCP context to a different open program
        server.createContext("/switch_program", safeHandler(exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String programName = qparams.get("name");
            String result = switchProgram(programName);
            sendResponse(exchange, result);
        }));

        // LIST_PROJECT_FILES - List all files in the current Ghidra project
        server.createContext("/list_project_files", safeHandler(exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String folder = qparams.get("folder");
            String result = listProjectFiles(folder);
            sendResponse(exchange, result);
        }));

        // OPEN_PROGRAM - Open a program from the current project
        server.createContext("/open_program", safeHandler(exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String path = qparams.get("path");
            boolean autoAnalyze = "true".equalsIgnoreCase(qparams.get("auto_analyze"));
            String result = openProgramFromProject(path, autoAnalyze);
            sendResponse(exchange, result);
        }));

        // ==================================================================================
        // FUNCTION HASH INDEX - Cross-binary documentation propagation
        // ==================================================================================

        // GET_FUNCTION_HASH - Compute normalized opcode hash for a function
        server.createContext("/get_function_hash", safeHandler(exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String functionAddress = qparams.get("address");
            String programName = qparams.get("program");
            String result = getFunctionHash(functionAddress, programName);
            sendResponse(exchange, result);
        }));

        // GET_BULK_FUNCTION_HASHES - Get hashes for multiple/all functions efficiently
        server.createContext("/get_bulk_function_hashes", safeHandler(exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            String filter = qparams.get("filter"); // "documented", "undocumented", or null for all
            String programName = qparams.get("program");
            String result = getBulkFunctionHashes(offset, limit, filter, programName);
            sendResponse(exchange, result);
        }));

        // GET_FUNCTION_DOCUMENTATION - Export all documentation for a function
        server.createContext("/get_function_documentation", safeHandler(exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String functionAddress = qparams.get("address");
            String result = getFunctionDocumentation(functionAddress);
            sendResponse(exchange, result);
        }));

        // APPLY_FUNCTION_DOCUMENTATION - Import documentation to a target function
        server.createContext("/apply_function_documentation", safeHandler(exchange -> {
            String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            String result = applyFunctionDocumentation(body);
            sendResponse(exchange, result);
        }));

        // ==================================================================================
        // CROSS-VERSION MATCHING TOOLS - Accelerate function documentation propagation
        // ==================================================================================

        // COMPARE_PROGRAMS_DOCUMENTATION - Compare documented vs undocumented counts across programs
        server.createContext("/compare_programs_documentation", safeHandler(exchange -> {
            String result = compareProgramsDocumentation();
            sendResponse(exchange, result);
        }));

        // FIND_UNDOCUMENTED_BY_STRING - Find FUN_* functions referencing a string
        server.createContext("/find_undocumented_by_string", safeHandler(exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String stringAddress = qparams.get("address");
            String programName = qparams.get("program");
            String result = findUndocumentedByString(stringAddress, programName);
            sendResponse(exchange, result);
        }));

        // BATCH_STRING_ANCHOR_REPORT - Generate report of source file strings and their FUN_* functions
        server.createContext("/batch_string_anchor_report", safeHandler(exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String pattern = qparams.getOrDefault("pattern", ".cpp");
            String programName = qparams.get("program");
            String result = batchStringAnchorReport(pattern, programName);
            sendResponse(exchange, result);
        }));

        // FUZZY MATCHING & DIFF - Cross-binary function comparison
        server.createContext("/get_function_signature", safeHandler(exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            String programName = qparams.get("program");
            String result = handleGetFunctionSignature(address, programName);
            sendResponse(exchange, result);
        }));

        server.createContext("/find_similar_functions_fuzzy", safeHandler(exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            String sourceProgramName = qparams.get("source_program");
            String targetProgramName = qparams.get("target_program");
            double threshold = parseDoubleOrDefault(qparams.get("threshold"), 0.7);
            int limit = parseIntOrDefault(qparams.get("limit"), 20);
            String result = handleFindSimilarFunctionsFuzzy(address, sourceProgramName, targetProgramName, threshold, limit);
            sendResponse(exchange, result);
        }));

        server.createContext("/bulk_fuzzy_match", safeHandler(exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String sourceProgramName = qparams.get("source_program");
            String targetProgramName = qparams.get("target_program");
            double threshold = parseDoubleOrDefault(qparams.get("threshold"), 0.7);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 50);
            String filter = qparams.get("filter");
            String result = handleBulkFuzzyMatch(sourceProgramName, targetProgramName, threshold, offset, limit, filter);
            sendResponse(exchange, result);
        }));

        server.createContext("/diff_functions", safeHandler(exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String addressA = qparams.get("address_a");
            String addressB = qparams.get("address_b");
            String programA = qparams.get("program_a");
            String programB = qparams.get("program_b");
            String result = handleDiffFunctions(addressA, addressB, programA, programB);
            sendResponse(exchange, result);
        }));

        // ==================================================================================
        // ANALYSIS CONTROL / UTILITY ENDPOINTS
        // ==================================================================================

        server.createContext("/get_function_count", safeHandler(exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String programName = qparams.get("program");
            sendResponse(exchange, getFunctionCount(programName));
        }));

        server.createContext("/search_strings", safeHandler(exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String query = qparams.get("query");
            int minLength = parseIntOrDefault(qparams.get("min_length"), 4);
            String encoding = qparams.get("encoding");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            String programName = qparams.get("program");
            sendResponse(exchange, searchStrings(query, minLength, encoding, offset, limit, programName));
        }));

        server.createContext("/list_analyzers", safeHandler(exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String programName = qparams.get("program");
            sendResponse(exchange, listAnalyzers(programName));
        }));

        server.createContext("/run_analysis", safeHandler(exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String programName = params.get("program");
            sendResponse(exchange, runAnalysis(programName));
        }));

        // ==========================================================================
        // PROJECT VERSION CONTROL ENDPOINTS (16 endpoints)
        // Uses Ghidra's internal Project/DomainFile API - no separate connection needed
        // ==========================================================================

        // --- Project Status (4 endpoints) ---

        server.createContext("/server/connect", safeHandler(exchange -> {
            Project project = tool.getProject();
            if (project == null) {
                sendResponse(exchange, "{\"error\": \"No project open in Ghidra\"}");
                return;
            }
            ProjectData data = project.getProjectData();
            boolean isShared = data.getProjectLocator().isTransient() ? false : (getProjectRepository() != null);
            sendResponse(exchange, "{\"status\": \"connected\", \"project\": \"" + escapeJson(project.getName()) + "\", " +
                "\"shared\": " + isShared + ", " +
                "\"message\": \"GUI plugin uses the open Ghidra project directly. No separate connection needed.\"}");
        }));

        server.createContext("/server/disconnect", safeHandler(exchange -> {
            sendResponse(exchange, "{\"status\": \"ok\", \"message\": \"GUI plugin uses the open project. No disconnect needed.\"}");
        }));

        server.createContext("/server/status", safeHandler(exchange -> {
            sendResponse(exchange, getProjectStatusJson());
        }));

        server.createContext("/server/repositories", safeHandler(exchange -> {
            Project project = tool.getProject();
            if (project == null) {
                sendResponse(exchange, "{\"error\": \"No project open\"}");
                return;
            }
            sendResponse(exchange, "{\"repositories\": [\"" + escapeJson(project.getName()) + "\"], \"count\": 1, " +
                "\"message\": \"GUI mode returns the current project. Use headless mode for multi-repo browsing.\"}");
        }));

        // --- Repository Browsing (3 endpoints) ---

        server.createContext("/server/repository/files", safeHandler(exchange -> {
            Map<String, String> params = parseQueryParams(exchange);
            String folderPath = params.get("path");
            if (folderPath == null) folderPath = params.get("folder");
            if (folderPath == null) folderPath = "/";
            sendResponse(exchange, listProjectFilesJson(folderPath));
        }));

        server.createContext("/server/repository/file", safeHandler(exchange -> {
            Map<String, String> params = parseQueryParams(exchange);
            String filePath = params.get("path");
            if (filePath == null) {
                sendResponse(exchange, "{\"error\": \"'path' parameter required\"}");
                return;
            }
            sendResponse(exchange, getProjectFileInfoJson(filePath));
        }));

        server.createContext("/server/repository/create", safeHandler(exchange -> {
            sendResponse(exchange, "{\"error\": \"Repository creation not available in GUI mode. Use Ghidra's Project Manager or headless mode.\"}");
        }));

        // --- Version Control Operations (4 endpoints) ---

        server.createContext("/server/version_control/checkout", safeHandler(exchange -> {
            Map<String, Object> params = parseJsonParams(exchange);
            String filePath = params.get("path") != null ? params.get("path").toString() : null;
            boolean exclusive = Boolean.parseBoolean(params.getOrDefault("exclusive", "true").toString());
            sendResponse(exchange, checkoutProjectFile(filePath, exclusive));
        }));

        server.createContext("/server/version_control/checkin", safeHandler(exchange -> {
            Map<String, Object> params = parseJsonParams(exchange);
            String filePath = params.get("path") != null ? params.get("path").toString() : null;
            String comment = params.getOrDefault("comment", "Checked in via GhidraMCP").toString();
            boolean keepCheckedOut = Boolean.parseBoolean(params.getOrDefault("keepCheckedOut", "false").toString());
            sendResponse(exchange, checkinProjectFile(filePath, comment, keepCheckedOut));
        }));

        server.createContext("/server/version_control/undo_checkout", safeHandler(exchange -> {
            Map<String, Object> params = parseJsonParams(exchange);
            String filePath = params.get("path") != null ? params.get("path").toString() : null;
            boolean keep = Boolean.parseBoolean(params.getOrDefault("keep", "false").toString());
            sendResponse(exchange, undoCheckoutProjectFile(filePath, keep));
        }));

        server.createContext("/server/version_control/add", safeHandler(exchange -> {
            Map<String, Object> params = parseJsonParams(exchange);
            String filePath = params.get("path") != null ? params.get("path").toString() : null;
            String comment = params.getOrDefault("comment", "Added via GhidraMCP").toString();
            sendResponse(exchange, addToVersionControl(filePath, comment));
        }));

        // --- Version History & Checkouts (2 endpoints) ---

        server.createContext("/server/version_history", safeHandler(exchange -> {
            Map<String, String> params = parseQueryParams(exchange);
            String filePath = params.get("path");
            sendResponse(exchange, getProjectFileVersionHistory(filePath));
        }));

        server.createContext("/server/checkouts", safeHandler(exchange -> {
            Map<String, String> params = parseQueryParams(exchange);
            String folderPath = params.get("path");
            if (folderPath == null) folderPath = "/";
            sendResponse(exchange, listProjectCheckouts(folderPath));
        }));

        // --- Admin Operations (3 endpoints) ---

        server.createContext("/server/admin/terminate_checkout", safeHandler(exchange -> {
            Map<String, Object> params = parseJsonParams(exchange);
            String filePath = params.get("path") != null ? params.get("path").toString() : null;
            sendResponse(exchange, terminateFileCheckout(filePath));
        }));

        server.createContext("/server/admin/users", safeHandler(exchange -> {
            sendResponse(exchange, "{\"error\": \"User listing requires headless mode with direct server connection.\"}");
        }));

        server.createContext("/server/admin/set_permissions", safeHandler(exchange -> {
            sendResponse(exchange, "{\"error\": \"Permission management requires headless mode with direct server connection.\"}");
        }));

        // ==========================================================================
        // PROJECT & TOOL MANAGEMENT ENDPOINTS (4 endpoints)
        // FrontEnd-level operations for project and tool management
        // ==========================================================================

        // PROJECT_INFO - Get detailed project info including running tools
        server.createContext("/project/info", safeHandler(exchange -> {
            sendResponse(exchange, getProjectInfo());
        }));

        // TOOL_RUNNING_TOOLS - List all running Ghidra tools
        server.createContext("/tool/running_tools", safeHandler(exchange -> {
            sendResponse(exchange, getRunningTools());
        }));

        // TOOL_LAUNCH_CODEBROWSER - Open a file in CodeBrowser (launches if needed)
        server.createContext("/tool/launch_codebrowser", safeHandler(exchange -> {
            Map<String, Object> params = parseJsonParams(exchange);
            String filePath = params.get("path") != null ? params.get("path").toString() : null;
            sendResponse(exchange, launchCodeBrowser(filePath));
        }));

        // SERVER_AUTHENTICATE - Register credentials for programmatic server authentication
        server.createContext("/server/authenticate", safeHandler(exchange -> {
            Map<String, Object> params = parseJsonParams(exchange);
            String username = params.get("username") != null ? params.get("username").toString() : null;
            String password = params.get("password") != null ? params.get("password").toString() : null;
            sendResponse(exchange, authenticateServer(username, password));
        }));

        server.setExecutor(null);
        new Thread(() -> {
            try {
                server.start();
                Msg.info(this, "GhidraMCP HTTP server started on port " + port);
            } catch (Exception e) {
                Msg.error(this, "Failed to start HTTP server on port " + port + ". Port might be in use.", e);
                server = null; // Ensure server isn't considered running
            }
        }, "GhidraMCP-HTTP-Server").start();
    }

    // ----------------------------------------------------------------------------------
    // Pagination-aware listing methods
    // ----------------------------------------------------------------------------------

    private String getAllFunctionNames(int offset, int limit, String programName) {
        return Response.r2s(listingService.getAllFunctionNames(offset, limit, programName));
    }

    // Backward compatible overload
    private String getAllFunctionNames(int offset, int limit) {
        return Response.r2s(listingService.getAllFunctionNames(offset, limit, null));
    }

    private String getAllClassNames(int offset, int limit, String programName) {
        return Response.r2s(listingService.getAllClassNames(offset, limit, programName));
    }

    // Backward compatible overload
    private String getAllClassNames(int offset, int limit) {
        return Response.r2s(listingService.getAllClassNames(offset, limit, null));
    }

    private String listSegments(int offset, int limit, String programName) {
        return Response.r2s(listingService.listSegments(offset, limit, programName));
    }

    // Backward compatible overload
    private String listSegments(int offset, int limit) {
        return Response.r2s(listingService.listSegments(offset, limit, null));
    }

    private String listImports(int offset, int limit, String programName) {
        return Response.r2s(listingService.listImports(offset, limit, programName));
    }

    // Backward compatible overload
    private String listImports(int offset, int limit) {
        return Response.r2s(listingService.listImports(offset, limit, null));
    }

    private String listExports(int offset, int limit, String programName) {
        return Response.r2s(listingService.listExports(offset, limit, programName));
    }

    // Backward compatible overload
    private String listExports(int offset, int limit) {
        return Response.r2s(listingService.listExports(offset, limit, null));
    }

    private String listNamespaces(int offset, int limit, String programName) {
        return Response.r2s(listingService.listNamespaces(offset, limit, programName));
    }

    // Backward compatible overload
    private String listNamespaces(int offset, int limit) {
        return Response.r2s(listingService.listNamespaces(offset, limit, null));
    }

    private String listDefinedData(int offset, int limit, String programName) {
        return Response.r2s(listingService.listDefinedData(offset, limit, programName));
    }

    // Backward compatible overload
    private String listDefinedData(int offset, int limit) {
        return Response.r2s(listingService.listDefinedData(offset, limit, null));
    }

    private String listDataItemsByXrefs(int offset, int limit, String format, String programName) {
        return Response.r2s(listingService.listDataItemsByXrefs(offset, limit, format, programName));
    }

    private String searchFunctionsByName(String searchTerm, int offset, int limit, String programName) {
        return Response.r2s(listingService.searchFunctionsByName(searchTerm, offset, limit, programName));
    }

    // Backward compatible overload
    private String searchFunctionsByName(String searchTerm, int offset, int limit) {
        return Response.r2s(listingService.searchFunctionsByName(searchTerm, offset, limit, null));
    }

    // ----------------------------------------------------------------------------------
    // Logic for rename, decompile, etc.
    // ----------------------------------------------------------------------------------

    private String decompileFunctionByName(String name) {
        return Response.r2s(functionService.decompileFunctionByName(name));
    }

    private String renameFunction(String oldName, String newName) {
        return Response.r2s(functionService.renameFunction(oldName, newName));
    }

    private String renameDataAtAddress(String addressStr, String newName) {
        return Response.r2s(symbolLabelService.renameDataAtAddress(addressStr, newName));
    }

    private String renameVariableInFunction(String functionName, String oldVarName, String newVarName) {
        return Response.r2s(functionService.renameVariableInFunction(functionName, oldVarName, newVarName));
    }

    // ----------------------------------------------------------------------------------
    // New methods to implement the new functionalities
    // ----------------------------------------------------------------------------------

    /**
     * Get function by address
     */
    private String getFunctionByAddress(String addressStr, String programName) {
        return Response.r2s(functionService.getFunctionByAddress(addressStr, programName));
    }

    // Backward compatibility overload
    private String getFunctionByAddress(String addressStr) {
        return Response.r2s(functionService.getFunctionByAddress(addressStr));
    }

    /**
     * Get current address selected in Ghidra GUI
     */
    private String getCurrentAddress() {
        CodeViewerService service = tool.getService(CodeViewerService.class);
        if (service == null) return "Code viewer service not available";

        ProgramLocation location = service.getCurrentLocation();
        return (location != null) ? location.getAddress().toString() : "No current location";
    }

    /**
     * Get current function selected in Ghidra GUI
     */
    private String getCurrentFunction() {
        CodeViewerService service = tool.getService(CodeViewerService.class);
        if (service == null) return "Code viewer service not available";

        ProgramLocation location = service.getCurrentLocation();
        if (location == null) return "No current location";

        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        Function func = program.getFunctionManager().getFunctionContaining(location.getAddress());
        if (func == null) return "No function at current location: " + location.getAddress();

        return String.format("Function: %s at %s\nSignature: %s",
            func.getName(),
            func.getEntryPoint(),
            func.getSignature());
    }

    /**
     * List all functions in the database
     */
    private String listFunctions(String programName) {
        return Response.r2s(listingService.listFunctions(programName));
    }

    private String listFunctionsEnhanced(int offset, int limit, String programName) {
        return Response.r2s(listingService.listFunctionsEnhanced(offset, limit, programName));
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

    private String decompileFunctionByAddress(String addressStr, String programName, int timeoutSeconds) {
        return Response.r2s(functionService.decompileFunctionByAddress(addressStr, programName, timeoutSeconds));
    }

    private String decompileFunctionByAddress(String addressStr, String programName) {
        return Response.r2s(functionService.decompileFunctionByAddress(addressStr, programName));
    }

    private String decompileFunctionByAddress(String addressStr) {
        return Response.r2s(functionService.decompileFunctionByAddress(addressStr));
    }

    private String disassembleFunction(String addressStr, String programName) {
        return Response.r2s(functionService.disassembleFunction(addressStr, programName));
    }

    private String disassembleFunction(String addressStr) {
        return Response.r2s(functionService.disassembleFunction(addressStr));
    }

    /**
     * Set a comment using the specified comment type (PRE_COMMENT or EOL_COMMENT)
     */
    @SuppressWarnings("deprecation")
    private String setCommentAtAddress(String addressStr, String comment, int commentType, String transactionName) {
        return Response.r2s(commentService.setCommentAtAddress(addressStr, comment, commentType, transactionName));
    }

    private String setDecompilerComment(String addressStr, String comment) {
        return Response.r2s(commentService.setDecompilerComment(addressStr, comment));
    }

    private String setDisassemblyComment(String addressStr, String comment) {
        return Response.r2s(commentService.setDisassemblyComment(addressStr, comment));
    }

    private String renameFunctionByAddress(String functionAddrStr, String newName) {
        return Response.r2s(functionService.renameFunctionByAddress(functionAddrStr, newName));
    }

    private com.xebyte.core.FunctionService.PrototypeResult setFunctionPrototype(String functionAddrStr, String prototype) {
        return functionService.setFunctionPrototype(functionAddrStr, prototype);
    }

    private com.xebyte.core.FunctionService.PrototypeResult setFunctionPrototype(String functionAddrStr, String prototype, String callingConvention) {
        return functionService.setFunctionPrototype(functionAddrStr, prototype, callingConvention);
    }

    private String listCallingConventions() {
        return Response.r2s(listingService.listCallingConventions(null));
    }

    private String setLocalVariableType(String functionAddrStr, String variableName, String newType) {
        return Response.r2s(functionService.setLocalVariableType(functionAddrStr, variableName, newType));
    }

    private String setFunctionNoReturn(String functionAddrStr, boolean noReturn) {
        return Response.r2s(functionService.setFunctionNoReturn(functionAddrStr, noReturn));
    }

    private String clearInstructionFlowOverride(String instructionAddrStr) {
        return Response.r2s(functionService.clearInstructionFlowOverride(instructionAddrStr));
    }

    private String setVariableStorage(String functionAddrStr, String variableName, String storageSpec) {
        return Response.r2s(functionService.setVariableStorage(functionAddrStr, variableName, storageSpec));
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
    private String runGhidraScript(String scriptPath, String scriptArgs) {
        return Response.r2s(programScriptService.runGhidraScript(scriptPath, scriptArgs));
    }

    /**
     * List available Ghidra scripts (v1.7.0)
     *
     * @param filter Optional filter string to match script names
     * @return JSON list of available scripts
     */
    private String listGhidraScripts(String filter) {
        return Response.r2s(programScriptService.listGhidraScripts(filter));
    }

    /**
     * Force decompiler reanalysis for a function (v1.7.0)
     *
     * Clears cached decompilation results and forces a fresh analysis.
     * Useful after making changes to function signatures, variables, or data types.
     *
     * @param functionAddrStr Function address to reanalyze
     * @return Success message with new decompilation
     */
    private String forceDecompile(String functionAddrStr) {
        return Response.r2s(functionService.forceDecompile(functionAddrStr));
    }

    /**
     * Get all references to a specific address (xref to)
     */
    private String getXrefsTo(String addressStr, int offset, int limit, String programName) {
        return Response.r2s(xrefCallGraphService.getXrefsTo(addressStr, offset, limit, programName));
    }

    /**
     * Get all references from a specific address (xref from)
     */
    private String getXrefsFrom(String addressStr, int offset, int limit, String programName) {
        return Response.r2s(xrefCallGraphService.getXrefsFrom(addressStr, offset, limit, programName));
    }

    /**
     * Get all references to a specific function by name
     */
    private String getFunctionXrefs(String functionName, int offset, int limit, String programName) {
        return Response.r2s(xrefCallGraphService.getFunctionXrefs(functionName, offset, limit, programName));
    }

/**
 * List all defined strings in the program with their addresses
 */
    private String listDefinedStrings(int offset, int limit, String filter, String programName) {
        return Response.r2s(listingService.listDefinedStrings(offset, limit, filter, programName));
    }

    private String getFunctionCount(String programName) {
        return Response.r2s(listingService.getFunctionCount(programName));
    }

    private String searchStrings(String query, int minLength, String encoding, int offset, int limit, String programName) {
        return Response.r2s(listingService.searchStrings(query, minLength, encoding, offset, limit, programName));
    }

    /**
     * List all registered analyzers and their enabled/disabled state.
     */
    private String listAnalyzers(String programName) {
        return Response.r2s(analysisService.listAnalyzers(programName));
    }

    /**
     * Trigger auto-analysis on the current or named program.
     */
    private String runAnalysis(String programName) {
        return Response.r2s(analysisService.runAnalysis(programName));
    }

    /**
     * Check if the given data is a string type
     */
    private boolean isStringData(Data data) {
        if (data == null) return false;

        DataType dt = data.getDataType();
        String typeName = dt.getName().toLowerCase();
        return typeName.contains("string") || typeName.contains("char") || typeName.equals("unicode");
    }

    /**
     * Check if a string meets quality criteria for listing
     * - Minimum length of 4 characters
     * - At least 80% printable ASCII characters
     */
    private boolean isQualityString(String str) {
        if (str == null || str.length() < 4) {
            return false;
        }

        int printableCount = 0;
        for (int i = 0; i < str.length(); i++) {
            char c = str.charAt(i);
            // Printable ASCII: space (32) to tilde (126), plus common whitespace
            if ((c >= 32 && c < 127) || c == '\n' || c == '\r' || c == '\t') {
                printableCount++;
            }
        }

        double printableRatio = (double) printableCount / str.length();
        return printableRatio >= 0.80;
    }

    /**
     * Escape special characters in a string for display
     */
    private String escapeString(String input) {
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
                sb.append(String.format("\\x%02x", (int)c & 0xFF));
            }
        }
        return sb.toString();
    }

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

    // ----------------------------------------------------------------------------------
    // Utility: parse query params, parse post params, pagination, etc.
    // ----------------------------------------------------------------------------------

    /**
     * Parse query parameters from the URL, e.g. ?offset=10&limit=100
     */
    private Map<String, String> parseQueryParams(HttpExchange exchange) {
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
    private Map<String, String> parsePostParams(HttpExchange exchange) throws IOException {
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

    /**
     * Parse JSON from POST request body
     */
    private Map<String, Object> parseJsonParams(HttpExchange exchange) throws IOException {
        byte[] body = exchange.getRequestBody().readAllBytes();
        String bodyStr = new String(body, StandardCharsets.UTF_8);
        
        // Simple JSON parsing - this is a basic implementation
        // In a production environment, you'd want to use a proper JSON library
        Map<String, Object> result = new HashMap<>();
        
        if (bodyStr.trim().isEmpty()) {
            return result;
        }
        
        try {
            // Remove outer braces and parse key-value pairs
            String content = bodyStr.trim();
            if (content.startsWith("{") && content.endsWith("}")) {
                content = content.substring(1, content.length() - 1).trim();
                
                // Simple parsing - split by commas but handle nested objects/arrays
                String[] parts = splitJsonPairs(content);
                
                for (String part : parts) {
                    String[] kv = part.split(":", 2);
                    if (kv.length == 2) {
                        String key = kv[0].trim().replaceAll("^\"|\"$", "");
                        String value = kv[1].trim();
                        
                        // Handle different value types
                        if (value.startsWith("\"") && value.endsWith("\"")) {
                            // String value — unescape JSON escape sequences
                            result.put(key, unescapeJsonString(value.substring(1, value.length() - 1)));
                        } else if (value.startsWith("[") && value.endsWith("]")) {
                            // Array value - parse into List
                            result.put(key, parseJsonArray(value));
                        } else if (value.startsWith("{") && value.endsWith("}")) {
                            // Object value - parse into nested Map
                            Map<String, String> nestedMap = new LinkedHashMap<>();
                            String inner = value.substring(1, value.length() - 1).trim();
                            if (!inner.isEmpty()) {
                                String[] nestedParts = splitJsonPairs(inner);
                                for (String np : nestedParts) {
                                    String[] nkv = np.split(":", 2);
                                    if (nkv.length == 2) {
                                        String nkey = nkv[0].trim().replaceAll("^\"|\"$", "");
                                        String nval = nkv[1].trim();
                                        if (nval.startsWith("\"") && nval.endsWith("\"")) {
                                            nval = unescapeJsonString(nval.substring(1, nval.length() - 1));
                                        }
                                        nestedMap.put(nkey, nval);
                                    }
                                }
                            }
                            result.put(key, nestedMap);
                        } else if (value.matches("\\d+")) {
                            // Integer value
                            result.put(key, Integer.parseInt(value));
                        } else {
                            // Default to string
                            result.put(key, value);
                        }
                    }
                }
            }
        } catch (Exception e) {
            Msg.error(this, "Error parsing JSON: " + e.getMessage(), e);
        }
        
        return result;
    }
    
    /**
     * Split JSON content by commas, but respect nested braces and brackets
     */
    private String[] splitJsonPairs(String content) {
        List<String> parts = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        int braceDepth = 0;
        int bracketDepth = 0;
        boolean inString = false;
        boolean escaped = false;
        
        for (char c : content.toCharArray()) {
            if (escaped) {
                escaped = false;
                current.append(c);
                continue;
            }
            
            if (c == '\\' && inString) {
                escaped = true;
                current.append(c);
                continue;
            }
            
            if (c == '"') {
                inString = !inString;
                current.append(c);
                continue;
            }
            
            if (!inString) {
                if (c == '{') braceDepth++;
                else if (c == '}') braceDepth--;
                else if (c == '[') bracketDepth++;
                else if (c == ']') bracketDepth--;
                else if (c == ',' && braceDepth == 0 && bracketDepth == 0) {
                    parts.add(current.toString().trim());
                    current = new StringBuilder();
                    continue;
                }
            }
            
            current.append(c);
        }
        
        if (current.length() > 0) {
            parts.add(current.toString().trim());
        }
        
        return parts.toArray(new String[0]);
    }

    /**
     * Parse a JSON array string into a List of Objects (can be Strings or Maps)
     * Example: "[\"0x6FAC8A58\", \"0x6FAC8A5C\"]" -> List<String>
     * Example: "[{\"address\": \"0x...\", \"comment\": \"...\"}]" -> List<Map<String, String>>
     */
    private List<Object> parseJsonArray(String arrayStr) {
        List<Object> result = new ArrayList<>();

        if (arrayStr == null || !arrayStr.startsWith("[") || !arrayStr.endsWith("]")) {
            return result;
        }

        // Remove outer brackets
        String content = arrayStr.substring(1, arrayStr.length() - 1).trim();

        if (content.isEmpty()) {
            return result;
        }

        // Split by comma, but respect quoted strings and nested objects/arrays
        StringBuilder current = new StringBuilder();
        boolean inString = false;
        boolean escaped = false;
        int braceDepth = 0;
        int bracketDepth = 0;

        for (char c : content.toCharArray()) {
            if (escaped) {
                escaped = false;
                current.append(c);
                continue;
            }

            if (c == '\\' && inString) {
                escaped = true;
                current.append(c);
                continue;
            }

            if (c == '"') {
                inString = !inString;
                current.append(c);
                continue;
            }

            if (!inString) {
                if (c == '{') braceDepth++;
                else if (c == '}') braceDepth--;
                else if (c == '[') bracketDepth++;
                else if (c == ']') bracketDepth--;
                else if (c == ',' && braceDepth == 0 && bracketDepth == 0) {
                    // End of current element
                    String element = current.toString().trim();
                    if (!element.isEmpty()) {
                        result.add(parseJsonElement(element));
                    }
                    current = new StringBuilder();
                    continue;
                }
            }

            current.append(c);
        }

        // Add last element
        String element = current.toString().trim();
        if (!element.isEmpty()) {
            result.add(parseJsonElement(element));
        }

        return result;
    }

    /**
     * Parse a single JSON element (string, number, object, array, etc.)
     */
    private Object parseJsonElement(String element) {
        element = element.trim();

        // String
        if (element.startsWith("\"") && element.endsWith("\"")) {
            return element.substring(1, element.length() - 1);
        }

        // Object
        if (element.startsWith("{") && element.endsWith("}")) {
            return parseJsonObject(element);
        }

        // Array
        if (element.startsWith("[") && element.endsWith("]")) {
            return parseJsonArray(element);
        }

        // Number
        if (element.matches("-?\\d+")) {
            return Integer.parseInt(element);
        }

        // Boolean
        if (element.equals("true")) return true;
        if (element.equals("false")) return false;

        // Null
        if (element.equals("null")) return null;

        // Default to string
        return element;
    }

    /**
     * Parse a JSON object string into a Map<String, String>
     * Example: "{\"address\": \"0x...\", \"comment\": \"...\"}" -> Map
     */
    private Map<String, String> parseJsonObject(String objectStr) {
        Map<String, String> result = new HashMap<>();

        if (objectStr == null || !objectStr.startsWith("{") || !objectStr.endsWith("}")) {
            return result;
        }

        // Remove outer braces
        String content = objectStr.substring(1, objectStr.length() - 1).trim();

        if (content.isEmpty()) {
            return result;
        }

        // Split by commas, respecting nested structures
        String[] pairs = splitJsonPairs(content);

        for (String pair : pairs) {
            String[] kv = pair.split(":", 2);
            if (kv.length == 2) {
                String key = kv[0].trim().replaceAll("^\"|\"$", "");
                String value = kv[1].trim();

                // Remove quotes from string values
                if (value.startsWith("\"") && value.endsWith("\"")) {
                    value = value.substring(1, value.length() - 1);
                }

                result.put(key, value);
            }
        }

        return result;
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

    private double parseDoubleOrDefault(String val, double defaultValue) {
        if (val == null) return defaultValue;
        try {
            return Double.parseDouble(val);
        }
        catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    /**
     * Escape non-ASCII chars to avoid potential decode issues.
     */
    private String escapeNonAscii(String input) {
        if (input == null) return "";
        StringBuilder sb = new StringBuilder();
        for (char c : input.toCharArray()) {
            if (c >= 32 && c < 127) {
                sb.append(c);
            }
            else {
                sb.append("\\x");
                sb.append(Integer.toHexString(c & 0xFF));
            }
        }
        return sb.toString();
    }

    public Program getCurrentProgram() {
        return programProvider.getCurrentProgram();
    }

    /**
     * Get a program by name, or return the current program if name is null/empty.
     * Delegates to FrontEndProgramProvider which checks CodeBrowser, cache, and project.
     *
     * @param programName The name or project path (e.g., "/LoD/1.00/D2Common.dll"), or null/empty for current
     * @return The requested program, or null if not found
     */
    public Program getProgram(String programName) {
        return programProvider.resolveProgram(programName);
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
            // Program was explicitly requested but not found - provide helpful error
            StringBuilder error = new StringBuilder();
            error.append("{\"error\": \"Program not found: ").append(escapeJson(programName)).append("\", ");
            error.append("\"hint\": \"Use full project path (e.g., /LoD/1.00/D2Common.dll) to open on-demand\", ");
            error.append("\"available_programs\": [");

            Program[] programs = programProvider.getAllOpenPrograms();
            for (int i = 0; i < programs.length; i++) {
                if (i > 0) error.append(", ");
                error.append("\"").append(escapeJson(programs[i].getName())).append("\"");
            }
            error.append("]}");

            return new Object[] { null, error.toString() };
        }

        if (program == null) {
            return new Object[] { null, "{\"error\": \"No program currently loaded. Use the 'program' parameter with a project path to open one.\"}" };
        }

        return new Object[] { program, null };
    }

    // ----------------------------------------------------------------------------------
    // Program Management Methods
    // ----------------------------------------------------------------------------------

    /**
     * List all currently open programs in Ghidra
     */
    private String saveCurrentProgram() {
        return Response.r2s(programScriptService.saveCurrentProgram());
    }

    private String listOpenPrograms() {
        return Response.r2s(programScriptService.listOpenPrograms());
    }

    /**
     * Get detailed information about the currently active program
     */
    private String getCurrentProgramInfo() {
        return Response.r2s(programScriptService.getCurrentProgramInfo());
    }

    /**
     * Switch MCP context to a different open program by name
     */
    private String switchProgram(String programName) {
        return Response.r2s(programScriptService.switchProgram(programName));
    }

    /**
     * List all files in the current Ghidra project
     */
    private String listProjectFiles(String folderPath) {
        return Response.r2s(programScriptService.listProjectFiles(folderPath));
    }

    /**
     * Open a program from the current project by path
     */
    private String openProgramFromProject(String path) {
        return Response.r2s(programScriptService.openProgramFromProject(path));
    }

    private String openProgramFromProject(String path, boolean autoAnalyze) {
        return Response.r2s(programScriptService.openProgramFromProject(path, autoAnalyze));
    }

    // ====================================================================================
    // FUNCTION HASH INDEX - Cross-binary documentation propagation
    // ====================================================================================

    /**
     * Compute a normalized opcode hash for a function.
     * The hash normalizes:
     * - Absolute addresses (call targets, jump targets, data refs) are replaced with placeholders
     * - Register-based operations are preserved
     * - Instruction mnemonics and operand types are included
     * 
     * This allows matching identical functions that are located at different addresses.
     */
    private String getFunctionHash(String functionAddress, String programName) {
        return Response.r2s(documentationHashService.getFunctionHash(functionAddress, programName));
    }

    // Backward compatibility overload
    private String getFunctionHash(String functionAddress) {
        return Response.r2s(documentationHashService.getFunctionHash(functionAddress));
    }

    private String getBulkFunctionHashes(int offset, int limit, String filter, String programName) {
        return Response.r2s(documentationHashService.getBulkFunctionHashes(offset, limit, filter, programName));
    }

    // Backward compatibility overload
    private String getBulkFunctionHashes(int offset, int limit, String filter) {
        return Response.r2s(documentationHashService.getBulkFunctionHashes(offset, limit, filter));
    }

    /**
     * Export all documentation for a function (for use in cross-binary propagation)
     */
    private String getFunctionDocumentation(String functionAddress) {
        return Response.r2s(documentationHashService.getFunctionDocumentation(functionAddress));
    }

    private String applyFunctionDocumentation(String jsonBody) {
        return Response.r2s(documentationHashService.applyFunctionDocumentation(jsonBody));
    }

    /**
     * Wraps an HttpHandler so that any Throwable is caught and returned as a JSON error response.
     * This prevents uncaught exceptions from crashing the HTTP server and dropping connections.
     */
    private com.sun.net.httpserver.HttpHandler safeHandler(com.sun.net.httpserver.HttpHandler handler) {
        return exchange -> {
            try {
                handler.handle(exchange);
            } catch (Throwable e) {
                try {
                    String msg = e.getMessage() != null ? e.getMessage() : e.toString();
                    String safeMsg = msg.replace("\\", "\\\\").replace("\"", "\\\"")
                                       .replace("\n", "\\n").replace("\r", "\\r");
                    sendResponse(exchange, "{\"error\": \"" + safeMsg + "\"}");
                } catch (Throwable ignored) {
                    // Last resort - response already sent or exchange broken
                    Msg.error(this, "Failed to send error response", ignored);
                }
            }
        };
    }

    private void sendResponse(HttpExchange exchange, String response) throws IOException {
        // Always return 200 — error information is in the response body.
        // The MCP bridge parses the body for errors; non-200 codes cause
        // misinterpretation (e.g. 404 treated as "endpoint not found").
        int statusCode = 200;

        byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
        Headers headers = exchange.getResponseHeaders();
        headers.set("Content-Type", "text/plain; charset=utf-8");
        // v1.6.1: Enable HTTP keep-alive for long-running operations
        headers.set("Connection", "keep-alive");
        headers.set("Keep-Alive", "timeout=" + HTTP_IDLE_TIMEOUT_SECONDS + ", max=100");
        exchange.sendResponseHeaders(statusCode, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
            os.flush();  // v1.7.2: Explicit flush to ensure response is sent immediately
        }
    }

    /**
     * Get labels within a specific function by name
     */
    public String getFunctionLabels(String functionName, int offset, int limit) {
        return Response.r2s(symbolLabelService.getFunctionLabels(functionName, offset, limit));
    }

    public String renameLabel(String addressStr, String oldName, String newName) {
        return Response.r2s(symbolLabelService.renameLabel(addressStr, oldName, newName));
    }

    /**
     * Get all jump target addresses from a function's disassembly
     */
    public String getFunctionJumpTargets(String functionName, int offset, int limit) {
        return Response.r2s(xrefCallGraphService.getFunctionJumpTargets(functionName, offset, limit));
    }

    public String createLabel(String addressStr, String labelName) {
        return Response.r2s(symbolLabelService.createLabel(addressStr, labelName));
    }

    public String batchCreateLabels(List<Map<String, String>> labels) {
        return Response.r2s(symbolLabelService.batchCreateLabels(labels));
    }

    public String renameOrLabel(String addressStr, String newName) {
        return Response.r2s(symbolLabelService.renameOrLabel(addressStr, newName));
    }

    public String deleteLabel(String addressStr, String labelName) {
        return Response.r2s(symbolLabelService.deleteLabel(addressStr, labelName));
    }

    public String batchDeleteLabels(List<Map<String, String>> labels) {
        return Response.r2s(symbolLabelService.batchDeleteLabels(labels));
    }

    /**
     * Get all functions called by the specified function (callees)
     */
    public String getFunctionCallees(String functionName, int offset, int limit, String programName) {
        return Response.r2s(xrefCallGraphService.getFunctionCallees(functionName, offset, limit, programName));
    }

    /**
     * Get all functions that call the specified function (callers)
     */
    public String getFunctionCallers(String functionName, int offset, int limit, String programName) {
        return Response.r2s(xrefCallGraphService.getFunctionCallers(functionName, offset, limit, programName));
    }

    /**
     * Get a call graph subgraph centered on the specified function
     */
    public String getFunctionCallGraph(String functionName, int depth, String direction, String programName) {
        return Response.r2s(xrefCallGraphService.getFunctionCallGraph(functionName, depth, direction, programName));
    }

    /**
     * Get the complete call graph for the entire program
     */
    public String getFullCallGraph(String format, int limit, String programName) {
        return Response.r2s(xrefCallGraphService.getFullCallGraph(format, limit, programName));
    }

    /**
     * Enhanced call graph analysis with cycle detection and path finding
     * Provides advanced graph algorithms for understanding function relationships
     */
    public String analyzeCallGraph(String startFunction, String endFunction, String analysisType, String programName) {
        return Response.r2s(xrefCallGraphService.analyzeCallGraph(startFunction, endFunction, analysisType, programName));
    }

    /**
     * List all data types available in the program with optional category filtering
     */
    public String listDataTypes(String category, int offset, int limit, String programName) {
        return Response.r2s(dataTypeService.listDataTypes(category, offset, limit, programName));
    }

    // Backward compatibility overload
    public String listDataTypes(String category, int offset, int limit) {
        return Response.r2s(dataTypeService.listDataTypes(category, offset, limit));
    }

    /**
     * Create a new structure data type with specified fields
     */
    public String createStruct(String name, String fieldsJson) {
        return Response.r2s(dataTypeService.createStruct(name, fieldsJson));
    }

    /**
     * Create a new enumeration data type with name-value pairs
     */
    public String createEnum(String name, String valuesJson, int size) {
        return Response.r2s(dataTypeService.createEnum(name, valuesJson, size));
    }

    /**
     * Serialize a List of objects to proper JSON string
     * Handles Map objects within the list
     */
    private String serializeListToJson(java.util.List<?> list) {
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < list.size(); i++) {
            if (i > 0) sb.append(",");
            Object item = list.get(i);
            if (item instanceof String) {
                sb.append("\"").append(escapeJsonString((String) item)).append("\"");
            } else if (item instanceof Number) {
                sb.append(item);
            } else if (item instanceof java.util.Map) {
                sb.append(serializeMapToJson((java.util.Map<?, ?>) item));
            } else if (item instanceof java.util.List) {
                sb.append(serializeListToJson((java.util.List<?>) item));
            } else {
                sb.append("\"").append(escapeJsonString(item.toString())).append("\"");
            }
        }
        sb.append("]");
        return sb.toString();
    }

    /**
     * Serialize a Map to proper JSON object
     */
    private String serializeMapToJson(java.util.Map<?, ?> map) {
        StringBuilder sb = new StringBuilder("{");
        boolean first = true;
        for (java.util.Map.Entry<?, ?> entry : map.entrySet()) {
            if (!first) sb.append(",");
            first = false;
            sb.append("\"").append(escapeJsonString(entry.getKey().toString())).append("\":");
            Object value = entry.getValue();
            if (value instanceof String) {
                sb.append("\"").append(escapeJsonString((String) value)).append("\"");
            } else if (value instanceof Number) {
                sb.append(value);
            } else if (value instanceof java.util.Map) {
                sb.append(serializeMapToJson((java.util.Map<?, ?>) value));
            } else if (value instanceof java.util.List) {
                sb.append(serializeListToJson((java.util.List<?>) value));
            } else if (value instanceof Boolean) {
                sb.append(value);
            } else if (value == null) {
                sb.append("null");
            } else {
                sb.append("\"").append(escapeJsonString(value.toString())).append("\"");
            }
        }
        sb.append("}");
        return sb.toString();
    }

    /**
     * Escape special characters in JSON string values
     */
    private String escapeJsonString(String str) {
        if (str == null) return "";
        return str.replace("\\", "\\\\")
                  .replace("\"", "\\\"")
                  .replace("\n", "\\n")
                  .replace("\r", "\\r")
                  .replace("\t", "\\t");
    }

    /**
     * Unescape JSON string escape sequences: \n → newline, \" → quote, \\ → backslash, etc.
     */
    private static String unescapeJsonString(String s) {
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
                        // Unicode escape: backslash-u + 4 hex digits
                        if (i + 5 < s.length()) {
                            try {
                                int cp = Integer.parseInt(s.substring(i + 2, i + 6), 16);
                                sb.append((char) cp);
                                i += 5;
                            } catch (NumberFormatException e) {
                                sb.append(c); // malformed, keep as-is
                            }
                        } else {
                            sb.append(c);
                        }
                        break;
                    default:
                        sb.append(c); // unknown escape, keep backslash
                        break;
                }
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    /**
     * Apply a specific data type at the given memory address
     */
    public String applyDataType(String addressStr, String typeName, boolean clearExisting) {
        return Response.r2s(dataTypeService.applyDataType(addressStr, typeName, clearExisting));
    }

    /**
     * Check if the plugin is running and accessible
     */
    private String checkConnection() {
        Program program = getCurrentProgram();
        if (program == null) {
            return "Connected: GhidraMCP plugin running, but no program loaded";
        }
        return "Connected: GhidraMCP plugin running with program '" + program.getName() + "'";
    }

    /**
     * Get version information about the plugin and Ghidra (v1.7.0)
     */
    private String getVersion() {
        StringBuilder version = new StringBuilder();
        version.append("{\n");
        version.append("  \"plugin_version\": \"").append(VersionInfo.getVersion()).append("\",\n");
        version.append("  \"plugin_name\": \"").append(VersionInfo.getAppName()).append("\",\n");
        version.append("  \"build_timestamp\": \"").append(VersionInfo.getBuildTimestamp()).append("\",\n");
        version.append("  \"build_number\": \"").append(VersionInfo.getBuildNumber()).append("\",\n");
        version.append("  \"full_version\": \"").append(VersionInfo.getFullVersion()).append("\",\n");
        version.append("  \"ghidra_version\": \"").append(VersionInfo.getGhidraVersion()).append("\",\n");
        version.append("  \"java_version\": \"").append(System.getProperty("java.version")).append("\",\n");
        version.append("  \"endpoint_count\": ").append(VersionInfo.getEndpointCount()).append("\n");
        version.append("}");
        return version.toString();
    }

    /**
     * Get metadata about the current program
     */
    private String getMetadata() {
        return Response.r2s(programScriptService.getMetadata());
    }

    /**
     * Convert a number to different representations
     */
    private String convertNumber(String text, int size) {
        return com.xebyte.core.ServiceUtils.convertNumber(text, size);
    }

    /**
     * List global variables/symbols with optional filtering
     */
    private String listGlobals(int offset, int limit, String filter, String programName) {
        return Response.r2s(listingService.listGlobals(offset, limit, filter, programName));
    }

    private String renameGlobalVariable(String oldName, String newName) {
        return Response.r2s(symbolLabelService.renameGlobalVariable(oldName, newName));
    }

    /**
     * Get all entry points in the program
     */
    private String getEntryPoints() {
        return Response.r2s(listingService.getEntryPoints(null));
    }

    // ----------------------------------------------------------------------------------
    // Data Type Analysis and Management Methods
    // ----------------------------------------------------------------------------------

    /**
     * Create a union data type with simplified approach for testing
     */
    private String createUnionSimple(String name, Object fieldsObj) {
        // Even simpler test - don't access any Ghidra APIs
        if (name == null || name.isEmpty()) return "Union name is required";
        if (fieldsObj == null) return "Fields are required";
        
        return "Union endpoint test successful - name: " + name;
    }

    /**
     * Create a union data type directly from fields object
     */
    private String createUnionDirect(String name, Object fieldsObj) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (name == null || name.isEmpty()) return "Union name is required";
        if (fieldsObj == null) return "Fields are required";

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
                        @SuppressWarnings("unchecked")
                        java.util.List<Object> fieldsList = (java.util.List<Object>) fieldsObj;
                        
                        for (Object fieldObj : fieldsList) {
                            if (fieldObj instanceof java.util.Map) {
                                @SuppressWarnings("unchecked")
                                java.util.Map<String, Object> fieldMap = (java.util.Map<String, Object>) fieldObj;
                                
                                String fieldName = (String) fieldMap.get("name");
                                String fieldType = (String) fieldMap.get("type");
                                
                                if (fieldName != null && fieldType != null) {
                                    DataType dt = findDataTypeByNameInAllCategories(dtm, fieldType);
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

        return result.toString();
    }

    /**
     * Create a union data type (legacy method)
     */
    private String createUnion(String name, String fieldsJson) {
        return Response.r2s(dataTypeService.createUnion(name, fieldsJson));
    }

    /**
     * Get the size of a data type
     */
    private String getTypeSize(String typeName) {
        return Response.r2s(dataTypeService.getTypeSize(typeName));
    }

    /**
     * Get the layout of a structure
     */
    private String getStructLayout(String structName) {
        return Response.r2s(dataTypeService.getStructLayout(structName));
    }

    /**
     * Search for data types by pattern
     */
    private String searchDataTypes(String pattern, int offset, int limit) {
        return Response.r2s(dataTypeService.searchDataTypes(pattern, offset, limit));
    }

    /**
     * Get all values in an enumeration
     */
    private String getEnumValues(String enumName) {
        return Response.r2s(dataTypeService.getEnumValues(enumName));
    }

    /**
     * Create a typedef (type alias)
     */
    private String createTypedef(String name, String baseType) {
        return Response.r2s(dataTypeService.createTypedef(name, baseType));
    }

    /**
     * Clone/copy a data type with a new name
     */
    private String cloneDataType(String sourceType, String newName) {
        return Response.r2s(dataTypeService.cloneDataType(sourceType, newName));
    }

    /**
     * Validate if a data type fits at a given address
     */
    private String validateDataType(String addressStr, String typeName) {
        return Response.r2s(dataTypeService.validateDataType(addressStr, typeName));
    }

    /**
     * Read memory at a specific address
     */
    private String readMemory(String addressStr, int length, String programName) {
        return Response.r2s(programScriptService.readMemory(addressStr, length, programName));
    }

    // Backward compatibility overload
    private String readMemory(String addressStr, int length) {
        return Response.r2s(programScriptService.readMemory(addressStr, length, null));
    }

    /**
     * Create an uninitialized memory block (e.g., for MMIO/peripheral regions).
     */
    private String createMemoryBlock(String name, String addressStr, long size,
                                     boolean read, boolean write, boolean execute,
                                     boolean isVolatile, String comment) {
        return Response.r2s(programScriptService.createMemoryBlock(name, addressStr, size, read, write, execute, isVolatile, comment));
    }

    /**
     * Import data types from various sources
     */
    private String importDataTypes(String source, String format) {
        return Response.r2s(dataTypeService.importDataTypes(source, format));
    }

    /**
     * Helper method to extract JSON values from simple JSON strings
     */
    private String extractJsonValue(String json, String key) {
        String searchPattern = "\"" + key + "\"\\s*:\\s*\"([^\"]+)\"";
        java.util.regex.Pattern pattern = java.util.regex.Pattern.compile(searchPattern);
        java.util.regex.Matcher matcher = pattern.matcher(json);
        if (matcher.find()) {
            return matcher.group(1);
        }
        return null;
    }

    /**
     * Convert an object to JSON string format
     */
    private String convertToJsonString(Object obj) {
        if (obj == null) return null;
        
        if (obj instanceof java.util.List) {
            java.util.List<?> list = (java.util.List<?>) obj;
            StringBuilder json = new StringBuilder("[");
            
            for (int i = 0; i < list.size(); i++) {
                if (i > 0) json.append(",");
                Object item = list.get(i);
                
                if (item instanceof java.util.Map) {
                    java.util.Map<?, ?> map = (java.util.Map<?, ?>) item;
                    json.append("{");
                    boolean first = true;
                    for (java.util.Map.Entry<?, ?> entry : map.entrySet()) {
                        if (!first) json.append(",");
                        json.append("\"").append(entry.getKey()).append("\":\"")
                            .append(entry.getValue()).append("\"");
                        first = false;
                    }
                    json.append("}");
                } else {
                    json.append("\"").append(item).append("\"");
                }
            }
            json.append("]");
            return json.toString();
        }
        
        return obj.toString();
    }

    // ===================================================================================
    // NEW DATA STRUCTURE MANAGEMENT METHODS
    // ===================================================================================

    /**
     * Delete a data type from the program
     */
    private String deleteDataType(String typeName) {
        return Response.r2s(dataTypeService.deleteDataType(typeName));
    }

    /**
     * Modify a field in an existing structure
     */
    private String modifyStructField(String structName, String fieldName, String newType, String newName) {
        return Response.r2s(dataTypeService.modifyStructField(structName, fieldName, newType, newName));
    }

    /**
     * Add a new field to an existing structure
     */
    private String addStructField(String structName, String fieldName, String fieldType, int offset) {
        return Response.r2s(dataTypeService.addStructField(structName, fieldName, fieldType, offset));
    }

    /**
     * Remove a field from an existing structure
     */
    private String removeStructField(String structName, String fieldName) {
        return Response.r2s(dataTypeService.removeStructField(structName, fieldName));
    }

    /**
     * Create an array data type
     */
    private String createArrayType(String baseType, int length, String name) {
        return Response.r2s(dataTypeService.createArrayType(baseType, length, name));
    }

    /**
     * Create a pointer data type
     */
    private String createPointerType(String baseType, String name) {
        return Response.r2s(dataTypeService.createPointerType(baseType, name));
    }

    /**
     * Create a new data type category
     */
    private String createDataTypeCategory(String categoryPath) {
        return Response.r2s(dataTypeService.createDataTypeCategory(categoryPath));
    }

    /**
     * Move a data type to a different category
     */
    private String moveDataTypeToCategory(String typeName, String categoryPath) {
        return Response.r2s(dataTypeService.moveDataTypeToCategory(typeName, categoryPath));
    }

    /**
     * List all data type categories
     */
    private String listDataTypeCategories(int offset, int limit) {
        return Response.r2s(dataTypeService.listDataTypeCategories(offset, limit));
    }

    /**
     * Create a function signature data type
     */
    private String createFunctionSignature(String name, String returnType, String parametersJson) {
        return Response.r2s(dataTypeService.createFunctionSignature(name, returnType, parametersJson));
    }

    // ==========================================================================
    // HIGH-PERFORMANCE DATA ANALYSIS METHODS (v1.3.0)
    // ==========================================================================

    /**
     * Helper to parse boolean from Object (can be Boolean or String "true"/"false")
     */
    private boolean parseBoolOrDefault(Object obj, boolean defaultValue) {
        if (obj == null) return defaultValue;
        if (obj instanceof Boolean) return (Boolean) obj;
        if (obj instanceof String) return Boolean.parseBoolean((String) obj);
        return defaultValue;
    }

    /**
     * Helper to escape strings for JSON
     */
    private String escapeJson(String str) {
        if (str == null) return "";
        return str.replace("\\", "\\\\")
                  .replace("\"", "\\\"")
                  .replace("\n", "\\n")
                  .replace("\r", "\\r")
                  .replace("\t", "\\t");
    }

    /**
     * Check if a function name is auto-generated (not user-assigned).
     * Covers FUN_, Ordinal_, and thunk variants of both.
     */
    private static boolean isAutoGeneratedName(String name) {
        return name.startsWith("FUN_") || name.startsWith("Ordinal_") ||
               name.startsWith("thunk_FUN_") || name.startsWith("thunk_Ordinal_");
    }

    /**
     * 1. GET_BULK_XREFS - Retrieve xrefs for multiple addresses in one call
     */
    private String getBulkXrefs(Object addressesObj) {
        return Response.r2s(xrefCallGraphService.getBulkXrefs(addressesObj));
    }

    /**
     * 2. ANALYZE_DATA_REGION - Comprehensive single-call data analysis
     */
    private String analyzeDataRegion(String startAddressStr, int maxScanBytes,
                                      boolean includeXrefMap, boolean includeAssemblyPatterns,
                                      boolean includeBoundaryDetection) {
        return Response.r2s(analysisService.analyzeDataRegion(startAddressStr, maxScanBytes, includeXrefMap, includeAssemblyPatterns, includeBoundaryDetection));
    }

    /**
     * 3. DETECT_ARRAY_BOUNDS - Array/table size detection
     */
    private String detectArrayBounds(String addressStr, boolean analyzeLoopBounds,
                                      boolean analyzeIndexing, int maxScanRange) {
        return Response.r2s(analysisService.detectArrayBounds(addressStr, analyzeLoopBounds, analyzeIndexing, maxScanRange));
    }

    /**
     * 4. GET_ASSEMBLY_CONTEXT - Assembly pattern analysis
     */
    private String getAssemblyContext(Object xrefSourcesObj, int contextInstructions,
                                      Object includePatternsObj) {
        return Response.r2s(xrefCallGraphService.getAssemblyContext(xrefSourcesObj, contextInstructions, includePatternsObj));
    }

    /**
     * 6. APPLY_DATA_CLASSIFICATION - Atomic type application
     */
    private String applyDataClassification(String addressStr, String classification,
                                           String name, String comment,
                                           Object typeDefinitionObj) {
        return Response.r2s(dataTypeService.applyDataClassification(addressStr, classification, name, comment, typeDefinitionObj));
    }

    /**
     * === FIELD-LEVEL ANALYSIS IMPLEMENTATIONS (v1.4.0) ===
     */

    /**
     * ANALYZE_STRUCT_FIELD_USAGE - Analyze how structure fields are accessed in decompiled code
     *
     * This method decompiles all functions that reference a structure and extracts usage patterns
     * for each field, including variable names, access types, and purposes.
     *
     * @param addressStr Address of the structure instance
     * @param structName Name of the structure type (optional - can be inferred if null)
     * @param maxFunctionsToAnalyze Maximum number of referencing functions to analyze
     * @return JSON string with field usage analysis
     */
    private String analyzeStructFieldUsage(String addressStr, String structName, int maxFunctionsToAnalyze) {
        return Response.r2s(dataTypeService.analyzeStructFieldUsage(addressStr, structName, maxFunctionsToAnalyze));
    }

    /**
     * GET_FIELD_ACCESS_CONTEXT - Get assembly/decompilation context for specific field offsets
     *
     * @param structAddressStr Address of the structure instance
     * @param fieldOffset Offset of the field within the structure
     * @param numExamples Number of usage examples to return
     * @return JSON string with field access contexts
     */
    private String getFieldAccessContext(String structAddressStr, int fieldOffset, int numExamples) {
        return Response.r2s(analysisService.getFieldAccessContext(structAddressStr, fieldOffset, numExamples));
    }

    /**
     * SUGGEST_FIELD_NAMES - AI-assisted field name suggestions based on usage patterns
     *
     * @param structAddressStr Address of the structure instance
     * @param structSize Size of the structure in bytes (0 for auto-detect)
     * @return JSON string with field name suggestions
     */
    private String suggestFieldNames(String structAddressStr, int structSize) {
        return Response.r2s(dataTypeService.suggestFieldNames(structAddressStr, structSize));
    }

    /**
     * 7. INSPECT_MEMORY_CONTENT - Memory content inspection with string detection
     *
     * Reads raw memory bytes and provides hex/ASCII representation with string detection hints.
     * This helps prevent misidentification of strings as numeric data.
     */
    private String inspectMemoryContent(String addressStr, int length, boolean detectStrings) {
        return Response.r2s(analysisService.inspectMemoryContent(addressStr, length, detectStrings));
    }

    // ============================================================================
    // MALWARE ANALYSIS IMPLEMENTATION METHODS
    // ============================================================================

    /**
     * Detect cryptographic constants in the binary (AES S-boxes, SHA constants, etc.)
     */
    private String detectCryptoConstants() {
        return Response.r2s(analysisService.detectCryptoConstants());
    }

    /**
     * Search for byte patterns with optional wildcards
     */
    private String searchBytePatterns(String pattern, String mask) {
        return Response.r2s(analysisService.searchBytePatterns(pattern, mask));
    }

    /**
     * Find functions structurally similar to the target function
     * Uses basic block count, instruction count, call count, and cyclomatic complexity
     */
    private String findSimilarFunctions(String targetFunction, double threshold) {
        return Response.r2s(analysisService.findSimilarFunctions(targetFunction, threshold));
    }
    
    
    /**
     * Analyze function control flow complexity
     * Calculates cyclomatic complexity, basic blocks, edges, and detailed metrics
     */
    private String analyzeControlFlow(String functionName) {
        return Response.r2s(analysisService.analyzeControlFlow(functionName));
    }

    /**
     * Detect anti-analysis and anti-debugging techniques
     * Scans for known anti-debug APIs, timing checks, VM detection, and SEH tricks
     */
    private String findAntiAnalysisTechniques() {
        return Response.r2s(malwareSecurityService.findAntiAnalysisTechniques());
    }
    

    /**
     * Batch decompile multiple functions
     */
    private String batchDecompileFunctions(String functionsParam) {
        return Response.r2s(functionService.batchDecompileFunctions(functionsParam));
    }

    /**
     * Find potentially unreachable code blocks
     */
    private String findDeadCode(String functionName) {
        return Response.r2s(analysisService.findDeadCode(functionName));
    }

    /**
     * Automatically identify and decrypt obfuscated strings
     */
    private String autoDecryptStrings() {
        return Response.r2s(malwareSecurityService.autoDecryptStrings());
    }

    /**
     * Identify and analyze suspicious API call chains
     * Detects threat patterns like process injection, persistence, credential theft
     */
    private String analyzeAPICallChains() {
        return Response.r2s(malwareSecurityService.analyzeAPICallChains());
    }
    
    

    /**
     * Enhanced IOC extraction with context and confidence scoring
     */
    private String extractIOCsWithContext() {
        return Response.r2s(malwareSecurityService.extractIOCsWithContext());
    }
    
    

    /**
     * Detect common malware behaviors and techniques
     */
    private String detectMalwareBehaviors() {
        return Response.r2s(malwareSecurityService.detectMalwareBehaviors());
    }
    

    /**
     * v1.5.0: Batch set multiple comments in a single operation
     * Reduces API calls from 10+ to 1 for typical function documentation
     */
    @SuppressWarnings("deprecation")
    private String batchSetComments(String functionAddress, List<Map<String, String>> decompilerComments,
                                    List<Map<String, String>> disassemblyComments, String plateComment) {
        return Response.r2s(commentService.batchSetComments(functionAddress, decompilerComments, disassemblyComments, plateComment));
    }

    private String clearFunctionComments(String functionAddress, boolean clearPlate, boolean clearPre, boolean clearEol) {
        return Response.r2s(commentService.clearFunctionComments(functionAddress, clearPlate, clearPre, clearEol));
    }

    private String setPlateComment(String functionAddress, String comment) {
        return Response.r2s(commentService.setPlateComment(functionAddress, comment));
    }

    /**
     * v1.5.0: Get all variables in a function (parameters and locals)
     */
    @SuppressWarnings("deprecation")
    private String getFunctionVariables(String functionName, String programName) {
        return Response.r2s(functionService.getFunctionVariables(functionName, programName));
    }

    // Backward compatibility overload
    @SuppressWarnings("deprecation")
    private String getFunctionVariables(String functionName) {
        return Response.r2s(functionService.getFunctionVariables(functionName));
    }

    /**
     * v1.5.0: Batch rename function and all its components atomically
     */
    @SuppressWarnings("deprecation")
    private String batchRenameFunctionComponents(String functionAddress, String functionName,
                                                Map<String, String> parameterRenames,
                                                Map<String, String> localRenames,
                                                String returnType) {
        return Response.r2s(functionService.batchRenameFunctionComponents(functionAddress, functionName, parameterRenames, localRenames, returnType));
    }

    /**
     * v1.5.0: Get valid Ghidra data type strings
     */
    private String getValidDataTypes(String category) {
        return Response.r2s(dataTypeService.getValidDataTypes(category));
    }

    /**
     * v1.5.0: Analyze function completeness for documentation
     */
    private String analyzeFunctionCompleteness(String functionAddress) {
        return Response.r2s(analysisService.analyzeFunctionCompleteness(functionAddress));
    }

    /**
     * v1.5.0: Find next undefined function needing analysis
     */
    private String findNextUndefinedFunction(String startAddress, String criteria,
                                            String pattern, String direction, String programName) {
        return Response.r2s(analysisService.findNextUndefinedFunction(startAddress, criteria, pattern, direction, programName));
    }
    
    // Backward compatibility overload
    private String findNextUndefinedFunction(String startAddress, String criteria,
                                            String pattern, String direction) {
        return Response.r2s(analysisService.findNextUndefinedFunction(startAddress, criteria, pattern, direction));
    }

    /**
     * v1.5.0: Batch set variable types
     */
    @SuppressWarnings("deprecation")
    private String batchSetVariableTypes(String functionAddress, Map<String, String> variableTypes, boolean forceIndividual) {
        Program program = getCurrentProgram();
        if (program == null) {
            return "{\"error\": \"No program loaded\"}";
        }

        // If forceIndividual is true, skip batch operations and use individual method
        if (forceIndividual) {
            return batchSetVariableTypesIndividual(functionAddress, variableTypes);
        }

        final StringBuilder result = new StringBuilder();
        result.append("{");
        final AtomicBoolean success = new AtomicBoolean(false);
        final AtomicReference<Integer> typesSet = new AtomicReference<>(0);

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Batch Set Variable Types");
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

                    DataTypeManager dtm = program.getDataTypeManager();

                    if (variableTypes != null) {
                        // Set parameter types
                        for (Parameter param : func.getParameters()) {
                            String newType = variableTypes.get(param.getName());
                            if (newType != null) {
                                DataType dt = dtm.getDataType(newType);
                                if (dt != null) {
                                    param.setDataType(dt, SourceType.USER_DEFINED);
                                    typesSet.getAndSet(typesSet.get() + 1);
                                }
                            }
                        }

                        // Set local variable types
                        for (Variable local : func.getLocalVariables()) {
                            String newType = variableTypes.get(local.getName());
                            if (newType != null) {
                                DataType dt = dtm.getDataType(newType);
                                if (dt != null) {
                                    local.setDataType(dt, SourceType.USER_DEFINED);
                                    typesSet.getAndSet(typesSet.get() + 1);
                                }
                            }
                        }
                    }

                    success.set(true);
                } catch (Exception e) {
                    // If batch operation fails, try individual operations as fallback
                    Msg.warn(this, "Batch set variable types failed, attempting individual operations: " + e.getMessage());
                    try {
                        program.endTransaction(tx, false);

                        // Try individual operations
                        String individualResult = batchSetVariableTypesIndividual(functionAddress, variableTypes);
                        result.append("\"fallback_used\": true, ");
                        result.append(individualResult);
                        return;
                    } catch (Exception fallbackE) {
                        result.append("\"error\": \"Batch operation failed and fallback also failed: ").append(e.getMessage()).append("\"");
                        Msg.error(this, "Both batch and individual type setting operations failed", e);
                    }
                } finally {
                    if (!result.toString().contains("\"fallback_used\"")) {
                        program.endTransaction(tx, success.get());
                    }
                }
            });

            if (success.get() && !result.toString().contains("\"fallback_used\"")) {
                result.append("\"success\": true, ");
                result.append("\"method\": \"batch\", ");
                result.append("\"variables_typed\": ").append(typesSet.get());
            }
        } catch (Exception e) {
            result.append("\"error\": \"").append(e.getMessage().replace("\"", "\\\"")).append("\"");
        }

        result.append("}");
        return result.toString();
    }

    /**
     * Individual variable type setting using setLocalVariableType (fallback method)
     * NOW USES OPTIMIZED SINGLE-DECOMPILE METHOD
     * This method was refactored to use batchSetVariableTypesOptimized() which decompiles
     * the function ONCE and applies all type changes within that single decompilation,
     * avoiding the repeated decompilation timeout issues that plagued the previous approach.
     */
    private String batchSetVariableTypesIndividual(String functionAddress, Map<String, String> variableTypes) {
        // Delegate to the optimized batch method that decompiles once
        // This fixes the issue where each setLocalVariableType() call caused its own decompilation
        return batchSetVariableTypesOptimized(functionAddress, variableTypes);
    }

    /**
     * OPTIMIZED: Batch set variable types - simple wrapper that calls setLocalVariableType
     * sequentially with proper spacing to avoid thread issues
     */
    private String batchSetVariableTypesOptimized(String functionAddress, Map<String, String> variableTypes) {
        if (variableTypes == null || variableTypes.isEmpty()) {
            return "{\"success\": true, \"method\": \"optimized\", \"variables_typed\": 0, \"variables_failed\": 0}";
        }

        final AtomicInteger variablesTyped = new AtomicInteger(0);
        final AtomicInteger variablesFailed = new AtomicInteger(0);
        final List<String> errors = new ArrayList<>();

        // Call setLocalVariableType for each variable with small delay between calls
        for (Map.Entry<String, String> entry : variableTypes.entrySet()) {
            String varName = entry.getKey();
            String newType = entry.getValue();

            try {
                // Call the working setLocalVariableType method
                String result = setLocalVariableType(functionAddress, varName, newType);

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

        // Build response
        StringBuilder result = new StringBuilder();
        result.append("{");
        result.append("\"success\": ").append(variablesFailed.get() == 0 && variablesTyped.get() > 0).append(", ");
        result.append("\"method\": \"optimized\", ");
        result.append("\"variables_typed\": ").append(variablesTyped.get()).append(", ");
        result.append("\"variables_failed\": ").append(variablesFailed.get());

        if (!errors.isEmpty()) {
            result.append(", \"errors\": [");
            for (int i = 0; i < errors.size(); i++) {
                if (i > 0) result.append(", ");
                result.append("\"").append(errors.get(i).replace("\"", "\\\"")).append("\"");
            }
            result.append("]");
        }

        result.append("}");
        return result.toString();
    }

    /**
     * NEW v1.6.0: Batch rename variables with partial success reporting and fallback
     */
    private String batchRenameVariables(String functionAddress, Map<String, String> variableRenames, boolean forceIndividual) {
        return Response.r2s(functionService.batchRenameVariables(functionAddress, variableRenames, forceIndividual));
    }

    /**
     * Validate that batch operations actually persisted by checking current state
     */
    private String validateBatchOperationResults(String functionAddress, Map<String, String> expectedRenames, Map<String, String> expectedTypes) {
        return Response.r2s(functionService.validateBatchOperationResults(functionAddress, expectedRenames, expectedTypes));
    }

    /**
     * NEW v1.6.0: Validate function prototype before applying
     */
    private String validateFunctionPrototype(String functionAddress, String prototype, String callingConvention) {
        return Response.r2s(dataTypeService.validateFunctionPrototype(functionAddress, prototype, callingConvention));
    }

    /**
     * NEW v1.6.0: Check if data type exists in type manager
     */
    private String validateDataTypeExists(String typeName) {
        return Response.r2s(dataTypeService.validateDataTypeExists(typeName));
    }

    /**
     * NEW v1.6.0: Determine if address has data/code and suggest operation
     */
    private String canRenameAtAddress(String addressStr) {
        return Response.r2s(symbolLabelService.canRenameAtAddress(addressStr));
    }

    /**
     * NEW v1.6.0: Comprehensive function analysis in single call
     */
    private String analyzeFunctionComplete(String name, boolean includeXrefs, boolean includeCallees,
                                          boolean includeCallers, boolean includeDisasm, boolean includeVariables,
                                          String programName) {
        return Response.r2s(analysisService.analyzeFunctionComplete(name, includeXrefs, includeCallees, includeCallers, includeDisasm, includeVariables, programName));
    }
    
    // Backward compatibility overload
    private String analyzeFunctionComplete(String name, boolean includeXrefs, boolean includeCallees,
                                          boolean includeCallers, boolean includeDisasm, boolean includeVariables) {
        return Response.r2s(analysisService.analyzeFunctionComplete(name, includeXrefs, includeCallees, includeCallers, includeDisasm, includeVariables));
    }

    /**
     * NEW v1.6.0: Enhanced function search with filtering and sorting
     */
    private String searchFunctionsEnhanced(String namePattern, Integer minXrefs, Integer maxXrefs,
                                          String callingConvention, Boolean hasCustomName, boolean regex,
                                          String sortBy, int offset, int limit, String programName) {
        return Response.r2s(analysisService.searchFunctionsEnhanced(namePattern, minXrefs, maxXrefs, callingConvention, hasCustomName, regex, sortBy, offset, limit, programName));
    }

    /**
     * NEW v1.7.1: Disassemble a range of bytes
     */
    private String disassembleBytes(String startAddress, String endAddress, Integer length,
                                   boolean restrictToExecuteMemory) {
        return Response.r2s(functionService.disassembleBytes(startAddress, endAddress, length, restrictToExecuteMemory));
    }

    /**
     * Create a function at the specified address.
     * Optionally disassembles bytes first and assigns a custom name.
     *
     * @param addressStr Starting address in hex format
     * @param name Optional function name (null for auto-generated)
     * @param disassembleFirst If true, disassemble bytes at address before creating function
     * @return JSON result with function creation status
     */
    private String deleteFunctionAtAddress(String addressStr) {
        return Response.r2s(functionService.deleteFunctionAtAddress(addressStr));
    }

    private String createFunctionAtAddress(String addressStr, String name, boolean disassembleFirst) {
        return Response.r2s(functionService.createFunctionAtAddress(addressStr, name, disassembleFirst));
    }

    private String generateScriptContent(String purpose, String workflowType, Map<String, Object> parameters) {
        return Response.r2s(programScriptService.generateScriptContent(purpose, workflowType, parameters));
    }

    private String generateScriptName(String workflowType) {
        return programScriptService.generateScriptName(workflowType);
    }

    /**
     * Execute a Ghidra script and capture all output, errors, and warnings (v1.9.1)
     * This enables automatic troubleshooting by providing comprehensive error information.
     *
     * Note: Since Ghidra scripts are typically run through the GUI via Script Manager,
     * this endpoint provides script discovery and validation. Full execution with output
     * capture should be done through Ghidra's Script Manager UI or headless mode.
     */
    private String runGhidraScriptWithCapture(String scriptName, String scriptArgs, int timeoutSeconds, boolean captureOutput) {
        return Response.r2s(programScriptService.runGhidraScriptWithCapture(scriptName, scriptArgs, timeoutSeconds, captureOutput));
    }

    // ===================================================================================
    // BOOKMARK METHODS (v1.9.4) - Progress tracking via Ghidra bookmarks
    // ===================================================================================

    /**
     * Set a bookmark at an address with category and comment.
     * Creates or updates the bookmark if one already exists at the address with the same category.
     */
    private String setBookmark(String addressStr, String category, String comment) {
        return Response.r2s(programScriptService.setBookmark(addressStr, category, comment));
    }

    /**
     * List bookmarks, optionally filtered by category and/or address.
     */
    private String listBookmarks(String category, String addressStr) {
        return Response.r2s(programScriptService.listBookmarks(category, addressStr));
    }

    /**
     * Delete a bookmark at an address with optional category filter.
     */
    private String deleteBookmark(String addressStr, String category) {
        return Response.r2s(programScriptService.deleteBookmark(addressStr, category));
    }



    /**
     * List all external locations (imports, ordinal imports, etc.)
     */
    private String listExternalLocations(int offset, int limit, String programName) {
        return Response.r2s(listingService.listExternalLocations(offset, limit, programName));
    }

    // Backward compatibility overload
    private String listExternalLocations(int offset, int limit) {
        return Response.r2s(listingService.listExternalLocations(offset, limit, null));
    }

    /**
     * Get details of a specific external location
     */
    private String getExternalLocationDetails(String address, String dllName, String programName) {
        return Response.r2s(listingService.getExternalLocationDetails(address, dllName, programName));
    }

    // Backward compatibility overload
    private String getExternalLocationDetails(String address, String dllName) {
        return Response.r2s(listingService.getExternalLocationDetails(address, dllName, null));
    }

    /**
     * Rename an external location (e.g., change Ordinal_123 to a real function name)
     */
    private String renameExternalLocation(String address, String newName) {
        return Response.r2s(symbolLabelService.renameExternalLocation(address, newName));
    }

    // ==================================================================================
    // CROSS-VERSION MATCHING TOOLS
    // ==================================================================================

    /**
     * Compare documentation status across all open programs.
     * Returns documented/undocumented function counts for each program.
     */
    private String compareProgramsDocumentation() {
        return Response.r2s(documentationHashService.compareProgramsDocumentation());
    }

    private String findUndocumentedByString(String stringAddress, String programName) {
        return Response.r2s(documentationHashService.findUndocumentedByString(stringAddress, programName));
    }

    private String batchStringAnchorReport(String pattern, String programName) {
        return Response.r2s(documentationHashService.batchStringAnchorReport(pattern, programName));
    }

    // ==========================================================================
    // FUZZY MATCHING & DIFF HANDLERS
    // ==========================================================================

    private String handleGetFunctionSignature(String addressStr, String programName) {
        return Response.r2s(documentationHashService.handleGetFunctionSignature(addressStr, programName));
    }

    private String handleFindSimilarFunctionsFuzzy(String addressStr, String sourceProgramName,
            String targetProgramName, double threshold, int limit) {
        return Response.r2s(documentationHashService.handleFindSimilarFunctionsFuzzy(addressStr, sourceProgramName,
            targetProgramName, threshold, limit));
    }

    private String handleBulkFuzzyMatch(String sourceProgramName, String targetProgramName,
            double threshold, int offset, int limit, String filter) {
        return Response.r2s(documentationHashService.handleBulkFuzzyMatch(sourceProgramName, targetProgramName,
            threshold, offset, limit, filter));
    }

    private String handleDiffFunctions(String addressA, String addressB, String programAName, String programBName) {
        return Response.r2s(documentationHashService.handleDiffFunctions(addressA, addressB, programAName, programBName));
    }

    // ==========================================================================
    // PROJECT VERSION CONTROL HELPER METHODS
    // Uses Ghidra's internal DomainFile/DomainFolder API
    // ==========================================================================

    private RepositoryAdapter getProjectRepository() {
        try {
            Project project = tool.getProject();
            if (project == null) return null;
            ProjectData data = project.getProjectData();
            // ProjectData.getRepository() is available on the implementation class
            java.lang.reflect.Method m = data.getClass().getMethod("getRepository");
            return (RepositoryAdapter) m.invoke(data);
        } catch (Exception e) {
            return null;
        }
    }

    private String getProjectStatusJson() {
        Project project = tool.getProject();
        if (project == null) {
            return "{\"connected\": false, \"error\": \"No project open\"}";
        }
        ProjectData data = project.getProjectData();
        RepositoryAdapter repo = getProjectRepository();
        StringBuilder sb = new StringBuilder();
        sb.append("{\"connected\": true");
        sb.append(", \"project\": \"").append(escapeJson(project.getName())).append("\"");
        sb.append(", \"shared\": ").append(repo != null);
        if (repo != null) {
            try {
                sb.append(", \"server_connected\": ").append(repo.isConnected());
                sb.append(", \"server_info\": \"").append(escapeJson(repo.getServerInfo().toString())).append("\"");
            } catch (Exception e) {
                sb.append(", \"server_connected\": false");
            }
        }
        sb.append(", \"file_count\": ").append(data.getFileCount());
        sb.append("}");
        return sb.toString();
    }

    private String listProjectFilesJson(String folderPath) {
        Project project = tool.getProject();
        if (project == null) return "{\"error\": \"No project open\"}";
        ProjectData data = project.getProjectData();
        DomainFolder folder;
        if (folderPath == null || folderPath.isEmpty() || folderPath.equals("/")) {
            folder = data.getRootFolder();
        } else {
            folder = data.getFolder(folderPath);
        }
        if (folder == null) return "{\"error\": \"Folder not found: " + escapeJson(folderPath) + "\"}";

        StringBuilder sb = new StringBuilder();
        sb.append("{\"folder\": \"").append(escapeJson(folder.getPathname())).append("\", \"files\": [");
        DomainFile[] files = folder.getFiles();
        for (int i = 0; i < files.length; i++) {
            if (i > 0) sb.append(", ");
            appendFileJson(sb, files[i]);
        }
        sb.append("], \"folders\": [");
        DomainFolder[] folders = folder.getFolders();
        for (int i = 0; i < folders.length; i++) {
            if (i > 0) sb.append(", ");
            sb.append("\"").append(escapeJson(folders[i].getName())).append("\"");
        }
        sb.append("], \"file_count\": ").append(files.length);
        sb.append(", \"folder_count\": ").append(folders.length).append("}");
        return sb.toString();
    }

    private void appendFileJson(StringBuilder sb, DomainFile f) {
        sb.append("{\"name\": \"").append(escapeJson(f.getName())).append("\"");
        sb.append(", \"path\": \"").append(escapeJson(f.getPathname())).append("\"");
        sb.append(", \"version\": ").append(f.getVersion());
        sb.append(", \"latest_version\": ").append(f.getLatestVersion());
        sb.append(", \"is_versioned\": ").append(f.isVersioned());
        sb.append(", \"is_checked_out\": ").append(f.isCheckedOut());
        sb.append(", \"is_checked_out_exclusive\": ").append(f.isCheckedOutExclusive());
        sb.append(", \"is_read_only\": ").append(f.isReadOnly());
        if (f.isCheckedOut()) {
            try {
                ItemCheckoutStatus status = f.getCheckoutStatus();
                if (status != null) {
                    sb.append(", \"checkout_user\": \"").append(escapeJson(status.getUser())).append("\"");
                    sb.append(", \"checkout_id\": ").append(status.getCheckoutId());
                    sb.append(", \"checkout_version\": ").append(status.getCheckoutVersion());
                }
            } catch (IOException e) {
                sb.append(", \"checkout_error\": \"").append(escapeJson(e.getMessage())).append("\"");
            }
        }
        sb.append("}");
    }

    private String getProjectFileInfoJson(String filePath) {
        Project project = tool.getProject();
        if (project == null) return "{\"error\": \"No project open\"}";
        DomainFile file = project.getProjectData().getFile(filePath);
        if (file == null) return "{\"error\": \"File not found: " + escapeJson(filePath) + "\"}";
        StringBuilder sb = new StringBuilder();
        appendFileJson(sb, file);
        return sb.toString();
    }

    private String checkoutProjectFile(String filePath, boolean exclusive) {
        Project project = tool.getProject();
        if (project == null) return "{\"error\": \"No project open\"}";
        if (filePath == null) return "{\"error\": \"'path' parameter required\"}";
        DomainFile file = project.getProjectData().getFile(filePath);
        if (file == null) return "{\"error\": \"File not found: " + escapeJson(filePath) + "\"}";
        try {
            boolean success = file.checkout(exclusive, new ConsoleTaskMonitor());
            return "{\"status\": \"" + (success ? "checked_out" : "checkout_failed") + "\", " +
                "\"path\": \"" + escapeJson(filePath) + "\", \"exclusive\": " + exclusive + "}";
        } catch (Exception e) {
            return "{\"error\": \"Checkout failed: " + escapeJson(e.getMessage()) + "\"}";
        }
    }

    private String checkinProjectFile(String filePath, String comment, boolean keepCheckedOut) {
        Project project = tool.getProject();
        if (project == null) return "{\"error\": \"No project open\"}";
        if (filePath == null) return "{\"error\": \"'path' parameter required\"}";
        DomainFile file = project.getProjectData().getFile(filePath);
        if (file == null) return "{\"error\": \"File not found: " + escapeJson(filePath) + "\"}";
        if (!file.isCheckedOut()) return "{\"error\": \"File is not checked out: " + escapeJson(filePath) + "\"}";
        try {
            file.checkin(new ghidra.framework.data.CheckinHandler() {
                public boolean keepCheckedOut() { return keepCheckedOut; }
                public String getComment() { return comment; }
                public boolean createKeepFile() { return false; }
            }, new ConsoleTaskMonitor());
            return "{\"status\": \"checked_in\", \"path\": \"" + escapeJson(filePath) + "\", " +
                "\"comment\": \"" + escapeJson(comment) + "\", \"keep_checked_out\": " + keepCheckedOut + "}";
        } catch (Exception e) {
            return "{\"error\": \"Checkin failed: " + escapeJson(e.getMessage()) + "\"}";
        }
    }

    private String undoCheckoutProjectFile(String filePath, boolean keep) {
        Project project = tool.getProject();
        if (project == null) return "{\"error\": \"No project open\"}";
        if (filePath == null) return "{\"error\": \"'path' parameter required\"}";
        DomainFile file = project.getProjectData().getFile(filePath);
        if (file == null) return "{\"error\": \"File not found: " + escapeJson(filePath) + "\"}";
        if (!file.isCheckedOut()) return "{\"error\": \"File is not checked out: " + escapeJson(filePath) + "\"}";
        try {
            file.undoCheckout(keep);
            return "{\"status\": \"checkout_undone\", \"path\": \"" + escapeJson(filePath) + "\", \"kept_copy\": " + keep + "}";
        } catch (Exception e) {
            return "{\"error\": \"Undo checkout failed: " + escapeJson(e.getMessage()) + "\"}";
        }
    }

    private String addToVersionControl(String filePath, String comment) {
        Project project = tool.getProject();
        if (project == null) return "{\"error\": \"No project open\"}";
        if (filePath == null) return "{\"error\": \"'path' parameter required\"}";
        DomainFile file = project.getProjectData().getFile(filePath);
        if (file == null) return "{\"error\": \"File not found: " + escapeJson(filePath) + "\"}";
        if (file.isVersioned()) return "{\"error\": \"File already under version control: " + escapeJson(filePath) + "\"}";
        try {
            file.addToVersionControl(comment, false, new ConsoleTaskMonitor());
            return "{\"status\": \"added\", \"path\": \"" + escapeJson(filePath) + "\", \"comment\": \"" + escapeJson(comment) + "\"}";
        } catch (Exception e) {
            return "{\"error\": \"Add to version control failed: " + escapeJson(e.getMessage()) + "\"}";
        }
    }

    private String getProjectFileVersionHistory(String filePath) {
        Project project = tool.getProject();
        if (project == null) return "{\"error\": \"No project open\"}";
        if (filePath == null) return "{\"error\": \"'path' parameter required\"}";
        DomainFile file = project.getProjectData().getFile(filePath);
        if (file == null) return "{\"error\": \"File not found: " + escapeJson(filePath) + "\"}";
        try {
            ghidra.framework.store.Version[] versions = file.getVersionHistory();
            StringBuilder sb = new StringBuilder();
            sb.append("{\"path\": \"").append(escapeJson(filePath)).append("\", \"versions\": [");
            for (int i = 0; i < versions.length; i++) {
                if (i > 0) sb.append(", ");
                sb.append("{\"version\": ").append(versions[i].getVersion());
                sb.append(", \"user\": \"").append(escapeJson(versions[i].getUser())).append("\"");
                sb.append(", \"comment\": \"").append(escapeJson(versions[i].getComment() != null ? versions[i].getComment() : "")).append("\"");
                sb.append(", \"date\": \"").append(new java.util.Date(versions[i].getCreateTime())).append("\"");
                sb.append("}");
            }
            sb.append("], \"count\": ").append(versions.length).append("}");
            return sb.toString();
        } catch (Exception e) {
            return "{\"error\": \"Failed to get version history: " + escapeJson(e.getMessage()) + "\"}";
        }
    }

    private String listProjectCheckouts(String folderPath) {
        Project project = tool.getProject();
        if (project == null) return "{\"error\": \"No project open\"}";
        ProjectData data = project.getProjectData();
        DomainFolder folder;
        if (folderPath == null || folderPath.isEmpty() || folderPath.equals("/")) {
            folder = data.getRootFolder();
        } else {
            folder = data.getFolder(folderPath);
        }
        if (folder == null) return "{\"error\": \"Folder not found: " + escapeJson(folderPath) + "\"}";

        StringBuilder sb = new StringBuilder();
        sb.append("{\"checkouts\": [");
        int count = collectCheckouts(sb, folder, 0);
        sb.append("], \"count\": ").append(count).append("}");
        return sb.toString();
    }

    private int collectCheckouts(StringBuilder sb, DomainFolder folder, int count) {
        for (DomainFile f : folder.getFiles()) {
            if (f.isCheckedOut()) {
                if (count > 0) sb.append(", ");
                appendFileJson(sb, f);
                count++;
            }
        }
        for (DomainFolder sub : folder.getFolders()) {
            count = collectCheckouts(sb, sub, count);
        }
        return count;
    }

    private String terminateFileCheckout(String filePath) {
        Project project = tool.getProject();
        if (project == null) return "{\"error\": \"No project open\"}";
        if (filePath == null) return "{\"error\": \"'path' parameter required\"}";
        DomainFile file = project.getProjectData().getFile(filePath);
        if (file == null) return "{\"error\": \"File not found: " + escapeJson(filePath) + "\"}";

        // First try: undo checkout with force via the DomainFile API
        if (file.isCheckedOut()) {
            try {
                file.undoCheckout(false, true);
                return "{\"status\": \"terminated\", \"path\": \"" + escapeJson(filePath) + "\", \"method\": \"undo_checkout_force\"}";
            } catch (Exception e) {
                // Fall through to repository adapter approach
            }
        }

        // Second try: use RepositoryAdapter for server-side termination
        RepositoryAdapter repo = getProjectRepository();
        if (repo == null) {
            return "{\"error\": \"Cannot terminate checkout: project has no repository connection\"}";
        }
        try {
            int lastSlash = filePath.lastIndexOf('/');
            String parentPath = lastSlash > 0 ? filePath.substring(0, lastSlash) : "/";
            String fileName = lastSlash >= 0 ? filePath.substring(lastSlash + 1) : filePath;
            ItemCheckoutStatus[] checkouts = repo.getCheckouts(parentPath, fileName);
            if (checkouts == null || checkouts.length == 0) {
                return "{\"error\": \"No active checkouts found for: " + escapeJson(filePath) + "\"}";
            }
            int terminated = 0;
            for (ItemCheckoutStatus cs : checkouts) {
                try {
                    repo.terminateCheckout(parentPath, fileName, cs.getCheckoutId(), false);
                    terminated++;
                } catch (Exception e) {
                    // continue trying others
                }
            }
            return "{\"status\": \"terminated\", \"path\": \"" + escapeJson(filePath) + "\", " +
                "\"terminated_count\": " + terminated + ", \"total_checkouts\": " + checkouts.length + "}";
        } catch (Exception e) {
            return "{\"error\": \"Terminate checkout failed: " + escapeJson(e.getMessage()) + "\"}";
        }
    }

    // ==========================================================================
    // PROJECT & TOOL MANAGEMENT HELPERS
    // ==========================================================================

    private String getProjectInfo() {
        Project project = tool.getProject();
        if (project == null) {
            return "{\"error\": \"No project open\"}";
        }
        ProjectData data = project.getProjectData();
        RepositoryAdapter repo = getProjectRepository();
        StringBuilder sb = new StringBuilder();
        sb.append("{\"project\": \"").append(escapeJson(project.getName())).append("\"");
        sb.append(", \"shared\": ").append(repo != null);
        if (repo != null) {
            try {
                sb.append(", \"server_connected\": ").append(repo.isConnected());
                sb.append(", \"server_info\": \"").append(escapeJson(repo.getServerInfo().toString())).append("\"");
            } catch (Exception e) {
                sb.append(", \"server_connected\": false");
            }
        }
        sb.append(", \"file_count\": ").append(data.getFileCount());

        // Open programs
        Program[] openProgs = programProvider.getAllOpenPrograms();
        sb.append(", \"open_programs\": [");
        for (int i = 0; i < openProgs.length; i++) {
            if (i > 0) sb.append(", ");
            sb.append("\"").append(escapeJson(openProgs[i].getName())).append("\"");
        }
        sb.append("]");
        sb.append(", \"open_program_count\": ").append(openProgs.length);

        // Current program
        Program current = programProvider.getCurrentProgram();
        if (current != null) {
            sb.append(", \"current_program\": \"").append(escapeJson(current.getName())).append("\"");
        }

        // Running tools
        try {
            ghidra.framework.model.ToolManager tm = project.getToolManager();
            if (tm != null) {
                PluginTool[] tools = tm.getRunningTools();
                sb.append(", \"running_tools\": [");
                boolean hasCodeBrowser = false;
                for (int i = 0; i < tools.length; i++) {
                    if (i > 0) sb.append(", ");
                    sb.append("\"").append(escapeJson(tools[i].getName())).append("\"");
                    if (tools[i].getService(ghidra.app.services.ProgramManager.class) != null) {
                        hasCodeBrowser = true;
                    }
                }
                sb.append("]");
                sb.append(", \"codebrowser_active\": ").append(hasCodeBrowser);
            }
        } catch (Exception e) {
            // ToolManager not available
        }

        sb.append("}");
        return sb.toString();
    }

    private String getRunningTools() {
        Project project = tool.getProject();
        if (project == null) {
            return "{\"error\": \"No project open\"}";
        }
        try {
            ghidra.framework.model.ToolManager tm = project.getToolManager();
            if (tm == null) {
                return "{\"error\": \"ToolManager not available\"}";
            }
            PluginTool[] tools = tm.getRunningTools();
            StringBuilder sb = new StringBuilder();
            sb.append("{\"tools\": [");
            for (int i = 0; i < tools.length; i++) {
                if (i > 0) sb.append(", ");
                sb.append("{\"name\": \"").append(escapeJson(tools[i].getName())).append("\"");
                sb.append(", \"instance\": \"").append(escapeJson(tools[i].getInstanceName())).append("\"");
                ghidra.app.services.ProgramManager pm = tools[i].getService(ghidra.app.services.ProgramManager.class);
                if (pm != null) {
                    sb.append(", \"has_program_manager\": true");
                    Program current = pm.getCurrentProgram();
                    if (current != null) {
                        sb.append(", \"current_program\": \"").append(escapeJson(current.getName())).append("\"");
                    }
                    Program[] progs = pm.getAllOpenPrograms();
                    sb.append(", \"open_programs\": [");
                    for (int j = 0; j < progs.length; j++) {
                        if (j > 0) sb.append(", ");
                        sb.append("\"").append(escapeJson(progs[j].getName())).append("\"");
                    }
                    sb.append("]");
                } else {
                    sb.append(", \"has_program_manager\": false");
                }
                sb.append("}");
            }
            sb.append("], \"count\": ").append(tools.length).append("}");
            return sb.toString();
        } catch (Exception e) {
            return "{\"error\": \"Failed to list tools: " + escapeJson(e.getMessage()) + "\"}";
        }
    }

    private String launchCodeBrowser(String filePath) {
        Project project = tool.getProject();
        if (project == null) {
            return "{\"error\": \"No project open\"}";
        }

        DomainFile domainFile = null;
        if (filePath != null && !filePath.trim().isEmpty()) {
            domainFile = project.getProjectData().getFile(filePath);
            if (domainFile == null) {
                return "{\"error\": \"File not found in project: " + escapeJson(filePath) + "\"}";
            }
        }

        try {
            ghidra.framework.model.ToolServices ts = project.getToolServices();
            if (ts == null) {
                return "{\"error\": \"ToolServices not available\"}";
            }

            // Find existing CodeBrowser or launch a new one
            ghidra.framework.model.ToolManager tm = project.getToolManager();
            PluginTool codeBrowser = null;
            if (tm != null) {
                for (PluginTool runningTool : tm.getRunningTools()) {
                    if (runningTool.getService(ghidra.app.services.ProgramManager.class) != null) {
                        codeBrowser = runningTool;
                        break;
                    }
                }
            }

            if (codeBrowser != null && domainFile != null) {
                // Existing CodeBrowser found - open the file in it
                final ghidra.app.services.ProgramManager pm = codeBrowser.getService(ghidra.app.services.ProgramManager.class);
                final Program program = (Program) domainFile.getDomainObject(this, false, false, TaskMonitor.DUMMY);
                javax.swing.SwingUtilities.invokeAndWait(() -> {
                    pm.openProgram(program);
                    pm.setCurrentProgram(program);
                });
                return "{\"success\": true, \"message\": \"Opened in existing CodeBrowser\", " +
                    "\"tool\": \"" + escapeJson(codeBrowser.getName()) + "\", " +
                    "\"program\": \"" + escapeJson(program.getName()) + "\", " +
                    "\"path\": \"" + escapeJson(filePath) + "\"}";
            } else if (domainFile != null) {
                // No CodeBrowser running - launch one with the file (must run on EDT)
                final DomainFile df = domainFile;
                final String fp = filePath;
                javax.swing.SwingUtilities.invokeAndWait(() -> {
                    ts.launchDefaultTool(Collections.singletonList(df));
                });
                return "{\"success\": true, \"message\": \"Launched new CodeBrowser\", " +
                    "\"path\": \"" + escapeJson(fp) + "\"}";
            } else {
                // No file specified - just launch empty CodeBrowser (must run on EDT)
                javax.swing.SwingUtilities.invokeAndWait(() -> {
                    ts.launchDefaultTool(Collections.emptyList());
                });
                return "{\"success\": true, \"message\": \"Launched new CodeBrowser (no file)\"}";
            }
        } catch (Exception e) {
            return "{\"error\": \"Failed to launch CodeBrowser: " + escapeJson(e.getMessage()) + "\"}";
        }
    }

    private String authenticateServer(String username, String password) {
        try {
            if (password == null || password.isEmpty()) {
                return "{\"error\": \"Password is required\"}";
            }
            // Resolve username if not provided
            if (username == null || username.isEmpty()) {
                username = ghidra.framework.preferences.Preferences.getProperty("PasswordPrompt.Name");
            }
            if (username == null || username.isEmpty()) {
                username = System.getProperty("user.name");
            }

            char[] passwordChars = password.toCharArray();
            if (this.authenticator != null) {
                // Update existing authenticator
                this.authenticator.updateCredentials(username, passwordChars);
                Msg.info(this, "GhidraMCP: Updated server credentials for user: " + username);
            } else {
                // Create and register new authenticator
                this.authenticator = new com.xebyte.core.GhidraMCPAuthenticator(username, passwordChars);
                ghidra.framework.client.ClientUtil.setClientAuthenticator(this.authenticator);
                Msg.info(this, "GhidraMCP: Registered server authenticator for user: " + username);
            }

            return "{\"success\": true, \"message\": \"Server credentials registered\", " +
                "\"username\": \"" + escapeJson(username) + "\"}";
        } catch (Exception e) {
            return "{\"error\": \"Failed to register authenticator: " + escapeJson(e.getMessage()) + "\"}";
        }
    }

    @Override
    public void dispose() {
        instanceCount--;
        // Only stop the server when the last plugin instance is disposed
        if (instanceCount <= 0) {
            stopServer();
            programProvider.releaseAll();
            instanceCount = 0;
        } else {
            Msg.info(this, "GhidraMCP: " + instanceCount + " tool window(s) still active, keeping server running.");
        }
        if (startServerAction != null) {
            tool.removeAction(startServerAction);
        }
        if (stopServerAction != null) {
            tool.removeAction(stopServerAction);
        }
        if (restartServerAction != null) {
            tool.removeAction(restartServerAction);
        }
        if (serverStatusAction != null) {
            tool.removeAction(serverStatusAction);
        }
        super.dispose();
    }
}
