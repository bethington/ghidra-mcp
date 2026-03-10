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
import ghidra.app.services.GoToService;

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
import com.xebyte.core.AnnotationScanner;
import com.xebyte.core.EndpointDef;
import com.xebyte.core.FrontEndProgramProvider;
import com.xebyte.core.JsonHelper;
import com.xebyte.core.ServerManager;

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
    private static String VERSION = "4.3.0"; // Default fallback
    private static String APP_NAME = "GhidraMCP";
    private static String GHIDRA_VERSION = "unknown"; // Loaded from version.properties (Maven-filtered)
    private static String BUILD_TIMESTAMP = "dev"; // Will be replaced by Maven
    private static String BUILD_NUMBER = "0"; // Will be replaced by Maven
    private static final int ENDPOINT_COUNT = 176;

    static {
        try (InputStream input = GhidraMCPPlugin.class
                .getResourceAsStream("/version.properties")) {
            if (input != null) {
                Properties props = new Properties();
                props.load(input);
                VERSION = props.getProperty("app.version", "4.3.0");
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
    private static final String UDS_ENABLED_OPTION = "Enable UDS Transport";
    private static final String TCP_ENABLED_OPTION = "Enable TCP Transport";
    private static final boolean DEFAULT_UDS_ENABLED = !System.getProperty("os.name", "").toLowerCase().contains("win");
    private static final boolean DEFAULT_TCP_ENABLED = System.getProperty("os.name", "").toLowerCase().contains("win");

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
        this.analysisService = new com.xebyte.core.AnalysisService(programProvider, threadingStrategy, this.functionService);
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

        // Register configuration options
        Options options = tool.getOptions(OPTION_CATEGORY_NAME);
        options.registerOption(PORT_OPTION_NAME, DEFAULT_PORT,
            null,
            "The network port number the TCP transport will listen on. " +
            "Requires Ghidra restart or plugin reload to take effect after changing.");
        options.registerOption(UDS_ENABLED_OPTION, DEFAULT_UDS_ENABLED, null,
            "Enable Unix Domain Socket transport for local multi-instance support.");
        options.registerOption(TCP_ENABLED_OPTION, DEFAULT_TCP_ENABLED, null,
            "Enable TCP transport for remote/network access.");

        boolean udsEnabled = options.getBoolean(UDS_ENABLED_OPTION, DEFAULT_UDS_ENABLED);
        boolean tcpEnabled = options.getBoolean(TCP_ENABLED_OPTION, DEFAULT_TCP_ENABLED);

        // Start UDS if enabled
        boolean udsOk = false;
        if (udsEnabled) {
            try {
                ServerManager.getInstance().registerTool(tool, null);
                udsOk = true;
                Msg.info(this, "GhidraMCP UDS server active at " + ServerManager.getInstance().getSocketPath());
            } catch (IOException e) {
                Msg.warn(this, "Failed to start UDS server: " + e.getMessage());
            }
        }

        // Start TCP if enabled, or as safety net if nothing else is running
        if (tcpEnabled || (!udsOk && !tcpEnabled)) {
            if (server != null && isServerRunning()) {
                Msg.info(this, "GhidraMCP TCP server already running — sharing with this tool window.");
            } else {
                try {
                    startServer();
                    ownsServer = true;
                    int port = options.getInt(PORT_OPTION_NAME, DEFAULT_PORT);
                    if (!tcpEnabled) {
                        Msg.warn(this, "GhidraMCP: Both transports disabled or UDS failed — started TCP on port " + port + " as safety net.");
                    } else {
                        Msg.info(this, "GhidraMCP TCP server active on port " + port);
                    }
                } catch (IOException e) {
                    Msg.error(this, "Failed to start TCP server: " + e.getMessage(), e);
                    if (!udsOk) {
                        Msg.showError(this, null, "GhidraMCP Server Error",
                            "Failed to start MCP server.\n\n" +
                            "No transports are running.\n\n" +
                            "Error: " + e.getMessage());
                    }
                }
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
        boolean anyRunning = isServerRunning() || ServerManager.getInstance().isRunning();
        startServerAction.setEnabled(!anyRunning);
        stopServerAction.setEnabled(anyRunning);
        restartServerAction.setEnabled(anyRunning);
    }

    private void createMenuActions() {
        startServerAction = new DockingAction("Start Server", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                Options opts = tool.getOptions(OPTION_CATEGORY_NAME);
                boolean uds = opts.getBoolean(UDS_ENABLED_OPTION, DEFAULT_UDS_ENABLED);
                boolean tcp = opts.getBoolean(TCP_ENABLED_OPTION, DEFAULT_TCP_ENABLED);
                StringBuilder started = new StringBuilder();
                if (uds && !ServerManager.getInstance().isRunning()) {
                    try {
                        ServerManager.getInstance().registerTool(tool, null);
                        started.append("UDS: ").append(ServerManager.getInstance().getSocketPath());
                    } catch (IOException e) {
                        Msg.showError(getClass(), null, "GhidraMCP", "Failed to start UDS server: " + e.getMessage());
                    }
                }
                if (tcp && !isServerRunning()) {
                    try {
                        startServer();
                        ownsServer = true;
                        if (started.length() > 0) started.append("\n");
                        started.append("TCP: port ").append(opts.getInt(PORT_OPTION_NAME, DEFAULT_PORT));
                    } catch (IOException e) {
                        Msg.showError(getClass(), null, "GhidraMCP", "Failed to start TCP server: " + e.getMessage());
                    }
                }
                updateMenuActionStates();
                if (started.length() > 0) {
                    Msg.showInfo(getClass(), null, "GhidraMCP", "Server started.\n" + started);
                }
            }
        };
        startServerAction.setMenuBarData(new MenuData(new String[]{"Tools", "GhidraMCP", "Start Server"}));

        stopServerAction = new DockingAction("Stop Server", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                stopServer();
                ServerManager.getInstance().stopUdsServer();
                updateMenuActionStates();
                Msg.showInfo(getClass(), null, "GhidraMCP", "All servers stopped.");
            }
        };
        stopServerAction.setMenuBarData(new MenuData(new String[]{"Tools", "GhidraMCP", "Stop Server"}));

        restartServerAction = new DockingAction("Restart Server", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                // Stop everything
                stopServer();
                ServerManager.getInstance().stopUdsServer();
                // Re-start based on current config
                startServerAction.actionPerformed(context);
            }
        };
        restartServerAction.setMenuBarData(new MenuData(new String[]{"Tools", "GhidraMCP", "Restart Server"}));

        serverStatusAction = new DockingAction("Server Status", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                Options opts = tool.getOptions(OPTION_CATEGORY_NAME);
                int port = opts.getInt(PORT_OPTION_NAME, DEFAULT_PORT);
                boolean udsRunning = ServerManager.getInstance().isRunning();
                String udsStatus = udsRunning
                    ? "Running (" + ServerManager.getInstance().getSocketPath() + ")"
                    : "Disabled";
                String tcpStatus = isServerRunning()
                    ? "Running (port " + port + ")"
                    : "Disabled";
                String message = "GhidraMCP Server Status\n\n" +
                    "UDS: " + udsStatus + "\n" +
                    "TCP: " + tcpStatus + "\n" +
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
        // SHARED ENDPOINTS — Annotation-driven registration via AnnotationScanner
        // Discovers @McpTool-annotated methods on service instances via reflection
        // ==========================================================================

        AnnotationScanner scanner = new AnnotationScanner(
            listingService, functionService, commentService, symbolLabelService,
            xrefCallGraphService, dataTypeService, analysisService,
            documentationHashService, malwareSecurityService, programScriptService);

        for (EndpointDef ep : scanner.getEndpoints()) {
            server.createContext(ep.path(), safeHandler(exchange -> {
                Map<String, String> query = parseQueryParams(exchange);
                Map<String, Object> body = "POST".equalsIgnoreCase(exchange.getRequestMethod())
                    ? parseJsonParams(exchange) : Map.of();
                try {
                    sendResponse(exchange, ep.handler().handle(query, body).toJson());
                } catch (IOException e) {
                    throw e;
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }));
        }

        // ==========================================================================
        // SCHEMA ENDPOINT — Serves machine-readable API metadata
        // ==========================================================================

        String schemaJson = scanner.generateSchema();
        server.createContext("/mcp/schema", safeHandler(exchange -> {
            sendResponse(exchange, schemaJson);
        }));

        // ==========================================================================
        // INFRASTRUCTURE ENDPOINTS (not in service layer)
        // ==========================================================================

        server.createContext("/check_connection", safeHandler(exchange -> {
            sendResponse(exchange, checkConnection());
        }));

        server.createContext("/get_version", safeHandler(exchange -> {
            sendResponse(exchange, getVersion());
        }));

        // ==========================================================================
        // GUI-ONLY ENDPOINTS (require PluginTool/CodeBrowser/Swing context)
        // ==========================================================================

        server.createContext("/get_current_address", safeHandler(exchange -> {
            sendResponse(exchange, getCurrentAddress());
        }));

        server.createContext("/get_current_function", safeHandler(exchange -> {
            sendResponse(exchange, getCurrentFunction());
        }));

        // GET_DATA_TYPE_SIZE - Get the size in bytes of a data type (not yet in service layer)
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

        // BATCH_SET_VARIABLE_TYPES - Set types for multiple variables (uses local optimized method)
        server.createContext("/batch_set_variable_types", safeHandler(exchange -> {
            try {
                Map<String, Object> params = parseJsonParams(exchange);
                String functionAddress = (String) params.get("function_address");

                // Handle variable_types as either Map or String (JSON parsing variation)
                Object vtObj = params.get("variable_types");
                Map<String, String> variableTypes;
                if (vtObj instanceof Map) {
                    @SuppressWarnings("unchecked")
                    Map<String, String> vtMap = (Map<String, String>) vtObj;
                    variableTypes = vtMap;
                } else if (vtObj instanceof String vtStr) {
                    variableTypes = new HashMap<>();
                    Map<String, Object> parsed = JsonHelper.parseJson(vtStr);
                    for (var e : parsed.entrySet()) {
                        variableTypes.put(e.getKey(), e.getValue() != null ? String.valueOf(e.getValue()) : null);
                    }
                } else {
                    variableTypes = new HashMap<>();
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

        server.createContext("/exit_ghidra", safeHandler(exchange -> {
            try {
                // Save first, then exit
                String saveResult = saveCurrentProgram(null);
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

        server.createContext("/server/admin/terminate_all_checkouts", safeHandler(exchange -> {
            Map<String, Object> params = parseJsonParams(exchange);
            String folderPath = params.get("path") != null ? params.get("path").toString() : "/";
            sendResponse(exchange, terminateAllCheckouts(folderPath));
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

        server.createContext("/project/info", safeHandler(exchange -> {
            sendResponse(exchange, getProjectInfo());
        }));

        server.createContext("/tool/running_tools", safeHandler(exchange -> {
            sendResponse(exchange, getRunningTools());
        }));

        server.createContext("/tool/launch_codebrowser", safeHandler(exchange -> {
            Map<String, Object> params = parseJsonParams(exchange);
            String filePath = params.get("path") != null ? params.get("path").toString() : null;
            sendResponse(exchange, launchCodeBrowser(filePath));
        }));

        server.createContext("/tool/goto_address", safeHandler(exchange -> {
            Map<String, Object> params = parseJsonParams(exchange);
            String address = params.get("address") != null ? params.get("address").toString() : null;
            sendResponse(exchange, gotoAddress(address));
        }));

        server.createContext("/batch_apply_documentation", safeHandler(exchange -> {
            Map<String, Object> params = parseJsonParams(exchange);
            sendResponse(exchange, batchApplyDocumentation(params));
        }));

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
        return listingService.getAllFunctionNames(offset, limit, programName).toJson();
    }

    // Backward compatible overload
    private String getAllFunctionNames(int offset, int limit) {
        return listingService.getAllFunctionNames(offset, limit, null).toJson();
    }

    private String getAllClassNames(int offset, int limit, String programName) {
        return listingService.getAllClassNames(offset, limit, programName).toJson();
    }

    // Backward compatible overload
    private String getAllClassNames(int offset, int limit) {
        return listingService.getAllClassNames(offset, limit, null).toJson();
    }

    private String listSegments(int offset, int limit, String programName) {
        return listingService.listSegments(offset, limit, programName).toJson();
    }

    // Backward compatible overload
    private String listSegments(int offset, int limit) {
        return listingService.listSegments(offset, limit, null).toJson();
    }

    private String listImports(int offset, int limit, String programName) {
        return listingService.listImports(offset, limit, programName).toJson();
    }

    // Backward compatible overload
    private String listImports(int offset, int limit) {
        return listingService.listImports(offset, limit, null).toJson();
    }

    private String listExports(int offset, int limit, String programName) {
        return listingService.listExports(offset, limit, programName).toJson();
    }

    // Backward compatible overload
    private String listExports(int offset, int limit) {
        return listingService.listExports(offset, limit, null).toJson();
    }

    private String listNamespaces(int offset, int limit, String programName) {
        return listingService.listNamespaces(offset, limit, programName).toJson();
    }

    // Backward compatible overload
    private String listNamespaces(int offset, int limit) {
        return listingService.listNamespaces(offset, limit, null).toJson();
    }

    private String listDefinedData(int offset, int limit, String programName) {
        return listingService.listDefinedData(offset, limit, programName).toJson();
    }

    // Backward compatible overload
    private String listDefinedData(int offset, int limit) {
        return listingService.listDefinedData(offset, limit, null).toJson();
    }

    private String listDataItemsByXrefs(int offset, int limit, String format, String programName) {
        return listingService.listDataItemsByXrefs(offset, limit, format, programName).toJson();
    }

    private String searchFunctionsByName(String searchTerm, int offset, int limit, String programName) {
        return listingService.searchFunctionsByName(searchTerm, offset, limit, programName).toJson();
    }

    // Backward compatible overload
    private String searchFunctionsByName(String searchTerm, int offset, int limit) {
        return listingService.searchFunctionsByName(searchTerm, offset, limit, null).toJson();
    }

    // ----------------------------------------------------------------------------------
    // Logic for rename, decompile, etc.
    // ----------------------------------------------------------------------------------

    private String decompileFunctionByName(String name) {
        return functionService.decompileFunctionByName(name).toJson();
    }

    private String renameFunction(String oldName, String newName, String programName) {
        return functionService.renameFunction(oldName, newName, programName).toJson();
    }

    private String renameDataAtAddress(String addressStr, String newName, String programName) {
        return symbolLabelService.renameDataAtAddress(addressStr, newName, programName).toJson();
    }

    private String renameDataAtAddress(String addressStr, String newName) {
        return symbolLabelService.renameDataAtAddress(addressStr, newName).toJson();
    }

    private String renameVariableInFunction(String functionName, String oldVarName, String newVarName, String programName) {
        return functionService.renameVariableInFunction(functionName, oldVarName, newVarName, programName).toJson();
    }

    // ----------------------------------------------------------------------------------
    // New methods to implement the new functionalities
    // ----------------------------------------------------------------------------------

    /**
     * Get function by address
     */
    private String getFunctionByAddress(String addressStr, String programName) {
        return functionService.getFunctionByAddress(addressStr, programName).toJson();
    }

    // Backward compatibility overload
    private String getFunctionByAddress(String addressStr) {
        return functionService.getFunctionByAddress(addressStr).toJson();
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
        return listingService.listFunctions(programName).toJson();
    }

    private String listFunctionsEnhanced(int offset, int limit, String programName) {
        return listingService.listFunctionsEnhanced(offset, limit, programName).toJson();
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
        return functionService.decompileFunctionByAddress(addressStr, programName, timeoutSeconds).toJson();
    }

    private String decompileFunctionByAddress(String addressStr, String programName) {
        return functionService.decompileFunctionByAddress(addressStr, programName).toJson();
    }

    private String decompileFunctionByAddress(String addressStr) {
        return functionService.decompileFunctionByAddress(addressStr).toJson();
    }

    private String disassembleFunction(String addressStr, String programName) {
        return functionService.disassembleFunction(addressStr, programName).toJson();
    }

    private String disassembleFunction(String addressStr) {
        return functionService.disassembleFunction(addressStr).toJson();
    }

    /**
     * Set a comment using the specified comment type (PRE_COMMENT or EOL_COMMENT)
     */
    @SuppressWarnings("deprecation")
    private String setCommentAtAddress(String addressStr, String comment, int commentType, String transactionName) {
        return commentService.setCommentAtAddress(addressStr, comment, commentType, transactionName).toJson();
    }

    private String setDecompilerComment(String addressStr, String comment, String programName) {
        return commentService.setDecompilerComment(addressStr, comment, programName).toJson();
    }

    private String setDecompilerComment(String addressStr, String comment) {
        return commentService.setDecompilerComment(addressStr, comment).toJson();
    }

    private String setDisassemblyComment(String addressStr, String comment, String programName) {
        return commentService.setDisassemblyComment(addressStr, comment, programName).toJson();
    }

    private String setDisassemblyComment(String addressStr, String comment) {
        return commentService.setDisassemblyComment(addressStr, comment).toJson();
    }

    private String renameFunctionByAddress(String functionAddrStr, String newName, String programName) {
        return functionService.renameFunctionByAddress(functionAddrStr, newName, programName).toJson();
    }

    // Backward compatible overload (used by batchApplyDocumentation)
    private String renameFunctionByAddress(String functionAddrStr, String newName) {
        return functionService.renameFunctionByAddress(functionAddrStr, newName).toJson();
    }

    private com.xebyte.core.FunctionService.PrototypeResult setFunctionPrototype(String functionAddrStr, String prototype) {
        return functionService.setFunctionPrototype(functionAddrStr, prototype);
    }

    private com.xebyte.core.FunctionService.PrototypeResult setFunctionPrototype(String functionAddrStr, String prototype, String callingConvention) {
        return functionService.setFunctionPrototype(functionAddrStr, prototype, callingConvention);
    }

    private com.xebyte.core.FunctionService.PrototypeResult setFunctionPrototype(String functionAddrStr, String prototype, String callingConvention, String programName) {
        return functionService.setFunctionPrototype(functionAddrStr, prototype, callingConvention, programName);
    }

    private String listCallingConventions(String programName) {
        return listingService.listCallingConventions(programName).toJson();
    }

    private String listCallingConventions() {
        return listingService.listCallingConventions(null).toJson();
    }

    private String setLocalVariableType(String functionAddrStr, String variableName, String newType, String programName) {
        return functionService.setLocalVariableType(functionAddrStr, variableName, newType, programName).toJson();
    }

    private String setLocalVariableType(String functionAddrStr, String variableName, String newType) {
        return functionService.setLocalVariableType(functionAddrStr, variableName, newType).toJson();
    }

    private String setFunctionNoReturn(String functionAddrStr, boolean noReturn, String programName) {
        return functionService.setFunctionNoReturn(functionAddrStr, noReturn, programName).toJson();
    }

    private String setFunctionNoReturn(String functionAddrStr, boolean noReturn) {
        return functionService.setFunctionNoReturn(functionAddrStr, noReturn).toJson();
    }

    private String clearInstructionFlowOverride(String instructionAddrStr, String programName) {
        return functionService.clearInstructionFlowOverride(instructionAddrStr, programName).toJson();
    }

    private String clearInstructionFlowOverride(String instructionAddrStr) {
        return functionService.clearInstructionFlowOverride(instructionAddrStr).toJson();
    }

    private String setVariableStorage(String functionAddrStr, String variableName, String storageSpec, String programName) {
        return functionService.setVariableStorage(functionAddrStr, variableName, storageSpec, programName).toJson();
    }

    private String setVariableStorage(String functionAddrStr, String variableName, String storageSpec) {
        return functionService.setVariableStorage(functionAddrStr, variableName, storageSpec).toJson();
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
    private String runGhidraScript(String scriptPath, String scriptArgs, String programName) {
        return programScriptService.runGhidraScript(scriptPath, scriptArgs, programName).toJson();
    }

    private String runGhidraScript(String scriptPath, String scriptArgs) {
        return programScriptService.runGhidraScript(scriptPath, scriptArgs).toJson();
    }

    /**
     * List available Ghidra scripts (v1.7.0)
     *
     * @param filter Optional filter string to match script names
     * @return JSON list of available scripts
     */
    private String listGhidraScripts(String filter) {
        return programScriptService.listGhidraScripts(filter).toJson();
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
        return functionService.forceDecompile(functionAddrStr).toJson();
    }

    /**
     * Get all references to a specific address (xref to)
     */
    private String getXrefsTo(String addressStr, int offset, int limit, String programName) {
        return xrefCallGraphService.getXrefsTo(addressStr, offset, limit, programName).toJson();
    }

    /**
     * Get all references from a specific address (xref from)
     */
    private String getXrefsFrom(String addressStr, int offset, int limit, String programName) {
        return xrefCallGraphService.getXrefsFrom(addressStr, offset, limit, programName).toJson();
    }

    /**
     * Get all references to a specific function by name
     */
    private String getFunctionXrefs(String functionName, int offset, int limit, String programName) {
        return xrefCallGraphService.getFunctionXrefs(functionName, offset, limit, programName).toJson();
    }

/**
 * List all defined strings in the program with their addresses
 */
    private String listDefinedStrings(int offset, int limit, String filter, String programName) {
        return listingService.listDefinedStrings(offset, limit, filter, programName).toJson();
    }

    private String getFunctionCount(String programName) {
        return listingService.getFunctionCount(programName).toJson();
    }

    private String searchStrings(String query, int minLength, String encoding, int offset, int limit, String programName) {
        return listingService.searchStrings(query, minLength, encoding, offset, limit, programName).toJson();
    }

    /**
     * List all registered analyzers and their enabled/disabled state.
     */
    private String listAnalyzers(String programName) {
        return analysisService.listAnalyzers(programName).toJson();
    }

    /**
     * Trigger auto-analysis on the current or named program.
     */
    private String runAnalysis(String programName) {
        return analysisService.runAnalysis(programName).toJson();
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
     * Parse JSON from POST request body using Gson.
     */
    private Map<String, Object> parseJsonParams(HttpExchange exchange) throws IOException {
        return com.xebyte.core.JsonHelper.parseBody(exchange.getRequestBody());
    }

    /**
     * Convert Object (potentially List<Object>) to List<Map<String, String>>.
     * Delegates to JsonHelper.toMapStringList for Gson compatibility.
     */
    private List<Map<String, String>> convertToMapList(Object obj) {
        return com.xebyte.core.JsonHelper.toMapStringList(obj);
    }

    /**
     * Convert a list of strings into one big newline-delimited string, applying offset & limit.
     */
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
    private String saveCurrentProgram(String programName) {
        return programScriptService.saveCurrentProgram(programName).toJson();
    }

    private String listOpenPrograms() {
        return programScriptService.listOpenPrograms().toJson();
    }

    /**
     * Get detailed information about the currently active program
     */
    private String getCurrentProgramInfo() {
        return programScriptService.getCurrentProgramInfo().toJson();
    }

    /**
     * Switch MCP context to a different open program by name
     */
    private String switchProgram(String programName) {
        return programScriptService.switchProgram(programName).toJson();
    }

    /**
     * List all files in the current Ghidra project
     */
    private String listProjectFiles(String folderPath) {
        return programScriptService.listProjectFiles(folderPath).toJson();
    }

    /**
     * Open a program from the current project by path
     */
    private String openProgramFromProject(String path) {
        return programScriptService.openProgramFromProject(path).toJson();
    }

    private String openProgramFromProject(String path, boolean autoAnalyze) {
        return programScriptService.openProgramFromProject(path, autoAnalyze).toJson();
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
        return documentationHashService.getFunctionHash(functionAddress, programName).toJson();
    }

    // Backward compatibility overload
    private String getFunctionHash(String functionAddress) {
        return documentationHashService.getFunctionHash(functionAddress).toJson();
    }

    private String getBulkFunctionHashes(int offset, int limit, String filter, String programName) {
        return documentationHashService.getBulkFunctionHashes(offset, limit, filter, programName).toJson();
    }

    // Backward compatibility overload
    private String getBulkFunctionHashes(int offset, int limit, String filter) {
        return documentationHashService.getBulkFunctionHashes(offset, limit, filter).toJson();
    }

    /**
     * Export all documentation for a function (for use in cross-binary propagation)
     */
    private String getFunctionDocumentation(String functionAddress, String programName) {
        return documentationHashService.getFunctionDocumentation(functionAddress, programName).toJson();
    }

    private String applyFunctionDocumentation(String jsonBody, String programName) {
        return documentationHashService.applyFunctionDocumentation(jsonBody, programName).toJson();
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

    /** Response-aware overload: serializes the Response to JSON/text before sending. */
    private void sendResponse(HttpExchange exchange, com.xebyte.core.Response response) throws IOException {
        sendResponse(exchange, response.toJson());
    }

    /**
     * Get labels within a specific function by name
     */
    public String getFunctionLabels(String functionName, int offset, int limit, String programName) {
        return symbolLabelService.getFunctionLabels(functionName, offset, limit, programName).toJson();
    }

    public String getFunctionLabels(String functionName, int offset, int limit) {
        return symbolLabelService.getFunctionLabels(functionName, offset, limit).toJson();
    }

    public String renameLabel(String addressStr, String oldName, String newName, String programName) {
        return symbolLabelService.renameLabel(addressStr, oldName, newName, programName).toJson();
    }

    public String renameLabel(String addressStr, String oldName, String newName) {
        return symbolLabelService.renameLabel(addressStr, oldName, newName).toJson();
    }

    /**
     * Get all jump target addresses from a function's disassembly
     */
    public String getFunctionJumpTargets(String functionName, int offset, int limit, String programName) {
        return xrefCallGraphService.getFunctionJumpTargets(functionName, offset, limit, programName).toJson();
    }

    public String getFunctionJumpTargets(String functionName, int offset, int limit) {
        return xrefCallGraphService.getFunctionJumpTargets(functionName, offset, limit).toJson();
    }

    public String createLabel(String addressStr, String labelName, String programName) {
        return symbolLabelService.createLabel(addressStr, labelName, programName).toJson();
    }

    public String createLabel(String addressStr, String labelName) {
        return symbolLabelService.createLabel(addressStr, labelName).toJson();
    }

    public String batchCreateLabels(List<Map<String, String>> labels, String programName) {
        return symbolLabelService.batchCreateLabels(labels, programName).toJson();
    }

    public String batchCreateLabels(List<Map<String, String>> labels) {
        return symbolLabelService.batchCreateLabels(labels).toJson();
    }

    public String renameOrLabel(String addressStr, String newName, String programName) {
        return symbolLabelService.renameOrLabel(addressStr, newName, programName).toJson();
    }

    public String renameOrLabel(String addressStr, String newName) {
        return symbolLabelService.renameOrLabel(addressStr, newName).toJson();
    }

    public String deleteLabel(String addressStr, String labelName, String programName) {
        return symbolLabelService.deleteLabel(addressStr, labelName, programName).toJson();
    }

    public String deleteLabel(String addressStr, String labelName) {
        return symbolLabelService.deleteLabel(addressStr, labelName).toJson();
    }

    public String batchDeleteLabels(List<Map<String, String>> labels, String programName) {
        return symbolLabelService.batchDeleteLabels(labels, programName).toJson();
    }

    public String batchDeleteLabels(List<Map<String, String>> labels) {
        return symbolLabelService.batchDeleteLabels(labels).toJson();
    }

    /**
     * Get all functions called by the specified function (callees)
     */
    public String getFunctionCallees(String functionName, int offset, int limit, String programName) {
        return xrefCallGraphService.getFunctionCallees(functionName, offset, limit, programName).toJson();
    }

    /**
     * Get all functions that call the specified function (callers)
     */
    public String getFunctionCallers(String functionName, int offset, int limit, String programName) {
        return xrefCallGraphService.getFunctionCallers(functionName, offset, limit, programName).toJson();
    }

    /**
     * Get a call graph subgraph centered on the specified function
     */
    public String getFunctionCallGraph(String functionName, int depth, String direction, String programName) {
        return xrefCallGraphService.getFunctionCallGraph(functionName, depth, direction, programName).toJson();
    }

    /**
     * Get the complete call graph for the entire program
     */
    public String getFullCallGraph(String format, int limit, String programName) {
        return xrefCallGraphService.getFullCallGraph(format, limit, programName).toJson();
    }

    /**
     * Enhanced call graph analysis with cycle detection and path finding
     * Provides advanced graph algorithms for understanding function relationships
     */
    public String analyzeCallGraph(String startFunction, String endFunction, String analysisType, String programName) {
        return xrefCallGraphService.analyzeCallGraph(startFunction, endFunction, analysisType, programName).toJson();
    }

    /**
     * List all data types available in the program with optional category filtering
     */
    public String listDataTypes(String category, int offset, int limit, String programName) {
        return dataTypeService.listDataTypes(category, offset, limit, programName).toJson();
    }

    // Backward compatibility overload
    public String listDataTypes(String category, int offset, int limit) {
        return dataTypeService.listDataTypes(category, offset, limit).toJson();
    }

    /**
     * Create a new structure data type with specified fields
     */
    public String createStruct(String name, String fieldsJson) {
        return dataTypeService.createStruct(name, fieldsJson).toJson();
    }

    /**
     * Create a new enumeration data type with name-value pairs
     */
    public String createEnum(String name, String valuesJson, int size) {
        return dataTypeService.createEnum(name, valuesJson, size).toJson();
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
     * Apply a specific data type at the given memory address
     */
    public String applyDataType(String addressStr, String typeName, boolean clearExisting) {
        return dataTypeService.applyDataType(addressStr, typeName, clearExisting).toJson();
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
        return programScriptService.getMetadata().toJson();
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
        return listingService.listGlobals(offset, limit, filter, programName).toJson();
    }

    private String renameGlobalVariable(String oldName, String newName, String programName) {
        return symbolLabelService.renameGlobalVariable(oldName, newName, programName).toJson();
    }

    private String renameGlobalVariable(String oldName, String newName) {
        return symbolLabelService.renameGlobalVariable(oldName, newName).toJson();
    }

    /**
     * Get all entry points in the program
     */
    private String getEntryPoints() {
        return listingService.getEntryPoints(null).toJson();
    }

    // ----------------------------------------------------------------------------------
    // Data Type Analysis and Management Methods
    // ----------------------------------------------------------------------------------

    /**
     * Create a union data type with simplified approach for testing
     */
    /**
     * Create a union data type directly from fields object
     */
    /**
     * Create a union data type (legacy method)
     */
    private String createUnion(String name, String fieldsJson) {
        return dataTypeService.createUnion(name, fieldsJson, null).toJson();
    }

    /**
     * Get the size of a data type
     */
    private String getTypeSize(String typeName) {
        return dataTypeService.getTypeSize(typeName).toJson();
    }

    /**
     * Get the layout of a structure
     */
    private String getStructLayout(String structName) {
        return dataTypeService.getStructLayout(structName).toJson();
    }

    /**
     * Search for data types by pattern
     */
    private String searchDataTypes(String pattern, int offset, int limit) {
        return dataTypeService.searchDataTypes(pattern, offset, limit).toJson();
    }

    /**
     * Get all values in an enumeration
     */
    private String getEnumValues(String enumName) {
        return dataTypeService.getEnumValues(enumName).toJson();
    }

    /**
     * Create a typedef (type alias)
     */
    private String createTypedef(String name, String baseType) {
        return dataTypeService.createTypedef(name, baseType).toJson();
    }

    /**
     * Clone/copy a data type with a new name
     */
    private String cloneDataType(String sourceType, String newName) {
        return dataTypeService.cloneDataType(sourceType, newName).toJson();
    }

    /**
     * Validate if a data type fits at a given address
     */
    private String validateDataType(String addressStr, String typeName) {
        return dataTypeService.validateDataType(addressStr, typeName).toJson();
    }

    /**
     * Read memory at a specific address
     */
    private String readMemory(String addressStr, int length, String programName) {
        return programScriptService.readMemory(addressStr, length, programName).toJson();
    }

    // Backward compatibility overload
    private String readMemory(String addressStr, int length) {
        return programScriptService.readMemory(addressStr, length, null).toJson();
    }

    /**
     * Create an uninitialized memory block (e.g., for MMIO/peripheral regions).
     */
    private String createMemoryBlock(String name, String addressStr, long size,
                                     boolean read, boolean write, boolean execute,
                                     boolean isVolatile, String comment) {
        return programScriptService.createMemoryBlock(name, addressStr, size, read, write, execute, isVolatile, comment).toJson();
    }

    /**
     * Import data types from various sources
     */
    private String importDataTypes(String source, String format) {
        return dataTypeService.importDataTypes(source, format).toJson();
    }

    /**
     * Helper method to extract JSON values from simple JSON strings
     */
    /**
     * Convert an object to JSON string format
     */
    // ===================================================================================
    // NEW DATA STRUCTURE MANAGEMENT METHODS
    // ===================================================================================

    /**
     * Delete a data type from the program
     */
    private String deleteDataType(String typeName) {
        return dataTypeService.deleteDataType(typeName).toJson();
    }

    /**
     * Modify a field in an existing structure
     */
    private String modifyStructField(String structName, String fieldName, String newType, String newName) {
        return dataTypeService.modifyStructField(structName, fieldName, newType, newName).toJson();
    }

    /**
     * Add a new field to an existing structure
     */
    private String addStructField(String structName, String fieldName, String fieldType, int offset) {
        return dataTypeService.addStructField(structName, fieldName, fieldType, offset).toJson();
    }

    /**
     * Remove a field from an existing structure
     */
    private String removeStructField(String structName, String fieldName) {
        return dataTypeService.removeStructField(structName, fieldName).toJson();
    }

    /**
     * Create an array data type
     */
    private String createArrayType(String baseType, int length, String name) {
        return dataTypeService.createArrayType(baseType, length, name).toJson();
    }

    /**
     * Create a pointer data type
     */
    private String createPointerType(String baseType, String name) {
        return dataTypeService.createPointerType(baseType, name).toJson();
    }

    /**
     * Create a new data type category
     */
    private String createDataTypeCategory(String categoryPath) {
        return dataTypeService.createDataTypeCategory(categoryPath).toJson();
    }

    /**
     * Move a data type to a different category
     */
    private String moveDataTypeToCategory(String typeName, String categoryPath) {
        return dataTypeService.moveDataTypeToCategory(typeName, categoryPath).toJson();
    }

    /**
     * List all data type categories
     */
    private String listDataTypeCategories(int offset, int limit) {
        return dataTypeService.listDataTypeCategories(offset, limit).toJson();
    }

    /**
     * Create a function signature data type
     */
    private String createFunctionSignature(String name, String returnType, String parametersJson) {
        return dataTypeService.createFunctionSignature(name, returnType, parametersJson).toJson();
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
        return xrefCallGraphService.getBulkXrefs(addressesObj).toJson();
    }

    /**
     * 2. ANALYZE_DATA_REGION - Comprehensive single-call data analysis
     */
    private String analyzeDataRegion(String startAddressStr, int maxScanBytes,
                                      boolean includeXrefMap, boolean includeAssemblyPatterns,
                                      boolean includeBoundaryDetection) {
        return analysisService.analyzeDataRegion(startAddressStr, maxScanBytes, includeXrefMap, includeAssemblyPatterns, includeBoundaryDetection).toJson();
    }

    /**
     * 3. DETECT_ARRAY_BOUNDS - Array/table size detection
     */
    private String detectArrayBounds(String addressStr, boolean analyzeLoopBounds,
                                      boolean analyzeIndexing, int maxScanRange) {
        return analysisService.detectArrayBounds(addressStr, analyzeLoopBounds, analyzeIndexing, maxScanRange).toJson();
    }

    /**
     * 4. GET_ASSEMBLY_CONTEXT - Assembly pattern analysis
     */
    private String getAssemblyContext(Object xrefSourcesObj, int contextInstructions,
                                      Object includePatternsObj) {
        return xrefCallGraphService.getAssemblyContext(xrefSourcesObj, contextInstructions, includePatternsObj).toJson();
    }

    /**
     * 6. APPLY_DATA_CLASSIFICATION - Atomic type application
     */
    private String applyDataClassification(String addressStr, String classification,
                                           String name, String comment,
                                           Object typeDefinitionObj) {
        return dataTypeService.applyDataClassification(addressStr, classification, name, comment, typeDefinitionObj).toJson();
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
        return dataTypeService.analyzeStructFieldUsage(addressStr, structName, maxFunctionsToAnalyze).toJson();
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
        return analysisService.getFieldAccessContext(structAddressStr, fieldOffset, numExamples).toJson();
    }

    /**
     * SUGGEST_FIELD_NAMES - AI-assisted field name suggestions based on usage patterns
     *
     * @param structAddressStr Address of the structure instance
     * @param structSize Size of the structure in bytes (0 for auto-detect)
     * @return JSON string with field name suggestions
     */
    private String suggestFieldNames(String structAddressStr, int structSize) {
        return dataTypeService.suggestFieldNames(structAddressStr, structSize).toJson();
    }

    /**
     * 7. INSPECT_MEMORY_CONTENT - Memory content inspection with string detection
     *
     * Reads raw memory bytes and provides hex/ASCII representation with string detection hints.
     * This helps prevent misidentification of strings as numeric data.
     */
    private String inspectMemoryContent(String addressStr, int length, boolean detectStrings) {
        return analysisService.inspectMemoryContent(addressStr, length, detectStrings).toJson();
    }

    // ============================================================================
    // MALWARE ANALYSIS IMPLEMENTATION METHODS
    // ============================================================================

    /**
     * Detect cryptographic constants in the binary (AES S-boxes, SHA constants, etc.)
     */
    private String detectCryptoConstants() {
        return analysisService.detectCryptoConstants().toJson();
    }

    /**
     * Search for byte patterns with optional wildcards
     */
    private String searchBytePatterns(String pattern, String mask) {
        return analysisService.searchBytePatterns(pattern, mask).toJson();
    }

    /**
     * Find functions structurally similar to the target function
     * Uses basic block count, instruction count, call count, and cyclomatic complexity
     */
    private String findSimilarFunctions(String targetFunction, double threshold) {
        return analysisService.findSimilarFunctions(targetFunction, threshold).toJson();
    }


    /**
     * Analyze function control flow complexity
     * Calculates cyclomatic complexity, basic blocks, edges, and detailed metrics
     */
    private String analyzeControlFlow(String functionName) {
        return analysisService.analyzeControlFlow(functionName).toJson();
    }

    /**
     * Detect anti-analysis and anti-debugging techniques
     * Scans for known anti-debug APIs, timing checks, VM detection, and SEH tricks
     */
    private String findAntiAnalysisTechniques() {
        return malwareSecurityService.findAntiAnalysisTechniques().toJson();
    }


    /**
     * Batch decompile multiple functions
     */
    private String batchDecompileFunctions(String functionsParam) {
        return functionService.batchDecompileFunctions(functionsParam).toJson();
    }

    /**
     * Find potentially unreachable code blocks
     */
    private String findDeadCode(String functionName) {
        return analysisService.findDeadCode(functionName).toJson();
    }

    /**
     * Automatically identify and decrypt obfuscated strings
     */
    private String autoDecryptStrings() {
        return malwareSecurityService.autoDecryptStrings().toJson();
    }

    /**
     * Identify and analyze suspicious API call chains
     * Detects threat patterns like process injection, persistence, credential theft
     */
    private String analyzeAPICallChains() {
        return malwareSecurityService.analyzeAPICallChains().toJson();
    }



    /**
     * Enhanced IOC extraction with context and confidence scoring
     */
    private String extractIOCsWithContext() {
        return malwareSecurityService.extractIOCsWithContext().toJson();
    }



    /**
     * Detect common malware behaviors and techniques
     */
    private String detectMalwareBehaviors() {
        return malwareSecurityService.detectMalwareBehaviors().toJson();
    }


    /**
     * v1.5.0: Batch set multiple comments in a single operation
     * Reduces API calls from 10+ to 1 for typical function documentation
     */
    @SuppressWarnings("deprecation")
    private String batchSetComments(String functionAddress, List<Map<String, String>> decompilerComments,
                                    List<Map<String, String>> disassemblyComments, String plateComment) {
        return commentService.batchSetComments(functionAddress, decompilerComments, disassemblyComments, plateComment).toJson();
    }

    private String clearFunctionComments(String functionAddress, boolean clearPlate, boolean clearPre, boolean clearEol) {
        return commentService.clearFunctionComments(functionAddress, clearPlate, clearPre, clearEol).toJson();
    }

    private String setPlateComment(String functionAddress, String comment) {
        return commentService.setPlateComment(functionAddress, comment).toJson();
    }

    /**
     * v1.5.0: Get all variables in a function (parameters and locals)
     */
    @SuppressWarnings("deprecation")
    private String getFunctionVariables(String functionName, String programName) {
        return functionService.getFunctionVariables(functionName, programName).toJson();
    }

    // Backward compatibility overload
    @SuppressWarnings("deprecation")
    private String getFunctionVariables(String functionName) {
        return functionService.getFunctionVariables(functionName).toJson();
    }

    /**
     * v1.5.0: Batch rename function and all its components atomically
     */
    @SuppressWarnings("deprecation")
    private String batchRenameFunctionComponents(String functionAddress, String functionName,
                                                Map<String, String> parameterRenames,
                                                Map<String, String> localRenames,
                                                String returnType) {
        return functionService.batchRenameFunctionComponents(functionAddress, functionName, parameterRenames, localRenames, returnType).toJson();
    }

    /**
     * v1.5.0: Get valid Ghidra data type strings
     */
    private String getValidDataTypes(String category) {
        return dataTypeService.getValidDataTypes(category).toJson();
    }

    /**
     * v1.5.0: Analyze function completeness for documentation
     */
    private String analyzeFunctionCompleteness(String functionAddress) {
        return analysisService.analyzeFunctionCompleteness(functionAddress).toJson();
    }

    private String analyzeFunctionCompleteness(String functionAddress, boolean compact) {
        return analysisService.analyzeFunctionCompleteness(functionAddress, compact).toJson();
    }

    /**
     * v4.0.0: Apply all documentation to a function in a single call.
     * Orchestrates: goto -> rename -> prototype -> variable types -> variable renames -> comments -> score.
     * Ordering matters: prototype MUST come before comments (set_function_prototype wipes plate comments).
     * Each step is optional — only fields present in params are applied.
     * Each step is independent — failures in one step don't prevent subsequent steps.
     */
    @SuppressWarnings("unchecked")
    private String batchApplyDocumentation(Map<String, Object> params) {
        String address = params.get("address") != null ? params.get("address").toString() : null;
        if (address == null || address.trim().isEmpty()) {
            return "{\"error\": \"address parameter is required\"}";
        }

        StringBuilder sb = new StringBuilder();
        sb.append("{\"address\": \"").append(com.xebyte.core.ServiceUtils.escapeJson(address)).append("\", \"steps\": {");
        java.util.List<String> errors = new java.util.ArrayList<>();
        boolean firstStep = true;

        // Step 1: Goto (optional) — navigate CodeBrowser to this function
        Object gotoParam = params.get("goto");
        boolean doGoto = gotoParam instanceof Boolean ? (Boolean) gotoParam : false;
        if (doGoto) {
            if (!firstStep) sb.append(", ");
            firstStep = false;
            try {
                String gotoResult = gotoAddress(address);
                boolean gotoOk = gotoResult != null && !gotoResult.contains("\"error\"");
                sb.append("\"goto\": {\"success\": ").append(gotoOk).append("}");
            } catch (Exception e) {
                sb.append("\"goto\": {\"success\": false, \"error\": \"").append(com.xebyte.core.ServiceUtils.escapeJson(e.getMessage())).append("\"}");
                errors.add("goto: " + e.getMessage());
            }
        }

        // Step 2: Rename function (optional)
        String name = params.get("name") != null ? params.get("name").toString() : null;
        if (name != null && !name.isEmpty()) {
            if (!firstStep) sb.append(", ");
            firstStep = false;
            try {
                String renameResult = renameFunctionByAddress(address, name);
                boolean renameOk = renameResult != null && (renameResult.contains("Success") || renameResult.contains("Renamed"));
                sb.append("\"rename\": {\"success\": ").append(renameOk);
                if (!renameOk) {
                    sb.append(", \"error\": \"").append(com.xebyte.core.ServiceUtils.escapeJson(renameResult)).append("\"");
                    errors.add("rename: " + renameResult);
                }
                sb.append("}");
            } catch (Exception e) {
                sb.append("\"rename\": {\"success\": false, \"error\": \"").append(com.xebyte.core.ServiceUtils.escapeJson(e.getMessage())).append("\"}");
                errors.add("rename: " + e.getMessage());
            }
        }

        // Step 3: Set prototype (optional) — MUST come BEFORE comments (wipes plate comment)
        String prototype = params.get("prototype") != null ? params.get("prototype").toString() : null;
        if (prototype != null && !prototype.isEmpty()) {
            if (!firstStep) sb.append(", ");
            firstStep = false;
            try {
                String callingConvention = params.get("calling_convention") != null ? params.get("calling_convention").toString() : null;
                com.xebyte.core.FunctionService.PrototypeResult protoResult = setFunctionPrototype(address, prototype, callingConvention);
                sb.append("\"prototype\": {\"success\": ").append(protoResult.isSuccess());
                if (!protoResult.isSuccess()) {
                    sb.append(", \"error\": \"").append(com.xebyte.core.ServiceUtils.escapeJson(protoResult.getErrorMessage())).append("\"");
                    errors.add("prototype: " + protoResult.getErrorMessage());
                }
                sb.append("}");
            } catch (Exception e) {
                sb.append("\"prototype\": {\"success\": false, \"error\": \"").append(com.xebyte.core.ServiceUtils.escapeJson(e.getMessage())).append("\"}");
                errors.add("prototype: " + e.getMessage());
            }
        }

        // Step 4: Set variable types (optional)
        Object varTypesObj = params.get("variable_types");
        if (varTypesObj instanceof Map) {
            if (!firstStep) sb.append(", ");
            firstStep = false;
            Map<String, Object> varTypes = (Map<String, Object>) varTypesObj;
            int setCount = 0, failCount = 0;
            java.util.List<String> typeErrors = new java.util.ArrayList<>();
            for (Map.Entry<String, Object> entry : varTypes.entrySet()) {
                try {
                    String typeResult = setLocalVariableType(address, entry.getKey(), entry.getValue().toString());
                    if (typeResult != null && (typeResult.contains("Success") || typeResult.contains("success") || typeResult.contains("Changed"))) {
                        setCount++;
                    } else {
                        failCount++;
                        typeErrors.add(entry.getKey() + ": " + (typeResult != null ? typeResult.substring(0, Math.min(typeResult.length(), 100)) : "null"));
                    }
                } catch (Exception e) {
                    failCount++;
                    typeErrors.add(entry.getKey() + ": " + e.getMessage());
                }
            }
            sb.append("\"variable_types\": {\"success\": ").append(failCount == 0);
            sb.append(", \"set\": ").append(setCount).append(", \"failed\": ").append(failCount);
            if (!typeErrors.isEmpty()) {
                sb.append(", \"errors\": [");
                for (int i = 0; i < typeErrors.size(); i++) {
                    if (i > 0) sb.append(", ");
                    sb.append("\"").append(com.xebyte.core.ServiceUtils.escapeJson(typeErrors.get(i))).append("\"");
                }
                sb.append("]");
                errors.addAll(typeErrors);
            }
            sb.append("}");
        }

        // Step 5: Rename variables (optional)
        Object varRenamesObj = params.get("variable_renames");
        if (varRenamesObj instanceof Map) {
            if (!firstStep) sb.append(", ");
            firstStep = false;
            Map<String, String> varRenames = new java.util.LinkedHashMap<>();
            for (Map.Entry<String, Object> entry : ((Map<String, Object>) varRenamesObj).entrySet()) {
                varRenames.put(entry.getKey(), entry.getValue().toString());
            }
            try {
                String renameResult = batchRenameVariables(address, varRenames, true);
                // batchRenameVariables returns JSON — pass through key fields
                boolean renameOk = renameResult != null && renameResult.contains("\"success\": true");
                sb.append("\"variable_renames\": {\"success\": ").append(renameOk);
                // Extract counts from JSON response
                try {
                    int renamedIdx = renameResult.indexOf("\"variables_renamed\":");
                    int failedIdx = renameResult.indexOf("\"variables_failed\":");
                    if (renamedIdx >= 0) {
                        String countStr = renameResult.substring(renamedIdx + 20).trim();
                        int end = countStr.indexOf(',');
                        if (end < 0) end = countStr.indexOf('}');
                        sb.append(", \"renamed\": ").append(countStr.substring(0, end).trim());
                    }
                    if (failedIdx >= 0) {
                        String countStr = renameResult.substring(failedIdx + 19).trim();
                        int end = countStr.indexOf(',');
                        if (end < 0) end = countStr.indexOf('}');
                        sb.append(", \"failed\": ").append(countStr.substring(0, end).trim());
                    }
                } catch (Exception ignored) { }
                if (!renameOk) errors.add("variable_renames: " + renameResult);
                sb.append("}");
            } catch (Exception e) {
                sb.append("\"variable_renames\": {\"success\": false, \"error\": \"").append(com.xebyte.core.ServiceUtils.escapeJson(e.getMessage())).append("\"}");
                errors.add("variable_renames: " + e.getMessage());
            }
        }

        // Step 6: Set comments (optional) — AFTER prototype to avoid wipe
        String plateComment = params.get("plate_comment") != null ? params.get("plate_comment").toString() : null;
        java.util.List<Map<String, String>> decompComments = convertToMapList(params.get("decompiler_comments"));
        java.util.List<Map<String, String>> disasmComments = convertToMapList(params.get("disassembly_comments"));
        boolean hasComments = plateComment != null ||
                              (decompComments != null && !decompComments.isEmpty()) ||
                              (disasmComments != null && !disasmComments.isEmpty());
        if (hasComments) {
            if (!firstStep) sb.append(", ");
            firstStep = false;
            try {
                String commentResult = batchSetComments(address, decompComments, disasmComments, plateComment);
                boolean commentOk = commentResult != null && commentResult.contains("\"success\": true");
                sb.append("\"comments\": {\"success\": ").append(commentOk);
                // Extract plate_comment_set from response
                if (commentResult != null && commentResult.contains("\"plate_comment_set\": true")) {
                    sb.append(", \"plate\": true");
                }
                try {
                    int decompIdx = commentResult.indexOf("\"decompiler_comments_set\":");
                    int disasmIdx = commentResult.indexOf("\"disassembly_comments_set\":");
                    if (decompIdx >= 0) {
                        String countStr = commentResult.substring(decompIdx + 26).trim();
                        int end = countStr.indexOf(',');
                        if (end < 0) end = countStr.indexOf('}');
                        sb.append(", \"decompiler\": ").append(countStr.substring(0, end).trim());
                    }
                    if (disasmIdx >= 0) {
                        String countStr = commentResult.substring(disasmIdx + 27).trim();
                        int end = countStr.indexOf(',');
                        if (end < 0) end = countStr.indexOf('}');
                        sb.append(", \"disassembly\": ").append(countStr.substring(0, end).trim());
                    }
                } catch (Exception ignored) { }
                if (!commentOk) errors.add("comments: " + commentResult);
                sb.append("}");
            } catch (Exception e) {
                sb.append("\"comments\": {\"success\": false, \"error\": \"").append(com.xebyte.core.ServiceUtils.escapeJson(e.getMessage())).append("\"}");
                errors.add("comments: " + e.getMessage());
            }
        }

        sb.append("}"); // close "steps"

        // Step 7: Completeness score (optional, default true)
        Object scoreParam = params.get("score");
        boolean doScore = scoreParam instanceof Boolean ? (Boolean) scoreParam : true;
        if (doScore) {
            try {
                // Always use compact mode internally — AI already has workflow guidance in its prompt
                String scoreResult = analyzeFunctionCompleteness(address, true);
                sb.append(", \"completeness\": ").append(scoreResult);
            } catch (Exception e) {
                sb.append(", \"completeness\": {\"error\": \"").append(com.xebyte.core.ServiceUtils.escapeJson(e.getMessage())).append("\"}");
            }
        }

        // Errors summary
        sb.append(", \"errors\": [");
        for (int i = 0; i < errors.size(); i++) {
            if (i > 0) sb.append(", ");
            sb.append("\"").append(com.xebyte.core.ServiceUtils.escapeJson(errors.get(i))).append("\"");
        }
        sb.append("]}");

        return sb.toString();
    }

    /**
     * v1.5.0: Find next undefined function needing analysis
     */
    private String findNextUndefinedFunction(String startAddress, String criteria,
                                            String pattern, String direction, String programName) {
        return analysisService.findNextUndefinedFunction(startAddress, criteria, pattern, direction, programName).toJson();
    }

    // Backward compatibility overload
    private String findNextUndefinedFunction(String startAddress, String criteria,
                                            String pattern, String direction) {
        return analysisService.findNextUndefinedFunction(startAddress, criteria, pattern, direction).toJson();
    }

    /**
     * v1.5.0: Batch set variable types
     */
    @SuppressWarnings("deprecation")
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
        return functionService.batchRenameVariables(functionAddress, variableRenames, forceIndividual).toJson();
    }

    /**
     * Validate that batch operations actually persisted by checking current state
     */
    private String validateBatchOperationResults(String functionAddress, Map<String, String> expectedRenames, Map<String, String> expectedTypes) {
        return functionService.validateBatchOperationResults(functionAddress, expectedRenames, expectedTypes).toJson();
    }

    /**
     * NEW v1.6.0: Validate function prototype before applying
     */
    private String validateFunctionPrototype(String functionAddress, String prototype, String callingConvention) {
        return dataTypeService.validateFunctionPrototype(functionAddress, prototype, callingConvention).toJson();
    }

    /**
     * NEW v1.6.0: Check if data type exists in type manager
     */
    private String validateDataTypeExists(String typeName) {
        return dataTypeService.validateDataTypeExists(typeName).toJson();
    }

    /**
     * NEW v1.6.0: Determine if address has data/code and suggest operation
     */
    private String canRenameAtAddress(String addressStr, String programName) {
        return symbolLabelService.canRenameAtAddress(addressStr, programName).toJson();
    }

    private String canRenameAtAddress(String addressStr) {
        return symbolLabelService.canRenameAtAddress(addressStr).toJson();
    }

    /**
     * NEW v1.6.0: Comprehensive function analysis in single call
     */
    private String analyzeFunctionComplete(String name, boolean includeXrefs, boolean includeCallees,
                                          boolean includeCallers, boolean includeDisasm, boolean includeVariables,
                                          String programName) {
        return analysisService.analyzeFunctionComplete(name, includeXrefs, includeCallees, includeCallers, includeDisasm, includeVariables, programName).toJson();
    }

    // Backward compatibility overload
    private String analyzeFunctionComplete(String name, boolean includeXrefs, boolean includeCallees,
                                          boolean includeCallers, boolean includeDisasm, boolean includeVariables) {
        return analysisService.analyzeFunctionComplete(name, includeXrefs, includeCallees, includeCallers, includeDisasm, includeVariables).toJson();
    }

    /**
     * NEW v1.6.0: Enhanced function search with filtering and sorting
     */
    private String searchFunctionsEnhanced(String namePattern, Integer minXrefs, Integer maxXrefs,
                                          String callingConvention, Boolean hasCustomName, boolean regex,
                                          String sortBy, int offset, int limit, String programName) {
        return analysisService.searchFunctionsEnhanced(namePattern, minXrefs, maxXrefs, callingConvention, hasCustomName, regex, sortBy, offset, limit, programName).toJson();
    }

    /**
     * NEW v1.7.1: Disassemble a range of bytes
     */
    private String disassembleBytes(String startAddress, String endAddress, Integer length,
                                   boolean restrictToExecuteMemory) {
        return functionService.disassembleBytes(startAddress, endAddress, length, restrictToExecuteMemory).toJson();
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
        return functionService.deleteFunctionAtAddress(addressStr).toJson();
    }

    private String createFunctionAtAddress(String addressStr, String name, boolean disassembleFirst) {
        return functionService.createFunctionAtAddress(addressStr, name, disassembleFirst).toJson();
    }

    private String generateScriptContent(String purpose, String workflowType, Map<String, Object> parameters) {
        return programScriptService.generateScriptContent(purpose, workflowType, parameters).toJson();
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
        return programScriptService.runGhidraScriptWithCapture(scriptName, scriptArgs, timeoutSeconds, captureOutput).toJson();
    }

    // ===================================================================================
    // BOOKMARK METHODS (v1.9.4) - Progress tracking via Ghidra bookmarks
    // ===================================================================================

    /**
     * Set a bookmark at an address with category and comment.
     * Creates or updates the bookmark if one already exists at the address with the same category.
     */
    private String setBookmark(String addressStr, String category, String comment) {
        return programScriptService.setBookmark(addressStr, category, comment).toJson();
    }

    /**
     * List bookmarks, optionally filtered by category and/or address.
     */
    private String listBookmarks(String category, String addressStr) {
        return programScriptService.listBookmarks(category, addressStr).toJson();
    }

    /**
     * Delete a bookmark at an address with optional category filter.
     */
    private String deleteBookmark(String addressStr, String category) {
        return programScriptService.deleteBookmark(addressStr, category).toJson();
    }



    /**
     * List all external locations (imports, ordinal imports, etc.)
     */
    private String listExternalLocations(int offset, int limit, String programName) {
        return listingService.listExternalLocations(offset, limit, programName).toJson();
    }

    // Backward compatibility overload
    private String listExternalLocations(int offset, int limit) {
        return listingService.listExternalLocations(offset, limit, null).toJson();
    }

    /**
     * Get details of a specific external location
     */
    private String getExternalLocationDetails(String address, String dllName, String programName) {
        return listingService.getExternalLocationDetails(address, dllName, programName).toJson();
    }

    // Backward compatibility overload
    private String getExternalLocationDetails(String address, String dllName) {
        return listingService.getExternalLocationDetails(address, dllName, null).toJson();
    }

    /**
     * Rename an external location (e.g., change Ordinal_123 to a real function name)
     */
    private String renameExternalLocation(String address, String newName, String programName) {
        return symbolLabelService.renameExternalLocation(address, newName, programName).toJson();
    }

    private String renameExternalLocation(String address, String newName) {
        return symbolLabelService.renameExternalLocation(address, newName).toJson();
    }

    // ==================================================================================
    // CROSS-VERSION MATCHING TOOLS
    // ==================================================================================

    /**
     * Compare documentation status across all open programs.
     * Returns documented/undocumented function counts for each program.
     */
    private String compareProgramsDocumentation() {
        return documentationHashService.compareProgramsDocumentation().toJson();
    }

    private String findUndocumentedByString(String stringAddress, String programName) {
        return documentationHashService.findUndocumentedByString(stringAddress, programName).toJson();
    }

    private String batchStringAnchorReport(String pattern, String programName) {
        return documentationHashService.batchStringAnchorReport(pattern, programName).toJson();
    }

    // ==========================================================================
    // FUZZY MATCHING & DIFF HANDLERS
    // ==========================================================================

    private String handleGetFunctionSignature(String addressStr, String programName) {
        return documentationHashService.handleGetFunctionSignature(addressStr, programName).toJson();
    }

    private String handleFindSimilarFunctionsFuzzy(String addressStr, String sourceProgramName,
            String targetProgramName, double threshold, int limit) {
        return documentationHashService.handleFindSimilarFunctionsFuzzy(addressStr, sourceProgramName,
            targetProgramName, threshold, limit).toJson();
    }

    private String handleBulkFuzzyMatch(String sourceProgramName, String targetProgramName,
            double threshold, int offset, int limit, String filter) {
        return documentationHashService.handleBulkFuzzyMatch(sourceProgramName, targetProgramName,
            threshold, offset, limit, filter).toJson();
    }

    private String handleDiffFunctions(String addressA, String addressB, String programAName, String programBName) {
        return documentationHashService.handleDiffFunctions(addressA, addressB, programAName, programBName).toJson();
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

        RepositoryAdapter repo = getProjectRepository();
        StringBuilder sb = new StringBuilder();
        sb.append("{\"checkouts\": [");
        int count = collectCheckouts(sb, folder, 0, repo);
        sb.append("], \"count\": ").append(count).append("}");
        return sb.toString();
    }

    private int collectCheckouts(StringBuilder sb, DomainFolder folder, int count, RepositoryAdapter repo) {
        for (DomainFile f : folder.getFiles()) {
            boolean localCheckout = f.isCheckedOut();
            ItemCheckoutStatus[] serverCheckouts = null;

            // Check server-side checkouts via RepositoryAdapter
            if (repo != null && f.isVersioned()) {
                try {
                    String path = f.getPathname();
                    int lastSlash = path.lastIndexOf('/');
                    String parentPath = lastSlash > 0 ? path.substring(0, lastSlash) : "/";
                    String fileName = lastSlash >= 0 ? path.substring(lastSlash + 1) : path;
                    serverCheckouts = repo.getCheckouts(parentPath, fileName);
                } catch (Exception e) { /* skip */ }
            }
            boolean serverCheckout = serverCheckouts != null && serverCheckouts.length > 0;

            if (localCheckout || serverCheckout) {
                if (count > 0) sb.append(", ");
                appendFileJson(sb, f);
                if (serverCheckout) {
                    sb.setLength(sb.length() - 1); // remove closing }
                    sb.append(", \"server_checkouts\": [");
                    for (int i = 0; i < serverCheckouts.length; i++) {
                        if (i > 0) sb.append(", ");
                        sb.append("{\"checkout_id\": ").append(serverCheckouts[i].getCheckoutId());
                        sb.append(", \"user\": \"").append(escapeJson(serverCheckouts[i].getUser())).append("\"");
                        sb.append(", \"checkout_version\": ").append(serverCheckouts[i].getCheckoutVersion());
                        sb.append("}");
                    }
                    sb.append("]}");
                }
                count++;
            }
        }
        for (DomainFolder sub : folder.getFolders()) {
            count = collectCheckouts(sb, sub, count, repo);
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

    /**
     * Terminate ALL server-side checkouts in a folder recursively.
     * Returns a summary of all terminated checkouts.
     */
    private String terminateAllCheckouts(String folderPath) {
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

        RepositoryAdapter repo = getProjectRepository();
        if (repo == null) {
            return "{\"error\": \"Cannot terminate checkouts: project has no repository connection\"}";
        }

        StringBuilder details = new StringBuilder();
        details.append("[");
        int[] counts = {0, 0}; // [files_with_checkouts, total_terminated]
        terminateCheckoutsRecursive(folder, repo, details, counts);
        details.append("]");

        return "{\"status\": \"terminated\", \"folder\": \"" + escapeJson(folderPath != null ? folderPath : "/") + "\", " +
            "\"files_with_checkouts\": " + counts[0] + ", " +
            "\"checkouts_terminated\": " + counts[1] + ", " +
            "\"details\": " + details.toString() + "}";
    }

    private void terminateCheckoutsRecursive(DomainFolder folder, RepositoryAdapter repo, StringBuilder details, int[] counts) {
        for (DomainFile f : folder.getFiles()) {
            if (!f.isVersioned()) continue;
            try {
                String path = f.getPathname();
                int lastSlash = path.lastIndexOf('/');
                String parentPath = lastSlash > 0 ? path.substring(0, lastSlash) : "/";
                String fileName = lastSlash >= 0 ? path.substring(lastSlash + 1) : path;
                ItemCheckoutStatus[] checkouts = repo.getCheckouts(parentPath, fileName);
                if (checkouts != null && checkouts.length > 0) {
                    int terminated = 0;
                    for (ItemCheckoutStatus cs : checkouts) {
                        try {
                            repo.terminateCheckout(parentPath, fileName, cs.getCheckoutId(), false);
                            terminated++;
                        } catch (Exception e) { /* continue */ }
                    }
                    if (counts[0] > 0) details.append(", ");
                    details.append("{\"path\": \"").append(escapeJson(path)).append("\"");
                    details.append(", \"terminated\": ").append(terminated);
                    details.append(", \"total\": ").append(checkouts.length).append("}");
                    counts[0]++;
                    counts[1] += terminated;
                }
            } catch (Exception e) { /* skip file */ }
        }
        for (DomainFolder sub : folder.getFolders()) {
            terminateCheckoutsRecursive(sub, repo, details, counts);
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

    /**
     * Navigate the CodeBrowser listing/decompiler to a specific address.
     * Finds the running CodeBrowser via ToolManager and uses GoToService.
     */
    private String gotoAddress(String addressStr) {
        if (addressStr == null || addressStr.trim().isEmpty()) {
            return "{\"error\": \"address parameter is required\"}";
        }

        try {
            Project project = tool.getProject();
            if (project == null) {
                return "{\"error\": \"No project open\"}";
            }

            // Find a running CodeBrowser
            ghidra.framework.model.ToolManager tm = project.getToolManager();
            if (tm == null) {
                return "{\"error\": \"ToolManager not available\"}";
            }

            PluginTool codeBrowser = null;
            for (PluginTool runningTool : tm.getRunningTools()) {
                if (runningTool.getService(ghidra.app.services.ProgramManager.class) != null) {
                    codeBrowser = runningTool;
                    break;
                }
            }

            if (codeBrowser == null) {
                return "{\"error\": \"No CodeBrowser running\"}";
            }

            // Get GoToService from the CodeBrowser
            GoToService goToService = codeBrowser.getService(GoToService.class);
            if (goToService == null) {
                return "{\"error\": \"GoToService not available in CodeBrowser\"}";
            }

            // Get the current program from the CodeBrowser
            ghidra.app.services.ProgramManager pm = codeBrowser.getService(ghidra.app.services.ProgramManager.class);
            Program program = pm.getCurrentProgram();
            if (program == null) {
                return "{\"error\": \"No program open in CodeBrowser\"}";
            }

            // Parse the address
            Address addr = program.getAddressFactory().getAddress(addressStr);
            if (addr == null) {
                return "{\"error\": \"Invalid address: " + escapeJson(addressStr) + "\"}";
            }

            // Navigate on the EDT
            final GoToService gts = goToService;
            final Address targetAddr = addr;
            final AtomicBoolean success = new AtomicBoolean(false);
            SwingUtilities.invokeAndWait(() -> {
                success.set(gts.goTo(targetAddr));
            });

            if (success.get()) {
                // Check if the address is in a function
                Function func = program.getFunctionManager().getFunctionContaining(addr);
                String funcInfo = func != null
                    ? ", \"function\": \"" + escapeJson(func.getName()) + "\""
                    : "";
                return "{\"success\": true, \"address\": \"" + addr.toString() + "\"" + funcInfo + "}";
            } else {
                return "{\"error\": \"GoToService could not navigate to " + escapeJson(addressStr) + "\"}";
            }
        } catch (Exception e) {
            return "{\"error\": \"Failed to navigate: " + escapeJson(e.getMessage()) + "\"}";
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
        // Deregister from UDS ServerManager
        ServerManager.getInstance().deregisterTool(tool);

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
