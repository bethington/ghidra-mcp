package com.xebyte;

import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.services.DebuggerTraceManagerService;

import ghidra.program.model.data.*;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.Msg;
import ghidra.trace.model.Trace;

import ghidra.framework.options.Options;

import docking.action.DockingAction;
import docking.action.MenuData;
import docking.ActionContext;

// Block model for control flow analysis

import com.xebyte.core.VersionInfo;
import com.xebyte.core.AnnotationScanner;
import com.xebyte.core.McpHttpServer;
import com.xebyte.core.FrontEndProgramProvider;
import com.xebyte.core.JsonHelper;
import com.xebyte.core.NamingPolicy;
import com.xebyte.core.ServerManager;

import ghidra.framework.main.ApplicationLevelPlugin;

import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectLocator;
import ghidra.framework.model.ProjectManager;
import ghidra.framework.main.AppInfo;

import com.sun.net.httpserver.Headers;
import com.xebyte.core.HttpExchange;

import javax.swing.SwingUtilities;
import java.nio.charset.StandardCharsets;
import java.io.*;
import java.util.*;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = ghidra.framework.main.UtilityPluginPackage.NAME,
    category = PluginCategoryNames.COMMON,
    shortDescription = "GhidraMCP - HTTP server plugin",
    description = "GhidraMCP - Starts an embedded HTTP server to expose program data via REST API and MCP bridge. " +
                  "Provides 205 endpoints for reverse engineering automation. " +
                  "Port configurable via Tool Options. " +
                  "Features: function analysis, decompilation, symbol management, cross-references, label operations, " +
                  "high-performance batch data analysis, field-level structure analysis, advanced call graph analysis, " +
                  "malware analysis (IOC extraction, behavior detection, anti-analysis detection), and Ghidra script automation. " +
                  "See https://github.com/bethington/ghidra-mcp for documentation and version history."
)
public class GhidraMCPPlugin extends Plugin implements ApplicationLevelPlugin {

    // Static singleton: one TCP server shared across all tool windows (fixes #35).
    // Serves this plugin's own FrontEnd-mode services; the socket is ServerManager's.
    private static int instanceCount = 0;
    // What this plugin's /mcp/schema serves, for the Server Status dialog.
    private int endpointCount;
    // Live plugin instances. The TCP server's route lambdas capture the
    // owning instance's services (programProvider, listingService, …); when
    // that instance is disposed first while others survive, the routes are
    // left bound to a dead PluginTool. dispose() consults this list to hand
    // ownership to a survivor by restarting the server with its services.
    private static final java.util.List<GhidraMCPPlugin> liveInstances =
        new java.util.concurrent.CopyOnWriteArrayList<>();
    private boolean ownsServer = false; // true if this instance started the server
    private static final String OPTION_CATEGORY_NAME = "GhidraMCP HTTP Server";
    private static final String PORT_OPTION_NAME = "Server Port";
    private static final int DEFAULT_PORT = 8089;
    private static final String UDS_ENABLED_OPTION = "Enable UDS Transport";
    private static final String TCP_ENABLED_OPTION = "Enable TCP Transport";
    private static final String STRICT_NAMING_ENFORCEMENT_OPTION = "Strict Naming Enforcement";
    private static final String LEGACY_STRICT_FUNCTION_NAMES_OPTION = "Strict Function Name Enforcement";
    // Both transports default ON. UDS gives per-PID socket files so multi-
    // instance setups don't race for the same TCP port (issue #175 primary
    // fix). TCP stays on by default because many users have HTTP-only
    // tooling pointed at 127.0.0.1:8089 (the release deploy/smoke test
    // itself uses it). When 8089 is in use, the port-range fallback below
    // walks 8089..8089+TCP_PORT_FALLBACK_RANGE-1 and surfaces the actual
    // bound port via /mcp/instance_info → tcp_port for bridge discovery.
    //
    // Users who want UDS-only (no TCP listener at all) can disable TCP via
    // Tool Options → GhidraMCP HTTP Server → "Enable TCP Transport".
    private static final boolean DEFAULT_UDS_ENABLED = true;
    private static final boolean DEFAULT_TCP_ENABLED = true;
    // Maximum TCP port-range fallback. If the configured port is in use, the
    // plugin tries port..port+TCP_PORT_FALLBACK_RANGE-1 and uses the first
    // that binds. Surfaces the actual port via /mcp/instance_info so the
    // bridge can discover it without hard-coding 8089.
    private static final int TCP_PORT_FALLBACK_RANGE = 16;

    private static final int HTTP_IDLE_TIMEOUT_SECONDS = 300;  // 5 minutes for idle connections

    // Menu actions for Tools > GhidraMCP submenu
    private DockingAction startServerAction;
    private DockingAction stopServerAction;
    private DockingAction restartServerAction;
    private DockingAction serverStatusAction;

    // Program provider for on-demand program access (FrontEnd mode)
    private final FrontEndProgramProvider programProvider;

    // Threading strategy shared by every service AND the AnnotationScanner's
    // dry-run wrapper, so a dry-run transaction and the write it wraps always
    // nest on the same thread (see AnnotationScanner.createHandler).
    private final com.xebyte.core.ThreadingStrategy threadingStrategy;

    // Service layer for delegated operations
    private final com.xebyte.core.CoreServices services;
    private final com.xebyte.core.GuiToolService guiToolService;
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
    private final com.xebyte.core.DebuggerService debuggerService;
    private final com.xebyte.core.PromptPolicyService promptPolicyService;

    public GhidraMCPPlugin(PluginTool tool) {
        super(tool);
        instanceCount++;
        liveInstances.add(this);

        // Initialize service layer — FrontEnd mode: opens programs on-demand from project
        this.programProvider = new FrontEndProgramProvider(tool, this);
        this.threadingStrategy = new com.xebyte.headless.DirectThreadingStrategy();
        this.services = com.xebyte.core.CoreServices.build(programProvider, threadingStrategy);
        this.listingService = services.listing();
        this.commentService = services.comment();
        this.symbolLabelService = services.symbolLabel();
        this.functionService = services.function();
        this.xrefCallGraphService = services.xrefCallGraph();
        this.dataTypeService = services.dataType();
        this.documentationHashService = services.documentationHash();
        this.analysisService = services.analysis();
        this.malwareSecurityService = services.malwareSecurity();
        this.programScriptService = services.programScript();
        this.debuggerService = new com.xebyte.core.DebuggerService(programProvider, threadingStrategy, tool);
        this.guiToolService = new com.xebyte.core.GuiToolService(tool);
        this.promptPolicyService = new com.xebyte.core.PromptPolicyService();
        Msg.info(this, "============================================");
        Msg.info(this, "GhidraMCP " + VersionInfo.getFullVersion());
        Msg.info(this, "============================================");

        // Server authenticator: ensure credentials are registered before any project opens.
        // GhidraMCPAuthInitializer implements ModuleInitializer, but that ExtensionPoint
        // is only reliable for Ghidra's own built-in modules — user extensions may not be
        // discovered by ClassSearcher in time. Call run() explicitly here as a guaranteed
        // fallback; it has an idempotency guard so double-invocation is safe.
        if (!com.xebyte.core.GhidraMCPAuthInitializer.isRegistered()) {
            new com.xebyte.core.GhidraMCPAuthInitializer().run();
        }
        if (com.xebyte.core.GhidraMCPAuthInitializer.isRegistered()) {
            Msg.info(this, "GhidraMCP: Server authenticator registered — auto-login active");
        } else {
            Msg.info(this, "GhidraMCP: No server credentials configured — GUI auth will be used");
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
        options.registerOption(STRICT_NAMING_ENFORCEMENT_OPTION,
            NamingPolicy.defaultStrictNamingEnforcement(), null,
            "Reject function/global names that fail the built-in name-quality checks " +
            "on rename_function, rename_symbol, " +
            "set_global, and related write guards. Also controls struct-field " +
            "Hungarian prefix auto-fixes. Disable when your naming convention " +
            "does not match the built-in heuristic; function/global convention warnings are still returned. " +
            "Takes effect when the MCP server starts or restarts.");
        migrateLegacyNamingOption(options);
        refreshNamingPolicyFromOptions();

        // One server, both transports. Each is attempted independently inside
        // McpHttpServer, so a Unix socket that cannot bind still leaves TCP up --
        // that is the safety net this used to arrange by starting two servers.
        ServerManager mgr = ServerManager.getInstance();
        if (mgr.isRunning()) {
            // Another tool window already brought it up; this one only joins the
            // tool map so deregistration counts it. The running server keeps the
            // scanner it was started with.
            Msg.info(this, "GhidraMCP server already running — sharing with this tool window.");
            try {
                mgr.registerTool(tool, buildScanner(), this::registerHandCodedRoutes, transportConfig());
            } catch (IOException e) {
                Msg.warn(this, "Failed to register tool with the running server: " + e.getMessage());
            }
        } else {
            McpHttpServer.Config config = transportConfig();
            try {
                mgr.registerTool(tool, buildScanner(), this::registerHandCodedRoutes, config);
                ownsServer = true;
                java.nio.file.Path sock = mgr.getSocketPath();
                if (sock != null) {
                    Msg.info(this, "GhidraMCP UDS server active at " + sock);
                }
                int actualPort = mgr.getBoundTcpPort();
                if (actualPort > 0) {
                    // The bound port is not always the configured one: port-range
                    // fallback fires whenever another instance holds it (#175).
                    String portStr = actualPort == config.port()
                        ? String.valueOf(actualPort)
                        : (actualPort + " (fallback; configured " + config.port() + " was in use)");
                    Msg.info(this, "GhidraMCP TCP server active on port " + portStr);
                }
                if (config.uds() && sock == null) {
                    Msg.warn(this, "GhidraMCP: the Unix socket did not bind; TCP only.");
                }
            } catch (IOException e) {
                Msg.error(this, "Failed to start MCP server: " + e.getMessage(), e);
                Msg.showError(this, null, "GhidraMCP Server Error",
                    "Failed to start MCP server.\n\n" +
                    "No transports are running.\n\n" +
                    "Error: " + e.getMessage());
            }
        }

        createMenuActions();
    }

    private boolean isServerRunning() {
        return ServerManager.getInstance().isRunning();
    }

    private void refreshNamingPolicyFromOptions() {
        Options options = tool.getOptions(OPTION_CATEGORY_NAME);
        boolean strict = options.getBoolean(STRICT_NAMING_ENFORCEMENT_OPTION,
            NamingPolicy.defaultStrictNamingEnforcement());

        // v5.11.2: load .ghidra-mcp/conventions.json from the active
        // project root before applying the Tool Option boolean override.
        // Order matters: the JSON sets all sections (including mode), then
        // the GUI toggle overrides JUST the mode bit. That keeps the GUI
        // checkbox as the user's most-recent intent without forcing them
        // to also delete the JSON file.
        java.nio.file.Path projectDir = resolveProjectRootDir();
        com.xebyte.core.ConventionConfigLoader.LoadResult loadResult =
                NamingPolicy.getInstance().refreshFromProjectRoot(projectDir);
        if (loadResult.loaded()) {
            Msg.info(this, "Loaded convention config from " + loadResult.resolvedFrom());
        } else if (loadResult.error() != null) {
            Msg.warn(this, "Convention config not loaded: " + loadResult.error()
                    + " — using built-in defaults");
        }
        for (String warning : loadResult.warnings()) {
            Msg.warn(this, "Convention config: " + warning);
        }

        // Apply the Tool Option toggle on top. setStrictNamingEnforcement()
        // preserves all other config sections — only the mode flips.
        NamingPolicy.getInstance().setStrictNamingEnforcement(strict, "tool_options");
        Msg.info(this, "GhidraMCP strict naming enforcement: " + strict);
    }

    /** Best-effort resolution of the active Ghidra project directory.
     * Returns null if no project is currently open. */
    private java.nio.file.Path resolveProjectRootDir() {
        try {
            Project project = tool.getProject();
            if (project == null) return null;
            ghidra.framework.model.ProjectLocator locator = project.getProjectLocator();
            if (locator == null) return null;
            java.io.File dir = locator.getProjectDir();
            return dir != null ? dir.toPath() : null;
        } catch (Exception e) {
            // Any reflection / API surprise here is non-fatal — fall back
            // to defaults. The active config is still usable, just without
            // the per-project overrides.
            return null;
        }
    }

    private void migrateLegacyNamingOption(Options options) {
        if (!options.contains(LEGACY_STRICT_FUNCTION_NAMES_OPTION)
                || !options.isDefaultValue(STRICT_NAMING_ENFORCEMENT_OPTION)) {
            return;
        }

        boolean legacyStrict = options.getBoolean(LEGACY_STRICT_FUNCTION_NAMES_OPTION,
                NamingPolicy.defaultStrictNamingEnforcement());
        options.setBoolean(STRICT_NAMING_ENFORCEMENT_OPTION, legacyStrict);
        options.removeOption(LEGACY_STRICT_FUNCTION_NAMES_OPTION);
        Msg.info(this, "Migrated GhidraMCP naming enforcement option from legacy function-name setting");
    }

    private void stopServer() {
        ServerManager.getInstance().stopUdsServer();
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
                StringBuilder started = new StringBuilder();
                ServerManager mgr = ServerManager.getInstance();
                if (!mgr.isRunning()) {
                    try {
                        startServer();
                        ownsServer = true;
                        java.nio.file.Path sock = mgr.getSocketPath();
                        if (sock != null) {
                            started.append("UDS: ").append(sock);
                        }
                        int boundPort = mgr.getBoundTcpPort();
                        if (boundPort > 0) {
                            if (started.length() > 0) started.append("\n");
                            started.append("TCP: port ").append(boundPort);
                        }
                    } catch (IOException e) {
                        Msg.showError(getClass(), null, "GhidraMCP", "Failed to start MCP server: " + e.getMessage());
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
                boolean udsRunning = ServerManager.getInstance().isRunning();
                String udsStatus = udsRunning
                    ? "Running (" + ServerManager.getInstance().getSocketPath() + ")"
                    : "Disabled";
                int statusPort = ServerManager.getInstance().getBoundTcpPort();
                String tcpStatus = statusPort > 0
                    ? "Running (port " + statusPort + ")"
                    : "Disabled";
                String message = "GhidraMCP Server Status\n\n" +
                    "UDS: " + udsStatus + "\n" +
                    "TCP: " + tcpStatus + "\n" +
                    "Strict naming enforcement: " + NamingPolicy.getInstance().isStrictNamingEnforcement() + "\n" +
                    "Version: " + VersionInfo.getFullVersion() + "\n" +
                    "Endpoints: " + endpointCount;
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

    /**
     * The scanner both transports serve from.
     *
     * <p>One scanner over one service set over one ProgramProvider. ServerManager
     * used to build a second of each for the Unix socket, which is why a program
     * the plugin could open on demand read as "not found" over UDS.
     */
    private AnnotationScanner buildScanner() {
        AnnotationScanner scanner = new AnnotationScanner(programProvider, threadingStrategy,
            services.plus(debuggerService, promptPolicyService,
                new com.xebyte.core.ProjectLifecycleService(programProvider),
                new com.xebyte.core.VersionControlService(programProvider,
                    new com.xebyte.core.ProjectServerSession(programProvider)),
                new com.xebyte.core.ServerLifecycleService(services.programScript(), guiLifecycle()),
                guiToolService,
                new com.xebyte.core.DocumentationApplyService(programProvider, services.function(), services.comment(), services.symbolLabel(),
                    services.analysis(), guiToolService::gotoAddress)));
        // The hand-coded routes are live on every transport, but the scanner only
        // knows annotated methods; without this they stay out of /mcp/schema and so
        // out of the bridge's dynamic tool discovery.
        com.xebyte.core.ManualToolDescriptors.addAll(
            scanner, com.xebyte.core.ManualToolDescriptors.SHARED_ROUTES);
        endpointCount = scanner.getDescriptors().size();
        Msg.info(this, "Endpoints: " + endpointCount);
        return scanner;
    }

    /**
     * The transports this tool asks for, from its options.
     *
     * <p>Several Ghidra instances are the common case (#175), so TCP falls back
     * through the next ports and the bridge learns the bound one from
     * /mcp/instance_info.
     */
    private McpHttpServer.Config transportConfig() {
        Options options = tool.getOptions(OPTION_CATEGORY_NAME);
        boolean uds = options.getBoolean(UDS_ENABLED_OPTION, DEFAULT_UDS_ENABLED);
        boolean tcp = options.getBoolean(TCP_ENABLED_OPTION, DEFAULT_TCP_ENABLED);
        // Neither enabled would leave the plugin installed and unreachable, with
        // nothing in the UI saying so. TCP is the one that reports a port.
        if (!uds && !tcp) {
            tcp = true;
        }
        int port = options.getInt(PORT_OPTION_NAME, DEFAULT_PORT);
        return new McpHttpServer.Config(uds, tcp, "127.0.0.1", port,
            TCP_PORT_FALLBACK_RANGE, ServerManager.GUI_WORKERS);
    }

    /** Start (or restart) the one server, serving this tool's services. */
    private void startServer() throws IOException {
        refreshNamingPolicyFromOptions();
        ServerManager mgr = ServerManager.getInstance();
        if (mgr.isRunning()) {
            mgr.rebind(buildScanner(), this::registerHandCodedRoutes);
        } else {
            mgr.registerTool(tool, buildScanner(), this::registerHandCodedRoutes,
                transportConfig());
        }
    }

    // ----------------------------------------------------------------------------------
    // Pagination-aware listing (consolidated under listProgramItems)
    // ----------------------------------------------------------------------------------

    // ----------------------------------------------------------------------------------
    // Logic for rename, decompile, etc.
    // ----------------------------------------------------------------------------------

    // ----------------------------------------------------------------------------------
    // New methods to implement the new functionalities
    // ----------------------------------------------------------------------------------

    // ----------------------------------------------------------------------------------
    // Utility: parse query params, parse post params, pagination, etc.
    // ----------------------------------------------------------------------------------

    /**
     * Parse JSON from POST request body using Gson.
     */
    private Map<String, Object> parseJsonParams(HttpExchange exchange) throws IOException {
        return com.xebyte.core.JsonHelper.parseBody(exchange.getRequestBody());
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
     * @param programName The name or project path (e.g., "/Project/1.0/example.dll"), or null/empty for current
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
            error.append("\"hint\": \"Use full project path (e.g., /Project/1.0/example.dll) to open on-demand\", ");
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
     * What the GUI adds to the shared {@code /exit_ghidra}: answer Ghidra's own prompts while
     * it saves, save the debugger traces too, and close the tools without writing their
     * layouts back.
     */
    private com.xebyte.core.ServerLifecycle guiLifecycle() {
        return new com.xebyte.core.ServerLifecycle() {
            @Override
            public void prepare() {
                promptPolicyService.enableFor("exit_ghidra", 30);
            }

            @Override
            public Map<String, Object> saveExtras() {
                return Map.of("traces", saveAllOpenDebuggerTraces());
            }

            @Override
            public void exit() {
                SwingUtilities.invokeLater(GhidraMCPPlugin.this::closeGhidraWithoutSavingToolLayouts);
            }
        };
    }

    private void closeGhidraWithoutSavingToolLayouts() {
        PluginTool currentTool = getTool();
        if (currentTool == null) {
            return;
        }

        Set<PluginTool> tools = Collections.newSetFromMap(new IdentityHashMap<>());
        tools.add(currentTool);
        try {
            Project project = currentTool.getProject();
            if (project != null && project.getToolManager() != null) {
                for (PluginTool runningTool : project.getToolManager().getRunningTools()) {
                    if (runningTool != null) {
                        tools.add(runningTool);
                    }
                }
            }
        } catch (Throwable e) {
            Msg.warn(this, "Unable to enumerate running tools before exit: " + e.getMessage());
        }

        for (PluginTool tool : tools) {
            try {
                tool.setConfigChanged(false);
            } catch (Throwable e) {
                Msg.warn(this, "Unable to clear tool layout change flag: " + e.getMessage());
            }
        }

        currentTool.close();

        // Closing every tool does NOT exit Ghidra -- the front end outlives them
        // and the JVM stays up. Measured: /exit_ghidra saved 5 programs, stopped
        // both servers, deregistered all 3 tools, and then sat there with the
        // project window still on screen, while the caller had already been told
        // "exiting Ghidra". Exit is the front end's own operation.
        try {
            AppInfo.exitGhidra();
        } catch (Throwable e) {
            Msg.error(this, "Tools closed but Ghidra did not exit: " + e.getMessage(), e);
        }
    }

    private Map<String, Object> saveAllOpenDebuggerTraces() {
        List<Map<String, Object>> saved = new ArrayList<>();
        List<Map<String, Object>> errors = new ArrayList<>();
        Set<Trace> seen = Collections.newSetFromMap(new IdentityHashMap<>());

        PluginTool currentTool = getTool();
        if (currentTool == null || currentTool.getProject() == null) {
            return JsonHelper.mapOf(
                "success", true,
                "saved_count", 0,
                "traces", saved,
                "errors", errors,
                "message", "No project/tool available for trace save"
            );
        }

        List<PluginTool> tools = new ArrayList<>();
        tools.add(currentTool);
        try {
            ghidra.framework.model.ToolManager tm = currentTool.getProject().getToolManager();
            if (tm != null) {
                for (PluginTool runningTool : tm.getRunningTools()) {
                    if (runningTool != null && !tools.contains(runningTool)) {
                        tools.add(runningTool);
                    }
                }
            }
        } catch (Throwable e) {
            errors.add(JsonHelper.mapOf(
                "error", "Unable to enumerate running tools: " +
                    (e.getMessage() != null ? e.getMessage() : e.toString())
            ));
        }

        for (PluginTool runningTool : tools) {
            DebuggerTraceManagerService traceMgr = runningTool.getService(DebuggerTraceManagerService.class);
            if (traceMgr == null) {
                continue;
            }
            List<Trace> traces = new ArrayList<>(traceMgr.getOpenTraces());
            for (Trace trace : traces) {
                if (trace == null || !seen.add(trace)) {
                    continue;
                }

                Map<String, Object> info = new LinkedHashMap<>();
                info.put("trace", trace.getName());
                info.put("tool", runningTool.getName());
                try {
                    saveTraceWithRetry(traceMgr, trace);
                    traceMgr.closeTraceNoConfirm(trace);
                    saved.add(info);
                } catch (Throwable e) {
                    info.put("error", e.getMessage() != null ? e.getMessage() : e.toString());
                    errors.add(info);
                    Msg.error(this, "Error saving debugger trace " + trace.getName(), e);
                }
            }
        }

        return JsonHelper.mapOf(
            "success", errors.isEmpty(),
            "saved_count", saved.size(),
            "traces", saved,
            "errors", errors
        );
    }

    /**
     * Save a debugger trace, retrying if the attempt races an in-flight
     * transaction on the trace's own domain object -- the same {@code
     * IOException: Unable to lock due to active transaction} documented for
     * program saves in {@code ProgramSaves.withRetry}, confirmed
     * live against a debugger trace too (2026-07-26): a trace accumulates its
     * own transactions from continuous Trace RMI sync writes (module/register
     * updates), and one can still be open when {@code exit_ghidra} saves on
     * the way out. A short backoff-and-retry on that specific message is the
     * same pragmatic fix as the program-save case.
     */
    private void saveTraceWithRetry(DebuggerTraceManagerService traceMgr, Trace trace)
            throws Exception {
        final int maxAttempts = 4;
        for (int attempt = 1; attempt <= maxAttempts; attempt++) {
            try {
                traceMgr.saveTrace(trace).get(30, TimeUnit.SECONDS);
                return;
            } catch (ExecutionException e) {
                Throwable cause = e.getCause();
                String msg = cause != null ? cause.getMessage() : e.getMessage();
                boolean isLockRace = msg != null && msg.contains("Unable to lock due to active transaction");
                if (!isLockRace || attempt == maxAttempts) {
                    throw e;
                }
                Msg.warn(this, "Trace save raced an active transaction (attempt "
                        + attempt + "/" + maxAttempts + "), retrying: " + msg);
                Thread.sleep(150L * attempt);
            }
        }
    }

    // ====================================================================================
    // FUNCTION HASH INDEX - Cross-binary documentation propagation
    // ====================================================================================

    /**
     * Register the hand-coded routes — the utility / GUI-state / Ghidra-Server
     * endpoints that predate the {@code @McpTool} convention and have no service
     * method to scan.
     *
     * <p>Defined once and registered on <em>every</em> running transport. They used to
     * be inlined into the TCP server's setup, so a bridge on the Unix socket — the
     * transport it prefers — could not reach {@code /exit_ghidra}, {@code /tool/*} or
     * any of the version-control routes: 208 tools over UDS against 240 over TCP,
     * measured on one instance. {@code ServerManager.registerTool} has always taken a
     * hook for exactly this and was being passed {@code null}.
     *
     * <p>Handlers take the transport-agnostic {@link com.xebyte.core.HttpExchange}; the
     * TCP side wraps its Sun exchange in {@link SunHttpExchangeAdapter} at registration.
     */
    private void registerHandCodedRoutes(McpHttpServer http) {
        // /check_connection, /mcp/health and /mcp/instance_info are McpHttpServer's own:
        // both servers answer them identically, bar server_kind.

        // ==========================================================================
        // INFRASTRUCTURE ENDPOINTS (not in service layer)
        // ==========================================================================

        // ==========================================================================
        // GUI-ONLY ENDPOINTS (require PluginTool/CodeBrowser/Swing context)
        // ==========================================================================

        // /open_project — open (or switch to) a Ghidra project from the
        // FrontEnd plugin programmatically. Mirrors the headless server's
        // /open_project route but additionally supports an optional
        // `headless` boolean (default true) that controls whether a
        // CodeBrowser window is auto-launched for `program` after the
        // project opens. Without the flag, the project is loaded into the
        // FrontEnd tool only — useful for automation that wants to access
        // programs via the `program` query parameter without spawning UI.
        //
        // Body: { "path": <.gpr or project dir>, "headless": true|false,
        //         "program": "<DomainFile path to launch in CodeBrowser>" }
        http.route("/open_project", exchange -> {
            Map<String, Object> params = parseJsonParams(exchange);
            String projectPath = params.get("path") != null ? params.get("path").toString() : null;
            boolean headless = params.get("headless") == null
                || Boolean.parseBoolean(String.valueOf(params.get("headless")));
            String programToLaunch = params.get("program") != null ? params.get("program").toString() : null;
            sendResponse(exchange, openProject(projectPath, headless, programToLaunch));
        });

        // The /server/* version-control and repository routes are @McpTools on
        // VersionControlService, over the open project and a ProjectServerSession.

        // ==========================================================================
        // PROJECT & TOOL MANAGEMENT ENDPOINTS (4 endpoints)
        // FrontEnd-level operations for project and tool management
        // ==========================================================================

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

    // ----------------------------------------------------------------------------------
    // Data Type Analysis and Management Methods
    // ----------------------------------------------------------------------------------

    /**
     * Helper method to extract JSON values from simple JSON strings
     */
    /**
     * Convert an object to JSON string format
     */
    // ===================================================================================
    // NEW DATA STRUCTURE MANAGEMENT METHODS
    // ===================================================================================

    // ==========================================================================
    // HIGH-PERFORMANCE DATA ANALYSIS METHODS (v1.3.0)
    // ==========================================================================

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
     * === FIELD-LEVEL ANALYSIS IMPLEMENTATIONS (v1.4.0) ===
     */

    // ============================================================================
    // MALWARE ANALYSIS IMPLEMENTATION METHODS
    // ============================================================================

    // ===================================================================================
    // BOOKMARK METHODS (v1.9.4) - Progress tracking via Ghidra bookmarks
    // ===================================================================================

    // ==================================================================================
    // CROSS-VERSION MATCHING TOOLS
    // ==================================================================================

    // ==========================================================================
    // FUZZY MATCHING & DIFF HANDLERS
    // ==========================================================================

    // ==========================================================================
    // PROJECT VERSION CONTROL HELPER METHODS
    // Uses Ghidra's internal DomainFile/DomainFolder API
    // ==========================================================================

    // ==========================================================================
    // PROJECT & TOOL MANAGEMENT HELPERS
    // ==========================================================================

    /**
     * Open (or switch to) a Ghidra project from the FrontEnd plugin.
     *
     * <p>When the requested project is already active this is a no-op
     * success. When a different project is active it is saved and closed
     * before opening the new one — destructive to any unsaved CodeBrowser
     * state, but matches the manual File &gt; Open Project flow.
     *
     * @param projectPath {@code .gpr} file, {@code <name>.rep} project
     *                    directory, or a directory whose name is the
     *                    project name (sibling .gpr/.rep expected).
     * @param headless    {@code true} (default) opens the project without
     *                    launching a CodeBrowser; {@code false} ALSO
     *                    launches CodeBrowser for {@code programToLaunch}.
     * @param programToLaunch project-internal DomainFile path to open in
     *                        CodeBrowser when {@code headless == false};
     *                        ignored otherwise.
     */
    private String openProject(String projectPath, boolean headless, String programToLaunch) {
        if (projectPath == null || projectPath.trim().isEmpty()) {
            return "{\"error\": \"path parameter is required\"}";
        }

        String trimmed = projectPath.trim();
        if (!trimmed.startsWith("ghidra://")) {
            java.nio.file.Path local = com.xebyte.core.SecurityConfig.getInstance()
                    .resolveWithinFileRoot(trimmed);
            if (local == null) {
                return "{\"error\": \"Path is outside this server's file root\"}";
            }
            trimmed = local.toString();
        }
        projectPath = trimmed;

        // Parse the path into a (location, name) pair for ProjectLocator.
        // Accept three shapes the user is likely to type:
        //   F:/proj/MyProj.gpr   — marker file
        //   F:/proj/MyProj.rep   — project data directory
        //   F:/proj/MyProj       — bare name, sibling .gpr/.rep expected
        File pathFile = new File(projectPath);
        String location;
        String name;
        String projExt = ProjectLocator.getProjectExtension();   // ".gpr"
        String dirExt = ProjectLocator.getProjectDirExtension(); // ".rep"
        String fname = pathFile.getName();
        if (fname.endsWith(projExt)) {
            location = pathFile.getParent();
            name = fname.substring(0, fname.length() - projExt.length());
        } else if (fname.endsWith(dirExt)) {
            location = pathFile.getParent();
            name = fname.substring(0, fname.length() - dirExt.length());
        } else {
            location = pathFile.getParent();
            name = fname;
        }
        if (location == null || location.isEmpty()) {
            return "{\"error\": \"path must include a parent directory: " + escapeJson(projectPath) + "\"}";
        }

        ProjectLocator locator;
        try {
            locator = new ProjectLocator(location, name);
        } catch (IllegalArgumentException e) {
            return "{\"error\": \"Invalid project path: " + escapeJson(e.getMessage()) + "\"}";
        }
        if (!locator.exists()) {
            return "{\"error\": \"Project does not exist: " + escapeJson(projectPath) + "\"}";
        }

        Project currentProject = tool.getProject();
        if (currentProject != null && locator.equals(currentProject.getProjectLocator())) {
            // Already open — honor headless flag for CodeBrowser side-effect anyway.
            String maybeLaunch = null;
            if (!headless && programToLaunch != null && !programToLaunch.isEmpty()) {
                maybeLaunch = programScriptService.openProgramFromProject(programToLaunch, false).toJson();
            }
            return "{\"success\": true, \"project\": \"" + escapeJson(name) + "\", "
                + "\"already_open\": true, \"headless\": " + headless
                + (maybeLaunch != null ? ", \"program_launch_result\": " + maybeLaunch : "")
                + "}";
        }

        ProjectManager pm = tool.getProjectManager();
        if (pm == null) {
            return "{\"error\": \"ProjectManager not available on this tool\"}";
        }

        // Must run on the EDT — FrontEndTool state updates expect Swing.
        final String[] errMsg = {null};
        final Project[] opened = {null};
        try {
            SwingUtilities.invokeAndWait(() -> {
                try {
                    if (currentProject != null) {
                        try { currentProject.save(); } catch (Exception ignored) { /* best-effort */ }
                        currentProject.close();
                    }
                    Project p = pm.openProject(locator, true, false);
                    if (p == null) {
                        errMsg[0] = "ProjectManager.openProject returned null";
                        return;
                    }
                    AppInfo.setActiveProject(p);
                    opened[0] = p;
                } catch (Exception e) {
                    errMsg[0] = e.getClass().getSimpleName() + ": " + e.getMessage();
                }
            });
        } catch (Exception e) {
            return "{\"error\": \"EDT invocation failed: " + escapeJson(e.getMessage()) + "\"}";
        }
        if (errMsg[0] != null) {
            return "{\"error\": \"Failed to open project: " + escapeJson(errMsg[0]) + "\"}";
        }
        if (opened[0] == null) {
            return "{\"error\": \"openProject returned null without an error\"}";
        }

        String launchResult = null;
        if (!headless && programToLaunch != null && !programToLaunch.isEmpty()) {
            launchResult = programScriptService.openProgramFromProject(programToLaunch, false).toJson();
        }
        StringBuilder json = new StringBuilder(256);
        json.append("{\"success\": true, \"project\": \"").append(escapeJson(opened[0].getName()))
            .append("\", \"headless\": ").append(headless);
        if (launchResult != null) {
            json.append(", \"program_launch_result\": ").append(launchResult);
        }
        json.append("}");
        return json.toString();
    }

    @Override
    public void dispose() {
        // Deregister from UDS ServerManager
        ServerManager.getInstance().deregisterTool(tool);

        liveInstances.remove(this);
        instanceCount--;

        // This instance's programProvider is dead either way — release the
        // programs it was holding, regardless of whether other windows
        // survive. (Previously only the last-disposed instance released.)
        try {
            programProvider.releaseAll();
        } catch (Exception e) {
            Msg.warn(this, "GhidraMCP: releaseAll on dispose: " + e.getMessage());
        }

        if (instanceCount <= 0) {
            stopServer();
            instanceCount = 0;
        } else if (ownsServer) {
            // The TCP routes (createContext lambdas) captured THIS
            // instance's services. With this PluginTool now disposed,
            // every subsequent HTTP request would execute against stale
            // services. Hand the server to a surviving instance by rebinding it
            // to that instance's scanner.
            //
            // This now covers BOTH transports. It used to restart only the
            // plugin's own TCP listener, because the Unix socket was served by
            // ServerManager's separate service set, which read through a
            // provider backed by the live tool map and so had nothing stale to
            // hand over. With one service set there is exactly one thing tied
            // to this window's lifetime, and both listeners serve from it.
            Msg.info(this, "GhidraMCP: owning tool window closed with "
                + instanceCount + " other window(s) still active — handing "
                + "the server to a survivor.");
            ownsServer = false;
            GhidraMCPPlugin survivor = liveInstances.isEmpty() ? null : liveInstances.get(0);
            if (survivor != null) {
                try {
                    ServerManager.getInstance().rebind(survivor.buildScanner(),
                        survivor::registerHandCodedRoutes);
                    survivor.ownsServer = true;
                } catch (IOException e) {
                    Msg.error(this, "GhidraMCP: failed to hand the server to a "
                        + "surviving tool window: " + e.getMessage()
                        + " — use Tools > GhidraMCP > Start Server.");
                }
            } else {
                stopServer();
            }
        } else {
            Msg.info(this, "GhidraMCP: " + instanceCount
                + " tool window(s) still active, keeping server running.");
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
