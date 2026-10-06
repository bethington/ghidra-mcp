/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.xebyte.headless;

import com.xebyte.core.HttpExchange;
import com.xebyte.core.McpHttpServer;
import com.xebyte.core.AmbiguousProgramException;
import com.xebyte.core.AnnotationScanner;
import com.xebyte.core.CoreServices;
import com.xebyte.core.JsonHelper;
import com.xebyte.core.ProgramProvider;
import com.xebyte.core.SecurityConfig;
import com.xebyte.core.ThreadingStrategy;
import com.xebyte.core.VersionInfo;
import ghidra.GhidraApplicationLayout;
import ghidra.GhidraLaunchable;
import ghidra.app.script.GhidraScriptUtil;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import java.io.*;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * Headless Ghidra MCP Server.
 *
 * This server provides the same REST API as the GUI plugin but runs in
 * headless mode without requiring the Ghidra GUI. Ideal for:
 * - Docker deployments
 * - CI/CD pipelines
 * - Automated analysis workflows
 * - Server-side reverse engineering
 *
 * Usage:
 *   java -jar GhidraMCPHeadless.jar --port 8089 --project /path/to/project
 *   java -jar GhidraMCPHeadless.jar --port 8089 --file /path/to/binary.exe
 */
public class GhidraMCPHeadlessServer implements GhidraLaunchable {

    private static final int DEFAULT_PORT = 8089;
    private static final String DEFAULT_BIND_ADDRESS = "127.0.0.1";

    private McpHttpServer http;
    private HeadlessProgramProvider programProvider;
    private DirectThreadingStrategy threadingStrategy;
    private int port = DEFAULT_PORT;
    private String bindAddress = DEFAULT_BIND_ADDRESS;
    // The Unix socket always runs; TCP only when asked for (--port/--bind/env).
    private boolean tcp = false;
    private boolean running = false;
    private boolean scriptingBundleHostAcquired = false;

    // Endpoint handler registry
    private CoreServices services;
    private HeadlessManagementService managementService;
    private int registeredEndpointCount;

    // Ghidra server connection manager
    private GhidraServerManager serverManager;

    public static void main(String[] args) {
        GhidraMCPHeadlessServer server = new GhidraMCPHeadlessServer();
        try {
            server.launch(new GhidraApplicationLayout(), args);
        } catch (Exception e) {
            System.err.println("Failed to launch headless server: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }

    @Override
    public void launch(GhidraApplicationLayout layout, String[] args) throws Exception {
        // Parse command line arguments
        parseArgs(args);

        // Initialize Ghidra in headless mode
        initializeGhidra(layout);

        // Create providers
        programProvider = new HeadlessProgramProvider();
        threadingStrategy = new DirectThreadingStrategy();

        services = CoreServices.build(programProvider, threadingStrategy);

        // Create server manager for shared Ghidra server support
        serverManager = new GhidraServerManager();

        managementService = new HeadlessManagementService(programProvider, serverManager);

        // Load initial programs if specified
        loadInitialPrograms(args);

        // Start the HTTP server
        startServer();

        // Through Ghidra's registry, not Runtime: a plain JVM hook runs concurrently
        // with Ghidra's own, which dispose the program databases (a save then fails
        // "File is read-only") and shut down logging. Not ShutdownPriority.FIRST:
        // ShutdownHook.compareTo subtracts priorities, and Integer.MIN_VALUE minus
        // DISPOSE_DATABASES overflows, so FIRST actually sorts after the disposers.
        ghidra.framework.ShutdownHookRegistry.addShutdownHook(this::stop,
                ghidra.framework.ShutdownPriority.DISPOSE_DATABASES.before());

        System.out.println("GhidraMCP Headless Server v" + VersionInfo.getVersion() + " running");
        System.out.println("Press Ctrl+C to stop");

        // Block main thread
        synchronized (this) {
            while (running) {
                try {
                    wait();
                } catch (InterruptedException e) {
                    break;
                }
            }
        }
    }

    private void parseArgs(String[] args) {
        // Check environment variable for bind address (Docker container support)
        String envBindAddress = System.getenv("GHIDRA_MCP_BIND_ADDRESS");
        if (envBindAddress != null && !envBindAddress.isEmpty()) {
            bindAddress = envBindAddress;
            tcp = true;
        }

        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--port":
                case "-p":
                    if (i + 1 < args.length) {
                        try {
                            port = Integer.parseInt(args[++i]);
                            tcp = true;
                        } catch (NumberFormatException e) {
                            System.err.println("Invalid port number: " + args[i]);
                        }
                    }
                    break;
                case "--bind":
                case "-b":
                    if (i + 1 < args.length) {
                        bindAddress = args[++i];
                        tcp = true;
                    }
                    break;
                case "--help":
                case "-h":
                    printUsage();
                    System.exit(0);
                    break;
                case "--version":
                case "-v":
                    System.out.println("GhidraMCP Headless Server v" + VersionInfo.getVersion());
                    System.exit(0);
                    break;
            }
        }
    }

    private void printUsage() {
        System.out.println("GhidraMCP Headless Server v" + VersionInfo.getVersion());
        System.out.println();
        System.out.println("Usage: java -jar GhidraMCPHeadless.jar [options]");
        System.out.println();
        System.out.println("Options:");
        System.out.println("  --port, -p <port>      Also serve TCP on this port (default: Unix socket only)");
        System.out.println("  --bind, -b <address>   Also serve TCP on this address (default 127.0.0.1)");
        System.out.println("                         Use 0.0.0.0 to allow remote connections");
        System.out.println("  --file, -f <file>      Binary file to load");
        System.out.println("  --project <path>       Ghidra project path");
        System.out.println("  --program <name>       Program name within project");
        System.out.println("  --help, -h             Show this help");
        System.out.println("  --version, -v          Show version");
        System.out.println();
        System.out.println("Environment Variables:");
        System.out.println("  GHIDRA_MCP_BIND_ADDRESS  Override bind address (for Docker)");
        System.out.println();
        System.out.println("Examples:");
        System.out.println("  # Start server with no initial program");
        System.out.println("  java -jar GhidraMCPHeadless.jar --port 8089");
        System.out.println();
        System.out.println("  # Start server accessible from Docker network");
        System.out.println("  java -jar GhidraMCPHeadless.jar --bind 0.0.0.0 --port 8089");
        System.out.println();
        System.out.println("  # Start server with a binary file");
        System.out.println("  java -jar GhidraMCPHeadless.jar --file /path/to/binary.exe");
        System.out.println();
        System.out.println("Always serves on $XDG_RUNTIME_DIR/ghidra-mcp/ghidra-<pid>.sock, where the");
        System.out.println("bridge discovers it; TCP additionally at http://<address>:<port>/ when asked.");
    }

    private void initializeGhidra(GhidraApplicationLayout layout) throws Exception {
        if (!Application.isInitialized()) {
            ApplicationConfiguration config = new HeadlessGhidraApplicationConfiguration();
            Application.initializeApplication(layout, config);
            System.out.println("Ghidra initialized in headless mode");
        }

        // Initialize the OSGi/BundleHost subsystem used by GhidraScriptProvider.
        // In GUI mode this is done by GhidraScriptMgrPlugin; in headless we must do it
        // explicitly or every /run_ghidra_script and /run_script_inline call throws
        // NullPointerException at JavaScriptProvider.getScriptInstance() because
        // GhidraScriptUtil.bundleHost is null.
        //
        // Gated on GHIDRA_MCP_ALLOW_SCRIPTS (via SecurityConfig) to avoid the Felix
        // OSGi framework startup cost (~hundreds of ms) when script execution is
        // disabled (default since v5.4.1). Held for the lifetime of the server;
        // released by stop().
        if (SecurityConfig.getInstance().areScriptsAllowed()) {
            try {
                // BundleHost.add() inspects each path: an existing directory yields a
                // GhidraSourceBundle, anything else (missing path, plain file) yields a
                // GhidraPlaceholderBundle. A placeholder makes JavaScriptProvider crash
                // later with `ClassCastException: GhidraPlaceholderBundle cannot be cast
                // to GhidraSourceBundle`. Ensure the user script dir exists before
                // acquire so it gets registered as a real source bundle.
                java.io.File userScriptDir = GhidraScriptUtil.USER_SCRIPTS_DIR != null
                        ? new java.io.File(GhidraScriptUtil.USER_SCRIPTS_DIR)
                        : new java.io.File(System.getProperty("user.home"), "ghidra_scripts");
                boolean scriptDirExisted = userScriptDir.exists();
                if (!scriptDirExisted) {
                    userScriptDir.mkdirs();
                }
                // acquireBundleHostReference() registers GhidraScriptUtil.USER_SCRIPTS_DIR
                // itself — not a local override — so a temp-dir fallback would still
                // leave the canonical (missing) path registered as a
                // GhidraPlaceholderBundle, which crashes JavaScriptProvider later with a
                // ClassCastException. If the canonical directory isn't a real, writable
                // directory after the mkdir attempt we therefore short-circuit: scripts
                // stay disabled but the server keeps running, instead of acquiring on a
                // placeholder path.
                if (!userScriptDir.isDirectory() || !userScriptDir.canWrite()) {
                    System.err.println(
                            "User script directory is missing or not writable ("
                                    + userScriptDir.getAbsolutePath()
                                    + "); skipping BundleHost init, script execution disabled.");
                    return;
                }
                System.out.println((scriptDirExisted ? "Using" : "Created")
                        + " user script directory: " + userScriptDir.getAbsolutePath());

                GhidraScriptUtil.acquireBundleHostReference();
                scriptingBundleHostAcquired = true;
                System.out.println(
                        "GhidraScriptUtil BundleHost acquired (script execution enabled)");

                // acquireBundleHostReference() registers script directories but leaves
                // them DISABLED. JavaScriptProvider.loadClass() then fails with
                // "Failed to get OSGi bundle containing script" because the Felix
                // framework refuses to resolve classes from disabled bundles.
                // HeadlessAnalyzer explicitly calls bundleHost.add(paths, true, true)
                // — we do the equivalent by enabling the user script dir bundle here.
                try {
                    ghidra.app.plugin.core.osgi.BundleHost bh =
                            GhidraScriptUtil.getBundleHost();
                    generic.jar.ResourceFile userScriptResource =
                            new generic.jar.ResourceFile(userScriptDir);
                    ghidra.app.plugin.core.osgi.GhidraBundle bundle =
                            bh.getGhidraBundle(userScriptResource);
                    if (bundle == null) {
                        bh.add(userScriptResource, true, false);
                        System.out.println(
                                "Added user script directory bundle (enabled): "
                                        + userScriptDir.getAbsolutePath());
                    } else if (!bundle.isEnabled()) {
                        bh.enable(bundle);
                        System.out.println(
                                "Enabled existing user script directory bundle: "
                                        + userScriptDir.getAbsolutePath());
                    }
                } catch (Throwable t2) {
                    System.err.println(
                            "Failed to enable user script bundle: " + t2.getMessage());
                    t2.printStackTrace();
                }
            } catch (Throwable t) {
                System.err.println(
                        "Failed to initialize GhidraScriptUtil BundleHost; script execution will fail: "
                                + t.getMessage());
                t.printStackTrace();
            }
        }
    }

    private void loadInitialPrograms(String[] args) {
        String filePath = null;
        String projectPath = null;
        String programName = null;

        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--file":
                case "-f":
                    if (i + 1 < args.length) {
                        filePath = args[++i];
                    }
                    break;
                case "--project":
                    if (i + 1 < args.length) {
                        projectPath = args[++i];
                    }
                    break;
                case "--program":
                    if (i + 1 < args.length) {
                        programName = args[++i];
                    }
                    break;
            }
        }

        // Load from file if specified
        if (filePath != null) {
            try {
                Program program = programProvider.importFile(new File(filePath), "/", "", "").program();
                System.out.println("Loaded program: " + program.getName());
            } catch (Exception e) {
                System.err.println("Failed to load program from " + filePath + ": " + e.getMessage());
            }
        }

        // Load from project if specified
        if (projectPath != null) {
            HeadlessProgramProvider.OpenProjectResult opened =
                    programProvider.openProject(projectPath, serverManager);
            if (opened.success) {
                System.out.println("Opened project: " + programProvider.getProjectName()
                        + (opened.shared ? " (shared repo " + opened.repository + ")" : ""));

                // If program name specified, load it
                if (programName != null) {
                    Program program = null;
                    try {
                        program = programProvider.openFromProject(programName);
                    } catch (AmbiguousProgramException e) {
                        System.err.println(e.getMessage());
                    }
                    if (program != null) {
                        System.out.println("Loaded program from project: " + program.getName());
                    } else {
                        System.err.println("Failed to load program: " + programName);
                        System.out.println("Available programs:");
                        for (String p : programProvider.programPaths(200)) {
                            System.out.println("  " + p);
                        }
                    }
                }
            } else {
                System.err.println("Failed to open project: "
                        + (opened.error != null ? opened.error : projectPath));
            }
        }
    }

    private void startServer() throws IOException {
        http = new McpHttpServer("headless", Map::of);
        registerEndpoints();
        http.start(new McpHttpServer.Config(true, tcp, bindAddress, port, 1, 10));
        running = true;
        System.out.println("Serving on " + http.socketPath()
                + (tcp ? " and " + bindAddress + ":" + http.tcpPort() : ""));
        if (com.xebyte.core.SecurityConfig.getInstance().isAuthEnabled()) {
            System.out.println("Auth: enabled (GHIDRA_MCP_AUTH_TOKEN)");
        }
    }

    private void registerEndpoints() {
        // ==========================================================================
        // INFRASTRUCTURE ENDPOINTS (not in service layer)
        // ==========================================================================

        // /check_connection, /mcp/health and /mcp/instance_info are McpHttpServer's own,
        // identical to the GUI's bar server_kind. /health, headless-only, is retired.

        // ==========================================================================
        // SHARED ENDPOINTS — Annotation-driven registration via AnnotationScanner
        // ==========================================================================

        AnnotationScanner scanner = new AnnotationScanner(programProvider, threadingStrategy,
            services.plus(managementService));

        http.endpoints(scanner);

        // These routes are registered below via their own http.route(...) calls
        // (utility/server/project endpoints that predate the @McpTool convention),
        // so they are already live and callable. Without this they stayed
        // invisible in /mcp/schema -- and therefore invisible to the Python
        // bridge's dynamic tool discovery. Mirrors the GUI-side wiring in
        // GhidraMCPPlugin; see ManualToolDescriptors for the shared metadata
        // source. Found via a live-schema-vs-catalog diff (v6.0.0).
        com.xebyte.core.ManualToolDescriptors.addAll(scanner,
            "/check_connection", "/exit_ghidra", "/mcp/health", "/mcp/schema",
            "/server/admin/set_permissions", "/server/admin/terminate_all_checkouts",
            "/server/admin/terminate_checkout", "/server/admin/users",
            "/server/checkouts", "/server/connect", "/server/disconnect",
            "/server/repositories", "/server/repository/create", "/server/repository/file",
            "/server/repository/files", "/server/version_control/add",
            "/server/version_control/checkin", "/server/version_control/checkout",
            "/server/version_control/undo_checkout", "/server/version_history");
        // Store scanner size for dynamic endpoint count reporting. Now includes
        // both the dispatch-table (@McpTool-scanned) endpoints and the manually-
        // registered routes just added to the schema above -- countEndpoints()
        // no longer needs a hand-maintained "+30" offset for these.
        registeredEndpointCount = scanner.getDescriptors().size();

        // ==========================================================================
        // HEADLESS-ONLY ENDPOINTS (no GUI equivalent)
        // ==========================================================================

        // --- Program Management --- (registered via HeadlessManagementService)

        // --- Project Lifecycle --- (/create_project registered via HeadlessManagementService)

        // /list_projects and /delete_project are @McpTools on HeadlessManagementService.

        // --- Project Organization ---
        // Note: /create_folder, /delete_file, /move_file and /move_folder are
        // NOT registered here because they are already registered via @McpTool
        // annotations on ProgramScriptService.{createFolder,deleteFile,
        // moveFile,moveFolder} which the AnnotationScanner picks up.
        // Re-registering them manually causes "cannot add context to list" on
        // headless startup (see #180). Those shared implementations reach
        // ProjectData through ProgramProvider.getProject(), which
        // HeadlessProgramProvider overrides -- that override is what keeps them
        // working without a PluginTool.

        // --- Server Endpoints ---

        http.route("/server/connect", exchange -> {
            sendResponse(exchange, serverManager.connect());
        });

        // /server/status registered via HeadlessManagementService

        http.route("/server/repositories", exchange -> {
            sendResponse(exchange, serverManager.listRepositories());
        });

        http.route("/server/disconnect", exchange -> {
            sendResponse(exchange, serverManager.disconnect());
        });

        http.route("/server/repository/files", exchange -> {
            Map<String, String> params = parseQueryParams(exchange);
            String repo = params.get("repo");
            String path = params.get("path");
            if (path == null) path = "/";
            sendResponse(exchange, serverManager.listRepositoryFiles(repo, path));
        });

        http.route("/server/repository/file", exchange -> {
            Map<String, String> params = parseQueryParams(exchange);
            String repo = params.get("repo");
            String path = params.get("path");
            sendResponse(exchange, serverManager.getFileInfo(repo, path));
        });

        http.route("/server/repository/create", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, serverManager.createRepository(params.get("name")));
        });

        // --- Version Control ---

        http.route("/server/version_control/checkout", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, serverManager.checkoutFile(params.get("repo"), params.get("path")));
        });

        http.route("/server/version_control/checkin", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            boolean keepCheckedOut = parseBooleanOrDefault(params.get("keepCheckedOut"), false);
            sendResponse(exchange, serverManager.checkinFile(
                params.get("repo"), params.get("path"), params.get("comment"), keepCheckedOut));
        });

        http.route("/server/version_control/undo_checkout", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, serverManager.undoCheckout(params.get("repo"), params.get("path")));
        });

        http.route("/server/version_control/add", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, serverManager.addToVersionControl(
                params.get("repo"), params.get("path"), params.get("comment")));
        });

        http.route("/server/version_history", exchange -> {
            Map<String, String> params = parseQueryParams(exchange);
            sendResponse(exchange, serverManager.getVersionHistory(params.get("repo"), params.get("path")));
        });

        http.route("/server/checkouts", exchange -> {
            Map<String, String> params = parseQueryParams(exchange);
            sendResponse(exchange, serverManager.getCheckouts(params.get("repo"), params.get("path")));
        });

        // --- Admin ---

        http.route("/server/admin/terminate_checkout", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String checkoutIdParam = params.getOrDefault("checkoutId", params.getOrDefault("checkout_id", "0"));
            long checkoutId = Long.parseLong(checkoutIdParam);
            sendResponse(exchange, serverManager.terminateCheckout(
                params.get("repo"), params.get("path"), checkoutId));
        });

        http.route("/server/admin/terminate_all_checkouts", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String folderPath = params.get("path");
            if (folderPath == null) folderPath = "/";
            sendResponse(exchange, serverManager.terminateAllCheckouts(
                params.get("repo"), folderPath));
        });

        http.route("/server/admin/users", exchange -> {
            sendResponse(exchange, serverManager.listServerUsers());
        });

        http.route("/server/admin/set_permissions", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            int accessLevel = parseIntOrDefault(params.get("accessLevel"), 1);
            sendResponse(exchange, serverManager.setUserPermissions(
                params.get("repo"), params.get("user"), accessLevel));
        });

        // --- Exit ---

        http.route("/exit_ghidra", exchange -> {
            sendResponse(exchange, exitServer());
        });

        System.out.println("Registered " + countEndpoints() + " REST API endpoints");
    }

    /**
     * Save every open program, answer with what was saved, then exit. The GUI's
     * /exit_ghidra always did this; headless used to exit and leave the saving to the
     * shutdown hook, after the caller had already been told it was done.
     */
    private String exitServer() {
        Object saved = services.programScript().saveAllOpenPrograms().asEmbeddable();
        new Thread(() -> {
            try { Thread.sleep(500); } catch (InterruptedException ignored) {}
            System.exit(0);
        }).start();
        return JsonHelper.toJson(JsonHelper.mapOf(
            "success", true,
            "message", "Saving all open programs, then exiting",
            "save", JsonHelper.mapOf("programs", saved)));
    }

    private int countEndpoints() {
        // registeredEndpointCount now includes both the annotation-scanned
        // endpoints and the manually-registered routes added via
        // ManualToolDescriptors.addAll(...) above -- no more hand-maintained
        // offset to keep in sync as routes are added or removed.
        return registeredEndpointCount;
    }

    public void stop() {
        running = false;
        synchronized (this) {
            notifyAll();
        }

        if (http != null) {
            System.out.println("Stopping HTTP server...");
            http.stop();
            http = null;
        }

        if (serverManager != null && serverManager.isConnected()) {
            System.out.println("Disconnecting from Ghidra server...");
            serverManager.disconnect();
        }

        if (programProvider != null) {
            try {
                System.out.println("Closing programs...");
                programProvider.releaseAll();
            } finally {
                // Release the .rep project lock. releaseAll() only
                // releases Program handles; the project lock acquired by
                // GhidraProject.openProject() is freed by closeProject().
                // Without this, even a clean shutdown leaves the project
                // locked and the next /open_project (or GUI open) fails
                // with "project is locked". try/finally so a release
                // failure on one program doesn't skip the lock release.
                System.out.println("Closing project...");
                try {
                    programProvider.closeProject();
                } catch (Exception e) {
                    System.err.println("Error closing project: " + e.getMessage());
                }
            }
        }

        if (scriptingBundleHostAcquired) {
            try {
                GhidraScriptUtil.releaseBundleHostReference();
                scriptingBundleHostAcquired = false;
                System.out.println("GhidraScriptUtil BundleHost released");
            } catch (Throwable t) {
                System.err.println(
                        "Error releasing GhidraScriptUtil BundleHost: " + t.getMessage());
            }
        }

        System.out.println("Server stopped");
    }

    // ==========================================================================
    // HTTP UTILITY METHODS
    // ==========================================================================

    private void sendResponse(HttpExchange exchange, String response) throws IOException {
        byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=UTF-8");
        // No Access-Control-Allow-Origin: the bridge is a same-host CLI
        // client, not a browser. Emitting ACAO:* on a no-auth loopback
        // server lets any web page the user visits read decompiled code
        // and drive write endpoints via fetch(). The GUI plugin's TCP
        // server has never emitted this header; aligning with it.
        exchange.sendResponseHeaders(200, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    private Map<String, String> parseQueryParams(HttpExchange exchange) {
        return McpHttpServer.parseQuery(exchange.getRequestURI().getRawQuery());
    }

    private Map<String, String> parsePostParams(HttpExchange exchange) throws IOException {
        Map<String, String> params = new HashMap<>();

        // Get content type
        String contentType = exchange.getRequestHeaders().getFirst("Content-Type");
        if (contentType == null) {
            contentType = "";
        }

        // Read body
        String body;
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(exchange.getRequestBody(), StandardCharsets.UTF_8))) {
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line);
                // Bound accumulation so a huge body can't exhaust memory.
                if (sb.length() > com.xebyte.core.SecurityConfig.MAX_REQUEST_BODY_BYTES) {
                    return params;  // oversized — treat as no params
                }
            }
            body = sb.toString();
        }

        if (body.isEmpty()) {
            return params;
        }

        // Parse based on content type
        if (contentType.contains("application/json")) {
            // Simple JSON parsing for flat objects
            body = body.trim();
            if (body.startsWith("{") && body.endsWith("}")) {
                body = body.substring(1, body.length() - 1);
                for (String pair : body.split(",")) {
                    String[] kv = pair.split(":", 2);
                    if (kv.length == 2) {
                        String key = kv[0].trim().replaceAll("^\"|\"$", "");
                        String value = kv[1].trim().replaceAll("^\"|\"$", "");
                        params.put(key, value);
                    }
                }
            }
        } else {
            // Form-urlencoded
            for (String param : body.split("&")) {
                String[] pair = param.split("=", 2);
                if (pair.length == 2) {
                    try {
                        String key = URLDecoder.decode(pair[0], StandardCharsets.UTF_8);
                        String value = URLDecoder.decode(pair[1], StandardCharsets.UTF_8);
                        params.put(key, value);
                    } catch (Exception e) {
                        // Skip malformed param
                    }
                }
            }
        }

        return params;
    }

    private int parseIntOrDefault(String value, int defaultValue) {
        if (value == null || value.isEmpty()) {
            return defaultValue;
        }
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    private boolean parseBooleanOrDefault(String value, boolean defaultValue) {
        if (value == null || value.isEmpty()) {
            return defaultValue;
        }
        return Boolean.parseBoolean(value);
    }


    // ==========================================================================
    // GETTERS
    // ==========================================================================

    public ProgramProvider getProgramProvider() {
        return programProvider;
    }

    public ThreadingStrategy getThreadingStrategy() {
        return threadingStrategy;
    }

    public boolean isRunning() {
        return running;
    }

}
