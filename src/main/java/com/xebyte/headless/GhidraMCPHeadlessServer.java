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

import com.sun.net.httpserver.HttpServer;
import com.xebyte.core.*;
import ghidra.GhidraApplicationLayout;
import ghidra.GhidraLaunchable;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.model.listing.Program;

import java.io.*;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * Headless Ghidra MCP Server.
 *
 * Uses {@link EndpointRegistrar#sharedEndpoints} for the ~150 shared service-backed endpoints,
 * plus headless-specific endpoints for project management, server management, and program lifecycle.
 *
 * Usage:
 *   java -jar GhidraMCPHeadless.jar --port 8089 --project /path/to/project
 *   java -jar GhidraMCPHeadless.jar --port 8089 --file /path/to/binary.exe
 */
public class GhidraMCPHeadlessServer implements GhidraLaunchable {

    private static final String VERSION = "4.0.0-headless";
    private static final int DEFAULT_PORT = 8089;
    private static final String DEFAULT_BIND_ADDRESS = "127.0.0.1";

    private HttpServer server;
    private HeadlessProgramProvider programProvider;
    private DirectThreadingStrategy threadingStrategy;
    private int port = DEFAULT_PORT;
    private String bindAddress = DEFAULT_BIND_ADDRESS;
    private boolean running = false;

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

        // Create server manager for shared Ghidra server support
        serverManager = new GhidraServerManager();

        // Load initial programs if specified
        loadInitialPrograms(args);

        // Start the HTTP server
        startServer();

        // Keep running until interrupted
        Runtime.getRuntime().addShutdownHook(new Thread(this::stop));

        System.out.println("GhidraMCP Headless Server v" + VERSION + " running on port " + port);
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
        }

        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--port":
                case "-p":
                    if (i + 1 < args.length) {
                        try {
                            port = Integer.parseInt(args[++i]);
                        } catch (NumberFormatException e) {
                            System.err.println("Invalid port number: " + args[i]);
                        }
                    }
                    break;
                case "--bind":
                case "-b":
                    if (i + 1 < args.length) {
                        bindAddress = args[++i];
                    }
                    break;
                case "--help":
                case "-h":
                    printUsage();
                    System.exit(0);
                    break;
                case "--version":
                case "-v":
                    System.out.println("GhidraMCP Headless Server v" + VERSION);
                    System.exit(0);
                    break;
            }
        }
    }

    private void printUsage() {
        System.out.println("GhidraMCP Headless Server v" + VERSION);
        System.out.println();
        System.out.println("Usage: java -jar GhidraMCPHeadless.jar [options]");
        System.out.println();
        System.out.println("Options:");
        System.out.println("  --port, -p <port>      Server port (default: 8089)");
        System.out.println("  --bind, -b <address>   Bind address (default: 127.0.0.1)");
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
        System.out.println("REST API endpoints available at http://<address>:<port>/");
    }

    private void initializeGhidra(GhidraApplicationLayout layout) throws Exception {
        if (!Application.isInitialized()) {
            ApplicationConfiguration config = new HeadlessGhidraApplicationConfiguration();
            Application.initializeApplication(layout, config);
            System.out.println("Ghidra initialized in headless mode");
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
            File file = new File(filePath);
            Program program = programProvider.loadProgramFromFile(file);
            if (program != null) {
                System.out.println("Loaded program: " + program.getName());
            } else {
                System.err.println("Failed to load program from: " + filePath);
            }
        }

        // Load from project if specified
        if (projectPath != null) {
            boolean success = programProvider.openProject(projectPath);
            if (success) {
                System.out.println("Opened project: " + programProvider.getProjectName());

                // If program name specified, load it
                if (programName != null) {
                    Program program = programProvider.loadProgramFromProject(programName);
                    if (program != null) {
                        System.out.println("Loaded program from project: " + program.getName());
                    } else {
                        System.err.println("Failed to load program: " + programName);
                        // List available programs
                        System.out.println("Available programs:");
                        for (String p : programProvider.listProjectPrograms()) {
                            System.out.println("  " + p);
                        }
                    }
                }
            } else {
                System.err.println("Failed to open project: " + projectPath);
            }
        }
    }

    // ==========================================================================
    // SERVER LIFECYCLE
    // ==========================================================================

    private void startServer() throws IOException {
        server = HttpServer.create(new InetSocketAddress(bindAddress, port), 0);

        // Create shared services
        ListingService listingService = new ListingService(programProvider);
        CommentService commentService = new CommentService(programProvider, threadingStrategy);
        SymbolLabelService symbolLabelService = new SymbolLabelService(programProvider, threadingStrategy);
        FunctionService functionService = new FunctionService(programProvider, threadingStrategy);
        XrefCallGraphService xrefCallGraphService = new XrefCallGraphService(programProvider, threadingStrategy);
        DataTypeService dataTypeService = new DataTypeService(programProvider, threadingStrategy);
        DocumentationHashService documentationHashService = new DocumentationHashService(programProvider, threadingStrategy, new BinaryComparisonService());
        documentationHashService.setFunctionService(functionService);
        AnalysisService analysisService = new AnalysisService(programProvider, threadingStrategy, functionService);
        MalwareSecurityService malwareSecurityService = new MalwareSecurityService(programProvider, threadingStrategy);
        ProgramScriptService programScriptService = new ProgramScriptService(programProvider, threadingStrategy);

        // Register shared endpoints via EndpointRegistrar
        EndpointRegistrar.ContextRegistrar registrar = (path, handler) ->
            server.createContext(path, sunExchange -> handler.accept(new SunHttpExchangeAdapter(sunExchange)));

        EndpointRegistrar.registerAll(registrar, EndpointRegistrar.sharedEndpoints(
            listingService, commentService, symbolLabelService, functionService,
            xrefCallGraphService, dataTypeService, documentationHashService,
            analysisService, malwareSecurityService, programScriptService));

        // Register headless-specific endpoints
        registerHeadlessEndpoints();

        server.setExecutor(java.util.concurrent.Executors.newFixedThreadPool(10));
        server.start();
        running = true;
        System.out.println("HTTP server started on " + bindAddress + ":" + port);
    }

    // ==========================================================================
    // HEADLESS-SPECIFIC ENDPOINTS
    // ==========================================================================

    private void registerHeadlessEndpoints() {
        // --- Version / Health ---
        server.createContext("/check_connection", exchange -> {
            sendResponse(exchange, "Connection OK - GhidraMCP Headless Server v" + VERSION);
        });

        server.createContext("/get_version", exchange -> {
            sendResponse(exchange, "{\"plugin_version\": \"" + VERSION + "\",\"plugin_name\": \"GhidraMCP Headless\",\"mode\": \"headless\"}");
        });

        server.createContext("/health", exchange -> {
            Program program = programProvider.getCurrentProgram();
            boolean loaded = (program != null);
            String json = "{\"status\": \"healthy\",\"version\": \"" + VERSION + "\",\"program_loaded\": " + loaded;
            if (loaded) {
                json += ",\"program_name\": \"" + escapeJson(program.getName()) + "\"";
            }
            json += "}";
            sendResponse(exchange, json);
        });

        // --- Headless mode stubs ---
        server.createContext("/get_current_address", exchange -> {
            sendResponse(exchange, "{\"error\": \"Headless mode - use address parameter with specific endpoints\"}");
        });

        server.createContext("/get_current_function", exchange -> {
            sendResponse(exchange, "{\"error\": \"Headless mode - use get_function_by_address\"}");
        });

        // --- Program lifecycle (headless-specific) ---
        server.createContext("/load_program", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String filePath = params.get("file");
            if (filePath == null || filePath.isEmpty()) {
                sendResponse(exchange, "{\"error\": \"File path required\"}");
                return;
            }
            File file = new File(filePath);
            if (!file.exists()) {
                sendResponse(exchange, "{\"error\": \"File not found: " + escapeJson(filePath) + "\"}");
                return;
            }
            Program program = programProvider.loadProgramFromFile(file);
            if (program != null) {
                sendResponse(exchange, "{\"success\": true, \"program\": \"" + escapeJson(program.getName()) + "\"}");
            } else {
                sendResponse(exchange, "{\"error\": \"Failed to load program from: " + escapeJson(filePath) + "\"}");
            }
        });

        server.createContext("/close_program", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String name = params.get("name");
            Program program = programProvider.getProgram(name);
            if (program == null) {
                sendResponse(exchange, "{\"error\": \"Program not found: " + (name != null ? escapeJson(name) : "current") + "\"}");
                return;
            }
            programProvider.closeProgram(program);
            sendResponse(exchange, "{\"success\": true, \"closed\": \"" + escapeJson(program.getName()) + "\"}");
        });

        server.createContext("/run_analysis", exchange -> {
            Map<String, String> params = parseQueryParams(exchange);
            String programName = params.get("program");
            Program program = programProvider.getProgram(programName);
            if (program == null) {
                sendResponse(exchange, "{\"error\": \"No program loaded\"}");
                return;
            }
            HeadlessProgramProvider.AnalysisResult result = programProvider.runAnalysis(program);
            sendResponse(exchange, "{\"success\": " + result.success + ", \"message\": \"" + escapeJson(result.message) +
                "\", \"duration_ms\": " + result.durationMs + ", \"total_functions\": " + result.totalFunctions +
                ", \"new_functions\": " + result.newFunctions + ", \"program\": \"" + escapeJson(program.getName()) + "\"}");
        });

        // --- Project management (headless-specific) ---
        server.createContext("/open_project", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String projectPath = params.get("path");
            if (projectPath == null || projectPath.isEmpty()) {
                sendResponse(exchange, "{\"error\": \"Project path required\"}");
                return;
            }
            boolean success = programProvider.openProject(projectPath);
            if (success) {
                sendResponse(exchange, "{\"success\": true, \"project\": \"" + escapeJson(programProvider.getProjectName()) + "\"}");
            } else {
                sendResponse(exchange, "{\"error\": \"Failed to open project: " + escapeJson(projectPath) + "\"}");
            }
        });

        server.createContext("/close_project", exchange -> {
            if (!programProvider.hasProject()) {
                sendResponse(exchange, "{\"error\": \"No project currently open\"}");
                return;
            }
            String projectName = programProvider.getProjectName();
            programProvider.closeProject();
            sendResponse(exchange, "{\"success\": true, \"closed\": \"" + escapeJson(projectName) + "\"}");
        });

        server.createContext("/list_project_files", exchange -> {
            if (!programProvider.hasProject()) {
                sendResponse(exchange, "{\"error\": \"No project currently open\"}");
                return;
            }
            List<HeadlessProgramProvider.ProjectFileInfo> files = programProvider.listProjectFiles();
            StringBuilder sb = new StringBuilder();
            sb.append("{\"project\": \"").append(escapeJson(programProvider.getProjectName())).append("\", \"files\": [");
            for (int i = 0; i < files.size(); i++) {
                HeadlessProgramProvider.ProjectFileInfo file = files.get(i);
                if (i > 0) sb.append(", ");
                sb.append("{\"name\": \"").append(escapeJson(file.name)).append("\", ");
                sb.append("\"path\": \"").append(escapeJson(file.path)).append("\", ");
                sb.append("\"contentType\": \"").append(escapeJson(file.contentType)).append("\", ");
                sb.append("\"readOnly\": ").append(file.readOnly).append("}");
            }
            sb.append("], \"count\": ").append(files.size()).append("}");
            sendResponse(exchange, sb.toString());
        });

        server.createContext("/load_program_from_project", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String programPath = params.get("path");
            if (programPath == null || programPath.isEmpty()) {
                sendResponse(exchange, "{\"error\": \"Program path required (e.g., /D2Client.dll)\"}");
                return;
            }
            if (!programProvider.hasProject()) {
                sendResponse(exchange, "{\"error\": \"No project currently open. Use /open_project first.\"}");
                return;
            }
            Program program = programProvider.loadProgramFromProject(programPath);
            if (program != null) {
                sendResponse(exchange, "{\"success\": true, \"program\": \"" + escapeJson(program.getName()) +
                    "\", \"path\": \"" + escapeJson(programPath) + "\"}");
            } else {
                sendResponse(exchange, "{\"error\": \"Failed to load program: " + escapeJson(programPath) + "\"}");
            }
        });

        server.createContext("/get_project_info", exchange -> {
            if (!programProvider.hasProject()) {
                sendResponse(exchange, "{\"has_project\": false}");
                return;
            }
            List<HeadlessProgramProvider.ProjectFileInfo> files = programProvider.listProjectFiles();
            int programCount = (int) files.stream()
                .filter(f -> "Program".equals(f.contentType)).count();
            sendResponse(exchange, "{\"has_project\": true, \"project_name\": \"" + escapeJson(programProvider.getProjectName()) +
                "\", \"file_count\": " + files.size() + ", \"program_count\": " + programCount + "}");
        });

        // --- Project lifecycle ---
        server.createContext("/create_project", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String parentDir = params.get("parentDir");
            String name = params.get("name");
            if (parentDir == null || parentDir.isEmpty()) { sendResponse(exchange, "{\"error\": \"parentDir required\"}"); return; }
            if (name == null || name.isEmpty()) { sendResponse(exchange, "{\"error\": \"name required\"}"); return; }
            try {
                boolean ok = programProvider.createProject(parentDir, name);
                if (ok) sendResponse(exchange, "{\"success\": true, \"name\": \"" + escapeJson(name) + "\", \"path\": \"" + escapeJson(parentDir) + "/" + escapeJson(name) + "\"}");
                else sendResponse(exchange, "{\"error\": \"Failed to create project\"}");
            } catch (Exception e) { sendResponse(exchange, "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}"); }
        });

        server.createContext("/delete_project", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String projectPath = params.get("projectPath");
            if (projectPath == null || projectPath.isEmpty()) { sendResponse(exchange, "{\"error\": \"projectPath required\"}"); return; }
            try {
                boolean ok = programProvider.deleteProject(projectPath);
                if (ok) sendResponse(exchange, "{\"success\": true, \"deleted\": \"" + escapeJson(projectPath) + "\"}");
                else sendResponse(exchange, "{\"error\": \"Failed to delete project\"}");
            } catch (Exception e) { sendResponse(exchange, "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}"); }
        });

        server.createContext("/list_projects", exchange -> {
            Map<String, String> params = parseQueryParams(exchange);
            try {
                List<HeadlessProgramProvider.ProjectInfo> projects = programProvider.listProjects(params.get("searchDir"));
                StringBuilder sb = new StringBuilder("[");
                for (int i = 0; i < projects.size(); i++) {
                    if (i > 0) sb.append(",");
                    HeadlessProgramProvider.ProjectInfo p = projects.get(i);
                    sb.append("{\"name\":\"").append(escapeJson(p.name)).append("\",");
                    sb.append("\"path\":\"").append(escapeJson(p.path)).append("\",");
                    sb.append("\"active\":").append(p.active).append("}");
                }
                sb.append("]");
                sendResponse(exchange, sb.toString());
            } catch (Exception e) { sendResponse(exchange, "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}"); }
        });

        // --- Project organization ---
        server.createContext("/create_folder", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            try {
                programProvider.createFolder(params.get("path"));
                sendResponse(exchange, "{\"success\": true, \"folder\": \"" + escapeJson(params.get("path")) + "\"}");
            } catch (Exception e) { sendResponse(exchange, "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}"); }
        });

        server.createContext("/move_file", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            try {
                programProvider.moveFile(params.get("filePath"), params.get("destFolder"));
                sendResponse(exchange, "{\"success\": true, \"moved\": \"" + escapeJson(params.get("filePath")) + "\", \"to\": \"" + escapeJson(params.get("destFolder")) + "\"}");
            } catch (Exception e) { sendResponse(exchange, "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}"); }
        });

        server.createContext("/move_folder", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            try {
                programProvider.moveFolder(params.get("sourcePath"), params.get("destPath"));
                sendResponse(exchange, "{\"success\": true, \"moved\": \"" + escapeJson(params.get("sourcePath")) + "\", \"to\": \"" + escapeJson(params.get("destPath")) + "\"}");
            } catch (Exception e) { sendResponse(exchange, "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}"); }
        });

        server.createContext("/delete_file", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            try {
                programProvider.deleteProjectFile(params.get("filePath"));
                sendResponse(exchange, "{\"success\": true, \"deleted\": \"" + escapeJson(params.get("filePath")) + "\"}");
            } catch (Exception e) { sendResponse(exchange, "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}"); }
        });

        // --- Analysis control ---
        server.createContext("/configure_analyzer", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String programName = params.get("program");
            String analyzerName = params.get("name");
            Program program = programProvider.getProgram(programName);
            if (program == null) { sendResponse(exchange, "{\"error\": \"No program loaded\"}"); return; }
            Boolean enabled = params.containsKey("enabled") ? Boolean.parseBoolean(params.get("enabled")) : null;
            try {
                programProvider.configureAnalyzer(program, analyzerName, enabled);
                sendResponse(exchange, "{\"success\": true, \"analyzer\": \"" + escapeJson(analyzerName) + "\"}");
            } catch (Exception e) { sendResponse(exchange, "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}"); }
        });

        // --- Server management ---
        server.createContext("/server/connect", exchange -> sendResponseR(exchange, serverManager.connect()));
        server.createContext("/server/status", exchange -> sendResponseR(exchange, serverManager.getStatus()));
        server.createContext("/server/repositories", exchange -> sendResponseR(exchange, serverManager.listRepositories()));
        server.createContext("/server/disconnect", exchange -> sendResponseR(exchange, serverManager.disconnect()));

        server.createContext("/server/repository/files", exchange -> {
            Map<String, String> params = parseQueryParams(exchange);
            String path = params.get("path");
            if (path == null) path = "/";
            sendResponseR(exchange, serverManager.listRepositoryFiles(params.get("repo"), path));
        });

        server.createContext("/server/repository/file", exchange -> {
            Map<String, String> params = parseQueryParams(exchange);
            sendResponseR(exchange, serverManager.getFileInfo(params.get("repo"), params.get("path")));
        });

        server.createContext("/server/repository/create", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponseR(exchange, serverManager.createRepository(params.get("name")));
        });

        server.createContext("/server/version_control/checkout", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponseR(exchange, serverManager.checkoutFile(params.get("repo"), params.get("path")));
        });

        server.createContext("/server/version_control/checkin", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            boolean keepCheckedOut = parseBooleanOrDefault(params.get("keepCheckedOut"), false);
            sendResponseR(exchange, serverManager.checkinFile(params.get("repo"), params.get("path"), params.get("comment"), keepCheckedOut));
        });

        server.createContext("/server/version_control/undo_checkout", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponseR(exchange, serverManager.undoCheckout(params.get("repo"), params.get("path")));
        });

        server.createContext("/server/version_control/add", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponseR(exchange, serverManager.addToVersionControl(params.get("repo"), params.get("path"), params.get("comment")));
        });

        server.createContext("/server/version_history", exchange -> {
            Map<String, String> params = parseQueryParams(exchange);
            sendResponseR(exchange, serverManager.getVersionHistory(params.get("repo"), params.get("path")));
        });

        server.createContext("/server/checkouts", exchange -> {
            Map<String, String> params = parseQueryParams(exchange);
            sendResponseR(exchange, serverManager.getCheckouts(params.get("repo"), params.get("path")));
        });

        server.createContext("/server/admin/terminate_checkout", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            long checkoutId = Long.parseLong(params.getOrDefault("checkoutId", "0"));
            sendResponseR(exchange, serverManager.terminateCheckout(params.get("repo"), params.get("path"), checkoutId));
        });

        server.createContext("/server/admin/users", exchange -> sendResponseR(exchange, serverManager.listServerUsers()));

        server.createContext("/server/admin/set_permissions", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            int accessLevel = parseIntOrDefault(params.get("accessLevel"), 1);
            sendResponseR(exchange, serverManager.setUserPermissions(params.get("repo"), params.get("user"), accessLevel));
        });

        // --- Exit ---
        server.createContext("/exit_ghidra", exchange -> {
            sendResponse(exchange, "{\"status\": \"shutting_down\"}");
            new Thread(() -> {
                try { Thread.sleep(500); } catch (InterruptedException ignored) {}
                System.exit(0);
            }).start();
        });

        System.out.println("Registered REST API endpoints (shared + headless-specific)");
    }

    public void stop() {
        running = false;
        synchronized (this) {
            notifyAll();
        }

        if (server != null) {
            System.out.println("Stopping HTTP server...");
            server.stop(2);
            server = null;
        }

        if (serverManager != null && serverManager.isConnected()) {
            System.out.println("Disconnecting from Ghidra server...");
            serverManager.disconnect();
        }

        if (programProvider != null) {
            System.out.println("Closing programs...");
            programProvider.closeAllPrograms();
        }

        System.out.println("Server stopped");
    }

    // ==========================================================================
    // HTTP UTILITY METHODS
    // ==========================================================================

    private void sendResponse(com.sun.net.httpserver.HttpExchange exchange, String response) throws IOException {
        byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=UTF-8");
        exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
        exchange.sendResponseHeaders(200, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    /** Send a Response (from services that return the sealed type). */
    private void sendResponseR(com.sun.net.httpserver.HttpExchange exchange, Response response) throws IOException {
        sendResponse(exchange, Response.r2s(response));
    }

    private Map<String, String> parseQueryParams(com.sun.net.httpserver.HttpExchange exchange) {
        Map<String, String> params = new HashMap<>();
        String query = exchange.getRequestURI().getRawQuery();
        if (query != null && !query.isEmpty()) {
            for (String param : query.split("&")) {
                String[] pair = param.split("=", 2);
                if (pair.length == 2) {
                    try {
                        String key = java.net.URLDecoder.decode(pair[0], StandardCharsets.UTF_8);
                        String value = java.net.URLDecoder.decode(pair[1], StandardCharsets.UTF_8);
                        params.put(key, value);
                    } catch (Exception e) {
                        // Skip malformed param
                    }
                }
            }
        }
        return params;
    }

    private Map<String, String> parsePostParams(com.sun.net.httpserver.HttpExchange exchange) throws IOException {
        Map<String, String> params = new HashMap<>();
        String contentType = exchange.getRequestHeaders().getFirst("Content-Type");
        if (contentType == null) contentType = "";
        String body;
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(exchange.getRequestBody(), StandardCharsets.UTF_8))) {
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) sb.append(line);
            body = sb.toString();
        }
        if (body.isEmpty()) return params;
        if (contentType.contains("application/json")) {
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
            for (String param : body.split("&")) {
                String[] pair = param.split("=", 2);
                if (pair.length == 2) {
                    try {
                        String key = java.net.URLDecoder.decode(pair[0], StandardCharsets.UTF_8);
                        String value = java.net.URLDecoder.decode(pair[1], StandardCharsets.UTF_8);
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
        if (value == null || value.isEmpty()) return defaultValue;
        try { return Integer.parseInt(value); } catch (NumberFormatException e) { return defaultValue; }
    }

    private boolean parseBooleanOrDefault(String value, boolean defaultValue) {
        if (value == null || value.isEmpty()) return defaultValue;
        return Boolean.parseBoolean(value);
    }

    private String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    // ==========================================================================
    // GETTERS
    // ==========================================================================

    public ProgramProvider getProgramProvider() { return programProvider; }
    public ThreadingStrategy getThreadingStrategy() { return threadingStrategy; }
    public boolean isRunning() { return running; }
    public int getPort() { return port; }
}
