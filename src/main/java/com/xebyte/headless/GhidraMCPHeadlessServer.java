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

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import com.xebyte.core.AnnotationScanner;
import com.xebyte.core.EndpointDef;
import com.xebyte.core.JsonHelper;
import com.xebyte.core.ProgramProvider;
import com.xebyte.core.ThreadingStrategy;
import ghidra.GhidraApplicationLayout;
import ghidra.GhidraLaunchable;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import java.io.*;
import java.net.InetSocketAddress;
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

    private static final String VERSION = "5.0.0-headless";
    private static final int DEFAULT_PORT = 8089;
    private static final String DEFAULT_BIND_ADDRESS = "127.0.0.1";

    private HttpServer server;
    private HeadlessProgramProvider programProvider;
    private DirectThreadingStrategy threadingStrategy;
    private int port = DEFAULT_PORT;
    private String bindAddress = DEFAULT_BIND_ADDRESS;
    private boolean running = false;

    // Endpoint handler registry
    private HeadlessEndpointHandler endpointHandler;
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

        // Create endpoint handler
        endpointHandler = new HeadlessEndpointHandler(programProvider, threadingStrategy);

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

    private void startServer() throws IOException {
        server = HttpServer.create(new InetSocketAddress(bindAddress, port), 0);
        registerEndpoints();
        server.setExecutor(java.util.concurrent.Executors.newFixedThreadPool(10));
        server.start();
        running = true;
        System.out.println("HTTP server started on " + bindAddress + ":" + port);
    }

    private void registerEndpoints() {
        // ==========================================================================
        // INFRASTRUCTURE ENDPOINTS (not in service layer)
        // ==========================================================================

        server.createContext("/check_connection", exchange -> {
            sendResponse(exchange, "Connection OK - GhidraMCP Headless Server v" + VERSION);
        });

        server.createContext("/health", exchange -> {
            sendResponse(exchange, endpointHandler.getHealth());
        });

        server.createContext("/get_version", exchange -> {
            sendResponse(exchange, endpointHandler.getVersion());
        });

        // ==========================================================================
        // SHARED ENDPOINTS — Annotation-driven registration via AnnotationScanner
        // ==========================================================================

        AnnotationScanner scanner = new AnnotationScanner(
            endpointHandler.getListingService(), endpointHandler.getFunctionService(),
            endpointHandler.getCommentService(), endpointHandler.getSymbolLabelService(),
            endpointHandler.getXrefCallGraphService(), endpointHandler.getDataTypeService(),
            endpointHandler.getAnalysisService(), endpointHandler.getDocumentationHashService(),
            endpointHandler.getMalwareSecurityService(), endpointHandler.getProgramScriptService());

        for (EndpointDef ep : scanner.getEndpoints()) {
            server.createContext(ep.path(), exchange -> {
                try {
                    Map<String, String> query = parseQueryParams(exchange);
                    Map<String, Object> body = "POST".equalsIgnoreCase(exchange.getRequestMethod())
                        ? JsonHelper.parseBody(exchange.getRequestBody()) : Map.of();
                    sendResponse(exchange, ep.handler().handle(query, body).toJson());
                } catch (Exception e) {
                    String msg = e.getMessage() != null ? e.getMessage() : e.toString();
                    sendResponse(exchange, "{\"error\": \"" + msg.replace("\\", "\\\\").replace("\"", "\\\"") + "\"}");
                }
            });
        }

        // Store scanner size for dynamic endpoint count reporting
        registeredEndpointCount = scanner.getEndpoints().size();

        // ==========================================================================
        // SCHEMA ENDPOINT — Serves machine-readable API metadata
        // ==========================================================================

        String schemaJson = scanner.generateSchema();
        server.createContext("/mcp/schema", exchange -> {
            sendResponse(exchange, schemaJson);
        });

        // ==========================================================================
        // HEADLESS-ONLY ENDPOINTS (no GUI equivalent)
        // ==========================================================================

        server.createContext("/get_current_address", exchange -> {
            sendResponse(exchange, "{\"error\": \"Headless mode - use address parameter with specific endpoints\"}");
        });

        server.createContext("/get_current_function", exchange -> {
            sendResponse(exchange, "{\"error\": \"Headless mode - use get_function_by_address\"}");
        });

        // --- Program Management ---

        server.createContext("/load_program", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String filePath = params.get("file");
            sendResponse(exchange, endpointHandler.loadProgram(filePath));
        });

        server.createContext("/close_program", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String name = params.get("name");
            sendResponse(exchange, endpointHandler.closeProgram(name));
        });

        // --- Project Management (headless-specific) ---

        server.createContext("/open_project", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String projectPath = params.get("path");
            sendResponse(exchange, endpointHandler.openProject(projectPath));
        });

        server.createContext("/close_project", exchange -> {
            sendResponse(exchange, endpointHandler.closeProject());
        });

        server.createContext("/load_program_from_project", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String programPath = params.get("path");
            sendResponse(exchange, endpointHandler.loadProgramFromProject(programPath));
        });

        server.createContext("/get_project_info", exchange -> {
            sendResponse(exchange, endpointHandler.getProjectInfo());
        });

        // GET_DATA_TYPE_SIZE - Not yet in service layer
        server.createContext("/get_data_type_size", exchange -> {
            Map<String, String> params = parseQueryParams(exchange);
            String typeName = params.get("type_name");
            String programName = params.get("program");
            sendResponse(exchange, endpointHandler.getDataTypeSize(typeName, programName));
        });

        // --- Project Lifecycle ---

        server.createContext("/create_project", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String parentDir = params.get("parentDir");
            String name = params.get("name");
            sendResponse(exchange, endpointHandler.createProject(parentDir, name));
        });

        server.createContext("/delete_project", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, endpointHandler.deleteProject(params.get("projectPath")));
        });

        server.createContext("/list_projects", exchange -> {
            Map<String, String> params = parseQueryParams(exchange);
            sendResponse(exchange, endpointHandler.listProjects(params.get("searchDir")));
        });

        // --- Project Organization ---

        server.createContext("/create_folder", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, endpointHandler.createFolder(params.get("path"), params.get("program")));
        });

        server.createContext("/move_file", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, endpointHandler.moveFile(params.get("filePath"), params.get("destFolder")));
        });

        server.createContext("/move_folder", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, endpointHandler.moveFolder(params.get("sourcePath"), params.get("destPath")));
        });

        server.createContext("/delete_file", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, endpointHandler.deleteFile(params.get("filePath")));
        });

        // --- Server Endpoints ---

        server.createContext("/server/connect", exchange -> {
            sendResponse(exchange, serverManager.connect());
        });

        server.createContext("/server/status", exchange -> {
            sendResponse(exchange, serverManager.getStatus());
        });

        server.createContext("/server/repositories", exchange -> {
            sendResponse(exchange, serverManager.listRepositories());
        });

        server.createContext("/server/disconnect", exchange -> {
            sendResponse(exchange, serverManager.disconnect());
        });

        server.createContext("/server/repository/files", exchange -> {
            Map<String, String> params = parseQueryParams(exchange);
            String repo = params.get("repo");
            String path = params.get("path");
            if (path == null) path = "/";
            sendResponse(exchange, serverManager.listRepositoryFiles(repo, path));
        });

        server.createContext("/server/repository/file", exchange -> {
            Map<String, String> params = parseQueryParams(exchange);
            String repo = params.get("repo");
            String path = params.get("path");
            sendResponse(exchange, serverManager.getFileInfo(repo, path));
        });

        server.createContext("/server/repository/create", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, serverManager.createRepository(params.get("name")));
        });

        // --- Version Control ---

        server.createContext("/server/version_control/checkout", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, serverManager.checkoutFile(params.get("repo"), params.get("path")));
        });

        server.createContext("/server/version_control/checkin", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            boolean keepCheckedOut = parseBooleanOrDefault(params.get("keepCheckedOut"), false);
            sendResponse(exchange, serverManager.checkinFile(
                params.get("repo"), params.get("path"), params.get("comment"), keepCheckedOut));
        });

        server.createContext("/server/version_control/undo_checkout", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, serverManager.undoCheckout(params.get("repo"), params.get("path")));
        });

        server.createContext("/server/version_control/add", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            sendResponse(exchange, serverManager.addToVersionControl(
                params.get("repo"), params.get("path"), params.get("comment")));
        });

        server.createContext("/server/version_history", exchange -> {
            Map<String, String> params = parseQueryParams(exchange);
            sendResponse(exchange, serverManager.getVersionHistory(params.get("repo"), params.get("path")));
        });

        server.createContext("/server/checkouts", exchange -> {
            Map<String, String> params = parseQueryParams(exchange);
            sendResponse(exchange, serverManager.getCheckouts(params.get("repo"), params.get("path")));
        });

        // --- Admin ---

        server.createContext("/server/admin/terminate_checkout", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            long checkoutId = Long.parseLong(params.getOrDefault("checkoutId", "0"));
            sendResponse(exchange, serverManager.terminateCheckout(
                params.get("repo"), params.get("path"), checkoutId));
        });

        server.createContext("/server/admin/users", exchange -> {
            sendResponse(exchange, serverManager.listServerUsers());
        });

        server.createContext("/server/admin/set_permissions", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            int accessLevel = parseIntOrDefault(params.get("accessLevel"), 1);
            sendResponse(exchange, serverManager.setUserPermissions(
                params.get("repo"), params.get("user"), accessLevel));
        });

        // --- Analysis Control ---

        server.createContext("/configure_analyzer", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            Boolean enabled = params.containsKey("enabled") ?
                parseBooleanOrDefault(params.get("enabled"), true) : null;
            sendResponse(exchange, endpointHandler.configureAnalyzer(
                params.get("program"), params.get("name"), enabled));
        });

        // --- Batch Variable Types (headless-specific parsing) ---

        server.createContext("/batch_set_variable_types", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            boolean forceIndividual = parseBooleanOrDefault(params.get("forceIndividual"), false);
            sendResponse(exchange, endpointHandler.batchSetVariableTypes(
                params.get("functionAddress"), params.get("variableTypes"), forceIndividual, params.get("program")));
        });

        // --- Exit ---

        server.createContext("/exit_ghidra", exchange -> {
            sendResponse(exchange, endpointHandler.exitServer());
        });

        System.out.println("Registered " + countEndpoints() + " REST API endpoints");
    }

    private int countEndpoints() {
        // registeredEndpointCount = shared endpoints from EndpointRegistry
        // 39 = infrastructure + schema + headless-only endpoints registered via createContext
        return registeredEndpointCount + 39;
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

    private void sendResponse(HttpExchange exchange, String response) throws IOException {
        byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=UTF-8");
        exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
        exchange.sendResponseHeaders(200, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    private Map<String, String> parseQueryParams(HttpExchange exchange) {
        Map<String, String> params = new HashMap<>();
        String query = exchange.getRequestURI().getRawQuery();
        if (query != null && !query.isEmpty()) {
            for (String param : query.split("&")) {
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

    private double parseDoubleOrDefault(String value, double defaultValue) {
        if (value == null || value.isEmpty()) {
            return defaultValue;
        }
        try {
            return Double.parseDouble(value);
        } catch (NumberFormatException e) {
            return defaultValue;
        }
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

    public int getPort() {
        return port;
    }
}
