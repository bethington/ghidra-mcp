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

    private static final String VERSION = "1.9.4-headless";
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
        // Legacy health check endpoint (plain text)
        server.createContext("/check_connection", exchange -> {
            sendResponse(exchange, "Connection OK - GhidraMCP Headless Server v" + VERSION);
        });

        // Health check endpoint (JSON, for Docker/Kubernetes)
        server.createContext("/health", exchange -> {
            sendResponse(exchange, endpointHandler.getHealth());
        });

        // Version endpoint
        server.createContext("/get_version", exchange -> {
            sendResponse(exchange, endpointHandler.getVersion());
        });

        // Metadata endpoint
        server.createContext("/get_metadata", exchange -> {
            sendResponse(exchange, endpointHandler.getMetadata());
        });

        // ==========================================================================
        // LISTING ENDPOINTS
        // ==========================================================================

        server.createContext("/list_methods", exchange -> {
            Map<String, String> params = parseQueryParams(exchange);
            int offset = parseIntOrDefault(params.get("offset"), 0);
            int limit = parseIntOrDefault(params.get("limit"), 100);
            String programName = params.get("program");
            sendResponse(exchange, endpointHandler.listMethods(offset, limit, programName));
        });

        server.createContext("/list_functions", exchange -> {
            Map<String, String> params = parseQueryParams(exchange);
            String programName = params.get("program");
            sendResponse(exchange, endpointHandler.listFunctions(programName));
        });

        server.createContext("/list_classes", exchange -> {
            Map<String, String> params = parseQueryParams(exchange);
            int offset = parseIntOrDefault(params.get("offset"), 0);
            int limit = parseIntOrDefault(params.get("limit"), 100);
            String programName = params.get("program");
            sendResponse(exchange, endpointHandler.listClasses(offset, limit, programName));
        });

        server.createContext("/list_segments", exchange -> {
            Map<String, String> params = parseQueryParams(exchange);
            int offset = parseIntOrDefault(params.get("offset"), 0);
            int limit = parseIntOrDefault(params.get("limit"), 100);
            String programName = params.get("program");
            sendResponse(exchange, endpointHandler.listSegments(offset, limit, programName));
        });

        server.createContext("/list_imports", exchange -> {
            Map<String, String> params = parseQueryParams(exchange);
            int offset = parseIntOrDefault(params.get("offset"), 0);
            int limit = parseIntOrDefault(params.get("limit"), 100);
            String programName = params.get("program");
            sendResponse(exchange, endpointHandler.listImports(offset, limit, programName));
        });

        server.createContext("/list_exports", exchange -> {
            Map<String, String> params = parseQueryParams(exchange);
            int offset = parseIntOrDefault(params.get("offset"), 0);
            int limit = parseIntOrDefault(params.get("limit"), 100);
            String programName = params.get("program");
            sendResponse(exchange, endpointHandler.listExports(offset, limit, programName));
        });

        server.createContext("/list_namespaces", exchange -> {
            Map<String, String> params = parseQueryParams(exchange);
            int offset = parseIntOrDefault(params.get("offset"), 0);
            int limit = parseIntOrDefault(params.get("limit"), 100);
            String programName = params.get("program");
            sendResponse(exchange, endpointHandler.listNamespaces(offset, limit, programName));
        });

        server.createContext("/list_data_items", exchange -> {
            Map<String, String> params = parseQueryParams(exchange);
            int offset = parseIntOrDefault(params.get("offset"), 0);
            int limit = parseIntOrDefault(params.get("limit"), 100);
            String programName = params.get("program");
            sendResponse(exchange, endpointHandler.listDataItems(offset, limit, programName));
        });

        server.createContext("/list_strings", exchange -> {
            Map<String, String> params = parseQueryParams(exchange);
            int offset = parseIntOrDefault(params.get("offset"), 0);
            int limit = parseIntOrDefault(params.get("limit"), 100);
            String filter = params.get("filter");
            String programName = params.get("program");
            sendResponse(exchange, endpointHandler.listStrings(offset, limit, filter, programName));
        });

        server.createContext("/list_data_types", exchange -> {
            Map<String, String> params = parseQueryParams(exchange);
            int offset = parseIntOrDefault(params.get("offset"), 0);
            int limit = parseIntOrDefault(params.get("limit"), 100);
            String category = params.get("category");
            String programName = params.get("program");
            sendResponse(exchange, endpointHandler.listDataTypes(offset, limit, category, programName));
        });

        // ==========================================================================
        // GETTER ENDPOINTS
        // ==========================================================================

        server.createContext("/get_function_by_address", exchange -> {
            Map<String, String> params = parseQueryParams(exchange);
            String address = params.get("address");
            String programName = params.get("program");
            sendResponse(exchange, endpointHandler.getFunctionByAddress(address, programName));
        });

        server.createContext("/get_current_address", exchange -> {
            // Headless mode has no cursor
            sendResponse(exchange, "{\"error\": \"Headless mode - use address parameter with specific endpoints\"}");
        });

        server.createContext("/get_current_function", exchange -> {
            // Headless mode has no cursor
            sendResponse(exchange, "{\"error\": \"Headless mode - use get_function_by_address\"}");
        });

        // ==========================================================================
        // DECOMPILE/DISASSEMBLE ENDPOINTS
        // ==========================================================================

        server.createContext("/decompile_function", exchange -> {
            Map<String, String> params = parseQueryParams(exchange);
            String address = params.get("address");
            String name = params.get("name");
            String programName = params.get("program");
            sendResponse(exchange, endpointHandler.decompileFunction(address, name, programName));
        });

        server.createContext("/disassemble_function", exchange -> {
            Map<String, String> params = parseQueryParams(exchange);
            String address = params.get("address");
            String programName = params.get("program");
            sendResponse(exchange, endpointHandler.disassembleFunction(address, programName));
        });

        // ==========================================================================
        // CROSS-REFERENCE ENDPOINTS
        // ==========================================================================

        server.createContext("/get_xrefs_to", exchange -> {
            Map<String, String> params = parseQueryParams(exchange);
            String address = params.get("address");
            int offset = parseIntOrDefault(params.get("offset"), 0);
            int limit = parseIntOrDefault(params.get("limit"), 100);
            String programName = params.get("program");
            sendResponse(exchange, endpointHandler.getXrefsTo(address, offset, limit, programName));
        });

        server.createContext("/get_xrefs_from", exchange -> {
            Map<String, String> params = parseQueryParams(exchange);
            String address = params.get("address");
            int offset = parseIntOrDefault(params.get("offset"), 0);
            int limit = parseIntOrDefault(params.get("limit"), 100);
            String programName = params.get("program");
            sendResponse(exchange, endpointHandler.getXrefsFrom(address, offset, limit, programName));
        });

        server.createContext("/get_function_xrefs", exchange -> {
            Map<String, String> params = parseQueryParams(exchange);
            String name = params.get("name");
            int offset = parseIntOrDefault(params.get("offset"), 0);
            int limit = parseIntOrDefault(params.get("limit"), 100);
            String programName = params.get("program");
            sendResponse(exchange, endpointHandler.getFunctionXrefs(name, offset, limit, programName));
        });

        // ==========================================================================
        // SEARCH ENDPOINTS
        // ==========================================================================

        server.createContext("/search_functions", exchange -> {
            Map<String, String> params = parseQueryParams(exchange);
            String query = params.get("query");
            int offset = parseIntOrDefault(params.get("offset"), 0);
            int limit = parseIntOrDefault(params.get("limit"), 100);
            String programName = params.get("program");
            sendResponse(exchange, endpointHandler.searchFunctions(query, offset, limit, programName));
        });

        // ==========================================================================
        // PHASE 1: ESSENTIAL ANALYSIS ENDPOINTS
        // ==========================================================================

        server.createContext("/get_function_callees", exchange -> {
            Map<String, String> params = parseQueryParams(exchange);
            String name = params.get("name");
            int offset = parseIntOrDefault(params.get("offset"), 0);
            int limit = parseIntOrDefault(params.get("limit"), 100);
            String programName = params.get("program");
            sendResponse(exchange, endpointHandler.getFunctionCallees(name, offset, limit, programName));
        });

        server.createContext("/get_function_callers", exchange -> {
            Map<String, String> params = parseQueryParams(exchange);
            String name = params.get("name");
            int offset = parseIntOrDefault(params.get("offset"), 0);
            int limit = parseIntOrDefault(params.get("limit"), 100);
            String programName = params.get("program");
            sendResponse(exchange, endpointHandler.getFunctionCallers(name, offset, limit, programName));
        });

        server.createContext("/get_function_variables", exchange -> {
            Map<String, String> params = parseQueryParams(exchange);
            String functionName = params.get("function_name");
            String programName = params.get("program");
            sendResponse(exchange, endpointHandler.getFunctionVariables(functionName, programName));
        });

        server.createContext("/set_function_prototype", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String prototype = params.get("prototype");
            String callingConvention = params.get("calling_convention");
            sendResponse(exchange, endpointHandler.setFunctionPrototype(functionAddress, prototype, callingConvention));
        });

        server.createContext("/set_local_variable_type", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String variableName = params.get("variable_name");
            String newType = params.get("new_type");
            sendResponse(exchange, endpointHandler.setLocalVariableType(functionAddress, variableName, newType));
        });

        server.createContext("/create_struct", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String name = params.get("name");
            String fields = params.get("fields");
            sendResponse(exchange, endpointHandler.createStruct(name, fields));
        });

        server.createContext("/apply_data_type", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String typeName = params.get("type_name");
            boolean clearExisting = !"false".equalsIgnoreCase(params.get("clear_existing"));
            sendResponse(exchange, endpointHandler.applyDataType(address, typeName, clearExisting));
        });

        server.createContext("/batch_rename_variables", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String variableRenames = params.get("variable_renames");
            sendResponse(exchange, endpointHandler.batchRenameVariables(functionAddress, variableRenames));
        });

        server.createContext("/set_plate_comment", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String comment = params.get("comment");
            sendResponse(exchange, endpointHandler.setPlateComment(functionAddress, comment));
        });

        // ==========================================================================
        // PHASE 2: PRODUCTIVITY ENDPOINTS
        // ==========================================================================

        server.createContext("/batch_set_comments", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String decompilerComments = params.get("decompiler_comments");
            String disassemblyComments = params.get("disassembly_comments");
            String plateComment = params.get("plate_comment");
            sendResponse(exchange, endpointHandler.batchSetComments(functionAddress, decompilerComments, disassemblyComments, plateComment));
        });

        server.createContext("/batch_create_labels", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String labels = params.get("labels");
            sendResponse(exchange, endpointHandler.batchCreateLabels(labels));
        });

        server.createContext("/search_functions_enhanced", exchange -> {
            Map<String, String> params = parseQueryParams(exchange);
            String namePattern = params.get("name_pattern");
            Integer minXrefs = params.get("min_xrefs") != null ? Integer.parseInt(params.get("min_xrefs")) : null;
            Integer maxXrefs = params.get("max_xrefs") != null ? Integer.parseInt(params.get("max_xrefs")) : null;
            Boolean hasCustomName = params.get("has_custom_name") != null ? Boolean.parseBoolean(params.get("has_custom_name")) : null;
            boolean regex = "true".equalsIgnoreCase(params.get("regex"));
            String sortBy = params.get("sort_by");
            int offset = parseIntOrDefault(params.get("offset"), 0);
            int limit = parseIntOrDefault(params.get("limit"), 100);
            String programName = params.get("program");
            sendResponse(exchange, endpointHandler.searchFunctionsEnhanced(namePattern, minXrefs, maxXrefs, hasCustomName, regex, sortBy, offset, limit, programName));
        });

        server.createContext("/analyze_function_complete", exchange -> {
            Map<String, String> params = parseQueryParams(exchange);
            String name = params.get("name");
            boolean includeXrefs = !"false".equalsIgnoreCase(params.get("include_xrefs"));
            boolean includeCallees = !"false".equalsIgnoreCase(params.get("include_callees"));
            boolean includeCallers = !"false".equalsIgnoreCase(params.get("include_callers"));
            boolean includeDisasm = !"false".equalsIgnoreCase(params.get("include_disasm"));
            boolean includeVariables = !"false".equalsIgnoreCase(params.get("include_variables"));
            String programName = params.get("program");
            sendResponse(exchange, endpointHandler.analyzeFunctionComplete(name, includeXrefs, includeCallees, includeCallers, includeDisasm, includeVariables, programName));
        });

        server.createContext("/get_bulk_xrefs", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String addresses = params.get("addresses");
            sendResponse(exchange, endpointHandler.getBulkXrefs(addresses));
        });

        server.createContext("/list_globals", exchange -> {
            Map<String, String> params = parseQueryParams(exchange);
            int offset = parseIntOrDefault(params.get("offset"), 0);
            int limit = parseIntOrDefault(params.get("limit"), 100);
            String filter = params.get("filter");
            String programName = params.get("program");
            sendResponse(exchange, endpointHandler.listGlobals(offset, limit, filter, programName));
        });

        server.createContext("/rename_global_variable", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String oldName = params.get("old_name");
            String newName = params.get("new_name");
            sendResponse(exchange, endpointHandler.renameGlobalVariable(oldName, newName));
        });

        server.createContext("/force_decompile", exchange -> {
            Map<String, String> params = parseQueryParams(exchange);
            String address = params.get("address");
            String name = params.get("name");
            String programName = params.get("program");
            sendResponse(exchange, endpointHandler.forceDecompile(address, name, programName));
        });

        server.createContext("/get_entry_points", exchange -> {
            Map<String, String> params = parseQueryParams(exchange);
            String programName = params.get("program");
            sendResponse(exchange, endpointHandler.getEntryPoints(programName));
        });

        server.createContext("/list_calling_conventions", exchange -> {
            Map<String, String> params = parseQueryParams(exchange);
            String programName = params.get("program");
            sendResponse(exchange, endpointHandler.listCallingConventions(programName));
        });

        server.createContext("/find_next_undefined_function", exchange -> {
            Map<String, String> params = parseQueryParams(exchange);
            String startAddress = params.get("start_address");
            String criteria = params.get("criteria");
            String pattern = params.get("pattern");
            String direction = params.get("direction");
            String programName = params.get("program");
            sendResponse(exchange, endpointHandler.findNextUndefinedFunction(startAddress, criteria, pattern, direction, programName));
        });

        // ==========================================================================
        // RENAME ENDPOINTS (POST)
        // ==========================================================================

        server.createContext("/rename_function", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String oldName = params.get("oldName");
            String newName = params.get("newName");
            sendResponse(exchange, endpointHandler.renameFunction(oldName, newName));
        });

        server.createContext("/rename_function_by_address", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("function_address");
            String newName = params.get("new_name");
            sendResponse(exchange, endpointHandler.renameFunctionByAddress(address, newName));
        });

        server.createContext("/save_program", exchange -> {
            sendResponse(exchange, endpointHandler.saveCurrentProgram());
        });

        server.createContext("/delete_function", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            sendResponse(exchange, endpointHandler.deleteFunctionAtAddress(address));
        });

        server.createContext("/create_function", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String name = params.get("name");
            boolean disassembleFirst = !"false".equalsIgnoreCase(params.get("disassemble_first"));
            sendResponse(exchange, endpointHandler.createFunctionAtAddress(address, name, disassembleFirst));
        });

        server.createContext("/create_memory_block", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String mbName = params.get("name");
            String mbAddress = params.get("address");
            long mbSize = params.get("size") != null ? Long.parseLong(params.get("size")) : 0;
            boolean mbRead = !"false".equalsIgnoreCase(params.get("read"));
            boolean mbWrite = !"false".equalsIgnoreCase(params.get("write"));
            boolean mbExecute = "true".equalsIgnoreCase(params.get("execute"));
            boolean mbVolatile = "true".equalsIgnoreCase(params.get("volatile"));
            String mbComment = params.get("comment");
            sendResponse(exchange, endpointHandler.createMemoryBlock(
                mbName, mbAddress, mbSize, mbRead, mbWrite, mbExecute, mbVolatile, mbComment));
        });

        server.createContext("/rename_data", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String newName = params.get("newName");
            sendResponse(exchange, endpointHandler.renameData(address, newName));
        });

        server.createContext("/rename_variable", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionName = params.get("functionName");
            String oldName = params.get("oldName");
            String newName = params.get("newName");
            sendResponse(exchange, endpointHandler.renameVariable(functionName, oldName, newName));
        });

        // ==========================================================================
        // COMMENT ENDPOINTS (POST)
        // ==========================================================================

        server.createContext("/set_decompiler_comment", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String comment = params.get("comment");
            sendResponse(exchange, endpointHandler.setDecompilerComment(address, comment));
        });

        server.createContext("/set_disassembly_comment", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String comment = params.get("comment");
            sendResponse(exchange, endpointHandler.setDisassemblyComment(address, comment));
        });

        // ==========================================================================
        // PROGRAM MANAGEMENT ENDPOINTS
        // ==========================================================================

        server.createContext("/list_open_programs", exchange -> {
            sendResponse(exchange, endpointHandler.listOpenPrograms());
        });

        server.createContext("/get_current_program_info", exchange -> {
            sendResponse(exchange, endpointHandler.getCurrentProgramInfo());
        });

        server.createContext("/switch_program", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String name = params.get("name");
            sendResponse(exchange, endpointHandler.switchProgram(name));
        });

        // ==========================================================================
        // HEADLESS-SPECIFIC ENDPOINTS
        // ==========================================================================

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

        server.createContext("/run_analysis", exchange -> {
            Map<String, String> params = parseQueryParams(exchange);
            String programName = params.get("program");
            sendResponse(exchange, endpointHandler.runAnalysis(programName));
        });

        // ==========================================================================
        // PROJECT MANAGEMENT ENDPOINTS (Headless-specific)
        // ==========================================================================

        server.createContext("/open_project", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String projectPath = params.get("path");
            sendResponse(exchange, endpointHandler.openProject(projectPath));
        });

        server.createContext("/close_project", exchange -> {
            sendResponse(exchange, endpointHandler.closeProject());
        });

        server.createContext("/list_project_files", exchange -> {
            sendResponse(exchange, endpointHandler.listProjectFiles());
        });

        server.createContext("/load_program_from_project", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String programPath = params.get("path");
            sendResponse(exchange, endpointHandler.loadProgramFromProject(programPath));
        });

        server.createContext("/get_project_info", exchange -> {
            sendResponse(exchange, endpointHandler.getProjectInfo());
        });

        // ==========================================================================
        // SHARED SERVER ENDPOINTS
        // ==========================================================================

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

        // ==========================================================================
        // PHASE 3: DATA TYPE SYSTEM ENDPOINTS
        // ==========================================================================

        server.createContext("/create_enum", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String name = params.get("name");
            String values = params.get("values");
            int size = parseIntOrDefault(params.get("size"), 4);
            sendResponse(exchange, endpointHandler.createEnum(name, values, size));
        });

        server.createContext("/create_union", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String name = params.get("name");
            String fields = params.get("fields");
            sendResponse(exchange, endpointHandler.createUnion(name, fields));
        });

        server.createContext("/create_typedef", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String name = params.get("name");
            String baseType = params.get("base_type");
            sendResponse(exchange, endpointHandler.createTypedef(name, baseType));
        });

        server.createContext("/create_array_type", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String baseType = params.get("base_type");
            int length = parseIntOrDefault(params.get("length"), 1);
            String name = params.get("name");
            sendResponse(exchange, endpointHandler.createArrayType(baseType, length, name));
        });

        server.createContext("/create_pointer_type", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String baseType = params.get("base_type");
            String name = params.get("name");
            sendResponse(exchange, endpointHandler.createPointerType(baseType, name));
        });

        server.createContext("/add_struct_field", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String structName = params.get("struct_name");
            String fieldName = params.get("field_name");
            String fieldType = params.get("field_type");
            int offset = parseIntOrDefault(params.get("offset"), -1);
            sendResponse(exchange, endpointHandler.addStructField(structName, fieldName, fieldType, offset));
        });

        server.createContext("/modify_struct_field", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String structName = params.get("struct_name");
            String fieldName = params.get("field_name");
            String newType = params.get("new_type");
            String newName = params.get("new_name");
            sendResponse(exchange, endpointHandler.modifyStructField(structName, fieldName, newType, newName));
        });

        server.createContext("/remove_struct_field", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String structName = params.get("struct_name");
            String fieldName = params.get("field_name");
            sendResponse(exchange, endpointHandler.removeStructField(structName, fieldName));
        });

        server.createContext("/delete_data_type", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String typeName = params.get("type_name");
            sendResponse(exchange, endpointHandler.deleteDataType(typeName));
        });

        server.createContext("/search_data_types", exchange -> {
            Map<String, String> params = parseQueryParams(exchange);
            String pattern = params.get("pattern");
            int offset = parseIntOrDefault(params.get("offset"), 0);
            int limit = parseIntOrDefault(params.get("limit"), 100);
            sendResponse(exchange, endpointHandler.searchDataTypes(pattern, offset, limit));
        });

        server.createContext("/validate_data_type_exists", exchange -> {
            Map<String, String> params = parseQueryParams(exchange);
            String typeName = params.get("type_name");
            sendResponse(exchange, endpointHandler.validateDataTypeExists(typeName));
        });

        server.createContext("/get_data_type_size", exchange -> {
            Map<String, String> params = parseQueryParams(exchange);
            String typeName = params.get("type_name");
            sendResponse(exchange, endpointHandler.getDataTypeSize(typeName));
        });

        server.createContext("/get_struct_layout", exchange -> {
            Map<String, String> params = parseQueryParams(exchange);
            String structName = params.get("struct_name");
            sendResponse(exchange, endpointHandler.getStructLayout(structName));
        });

        server.createContext("/get_enum_values", exchange -> {
            Map<String, String> params = parseQueryParams(exchange);
            String enumName = params.get("enum_name");
            sendResponse(exchange, endpointHandler.getEnumValues(enumName));
        });

        server.createContext("/clone_data_type", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String sourceType = params.get("source_type");
            String newName = params.get("new_name");
            sendResponse(exchange, endpointHandler.cloneDataType(sourceType, newName));
        });

        // ==========================================================================
        // PHASE 4: ADVANCED FEATURES ENDPOINTS
        // ==========================================================================

        server.createContext("/run_script", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String scriptPath = params.get("script_path");
            String args = params.get("args");
            sendResponse(exchange, endpointHandler.runScript(scriptPath, args));
        });

        server.createContext("/list_scripts", exchange -> {
            Map<String, String> params = parseQueryParams(exchange);
            String filter = params.get("filter");
            sendResponse(exchange, endpointHandler.listScripts(filter));
        });

        server.createContext("/search_byte_patterns", exchange -> {
            Map<String, String> params = parseQueryParams(exchange);
            String pattern = params.get("pattern");
            String mask = params.get("mask");
            sendResponse(exchange, endpointHandler.searchBytePatterns(pattern, mask));
        });

        server.createContext("/analyze_data_region", exchange -> {
            Map<String, String> params = parseQueryParams(exchange);
            String address = params.get("address");
            int maxScanBytes = parseIntOrDefault(params.get("max_scan_bytes"), 1024);
            boolean includeXrefMap = parseBooleanOrDefault(params.get("include_xref_map"), true);
            boolean includeAssemblyPatterns = parseBooleanOrDefault(params.get("include_assembly_patterns"), true);
            boolean includeBoundaryDetection = parseBooleanOrDefault(params.get("include_boundary_detection"), true);
            sendResponse(exchange, endpointHandler.analyzeDataRegion(address, maxScanBytes, includeXrefMap, includeAssemblyPatterns, includeBoundaryDetection));
        });

        server.createContext("/get_function_hash", exchange -> {
            Map<String, String> params = parseQueryParams(exchange);
            String address = params.get("address");
            String programName = params.get("program");
            sendResponse(exchange, endpointHandler.getFunctionHash(address, programName));
        });

        server.createContext("/get_bulk_function_hashes", exchange -> {
            Map<String, String> params = parseQueryParams(exchange);
            int offset = parseIntOrDefault(params.get("offset"), 0);
            int limit = parseIntOrDefault(params.get("limit"), 100);
            String filter = params.get("filter");
            String programName = params.get("program");
            sendResponse(exchange, endpointHandler.getBulkFunctionHashes(offset, limit, filter, programName));
        });

        server.createContext("/detect_array_bounds", exchange -> {
            Map<String, String> params = parseQueryParams(exchange);
            String address = params.get("address");
            boolean analyzeLoopBounds = parseBooleanOrDefault(params.get("analyze_loop_bounds"), true);
            boolean analyzeIndexing = parseBooleanOrDefault(params.get("analyze_indexing"), true);
            int maxScanRange = parseIntOrDefault(params.get("max_scan_range"), 2048);
            sendResponse(exchange, endpointHandler.detectArrayBounds(address, analyzeLoopBounds, analyzeIndexing, maxScanRange));
        });

        server.createContext("/get_assembly_context", exchange -> {
            Map<String, String> params = parseQueryParams(exchange);
            String xrefSources = params.get("xref_sources");
            int contextInstructions = parseIntOrDefault(params.get("context_instructions"), 5);
            String includePatterns = params.get("include_patterns");
            if (includePatterns == null) includePatterns = "LEA,MOV,CMP,IMUL,ADD,SUB";
            sendResponse(exchange, endpointHandler.getAssemblyContext(xrefSources, contextInstructions, includePatterns));
        });

        server.createContext("/analyze_struct_field_usage", exchange -> {
            Map<String, String> params = parseQueryParams(exchange);
            String address = params.get("address");
            String structName = params.get("struct_name");
            int maxFunctions = parseIntOrDefault(params.get("max_functions"), 10);
            sendResponse(exchange, endpointHandler.analyzeStructFieldUsage(address, structName, maxFunctions));
        });

        server.createContext("/get_field_access_context", exchange -> {
            Map<String, String> params = parseQueryParams(exchange);
            String structAddress = params.get("struct_address");
            int fieldOffset = parseIntOrDefault(params.get("field_offset"), 0);
            int numExamples = parseIntOrDefault(params.get("num_examples"), 5);
            sendResponse(exchange, endpointHandler.getFieldAccessContext(structAddress, fieldOffset, numExamples));
        });

        server.createContext("/rename_or_label", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String name = params.get("name");
            sendResponse(exchange, endpointHandler.renameOrLabel(address, name));
        });

        server.createContext("/can_rename_at_address", exchange -> {
            Map<String, String> params = parseQueryParams(exchange);
            String address = params.get("address");
            sendResponse(exchange, endpointHandler.canRenameAtAddress(address));
        });

        // FUZZY MATCHING & DIFF
        server.createContext("/get_function_signature", exchange -> {
            Map<String, String> params = parseQueryParams(exchange);
            String address = params.get("address");
            String programName = params.get("program");
            sendResponse(exchange, endpointHandler.getFunctionSignature(address, programName));
        });

        server.createContext("/find_similar_functions_fuzzy", exchange -> {
            Map<String, String> params = parseQueryParams(exchange);
            String address = params.get("address");
            String sourceProgramName = params.get("source_program");
            String targetProgramName = params.get("target_program");
            double threshold = parseDoubleOrDefault(params.get("threshold"), 0.7);
            int limit = parseIntOrDefault(params.get("limit"), 20);
            sendResponse(exchange, endpointHandler.findSimilarFunctionsFuzzy(
                address, sourceProgramName, targetProgramName, threshold, limit));
        });

        server.createContext("/bulk_fuzzy_match", exchange -> {
            Map<String, String> params = parseQueryParams(exchange);
            String sourceProgramName = params.get("source_program");
            String targetProgramName = params.get("target_program");
            double threshold = parseDoubleOrDefault(params.get("threshold"), 0.7);
            int offset = parseIntOrDefault(params.get("offset"), 0);
            int limit = parseIntOrDefault(params.get("limit"), 50);
            String filter = params.get("filter");
            sendResponse(exchange, endpointHandler.bulkFuzzyMatch(
                sourceProgramName, targetProgramName, threshold, offset, limit, filter));
        });

        server.createContext("/diff_functions", exchange -> {
            Map<String, String> params = parseQueryParams(exchange);
            String addressA = params.get("address_a");
            String addressB = params.get("address_b");
            String programA = params.get("program_a");
            String programB = params.get("program_b");
            sendResponse(exchange, endpointHandler.diffFunctions(addressA, addressB, programA, programB));
        });

        System.out.println("Registered " + countEndpoints() + " REST API endpoints");
    }

    private int countEndpoints() {
        // Count contexts registered - this is an approximation
        return 95; // 91 + 4 shared server endpoints
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
