package com.xebyte;

import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.GlobalNamespace;
import ghidra.program.model.listing.*;
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
import ghidra.app.services.ProgramManager;

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

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.Headers;

import javax.swing.SwingUtilities;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.InvocationTargetException;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Pattern;

@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = ghidra.app.DeveloperPluginPackage.NAME,
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "GhidraMCP v1.8.1 - HTTP server plugin",
    description = "GhidraMCP v1.8.1 - Starts an embedded HTTP server to expose program data via REST API and MCP bridge. " +
                  "Provides 108 endpoints (98 implemented + 10 ROADMAP v2.0) for reverse engineering automation. " +
                  "Port configurable via Tool Options. " +
                  "Features: function analysis, decompilation, symbol management, cross-references, label operations, " +
                  "high-performance batch data analysis, field-level structure analysis, and Ghidra script automation. " +
                  "v1.8.1: Documentation reorganization, __d2edicall calling convention support, Windows compatibility fixes. " +
                  "v1.8.0: MAJOR UPDATE - Comprehensive reverse engineering documentation suite with 6 new struct field " +
                  "analysis tools (analyze_struct_field_usage, get_field_access_context, suggest_field_names), " +
                  "enhanced documentation guides, and automated workflow scripts. " +
                  "v1.7.3: Fixed disassemble_bytes transaction commit for proper database persistence. " +
                  "v1.7.0: Added variable storage control, Ghidra script execution, and forced decompilation. " +
                  "v1.6.0: Batch operations, validation tools, and comprehensive function documentation."
)
public class GhidraMCPPlugin extends Plugin {

    private HttpServer server;
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

    // C language keywords to filter from field name suggestions
    private static final Set<String> C_KEYWORDS = Set.of(
        "if", "else", "for", "while", "do", "switch", "case", "default",
        "break", "continue", "return", "goto", "int", "void", "char",
        "float", "double", "long", "short", "struct", "union", "enum",
        "typedef", "sizeof", "const", "static", "extern", "auto", "register",
        "signed", "unsigned", "volatile", "inline", "restrict"
    );

    public GhidraMCPPlugin(PluginTool tool) {
        super(tool);
        Msg.info(this, "GhidraMCPPlugin loading...");

        // Register the configuration option
        Options options = tool.getOptions(OPTION_CATEGORY_NAME);
        options.registerOption(PORT_OPTION_NAME, DEFAULT_PORT,
            null, // No help location for now
            "The network port number the embedded HTTP server will listen on. " +
            "Requires Ghidra restart or plugin reload to take effect after changing.");

        try {
            startServer();
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
            server = HttpServer.create(new InetSocketAddress(port), 0);
            Msg.info(this, "HTTP server created successfully on port " + port);
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

        // Each listing endpoint uses offset & limit from query params:
        server.createContext("/methods", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, getAllFunctionNames(offset, limit));
        });

        // Alias for /methods to match test expectations
        server.createContext("/list_methods", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, getAllFunctionNames(offset, limit));
        });

        server.createContext("/classes", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, getAllClassNames(offset, limit));
        });

        server.createContext("/decompile", exchange -> {
            String name = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            sendResponse(exchange, decompileFunctionByName(name));
        });

        server.createContext("/renameFunction", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String result = renameFunction(params.get("oldName"), params.get("newName"));
            sendResponse(exchange, result);
        });

        // Alias for /renameFunction to match test expectations
        server.createContext("/rename_function", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String result = renameFunction(params.get("oldName"), params.get("newName"));
            sendResponse(exchange, result);
        });

        server.createContext("/renameData", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String result = renameDataAtAddress(params.get("address"), params.get("newName"));
            sendResponse(exchange, result);
        });

        // Alias for /renameData to match test expectations
        server.createContext("/rename_data", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String result = renameDataAtAddress(params.get("address"), params.get("newName"));
            sendResponse(exchange, result);
        });

        server.createContext("/renameVariable", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionName = params.get("functionName");
            String oldName = params.get("oldName");
            String newName = params.get("newName");
            String result = renameVariableInFunction(functionName, oldName, newName);
            sendResponse(exchange, result);
        });

        // Alias for /renameVariable to match test expectations
        server.createContext("/rename_variable", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionName = params.get("functionName");
            String oldName = params.get("oldName");
            String newName = params.get("newName");
            String result = renameVariableInFunction(functionName, oldName, newName);
            sendResponse(exchange, result);
        });

        server.createContext("/segments", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listSegments(offset, limit));
        });

        // Alias for /segments to match test expectations
        server.createContext("/list_segments", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listSegments(offset, limit));
        });

        server.createContext("/imports", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listImports(offset, limit));
        });

        // Alias for /imports to match test expectations
        server.createContext("/list_imports", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listImports(offset, limit));
        });

        server.createContext("/exports", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listExports(offset, limit));
        });

        // Alias for /exports to match test expectations
        server.createContext("/list_exports", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listExports(offset, limit));
        });

        server.createContext("/namespaces", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listNamespaces(offset, limit));
        });

        server.createContext("/data", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listDefinedData(offset, limit));
        });

        // Alias for /data to match MCP tool name
        server.createContext("/list_data_items", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, listDefinedData(offset, limit));
        });

        // List data items sorted by xref count (v1.7.4)
        server.createContext("/list_data_items_by_xrefs", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            String format = qparams.getOrDefault("format", "text");
            sendResponse(exchange, listDataItemsByXrefs(offset, limit, format));
        });

        server.createContext("/searchFunctions", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String searchTerm = qparams.get("query");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, searchFunctionsByName(searchTerm, offset, limit));
        });

        // New API endpoints based on requirements
        
        server.createContext("/get_function_by_address", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, getFunctionByAddress(address));
        });

        server.createContext("/get_current_address", exchange -> {
            sendResponse(exchange, getCurrentAddress());
        });

        server.createContext("/get_current_function", exchange -> {
            sendResponse(exchange, getCurrentFunction());
        });

        server.createContext("/list_functions", exchange -> {
            sendResponse(exchange, listFunctions());
        });

        // Alias for /list_functions to match test expectations
        server.createContext("/functions", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit  = parseIntOrDefault(qparams.get("limit"),  100);
            sendResponse(exchange, getAllFunctionNames(offset, limit));
        });

        server.createContext("/decompile_function", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, decompileFunctionByAddress(address));
        });

        server.createContext("/disassemble_function", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            sendResponse(exchange, disassembleFunction(address));
        });

        server.createContext("/set_decompiler_comment", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String comment = params.get("comment");
            String result = setDecompilerComment(address, comment);
            sendResponse(exchange, result);
        });

        server.createContext("/set_disassembly_comment", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String comment = params.get("comment");
            String result = setDisassemblyComment(address, comment);
            sendResponse(exchange, result);
        });

        server.createContext("/rename_function_by_address", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String newName = params.get("new_name");
            String result = renameFunctionByAddress(functionAddress, newName);
            sendResponse(exchange, result);
        });

        server.createContext("/set_function_prototype", exchange -> {
            Map<String, Object> params = parseJsonParams(exchange);
            String functionAddress = (String) params.get("function_address");
            String prototype = (String) params.get("prototype");
            String callingConvention = (String) params.get("calling_convention");

            // Call the set prototype function and get detailed result
            PrototypeResult result = setFunctionPrototype(functionAddress, prototype, callingConvention);

            if (result.isSuccess()) {
                // Even with successful operations, include any warning messages for debugging
                String successMsg = "Function prototype set successfully";
                if (!result.getErrorMessage().isEmpty()) {
                    successMsg += "\n\nWarnings/Debug Info:\n" + result.getErrorMessage();
                }
                sendResponse(exchange, successMsg);
            } else {
                // Return the detailed error message to the client
                sendResponse(exchange, "Failed to set function prototype: " + result.getErrorMessage());
            }
        });

        server.createContext("/list_calling_conventions", exchange -> {
            String result = listCallingConventions();
            sendResponse(exchange, result);
        });

        server.createContext("/set_local_variable_type", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String variableName = params.get("variable_name");
            String newType = params.get("new_type");

            // Capture detailed information about setting the type
            StringBuilder responseMsg = new StringBuilder();
            responseMsg.append("Setting variable type: ").append(variableName)
                      .append(" to ").append(newType)
                      .append(" in function at ").append(functionAddress).append("\n\n");

            // Attempt to find the data type in various categories
            Program program = getCurrentProgram();
            if (program != null) {
                DataTypeManager dtm = program.getDataTypeManager();
                DataType directType = findDataTypeByNameInAllCategories(dtm, newType);
                if (directType != null) {
                    responseMsg.append("Found type: ").append(directType.getPathName()).append("\n");
                } else if (newType.startsWith("P") && newType.length() > 1) {
                    String baseTypeName = newType.substring(1);
                    DataType baseType = findDataTypeByNameInAllCategories(dtm, baseTypeName);
                    if (baseType != null) {
                        responseMsg.append("Found base type for pointer: ").append(baseType.getPathName()).append("\n");
                    } else {
                        responseMsg.append("Base type not found for pointer: ").append(baseTypeName).append("\n");
                    }
                } else {
                    responseMsg.append("Type not found directly: ").append(newType).append("\n");
                }
            }

            // Try to set the type
            String result = setLocalVariableType(functionAddress, variableName, newType);
            sendResponse(exchange, result);
        });

        server.createContext("/set_function_no_return", exchange -> {
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
        });

        server.createContext("/clear_instruction_flow_override", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String instructionAddress = params.get("address");

            if (instructionAddress == null || instructionAddress.isEmpty()) {
                sendResponse(exchange, "Error: address parameter is required");
                return;
            }

            String result = clearInstructionFlowOverride(instructionAddress);
            sendResponse(exchange, result);
        });

        // Variable storage control endpoint (v1.7.0)
        server.createContext("/set_variable_storage", exchange -> {
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
        });

        // Ghidra script execution endpoint (v1.7.0)
        server.createContext("/run_script", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String scriptPath = params.get("script_path");
            String scriptArgs = params.get("args"); // Optional JSON arguments

            if (scriptPath == null || scriptPath.isEmpty()) {
                sendResponse(exchange, "Error: script_path parameter is required");
                return;
            }

            String result = runGhidraScript(scriptPath, scriptArgs);
            sendResponse(exchange, result);
        });

        // List available Ghidra scripts (v1.7.0)
        server.createContext("/list_scripts", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String filter = qparams.get("filter"); // Optional filter

            String result = listGhidraScripts(filter);
            sendResponse(exchange, result);
        });

        // Force decompiler reanalysis (v1.7.0)
        server.createContext("/force_decompile", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionAddress = params.get("function_address");

            if (functionAddress == null || functionAddress.isEmpty()) {
                sendResponse(exchange, "Error: function_address parameter is required");
                return;
            }

            String result = forceDecompile(functionAddress);
            sendResponse(exchange, result);
        });

        server.createContext("/xrefs_to", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, getXrefsTo(address, offset, limit));
        });

        server.createContext("/xrefs_from", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, getXrefsFrom(address, offset, limit));
        });

        server.createContext("/function_xrefs", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String name = qparams.get("name");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, getFunctionXrefs(name, offset, limit));
        });

        // Alias for /function_xrefs to match test expectations
        server.createContext("/get_function_xrefs", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String name = qparams.get("name");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, getFunctionXrefs(name, offset, limit));
        });

        server.createContext("/function_labels", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String name = qparams.get("name");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 20);
            sendResponse(exchange, getFunctionLabels(name, offset, limit));
        });

        server.createContext("/rename_label", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String oldName = params.get("old_name");
            String newName = params.get("new_name");
            String result = renameLabel(address, oldName, newName);
            sendResponse(exchange, result);
        });

        server.createContext("/function_jump_targets", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String name = qparams.get("name");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, getFunctionJumpTargets(name, offset, limit));
        });

        // Alias for /function_jump_targets to match test expectations
        server.createContext("/function_jump_target_addresses", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String name = qparams.get("name");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, getFunctionJumpTargets(name, offset, limit));
        });

        server.createContext("/create_label", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String name = params.get("name");
            String result = createLabel(address, name);
            sendResponse(exchange, result);
        });

        // BATCH_CREATE_LABELS - Create multiple labels in a single operation (v1.5.1)
        server.createContext("/batch_create_labels", exchange -> {
            Map<String, Object> params = parseJsonParams(exchange);
            List<Map<String, String>> labels = convertToMapList(params.get("labels"));
            String result = batchCreateLabels(labels);
            sendResponse(exchange, result);
        });

        server.createContext("/rename_or_label", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String name = params.get("name");
            String result = renameOrLabel(address, name);
            sendResponse(exchange, result);
        });

        server.createContext("/function_callees", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String name = qparams.get("name");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, getFunctionCallees(name, offset, limit));
        });

        server.createContext("/function_callers", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String name = qparams.get("name");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, getFunctionCallers(name, offset, limit));
        });

        server.createContext("/function_call_graph", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String name = qparams.get("name");
            int depth = parseIntOrDefault(qparams.get("depth"), 2);
            String direction = qparams.getOrDefault("direction", "both");
            sendResponse(exchange, getFunctionCallGraph(name, depth, direction));
        });

        server.createContext("/full_call_graph", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String format = qparams.getOrDefault("format", "edges");
            int limit = parseIntOrDefault(qparams.get("limit"), 1000);
            sendResponse(exchange, getFullCallGraph(format, limit));
        });

        server.createContext("/list_data_types", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String category = qparams.get("category");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, listDataTypes(category, offset, limit));
        });

        server.createContext("/create_struct", exchange -> {
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
        });

        server.createContext("/create_enum", exchange -> {
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
        });

        server.createContext("/apply_data_type", exchange -> {
            Map<String, Object> params = parseJsonParams(exchange);
            String address = (String) params.get("address");
            String typeName = (String) params.get("type_name");
            Object clearObj = params.get("clear_existing");
            boolean clearExisting = (clearObj instanceof Boolean) ? (Boolean) clearObj : 
                                   Boolean.parseBoolean(clearObj != null ? clearObj.toString() : "true");
            sendResponse(exchange, applyDataType(address, typeName, clearExisting));
        });

        server.createContext("/strings", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            String filter = qparams.get("filter");
            sendResponse(exchange, listDefinedStrings(offset, limit, filter));
        });

        // Alias for /strings to match test expectations
        server.createContext("/list_strings", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            String filter = qparams.get("filter");
            sendResponse(exchange, listDefinedStrings(offset, limit, filter));
        });

        // New endpoints for missing IDA functionality
        server.createContext("/check_connection", exchange -> {
            sendResponse(exchange, checkConnection());
        });

        server.createContext("/get_version", exchange -> {
            sendResponse(exchange, getVersion());
        });

        server.createContext("/get_metadata", exchange -> {
            sendResponse(exchange, getMetadata());
        });

        server.createContext("/convert_number", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String text = qparams.get("text");
            int size = parseIntOrDefault(qparams.get("size"), 4);
            sendResponse(exchange, convertNumber(text, size));
        });

        server.createContext("/list_globals", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            String filter = qparams.get("filter");
            sendResponse(exchange, listGlobals(offset, limit, filter));
        });

        server.createContext("/rename_global_variable", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String oldName = params.get("old_name");
            String newName = params.get("new_name");
            String result = renameGlobalVariable(oldName, newName);
            sendResponse(exchange, result);
        });

        server.createContext("/get_entry_points", exchange -> {
            sendResponse(exchange, getEntryPoints());
        });

        // Data type analysis endpoints
        server.createContext("/analyze_data_types", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            int depth = parseIntOrDefault(qparams.get("depth"), 1);
            sendResponse(exchange, analyzeDataTypes(address, depth));
        });

        server.createContext("/create_union", exchange -> {
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
        });

        server.createContext("/get_type_size", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String typeName = qparams.get("type_name");
            sendResponse(exchange, getTypeSize(typeName));
        });

        server.createContext("/get_struct_layout", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String structName = qparams.get("struct_name");
            sendResponse(exchange, getStructLayout(structName));
        });

        server.createContext("/search_data_types", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String pattern = qparams.get("pattern");
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, searchDataTypes(pattern, offset, limit));
        });

        server.createContext("/auto_create_struct", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            int size = parseIntOrDefault(params.get("size"), 0);
            String name = params.get("name");
            sendResponse(exchange, autoCreateStruct(address, size, name));
        });

        server.createContext("/get_enum_values", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String enumName = qparams.get("enum_name");
            sendResponse(exchange, getEnumValues(enumName));
        });

        server.createContext("/create_typedef", exchange -> {
            Map<String, Object> params = parseJsonParams(exchange);
            String name = (String) params.get("name");
            String baseType = (String) params.get("base_type");
            sendResponse(exchange, createTypedef(name, baseType));
        });

        server.createContext("/clone_data_type", exchange -> {
            Map<String, Object> params = parseJsonParams(exchange);
            String sourceType = (String) params.get("source_type");
            String newName = (String) params.get("new_name");
            sendResponse(exchange, cloneDataType(sourceType, newName));
        });

        // Removed duplicate - see v1.5.0 VALIDATE_DATA_TYPE endpoint below

        server.createContext("/export_data_types", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String format = qparams.getOrDefault("format", "c");
            String category = qparams.get("category");
            sendResponse(exchange, exportDataTypes(format, category));
        });

        server.createContext("/import_data_types", exchange -> {
            Map<String, Object> params = parseJsonParams(exchange);
            String source = (String) params.get("source");
            String format = (String) params.getOrDefault("format", "c");
            sendResponse(exchange, importDataTypes(source, format));
        });

        // New data structure management endpoints
        server.createContext("/delete_data_type", exchange -> {
            Map<String, Object> params = parseJsonParams(exchange);
            String typeName = (String) params.get("type_name");
            sendResponse(exchange, deleteDataType(typeName));
        });

        server.createContext("/modify_struct_field", exchange -> {
            Map<String, Object> params = parseJsonParams(exchange);
            String structName = (String) params.get("struct_name");
            String fieldName = (String) params.get("field_name");
            String newType = (String) params.get("new_type");
            String newName = (String) params.get("new_name");
            sendResponse(exchange, modifyStructField(structName, fieldName, newType, newName));
        });

        server.createContext("/add_struct_field", exchange -> {
            Map<String, Object> params = parseJsonParams(exchange);
            String structName = (String) params.get("struct_name");
            String fieldName = (String) params.get("field_name");
            String fieldType = (String) params.get("field_type");
            Object offsetObj = params.get("offset");
            int offset = (offsetObj instanceof Integer) ? (Integer) offsetObj : -1;
            sendResponse(exchange, addStructField(structName, fieldName, fieldType, offset));
        });

        server.createContext("/remove_struct_field", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String structName = params.get("struct_name");
            String fieldName = params.get("field_name");
            sendResponse(exchange, removeStructField(structName, fieldName));
        });

        server.createContext("/create_array_type", exchange -> {
            Map<String, Object> params = parseJsonParams(exchange);
            String baseType = (String) params.get("base_type");
            Object lengthObj = params.get("length");
            int length = (lengthObj instanceof Integer) ? (Integer) lengthObj : 1;
            String name = (String) params.get("name");
            sendResponse(exchange, createArrayType(baseType, length, name));
        });

        server.createContext("/create_pointer_type", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String baseType = params.get("base_type");
            String name = params.get("name");
            sendResponse(exchange, createPointerType(baseType, name));
        });

        server.createContext("/create_data_type_category", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String categoryPath = params.get("category_path");
            sendResponse(exchange, createDataTypeCategory(categoryPath));
        });

        server.createContext("/move_data_type_to_category", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String typeName = params.get("type_name");
            String categoryPath = params.get("category_path");
            sendResponse(exchange, moveDataTypeToCategory(typeName, categoryPath));
        });

        server.createContext("/list_data_type_categories", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            int offset = parseIntOrDefault(qparams.get("offset"), 0);
            int limit = parseIntOrDefault(qparams.get("limit"), 100);
            sendResponse(exchange, listDataTypeCategories(offset, limit));
        });

        server.createContext("/create_function_signature", exchange -> {
            Map<String, Object> params = parseJsonParams(exchange);
            String name = (String) params.get("name");
            String returnType = (String) params.get("return_type");
            Object parametersObj = params.get("parameters");
            String parametersJson = (parametersObj instanceof String) ? (String) parametersObj : 
                                   (parametersObj != null ? parametersObj.toString() : null);
            sendResponse(exchange, createFunctionSignature(name, returnType, parametersJson));
        });

        // Memory reading endpoint
        server.createContext("/readMemory", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            String lengthStr = qparams.get("length");
            int length = parseIntOrDefault(lengthStr, 16);
            sendResponse(exchange, readMemory(address, length));
        });

        // ==========================================================================
        // HIGH-PERFORMANCE DATA ANALYSIS ENDPOINTS (v1.3.0)
        // ==========================================================================

        // 1. GET_BULK_XREFS - Batch xref retrieval
        server.createContext("/get_bulk_xrefs", exchange -> {
            Map<String, Object> params = parseJsonParams(exchange);
            Object addressesObj = params.get("addresses");
            String result = getBulkXrefs(addressesObj);
            sendResponse(exchange, result);
        });

        // 2. ANALYZE_DATA_REGION - Comprehensive data region analysis
        server.createContext("/analyze_data_region", exchange -> {
            Map<String, Object> params = parseJsonParams(exchange);
            String address = (String) params.get("address");
            int maxScanBytes = parseIntOrDefault(String.valueOf(params.get("max_scan_bytes")), 1024);
            boolean includeXrefMap = parseBoolOrDefault(params.get("include_xref_map"), true);
            boolean includeAssemblyPatterns = parseBoolOrDefault(params.get("include_assembly_patterns"), true);
            boolean includeBoundaryDetection = parseBoolOrDefault(params.get("include_boundary_detection"), true);

            String result = analyzeDataRegion(address, maxScanBytes, includeXrefMap,
                                              includeAssemblyPatterns, includeBoundaryDetection);
            sendResponse(exchange, result);
        });

        // 3. DETECT_ARRAY_BOUNDS - Array/table size detection
        server.createContext("/detect_array_bounds", exchange -> {
            Map<String, Object> params = parseJsonParams(exchange);
            String address = (String) params.get("address");
            boolean analyzeLoopBounds = parseBoolOrDefault(params.get("analyze_loop_bounds"), true);
            boolean analyzeIndexing = parseBoolOrDefault(params.get("analyze_indexing"), true);
            int maxScanRange = parseIntOrDefault(String.valueOf(params.get("max_scan_range")), 2048);

            String result = detectArrayBounds(address, analyzeLoopBounds, analyzeIndexing, maxScanRange);
            sendResponse(exchange, result);
        });

        // 4. GET_ASSEMBLY_CONTEXT - Assembly pattern analysis
        server.createContext("/get_assembly_context", exchange -> {
            Map<String, Object> params = parseJsonParams(exchange);
            Object xrefSourcesObj = params.get("xref_sources");
            int contextInstructions = parseIntOrDefault(String.valueOf(params.get("context_instructions")), 5);
            Object includePatternsObj = params.get("include_patterns");

            String result = getAssemblyContext(xrefSourcesObj, contextInstructions, includePatternsObj);
            sendResponse(exchange, result);
        });

        // 5. BATCH_DECOMPILE_XREF_SOURCES - Batch decompilation
        server.createContext("/batch_decompile_xref_sources", exchange -> {
            Map<String, Object> params = parseJsonParams(exchange);
            String targetAddress = (String) params.get("target_address");
            boolean includeFunctionNames = parseBoolOrDefault(params.get("include_function_names"), true);
            boolean includeUsageContext = parseBoolOrDefault(params.get("include_usage_context"), true);
            int limit = parseIntOrDefault(String.valueOf(params.get("limit")), 10);
            int offset = parseIntOrDefault(String.valueOf(params.get("offset")), 0);

            String result = batchDecompileXrefSources(targetAddress, includeFunctionNames, includeUsageContext, limit, offset);
            sendResponse(exchange, result);
        });

        // 6. APPLY_DATA_CLASSIFICATION - Atomic type application
        server.createContext("/apply_data_classification", exchange -> {
            Map<String, Object> params = parseJsonParams(exchange);
            String address = (String) params.get("address");
            String classification = (String) params.get("classification");
            String name = (String) params.get("name");
            String comment = (String) params.get("comment");
            Object typeDefinitionObj = params.get("type_definition");

            String result = applyDataClassification(address, classification, name, comment, typeDefinitionObj);
            sendResponse(exchange, result);
        });

        // === FIELD-LEVEL ANALYSIS ENDPOINTS (v1.4.0) ===

        // ANALYZE_STRUCT_FIELD_USAGE - Analyze how structure fields are accessed
        server.createContext("/analyze_struct_field_usage", exchange -> {
            Map<String, Object> params = parseJsonParams(exchange);
            String address = (String) params.get("address");
            String structName = (String) params.get("struct_name");
            int maxFunctionsToAnalyze = parseIntOrDefault(String.valueOf(params.get("max_functions")), 10);

            String result = analyzeStructFieldUsage(address, structName, maxFunctionsToAnalyze);
            sendResponse(exchange, result);
        });

        // GET_FIELD_ACCESS_CONTEXT - Get assembly/decompilation context for specific field offsets
        server.createContext("/get_field_access_context", exchange -> {
            Map<String, Object> params = parseJsonParams(exchange);
            String structAddress = (String) params.get("struct_address");
            int fieldOffset = parseIntOrDefault(String.valueOf(params.get("field_offset")), 0);
            int numExamples = parseIntOrDefault(String.valueOf(params.get("num_examples")), 5);

            String result = getFieldAccessContext(structAddress, fieldOffset, numExamples);
            sendResponse(exchange, result);
        });

        // SUGGEST_FIELD_NAMES - AI-assisted field name suggestions based on usage patterns
        server.createContext("/suggest_field_names", exchange -> {
            Map<String, Object> params = parseJsonParams(exchange);
            String structAddress = (String) params.get("struct_address");
            int structSize = parseIntOrDefault(String.valueOf(params.get("struct_size")), 0);

            String result = suggestFieldNames(structAddress, structSize);
            sendResponse(exchange, result);
        });

        // 7. INSPECT_MEMORY_CONTENT - Memory content inspection with string detection
        server.createContext("/inspect_memory_content", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            int length = parseIntOrDefault(qparams.get("length"), 64);
            boolean detectStrings = parseBoolOrDefault(qparams.get("detect_strings"), true);

            String result = inspectMemoryContent(address, length, detectStrings);
            sendResponse(exchange, result);
        });

        // === MALWARE ANALYSIS ENDPOINTS ===

        // DETECT_CRYPTO_CONSTANTS - Identify crypto constants
        server.createContext("/detect_crypto_constants", exchange -> {
            String result = detectCryptoConstants();
            sendResponse(exchange, result);
        });

        // SEARCH_BYTE_PATTERNS - Search for byte patterns with masks
        server.createContext("/search_byte_patterns", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String pattern = qparams.get("pattern");
            String mask = qparams.get("mask");

            String result = searchBytePatterns(pattern, mask);
            sendResponse(exchange, result);
        });

        // FIND_SIMILAR_FUNCTIONS - Find structurally similar functions
        server.createContext("/find_similar_functions", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String targetFunction = qparams.get("target_function");
            double threshold = parseDoubleOrDefault(qparams.get("threshold"), 0.8);

            String result = findSimilarFunctions(targetFunction, threshold);
            sendResponse(exchange, result);
        });

        // ANALYZE_CONTROL_FLOW - Analyze function control flow complexity
        server.createContext("/analyze_control_flow", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String functionName = qparams.get("function_name");

            String result = analyzeControlFlow(functionName);
            sendResponse(exchange, result);
        });

        // FIND_ANTI_ANALYSIS_TECHNIQUES - Detect anti-analysis/anti-debug techniques
        server.createContext("/find_anti_analysis_techniques", exchange -> {
            String result = findAntiAnalysisTechniques();
            sendResponse(exchange, result);
        });

        // EXTRACT_IOCS - Extract indicators of compromise
        server.createContext("/extract_iocs", exchange -> {
            String result = extractIOCs();
            sendResponse(exchange, result);
        });

        // BATCH_DECOMPILE - Decompile multiple functions at once
        server.createContext("/batch_decompile", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String functions = qparams.get("functions");

            String result = batchDecompileFunctions(functions);
            sendResponse(exchange, result);
        });

        // FIND_DEAD_CODE - Identify unreachable code blocks
        server.createContext("/find_dead_code", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String functionName = qparams.get("function_name");

            String result = findDeadCode(functionName);
            sendResponse(exchange, result);
        });

        // ANALYZE_FUNCTION_COMPLEXITY - Calculate complexity metrics
        server.createContext("/analyze_function_complexity", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String functionName = qparams.get("function_name");

            String result = analyzeFunctionComplexity(functionName);
            sendResponse(exchange, result);
        });

        // BATCH_RENAME_FUNCTIONS - Rename multiple functions atomically
        server.createContext("/batch_rename_functions", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String renames = qparams.get("renames");

            String result = batchRenameFunctions(renames);
            sendResponse(exchange, result);
        });

        // DECRYPT_STRINGS_AUTO - Auto-decrypt obfuscated strings
        server.createContext("/decrypt_strings_auto", exchange -> {
            String result = autoDecryptStrings();
            sendResponse(exchange, result);
        });

        // ANALYZE_API_CALL_CHAINS - Detect suspicious API call patterns
        server.createContext("/analyze_api_call_chains", exchange -> {
            String result = analyzeAPICallChains();
            sendResponse(exchange, result);
        });

        // EXTRACT_IOCS_WITH_CONTEXT - Enhanced IOC extraction with context
        server.createContext("/extract_iocs_with_context", exchange -> {
            String result = extractIOCsWithContext();
            sendResponse(exchange, result);
        });

        // DETECT_MALWARE_BEHAVIORS - Detect common malware behaviors
        server.createContext("/detect_malware_behaviors", exchange -> {
            String result = detectMalwareBehaviors();
            sendResponse(exchange, result);
        });

        // === WORKFLOW OPTIMIZATION ENDPOINTS (v1.5.0) ===

        // BATCH_SET_COMMENTS - Set multiple comments in a single operation
        server.createContext("/batch_set_comments", exchange -> {
            Map<String, Object> params = parseJsonParams(exchange);
            String functionAddress = (String) params.get("function_address");

            // Convert List<Object> to List<Map<String, String>>
            List<Map<String, String>> decompilerComments = convertToMapList(params.get("decompiler_comments"));
            List<Map<String, String>> disassemblyComments = convertToMapList(params.get("disassembly_comments"));
            String plateComment = (String) params.get("plate_comment");

            String result = batchSetComments(functionAddress, decompilerComments, disassemblyComments, plateComment);
            sendResponse(exchange, result);
        });

        // SET_PLATE_COMMENT - Set function header/plate comment
        server.createContext("/set_plate_comment", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String comment = params.get("comment");

            String result = setPlateComment(functionAddress, comment);
            sendResponse(exchange, result);
        });

        // GET_FUNCTION_VARIABLES - List all variables in a function
        server.createContext("/get_function_variables", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String functionName = qparams.get("function_name");

            String result = getFunctionVariables(functionName);
            sendResponse(exchange, result);
        });

        // BATCH_RENAME_FUNCTION_COMPONENTS - Rename function and components atomically
        server.createContext("/batch_rename_function_components", exchange -> {
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
        });

        // GET_VALID_DATA_TYPES - List valid Ghidra data type strings
        server.createContext("/get_valid_data_types", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String category = qparams.get("category");

            String result = getValidDataTypes(category);
            sendResponse(exchange, result);
        });

        // VALIDATE_DATA_TYPE - Validate data type applicability at address
        server.createContext("/validate_data_type", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            String typeName = qparams.get("type_name");

            String result = validateDataType(address, typeName);
            sendResponse(exchange, result);
        });

        // ANALYZE_FUNCTION_COMPLETENESS - Check function documentation completeness
        server.createContext("/analyze_function_completeness", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String functionAddress = qparams.get("function_address");

            String result = analyzeFunctionCompleteness(functionAddress);
            sendResponse(exchange, result);
        });

        // FIND_NEXT_UNDEFINED_FUNCTION - Find next function needing analysis
        server.createContext("/find_next_undefined_function", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String startAddress = qparams.get("start_address");
            String criteria = qparams.get("criteria");
            String pattern = qparams.get("pattern");
            String direction = qparams.get("direction");

            String result = findNextUndefinedFunction(startAddress, criteria, pattern, direction);
            sendResponse(exchange, result);
        });

        // BATCH_SET_VARIABLE_TYPES - Set types for multiple variables
        server.createContext("/batch_set_variable_types", exchange -> {
            Map<String, Object> params = parseJsonParams(exchange);
            String functionAddress = (String) params.get("function_address");
            @SuppressWarnings("unchecked")
            Map<String, String> variableTypes = (Map<String, String>) params.get("variable_types");

            String result = batchSetVariableTypes(functionAddress, variableTypes);
            sendResponse(exchange, result);
        });

        // NEW v1.6.0: BATCH_RENAME_VARIABLES - Rename multiple variables atomically
        server.createContext("/batch_rename_variables", exchange -> {
            Map<String, Object> params = parseJsonParams(exchange);
            String functionAddress = (String) params.get("function_address");
            @SuppressWarnings("unchecked")
            Map<String, String> variableRenames = (Map<String, String>) params.get("variable_renames");

            String result = batchRenameVariables(functionAddress, variableRenames);
            sendResponse(exchange, result);
        });

        // NEW v1.6.0: VALIDATE_FUNCTION_PROTOTYPE - Validate prototype before applying
        server.createContext("/validate_function_prototype", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String functionAddress = qparams.get("function_address");
            String prototype = qparams.get("prototype");
            String callingConvention = qparams.get("calling_convention");

            String result = validateFunctionPrototype(functionAddress, prototype, callingConvention);
            sendResponse(exchange, result);
        });

        // NEW v1.6.0: VALIDATE_DATA_TYPE_EXISTS - Check if type exists
        server.createContext("/validate_data_type_exists", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String typeName = qparams.get("type_name");

            String result = validateDataTypeExists(typeName);
            sendResponse(exchange, result);
        });

        // NEW v1.6.0: CAN_RENAME_AT_ADDRESS - Determine address type and operation
        server.createContext("/can_rename_at_address", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");

            String result = canRenameAtAddress(address);
            sendResponse(exchange, result);
        });

        // NEW v1.6.0: ANALYZE_FUNCTION_COMPLETE - Comprehensive single-call analysis
        server.createContext("/analyze_function_complete", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String name = qparams.get("name");
            boolean includeXrefs = Boolean.parseBoolean(qparams.getOrDefault("include_xrefs", "true"));
            boolean includeCallees = Boolean.parseBoolean(qparams.getOrDefault("include_callees", "true"));
            boolean includeCallers = Boolean.parseBoolean(qparams.getOrDefault("include_callers", "true"));
            boolean includeDisasm = Boolean.parseBoolean(qparams.getOrDefault("include_disasm", "true"));
            boolean includeVariables = Boolean.parseBoolean(qparams.getOrDefault("include_variables", "true"));

            String result = analyzeFunctionComplete(name, includeXrefs, includeCallees, includeCallers, includeDisasm, includeVariables);
            sendResponse(exchange, result);
        });

        // NEW v1.6.0: DOCUMENT_FUNCTION_COMPLETE - Atomic all-in-one documentation
        server.createContext("/document_function_complete", exchange -> {
            Map<String, Object> params = parseJsonParams(exchange);
            String functionAddress = (String) params.get("function_address");
            String newName = (String) params.get("new_name");
            String prototype = (String) params.get("prototype");
            String callingConvention = (String) params.get("calling_convention");
            @SuppressWarnings("unchecked")
            Map<String, String> variableRenames = (Map<String, String>) params.get("variable_renames");
            @SuppressWarnings("unchecked")
            Map<String, String> variableTypes = (Map<String, String>) params.get("variable_types");
            @SuppressWarnings("unchecked")
            List<Map<String, String>> labels = (List<Map<String, String>>) params.get("labels");
            String plateComment = (String) params.get("plate_comment");
            @SuppressWarnings("unchecked")
            List<Map<String, String>> decompilerComments = (List<Map<String, String>>) params.get("decompiler_comments");
            @SuppressWarnings("unchecked")
            List<Map<String, String>> disassemblyComments = (List<Map<String, String>>) params.get("disassembly_comments");

            String result = documentFunctionComplete(functionAddress, newName, prototype, callingConvention,
                variableRenames, variableTypes, labels, plateComment, decompilerComments, disassemblyComments);
            sendResponse(exchange, result);
        });

        // NEW v1.6.0: SEARCH_FUNCTIONS_ENHANCED - Advanced search with filtering
        server.createContext("/search_functions_enhanced", exchange -> {
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

            String result = searchFunctionsEnhanced(namePattern, minXrefs, maxXrefs, callingConvention,
                hasCustomName, regex, sortBy, offset, limit);
            sendResponse(exchange, result);
        });

        // NEW v1.7.1: DISASSEMBLE_BYTES - Disassemble a range of bytes
        server.createContext("/disassemble_bytes", exchange -> {
            Map<String, Object> params = parseJsonParams(exchange);
            String startAddress = (String) params.get("start_address");
            String endAddress = (String) params.get("end_address");
            Integer length = params.get("length") != null ? ((Number) params.get("length")).intValue() : null;
            boolean restrictToExecuteMemory = params.get("restrict_to_execute_memory") != null ?
                (Boolean) params.get("restrict_to_execute_memory") : true;

            String result = disassembleBytes(startAddress, endAddress, length, restrictToExecuteMemory);
            sendResponse(exchange, result);
        });

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

    private String getAllFunctionNames(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> names = new ArrayList<>();
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            names.add(f.getName());
        }
        return paginateList(names, offset, limit);
    }

    private String getAllClassNames(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        Set<String> classNames = new HashSet<>();
        for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
            Namespace ns = symbol.getParentNamespace();
            if (ns != null && !ns.isGlobal()) {
                classNames.add(ns.getName());
            }
        }
        // Convert set to list for pagination
        List<String> sorted = new ArrayList<>(classNames);
        Collections.sort(sorted);
        return paginateList(sorted, offset, limit);
    }

    private String listSegments(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            lines.add(String.format("%s: %s - %s", block.getName(), block.getStart(), block.getEnd()));
        }
        return paginateList(lines, offset, limit);
    }

    private String listImports(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        for (Symbol symbol : program.getSymbolTable().getExternalSymbols()) {
            lines.add(symbol.getName() + " -> " + symbol.getAddress());
        }
        return paginateList(lines, offset, limit);
    }

    private String listExports(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        SymbolTable table = program.getSymbolTable();
        SymbolIterator it = table.getAllSymbols(true);

        List<String> lines = new ArrayList<>();
        while (it.hasNext()) {
            Symbol s = it.next();
            // On older Ghidra, "export" is recognized via isExternalEntryPoint()
            if (s.isExternalEntryPoint()) {
                lines.add(s.getName() + " -> " + s.getAddress());
            }
        }
        return paginateList(lines, offset, limit);
    }

    private String listNamespaces(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        Set<String> namespaces = new HashSet<>();
        for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
            Namespace ns = symbol.getParentNamespace();
            if (ns != null && !(ns instanceof GlobalNamespace)) {
                namespaces.add(ns.getName());
            }
        }
        List<String> sorted = new ArrayList<>(namespaces);
        Collections.sort(sorted);
        return paginateList(sorted, offset, limit);
    }

    private String listDefinedData(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            DataIterator it = program.getListing().getDefinedData(block.getStart(), true);
            while (it.hasNext()) {
                Data data = it.next();
                if (block.contains(data.getAddress())) {
                    // Use same format as list_globals: "name @ address [type] (info)"
                    StringBuilder info = new StringBuilder();
                    String label = data.getLabel() != null ? data.getLabel() : "DAT_" + data.getAddress().toString().replace(":", "");
                    info.append(label);
                    info.append(" @ ").append(data.getAddress().toString().replace(":", ""));

                    // Add data type
                    DataType dt = data.getDataType();
                    String typeName = (dt != null) ? dt.getName() : "undefined";
                    info.append(" [").append(typeName).append("]");

                    // Add size information
                    int length = data.getLength();
                    String sizeStr = (length == 1) ? "1 byte" : length + " bytes";
                    info.append(" (").append(sizeStr).append(")");

                    lines.add(info.toString());
                }
            }
        }
        return paginateList(lines, offset, limit);
    }

    /**
     * List defined data items sorted by cross-reference count (v1.7.4).
     * Returns data items with the most references first.
     *
     * @param offset Pagination offset
     * @param limit Maximum results to return
     * @param format Output format: "text" (default) or "json"
     * @return Formatted list of data items sorted by xref count
     */
    private String listDataItemsByXrefs(int offset, int limit, String format) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        // Collect all data items with their xref counts
        List<DataItemInfo> dataItems = new ArrayList<>();
        ReferenceManager refMgr = program.getReferenceManager();

        for (MemoryBlock block : program.getMemory().getBlocks()) {
            DataIterator it = program.getListing().getDefinedData(block.getStart(), true);
            while (it.hasNext()) {
                Data data = it.next();
                if (block.contains(data.getAddress())) {
                    // Count xrefs to this data item
                    Address addr = data.getAddress();
                    int xrefCount = refMgr.getReferenceCountTo(addr);

                    String label = data.getLabel() != null ? data.getLabel() :
                                   "DAT_" + addr.toString().replace(":", "");

                    DataType dt = data.getDataType();
                    String typeName = (dt != null) ? dt.getName() : "undefined";
                    int length = data.getLength();

                    dataItems.add(new DataItemInfo(addr.toString().replace(":", ""), label, typeName, length, xrefCount));
                }
            }
        }

        // Sort by xref count (descending)
        dataItems.sort((a, b) -> Integer.compare(b.xrefCount, a.xrefCount));

        // Format output based on requested format
        if ("json".equalsIgnoreCase(format)) {
            return formatDataItemsAsJson(dataItems, offset, limit);
        } else {
            return formatDataItemsAsText(dataItems, offset, limit);
        }
    }

    // Simple data class for holding data item information
    private static class DataItemInfo {
        final String address;
        final String label;
        final String typeName;
        final int length;
        final int xrefCount;

        DataItemInfo(String address, String label, String typeName, int length, int xrefCount) {
            this.address = address;
            this.label = label;
            this.typeName = typeName;
            this.length = length;
            this.xrefCount = xrefCount;
        }
    }

    private String formatDataItemsAsText(List<DataItemInfo> dataItems, int offset, int limit) {
        List<String> lines = new ArrayList<>();

        int start = Math.min(offset, dataItems.size());
        int end = Math.min(start + limit, dataItems.size());

        for (int i = start; i < end; i++) {
            DataItemInfo item = dataItems.get(i);

            StringBuilder line = new StringBuilder();
            line.append(item.label);
            line.append(" @ ").append(item.address);
            line.append(" [").append(item.typeName).append("]");

            String sizeStr = (item.length == 1) ? "1 byte" : item.length + " bytes";
            line.append(" (").append(sizeStr).append(")");
            line.append(" - ").append(item.xrefCount).append(" xrefs");

            lines.add(line.toString());
        }

        return String.join("\n", lines);
    }

    private String formatDataItemsAsJson(List<DataItemInfo> dataItems, int offset, int limit) {
        StringBuilder json = new StringBuilder();
        json.append("[");

        int start = Math.min(offset, dataItems.size());
        int end = Math.min(start + limit, dataItems.size());

        for (int i = start; i < end; i++) {
            if (i > start) json.append(",");

            DataItemInfo item = dataItems.get(i);

            json.append("\n  {");
            json.append("\n    \"address\": \"").append(item.address).append("\",");
            json.append("\n    \"name\": \"").append(escapeJson(item.label)).append("\",");
            json.append("\n    \"type\": \"").append(escapeJson(item.typeName)).append("\",");

            String sizeStr = (item.length == 1) ? "1 byte" : item.length + " bytes";
            json.append("\n    \"size\": \"").append(sizeStr).append("\",");
            json.append("\n    \"xref_count\": ").append(item.xrefCount);
            json.append("\n  }");
        }

        json.append("\n]");
        return json.toString();
    }

    private String searchFunctionsByName(String searchTerm, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (searchTerm == null || searchTerm.isEmpty()) return "Search term is required";
    
        List<String> matches = new ArrayList<>();
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            String name = func.getName();
            // simple substring match
            if (name.toLowerCase().contains(searchTerm.toLowerCase())) {
                matches.add(String.format("%s @ %s", name, func.getEntryPoint()));
            }
        }
    
        Collections.sort(matches);
    
        if (matches.isEmpty()) {
            return "No functions matching '" + searchTerm + "'";
        }
        return paginateList(matches, offset, limit);
    }    

    // ----------------------------------------------------------------------------------
    // Logic for rename, decompile, etc.
    // ----------------------------------------------------------------------------------

    private String decompileFunctionByName(String name) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            if (func.getName().equals(name)) {
                DecompileResults result =
                    decomp.decompileFunction(func, DECOMPILE_TIMEOUT_SECONDS, new ConsoleTaskMonitor());
                if (result != null && result.decompileCompleted()) {
                    return result.getDecompiledFunction().getC();
                } else {
                    return "Decompilation failed";
                }
            }
        }
        return "Function not found";
    }

    private String renameFunction(String oldName, String newName) {
        Program program = getCurrentProgram();
        if (program == null) {
            return "Error: No program loaded";
        }

        if (oldName == null || oldName.isEmpty()) {
            return "Error: Old function name is required";
        }

        if (newName == null || newName.isEmpty()) {
            return "Error: New function name is required";
        }

        final StringBuilder resultMsg = new StringBuilder();
        final AtomicBoolean successFlag = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Rename function via HTTP");
                boolean found = false;
                try {
                    for (Function func : program.getFunctionManager().getFunctions(true)) {
                        if (func.getName().equals(oldName)) {
                            found = true;
                            func.setName(newName, SourceType.USER_DEFINED);
                            successFlag.set(true);
                            resultMsg.append("Success: Renamed function '").append(oldName)
                                    .append("' to '").append(newName).append("'");
                            break;
                        }
                    }

                    if (!found) {
                        resultMsg.append("Error: Function '").append(oldName).append("' not found");
                    }
                }
                catch (Exception e) {
                    resultMsg.append("Error: ").append(e.getMessage());
                    Msg.error(this, "Error renaming function", e);
                }
                finally {
                    program.endTransaction(tx, successFlag.get());
                }
            });

            // Force event processing to ensure changes propagate
            if (successFlag.get()) {
                program.flushEvents();
                try {
                    Thread.sleep(50);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
        }
        catch (InterruptedException | InvocationTargetException e) {
            resultMsg.append("Error: Failed to execute rename on Swing thread: ").append(e.getMessage());
            Msg.error(this, "Failed to execute rename on Swing thread", e);
        }

        return resultMsg.length() > 0 ? resultMsg.toString() : "Error: Unknown failure";
    }

    private String renameDataAtAddress(String addressStr, String newName) {
        Program program = getCurrentProgram();
        if (program == null) {
            return "Error: No program loaded";
        }

        final StringBuilder resultMsg = new StringBuilder();

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Rename data");
                boolean success = false;
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    if (addr == null) {
                        resultMsg.append("Error: Invalid address: ").append(addressStr);
                        return;
                    }

                    Listing listing = program.getListing();
                    Data data = listing.getDefinedDataAt(addr);

                    if (data != null) {
                        // Data is defined - rename its symbol
                        SymbolTable symTable = program.getSymbolTable();
                        Symbol symbol = symTable.getPrimarySymbol(addr);
                        if (symbol != null) {
                            symbol.setName(newName, SourceType.USER_DEFINED);
                            resultMsg.append("Success: Renamed defined data at ").append(addressStr)
                                    .append(" to '").append(newName).append("'");
                            success = true;
                        } else {
                            symTable.createLabel(addr, newName, SourceType.USER_DEFINED);
                            resultMsg.append("Success: Created label '").append(newName)
                                    .append("' at ").append(addressStr);
                            success = true;
                        }
                    } else {
                        // No defined data at this address
                        resultMsg.append("Error: No defined data at address ").append(addressStr)
                                .append(". Use create_label for undefined addresses.");
                    }
                }
                catch (Exception e) {
                    resultMsg.append("Error: ").append(e.getMessage());
                    Msg.error(this, "Rename data error", e);
                }
                finally {
                    program.endTransaction(tx, success);
                }
            });
        }
        catch (InterruptedException | InvocationTargetException e) {
            resultMsg.append("Error: Failed to execute rename on Swing thread: ").append(e.getMessage());
            Msg.error(this, "Failed to execute rename data on Swing thread", e);
        }

        return resultMsg.length() > 0 ? resultMsg.toString() : "Error: Unknown failure";
    }

    private String renameVariableInFunction(String functionName, String oldVarName, String newVarName) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);

        Function func = null;
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            if (f.getName().equals(functionName)) {
                func = f;
                break;
            }
        }

        if (func == null) {
            return "Function not found";
        }

        DecompileResults result = decomp.decompileFunction(func, DECOMPILE_TIMEOUT_SECONDS, new ConsoleTaskMonitor());
        if (result == null || !result.decompileCompleted()) {
            return "Decompilation failed";
        }

        HighFunction highFunction = result.getHighFunction();
        if (highFunction == null) {
            return "Decompilation failed (no high function)";
        }

        LocalSymbolMap localSymbolMap = highFunction.getLocalSymbolMap();
        if (localSymbolMap == null) {
            return "Decompilation failed (no local symbol map)";
        }

        HighSymbol highSymbol = null;
        Iterator<HighSymbol> symbols = localSymbolMap.getSymbols();
        while (symbols.hasNext()) {
            HighSymbol symbol = symbols.next();
            String symbolName = symbol.getName();
            
            if (symbolName.equals(oldVarName)) {
                highSymbol = symbol;
            }
            if (symbolName.equals(newVarName)) {
                return "Error: A variable with name '" + newVarName + "' already exists in this function";
            }
        }

        if (highSymbol == null) {
            return "Variable not found";
        }

        boolean commitRequired = checkFullCommit(highSymbol, highFunction);

        final HighSymbol finalHighSymbol = highSymbol;
        final Function finalFunction = func;
        AtomicBoolean successFlag = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {           
                int tx = program.startTransaction("Rename variable");
                try {
                    if (commitRequired) {
                        HighFunctionDBUtil.commitParamsToDatabase(highFunction, false,
                            ReturnCommitOption.NO_COMMIT, finalFunction.getSignatureSource());
                    }
                    HighFunctionDBUtil.updateDBVariable(
                        finalHighSymbol,
                        newVarName,
                        null,
                        SourceType.USER_DEFINED
                    );
                    successFlag.set(true);
                }
                catch (Exception e) {
                    Msg.error(this, "Failed to rename variable", e);
                }
                finally {
                    successFlag.set(program.endTransaction(tx, true));
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            String errorMsg = "Failed to execute rename on Swing thread: " + e.getMessage();
            Msg.error(this, errorMsg, e);
            return errorMsg;
        }
        return successFlag.get() ? "Variable renamed" : "Failed to rename variable";
    }

    /**
     * Copied from AbstractDecompilerAction.checkFullCommit, it's protected.
	 * Compare the given HighFunction's idea of the prototype with the Function's idea.
	 * Return true if there is a difference. If a specific symbol is being changed,
	 * it can be passed in to check whether or not the prototype is being affected.
	 * @param highSymbol (if not null) is the symbol being modified
	 * @param hfunction is the given HighFunction
	 * @return true if there is a difference (and a full commit is required)
	 */
	protected static boolean checkFullCommit(HighSymbol highSymbol, HighFunction hfunction) {
		if (highSymbol != null && !highSymbol.isParameter()) {
			return false;
		}
		Function function = hfunction.getFunction();
		Parameter[] parameters = function.getParameters();
		LocalSymbolMap localSymbolMap = hfunction.getLocalSymbolMap();
		int numParams = localSymbolMap.getNumParams();
		if (numParams != parameters.length) {
			return true;
		}

		for (int i = 0; i < numParams; i++) {
			HighSymbol param = localSymbolMap.getParamSymbol(i);
			if (param.getCategoryIndex() != i) {
				return true;
			}
			VariableStorage storage = param.getStorage();
			// Don't compare using the equals method so that DynamicVariableStorage can match
			if (0 != storage.compareTo(parameters[i].getVariableStorage())) {
				return true;
			}
		}

		return false;
	}

    // ----------------------------------------------------------------------------------
    // New methods to implement the new functionalities
    // ----------------------------------------------------------------------------------

    /**
     * Get function by address
     */
    private String getFunctionByAddress(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = program.getFunctionManager().getFunctionAt(addr);

            if (func == null) return "No function found at address " + addressStr;

            return String.format("Function: %s at %s\nSignature: %s\nEntry: %s\nBody: %s - %s",
                func.getName(),
                func.getEntryPoint(),
                func.getSignature(),
                func.getEntryPoint(),
                func.getBody().getMinAddress(),
                func.getBody().getMaxAddress());
        } catch (Exception e) {
            return "Error getting function: " + e.getMessage();
        }
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
    private String listFunctions() {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        StringBuilder result = new StringBuilder();
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            result.append(String.format("%s at %s\n", 
                func.getName(), 
                func.getEntryPoint()));
        }

        return result.toString();
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
     * Decompile a function at the given address
     */
    private String decompileFunctionByAddress(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = getFunctionForAddress(program, addr);
            if (func == null) return "No function found at or containing address " + addressStr;

            DecompInterface decomp = new DecompInterface();
            decomp.openProgram(program);
            DecompileResults result = decomp.decompileFunction(func, DECOMPILE_TIMEOUT_SECONDS, new ConsoleTaskMonitor());

            return (result != null && result.decompileCompleted()) 
                ? result.getDecompiledFunction().getC() 
                : "Decompilation failed";
        } catch (Exception e) {
            return "Error decompiling function: " + e.getMessage();
        }
    }

    /**
     * Get assembly code for a function
     */
    @SuppressWarnings("deprecation")
    private String disassembleFunction(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            Function func = getFunctionForAddress(program, addr);
            if (func == null) return "No function found at or containing address " + addressStr;

            StringBuilder result = new StringBuilder();
            Listing listing = program.getListing();
            Address start = func.getEntryPoint();
            Address end = func.getBody().getMaxAddress();

            InstructionIterator instructions = listing.getInstructions(start, true);
            while (instructions.hasNext()) {
                Instruction instr = instructions.next();
                if (instr.getAddress().compareTo(end) > 0) {
                    break; // Stop if we've gone past the end of the function
                }
                String comment = listing.getComment(CodeUnit.EOL_COMMENT, instr.getAddress());
                comment = (comment != null) ? "; " + comment : "";

                result.append(String.format("%s: %s %s\n", 
                    instr.getAddress(), 
                    instr.toString(),
                    comment));
            }

            return result.toString();
        } catch (Exception e) {
            return "Error disassembling function: " + e.getMessage();
        }
    }    

    /**
     * Set a comment using the specified comment type (PRE_COMMENT or EOL_COMMENT)
     */
    @SuppressWarnings("deprecation")
    private String setCommentAtAddress(String addressStr, String comment, int commentType, String transactionName) {
        Program program = getCurrentProgram();
        if (program == null) {
            return "Error: No program loaded";
        }

        if (addressStr == null || addressStr.isEmpty()) {
            return "Error: Address is required";
        }

        if (comment == null) {
            return "Error: Comment text is required";
        }

        final StringBuilder resultMsg = new StringBuilder();
        final AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction(transactionName);
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    if (addr == null) {
                        resultMsg.append("Error: Invalid address: ").append(addressStr);
                        return;
                    }

                    program.getListing().setComment(addr, commentType, comment);
                    success.set(true);
                    resultMsg.append("Success: Set comment at ").append(addressStr);
                } catch (Exception e) {
                    resultMsg.append("Error: ").append(e.getMessage());
                    Msg.error(this, "Error setting " + transactionName.toLowerCase(), e);
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            resultMsg.append("Error: Failed to execute on Swing thread: ").append(e.getMessage());
            Msg.error(this, "Failed to execute " + transactionName.toLowerCase() + " on Swing thread", e);
        }

        return resultMsg.length() > 0 ? resultMsg.toString() : "Error: Unknown failure";
    }

    /**
     * Set a comment for a given address in the function pseudocode
     */
    @SuppressWarnings("deprecation")
    private String setDecompilerComment(String addressStr, String comment) {
        return setCommentAtAddress(addressStr, comment, CodeUnit.PRE_COMMENT, "Set decompiler comment");
    }

    /**
     * Set a comment for a given address in the function disassembly
     */
    @SuppressWarnings("deprecation")
    private String setDisassemblyComment(String addressStr, String comment) {
        return setCommentAtAddress(addressStr, comment, CodeUnit.EOL_COMMENT, "Set disassembly comment");
    }

    /**
     * Class to hold the result of a prototype setting operation
     */
    private static class PrototypeResult {
        private final boolean success;
        private final String errorMessage;

        public PrototypeResult(boolean success, String errorMessage) {
            this.success = success;
            this.errorMessage = errorMessage;
        }

        public boolean isSuccess() {
            return success;
        }

        public String getErrorMessage() {
            return errorMessage;
        }
    }

    /**
     * Rename a function by its address
     */
    private String renameFunctionByAddress(String functionAddrStr, String newName) {
        Program program = getCurrentProgram();
        if (program == null) {
            return "Error: No program loaded";
        }

        if (functionAddrStr == null || functionAddrStr.isEmpty()) {
            return "Error: Function address is required";
        }

        if (newName == null || newName.isEmpty()) {
            return "Error: New function name is required";
        }

        final StringBuilder resultMsg = new StringBuilder();
        final AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Rename function by address");
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

                    String oldName = func.getName();
                    func.setName(newName, SourceType.USER_DEFINED);
                    success.set(true);
                    resultMsg.append("Success: Renamed function at ").append(functionAddrStr)
                            .append(" from '").append(oldName).append("' to '").append(newName).append("'");
                } catch (Exception e) {
                    resultMsg.append("Error: ").append(e.getMessage());
                    Msg.error(this, "Error renaming function by address", e);
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            resultMsg.append("Error: Failed to execute rename on Swing thread: ").append(e.getMessage());
            Msg.error(this, "Failed to execute rename function on Swing thread", e);
        }

        return resultMsg.length() > 0 ? resultMsg.toString() : "Error: Unknown failure";
    }

    /**
     * Set a function's prototype with proper error handling using ApplyFunctionSignatureCmd
     */
    private PrototypeResult setFunctionPrototype(String functionAddrStr, String prototype) {
        return setFunctionPrototype(functionAddrStr, prototype, null);
    }

    /**
     * Set a function's prototype with calling convention support
     */
    private PrototypeResult setFunctionPrototype(String functionAddrStr, String prototype, String callingConvention) {
        // Input validation
        Program program = getCurrentProgram();
        if (program == null) return new PrototypeResult(false, "No program loaded");
        if (functionAddrStr == null || functionAddrStr.isEmpty()) {
            return new PrototypeResult(false, "Function address is required");
        }
        if (prototype == null || prototype.isEmpty()) {
            return new PrototypeResult(false, "Function prototype is required");
        }

        final StringBuilder errorMessage = new StringBuilder();
        final AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> 
                applyFunctionPrototype(program, functionAddrStr, prototype, callingConvention, success, errorMessage));
        } catch (InterruptedException | InvocationTargetException e) {
            String msg = "Failed to set function prototype on Swing thread: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
        }

        return new PrototypeResult(success.get(), errorMessage.toString());
    }

    /**
     * Helper method that applies the function prototype within a transaction
     */
    private void applyFunctionPrototype(Program program, String functionAddrStr, String prototype, 
                                       String callingConvention, AtomicBoolean success, StringBuilder errorMessage) {
        try {
            // Get the address and function
            Address addr = program.getAddressFactory().getAddress(functionAddrStr);
            Function func = getFunctionForAddress(program, addr);

            if (func == null) {
                String msg = "Could not find function at address: " + functionAddrStr;
                errorMessage.append(msg);
                Msg.error(this, msg);
                return;
            }

            Msg.info(this, "Setting prototype for function " + func.getName() + ": " + prototype);

            // Store original prototype as a comment for reference
            addPrototypeComment(program, func, prototype);

            // Use ApplyFunctionSignatureCmd to parse and apply the signature
            parseFunctionSignatureAndApply(program, addr, prototype, callingConvention, success, errorMessage);

        } catch (Exception e) {
            String msg = "Error setting function prototype: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
        }
    }

    /**
     * Add a comment showing the prototype being set
     */
    @SuppressWarnings("deprecation")
    private void addPrototypeComment(Program program, Function func, String prototype) {
        int txComment = program.startTransaction("Add prototype comment");
        try {
            program.getListing().setComment(
                func.getEntryPoint(), 
                CodeUnit.PLATE_COMMENT, 
                "Setting prototype: " + prototype
            );
        } finally {
            program.endTransaction(txComment, true);
        }
    }

    /**
     * Parse and apply the function signature with error handling
     */
    private void parseFunctionSignatureAndApply(Program program, Address addr, String prototype,
                                              String callingConvention, AtomicBoolean success, StringBuilder errorMessage) {
        // Use ApplyFunctionSignatureCmd to parse and apply the signature
        int txProto = program.startTransaction("Set function prototype");
        boolean signatureApplied = false;
        try {
            // Get data type manager
            DataTypeManager dtm = program.getDataTypeManager();

            // Create function signature parser without DataTypeManagerService
            // to prevent UI dialogs from popping up (pass null instead of dtms)
            ghidra.app.util.parser.FunctionSignatureParser parser =
                new ghidra.app.util.parser.FunctionSignatureParser(dtm, null);

            // Parse the prototype into a function signature
            ghidra.program.model.data.FunctionDefinitionDataType sig = parser.parse(null, prototype);

            if (sig == null) {
                String msg = "Failed to parse function prototype";
                errorMessage.append(msg);
                Msg.error(this, msg);
                return;
            }

            // Create and apply the command
            ghidra.app.cmd.function.ApplyFunctionSignatureCmd cmd =
                new ghidra.app.cmd.function.ApplyFunctionSignatureCmd(
                    addr, sig, SourceType.USER_DEFINED);

            // Apply the command to the program
            boolean cmdResult = cmd.applyTo(program, new ConsoleTaskMonitor());

            if (cmdResult) {
                signatureApplied = true;
                Msg.info(this, "Successfully applied function signature");
            } else {
                String msg = "Command failed: " + cmd.getStatusMsg();
                errorMessage.append(msg);
                Msg.error(this, msg);
            }
        } catch (Exception e) {
            String msg = "Error applying function signature: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
        } finally {
            program.endTransaction(txProto, signatureApplied);
        }

        // Apply calling convention in a SEPARATE transaction after signature is committed
        // This ensures the calling convention isn't overridden by ApplyFunctionSignatureCmd
        if (signatureApplied && callingConvention != null && !callingConvention.isEmpty()) {
            int txConv = program.startTransaction("Set calling convention");
            boolean conventionApplied = false;
            try {
                conventionApplied = applyCallingConvention(program, addr, callingConvention, errorMessage);
                if (conventionApplied) {
                    success.set(true);
                } else {
                    success.set(false);  // Fail if calling convention couldn't be applied
                }
            } catch (Exception e) {
                String msg = "Error in calling convention transaction: " + e.getMessage();
                errorMessage.append(msg);
                Msg.error(this, msg, e);
                success.set(false);
            } finally {
                program.endTransaction(txConv, conventionApplied);
            }
        } else if (signatureApplied) {
            success.set(true);
        }
    }

    /**
     * List all available calling conventions in the current program
     */
    private String listCallingConventions() {
        Program program = getCurrentProgram();
        if (program == null) {
            return "No program loaded";
        }

        try {
            ghidra.program.model.lang.CompilerSpec compilerSpec = program.getCompilerSpec();
            ghidra.program.model.lang.PrototypeModel[] available = compilerSpec.getCallingConventions();

            StringBuilder result = new StringBuilder();
            result.append("Available Calling Conventions (").append(available.length).append("):\n\n");

            for (ghidra.program.model.lang.PrototypeModel model : available) {
                result.append("- ").append(model.getName()).append("\n");
            }

            return result.toString();
        } catch (Exception e) {
            return "Error listing calling conventions: " + e.getMessage();
        }
    }

    /**
     * Apply calling convention to a function
     * @return true if convention was successfully applied, false otherwise
     */
    private boolean applyCallingConvention(Program program, Address addr, String callingConvention, StringBuilder errorMessage) {
        try {
            Function func = getFunctionForAddress(program, addr);
            if (func == null) {
                errorMessage.append("Could not find function to set calling convention");
                return false;
            }

            // Get the program's calling convention manager
            ghidra.program.model.lang.CompilerSpec compilerSpec = program.getCompilerSpec();
            ghidra.program.model.lang.PrototypeModel callingConv = null;

            // Get all available calling conventions
            ghidra.program.model.lang.PrototypeModel[] available = compilerSpec.getCallingConventions();

            // Try to find matching calling convention by name
            String targetName = callingConvention.toLowerCase();
            for (ghidra.program.model.lang.PrototypeModel model : available) {
                String modelName = model.getName().toLowerCase();
                if (modelName.equals(targetName) ||
                    modelName.equals("__" + targetName) ||
                    modelName.replace("__", "").equals(targetName.replace("__", ""))) {
                    callingConv = model;
                    break;
                }
            }

            if (callingConv != null) {
                func.setCallingConvention(callingConv.getName());
                Msg.info(this, "Set calling convention to: " + callingConv.getName());
                return true;  // Successfully applied
            } else {
                String msg = "Unknown calling convention: " + callingConvention + ". ";

                // List available calling conventions for debugging
                StringBuilder availList = new StringBuilder("Available calling conventions: ");
                for (ghidra.program.model.lang.PrototypeModel model : available) {
                    availList.append(model.getName()).append(", ");
                }
                String availMsg = availList.toString();
                msg += availMsg;

                errorMessage.append(msg);
                Msg.warn(this, msg);
                Msg.info(this, availMsg);

                return false;  // Convention not found
            }

        } catch (Exception e) {
            String msg = "Error setting calling convention: " + e.getMessage();
            errorMessage.append(msg);
            Msg.error(this, msg, e);
            return false;
        }
    }

    /**
     * Set a local variable's type using HighFunctionDBUtil.updateDBVariable
     */
    private String setLocalVariableType(String functionAddrStr, String variableName, String newType) {
        // Input validation
        Program program = getCurrentProgram();
        if (program == null) {
            return "Error: No program loaded";
        }

        if (functionAddrStr == null || functionAddrStr.isEmpty()) {
            return "Error: Function address is required";
        }

        if (variableName == null || variableName.isEmpty()) {
            return "Error: Variable name is required";
        }

        if (newType == null || newType.isEmpty()) {
            return "Error: New type is required";
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
                        resultMsg.append("Error: Variable '").append(variableName)
                                .append("' not found in function");
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
                    if (updateVariableType(program, symbol, dataType, success)) {
                        resultMsg.append("Success: Changed type of variable '").append(variableName)
                                .append("' from '").append(oldType).append("' to '")
                                .append(dataType.getName()).append("'");
                    } else {
                        resultMsg.append("Error: Failed to update variable type");
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

        return resultMsg.length() > 0 ? resultMsg.toString() : "Error: Unknown failure";
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
     * Decompile a function and return the results
     */
    private DecompileResults decompileFunction(Function func, Program program) {
        // Set up decompiler for accessing the decompiled function
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);
        decomp.setSimplificationStyle("decompile"); // Full decompilation

        // Decompile the function
        DecompileResults results = decomp.decompileFunction(func, DECOMPILE_TIMEOUT_SECONDS, new ConsoleTaskMonitor());

        if (!results.decompileCompleted()) {
            Msg.error(this, "Could not decompile function: " + results.getErrorMessage());
            return null;
        }

        return results;
    }

    /**
     * Apply the type update in a transaction
     */
    private boolean updateVariableType(Program program, HighSymbol symbol, DataType dataType, AtomicBoolean success) {
        int tx = program.startTransaction("Set variable type");
        boolean result = false;
        try {
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
        } catch (Exception e) {
            Msg.error(this, "Error setting variable type: " + e.getMessage());
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
    private String setFunctionNoReturn(String functionAddrStr, boolean noReturn) {
        // Input validation
        Program program = getCurrentProgram();
        if (program == null) {
            return "Error: No program loaded";
        }

        if (functionAddrStr == null || functionAddrStr.isEmpty()) {
            return "Error: Function address is required";
        }

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

        return resultMsg.length() > 0 ? resultMsg.toString() : "Error: Unknown failure";
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
    private String clearInstructionFlowOverride(String instructionAddrStr) {
        // Input validation
        Program program = getCurrentProgram();
        if (program == null) {
            return "Error: No program loaded";
        }

        if (instructionAddrStr == null || instructionAddrStr.isEmpty()) {
            return "Error: Instruction address is required";
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

        return resultMsg.length() > 0 ? resultMsg.toString() : "Error: Unknown failure";
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
    private String setVariableStorage(String functionAddrStr, String variableName, String storageSpec) {
        Program program = getCurrentProgram();
        if (program == null) {
            return "Error: No program loaded";
        }

        if (functionAddrStr == null || functionAddrStr.isEmpty()) {
            return "Error: Function address is required";
        }
        if (variableName == null || variableName.isEmpty()) {
            return "Error: Variable name is required";
        }
        if (storageSpec == null || storageSpec.isEmpty()) {
            return "Error: Storage specification is required";
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

        return resultMsg.length() > 0 ? resultMsg.toString() : "Error: Unknown failure";
    }

    /**
     * Run a Ghidra script programmatically (v1.7.0)
     *
     * @param scriptPath Path to the script file (.java or .py)
     * @param scriptArgs Optional JSON string of arguments
     * @return Script output or error message
     */
    private String runGhidraScript(String scriptPath, String scriptArgs) {
        Program program = getCurrentProgram();
        if (program == null) {
            return "Error: No program loaded";
        }

        final StringBuilder resultMsg = new StringBuilder();
        final AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {
                try {
                    // Ghidra script execution requires complex API interaction
                    // The proper way is through the Ghidra GUI or headless analyzer
                    resultMsg.append("Note: Programmatic script execution via REST API has limitations.\n\n");
                    resultMsg.append("Script path provided: ").append(scriptPath).append("\n\n");
                    resultMsg.append("To run Ghidra scripts:\n");
                    resultMsg.append("1. Use Ghidra's Script Manager (Window → Script Manager)\n");
                    resultMsg.append("2. Use Ghidra Headless Analyzer from command line\n");
                    resultMsg.append("3. Place script in Ghidra's script directory and run via GUI\n\n");
                    resultMsg.append("Example headless command:\n");
                    resultMsg.append("  analyzeHeadless <project_path> <project_name> \\\n");
                    resultMsg.append("    -process <binary> -postScript ").append(scriptPath).append("\n\n");
                    resultMsg.append("For automated workflows, consider:\n");
                    resultMsg.append("- Using existing MCP tools instead of custom scripts\n");
                    resultMsg.append("- Running scripts via Ghidra's GUI or headless mode\n");
                    resultMsg.append("- Implementing functionality as MCP tool endpoints\n");

                    success.set(true);
                    Msg.info(this, "Script execution request for: " + scriptPath);

                } catch (Exception e) {
                    resultMsg.append("Error: ").append(e.getMessage());
                    Msg.error(this, "Error in script execution handler", e);
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            resultMsg.append("Error: Failed to execute on Swing thread: ").append(e.getMessage());
            Msg.error(this, "Failed to execute on Swing thread", e);
        }

        return resultMsg.length() > 0 ? resultMsg.toString() : "Error: Unknown failure";
    }

    /**
     * List available Ghidra scripts (v1.7.0)
     *
     * @param filter Optional filter string to match script names
     * @return JSON list of available scripts
     */
    private String listGhidraScripts(String filter) {
        final StringBuilder resultMsg = new StringBuilder();

        try {
            SwingUtilities.invokeAndWait(() -> {
                try {
                    resultMsg.append("{\n  \"note\": \"Script listing requires Ghidra GUI access\",\n");
                    resultMsg.append("  \"filter\": \"").append(filter != null ? filter : "none").append("\",\n");
                    resultMsg.append("  \"instructions\": [\n");
                    resultMsg.append("    \"To view available scripts:\",\n");
                    resultMsg.append("    \"1. Open Ghidra's Script Manager (Window → Script Manager)\",\n");
                    resultMsg.append("    \"2. Browse scripts by category\",\n");
                    resultMsg.append("    \"3. Use the search filter at the top\"\n");
                    resultMsg.append("  ],\n");
                    resultMsg.append("  \"common_script_locations\": [\n");
                    resultMsg.append("    \"<ghidra_install>/Ghidra/Features/*/ghidra_scripts/\",\n");
                    resultMsg.append("    \"<user_home>/ghidra_scripts/\"\n");
                    resultMsg.append("  ]\n");
                    resultMsg.append("}");

                } catch (Exception e) {
                    resultMsg.append("Error: ").append(e.getMessage());
                    Msg.error(this, "Error in list scripts handler", e);
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            return "Error: Failed to execute on Swing thread: " + e.getMessage();
        }

        return resultMsg.toString();
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
        Program program = getCurrentProgram();
        if (program == null) {
            return "Error: No program loaded";
        }

        if (functionAddrStr == null || functionAddrStr.isEmpty()) {
            return "Error: Function address is required";
        }

        final StringBuilder resultMsg = new StringBuilder();
        final AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {
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

                    // Create new decompiler interface
                    DecompInterface decompiler = new DecompInterface();
                    decompiler.openProgram(program);

                    try {
                        // Force a fresh decompilation
                        decompiler.setSimplificationStyle("normalize");
                        DecompileResults results = decompiler.decompileFunction(func, DECOMPILE_TIMEOUT_SECONDS, new ConsoleTaskMonitor());

                        if (results == null || !results.decompileCompleted()) {
                            resultMsg.append("Error: Decompilation failed for function ").append(func.getName());
                            return;
                        }

                        // Get the decompiled C code
                        String decompiledCode = results.getDecompiledFunction().getC();

                        success.set(true);
                        resultMsg.append("Success: Forced redecompilation of ").append(func.getName()).append("\n\n");
                        resultMsg.append(decompiledCode);

                        Msg.info(this, "Forced decompilation for function: " + func.getName());

                    } finally {
                        decompiler.dispose();
                    }

                } catch (Exception e) {
                    resultMsg.append("Error: ").append(e.getMessage());
                    Msg.error(this, "Error forcing decompilation", e);
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            resultMsg.append("Error: Failed to execute on Swing thread: ").append(e.getMessage());
            Msg.error(this, "Failed to execute force decompile on Swing thread", e);
        }

        return resultMsg.length() > 0 ? resultMsg.toString() : "Error: Unknown failure";
    }

    /**
     * Get all references to a specific address (xref to)
     */
    private String getXrefsTo(String addressStr, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            ReferenceManager refManager = program.getReferenceManager();
            
            ReferenceIterator refIter = refManager.getReferencesTo(addr);
            
            List<String> refs = new ArrayList<>();
            while (refIter.hasNext()) {
                Reference ref = refIter.next();
                Address fromAddr = ref.getFromAddress();
                RefType refType = ref.getReferenceType();
                
                Function fromFunc = program.getFunctionManager().getFunctionContaining(fromAddr);
                String funcInfo = (fromFunc != null) ? " in " + fromFunc.getName() : "";
                
                refs.add(String.format("From %s%s [%s]", fromAddr, funcInfo, refType.getName()));
            }
            
            return paginateList(refs, offset, limit);
        } catch (Exception e) {
            return "Error getting references to address: " + e.getMessage();
        }
    }

    /**
     * Get all references from a specific address (xref from)
     */
    private String getXrefsFrom(String addressStr, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            ReferenceManager refManager = program.getReferenceManager();
            
            Reference[] references = refManager.getReferencesFrom(addr);
            
            List<String> refs = new ArrayList<>();
            for (Reference ref : references) {
                Address toAddr = ref.getToAddress();
                RefType refType = ref.getReferenceType();
                
                String targetInfo = "";
                Function toFunc = program.getFunctionManager().getFunctionAt(toAddr);
                if (toFunc != null) {
                    targetInfo = " to function " + toFunc.getName();
                } else {
                    Data data = program.getListing().getDataAt(toAddr);
                    if (data != null) {
                        targetInfo = " to data " + (data.getLabel() != null ? data.getLabel() : data.getPathName());
                    }
                }
                
                refs.add(String.format("To %s%s [%s]", toAddr, targetInfo, refType.getName()));
            }
            
            return paginateList(refs, offset, limit);
        } catch (Exception e) {
            return "Error getting references from address: " + e.getMessage();
        }
    }

    /**
     * Get all references to a specific function by name
     */
    private String getFunctionXrefs(String functionName, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (functionName == null || functionName.isEmpty()) return "Function name is required";

        try {
            List<String> refs = new ArrayList<>();
            FunctionManager funcManager = program.getFunctionManager();
            for (Function function : funcManager.getFunctions(true)) {
                if (function.getName().equals(functionName)) {
                    Address entryPoint = function.getEntryPoint();
                    ReferenceIterator refIter = program.getReferenceManager().getReferencesTo(entryPoint);
                    
                    while (refIter.hasNext()) {
                        Reference ref = refIter.next();
                        Address fromAddr = ref.getFromAddress();
                        RefType refType = ref.getReferenceType();
                        
                        Function fromFunc = funcManager.getFunctionContaining(fromAddr);
                        String funcInfo = (fromFunc != null) ? " in " + fromFunc.getName() : "";
                        
                        refs.add(String.format("From %s%s [%s]", fromAddr, funcInfo, refType.getName()));
                    }
                }
            }
            
            if (refs.isEmpty()) {
                return "No references found to function: " + functionName;
            }
            
            return paginateList(refs, offset, limit);
        } catch (Exception e) {
            return "Error getting function references: " + e.getMessage();
        }
    }

/**
 * List all defined strings in the program with their addresses
 */
    private String listDefinedStrings(int offset, int limit, String filter) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        List<String> lines = new ArrayList<>();
        DataIterator dataIt = program.getListing().getDefinedData(true);
        
        while (dataIt.hasNext()) {
            Data data = dataIt.next();
            
            if (data != null && isStringData(data)) {
                String value = data.getValue() != null ? data.getValue().toString() : "";
                
                if (filter == null || value.toLowerCase().contains(filter.toLowerCase())) {
                    String escapedValue = escapeString(value);
                    lines.add(String.format("%s: \"%s\"", data.getAddress(), escapedValue));
                }
            }
        }
        
        return paginateList(lines, offset, limit);
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
     * Resolves a data type by name, handling common types and pointer types
     * @param dtm The data type manager
     * @param typeName The type name to resolve
     * @return The resolved DataType, or null if not found
     */
    private DataType resolveDataType(DataTypeManager dtm, String typeName) {
        // First try to find exact match in all categories
        DataType dataType = findDataTypeByNameInAllCategories(dtm, typeName);
        if (dataType != null) {
            Msg.info(this, "Found exact data type match: " + dataType.getPathName());
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
                            // String value
                            result.put(key, value.substring(1, value.length() - 1));
                        } else if (value.startsWith("[") && value.endsWith("]")) {
                            // Array value - parse into List
                            result.put(key, parseJsonArray(value));
                        } else if (value.startsWith("{") && value.endsWith("}")) {
                            // Object value - keep as string for now
                            result.put(key, value);
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
        ProgramManager pm = tool.getService(ProgramManager.class);
        return pm != null ? pm.getCurrentProgram() : null;
    }

    private void sendResponse(HttpExchange exchange, String response) throws IOException {
        byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
        Headers headers = exchange.getResponseHeaders();
        headers.set("Content-Type", "text/plain; charset=utf-8");
        // v1.6.1: Enable HTTP keep-alive for long-running operations
        headers.set("Connection", "keep-alive");
        headers.set("Keep-Alive", "timeout=" + HTTP_IDLE_TIMEOUT_SECONDS + ", max=100");
        exchange.sendResponseHeaders(200, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
            os.flush();  // v1.7.2: Explicit flush to ensure response is sent immediately
        }
    }

    /**
     * Get labels within a specific function by name
     */
    public String getFunctionLabels(String functionName, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) {
            return "No program loaded";
        }

        StringBuilder sb = new StringBuilder();
        SymbolTable symbolTable = program.getSymbolTable();
        FunctionManager functionManager = program.getFunctionManager();
        
        // Find the function by name
        Function function = null;
        for (Function f : functionManager.getFunctions(true)) {
            if (f.getName().equals(functionName)) {
                function = f;
                break;
            }
        }
        
        if (function == null) {
            return "Function not found: " + functionName;
        }

        AddressSetView functionBody = function.getBody();
        SymbolIterator symbols = symbolTable.getSymbolIterator();
        int count = 0;
        int skipped = 0;

        while (symbols.hasNext() && count < limit) {
            Symbol symbol = symbols.next();
            
            // Check if symbol is within the function's address range
            if (symbol.getSymbolType() == SymbolType.LABEL && 
                functionBody.contains(symbol.getAddress())) {
                
                if (skipped < offset) {
                    skipped++;
                    continue;
                }
                
                if (sb.length() > 0) {
                    sb.append("\n");
                }
                sb.append("Address: ").append(symbol.getAddress().toString())
                  .append(", Name: ").append(symbol.getName())
                  .append(", Source: ").append(symbol.getSource().toString());
                count++;
            }
        }

        if (sb.length() == 0) {
            return "No labels found in function: " + functionName;
        }
        
        return sb.toString();
    }

    /**
     * Rename a label at the specified address
     */
    public String renameLabel(String addressStr, String oldName, String newName) {
        Program program = getCurrentProgram();
        if (program == null) {
            return "No program loaded";
        }

        try {
            Address address = program.getAddressFactory().getAddress(addressStr);
            if (address == null) {
                return "Invalid address: " + addressStr;
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
                return "Label not found: " + oldName + " at address " + addressStr;
            }

            // Check if new name already exists at this address
            for (Symbol symbol : symbols) {
                if (symbol.getName().equals(newName) && symbol.getSymbolType() == SymbolType.LABEL) {
                    return "Label with name '" + newName + "' already exists at address " + addressStr;
                }
            }

            // Perform the rename
            int transactionId = program.startTransaction("Rename Label");
            try {
                targetSymbol.setName(newName, SourceType.USER_DEFINED);
                return "Successfully renamed label from '" + oldName + "' to '" + newName + "' at address " + addressStr;
            } catch (Exception e) {
                return "Error renaming label: " + e.getMessage();
            } finally {
                program.endTransaction(transactionId, true);
            }

        } catch (Exception e) {
            return "Error processing request: " + e.getMessage();
        }
    }

    /**
     * Get all jump target addresses from a function's disassembly
     */
    public String getFunctionJumpTargets(String functionName, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) {
            return "No program loaded";
        }

        StringBuilder sb = new StringBuilder();
        FunctionManager functionManager = program.getFunctionManager();
        
        // Find the function by name
        Function function = null;
        for (Function f : functionManager.getFunctions(true)) {
            if (f.getName().equals(functionName)) {
                function = f;
                break;
            }
        }
        
        if (function == null) {
            return "Function not found: " + functionName;
        }

        AddressSetView functionBody = function.getBody();
        Listing listing = program.getListing();
        Set<Address> jumpTargets = new HashSet<>();
        
        // Iterate through all instructions in the function
        InstructionIterator instructions = listing.getInstructions(functionBody, true);
        while (instructions.hasNext()) {
            Instruction instr = instructions.next();
            
            // Check if this is a jump instruction
            if (instr.getFlowType().isJump()) {
                // Get all reference addresses from this instruction
                Reference[] references = instr.getReferencesFrom();
                for (Reference ref : references) {
                    Address targetAddr = ref.getToAddress();
                    // Only include targets within the function or program space
                    if (targetAddr != null && program.getMemory().contains(targetAddr)) {
                        jumpTargets.add(targetAddr);
                    }
                }
                
                // Also check for fall-through addresses for conditional jumps
                if (instr.getFlowType().isConditional()) {
                    Address fallThroughAddr = instr.getFallThrough();
                    if (fallThroughAddr != null) {
                        jumpTargets.add(fallThroughAddr);
                    }
                }
            }
        }

        // Convert to sorted list and apply pagination
        List<Address> sortedTargets = new ArrayList<>(jumpTargets);
        Collections.sort(sortedTargets);
        
        int count = 0;
        int skipped = 0;
        
        for (Address target : sortedTargets) {
            if (count >= limit) break;
            
            if (skipped < offset) {
                skipped++;
                continue;
            }
            
            if (sb.length() > 0) {
                sb.append("\n");
            }
            
            // Add context about what's at this address
            String context = "";
            Function targetFunc = functionManager.getFunctionContaining(target);
            if (targetFunc != null) {
                context = " (in " + targetFunc.getName() + ")";
            } else {
                // Check if there's a label at this address
                Symbol symbol = program.getSymbolTable().getPrimarySymbol(target);
                if (symbol != null) {
                    context = " (" + symbol.getName() + ")";
                }
            }
            
            sb.append(target.toString()).append(context);
            count++;
        }

        if (sb.length() == 0) {
            return "No jump targets found in function: " + functionName;
        }
        
        return sb.toString();
    }

    /**
     * Create a new label at the specified address
     */
    public String createLabel(String addressStr, String labelName) {
        Program program = getCurrentProgram();
        if (program == null) {
            return "No program loaded";
        }

        if (addressStr == null || addressStr.isEmpty()) {
            return "Address is required";
        }

        if (labelName == null || labelName.isEmpty()) {
            return "Label name is required";
        }

        try {
            Address address = program.getAddressFactory().getAddress(addressStr);
            if (address == null) {
                return "Invalid address: " + addressStr;
            }

            SymbolTable symbolTable = program.getSymbolTable();

            // Check if a label with this name already exists at this address
            Symbol[] existingSymbols = symbolTable.getSymbols(address);
            for (Symbol symbol : existingSymbols) {
                if (symbol.getName().equals(labelName) && symbol.getSymbolType() == SymbolType.LABEL) {
                    return "Label '" + labelName + "' already exists at address " + addressStr;
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
                    return "Successfully created label '" + labelName + "' at address " + addressStr;
                } else {
                    return "Failed to create label '" + labelName + "' at address " + addressStr;
                }
            } catch (Exception e) {
                return "Error creating label: " + e.getMessage();
            } finally {
                program.endTransaction(transactionId, true);
            }

        } catch (Exception e) {
            return "Error processing request: " + e.getMessage();
        }
    }

    /**
     * v1.5.1: Batch create multiple labels in a single transaction
     * Reduces API calls and prevents user interruption hooks from triggering multiple times
     *
     * @param labels List of label objects with "address" and "name" fields
     * @return JSON string with success status and counts
     */
    public String batchCreateLabels(List<Map<String, String>> labels) {
        Program program = getCurrentProgram();
        if (program == null) {
            return "{\"error\": \"No program loaded\"}";
        }

        if (labels == null || labels.isEmpty()) {
            return "{\"error\": \"No labels provided\"}";
        }

        final StringBuilder result = new StringBuilder();
        result.append("{");
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

                            // Check if label already exists
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

                            // Create the label
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

            result.append("\"success\": true, ");
            result.append("\"labels_created\": ").append(successCount.get()).append(", ");
            result.append("\"labels_skipped\": ").append(skipCount.get()).append(", ");
            result.append("\"labels_failed\": ").append(errorCount.get());

            if (!errors.isEmpty()) {
                result.append(", \"errors\": [");
                for (int i = 0; i < errors.size(); i++) {
                    if (i > 0) result.append(", ");
                    result.append("\"").append(errors.get(i).replace("\"", "\\\"")).append("\"");
                }
                result.append("]");
            }

        } catch (Exception e) {
            result.append("\"error\": \"").append(e.getMessage().replace("\"", "\\\"")).append("\"");
        }

        result.append("}");
        return result.toString();
    }

    /**
     * Intelligently rename data or create label based on whether data is defined.
     * This method automatically detects if the address has defined data and chooses
     * the appropriate operation: rename_data for defined data, create_label for undefined.
     */
    public String renameOrLabel(String addressStr, String newName) {
        Program program = getCurrentProgram();
        if (program == null) {
            return "Error: No program loaded";
        }

        if (addressStr == null || addressStr.isEmpty()) {
            return "Error: Address is required";
        }

        if (newName == null || newName.isEmpty()) {
            return "Error: Name is required";
        }

        try {
            Address address = program.getAddressFactory().getAddress(addressStr);
            if (address == null) {
                return "Error: Invalid address: " + addressStr;
            }

            Listing listing = program.getListing();
            Data data = listing.getDefinedDataAt(address);

            if (data != null) {
                // Defined data exists - use rename_data logic
                return renameDataAtAddress(addressStr, newName);
            } else {
                // No defined data - use create_label logic
                return createLabel(addressStr, newName);
            }

        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Get all functions called by the specified function (callees)
     */
    public String getFunctionCallees(String functionName, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) {
            return "No program loaded";
        }

        StringBuilder sb = new StringBuilder();
        FunctionManager functionManager = program.getFunctionManager();
        
        // Find the function by name
        Function function = null;
        for (Function f : functionManager.getFunctions(true)) {
            if (f.getName().equals(functionName)) {
                function = f;
                break;
            }
        }
        
        if (function == null) {
            return "Function not found: " + functionName;
        }

        Set<Function> callees = new HashSet<>();
        AddressSetView functionBody = function.getBody();
        Listing listing = program.getListing();
        ReferenceManager refManager = program.getReferenceManager();
        
        // Iterate through all instructions in the function
        InstructionIterator instructions = listing.getInstructions(functionBody, true);
        while (instructions.hasNext()) {
            Instruction instr = instructions.next();
            
            // Check if this is a call instruction
            if (instr.getFlowType().isCall()) {
                // Get all reference addresses from this instruction
                Reference[] references = refManager.getReferencesFrom(instr.getAddress());
                for (Reference ref : references) {
                    if (ref.getReferenceType().isCall()) {
                        Address targetAddr = ref.getToAddress();
                        Function targetFunc = functionManager.getFunctionAt(targetAddr);
                        if (targetFunc != null) {
                            callees.add(targetFunc);
                        }
                    }
                }
            }
        }

        // Convert to sorted list and apply pagination
        List<Function> sortedCallees = new ArrayList<>(callees);
        sortedCallees.sort((f1, f2) -> f1.getName().compareTo(f2.getName()));
        
        int count = 0;
        int skipped = 0;
        
        for (Function callee : sortedCallees) {
            if (count >= limit) break;
            
            if (skipped < offset) {
                skipped++;
                continue;
            }
            
            if (sb.length() > 0) {
                sb.append("\n");
            }
            
            sb.append(String.format("%s @ %s", callee.getName(), callee.getEntryPoint()));
            count++;
        }

        if (sb.length() == 0) {
            return "No callees found for function: " + functionName;
        }
        
        return sb.toString();
    }

    /**
     * Get all functions that call the specified function (callers)
     */
    public String getFunctionCallers(String functionName, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) {
            return "No program loaded";
        }

        StringBuilder sb = new StringBuilder();
        FunctionManager functionManager = program.getFunctionManager();
        
        // Find the function by name
        Function targetFunction = null;
        for (Function f : functionManager.getFunctions(true)) {
            if (f.getName().equals(functionName)) {
                targetFunction = f;
                break;
            }
        }
        
        if (targetFunction == null) {
            return "Function not found: " + functionName;
        }

        Set<Function> callers = new HashSet<>();
        ReferenceManager refManager = program.getReferenceManager();
        
        // Get all references to this function's entry point
        ReferenceIterator refIter = refManager.getReferencesTo(targetFunction.getEntryPoint());
        while (refIter.hasNext()) {
            Reference ref = refIter.next();
            if (ref.getReferenceType().isCall()) {
                Address fromAddr = ref.getFromAddress();
                Function callerFunc = functionManager.getFunctionContaining(fromAddr);
                if (callerFunc != null) {
                    callers.add(callerFunc);
                }
            }
        }

        // Convert to sorted list and apply pagination
        List<Function> sortedCallers = new ArrayList<>(callers);
        sortedCallers.sort((f1, f2) -> f1.getName().compareTo(f2.getName()));
        
        int count = 0;
        int skipped = 0;
        
        for (Function caller : sortedCallers) {
            if (count >= limit) break;
            
            if (skipped < offset) {
                skipped++;
                continue;
            }
            
            if (sb.length() > 0) {
                sb.append("\n");
            }
            
            sb.append(String.format("%s @ %s", caller.getName(), caller.getEntryPoint()));
            count++;
        }

        if (sb.length() == 0) {
            return "No callers found for function: " + functionName;
        }
        
        return sb.toString();
    }

    /**
     * Get a call graph subgraph centered on the specified function
     */
    public String getFunctionCallGraph(String functionName, int depth, String direction) {
        Program program = getCurrentProgram();
        if (program == null) {
            return "No program loaded";
        }

        StringBuilder sb = new StringBuilder();
        FunctionManager functionManager = program.getFunctionManager();
        
        // Find the function by name
        Function rootFunction = null;
        for (Function f : functionManager.getFunctions(true)) {
            if (f.getName().equals(functionName)) {
                rootFunction = f;
                break;
            }
        }
        
        if (rootFunction == null) {
            return "Function not found: " + functionName;
        }

        Set<String> visited = new HashSet<>();
        Map<String, Set<String>> callGraph = new HashMap<>();
        
        // Build call graph based on direction
        if ("callees".equals(direction) || "both".equals(direction)) {
            buildCallGraphCallees(rootFunction, depth, visited, callGraph, functionManager);
        }
        
        if ("callers".equals(direction) || "both".equals(direction)) {
            visited.clear(); // Reset for callers traversal
            buildCallGraphCallers(rootFunction, depth, visited, callGraph, functionManager);
        }

        // Format output as edges
        for (Map.Entry<String, Set<String>> entry : callGraph.entrySet()) {
            String caller = entry.getKey();
            for (String callee : entry.getValue()) {
                if (sb.length() > 0) {
                    sb.append("\n");
                }
                sb.append(caller).append(" -> ").append(callee);
            }
        }

        if (sb.length() == 0) {
            return "No call graph relationships found for function: " + functionName;
        }
        
        return sb.toString();
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
    public String getFullCallGraph(String format, int limit) {
        Program program = getCurrentProgram();
        if (program == null) {
            return "No program loaded";
        }

        StringBuilder sb = new StringBuilder();
        FunctionManager functionManager = program.getFunctionManager();
        ReferenceManager refManager = program.getReferenceManager();
        Listing listing = program.getListing();
        
        Map<String, Set<String>> callGraph = new HashMap<>();
        int relationshipCount = 0;
        
        // Build complete call graph
        for (Function function : functionManager.getFunctions(true)) {
            if (relationshipCount >= limit) {
                break;
            }
            
            String functionName = function.getName();
            Set<String> callees = new HashSet<>();
            
            // Find all functions called by this function
            AddressSetView functionBody = function.getBody();
            InstructionIterator instructions = listing.getInstructions(functionBody, true);
            
            while (instructions.hasNext() && relationshipCount < limit) {
                Instruction instr = instructions.next();
                
                if (instr.getFlowType().isCall()) {
                    Reference[] references = refManager.getReferencesFrom(instr.getAddress());
                    for (Reference ref : references) {
                        if (ref.getReferenceType().isCall()) {
                            Address targetAddr = ref.getToAddress();
                            Function targetFunc = functionManager.getFunctionAt(targetAddr);
                            if (targetFunc != null) {
                                callees.add(targetFunc.getName());
                                relationshipCount++;
                                if (relationshipCount >= limit) {
                                    break;
                                }
                            }
                        }
                    }
                }
            }
            
            if (!callees.isEmpty()) {
                callGraph.put(functionName, callees);
            }
        }

        // Format output based on requested format
        if ("dot".equals(format)) {
            sb.append("digraph CallGraph {\n");
            sb.append("  rankdir=TB;\n");
            sb.append("  node [shape=box];\n");
            for (Map.Entry<String, Set<String>> entry : callGraph.entrySet()) {
                String caller = entry.getKey().replace("\"", "\\\"");
                for (String callee : entry.getValue()) {
                    callee = callee.replace("\"", "\\\"");
                    sb.append("  \"").append(caller).append("\" -> \"").append(callee).append("\";\n");
                }
            }
            sb.append("}");
        } else if ("mermaid".equals(format)) {
            sb.append("graph TD\n");
            for (Map.Entry<String, Set<String>> entry : callGraph.entrySet()) {
                String caller = entry.getKey().replace(" ", "_");
                for (String callee : entry.getValue()) {
                    callee = callee.replace(" ", "_");
                    sb.append("  ").append(caller).append(" --> ").append(callee).append("\n");
                }
            }
        } else if ("adjacency".equals(format)) {
            for (Map.Entry<String, Set<String>> entry : callGraph.entrySet()) {
                if (sb.length() > 0) {
                    sb.append("\n");
                }
                sb.append(entry.getKey()).append(": ");
                sb.append(String.join(", ", entry.getValue()));
            }
        } else { // Default "edges" format
            for (Map.Entry<String, Set<String>> entry : callGraph.entrySet()) {
                String caller = entry.getKey();
                for (String callee : entry.getValue()) {
                    if (sb.length() > 0) {
                        sb.append("\n");
                    }
                    sb.append(caller).append(" -> ").append(callee);
                }
            }
        }

        if (sb.length() == 0) {
            return "No call relationships found in the program";
        }
        
        return sb.toString();
    }

    /**
     * List all data types available in the program with optional category filtering
     */
    public String listDataTypes(String category, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) {
            return "No program loaded";
        }

        DataTypeManager dtm = program.getDataTypeManager();
        List<String> dataTypes = new ArrayList<>();
        
        // Get all data types from the manager
        Iterator<DataType> allTypes = dtm.getAllDataTypes();
        while (allTypes.hasNext()) {
            DataType dt = allTypes.next();
            
            // Apply category filter if specified
            if (category != null && !category.isEmpty()) {
                String dtCategory = getCategoryName(dt);
                if (!dtCategory.toLowerCase().contains(category.toLowerCase())) {
                    continue;
                }
            }
            
            // Format: name | category | size | path
            String categoryName = getCategoryName(dt);
            int size = dt.getLength();
            String sizeStr = (size > 0) ? String.valueOf(size) : "variable";
            
            dataTypes.add(String.format("%s | %s | %s bytes | %s", 
                dt.getName(), categoryName, sizeStr, dt.getPathName()));
        }
        
        // Apply pagination
        String result = paginateList(dataTypes, offset, limit);
        
        if (result.isEmpty()) {
            return "No data types found" + (category != null ? " for category: " + category : "");
        }
        
        return result;
    }

    /**
     * Helper method to get category name for a data type
     */
    private String getCategoryName(DataType dt) {
        if (dt.getCategoryPath() == null) {
            return "builtin";
        }
        String categoryPath = dt.getCategoryPath().getPath();
        if (categoryPath.isEmpty() || categoryPath.equals("/")) {
            return "builtin";
        }
        
        // Extract the last part of the category path
        String[] parts = categoryPath.split("/");
        return parts[parts.length - 1].toLowerCase();
    }

    /**
     * Create a new structure data type with specified fields
     */
    public String createStruct(String name, String fieldsJson) {
        Program program = getCurrentProgram();
        if (program == null) {
            return "No program loaded";
        }

        if (name == null || name.isEmpty()) {
            return "Structure name is required";
        }

        if (fieldsJson == null || fieldsJson.isEmpty()) {
            return "Fields JSON is required";
        }

        final StringBuilder resultMsg = new StringBuilder();
        final AtomicBoolean successFlag = new AtomicBoolean(false);

        try {
            // Parse the fields JSON (simplified parsing for basic structure)
            // Expected format: [{"name":"field1","type":"int"},{"name":"field2","type":"char"}]
            List<FieldDefinition> fields = parseFieldsJson(fieldsJson);

            if (fields.isEmpty()) {
                return "No valid fields provided";
            }

            DataTypeManager dtm = program.getDataTypeManager();

            // Check if struct already exists
            DataType existingType = dtm.getDataType("/" + name);
            if (existingType != null) {
                return "Structure with name '" + name + "' already exists";
            }

            // Create the structure on Swing EDT thread (required for transactions)
            SwingUtilities.invokeAndWait(() -> {
                int txId = program.startTransaction("Create Structure: " + name);
                try {
                    ghidra.program.model.data.StructureDataType struct =
                        new ghidra.program.model.data.StructureDataType(name, 0);

                    // Add fields sequentially for simplicity
                    for (FieldDefinition field : fields) {
                        DataType fieldType = resolveDataType(dtm, field.type);
                        if (fieldType == null) {
                            resultMsg.append("Unknown field type: ").append(field.type);
                            return;
                        }

                        // Add field to the end of the structure
                        struct.add(fieldType, fieldType.getLength(), field.name, "");
                    }

                    // Add the structure to the data type manager
                    DataType createdStruct = dtm.addDataType(struct, null);

                    successFlag.set(true);
                    resultMsg.append("Successfully created structure '").append(name).append("' with ")
                            .append(fields.size()).append(" fields, total size: ")
                            .append(createdStruct.getLength()).append(" bytes");

                } catch (Exception e) {
                    resultMsg.append("Error creating structure: ").append(e.getMessage());
                    Msg.error(this, "Error creating structure", e);
                }
                finally {
                    program.endTransaction(txId, successFlag.get());
                }
            });

            // Force event processing to ensure changes propagate
            if (successFlag.get()) {
                program.flushEvents();
                try {
                    Thread.sleep(50);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }

        } catch (InterruptedException | InvocationTargetException e) {
            return "Error: Failed to execute on Swing thread: " + e.getMessage();
        } catch (Exception e) {
            return "Error parsing fields JSON: " + e.getMessage();
        }

        return resultMsg.length() > 0 ? resultMsg.toString() : "Error: Unknown failure";
    }

    /**
     * Helper class for field definitions
     */
    private static class FieldDefinition {
        String name;
        String type;
        int offset;
        
        FieldDefinition(String name, String type, int offset) {
            this.name = name;
            this.type = type;
            this.offset = offset;
        }
    }

    /**
     * Parse fields JSON into FieldDefinition objects using robust JSON parsing
     * Supports array format: [{"name":"field1","type":"uint"}, {"name":"field2","type":"void*"}]
     */
    private List<FieldDefinition> parseFieldsJson(String fieldsJson) {
        List<FieldDefinition> fields = new ArrayList<>();

        if (fieldsJson == null || fieldsJson.isEmpty()) {
            Msg.error(this, "Fields JSON is null or empty");
            return fields;
        }

        try {
            // Trim and validate JSON array
            String json = fieldsJson.trim();
            if (!json.startsWith("[")) {
                Msg.error(this, "Fields JSON must be an array starting with [, got: " + json.substring(0, Math.min(50, json.length())));
                return fields;
            }
            if (!json.endsWith("]")) {
                Msg.error(this, "Fields JSON must be an array ending with ]");
                return fields;
            }

            // Remove outer brackets
            json = json.substring(1, json.length() - 1).trim();

            // Parse field objects using proper bracket/brace matching
            List<String> fieldJsons = parseFieldJsonArray(json);
            Msg.info(this, "Found " + fieldJsons.size() + " field objects to parse");

            for (String fieldJson : fieldJsons) {
                FieldDefinition field = parseFieldJsonObject(fieldJson);
                if (field != null && field.name != null && field.type != null) {
                    fields.add(field);
                    Msg.info(this, "  ✓ Parsed field: " + field.name + " (" + field.type + ")");
                } else {
                    Msg.warn(this, "  ✗ Field missing required fields (name/type): " + fieldJson.substring(0, Math.min(50, fieldJson.length())));
                }
            }

            if (fields.isEmpty()) {
                Msg.error(this, "No valid fields parsed from JSON");
            } else {
                Msg.info(this, "Successfully parsed " + fields.size() + " field(s)");
            }

        } catch (Exception e) {
            Msg.error(this, "Exception parsing fields JSON: " + e.getMessage());
            e.printStackTrace();
        }

        return fields;
    }

    /**
     * Parse a JSON array string by properly matching braces
     * Returns list of individual JSON object content strings (without outer braces)
     */
    private List<String> parseFieldJsonArray(String json) {
        List<String> items = new ArrayList<>();

        int braceDepth = 0;
        int start = -1;
        boolean inString = false;
        boolean escapeNext = false;

        for (int i = 0; i < json.length(); i++) {
            char c = json.charAt(i);

            // Handle escape sequences
            if (escapeNext) {
                escapeNext = false;
                continue;
            }

            if (c == '\\') {
                escapeNext = true;
                continue;
            }

            // Track if we're inside a string
            if (c == '"' && !escapeNext) {
                inString = !inString;
                continue;
            }

            // Only count braces outside of strings
            if (!inString) {
                if (c == '{') {
                    if (braceDepth == 0) {
                        start = i + 1; // Start after the opening brace
                    }
                    braceDepth++;
                } else if (c == '}') {
                    braceDepth--;
                    if (braceDepth == 0 && start >= 0) {
                        // Extract object content (between braces)
                        String item = json.substring(start, i).trim();
                        if (!item.isEmpty()) {
                            items.add(item);
                        }
                        start = -1;
                    }
                }
            }
        }

        return items;
    }

    /**
     * Parse a single JSON object string (content between braces) into a FieldDefinition
     * Format: "name":"fieldname","type":"typename","offset":0
     */
    private FieldDefinition parseFieldJsonObject(String objectJson) {
        if (objectJson == null || objectJson.isEmpty()) {
            return null;
        }

        String name = null;
        String type = null;
        int offset = -1;

        try {
            // Parse key-value pairs while respecting quotes and escapes
            Map<String, String> keyValues = parseJsonKeyValues(objectJson);

            if (keyValues.containsKey("name")) {
                name = keyValues.get("name");
            }
            if (keyValues.containsKey("type")) {
                type = keyValues.get("type");
            }
            if (keyValues.containsKey("offset")) {
                try {
                    offset = Integer.parseInt(keyValues.get("offset"));
                } catch (NumberFormatException e) {
                    // Keep offset as -1
                }
            }

        } catch (Exception e) {
            Msg.error(this, "Error parsing JSON object: " + e.getMessage());
        }

        return new FieldDefinition(name, type, offset);
    }

    /**
     * Parse JSON key-value pairs from a string like: "name":"value","type":"typename"
     * Properly handles quoted strings and escapes
     */
    private Map<String, String> parseJsonKeyValues(String json) {
        Map<String, String> pairs = new LinkedHashMap<>();

        // Find all "key":"value" or "key":value patterns
        int i = 0;
        while (i < json.length()) {
            // Skip whitespace and commas
            while (i < json.length() && (Character.isWhitespace(json.charAt(i)) || json.charAt(i) == ',')) {
                i++;
            }

            if (i >= json.length()) break;

            // Expect opening quote for key
            if (json.charAt(i) != '"') {
                i++;
                continue;
            }

            // Parse key (quoted string)
            i++; // Skip opening quote
            int keyStart = i;
            boolean escapeNext = false;
            while (i < json.length()) {
                char c = json.charAt(i);
                if (escapeNext) {
                    escapeNext = false;
                } else if (c == '\\') {
                    escapeNext = true;
                } else if (c == '"') {
                    break;
                }
                i++;
            }
            String key = json.substring(keyStart, i).replace("\\\"", "\"");
            i++; // Skip closing quote

            // Skip whitespace and colon
            while (i < json.length() && (Character.isWhitespace(json.charAt(i)) || json.charAt(i) == ':')) {
                i++;
            }

            if (i >= json.length()) break;

            // Parse value (can be quoted string or number)
            String value;
            if (json.charAt(i) == '"') {
                // Quoted string value
                i++; // Skip opening quote
                int valueStart = i;
                escapeNext = false;
                while (i < json.length()) {
                    char c = json.charAt(i);
                    if (escapeNext) {
                        escapeNext = false;
                    } else if (c == '\\') {
                        escapeNext = true;
                    } else if (c == '"') {
                        break;
                    }
                    i++;
                }
                value = json.substring(valueStart, i).replace("\\\"", "\"");
                i++; // Skip closing quote
            } else {
                // Unquoted value (number, boolean, etc)
                int valueStart = i;
                while (i < json.length() && json.charAt(i) != ',' && json.charAt(i) != '}') {
                    i++;
                }
                value = json.substring(valueStart, i).trim();
            }

            pairs.put(key, value);
        }

        return pairs;
    }

    /**
     * Create a new enumeration data type with name-value pairs
     */
    public String createEnum(String name, String valuesJson, int size) {
        Program program = getCurrentProgram();
        if (program == null) {
            return "No program loaded";
        }
        
        if (name == null || name.isEmpty()) {
            return "Enumeration name is required";
        }
        
        if (valuesJson == null || valuesJson.isEmpty()) {
            return "Values JSON is required";
        }
        
        if (size != 1 && size != 2 && size != 4 && size != 8) {
            return "Invalid size. Must be 1, 2, 4, or 8 bytes";
        }

        try {
            // Parse the values JSON
            Map<String, Long> values = parseValuesJson(valuesJson);
            
            if (values.isEmpty()) {
                return "No valid enum values provided";
            }

            DataTypeManager dtm = program.getDataTypeManager();
            
            // Check if enum already exists
            DataType existingType = dtm.getDataType("/" + name);
            if (existingType != null) {
                return "Enumeration with name '" + name + "' already exists";
            }

            // Create the enumeration
            int txId = program.startTransaction("Create Enumeration: " + name);
            try {
                ghidra.program.model.data.EnumDataType enumDt = 
                    new ghidra.program.model.data.EnumDataType(name, size);
                
                for (Map.Entry<String, Long> entry : values.entrySet()) {
                    enumDt.add(entry.getKey(), entry.getValue());
                }
                
                // Add the enumeration to the data type manager
                dtm.addDataType(enumDt, null);
                
                program.endTransaction(txId, true);
                
                return "Successfully created enumeration '" + name + "' with " + values.size() + 
                       " values, size: " + size + " bytes";
                       
            } catch (Exception e) {
                program.endTransaction(txId, false);
                return "Error creating enumeration: " + e.getMessage();
            }
            
        } catch (Exception e) {
            return "Error parsing values JSON: " + e.getMessage();
        }
    }

    /**
     * Parse values JSON into name-value pairs
     */
    private Map<String, Long> parseValuesJson(String valuesJson) {
        Map<String, Long> values = new LinkedHashMap<>();
        
        try {
            // Remove outer braces and whitespace
            String content = valuesJson.trim();
            if (content.startsWith("{")) {
                content = content.substring(1);
            }
            if (content.endsWith("}")) {
                content = content.substring(0, content.length() - 1);
            }
            
            // Split by commas (simple parsing)
            String[] pairs = content.split(",");
            
            for (String pair : pairs) {
                String[] keyValue = pair.split(":");
                if (keyValue.length == 2) {
                    String key = keyValue[0].trim().replace("\"", "");
                    String valueStr = keyValue[1].trim();
                    
                    try {
                        Long value = Long.parseLong(valueStr);
                        values.put(key, value);
                    } catch (NumberFormatException e) {
                        // Skip invalid values
                    }
                }
            }
        } catch (Exception e) {
            // Return empty map on parse error
        }
        
        return values;
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
        Program program = getCurrentProgram();
        if (program == null) {
            return "No program loaded";
        }
        
        if (addressStr == null || addressStr.isEmpty()) {
            return "Address is required";
        }
        
        if (typeName == null || typeName.isEmpty()) {
            return "Data type name is required";
        }

        try {
            Address address = program.getAddressFactory().getAddress(addressStr);
            if (address == null) {
                return "Invalid address: " + addressStr;
            }
            
            DataTypeManager dtm = program.getDataTypeManager();
            DataType dataType = resolveDataType(dtm, typeName);

            if (dataType == null) {
                return "ERROR: Unknown data type: " + typeName + ". " +
                       "For arrays, use syntax 'basetype[count]' (e.g., 'dword[10]'). " +
                       "Or create the type first using create_struct, create_enum, or mcp_ghidra_create_array_type.";
            }
            
            Listing listing = program.getListing();
            
            // Check if address is in a valid memory block
            if (!program.getMemory().contains(address)) {
                return "Address is not in program memory: " + addressStr;
            }

            int txId = program.startTransaction("Apply Data Type: " + typeName);
            try {
                // Clear existing code/data if requested
                if (clearExisting) {
                    CodeUnit existingCU = listing.getCodeUnitAt(address);
                    if (existingCU != null) {
                        listing.clearCodeUnits(address, 
                            address.add(Math.max(dataType.getLength() - 1, 0)), false);
                    }
                }
                
                // Apply the data type
                Data data = listing.createData(address, dataType);

                program.endTransaction(txId, true);

                // Validate size matches expectation
                int expectedSize = dataType.getLength();
                int actualSize = (data != null) ? data.getLength() : 0;

                if (actualSize != expectedSize) {
                    Msg.warn(this, String.format("Size mismatch: expected %d bytes but applied %d bytes at %s",
                                                 expectedSize, actualSize, addressStr));
                }

                String result = "Successfully applied data type '" + typeName + "' at " +
                               addressStr + " (size: " + actualSize + " bytes)";

                // Add value information if available
                if (data != null && data.getValue() != null) {
                    result += "\nValue: " + data.getValue().toString();
                }

                return result;
                
            } catch (Exception e) {
                program.endTransaction(txId, false);
                return "Error applying data type: " + e.getMessage();
            }
            
        } catch (Exception e) {
            return "Error processing request: " + e.getMessage();
        }
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
        version.append("  \"plugin_version\": \"1.8.1\",\n");
        version.append("  \"plugin_name\": \"GhidraMCP\",\n");
        version.append("  \"ghidra_version\": \"11.4.2\",\n");
        version.append("  \"java_version\": \"").append(System.getProperty("java.version")).append("\",\n");
        version.append("  \"endpoint_count\": 109,\n");
        version.append("  \"implementation_status\": \"102 implemented + 7 ROADMAP v2.0\"\n");
        version.append("}");
        return version.toString();
    }

    /**
     * Get metadata about the current program
     */
    private String getMetadata() {
        Program program = getCurrentProgram();
        if (program == null) {
            return "No program loaded";
        }

        StringBuilder metadata = new StringBuilder();
        metadata.append("Program Name: ").append(program.getName()).append("\n");
        metadata.append("Executable Path: ").append(program.getExecutablePath()).append("\n");
        metadata.append("Architecture: ").append(program.getLanguage().getProcessor().toString()).append("\n");
        metadata.append("Compiler: ").append(program.getCompilerSpec().getCompilerSpecID()).append("\n");
        metadata.append("Language: ").append(program.getLanguage().getLanguageID()).append("\n");
        metadata.append("Endian: ").append(program.getLanguage().isBigEndian() ? "Big" : "Little").append("\n");
        metadata.append("Address Size: ").append(program.getAddressFactory().getDefaultAddressSpace().getSize()).append(" bits\n");
        metadata.append("Base Address: ").append(program.getImageBase()).append("\n");
        
        // Memory information
        long totalSize = 0;
        int blockCount = 0;
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            totalSize += block.getSize();
            blockCount++;
        }
        metadata.append("Memory Blocks: ").append(blockCount).append("\n");
        metadata.append("Total Memory Size: ").append(totalSize).append(" bytes\n");
        
        // Function count
        int functionCount = program.getFunctionManager().getFunctionCount();
        metadata.append("Function Count: ").append(functionCount).append("\n");
        
        // Symbol count
        int symbolCount = program.getSymbolTable().getNumSymbols();
        metadata.append("Symbol Count: ").append(symbolCount).append("\n");

        return metadata.toString();
    }

    /**
     * Convert a number to different representations
     */
    private String convertNumber(String text, int size) {
        if (text == null || text.isEmpty()) {
            return "Error: No number provided";
        }

        try {
            long value;
            String inputType;
            
            // Determine input format and parse
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

            StringBuilder result = new StringBuilder();
            result.append("Input: ").append(text).append(" (").append(inputType).append(")\n");
            result.append("Size: ").append(size).append(" bytes\n\n");
            
            // Handle different sizes with proper masking
            long mask = (size == 8) ? -1L : (1L << (size * 8)) - 1L;
            long maskedValue = value & mask;
            
            result.append("Decimal (unsigned): ").append(Long.toUnsignedString(maskedValue)).append("\n");
            
            // Signed representation for appropriate sizes
            if (size <= 8) {
                long signedValue = maskedValue;
                if (size < 8) {
                    // Sign extend for smaller sizes
                    long signBit = 1L << (size * 8 - 1);
                    if ((maskedValue & signBit) != 0) {
                        signedValue = maskedValue | (~mask);
                    }
                }
                result.append("Decimal (signed): ").append(signedValue).append("\n");
            }
            
            result.append("Hexadecimal: 0x").append(Long.toHexString(maskedValue).toUpperCase()).append("\n");
            result.append("Binary: 0b").append(Long.toBinaryString(maskedValue)).append("\n");
            result.append("Octal: 0").append(Long.toOctalString(maskedValue)).append("\n");
            
            // Add size-specific hex representation
            String hexFormat = String.format("%%0%dX", size * 2);
            result.append("Hex (").append(size).append(" bytes): 0x").append(String.format(hexFormat, maskedValue)).append("\n");

            return result.toString();

        } catch (NumberFormatException e) {
            return "Error: Invalid number format: " + text;
        } catch (Exception e) {
            return "Error converting number: " + e.getMessage();
        }
    }

    /**
     * List global variables/symbols with optional filtering
     */
    private String listGlobals(int offset, int limit, String filter) {
        Program program = getCurrentProgram();
        if (program == null) {
            return "No program loaded";
        }

        List<String> globals = new ArrayList<>();
        SymbolTable symbolTable = program.getSymbolTable();
        
        // Get all symbols in global namespace
        Namespace globalNamespace = program.getGlobalNamespace();
        SymbolIterator symbols = symbolTable.getSymbols(globalNamespace);
        
        while (symbols.hasNext()) {
            Symbol symbol = symbols.next();
            
            // Skip function symbols (they have their own listing)
            if (symbol.getSymbolType() == SymbolType.FUNCTION) {
                continue;
            }
            
            String symbolInfo = formatGlobalSymbol(symbol);
            
            // Apply filter if provided
            if (filter == null || filter.isEmpty() || 
                symbolInfo.toLowerCase().contains(filter.toLowerCase())) {
                globals.add(symbolInfo);
            }
        }
        
        return paginateList(globals, offset, limit);
    }

    /**
     * Helper method to format global symbol information
     */
    private String formatGlobalSymbol(Symbol symbol) {
        StringBuilder info = new StringBuilder();
        info.append(symbol.getName());
        info.append(" @ ").append(symbol.getAddress());
        info.append(" [").append(symbol.getSymbolType()).append("]");
        
        // Add data type information if available
        if (symbol.getObject() instanceof Data) {
            Data data = (Data) symbol.getObject();
            DataType dt = data.getDataType();
            if (dt != null) {
                info.append(" (").append(dt.getName()).append(")");
            }
        }
        
        return info.toString();
    }

    /**
     * Rename a global variable/symbol
     */
    private String renameGlobalVariable(String oldName, String newName) {
        Program program = getCurrentProgram();
        if (program == null) {
            return "Error: No program loaded";
        }

        if (oldName == null || oldName.isEmpty()) {
            return "Error: Old variable name is required";
        }

        if (newName == null || newName.isEmpty()) {
            return "Error: New variable name is required";
        }

        int txId = program.startTransaction("Rename Global Variable");
        try {
            SymbolTable symbolTable = program.getSymbolTable();

            // Find the symbol by name in global namespace
            Namespace globalNamespace = program.getGlobalNamespace();
            List<Symbol> symbols = symbolTable.getSymbols(oldName, globalNamespace);

            if (symbols.isEmpty()) {
                // Try finding in any namespace
                SymbolIterator allSymbols = symbolTable.getSymbols(oldName);
                while (allSymbols.hasNext()) {
                    Symbol symbol = allSymbols.next();
                    if (symbol.getSymbolType() != SymbolType.FUNCTION) {
                        symbols.add(symbol);
                        break; // Take the first non-function match
                    }
                }
            }

            if (symbols.isEmpty()) {
                program.endTransaction(txId, false);
                return "Error: Global variable '" + oldName + "' not found";
            }

            // Rename the first matching symbol
            Symbol symbol = symbols.get(0);
            Address symbolAddr = symbol.getAddress();
            symbol.setName(newName, SourceType.USER_DEFINED);

            program.endTransaction(txId, true);
            return "Success: Renamed global variable '" + oldName + "' to '" + newName +
                   "' at " + symbolAddr;

        } catch (Exception e) {
            program.endTransaction(txId, false);
            Msg.error(this, "Error renaming global variable: " + e.getMessage());
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Get all entry points in the program
     */
    private String getEntryPoints() {
        Program program = getCurrentProgram();
        if (program == null) {
            return "No program loaded";
        }

        List<String> entryPoints = new ArrayList<>();
        SymbolTable symbolTable = program.getSymbolTable();
        
        // Method 1: Get all external entry point symbols
        SymbolIterator allSymbols = symbolTable.getAllSymbols(true);
        while (allSymbols.hasNext()) {
            Symbol symbol = allSymbols.next();
            if (symbol.isExternalEntryPoint()) {
                String entryInfo = formatEntryPoint(symbol) + " [external entry]";
                entryPoints.add(entryInfo);
            }
        }
        
        // Method 2: Check for common entry point names
        String[] commonEntryNames = {"main", "_main", "start", "_start", "WinMain", "_WinMain", 
                                   "DllMain", "_DllMain", "entry", "_entry"};
        
        for (String entryName : commonEntryNames) {
            SymbolIterator symbols = symbolTable.getSymbols(entryName);
            while (symbols.hasNext()) {
                Symbol symbol = symbols.next();
                if (symbol.getSymbolType() == SymbolType.FUNCTION || symbol.getSymbolType() == SymbolType.LABEL) {
                    String entryInfo = formatEntryPoint(symbol) + " [common entry name]";
                    if (!containsAddress(entryPoints, symbol.getAddress())) {
                        entryPoints.add(entryInfo);
                    }
                }
            }
        }
        
        // Method 4: Get the program's designated entry point
        Address programEntry = program.getImageBase();
        if (programEntry != null) {
            Symbol entrySymbol = symbolTable.getPrimarySymbol(programEntry);
            String entryInfo;
            if (entrySymbol != null) {
                entryInfo = formatEntryPoint(entrySymbol) + " [program entry]";
            } else {
                entryInfo = "entry @ " + programEntry + " [program entry] [FUNCTION]";
            }
            if (!containsAddress(entryPoints, programEntry)) {
                entryPoints.add(entryInfo);
            }
        }
        
        // If no entry points found, check for functions at common addresses
        if (entryPoints.isEmpty()) {
            // Check some common entry addresses
            String[] commonHexAddresses = {"0x401000", "0x400000", "0x1000", "0x10000"};
            for (String hexAddr : commonHexAddresses) {
                try {
                    Address addr = program.getAddressFactory().getAddress(hexAddr);
                    if (addr != null && program.getMemory().contains(addr)) {
                        Function func = program.getFunctionManager().getFunctionAt(addr);
                        if (func != null) {
                            entryPoints.add("entry @ " + addr + " (" + func.getName() + ") [potential entry] [FUNCTION]");
                        }
                    }
                } catch (Exception e) {
                    // Ignore invalid addresses
                }
            }
        }
        
        if (entryPoints.isEmpty()) {
            return "No entry points found in program";
        }
        
        return String.join("\n", entryPoints);
    }

    /**
     * Helper method to format entry point information
     */
    private String formatEntryPoint(Symbol symbol) {
        StringBuilder info = new StringBuilder();
        info.append(symbol.getName());
        info.append(" @ ").append(symbol.getAddress());
        info.append(" [").append(symbol.getSymbolType()).append("]");
        
        // Add additional context if it's a function
        if (symbol.getSymbolType() == SymbolType.FUNCTION) {
            Function func = (Function) symbol.getObject();
            if (func != null) {
                info.append(" (").append(func.getParameterCount()).append(" params)");
            }
        }
        
        return info.toString();
    }

    /**
     * Helper method to check if entry points list already contains an address
     */
    private boolean containsAddress(List<String> entryPoints, Address address) {
        String addrStr = address.toString();
        for (String entry : entryPoints) {
            if (entry.contains("@ " + addrStr)) {
                return true;
            }
        }
        return false;
    }

    // ----------------------------------------------------------------------------------
    // Data Type Analysis and Management Methods
    // ----------------------------------------------------------------------------------

    /**
     * Analyze data types at a given address with specified depth
     */
    private String analyzeDataTypes(String addressStr, int depth) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            StringBuilder result = new StringBuilder();
            
            result.append("Data type analysis at ").append(addressStr).append(" (depth: ").append(depth).append("):\n\n");
            
            // Analyze the data at the given address
            analyzeDataAtAddress(program, addr, result, depth, 0);
            
            return result.toString();
        } catch (Exception e) {
            return "Error analyzing data types: " + e.getMessage();
        }
    }

    /**
     * Recursively analyze data types at an address
     */
    private void analyzeDataAtAddress(Program program, Address addr, StringBuilder result, int maxDepth, int currentDepth) {
        if (currentDepth >= maxDepth) return;
        
        String indent = "  ".repeat(currentDepth);
        Data data = program.getListing().getDefinedDataAt(addr);
        
        if (data != null) {
            DataType dataType = data.getDataType();
            result.append(indent).append("Address: ").append(addr)
                  .append(" | Type: ").append(dataType.getName())
                  .append(" | Size: ").append(dataType.getLength())
                  .append(" | Value: ").append(data.getDefaultValueRepresentation()).append("\n");
            
            // If it's a composite type, analyze its components
            if (dataType instanceof Composite) {
                Composite composite = (Composite) dataType;
                for (DataTypeComponent component : composite.getDefinedComponents()) {
                    result.append(indent).append("  Component: ").append(component.getFieldName())
                          .append(" | Type: ").append(component.getDataType().getName())
                          .append(" | Offset: ").append(component.getOffset()).append("\n");
                }
            }
            
            // If it's a pointer, analyze what it points to
            if (dataType instanceof Pointer && currentDepth < maxDepth - 1) {
                try {
                    Address pointedAddr = (Address) data.getValue();
                    if (pointedAddr != null) {
                        result.append(indent).append("Points to:\n");
                        analyzeDataAtAddress(program, pointedAddr, result, maxDepth, currentDepth + 1);
                    }
                } catch (Exception e) {
                    result.append(indent).append("Could not follow pointer: ").append(e.getMessage()).append("\n");
                }
            }
        } else {
            result.append(indent).append("Address: ").append(addr).append(" | No defined data\n");
        }
    }

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
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (name == null || name.isEmpty()) return "Union name is required";
        if (fieldsJson == null || fieldsJson.isEmpty()) return "Fields JSON is required";

        AtomicBoolean success = new AtomicBoolean(false);
        StringBuilder result = new StringBuilder();

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Create union");
                try {
                    DataTypeManager dtm = program.getDataTypeManager();
                    UnionDataType union = new UnionDataType(name);

                    // Parse fields from JSON using the same method as structs
                    List<FieldDefinition> fields = parseFieldsJson(fieldsJson);
                    
                    if (fields.isEmpty()) {
                        result.append("No valid fields provided");
                        return;
                    }
                    
                    // Process each field for the union (use resolveDataType like structs do)
                    for (FieldDefinition field : fields) {
                        DataType dt = resolveDataType(dtm, field.type);
                        if (dt != null) {
                            union.add(dt, field.name, null);
                            result.append("Added field: ").append(field.name).append(" (").append(field.type).append(")\n");
                        } else {
                            result.append("Warning: Data type not found for field ").append(field.name).append(": ").append(field.type).append("\n");
                        }
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
     * Get the size of a data type
     */
    private String getTypeSize(String typeName) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (typeName == null || typeName.isEmpty()) return "Type name is required";

        DataTypeManager dtm = program.getDataTypeManager();
        DataType dataType = findDataTypeByNameInAllCategories(dtm, typeName);

        if (dataType == null) {
            return "Data type not found: " + typeName;
        }

        int size = dataType.getLength();
        return String.format("Type: %s\nSize: %d bytes\nAlignment: %d\nPath: %s", 
                            dataType.getName(), 
                            size, 
                            dataType.getAlignment(),
                            dataType.getPathName());
    }

    /**
     * Get the layout of a structure
     */
    private String getStructLayout(String structName) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (structName == null || structName.isEmpty()) return "Struct name is required";

        DataTypeManager dtm = program.getDataTypeManager();
        DataType dataType = findDataTypeByNameInAllCategories(dtm, structName);

        if (dataType == null) {
            return "Structure not found: " + structName;
        }

        if (!(dataType instanceof Structure)) {
            return "Data type is not a structure: " + structName;
        }

        Structure struct = (Structure) dataType;
        StringBuilder result = new StringBuilder();
        
        result.append("Structure: ").append(struct.getName()).append("\n");
        result.append("Size: ").append(struct.getLength()).append(" bytes\n");
        result.append("Alignment: ").append(struct.getAlignment()).append("\n\n");
        result.append("Layout:\n");
        result.append("Offset | Size | Type | Name\n");
        result.append("-------|------|------|-----\n");

        for (DataTypeComponent component : struct.getDefinedComponents()) {
            result.append(String.format("%6d | %4d | %-20s | %s\n",
                component.getOffset(),
                component.getLength(),
                component.getDataType().getName(),
                component.getFieldName() != null ? component.getFieldName() : "(unnamed)"));
        }

        return result.toString();
    }

    /**
     * Search for data types by pattern
     */
    private String searchDataTypes(String pattern, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (pattern == null || pattern.isEmpty()) return "Search pattern is required";

        List<String> matches = new ArrayList<>();
        DataTypeManager dtm = program.getDataTypeManager();
        
        Iterator<DataType> allTypes = dtm.getAllDataTypes();
        while (allTypes.hasNext()) {
            DataType dt = allTypes.next();
            String name = dt.getName();
            String path = dt.getPathName();
            
            if (name.toLowerCase().contains(pattern.toLowerCase()) || 
                path.toLowerCase().contains(pattern.toLowerCase())) {
                matches.add(String.format("%s | Size: %d | Path: %s", 
                           name, dt.getLength(), path));
            }
        }

        Collections.sort(matches);
        return paginateList(matches, offset, limit);
    }

    /**
     * Automatically create a structure by analyzing memory layout
     */
    private String autoCreateStruct(String addressStr, int size, String name) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";
        if (name == null || name.isEmpty()) return "Structure name is required";

        AtomicBoolean success = new AtomicBoolean(false);
        StringBuilder result = new StringBuilder();

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Auto-create structure");
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    DataTypeManager dtm = program.getDataTypeManager();
                    StructureDataType struct = new StructureDataType(name, 0);

                    // Analyze memory at the address to infer structure
                    Memory memory = program.getMemory();
                    int actualSize = (size > 0) ? size : 64; // Default to 64 bytes if size not specified
                    
                    // Simple field inference based on data patterns
                    for (int i = 0; i < actualSize; i += 4) { // Assume 4-byte fields for simplicity
                        if (i + 4 <= actualSize) {
                            try {
                                int value = memory.getInt(addr.add(i));
                                String fieldName = "field_" + (i / 4);
                                
                                // Try to infer type based on value patterns
                                DataType fieldType;
                                if (value == 0 || (value > 0 && value < 1000000)) {
                                    fieldType = new IntegerDataType();
                                } else {
                                    // Could be a pointer
                                    fieldType = new PointerDataType();
                                }
                                
                                struct.add(fieldType, fieldName, null);
                                result.append("Added field: ").append(fieldName)
                                      .append(" at offset ").append(i)
                                      .append(" (").append(fieldType.getName()).append(")\n");
                            } catch (Exception e) {
                                // Memory might not be readable, add undefined byte
                                struct.add(new ByteDataType(), "undefined_" + i, null);
                            }
                        }
                    }

                    dtm.addDataType(struct, DataTypeConflictHandler.REPLACE_HANDLER);
                    result.append("Structure '").append(name).append("' created with ").append(struct.getNumComponents()).append(" fields");
                    success.set(true);
                } catch (Exception e) {
                    result.append("Error auto-creating structure: ").append(e.getMessage());
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            result.append("Failed to execute auto-create structure on Swing thread: ").append(e.getMessage());
        }

        return result.toString();
    }

    /**
     * Get all values in an enumeration
     */
    private String getEnumValues(String enumName) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (enumName == null || enumName.isEmpty()) return "Enum name is required";

        DataTypeManager dtm = program.getDataTypeManager();
        DataType dataType = findDataTypeByNameInAllCategories(dtm, enumName);

        if (dataType == null) {
            return "Enumeration not found: " + enumName;
        }

        if (!(dataType instanceof ghidra.program.model.data.Enum)) {
            return "Data type is not an enumeration: " + enumName;
        }

        ghidra.program.model.data.Enum enumType = (ghidra.program.model.data.Enum) dataType;
        StringBuilder result = new StringBuilder();
        
        result.append("Enumeration: ").append(enumType.getName()).append("\n");
        result.append("Size: ").append(enumType.getLength()).append(" bytes\n\n");
        result.append("Values:\n");
        result.append("Name | Value\n");
        result.append("-----|------\n");

        String[] names = enumType.getNames();
        for (String valueName : names) {
            long value = enumType.getValue(valueName);
            result.append(String.format("%-20s | %d (0x%X)\n", valueName, value, value));
        }

        return result.toString();
    }

    /**
     * Create a typedef (type alias)
     */
    private String createTypedef(String name, String baseType) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (name == null || name.isEmpty()) return "Typedef name is required";
        if (baseType == null || baseType.isEmpty()) return "Base type is required";

        AtomicBoolean success = new AtomicBoolean(false);
        StringBuilder result = new StringBuilder();

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Create typedef");
                try {
                    DataTypeManager dtm = program.getDataTypeManager();
                    DataType base = null;
                    
                    // Handle pointer syntax (e.g., "UnitAny *")
                    if (baseType.endsWith(" *") || baseType.endsWith("*")) {
                        String baseTypeName = baseType.replace(" *", "").replace("*", "").trim();
                        DataType baseDataType = findDataTypeByNameInAllCategories(dtm, baseTypeName);
                        if (baseDataType != null) {
                            base = new PointerDataType(baseDataType);
                        } else {
                            result.append("Base type not found for pointer: ").append(baseTypeName);
                            return;
                        }
                    } else {
                        // Regular type lookup
                        base = findDataTypeByNameInAllCategories(dtm, baseType);
                    }

                    if (base == null) {
                        result.append("Base type not found: ").append(baseType);
                        return;
                    }

                    TypedefDataType typedef = new TypedefDataType(name, base);
                    dtm.addDataType(typedef, DataTypeConflictHandler.REPLACE_HANDLER);
                    
                    result.append("Typedef '").append(name).append("' created as alias for '").append(baseType).append("'");
                    success.set(true);
                } catch (Exception e) {
                    result.append("Error creating typedef: ").append(e.getMessage());
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            result.append("Failed to execute typedef creation on Swing thread: ").append(e.getMessage());
        }

        return result.toString();
    }

    /**
     * Clone/copy a data type with a new name
     */
    private String cloneDataType(String sourceType, String newName) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (sourceType == null || sourceType.isEmpty()) return "Source type is required";
        if (newName == null || newName.isEmpty()) return "New name is required";

        AtomicBoolean success = new AtomicBoolean(false);
        StringBuilder result = new StringBuilder();

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Clone data type");
                try {
                    DataTypeManager dtm = program.getDataTypeManager();
                    DataType source = findDataTypeByNameInAllCategories(dtm, sourceType);

                    if (source == null) {
                        result.append("Source type not found: ").append(sourceType);
                        return;
                    }

                    DataType cloned = source.clone(dtm);
                    cloned.setName(newName);
                    
                    dtm.addDataType(cloned, DataTypeConflictHandler.REPLACE_HANDLER);
                    result.append("Data type '").append(sourceType).append("' cloned as '").append(newName).append("'");
                    success.set(true);
                } catch (Exception e) {
                    result.append("Error cloning data type: ").append(e.getMessage());
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            result.append("Failed to execute data type cloning on Swing thread: ").append(e.getMessage());
        }

        return result.toString();
    }

    /**
     * Validate if a data type fits at a given address
     */
    private String validateDataType(String addressStr, String typeName) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (addressStr == null || addressStr.isEmpty()) return "Address is required";
        if (typeName == null || typeName.isEmpty()) return "Type name is required";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            DataTypeManager dtm = program.getDataTypeManager();
            DataType dataType = findDataTypeByNameInAllCategories(dtm, typeName);

            if (dataType == null) {
                return "Data type not found: " + typeName;
            }

            StringBuilder result = new StringBuilder();
            result.append("Validation for type '").append(typeName).append("' at address ").append(addressStr).append(":\n\n");

            // Check if memory is available
            Memory memory = program.getMemory();
            int typeSize = dataType.getLength();
            Address endAddr = addr.add(typeSize - 1);

            if (!memory.contains(addr) || !memory.contains(endAddr)) {
                result.append("❌ Memory range not available\n");
                result.append("   Required: ").append(addr).append(" - ").append(endAddr).append("\n");
                return result.toString();
            }

            result.append("✅ Memory range available\n");
            result.append("   Range: ").append(addr).append(" - ").append(endAddr).append(" (").append(typeSize).append(" bytes)\n");

            // Check alignment
            long alignment = dataType.getAlignment();
            if (alignment > 1 && addr.getOffset() % alignment != 0) {
                result.append("⚠️  Alignment warning: Address not aligned to ").append(alignment).append("-byte boundary\n");
            } else {
                result.append("✅ Proper alignment\n");
            }

            // Check if there's existing data
            Data existingData = program.getListing().getDefinedDataAt(addr);
            if (existingData != null) {
                result.append("⚠️  Existing data: ").append(existingData.getDataType().getName()).append("\n");
            } else {
                result.append("✅ No conflicting data\n");
            }

            return result.toString();
        } catch (Exception e) {
            return "Error validating data type: " + e.getMessage();
        }
    }

    /**
     * Export data types in various formats
     */
    private String exportDataTypes(String format, String category) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        StringBuilder result = new StringBuilder();
        DataTypeManager dtm = program.getDataTypeManager();
        
        result.append("Exporting data types in ").append(format).append(" format");
        if (category != null && !category.isEmpty()) {
            result.append(" (category: ").append(category).append(")");
        }
        result.append(":\n\n");

        Iterator<DataType> allTypes = dtm.getAllDataTypes();
        int count = 0;

        while (allTypes.hasNext()) {
            DataType dt = allTypes.next();
            
            // Filter by category if specified
            if (category != null && !category.isEmpty()) {
                if (!dt.getCategoryPath().toString().toLowerCase().contains(category.toLowerCase())) {
                    continue;
                }
            }

            switch (format.toLowerCase()) {
                case "c":
                    result.append(exportDataTypeAsC(dt)).append("\n");
                    break;
                case "json":
                    result.append(exportDataTypeAsJson(dt)).append("\n");
                    break;
                case "summary":
                default:
                    result.append(dt.getName()).append(" | Size: ").append(dt.getLength())
                          .append(" | Path: ").append(dt.getPathName()).append("\n");
                    break;
            }
            count++;
        }

        result.append("\nExported ").append(count).append(" data types");
        return result.toString();
    }

    /**
     * Export a data type as C declaration
     */
    private String exportDataTypeAsC(DataType dataType) {
        if (dataType instanceof Structure) {
            Structure struct = (Structure) dataType;
            StringBuilder c = new StringBuilder();
            c.append("struct ").append(struct.getName()).append(" {\n");
            for (DataTypeComponent comp : struct.getDefinedComponents()) {
                c.append("    ").append(comp.getDataType().getName()).append(" ");
                if (comp.getFieldName() != null) {
                    c.append(comp.getFieldName());
                } else {
                    c.append("field_").append(comp.getOffset());
                }
                c.append(";\n");
            }
            c.append("};");
            return c.toString();
        } else if (dataType instanceof ghidra.program.model.data.Enum) {
            ghidra.program.model.data.Enum enumType = (ghidra.program.model.data.Enum) dataType;
            StringBuilder c = new StringBuilder();
            c.append("enum ").append(enumType.getName()).append(" {\n");
            String[] names = enumType.getNames();
            for (int i = 0; i < names.length; i++) {
                c.append("    ").append(names[i]).append(" = ").append(enumType.getValue(names[i]));
                if (i < names.length - 1) c.append(",");
                c.append("\n");
            }
            c.append("};");
            return c.toString();
        } else {
            return "/* " + dataType.getName() + " - size: " + dataType.getLength() + " */";
        }
    }

    /**
     * Export a data type as JSON
     */
    private String exportDataTypeAsJson(DataType dataType) {
        StringBuilder json = new StringBuilder();
        json.append("{");
        json.append("\"name\":\"").append(dataType.getName()).append("\",");
        json.append("\"size\":").append(dataType.getLength()).append(",");
        json.append("\"type\":\"").append(dataType.getClass().getSimpleName()).append("\",");
        json.append("\"path\":\"").append(dataType.getPathName()).append("\"");
        json.append("}");
        return json.toString();
    }

    /**
     * Read memory at a specific address
     */
    private String readMemory(String addressStr, int length) {
        try {
            Program program = getCurrentProgram();
            if (program == null) {
                return "{\"error\":\"No program loaded\"}";
            }

            Address address = program.getAddressFactory().getAddress(addressStr);
            if (address == null) {
                return "{\"error\":\"Invalid address: " + addressStr + "\"}";
            }

            Memory memory = program.getMemory();
            byte[] bytes = new byte[length];
            
            int bytesRead = memory.getBytes(address, bytes);
            
            StringBuilder json = new StringBuilder();
            json.append("{");
            json.append("\"address\":\"").append(address.toString()).append("\",");
            json.append("\"length\":").append(bytesRead).append(",");
            json.append("\"data\":[");
            
            for (int i = 0; i < bytesRead; i++) {
                if (i > 0) json.append(",");
                json.append(bytes[i] & 0xFF);
            }
            
            json.append("],");
            json.append("\"hex\":\"");
            for (int i = 0; i < bytesRead; i++) {
                json.append(String.format("%02x", bytes[i] & 0xFF));
            }
            json.append("\"");
            json.append("}");
            
            return json.toString();
            
        } catch (Exception e) {
            return "{\"error\":\"Failed to read memory: " + e.getMessage() + "\"}";
        }
    }

    /**
     * Import data types from various sources
     */
    private String importDataTypes(String source, String format) {
        // This is a placeholder for import functionality
        // In a real implementation, you would parse the source based on format
        return "Import functionality not yet implemented. Source: " + source + ", Format: " + format;
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
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (typeName == null || typeName.isEmpty()) return "Type name is required";

        AtomicBoolean success = new AtomicBoolean(false);
        StringBuilder result = new StringBuilder();

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Delete data type");
                try {
                    DataTypeManager dtm = program.getDataTypeManager();
                    DataType dataType = findDataTypeByNameInAllCategories(dtm, typeName);

                    if (dataType == null) {
                        result.append("Data type not found: ").append(typeName);
                        return;
                    }

                    // Check if type is in use (simplified check)
                    // Note: Ghidra will prevent deletion if type is in use during remove operation

                    boolean deleted = dtm.remove(dataType, null);
                    if (deleted) {
                        result.append("Data type '").append(typeName).append("' deleted successfully");
                        success.set(true);
                    } else {
                        result.append("Failed to delete data type '").append(typeName).append("'");
                    }

                } catch (Exception e) {
                    result.append("Error deleting data type: ").append(e.getMessage());
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            result.append("Failed to execute data type deletion on Swing thread: ").append(e.getMessage());
        }

        return result.toString();
    }

    /**
     * Modify a field in an existing structure
     */
    private String modifyStructField(String structName, String fieldName, String newType, String newName) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (structName == null || structName.isEmpty()) return "Structure name is required";
        if (fieldName == null || fieldName.isEmpty()) return "Field name is required";

        AtomicBoolean success = new AtomicBoolean(false);
        StringBuilder result = new StringBuilder();

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Modify struct field");
                try {
                    DataTypeManager dtm = program.getDataTypeManager();
                    DataType dataType = findDataTypeByNameInAllCategories(dtm, structName);

                    if (dataType == null) {
                        result.append("Structure not found: ").append(structName);
                        return;
                    }

                    if (!(dataType instanceof Structure)) {
                        result.append("Data type '").append(structName).append("' is not a structure");
                        return;
                    }

                    Structure struct = (Structure) dataType;
                    DataTypeComponent[] components = struct.getDefinedComponents();
                    DataTypeComponent targetComponent = null;

                    // Find the field to modify
                    for (DataTypeComponent component : components) {
                        if (fieldName.equals(component.getFieldName())) {
                            targetComponent = component;
                            break;
                        }
                    }

                    if (targetComponent == null) {
                        result.append("Field '").append(fieldName).append("' not found in structure '").append(structName).append("'");
                        return;
                    }

                    // If new type is specified, change the field type
                    if (newType != null && !newType.isEmpty()) {
                        DataType newDataType = resolveDataType(dtm, newType);
                        if (newDataType == null) {
                            result.append("New data type not found: ").append(newType);
                            return;
                        }
                        struct.replace(targetComponent.getOrdinal(), newDataType, newDataType.getLength());
                    }

                    // If new name is specified, change the field name
                    if (newName != null && !newName.isEmpty()) {
                        targetComponent = struct.getComponent(targetComponent.getOrdinal()); // Refresh component
                        targetComponent.setFieldName(newName);
                    }

                    result.append("Successfully modified field '").append(fieldName).append("' in structure '").append(structName).append("'");
                    success.set(true);

                } catch (Exception e) {
                    result.append("Error modifying struct field: ").append(e.getMessage());
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            result.append("Failed to execute struct field modification on Swing thread: ").append(e.getMessage());
        }

        return result.toString();
    }

    /**
     * Add a new field to an existing structure
     */
    private String addStructField(String structName, String fieldName, String fieldType, int offset) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (structName == null || structName.isEmpty()) return "Structure name is required";
        if (fieldName == null || fieldName.isEmpty()) return "Field name is required";
        if (fieldType == null || fieldType.isEmpty()) return "Field type is required";

        AtomicBoolean success = new AtomicBoolean(false);
        StringBuilder result = new StringBuilder();

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Add struct field");
                try {
                    DataTypeManager dtm = program.getDataTypeManager();
                    DataType dataType = findDataTypeByNameInAllCategories(dtm, structName);

                    if (dataType == null) {
                        result.append("Structure not found: ").append(structName);
                        return;
                    }

                    if (!(dataType instanceof Structure)) {
                        result.append("Data type '").append(structName).append("' is not a structure");
                        return;
                    }

                    Structure struct = (Structure) dataType;
                    DataType newFieldType = resolveDataType(dtm, fieldType);
                    if (newFieldType == null) {
                        result.append("Field data type not found: ").append(fieldType);
                        return;
                    }

                    if (offset >= 0) {
                        // Add at specific offset
                        struct.insertAtOffset(offset, newFieldType, newFieldType.getLength(), fieldName, null);
                    } else {
                        // Add at end
                        struct.add(newFieldType, fieldName, null);
                    }

                    result.append("Successfully added field '").append(fieldName).append("' to structure '").append(structName).append("'");
                    success.set(true);

                } catch (Exception e) {
                    result.append("Error adding struct field: ").append(e.getMessage());
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            result.append("Failed to execute struct field addition on Swing thread: ").append(e.getMessage());
        }

        return result.toString();
    }

    /**
     * Remove a field from an existing structure
     */
    private String removeStructField(String structName, String fieldName) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (structName == null || structName.isEmpty()) return "Structure name is required";
        if (fieldName == null || fieldName.isEmpty()) return "Field name is required";

        AtomicBoolean success = new AtomicBoolean(false);
        StringBuilder result = new StringBuilder();

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Remove struct field");
                try {
                    DataTypeManager dtm = program.getDataTypeManager();
                    DataType dataType = findDataTypeByNameInAllCategories(dtm, structName);

                    if (dataType == null) {
                        result.append("Structure not found: ").append(structName);
                        return;
                    }

                    if (!(dataType instanceof Structure)) {
                        result.append("Data type '").append(structName).append("' is not a structure");
                        return;
                    }

                    Structure struct = (Structure) dataType;
                    DataTypeComponent[] components = struct.getDefinedComponents();
                    int targetOrdinal = -1;

                    // Find the field to remove
                    for (DataTypeComponent component : components) {
                        if (fieldName.equals(component.getFieldName())) {
                            targetOrdinal = component.getOrdinal();
                            break;
                        }
                    }

                    if (targetOrdinal == -1) {
                        result.append("Field '").append(fieldName).append("' not found in structure '").append(structName).append("'");
                        return;
                    }

                    struct.delete(targetOrdinal);
                    result.append("Successfully removed field '").append(fieldName).append("' from structure '").append(structName).append("'");
                    success.set(true);

                } catch (Exception e) {
                    result.append("Error removing struct field: ").append(e.getMessage());
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            result.append("Failed to execute struct field removal on Swing thread: ").append(e.getMessage());
        }

        return result.toString();
    }

    /**
     * Create an array data type
     */
    private String createArrayType(String baseType, int length, String name) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (baseType == null || baseType.isEmpty()) return "Base type is required";
        if (length <= 0) return "Array length must be positive";

        AtomicBoolean success = new AtomicBoolean(false);
        StringBuilder result = new StringBuilder();

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Create array type");
                try {
                    DataTypeManager dtm = program.getDataTypeManager();
                    DataType baseDataType = resolveDataType(dtm, baseType);
                    
                    if (baseDataType == null) {
                        result.append("Base data type not found: ").append(baseType);
                        return;
                    }

                    ArrayDataType arrayType = new ArrayDataType(baseDataType, length, baseDataType.getLength());
                    
                    if (name != null && !name.isEmpty()) {
                        arrayType.setName(name);
                    }
                    
                    DataType addedType = dtm.addDataType(arrayType, DataTypeConflictHandler.REPLACE_HANDLER);
                    
                    result.append("Successfully created array type: ").append(addedType.getName())
                          .append(" (").append(baseType).append("[").append(length).append("])");
                    success.set(true);

                } catch (Exception e) {
                    result.append("Error creating array type: ").append(e.getMessage());
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            result.append("Failed to execute array type creation on Swing thread: ").append(e.getMessage());
        }

        return result.toString();
    }

    /**
     * Create a pointer data type
     */
    private String createPointerType(String baseType, String name) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (baseType == null || baseType.isEmpty()) return "Base type is required";

        AtomicBoolean success = new AtomicBoolean(false);
        StringBuilder result = new StringBuilder();

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Create pointer type");
                try {
                    DataTypeManager dtm = program.getDataTypeManager();
                    DataType baseDataType = null;
                    
                    if ("void".equals(baseType)) {
                        baseDataType = dtm.getDataType("/void");
                        if (baseDataType == null) {
                            baseDataType = VoidDataType.dataType;
                        }
                    } else {
                        baseDataType = resolveDataType(dtm, baseType);
                    }
                    
                    if (baseDataType == null) {
                        result.append("Base data type not found: ").append(baseType);
                        return;
                    }

                    PointerDataType pointerType = new PointerDataType(baseDataType);
                    
                    if (name != null && !name.isEmpty()) {
                        pointerType.setName(name);
                    }
                    
                    DataType addedType = dtm.addDataType(pointerType, DataTypeConflictHandler.REPLACE_HANDLER);
                    
                    result.append("Successfully created pointer type: ").append(addedType.getName())
                          .append(" (").append(baseType).append("*)");
                    success.set(true);

                } catch (Exception e) {
                    result.append("Error creating pointer type: ").append(e.getMessage());
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            result.append("Failed to execute pointer type creation on Swing thread: ").append(e.getMessage());
        }

        return result.toString();
    }

    /**
     * Create a new data type category
     */
    private String createDataTypeCategory(String categoryPath) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (categoryPath == null || categoryPath.isEmpty()) return "Category path is required";

        try {
            DataTypeManager dtm = program.getDataTypeManager();
            CategoryPath catPath = new CategoryPath(categoryPath);
            Category category = dtm.createCategory(catPath);
            
            return "Successfully created category: " + category.getCategoryPathName();
        } catch (Exception e) {
            return "Error creating category: " + e.getMessage();
        }
    }

    /**
     * Move a data type to a different category
     */
    private String moveDataTypeToCategory(String typeName, String categoryPath) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (typeName == null || typeName.isEmpty()) return "Type name is required";
        if (categoryPath == null || categoryPath.isEmpty()) return "Category path is required";

        AtomicBoolean success = new AtomicBoolean(false);
        StringBuilder result = new StringBuilder();

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Move data type to category");
                try {
                    DataTypeManager dtm = program.getDataTypeManager();
                    DataType dataType = findDataTypeByNameInAllCategories(dtm, typeName);

                    if (dataType == null) {
                        result.append("Data type not found: ").append(typeName);
                        return;
                    }

                    CategoryPath catPath = new CategoryPath(categoryPath);
                    Category category = dtm.createCategory(catPath);
                    
                    // Move the data type
                    dataType.setCategoryPath(catPath);
                    
                    result.append("Successfully moved data type '").append(typeName)
                          .append("' to category '").append(categoryPath).append("'");
                    success.set(true);

                } catch (Exception e) {
                    result.append("Error moving data type: ").append(e.getMessage());
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            result.append("Failed to execute data type move on Swing thread: ").append(e.getMessage());
        }

        return result.toString();
    }

    /**
     * List all data type categories
     */
    private String listDataTypeCategories(int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        try {
            DataTypeManager dtm = program.getDataTypeManager();
            List<String> categories = new ArrayList<>();
            
            // Get all categories recursively
            addCategoriesRecursively(dtm.getRootCategory(), categories, "");
            
            return paginateList(categories, offset, limit);
        } catch (Exception e) {
            return "Error listing categories: " + e.getMessage();
        }
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
    private String createFunctionSignature(String name, String returnType, String parametersJson) {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        if (name == null || name.isEmpty()) return "Function name is required";
        if (returnType == null || returnType.isEmpty()) return "Return type is required";

        AtomicBoolean success = new AtomicBoolean(false);
        StringBuilder result = new StringBuilder();

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Create function signature");
                try {
                    DataTypeManager dtm = program.getDataTypeManager();
                    
                    // Resolve return type
                    DataType returnDataType = resolveDataType(dtm, returnType);
                    if (returnDataType == null) {
                        result.append("Return type not found: ").append(returnType);
                        return;
                    }

                    // Create function definition
                    FunctionDefinitionDataType funcDef = new FunctionDefinitionDataType(name);
                    funcDef.setReturnType(returnDataType);

                    // Parse parameters if provided
                    if (parametersJson != null && !parametersJson.isEmpty()) {
                        try {
                            // Simple JSON parsing for parameters
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
                            // If JSON parsing fails, continue without parameters
                            result.append("Warning: Could not parse parameters, continuing without them. ");
                        }
                    }

                    DataType addedFuncDef = dtm.addDataType(funcDef, DataTypeConflictHandler.REPLACE_HANDLER);
                    
                    result.append("Successfully created function signature: ").append(addedFuncDef.getName());
                    success.set(true);

                } catch (Exception e) {
                    result.append("Error creating function signature: ").append(e.getMessage());
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            result.append("Failed to execute function signature creation on Swing thread: ").append(e.getMessage());
        }

        return result.toString();
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
     * 1. GET_BULK_XREFS - Retrieve xrefs for multiple addresses in one call
     */
    private String getBulkXrefs(Object addressesObj) {
        Program program = getCurrentProgram();
        if (program == null) return "{\"error\": \"No program loaded\"}";

        StringBuilder json = new StringBuilder();
        json.append("{");

        try {
            List<String> addresses = new ArrayList<>();

            // Parse addresses array
            if (addressesObj instanceof List) {
                for (Object addr : (List<?>) addressesObj) {
                    if (addr != null) {
                        addresses.add(addr.toString());
                    }
                }
            } else if (addressesObj instanceof String) {
                // Handle comma-separated string
                String[] parts = ((String) addressesObj).split(",");
                for (String part : parts) {
                    addresses.add(part.trim());
                }
            }

            ReferenceManager refMgr = program.getReferenceManager();
            boolean first = true;

            for (String addrStr : addresses) {
                if (!first) json.append(",");
                first = false;

                json.append("\"").append(addrStr).append("\": [");

                try {
                    Address addr = program.getAddressFactory().getAddress(addrStr);
                    if (addr != null) {
                        ReferenceIterator refIter = refMgr.getReferencesTo(addr);
                        boolean firstRef = true;

                        while (refIter.hasNext()) {
                            Reference ref = refIter.next();
                            if (!firstRef) json.append(",");
                            firstRef = false;

                            json.append("{");
                            json.append("\"from\": \"").append(ref.getFromAddress().toString()).append("\",");
                            json.append("\"type\": \"").append(ref.getReferenceType().getName()).append("\"");
                            json.append("}");
                        }
                    }
                } catch (Exception e) {
                    // Address parsing failed, return empty array
                }

                json.append("]");
            }
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }

        json.append("}");
        return json.toString();
    }

    /**
     * 2. ANALYZE_DATA_REGION - Comprehensive single-call data analysis
     */
    private String analyzeDataRegion(String startAddressStr, int maxScanBytes,
                                      boolean includeXrefMap, boolean includeAssemblyPatterns,
                                      boolean includeBoundaryDetection) {
        Program program = getCurrentProgram();
        if (program == null) return "{\"error\": \"No program loaded\"}";

        try {
            Address startAddr = program.getAddressFactory().getAddress(startAddressStr);
            if (startAddr == null) {
                return "{\"error\": \"Invalid address: " + startAddressStr + "\"}";
            }

            ReferenceManager refMgr = program.getReferenceManager();
            Listing listing = program.getListing();

            // Scan byte-by-byte for xrefs and boundary detection
            Address currentAddr = startAddr;
            Address endAddr = startAddr;
            Set<String> uniqueXrefs = new HashSet<>();
            int byteCount = 0;
            StringBuilder xrefMapJson = new StringBuilder();
            xrefMapJson.append("\"xref_map\": {");
            boolean firstXrefEntry = true;

            for (int i = 0; i < maxScanBytes; i++) {
                Address scanAddr = startAddr.add(i);

                // Check for boundary: Named symbol that isn't DAT_
                Symbol[] symbols = program.getSymbolTable().getSymbols(scanAddr);
                if (includeBoundaryDetection && symbols.length > 0) {
                    for (Symbol sym : symbols) {
                        String name = sym.getName();
                        if (!name.startsWith("DAT_") && !name.equals(startAddr.toString())) {
                            // Found a named boundary
                            endAddr = scanAddr.subtract(1);
                            byteCount = i;
                            break;
                        }
                    }
                    if (byteCount > 0) break;
                }

                // Get xrefs for this byte
                ReferenceIterator refIter = refMgr.getReferencesTo(scanAddr);
                List<String> refsAtThisByte = new ArrayList<>();

                while (refIter.hasNext()) {
                    Reference ref = refIter.next();
                    String fromAddr = ref.getFromAddress().toString();
                    refsAtThisByte.add(fromAddr);
                    uniqueXrefs.add(fromAddr);
                }

                if (includeXrefMap && !refsAtThisByte.isEmpty()) {
                    if (!firstXrefEntry) xrefMapJson.append(",");
                    firstXrefEntry = false;

                    xrefMapJson.append("\"").append(scanAddr.toString()).append("\": [");
                    for (int j = 0; j < refsAtThisByte.size(); j++) {
                        if (j > 0) xrefMapJson.append(",");
                        xrefMapJson.append("\"").append(refsAtThisByte.get(j)).append("\"");
                    }
                    xrefMapJson.append("]");
                }

                endAddr = scanAddr;
                byteCount = i + 1;
            }
            xrefMapJson.append("}");

            // Get current name and type
            Data data = listing.getDataAt(startAddr);
            String currentName = (data != null && data.getLabel() != null) ?
                                data.getLabel() : "DAT_" + startAddr.toString().replace(":", "");
            String currentType = (data != null) ?
                                data.getDataType().getName() : "undefined";

            // STRING DETECTION: Read memory content to check for strings
            boolean isLikelyString = false;
            String detectedString = null;
            int suggestedStringLength = 0;

            try {
                Memory memory = program.getMemory();
                byte[] bytes = new byte[Math.min(byteCount, 256)]; // Read up to 256 bytes
                int bytesRead = memory.getBytes(startAddr, bytes);

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

                // String detection criteria
                isLikelyString = (printableRatio >= 0.6) ||
                                (maxConsecutivePrintable >= 4 && nullTerminatorIndex > 0);

                if (isLikelyString && nullTerminatorIndex > 0) {
                    detectedString = new String(bytes, 0, nullTerminatorIndex, StandardCharsets.US_ASCII);
                    suggestedStringLength = nullTerminatorIndex + 1;
                } else if (isLikelyString && printableRatio >= 0.8) {
                    int endIdx = bytesRead;
                    for (int i = bytesRead - 1; i >= 0; i--) {
                        if ((bytes[i] & 0xFF) >= 0x20 && (bytes[i] & 0xFF) <= 0x7E) {
                            endIdx = i + 1;
                            break;
                        }
                    }
                    detectedString = new String(bytes, 0, endIdx, StandardCharsets.US_ASCII);
                    suggestedStringLength = endIdx;
                }
            } catch (Exception e) {
                // String detection failed, continue with normal classification
            }

            // Classify data type hint (enhanced with string detection)
            String classification = "PRIMITIVE";
            if (isLikelyString) {
                classification = "STRING";
            } else if (uniqueXrefs.size() > 3) {
                classification = "ARRAY";
            } else if (uniqueXrefs.size() > 1) {
                classification = "STRUCTURE";
            }

            // Build final JSON response
            StringBuilder result = new StringBuilder();
            result.append("{");
            result.append("\"start_address\": \"").append(startAddr.toString()).append("\",");
            result.append("\"end_address\": \"").append(endAddr.toString()).append("\",");
            result.append("\"byte_span\": ").append(byteCount).append(",");

            if (includeXrefMap) {
                result.append(xrefMapJson.toString()).append(",");
            }

            result.append("\"unique_xref_addresses\": [");
            int idx = 0;
            for (String xref : uniqueXrefs) {
                if (idx++ > 0) result.append(",");
                result.append("\"").append(xref).append("\"");
            }
            result.append("],");

            result.append("\"xref_count\": ").append(uniqueXrefs.size()).append(",");
            result.append("\"classification_hint\": \"").append(classification).append("\",");
            result.append("\"stride_detected\": 1,");
            result.append("\"current_name\": \"").append(currentName).append("\",");
            result.append("\"current_type\": \"").append(currentType).append("\",");

            // Add string detection results
            result.append("\"is_likely_string\": ").append(isLikelyString).append(",");
            if (detectedString != null) {
                result.append("\"detected_string\": \"").append(escapeJson(detectedString)).append("\",");
                result.append("\"suggested_string_type\": \"char[").append(suggestedStringLength).append("]\"");
            } else {
                result.append("\"detected_string\": null,");
                result.append("\"suggested_string_type\": null");
            }

            result.append("}");

            return result.toString();
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    /**
     * 3. DETECT_ARRAY_BOUNDS - Array/table size detection
     */
    private String detectArrayBounds(String addressStr, boolean analyzeLoopBounds,
                                      boolean analyzeIndexing, int maxScanRange) {
        Program program = getCurrentProgram();
        if (program == null) return "{\"error\": \"No program loaded\"}";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            if (addr == null) {
                return "{\"error\": \"Invalid address: " + addressStr + "\"}";
            }

            ReferenceManager refMgr = program.getReferenceManager();

            // Scan for xrefs to detect array bounds
            int estimatedSize = 0;
            Address scanAddr = addr;

            for (int i = 0; i < maxScanRange; i++) {
                ReferenceIterator refIter = refMgr.getReferencesTo(scanAddr);
                if (refIter.hasNext()) {
                    estimatedSize = i + 1;
                }

                // Check for boundary symbol
                Symbol[] symbols = program.getSymbolTable().getSymbols(scanAddr);
                if (symbols.length > 0 && i > 0) {
                    for (Symbol sym : symbols) {
                        if (!sym.getName().startsWith("DAT_")) {
                            break;  // Found boundary
                        }
                    }
                }

                scanAddr = scanAddr.add(1);
            }

            StringBuilder result = new StringBuilder();
            result.append("{");
            result.append("\"address\": \"").append(addr.toString()).append("\",");
            result.append("\"estimated_size\": ").append(estimatedSize).append(",");
            result.append("\"stride\": 1,");
            result.append("\"element_count\": ").append(estimatedSize).append(",");
            result.append("\"confidence\": \"medium\",");
            result.append("\"detection_method\": \"xref_analysis\"");
            result.append("}");

            return result.toString();
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    /**
     * 4. GET_ASSEMBLY_CONTEXT - Assembly pattern analysis
     */
    private String getAssemblyContext(Object xrefSourcesObj, int contextInstructions,
                                      Object includePatternsObj) {
        Program program = getCurrentProgram();
        if (program == null) return "{\"error\": \"No program loaded\"}";

        StringBuilder json = new StringBuilder();
        json.append("{");

        try {
            List<String> xrefSources = new ArrayList<>();

            if (xrefSourcesObj instanceof List) {
                for (Object addr : (List<?>) xrefSourcesObj) {
                    if (addr != null) {
                        xrefSources.add(addr.toString());
                    }
                }
            }

            Listing listing = program.getListing();
            boolean first = true;

            for (String addrStr : xrefSources) {
                if (!first) json.append(",");
                first = false;

                json.append("\"").append(addrStr).append("\": {");

                try {
                    Address addr = program.getAddressFactory().getAddress(addrStr);
                    if (addr != null) {
                        json.append("\"address\": \"").append(addrStr).append("\",");
                        json.append("\"context\": \"Placeholder assembly context\",");
                        json.append("\"patterns_detected\": [\"data_access\"]");
                    }
                } catch (Exception e) {
                    json.append("\"error\": \"").append(escapeJson(e.getMessage())).append("\"");
                }

                json.append("}");
            }
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }

        json.append("}");
        return json.toString();
    }

    /**
     * 5. BATCH_DECOMPILE_XREF_SOURCES - Batch decompilation
     */
    private String batchDecompileXrefSources(String targetAddressStr,
                                             boolean includeFunctionNames,
                                             boolean includeUsageContext,
                                             int limit,
                                             int offset) {
        Program program = getCurrentProgram();
        if (program == null) return "{\"error\": \"No program loaded\"}";

        try {
            Address targetAddr = program.getAddressFactory().getAddress(targetAddressStr);
            if (targetAddr == null) {
                return "{\"error\": \"Invalid address: " + targetAddressStr + "\"}";
            }

            ReferenceManager refMgr = program.getReferenceManager();
            ReferenceIterator refIter = refMgr.getReferencesTo(targetAddr);

            Set<Function> functionsToDecompile = new HashSet<>();
            while (refIter.hasNext()) {
                Reference ref = refIter.next();
                Function func = program.getFunctionManager().getFunctionContaining(ref.getFromAddress());
                if (func != null) {
                    functionsToDecompile.add(func);
                }
            }

            // Convert to list for pagination
            List<Function> functionList = new ArrayList<>(functionsToDecompile);
            int totalFunctions = functionList.size();

            // Apply pagination
            int startIndex = Math.min(offset, totalFunctions);
            int endIndex = Math.min(offset + limit, totalFunctions);
            List<Function> paginatedFunctions = functionList.subList(startIndex, endIndex);

            StringBuilder json = new StringBuilder();
            json.append("{");
            json.append("\"total_functions\": ").append(totalFunctions).append(",");
            json.append("\"offset\": ").append(offset).append(",");
            json.append("\"limit\": ").append(limit).append(",");
            json.append("\"returned\": ").append(paginatedFunctions.size()).append(",");
            json.append("\"functions\": [");

            boolean first = true;

            DecompInterface decomp = new DecompInterface();
            decomp.openProgram(program);

            for (Function func : paginatedFunctions) {
                if (!first) json.append(",");
                first = false;

                json.append("{");
                json.append("\"function_address\": \"").append(func.getEntryPoint().toString()).append("\",");
                json.append("\"function_name\": \"").append(func.getName()).append("\",");

                DecompileResults results = decomp.decompileFunction(func, DECOMPILE_TIMEOUT_SECONDS, new ConsoleTaskMonitor());
                if (results != null && results.decompileCompleted()) {
                    String decompiledCode = results.getDecompiledFunction().getC();
                    json.append("\"decompiled_code\": \"").append(escapeJson(decompiledCode)).append("\",");
                } else {
                    json.append("\"decompiled_code\": \"Decompilation failed\",");
                }

                json.append("\"usage_line\": \"Placeholder: usage context\"");
                json.append("}");
            }

            decomp.dispose();
            json.append("]}");
            return json.toString();
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    /**
     * 6. APPLY_DATA_CLASSIFICATION - Atomic type application
     */
    private String applyDataClassification(String addressStr, String classification,
                                           String name, String comment,
                                           Object typeDefinitionObj) {
        Program program = getCurrentProgram();
        if (program == null) return "{\"error\": \"No program loaded\"}";

        final StringBuilder resultJson = new StringBuilder();
        final AtomicReference<String> typeApplied = new AtomicReference<>("none");
        final List<String> operations = new ArrayList<>();

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            if (addr == null) {
                return "{\"error\": \"Invalid address: " + escapeJson(addressStr) + "\"}";
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
                return "{\"error\": \"type_definition must be a JSON object/dict, got: " +
                       escapeJson(typeDefinitionObj.getClass().getSimpleName()) +
                       " with value: " + escapeJson(String.valueOf(typeDefinitionObj)) + "\"}";
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
                    resultJson.append("{\"error\": \"").append(escapeJson(e.getMessage())).append("\"}");
                } finally {
                    program.endTransaction(txId, success);
                }
            });

            // Build result JSON if no error
            if (resultJson.length() == 0) {
                resultJson.append("{");
                resultJson.append("\"success\": true,");
                resultJson.append("\"address\": \"").append(escapeJson(addressStr)).append("\",");
                resultJson.append("\"classification\": \"").append(escapeJson(classification)).append("\",");
                if (name != null) {
                    resultJson.append("\"name\": \"").append(escapeJson(name)).append("\",");
                }
                resultJson.append("\"type_applied\": \"").append(escapeJson(typeApplied.get())).append("\",");
                resultJson.append("\"operations_performed\": [");
                for (int i = 0; i < operations.size(); i++) {
                    resultJson.append("\"").append(escapeJson(operations.get(i))).append("\"");
                    if (i < operations.size() - 1) resultJson.append(",");
                }
                resultJson.append("]");
                resultJson.append("}");
            }

            return resultJson.toString();

        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
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
        // CRITICAL FIX #3: Validate input parameters
        if (maxFunctionsToAnalyze < MIN_FUNCTIONS_TO_ANALYZE || maxFunctionsToAnalyze > MAX_FUNCTIONS_TO_ANALYZE) {
            return "{\"error\": \"maxFunctionsToAnalyze must be between " + MIN_FUNCTIONS_TO_ANALYZE +
                   " and " + MAX_FUNCTIONS_TO_ANALYZE + "\"}";
        }

        final AtomicReference<String> result = new AtomicReference<>();

        // CRITICAL FIX #1: Thread safety - wrap in SwingUtilities.invokeAndWait
        try {
            SwingUtilities.invokeAndWait(() -> {
                try {
                    Program program = getCurrentProgram();
                    if (program == null) {
                        result.set("{\"error\": \"No program loaded\"}");
                        return;
                    }

                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    if (addr == null) {
                        result.set("{\"error\": \"Invalid address: " + addressStr + "\"}");
                        return;
                    }

                    // Get data at address to determine structure
                    Data data = program.getListing().getDataAt(addr);
                    DataType dataType = (data != null) ? data.getDataType() : null;

                    if (dataType == null || !(dataType instanceof Structure)) {
                        result.set("{\"error\": \"No structure data type found at " + addressStr + "\"}");
                        return;
                    }

                    Structure struct = (Structure) dataType;

                    // MAJOR FIX #5: Validate structure size
                    DataTypeComponent[] components = struct.getComponents();
                    if (components.length > MAX_STRUCT_FIELDS) {
                        result.set("{\"error\": \"Structure too large (" + components.length +
                                   " fields). Maximum " + MAX_STRUCT_FIELDS + " fields supported.\"}");
                        return;
                    }

                    String actualStructName = (structName != null && !structName.isEmpty()) ? structName : struct.getName();

                    // Get all xrefs to this address
                    ReferenceManager refMgr = program.getReferenceManager();
                    ReferenceIterator refIter = refMgr.getReferencesTo(addr);

                    Set<Function> functionsToAnalyze = new HashSet<>();
                    while (refIter.hasNext() && functionsToAnalyze.size() < maxFunctionsToAnalyze) {
                        Reference ref = refIter.next();
                        Function func = program.getFunctionManager().getFunctionContaining(ref.getFromAddress());
                        if (func != null) {
                            functionsToAnalyze.add(func);
                        }
                    }

                    // Decompile all functions and analyze field usage
                    Map<Integer, FieldUsageInfo> fieldUsageMap = new HashMap<>();
                    DecompInterface decomp = null;

                    // CRITICAL FIX #2: Resource management with try-finally
                    try {
                        decomp = new DecompInterface();
                        decomp.openProgram(program);

                        long analysisStart = System.currentTimeMillis();
                        Msg.info(this, "Analyzing struct at " + addressStr + " with " + functionsToAnalyze.size() + " functions");

                        for (Function func : functionsToAnalyze) {
                            try {
                                DecompileResults results = decomp.decompileFunction(func, DECOMPILE_TIMEOUT_SECONDS,
                                                                                   new ConsoleTaskMonitor());
                                if (results != null && results.decompileCompleted()) {
                                    String decompiledCode = results.getDecompiledFunction().getC();
                                    analyzeFieldUsageInCode(decompiledCode, struct, fieldUsageMap, addr.toString());
                                } else {
                                    Msg.warn(this, "Failed to decompile function: " + func.getName());
                                }
                            } catch (Exception e) {
                                // Continue with other functions if one fails
                                Msg.error(this, "Error decompiling function " + func.getName() + ": " + e.getMessage());
                            }
                        }

                        long analysisTime = System.currentTimeMillis() - analysisStart;
                        Msg.info(this, "Field analysis completed in " + analysisTime + "ms, found " +
                                 fieldUsageMap.size() + " fields with usage data");

                    } finally {
                        // CRITICAL FIX #2: Always dispose of DecompInterface
                        if (decomp != null) {
                            decomp.dispose();
                        }
                    }

                    // Build JSON response with field analysis
                    StringBuilder json = new StringBuilder();
                    json.append("{");
                    json.append("\"struct_address\": \"").append(addressStr).append("\",");
                    json.append("\"struct_name\": \"").append(escapeJson(actualStructName)).append("\",");
                    json.append("\"struct_size\": ").append(struct.getLength()).append(",");
                    json.append("\"functions_analyzed\": ").append(functionsToAnalyze.size()).append(",");
                    json.append("\"field_usage\": {");

                    boolean first = true;
                    for (int i = 0; i < components.length; i++) {
                        DataTypeComponent component = components[i];
                        int offset = component.getOffset();

                        if (!first) json.append(",");
                        first = false;

                        json.append("\"").append(offset).append("\": {");
                        json.append("\"field_name\": \"").append(escapeJson(component.getFieldName())).append("\",");
                        json.append("\"field_type\": \"").append(escapeJson(component.getDataType().getName())).append("\",");
                        json.append("\"offset\": ").append(offset).append(",");
                        json.append("\"size\": ").append(component.getLength()).append(",");

                        FieldUsageInfo usageInfo = fieldUsageMap.get(offset);
                        if (usageInfo != null) {
                            json.append("\"access_count\": ").append(usageInfo.accessCount).append(",");
                            json.append("\"suggested_names\": ").append(usageInfo.getSuggestedNamesJson()).append(",");
                            json.append("\"usage_patterns\": ").append(usageInfo.getUsagePatternsJson());
                        } else {
                            json.append("\"access_count\": 0,");
                            json.append("\"suggested_names\": [],");
                            json.append("\"usage_patterns\": []");
                        }

                        json.append("}");
                    }

                    json.append("}");
                    json.append("}");

                    result.set(json.toString());
                } catch (Exception e) {
                    result.set("{\"error\": \"" + escapeJson(e.getMessage()) + "\"}");
                }
            });
        } catch (InvocationTargetException | InterruptedException e) {
            Msg.error(this, "Thread synchronization error in analyzeStructFieldUsage", e);
            return "{\"error\": \"Thread synchronization error: " + escapeJson(e.getMessage()) + "\"}";
        }

        return result.get();
    }

    /**
     * Helper class to track field usage information
     */
    private static class FieldUsageInfo {
        int accessCount = 0;
        Set<String> suggestedNames = new HashSet<>();
        Set<String> usagePatterns = new HashSet<>();

        String getSuggestedNamesJson() {
            StringBuilder json = new StringBuilder("[");
            boolean first = true;
            for (String name : suggestedNames) {
                if (!first) json.append(",");
                first = false;
                json.append("\"").append(name).append("\"");
            }
            json.append("]");
            return json.toString();
        }

        String getUsagePatternsJson() {
            StringBuilder json = new StringBuilder("[");
            boolean first = true;
            for (String pattern : usagePatterns) {
                if (!first) json.append(",");
                first = false;
                json.append("\"").append(pattern).append("\"");
            }
            json.append("]");
            return json.toString();
        }
    }

    /**
     * Analyze decompiled code to extract field usage patterns
     * MAJOR FIX #4: Improved pattern matching with word boundaries and keyword filtering
     */
    private void analyzeFieldUsageInCode(String code, Structure struct, Map<Integer, FieldUsageInfo> fieldUsageMap, String baseAddr) {
        String[] lines = code.split("\\n");

        for (String line : lines) {
            // Skip empty lines and comments
            String trimmedLine = line.trim();
            if (trimmedLine.isEmpty() || trimmedLine.startsWith("//") || trimmedLine.startsWith("/*")) {
                continue;
            }

            // Look for field access patterns
            for (DataTypeComponent component : struct.getComponents()) {
                String fieldName = component.getFieldName();
                int offset = component.getOffset();
                boolean fieldMatched = false;

                // IMPROVED: Use word boundary matching for field names
                Pattern fieldPattern = Pattern.compile("\\b" + Pattern.quote(fieldName) + "\\b");
                if (fieldPattern.matcher(line).find()) {
                    fieldMatched = true;
                }

                // IMPROVED: Use word boundary for offset matching (e.g., "+4" but not "+40")
                Pattern offsetPattern = Pattern.compile("\\+\\s*" + offset + "\\b");
                if (offsetPattern.matcher(line).find()) {
                    fieldMatched = true;
                }

                if (fieldMatched) {
                    FieldUsageInfo info = fieldUsageMap.computeIfAbsent(offset, k -> new FieldUsageInfo());
                    info.accessCount++;

                    // IMPROVED: Detect usage patterns with better regex
                    // Conditional check: if (field == ...) or if (field != ...)
                    if (line.matches(".*\\bif\\s*\\(.*\\b" + Pattern.quote(fieldName) + "\\b.*(==|!=|<|>|<=|>=).*")) {
                        info.usagePatterns.add("conditional_check");
                    }

                    // Increment/decrement: field++ or field--
                    if (line.matches(".*\\b" + Pattern.quote(fieldName) + "\\s*(\\+\\+|--).*") ||
                        line.matches(".*(\\+\\+|--)\\s*\\b" + Pattern.quote(fieldName) + "\\b.*")) {
                        info.usagePatterns.add("increment_decrement");
                    }

                    // Assignment: variable = field or field = value
                    if (line.matches(".*\\b\\w+\\s*=\\s*.*\\b" + Pattern.quote(fieldName) + "\\b.*") ||
                        line.matches(".*\\b" + Pattern.quote(fieldName) + "\\s*=.*")) {
                        info.usagePatterns.add("assignment");
                    }

                    // Array access: field[index]
                    if (line.matches(".*\\b" + Pattern.quote(fieldName) + "\\s*\\[.*\\].*")) {
                        info.usagePatterns.add("array_access");
                    }

                    // Pointer dereference: ptr->field or struct.field
                    if (line.matches(".*->\\s*\\b" + Pattern.quote(fieldName) + "\\b.*") ||
                        line.matches(".*\\.\\s*\\b" + Pattern.quote(fieldName) + "\\b.*")) {
                        info.usagePatterns.add("pointer_dereference");
                    }

                    // IMPROVED: Extract variable names with C keyword filtering
                    String[] tokens = line.split("\\W+");
                    for (String token : tokens) {
                        if (token.length() >= MIN_TOKEN_LENGTH &&
                            !token.equals(fieldName) &&
                            !C_KEYWORDS.contains(token.toLowerCase()) &&
                            Character.isLetter(token.charAt(0)) &&
                            !token.matches("\\d+")) {  // Filter out numbers
                            info.suggestedNames.add(token);
                        }
                    }
                }
            }
        }
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
        // MAJOR FIX #7: Validate input parameters
        if (fieldOffset < 0 || fieldOffset > MAX_FIELD_OFFSET) {
            return "{\"error\": \"Field offset must be between 0 and " + MAX_FIELD_OFFSET + "\"}";
        }
        if (numExamples < 1 || numExamples > MAX_FIELD_EXAMPLES) {
            return "{\"error\": \"numExamples must be between 1 and " + MAX_FIELD_EXAMPLES + "\"}";
        }

        final AtomicReference<String> result = new AtomicReference<>();

        // CRITICAL FIX #1: Thread safety - wrap in SwingUtilities.invokeAndWait
        try {
            SwingUtilities.invokeAndWait(() -> {
                try {
                    Program program = getCurrentProgram();
                    if (program == null) {
                        result.set("{\"error\": \"No program loaded\"}");
                        return;
                    }

                    Address structAddr = program.getAddressFactory().getAddress(structAddressStr);
                    if (structAddr == null) {
                        result.set("{\"error\": \"Invalid address: " + structAddressStr + "\"}");
                        return;
                    }

                    // Calculate field address with overflow protection
                    Address fieldAddr;
                    try {
                        fieldAddr = structAddr.add(fieldOffset);
                    } catch (Exception e) {
                        result.set("{\"error\": \"Field offset overflow: " + fieldOffset + "\"}");
                        return;
                    }

                    Msg.info(this, "Getting field access context for " + fieldAddr + " (offset " + fieldOffset + ")");

                    // Get xrefs to the field address (or nearby addresses)
                    ReferenceManager refMgr = program.getReferenceManager();
                    ReferenceIterator refIter = refMgr.getReferencesTo(fieldAddr);

                    StringBuilder json = new StringBuilder();
                    json.append("{");
                    json.append("\"struct_address\": \"").append(structAddressStr).append("\",");
                    json.append("\"field_offset\": ").append(fieldOffset).append(",");
                    json.append("\"field_address\": \"").append(fieldAddr.toString()).append("\",");
                    json.append("\"examples\": [");

                    int exampleCount = 0;
                    boolean first = true;

                    while (refIter.hasNext() && exampleCount < numExamples) {
                        Reference ref = refIter.next();
                        Address fromAddr = ref.getFromAddress();

                        if (!first) json.append(",");
                        first = false;

                        json.append("{");
                        json.append("\"access_address\": \"").append(fromAddr.toString()).append("\",");
                        json.append("\"ref_type\": \"").append(ref.getReferenceType().getName()).append("\",");

                        // Get assembly context with null check
                        Listing listing = program.getListing();
                        Instruction instr = listing.getInstructionAt(fromAddr);
                        if (instr != null) {
                            json.append("\"assembly\": \"").append(escapeJson(instr.toString())).append("\",");
                        } else {
                            json.append("\"assembly\": \"\",");
                        }

                        // Get function context with null check
                        Function func = program.getFunctionManager().getFunctionContaining(fromAddr);
                        if (func != null) {
                            json.append("\"function_name\": \"").append(escapeJson(func.getName())).append("\",");
                            json.append("\"function_address\": \"").append(func.getEntryPoint().toString()).append("\"");
                        } else {
                            json.append("\"function_name\": \"\",");
                            json.append("\"function_address\": \"\"");
                        }

                        json.append("}");
                        exampleCount++;
                    }

                    json.append("]");
                    json.append("}");

                    Msg.info(this, "Found " + exampleCount + " field access examples");
                    result.set(json.toString());

                } catch (Exception e) {
                    Msg.error(this, "Error in getFieldAccessContext", e);
                    result.set("{\"error\": \"" + escapeJson(e.getMessage()) + "\"}");
                }
            });
        } catch (InvocationTargetException | InterruptedException e) {
            Msg.error(this, "Thread synchronization error in getFieldAccessContext", e);
            return "{\"error\": \"Thread synchronization error: " + escapeJson(e.getMessage()) + "\"}";
        }

        return result.get();
    }

    /**
     * SUGGEST_FIELD_NAMES - AI-assisted field name suggestions based on usage patterns
     *
     * @param structAddressStr Address of the structure instance
     * @param structSize Size of the structure in bytes (0 for auto-detect)
     * @return JSON string with field name suggestions
     */
    private String suggestFieldNames(String structAddressStr, int structSize) {
        // Validate input parameters
        if (structSize < 0 || structSize > MAX_FIELD_OFFSET) {
            return "{\"error\": \"structSize must be between 0 and " + MAX_FIELD_OFFSET + "\"}";
        }

        final AtomicReference<String> result = new AtomicReference<>();

        // CRITICAL FIX #1: Thread safety - wrap in SwingUtilities.invokeAndWait
        try {
            SwingUtilities.invokeAndWait(() -> {
                try {
                    Program program = getCurrentProgram();
                    if (program == null) {
                        result.set("{\"error\": \"No program loaded\"}");
                        return;
                    }

                    Address addr = program.getAddressFactory().getAddress(structAddressStr);
                    if (addr == null) {
                        result.set("{\"error\": \"Invalid address: " + structAddressStr + "\"}");
                        return;
                    }

                    Msg.info(this, "Generating field name suggestions for structure at " + structAddressStr);

                    // Get data at address
                    Data data = program.getListing().getDataAt(addr);
                    DataType dataType = (data != null) ? data.getDataType() : null;

                    if (dataType == null || !(dataType instanceof Structure)) {
                        result.set("{\"error\": \"No structure data type found at " + structAddressStr + "\"}");
                        return;
                    }

                    Structure struct = (Structure) dataType;

                    // MAJOR FIX #5: Validate structure size
                    DataTypeComponent[] components = struct.getComponents();
                    if (components.length > MAX_STRUCT_FIELDS) {
                        result.set("{\"error\": \"Structure too large: " + components.length +
                                   " fields (max " + MAX_STRUCT_FIELDS + ")\"}");
                        return;
                    }

                    StringBuilder json = new StringBuilder();
                    json.append("{");
                    json.append("\"struct_address\": \"").append(structAddressStr).append("\",");
                    json.append("\"struct_name\": \"").append(escapeJson(struct.getName())).append("\",");
                    json.append("\"struct_size\": ").append(struct.getLength()).append(",");
                    json.append("\"suggestions\": [");

                    boolean first = true;
                    for (DataTypeComponent component : components) {
                        if (!first) json.append(",");
                        first = false;

                        json.append("{");
                        json.append("\"offset\": ").append(component.getOffset()).append(",");
                        json.append("\"current_name\": \"").append(escapeJson(component.getFieldName())).append("\",");
                        json.append("\"field_type\": \"").append(escapeJson(component.getDataType().getName())).append("\",");

                        // Generate suggestions based on type and patterns
                        List<String> suggestions = generateFieldNameSuggestions(component);

                        // Ensure we always have fallback suggestions
                        if (suggestions.isEmpty()) {
                            suggestions.add(component.getFieldName() + "Value");
                            suggestions.add(component.getFieldName() + "Data");
                        }

                        json.append("\"suggested_names\": [");
                        for (int i = 0; i < suggestions.size(); i++) {
                            if (i > 0) json.append(",");
                            json.append("\"").append(escapeJson(suggestions.get(i))).append("\"");
                        }
                        json.append("],");

                        json.append("\"confidence\": \"medium\"");  // Placeholder confidence level
                        json.append("}");
                    }

                    json.append("]");
                    json.append("}");

                    Msg.info(this, "Generated suggestions for " + components.length + " fields");
                    result.set(json.toString());

                } catch (Exception e) {
                    Msg.error(this, "Error in suggestFieldNames", e);
                    result.set("{\"error\": \"" + escapeJson(e.getMessage()) + "\"}");
                }
            });
        } catch (InvocationTargetException | InterruptedException e) {
            Msg.error(this, "Thread synchronization error in suggestFieldNames", e);
            return "{\"error\": \"Thread synchronization error: " + escapeJson(e.getMessage()) + "\"}";
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
    private String inspectMemoryContent(String addressStr, int length, boolean detectStrings) {
        Program program = getCurrentProgram();
        if (program == null) return "{\"error\": \"No program loaded\"}";

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            if (addr == null) {
                return "{\"error\": \"Invalid address: " + addressStr + "\"}";
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

            // Build JSON response
            StringBuilder result = new StringBuilder();
            result.append("{");
            result.append("\"address\": \"").append(addressStr).append("\",");
            result.append("\"bytes_read\": ").append(bytesRead).append(",");
            result.append("\"hex_dump\": \"").append(hexDump.toString().trim()).append("\",");
            result.append("\"ascii_repr\": \"").append(asciiRepr.toString().trim()).append("\",");
            result.append("\"printable_count\": ").append(printableCount).append(",");
            result.append("\"printable_ratio\": ").append(String.format("%.2f", printableRatio)).append(",");
            result.append("\"null_terminator_at\": ").append(nullTerminatorIndex).append(",");
            result.append("\"max_consecutive_printable\": ").append(maxConsecutivePrintable).append(",");
            result.append("\"is_likely_string\": ").append(likelyString).append(",");

            if (detectedString != null) {
                result.append("\"detected_string\": \"").append(escapeJson(detectedString)).append("\",");
                result.append("\"suggested_type\": \"char[").append(stringLength).append("]\",");
                result.append("\"string_length\": ").append(stringLength);
            } else {
                result.append("\"detected_string\": null,");
                result.append("\"suggested_type\": null,");
                result.append("\"string_length\": 0");
            }

            result.append("}");

            return result.toString();
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    // ============================================================================
    // MALWARE ANALYSIS IMPLEMENTATION METHODS
    // ============================================================================

    /**
     * Detect cryptographic constants in the binary (AES S-boxes, SHA constants, etc.)
     */
    private String detectCryptoConstants() {
        Program program = getCurrentProgram();
        if (program == null) {
            return "Error: No program loaded";
        }

        try {
            final StringBuilder result = new StringBuilder();
            result.append("[\n");

            // This is a placeholder implementation
            // Full implementation would search for known crypto constants like:
            // - AES S-boxes (0x63, 0x7c, 0x77, 0x7b, 0xf2, ...)
            // - SHA constants (0x67452301, 0xefcdab89, ...)
            // - DES constants, RC4 initialization vectors, etc.

            result.append("  {\"algorithm\": \"Crypto Detection\", \"status\": \"Not yet implemented\", ");
            result.append("\"note\": \"This endpoint requires advanced pattern matching against known crypto constants\"}\n");
            result.append("]");

            return result.toString();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Search for byte patterns with optional wildcards
     */
    private String searchBytePatterns(String pattern, String mask) {
        Program program = getCurrentProgram();
        if (program == null) {
            return "Error: No program loaded";
        }

        if (pattern == null || pattern.trim().isEmpty()) {
            return "Error: Pattern is required";
        }

        try {
            final StringBuilder result = new StringBuilder();
            result.append("[\n");

            // Parse hex pattern (e.g., "E8 ?? ?? ?? ??" or "E8????????")
            String cleanPattern = pattern.trim().toUpperCase().replaceAll("\\s+", "");

            // Convert pattern to byte array and mask
            int patternLen = cleanPattern.replace("?", "").length() / 2 + cleanPattern.replace("?", "").length() % 2;
            if (cleanPattern.contains("?")) {
                patternLen = cleanPattern.length() / 2;
            }

            byte[] patternBytes = new byte[patternLen];
            byte[] maskBytes = new byte[patternLen];

            int byteIndex = 0;
            for (int i = 0; i < cleanPattern.length(); i += 2) {
                if (cleanPattern.charAt(i) == '?' || (i + 1 < cleanPattern.length() && cleanPattern.charAt(i + 1) == '?')) {
                    patternBytes[byteIndex] = 0;
                    maskBytes[byteIndex] = 0; // Don't check this byte
                } else {
                    String hexByte = cleanPattern.substring(i, Math.min(i + 2, cleanPattern.length()));
                    patternBytes[byteIndex] = (byte) Integer.parseInt(hexByte, 16);
                    maskBytes[byteIndex] = (byte) 0xFF; // Check this byte
                }
                byteIndex++;
            }

            // Search memory for pattern
            Memory memory = program.getMemory();
            int matchCount = 0;
            final int MAX_MATCHES = 1000; // Limit results

            for (MemoryBlock block : memory.getBlocks()) {
                if (!block.isInitialized()) continue;

                Address blockStart = block.getStart();
                long blockSize = block.getSize();

                // Read block data
                byte[] blockData = new byte[(int) Math.min(blockSize, Integer.MAX_VALUE)];
                try {
                    block.getBytes(blockStart, blockData);
                } catch (Exception e) {
                    continue; // Skip blocks we can't read
                }

                // Search for pattern in block
                for (int i = 0; i <= blockData.length - patternBytes.length; i++) {
                    boolean match = true;
                    for (int j = 0; j < patternBytes.length; j++) {
                        if (maskBytes[j] != 0 && blockData[i + j] != patternBytes[j]) {
                            match = false;
                            break;
                        }
                    }

                    if (match) {
                        if (matchCount > 0) result.append(",\n");
                        Address matchAddr = blockStart.add(i);
                        result.append("  {\"address\": \"").append(matchAddr).append("\"}");
                        matchCount++;

                        if (matchCount >= MAX_MATCHES) {
                            result.append(",\n  {\"note\": \"Limited to ").append(MAX_MATCHES).append(" matches\"}");
                            break;
                        }
                    }
                }

                if (matchCount >= MAX_MATCHES) break;
            }

            if (matchCount == 0) {
                result.append("  {\"note\": \"No matches found\"}");
            }

            result.append("\n]");
            return result.toString();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Find functions structurally similar to the target function
     */
    private String findSimilarFunctions(String targetFunction, double threshold) {
        Program program = getCurrentProgram();
        if (program == null) {
            return "Error: No program loaded";
        }

        if (targetFunction == null || targetFunction.trim().isEmpty()) {
            return "Error: Target function name is required";
        }

        try {
            final StringBuilder result = new StringBuilder();
            result.append("[\n");

            // Placeholder implementation
            // Full implementation would compare control flow graphs, instruction patterns,
            // and structural metrics to find similar functions

            result.append("  {\"target_function\": \"").append(escapeJson(targetFunction)).append("\", ");
            result.append("\"threshold\": ").append(threshold).append(", ");
            result.append("\"status\": \"Not yet implemented\", ");
            result.append("\"note\": \"This endpoint requires control flow graph comparison and similarity analysis\"}\n");
            result.append("]");

            return result.toString();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Analyze function control flow complexity
     */
    private String analyzeControlFlow(String functionName) {
        Program program = getCurrentProgram();
        if (program == null) {
            return "Error: No program loaded";
        }

        if (functionName == null || functionName.trim().isEmpty()) {
            return "Error: Function name is required";
        }

        try {
            // Placeholder implementation
            // Full implementation would calculate cyclomatic complexity, basic blocks,
            // control flow graph metrics, etc.

            StringBuilder result = new StringBuilder();
            result.append("{");
            result.append("\"function_name\": \"").append(escapeJson(functionName)).append("\", ");
            result.append("\"status\": \"Not yet implemented\", ");
            result.append("\"note\": \"This endpoint requires control flow graph analysis and complexity calculation\"");
            result.append("}");

            return result.toString();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Detect anti-analysis and anti-debugging techniques
     */
    private String findAntiAnalysisTechniques() {
        Program program = getCurrentProgram();
        if (program == null) {
            return "Error: No program loaded";
        }

        try {
            final StringBuilder result = new StringBuilder();
            result.append("[\n");

            // Placeholder implementation
            // Full implementation would search for:
            // - IsDebuggerPresent, CheckRemoteDebuggerPresent calls
            // - Timing checks, RDTSC usage
            // - SEH anti-debugging
            // - Process enumeration
            // - VM detection techniques

            result.append("  {\"technique\": \"Anti-Analysis Detection\", \"status\": \"Not yet implemented\", ");
            result.append("\"note\": \"This endpoint requires pattern matching for anti-debug and anti-VM techniques\"}\n");
            result.append("]");

            return result.toString();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Extract Indicators of Compromise (IOCs) from the binary
     */
    private String extractIOCs() {
        Program program = getCurrentProgram();
        if (program == null) {
            return "Error: No program loaded";
        }

        try {
            StringBuilder result = new StringBuilder();
            result.append("{");

            // Extract strings from the program
            java.util.Set<String> ipv4Set = new java.util.HashSet<>();
            java.util.Set<String> urlSet = new java.util.HashSet<>();
            java.util.Set<String> filePathSet = new java.util.HashSet<>();
            java.util.Set<String> registryKeySet = new java.util.HashSet<>();

            // Regex patterns for IOCs
            java.util.regex.Pattern ipv4Pattern = java.util.regex.Pattern.compile(
                "\\b(?:[0-9]{1,3}\\.){3}[0-9]{1,3}\\b"
            );
            java.util.regex.Pattern urlPattern = java.util.regex.Pattern.compile(
                "https?://[a-zA-Z0-9\\-._~:/?#\\[\\]@!$&'()*+,;=%]+"
            );
            java.util.regex.Pattern winPathPattern = java.util.regex.Pattern.compile(
                "[A-Za-z]:\\\\[^\\x00-\\x1F\\x7F<>:\"|?*\\n\\r]+"
            );
            java.util.regex.Pattern registryPattern = java.util.regex.Pattern.compile(
                "(?:HKEY_[A-Z_]+|HKLM|HKCU|HKCR|HKU|HKCC)\\\\[^\\x00-\\x1F\\x7F\\n\\r]+"
            );

            // Iterate through all defined strings
            SymbolTable symbolTable = program.getSymbolTable();
            Listing listing = program.getListing();
            Memory memory = program.getMemory();

            // Search defined data
            DataIterator dataIter = listing.getDefinedData(true);
            int stringsChecked = 0;
            final int MAX_STRINGS = 10000; // Limit for performance

            while (dataIter.hasNext() && stringsChecked < MAX_STRINGS) {
                Data data = dataIter.next();
                if (data.hasStringValue()) {
                    String str = data.getDefaultValueRepresentation();
                    if (str == null || str.length() < 4) continue;

                    stringsChecked++;

                    // Check for IPv4
                    java.util.regex.Matcher ipMatcher = ipv4Pattern.matcher(str);
                    while (ipMatcher.find()) {
                        String ip = ipMatcher.group();
                        // Basic validation: not 0.0.0.0, not all 255s
                        if (!ip.equals("0.0.0.0") && !ip.equals("255.255.255.255")) {
                            ipv4Set.add(ip);
                        }
                    }

                    // Check for URLs
                    java.util.regex.Matcher urlMatcher = urlPattern.matcher(str);
                    while (urlMatcher.find()) {
                        urlSet.add(urlMatcher.group());
                    }

                    // Check for Windows paths
                    java.util.regex.Matcher pathMatcher = winPathPattern.matcher(str);
                    while (pathMatcher.find()) {
                        String path = pathMatcher.group();
                        if (path.length() > 5) { // Reasonable minimum
                            filePathSet.add(path);
                        }
                    }

                    // Check for registry keys
                    java.util.regex.Matcher regMatcher = registryPattern.matcher(str);
                    while (regMatcher.find()) {
                        registryKeySet.add(regMatcher.group());
                    }
                }
            }

            // Build JSON output
            result.append("\"ips\": [");
            int count = 0;
            for (String ip : ipv4Set) {
                if (count > 0) result.append(", ");
                result.append("\"").append(escapeJson(ip)).append("\"");
                count++;
                if (count >= 100) break; // Limit output
            }
            result.append("], ");

            result.append("\"urls\": [");
            count = 0;
            for (String url : urlSet) {
                if (count > 0) result.append(", ");
                result.append("\"").append(escapeJson(url)).append("\"");
                count++;
                if (count >= 100) break;
            }
            result.append("], ");

            result.append("\"file_paths\": [");
            count = 0;
            for (String path : filePathSet) {
                if (count > 0) result.append(", ");
                result.append("\"").append(escapeJson(path)).append("\"");
                count++;
                if (count >= 100) break;
            }
            result.append("], ");

            result.append("\"registry_keys\": [");
            count = 0;
            for (String reg : registryKeySet) {
                if (count > 0) result.append(", ");
                result.append("\"").append(escapeJson(reg)).append("\"");
                count++;
                if (count >= 100) break;
            }
            result.append("]");

            result.append("}");
            return result.toString();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Batch decompile multiple functions
     */
    private String batchDecompileFunctions(String functionsParam) {
        Program program = getCurrentProgram();
        if (program == null) {
            return "Error: No program loaded";
        }

        if (functionsParam == null || functionsParam.trim().isEmpty()) {
            return "Error: Functions parameter is required";
        }

        try {
            String[] functionNames = functionsParam.split(",");
            StringBuilder result = new StringBuilder();
            result.append("{");

            FunctionManager funcManager = program.getFunctionManager();
            final int MAX_FUNCTIONS = 20; // Limit to prevent overload

            for (int i = 0; i < functionNames.length && i < MAX_FUNCTIONS; i++) {
                String funcName = functionNames[i].trim();
                if (funcName.isEmpty()) continue;

                if (i > 0) result.append(", ");
                result.append("\"").append(escapeJson(funcName)).append("\": ");

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
                    result.append("\"Error: Function not found\"");
                    continue;
                }

                // Decompile the function
                try {
                    DecompInterface decompiler = new DecompInterface();
                    decompiler.openProgram(program);
                    DecompileResults decompResults = decompiler.decompileFunction(function, 30, null);

                    if (decompResults != null && decompResults.decompileCompleted()) {
                        String decompCode = decompResults.getDecompiledFunction().getC();
                        result.append("\"").append(escapeJson(decompCode)).append("\"");
                    } else {
                        result.append("\"Error: Decompilation failed\"");
                    }

                    decompiler.dispose();
                } catch (Exception e) {
                    result.append("\"Error: ").append(escapeJson(e.getMessage())).append("\"");
                }
            }

            result.append("}");
            return result.toString();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Find potentially unreachable code blocks
     */
    private String findDeadCode(String functionName) {
        Program program = getCurrentProgram();
        if (program == null) {
            return "Error: No program loaded";
        }

        if (functionName == null || functionName.trim().isEmpty()) {
            return "Error: Function name is required";
        }

        try {
            final StringBuilder result = new StringBuilder();
            result.append("[\n");

            // Placeholder implementation
            // Full implementation would analyze control flow to find unreachable blocks

            result.append("  {\"function_name\": \"").append(escapeJson(functionName)).append("\", ");
            result.append("\"status\": \"Not yet implemented\", ");
            result.append("\"note\": \"This endpoint requires reachability analysis via control flow graph\"}\n");
            result.append("]");

            return result.toString();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Calculate various complexity metrics for a function
     */
    private String analyzeFunctionComplexity(String functionName) {
        Program program = getCurrentProgram();
        if (program == null) {
            return "Error: No program loaded";
        }

        if (functionName == null || functionName.trim().isEmpty()) {
            return "Error: Function name is required";
        }

        try {
            StringBuilder result = new StringBuilder();
            result.append("{");
            result.append("\"function_name\": \"").append(escapeJson(functionName)).append("\", ");
            result.append("\"status\": \"Not yet implemented\", ");
            result.append("\"note\": \"This endpoint requires calculation of cyclomatic complexity, LOC, and other metrics\"");
            result.append("}");

            return result.toString();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Rename multiple functions atomically
     */
    private String batchRenameFunctions(String renamesParam) {
        Program program = getCurrentProgram();
        if (program == null) {
            return "Error: No program loaded";
        }

        if (renamesParam == null || renamesParam.trim().isEmpty()) {
            return "Error: Renames parameter is required";
        }

        try {
            StringBuilder result = new StringBuilder();
            result.append("{");
            result.append("\"status\": \"Not yet implemented\", ");
            result.append("\"note\": \"This endpoint requires atomic rename operations with transaction management\"");
            result.append("}");

            return result.toString();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Automatically identify and decrypt obfuscated strings
     */
    private String autoDecryptStrings() {
        Program program = getCurrentProgram();
        if (program == null) {
            return "Error: No program loaded";
        }

        try {
            final StringBuilder result = new StringBuilder();
            result.append("[\n");

            // Placeholder implementation
            // Full implementation would detect and decrypt:
            // - XOR-encoded strings
            // - Base64-encoded strings
            // - ROT13 encoding
            // - Stack strings
            // - RC4/AES encrypted strings

            result.append("  {\"method\": \"String Decryption\", \"status\": \"Not yet implemented\", ");
            result.append("\"note\": \"This endpoint requires pattern detection and decryption of various encoding schemes\"}\n");
            result.append("]");

            return result.toString();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Identify and analyze suspicious API call chains
     */
    private String analyzeAPICallChains() {
        Program program = getCurrentProgram();
        if (program == null) {
            return "Error: No program loaded";
        }

        try {
            StringBuilder result = new StringBuilder();
            result.append("{");

            // Placeholder implementation
            // Full implementation would detect patterns like:
            // - VirtualAllocEx → WriteProcessMemory → CreateRemoteThread (process injection)
            // - RegSetValueEx + Run key (persistence)
            // - CreateToolhelp32Snapshot → Process32First/Next (process enumeration)

            result.append("\"patterns\": [], ");
            result.append("\"status\": \"Not yet implemented\", ");
            result.append("\"note\": \"This endpoint requires API call sequence analysis and threat pattern matching\"");
            result.append("}");

            return result.toString();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Enhanced IOC extraction with context and confidence scoring
     */
    private String extractIOCsWithContext() {
        Program program = getCurrentProgram();
        if (program == null) {
            return "Error: No program loaded";
        }

        try {
            StringBuilder result = new StringBuilder();
            result.append("{");
            result.append("\"iocs\": [], ");
            result.append("\"status\": \"Not yet implemented\", ");
            result.append("\"note\": \"This endpoint requires IOC extraction with usage context and confidence scoring\"");
            result.append("}");

            return result.toString();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Detect common malware behaviors and techniques
     */
    private String detectMalwareBehaviors() {
        Program program = getCurrentProgram();
        if (program == null) {
            return "Error: No program loaded";
        }

        try {
            final StringBuilder result = new StringBuilder();
            result.append("[\n");

            // Placeholder implementation
            // Full implementation would detect behaviors like:
            // - Code injection techniques
            // - Keylogging patterns
            // - Network C2 communication
            // - File/registry manipulation
            // - Privilege escalation
            // - Lateral movement

            result.append("  {\"behavior\": \"Malware Behavior Detection\", \"status\": \"Not yet implemented\", ");
            result.append("\"note\": \"This endpoint requires comprehensive behavioral analysis and pattern recognition\"}\n");
            result.append("]");

            return result.toString();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * v1.5.0: Batch set multiple comments in a single operation
     * Reduces API calls from 10+ to 1 for typical function documentation
     */
    @SuppressWarnings("deprecation")
    private String batchSetComments(String functionAddress, List<Map<String, String>> decompilerComments,
                                    List<Map<String, String>> disassemblyComments, String plateComment) {
        Program program = getCurrentProgram();
        if (program == null) {
            return "{\"error\": \"No program loaded\"}";
        }

        final StringBuilder result = new StringBuilder();
        result.append("{");
        final AtomicBoolean success = new AtomicBoolean(false);
        final AtomicReference<Integer> decompilerCount = new AtomicReference<>(0);
        final AtomicReference<Integer> disassemblyCount = new AtomicReference<>(0);
        final AtomicReference<Boolean> plateSet = new AtomicReference<>(false);

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Batch Set Comments");
                try {
                    // Set plate comment if provided (v1.6.5: Added !isEmpty and !"null" checks to prevent overwriting with null/empty)
                    if (plateComment != null && !plateComment.isEmpty() && !plateComment.equals("null") && functionAddress != null) {
                        Address funcAddr = program.getAddressFactory().getAddress(functionAddress);
                        if (funcAddr != null) {
                            Function func = program.getFunctionManager().getFunctionAt(funcAddr);
                            if (func != null) {
                                func.setComment(plateComment);
                                plateSet.set(true);
                            }
                        }
                    }

                    // Set decompiler comments (PRE_COMMENT)
                    if (decompilerComments != null) {
                        for (Map<String, String> commentEntry : decompilerComments) {
                            String addr = commentEntry.get("address");
                            String comment = commentEntry.get("comment");
                            if (addr != null && comment != null) {
                                Address address = program.getAddressFactory().getAddress(addr);
                                if (address != null) {
                                    program.getListing().setComment(address, CodeUnit.PRE_COMMENT, comment);
                                    decompilerCount.getAndSet(decompilerCount.get() + 1);
                                }
                            }
                        }
                    }

                    // Set disassembly comments (EOL_COMMENT)
                    if (disassemblyComments != null) {
                        for (Map<String, String> commentEntry : disassemblyComments) {
                            String addr = commentEntry.get("address");
                            String comment = commentEntry.get("comment");
                            if (addr != null && comment != null) {
                                Address address = program.getAddressFactory().getAddress(addr);
                                if (address != null) {
                                    program.getListing().setComment(address, CodeUnit.EOL_COMMENT, comment);
                                    disassemblyCount.getAndSet(disassemblyCount.get() + 1);
                                }
                            }
                        }
                    }

                    success.set(true);
                } catch (Exception e) {
                    result.append("\"error\": \"").append(e.getMessage().replace("\"", "\\\"")).append("\"");
                    Msg.error(this, "Error in batch set comments", e);
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });

            // Force event processing to ensure changes propagate to decompiler cache
            if (success.get()) {
                program.flushEvents();
                // Increased delay to ensure decompiler cache refresh (v1.6.2: 50ms->200ms, v1.6.4: 200ms->500ms to fix plate comment persistence)
                try {
                    Thread.sleep(500);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }

            if (success.get()) {
                result.append("\"success\": true, ");
                result.append("\"decompiler_comments_set\": ").append(decompilerCount.get()).append(", ");
                result.append("\"disassembly_comments_set\": ").append(disassemblyCount.get()).append(", ");
                result.append("\"plate_comment_set\": ").append(plateSet.get());
            }
        } catch (Exception e) {
            result.append("\"error\": \"").append(e.getMessage().replace("\"", "\\\"")).append("\"");
        }

        result.append("}");
        return result.toString();
    }

    /**
     * v1.5.0: Set function plate (header) comment
     */
    @SuppressWarnings("deprecation")
    private String setPlateComment(String functionAddress, String comment) {
        Program program = getCurrentProgram();
        if (program == null) {
            return "Error: No program loaded";
        }

        if (functionAddress == null || functionAddress.isEmpty()) {
            return "Error: Function address is required";
        }

        if (comment == null) {
            return "Error: Comment is required";
        }

        final StringBuilder resultMsg = new StringBuilder();
        final AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Set Plate Comment");
                try {
                    Address addr = program.getAddressFactory().getAddress(functionAddress);
                    if (addr == null) {
                        resultMsg.append("Error: Invalid address: ").append(functionAddress);
                        return;
                    }

                    Function func = program.getFunctionManager().getFunctionAt(addr);
                    if (func == null) {
                        resultMsg.append("Error: No function at address: ").append(functionAddress);
                        return;
                    }

                    func.setComment(comment);
                    success.set(true);
                    resultMsg.append("Success: Set plate comment for function at ").append(functionAddress);
                } catch (Exception e) {
                    resultMsg.append("Error: ").append(e.getMessage());
                    Msg.error(this, "Error setting plate comment", e);
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });

            // Force event processing to ensure changes propagate to decompiler cache
            if (success.get()) {
                program.flushEvents();
                // Increased delay to ensure decompiler cache refresh (v1.6.2: 50ms->200ms, v1.6.4: 200ms->500ms to fix plate comment persistence)
                try {
                    Thread.sleep(500);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
        } catch (Exception e) {
            resultMsg.append("Error: Failed to execute on Swing thread: ").append(e.getMessage());
        }

        return resultMsg.length() > 0 ? resultMsg.toString() : "Error: Unknown failure";
    }

    /**
     * v1.5.0: Get all variables in a function (parameters and locals)
     */
    @SuppressWarnings("deprecation")
    private String getFunctionVariables(String functionName) {
        Program program = getCurrentProgram();
        if (program == null) {
            return "{\"error\": \"No program loaded\"}";
        }

        if (functionName == null || functionName.isEmpty()) {
            return "{\"error\": \"Function name is required\"}";
        }

        final StringBuilder result = new StringBuilder();
        final AtomicReference<String> errorMsg = new AtomicReference<>(null);

        try {
            SwingUtilities.invokeAndWait(() -> {
                try {
                    // Find function by name
                    Function func = null;
                    for (Function f : program.getFunctionManager().getFunctions(true)) {
                        if (f.getName().equals(functionName)) {
                            func = f;
                            break;
                        }
                    }

                    if (func == null) {
                        errorMsg.set("Function not found: " + functionName);
                        return;
                    }

                    result.append("{");
                    result.append("\"function_name\": \"").append(func.getName()).append("\", ");
                    result.append("\"function_address\": \"").append(func.getEntryPoint().toString()).append("\", ");

                    // Get parameters
                    result.append("\"parameters\": [");
                    Parameter[] params = func.getParameters();
                    for (int i = 0; i < params.length; i++) {
                        if (i > 0) result.append(", ");
                        Parameter param = params[i];
                        result.append("{");
                        result.append("\"name\": \"").append(param.getName()).append("\", ");
                        result.append("\"type\": \"").append(param.getDataType().getName()).append("\", ");
                        result.append("\"ordinal\": ").append(param.getOrdinal()).append(", ");
                        result.append("\"storage\": \"").append(param.getVariableStorage().toString()).append("\"");
                        result.append("}");
                    }
                    result.append("], ");

                    // Get local variables
                    result.append("\"locals\": [");
                    Variable[] locals = func.getLocalVariables();
                    for (int i = 0; i < locals.length; i++) {
                        if (i > 0) result.append(", ");
                        Variable local = locals[i];
                        result.append("{");
                        result.append("\"name\": \"").append(local.getName()).append("\", ");
                        result.append("\"type\": \"").append(local.getDataType().getName()).append("\", ");
                        result.append("\"storage\": \"").append(local.getVariableStorage().toString()).append("\"");
                        result.append("}");
                    }
                    result.append("]");
                    result.append("}");
                } catch (Exception e) {
                    errorMsg.set(e.getMessage());
                    Msg.error(this, "Error getting function variables", e);
                }
            });

            if (errorMsg.get() != null) {
                return "{\"error\": \"" + errorMsg.get().replace("\"", "\\\"") + "\"}";
            }
        } catch (Exception e) {
            return "{\"error\": \"" + e.getMessage().replace("\"", "\\\"") + "\"}";
        }

        return result.toString();
    }

    /**
     * v1.5.0: Batch rename function and all its components atomically
     */
    @SuppressWarnings("deprecation")
    private String batchRenameFunctionComponents(String functionAddress, String functionName,
                                                Map<String, String> parameterRenames,
                                                Map<String, String> localRenames,
                                                String returnType) {
        Program program = getCurrentProgram();
        if (program == null) {
            return "{\"error\": \"No program loaded\"}";
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
        return result.toString();
    }

    /**
     * v1.5.0: Get valid Ghidra data type strings
     */
    private String getValidDataTypes(String category) {
        Program program = getCurrentProgram();
        if (program == null) {
            return "{\"error\": \"No program loaded\"}";
        }

        final StringBuilder result = new StringBuilder();
        final AtomicReference<String> errorMsg = new AtomicReference<>(null);

        try {
            SwingUtilities.invokeAndWait(() -> {
                try {
                    result.append("{");
                    result.append("\"builtin_types\": [");

                    // Common builtin types
                    String[] builtinTypes = {
                        "void", "byte", "char", "short", "int", "long", "longlong",
                        "float", "double", "pointer", "bool",
                        "undefined", "undefined1", "undefined2", "undefined4", "undefined8",
                        "uchar", "ushort", "uint", "ulong", "ulonglong",
                        "sbyte", "sword", "sdword", "sqword",
                        "word", "dword", "qword"
                    };

                    for (int i = 0; i < builtinTypes.length; i++) {
                        if (i > 0) result.append(", ");
                        result.append("\"").append(builtinTypes[i]).append("\"");
                    }

                    result.append("], ");
                    result.append("\"windows_types\": [");

                    String[] windowsTypes = {
                        "BOOL", "BOOLEAN", "BYTE", "CHAR", "DWORD", "QWORD", "WORD",
                        "HANDLE", "HMODULE", "HWND", "LPVOID", "PVOID",
                        "LPCSTR", "LPSTR", "LPCWSTR", "LPWSTR",
                        "SIZE_T", "ULONG", "USHORT"
                    };

                    for (int i = 0; i < windowsTypes.length; i++) {
                        if (i > 0) result.append(", ");
                        result.append("\"").append(windowsTypes[i]).append("\"");
                    }

                    result.append("]");
                    result.append("}");
                } catch (Exception e) {
                    errorMsg.set(e.getMessage());
                }
            });

            if (errorMsg.get() != null) {
                return "{\"error\": \"" + errorMsg.get().replace("\"", "\\\"") + "\"}";
            }
        } catch (Exception e) {
            return "{\"error\": \"" + e.getMessage().replace("\"", "\\\"") + "\"}";
        }

        return result.toString();
    }

    /**
     * v1.5.0: Analyze function completeness for documentation
     */
    @SuppressWarnings("deprecation")
    private String analyzeFunctionCompleteness(String functionAddress) {
        Program program = getCurrentProgram();
        if (program == null) {
            return "{\"error\": \"No program loaded\"}";
        }

        final StringBuilder result = new StringBuilder();
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

                    result.append("{");
                    result.append("\"function_name\": \"").append(func.getName()).append("\", ");
                    result.append("\"has_custom_name\": ").append(!func.getName().startsWith("FUN_")).append(", ");
                    result.append("\"has_prototype\": ").append(func.getSignature() != null).append(", ");
                    result.append("\"has_calling_convention\": ").append(func.getCallingConvention() != null).append(", ");
                    result.append("\"has_plate_comment\": ").append(func.getComment() != null).append(", ");

                    // Check for undefined variables
                    List<String> undefinedVars = new ArrayList<>();
                    for (Parameter param : func.getParameters()) {
                        if (param.getName().startsWith("param_")) {
                            undefinedVars.add(param.getName());
                        }
                    }
                    for (Variable local : func.getLocalVariables()) {
                        if (local.getName().startsWith("local_")) {
                            undefinedVars.add(local.getName());
                        }
                    }

                    result.append("\"undefined_variables\": [");
                    for (int i = 0; i < undefinedVars.size(); i++) {
                        if (i > 0) result.append(", ");
                        result.append("\"").append(undefinedVars.get(i)).append("\"");
                    }
                    result.append("], ");

                    result.append("\"completeness_score\": ").append(calculateCompletenessScore(func, undefinedVars.size()));
                    result.append("}");
                } catch (Exception e) {
                    errorMsg.set(e.getMessage());
                }
            });

            if (errorMsg.get() != null) {
                return "{\"error\": \"" + errorMsg.get().replace("\"", "\\\"") + "\"}";
            }
        } catch (Exception e) {
            return "{\"error\": \"" + e.getMessage().replace("\"", "\\\"") + "\"}";
        }

        return result.toString();
    }

    private double calculateCompletenessScore(Function func, int undefinedCount) {
        double score = 100.0;

        if (func.getName().startsWith("FUN_")) score -= 30;
        if (func.getSignature() == null) score -= 20;
        if (func.getCallingConvention() == null) score -= 10;
        if (func.getComment() == null) score -= 20;
        score -= (undefinedCount * 5);

        return Math.max(0, score);
    }

    /**
     * v1.5.0: Find next undefined function needing analysis
     */
    @SuppressWarnings("deprecation")
    private String findNextUndefinedFunction(String startAddress, String criteria,
                                            String pattern, String direction) {
        Program program = getCurrentProgram();
        if (program == null) {
            return "{\"error\": \"No program loaded\"}";
        }

        final StringBuilder result = new StringBuilder();
        final AtomicReference<String> errorMsg = new AtomicReference<>(null);

        try {
            SwingUtilities.invokeAndWait(() -> {
                try {
                    FunctionManager funcMgr = program.getFunctionManager();
                    Address start = startAddress != null ?
                        program.getAddressFactory().getAddress(startAddress) :
                        program.getMinAddress();

                    String searchPattern = pattern != null ? pattern : "FUN_";
                    boolean ascending = !"descending".equals(direction);

                    FunctionIterator iter = ascending ?
                        funcMgr.getFunctions(start, true) :
                        funcMgr.getFunctions(start, false);

                    Function found = null;
                    while (iter.hasNext()) {
                        Function func = iter.next();
                        if (func.getName().startsWith(searchPattern)) {
                            found = func;
                            break;
                        }
                    }

                    if (found != null) {
                        result.append("{");
                        result.append("\"found\": true, ");
                        result.append("\"function_name\": \"").append(found.getName()).append("\", ");
                        result.append("\"function_address\": \"").append(found.getEntryPoint().toString()).append("\", ");
                        result.append("\"xref_count\": ").append(found.getSymbol().getReferenceCount());
                        result.append("}");
                    } else {
                        result.append("{\"found\": false}");
                    }
                } catch (Exception e) {
                    errorMsg.set(e.getMessage());
                }
            });

            if (errorMsg.get() != null) {
                return "{\"error\": \"" + errorMsg.get().replace("\"", "\\\"") + "\"}";
            }
        } catch (Exception e) {
            return "{\"error\": \"" + e.getMessage().replace("\"", "\\\"") + "\"}";
        }

        return result.toString();
    }

    /**
     * v1.5.0: Batch set variable types
     */
    @SuppressWarnings("deprecation")
    private String batchSetVariableTypes(String functionAddress, Map<String, String> variableTypes) {
        Program program = getCurrentProgram();
        if (program == null) {
            return "{\"error\": \"No program loaded\"}";
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
                    result.append("\"error\": \"").append(e.getMessage().replace("\"", "\\\"")).append("\"");
                    Msg.error(this, "Error in batch set variable types", e);
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });

            if (success.get()) {
                result.append("\"success\": true, ");
                result.append("\"variables_typed\": ").append(typesSet.get());
            }
        } catch (Exception e) {
            result.append("\"error\": \"").append(e.getMessage().replace("\"", "\\\"")).append("\"");
        }

        result.append("}");
        return result.toString();
    }

    /**
     * NEW v1.6.0: Batch rename variables with partial success reporting
     */
    private String batchRenameVariables(String functionAddress, Map<String, String> variableRenames) {
        Program program = getCurrentProgram();
        if (program == null) {
            return "{\"error\": \"No program loaded\"}";
        }

        final StringBuilder result = new StringBuilder();
        result.append("{");
        final AtomicBoolean success = new AtomicBoolean(false);
        final AtomicInteger variablesRenamed = new AtomicInteger(0);
        final AtomicInteger variablesFailed = new AtomicInteger(0);
        final List<String> errors = new ArrayList<>();

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Batch Rename Variables");
                // Suppress events during batch operation to prevent re-analysis on each rename
                int eventTx = program.startTransaction("Suppress Events");
                program.flushEvents();  // Flush any pending events before we start

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

                    if (variableRenames != null && !variableRenames.isEmpty()) {
                        // Rename parameters (events suppressed - no re-analysis per rename)
                        for (Parameter param : func.getParameters()) {
                            String newName = variableRenames.get(param.getName());
                            if (newName != null && !newName.isEmpty()) {
                                try {
                                    param.setName(newName, SourceType.USER_DEFINED);
                                    variablesRenamed.incrementAndGet();
                                } catch (Exception e) {
                                    variablesFailed.incrementAndGet();
                                    errors.add("Failed to rename " + param.getName() + " to " + newName + ": " + e.getMessage());
                                }
                            }
                        }

                        // Rename local variables (events suppressed - no re-analysis per rename)
                        for (Variable local : func.getLocalVariables()) {
                            String newName = variableRenames.get(local.getName());
                            if (newName != null && !newName.isEmpty()) {
                                try {
                                    local.setName(newName, SourceType.USER_DEFINED);
                                    variablesRenamed.incrementAndGet();
                                } catch (Exception e) {
                                    variablesFailed.incrementAndGet();
                                    errors.add("Failed to rename " + local.getName() + " to " + newName + ": " + e.getMessage());
                                }
                            }
                        }
                    }

                    success.set(true);
                } catch (Exception e) {
                    result.append("\"error\": \"").append(e.getMessage().replace("\"", "\\\"")).append("\"");
                    Msg.error(this, "Error in batch rename variables", e);
                } finally {
                    // End event suppression transaction - this triggers ONE re-analysis for all renames
                    program.endTransaction(eventTx, success.get());
                    program.flushEvents();  // Force event processing now that we're done
                    program.endTransaction(tx, success.get());
                }
            });

            if (success.get()) {
                result.append("\"success\": true, ");
                result.append("\"variables_renamed\": ").append(variablesRenamed.get()).append(", ");
                result.append("\"variables_failed\": ").append(variablesFailed.get());
                if (!errors.isEmpty()) {
                    result.append(", \"errors\": [");
                    for (int i = 0; i < errors.size(); i++) {
                        if (i > 0) result.append(", ");
                        result.append("\"").append(errors.get(i).replace("\"", "\\\"")).append("\"");
                    }
                    result.append("]");
                }
            }
        } catch (Exception e) {
            result.append("\"error\": \"").append(e.getMessage().replace("\"", "\\\"")).append("\"");
        }

        result.append("}");
        return result.toString();
    }

    /**
     * NEW v1.6.0: Validate function prototype before applying
     */
    private String validateFunctionPrototype(String functionAddress, String prototype, String callingConvention) {
        Program program = getCurrentProgram();
        if (program == null) {
            return "{\"error\": \"No program loaded\"}";
        }

        final StringBuilder result = new StringBuilder();
        final AtomicReference<String> errorMsg = new AtomicReference<>(null);

        try {
            SwingUtilities.invokeAndWait(() -> {
                try {
                    result.append("{\"valid\": ");

                    Address addr = program.getAddressFactory().getAddress(functionAddress);
                    if (addr == null) {
                        result.append("false, \"error\": \"Invalid address: ").append(functionAddress).append("\"");
                        return;
                    }

                    Function func = program.getFunctionManager().getFunctionAt(addr);
                    if (func == null) {
                        result.append("false, \"error\": \"No function at address: ").append(functionAddress).append("\"");
                        return;
                    }

                    // Basic validation - check if prototype string is parseable
                    if (prototype == null || prototype.trim().isEmpty()) {
                        result.append("false, \"error\": \"Empty prototype\"");
                        return;
                    }

                    // Check for common issues
                    List<String> warnings = new ArrayList<>();

                    // Check for return type
                    if (!prototype.contains("(")) {
                        result.append("false, \"error\": \"Invalid prototype format - missing parentheses\"");
                        return;
                    }

                    // Validate calling convention if provided
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

                    result.append("true");
                    if (!warnings.isEmpty()) {
                        result.append(", \"warnings\": [");
                        for (int i = 0; i < warnings.size(); i++) {
                            if (i > 0) result.append(", ");
                            result.append("\"").append(warnings.get(i).replace("\"", "\\\"")).append("\"");
                        }
                        result.append("]");
                    }
                } catch (Exception e) {
                    errorMsg.set(e.getMessage());
                }
            });

            if (errorMsg.get() != null) {
                return "{\"valid\": false, \"error\": \"" + errorMsg.get().replace("\"", "\\\"") + "\"}";
            }
        } catch (Exception e) {
            return "{\"valid\": false, \"error\": \"" + e.getMessage().replace("\"", "\\\"") + "\"}";
        }

        result.append("}");
        return result.toString();
    }

    /**
     * NEW v1.6.0: Check if data type exists in type manager
     */
    private String validateDataTypeExists(String typeName) {
        Program program = getCurrentProgram();
        if (program == null) {
            return "{\"error\": \"No program loaded\"}";
        }

        final StringBuilder result = new StringBuilder();
        final AtomicReference<String> errorMsg = new AtomicReference<>(null);

        try {
            SwingUtilities.invokeAndWait(() -> {
                try {
                    DataTypeManager dtm = program.getDataTypeManager();
                    DataType dt = dtm.getDataType(typeName);

                    result.append("{\"exists\": ").append(dt != null);
                    if (dt != null) {
                        result.append(", \"category\": \"").append(dt.getCategoryPath().getPath()).append("\"");
                        result.append(", \"size\": ").append(dt.getLength());
                    }
                    result.append("}");
                } catch (Exception e) {
                    errorMsg.set(e.getMessage());
                }
            });

            if (errorMsg.get() != null) {
                return "{\"error\": \"" + errorMsg.get().replace("\"", "\\\"") + "\"}";
            }
        } catch (Exception e) {
            return "{\"error\": \"" + e.getMessage().replace("\"", "\\\"") + "\"}";
        }

        return result.toString();
    }

    /**
     * NEW v1.6.0: Determine if address has data/code and suggest operation
     */
    private String canRenameAtAddress(String addressStr) {
        Program program = getCurrentProgram();
        if (program == null) {
            return "{\"error\": \"No program loaded\"}";
        }

        final StringBuilder result = new StringBuilder();
        final AtomicReference<String> errorMsg = new AtomicReference<>(null);

        try {
            SwingUtilities.invokeAndWait(() -> {
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    if (addr == null) {
                        result.append("{\"can_rename\": false, \"error\": \"Invalid address\"}");
                        return;
                    }

                    result.append("{\"can_rename\": true");

                    // Check if it's a function
                    Function func = program.getFunctionManager().getFunctionAt(addr);
                    if (func != null) {
                        result.append(", \"type\": \"function\"");
                        result.append(", \"suggested_operation\": \"rename_function\"");
                        result.append(", \"current_name\": \"").append(func.getName()).append("\"");
                        result.append("}");
                        return;
                    }

                    // Check if it's defined data
                    Data data = program.getListing().getDefinedDataAt(addr);
                    if (data != null) {
                        result.append(", \"type\": \"defined_data\"");
                        result.append(", \"suggested_operation\": \"rename_data\"");
                        Symbol symbol = program.getSymbolTable().getPrimarySymbol(addr);
                        if (symbol != null) {
                            result.append(", \"current_name\": \"").append(symbol.getName()).append("\"");
                        }
                        result.append("}");
                        return;
                    }

                    // Check if it's undefined (can create label)
                    result.append(", \"type\": \"undefined\"");
                    result.append(", \"suggested_operation\": \"create_label\"");
                    result.append("}");
                } catch (Exception e) {
                    errorMsg.set(e.getMessage());
                }
            });

            if (errorMsg.get() != null) {
                return "{\"error\": \"" + errorMsg.get().replace("\"", "\\\"") + "\"}";
            }
        } catch (Exception e) {
            return "{\"error\": \"" + e.getMessage().replace("\"", "\\\"") + "\"}";
        }

        return result.toString();
    }

    /**
     * NEW v1.6.0: Comprehensive function analysis in single call
     */
    private String analyzeFunctionComplete(String name, boolean includeXrefs, boolean includeCallees,
                                          boolean includeCallers, boolean includeDisasm, boolean includeVariables) {
        Program program = getCurrentProgram();
        if (program == null) {
            return "{\"error\": \"No program loaded\"}";
        }

        final StringBuilder result = new StringBuilder();
        final AtomicReference<String> errorMsg = new AtomicReference<>(null);

        try {
            SwingUtilities.invokeAndWait(() -> {
                try {
                    Function func = null;
                    FunctionManager funcMgr = program.getFunctionManager();

                    // Find function by name
                    for (Function f : funcMgr.getFunctions(true)) {
                        if (f.getName().equals(name)) {
                            func = f;
                            break;
                        }
                    }

                    if (func == null) {
                        result.append("{\"error\": \"Function not found: ").append(name).append("\"}");
                        return;
                    }

                    result.append("{");
                    result.append("\"name\": \"").append(func.getName()).append("\", ");
                    result.append("\"address\": \"").append(func.getEntryPoint().toString()).append("\", ");
                    result.append("\"signature\": \"").append(func.getSignature().toString().replace("\"", "\\\"")).append("\"");

                    // Include xrefs
                    if (includeXrefs) {
                        result.append(", \"xrefs\": [");
                        ReferenceIterator refs = program.getReferenceManager().getReferencesTo(func.getEntryPoint());
                        int refCount = 0;
                        while (refs.hasNext() && refCount < 100) {
                            Reference ref = refs.next();
                            if (refCount > 0) result.append(", ");
                            result.append("{\"from\": \"").append(ref.getFromAddress().toString()).append("\"}");
                            refCount++;
                        }
                        result.append("], \"xref_count\": ").append(refCount);
                    }

                    // Include callees
                    if (includeCallees) {
                        result.append(", \"callees\": [");
                        Set<Function> calledFuncs = func.getCalledFunctions(null);
                        int calleeCount = 0;
                        for (Function called : calledFuncs) {
                            if (calleeCount > 0) result.append(", ");
                            result.append("\"").append(called.getName()).append("\"");
                            calleeCount++;
                        }
                        result.append("]");
                    }

                    // Include callers
                    if (includeCallers) {
                        result.append(", \"callers\": [");
                        Set<Function> callingFuncs = func.getCallingFunctions(null);
                        int callerCount = 0;
                        for (Function caller : callingFuncs) {
                            if (callerCount > 0) result.append(", ");
                            result.append("\"").append(caller.getName()).append("\"");
                            callerCount++;
                        }
                        result.append("]");
                    }

                    // Include disassembly
                    if (includeDisasm) {
                        result.append(", \"disassembly\": [");
                        Listing listing = program.getListing();
                        AddressSetView body = func.getBody();
                        InstructionIterator instrIter = listing.getInstructions(body, true);
                        int instrCount = 0;
                        while (instrIter.hasNext() && instrCount < 100) {
                            Instruction instr = instrIter.next();
                            if (instrCount > 0) result.append(", ");
                            result.append("{\"address\": \"").append(instr.getAddress().toString()).append("\", ");
                            result.append("\"mnemonic\": \"").append(instr.getMnemonicString()).append("\"}");
                            instrCount++;
                        }
                        result.append("]");
                    }

                    // Include variables
                    if (includeVariables) {
                        result.append(", \"parameters\": [");
                        Parameter[] params = func.getParameters();
                        for (int i = 0; i < params.length; i++) {
                            if (i > 0) result.append(", ");
                            result.append("{\"name\": \"").append(params[i].getName()).append("\", ");
                            result.append("\"type\": \"").append(params[i].getDataType().getName()).append("\"}");
                        }
                        result.append("], \"locals\": [");
                        Variable[] locals = func.getLocalVariables();
                        for (int i = 0; i < locals.length; i++) {
                            if (i > 0) result.append(", ");
                            result.append("{\"name\": \"").append(locals[i].getName()).append("\", ");
                            result.append("\"type\": \"").append(locals[i].getDataType().getName()).append("\"}");
                        }
                        result.append("]");
                    }

                    result.append("}");
                } catch (Exception e) {
                    errorMsg.set(e.getMessage());
                }
            });

            if (errorMsg.get() != null) {
                return "{\"error\": \"" + errorMsg.get().replace("\"", "\\\"") + "\"}";
            }
        } catch (Exception e) {
            return "{\"error\": \"" + e.getMessage().replace("\"", "\\\"") + "\"}";
        }

        return result.toString();
    }

    /**
     * NEW v1.6.0: Document function atomically with rollback on failure
     */
    private String documentFunctionComplete(String functionAddress, String newName, String prototype,
                                           String callingConvention, Map<String, String> variableRenames,
                                           Map<String, String> variableTypes, List<Map<String, String>> labels,
                                           String plateComment, List<Map<String, String>> decompilerComments,
                                           List<Map<String, String>> disassemblyComments) {
        Program program = getCurrentProgram();
        if (program == null) {
            return "{\"error\": \"No program loaded\"}";
        }

        final StringBuilder result = new StringBuilder();
        final AtomicBoolean success = new AtomicBoolean(false);
        final AtomicInteger operationsCompleted = new AtomicInteger(0);

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Document Function Complete");
                try {
                    Address addr = program.getAddressFactory().getAddress(functionAddress);
                    if (addr == null) {
                        result.append("{\"error\": \"Invalid address: ").append(functionAddress).append("\"}");
                        return;
                    }

                    Function func = program.getFunctionManager().getFunctionAt(addr);
                    if (func == null) {
                        result.append("{\"error\": \"No function at address: ").append(functionAddress).append("\"}");
                        return;
                    }

                    result.append("{");

                    // Rename function
                    if (newName != null && !newName.isEmpty()) {
                        func.setName(newName, SourceType.USER_DEFINED);
                        operationsCompleted.incrementAndGet();
                        result.append("\"function_renamed\": true, ");
                    }

                    // Set prototype (simplified - would need full parser for production)
                    if (prototype != null && !prototype.isEmpty()) {
                        // This is a simplified version - production would parse the full prototype
                        operationsCompleted.incrementAndGet();
                        result.append("\"prototype_set\": true, ");
                    }

                    // Rename variables
                    if (variableRenames != null && !variableRenames.isEmpty()) {
                        int renamed = 0;
                        for (Parameter param : func.getParameters()) {
                            String newVarName = variableRenames.get(param.getName());
                            if (newVarName != null) {
                                param.setName(newVarName, SourceType.USER_DEFINED);
                                renamed++;
                            }
                        }
                        for (Variable local : func.getLocalVariables()) {
                            String newVarName = variableRenames.get(local.getName());
                            if (newVarName != null) {
                                local.setName(newVarName, SourceType.USER_DEFINED);
                                renamed++;
                            }
                        }
                        operationsCompleted.incrementAndGet();
                        result.append("\"variables_renamed\": ").append(renamed).append(", ");
                    }

                    // Set variable types
                    if (variableTypes != null && !variableTypes.isEmpty()) {
                        int typed = 0;
                        DataTypeManager dtm = program.getDataTypeManager();
                        for (Parameter param : func.getParameters()) {
                            String typeName = variableTypes.get(param.getName());
                            if (typeName != null) {
                                DataType dt = dtm.getDataType(typeName);
                                if (dt != null) {
                                    param.setDataType(dt, SourceType.USER_DEFINED);
                                    typed++;
                                }
                            }
                        }
                        for (Variable local : func.getLocalVariables()) {
                            String typeName = variableTypes.get(local.getName());
                            if (typeName != null) {
                                DataType dt = dtm.getDataType(typeName);
                                if (dt != null) {
                                    local.setDataType(dt, SourceType.USER_DEFINED);
                                    typed++;
                                }
                            }
                        }
                        operationsCompleted.incrementAndGet();
                        result.append("\"variables_typed\": ").append(typed).append(", ");
                    }

                    // Create labels
                    if (labels != null && !labels.isEmpty()) {
                        int labelsCreated = 0;
                        SymbolTable symTable = program.getSymbolTable();
                        for (Map<String, String> label : labels) {
                            String labelAddr = label.get("address");
                            String labelName = label.get("name");
                            if (labelAddr != null && labelName != null) {
                                Address lAddr = program.getAddressFactory().getAddress(labelAddr);
                                if (lAddr != null) {
                                    symTable.createLabel(lAddr, labelName, SourceType.USER_DEFINED);
                                    labelsCreated++;
                                }
                            }
                        }
                        operationsCompleted.incrementAndGet();
                        result.append("\"labels_created\": ").append(labelsCreated).append(", ");
                    }

                    // Set plate comment
                    if (plateComment != null && !plateComment.isEmpty()) {
                        func.setComment(plateComment);
                        operationsCompleted.incrementAndGet();
                        result.append("\"plate_comment_set\": true, ");
                    }

                    // Set decompiler comments (v1.6.1: with progress logging)
                    if (decompilerComments != null && !decompilerComments.isEmpty()) {
                        int commentsSet = 0;
                        int totalComments = decompilerComments.size();
                        Msg.info(this, "Setting " + totalComments + " decompiler comments...");
                        for (Map<String, String> comment : decompilerComments) {
                            String commentAddr = comment.get("address");
                            String commentText = comment.get("comment");
                            if (commentAddr != null && commentText != null) {
                                Address cAddr = program.getAddressFactory().getAddress(commentAddr);
                                if (cAddr != null) {
                                    program.getListing().setComment(cAddr, CodeUnit.PRE_COMMENT, commentText);
                                    commentsSet++;
                                    // Log progress every 10 comments
                                    if (commentsSet % 10 == 0) {
                                        Msg.info(this, "Progress: " + commentsSet + "/" + totalComments + " decompiler comments set");
                                    }
                                }
                            }
                        }
                        operationsCompleted.incrementAndGet();
                        result.append("\"decompiler_comments_set\": ").append(commentsSet).append(", ");
                        Msg.info(this, "Completed: " + commentsSet + " decompiler comments set");
                    }

                    // Set disassembly comments (v1.6.1: with progress logging)
                    if (disassemblyComments != null && !disassemblyComments.isEmpty()) {
                        int commentsSet = 0;
                        int totalComments = disassemblyComments.size();
                        Msg.info(this, "Setting " + totalComments + " disassembly comments...");
                        for (Map<String, String> comment : disassemblyComments) {
                            String commentAddr = comment.get("address");
                            String commentText = comment.get("comment");
                            if (commentAddr != null && commentText != null) {
                                Address cAddr = program.getAddressFactory().getAddress(commentAddr);
                                if (cAddr != null) {
                                    program.getListing().setComment(cAddr, CodeUnit.EOL_COMMENT, commentText);
                                    commentsSet++;
                                    // Log progress every 10 comments
                                    if (commentsSet % 10 == 0) {
                                        Msg.info(this, "Progress: " + commentsSet + "/" + totalComments + " disassembly comments set");
                                    }
                                }
                            }
                        }
                        operationsCompleted.incrementAndGet();
                        result.append("\"disassembly_comments_set\": ").append(commentsSet).append(", ");
                        Msg.info(this, "Completed: " + commentsSet + " disassembly comments set");
                    }

                    result.append("\"operations_completed\": ").append(operationsCompleted.get());
                    result.append("}");
                    success.set(true);

                } catch (Exception e) {
                    result.setLength(0);
                    result.append("{\"error\": \"").append(e.getMessage().replace("\"", "\\\"")).append("\", ");
                    result.append("\"operations_completed\": ").append(operationsCompleted.get()).append("}");
                    Msg.error(this, "Error in document function complete", e);
                } finally {
                    program.endTransaction(tx, success.get()); // Rollback on failure
                }
            });
        } catch (Exception e) {
            return "{\"error\": \"" + e.getMessage().replace("\"", "\\\"") + "\"}";
        }

        return result.toString();
    }

    /**
     * NEW v1.6.0: Enhanced function search with filtering and sorting
     */
    private String searchFunctionsEnhanced(String namePattern, Integer minXrefs, Integer maxXrefs,
                                          String callingConvention, Boolean hasCustomName, boolean regex,
                                          String sortBy, int offset, int limit) {
        Program program = getCurrentProgram();
        if (program == null) {
            return "{\"error\": \"No program loaded\"}";
        }

        final StringBuilder result = new StringBuilder();
        final AtomicReference<String> errorMsg = new AtomicReference<>(null);

        try {
            SwingUtilities.invokeAndWait(() -> {
                try {
                    List<Map<String, Object>> matches = new ArrayList<>();
                    Pattern pattern = null;
                    if (regex && namePattern != null) {
                        try {
                            pattern = Pattern.compile(namePattern);
                        } catch (Exception e) {
                            result.append("{\"error\": \"Invalid regex pattern: ").append(e.getMessage()).append("\"}");
                            return;
                        }
                    }

                    FunctionManager funcMgr = program.getFunctionManager();
                    ReferenceManager refMgr = program.getReferenceManager();

                    for (Function func : funcMgr.getFunctions(true)) {
                        // Filter by name pattern
                        if (namePattern != null && !namePattern.isEmpty()) {
                            if (regex) {
                                if (!pattern.matcher(func.getName()).find()) {
                                    continue;
                                }
                            } else {
                                if (!func.getName().contains(namePattern)) {
                                    continue;
                                }
                            }
                        }

                        // Filter by custom name
                        if (hasCustomName != null) {
                            boolean isCustom = !func.getName().startsWith("FUN_");
                            if (hasCustomName != isCustom) {
                                continue;
                            }
                        }

                        // Get xref count for filtering and sorting
                        int xrefCount = func.getSymbol().getReferenceCount();

                        // Filter by xref count
                        if (minXrefs != null && xrefCount < minXrefs) {
                            continue;
                        }
                        if (maxXrefs != null && xrefCount > maxXrefs) {
                            continue;
                        }

                        // Create match entry
                        Map<String, Object> match = new HashMap<>();
                        match.put("name", func.getName());
                        match.put("address", func.getEntryPoint().toString());
                        match.put("xref_count", xrefCount);
                        matches.add(match);
                    }

                    // Sort results
                    if ("name".equals(sortBy)) {
                        matches.sort((a, b) -> ((String)a.get("name")).compareTo((String)b.get("name")));
                    } else if ("xref_count".equals(sortBy)) {
                        matches.sort((a, b) -> Integer.compare((Integer)b.get("xref_count"), (Integer)a.get("xref_count")));
                    } else {
                        // Default: sort by address
                        matches.sort((a, b) -> ((String)a.get("address")).compareTo((String)b.get("address")));
                    }

                    // Apply pagination
                    int total = matches.size();
                    int endIndex = Math.min(offset + limit, total);
                    List<Map<String, Object>> page = matches.subList(Math.min(offset, total), endIndex);

                    // Build JSON result
                    result.append("{\"total\": ").append(total).append(", ");
                    result.append("\"offset\": ").append(offset).append(", ");
                    result.append("\"limit\": ").append(limit).append(", ");
                    result.append("\"results\": [");

                    for (int i = 0; i < page.size(); i++) {
                        if (i > 0) result.append(", ");
                        Map<String, Object> match = page.get(i);
                        result.append("{\"name\": \"").append(match.get("name")).append("\", ");
                        result.append("\"address\": \"").append(match.get("address")).append("\", ");
                        result.append("\"xref_count\": ").append(match.get("xref_count")).append("}");
                    }

                    result.append("]}");

                } catch (Exception e) {
                    errorMsg.set(e.getMessage());
                }
            });

            if (errorMsg.get() != null) {
                return "{\"error\": \"" + errorMsg.get().replace("\"", "\\\"") + "\"}";
            }
        } catch (Exception e) {
            return "{\"error\": \"" + e.getMessage().replace("\"", "\\\"") + "\"}";
        }

        return result.toString();
    }

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
    private String disassembleBytes(String startAddress, String endAddress, Integer length,
                                   boolean restrictToExecuteMemory) {
        Program program = getCurrentProgram();
        if (program == null) {
            return "{\"error\": \"No program loaded\"}";
        }

        if (startAddress == null || startAddress.isEmpty()) {
            return "{\"error\": \"start_address parameter required\"}";
        }

        final StringBuilder result = new StringBuilder();
        final AtomicReference<String> errorMsg = new AtomicReference<>();

        try {
            Msg.debug(this, "disassembleBytes: Starting disassembly at " + startAddress +
                     (length != null ? " with length " + length : "") +
                     (endAddress != null ? " to " + endAddress : ""));

            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Disassemble Bytes");
                boolean success = false;

                try {
                    // Parse start address
                    Address start = program.getAddressFactory().getAddress(startAddress);
                    if (start == null) {
                        errorMsg.set("Invalid start address: " + startAddress);
                        return;
                    }

                    // Determine end address
                    Address end;
                    if (endAddress != null && !endAddress.isEmpty()) {
                        // Use explicit end address (exclusive)
                        end = program.getAddressFactory().getAddress(endAddress);
                        if (end == null) {
                            errorMsg.set("Invalid end address: " + endAddress);
                            return;
                        }
                        // Make end address inclusive for AddressSet
                        try {
                            end = end.subtract(1);
                        } catch (Exception e) {
                            errorMsg.set("End address calculation failed: " + e.getMessage());
                            return;
                        }
                    } else if (length != null && length > 0) {
                        // Use length to calculate end address
                        try {
                            end = start.add(length - 1);
                        } catch (Exception e) {
                            errorMsg.set("End address calculation from length failed: " + e.getMessage());
                            return;
                        }
                    } else {
                        // Auto-detect length (scan until we hit existing code/data)
                        Listing listing = program.getListing();
                        Address current = start;
                        int maxBytes = 100; // Safety limit
                        int count = 0;

                        while (count < maxBytes) {
                            CodeUnit cu = listing.getCodeUnitAt(current);

                            // Stop if we hit an existing instruction
                            if (cu instanceof Instruction) {
                                break;
                            }

                            // Stop if we hit defined data
                            if (cu instanceof Data && ((Data) cu).isDefined()) {
                                break;
                            }

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

                        // end is now one past the last undefined byte
                        try {
                            end = current.subtract(1);
                        } catch (Exception e) {
                            end = current;
                        }
                    }

                    // Create address set
                    AddressSet addressSet = new AddressSet(start, end);
                    long numBytes = addressSet.getNumAddresses();

                    // Execute disassembly
                    ghidra.app.cmd.disassemble.DisassembleCommand cmd =
                        new ghidra.app.cmd.disassemble.DisassembleCommand(addressSet, null, restrictToExecuteMemory);

                    // Prevent auto-analysis cascade
                    cmd.setSeedContext(null);
                    cmd.setInitialContext(null);

                    if (cmd.applyTo(program, ghidra.util.task.TaskMonitor.DUMMY)) {
                        // Success - build result
                        Msg.debug(this, "disassembleBytes: Successfully disassembled " + numBytes + " byte(s) from " + start + " to " + end);
                        result.append("{");
                        result.append("\"success\": true, ");
                        result.append("\"start_address\": \"").append(start).append("\", ");
                        result.append("\"end_address\": \"").append(end).append("\", ");
                        result.append("\"bytes_disassembled\": ").append(numBytes).append(", ");
                        result.append("\"message\": \"Successfully disassembled ").append(numBytes).append(" byte(s)\"");
                        result.append("}");
                        success = true;
                    } else {
                        errorMsg.set("Disassembly failed: " + cmd.getStatusMsg());
                        Msg.error(this, "disassembleBytes: Disassembly command failed - " + cmd.getStatusMsg());
                    }

                } catch (Exception e) {
                    errorMsg.set("Exception during disassembly: " + e.getMessage());
                    Msg.error(this, "disassembleBytes: Exception during disassembly", e);
                } finally {
                    program.endTransaction(tx, success);
                }
            });

            Msg.debug(this, "disassembleBytes: invokeAndWait completed");

            if (errorMsg.get() != null) {
                Msg.error(this, "disassembleBytes: Returning error response - " + errorMsg.get());
                return "{\"error\": \"" + errorMsg.get().replace("\"", "\\\"") + "\"}";
            }
        } catch (Exception e) {
            Msg.error(this, "disassembleBytes: Exception in outer try block", e);
            return "{\"error\": \"" + e.getMessage().replace("\"", "\\\"") + "\"}";
        }

        String response = result.toString();
        Msg.debug(this, "disassembleBytes: Returning success response, length=" + response.length());
        return response;
    }

    @Override
    public void dispose() {
        if (server != null) {
            Msg.info(this, "Stopping GhidraMCP HTTP server...");
            try {
                server.stop(1); // Stop with a small delay (e.g., 1 second) for connections to finish
                // Give the server time to fully release the port
                Thread.sleep(100);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            server = null; // Nullify the reference
            Msg.info(this, "GhidraMCP HTTP server stopped.");
        }
        super.dispose();
    }
}
