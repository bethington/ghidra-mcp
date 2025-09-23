package com.lauriewired;

import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
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

import javax.swing.SwingUtilities;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.InvocationTargetException;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;

@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = ghidra.app.DeveloperPluginPackage.NAME,
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "GhidraMCP v1.2.0 - HTTP server plugin",
    description = "GhidraMCP v1.2.0 - Starts an embedded HTTP server to expose program data via REST API and MCP bridge. " +
                  "Provides 57+ endpoints for reverse engineering automation. Port configurable via Tool Options. " +
                  "Features: function analysis, decompilation, symbol management, cross-references, and label operations."
)
public class GhidraMCPPlugin extends Plugin {

    private HttpServer server;
    private static final String OPTION_CATEGORY_NAME = "GhidraMCP HTTP Server";
    private static final String PORT_OPTION_NAME = "Server Port";
    private static final int DEFAULT_PORT = 8089;

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
        }
        catch (IOException e) {
            Msg.error(this, "Failed to start HTTP server", e);
        }
        Msg.info(this, "GhidraMCPPlugin loaded!");
    }

    private void startServer() throws IOException {
        // Read the configured port
        Options options = tool.getOptions(OPTION_CATEGORY_NAME);
        int port = options.getInt(PORT_OPTION_NAME, DEFAULT_PORT);

        // Stop existing server if running (e.g., if plugin is reloaded)
        if (server != null) {
            Msg.info(this, "Stopping existing HTTP server before starting new one.");
            server.stop(0);
            server = null;
        }

        server = HttpServer.create(new InetSocketAddress(port), 0);

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
            String response = renameFunction(params.get("oldName"), params.get("newName"))
                    ? "Renamed successfully" : "Rename failed";
            sendResponse(exchange, response);
        });

        // Alias for /renameFunction to match test expectations
        server.createContext("/rename_function", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String response = renameFunction(params.get("oldName"), params.get("newName"))
                    ? "Renamed successfully" : "Rename failed";
            sendResponse(exchange, response);
        });

        server.createContext("/renameData", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            renameDataAtAddress(params.get("address"), params.get("newName"));
            sendResponse(exchange, "Rename data attempted");
        });

        // Alias for /renameData to match test expectations
        server.createContext("/rename_data", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            renameDataAtAddress(params.get("address"), params.get("newName"));
            sendResponse(exchange, "Rename data attempted");
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
            boolean success = setDecompilerComment(address, comment);
            sendResponse(exchange, success ? "Comment set successfully" : "Failed to set comment");
        });

        server.createContext("/set_disassembly_comment", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String address = params.get("address");
            String comment = params.get("comment");
            boolean success = setDisassemblyComment(address, comment);
            sendResponse(exchange, success ? "Comment set successfully" : "Failed to set comment");
        });

        server.createContext("/rename_function_by_address", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String newName = params.get("new_name");
            boolean success = renameFunctionByAddress(functionAddress, newName);
            sendResponse(exchange, success ? "Function renamed successfully" : "Failed to rename function");
        });

        server.createContext("/set_function_prototype", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String functionAddress = params.get("function_address");
            String prototype = params.get("prototype");

            // Call the set prototype function and get detailed result
            PrototypeResult result = setFunctionPrototype(functionAddress, prototype);

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
            boolean success = setLocalVariableType(functionAddress, variableName, newType);

            String successMsg = success ? "Variable type set successfully" : "Failed to set variable type";
            responseMsg.append("\nResult: ").append(successMsg);

            sendResponse(exchange, responseMsg.toString());
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
            String fieldsJson = (fieldsObj instanceof String) ? (String) fieldsObj : 
                                (fieldsObj != null ? fieldsObj.toString() : null);
            sendResponse(exchange, createStruct(name, fieldsJson));
        });

        server.createContext("/create_enum", exchange -> {
            Map<String, Object> params = parseJsonParams(exchange);
            String name = (String) params.get("name");
            Object valuesObj = params.get("values");
            String valuesJson = (valuesObj instanceof String) ? (String) valuesObj : 
                                (valuesObj != null ? valuesObj.toString() : null);
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
            boolean success = renameGlobalVariable(oldName, newName);
            sendResponse(exchange, success ? "Global variable renamed successfully" : "Failed to rename global variable");
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
                // Convert to JSON string like struct endpoint does
                String fieldsJson = (fieldsObj instanceof String) ? (String) fieldsObj : 
                                    (fieldsObj != null ? fieldsObj.toString() : null);
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
            Map<String, String> params = parsePostParams(exchange);
            String name = params.get("name");
            String baseType = params.get("base_type");
            sendResponse(exchange, createTypedef(name, baseType));
        });

        server.createContext("/clone_data_type", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String sourceType = params.get("source_type");
            String newName = params.get("new_name");
            sendResponse(exchange, cloneDataType(sourceType, newName));
        });

        server.createContext("/validate_data_type", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            String typeName = qparams.get("type_name");
            sendResponse(exchange, validateDataType(address, typeName));
        });

        server.createContext("/export_data_types", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String format = qparams.getOrDefault("format", "c");
            String category = qparams.get("category");
            sendResponse(exchange, exportDataTypes(format, category));
        });

        server.createContext("/import_data_types", exchange -> {
            Map<String, String> params = parsePostParams(exchange);
            String source = params.get("source");
            String format = params.getOrDefault("format", "c");
            sendResponse(exchange, importDataTypes(source, format));
        });

        // Memory reading endpoint
        server.createContext("/readMemory", exchange -> {
            Map<String, String> qparams = parseQueryParams(exchange);
            String address = qparams.get("address");
            String lengthStr = qparams.get("length");
            int length = parseIntOrDefault(lengthStr, 16);
            sendResponse(exchange, readMemory(address, length));
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
                    String label   = data.getLabel() != null ? data.getLabel() : "(unnamed)";
                    String valRepr = data.getDefaultValueRepresentation();
                    lines.add(String.format("%s: %s = %s",
                        data.getAddress(),
                        escapeNonAscii(label),
                        escapeNonAscii(valRepr)
                    ));
                }
            }
        }
        return paginateList(lines, offset, limit);
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
                    decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
                if (result != null && result.decompileCompleted()) {
                    return result.getDecompiledFunction().getC();
                } else {
                    return "Decompilation failed";
                }
            }
        }
        return "Function not found";
    }

    private boolean renameFunction(String oldName, String newName) {
        Program program = getCurrentProgram();
        if (program == null) return false;

        AtomicBoolean successFlag = new AtomicBoolean(false);
        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Rename function via HTTP");
                try {
                    for (Function func : program.getFunctionManager().getFunctions(true)) {
                        if (func.getName().equals(oldName)) {
                            func.setName(newName, SourceType.USER_DEFINED);
                            successFlag.set(true);
                            break;
                        }
                    }
                }
                catch (Exception e) {
                    Msg.error(this, "Error renaming function", e);
                }
                finally {
                    successFlag.set(program.endTransaction(tx, successFlag.get()));
                }
            });
        }
        catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute rename on Swing thread", e);
        }
        return successFlag.get();
    }

    private void renameDataAtAddress(String addressStr, String newName) {
        Program program = getCurrentProgram();
        if (program == null) return;

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Rename data");
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    Listing listing = program.getListing();
                    Data data = listing.getDefinedDataAt(addr);
                    if (data != null) {
                        SymbolTable symTable = program.getSymbolTable();
                        Symbol symbol = symTable.getPrimarySymbol(addr);
                        if (symbol != null) {
                            symbol.setName(newName, SourceType.USER_DEFINED);
                        } else {
                            symTable.createLabel(addr, newName, SourceType.USER_DEFINED);
                        }
                    }
                }
                catch (Exception e) {
                    Msg.error(this, "Rename data error", e);
                }
                finally {
                    program.endTransaction(tx, true);
                }
            });
        }
        catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute rename data on Swing thread", e);
        }
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

        DecompileResults result = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());
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
            DecompileResults result = decomp.decompileFunction(func, 30, new ConsoleTaskMonitor());

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
    private boolean setCommentAtAddress(String addressStr, String comment, int commentType, String transactionName) {
        Program program = getCurrentProgram();
        if (program == null) return false;
        if (addressStr == null || addressStr.isEmpty() || comment == null) return false;

        AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction(transactionName);
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    program.getListing().setComment(addr, commentType, comment);
                    success.set(true);
                } catch (Exception e) {
                    Msg.error(this, "Error setting " + transactionName.toLowerCase(), e);
                } finally {
                    success.set(program.endTransaction(tx, success.get()));
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute " + transactionName.toLowerCase() + " on Swing thread", e);
        }

        return success.get();
    }

    /**
     * Set a comment for a given address in the function pseudocode
     */
    @SuppressWarnings("deprecation")
    private boolean setDecompilerComment(String addressStr, String comment) {
        return setCommentAtAddress(addressStr, comment, CodeUnit.PRE_COMMENT, "Set decompiler comment");
    }

    /**
     * Set a comment for a given address in the function disassembly
     */
    @SuppressWarnings("deprecation")
    private boolean setDisassemblyComment(String addressStr, String comment) {
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
    private boolean renameFunctionByAddress(String functionAddrStr, String newName) {
        Program program = getCurrentProgram();
        if (program == null) return false;
        if (functionAddrStr == null || functionAddrStr.isEmpty() || 
            newName == null || newName.isEmpty()) {
            return false;
        }

        AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {
                performFunctionRename(program, functionAddrStr, newName, success);
            });
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute rename function on Swing thread", e);
        }

        return success.get();
    }

    /**
     * Helper method to perform the actual function rename within a transaction
     */
    private void performFunctionRename(Program program, String functionAddrStr, String newName, AtomicBoolean success) {
        int tx = program.startTransaction("Rename function by address");
        try {
            Address addr = program.getAddressFactory().getAddress(functionAddrStr);
            Function func = getFunctionForAddress(program, addr);

            if (func == null) {
                Msg.error(this, "Could not find function at address: " + functionAddrStr);
                return;
            }

            func.setName(newName, SourceType.USER_DEFINED);
            success.set(true);
        } catch (Exception e) {
            Msg.error(this, "Error renaming function by address", e);
        } finally {
            program.endTransaction(tx, success.get());
        }
    }

    /**
     * Set a function's prototype with proper error handling using ApplyFunctionSignatureCmd
     */
    private PrototypeResult setFunctionPrototype(String functionAddrStr, String prototype) {
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
                applyFunctionPrototype(program, functionAddrStr, prototype, success, errorMessage));
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
                                       AtomicBoolean success, StringBuilder errorMessage) {
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
            parseFunctionSignatureAndApply(program, addr, prototype, success, errorMessage);

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
                                              AtomicBoolean success, StringBuilder errorMessage) {
        // Use ApplyFunctionSignatureCmd to parse and apply the signature
        int txProto = program.startTransaction("Set function prototype");
        try {
            // Get data type manager
            DataTypeManager dtm = program.getDataTypeManager();

            // Get data type manager service
            ghidra.app.services.DataTypeManagerService dtms = 
                tool.getService(ghidra.app.services.DataTypeManagerService.class);

            // Create function signature parser
            ghidra.app.util.parser.FunctionSignatureParser parser = 
                new ghidra.app.util.parser.FunctionSignatureParser(dtm, dtms);

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
                success.set(true);
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
            program.endTransaction(txProto, success.get());
        }
    }

    /**
     * Set a local variable's type using HighFunctionDBUtil.updateDBVariable
     */
    private boolean setLocalVariableType(String functionAddrStr, String variableName, String newType) {
        // Input validation
        Program program = getCurrentProgram();
        if (program == null) return false;
        if (functionAddrStr == null || functionAddrStr.isEmpty() || 
            variableName == null || variableName.isEmpty() ||
            newType == null || newType.isEmpty()) {
            return false;
        }

        AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> 
                applyVariableType(program, functionAddrStr, variableName, newType, success));
        } catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute set variable type on Swing thread", e);
        }

        return success.get();
    }

    /**
     * Helper method that performs the actual variable type change
     */
    private void applyVariableType(Program program, String functionAddrStr, 
                                  String variableName, String newType, AtomicBoolean success) {
        try {
            // Find the function
            Address addr = program.getAddressFactory().getAddress(functionAddrStr);
            Function func = getFunctionForAddress(program, addr);

            if (func == null) {
                Msg.error(this, "Could not find function at address: " + functionAddrStr);
                return;
            }

            DecompileResults results = decompileFunction(func, program);
            if (results == null || !results.decompileCompleted()) {
                return;
            }

            ghidra.program.model.pcode.HighFunction highFunction = results.getHighFunction();
            if (highFunction == null) {
                Msg.error(this, "No high function available");
                return;
            }

            // Find the symbol by name
            HighSymbol symbol = findSymbolByName(highFunction, variableName);
            if (symbol == null) {
                Msg.error(this, "Could not find variable '" + variableName + "' in decompiled function");
                return;
            }

            // Get high variable
            HighVariable highVar = symbol.getHighVariable();
            if (highVar == null) {
                Msg.error(this, "No HighVariable found for symbol: " + variableName);
                return;
            }

            Msg.info(this, "Found high variable for: " + variableName + 
                     " with current type " + highVar.getDataType().getName());

            // Find the data type
            DataTypeManager dtm = program.getDataTypeManager();
            DataType dataType = resolveDataType(dtm, newType);

            if (dataType == null) {
                Msg.error(this, "Could not resolve data type: " + newType);
                return;
            }

            Msg.info(this, "Using data type: " + dataType.getName() + " for variable " + variableName);

            // Apply the type change in a transaction
            updateVariableType(program, symbol, dataType, success);

        } catch (Exception e) {
            Msg.error(this, "Error setting variable type: " + e.getMessage());
        }
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
        DecompileResults results = decomp.decompileFunction(func, 60, new ConsoleTaskMonitor());

        if (!results.decompileCompleted()) {
            Msg.error(this, "Could not decompile function: " + results.getErrorMessage());
            return null;
        }

        return results;
    }

    /**
     * Apply the type update in a transaction
     */
    private void updateVariableType(Program program, HighSymbol symbol, DataType dataType, AtomicBoolean success) {
        int tx = program.startTransaction("Set variable type");
        try {
            // Use HighFunctionDBUtil to update the variable with the new type
            HighFunctionDBUtil.updateDBVariable(
                symbol,                // The high symbol to modify
                symbol.getName(),      // Keep original name
                dataType,              // The new data type
                SourceType.USER_DEFINED // Mark as user-defined
            );

            success.set(true);
            Msg.info(this, "Successfully set variable type using HighFunctionDBUtil");
        } catch (Exception e) {
            Msg.error(this, "Error setting variable type: " + e.getMessage());
        } finally {
            program.endTransaction(tx, success.get());
        }
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

                // Fallback to int if we couldn't find it
                Msg.warn(this, "Unknown type: " + typeName + ", defaulting to int");
                return dtm.getDataType("/int");
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
                            // Array value - keep as string for now
                            result.put(key, value);
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
        exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
        exchange.sendResponseHeaders(200, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
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

            // Create the structure
            int txId = program.startTransaction("Create Structure: " + name);
            try {
                ghidra.program.model.data.StructureDataType struct = 
                    new ghidra.program.model.data.StructureDataType(name, 0);
                
                // Add fields sequentially for simplicity
                for (FieldDefinition field : fields) {
                    DataType fieldType = resolveDataType(dtm, field.type);
                    if (fieldType == null) {
                        return "Unknown field type: " + field.type;
                    }
                    
                    // Add field to the end of the structure
                    struct.add(fieldType, fieldType.getLength(), field.name, "");
                }
                
                // Add the structure to the data type manager
                DataType createdStruct = dtm.addDataType(struct, null);
                
                program.endTransaction(txId, true);
                
                return "Successfully created structure '" + name + "' with " + fields.size() + 
                       " fields, total size: " + createdStruct.getLength() + " bytes";
                       
            } catch (Exception e) {
                program.endTransaction(txId, false);
                return "Error creating structure: " + e.getMessage();
            }
            
        } catch (Exception e) {
            return "Error parsing fields JSON: " + e.getMessage();
        }
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
     * Parse fields JSON into FieldDefinition objects
     */
    private List<FieldDefinition> parseFieldsJson(String fieldsJson) {
        List<FieldDefinition> fields = new ArrayList<>();
        
        try {
            // Remove outer brackets and whitespace
            String content = fieldsJson.trim();
            if (content.startsWith("[")) {
                content = content.substring(1);
            }
            if (content.endsWith("]")) {
                content = content.substring(0, content.length() - 1);
            }
            
            // Split by field objects (simple parsing)
            String[] fieldStrings = content.split("\\},\\s*\\{");
            
            for (String fieldStr : fieldStrings) {
                // Clean up braces
                fieldStr = fieldStr.replace("{", "").replace("}", "").trim();
                
                String name = null;
                String type = null;
                int offset = -1;
                
                // Parse key-value pairs
                String[] pairs = fieldStr.split(",");
                for (String pair : pairs) {
                    String[] keyValue = pair.split(":");
                    if (keyValue.length == 2) {
                        String key = keyValue[0].trim().replace("\"", "");
                        String value = keyValue[1].trim().replace("\"", "");
                        
                        switch (key) {
                            case "name":
                                name = value;
                                break;
                            case "type":
                                type = value;
                                break;
                            case "offset":
                                try {
                                    offset = Integer.parseInt(value);
                                } catch (NumberFormatException e) {
                                    // Ignore invalid offset
                                }
                                break;
                        }
                    }
                }
                
                if (name != null && type != null) {
                    fields.add(new FieldDefinition(name, type, offset));
                }
            }
        } catch (Exception e) {
            // Return empty list on parse error
        }
        
        return fields;
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
                return "Unknown data type: " + typeName;
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
                
                String result = "Successfully applied data type '" + typeName + "' at " + 
                               addressStr + " (size: " + dataType.getLength() + " bytes)";
                
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
    private boolean renameGlobalVariable(String oldName, String newName) {
        Program program = getCurrentProgram();
        if (program == null) {
            return false;
        }

        if (oldName == null || oldName.isEmpty() || newName == null || newName.isEmpty()) {
            return false;
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
                return false;
            }
            
            // Rename the first matching symbol
            Symbol symbol = symbols.get(0);
            symbol.setName(newName, SourceType.USER_DEFINED);
            
            program.endTransaction(txId, true);
            return true;
            
        } catch (Exception e) {
            program.endTransaction(txId, false);
            Msg.error(this, "Error renaming global variable: " + e.getMessage());
            return false;
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
                    DataType base = findDataTypeByNameInAllCategories(dtm, baseType);

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

    @Override
    public void dispose() {
        if (server != null) {
            Msg.info(this, "Stopping GhidraMCP HTTP server...");
            server.stop(1); // Stop with a small delay (e.g., 1 second) for connections to finish
            server = null; // Nullify the reference
            Msg.info(this, "GhidraMCP HTTP server stopped.");
        }
        super.dispose();
    }
}
