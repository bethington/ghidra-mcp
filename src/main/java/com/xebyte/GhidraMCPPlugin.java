package com.xebyte;

import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.data.*;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.services.CodeViewerService;
import ghidra.app.services.GoToService;

import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;

import docking.action.DockingAction;
import docking.action.MenuData;
import docking.ActionContext;

import com.xebyte.core.*;

import ghidra.framework.main.ApplicationLevelPlugin;

import ghidra.framework.model.DomainFile;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectData;
import ghidra.framework.client.RepositoryAdapter;

import ghidra.util.task.TaskMonitor;

import javax.swing.SwingUtilities;
import java.io.*;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;

// Load version from properties file (populated by Maven during build)
class VersionInfo {
    private static String VERSION = "4.0.0"; // Default fallback
    private static String APP_NAME = "GhidraMCP";
    private static String GHIDRA_VERSION = "unknown";
    private static String BUILD_TIMESTAMP = "dev";
    private static String BUILD_NUMBER = "0";
    private static final int ENDPOINT_COUNT = 171;

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

    public static String getVersion() { return VERSION; }
    public static String getAppName() { return APP_NAME; }
    public static String getGhidraVersion() { return GHIDRA_VERSION; }
    public static String getBuildTimestamp() { return BUILD_TIMESTAMP; }
    public static String getBuildNumber() { return BUILD_NUMBER; }
    public static int getEndpointCount() { return ENDPOINT_COUNT; }
    public static String getFullVersion() {
        return VERSION + " (build " + BUILD_NUMBER + ", " + BUILD_TIMESTAMP + ")";
    }
}

@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = ghidra.framework.main.UtilityPluginPackage.NAME,
    category = PluginCategoryNames.COMMON,
    shortDescription = "GhidraMCP - MCP server plugin",
    description = "GhidraMCP - Starts a UDS server to expose program data via MCP bridge. " +
                  "Provides 171 endpoints for reverse engineering automation. " +
                  "See https://github.com/bethington/ghidra-mcp for documentation and version history."
)
public class GhidraMCPPlugin extends Plugin implements ApplicationLevelPlugin {

    private static int instanceCount = 0;

    // Menu action for Tools > GhidraMCP submenu
    private DockingAction serverStatusAction;

    // Program provider for on-demand program access (FrontEnd mode)
    private final FrontEndProgramProvider programProvider;

    // Server authenticator for programmatic login
    private GhidraMCPAuthenticator authenticator;

    // Service layer for delegated operations
    private final FunctionService functionService;
    private final AnalysisService analysisService;
    private final ProgramScriptService programScriptService;

    public GhidraMCPPlugin(PluginTool tool) {
        super(tool);
        instanceCount++;

        // Initialize service layer — FrontEnd mode: opens programs on-demand from project
        this.programProvider = new FrontEndProgramProvider(tool, this);
        ThreadingStrategy threadingStrategy = new com.xebyte.headless.DirectThreadingStrategy();
        this.functionService = new FunctionService(programProvider, threadingStrategy);
        this.analysisService = new AnalysisService(programProvider, threadingStrategy, this.functionService);
        this.programScriptService = new ProgramScriptService(programProvider, threadingStrategy);

        Msg.info(this, "============================================");
        Msg.info(this, "GhidraMCP " + VersionInfo.getFullVersion());
        Msg.info(this, "Endpoints: " + VersionInfo.getEndpointCount());
        Msg.info(this, "============================================");

        // Register with ServerManager for UDS transport (shared across all CodeBrowser windows)
        try {
            ServerManager.getInstance().registerTool(tool, this::registerGuiEndpoints);
        } catch (IOException e) {
            Msg.error(this, "Failed to start UDS server: " + e.getMessage(), e);
        }

        if (GhidraMCPAuthInitializer.isRegistered()) {
            this.authenticator = GhidraMCPAuthInitializer.getAuthenticator();
            Msg.info(this, "GhidraMCP: Server authenticator was registered at startup");
        }

        Path socketPath = ServerManager.getInstance().getSocketPath();
        Msg.info(this, "GhidraMCPPlugin loaded successfully on UDS: " +
            (socketPath != null ? socketPath : "N/A"));

        createMenuActions();
    }

    private void createMenuActions() {
        serverStatusAction = new DockingAction("Server Status", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                Path socketPath = ServerManager.getInstance().getSocketPath();
                String status = socketPath != null ? "Running" : "Stopped";
                String message = "GhidraMCP Server Status\n\n" +
                    "Status: " + status + "\n" +
                    "Socket: " + (socketPath != null ? socketPath : "N/A") + "\n" +
                    "Version: " + VersionInfo.getFullVersion() + "\n" +
                    "Endpoints: " + VersionInfo.getEndpointCount();
                Msg.showInfo(getClass(), null, "GhidraMCP", message);
            }
        };
        serverStatusAction.setMenuBarData(new MenuData(new String[]{"Tools", "GhidraMCP", "Server Status"}));
        tool.addAction(serverStatusAction);
    }

    // ==================================================================================
    // GUI-specific endpoint registration (passed to ServerManager)
    // ==================================================================================

    private void registerGuiEndpoints(EndpointRegistrar.ContextRegistrar registrar) {

        // ======================================================================
        // GUI-specific utility endpoints
        // ======================================================================

        registrar.createContext("/check_connection", EndpointRegistrar.safeHandler(exchange -> {
            Program program = getCurrentProgram();
            String msg = (program != null)
                ? "Connected: GhidraMCP plugin running with program '" + program.getName() + "'"
                : "Connected: GhidraMCP plugin running, but no program loaded";
            EndpointRegistrar.sendResponse(exchange, Response.text(msg));
        }));

        registrar.createContext("/get_version", EndpointRegistrar.safeHandler(exchange -> {
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
            EndpointRegistrar.sendResponse(exchange, Response.text(version.toString()));
        }));

        registrar.createContext("/convert_number", EndpointRegistrar.safeHandler(exchange -> {
            Map<String, String> qparams = EndpointRegistrar.parseQueryParams(exchange);
            String text = qparams.get("text");
            int size = EndpointRegistrar.parseIntOrDefault(qparams.get("size"), 4);
            EndpointRegistrar.sendResponse(exchange, Response.text(ServiceUtils.convertNumber(text, size)));
        }));

        // ======================================================================
        // GUI-specific endpoints (need CodeViewerService, tool, etc.)
        // ======================================================================

        registrar.createContext("/get_current_address", EndpointRegistrar.safeHandler(exchange -> {
            EndpointRegistrar.sendResponse(exchange, Response.text(getCurrentAddress()));
        }));

        registrar.createContext("/get_current_function", EndpointRegistrar.safeHandler(exchange -> {
            EndpointRegistrar.sendResponse(exchange, Response.text(getCurrentFunction()));
        }));

        // ======================================================================
        // Complex inline endpoints (no service method)
        // ======================================================================

        // GET_DATA_TYPE_SIZE - uses plugin-local resolveDataType
        registrar.createContext("/get_data_type_size", EndpointRegistrar.safeHandler(exchange -> {
            Map<String, String> qparams = EndpointRegistrar.parseQueryParams(exchange);
            String typeName = qparams.get("type_name");
            if (typeName == null || typeName.isEmpty()) {
                EndpointRegistrar.sendResponse(exchange, Response.err("type_name parameter is required"));
                return;
            }
            Program program = getCurrentProgram();
            if (program == null) {
                EndpointRegistrar.sendResponse(exchange, Response.err("No program open"));
                return;
            }
            DataType dt = ServiceUtils.findDataTypeByNameInAllCategories(
                program.getDataTypeManager(), typeName);
            if (dt == null) {
                EndpointRegistrar.sendResponse(exchange, Response.err("Data type not found: " + typeName));
                return;
            }
            String category = dt.getCategoryPath().toString();
            if (category.equals("/")) category = "builtin";
            EndpointRegistrar.sendResponse(exchange, Response.ok(Map.of(
                "type_name", dt.getName(),
                "size", dt.getLength(),
                "category", category)));
        }));

        // ANALYZE_FUNCTION_COMPLETENESS - with decompiler cache refresh
        registrar.createContext("/analyze_function_completeness", EndpointRegistrar.safeHandler(exchange -> {
            Map<String, String> qparams = EndpointRegistrar.parseQueryParams(exchange);
            String functionAddress = qparams.get("function_address");
            // Force decompiler cache refresh before analysis
            Program program = getCurrentProgram();
            if (program != null && functionAddress != null && !functionAddress.isEmpty()) {
                try {
                    Address addr = program.getAddressFactory().getAddress(functionAddress);
                    if (addr != null) {
                        Function func = program.getFunctionManager().getFunctionAt(addr);
                        if (func != null) {
                            ghidra.app.decompiler.DecompInterface tempDecomp = new ghidra.app.decompiler.DecompInterface();
                            tempDecomp.openProgram(program);
                            tempDecomp.flushCache();
                            tempDecomp.decompileFunction(func, 60, new ghidra.util.task.ConsoleTaskMonitor());
                            tempDecomp.dispose();
                        }
                    }
                } catch (Exception e) {
                    Msg.warn(this, "Failed to refresh cache before completeness analysis: " + e.getMessage());
                }
            }
            EndpointRegistrar.sendResponse(exchange, analysisService.analyzeFunctionCompleteness(functionAddress));
        }));

        // BATCH_ANALYZE_COMPLETENESS - loop over addresses
        registrar.createContext("/batch_analyze_completeness", EndpointRegistrar.safeHandler(exchange -> {
            Map<String, Object> params = EndpointRegistrar.parseJsonParams(exchange);
            @SuppressWarnings("unchecked")
            List<String> addresses = (List<String>) params.get("addresses");
            if (addresses == null || addresses.isEmpty()) {
                EndpointRegistrar.sendResponse(exchange, Response.err("Missing required parameter: addresses"));
                return;
            }
            // Refresh decompiler cache once for all functions
            Program program = getCurrentProgram();
            if (program != null) {
                try {
                    ghidra.app.decompiler.DecompInterface tempDecomp = new ghidra.app.decompiler.DecompInterface();
                    tempDecomp.openProgram(program);
                    tempDecomp.flushCache();
                    for (String addr : addresses) {
                        Address a = program.getAddressFactory().getAddress(addr);
                        if (a != null) {
                            Function f = program.getFunctionManager().getFunctionAt(a);
                            if (f != null) {
                                tempDecomp.decompileFunction(f, 60, new ghidra.util.task.ConsoleTaskMonitor());
                            }
                        }
                    }
                    tempDecomp.dispose();
                } catch (Exception e) {
                    Msg.warn(this, "Failed to refresh cache for batch completeness: " + e.getMessage());
                }
            }
            List<Object> results = new ArrayList<>();
            for (String addr : addresses) {
                results.add(analysisService.analyzeFunctionCompleteness(addr));
            }
            EndpointRegistrar.sendResponse(exchange, Response.ok(Map.of(
                "results", results, "count", addresses.size())));
        }));

        // BATCH_SET_VARIABLE_TYPES - uses plugin-local optimized method
        registrar.createContext("/batch_set_variable_types", EndpointRegistrar.safeHandler(exchange -> {
            Map<String, Object> params = EndpointRegistrar.parseJsonParams(exchange);
            String functionAddress = (String) params.get("function_address");
            Map<String, String> variableTypes = new HashMap<>();
            Object vtObj = params.get("variable_types");
            if (vtObj instanceof Map) {
                @SuppressWarnings("unchecked")
                Map<String, String> vtMap = (Map<String, String>) vtObj;
                variableTypes = vtMap;
            }
            String result = batchSetVariableTypesOptimized(functionAddress, variableTypes);
            EndpointRegistrar.sendResponse(exchange, Response.text(result));
        }));

        // RUN_SCRIPT_INLINE - complex inline logic
        registrar.createContext("/run_script_inline", EndpointRegistrar.safeHandler(exchange -> {
            Map<String, Object> params = EndpointRegistrar.parseJsonParams(exchange);
            String code = (String) params.get("code");
            String scriptArgs = (String) params.get("args");
            if (code == null || code.isEmpty()) {
                EndpointRegistrar.sendResponse(exchange, Response.err("code parameter is required"));
                return;
            }
            String uid = Long.toHexString(System.nanoTime());
            String userClass = null;
            java.util.regex.Matcher m = java.util.regex.Pattern
                .compile("public\\s+class\\s+(\\w+)").matcher(code);
            if (m.find()) userClass = m.group(1);
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
                EndpointRegistrar.sendResponse(exchange,
                    programScriptService.runGhidraScript(tempScript.getAbsolutePath(), scriptArgs));
            } catch (Throwable e2) {
                EndpointRegistrar.sendResponse(exchange, Response.err(e2.getMessage()));
            } finally {
                if (!tempScript.delete()) tempScript.deleteOnExit();
                File classFile = new File(scriptDir, className + ".class");
                if (classFile.exists() && !classFile.delete()) classFile.deleteOnExit();
            }
        }));

        // GET_FUNCTION_VARIABLES - with function_address->function_name resolution
        registrar.createContext("/get_function_variables", EndpointRegistrar.safeHandler(exchange -> {
            Map<String, String> qparams = EndpointRegistrar.parseQueryParams(exchange);
            String functionName = qparams.get("function_name");
            String functionAddress = qparams.get("function_address");
            String programName = qparams.get("program");
            // Accept function_address as alternative to function_name
            if ((functionName == null || functionName.isEmpty()) && functionAddress != null && !functionAddress.isEmpty()) {
                Program prog = programProvider.resolveProgram(programName);
                if (prog != null) {
                    Address addr = prog.getAddressFactory().getAddress(functionAddress);
                    if (addr != null) {
                        Function func = prog.getFunctionManager().getFunctionAt(addr);
                        if (func == null) func = prog.getFunctionManager().getFunctionContaining(addr);
                        if (func != null) functionName = func.getName();
                    }
                }
            }
            EndpointRegistrar.sendResponse(exchange, functionService.getFunctionVariables(functionName, programName));
        }));

        // FORCE_DECOMPILE - with GET/POST fallback for backward compat
        registrar.createContext("/force_decompile", EndpointRegistrar.safeHandler(exchange -> {
            Map<String, String> params = EndpointRegistrar.parseQueryParams(exchange);
            String functionAddress = params.get("address");
            if (functionAddress == null || functionAddress.isEmpty()) {
                Map<String, String> postParams = EndpointRegistrar.parsePostParams(exchange);
                functionAddress = postParams.get("function_address");
                if (functionAddress == null || functionAddress.isEmpty()) {
                    functionAddress = postParams.get("address");
                }
            }
            if (functionAddress == null || functionAddress.isEmpty()) {
                EndpointRegistrar.sendResponse(exchange, Response.err("address parameter is required"));
                return;
            }
            EndpointRegistrar.sendResponse(exchange, functionService.forceDecompile(functionAddress));
        }));

        // ======================================================================
        // PROJECT VERSION CONTROL ENDPOINTS (GUI mode - uses tool.getProject())
        // ======================================================================

        registrar.createContext("/server/connect", EndpointRegistrar.safeHandler(exchange -> {
            Project project = tool.getProject();
            if (project == null) {
                EndpointRegistrar.sendResponse(exchange, Response.err("No project open in Ghidra"));
                return;
            }
            boolean isShared = getProjectRepository() != null;
            EndpointRegistrar.sendResponse(exchange, Response.ok(Map.of(
                "status", "connected",
                "project", project.getName(),
                "shared", isShared,
                "message", "GUI plugin uses the open Ghidra project directly.")));
        }));

        registrar.createContext("/server/disconnect", EndpointRegistrar.safeHandler(exchange -> {
            EndpointRegistrar.sendResponse(exchange, Response.ok(Map.of(
                "status", "ok",
                "message", "GUI plugin uses the open project. No disconnect needed.")));
        }));

        registrar.createContext("/server/status", EndpointRegistrar.safeHandler(exchange -> {
            EndpointRegistrar.sendResponse(exchange, Response.text(getProjectStatusJson()));
        }));

        registrar.createContext("/server/repositories", EndpointRegistrar.safeHandler(exchange -> {
            Project project = tool.getProject();
            if (project == null) {
                EndpointRegistrar.sendResponse(exchange, Response.err("No project open"));
                return;
            }
            EndpointRegistrar.sendResponse(exchange, Response.ok(Map.of(
                "repositories", List.of(project.getName()),
                "count", 1,
                "message", "GUI mode returns the current project.")));
        }));

        registrar.createContext("/server/repository/files", EndpointRegistrar.safeHandler(exchange -> {
            Map<String, String> params = EndpointRegistrar.parseQueryParams(exchange);
            String folderPath = params.get("path");
            if (folderPath == null) folderPath = params.get("folder");
            if (folderPath == null) folderPath = "/";
            EndpointRegistrar.sendResponse(exchange, Response.text(listProjectFilesJson(folderPath)));
        }));

        registrar.createContext("/server/repository/file", EndpointRegistrar.safeHandler(exchange -> {
            Map<String, String> params = EndpointRegistrar.parseQueryParams(exchange);
            String filePath = params.get("path");
            if (filePath == null) {
                EndpointRegistrar.sendResponse(exchange, Response.err("'path' parameter required"));
                return;
            }
            EndpointRegistrar.sendResponse(exchange, Response.text(getProjectFileInfoJson(filePath)));
        }));

        registrar.createContext("/server/repository/create", EndpointRegistrar.safeHandler(exchange -> {
            EndpointRegistrar.sendResponse(exchange, Response.err("Repository creation not available in GUI mode."));
        }));

        registrar.createContext("/server/version_control/checkout", EndpointRegistrar.safeHandler(exchange -> {
            Map<String, Object> params = EndpointRegistrar.parseJsonParams(exchange);
            String filePath = params.get("path") != null ? params.get("path").toString() : null;
            boolean exclusive = params.get("exclusive") == null || Boolean.parseBoolean(params.get("exclusive").toString());
            EndpointRegistrar.sendResponse(exchange, Response.text(checkoutProjectFile(filePath, exclusive)));
        }));

        registrar.createContext("/server/version_control/checkin", EndpointRegistrar.safeHandler(exchange -> {
            Map<String, Object> params = EndpointRegistrar.parseJsonParams(exchange);
            String filePath = params.get("path") != null ? params.get("path").toString() : null;
            String comment = params.getOrDefault("comment", "Checked in via GhidraMCP").toString();
            boolean keepCheckedOut = Boolean.parseBoolean(params.getOrDefault("keepCheckedOut", "false").toString());
            EndpointRegistrar.sendResponse(exchange, Response.text(checkinProjectFile(filePath, comment, keepCheckedOut)));
        }));

        registrar.createContext("/server/version_control/undo_checkout", EndpointRegistrar.safeHandler(exchange -> {
            Map<String, Object> params = EndpointRegistrar.parseJsonParams(exchange);
            String filePath = params.get("path") != null ? params.get("path").toString() : null;
            boolean keep = Boolean.parseBoolean(params.getOrDefault("keep", "false").toString());
            EndpointRegistrar.sendResponse(exchange, Response.text(undoCheckoutProjectFile(filePath, keep)));
        }));

        registrar.createContext("/server/version_control/add", EndpointRegistrar.safeHandler(exchange -> {
            Map<String, Object> params = EndpointRegistrar.parseJsonParams(exchange);
            String filePath = params.get("path") != null ? params.get("path").toString() : null;
            String comment = params.getOrDefault("comment", "Added via GhidraMCP").toString();
            EndpointRegistrar.sendResponse(exchange, Response.text(addToVersionControl(filePath, comment)));
        }));

        registrar.createContext("/server/version_history", EndpointRegistrar.safeHandler(exchange -> {
            Map<String, String> params = EndpointRegistrar.parseQueryParams(exchange);
            EndpointRegistrar.sendResponse(exchange, Response.text(getProjectFileVersionHistory(params.get("path"))));
        }));

        registrar.createContext("/server/checkouts", EndpointRegistrar.safeHandler(exchange -> {
            Map<String, String> params = EndpointRegistrar.parseQueryParams(exchange);
            String folderPath = params.get("path");
            if (folderPath == null) folderPath = "/";
            EndpointRegistrar.sendResponse(exchange, Response.text(listProjectCheckouts(folderPath)));
        }));

        registrar.createContext("/server/admin/terminate_checkout", EndpointRegistrar.safeHandler(exchange -> {
            Map<String, Object> params = EndpointRegistrar.parseJsonParams(exchange);
            String filePath = params.get("path") != null ? params.get("path").toString() : null;
            EndpointRegistrar.sendResponse(exchange, Response.text(terminateFileCheckout(filePath)));
        }));

        registrar.createContext("/server/admin/terminate_all_checkouts", EndpointRegistrar.safeHandler(exchange -> {
            Map<String, Object> params = EndpointRegistrar.parseJsonParams(exchange);
            String folderPath = params.get("path") != null ? params.get("path").toString() : "/";
            EndpointRegistrar.sendResponse(exchange, Response.text(terminateAllCheckouts(folderPath)));
        }));

        registrar.createContext("/server/admin/users", EndpointRegistrar.safeHandler(exchange -> {
            EndpointRegistrar.sendResponse(exchange, Response.err("User listing requires headless mode."));
        }));

        registrar.createContext("/server/admin/set_permissions", EndpointRegistrar.safeHandler(exchange -> {
            EndpointRegistrar.sendResponse(exchange, Response.err("Permission management requires headless mode."));
        }));

        // ======================================================================
        // PROJECT & TOOL MANAGEMENT ENDPOINTS
        // ======================================================================

        registrar.createContext("/project/info", EndpointRegistrar.safeHandler(exchange -> {
            EndpointRegistrar.sendResponse(exchange, Response.text(getProjectInfo()));
        }));

        registrar.createContext("/tool/running_tools", EndpointRegistrar.safeHandler(exchange -> {
            EndpointRegistrar.sendResponse(exchange, Response.text(getRunningTools()));
        }));

        registrar.createContext("/tool/launch_codebrowser", EndpointRegistrar.safeHandler(exchange -> {
            Map<String, Object> params = EndpointRegistrar.parseJsonParams(exchange);
            String filePath = params.get("path") != null ? params.get("path").toString() : null;
            EndpointRegistrar.sendResponse(exchange, Response.text(launchCodeBrowser(filePath)));
        }));

        registrar.createContext("/tool/goto_address", EndpointRegistrar.safeHandler(exchange -> {
            Map<String, Object> params = EndpointRegistrar.parseJsonParams(exchange);
            String address = params.get("address") != null ? params.get("address").toString() : null;
            EndpointRegistrar.sendResponse(exchange, Response.text(gotoAddress(address)));
        }));

        registrar.createContext("/server/authenticate", EndpointRegistrar.safeHandler(exchange -> {
            Map<String, Object> params = EndpointRegistrar.parseJsonParams(exchange);
            String username = params.get("username") != null ? params.get("username").toString() : null;
            String password = params.get("password") != null ? params.get("password").toString() : null;
            EndpointRegistrar.sendResponse(exchange, Response.text(authenticateServer(username, password)));
        }));
    }

    // ==================================================================================
    // GUI-specific helper methods (cannot be in shared endpoints)
    // ==================================================================================

    private String getCurrentAddress() {
        CodeViewerService service = tool.getService(CodeViewerService.class);
        if (service == null) return "Code viewer service not available";
        ProgramLocation location = service.getCurrentLocation();
        return (location != null) ? location.getAddress().toString() : "No current location";
    }

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
            func.getName(), func.getEntryPoint(), func.getSignature());
    }

    public Program getCurrentProgram() {
        return programProvider.getCurrentProgram();
    }

    // ==================================================================================
    // Plugin-local methods that have no service equivalent
    // ==================================================================================

    /**
     * Optimized batch set variable types - calls setLocalVariableType sequentially.
     */
    private String batchSetVariableTypesOptimized(String functionAddress, Map<String, String> variableTypes) {
        if (variableTypes == null || variableTypes.isEmpty()) {
            return "{\"success\": true, \"method\": \"optimized\", \"variables_typed\": 0, \"variables_failed\": 0}";
        }
        int variablesTyped = 0;
        int variablesFailed = 0;
        List<String> errors = new ArrayList<>();
        for (Map.Entry<String, String> entry : variableTypes.entrySet()) {
            try {
                Response result = functionService.setLocalVariableType(
                    functionAddress, entry.getKey(), entry.getValue());
                String resultStr = Response.r2s(result);
                if (resultStr.toLowerCase().contains("success")) {
                    variablesTyped++;
                } else {
                    errors.add(entry.getKey() + ": " + resultStr);
                    variablesFailed++;
                }
                Thread.sleep(50);
            } catch (Exception e) {
                errors.add(entry.getKey() + ": " + e.getMessage());
                variablesFailed++;
            }
        }
        return JsonHelper.toJson(Map.of(
            "success", variablesFailed == 0 && variablesTyped > 0,
            "method", "optimized",
            "variables_typed", variablesTyped,
            "variables_failed", variablesFailed));
    }

    // ==================================================================================
    // Project/Tool GUI-specific methods
    // ==================================================================================

    private RepositoryAdapter getProjectRepository() {
        try {
            Project project = tool.getProject();
            if (project == null) return null;
            ProjectData data = project.getProjectData();
            return data.getRepository();
        } catch (Exception e) {
            return null;
        }
    }

    private String getProjectStatusJson() {
        Project project = tool.getProject();
        if (project == null) return JsonHelper.errorJson("No project open");
        ProjectData data = project.getProjectData();
        RepositoryAdapter repo = getProjectRepository();
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("project", project.getName());
        status.put("shared", repo != null);
        if (repo != null) {
            try {
                status.put("server_connected", repo.isConnected());
                status.put("server_info", repo.getServerInfo().toString());
            } catch (Exception e) {
                status.put("server_connected", false);
            }
        }
        status.put("file_count", data.getFileCount());
        return JsonHelper.toJson(status);
    }

    private String listProjectFilesJson(String folderPath) {
        Project project = tool.getProject();
        if (project == null) return JsonHelper.errorJson("No project open");
        ProjectData data = project.getProjectData();
        ghidra.framework.model.DomainFolder folder = data.getFolder(folderPath);
        if (folder == null) return JsonHelper.errorJson("Folder not found: " + folderPath);
        List<Map<String, Object>> files = new ArrayList<>();
        for (DomainFile df : folder.getFiles()) {
            Map<String, Object> info = new LinkedHashMap<>();
            info.put("name", df.getName());
            info.put("path", df.getPathname());
            info.put("content_type", df.getContentType());
            info.put("version", df.getVersion());
            info.put("read_only", df.isReadOnly());
            info.put("checked_out", df.isCheckedOut());
            info.put("versioned", df.isVersioned());
            files.add(info);
        }
        // Include subfolders
        List<String> subfolders = new ArrayList<>();
        for (ghidra.framework.model.DomainFolder sub : folder.getFolders()) {
            subfolders.add(sub.getPathname());
        }
        return JsonHelper.toJson(Map.of("files", files, "subfolders", subfolders, "path", folderPath));
    }

    private String getProjectFileInfoJson(String filePath) {
        Project project = tool.getProject();
        if (project == null) return JsonHelper.errorJson("No project open");
        DomainFile df = project.getProjectData().getFile(filePath);
        if (df == null) return JsonHelper.errorJson("File not found: " + filePath);
        Map<String, Object> info = new LinkedHashMap<>();
        info.put("name", df.getName());
        info.put("path", df.getPathname());
        info.put("content_type", df.getContentType());
        info.put("version", df.getVersion());
        info.put("read_only", df.isReadOnly());
        info.put("checked_out", df.isCheckedOut());
        info.put("versioned", df.isVersioned());
        return JsonHelper.toJson(info);
    }

    private String checkoutProjectFile(String filePath, boolean exclusive) {
        Project project = tool.getProject();
        if (project == null) return JsonHelper.errorJson("No project open");
        if (filePath == null) return JsonHelper.errorJson("'path' parameter required");
        DomainFile df = project.getProjectData().getFile(filePath);
        if (df == null) return JsonHelper.errorJson("File not found: " + filePath);
        try {
            if (df.isCheckedOut()) return JsonHelper.toJson(Map.of("status", "already_checked_out", "path", filePath));
            df.checkout(exclusive, TaskMonitor.DUMMY);
            return JsonHelper.toJson(Map.of("status", "checked_out", "path", filePath, "exclusive", exclusive));
        } catch (Exception e) {
            return JsonHelper.errorJson("Checkout failed: " + e.getMessage());
        }
    }

    private String checkinProjectFile(String filePath, String comment, boolean keepCheckedOut) {
        Project project = tool.getProject();
        if (project == null) return JsonHelper.errorJson("No project open");
        if (filePath == null) return JsonHelper.errorJson("'path' parameter required");
        DomainFile df = project.getProjectData().getFile(filePath);
        if (df == null) return JsonHelper.errorJson("File not found: " + filePath);
        try {
            if (!df.isCheckedOut()) return JsonHelper.errorJson("File is not checked out");
            df.checkin(new ghidra.framework.data.CheckinHandler() {
                public boolean keepCheckedOut() { return keepCheckedOut; }
                public String getComment() { return comment; }
                public boolean createKeepFile() { return false; }
            }, TaskMonitor.DUMMY);
            return JsonHelper.toJson(Map.of("status", "checked_in", "path", filePath));
        } catch (Exception e) {
            return JsonHelper.errorJson("Checkin failed: " + e.getMessage());
        }
    }

    private String undoCheckoutProjectFile(String filePath, boolean keep) {
        Project project = tool.getProject();
        if (project == null) return JsonHelper.errorJson("No project open");
        if (filePath == null) return JsonHelper.errorJson("'path' parameter required");
        DomainFile df = project.getProjectData().getFile(filePath);
        if (df == null) return JsonHelper.errorJson("File not found: " + filePath);
        try {
            if (!df.isCheckedOut()) return JsonHelper.errorJson("File is not checked out");
            df.undoCheckout(keep);
            return JsonHelper.toJson(Map.of("status", "checkout_undone", "path", filePath));
        } catch (Exception e) {
            return JsonHelper.errorJson("Undo checkout failed: " + e.getMessage());
        }
    }

    private String addToVersionControl(String filePath, String comment) {
        Project project = tool.getProject();
        if (project == null) return JsonHelper.errorJson("No project open");
        if (filePath == null) return JsonHelper.errorJson("'path' parameter required");
        DomainFile df = project.getProjectData().getFile(filePath);
        if (df == null) return JsonHelper.errorJson("File not found: " + filePath);
        try {
            df.addToVersionControl(comment, false, TaskMonitor.DUMMY);
            return JsonHelper.toJson(Map.of("status", "added", "path", filePath));
        } catch (Exception e) {
            return JsonHelper.errorJson("Add to version control failed: " + e.getMessage());
        }
    }

    private String getProjectFileVersionHistory(String filePath) {
        Project project = tool.getProject();
        if (project == null) return JsonHelper.errorJson("No project open");
        if (filePath == null) return JsonHelper.errorJson("'path' parameter required");
        DomainFile df = project.getProjectData().getFile(filePath);
        if (df == null) return JsonHelper.errorJson("File not found: " + filePath);
        try {
            ghidra.framework.store.Version[] versions = df.getVersionHistory();
            if (versions == null) return JsonHelper.toJson(Map.of("versions", List.of(), "path", filePath));
            List<Map<String, Object>> vlist = new ArrayList<>();
            for (ghidra.framework.store.Version v : versions) {
                vlist.add(Map.of(
                    "version", v.getVersion(),
                    "user", v.getUser(),
                    "comment", v.getComment() != null ? v.getComment() : "",
                    "timestamp", v.getCreateTime()));
            }
            return JsonHelper.toJson(Map.of("versions", vlist, "path", filePath));
        } catch (Exception e) {
            return JsonHelper.errorJson("Failed to get version history: " + e.getMessage());
        }
    }

    private String listProjectCheckouts(String folderPath) {
        Project project = tool.getProject();
        if (project == null) return JsonHelper.errorJson("No project open");
        ProjectData data = project.getProjectData();
        ghidra.framework.model.DomainFolder folder = data.getFolder(folderPath);
        if (folder == null) return JsonHelper.errorJson("Folder not found: " + folderPath);
        List<Map<String, Object>> checkouts = new ArrayList<>();
        collectCheckouts(folder, checkouts);
        return JsonHelper.toJson(Map.of("checkouts", checkouts, "count", checkouts.size(), "path", folderPath));
    }

    private void collectCheckouts(ghidra.framework.model.DomainFolder folder, List<Map<String, Object>> checkouts) {
        for (DomainFile df : folder.getFiles()) {
            if (df.isCheckedOut()) {
                Map<String, Object> info = new LinkedHashMap<>();
                info.put("path", df.getPathname());
                info.put("name", df.getName());
                info.put("version", df.getVersion());
                info.put("exclusive", df.isCheckedOutExclusive());
                checkouts.add(info);
            }
        }
        for (ghidra.framework.model.DomainFolder sub : folder.getFolders()) {
            collectCheckouts(sub, checkouts);
        }
    }

    private String terminateFileCheckout(String filePath) {
        Project project = tool.getProject();
        if (project == null) return JsonHelper.errorJson("No project open");
        if (filePath == null) return JsonHelper.errorJson("'path' parameter required");
        DomainFile df = project.getProjectData().getFile(filePath);
        if (df == null) return JsonHelper.errorJson("File not found: " + filePath);
        try {
            if (!df.isCheckedOut()) return JsonHelper.errorJson("File is not checked out");
            df.undoCheckout(false);
            return JsonHelper.toJson(Map.of("status", "terminated", "path", filePath));
        } catch (Exception e) {
            return JsonHelper.errorJson("Terminate checkout failed: " + e.getMessage());
        }
    }

    private String terminateAllCheckouts(String folderPath) {
        Project project = tool.getProject();
        if (project == null) return JsonHelper.errorJson("No project open");
        ProjectData data = project.getProjectData();
        ghidra.framework.model.DomainFolder folder = data.getFolder(folderPath);
        if (folder == null) return JsonHelper.errorJson("Folder not found: " + folderPath);
        List<String> terminated = new ArrayList<>();
        terminateCheckoutsRecursive(folder, terminated);
        return JsonHelper.toJson(Map.of("status", "terminated", "count", terminated.size(), "files", terminated));
    }

    private void terminateCheckoutsRecursive(ghidra.framework.model.DomainFolder folder, List<String> terminated) {
        for (DomainFile df : folder.getFiles()) {
            if (df.isCheckedOut()) {
                try {
                    df.undoCheckout(false);
                    terminated.add(df.getPathname());
                } catch (Exception e) {
                    Msg.warn(this, "Failed to terminate checkout for " + df.getPathname() + ": " + e.getMessage());
                }
            }
        }
        for (ghidra.framework.model.DomainFolder sub : folder.getFolders()) {
            terminateCheckoutsRecursive(sub, terminated);
        }
    }

    private String getProjectInfo() {
        Project project = tool.getProject();
        if (project == null) return JsonHelper.errorJson("No project open");
        ProjectData data = project.getProjectData();
        RepositoryAdapter repo = getProjectRepository();
        Map<String, Object> info = new LinkedHashMap<>();
        info.put("project", project.getName());
        info.put("shared", repo != null);
        if (repo != null) {
            try {
                info.put("server_connected", repo.isConnected());
                info.put("server_info", repo.getServerInfo().toString());
            } catch (Exception e) {
                info.put("server_connected", false);
            }
        }
        info.put("file_count", data.getFileCount());
        Program[] openProgs = programProvider.getAllOpenPrograms();
        List<String> progNames = new ArrayList<>();
        for (Program p : openProgs) progNames.add(p.getName());
        info.put("open_programs", progNames);
        info.put("open_program_count", openProgs.length);
        Program current = programProvider.getCurrentProgram();
        if (current != null) info.put("current_program", current.getName());
        try {
            ghidra.framework.model.ToolManager tm = project.getToolManager();
            if (tm != null) {
                PluginTool[] tools = tm.getRunningTools();
                List<String> toolNames = new ArrayList<>();
                boolean hasCodeBrowser = false;
                for (PluginTool t : tools) {
                    toolNames.add(t.getName());
                    if (t.getService(ghidra.app.services.ProgramManager.class) != null) hasCodeBrowser = true;
                }
                info.put("running_tools", toolNames);
                info.put("codebrowser_active", hasCodeBrowser);
            }
        } catch (Exception e) { /* ignore */ }
        return JsonHelper.toJson(info);
    }

    private String getRunningTools() {
        Project project = tool.getProject();
        if (project == null) return JsonHelper.errorJson("No project open");
        try {
            ghidra.framework.model.ToolManager tm = project.getToolManager();
            if (tm == null) return JsonHelper.errorJson("ToolManager not available");
            PluginTool[] tools = tm.getRunningTools();
            List<Map<String, Object>> toolList = new ArrayList<>();
            for (PluginTool t : tools) {
                Map<String, Object> toolInfo = new LinkedHashMap<>();
                toolInfo.put("name", t.getName());
                toolInfo.put("instance", t.getInstanceName());
                ghidra.app.services.ProgramManager pm = t.getService(ghidra.app.services.ProgramManager.class);
                if (pm != null) {
                    toolInfo.put("has_program_manager", true);
                    Program cp = pm.getCurrentProgram();
                    if (cp != null) toolInfo.put("current_program", cp.getName());
                    Program[] progs = pm.getAllOpenPrograms();
                    List<String> pnames = new ArrayList<>();
                    for (Program p : progs) pnames.add(p.getName());
                    toolInfo.put("open_programs", pnames);
                } else {
                    toolInfo.put("has_program_manager", false);
                }
                toolList.add(toolInfo);
            }
            return JsonHelper.toJson(Map.of("tools", toolList, "count", tools.length));
        } catch (Exception e) {
            return JsonHelper.errorJson("Failed to list tools: " + e.getMessage());
        }
    }

    private String launchCodeBrowser(String filePath) {
        Project project = tool.getProject();
        if (project == null) return JsonHelper.errorJson("No project open");
        DomainFile domainFile = null;
        if (filePath != null && !filePath.trim().isEmpty()) {
            domainFile = project.getProjectData().getFile(filePath);
            if (domainFile == null) return JsonHelper.errorJson("File not found in project: " + filePath);
        }
        try {
            ghidra.framework.model.ToolServices ts = project.getToolServices();
            if (ts == null) return JsonHelper.errorJson("ToolServices not available");
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
                final ghidra.app.services.ProgramManager pm = codeBrowser.getService(ghidra.app.services.ProgramManager.class);
                final Program program = (Program) domainFile.getDomainObject(this, false, false, TaskMonitor.DUMMY);
                SwingUtilities.invokeAndWait(() -> {
                    pm.openProgram(program);
                    pm.setCurrentProgram(program);
                });
                return JsonHelper.toJson(Map.of("success", true, "message", "Opened in existing CodeBrowser",
                    "tool", codeBrowser.getName(), "program", program.getName(), "path", filePath));
            } else if (domainFile != null) {
                final DomainFile df = domainFile;
                SwingUtilities.invokeAndWait(() -> ts.launchDefaultTool(Collections.singletonList(df)));
                return JsonHelper.toJson(Map.of("success", true, "message", "Launched new CodeBrowser", "path", filePath));
            } else {
                SwingUtilities.invokeAndWait(() -> ts.launchDefaultTool(Collections.emptyList()));
                return JsonHelper.toJson(Map.of("success", true, "message", "Launched new CodeBrowser (no file)"));
            }
        } catch (Exception e) {
            return JsonHelper.errorJson("Failed to launch CodeBrowser: " + e.getMessage());
        }
    }

    private String gotoAddress(String addressStr) {
        if (addressStr == null || addressStr.trim().isEmpty()) return JsonHelper.errorJson("address parameter is required");
        try {
            Project project = tool.getProject();
            if (project == null) return JsonHelper.errorJson("No project open");
            ghidra.framework.model.ToolManager tm = project.getToolManager();
            if (tm == null) return JsonHelper.errorJson("ToolManager not available");
            PluginTool codeBrowser = null;
            for (PluginTool runningTool : tm.getRunningTools()) {
                if (runningTool.getService(ghidra.app.services.ProgramManager.class) != null) {
                    codeBrowser = runningTool;
                    break;
                }
            }
            if (codeBrowser == null) return JsonHelper.errorJson("No CodeBrowser running");
            GoToService goToService = codeBrowser.getService(GoToService.class);
            if (goToService == null) return JsonHelper.errorJson("GoToService not available");
            ghidra.app.services.ProgramManager pm = codeBrowser.getService(ghidra.app.services.ProgramManager.class);
            Program program = pm.getCurrentProgram();
            if (program == null) return JsonHelper.errorJson("No program open in CodeBrowser");
            Address addr = program.getAddressFactory().getAddress(addressStr);
            if (addr == null) return JsonHelper.errorJson("Invalid address: " + addressStr);
            final GoToService gts = goToService;
            final Address targetAddr = addr;
            final AtomicBoolean success = new AtomicBoolean(false);
            SwingUtilities.invokeAndWait(() -> success.set(gts.goTo(targetAddr)));
            if (success.get()) {
                Function func = program.getFunctionManager().getFunctionContaining(addr);
                Map<String, Object> result = new LinkedHashMap<>();
                result.put("success", true);
                result.put("address", addr.toString());
                if (func != null) result.put("function", func.getName());
                return JsonHelper.toJson(result);
            } else {
                return JsonHelper.errorJson("GoToService could not navigate to " + addressStr);
            }
        } catch (Exception e) {
            return JsonHelper.errorJson("Failed to navigate: " + e.getMessage());
        }
    }

    private String authenticateServer(String username, String password) {
        try {
            if (password == null || password.isEmpty()) return JsonHelper.errorJson("Password is required");
            if (username == null || username.isEmpty()) {
                username = ghidra.framework.preferences.Preferences.getProperty("PasswordPrompt.Name");
            }
            if (username == null || username.isEmpty()) {
                username = System.getProperty("user.name");
            }
            char[] passwordChars = password.toCharArray();
            if (this.authenticator != null) {
                this.authenticator.updateCredentials(username, passwordChars);
            } else {
                this.authenticator = new GhidraMCPAuthenticator(username, passwordChars);
                ghidra.framework.client.ClientUtil.setClientAuthenticator(this.authenticator);
            }
            return JsonHelper.toJson(Map.of("success", true, "message", "Server credentials registered", "username", username));
        } catch (Exception e) {
            return JsonHelper.errorJson("Failed to register authenticator: " + e.getMessage());
        }
    }

    @Override
    public void dispose() {
        // Deregister from ServerManager (UDS transport)
        ServerManager.getInstance().deregisterTool(tool);

        instanceCount--;
        if (instanceCount <= 0) {
            programProvider.releaseAll();
            instanceCount = 0;
        }
        if (serverStatusAction != null) tool.removeAction(serverStatusAction);
        super.dispose();
    }
}
