package com.xebyte.core;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Static singleton that owns the UDS HTTP server, service instances, and
 * tool registry. Shared across all CodeBrowser windows in one JVM.
 */
public class ServerManager {

    private static ServerManager instance;

    public static synchronized ServerManager getInstance() {
        if (instance == null) instance = new ServerManager();
        return instance;
    }

    private final Map<String, PluginTool> tools = new ConcurrentHashMap<>();
    private final AtomicReference<String> activeToolId = new AtomicReference<>();
    private MultiToolProgramProvider programProvider;
    private UdsHttpServer server;

    private ServerManager() {}

    public synchronized void registerTool(PluginTool tool,
            java.util.function.Consumer<AnnotationScanner.ContextRegistrar> guiEndpoints) throws IOException {
        String toolId = String.valueOf(System.identityHashCode(tool));
        tools.put(toolId, tool);
        activeToolId.compareAndSet(null, toolId);
        Msg.info(this, "Registered tool " + toolId + " (total: " + tools.size() + ")");

        cleanStaleFiles();

        if (server == null) {
            programProvider = new MultiToolProgramProvider(tools, activeToolId);
            SwingThreadingStrategy ts = new SwingThreadingStrategy();

            ListingService listingService = new ListingService(programProvider);
            CommentService commentService = new CommentService(programProvider, ts);
            SymbolLabelService symbolLabelService = new SymbolLabelService(programProvider, ts);
            FunctionService functionService = new FunctionService(programProvider, ts);
            XrefCallGraphService xrefCallGraphService = new XrefCallGraphService(programProvider, ts);
            DataTypeService dataTypeService = new DataTypeService(programProvider, ts);
            DocumentationHashService documentationHashService = new DocumentationHashService(programProvider, ts, new BinaryComparisonService());
            documentationHashService.setFunctionService(functionService);
            AnalysisService analysisService = new AnalysisService(programProvider, ts, functionService);
            MalwareSecurityService malwareSecurityService = new MalwareSecurityService(programProvider, ts);
            ProgramScriptService programScriptService = new ProgramScriptService(programProvider, ts);

            var toolDefs = AnnotationScanner.scan(
                listingService, commentService, symbolLabelService, functionService,
                xrefCallGraphService, dataTypeService, documentationHashService,
                analysisService, malwareSecurityService, programScriptService);
            startServer(toolDefs, guiEndpoints);
        }
    }

    public synchronized void deregisterTool(PluginTool tool) {
        String toolId = String.valueOf(System.identityHashCode(tool));
        tools.remove(toolId);
        if (toolId.equals(activeToolId.get())) {
            var iter = tools.keySet().iterator();
            activeToolId.set(iter.hasNext() ? iter.next() : null);
        }
        Msg.info(this, "Deregistered tool " + toolId + " (remaining: " + tools.size() + ")");

        if (tools.isEmpty()) {
            stopServer();
            instance = null;
        }
    }

    public PluginTool getActiveTool() {
        return programProvider != null ? programProvider.getActiveTool() : null;
    }

    public MultiToolProgramProvider getProgramProvider() { return programProvider; }

    public Path getSocketPath() {
        return server != null ? server.getSocketPath() : null;
    }

    private void startServer(java.util.List<AnnotationScanner.ToolDef> toolDefs,
            java.util.function.Consumer<AnnotationScanner.ContextRegistrar> guiEndpoints) throws IOException {
        Path socketDir = getSocketDir();
        Files.createDirectories(socketDir);
        Path socketPath = socketDir.resolve(getSocketName());

        server = new UdsHttpServer(socketPath);
        AnnotationScanner.ContextRegistrar registrar = (path, handler) ->
            server.createContext(path, handler::accept);
        AnnotationScanner.registerHttp(registrar, toolDefs);

        // Serve MCP tool schema
        String schemaJson = AnnotationScanner.toSchemaJson(toolDefs);
        registrar.createContext("/mcp/schema", exchange -> {
            try {
                AnnotationScanner.sendResponse(exchange, schemaJson);
            } catch (Exception ignored) {}
        });

        // Live instance info — queried by bridge on demand
        registrar.createContext("/mcp/instance_info", exchange -> {
            try {
                AnnotationScanner.sendResponse(exchange, Response.ok(buildInstanceInfo()).toJson());
            } catch (Exception ignored) {}
        });

        // Register GUI-specific endpoints
        if (guiEndpoints != null) {
            guiEndpoints.accept(registrar);
        }

        server.start();
    }

    private Map<String, Object> buildInstanceInfo() {
        long pid = ProcessHandle.current().pid();
        String projectName = "unknown";
        String projectPath = "";

        PluginTool activeTool = getActiveTool();
        if (activeTool != null) {
            ghidra.framework.model.Project proj = activeTool.getProject();
            if (proj != null) {
                projectName = proj.getName();
                projectPath = proj.getProjectLocator().toString();
            }
        }

        var openNames = new java.util.HashSet<String>();
        if (activeTool != null) {
            ghidra.framework.model.Project proj = activeTool.getProject();
            if (proj != null) {
                try {
                    ghidra.framework.model.ToolManager tm = proj.getToolManager();
                    if (tm != null) {
                        for (PluginTool runningTool : tm.getRunningTools()) {
                            ghidra.app.services.ProgramManager pm = runningTool.getService(ghidra.app.services.ProgramManager.class);
                            if (pm != null) {
                                for (Program p : pm.getAllOpenPrograms()) {
                                    openNames.add(p.getName());
                                }
                            }
                        }
                    }
                } catch (Exception e) {
                    Msg.warn(this, "Failed to query running tools: " + e.getMessage());
                }
            }
        }

        var programs = new java.util.ArrayList<Map<String, Object>>();
        if (activeTool != null) {
            ghidra.framework.model.Project proj = activeTool.getProject();
            if (proj != null) {
                collectPrograms(proj.getProjectData().getRootFolder(), openNames, programs);
            }
        }

        var info = new LinkedHashMap<String, Object>();
        info.put("pid", pid);
        info.put("project", projectName);
        info.put("project_path", projectPath);
        info.put("programs", programs);
        info.put("tools", tools.size());
        return info;
    }

    private void stopServer() {
        if (server != null) {
            Msg.info(this, "Stopping GhidraMCP UDS server...");
            server.stop();
            server = null;
            Msg.info(this, "GhidraMCP UDS server stopped.");
        }
    }

    private void collectPrograms(ghidra.framework.model.DomainFolder folder,
            java.util.Set<String> openNames, java.util.List<Map<String, Object>> out) {
        for (ghidra.framework.model.DomainFile df : folder.getFiles()) {
            var entry = new LinkedHashMap<String, Object>();
            entry.put("name", df.getName());
            entry.put("path", df.getPathname());
            entry.put("open", openNames.contains(df.getName()));
            out.add(entry);
        }
        for (ghidra.framework.model.DomainFolder sub : folder.getFolders()) {
            collectPrograms(sub, openNames, out);
        }
    }

    private void cleanStaleFiles() {
        try {
            Path dir = getSocketDir();
            if (!Files.isDirectory(dir)) return;
            for (Path p : (Iterable<Path>) Files.list(dir)::iterator) {
                String name = p.getFileName().toString();
                if (!name.endsWith(".sock")) continue;
                int dashIdx = name.lastIndexOf('-');
                int dotIdx = name.lastIndexOf('.');
                if (dashIdx < 0 || dotIdx < 0) continue;
                try {
                    long pid = Long.parseLong(name.substring(dashIdx + 1, dotIdx));
                    if (!ProcessHandle.of(pid).isPresent()) {
                        Files.deleteIfExists(p);
                        Msg.info(this, "Cleaned stale socket: " + name);
                    }
                } catch (NumberFormatException e) {
                    // not our file format
                }
            }
        } catch (IOException e) {
            Msg.warn(this, "Failed to clean stale files: " + e.getMessage());
        }
    }

    private Path getSocketDir() {
        String xdg = System.getenv("XDG_RUNTIME_DIR");
        if (xdg != null && !xdg.isEmpty()) return Path.of(xdg, "ghidra-mcp");
        String tmpdir = System.getenv("TMPDIR");
        String user = System.getProperty("user.name", "unknown");
        if (tmpdir != null && !tmpdir.isEmpty()) return Path.of(tmpdir, "ghidra-mcp-" + user);
        return Path.of("/tmp", "ghidra-mcp-" + user);
    }

    private String getSocketName() {
        long pid = ProcessHandle.current().pid();
        return "ghidra-" + pid + ".sock";
    }
}
