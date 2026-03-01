package com.xebyte.core;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
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

    public synchronized void registerTool(PluginTool tool) throws IOException {
        String toolId = String.valueOf(System.identityHashCode(tool));
        tools.put(toolId, tool);
        activeToolId.compareAndSet(null, toolId);
        Msg.info(this, "Registered tool " + toolId + " (total: " + tools.size() + ")");

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
            documentationHashService.setCommentService(commentService);
            documentationHashService.setAnalysisService(analysisService);
            MalwareSecurityService malwareSecurityService = new MalwareSecurityService(programProvider, ts);
            ProgramScriptService programScriptService = new ProgramScriptService(programProvider, ts);

            var toolDefs = AnnotationScanner.scan(
                listingService, commentService, symbolLabelService, functionService,
                xrefCallGraphService, dataTypeService, documentationHashService,
                analysisService, malwareSecurityService, programScriptService);
            startServer(toolDefs);
        }
        writeMetadata();
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
        } else {
            writeMetadata();
        }
    }

    public PluginTool getActiveTool() {
        return programProvider != null ? programProvider.getActiveTool() : null;
    }

    public MultiToolProgramProvider getProgramProvider() { return programProvider; }

    public Path getSocketPath() {
        return server != null ? server.getSocketPath() : null;
    }

    private void startServer(java.util.List<AnnotationScanner.ToolDef> toolDefs) throws IOException {
        Path socketDir = getSocketDir();
        Files.createDirectories(socketDir);
        Path socketPath = socketDir.resolve(getSocketName());

        server = new UdsHttpServer(socketPath);
        EndpointRegistrar.ContextRegistrar registrar = (path, handler) ->
            server.createContext(path, handler::accept);
        AnnotationScanner.registerHttp(registrar, toolDefs);

        // Serve MCP tool schema
        String schemaJson = AnnotationScanner.toSchemaJson(toolDefs);
        registrar.createContext("/mcp/schema", EndpointRegistrar.safeHandler(exchange -> {
            EndpointRegistrar.sendResponse(exchange, Response.text(schemaJson));
        }));

        server.start();
    }

    private void stopServer() {
        if (server != null) {
            Msg.info(this, "Stopping GhidraMCP UDS server...");
            server.stop();
            try {
                Path metaPath = getSocketDir().resolve(getSocketName().replace(".sock", ".json"));
                Files.deleteIfExists(metaPath);
            } catch (IOException e) {
                Msg.warn(this, "Could not delete metadata file: " + e.getMessage());
            }
            server = null;
            Msg.info(this, "GhidraMCP UDS server stopped.");
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
        String project = "ghidra";
        PluginTool activeTool = getActiveTool();
        if (activeTool != null) {
            ghidra.framework.model.Project proj = activeTool.getProject();
            if (proj != null) {
                project = proj.getName().replaceAll("[^a-zA-Z0-9_-]", "_");
            }
        }
        long pid = ProcessHandle.current().pid();
        return project + "-" + pid + ".sock";
    }

    private void writeMetadata() {
        try {
            Path metaPath = getSocketDir().resolve(getSocketName().replace(".sock", ".json"));
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
            var programNames = new java.util.ArrayList<String>();
            if (programProvider != null) {
                for (Program p : programProvider.getAllOpenPrograms()) {
                    programNames.add(p.getName());
                }
            }
            var meta = new LinkedHashMap<String, Object>();
            meta.put("pid", pid);
            meta.put("project", projectName);
            meta.put("project_path", projectPath);
            meta.put("programs", programNames);
            meta.put("tools", tools.size());
            meta.put("started", Instant.now().toString());
            Files.writeString(metaPath, JsonHelper.toJson(meta));
        } catch (IOException e) {
            Msg.warn(this, "Could not write metadata: " + e.getMessage());
        }
    }
}
