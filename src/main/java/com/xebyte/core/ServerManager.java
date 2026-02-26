package com.xebyte.core;

import com.xebyte.VersionInfo;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import com.xebyte.core.services.CommentService;
import com.xebyte.core.services.FunctionService;
import com.xebyte.core.services.ListingService;
import com.xebyte.core.services.AnalysisService;
import com.xebyte.core.services.ComparisonService;
import com.xebyte.core.services.DataTypeService;
import com.xebyte.core.services.MutationService;
import com.xebyte.core.services.SymbolService;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Static singleton that owns the UDS HTTP server, service instances, and
 * tool registry. Shared across all CodeBrowser windows in one JVM.
 *
 * Endpoint handlers and HTTP utilities live in {@link EndpointRouter}.
 *
 * Lifecycle:
 *   1. First registerTool() → creates socket dir, starts UDS server, creates services
 *   2. Subsequent registerTool() → adds to tool registry, updates metadata
 *   3. deregisterTool() → removes from registry, updates metadata
 *   4. Last deregisterTool() → stops server, deletes socket + metadata
 */
public class ServerManager {

    // ==================== SINGLETON ====================

    private static ServerManager instance;

    public static synchronized ServerManager getInstance() {
        if (instance == null) {
            instance = new ServerManager();
        }
        return instance;
    }

    // ==================== TOOL REGISTRY ====================

    private final Map<String, PluginTool> tools = new ConcurrentHashMap<>();
    private final AtomicReference<String> activeToolId = new AtomicReference<>();
    private MultiToolProgramProvider programProvider;

    // ==================== SERVER ====================

    private UdsHttpServer server;

    private ServerManager() {
        // Private constructor for singleton
    }

    /**
     * Register a PluginTool (CodeBrowser window). First call starts the server.
     */
    public synchronized void registerTool(PluginTool tool) throws IOException {
        String toolId = String.valueOf(System.identityHashCode(tool));
        tools.put(toolId, tool);
        activeToolId.compareAndSet(null, toolId);

        Msg.info(this, "Registered tool " + toolId + " (total: " + tools.size() + ")");

        if (server == null) {
            // First tool — create services and start server
            programProvider = new MultiToolProgramProvider(tools, activeToolId);
            SwingThreadingStrategy ts = new SwingThreadingStrategy();
            ListingService listingService = new ListingService(programProvider, ts);
            CommentService commentService = new CommentService(programProvider, ts);
            SymbolService symbolService = new SymbolService(programProvider, ts);
            FunctionService functionService = new FunctionService(programProvider, ts);
            MutationService mutationService = new MutationService(programProvider, ts);
            DataTypeService dataTypeService = new DataTypeService(programProvider, ts);
            AnalysisService analysisService = new AnalysisService(programProvider, ts);
            ComparisonService comparisonService = new ComparisonService(programProvider, ts);

            EndpointRouter router = new EndpointRouter(
                programProvider, this::getActiveTool,
                listingService, commentService, symbolService, functionService,
                mutationService, dataTypeService, analysisService, comparisonService);

            startServer(router);
            Msg.info(this, "GhidraMCP " + VersionInfo.getFullVersion() +
                " — UDS server started at " + server.getSocketPath());
        }

        writeMetadata();
    }

    /**
     * Deregister a PluginTool. Last tool stops the server.
     */
    public synchronized void deregisterTool(PluginTool tool) {
        String toolId = String.valueOf(System.identityHashCode(tool));
        tools.remove(toolId);

        // Update active tool reference
        if (toolId.equals(activeToolId.get())) {
            var iter = tools.keySet().iterator();
            activeToolId.set(iter.hasNext() ? iter.next() : null);
        }

        Msg.info(this, "Deregistered tool " + toolId + " (remaining: " + tools.size() + ")");

        if (tools.isEmpty()) {
            stopServer();
            instance = null; // Allow re-creation if new tool registers later
        } else {
            writeMetadata();
        }
    }

    /**
     * Get the currently active PluginTool.
     */
    public PluginTool getActiveTool() {
        return programProvider != null ? programProvider.getActiveTool() : null;
    }

    private void startServer(EndpointRouter router) throws IOException {
        Path socketDir = getSocketDir();
        Files.createDirectories(socketDir);
        Path socketPath = socketDir.resolve(getSocketName());

        server = new UdsHttpServer(socketPath);
        router.registerAll(server);
        server.start();
    }

    private void stopServer() {
        if (server != null) {
            Msg.info(this, "Stopping GhidraMCP UDS server...");
            server.stop();
            // Delete metadata sidecar
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

    // ==================== SOCKET DIRECTORY + METADATA ====================

    private Path getSocketDir() {
        // $XDG_RUNTIME_DIR/ghidra-mcp/ → $TMPDIR/ghidra-mcp-<user> → /tmp/ghidra-mcp-<user>
        String xdg = System.getenv("XDG_RUNTIME_DIR");
        if (xdg != null && !xdg.isEmpty()) {
            return Path.of(xdg, "ghidra-mcp");
        }
        String tmpdir = System.getenv("TMPDIR");
        String user = System.getProperty("user.name", "unknown");
        if (tmpdir != null && !tmpdir.isEmpty()) {
            return Path.of(tmpdir, "ghidra-mcp-" + user);
        }
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

            // Collect project info
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

            // Collect program names
            StringBuilder programs = new StringBuilder("[");
            Program[] allPrograms = programProvider.getAllOpenPrograms();
            for (int i = 0; i < allPrograms.length; i++) {
                if (i > 0) programs.append(", ");
                programs.append("\"").append(allPrograms[i].getName().replace("\"", "\\\"")).append("\"");
            }
            programs.append("]");

            String json = "{\n" +
                "  \"pid\": " + pid + ",\n" +
                "  \"project\": \"" + projectName.replace("\"", "\\\"") + "\",\n" +
                "  \"project_path\": \"" + projectPath.replace("\"", "\\\"").replace("\\", "\\\\") + "\",\n" +
                "  \"programs\": " + programs + ",\n" +
                "  \"tools\": " + tools.size() + ",\n" +
                "  \"started\": \"" + Instant.now() + "\"\n" +
                "}";
            Files.writeString(metaPath, json);
        } catch (IOException e) {
            Msg.warn(this, "Could not write metadata: " + e.getMessage());
        }
    }
}
