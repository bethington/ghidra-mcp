package com.xebyte.core;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import java.io.IOException;
import java.io.OutputStream;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
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
    // Bound TCP port for the legacy HTTP transport when the plugin picked
    // a port-range fallback (issue #175). -1 means "TCP not running or
    // port unknown". Surfaced via /mcp/instance_info so the bridge can
    // connect to the actual bound port without hard-coding 8089.
    private volatile int boundTcpPort = -1;

    public void setBoundTcpPort(int port) {
        this.boundTcpPort = port;
    }

    public int getBoundTcpPort() {
        return boundTcpPort;
    }

    private ServerManager() {}

    public synchronized void registerTool(PluginTool tool,
            java.util.function.Consumer<UdsHttpServer> guiEndpoints) throws IOException {
        String toolId = String.valueOf(System.identityHashCode(tool));
        tools.put(toolId, tool);
        activeToolId.compareAndSet(null, toolId);
        Msg.info(this, "Registered tool " + toolId + " (total: " + tools.size() + ")");

        cleanStaleFiles();

        if (server == null) {
            programProvider = new MultiToolProgramProvider(tools, activeToolId);
            com.xebyte.core.ThreadingStrategy ts = new com.xebyte.core.SwingThreadingStrategy();

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

            AnnotationScanner scanner = new AnnotationScanner(programProvider,
                listingService, functionService, commentService, symbolLabelService,
                xrefCallGraphService, dataTypeService, analysisService,
                documentationHashService, malwareSecurityService, programScriptService);

            startServer(scanner, guiEndpoints);
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

    public boolean isRunning() { return server != null; }

    /** Stop the UDS server without deregistering tools. Use for manual stop/restart. */
    public synchronized void stopUdsServer() {
        stopServer();
    }

    public Path getSocketPath() {
        return server != null ? server.getSocketPath() : null;
    }

    private void startServer(AnnotationScanner scanner,
            java.util.function.Consumer<UdsHttpServer> guiEndpoints) throws IOException {
        Path socketDir = getSocketDir();
        Files.createDirectories(socketDir);
        hardenSocketDir(socketDir);
        Path socketPath = socketDir.resolve(getSocketName());

        server = new UdsHttpServer(socketPath);

        // Register all annotation-scanned endpoints on the UDS server
        for (EndpointDef ep : scanner.getEndpoints()) {
            server.createContext(ep.path(), exchange -> {
                try {
                    Map<String, String> query = parseQueryString(exchange.getRequestURI().getRawQuery());
                    Map<String, Object> body = "POST".equalsIgnoreCase(exchange.getRequestMethod())
                        ? JsonHelper.parseBody(exchange.getRequestBody()) : Map.of();
                    String json = ep.handler().handle(query, body).toJson();
                    sendJsonResponse(exchange, json);
                } catch (Exception e) {
                    sendJsonResponse(exchange, Response.err(e.getMessage()).toJson());
                }
            });
        }

        // Serve MCP tool schema
        String schemaJson = scanner.generateSchema();
        server.createContext("/mcp/schema", exchange -> {
            try {
                sendJsonResponse(exchange, schemaJson);
            } catch (Exception ignored) {}
        });

        // Live instance info — queried by bridge on demand
        server.createContext("/mcp/instance_info", exchange -> {
            try {
                sendJsonResponse(exchange, Response.ok(buildInstanceInfo()).toJson());
            } catch (Exception ignored) {}
        });

        // Register GUI-specific endpoints
        if (guiEndpoints != null) {
            guiEndpoints.accept(server);
        }

        server.start();
    }

    /** Send a JSON response on a transport-agnostic HttpExchange. */
    static void sendJsonResponse(HttpExchange exchange, String json) {
        try {
            byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json; charset=UTF-8");
            exchange.sendResponseHeaders(200, bytes.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(bytes);
            }
        } catch (IOException e) {
            Msg.error(ServerManager.class, "Failed to send response: " + e.getMessage());
        }
    }

    /** Parse URL query string into a map. */
    static Map<String, String> parseQueryString(String query) {
        Map<String, String> params = new LinkedHashMap<>();
        if (query == null || query.isEmpty()) return params;
        for (String pair : query.split("&")) {
            int eq = pair.indexOf('=');
            if (eq > 0) {
                String key = URLDecoder.decode(pair.substring(0, eq), StandardCharsets.UTF_8);
                String val = URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8);
                params.put(key, val);
            } else if (!pair.isEmpty()) {
                params.put(URLDecoder.decode(pair, StandardCharsets.UTF_8), "");
            }
        }
        return params;
    }

    /**
     * Build the /mcp/instance_info JSON string. Exposed so the TCP server
     * in GhidraMCPPlugin can serve the same endpoint as the UDS server --
     * needed by the bridge's TCP port-range scanner (issue #175 + Copilot).
     */
    public String buildInstanceInfoJson() {
        return Response.ok(buildInstanceInfo()).toJson();
    }

    Map<String, Object> buildInstanceInfo() {
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
        // Tell the bridge which TCP port this instance is actually bound to.
        // -1 means TCP transport is not running (UDS only). The bridge uses
        // this to support port-range fallback when issue #175's multi-instance
        // case has pushed us off the default 8089.
        info.put("tcp_port", boundTcpPort);
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

    /**
     * Verify the socket directory is owned by the current user and lock it
     * to mode {@code 0700}. The {@code /tmp/ghidra-mcp-<user>} fallback path
     * is predictable; on a multi-user host an attacker can pre-create it
     * (sticky {@code /tmp} allows new entries) and {@code createDirectories}
     * silently succeeds on an existing dir regardless of owner. Binding a
     * socket inside an attacker-owned directory lets them delete/replace it
     * and intercept bridge connections — full unauthenticated access to the
     * RE endpoints. Refuse to start in that case.
     * <p>
     * No-op on platforms without POSIX file attributes (Windows).
     */
    private void hardenSocketDir(Path socketDir) throws IOException {
        if (!socketDir.getFileSystem().supportedFileAttributeViews().contains("posix")) {
            return;
        }
        java.nio.file.attribute.PosixFileAttributes attrs =
            Files.readAttributes(socketDir, java.nio.file.attribute.PosixFileAttributes.class);
        String owner = attrs.owner().getName();
        String me = System.getProperty("user.name");
        if (me != null && !me.equals(owner)) {
            throw new IOException(
                "Refusing to bind UDS socket: directory " + socketDir
                + " is owned by '" + owner + "' (expected '" + me + "'). "
                + "This may be a socket-hijack attempt. Remove the directory "
                + "or set XDG_RUNTIME_DIR to a private location.");
        }
        try {
            Files.setPosixFilePermissions(socketDir,
                java.nio.file.attribute.PosixFilePermissions.fromString("rwx------"));
        } catch (IOException e) {
            Msg.warn(this, "Could not chmod socket dir " + socketDir
                + " to 0700: " + e.getMessage());
        }
    }

    private Path getSocketDir() {
        return resolveSocketDir(
            System.getenv("XDG_RUNTIME_DIR"),
            System.getenv("TMPDIR"),
            System.getProperty("java.io.tmpdir"),
            System.getProperty("user.name", "unknown"));
    }

    /**
     * Resolve the UDS socket directory: XDG_RUNTIME_DIR, then TMPDIR, then
     * java.io.tmpdir, then literal /tmp.
     *
     * The java.io.tmpdir step matters on Windows, where TMPDIR is unset and
     * the literal "/tmp" is drive-relative: it resolves against the JVM's
     * working drive (e.g. F:\tmp when Ghidra runs from F:), which a bridge
     * running from another drive never scans. java.io.tmpdir honors %TEMP%,
     * giving both sides the same absolute location; the Python side lists
     * %TEMP%\ghidra-mcp-&lt;user&gt; among its discovery candidates.
     */
    public static Path resolveSocketDir(String xdgRuntimeDir, String tmpdirEnv,
            String javaIoTmpdir, String user) {
        if (xdgRuntimeDir != null && !xdgRuntimeDir.isEmpty()) {
            return Path.of(xdgRuntimeDir, "ghidra-mcp");
        }
        if (user == null || user.isEmpty()) {
            user = "unknown";
        }
        if (tmpdirEnv != null && !tmpdirEnv.isEmpty()) {
            return Path.of(tmpdirEnv, "ghidra-mcp-" + user);
        }
        if (javaIoTmpdir != null && !javaIoTmpdir.isEmpty()) {
            return Path.of(javaIoTmpdir, "ghidra-mcp-" + user);
        }
        return Path.of("/tmp", "ghidra-mcp-" + user);
    }

    private String getSocketName() {
        long pid = ProcessHandle.current().pid();
        return "ghidra-" + pid + ".sock";
    }
}
