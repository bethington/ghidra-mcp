package com.xebyte.core;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import java.io.IOException;
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
    /** Request threads for GUI transports; see {@link McpHttpServer.Config#workers()}. */
    public static final int GUI_WORKERS = 3;

    private McpHttpServer server;
    /** What the caller last started with, so a survivor can take the server over. */
    private AnnotationScanner lastScanner;
    private java.util.function.Consumer<McpHttpServer> lastGuiEndpoints;
    private McpHttpServer.Config lastConfig;

    /**
     * The port the TCP listener actually bound, or -1 when it is not running.
     *
     * <p>Read from the listener rather than tracked in a field: with port-range
     * fallback (#175) the bound port is not the configured one, and a field only
     * tells the truth for as long as everyone remembers to update it.
     */
    public int getBoundTcpPort() {
        return server != null ? server.tcpPort() : -1;
    }

    /**
     * Rebind the server to a different caller's scanner.
     *
     * <p>The routes close over the services of whichever plugin instance
     * supplied the scanner. When that tool window is disposed those services go
     * stale, so a surviving window hands its own over. McpHttpServer refuses a
     * duplicate route by design, so this is a stop and a fresh start, not a swap.
     */
    public synchronized void rebind(AnnotationScanner scanner,
            java.util.function.Consumer<McpHttpServer> guiEndpoints) throws IOException {
        if (server == null || lastConfig == null) {
            return;
        }
        McpHttpServer.Config config = lastConfig;
        stopServer();
        startServer(scanner, guiEndpoints, config);
    }

    private ServerManager() {}

    /**
     * Register a CodeBrowser/FrontEnd tool and, on the first one, start the server.
     *
     * <p>The scanner comes from the caller. This used to build a second, parallel
     * set of every service over a second ProgramProvider, so the same request
     * answered differently depending on which transport carried it: the provider
     * here saw only programs a CodeBrowser already had open, while the plugin's
     * saw those plus its cache plus anything it could open from the project.
     * One service set, one provider, one answer.
     */
    public synchronized void registerTool(PluginTool tool, AnnotationScanner scanner,
            java.util.function.Consumer<McpHttpServer> guiEndpoints,
            McpHttpServer.Config config) throws IOException {
        String toolId = String.valueOf(System.identityHashCode(tool));
        tools.put(toolId, tool);
        activeToolId.compareAndSet(null, toolId);
        Msg.info(this, "Registered tool " + toolId + " (total: " + tools.size() + ")");

        if (server == null) {
            startServer(scanner, guiEndpoints, config);
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

    public boolean isRunning() { return server != null; }

    /** Stop the UDS server without deregistering tools. Use for manual stop/restart. */
    public synchronized void stopUdsServer() {
        stopServer();
    }

    public Path getSocketPath() {
        return server != null ? server.socketPath() : null;
    }

    private void startServer(AnnotationScanner scanner,
            java.util.function.Consumer<McpHttpServer> guiEndpoints,
            McpHttpServer.Config config) throws IOException {
        lastScanner = scanner;
        lastGuiEndpoints = guiEndpoints;
        lastConfig = config;
        server = new McpHttpServer("gui", () -> Map.of("tools", tools.size()));
        server.endpoints(scanner);
        // The scanner arrives with its manual descriptors already added (the plugin's
        // buildScanner owns that); adding them here too listed every hand-coded route
        // twice in /mcp/schema.
        if (guiEndpoints != null) {
            guiEndpoints.accept(server);
        }
        server.start(config);
    }

    private void stopServer() {
        if (server != null) {
            server.stop();
            server = null;
        }
    }

}
