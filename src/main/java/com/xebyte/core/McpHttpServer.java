package com.xebyte.core;

import ghidra.util.Msg;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;

/**
 * The GhidraMCP endpoint surface, served over a Unix domain socket and, when asked,
 * over TCP.
 *
 * <p>The GUI plugin and the headless server serve the same thing: an
 * {@link AnnotationScanner}'s endpoints, some hand-written routes, and the identity
 * routes built here -- {@code /mcp/schema}, {@code /mcp/instance_info},
 * {@code /mcp/health} and {@code /check_connection}. They differ only in which other
 * routes they register; transports, request guarding, bridge discovery and "who are
 * you, and are you alive" live here, once. Those answers used to be written twice:
 * plain text in two different formats for {@code /check_connection}, and a health
 * route under a different name on each server, so no probe could ask both the same
 * question.
 */
public final class McpHttpServer {

    /**
     * Which listeners to run.
     *
     * @param uds       serve on {@code <socket dir>/ghidra-<pid>.sock}
     * @param tcp       serve on {@code bindAddress:port}
     * @param portRange ports to try from {@code port} upward when it is taken (1 = exact)
     * @param workers   request threads, shared by both listeners. Small in the GUI:
     *                  most handlers queue on the single Swing thread, and a deeper
     *                  queue there trips Ghidra's own 20 s Swing.runNow deadlock timeouts.
     */
    public record Config(boolean uds, boolean tcp, String bindAddress, int port, int portRange,
            int workers) {}

    /** Liveness probes stay token-less. Exact match: a prefix would let traversal inherit it. */
    private static final Set<String> AUTH_EXEMPT = Set.of("/mcp/health", "/check_connection");
    private static final long SLOW_HANDLER_WARN_MS = 2000;

    private final Map<String, UdsHttpServer.Handler> routes = new LinkedHashMap<>();
    private final String serverKind;
    private final Supplier<Map<String, Object>> instanceExtras;
    private long startMillis;
    private final AtomicInteger activeRequests = new AtomicInteger();
    private AnnotationScanner scanner;
    private java.util.concurrent.ThreadPoolExecutor executor;
    private UdsHttpServer uds;
    private com.sun.net.httpserver.HttpServer tcp;
    private volatile int tcpPort = -1;

    /**
     * @param serverKind     {@code "gui"} or {@code "headless"}, reported by every identity route
     * @param instanceExtras server-specific additions to {@code /mcp/instance_info}
     *                       (the GUI's registered tool count); may return an empty map
     */
    public McpHttpServer(String serverKind, Supplier<Map<String, Object>> instanceExtras) {
        this.serverKind = serverKind;
        this.instanceExtras = instanceExtras;
    }

    /** Serve every endpoint of {@code scanner}, and its schema as {@code /mcp/schema}. */
    public void endpoints(AnnotationScanner scanner) {
        this.scanner = scanner;
        for (EndpointDef ep : scanner.getEndpoints()) {
            route(ep.path(), exchange -> {
                Map<String, String> query = parseQuery(exchange.getRequestURI().getRawQuery());
                Map<String, Object> body = "POST".equalsIgnoreCase(exchange.getRequestMethod())
                        ? JsonHelper.parseBody(exchange.getRequestBody()) : Map.of();
                try {
                    sendJson(exchange, ep.handler().handle(query, body).toJson());
                } catch (IOException e) {
                    throw e;
                } catch (Exception e) {
                    throw new IllegalStateException(e);
                }
            });
        }
    }

    /** Add a route. A path registered twice is a bug (see #180), so it fails loudly. */
    public void route(String path, UdsHttpServer.Handler handler) {
        if (routes.putIfAbsent(path, handler) != null) {
            throw new IllegalStateException("Route registered twice: " + path);
        }
    }

    public synchronized void start(Config config) throws IOException {
        startMillis = System.currentTimeMillis();
        ProgramProvider provider = scanner != null ? scanner.getProgramProvider() : null;
        // Generated at start, not in endpoints(): callers add manual descriptors in between.
        String schemaJson = scanner != null ? scanner.generateSchema() : "{\"tools\": []}";
        int endpointCount = scanner != null ? scanner.getDescriptors().size() : 0;
        routes.put("/mcp/schema", exchange -> sendJson(exchange, schemaJson));
        routes.put("/mcp/instance_info", exchange ->
            sendJson(exchange, Response.ok(instanceInfo(provider, endpointCount)).toJson()));
        routes.put("/mcp/health", exchange ->
            sendJson(exchange, Response.ok(health(provider, endpointCount)).toJson()));
        routes.put("/check_connection", exchange ->
            sendJson(exchange, Response.ok(checkConnection(provider)).toJson()));
        AtomicInteger threadNo = new AtomicInteger(1);
        executor = (java.util.concurrent.ThreadPoolExecutor) Executors.newFixedThreadPool(config.workers(), r -> {
            Thread t = new Thread(r, "GhidraMCP-HTTP-" + threadNo.getAndIncrement());
            t.setDaemon(true);
            return t;
        });
        // Each requested transport is attempted independently: a Unix socket that
        // cannot bind (stale socket dir, hostile /tmp) must not take TCP down with
        // it, because TCP is the fallback the GUI relies on to stay reachable.
        // Only when nothing at all came up is this a failure.
        IOException udsFailure = null;
        IOException tcpFailure = null;
        if (config.uds()) {
            try {
                startUds();
            } catch (IOException | RuntimeException e) {
                udsFailure = e instanceof IOException io ? io : new IOException(e);
                Msg.warn(this, "UDS listener did not start: " + e.getMessage());
            }
        }
        if (config.tcp()) {
            try {
                startTcp(config);
            } catch (IOException | RuntimeException e) {
                tcpFailure = e instanceof IOException io ? io : new IOException(e);
                Msg.warn(this, "TCP listener did not start: " + e.getMessage());
            }
        }
        if (uds == null && tcp == null) {
            stop();
            IOException first = udsFailure != null ? udsFailure : tcpFailure;
            throw first != null ? first
                    : new IOException("No transport was requested");
        }
    }

    /**
     * Liveness and identity, cheap and auth-exempt: which kind of server answered, which
     * build, and whether a program is current. The doctor tool used to tell the two
     * servers apart by sniffing two different English sentences.
     */
    private Map<String, Object> checkConnection(ProgramProvider provider) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("status", "ok");
        out.put("server_kind", serverKind);
        out.put("version", VersionInfo.getVersion());
        out.put("program", currentProgramName(provider));
        return out;
    }

    /** {@link #checkConnection} plus load and build detail, for dashboards and smoke tests. */
    private Map<String, Object> health(ProgramProvider provider, int endpointCount) {
        Runtime rt = Runtime.getRuntime();
        long mb = 1024L * 1024L;
        Map<String, Object> out = checkConnection(provider);
        out.put("connected", true);
        out.put("open_program_count", provider != null ? provider.getAllOpenPrograms().length : 0);
        out.put("uptime_seconds", (System.currentTimeMillis() - startMillis) / 1000L);
        out.put("active_requests", activeRequests.get());
        out.put("version", JsonHelper.mapOf(
            "plugin_version", VersionInfo.getVersion(),
            "plugin_name", VersionInfo.getAppName(),
            "full_version", VersionInfo.getFullVersion(),
            "build_timestamp", VersionInfo.getBuildTimestamp(),
            "build_number", VersionInfo.getBuildNumber(),
            "ghidra_version", VersionInfo.getGhidraVersion(),
            "java_version", System.getProperty("java.version"),
            "endpoint_count", endpointCount));
        out.put("http_pool", poolStats());
        out.put("memory_mb", JsonHelper.mapOf(
            "used", (rt.totalMemory() - rt.freeMemory()) / mb,
            "total", rt.totalMemory() / mb,
            "max", rt.maxMemory() / mb));
        return out;
    }

    /**
     * What the bridge's discovery reads: the project, its programs with {@code open}
     * marking the ones this server has open (by path: two versions of one DLL share a
     * name), and how to reach this server.
     */
    private Map<String, Object> instanceInfo(ProgramProvider provider, int endpointCount) {
        ghidra.framework.model.Project project = provider != null ? provider.getProject() : null;
        java.util.Set<String> openPaths = new java.util.HashSet<>();
        if (provider != null) {
            for (ghidra.program.model.listing.Program p : provider.getAllOpenPrograms()) {
                openPaths.add(ProjectProgramProvider.keyFor(p));
            }
        }
        List<Map<String, Object>> programs = new java.util.ArrayList<>();
        if (project != null) {
            collectPrograms(project.getProjectData().getRootFolder(), openPaths, programs);
        }
        Map<String, Object> info = new LinkedHashMap<>();
        info.put("pid", ProcessHandle.current().pid());
        info.put("server_kind", serverKind);
        info.put("version", VersionInfo.getVersion());
        info.put("endpoint_count", endpointCount);
        info.put("project", project != null ? project.getName() : "unknown");
        info.put("project_path", project != null ? project.getProjectLocator().toString() : "");
        info.put("programs", programs);
        info.putAll(instanceExtras.get());
        info.put("tcp_port", tcpPort);
        return info;
    }

    private static void collectPrograms(ghidra.framework.model.DomainFolder folder,
            java.util.Set<String> openPaths, List<Map<String, Object>> out) {
        for (ghidra.framework.model.DomainFile df : folder.getFiles()) {
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("name", df.getName());
            entry.put("path", df.getPathname());
            entry.put("open", openPaths.contains(df.getPathname()));
            out.add(entry);
        }
        for (ghidra.framework.model.DomainFolder sub : folder.getFolders()) {
            collectPrograms(sub, openPaths, out);
        }
    }

    private static String currentProgramName(ProgramProvider provider) {
        ghidra.program.model.listing.Program current = provider != null ? provider.getCurrentProgram() : null;
        return current != null ? current.getName() : null;
    }

    public synchronized void stop() {
        if (tcp != null) {
            tcp.stop(1);
            tcp = null;
            tcpPort = -1;
            Msg.info(this, "GhidraMCP TCP server stopped");
        }
        if (uds != null) {
            uds.stop();
            uds = null;
        }
        if (executor != null) {
            executor.shutdown();
            try {
                if (!executor.awaitTermination(5, java.util.concurrent.TimeUnit.SECONDS)) {
                    executor.shutdownNow();
                }
            } catch (InterruptedException e) {
                executor.shutdownNow();
                Thread.currentThread().interrupt();
            }
            executor = null;
        }
    }

    public boolean isRunning() { return uds != null || tcp != null; }

    /** The bound TCP port, or -1 when TCP is not running. */
    public int tcpPort() { return tcpPort; }

    public Path socketPath() { return uds != null ? uds.getSocketPath() : null; }

    public int activeRequests() { return activeRequests.get(); }

    /** Request-pool figures for a health endpoint; empty while stopped. */
    public Map<String, Object> poolStats() {
        var pool = executor;
        if (pool == null) {
            return Map.of();
        }
        return JsonHelper.mapOf(
                "configured_size", pool.getCorePoolSize(),
                "current_size", pool.getPoolSize(),
                "largest_size", pool.getLargestPoolSize(),
                "queue_size", pool.getQueue().size(),
                "completed_tasks", pool.getCompletedTaskCount());
    }

    // ------------------------------------------------------------------ listeners

    private void startUds() throws IOException {
        Path socketDir = resolveSocketDir(
                System.getenv("XDG_RUNTIME_DIR"),
                System.getenv("TMPDIR"),
                System.getProperty("java.io.tmpdir"),
                System.getProperty("user.name", "unknown"));
        Files.createDirectories(socketDir);
        hardenSocketDir(socketDir);
        cleanStaleSockets(socketDir);
        uds = new UdsHttpServer(socketDir.resolve("ghidra-" + ProcessHandle.current().pid() + ".sock"), executor);
        // A browser cannot open a Unix socket, so no cross-origin guard here.
        routes.forEach((path, handler) -> uds.createContext(path, guard(handler, false)));
        uds.start();
    }

    private void startTcp(Config config) throws IOException {
        String bindError = SecurityConfig.getInstance().requireAuthForNonLoopbackBind(config.bindAddress());
        if (bindError != null) {
            throw new IOException(bindError);
        }
        java.net.BindException lastBindException = null;
        int last = config.port() + Math.max(1, config.portRange()) - 1;
        for (int candidate = config.port(); candidate <= last; candidate++) {
            try {
                tcp = com.sun.net.httpserver.HttpServer.create(
                        new InetSocketAddress(config.bindAddress(), candidate), 0);
                // The bound port, not the candidate: port 0 asks the OS to pick one.
                tcpPort = tcp.getAddress().getPort();
                break;
            } catch (java.net.BindException e) {
                lastBindException = e;
            }
        }
        if (tcp == null) {
            throw new IOException("No free TCP port in " + config.port() + "-" + last
                    + " on " + config.bindAddress(), lastBindException);
        }
        if (config.port() != 0 && tcpPort != config.port()) {
            Msg.warn(this, "Port " + config.port() + " was in use; bound " + tcpPort
                    + " instead. The bridge discovers it via /mcp/instance_info.");
        }
        routes.forEach((path, handler) -> {
            UdsHttpServer.Handler guarded = guard(handler, true);
            tcp.createContext(path, sun -> guarded.handle(new SunHttpExchangeAdapter(sun)));
        });
        tcp.setExecutor(executor);
        tcp.start();
        Msg.info(this, "GhidraMCP TCP server listening on " + config.bindAddress() + ":" + tcpPort);
    }

    // ------------------------------------------------------------------ request guard

    /**
     * Every route on every transport goes through here: bearer auth, the
     * cross-origin guard (TCP only), the body bound, a generic error for anything
     * uncaught, and in-flight / slow-request accounting.
     */
    private UdsHttpServer.Handler guard(UdsHttpServer.Handler handler, boolean browserReachable) {
        return exchange -> {
            long startNanos = System.nanoTime();
            String path = exchange.getRequestURI().getPath();
            activeRequests.incrementAndGet();
            try {
                if (!AUTH_EXEMPT.contains(path)) {
                    SecurityConfig sec = SecurityConfig.getInstance();
                    if (browserReachable) {
                        String crossOriginError = sec.rejectCrossOriginRequest(
                                exchange.getRequestHeaders().getFirst("Host"),
                                exchange.getRequestHeaders().getFirst("Origin"));
                        if (crossOriginError != null) {
                            sendStatus(exchange, 403, crossOriginError);
                            return;
                        }
                    }
                    if (sec.isAuthEnabled()
                            && !sec.matchesBearerAuth(exchange.getRequestHeaders().getFirst("Authorization"))) {
                        exchange.getResponseHeaders().set("WWW-Authenticate", "Bearer");
                        sendStatus(exchange, 401, "Unauthorized");
                        return;
                    }
                    if (SecurityConfig.exceedsMaxBody(exchange.getRequestHeaders().getFirst("Content-Length"))) {
                        sendStatus(exchange, 413, "Request body too large");
                        return;
                    }
                }
                handler.handle(exchange);
            } catch (Throwable e) {
                // Full detail to the Ghidra log only: exception text can leak paths
                // and class names. Deliberate validation errors come back from the
                // handlers themselves as Response.err and never reach this.
                Msg.error(McpHttpServer.class, "Unhandled error handling " + path, e);
                try {
                    sendJson(exchange, Response.err(
                            "Internal server error. See the Ghidra application log for details.").toJson());
                } catch (Throwable ignored) {
                    // Response already committed, or the exchange is gone.
                }
            } finally {
                activeRequests.decrementAndGet();
                long elapsedMs = (System.nanoTime() - startNanos) / 1_000_000L;
                if (elapsedMs >= SLOW_HANDLER_WARN_MS) {
                    Msg.warn(McpHttpServer.class, String.format("SLOW %s %s took %d ms",
                            exchange.getRequestMethod(), path, elapsedMs));
                }
            }
        };
    }

    // ------------------------------------------------------------------ socket dir

    /**
     * Resolve the UDS socket directory: XDG_RUNTIME_DIR, then TMPDIR, then
     * java.io.tmpdir, then literal /tmp. The bridge scans the same candidates.
     *
     * <p>The java.io.tmpdir step matters on Windows, where TMPDIR is unset and
     * the literal "/tmp" is drive-relative: it resolves against the JVM's
     * working drive (e.g. F:\tmp when Ghidra runs from F:), which a bridge
     * running from another drive never scans. java.io.tmpdir honors %TEMP%,
     * giving both sides the same absolute location.
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

    /**
     * Refuse a socket dir someone else owns, and chmod ours to 0700. The fallback
     * {@code /tmp/ghidra-mcp-<user>} is predictable; on a multi-user host an attacker
     * can pre-create it (sticky /tmp allows new entries) and replace or intercept
     * the socket -- full unauthenticated access to the RE endpoints. No-op without
     * POSIX attributes (Windows).
     */
    private static void hardenSocketDir(Path socketDir) throws IOException {
        if (!socketDir.getFileSystem().supportedFileAttributeViews().contains("posix")) {
            return;
        }
        var attrs = Files.readAttributes(socketDir, java.nio.file.attribute.PosixFileAttributes.class);
        String owner = attrs.owner().getName();
        String me = System.getProperty("user.name");
        if (me != null && !me.equals(owner)) {
            throw new IOException("Refusing to bind UDS socket: directory " + socketDir
                    + " is owned by '" + owner + "' (expected '" + me + "'). "
                    + "This may be a socket-hijack attempt. Remove the directory "
                    + "or set XDG_RUNTIME_DIR to a private location.");
        }
        try {
            Files.setPosixFilePermissions(socketDir,
                    java.nio.file.attribute.PosixFilePermissions.fromString("rwx------"));
        } catch (IOException e) {
            Msg.warn(McpHttpServer.class, "Could not chmod socket dir " + socketDir + " to 0700: " + e.getMessage());
        }
    }

    /** Remove {@code ghidra-<pid>.sock} files whose process is gone. */
    private static void cleanStaleSockets(Path socketDir) {
        try (var entries = Files.list(socketDir)) {
            for (Path p : (Iterable<Path>) entries::iterator) {
                String name = p.getFileName().toString();
                if (!name.startsWith("ghidra-") || !name.endsWith(".sock")) {
                    continue;
                }
                try {
                    long pid = Long.parseLong(name.substring("ghidra-".length(), name.length() - ".sock".length()));
                    if (ProcessHandle.of(pid).isEmpty()) {
                        Files.deleteIfExists(p);
                        Msg.info(McpHttpServer.class, "Cleaned stale socket: " + name);
                    }
                } catch (NumberFormatException e) {
                    // not ours
                }
            }
        } catch (IOException e) {
            Msg.warn(McpHttpServer.class, "Could not clean stale sockets in " + socketDir + ": " + e.getMessage());
        }
    }

    // ------------------------------------------------------------------ helpers

    public static void sendJson(HttpExchange exchange, String json) throws IOException {
        byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=UTF-8");
        exchange.sendResponseHeaders(200, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    private static void sendStatus(HttpExchange exchange, int status, String error) throws IOException {
        byte[] bytes = Response.err(error).toJson().getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    public static Map<String, String> parseQuery(String rawQuery) {
        Map<String, String> params = new LinkedHashMap<>();
        if (rawQuery == null || rawQuery.isEmpty()) return params;
        for (String pair : rawQuery.split("&")) {
            int eq = pair.indexOf('=');
            if (eq > 0) {
                params.put(URLDecoder.decode(pair.substring(0, eq), StandardCharsets.UTF_8),
                        URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8));
            } else if (!pair.isEmpty()) {
                params.put(URLDecoder.decode(pair, StandardCharsets.UTF_8), "");
            }
        }
        return params;
    }
}
