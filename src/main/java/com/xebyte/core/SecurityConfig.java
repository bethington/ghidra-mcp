package com.xebyte.core;

import com.xebyte.core.settings.DotEnv;
import com.xebyte.core.settings.ServerSettings;
import com.xebyte.core.settings.SettingRefusedException;
import com.xebyte.core.settings.SettingsRegistry;
import ghidra.util.Msg;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

/**
 * The server's security switches. All are off by default, so a localhost-only deployment
 * sees no behaviour change.
 *
 * <ul>
 *   <li>{@code auth.token} (secret, server scope only: {@code GHIDRA_MCP_AUTH_TOKEN}) — if set,
 *       every HTTP request must carry a matching {@code Authorization: Bearer &lt;token&gt;}
 *       header; {@code /mcp/health} and {@code /check_connection} are exempt. Compared in
 *       constant time. Read once at startup.
 *   <li>{@code scripts.allow} (guardrail) — allows {@code /run_ghidra_script} and
 *       {@code /run_script_inline}, which execute arbitrary Java in the Ghidra process.
 *   <li>{@code files.root} (guardrail) — endpoints that take a real <em>filesystem</em> path
 *       canonicalize it ({@link #resolveWithinFileRoot(String)}) and require it to fall under
 *       this directory. {@code /open_project} is contained the same way; a {@code ghidra://}
 *       URL names a server repository and is not a path. {@code /delete_file} takes project
 *       <em>domain</em> paths, so its containment is {@code project.folder_scope}.
 *   <li>{@code project.folder_scope} (guardrail) — the project folder programs must lie in to
 *       be served or changed ({@link #isPathInProjectScope(String)}).
 * </ul>
 *
 * <p>Guardrails are settings: the server operator sets them in the server's environment, and
 * the project's and this machine's settings can only make them stricter. They are resolved on
 * every check, through the {@link SettingsService} a server hands {@link #useSettings}, so a
 * tightening takes effect without a restart.
 *
 * <p>Also enforces a bind-hardening rule at headless startup:
 * {@link #requireAuthForNonLoopbackBind(String)} refuses to start the server on a
 * non-loopback address unless a token is configured.
 */
public final class SecurityConfig {

    private static final SecurityConfig INSTANCE = new SecurityConfig();

    /**
     * Hard ceiling on an HTTP request body, in bytes. Bounds the memory a
     * single request can force the server to allocate (a lying or absent
     * {@code Content-Length} otherwise lets {@code readAllBytes()} grow
     * unbounded). Generous enough for the largest legitimate batch operations
     * (thousands of rename/comment entries) while stopping a multi-GB
     * allocation DoS. Bodies carry JSON metadata only — file imports pass a
     * path, not file bytes — so 64 MiB is comfortably above real usage.
     */
    public static final long MAX_REQUEST_BODY_BYTES = 64L * 1024 * 1024;

    /**
     * True when a {@code Content-Length} header value parses to a size over
     * {@link #MAX_REQUEST_BODY_BYTES}. A null/absent/unparseable header returns
     * false (the actual read is still bounded downstream), so this is only a
     * fast-reject for honest clients that declare an oversized body.
     */
    public static boolean exceedsMaxBody(String contentLengthHeader) {
        if (contentLengthHeader == null) return false;
        try {
            return Long.parseLong(contentLengthHeader.trim()) > MAX_REQUEST_BODY_BYTES;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    private final byte[] tokenBytes;     // null if auth disabled
    private volatile Function<String, Object> guardrails = SecurityConfig::fromEnvironment;
    /** The last {@code files.root} canonicalized, with the value it came from. */
    private volatile CanonicalRoot canonicalRoot;

    private record CanonicalRoot(String raw, Path path) {}

    private SecurityConfig() {
        String rawToken = ServerSettings.string("auth.token");
        this.tokenBytes = rawToken.isEmpty()
                ? null
                : rawToken.getBytes(StandardCharsets.UTF_8);
    }

    /** Before a server wires its settings in: server-scope settings alone. */
    private static Object fromEnvironment(String key) {
        return ServerSettings.value(key);
    }

    /** Resolve guardrails through {@code settings}, so project and local values apply. */
    public void useSettings(SettingsService settings) {
        guardrails = key -> {
            try {
                return settings.value(key, null);
            } catch (SettingRefusedException e) {
                // An unreadable project store must not take the operator's value with it.
                Msg.warn(SecurityConfig.class, key + ": " + e.getMessage() + "; using the server's value");
                return fromEnvironment(key);
            }
        };
    }

    private Object guardrail(String key) {
        return guardrails.apply(key);
    }

    /** Environment variables renamed in 7.3.0+, mapped to their registry-derived names. */
    private static final Map<String, String> RETIRED = Map.ofEntries(
        Map.entry("GHIDRA_MCP_ALLOW_SCRIPTS", "GHIDRA_MCP_SCRIPTS_ALLOW"),
        Map.entry("GHIDRA_MCP_FILE_ROOT", "GHIDRA_MCP_FILES_ROOT"),
        Map.entry("GHIDRA_MCP_PROJECT_FOLDER", "GHIDRA_MCP_PROJECT_FOLDER_SCOPE"),
        Map.entry("GHIDRA_MCP_BIND_ADDRESS", SettingsRegistry.DEFAULT.get("server.bind_address").envName()),
        Map.entry("GHIDRA_MCP_MAX_CACHED_PROGRAMS", SettingsRegistry.DEFAULT.get("programs.max_cached").envName()),
        Map.entry("GHIDRA_MCP_SHARED_PROJECT_DIR", SettingsRegistry.DEFAULT.get("project.shared_dir").envName()),
        Map.entry("GHIDRA_SERVER_HOST", SettingsRegistry.DEFAULT.get("ghidra_server.host").envName()),
        Map.entry("GHIDRA_SERVER_PORT", SettingsRegistry.DEFAULT.get("ghidra_server.port").envName()),
        Map.entry("GHIDRA_SERVER_USER", SettingsRegistry.DEFAULT.get("ghidra_server.user").envName()),
        Map.entry("GHIDRA_SERVER_PASSWORD", SettingsRegistry.DEFAULT.get("ghidra_server.password").envName()));

    /**
     * A startup refusal naming any retired variable present in the process environment or
     * standard {@code .env} files, or {@code null}.
     */
    public static String retiredVariables() {
        return retiredVariables(System.getenv(), DotEnv.loadStandard());
    }

    public static String retiredVariables(Map<String, String> processEnv, Map<String, String> dotEnv) {
        List<String> set = RETIRED.keySet().stream()
            .filter(name -> processEnv.containsKey(name) || dotEnv.containsKey(name))
            .sorted()
            .map(old -> old + " (now " + RETIRED.get(old) + ")").toList();
        return set.isEmpty() ? null : "Retired environment variable(s) set: " + String.join(", ", set)
            + ". Rename them; the server does not read the old names.";
    }

    public static SecurityConfig getInstance() {
        return INSTANCE;
    }

    /** True when {@code auth.token} is set. */
    public boolean isAuthEnabled() {
        return tokenBytes != null;
    }

    /**
     * Extract the bearer token from an {@code Authorization} header value
     * and compare it constant-time against the configured token.
     *
     * @param authHeader the full header value (e.g. {@code "Bearer abc123"});
     *                   may be {@code null}
     * @return true if auth is disabled, or if the token matches
     */
    public boolean matchesBearerAuth(String authHeader) {
        if (tokenBytes == null) return true;  // auth disabled
        if (authHeader == null) return false;
        // Accept "Bearer <token>" with any amount of whitespace
        String prefix = "Bearer ";
        if (authHeader.length() < prefix.length()
                || !authHeader.regionMatches(true, 0, prefix, 0, prefix.length())) {
            return false;
        }
        byte[] presented = authHeader.substring(prefix.length()).trim()
                .getBytes(StandardCharsets.UTF_8);
        return constantTimeEquals(tokenBytes, presented);
    }

    /** The {@code scripts.allow} guardrail. */
    public boolean areScriptsAllowed() {
        return (Boolean) guardrail("scripts.allow");
    }

    /** True when {@code project.folder_scope} confines programs to a folder. */
    public boolean hasProjectFolderScope() {
        return getProjectFolderScope() != null;
    }

    /**
     * The project-folder scope prefix (e.g. {@code "/Project/1.0"}) without a trailing
     * slash, or {@code null} when none is set.
     */
    public String getProjectFolderScope() {
        String scope = ((String) guardrail("project.folder_scope")).trim();
        if (scope.length() > 1 && scope.endsWith("/")) {
            scope = scope.substring(0, scope.length() - 1);
        }
        return scope.isEmpty() ? null : scope;
    }

    /**
     * Pin {@code project.folder_scope}, every other guardrail reading the environment.
     * Package-private: settings are the only way a server sets it; tests in this package
     * set it here.
     */
    void setProjectFolderScopeForTest(String scope) {
        String value = scope == null ? "" : scope;
        guardrails = key -> "project.folder_scope".equals(key) ? value : fromEnvironment(key);
    }

    /**
     * Test whether {@code domainFilePath} falls under the configured project
     * folder scope. Always returns {@code true} when no scope is configured
     * (default — preserves general-user behavior).
     *
     * Uses the {@code path == prefix || path.startsWith(prefix + "/")} idiom
     * to prevent prefix-collision attacks (e.g. {@code /Project/1.0-OTHER}
     * does NOT match scope {@code /Project/1.0}).
     *
     * @param domainFilePath the project-relative path of a Ghidra DomainFile
     *                       (e.g. {@code "/Project/1.0/example.dll"});
     *                       null returns true (unscoped equivalent)
     */
    public boolean isPathInProjectScope(String domainFilePath) {
        return pathWithinScope(domainFilePath, getProjectFolderScope());
    }

    /**
     * Prefix-collision-safe scope match, factored out for direct unit testing
     * (the instance method resolves the scope from settings, so the branch where
     * a scope <em>is</em> configured is awkward to exercise otherwise).
     *
     * <p>A null {@code scopePrefix} (no scope configured) or null
     * {@code domainFilePath} both return true — the unscoped default. The
     * {@code equals || startsWith(prefix + "/")} idiom prevents prefix-collision
     * escapes (e.g. {@code /Project/1.0-OTHER} does NOT match {@code /Project/1.0}).
     */
    public static boolean pathWithinScope(String domainFilePath, String scopePrefix) {
        if (scopePrefix == null) return true;
        if (domainFilePath == null) return true;
        if (domainFilePath.equals(scopePrefix)) return true;
        return domainFilePath.startsWith(scopePrefix + "/");
    }

    /** True when {@code files.root} confines filesystem paths. */
    public boolean hasFileRoot() {
        return getFileRoot() != null;
    }

    /** The {@code files.root} directory, or {@code null} when none is set. */
    public String getFileRoot() {
        String root = ((String) guardrail("files.root")).trim();
        return root.isEmpty() ? null : root;
    }

    /**
     * Canonicalize {@code userPath} and verify it falls under {@link #getFileRoot()}. When
     * no file root is set this returns the path as-is. Returns {@code null} when a root is
     * set and the path escapes it.
     */
    public Path resolveWithinFileRoot(String userPath) {
        if (userPath == null) return null;
        Path requested = canonical(userPath);
        Path root = canonicalRoot();
        if (root == null) {
            return requested;  // no allow-list configured
        }
        return requested.startsWith(root) ? requested : null;
    }

    private Path canonicalRoot() {
        String root = getFileRoot();
        if (root == null) {
            return null;
        }
        CanonicalRoot cached = canonicalRoot;
        if (cached == null || !cached.raw().equals(root)) {
            cached = new CanonicalRoot(root, canonical(root));
            canonicalRoot = cached;
        }
        return cached.path();
    }

    private static Path canonical(String path) {
        try {
            return new File(path).getCanonicalFile().toPath();
        } catch (IOException e) {
            return Paths.get(path).toAbsolutePath().normalize();
        }
    }

    /**
     * Validate a bind address at server startup. When auth is NOT configured,
     * only loopback is permitted. Returns an error message to throw, or
     * {@code null} if the bind is acceptable.
     */
    public String requireAuthForNonLoopbackBind(String bindAddress) {
        if (bindAddress == null) return null;
        if (isAuthEnabled()) return null;
        if ("127.0.0.1".equals(bindAddress) || "localhost".equalsIgnoreCase(bindAddress)
                || "::1".equals(bindAddress)) {
            return null;
        }
        return "Refusing to bind " + bindAddress
                + " without GHIDRA_MCP_AUTH_TOKEN. Set the env var to a"
                + " strong shared secret before binding to a non-loopback address.";
    }

    /**
     * Anti-DNS-rebinding / anti-CSRF guard for the loopback-trust deployment.
     *
     * <p>When no auth token is configured (the default), the server trusts any
     * local caller — but a web page on <em>any</em> site the operator visits can
     * still issue a cross-origin {@code fetch()} to {@code 127.0.0.1} (responses
     * are {@code text/plain} and bodies parse as JSON regardless of
     * Content-Type, so it is a CORS "simple request" with no preflight), and a
     * DNS-rebinding attacker can point a hostname at loopback. This rejects
     * those by requiring the {@code Host} header — and the {@code Origin} header
     * when a browser sends one — to name a loopback address. Non-browser CLI
     * clients (the MCP bridge over TCP) send a loopback Host and no Origin, so
     * they pass unaffected.
     *
     * <p><b>Not enforced when a token is set:</b> the bearer token is the auth
     * control then (an attacker page cannot supply it, and adding an
     * {@code Authorization} header forces a CORS preflight that fails), and the
     * operator may legitimately bind a non-loopback interface and reach it by
     * hostname/IP — where a loopback-only Host check would be wrong.
     *
     * @param hostHeader   the request {@code Host} header (may be null)
     * @param originHeader the request {@code Origin} header (may be null)
     * @return null if the request is allowed; a stable error message (no
     *         attacker-controlled input reflected) if it must be rejected 403
     */
    public String rejectCrossOriginRequest(String hostHeader, String originHeader) {
        if (isAuthEnabled()) return null;  // token is the control; hostnames may be non-loopback
        if (originHeader != null && !originHeader.trim().isEmpty()
                && !isLoopbackOriginHeader(originHeader)) {
            return "Cross-origin request refused. This loopback server rejects browser "
                    + "requests from other origins to prevent CSRF / DNS-rebinding. Set "
                    + "GHIDRA_MCP_AUTH_TOKEN to allow authenticated cross-origin access.";
        }
        if (hostHeader != null && !hostHeader.trim().isEmpty()
                && !isLoopbackHostHeader(hostHeader)) {
            return "Request refused: non-loopback Host header. This blocks DNS-rebinding "
                    + "attacks against the loopback server. Set GHIDRA_MCP_AUTH_TOKEN to "
                    + "bind and reach a non-loopback address.";
        }
        return null;
    }

    /** True if an HTTP {@code Host} header names a loopback address. */
    public static boolean isLoopbackHostHeader(String hostHeader) {
        return isLoopbackHostName(extractHost(hostHeader));
    }

    /**
     * True if an {@code Origin} header names a loopback address. The literal
     * string {@code "null"} (an opaque origin from sandboxed / {@code file://}
     * contexts) is NOT loopback and returns false.
     */
    public static boolean isLoopbackOriginHeader(String originHeader) {
        if (originHeader == null) return false;
        String o = originHeader.trim();
        if (o.isEmpty() || o.equalsIgnoreCase("null")) return false;
        int scheme = o.indexOf("://");
        String authority = scheme >= 0 ? o.substring(scheme + 3) : o;
        int slash = authority.indexOf('/');   // Origin carries no path, but strip defensively
        if (slash >= 0) authority = authority.substring(0, slash);
        return isLoopbackHostName(extractHost(authority));
    }

    private static boolean isLoopbackHostName(String host) {
        if (host == null) return false;
        return host.equals("127.0.0.1") || host.equals("localhost") || host.equals("::1");
    }

    /**
     * Extract the lowercased host from an HTTP {@code Host} header or a URL
     * authority, stripping any port and IPv6 brackets. Returns null for
     * null/empty input.
     */
    public static String extractHost(String authority) {
        if (authority == null) return null;
        String a = authority.trim();
        if (a.isEmpty()) return null;
        if (a.startsWith("[")) {                 // IPv6 literal: [::1]:8089 or [::1]
            int end = a.indexOf(']');
            return (end > 0 ? a.substring(1, end) : a).toLowerCase();
        }
        int colon = a.indexOf(':');
        // Only strip a trailing :port when there's exactly one colon. A bare
        // IPv6 (multiple colons, no brackets) has no port to split off.
        if (colon >= 0 && a.indexOf(':', colon + 1) < 0) {
            return a.substring(0, colon).toLowerCase();
        }
        return a.toLowerCase();
    }

    /**
     * Timing-safe byte array comparison. Always iterates the longer of the
     * two arrays to avoid leaking length via timing. Returns false if arrays
     * differ in length.
     */
    private static boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a == null || b == null) return false;
        int diff = a.length ^ b.length;
        int max = Math.max(a.length, b.length);
        for (int i = 0; i < max; i++) {
            byte ab = i < a.length ? a[i] : 0;
            byte bb = i < b.length ? b[i] : 0;
            diff |= (ab ^ bb);
        }
        return diff == 0;
    }
}
