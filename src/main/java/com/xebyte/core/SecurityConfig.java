package com.xebyte.core;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Read-once, thread-safe snapshot of security-relevant environment variables.
 *
 * v5.4.1 introduces three opt-in hardening switches. All are off by default
 * so existing localhost-only deployments see no behavior change.
 *
 * <ul>
 *   <li>{@code GHIDRA_MCP_AUTH_TOKEN} — if set, every HTTP request must
 *       carry a matching {@code Authorization: Bearer &lt;token&gt;} header.
 *       Read-only health endpoints ({@code /mcp/health}, {@code /check_connection})
 *       are always exempt. Constant-time comparison is used to resist timing
 *       attacks. When unset, no authentication is enforced (pre-v5.4.1
 *       behavior).
 *   <li>{@code GHIDRA_MCP_ALLOW_SCRIPTS} — set to {@code "1"}, {@code "true"},
 *       or {@code "yes"} (case-insensitive) to allow {@code /run_script} and
 *       {@code /run_script_inline}. These endpoints execute arbitrary Java
 *       code against the Ghidra process and are off by default in v5.4.1+.
 *       Without an explicit opt-in they return 403. Scripts endpoints were
 *       always-on before v5.4.1; the flip to default-off is a deliberate
 *       breaking change in the security release.
 *   <li>{@code GHIDRA_MCP_FILE_ROOT} — if set to a directory path, every
 *       endpoint that takes a filesystem path ({@code /import_file},
 *       {@code /delete_file}, {@code /open_project}, etc.) canonicalizes the
 *       input and requires that the resolved path fall under this root.
 *       Prevents path traversal. When unset, paths are accepted as-is
 *       (pre-v5.4.1 behavior).
 * </ul>
 *
 * Also enforces a bind-hardening rule at headless startup:
 * {@link #requireAuthForNonLoopbackBind(String)} refuses to start the
 * server on a non-loopback address unless a token is configured.
 */
public final class SecurityConfig {

    private static final SecurityConfig INSTANCE = new SecurityConfig();

    private final byte[] tokenBytes;     // null if auth disabled
    private final boolean scriptsAllowed;
    private final String fileRoot;       // null if disabled
    private final Path fileRootCanonical;

    private SecurityConfig() {
        String rawToken = System.getenv("GHIDRA_MCP_AUTH_TOKEN");
        this.tokenBytes = (rawToken != null && !rawToken.isEmpty())
                ? rawToken.getBytes(StandardCharsets.UTF_8)
                : null;

        String rawScripts = System.getenv("GHIDRA_MCP_ALLOW_SCRIPTS");
        this.scriptsAllowed = rawScripts != null
                && (rawScripts.equalsIgnoreCase("1")
                    || rawScripts.equalsIgnoreCase("true")
                    || rawScripts.equalsIgnoreCase("yes"));

        String rawRoot = System.getenv("GHIDRA_MCP_FILE_ROOT");
        if (rawRoot != null && !rawRoot.isEmpty()) {
            this.fileRoot = rawRoot;
            Path p;
            try {
                p = new File(rawRoot).getCanonicalFile().toPath();
            } catch (IOException e) {
                p = Paths.get(rawRoot).toAbsolutePath().normalize();
            }
            this.fileRootCanonical = p;
        } else {
            this.fileRoot = null;
            this.fileRootCanonical = null;
        }
    }

    public static SecurityConfig getInstance() {
        return INSTANCE;
    }

    /** True when {@code GHIDRA_MCP_AUTH_TOKEN} is set. */
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

    /** True when {@code GHIDRA_MCP_ALLOW_SCRIPTS} opts in. */
    public boolean areScriptsAllowed() {
        return scriptsAllowed;
    }

    /** True when {@code GHIDRA_MCP_FILE_ROOT} is set. */
    public boolean hasFileRoot() {
        return fileRoot != null;
    }

    public String getFileRoot() {
        return fileRoot;
    }

    /**
     * Canonicalize {@code userPath} and verify it falls under
     * {@link #getFileRoot()}. When no file root is configured this returns the
     * path as-is (pre-v5.4.1 behavior). Returns {@code null} when a root is
     * configured and the path escapes it.
     */
    public Path resolveWithinFileRoot(String userPath) {
        if (userPath == null) return null;
        Path requested;
        try {
            requested = new File(userPath).getCanonicalFile().toPath();
        } catch (IOException e) {
            requested = Paths.get(userPath).toAbsolutePath().normalize();
        }
        if (fileRootCanonical == null) {
            return requested;  // no allow-list configured
        }
        return requested.startsWith(fileRootCanonical) ? requested : null;
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
