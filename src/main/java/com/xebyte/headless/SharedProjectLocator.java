package com.xebyte.headless;

import com.xebyte.core.SecurityConfig;
import ghidra.framework.protocol.ghidra.GhidraURL;

import java.net.URI;
import java.nio.file.Path;
import java.util.Locale;
import java.util.Objects;

/**
 * Parse {@code ghidra://} server URLs and resolve the persistent local project
 * directory that holds working copies for a shared repository.
 *
 * <p>A GhidraURLConnection view is read-only / transient — checkouts need a
 * real local {@code .rep}. The directory is therefore durable (never
 * {@code /tmp}) and keyed by host+port+repo so two JVMs cannot share one
 * project lock by accident.
 */
public final class SharedProjectLocator {

    /** Matches {@link com.xebyte.headless.GhidraServerManager}'s default. */
    public static final int DEFAULT_SERVER_PORT = 13100;

    public static final String SHARED_PROJECT_DIR_ENV = "GHIDRA_MCP_SHARED_PROJECT_DIR";

    private SharedProjectLocator() {}

    /**
     * Host / port / repository identified by a server URL.
     *
     * @param host repository server hostname
     * @param port RMI port (never -1; port-less URLs resolve to
     *             {@link #DEFAULT_SERVER_PORT})
     * @param repo repository name (first path segment)
     */
    public record Parsed(String host, int port, String repo) {
        public Parsed {
            Objects.requireNonNull(host, "host");
            Objects.requireNonNull(repo, "repo");
            if (host.isBlank()) {
                throw new IllegalArgumentException("host must not be blank");
            }
            if (repo.isBlank()) {
                throw new IllegalArgumentException("repo must not be blank");
            }
            if (port <= 0) {
                throw new IllegalArgumentException("port must be positive: " + port);
            }
        }

        /** Filesystem-safe key so two hosts cannot collide on one project dir. */
        public String directoryKey() {
            return sanitize(host) + "_" + port + "_" + sanitize(repo);
        }
    }

    /**
     * True when {@code path} is a Ghidra protocol string (server or local).
     * Used to refuse falling through to the local {@code .gpr} branch.
     */
    public static boolean isGhidraUrl(String path) {
        if (path == null) {
            return false;
        }
        String trimmed = path.trim();
        if (trimmed.isEmpty()) {
            return false;
        }
        // isGhidraURL is regex-only and does not need the protocol handler
        // registered — safe in offline tests and before Application.initialize.
        return GhidraURL.isGhidraURL(trimmed)
                || trimmed.regionMatches(true, 0, "ghidra:", 0, 7);
    }

    /**
     * Parse a server repository URL. Rejects local {@code ghidra:/path} forms
     * and anything missing host or repository — callers must not treat those
     * as a silent local-project open.
     *
     * @throws IllegalArgumentException when the string is not a usable
     *         {@code ghidra://host[:port]/repo} URL
     */
    public static Parsed parseServerUrl(String url) {
        if (url == null || url.isBlank()) {
            throw new IllegalArgumentException("ghidra:// URL required");
        }
        String trimmed = url.trim();
        if (!isGhidraUrl(trimmed)) {
            throw new IllegalArgumentException("not a ghidra:// URL: " + trimmed);
        }
        // Local project URLs (ghidra:/path/to/project) are a different shape —
        // opening them as a shared project would invent a bogus host.
        //
        // Tested with isServerURL alone rather than also calling
        // isLocalGhidraURL: Ghidra 12.1.3 REMOVED isLocalGhidraURL, and the
        // negation covers it anyway — anything that is not a server URL is
        // rejected here regardless of why. Keeping the removed call cost a
        // NoSuchMethodError at runtime on 12.1.3 while still compiling on
        // 12.1.2, which is the worst of both.
        if (!GhidraURL.isServerURL(trimmed)) {
            throw new IllegalArgumentException(
                    "expected a Ghidra Server URL (ghidra://host[:port]/repo), got: "
                            + trimmed);
        }

        // URI parses ghidra:// without the URLStreamHandler that GhidraURL.toURL
        // requires — that handler is only installed after Application init.
        final URI uri;
        try {
            uri = URI.create(trimmed);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("malformed ghidra:// URL: " + trimmed, e);
        }

        String host = uri.getHost();
        if (host == null || host.isBlank()) {
            throw new IllegalArgumentException(
                    "ghidra:// URL missing host: " + trimmed);
        }

        int port = uri.getPort();
        if (port < 0) {
            // Port-less form (ghidra://host/repo) — same default as analyzeHeadless.
            port = DEFAULT_SERVER_PORT;
        }

        String path = uri.getPath();
        if (path == null || path.isBlank() || "/".equals(path)) {
            throw new IllegalArgumentException(
                    "ghidra:// URL missing repository name: " + trimmed);
        }
        // First segment is the repository; deeper segments name a folder/file
        // inside it and are ignored for project open (open the repo, not a view).
        String stripped = path.startsWith("/") ? path.substring(1) : path;
        int slash = stripped.indexOf('/');
        String repo = slash < 0 ? stripped : stripped.substring(0, slash);
        if (repo.isBlank()) {
            throw new IllegalArgumentException(
                    "ghidra:// URL missing repository name: " + trimmed);
        }

        return new Parsed(host, port, repo);
    }

    /**
     * Resolve the parent directory that will hold {@code <repo>.gpr}/{@code .rep}.
     *
     * <p>Default: {@code ~/ghidra-shared-projects/<host>_<port>_<repo>}.
     * Override root with {@code GHIDRA_MCP_SHARED_PROJECT_DIR} (key still appended).
     * Routed through {@link SecurityConfig#resolveWithinFileRoot} so a configured
     * {@code GHIDRA_MCP_FILE_ROOT} cannot be escaped.
     */
    public static Path resolveProjectDir(Parsed parsed) {
        return resolveProjectDir(parsed, System.getenv(SHARED_PROJECT_DIR_ENV),
                SecurityConfig.getInstance());
    }

    /**
     * Testable overload — same rules as {@link #resolveProjectDir(Parsed)}.
     *
     * @param overrideRoot value of {@code GHIDRA_MCP_SHARED_PROJECT_DIR}, or null
     */
    public static Path resolveProjectDir(Parsed parsed, String overrideRoot, SecurityConfig security) {
        Objects.requireNonNull(parsed, "parsed");
        Objects.requireNonNull(security, "security");

        Path root;
        if (overrideRoot != null && !overrideRoot.isBlank()) {
            String trimmed = overrideRoot.trim();
            Path input = Path.of(trimmed);
            if (!input.isAbsolute()) {
                // Relative roots bind to the server cwd — never what an agent meant.
                throw new IllegalArgumentException(
                        SHARED_PROJECT_DIR_ENV + " must be an absolute path: " + trimmed);
            }
            root = input;
        } else {
            // Deliberately NOT a dotted directory. Ghidra 12.1.3's ProjectLocator
            // rejects any path element starting with '.' ("Path element starting
            // with '.' is not permitted"), so ~/.ghidra-mcp/... makes every
            // shared-project open fail. Older Ghidra accepted it, which is why
            // this only surfaced on upgrade.
            root = Path.of(System.getProperty("user.home"), "ghidra-shared-projects");
        }

        Path projectDir = root.resolve(parsed.directoryKey()).toAbsolutePath().normalize();
        Path resolved = security.resolveWithinFileRoot(projectDir.toString());
        if (resolved == null) {
            throw new IllegalArgumentException(
                    "shared project dir escapes GHIDRA_MCP_FILE_ROOT: " + projectDir
                            + " (root=" + security.getFileRoot() + ")");
        }
        return resolved;
    }

    /** True when {@code path} should take the local {@code .gpr} open branch. */
    public static boolean isLocalProjectPath(String path) {
        return path != null && !path.isBlank() && !isGhidraUrl(path);
    }

    private static String sanitize(String raw) {
        // Project dirs cannot contain path separators; colon appears in IPv6.
        StringBuilder sb = new StringBuilder(raw.length());
        for (int i = 0; i < raw.length(); i++) {
            char c = raw.charAt(i);
            if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
                    || (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_') {
                sb.append(c);
            } else {
                sb.append('_');
            }
        }
        String out = sb.toString();
        if (out.isEmpty()) {
            // Degenerate host after sanitize — still unique enough via port+repo.
            return "host";
        }
        return out.toLowerCase(Locale.ROOT);
    }
}
