package com.xebyte.core;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Hand-authored {@link AnnotationScanner.ToolDescriptor}s for HTTP routes that are
 * registered directly via {@code createContext}/{@code safeContext} in
 * {@link com.xebyte.GhidraMCPPlugin} and/or
 * {@link com.xebyte.headless.GhidraMCPHeadlessServer}, rather than discovered via
 * {@code @McpTool} reflection (utility/server/project/tool routes that predate the
 * annotation-scanner convention). Without this registry these routes are fully live
 * and callable but invisible in {@code /mcp/schema} -- the Python bridge's dynamic
 * tool discovery reads only that schema, so an AI agent connected through the bridge
 * could never see or call them (found via a live-schema-vs-catalog diff, v6.0.0).
 *
 * <p>Path/method/category/description/params are sourced verbatim from
 * {@code tests/endpoints.json}'s hand-registered entries (see
 * {@code RegenerateEndpointsJson}'s "preserved (hand-registered)" merge rule --
 * that file is the existing source of truth for these routes' metadata). Params
 * carry only a name and a source inferred from the route's HTTP method (GET -&gt;
 * query, POST -&gt; body); the catalog does not track per-param type/required detail
 * for hand-registered routes, and every one of these handlers already parses its
 * own params permissively, so marking them optional-string is accurate enough for
 * tool discovery without overclaiming precision the source data doesn't have.
 *
 * <p>{@code ManualToolDescriptorsParityTest} enforces that every path a server
 * registers manually has an entry here, so a future added route can't silently
 * repeat this gap.
 */
public final class ManualToolDescriptors {

    private ManualToolDescriptors() {}

    private static AnnotationScanner.ParamDescriptor p(String name, String source) {
        return new AnnotationScanner.ParamDescriptor(name, "string", source, true, null, "", "");
    }

    private static List<AnnotationScanner.ParamDescriptor> params(String method, String... names) {
        String source = "GET".equalsIgnoreCase(method) ? "query" : "body";
        List<AnnotationScanner.ParamDescriptor> out = new java.util.ArrayList<>();
        for (String n : names) out.add(p(n, source));
        return out;
    }

    private static void add(Map<String, AnnotationScanner.ToolDescriptor> m,
            String path, String method, String category, String description, String... paramNames) {
        m.put(path, new AnnotationScanner.ToolDescriptor(
            path, method, description, category, "", params(method, paramNames)));
    }

    /** Keyed by path. Built once; entries never mutate after class init. */
    private static final Map<String, AnnotationScanner.ToolDescriptor> ALL = buildAll();

    private static Map<String, AnnotationScanner.ToolDescriptor> buildAll() {
        Map<String, AnnotationScanner.ToolDescriptor> m = new LinkedHashMap<>();
        add(m, "/batch_apply_documentation", "POST", "analysis", "Apply all documentation to a function in one call", "address", "name", "prototype", "calling_convention", "variable_types", "variable_renames", "plate_comment", "decompiler_comments", "disassembly_comments", "goto", "score", "program");
        add(m, "/check_connection", "GET", "utility", "Health check endpoint");
        add(m, "/configure_analyzer", "POST", "analysis", "Configure an analysis plugin", "name", "enabled", "program");
        add(m, "/delete_project", "POST", "project", "Delete a Ghidra project", "projectPath");
        add(m, "/exit_ghidra", "POST", "program", "Save and exit Ghidra");
        add(m, "/get_current_address", "GET", "getter", "Get cursor address (GUI only)");
        add(m, "/get_current_function", "GET", "getter", "Get function at cursor (GUI only)");
        add(m, "/get_current_selection", "GET", "getter", "Get highlighted address ranges in the CodeBrowser listing (GUI only). Returns {program, is_empty, ranges:[{start,end,length}], min_address, max_address, num_addresses} or an empty-selection payload when nothing is highlighted.");
        add(m, "/get_version", "GET", "utility", "Get plugin version");
        add(m, "/health", "GET", "utility", "Health check endpoint for headless server");
        add(m, "/list_projects", "GET", "project", "List available Ghidra projects", "searchDir");
        add(m, "/mcp/health", "GET", "utility", "HTTP server health: pool stats, uptime, memory, active request count");
        add(m, "/mcp/schema", "GET", "utility", "Machine-readable API schema with endpoint metadata");
        add(m, "/move_file", "POST", "project", "Move a file to another project folder", "filePath", "destFolder");
        add(m, "/move_folder", "POST", "project", "Move a folder to another location", "sourcePath", "destPath");
        add(m, "/open_project", "POST", "headless", "Open an existing Ghidra project (.gpr file or directory). GUI mode adds optional `headless` (default true) to suppress auto-launching CodeBrowser, and optional `program` to auto-launch CodeBrowser for a specific file when headless=false. Headless server ignores the extra params.", "path", "headless", "program");
        add(m, "/project/info", "GET", "project", "Get detailed project info including running tools and open programs");
        add(m, "/server/admin/set_permissions", "POST", "server", "Set user permissions on a repository", "repo", "user", "accessLevel");
        add(m, "/server/admin/terminate_all_checkouts", "POST", "server", "Terminate all checkouts in a folder recursively", "repo", "path");
        add(m, "/server/admin/terminate_checkout", "POST", "server", "Terminate all checkouts on a single file", "repo", "path", "checkoutId", "checkout_id");
        add(m, "/server/admin/users", "GET", "server", "List all users on the server");
        add(m, "/server/authenticate", "POST", "server", "Register server credentials for programmatic authentication", "username", "password");
        add(m, "/server/checkouts", "GET", "server", "List all checked-out files in a folder, including server-side checkouts", "path");
        add(m, "/server/connect", "POST", "server", "Connect to a Ghidra server", "host", "port");
        add(m, "/server/disconnect", "POST", "server", "Disconnect from the Ghidra server");
        add(m, "/server/repositories", "GET", "server", "List repositories on the connected server");
        add(m, "/server/repository/create", "POST", "server", "Create a new repository on the server", "name");
        add(m, "/server/repository/file", "GET", "server", "Get file info from a server repository", "repo", "path");
        add(m, "/server/repository/files", "GET", "server", "List files in a server repository folder", "repo", "path");
        add(m, "/server/status", "GET", "headless", "Check headless server connection status");
        add(m, "/server/version_control/add", "POST", "server", "Add a file to version control", "repo", "path", "comment", "keepCheckedOut");
        add(m, "/server/version_control/checkin", "POST", "server", "Check in a version-controlled file", "repo", "path", "comment", "keepCheckedOut");
        add(m, "/server/version_control/checkout", "POST", "server", "Check out a version-controlled file", "repo", "path");
        add(m, "/server/version_control/undo_checkout", "POST", "server", "Undo a file checkout", "repo", "path");
        add(m, "/server/version_history", "GET", "server", "Get version history for a file", "repo", "path");
        add(m, "/tool/goto_address", "POST", "utility", "Navigate CodeBrowser listing and decompiler to a specific address", "address");
        add(m, "/tool/launch_codebrowser", "POST", "utility", "Open a file in CodeBrowser, launching a new one if needed", "path");
        add(m, "/tool/running_tools", "GET", "utility", "List all running Ghidra tool windows");
        return m;
    }

    /**
     * Add the descriptor for each requested path to {@code scanner}'s schema output.
     * Fails loudly (not silently) if a path has no registered descriptor -- that means
     * either this registry drifted from a server's actual createContext/safeContext
     * calls, or a new manual route was added without a matching entry here.
     *
     * @throws IllegalStateException if any path is not present in {@link #ALL}
     */
    public static void addAll(AnnotationScanner scanner, String... paths) {
        for (String path : paths) {
            AnnotationScanner.ToolDescriptor td = ALL.get(path);
            if (td == null) {
                throw new IllegalStateException("No ManualToolDescriptors entry for \"" + path
                    + "\" -- add one to ManualToolDescriptors.buildAll(), or remove the"
                    + " createContext/safeContext call if the route no longer exists.");
            }
            scanner.addManualDescriptor(td);
        }
    }

    /** Every path this registry knows a descriptor for (for parity tests). */
    public static java.util.Set<String> knownPaths() {
        return java.util.Collections.unmodifiableSet(ALL.keySet());
    }
}
