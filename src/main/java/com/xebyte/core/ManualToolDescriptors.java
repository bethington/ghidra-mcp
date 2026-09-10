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
 * that file is the existing source of truth for these routes' metadata). The
 * param NAMES come from there and their source is inferred from the route's HTTP
 * method (GET -&gt; query, POST -&gt; body); the catalog does not track per-param
 * type/required detail for hand-registered routes, and every one of these handlers
 * already parses its own params permissively, so marking them optional-string is
 * accurate enough for tool discovery without overclaiming precision the source
 * data doesn't have.
 *
 * <p>The param DESCRIPTIONS, by contrast, are written here against what the
 * handlers actually do, because there is nowhere else for them to come from: an
 * {@code @McpTool} method gets them from {@code @Param(description = ...)}, and a
 * hand-registered route has no annotation at all. Several of these parameters are
 * mode-dependent (the GUI plugin drives the already-open project and ignores the
 * repository selector; the headless server holds a real server connection and
 * reads it) or accepted and never read, and the descriptions say which.
 *
 * <p>{@code ManualToolDescriptorsParityTest} enforces that every path a server
 * registers manually has an entry here, so a future added route can't silently
 * repeat this gap.
 */
public final class ManualToolDescriptors {

    private ManualToolDescriptors() {}

    private static AnnotationScanner.ParamDescriptor p(String name, String source, String description) {
        return new AnnotationScanner.ParamDescriptor(name, "string", source, true, null, description, "", false);
    }

    /**
     * Build a descriptor list from alternating name/description pairs.
     *
     * <p>Pairs, not bare names, on purpose: a hand-registered route's parameters
     * reach {@code /mcp/schema} through here and nowhere else, so a parameter
     * added without a description lands in every client's {@code inputSchema}
     * with nothing to say. The odd-count guard makes forgetting one a build-time
     * failure rather than a silent blank.
     *
     * @throws IllegalArgumentException if the varargs are not name/description pairs
     */
    private static List<AnnotationScanner.ParamDescriptor> params(String method, String... nameThenDescription) {
        if (nameThenDescription.length % 2 != 0) {
            throw new IllegalArgumentException("ManualToolDescriptors.params() takes alternating"
                + " name/description pairs; got an odd argument count ("
                + nameThenDescription.length + "). Every hand-registered parameter needs a description.");
        }
        String source = "GET".equalsIgnoreCase(method) ? "query" : "body";
        List<AnnotationScanner.ParamDescriptor> out = new java.util.ArrayList<>();
        for (int i = 0; i < nameThenDescription.length; i += 2) {
            out.add(p(nameThenDescription[i], source, nameThenDescription[i + 1]));
        }
        return out;
    }

    private static void add(Map<String, AnnotationScanner.ToolDescriptor> m,
            String path, String method, String category, String description, String... paramPairs) {
        m.put(path, new AnnotationScanner.ToolDescriptor(
            path, method, description, category, "", params(method, paramPairs)));
    }

    /** Keyed by path. Built once; entries never mutate after class init. */
    private static final Map<String, AnnotationScanner.ToolDescriptor> ALL = buildAll();

    // Reused wording. GUI mode drives the already-open project and ignores the
    // repository selector entirely; only the headless server, which holds a
    // direct Ghidra Server connection, reads it.
    private static final String REPO_HEADLESS_ONLY =
            "Repository name on the Ghidra Server. Read only by the headless server —"
            + " the GUI plugin works on the already-open project and ignores it.";

    private static Map<String, AnnotationScanner.ToolDescriptor> buildAll() {
        Map<String, AnnotationScanner.ToolDescriptor> m = new LinkedHashMap<>();
        add(m, "/batch_apply_documentation", "POST", "analysis",
            "Apply all documentation to a function in one call",
            "address", "Function entry address, as 0x<hex> or <space>:<hex>. Required: every step below is applied to the function at this address.",
            "name", "New function name. Omit or leave empty to skip the rename step.",
            "prototype", "Full C signature. Applied BEFORE the comment step on purpose, because setting a prototype wipes the plate comment.",
            "calling_convention", "Convention for the prototype step, e.g. __stdcall. Read only when prototype is also given.",
            "variable_types", "Object mapping variable name to new type. Each is applied on its own; the step reports set/failed counts plus per-variable errors.",
            "variable_renames", "Object mapping each variable's CURRENT name to its new name.",
            "plate_comment", "Plate comment for the function. Pass real multi-line text: an escaped newline sequence is stored as those two literal characters, not as a line break.",
            "decompiler_comments", "Array of {address, comment} objects setting PRE comments. Each entry carries its own address; the top-level address is the function entry only.",
            "disassembly_comments", "Array of {address, comment} objects setting EOL comments. Each entry carries its own address.",
            "goto", "True navigates the CodeBrowser to address before anything else. Must be a JSON boolean: any other type is read as FALSE. Default false.",
            "score", "True (the default) appends a compact completeness score. Must be a JSON boolean: any other type falls back to the default and is read as TRUE, so the string false does not switch it off.",
            "program", "Accepted but not read by this route: every step runs against the active program. Use the individual tools when you need to target a specific one.");
        add(m, "/check_connection", "GET", "utility", "Health check endpoint");
        add(m, "/configure_analyzer", "POST", "analysis", "Configure an analysis plugin",
            "name", "Analyzer name exactly as Ghidra registers it, e.g. Decompiler Parameter ID.",
            "enabled", "True enables the analyzer, false disables it. Omitting the key entirely leaves the current setting alone.",
            "program", "Target program name (omit to use the active program). Headless mode only.");
        add(m, "/delete_project", "POST", "project", "Delete a Ghidra project",
            "projectPath", "Filesystem path of the project to delete: its .gpr file or the project directory. Headless mode only; the GUI plugin does not register this route.");
        add(m, "/exit_ghidra", "POST", "program", "Save and exit Ghidra");
        add(m, "/get_current_address", "GET", "getter", "Get cursor address (GUI only)");
        add(m, "/get_current_function", "GET", "getter", "Get function at cursor (GUI only)");
        add(m, "/get_current_selection", "GET", "getter", "Get highlighted address ranges in the CodeBrowser listing (GUI only). Returns {program, is_empty, ranges:[{start,end,length}], min_address, max_address, num_addresses} or an empty-selection payload when nothing is highlighted.");
        add(m, "/get_version", "GET", "utility", "Get plugin version");
        add(m, "/health", "GET", "utility", "Health check endpoint for headless server");
        add(m, "/list_projects", "GET", "project", "List available Ghidra projects",
            "searchDir", "Directory to scan for .gpr projects. Headless mode only; the GUI plugin does not register this route.");
        add(m, "/mcp/health", "GET", "utility", "HTTP server health: pool stats, uptime, memory, active request count");
        add(m, "/mcp/schema", "GET", "utility", "Machine-readable API schema with endpoint metadata");
        // /move_file and /move_folder used to live here: manually routed in the
        // headless server, absent from the GUI/FrontEnd server entirely, and so
        // present in tests/endpoints.json but missing from the live /mcp/schema
        // that the bridge discovers from. They are now @McpTool methods on
        // ProgramScriptService.{moveFile,moveFolder}, which registers them in
        // every mode. Do not re-add them here -- double registration throws
        // "cannot add context to list" on headless startup (see #180).
        add(m, "/open_project", "POST", "headless", "Open an existing Ghidra project (.gpr file or directory). GUI mode adds optional `headless` (default true) to suppress auto-launching CodeBrowser, and optional `program` to auto-launch CodeBrowser for a specific file when headless=false. Headless server ignores the extra params.",
            "path", "Path to the project: its .gpr file or the project directory holding it.",
            "headless", "GUI mode only. True (the default) loads the project into the FrontEnd tool without opening a CodeBrowser window; false launches one for `program`. The headless server ignores it.",
            "program", "GUI mode only, and only when headless=false: the DomainFile path to open in the launched CodeBrowser.");
        add(m, "/project/info", "GET", "project", "Get detailed project info including running tools and open programs");
        add(m, "/server/admin/set_permissions", "POST", "server", "Set user permissions on a repository",
            "repo", REPO_HEADLESS_ONLY + " The GUI plugin answers that this operation needs headless mode.",
            "user", "Server user whose access is being set. The repository ACL is read, this one entry replaced or appended, and every other user preserved.",
            "accessLevel", "Numeric Ghidra access level: 0 no access, 1 read only, 2 read/write, 3 admin. Defaults to 1.");
        add(m, "/server/admin/terminate_all_checkouts", "POST", "server", "Terminate all checkouts in a folder recursively",
            "repo", REPO_HEADLESS_ONLY,
            "path", "Folder to walk recursively, terminating every checkout under it. Defaults to / — the whole repository or project.");
        add(m, "/server/admin/terminate_checkout", "POST", "server", "Terminate all checkouts on a single file",
            "repo", REPO_HEADLESS_ONLY,
            "path", "Path of the file whose checkout is being terminated.",
            "checkoutId", "Numeric checkout id to terminate, as /server/checkouts reports it. Headless mode only, and defaults to 0 when absent; the GUI plugin terminates by path alone.",
            "checkout_id", "Alternative spelling of checkoutId, read only when checkoutId is absent.");
        add(m, "/server/admin/users", "GET", "server", "List all users on the server");
        add(m, "/server/authenticate", "POST", "server", "Register server credentials for programmatic authentication",
            "username", "Server username. Omit to fall back to Ghidra's stored PasswordPrompt.Name, then to the OS user name.",
            "password", "Server password. Required — the call is refused without it.");
        add(m, "/server/checkouts", "GET", "server", "List all checked-out files in a folder, including server-side checkouts",
            "path", "Folder to list checkouts under. Defaults to / — everything.");
        add(m, "/server/connect", "POST", "server", "Connect to a Ghidra server",
            "host", "Accepted but not read: the headless server connects using its configured host (GHIDRA_SERVER_* environment), and the GUI plugin uses the already-open project.",
            "port", "Accepted but not read, for the same reason as host.");
        add(m, "/server/disconnect", "POST", "server", "Disconnect from the Ghidra server");
        add(m, "/server/repositories", "GET", "server", "List repositories on the connected server");
        add(m, "/server/repository/create", "POST", "server", "Create a new repository on the server",
            "name", "Name for the new repository. Headless mode only; the GUI plugin refuses and points at Ghidra's Project Manager.");
        add(m, "/server/repository/file", "GET", "server", "Get file info from a server repository",
            "repo", REPO_HEADLESS_ONLY,
            "path", "Path of the file to describe. Required.");
        add(m, "/server/repository/files", "GET", "server", "List files in a server repository folder",
            "repo", REPO_HEADLESS_ONLY,
            "path", "Folder to list. Defaults to / — the repository or project root.");
        add(m, "/server/status", "GET", "headless", "Check headless server connection status");
        add(m, "/server/version_control/add", "POST", "server", "Add a file to version control",
            "repo", REPO_HEADLESS_ONLY,
            "path", "Path of the not-yet-versioned file to add.",
            "comment", "Check-in comment recorded for the initial version. Defaults to a generic Added via GhidraMCP.",
            "keepCheckedOut", "Accepted but not read on this route — neither handler passes it through. Use /server/version_control/checkin, where it does apply.");
        add(m, "/server/version_control/checkin", "POST", "server", "Check in a version-controlled file",
            "repo", REPO_HEADLESS_ONLY,
            "path", "Path of the checked-out file to check in.",
            "comment", "Check-in comment recorded on the new version. Defaults to a generic Checked in via GhidraMCP.",
            "keepCheckedOut", "True keeps the file checked out after the version lands, so you can keep editing. False (the default) releases the checkout.");
        add(m, "/server/version_control/checkout", "POST", "server", "Check out a version-controlled file",
            "repo", REPO_HEADLESS_ONLY,
            "path", "Path of the versioned file to check out.");
        add(m, "/server/version_control/undo_checkout", "POST", "server", "Undo a file checkout",
            "repo", REPO_HEADLESS_ONLY,
            "path", "Path of the checked-out file to release. Any local changes not checked in are discarded.");
        add(m, "/server/version_history", "GET", "server", "Get version history for a file",
            "repo", REPO_HEADLESS_ONLY,
            "path", "Path of the versioned file whose history to return.");
        add(m, "/tool/goto_address", "POST", "utility", "Navigate CodeBrowser listing and decompiler to a specific address",
            "address", "Address to navigate to, as 0x<hex> or <space>:<hex>. GUI mode only — it moves a CodeBrowser window.");
        add(m, "/tool/launch_codebrowser", "POST", "utility", "Open a file in CodeBrowser, launching a new one if needed",
            "path", "DomainFile path of the program to open, e.g. /Vanilla/1.13c/D2Common.dll. GUI mode only.");
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
