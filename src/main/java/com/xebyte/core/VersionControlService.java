package com.xebyte.core;

import ghidra.framework.client.RepositoryAdapter;
import ghidra.framework.client.RepositoryServerAdapter;
import ghidra.framework.remote.RepositoryItem;
import ghidra.framework.remote.User;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Version control and server administration, served identically by the GUI and headless.
 *
 * <p>These were 17 hand-coded routes implemented twice. The routes that act on the open
 * project's files delegate to {@link ProjectVersionControl}; the server-level ones
 * (repositories, browsing, users) work through a {@link ServerSession}, which is the only
 * thing that differs between the two servers.
 *
 * <p>Parameters and responses are snake_case. The routes this replaces disagreed:
 * {@code keepCheckedOut} on the GUI and headless alike, {@code checkoutId} with a
 * {@code checkout_id} fallback, {@code accessLevel}.
 */
public class VersionControlService {

    private static final String NOT_CONNECTED = "Not connected to server. Use /server/connect first.";

    private final ProjectVersionControl files;
    private final ServerSession session;
    private final Map<String, RepositoryAdapter> repositories = new ConcurrentHashMap<>();

    public VersionControlService(ProgramProvider provider, ServerSession session) {
        this.files = new ProjectVersionControl(provider);
        this.session = session;
    }

    // ================================================================== project files

    @McpTool(path = "/checkin_program", dryRun = false, method = "POST",
            description = "Check a program in to the shared Ghidra Server as a new version. Saves pending "
                + "edits and closes the program first (a file checked in while open must stay checked "
                + "out). Requires a shared project and the file checked out. Returns "
                + "version_before/version/version_bumped. dry_run=true checks everything and reports "
                + "what would happen (programs it would save, whether it would close one) without "
                + "doing any of it.",
            category = "server", access = ToolAccess.WRITE)
    public Response checkinProgram(
            @Param(value = "path", source = ParamSource.BODY, defaultValue = "",
                   description = "Project path of the file; empty uses the sole open program") String path,
            @Param(value = "comment", source = ParamSource.BODY, defaultValue = "",
                   description = "Check-in comment recorded on the new version") String comment,
            @Param(value = "keep_checked_out", source = ParamSource.BODY, defaultValue = "false",
                   description = "Keep the file checked out after the new version lands, so you can keep "
                               + "editing. False (the default) releases the checkout.") boolean keepCheckedOut,
            @Param(value = "dry_run", source = ParamSource.BODY, defaultValue = "false",
                   description = "Report what the check-in would do without saving, closing or "
                               + "checking in anything.") boolean dryRun) {
        return files.checkin(path, comment, keepCheckedOut, dryRun);
    }

    @McpTool(path = "/server/version_control/checkout", dryRun = false, method = "POST",
            description = "Check out a file of the open shared project into a local working copy. Does not "
                + "open the program. Requires /open_project on a shared project.",
            category = "server", access = ToolAccess.WRITE)
    public Response checkout(
            @Param(value = "path", source = ParamSource.BODY,
                   description = "Path of the versioned file to check out") String path,
            @Param(value = "exclusive", source = ParamSource.BODY, defaultValue = "true",
                   description = "Take an exclusive checkout (the default). False allows others to check "
                               + "the file out concurrently.") boolean exclusive) {
        return files.checkout(path, exclusive);
    }

    @McpTool(path = "/server/version_control/undo_checkout", dryRun = false, method = "POST",
            description = "Undo a checkout in the open shared project, discarding local changes that were "
                + "not checked in. Close the program first: an open file cannot be released.",
            category = "server", access = ToolAccess.DESTRUCTIVE)
    public Response undoCheckout(
            @Param(value = "path", source = ParamSource.BODY,
                   description = "Path of the checked-out file to release. Any local changes not checked "
                               + "in are discarded.") String path,
            @Param(value = "keep", source = ParamSource.BODY, defaultValue = "false",
                   description = "Keep the local copy as a private file instead of discarding it") boolean keep) {
        return files.undoCheckout(path, keep);
    }

    @McpTool(path = "/server/version_control/add", dryRun = false, method = "POST",
            description = "Add a file of the open shared project to version control.",
            category = "server", access = ToolAccess.WRITE)
    public Response addToVersionControl(
            @Param(value = "path", source = ParamSource.BODY,
                   description = "Path of the not-yet-versioned file to add") String path,
            @Param(value = "comment", source = ParamSource.BODY, defaultValue = "",
                   description = "Comment recorded for the initial version. Defaults to \"Added via "
                               + "GhidraMCP\".") String comment,
            @Param(value = "keep_checked_out", source = ParamSource.BODY, defaultValue = "false",
                   description = "Keep the file checked out afterwards, so local edits can continue without "
                               + "a second checkout") boolean keepCheckedOut) {
        return files.addToVersionControl(path, comment, keepCheckedOut);
    }

    @McpTool(path = "/server/version_history",
            description = "Version history of a versioned file: version, user, comment and time of each.",
            category = "server", access = ToolAccess.READ_ONLY)
    public Response versionHistory(
            @Param(value = "path", description = "Path of the versioned file whose history to return") String path) {
        return files.versionHistory(path);
    }

    @McpTool(path = "/server/checkouts",
            description = "What is checked out under a file or folder of the open project, locally or on the "
                + "server (with the holders' users and checkout ids). modified_since_checkout says whether a "
                + "checkout holds uncommitted work, which is what decides if it is safe to release.",
            category = "server", access = ToolAccess.READ_ONLY)
    public Response checkouts(
            @Param(value = "path", defaultValue = "/",
                   description = "File or folder to report under. Defaults to / (everything).") String path) {
        return files.checkouts(path);
    }

    @McpTool(path = "/server/admin/terminate_checkout", dryRun = false, method = "POST",
            description = "Force-release the checkouts of a single file. Without checkout_id: this project's "
                + "own checkout first, then every server checkout of the file.",
            category = "server", access = ToolAccess.DESTRUCTIVE)
    public Response terminateCheckout(
            @Param(value = "path", source = ParamSource.BODY,
                   description = "Path of the file whose checkout is being terminated") String path,
            @Param(value = "checkout_id", source = ParamSource.BODY, defaultValue = "",
                   description = "Terminate only this checkout, as /server/checkouts reports it. Empty "
                               + "terminates every checkout of the file.") String checkoutId) {
        Long id = null;
        if (checkoutId != null && !checkoutId.isBlank()) {
            try {
                id = Long.parseLong(checkoutId.trim());
            } catch (NumberFormatException e) {
                return Response.err("checkout_id must be a number: " + checkoutId);
            }
        }
        return files.terminateCheckout(path, id);
    }

    @McpTool(path = "/server/admin/terminate_all_checkouts", dryRun = false, method = "POST",
            description = "Force-release every server checkout under a folder, recursively, and report how "
                + "many landed.",
            category = "server", access = ToolAccess.DESTRUCTIVE)
    public Response terminateAllCheckouts(
            @Param(value = "path", source = ParamSource.BODY, defaultValue = "/",
                   description = "Folder to walk recursively. Defaults to / (the whole project).") String path) {
        return files.terminateAllCheckouts(path);
    }

    // ================================================================ server connection

    @McpTool(path = "/server/connect", dryRun = false, method = "POST",
            description = "Establish the Ghidra Server connection, or report the existing one. Takes no "
                + "parameters: the GUI's connection is its open project, and headless connects with "
                + "GHIDRA_SERVER_HOST, GHIDRA_SERVER_PORT, GHIDRA_SERVER_USER and GHIDRA_SERVER_PASSWORD.",
            category = "server", access = ToolAccess.WRITE)
    public Response connect() {
        repositories.clear();
        return session.connect();
    }

    @McpTool(path = "/server/disconnect", dryRun = false, method = "POST",
            description = "Disconnect from the Ghidra Server.",
            category = "server", access = ToolAccess.WRITE)
    public Response disconnect() {
        repositories.clear();
        return session.disconnect();
    }

    @McpTool(path = "/server/authenticate", dryRun = false, method = "POST",
            description = "Register Ghidra Server credentials for this process, replacing any from the "
                + "environment. They are used for every server connection from now on, including "
                + "opening a shared project and /server/connect.",
            category = "server", access = ToolAccess.WRITE)
    public Response authenticate(
            @Param(value = "username", source = ParamSource.BODY, defaultValue = "",
                   description = "Server username. Omit to fall back to Ghidra's stored "
                               + "PasswordPrompt.Name, then to the OS user name.") String username,
            @Param(value = "password", source = ParamSource.BODY, defaultValue = "",
                   description = "Server password. Required: the call is refused without it.") String password) {
        if (password == null || password.isEmpty()) {
            return Response.err("Password is required");
        }
        String user = username;
        if (user == null || user.isEmpty()) {
            user = ghidra.framework.preferences.Preferences.getProperty("PasswordPrompt.Name");
        }
        if (user == null || user.isEmpty()) {
            user = System.getProperty("user.name");
        }
        try {
            session.useCredentials(user, password.toCharArray());
            repositories.clear();
            return Response.ok(Map.of("success", true, "message", "Server credentials registered",
                "username", user));
        } catch (Exception e) {
            return Response.err("Failed to register authenticator: " + messageOf(e));
        }
    }

    @McpTool(path = "/server/status",
            description = "Whether a Ghidra Server is connected (not whether a project is open: see "
                + "/get_project_info).",
            category = "server", access = ToolAccess.READ_ONLY)
    public Response status() {
        return Response.ok(session.status());
    }

    // ============================================================ server repositories

    /** The connected server, or the error to answer with. */
    private RepositoryServerAdapter connected() {
        return session.server();
    }

    private RepositoryAdapter repository(RepositoryServerAdapter server, String name) throws Exception {
        RepositoryAdapter repo = repositories.get(name);
        if (repo == null || !repo.isConnected() || repo.getServer() != server) {
            repo = server.getRepository(name);
            if (repo != null) {
                repo.connect();
                repositories.put(name, repo);
            }
        }
        return repo;
    }

    private static String messageOf(Exception e) {
        return e.getMessage() != null ? e.getMessage() : e.toString();
    }

    private static String parentOf(String path) {
        int slash = path.lastIndexOf('/');
        return slash > 0 ? path.substring(0, slash) : "/";
    }

    @McpTool(path = "/server/repositories",
            description = "List the repositories on the connected Ghidra Server.",
            category = "server", access = ToolAccess.READ_ONLY)
    public Response repositories() {
        RepositoryServerAdapter server = connected();
        if (server == null) return Response.err(NOT_CONNECTED);
        try {
            String[] names = server.getRepositoryNames();
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("repositories", List.of(names));
            out.put("count", names.length);
            return Response.ok(out);
        } catch (Exception e) {
            return Response.err("Failed to list repositories: " + messageOf(e));
        }
    }

    @McpTool(path = "/server/repository/files",
            description = "List the files and folders of a server repository folder. This is the server's "
                + "own tree; the open project's tree is /list_project_files.",
            category = "server", access = ToolAccess.READ_ONLY)
    public Response repositoryFiles(
            @Param(value = "repo", description = "Repository name, as /server/repositories lists them") String repo,
            @Param(value = "path", defaultValue = "/",
                   description = "Folder to list. Defaults to / (the repository root).") String path) {
        RepositoryServerAdapter server = connected();
        if (server == null) return Response.err(NOT_CONNECTED);
        if (repo == null || repo.isBlank()) return Response.err("repo is required");
        String at = path == null || path.isBlank() ? "/" : path;
        try {
            RepositoryAdapter adapter = repository(server, repo);
            if (adapter == null) return Response.err("Repository not found: " + repo);
            String[] folders = adapter.getSubfolderList(at);
            RepositoryItem[] items = adapter.getItemList(at);
            List<Map<String, Object>> files = new ArrayList<>();
            if (items != null) {
                for (RepositoryItem item : items) {
                    files.add(itemRow(item));
                }
            }
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("repository", repo);
            out.put("path", at);
            out.put("folders", folders != null ? List.of(folders) : List.of());
            out.put("files", files);
            out.put("total_count", (folders != null ? folders.length : 0) + files.size());
            return Response.ok(out);
        } catch (Exception e) {
            return Response.err("Failed to list files: " + messageOf(e));
        }
    }

    @McpTool(path = "/server/repository/file",
            description = "Describe one file of a server repository: name, path, content type, version.",
            category = "server", access = ToolAccess.READ_ONLY)
    public Response repositoryFile(
            @Param(value = "repo", description = "Repository name, as /server/repositories lists them") String repo,
            @Param(value = "path", description = "Path of the file to describe") String path) {
        RepositoryServerAdapter server = connected();
        if (server == null) return Response.err(NOT_CONNECTED);
        if (repo == null || repo.isBlank() || path == null || path.isBlank()) {
            return Response.err("repo and path are required");
        }
        try {
            RepositoryAdapter adapter = repository(server, repo);
            if (adapter == null) return Response.err("Repository not found: " + repo);
            RepositoryItem item = adapter.getItem(parentOf(path), path.substring(path.lastIndexOf('/') + 1));
            if (item == null) return Response.err("File not found: " + path);
            return Response.ok(itemRow(item));
        } catch (Exception e) {
            return Response.err("Failed to get file info: " + messageOf(e));
        }
    }

    private static Map<String, Object> itemRow(RepositoryItem item) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("name", item.getName());
        row.put("path", item.getPathName());
        row.put("type", item.getContentType());
        row.put("version", item.getVersion());
        return row;
    }

    @McpTool(path = "/server/repository/create", dryRun = false, method = "POST",
            description = "Create a new repository on the connected Ghidra Server (needs admin access).",
            category = "server", access = ToolAccess.WRITE)
    public Response createRepository(
            @Param(value = "name", source = ParamSource.BODY,
                   description = "Name for the new repository") String name) {
        RepositoryServerAdapter server = connected();
        if (server == null) return Response.err(NOT_CONNECTED);
        if (name == null || name.isBlank()) return Response.err("name is required");
        try {
            RepositoryAdapter created = server.createRepository(name.trim());
            if (created == null) return Response.err("Failed to create repository: server returned null");
            created.connect();
            repositories.put(name.trim(), created);
            return Response.ok(Map.of("status", "created", "repository", name.trim()));
        } catch (Exception e) {
            return Response.err("Failed to create repository: " + messageOf(e));
        }
    }

    // ============================================================= server administration

    @McpTool(path = "/server/admin/users",
            description = "List all users registered on the server (needs admin access).",
            category = "server", access = ToolAccess.READ_ONLY)
    public Response users() {
        RepositoryServerAdapter server = connected();
        if (server == null) return Response.err(NOT_CONNECTED);
        try {
            String[] names = server.getAllUsers();
            List<Map<String, Object>> users = new ArrayList<>();
            if (names != null) {
                for (String name : names) {
                    users.add(Map.of("name", name));
                }
            }
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("users", users);
            out.put("count", users.size());
            return Response.ok(out);
        } catch (Exception e) {
            return Response.err("Failed to list users (admin access required): " + messageOf(e));
        }
    }

    @McpTool(path = "/server/admin/set_permissions", dryRun = false, method = "POST",
            description = "Set one user's access to a repository (needs admin access). The repository's ACL is "
                + "read, this one entry replaced or appended, and every other user preserved.",
            category = "server", access = ToolAccess.WRITE)
    public Response setPermissions(
            @Param(value = "repo", source = ParamSource.BODY,
                   description = "Repository name, as /server/repositories lists them") String repo,
            @Param(value = "user", source = ParamSource.BODY,
                   description = "Server user whose access is being set") String user,
            @Param(value = "access_level", source = ParamSource.BODY,
                   description = "The access to grant: read_only (0), write (1) or admin (2), by name or "
                               + "number. Required: there is no safe default for a permission.") String level) {
        RepositoryServerAdapter server = connected();
        if (server == null) return Response.err(NOT_CONNECTED);
        if (repo == null || repo.isBlank() || user == null || user.isBlank()) {
            return Response.err("repo and user are required");
        }
        Integer accessLevel = parseAccessLevel(level);
        if (accessLevel == null) {
            return Response.err("access_level must be read_only (0), write (1) or admin (2); got '" + level + "'");
        }
        try {
            RepositoryAdapter adapter = repository(server, repo);
            if (adapter == null) return Response.err("Repository not found: " + repo);
            // setUserList REPLACES the repository ACL wholesale: passing one entry would
            // silently strip every other user, admins included. Merge into the existing
            // list and keep the anonymous-access flag.
            User[] merged = mergeUserPermission(adapter.getUserList(), user, accessLevel);
            boolean anonymous = adapter.anonymousAccessAllowed();
            adapter.setUserList(merged, anonymous);
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("status", "permissions_set");
            out.put("repository", repo);
            out.put("user", user);
            out.put("access_level", accessLevel);
            out.put("total_users", merged.length);
            out.put("anonymous_access", anonymous);
            return Response.ok(out);
        } catch (Exception e) {
            return Response.err("Failed to set permissions (admin access required): " + messageOf(e));
        }
    }

    /**
     * A Ghidra repository access level from its name or number: {@code read_only}/0,
     * {@code write}/1, {@code admin}/2. Null when it is neither. (An earlier description
     * of this parameter listed a four-level 0-3 scale that does not exist and a default
     * that silently granted write access.)
     */
    public static Integer parseAccessLevel(String text) {
        if (text == null) {
            return null;
        }
        return switch (text.trim().toLowerCase().replace('-', '_')) {
            case "0", "read_only", "readonly", "read" -> User.READ_ONLY;
            case "1", "write" -> User.WRITE;
            case "2", "admin" -> User.ADMIN;
            default -> null;
        };
    }

    /** {@code existing} with {@code userName}'s entry replaced, or appended if absent. */
    public static User[] mergeUserPermission(User[] existing, String userName, int accessLevel) {
        User updated = new User(userName, accessLevel);
        if (existing == null || existing.length == 0) {
            return new User[] {updated};
        }
        for (int i = 0; i < existing.length; i++) {
            if (existing[i] != null && userName.equals(existing[i].getName())) {
                User[] out = existing.clone();
                out[i] = updated;
                return out;
            }
        }
        User[] out = new User[existing.length + 1];
        System.arraycopy(existing, 0, out, 0, existing.length);
        out[existing.length] = updated;
        return out;
    }
}
