package com.xebyte.headless;

import com.xebyte.core.*;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import java.io.File;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Program and project management endpoints for headless mode.
 * Only passed to AnnotationScanner in GhidraMCPHeadlessServer,
 * so this category is absent from the GUI plugin schema.
 */
@McpToolGroup(value = "headless", description = "Headless server program management (no GUI required)")
public class HeadlessManagementService {

    private final HeadlessProgramProvider programProvider;
    private final GhidraServerManager serverManager;

    public HeadlessManagementService(HeadlessProgramProvider programProvider,
                                     GhidraServerManager serverManager) {
        this.programProvider = programProvider;
        this.serverManager = serverManager;
    }

    // ========================================================================
    // Filesystem containment
    // ========================================================================

    /**
     * Resolve a caller-supplied filesystem path against {@code GHIDRA_MCP_FILE_ROOT},
     * matching the containment /import_file applies. Returns the
     * canonical {@link File} when allowed, or {@code null} (after a server-side
     * log that keeps the configured root out of the client response) when a root
     * is configured and the path escapes it. With no root set the path is
     * returned canonicalized — pre-v5.4.1 behavior, so general users are
     * unaffected.
     */
    private File resolveWithinRootOrLog(String userPath, String endpoint) {
        SecurityConfig security = SecurityConfig.getInstance();
        Path resolved = security.resolveWithinFileRoot(userPath);
        if (resolved == null) {
            Msg.warn(this, "Rejected " + endpoint + " for '" + userPath
                + "': outside configured GHIDRA_MCP_FILE_ROOT (" + security.getFileRoot() + ")");
            return null;
        }
        return resolved.toFile();
    }

    private static final String FILE_ROOT_DENY =
        "Access denied: path is outside the configured file root";

    // ========================================================================
    // Project management
    // ========================================================================

    @McpTool(path = "/create_project", dryRun = false, method = "POST", description = "Create a new Ghidra project", category = "headless", access = ToolAccess.WRITE)
    public Response createProject(
            @Param(value = "parentDir", source = ParamSource.BODY,
                   description = "Existing filesystem directory that will CONTAIN the new project, e.g. "
                               + "C:/ghidra_projects. It must resolve inside the server's configured file "
                               + "root or the call is denied.") String parentDir,
            @Param(value = "name", source = ParamSource.BODY,
                   description = "Project name. The project is created at parentDir/name and the response "
                               + "echoes that path.") String name) {
        if (parentDir == null || parentDir.isEmpty()) return Response.err("parentDir required");
        if (name == null || name.isEmpty()) return Response.err("name required");
        File parent = resolveWithinRootOrLog(parentDir, "/create_project");
        if (parent == null) return Response.err(FILE_ROOT_DENY);
        parentDir = parent.getPath();
        try {
            boolean ok = programProvider.createProject(parentDir, name);
            if (ok) {
                return Response.ok(JsonHelper.mapOf(
                    "success", true,
                    "name", name,
                    "path", parentDir + "/" + name));
            }
            return Response.err("Failed to create project");
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    // Both below were hand-coded routes on the server until 7.0, outside the file-root
    // allow-list every filesystem-touching sibling here applies -- including a
    // recursive project DELETE. They take the same check now.

    @McpTool(path = "/list_projects", description = "Find Ghidra projects (.gpr) in a directory", category = "project", access = ToolAccess.READ_ONLY)
    public Response listProjects(
            @Param(value = "searchDir", defaultValue = "",
                   description = "Directory to search for .gpr files. Omit for the server user's home "
                               + "directory. Must resolve inside the configured file root.") String searchDir) {
        String dir = searchDir == null || searchDir.isEmpty()
            ? System.getProperty("user.home") : searchDir;
        File resolved = resolveWithinRootOrLog(dir, "/list_projects");
        if (resolved == null) return Response.err(FILE_ROOT_DENY);
        try {
            List<Map<String, Object>> projects = new java.util.ArrayList<>();
            for (HeadlessProgramProvider.ProjectInfo p : programProvider.listProjects(resolved.getPath())) {
                projects.add(JsonHelper.mapOf("name", p.name, "path", p.path, "active", p.active));
            }
            return Response.ok(JsonHelper.mapOf("projects", projects, "count", projects.size()));
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    @McpTool(path = "/delete_project", dryRun = false, method = "POST", description = "Delete a Ghidra project from disk", category = "project", access = ToolAccess.DESTRUCTIVE)
    public Response deleteProject(
            @Param(value = "projectPath", source = ParamSource.BODY,
                   description = "The project's .gpr file or its directory. Must resolve inside the "
                               + "configured file root.") String projectPath) {
        if (projectPath == null || projectPath.isEmpty()) return Response.err("projectPath required");
        File resolved = resolveWithinRootOrLog(projectPath, "/delete_project");
        if (resolved == null) return Response.err(FILE_ROOT_DENY);
        try {
            if (programProvider.deleteProject(resolved.getPath())) {
                return Response.ok(JsonHelper.mapOf("success", true, "deleted", resolved.getPath()));
            }
            return Response.err("Failed to delete project");
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    @McpTool(path = "/open_project", dryRun = false, method = "POST",
            description = "Open a Ghidra project: a local .gpr/directory, or a shared "
                + "Ghidra Server repository via ghidra://host[:port]/repo (creates a "
                + "persistent local shared project under ~/.ghidra-mcp/shared-projects/ "
                + "keyed by host_port_repo, overridable with GHIDRA_MCP_SHARED_PROJECT_DIR). "
                + "Does not auto-open repository files — max ~5 shared-server programs open "
                + "at once; opening 20+ crashes Ghidra. Requires /server/connect first for "
                + "URL opens. The local tree mirrors YOUR working copy (not other users' "
                + "checkins until you refresh).",
            category = "headless", access = ToolAccess.WRITE)
    public Response openProject(
            @Param(value = "path", source = ParamSource.BODY,
                   description = "Path to an existing project: either its .gpr file, the "
                               + "project directory holding it, or a ghidra://host[:port]/repo "
                               + "URL for a shared Ghidra Server repository.") String projectPath) {
        if (projectPath == null || projectPath.isEmpty()) {
            return Response.err("Project path required");
        }
        // A local path is a filesystem path, so it stays under GHIDRA_MCP_FILE_ROOT like the
        // other filesystem endpoints; a ghidra:// URL names a server repository instead.
        if (!projectPath.startsWith("ghidra://")) {
            File local = resolveWithinRootOrLog(projectPath, "/open_project");
            if (local == null) {
                return Response.err(FILE_ROOT_DENY);
            }
            projectPath = local.getPath();
        }
        HeadlessProgramProvider.OpenProjectResult result =
            programProvider.openProject(projectPath, serverManager);
        if (result.success) {
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("success", true);
            body.put("project", result.projectName);
            body.put("shared", result.shared);
            if (result.repository != null) {
                body.put("repository", result.repository);
            }
            if (result.localProjectDir != null) {
                body.put("local_project_dir", result.localProjectDir);
            }
            return Response.ok(body);
        }
        return Response.err(result.error != null ? result.error
                : ("Failed to open project: " + projectPath));
    }

    @McpTool(path = "/close_project", dryRun = false, method = "POST", description = "Close the currently open project", category = "headless", access = ToolAccess.DESTRUCTIVE)
    public Response closeProject() {
        if (!programProvider.hasProject()) {
            return Response.err("No project currently open");
        }
        String projectName = programProvider.getProjectName();
        programProvider.closeProject();
        return Response.ok(JsonHelper.mapOf("success", true, "closed", projectName));
    }

    // ========================================================================
    // Server status
    // ========================================================================

}
