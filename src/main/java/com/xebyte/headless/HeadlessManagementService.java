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
    // GZF export / import
    // ========================================================================

    @McpTool(path = "/export_program", dryRun = false, method = "POST",
            description = "Export a program to a GZF (Ghidra packed-database) file on disk. The resulting .gzf "
                + "can be imported into any Ghidra GUI (File \u2192 Import) or back into a project via "
                + "/import_program. Resolution order: (1) the in-memory program with that name (captures live "
                + "analyst edits); (2) a DomainFile in the open project (on-disk state). Output is written to "
                + "`output_dir/output_name` (defaults: /data/exports and `<program>.gzf`). Refuses to overwrite "
                + "an existing file.",
            category = "headless", access = ToolAccess.WRITE)
    public Response exportProgram(
            @Param(value = "program_name", source = ParamSource.BODY,
                description = "Program name or project path (e.g. 'myprog' or '/myprog').") String programName,
            @Param(value = "output_dir", source = ParamSource.BODY, defaultValue = "/data/exports",
                description = "Directory the .gzf will be written to. Must already exist.") String outputDir,
            @Param(value = "output_name", source = ParamSource.BODY, defaultValue = "",
                description = "Output file name. Defaults to `<program>.gzf`. `.gzf` is appended if missing.") String outputName) {
        if (programName == null || programName.isEmpty()) {
            return Response.err("program_name required");
        }
        String dirPath = (outputDir == null || outputDir.isEmpty()) ? "/data/exports" : outputDir;
        File dir = resolveWithinRootOrLog(dirPath, "/export_program");
        if (dir == null) return Response.err(FILE_ROOT_DENY);
        if (!dir.isDirectory()) {
            return Response.err("output_dir not a directory: " + dir.getAbsolutePath());
        }
        String name;
        if (outputName == null || outputName.isEmpty()) {
            name = HeadlessPaths.safeBasename(programName) + ".gzf";
        } else {
            String invalid = HeadlessPaths.validateFilename(outputName);
            if (invalid != null) {
                return Response.err("invalid output_name: " + invalid);
            }
            name = outputName;
        }
        if (!name.toLowerCase().endsWith(".gzf")) {
            name = name + ".gzf";
        }
        File out = new File(dir, name);
        if (!HeadlessPaths.isWithin(dir, out)) {
            return Response.err("output_name escapes output_dir: " + name);
        }

        HeadlessProgramProvider.ExportResult res = programProvider.exportProgramToGzf(programName, out);
        if (!res.success) {
            return Response.err(res.error);
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("success", true);
        body.put("program", res.programName);
        body.put("path", res.outputPath);
        body.put("size_bytes", res.sizeBytes);
        body.put("content_type", "GZF");
        return Response.ok(body);
    }

    @McpTool(path = "/import_program", dryRun = false, method = "POST",
            description = "Import a GZF (Ghidra packed-database) file into the open project. The GZF must already "
                + "exist on disk at `gzf_path` (typically staged on a shared volume by the orchestrator). Lands at "
                + "`target_folder/target_name` (defaults: `/` and the GZF basename sans `.gzf`). Set `overwrite=true` "
                + "to replace an existing program at the destination; otherwise the call fails on collision.",
            category = "headless", access = ToolAccess.WRITE)
    public Response importProgram(
            @Param(value = "gzf_path", source = ParamSource.BODY,
                description = "Absolute path to the .gzf file on disk.") String gzfPath,
            @Param(value = "target_folder", source = ParamSource.BODY, defaultValue = "/",
                description = "Destination folder in the project. Intermediate folders are created.") String targetFolder,
            @Param(value = "target_name", source = ParamSource.BODY, defaultValue = "",
                description = "Destination file name in the project. Defaults to the GZF basename sans `.gzf`.") String targetName,
            @Param(value = "overwrite", source = ParamSource.BODY, defaultValue = "false",
                description = "When true, delete any existing program at the destination before importing.") boolean overwrite) {
        if (gzfPath == null || gzfPath.isEmpty()) {
            return Response.err("gzf_path required");
        }
        File gzf = resolveWithinRootOrLog(gzfPath, "/import_program");
        if (gzf == null) return Response.err(FILE_ROOT_DENY);

        HeadlessProgramProvider.ImportResult res =
            programProvider.importProgramFromGzf(gzf, targetFolder, targetName, overwrite);
        if (!res.success) {
            return Response.err(res.error);
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("success", true);
        body.put("project", programProvider.getProjectName());
        body.put("folder", res.folderPath);
        body.put("program", res.programName);
        body.put("content_type", res.contentType);
        return Response.ok(body);
    }

    // ========================================================================
    // GAR project archive / restore
    // ========================================================================

    @McpTool(path = "/archive_project", dryRun = false, method = "POST",
            description = "Archive the currently open project to a Ghidra-native .gar file. The result can be "
                + "restored into any Ghidra GUI via File \u2192 Restore Project, or back into a headless instance "
                + "via /restore_project. Captures the entire project (all programs, folders, settings, "
                + "version-control metadata) \u2014 unlike /export_program which ships a single program as .gzf. "
                + "Output is written to `output_dir/output_name` (defaults: /data/exports and `<project>.gar`). "
                + "Refuses to overwrite an existing file. Callers should /save_all_programs first to flush "
                + "pending in-memory edits.",
            category = "headless", access = ToolAccess.WRITE)
    public Response archiveProject(
            @Param(value = "output_dir", source = ParamSource.BODY, defaultValue = "/data/exports",
                description = "Directory the .gar will be written to. Must already exist.") String outputDir,
            @Param(value = "output_name", source = ParamSource.BODY, defaultValue = "",
                description = "Output file name. Defaults to `<project>.gar`. `.gar` is appended if missing.") String outputName) {
        String dirPath = (outputDir == null || outputDir.isEmpty()) ? "/data/exports" : outputDir;
        File dir = resolveWithinRootOrLog(dirPath, "/archive_project");
        if (dir == null) return Response.err(FILE_ROOT_DENY);
        if (!dir.isDirectory()) {
            return Response.err("output_dir not a directory: " + dir.getAbsolutePath());
        }
        String projectName = programProvider.getProjectName();
        String name;
        if (outputName == null || outputName.isEmpty()) {
            name = HeadlessPaths.safeBasename(projectName == null ? "project" : projectName) + ".gar";
        } else {
            String invalid = HeadlessPaths.validateFilename(outputName);
            if (invalid != null) {
                return Response.err("invalid output_name: " + invalid);
            }
            name = outputName;
        }
        if (!name.toLowerCase().endsWith(".gar")) {
            name = name + ".gar";
        }
        File out = new File(dir, name);
        if (!HeadlessPaths.isWithin(dir, out)) {
            return Response.err("output_name escapes output_dir: " + name);
        }

        HeadlessProgramProvider.ArchiveResult res = programProvider.archiveCurrentProject(out);
        if (!res.success) {
            return Response.err(res.error);
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("success", true);
        body.put("project", res.projectName);
        body.put("path", res.outputPath);
        body.put("size_bytes", res.sizeBytes);
        body.put("content_type", "GAR");
        return Response.ok(body);
    }

    @McpTool(path = "/restore_project", dryRun = false, method = "POST",
            description = "Restore a Ghidra .gar archive into a fresh on-disk project at `parent_dir/project_name`. "
                + "Closes any currently-open project first. The restored project is NOT re-opened automatically; "
                + "follow up with /open_project so owner reset and project bookkeeping run via the same code path "
                + "as a user-driven open. Fails loudly if the destination project already exists.",
            category = "headless", access = ToolAccess.DESTRUCTIVE)
    public Response restoreProject(
            @Param(value = "gar_path", source = ParamSource.BODY,
                description = "Absolute path to the .gar file on disk.") String garPath,
            @Param(value = "parent_dir", source = ParamSource.BODY, defaultValue = "/data/ghidra_projects",
                description = "Directory under which the new project (project_name.gpr + project_name.rep/) will be created.") String parentDir,
            @Param(value = "project_name", source = ParamSource.BODY,
                description = "Name of the new project to create from the archive.") String projectName) {
        if (garPath == null || garPath.isEmpty()) {
            return Response.err("gar_path required");
        }
        File gar = new File(garPath);

        HeadlessProgramProvider.RestoreResult res =
            programProvider.restoreProject(gar, parentDir, projectName);
        if (!res.success) {
            return Response.err(res.error);
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("success", true);
        body.put("project", res.projectName);
        body.put("project_dir", res.projectDir);
        return Response.ok(body);
    }

    // ========================================================================
    // Server status
    // ========================================================================

    @McpTool(path = "/server/status", description = "Whether a Ghidra Server is connected (not whether a project is open: see /get_project_info)", category = "headless", access = ToolAccess.READ_ONLY)
    public Response serverStatus() {
        return Response.text(serverManager.getStatus());
    }
}
