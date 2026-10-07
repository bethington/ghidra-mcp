package com.xebyte.core;

import ghidra.framework.model.Project;
import ghidra.util.Msg;

import java.io.File;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Programs and projects as files: GZF export and import for one program, GAR archive and
 * restore for a whole project. Served by both the GUI and headless. Creating and deleting
 * a project stay headless-only, since on the GUI they would replace the project the user
 * has open.
 */
public class ProjectLifecycleService {

    private static final String FILE_ROOT_DENY =
        "Access denied: path is outside the configured file root";

    private final ProjectProgramProvider provider;
    private final ProjectLifecycle lifecycle;

    public ProjectLifecycleService(ProjectProgramProvider provider) {
        this.provider = provider;
        this.lifecycle = new ProjectLifecycle(provider);
    }

    private String projectName() {
        Project project = provider.getProject();
        return project == null ? null : project.getName();
    }

    /**
     * Resolve a caller-supplied filesystem path against {@code files.root},
     * matching the containment /import_file applies. Returns the canonical {@link File}
     * when allowed, or {@code null} (after a server-side log that keeps the configured
     * root out of the client response) when a root is configured and the path escapes it.
     */
    private File resolveWithinRootOrLog(String userPath, String endpoint) {
        SecurityConfig security = SecurityConfig.getInstance();
        Path resolved = security.resolveWithinFileRoot(userPath);
        if (resolved == null) {
            Msg.warn(this, "Rejected " + endpoint + " for '" + userPath
                + "': outside configured files.root (" + security.getFileRoot() + ")");
            return null;
        }
        return resolved.toFile();
    }

    @McpTool(path = "/export_program", dryRun = false, method = "POST",
            description = "Export a program to a GZF (Ghidra packed-database) file on disk. The resulting .gzf "
                + "can be imported into any Ghidra GUI (File \u2192 Import) or back into a project via "
                + "/import_program. Resolution order: (1) the in-memory program with that name (captures live "
                + "analyst edits); (2) a DomainFile in the open project (on-disk state). Output is written to "
                + "`output_dir/output_name` (defaults: /data/exports and `<program>.gzf`). Refuses to overwrite "
                + "an existing file.",
            category = "project", access = ToolAccess.WRITE)
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
            name = SafePaths.safeBasename(programName) + ".gzf";
        } else {
            String invalid = SafePaths.validateFilename(outputName);
            if (invalid != null) {
                return Response.err("invalid output_name: " + invalid);
            }
            name = outputName;
        }
        if (!name.toLowerCase().endsWith(".gzf")) {
            name = name + ".gzf";
        }
        File out = new File(dir, name);
        if (!SafePaths.isWithin(dir, out)) {
            return Response.err("output_name escapes output_dir: " + name);
        }

        ProjectLifecycle.ExportResult res = lifecycle.exportProgramToGzf(programName, out);
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
            category = "project", access = ToolAccess.WRITE)
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

        ProjectLifecycle.ImportResult res =
            lifecycle.importProgramFromGzf(gzf, targetFolder, targetName, overwrite);
        if (!res.success) {
            return Response.err(res.error);
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("success", true);
        body.put("project", projectName());
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
                + "Refuses to overwrite an existing file, and refuses while an open program has unsaved "
                + "changes, since the archive would not contain them: save first.",
            category = "project", access = ToolAccess.WRITE)
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
        String projectName = projectName();
        String name;
        if (outputName == null || outputName.isEmpty()) {
            name = SafePaths.safeBasename(projectName == null ? "project" : projectName) + ".gar";
        } else {
            String invalid = SafePaths.validateFilename(outputName);
            if (invalid != null) {
                return Response.err("invalid output_name: " + invalid);
            }
            name = outputName;
        }
        if (!name.toLowerCase().endsWith(".gar")) {
            name = name + ".gar";
        }
        File out = new File(dir, name);
        if (!SafePaths.isWithin(dir, out)) {
            return Response.err("output_name escapes output_dir: " + name);
        }

        ProjectLifecycle.ArchiveResult res = lifecycle.archiveCurrentProject(out);
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
                + "The open project is left alone, and the restored one is NOT opened automatically; "
                + "follow up with /open_project so owner reset and project bookkeeping run via the same code path "
                + "as a user-driven open. Fails loudly if the destination project already exists.",
            category = "project", access = ToolAccess.WRITE)
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
        File gar = resolveWithinRootOrLog(garPath, "/restore_project");
        if (gar == null) return Response.err(FILE_ROOT_DENY);
        String parentPath = (parentDir == null || parentDir.isEmpty()) ? "/data/ghidra_projects" : parentDir;
        File parent = resolveWithinRootOrLog(parentPath, "/restore_project");
        if (parent == null) return Response.err(FILE_ROOT_DENY);

        ProjectLifecycle.RestoreResult res =
            lifecycle.restoreProject(gar, parent.getPath(), projectName);
        if (!res.success) {
            return Response.err(res.error);
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("success", true);
        body.put("project", res.projectName);
        body.put("project_dir", res.projectDir);
        return Response.ok(body);
    }

}
