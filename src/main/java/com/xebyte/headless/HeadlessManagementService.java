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
    // Program management
    // ========================================================================

    @McpTool(path = "/load_program", method = "POST",
            description = "Load a binary file into the headless server for analysis. "
                + "For raw firmware (no recognizable header), pass `language` (e.g. 'ARM:LE:32:Cortex') "
                + "and optionally `compiler_spec` (e.g. 'default'); the file is then imported as raw binary "
                + "with the requested processor. When `language` is omitted, the loader auto-detects the format.",
            category = "headless")
    public Response loadProgram(
            @Param(value = "file", source = ParamSource.BODY, description = "Absolute path to the binary file") String filePath,
            @Param(value = "language", source = ParamSource.BODY, defaultValue = "",
                description = "Optional Ghidra language ID for raw binaries (e.g. 'ARM:LE:32:Cortex', 'x86:LE:64:default'). Leave empty to auto-detect.") String languageId,
            @Param(value = "compiler_spec", source = ParamSource.BODY, defaultValue = "",
                description = "Optional compiler-spec ID (e.g. 'default', 'gcc', 'windows'). Only consulted when `language` is set; falls back to the language default when empty.") String compilerSpecId) {
        if (filePath == null || filePath.isEmpty()) {
            return Response.err("file path required");
        }
        // Enforce the GHIDRA_MCP_FILE_ROOT allow-list before touching the disk.
        // resolveWithinFileRoot canonicalizes the path (resolving symlinks and
        // `..`) and returns null when a root is configured and the path escapes
        // it; with no root configured it returns the canonical path unchanged.
        // filePath is non-null here, so a null result means "outside the root".
        SecurityConfig security = SecurityConfig.getInstance();
        Path resolved = security.resolveWithinFileRoot(filePath);
        if (resolved == null) {
            // Log the configured root server-side for the operator, but keep it
            // out of the client response so we don't disclose the filesystem
            // layout to the (untrusted) caller.
            Msg.warn(this, "Rejected /load_program for '" + filePath
                + "': outside configured GHIDRA_MCP_FILE_ROOT ("
                + security.getFileRoot() + ")");
            return Response.err("Access denied: path is outside the configured file root");
        }
        File file = resolved.toFile();
        if (!file.exists()) {
            return Response.err("File not found: " + filePath);
        }
        // Normalize once so the provider call and the error messages all use the
        // same trimmed values (a doc-copied " ARM:LE:32:Cortex " otherwise passes
        // the non-empty check but fails lookup with a confusing message).
        String normalizedLanguageId = (languageId == null) ? "" : languageId.trim();
        String normalizedCompilerSpecId = (compilerSpecId == null) ? "" : compilerSpecId.trim();
        boolean hasLanguage = !normalizedLanguageId.isEmpty();
        Program program = hasLanguage
            ? programProvider.loadProgramFromFileWithLanguage(file, normalizedLanguageId, normalizedCompilerSpecId)
            : programProvider.loadProgramFromFile(file);
        if (program != null) {
            String langOut = program.getLanguageID() != null
                ? program.getLanguageID().getIdAsString() : "";
            return Response.text(JsonHelper.toJson(JsonHelper.mapOf(
                "success", true,
                "program", program.getName(),
                "language", langOut)));
        }
        if (hasLanguage) {
            return Response.err("Failed to load program with language '" + normalizedLanguageId
                + "' from: " + filePath);
        }
        return Response.err("Failed to load program from: " + filePath
            + " (auto-detect failed; for raw firmware pass `language`, e.g. 'ARM:LE:32:Cortex')");
    }

    // ========================================================================
    // Project management
    // ========================================================================

    @McpTool(path = "/create_project", method = "POST", description = "Create a new Ghidra project", category = "headless")
    public Response createProject(
            @Param(value = "parentDir", source = ParamSource.BODY) String parentDir,
            @Param(value = "name", source = ParamSource.BODY) String name) {
        if (parentDir == null || parentDir.isEmpty()) return Response.err("parentDir required");
        if (name == null || name.isEmpty()) return Response.err("name required");
        try {
            boolean ok = programProvider.createProject(parentDir, name);
            if (ok) {
                return Response.text("{\"success\": true, \"name\": \"" + ServiceUtils.escapeJson(name)
                    + "\", \"path\": \"" + ServiceUtils.escapeJson(parentDir + "/" + name) + "\"}");
            }
            return Response.err("Failed to create project");
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    @McpTool(path = "/open_project", method = "POST", description = "Open an existing Ghidra project (.gpr file or directory)", category = "headless")
    public Response openProject(
            @Param(value = "path", source = ParamSource.BODY) String projectPath) {
        if (projectPath == null || projectPath.isEmpty()) {
            return Response.err("Project path required");
        }
        boolean success = programProvider.openProject(projectPath);
        if (success) {
            return Response.text("{\"success\": true, \"project\": \"" + ServiceUtils.escapeJson(programProvider.getProjectName()) + "\"}");
        }
        return Response.err("Failed to open project: " + projectPath);
    }

    @McpTool(path = "/close_project", method = "POST", description = "Close the currently open project", category = "headless")
    public Response closeProject() {
        if (!programProvider.hasProject()) {
            return Response.err("No project currently open");
        }
        String projectName = programProvider.getProjectName();
        programProvider.closeProject();
        return Response.text("{\"success\": true, \"closed\": \"" + ServiceUtils.escapeJson(projectName) + "\"}");
    }

    @McpTool(path = "/load_program_from_project", method = "POST", description = "Load a program from the open project. Returns structured diagnostics on failure (available paths, server-binding state) so the operator can tell server-side-checkout-but-not-shared from path-typo from server-unreachable. See discussion #119.", category = "headless")
    public Response loadProgramFromProject(
            @Param(value = "path", source = ParamSource.BODY, description = "Program path within the project") String programPath) {
        if (programPath == null || programPath.isEmpty()) {
            return Response.err("Program path required");
        }
        if (!programProvider.hasProject()) {
            return Response.err("No project open. Call /open_project first.");
        }

        HeadlessProgramProvider.ProgramLoadResult res =
            programProvider.loadProgramFromProjectDetailed(programPath);

        if (res.success) {
            Map<String, Object> ok = new LinkedHashMap<>();
            ok.put("success", true);
            ok.put("program", res.program.getName());
            ok.put("path", programPath);
            return Response.ok(ok);
        }

        // Structured failure — exposed so a Docker-headless user can tell
        // "wrong path" from "project not bound to server" from "server
        // unreachable" without needing to read Ghidra logs in the container.
        Map<String, Object> diagnostics = new LinkedHashMap<>();
        diagnostics.put("project_open", true);
        diagnostics.put("project_name", programProvider.getProjectName());
        HeadlessProgramProvider.ServerBindingInfo binding = programProvider.getProjectServerInfo();
        if (binding != null) {
            diagnostics.put("project_server_bound", binding.serverBound);
            if (binding.serverBound) {
                diagnostics.put("server", binding.serverInfo);
                diagnostics.put("server_repo", binding.repoName);
            }
        }
        if (res.availablePaths != null) {
            diagnostics.put("available_program_paths", res.availablePaths);
        }
        if (res.serverHint != null && !res.serverHint.isEmpty()) {
            diagnostics.put("suggestion", res.serverHint);
        }

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("success", false);
        body.put("error", res.error);
        body.put("requested_path", programPath);
        body.put("diagnostics", diagnostics);
        return Response.ok(body);
    }

    @McpTool(path = "/checkin_program", method = "POST", description = "Check a program back in to the shared Ghidra Server as a new version (the write-back path GhidraServerManager.checkinFile can't provide — see #119). Requires a shared (server-bound) project opened via /open_project and the file checked out. Saves pending edits and releases the open program first so keep_checked_out=false can actually drop the server checkout. Returns version_before/version/version_bumped.", category = "headless")
    public Response checkinProgram(
            @Param(value = "path", source = ParamSource.BODY, description = "Project path of the file (e.g. '/scratch/writetest'); empty uses the current program") String path,
            @Param(value = "comment", source = ParamSource.BODY, description = "Checkin comment") String comment,
            @Param(value = "keep_checked_out", source = ParamSource.BODY, defaultValue = "false", description = "Keep the file checked out after the new version lands") boolean keepCheckedOut) {
        if (!programProvider.hasProject()) {
            return Response.err("No project open. Call /open_project first.");
        }
        Map<String, Object> res = programProvider.checkinProgram(path, comment, keepCheckedOut);
        return Response.ok(res);
    }

    @McpTool(path = "/get_project_info", description = "Get info about the currently open project, including server-binding state. A shared (server-bound) project is required for /server/version_control/checkout to deliver content the headless can open; if `project_server_bound` is false, the open project is local-only.", category = "headless")
    public Response getProjectInfo() {
        if (!programProvider.hasProject()) {
            return Response.text("{\"has_project\": false}");
        }
        List<HeadlessProgramProvider.ProjectFileInfo> files = programProvider.listProjectFiles();
        int programCount = (int) files.stream().filter(f -> "Program".equals(f.contentType)).count();

        Map<String, Object> info = new LinkedHashMap<>();
        info.put("has_project", true);
        info.put("project_name", programProvider.getProjectName());
        info.put("file_count", files.size());
        info.put("program_count", programCount);

        // Server-binding visibility (#119) — lets the operator confirm at
        // a glance whether checkout flows will actually deliver content
        // their /load_program_from_project can pick up.
        HeadlessProgramProvider.ServerBindingInfo binding = programProvider.getProjectServerInfo();
        if (binding != null) {
            info.put("project_server_bound", binding.serverBound);
            if (binding.serverBound) {
                info.put("server", binding.serverInfo);
                info.put("server_repo", binding.repoName);
            }
        }
        return Response.ok(info);
    }

    // ========================================================================
    // GZF export / import
    // ========================================================================

    @McpTool(path = "/export_program", method = "POST",
            description = "Export a program to a GZF (Ghidra packed-database) file on disk. The resulting .gzf "
                + "can be imported into any Ghidra GUI (File \u2192 Import) or back into a project via "
                + "/import_program. Resolution order: (1) the in-memory program with that name (captures live "
                + "analyst edits); (2) a DomainFile in the open project (on-disk state). Output is written to "
                + "`output_dir/output_name` (defaults: /data/exports and `<program>.gzf`). Refuses to overwrite "
                + "an existing file.",
            category = "headless")
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
        File dir = new File(dirPath);
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

    @McpTool(path = "/import_program", method = "POST",
            description = "Import a GZF (Ghidra packed-database) file into the open project. The GZF must already "
                + "exist on disk at `gzf_path` (typically staged on a shared volume by the orchestrator). Lands at "
                + "`target_folder/target_name` (defaults: `/` and the GZF basename sans `.gzf`). Set `overwrite=true` "
                + "to replace an existing program at the destination; otherwise the call fails on collision.",
            category = "headless")
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
        File gzf = new File(gzfPath);

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

    @McpTool(path = "/archive_project", method = "POST",
            description = "Archive the currently open project to a Ghidra-native .gar file. The result can be "
                + "restored into any Ghidra GUI via File \u2192 Restore Project, or back into a headless instance "
                + "via /restore_project. Captures the entire project (all programs, folders, settings, "
                + "version-control metadata) \u2014 unlike /export_program which ships a single program as .gzf. "
                + "Output is written to `output_dir/output_name` (defaults: /data/exports and `<project>.gar`). "
                + "Refuses to overwrite an existing file. Callers should /save_all_programs first to flush "
                + "pending in-memory edits.",
            category = "headless")
    public Response archiveProject(
            @Param(value = "output_dir", source = ParamSource.BODY, defaultValue = "/data/exports",
                description = "Directory the .gar will be written to. Must already exist.") String outputDir,
            @Param(value = "output_name", source = ParamSource.BODY, defaultValue = "",
                description = "Output file name. Defaults to `<project>.gar`. `.gar` is appended if missing.") String outputName) {
        String dirPath = (outputDir == null || outputDir.isEmpty()) ? "/data/exports" : outputDir;
        File dir = new File(dirPath);
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

    @McpTool(path = "/restore_project", method = "POST",
            description = "Restore a Ghidra .gar archive into a fresh on-disk project at `parent_dir/project_name`. "
                + "Closes any currently-open project first. The restored project is NOT re-opened automatically; "
                + "follow up with /open_project so owner reset and project bookkeeping run via the same code path "
                + "as a user-driven open. Fails loudly if the destination project already exists.",
            category = "headless")
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

    @McpTool(path = "/server/status", description = "Check headless server connection status", category = "headless")
    public Response serverStatus() {
        return Response.text(serverManager.getStatus());
    }
}
