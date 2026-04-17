package com.xebyte.headless;

import com.xebyte.core.*;
import ghidra.program.model.listing.Program;

import java.io.File;
import java.util.List;

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

    @McpTool(path = "/load_program", method = "POST", description = "Load a binary file into the headless server for analysis", category = "headless")
    public Response loadProgram(
            @Param(value = "file", source = ParamSource.BODY, description = "Absolute path to the binary file") String filePath) {
        if (filePath == null || filePath.isEmpty()) {
            return Response.err("file path required");
        }
        File file = new File(filePath);
        if (!file.exists()) {
            return Response.err("File not found: " + filePath);
        }
        Program program = programProvider.loadProgramFromFile(file);
        if (program != null) {
            return Response.text("{\"success\": true, \"program\": \"" + ServiceUtils.escapeJson(program.getName()) + "\"}");
        }
        return Response.err("Failed to load program from: " + filePath);
    }

    @McpTool(path = "/close_program", method = "POST", description = "Close a loaded program and free its resources", category = "headless")
    public Response closeProgram(
            @Param(value = "name", source = ParamSource.BODY, description = "Program name (as shown by list_open_programs)") String name) {
        Program program = programProvider.getProgram(name);
        if (program == null) {
            return Response.err("Program not found: " + (name != null ? name : "current"));
        }
        programProvider.closeProgram(program);
        return Response.text("{\"success\": true, \"closed\": \"" + ServiceUtils.escapeJson(program.getName()) + "\"}");
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

    @McpTool(path = "/load_program_from_project", method = "POST", description = "Load a program from the open project", category = "headless")
    public Response loadProgramFromProject(
            @Param(value = "path", source = ParamSource.BODY, description = "Program path within the project") String programPath) {
        if (programPath == null || programPath.isEmpty()) {
            return Response.err("Program path required");
        }
        if (!programProvider.hasProject()) {
            return Response.err("No project open. Use open_project first.");
        }
        Program program = programProvider.loadProgramFromProject(programPath);
        if (program != null) {
            return Response.text("{\"success\": true, \"program\": \"" + ServiceUtils.escapeJson(program.getName())
                + "\", \"path\": \"" + ServiceUtils.escapeJson(programPath) + "\"}");
        }
        return Response.err("Failed to load program: " + programPath);
    }

    @McpTool(path = "/get_project_info", description = "Get info about the currently open project", category = "headless")
    public Response getProjectInfo() {
        if (!programProvider.hasProject()) {
            return Response.text("{\"has_project\": false}");
        }
        List<HeadlessProgramProvider.ProjectFileInfo> files = programProvider.listProjectFiles();
        int programCount = (int) files.stream().filter(f -> "Program".equals(f.contentType)).count();
        return Response.text("{\"has_project\": true"
            + ", \"project_name\": \"" + ServiceUtils.escapeJson(programProvider.getProjectName()) + "\""
            + ", \"file_count\": " + files.size()
            + ", \"program_count\": " + programCount + "}");
    }

    // ========================================================================
    // Server status
    // ========================================================================

    @McpTool(path = "/server/status", description = "Check headless server connection status", category = "headless")
    public Response serverStatus() {
        return Response.text(serverManager.getStatus());
    }
}
