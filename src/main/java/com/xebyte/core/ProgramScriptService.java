package com.xebyte.core;

import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;

import javax.swing.SwingUtilities;
import java.io.*;
import java.lang.reflect.InvocationTargetException;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Service for program management, script execution, memory, and bookmark operations.
 * Extracted from GhidraMCPPlugin as part of v4.0.0 refactor.
 */
public class ProgramScriptService {

    private final ProgramProvider programProvider;
    private final ThreadingStrategy threadingStrategy;

    public ProgramScriptService(ProgramProvider programProvider, ThreadingStrategy threadingStrategy) {
        this.programProvider = programProvider;
        this.threadingStrategy = threadingStrategy;
    }

    // ========================================================================
    // Program resolution helper
    // ========================================================================

    private Object[] getProgramOrError(String programName) {
        Program program = null;
        if (programName != null && !programName.isEmpty()) {
            program = programProvider.resolveProgram(programName);
        } else {
            program = programProvider.getCurrentProgram();
        }
        if (program == null) {
            String available = "";
            Program[] all = programProvider.getAllOpenPrograms();
            if (all != null && all.length > 0) {
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < all.length; i++) {
                    if (i > 0) sb.append(", ");
                    sb.append(all[i].getName());
                }
                available = " Available programs: " + sb;
            }
            String error = programName != null && !programName.isEmpty()
                    ? ServiceUtils.programNotFoundError(programName) + available
                    : "No program loaded." + available;
            return new Object[]{null, error};
        }
        return new Object[]{program, null};
    }

    /**
     * Retrieve the PluginTool from the ProgramProvider if it is a GuiProgramProvider.
     * Returns null when running headless.
     */
    private PluginTool getToolFromProvider() {
        if (programProvider instanceof MultiToolProgramProvider mtp) {
            return mtp.getActiveTool();
        }
        if (programProvider instanceof GuiProgramProvider gpp) {
            return gpp.getTool();
        }
        return null;
    }

    // ========================================================================
    // Program Metadata
    // ========================================================================

    /**
     * Get metadata about the current program including name, architecture,
     * memory layout, function count, and symbol count.
     */
    @McpTool(value = "/get_metadata", description = "Get metadata about the current program/database")

    public Response getMetadata() {
        Program program = programProvider.getCurrentProgram();
        if (program == null) {
            return Response.err("No program loaded");
        }

        StringBuilder metadata = new StringBuilder();
        metadata.append("Program Name: ").append(program.getName()).append("\n");
        metadata.append("Executable Path: ").append(program.getExecutablePath()).append("\n");
        metadata.append("Architecture: ").append(program.getLanguage().getProcessor().toString()).append("\n");
        metadata.append("Compiler: ").append(program.getCompilerSpec().getCompilerSpecID()).append("\n");
        metadata.append("Language: ").append(program.getLanguage().getLanguageID()).append("\n");
        metadata.append("Endian: ").append(program.getLanguage().isBigEndian() ? "Big" : "Little").append("\n");
        metadata.append("Address Size: ").append(program.getAddressFactory().getDefaultAddressSpace().getSize()).append(" bits\n");
        metadata.append("Base Address: ").append(program.getImageBase()).append("\n");

        // Memory information
        long totalSize = 0;
        int blockCount = 0;
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            totalSize += block.getSize();
            blockCount++;
        }
        metadata.append("Memory Blocks: ").append(blockCount).append("\n");
        metadata.append("Total Memory Size: ").append(totalSize).append(" bytes\n");

        // Function count
        int functionCount = program.getFunctionManager().getFunctionCount();
        metadata.append("Function Count: ").append(functionCount).append("\n");

        // Symbol count
        int symbolCount = program.getSymbolTable().getNumSymbols();
        metadata.append("Symbol Count: ").append(symbolCount).append("\n");

        return Response.text(metadata.toString());
    }

    // ========================================================================
    // Program Management
    // ========================================================================

    /**
     * Save the currently active program to its domain file.
     */
    @McpTool(value = "/save_program", description = "Save the current program in Ghidra")

    public Response saveCurrentProgram() {
        Program program = programProvider.getCurrentProgram();
        if (program == null) {
            return Response.err("No program loaded");
        }

        final StringBuilder result = new StringBuilder();
        final AtomicReference<String> errorMsg = new AtomicReference<>();

        try {
            SwingUtilities.invokeAndWait(() -> {
                try {
                    ghidra.framework.model.DomainFile df = program.getDomainFile();
                    if (df == null) {
                        errorMsg.set("Program has no domain file");
                        return;
                    }
                    df.save(new ConsoleTaskMonitor());
                    result.append("{");
                    result.append("\"success\": true, ");
                    result.append("\"program\": \"").append(program.getName().replace("\"", "\\\"")).append("\", ");
                    result.append("\"message\": \"Program saved successfully\"");
                    result.append("}");
                } catch (Throwable e) {
                    String msg = e.getMessage() != null ? e.getMessage() : e.toString();
                    errorMsg.set(msg);
                    Msg.error(this, "Error saving program", e);
                }
            });

            if (errorMsg.get() != null) {
                return Response.err(errorMsg.get());
            }
        } catch (Throwable e) {
            String msg = e.getMessage() != null ? e.getMessage() : e.toString();
            return Response.err(msg);
        }

        return result.length() > 0 ? Response.text(result.toString()) : Response.err("Unknown failure");
    }

    /**
     * Save and exit Ghidra cleanly.
     */
    @McpTool(value = "/exit_ghidra", method = McpTool.Method.POST,
             description = "Save the current program and exit Ghidra cleanly")
    public Response exitGhidra() {
        Response saveResult = saveCurrentProgram();
        PluginTool tool = getToolFromProvider();
        if (tool == null) {
            return Response.err("Exit requires GUI mode (PluginTool not available)");
        }
        new Thread(() -> {
            try { Thread.sleep(500); } catch (InterruptedException ignored) {}
            SwingUtilities.invokeLater(tool::close);
        }).start();
        return Response.ok(Map.of(
            "success", true,
            "message", "Saving and exiting Ghidra",
            "save", Response.r2s(saveResult)));
    }

    /**
     * List all currently open programs in Ghidra.
     */
    @McpTool(value = "/list_open_programs", description = "List all currently open programs in Ghidra")

    public Response listOpenPrograms() {
        Program[] programs = programProvider.getAllOpenPrograms();
        if (programs == null || programs.length == 0) {
            return Response.text("{\"programs\": [], \"count\": 0, \"current_program\": \"\"}");
        }

        Program currentProgram = programProvider.getCurrentProgram();

        StringBuilder result = new StringBuilder();
        result.append("{\"programs\": [");

        boolean first = true;
        for (Program prog : programs) {
            if (!first) result.append(", ");
            first = false;

            result.append("{");
            result.append("\"name\": \"").append(ServiceUtils.escapeJson(prog.getName())).append("\", ");
            result.append("\"path\": \"").append(ServiceUtils.escapeJson(prog.getDomainFile().getPathname())).append("\", ");
            result.append("\"is_current\": ").append(prog == currentProgram).append(", ");
            result.append("\"executable_path\": \"").append(ServiceUtils.escapeJson(prog.getExecutablePath() != null ? prog.getExecutablePath() : "")).append("\", ");
            result.append("\"language\": \"").append(ServiceUtils.escapeJson(prog.getLanguageID().getIdAsString())).append("\", ");
            result.append("\"compiler\": \"").append(ServiceUtils.escapeJson(prog.getCompilerSpec().getCompilerSpecID().getIdAsString())).append("\", ");
            result.append("\"image_base\": \"").append(prog.getImageBase().toString()).append("\", ");
            result.append("\"memory_size\": ").append(prog.getMemory().getSize()).append(", ");
            result.append("\"function_count\": ").append(prog.getFunctionManager().getFunctionCount());
            result.append("}");
        }

        result.append("], \"count\": ").append(programs.length);
        result.append(", \"current_program\": \"").append(currentProgram != null ? ServiceUtils.escapeJson(currentProgram.getName()) : "").append("\"");
        result.append("}");

        return Response.text(result.toString());
    }

    /**
     * Get detailed information about the currently active program.
     */
    @McpTool(value = "/get_current_program_info", description = "Get detailed information about the currently active program")

    public Response getCurrentProgramInfo() {
        Program program = programProvider.getCurrentProgram();
        if (program == null) {
            return Response.err("No program currently loaded");
        }

        StringBuilder result = new StringBuilder();
        result.append("{");
        result.append("\"name\": \"").append(ServiceUtils.escapeJson(program.getName())).append("\", ");
        result.append("\"path\": \"").append(ServiceUtils.escapeJson(program.getDomainFile().getPathname())).append("\", ");
        result.append("\"executable_path\": \"").append(ServiceUtils.escapeJson(program.getExecutablePath() != null ? program.getExecutablePath() : "")).append("\", ");
        result.append("\"executable_format\": \"").append(ServiceUtils.escapeJson(program.getExecutableFormat())).append("\", ");
        result.append("\"language\": \"").append(ServiceUtils.escapeJson(program.getLanguageID().getIdAsString())).append("\", ");
        result.append("\"compiler\": \"").append(ServiceUtils.escapeJson(program.getCompilerSpec().getCompilerSpecID().getIdAsString())).append("\", ");
        result.append("\"address_size\": ").append(program.getAddressFactory().getDefaultAddressSpace().getSize()).append(", ");
        result.append("\"image_base\": \"").append(program.getImageBase().toString()).append("\", ");
        result.append("\"min_address\": \"").append(program.getMinAddress() != null ? program.getMinAddress().toString() : "null").append("\", ");
        result.append("\"max_address\": \"").append(program.getMaxAddress() != null ? program.getMaxAddress().toString() : "null").append("\", ");
        result.append("\"memory_size\": ").append(program.getMemory().getSize()).append(", ");
        result.append("\"function_count\": ").append(program.getFunctionManager().getFunctionCount()).append(", ");
        result.append("\"symbol_count\": ").append(program.getSymbolTable().getNumSymbols()).append(", ");
        result.append("\"data_type_count\": ").append(program.getDataTypeManager().getDataTypeCount(true)).append(", ");

        // Get creation and modification dates
        result.append("\"creation_date\": \"").append(program.getCreationDate() != null ? program.getCreationDate().toString() : "unknown").append("\", ");

        // Get memory block count
        result.append("\"memory_block_count\": ").append(program.getMemory().getBlocks().length);

        result.append("}");
        return Response.text(result.toString());
    }

    /**
     * Switch MCP context to a different open program by name.
     */
    @McpTool(value = "/switch_program", description = "Switch MCP context to a different open program")

    public Response switchProgram(

            @Param(value = "name") String programName) {
        if (programName == null || programName.trim().isEmpty()) {
            return Response.err("Program name is required");
        }

        Program[] programs = programProvider.getAllOpenPrograms();
        if (programs == null || programs.length == 0) {
            return Response.err("No programs are currently open");
        }

        Program targetProgram = null;

        // Find program by name (case-insensitive match)
        for (Program prog : programs) {
            if (prog.getName().equalsIgnoreCase(programName.trim())) {
                targetProgram = prog;
                break;
            }
        }

        // If not found by exact name, try partial match on path
        if (targetProgram == null) {
            for (Program prog : programs) {
                if (prog.getDomainFile().getPathname().toLowerCase().contains(programName.toLowerCase())) {
                    targetProgram = prog;
                    break;
                }
            }
        }

        if (targetProgram == null) {
            StringBuilder availablePrograms = new StringBuilder();
            for (int i = 0; i < programs.length; i++) {
                if (i > 0) availablePrograms.append(", ");
                availablePrograms.append(programs[i].getName());
            }
            return Response.err("Program not found: " + programName + ". Available: " + availablePrograms);
        }

        // Switch to the target program
        programProvider.setCurrentProgram(targetProgram);

        return Response.text("{\"success\": true, \"switched_to\": \"" + ServiceUtils.escapeJson(targetProgram.getName()) +
               "\", \"path\": \"" + ServiceUtils.escapeJson(targetProgram.getDomainFile().getPathname()) + "\"}");
    }

    /**
     * List all files in the current Ghidra project.
     */
    @McpTool(value = "/list_project_files", description = "List all files in the current Ghidra project")

    public Response listProjectFiles(

            @Param(value = "folder") String folderPath) {
        PluginTool tool = getToolFromProvider();
        if (tool == null) {
            return Response.err("Project listing requires GUI mode (PluginTool not available)");
        }

        ghidra.framework.model.Project project = tool.getProject();
        if (project == null) {
            return Response.err("No project is currently open");
        }

        ghidra.framework.model.ProjectData projectData = project.getProjectData();
        ghidra.framework.model.DomainFolder rootFolder = projectData.getRootFolder();

        // If folder path specified, navigate to it
        ghidra.framework.model.DomainFolder targetFolder = rootFolder;
        if (folderPath != null && !folderPath.trim().isEmpty() && !folderPath.equals("/")) {
            // Navigate through path segments (handles nested folders like "LoD/1.07")
            String cleanPath = folderPath.startsWith("/") ? folderPath.substring(1) : folderPath;
            String[] pathParts = cleanPath.split("/");
            for (String part : pathParts) {
                if (part.isEmpty()) continue;
                ghidra.framework.model.DomainFolder nextFolder = targetFolder.getFolder(part);
                if (nextFolder == null) {
                    return Response.err("Folder not found: " + folderPath);
                }
                targetFolder = nextFolder;
            }
        }

        StringBuilder result = new StringBuilder();
        result.append("{\"project_name\": \"").append(ServiceUtils.escapeJson(project.getName())).append("\", ");
        result.append("\"current_folder\": \"").append(ServiceUtils.escapeJson(targetFolder.getPathname())).append("\", ");
        result.append("\"folders\": [");

        // List subfolders
        ghidra.framework.model.DomainFolder[] subfolders = targetFolder.getFolders();
        for (int i = 0; i < subfolders.length; i++) {
            if (i > 0) result.append(", ");
            result.append("\"").append(ServiceUtils.escapeJson(subfolders[i].getName())).append("\"");
        }
        result.append("], ");

        result.append("\"files\": [");

        // List files in folder
        ghidra.framework.model.DomainFile[] files = targetFolder.getFiles();
        boolean first = true;
        for (ghidra.framework.model.DomainFile file : files) {
            if (!first) result.append(", ");
            first = false;

            result.append("{");
            result.append("\"name\": \"").append(ServiceUtils.escapeJson(file.getName())).append("\", ");
            result.append("\"path\": \"").append(ServiceUtils.escapeJson(file.getPathname())).append("\", ");
            result.append("\"content_type\": \"").append(ServiceUtils.escapeJson(file.getContentType())).append("\", ");
            result.append("\"version\": ").append(file.getVersion()).append(", ");
            result.append("\"is_read_only\": ").append(file.isReadOnly()).append(", ");
            result.append("\"is_versioned\": ").append(file.isVersioned());
            result.append("}");
        }
        result.append("]");

        result.append("}");
        return Response.text(result.toString());
    }

    /**
     * Open a program from the current project by path.
     */
    @McpTool(value = "/open_program", method = McpTool.Method.POST, description = "Open a program from the current Ghidra project")

    public Response openProgramFromProject(

            @Param(value = "path") String path) {
        return openProgramFromProject(path, false);
    }

    public Response openProgramFromProject(String path, boolean autoAnalyze) {
        if (path == null || path.trim().isEmpty()) {
            return Response.err("Program path is required");
        }

        PluginTool tool = getToolFromProvider();
        if (tool == null) {
            return Response.err("Opening programs requires GUI mode (PluginTool not available)");
        }

        ghidra.framework.model.Project project = tool.getProject();
        if (project == null) {
            return Response.err("No project is currently open");
        }

        ghidra.framework.model.ProjectData projectData = project.getProjectData();
        ghidra.framework.model.DomainFile domainFile = projectData.getFile(path);

        if (domainFile == null) {
            return Response.err("File not found in project: " + path);
        }

        // Check if already open
        Program[] openPrograms = programProvider.getAllOpenPrograms();
        for (Program prog : openPrograms) {
            if (prog.getDomainFile().getPathname().equals(path)) {
                // Already open, just switch to it
                programProvider.setCurrentProgram(prog);
                return Response.text("{\"success\": true, \"message\": \"Program already open, switched to it\", " +
                       "\"name\": \"" + ServiceUtils.escapeJson(prog.getName()) + "\", " +
                       "\"path\": \"" + ServiceUtils.escapeJson(path) + "\"}");
            }
        }

        // Open the program
        try {
            // Find a ProgramManager from any running CodeBrowser
            ProgramManager pm = null;
            ghidra.framework.model.ToolManager tm = project.getToolManager();
            if (tm != null) {
                for (PluginTool runningTool : tm.getRunningTools()) {
                    pm = runningTool.getService(ProgramManager.class);
                    if (pm != null) break;
                }
            }

            Program program;
            if (pm != null) {
                // CodeBrowser exists — open in it
                program = (Program) domainFile.getDomainObject(tool, false, false, ghidra.util.task.TaskMonitor.DUMMY);
                if (program == null) {
                    return Response.err("Failed to open program: " + path);
                }
                pm.openProgram(program);
                pm.setCurrentProgram(program);
            } else {
                // No CodeBrowser running — launch one from the active workspace
                if (tm == null) {
                    return Response.err("ToolManager not available");
                }
                ghidra.framework.model.Workspace ws = tm.getActiveWorkspace();
                if (ws == null) {
                    return Response.err("No active workspace");
                }
                // Find the CodeBrowser template
                ghidra.framework.model.ToolChest chest = project.getLocalToolChest();
                ghidra.framework.model.ToolTemplate template = chest != null ? chest.getToolTemplate("CodeBrowser") : null;
                PluginTool launched;
                if (template != null) {
                    launched = ws.runTool(template);
                } else {
                    launched = ws.createTool();
                }
                if (launched == null) {
                    return Response.err("Failed to launch CodeBrowser");
                }
                ProgramManager launchedPm = launched.getService(ProgramManager.class);
                if (launchedPm == null) {
                    return Response.err("Launched tool has no ProgramManager");
                }
                program = (Program) domainFile.getDomainObject(launched, false, false, ghidra.util.task.TaskMonitor.DUMMY);
                if (program == null) {
                    return Response.err("Failed to open program: " + path);
                }
                launchedPm.openProgram(program);
                launchedPm.setCurrentProgram(program);
            }

            // Optionally trigger auto-analysis
            boolean analyzed = false;
            if (autoAnalyze) {
                try {
                    AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
                    mgr.reAnalyzeAll(null);
                    mgr.startAnalysis(ghidra.util.task.TaskMonitor.DUMMY);
                    analyzed = true;
                } catch (Exception ae) {
                    Msg.warn(this, "Auto-analysis failed: " + ae.getMessage());
                }
            }

            return Response.text("{\"success\": true, \"message\": \"Program opened successfully\", " +
                   "\"name\": \"" + ServiceUtils.escapeJson(program.getName()) + "\", " +
                   "\"path\": \"" + ServiceUtils.escapeJson(path) + "\", " +
                   "\"auto_analyzed\": " + analyzed + ", " +
                   "\"function_count\": " + program.getFunctionManager().getFunctionCount() + "}");
        } catch (Exception e) {
            return Response.err("Failed to open program: " + e.getMessage());
        }
    }

    // ========================================================================
    // Script Execution
    // ========================================================================

    /**
     * Execute a Ghidra script by path with optional arguments.
     *
     * @param scriptPath Path to the script file
     * @param scriptArgs Optional space-separated arguments for the script
     * @return Script output or error message
     */
    @McpTool(value = "/run_script", description = "Run a Ghidra script programmatically (v1.7.0)", method = McpTool.Method.POST)

    public Response runGhidraScript(

            @Param(value = "script_path") String scriptPath,

            @Param(value = "args") String scriptArgs) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) {
            return Response.err("No program loaded");
        }

        final StringBuilder resultMsg = new StringBuilder();
        final AtomicBoolean success = new AtomicBoolean(false);
        final ByteArrayOutputStream outputCapture = new ByteArrayOutputStream();
        final PrintStream originalOut = System.out;
        final PrintStream originalErr = System.err;

        // Track whether we copied the script (for cleanup)
        final File[] copiedScript = {null};

        // Get the PluginTool for script state (GUI mode only)
        final PluginTool pluginTool = getToolFromProvider();

        try {
            SwingUtilities.invokeAndWait(() -> {
                try {
                    // Capture console output
                    PrintStream captureStream = new PrintStream(outputCapture);
                    System.setOut(captureStream);
                    System.setErr(captureStream);

                    resultMsg.append("=== GHIDRA SCRIPT EXECUTION ===\n");
                    resultMsg.append("Script: ").append(scriptPath).append("\n");
                    resultMsg.append("Program: ").append(program.getName()).append("\n");
                    resultMsg.append("Time: ").append(new Date().toString()).append("\n\n");

                    // Resolve script file - search standard locations
                    File ghidraScriptsDir = new File(System.getProperty("user.home"), "ghidra_scripts");
                    String[] possiblePaths = {
                        scriptPath,  // Absolute or relative path as-is
                        new File(ghidraScriptsDir, scriptPath).getPath(),
                        new File(ghidraScriptsDir, new File(scriptPath).getName()).getPath(),
                        "./ghidra_scripts/" + scriptPath,
                        "./ghidra_scripts/" + new File(scriptPath).getName()
                    };

                    File resolvedFile = null;
                    for (String p : possiblePaths) {
                        try {
                            File candidate = new File(p);
                            if (candidate.exists() && candidate.isFile()) {
                                resolvedFile = candidate;
                                break;
                            }
                        } catch (Exception e) {
                            // Continue
                        }
                    }

                    if (resolvedFile == null) {
                        resultMsg.append("ERROR: Script file not found. Searched:\n");
                        for (String p : possiblePaths) {
                            resultMsg.append("  - ").append(p).append("\n");
                        }
                        return;
                    }

                    // Issue #2 fix: If the script is NOT already in ~/ghidra_scripts/,
                    // copy it there so Ghidra's OSGi class loader can find the source bundle.
                    File scriptFileForExecution = resolvedFile;
                    try {
                        ghidraScriptsDir.mkdirs();
                        String canonicalScriptsDir = ghidraScriptsDir.getCanonicalPath();
                        String canonicalResolved = resolvedFile.getCanonicalPath();
                        if (!canonicalResolved.startsWith(canonicalScriptsDir + File.separator)) {
                            // Copy to ~/ghidra_scripts/
                            File dest = new File(ghidraScriptsDir, resolvedFile.getName());
                            java.nio.file.Files.copy(resolvedFile.toPath(), dest.toPath(),
                                java.nio.file.StandardCopyOption.REPLACE_EXISTING);
                            scriptFileForExecution = dest;
                            copiedScript[0] = dest;
                            resultMsg.append("Copied to: ").append(dest.getAbsolutePath()).append("\n");
                        }
                    } catch (Exception e) {
                        resultMsg.append("Warning: Could not copy script to ~/ghidra_scripts/: ").append(e.getMessage()).append("\n");
                    }

                    generic.jar.ResourceFile scriptFile = new generic.jar.ResourceFile(scriptFileForExecution);

                    resultMsg.append("Found script: ").append(scriptFile.getAbsolutePath()).append("\n");
                    resultMsg.append("Size: ").append(scriptFile.length()).append(" bytes\n\n");

                    // Get script provider
                    ghidra.app.script.GhidraScriptProvider provider = ghidra.app.script.GhidraScriptUtil.getProvider(scriptFile);
                    if (provider == null) {
                        resultMsg.append("ERROR: No script provider found for: ").append(scriptFile.getName()).append("\n");
                        return;
                    }

                    resultMsg.append("Script provider: ").append(provider.getClass().getSimpleName()).append("\n");

                    // Create script instance
                    StringWriter scriptWriter = new StringWriter();
                    PrintWriter scriptPrintWriter = new PrintWriter(scriptWriter);

                    ghidra.app.script.GhidraScript script = provider.getScriptInstance(scriptFile, scriptPrintWriter);
                    if (script == null) {
                        resultMsg.append("ERROR: Failed to create script instance\n");
                        return;
                    }

                    // Set up script state
                    ghidra.program.util.ProgramLocation location = new ghidra.program.util.ProgramLocation(program, program.getMinAddress());
                    ghidra.app.script.GhidraState scriptState;
                    if (pluginTool != null) {
                        scriptState = new ghidra.app.script.GhidraState(pluginTool, pluginTool.getProject(), program, location, null, null);
                    } else {
                        scriptState = new ghidra.app.script.GhidraState(null, null, program, location, null, null);
                    }

                    ghidra.util.task.TaskMonitor scriptMonitor = new ghidra.util.task.ConsoleTaskMonitor();

                    script.set(scriptState, scriptMonitor, scriptPrintWriter);

                    // Issue #1 + #5 fix: Parse and set script args BEFORE execution,
                    // so getScriptArgs() returns them instead of falling through to askString()
                    String[] args = new String[0];
                    if (scriptArgs != null && !scriptArgs.trim().isEmpty()) {
                        args = scriptArgs.trim().split("\\s+");
                        script.setScriptArgs(args);
                        resultMsg.append("Script args: ").append(Arrays.toString(args)).append("\n");
                    }

                    resultMsg.append("\n--- SCRIPT OUTPUT ---\n");

                    // Execute the script
                    script.runScript(scriptFile.getName(), args);

                    // Get script output
                    String scriptOutput = scriptWriter.toString();
                    if (!scriptOutput.isEmpty()) {
                        resultMsg.append(scriptOutput).append("\n");
                    }

                    success.set(true);
                    resultMsg.append("\n=== SCRIPT COMPLETED SUCCESSFULLY ===\n");

                } catch (Exception e) {
                    resultMsg.append("\n=== SCRIPT EXECUTION ERROR ===\n");
                    resultMsg.append("Error: ").append(e.getClass().getSimpleName()).append(": ").append(e.getMessage()).append("\n");

                    StringWriter sw = new StringWriter();
                    PrintWriter pw = new PrintWriter(sw);
                    e.printStackTrace(pw);
                    resultMsg.append("Stack trace:\n").append(sw.toString()).append("\n");

                    Msg.error(this, "Script execution failed: " + scriptPath, e);
                } finally {
                    // Restore original output streams
                    System.setOut(originalOut);
                    System.setErr(originalErr);

                    // Append any captured console output
                    String capturedOutput = outputCapture.toString();
                    if (!capturedOutput.isEmpty()) {
                        resultMsg.append("\n--- CONSOLE OUTPUT ---\n");
                        resultMsg.append(capturedOutput).append("\n");
                    }

                    // Clean up copied script
                    if (copiedScript[0] != null) {
                        if (!copiedScript[0].delete()) {
                            copiedScript[0].deleteOnExit();
                        }
                    }
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            resultMsg.append("ERROR: Failed to execute on Swing thread: ").append(e.getMessage()).append("\n");
            Msg.error(this, "Failed to execute on Swing thread", e);
        }

        return Response.text(resultMsg.toString());
    }

    /**
     * List available Ghidra scripts.
     *
     * @param filter Optional filter string to match script names
     * @return JSON list of available scripts
     */
    @McpTool(value = "/list_scripts", description = "List available Ghidra scripts (v1.7.0)")

    public Response listGhidraScripts(

            @Param(value = "filter", required = false) String filter) {
        final StringBuilder resultMsg = new StringBuilder();

        try {
            SwingUtilities.invokeAndWait(() -> {
                try {
                    resultMsg.append("{\n  \"note\": \"Script listing requires Ghidra GUI access\",\n");
                    resultMsg.append("  \"filter\": \"").append(filter != null ? filter : "none").append("\",\n");
                    resultMsg.append("  \"instructions\": [\n");
                    resultMsg.append("    \"To view available scripts:\",\n");
                    resultMsg.append("    \"1. Open Ghidra's Script Manager (Window → Script Manager)\",\n");
                    resultMsg.append("    \"2. Browse scripts by category\",\n");
                    resultMsg.append("    \"3. Use the search filter at the top\"\n");
                    resultMsg.append("  ],\n");
                    resultMsg.append("  \"common_script_locations\": [\n");
                    resultMsg.append("    \"<ghidra_install>/Ghidra/Features/*/ghidra_scripts/\",\n");
                    resultMsg.append("    \"<user_home>/ghidra_scripts/\"\n");
                    resultMsg.append("  ]\n");
                    resultMsg.append("}");

                } catch (Exception e) {
                    resultMsg.append("Error: ").append(e.getMessage());
                    Msg.error(this, "Error in list scripts handler", e);
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            return Response.err("Failed to execute on Swing thread: " + e.getMessage());
        }

        return Response.text(resultMsg.toString());
    }

    // ========================================================================
    // Memory Operations
    // ========================================================================

    /**
     * Read memory at a specific address.
     */
    @McpTool(value = "/read_memory", description = "Read raw bytes from memory at the specified address")

    public Response readMemory(

            @Param(value = "address") String addressStr,

            @Param(value = "length", type = "integer") int length,

            @Param(value = "program", required = false) String programName) {
        try {
            Object[] programResult = getProgramOrError(programName);
            Program program = (Program) programResult[0];
            if (program == null) {
                return Response.err((String) programResult[1]);
            }

            Address address = program.getAddressFactory().getAddress(addressStr);
            if (address == null) {
                return Response.err("Invalid address: " + addressStr);
            }

            Memory memory = program.getMemory();
            byte[] bytes = new byte[length];

            int bytesRead = memory.getBytes(address, bytes);

            StringBuilder json = new StringBuilder();
            json.append("{");
            json.append("\"address\":\"").append(address.toString()).append("\",");
            json.append("\"length\":").append(bytesRead).append(",");
            json.append("\"data\":[");

            for (int i = 0; i < bytesRead; i++) {
                if (i > 0) json.append(",");
                json.append(bytes[i] & 0xFF);
            }

            json.append("],");
            json.append("\"hex\":\"");
            for (int i = 0; i < bytesRead; i++) {
                json.append(String.format("%02x", bytes[i] & 0xFF));
            }
            json.append("\"");
            json.append("}");

            return Response.text(json.toString());

        } catch (Exception e) {
            return Response.err("Failed to read memory: " + e.getMessage());
        }
    }

    /**
     * Create an uninitialized memory block (e.g., for MMIO/peripheral regions).
     */
    @McpTool(value = "/create_memory_block", description = "Create an uninitialized memory block at the specified address", method = McpTool.Method.POST)

    public Response createMemoryBlock(

            @Param(value = "name") String name,

            @Param(value = "address") String addressStr,

            @Param(value = "size") long size,

            @Param(value = "read", type = "boolean") boolean read,

            @Param(value = "write", type = "boolean") boolean write,

            @Param(value = "execute", type = "boolean") boolean execute,

            @Param(value = "isVolatile", type = "boolean") boolean isVolatile,

            @Param(value = "comment") String comment) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) {
            return Response.err("No program loaded");
        }
        if (name == null || name.isEmpty()) {
            return Response.err("name parameter required");
        }
        if (addressStr == null || addressStr.isEmpty()) {
            return Response.err("address parameter required");
        }
        if (size <= 0) {
            return Response.err("size must be positive");
        }

        final StringBuilder result = new StringBuilder();
        final AtomicReference<String> errorMsg = new AtomicReference<>();

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Create memory block");
                boolean txSuccess = false;
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    if (addr == null) {
                        errorMsg.set("Invalid address: " + addressStr);
                        return;
                    }

                    // Check for overlap with existing blocks
                    Address end = addr.add(size - 1);
                    for (MemoryBlock existing : program.getMemory().getBlocks()) {
                        if (existing.contains(addr) || existing.contains(end) ||
                            (addr.compareTo(existing.getStart()) <= 0 && end.compareTo(existing.getEnd()) >= 0)) {
                            errorMsg.set("Address range overlaps with existing block '" + existing.getName() +
                                         "' (" + existing.getStart() + " - " + existing.getEnd() + ")");
                            return;
                        }
                    }

                    MemoryBlock block = program.getMemory().createUninitializedBlock(
                        name, addr, size, false);

                    block.setRead(read);
                    block.setWrite(write);
                    block.setExecute(execute);
                    block.setVolatile(isVolatile);
                    if (comment != null && !comment.isEmpty()) {
                        block.setComment(comment);
                    }

                    txSuccess = true;
                    result.append("{");
                    result.append("\"success\": true, ");
                    result.append("\"name\": \"").append(name.replace("\"", "\\\"")).append("\", ");
                    result.append("\"start\": \"").append(block.getStart()).append("\", ");
                    result.append("\"end\": \"").append(block.getEnd()).append("\", ");
                    result.append("\"size\": ").append(block.getSize()).append(", ");
                    result.append("\"permissions\": \"");
                    result.append(read ? "r" : "-");
                    result.append(write ? "w" : "-");
                    result.append(execute ? "x" : "-");
                    result.append("\", ");
                    result.append("\"volatile\": ").append(isVolatile).append(", ");
                    result.append("\"message\": \"Memory block '").append(name.replace("\"", "\\\""))
                          .append("' created at ").append(addr).append("\"");
                    result.append("}");
                } catch (Throwable e) {
                    String msg = e.getMessage() != null ? e.getMessage() : e.toString();
                    errorMsg.set(msg);
                    Msg.error(this, "Error creating memory block", e);
                } finally {
                    program.endTransaction(tx, txSuccess);
                }
            });

            if (errorMsg.get() != null) {
                return Response.err(errorMsg.get());
            }
        } catch (Throwable e) {
            String msg = e.getMessage() != null ? e.getMessage() : e.toString();
            return Response.err("Failed to execute on Swing thread: " + msg);
        }

        return result.length() > 0 ? Response.text(result.toString()) : Response.err("Unknown failure");
    }

    // ========================================================================
    // Bookmark Operations
    // ========================================================================

    /**
     * Set a bookmark at an address with category and comment.
     * Creates or updates the bookmark if one already exists at the address with the same category.
     */
    @McpTool(value = "/set_bookmark", description = "Set a bookmark at the specified address", method = McpTool.Method.POST)

    public Response setBookmark(

            @Param(value = "address") String addressStr,

            @Param(value = "category") String category,

            @Param(value = "comment") String comment) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) {
            return Response.err("No program loaded");
        }
        if (addressStr == null || addressStr.isEmpty()) {
            return Response.err("Address is required");
        }
        if (category == null || category.isEmpty()) {
            category = "Note";  // Default category
        }
        if (comment == null) {
            comment = "";
        }

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            if (addr == null) {
                return Response.err("Invalid address: " + addressStr);
            }

            BookmarkManager bookmarkManager = program.getBookmarkManager();
            final String finalCategory = category;
            final String finalComment = comment;

            int transactionId = program.startTransaction("Set bookmark at " + addressStr);
            try {
                // Check if bookmark already exists at this address with this category
                Bookmark existing = bookmarkManager.getBookmark(addr, BookmarkType.NOTE, finalCategory);
                if (existing != null) {
                    // Remove existing to update
                    bookmarkManager.removeBookmark(existing);
                }

                // Create new bookmark
                bookmarkManager.setBookmark(addr, BookmarkType.NOTE, finalCategory, finalComment);
                program.endTransaction(transactionId, true);

                return Response.text("{\"success\": true, \"address\": \"" + escapeJsonString(addr.toString()) +
                       "\", \"category\": \"" + escapeJsonString(finalCategory) +
                       "\", \"comment\": \"" + escapeJsonString(finalComment) + "\"}");

            } catch (Exception e) {
                program.endTransaction(transactionId, false);
                throw e;
            }

        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    /**
     * List bookmarks, optionally filtered by category and/or address.
     */
    @McpTool(value = "/list_bookmarks", description = "List bookmarks in the program")

    public Response listBookmarks(

            @Param(value = "category") String category,

            @Param(value = "address") String addressStr) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) {
            return Response.err("No program loaded");
        }

        try {
            BookmarkManager bookmarkManager = program.getBookmarkManager();
            List<Map<String, String>> bookmarks = new ArrayList<>();

            // If specific address provided, get bookmarks at that address
            if (addressStr != null && !addressStr.isEmpty()) {
                Address addr = program.getAddressFactory().getAddress(addressStr);
                if (addr == null) {
                    return Response.err("Invalid address: " + addressStr);
                }

                Bookmark[] bms = bookmarkManager.getBookmarks(addr);
                for (Bookmark bm : bms) {
                    if (category == null || category.isEmpty() || bm.getCategory().equals(category)) {
                        Map<String, String> bmMap = new HashMap<>();
                        bmMap.put("address", bm.getAddress().toString());
                        bmMap.put("category", bm.getCategory());
                        bmMap.put("comment", bm.getComment());
                        bmMap.put("type", bm.getTypeString());
                        bookmarks.add(bmMap);
                    }
                }
            } else {
                // Iterate all bookmarks
                BookmarkType[] types = bookmarkManager.getBookmarkTypes();
                for (BookmarkType type : types) {
                    Iterator<Bookmark> iter = bookmarkManager.getBookmarksIterator(type.getTypeString());
                    while (iter.hasNext()) {
                        Bookmark bm = iter.next();
                        if (category == null || category.isEmpty() || bm.getCategory().equals(category)) {
                            Map<String, String> bmMap = new HashMap<>();
                            bmMap.put("address", bm.getAddress().toString());
                            bmMap.put("category", bm.getCategory());
                            bmMap.put("comment", bm.getComment());
                            bmMap.put("type", bm.getTypeString());
                            bookmarks.add(bmMap);
                        }
                    }
                }
            }

            // Build JSON response
            StringBuilder response = new StringBuilder();
            response.append("{\"success\": true, \"bookmarks\": [");
            for (int i = 0; i < bookmarks.size(); i++) {
                if (i > 0) response.append(", ");
                Map<String, String> bm = bookmarks.get(i);
                response.append("{");
                response.append("\"address\": \"").append(escapeJsonString(bm.get("address"))).append("\", ");
                response.append("\"category\": \"").append(escapeJsonString(bm.get("category"))).append("\", ");
                response.append("\"comment\": \"").append(escapeJsonString(bm.get("comment"))).append("\", ");
                response.append("\"type\": \"").append(escapeJsonString(bm.get("type"))).append("\"");
                response.append("}");
            }
            response.append("], \"count\": ").append(bookmarks.size()).append("}");

            return Response.text(response.toString());

        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    /**
     * Delete a bookmark at an address with optional category filter.
     */
    @McpTool(value = "/delete_bookmark", description = "Delete a bookmark at the specified address", method = McpTool.Method.POST)

    public Response deleteBookmark(

            @Param(value = "address") String addressStr,

            @Param(value = "category") String category) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) {
            return Response.err("No program loaded");
        }
        if (addressStr == null || addressStr.isEmpty()) {
            return Response.err("Address is required");
        }

        try {
            Address addr = program.getAddressFactory().getAddress(addressStr);
            if (addr == null) {
                return Response.err("Invalid address: " + addressStr);
            }

            BookmarkManager bookmarkManager = program.getBookmarkManager();

            int transactionId = program.startTransaction("Delete bookmark at " + addressStr);
            try {
                int deleted = 0;
                Bookmark[] bms = bookmarkManager.getBookmarks(addr);

                for (Bookmark bm : bms) {
                    if (category == null || category.isEmpty() || bm.getCategory().equals(category)) {
                        bookmarkManager.removeBookmark(bm);
                        deleted++;
                    }
                }

                program.endTransaction(transactionId, true);
                return Response.text("{\"success\": true, \"deleted\": " + deleted + ", \"address\": \"" + escapeJsonString(addr.toString()) + "\"}");

            } catch (Exception e) {
                program.endTransaction(transactionId, false);
                throw e;
            }

        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    /**
     * Run a Ghidra script with enhanced output capture and JSON response.
     * Locates the script in standard directories, executes it, and returns structured results.
     */
    @McpTool(value = "/run_ghidra_script", description = "Run a Ghidra script by name and capture all output including errors", method = McpTool.Method.POST)

    public Response runGhidraScriptWithCapture(

            @Param(value = "script_name") String scriptName,

            @Param(value = "args") String scriptArgs,

            @Param(value = "timeoutSeconds", type = "integer") int timeoutSeconds,

            @Param(value = "captureOutput", type = "boolean") boolean captureOutput) {
        if (scriptName == null || scriptName.isEmpty()) {
            return Response.err("Script name is required");
        }

        Program program = programProvider.getCurrentProgram();
        if (program == null) {
            return Response.err("No program loaded");
        }

        try {
            // Locate the script file - search Ghidra's standard script directories
            java.io.File scriptFile = null;
            String filename = scriptName;
            boolean hasExtension = scriptName.contains(".");

            String[] searchDirs = {
                System.getProperty("user.home") + "/ghidra_scripts",
                System.getProperty("user.dir") + "/ghidra_scripts",
                "./ghidra_scripts"
            };

            String[] extensions = hasExtension ? new String[]{""} : new String[]{".java", ".py", ""};

            for (String dirPath : searchDirs) {
                if (dirPath == null) continue;
                for (String ext : extensions) {
                    java.io.File candidate = new java.io.File(dirPath, filename + ext);
                    if (candidate.exists()) {
                        scriptFile = candidate;
                        break;
                    }
                }
                if (scriptFile != null) break;
            }

            // Also try as absolute path
            if (scriptFile == null) {
                java.io.File candidate = new java.io.File(scriptName);
                if (candidate.exists()) {
                    scriptFile = candidate;
                }
            }

            if (scriptFile == null) {
                StringBuilder searched = new StringBuilder();
                for (String dir : searchDirs) {
                    if (dir != null) searched.append(dir).append(", ");
                }
                return Response.err("Script '" + scriptName + "' not found. Searched: " + searched);
            }

            // Execute the script via the existing execution method
            long startTime = System.currentTimeMillis();
            Response scriptResponse = runGhidraScript(scriptFile.getAbsolutePath(), scriptArgs);
            double executionTime = (System.currentTimeMillis() - startTime) / 1000.0;

            // Extract the text content from the Response
            String output = "";
            if (scriptResponse instanceof Response.Text t) {
                output = t.content();
            } else if (scriptResponse instanceof Response.Err e) {
                output = e.message();
            }

            boolean succeeded = output.contains("SCRIPT COMPLETED SUCCESSFULLY");

            // Build JSON response
            StringBuilder response = new StringBuilder();
            response.append("{");
            response.append("\"success\": ").append(succeeded).append(", ");
            response.append("\"script_name\": \"").append(escapeJsonString(scriptName)).append("\", ");
            response.append("\"script_path\": \"").append(escapeJsonString(scriptFile.getAbsolutePath())).append("\", ");
            response.append("\"execution_time_seconds\": ").append(String.format("%.2f", executionTime)).append(", ");
            response.append("\"console_output\": \"").append(escapeJsonString(output)).append("\"");
            response.append("}");

            return Response.text(response.toString());

        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    // ========================================================================
    // JSON Helpers
    // ========================================================================

    /**
     * Serialize a List of objects to proper JSON string.
     * Handles Map objects within the list.
     */
    private String serializeListToJson(List<?> list) {
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < list.size(); i++) {
            if (i > 0) sb.append(",");
            Object item = list.get(i);
            if (item instanceof String) {
                sb.append("\"").append(escapeJsonString((String) item)).append("\"");
            } else if (item instanceof Number) {
                sb.append(item);
            } else if (item instanceof Map) {
                sb.append(serializeMapToJson((Map<?, ?>) item));
            } else if (item instanceof List) {
                sb.append(serializeListToJson((List<?>) item));
            } else {
                sb.append("\"").append(escapeJsonString(item.toString())).append("\"");
            }
        }
        sb.append("]");
        return sb.toString();
    }

    /**
     * Serialize a Map to proper JSON object.
     */
    private String serializeMapToJson(Map<?, ?> map) {
        StringBuilder sb = new StringBuilder("{");
        boolean first = true;
        for (Map.Entry<?, ?> entry : map.entrySet()) {
            if (!first) sb.append(",");
            first = false;
            sb.append("\"").append(escapeJsonString(entry.getKey().toString())).append("\":");
            Object value = entry.getValue();
            if (value instanceof String) {
                sb.append("\"").append(escapeJsonString((String) value)).append("\"");
            } else if (value instanceof Number) {
                sb.append(value);
            } else if (value instanceof Map) {
                sb.append(serializeMapToJson((Map<?, ?>) value));
            } else if (value instanceof List) {
                sb.append(serializeListToJson((List<?>) value));
            } else if (value instanceof Boolean) {
                sb.append(value);
            } else if (value == null) {
                sb.append("null");
            } else {
                sb.append("\"").append(escapeJsonString(value.toString())).append("\"");
            }
        }
        sb.append("}");
        return sb.toString();
    }

    /**
     * Escape special characters in JSON string values.
     */
    private String escapeJsonString(String str) {
        if (str == null) return "";
        return str.replace("\\", "\\\\")
                  .replace("\"", "\\\"")
                  .replace("\n", "\\n")
                  .replace("\r", "\\r")
                  .replace("\t", "\\t");
    }

    // ========================================================================
    // Script Generation
    // ========================================================================

    /**
     * Generate script content based on workflow type and parameters.
     * Dispatches to specific script generators based on workflowType.
     */
    public Response generateScriptContent(String purpose, String workflowType, Map<String, Object> parameters) {
        if (parameters == null) {
            parameters = new HashMap<>();
        }

        switch (workflowType) {
            case "document_functions":
                return Response.text(generateDocumentFunctionsScript(purpose, parameters));
            case "fix_ordinals":
                return Response.text(generateFixOrdinalsScript(purpose, parameters));
            case "bulk_rename":
                return Response.text(generateBulkRenameScript(purpose, parameters));
            case "analyze_structures":
                return Response.text(generateAnalyzeStructuresScript(purpose, parameters));
            case "find_patterns":
                return Response.text(generateFindPatternsScript(purpose, parameters));
            case "custom":
            default:
                return Response.text(generateCustomScript(purpose, parameters));
        }
    }

    private String generateDocumentFunctionsScript(String purpose, Map<String, Object> parameters) {
        return "import ghidra.app.script.GhidraScript;\n" +
               "import ghidra.program.model.listing.Function;\n" +
               "import ghidra.program.model.listing.FunctionManager;\n\n" +
               "public class DocumentFunctions extends GhidraScript {\n" +
               "    public void run() throws Exception {\n" +
               "        FunctionManager funcMgr = currentProgram.getFunctionManager();\n" +
               "        int documentedCount = 0;\n" +
               "        \n" +
               "        // Purpose: " + purpose + "\n" +
               "        for (Function func : funcMgr.getFunctions(true)) {\n" +
               "            try {\n" +
               "                // Add custom documentation logic here\n" +
               "                // Example: set_plate_comment(func.getEntryPoint(), \"Documented: \" + func.getName());\n" +
               "                documentedCount++;\n" +
               "                \n" +
               "                if (documentedCount % 100 == 0) {\n" +
               "                    println(\"Processed \" + documentedCount + \" functions\");\n" +
               "                }\n" +
               "            } catch (Exception e) {\n" +
               "                println(\"Error processing \" + func.getName() + \": \" + e.getMessage());\n" +
               "            }\n" +
               "        }\n" +
               "        \n" +
               "        println(\"Document functions workflow complete! Processed \" + documentedCount + \" functions.\");\n" +
               "    }\n" +
               "}\n";
    }

    private String generateFixOrdinalsScript(String purpose, Map<String, Object> parameters) {
        return "import ghidra.app.script.GhidraScript;\n" +
               "import ghidra.program.model.symbol.ExternalManager;\n" +
               "import ghidra.program.model.symbol.ExternalLocation;\n" +
               "import ghidra.program.model.symbol.ExternalLocationIterator;\n\n" +
               "public class FixOrdinalImports extends GhidraScript {\n" +
               "    public void run() throws Exception {\n" +
               "        ExternalManager extMgr = currentProgram.getExternalManager();\n" +
               "        int fixedCount = 0;\n" +
               "        \n" +
               "        // Purpose: " + purpose + "\n" +
               "        for (String libName : extMgr.getExternalLibraryNames()) {\n" +
               "            ExternalLocationIterator iter = extMgr.getExternalLocations(libName);\n" +
               "            while (iter.hasNext()) {\n" +
               "                ExternalLocation extLoc = iter.next();\n" +
               "                String label = extLoc.getLabel();\n" +
               "                \n" +
               "                // Check if this is an ordinal import (e.g., \"Ordinal_123\")\n" +
               "                if (label.startsWith(\"Ordinal_\")) {\n" +
               "                    try {\n" +
               "                        // Add logic to determine correct function name from ordinal\n" +
               "                        // Then rename: extLoc.setName(..., correctName, SourceType.USER_DEFINED);\n" +
               "                        fixedCount++;\n" +
               "                    } catch (Exception e) {\n" +
               "                        println(\"Error fixing ordinal \" + label + \": \" + e.getMessage());\n" +
               "                    }\n" +
               "                }\n" +
               "            }\n" +
               "        }\n" +
               "        \n" +
               "        println(\"Fix ordinals workflow complete! Fixed \" + fixedCount + \" ordinal imports.\");\n" +
               "    }\n" +
               "}\n";
    }

    private String generateBulkRenameScript(String purpose, Map<String, Object> parameters) {
        return "import ghidra.app.script.GhidraScript;\n" +
               "import ghidra.program.model.symbol.SymbolTable;\n" +
               "import ghidra.program.model.symbol.Symbol;\n" +
               "import ghidra.program.model.symbol.SourceType;\n\n" +
               "public class BulkRenameSymbols extends GhidraScript {\n" +
               "    public void run() throws Exception {\n" +
               "        SymbolTable symTable = currentProgram.getSymbolTable();\n" +
               "        int renamedCount = 0;\n" +
               "        \n" +
               "        // Purpose: " + purpose + "\n" +
               "        for (Symbol symbol : symTable.getAllSymbols(true)) {\n" +
               "            try {\n" +
               "                String currentName = symbol.getName();\n" +
               "                // Add pattern matching logic here\n" +
               "                // Example: if (currentName.matches(\"var_.*\")) { newName = ... }\n" +
               "                renamedCount++;\n" +
               "            } catch (Exception e) {\n" +
               "                println(\"Error renaming symbol: \" + e.getMessage());\n" +
               "            }\n" +
               "        }\n" +
               "        \n" +
               "        println(\"Bulk rename workflow complete! Renamed \" + renamedCount + \" symbols.\");\n" +
               "    }\n" +
               "}\n";
    }

    private String generateAnalyzeStructuresScript(String purpose, Map<String, Object> parameters) {
        return "import ghidra.app.script.GhidraScript;\n" +
               "import ghidra.program.model.data.DataType;\n" +
               "import ghidra.program.model.data.DataTypeManager;\n" +
               "import ghidra.program.model.data.Structure;\n\n" +
               "public class AnalyzeStructures extends GhidraScript {\n" +
               "    public void run() throws Exception {\n" +
               "        DataTypeManager dtMgr = currentProgram.getDataTypeManager();\n" +
               "        int analyzedCount = 0;\n" +
               "        \n" +
               "        // Purpose: " + purpose + "\n" +
               "        for (DataType dt : dtMgr.getAllDataTypes()) {\n" +
               "            if (dt instanceof Structure) {\n" +
               "                try {\n" +
               "                    Structure struct = (Structure) dt;\n" +
               "                    // Add analysis logic here\n" +
               "                    analyzedCount++;\n" +
               "                } catch (Exception e) {\n" +
               "                    println(\"Error analyzing \" + dt.getName() + \": \" + e.getMessage());\n" +
               "                }\n" +
               "            }\n" +
               "        }\n" +
               "        \n" +
               "        println(\"Analyze structures workflow complete! Analyzed \" + analyzedCount + \" structures.\");\n" +
               "    }\n" +
               "}\n";
    }

    private String generateFindPatternsScript(String purpose, Map<String, Object> parameters) {
        return "import ghidra.app.script.GhidraScript;\n" +
               "import ghidra.program.model.listing.Function;\n" +
               "import ghidra.program.model.listing.FunctionManager;\n\n" +
               "public class FindPatterns extends GhidraScript {\n" +
               "    public void run() throws Exception {\n" +
               "        FunctionManager funcMgr = currentProgram.getFunctionManager();\n" +
               "        int foundCount = 0;\n" +
               "        \n" +
               "        // Purpose: " + purpose + "\n" +
               "        for (Function func : funcMgr.getFunctions(true)) {\n" +
               "            try {\n" +
               "                // Add pattern matching logic here\n" +
               "                // Example: if (matchesPattern(func)) { handleMatch(func); }\n" +
               "                foundCount++;\n" +
               "            } catch (Exception e) {\n" +
               "                println(\"Error processing \" + func.getName() + \": \" + e.getMessage());\n" +
               "            }\n" +
               "        }\n" +
               "        \n" +
               "        println(\"Find patterns workflow complete! Found \" + foundCount + \" matching patterns.\");\n" +
               "    }\n" +
               "}\n";
    }

    private String generateCustomScript(String purpose, Map<String, Object> parameters) {
        return "import ghidra.app.script.GhidraScript;\n" +
               "import ghidra.program.model.listing.Function;\n" +
               "import ghidra.program.model.listing.FunctionManager;\n\n" +
               "public class CustomAnalysis extends GhidraScript {\n" +
               "    public void run() throws Exception {\n" +
               "        // Purpose: " + purpose + "\n" +
               "        println(\"Custom analysis script started...\");\n" +
               "        \n" +
               "        // Add your custom analysis logic here\n" +
               "        FunctionManager funcMgr = currentProgram.getFunctionManager();\n" +
               "        int count = 0;\n" +
               "        \n" +
               "        for (Function func : funcMgr.getFunctions(true)) {\n" +
               "            // Add logic here\n" +
               "            count++;\n" +
               "        }\n" +
               "        \n" +
               "        println(\"Custom analysis complete! Processed \" + count + \" items.\");\n" +
               "    }\n" +
               "}\n";
    }

    /**
     * Generate a script filename based on the workflow type.
     */
    public String generateScriptName(String workflowType) {
        switch (workflowType) {
            case "document_functions":
                return "DocumentFunctions.java";
            case "fix_ordinals":
                return "FixOrdinalImports.java";
            case "bulk_rename":
                return "BulkRenameSymbols.java";
            case "analyze_structures":
                return "AnalyzeStructures.java";
            case "find_patterns":
                return "FindPatterns.java";
            default:
                return "CustomAnalysis.java";
        }
    }
}
