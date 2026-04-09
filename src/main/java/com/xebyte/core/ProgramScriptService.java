package com.xebyte.core;

import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.util.importer.AutoImporter;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.LoadResults;
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;

import javax.swing.SwingUtilities;
import java.io.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Service for program management, script execution, memory, and bookmark operations.
 * Extracted from GhidraMCPPlugin as part of v4.0.0 refactor.
 */
@McpToolGroup(value = "program", description = "Program management, script execution, memory read, bookmarks, save")
public class ProgramScriptService {

    private final ProgramProvider programProvider;
    private final ThreadingStrategy threadingStrategy;

    public ProgramScriptService(ProgramProvider programProvider, ThreadingStrategy threadingStrategy) {
        this.programProvider = programProvider;
        this.threadingStrategy = threadingStrategy;
    }

    /**
     * Retrieve the PluginTool from the ProgramProvider if it is a GuiProgramProvider/FrontEndProgramProvider.
     * Returns null when running headless.
     */
    private PluginTool getToolFromProvider() {
        if (programProvider instanceof GuiProgramProvider gpp) {
            return gpp.getTool();
        }
        if (programProvider instanceof FrontEndProgramProvider fpp) {
            return fpp.getTool();
        }
        if (programProvider instanceof MultiToolProgramProvider mtp) {
            return mtp.getActiveTool();
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
    public Response getMetadata() {
        return getMetadata(null);
    }

    @McpTool(path = "/get_metadata", description = "Get program metadata", category = "program")
    public Response getMetadata(
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

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
    public Response saveCurrentProgram() {
        return saveCurrentProgram(null);
    }

    @McpTool(path = "/save_program", description = "Save current program", category = "program")
    public Response saveCurrentProgram(
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        final AtomicReference<Map<String, Object>> resultData = new AtomicReference<>();
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
                    resultData.set(JsonHelper.mapOf(
                        "success", true,
                        "program", program.getName(),
                        "message", "Program saved successfully"
                    ));
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

        return resultData.get() != null ? Response.ok(resultData.get()) : Response.err("Unknown failure");
    }

    /**
     * List all currently open programs in Ghidra.
     */
    @McpTool(path = "/list_open_programs", description = "List all open programs. If more than one program is listed, always pass the program name explicitly in subsequent tool calls — omitting it will silently target the active program, which may not be the intended one.", category = "program")
    public Response listOpenPrograms() {
        Program[] programs = programProvider.getAllOpenPrograms();
        if (programs == null || programs.length == 0) {
            return Response.ok(JsonHelper.mapOf("programs", List.of(), "count", 0, "current_program", ""));
        }

        Program currentProgram = programProvider.resolveProgram(null);

        List<Map<String, Object>> programList = new ArrayList<>();
        for (Program prog : programs) {
            int physicalSpaceCount = ServiceUtils.getPhysicalSpaceCount(prog);
            programList.add(JsonHelper.mapOf(
                "name", prog.getName(),
                "path", prog.getDomainFile().getPathname(),
                "is_current", prog == currentProgram,
                "executable_path", prog.getExecutablePath() != null ? prog.getExecutablePath() : "",
                "language", prog.getLanguageID().getIdAsString(),
                "compiler", prog.getCompilerSpec().getCompilerSpecID().getIdAsString(),
                "image_base", prog.getImageBase().toString(),
                "memory_size", prog.getMemory().getSize(),
                "function_count", prog.getFunctionManager().getFunctionCount(),
                "has_multiple_address_spaces", physicalSpaceCount > 1
            ));
        }

        return Response.ok(JsonHelper.mapOf(
            "programs", programList,
            "count", programs.length,
            "current_program", currentProgram != null ? currentProgram.getName() : ""
        ));
    }

    public Response getAddressSpaces() {
        return getAddressSpaces(null);
    }

    /**
     * List all physical address spaces in the program.
     * Returns only RAM and CODE spaces; excludes pseudo-spaces (EXTERNAL, STACK, etc.)
     * and overlay spaces. Useful for embedded/microcontroller targets where multiple
     * address spaces exist and plain hex addresses may be ambiguous.
     */
    @McpTool(path = "/get_address_spaces",
             description = "List all physical address spaces in the program. On programs with multiple "
                         + "address spaces (e.g., embedded targets), use the returned space names to "
                         + "prefix addresses (e.g., mem:1000, code:ff00) for unambiguous resolution. "
                         + "Also check addressable_unit_size: a value > 1 means the space is word-addressed "
                         + "(e.g., AVR code space uses 2-byte words). MCP tools and Ghidra both use word "
                         + "addresses natively for such spaces — code:001478 is word 0x1478, not byte 0x1478. "
                         + "Do NOT multiply or divide addresses seen in Ghidra output; use them as-is.",
             category = "program")
    public Response getAddressSpaces(
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        List<Map<String, Object>> spaces = buildAddressSpacesList(program);
        return Response.ok(JsonHelper.mapOf("address_spaces", spaces, "count", spaces.size()));
    }

    private List<Map<String, Object>> buildAddressSpacesList(Program program) {
        List<Map<String, Object>> spaces = new ArrayList<>();
        AddressSpace defaultSpace = program.getAddressFactory().getDefaultAddressSpace();
        for (AddressSpace space : program.getAddressFactory().getAddressSpaces()) {
            if (space.isOverlaySpace()) continue;
            int type = space.getType();
            if (type != AddressSpace.TYPE_RAM && type != AddressSpace.TYPE_CODE) continue;
            long maxOff = space.getMaxAddress().getOffset();
            long minOff = space.getMinAddress().getOffset();
            // Safe unsigned size: (maxOff - minOff + 1) overflows for full 64-bit spaces (maxOff == -1L)
            long size = maxOff - minOff + 1;
            if (size == 0 && Long.compareUnsigned(maxOff, minOff) > 0) {
                size = Long.MAX_VALUE; // Full 64-bit space; clamp to avoid emitting 0
            }
            int unitSize = space.getAddressableUnitSize();
            // size_bytes: guard against overflow when size is clamped or unitSize > 1
            long sizeBytes = (size == Long.MAX_VALUE || unitSize <= 0)
                    ? Long.MAX_VALUE
                    : size * unitSize;
            spaces.add(JsonHelper.mapOf(
                "name",                  space.getName(),
                "start",                 space.getMinAddress().toString(false),
                "end",                   space.getMaxAddress().toString(false),
                "size",                  size,
                "addressable_unit_size", unitSize,
                "size_bytes",            sizeBytes,
                "address_size_bits",     space.getSize(),
                "is_default",            space == defaultSpace
            ));
        }
        return spaces;
    }

    /**
     * Get detailed information about the currently active program.
     */
    public Response getCurrentProgramInfo() {
        return getCurrentProgramInfo(null);
    }

    @McpTool(path = "/get_current_program_info", description = "Get detailed info about the active program. When multiple programs are open, call this first to confirm which program will receive tool calls that omit the program argument.", category = "program")
    public Response getCurrentProgramInfo(
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        List<Map<String, Object>> addressSpaces = buildAddressSpacesList(program);
        boolean multiSpace = addressSpaces.size() > 1;

        Map<String, Object> info = new java.util.LinkedHashMap<>();
        info.put("name", program.getName());
        info.put("path", program.getDomainFile().getPathname());
        info.put("executable_path", program.getExecutablePath() != null ? program.getExecutablePath() : "");
        info.put("executable_format", program.getExecutableFormat());
        info.put("language", program.getLanguageID().getIdAsString());
        info.put("compiler", program.getCompilerSpec().getCompilerSpecID().getIdAsString());
        info.put("address_size", program.getAddressFactory().getDefaultAddressSpace().getSize());
        info.put("image_base", program.getImageBase().toString());
        info.put("min_address", program.getMinAddress() != null ? program.getMinAddress().toString() : "null");
        info.put("max_address", program.getMaxAddress() != null ? program.getMaxAddress().toString() : "null");
        info.put("memory_size", program.getMemory().getSize());
        info.put("function_count", program.getFunctionManager().getFunctionCount());
        info.put("symbol_count", program.getSymbolTable().getNumSymbols());
        info.put("data_type_count", program.getDataTypeManager().getDataTypeCount(true));
        info.put("creation_date", program.getCreationDate() != null ? program.getCreationDate().toString() : "unknown");
        info.put("memory_block_count", program.getMemory().getBlocks().length);
        info.put("address_spaces", addressSpaces);
        info.put("has_multiple_address_spaces", multiSpace);
        if (multiSpace) {
            info.put("address_space_warning",
                "This program has multiple address spaces. Plain hex addresses will resolve to the "
                + "default space and may be incorrect. Use <space>:<hex> format (e.g., mem:1000) "
                + "or call get_address_spaces first.");
        }
        return Response.ok(info);
    }

    /**
     * Switch MCP context to a different open program by name.
     */
    @McpTool(path = "/switch_program", description = "Switch MCP context to a different program", category = "program")
    public Response switchProgram(
            @Param(value = "program", description = "Program name to switch to") String programName) {
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
            List<String> availablePrograms = new ArrayList<>();
            for (Program prog : programs) {
                availablePrograms.add(prog.getName());
            }
            return Response.ok(JsonHelper.mapOf(
                "error", "Program not found: " + programName,
                "available_programs", availablePrograms
            ));
        }

        // Switch to the target program
        programProvider.setCurrentProgram(targetProgram);

        return Response.ok(JsonHelper.mapOf(
            "success", true,
            "switched_to", targetProgram.getName(),
            "path", targetProgram.getDomainFile().getPathname()
        ));
    }

    /**
     * List all files in the current Ghidra project.
     */
    @McpTool(path = "/list_project_files", description = "List files in the current project", category = "program")
    public Response listProjectFiles(
            @Param(value = "folder", description = "Project folder path") String folderPath) {
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

        // List subfolders
        ghidra.framework.model.DomainFolder[] subfolders = targetFolder.getFolders();
        List<String> folderNames = new ArrayList<>();
        for (ghidra.framework.model.DomainFolder subfolder : subfolders) {
            folderNames.add(subfolder.getName());
        }

        // List files in folder
        ghidra.framework.model.DomainFile[] files = targetFolder.getFiles();
        List<Map<String, Object>> fileList = new ArrayList<>();
        for (ghidra.framework.model.DomainFile file : files) {
            fileList.add(JsonHelper.mapOf(
                "name", file.getName(),
                "path", file.getPathname(),
                "content_type", file.getContentType(),
                "version", file.getVersion(),
                "is_read_only", file.isReadOnly(),
                "is_versioned", file.isVersioned()
            ));
        }

        return Response.ok(JsonHelper.mapOf(
            "project_name", project.getName(),
            "current_folder", targetFolder.getPathname(),
            "folders", folderNames,
            "files", fileList
        ));
    }

    /**
     * Open a program from the current project by path.
     */
    public Response openProgramFromProject(String path) {
        return openProgramFromProject(path, false);
    }

    @McpTool(path = "/open_program", description = "Open a program from the current project", category = "program")
    public Response openProgramFromProject(
            @Param(value = "path", description = "Program path in project") String path,
            @Param(value = "auto_analyze", defaultValue = "false", description = "Run auto-analysis") boolean autoAnalyze) {
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
                return Response.ok(JsonHelper.mapOf(
                    "success", true,
                    "message", "Program already open, switched to it",
                    "name", prog.getName(),
                    "path", path
                ));
            }
        }

        // Open the program
        try {
            // Find a ProgramManager from an existing CodeBrowser, or launch one
            ProgramManager pm = findOrCreateProgramManager(tool);
            if (pm == null) {
                return Response.err("Could not find or create a CodeBrowser tool");
            }

            Program program = (Program) domainFile.getDomainObject(
                tool, false, false, ghidra.util.task.TaskMonitor.DUMMY);
            if (program == null) {
                return Response.err("Failed to open program: " + path);
            }

            // Add to tool and set as current
            pm.openProgram(program);
            pm.setCurrentProgram(program);

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

            return Response.ok(JsonHelper.mapOf(
                "success", true,
                "message", "Program opened successfully",
                "name", program.getName(),
                "path", path,
                "auto_analyzed", analyzed,
                "function_count", program.getFunctionManager().getFunctionCount()
            ));
        } catch (Exception e) {
            return Response.err("Failed to open program: " + e.getMessage());
        }
    }

    // ========================================================================
    // Import & Analysis

    @McpTool(path = "/import_file", method = "POST",
            description = "Import a binary file from disk into the current Ghidra project and open it. "
                + "For raw firmware binaries, specify language (e.g. 'ARM:LE:32:Cortex') and optionally compiler_spec (e.g. 'default').",
            category = "program")
    public Response importFile(
            @Param(value = "file_path", source = ParamSource.BODY, description = "Absolute path to the binary file on disk") String filePath,
            @Param(value = "project_folder", source = ParamSource.BODY, defaultValue = "/", description = "Destination folder in the Ghidra project") String projectFolder,
            @Param(value = "language", source = ParamSource.BODY, defaultValue = "", description = "Language ID for raw binaries (e.g. 'ARM:LE:32:Cortex', 'x86:LE:64:default'). If omitted, auto-detect.") String languageId,
            @Param(value = "compiler_spec", source = ParamSource.BODY, defaultValue = "", description = "Compiler spec ID (e.g. 'default', 'gcc', 'windows'). If omitted, uses language default.") String compilerSpecId,
            @Param(value = "auto_analyze", source = ParamSource.BODY, defaultValue = "true", description = "Start auto-analysis after import") boolean autoAnalyze) {

        if (filePath == null || filePath.trim().isEmpty()) {
            return Response.err("file_path is required");
        }

        File file = new File(filePath);
        if (!file.exists()) {
            return Response.err("File not found: " + filePath);
        }

        PluginTool tool = getToolFromProvider();
        if (tool == null) {
            return Response.err("Import requires GUI mode (PluginTool not available)");
        }

        ghidra.framework.model.Project project = tool.getProject();
        if (project == null) {
            return Response.err("No project is currently open");
        }

        boolean hasLanguage = languageId != null && !languageId.isEmpty();

        try {
            MessageLog log = new MessageLog();
            Program program;

            if (hasLanguage) {
                // Resolve language and compiler spec
                ghidra.program.model.lang.LanguageService langService =
                    ghidra.program.util.DefaultLanguageService.getLanguageService();
                ghidra.program.model.lang.Language language = langService.getLanguage(
                    new ghidra.program.model.lang.LanguageID(languageId));

                ghidra.program.model.lang.CompilerSpec compilerSpec;
                if (compilerSpecId != null && !compilerSpecId.isEmpty()) {
                    compilerSpec = language.getCompilerSpecByID(
                        new ghidra.program.model.lang.CompilerSpecID(compilerSpecId));
                } else {
                    compilerSpec = language.getDefaultCompilerSpec();
                }

                // Import as raw binary with explicit language/compiler spec
                ghidra.app.util.opinion.Loaded<Program> loaded = AutoImporter.importAsBinary(
                    file, project, projectFolder, language, compilerSpec,
                    this, log, ghidra.util.task.TaskMonitor.DUMMY);

                if (loaded == null) {
                    return Response.err("Import failed: no results. Log: " + log);
                }
                // getDomainObject(consumer) registers us as a consumer so the program stays open
                program = loaded.getDomainObject(this);
                if (program == null) {
                    return Response.err("Import failed: no primary program. Log: " + log);
                }
                // Save to project folder (creates DomainFile)
                loaded.save(ghidra.util.task.TaskMonitor.DUMMY);
                loaded.release(this);
            } else {
                // Auto-detect format
                LoadResults<Program> loadResults = AutoImporter.importByUsingBestGuess(
                    file, project, projectFolder,
                    this, log, ghidra.util.task.TaskMonitor.DUMMY);

                if (loadResults == null) {
                    return Response.err("Import failed: no load spec found. Specify 'language' for raw binaries. Log: " + log);
                }
                program = loadResults.getPrimaryDomainObject();
                if (program == null) {
                    return Response.err("Import failed: no primary program. Log: " + log);
                }
                // Save to project folder before releasing (prevents "Database is closed")
                loadResults.save(ghidra.util.task.TaskMonitor.DUMMY);
                loadResults.release(this);
            }

            // Suppress the "Analysis Options" dialog — we handle analysis programmatically
            ghidra.program.util.GhidraProgramUtilities.markProgramNotToAskToAnalyze(program);

            // Open in CodeBrowser
            ProgramManager pm = findOrCreateProgramManager(tool);
            if (pm == null) {
                return Response.err("Could not find or create a CodeBrowser tool");
            }

            pm.openProgram(program);
            pm.setCurrentProgram(program);

            // Optionally trigger auto-analysis
            boolean analyzing = false;
            if (autoAnalyze) {
                try {
                    AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
                    mgr.reAnalyzeAll(null);
                    mgr.startAnalysis(ghidra.util.task.TaskMonitor.DUMMY);
                    analyzing = true;
                } catch (Exception ae) {
                    Msg.warn(this, "Auto-analysis failed: " + ae.getMessage());
                }
            }

            return Response.ok(JsonHelper.mapOf(
                "success", true,
                "name", program.getName(),
                "path", program.getDomainFile().getPathname(),
                "language", program.getLanguageID().getIdAsString(),
                "analyzing", analyzing
            ));
        } catch (Exception e) {
            String msg = e.getMessage();
            if (msg == null || msg.isEmpty()) {
                msg = e.getClass().getName();
                // Include cause if available
                if (e.getCause() != null) {
                    msg += ": " + (e.getCause().getMessage() != null
                        ? e.getCause().getMessage() : e.getCause().getClass().getName());
                }
            }
            Msg.error(this, "Import failed", e);
            return Response.err("Import failed: " + msg);
        }
    }

    @McpTool(path = "/reanalyze", method = "POST", description = "Trigger full auto-analysis on a program", category = "program")
    public Response reanalyze(
            @Param(value = "program", defaultValue = "", description = "Program name (default: current program)") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        try {
            AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
            mgr.reAnalyzeAll(null);
            mgr.startAnalysis(ghidra.util.task.TaskMonitor.DUMMY);
            return Response.ok(JsonHelper.mapOf(
                "success", true,
                "name", program.getName(),
                "analyzing", true,
                "message", "Auto-analysis started for " + program.getName()
            ));
        } catch (Exception e) {
            return Response.err("Failed to start analysis: " + e.getMessage());
        }
    }

    @McpTool(path = "/analysis_status", description = "Get auto-analysis status for open programs", category = "program")
    public Response analysisStatus(
            @Param(value = "program", description = "Program name (omit for all open programs)") String programName) {

        Program[] allPrograms = programProvider.getAllOpenPrograms();
        if (allPrograms == null || allPrograms.length == 0) {
            return Response.err("No programs are currently open");
        }

        List<Map<String, Object>> results = new ArrayList<>();
        for (Program prog : allPrograms) {
            if (programName != null && !programName.isEmpty() && !prog.getName().equals(programName)) {
                continue;
            }
            boolean analyzing = false;
            try {
                AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(prog);
                analyzing = mgr.isAnalyzing();
            } catch (Exception e) {
                // May not have an analysis manager in headless mode
            }
            results.add(JsonHelper.mapOf(
                "name", prog.getName(),
                "analyzing", analyzing,
                "function_count", prog.getFunctionManager().getFunctionCount()
            ));
        }

        if (programName != null && !programName.isEmpty() && results.isEmpty()) {
            return Response.err("Program not found: " + programName);
        }

        if (results.size() == 1) {
            return Response.ok(results.get(0));
        }
        return Response.ok(JsonHelper.mapOf("programs", results));
    }

    // ========================================================================
    // Script Execution
    /**
     * Find an existing ProgramManager or launch a new CodeBrowser to get one.
     */
    private ProgramManager findOrCreateProgramManager(PluginTool tool) {
        // 1. Try the tool directly (works if it's a CodeBrowser)
        ProgramManager pm = tool.getService(ProgramManager.class);
        if (pm != null) return pm;

        // 2. Try MultiToolProgramProvider which searches across all running tools
        if (programProvider instanceof MultiToolProgramProvider mtp) {
            pm = mtp.findProgramManager();
            if (pm != null) return pm;
        }

        // 3. Launch a new CodeBrowser via the workspace
        try {
            ghidra.framework.model.Project project = tool.getProject();
            if (project != null) {
                ghidra.framework.model.ToolManager tm = project.getToolManager();
                if (tm != null) {
                    ghidra.framework.model.ToolTemplate template =
                        project.getLocalToolChest().getToolTemplate("CodeBrowser");
                    if (template != null) {
                        ghidra.framework.model.Workspace ws = tm.getActiveWorkspace();
                        PluginTool newTool = ws.runTool(template);
                        if (newTool != null) {
                            pm = newTool.getService(ProgramManager.class);
                            if (pm != null) return pm;
                        }
                    }
                }
            }
        } catch (Exception e) {
            Msg.warn(this, "Failed to launch CodeBrowser: " + e.getMessage());
        }

        return null;
    }

    // ========================================================================

    /**
     * Execute a Ghidra script by path with optional arguments.
     *
     * @param scriptPath Path to the script file
     * @param scriptArgs Optional space-separated arguments for the script
     * @return Script output or error message
     */
    public Response runGhidraScript(String scriptPath, String scriptArgs) {
        return runGhidraScript(scriptPath, scriptArgs, (String) null);
    }

    @McpTool(path = "/run_script", method = "POST", description = "Execute a Ghidra script by path", category = "program")
    public Response runGhidraScript(
            @Param(value = "script_path", source = ParamSource.BODY) String scriptPath,
            @Param(value = "args", source = ParamSource.BODY, defaultValue = "") String scriptArgs,
            @Param(value = "program", description = "Target program name", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

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
        } catch (Exception e) {
            resultMsg.append("ERROR: Failed to execute on Swing thread: ").append(e.getMessage()).append("\n");
            Msg.error(this, "Failed to execute on Swing thread", e);
        }

        return Response.text(resultMsg.toString());
    }

    @McpTool(path = "/run_script_inline", method = "POST", description = "Execute inline Ghidra script code. Pass the full Java source as the 'code' body parameter.", category = "program")
    public Response runScriptInline(
            @Param(value = "code", source = ParamSource.BODY) String code,
            @Param(value = "args", source = ParamSource.BODY, defaultValue = "") String args) {
        if (code == null || code.trim().isEmpty()) {
            return Response.err("code parameter required");
        }

        // Use unique class name per invocation so Ghidra recompiles each time.
        // If user provides their own class, extract its name for the filename.
        String className = "McpInline_" + Long.toHexString(System.nanoTime());
        java.util.regex.Matcher m = java.util.regex.Pattern
            .compile("public\\s+class\\s+(\\w+)").matcher(code);
        if (m.find()) {
            className = m.group(1);
        }

        // Write to ~/ghidra_scripts/ so OSGi classloader can find the source bundle
        File scriptsDir = new File(System.getProperty("user.home"), "ghidra_scripts");
        scriptsDir.mkdirs();

        // Pre-cleanup: remove stale McpInline_*.java files so Ghidra's per-directory
        // build state doesn't contaminate this run's output with old failures.
        //
        // Three cases handled:
        //  1. Oracle exists (McpInline_*.java_failed)  → confirmed failure from a
        //     previous run; delete both the .java and the oracle immediately.
        //  2. No oracle, file older than 60 s          → crash-orphaned (server died
        //     before the oracle could be written); delete as a safe fallback.
        //  3. No oracle, file is fresh                 → likely a concurrent parallel
        //     agent; leave it alone.
        // Also purge any orphaned oracles whose .java has already been deleted.
        long now = System.currentTimeMillis();
        File[] staleJava = scriptsDir.listFiles(
            (d, n) -> n.startsWith("McpInline_") && n.endsWith(".java"));
        if (staleJava != null) {
            for (File stale : staleJava) {
                File oracle = new File(scriptsDir, stale.getName() + "_failed");
                if (oracle.exists()) {
                    oracle.delete();
                    stale.delete();
                } else if (now - stale.lastModified() > 60_000L) {
                    stale.delete();
                }
            }
        }
        File[] orphanOracles = scriptsDir.listFiles(
            (d, n) -> n.startsWith("McpInline_") && n.endsWith(".java_failed"));
        if (orphanOracles != null) {
            for (File o : orphanOracles) {
                String javaName = o.getName().substring(0, o.getName().length() - "_failed".length());
                if (!new File(scriptsDir, javaName).exists()) o.delete();
            }
        }

        File tempScript = new File(scriptsDir, className + ".java");

        // Capture response so the finally block can decide success vs failure.
        Response[] responseHolder = {null};

        try {
            // If code doesn't contain a class definition, wrap it.
            // Hoist any import statements to file level so they don't land inside run().
            String scriptCode = code;
            if (!code.contains("extends GhidraScript")) {
                StringBuilder topImports = new StringBuilder("import ghidra.app.script.GhidraScript;\n");
                StringBuilder body = new StringBuilder();
                for (String line : code.split("\n", -1)) {
                    String stripped = line.stripLeading();
                    if (stripped.startsWith("import ") && stripped.endsWith(";")) {
                        topImports.append(stripped).append("\n");
                    } else {
                        body.append(line).append("\n");
                    }
                }
                scriptCode = topImports
                    + "public class " + className + " extends GhidraScript {\n"
                    + "    @Override\n"
                    + "    public void run() throws Exception {\n"
                    + body
                    + "    }\n"
                    + "}\n";
            }

            java.nio.file.Files.writeString(tempScript.toPath(), scriptCode);
            responseHolder[0] = runGhidraScript(tempScript.getAbsolutePath(), args);
            return responseHolder[0];
        } catch (Exception e) {
            return Response.err("Failed to create inline script: " + e.getMessage());
        } finally {
            if (!tempScript.exists()) {
                // File was never written or was already cleaned up — nothing to do.
            } else {
                boolean succeeded = responseHolder[0] != null
                    && responseHolder[0].toJson().contains("SCRIPT COMPLETED SUCCESSFULLY");
                if (succeeded) {
                    // Clean run: remove the source file immediately.
                    if (!tempScript.delete()) tempScript.deleteOnExit();
                } else {
                    // Failed run: leave .java on disk for next run's pre-cleanup to remove
                    // (which will clear Ghidra's build-state entry for it), and write an
                    // oracle so that cleanup is instant rather than time-delayed.
                    try {
                        File oracle = new File(scriptsDir, className + ".java_failed");
                        String failureInfo = responseHolder[0] != null
                            ? responseHolder[0].toJson()
                            : "exception before script execution";
                        java.nio.file.Files.writeString(oracle.toPath(), failureInfo);
                    } catch (Exception oracleEx) {
                        // Oracle write failed; fall back to immediate deletion so the file
                        // doesn't linger forever without a matching oracle.
                        if (!tempScript.delete()) tempScript.deleteOnExit();
                    }
                }
            }
        }
    }

    /**
     * List available Ghidra scripts.
     *
     * @param filter Optional filter string to match script names
     * @return JSON list of available scripts
     */
    @McpTool(path = "/list_scripts", description = "List available Ghidra scripts", category = "program")
    public Response listGhidraScripts(
            @Param(value = "filter", description = "Script name filter", defaultValue = "") String filter) {
        final AtomicReference<Map<String, Object>> resultData = new AtomicReference<>();
        final AtomicReference<String> errorMsg = new AtomicReference<>();

        try {
            SwingUtilities.invokeAndWait(() -> {
                try {
                    resultData.set(JsonHelper.mapOf(
                        "note", "Script listing requires Ghidra GUI access",
                        "filter", filter != null ? filter : "none",
                        "instructions", List.of(
                            "To view available scripts:",
                            "1. Open Ghidra's Script Manager (Window -> Script Manager)",
                            "2. Browse scripts by category",
                            "3. Use the search filter at the top"
                        ),
                        "common_script_locations", List.of(
                            "<ghidra_install>/Ghidra/Features/*/ghidra_scripts/",
                            "<user_home>/ghidra_scripts/"
                        )
                    ));
                } catch (Exception e) {
                    errorMsg.set(e.getMessage());
                    Msg.error(this, "Error in list scripts handler", e);
                }
            });
        } catch (Exception e) {
            return Response.err("Failed to execute on Swing thread: " + e.getMessage());
        }

        if (errorMsg.get() != null) {
            return Response.err(errorMsg.get());
        }
        return resultData.get() != null ? Response.ok(resultData.get()) : Response.err("Unknown failure");
    }

    // ========================================================================
    // Memory Operations
    // ========================================================================

    /**
     * Read memory at a specific address.
     */
    @McpTool(path = "/read_memory", description = "Read raw memory bytes. Always pass the 'program' argument to target the correct binary — especially when multiple programs are open. On programs with multiple address spaces (e.g., embedded targets), prefix addresses with the space name (mem:1000) to avoid ambiguous resolution.", category = "program")
    public Response readMemory(
            @Param(value = "address", paramType = "address",
                   description = "Address in the program. Accepts 0x<hex> (default space) or <space>:<hex> "
                               + "(e.g., mem:1000, code:ff00). Note: some programs — particularly "
                               + "embedded/microcontroller targets — are not address-space-agnostic; "
                               + "use get_address_spaces to discover spaces before assuming a plain hex "
                               + "address is unambiguous.") String addressStr,
            @Param(value = "length", defaultValue = "16", description = "Number of bytes") int length,
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        try {
            ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
            if (pe.hasError()) return pe.error();
            Program program = pe.program();

            Address address = ServiceUtils.parseAddress(program, addressStr);
            if (address == null) {
                return Response.err(ServiceUtils.getLastParseError());
            }

            Memory memory = program.getMemory();
            int MAX_READ_BYTES = 16 * 1024 * 1024; // 16 MB safety limit
            if (length <= 0 || length > MAX_READ_BYTES) {
                return Response.err("length must be between 1 and " + MAX_READ_BYTES + " bytes");
            }
            byte[] bytes = new byte[length];

            int bytesRead = memory.getBytes(address, bytes);

            List<Integer> dataList = new ArrayList<>();
            StringBuilder hexStr = new StringBuilder();
            for (int i = 0; i < bytesRead; i++) {
                dataList.add(bytes[i] & 0xFF);
                hexStr.append(String.format("%02x", bytes[i] & 0xFF));
            }

            Map<String, Object> memResult = new LinkedHashMap<>();
            memResult.putAll(ServiceUtils.addressToJson(address, program));
            memResult.put("length", bytesRead);
            memResult.put("data", dataList);
            memResult.put("hex", hexStr.toString());
            return Response.ok(memResult);

        } catch (Exception e) {
            return Response.err("Failed to read memory: " + e.getMessage());
        }
    }

    /**
     * Create an uninitialized memory block (e.g., for MMIO/peripheral regions).
     */
    public Response createMemoryBlock(String name, String addressStr, long size,
                                     boolean read, boolean write, boolean execute,
                                     boolean isVolatile, String comment) {
        return createMemoryBlock(name, addressStr, size, read, write, execute, isVolatile, comment, null);
    }

    @McpTool(path = "/create_memory_block", method = "POST", description = "Create a new memory block. On programs with multiple address spaces (e.g., embedded targets), prefix addresses with the space name (mem:1000) to avoid ambiguous resolution.", category = "program")
    public Response createMemoryBlock(
            @Param(value = "name", source = ParamSource.BODY) String name,
            @Param(value = "address", paramType = "address", source = ParamSource.BODY,
                   description = "Address in the program. Accepts 0x<hex> (default space) or <space>:<hex> "
                               + "(e.g., mem:1000, code:ff00). Note: some programs — particularly "
                               + "embedded/microcontroller targets — are not address-space-agnostic; "
                               + "use get_address_spaces to discover spaces before assuming a plain hex "
                               + "address is unambiguous.") String addressStr,
            @Param(value = "size", source = ParamSource.BODY, defaultValue = "0") long size,
            @Param(value = "read", source = ParamSource.BODY, defaultValue = "true") boolean read,
            @Param(value = "write", source = ParamSource.BODY, defaultValue = "true") boolean write,
            @Param(value = "execute", source = ParamSource.BODY, defaultValue = "false") boolean execute,
            @Param(value = "volatile", source = ParamSource.BODY, defaultValue = "false") boolean isVolatile,
            @Param(value = "comment", source = ParamSource.BODY, defaultValue = "") String comment,
            @Param(value = "program", description = "Target program name", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        if (name == null || name.isEmpty()) {
            return Response.err("name parameter required");
        }
        if (addressStr == null || addressStr.isEmpty()) {
            return Response.err("address parameter required");
        }
        if (size <= 0) {
            return Response.err("size must be positive");
        }

        // Resolve address before entering EDT lambda
        Address addr = ServiceUtils.parseAddress(program, addressStr);
        if (addr == null) {
            return Response.err(ServiceUtils.getLastParseError());
        }

        final AtomicReference<Map<String, Object>> resultData = new AtomicReference<>();
        final AtomicReference<String> errorMsg = new AtomicReference<>();

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Create memory block");
                boolean txSuccess = false;
                try {
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

                    String permissions = (read ? "r" : "-") + (write ? "w" : "-") + (execute ? "x" : "-");
                    resultData.set(JsonHelper.mapOf(
                        "success", true,
                        "name", name,
                        "start", block.getStart().toString(),
                        "end", block.getEnd().toString(),
                        "size", block.getSize(),
                        "permissions", permissions,
                        "volatile", isVolatile,
                        "message", "Memory block '" + name + "' created at " + addr
                    ));
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

        return resultData.get() != null ? Response.ok(resultData.get()) : Response.err("Unknown failure");
    }

    // ========================================================================
    // Bookmark Operations
    // ========================================================================

    /**
     * Set a bookmark at an address with category and comment.
     * Creates or updates the bookmark if one already exists at the address with the same category.
     */
    public Response setBookmark(String addressStr, String category, String comment) {
        return setBookmark(addressStr, category, comment, null);
    }

    @McpTool(path = "/set_bookmark", method = "POST", description = "Create or update a bookmark. On programs with multiple address spaces (e.g., embedded targets), prefix addresses with the space name (mem:1000) to avoid ambiguous resolution.", category = "program")
    public Response setBookmark(
            @Param(value = "address", paramType = "address", source = ParamSource.BODY,
                   description = "Address in the program. Accepts 0x<hex> (default space) or <space>:<hex> "
                               + "(e.g., mem:1000, code:ff00). Note: some programs — particularly "
                               + "embedded/microcontroller targets — are not address-space-agnostic; "
                               + "use get_address_spaces to discover spaces before assuming a plain hex "
                               + "address is unambiguous.") String addressStr,
            @Param(value = "category", source = ParamSource.BODY, defaultValue = "") String category,
            @Param(value = "comment", source = ParamSource.BODY, defaultValue = "") String comment,
            @Param(value = "program", description = "Target program name", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

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
            Address addr = ServiceUtils.parseAddress(program, addressStr);
            if (addr == null) {
                return Response.err(ServiceUtils.getLastParseError());
            }

            BookmarkManager bookmarkManager = program.getBookmarkManager();
            final String finalCategory = category;
            final String finalComment = comment;

            int transactionId = program.startTransaction("Set bookmark at " + addressStr);
            boolean txSuccess = false;
            try {
                // Check if bookmark already exists at this address with this category
                Bookmark existing = bookmarkManager.getBookmark(addr, BookmarkType.NOTE, finalCategory);
                if (existing != null) {
                    // Remove existing to update
                    bookmarkManager.removeBookmark(existing);
                }

                // Create new bookmark
                bookmarkManager.setBookmark(addr, BookmarkType.NOTE, finalCategory, finalComment);
                txSuccess = true;

                Map<String, Object> bmResult = new LinkedHashMap<>();
                bmResult.put("success", true);
                bmResult.putAll(ServiceUtils.addressToJson(addr, program));
                bmResult.put("category", finalCategory);
                bmResult.put("comment", finalComment);
                return Response.ok(bmResult);

            } catch (Exception e) {
                throw e;
            } finally {
                program.endTransaction(transactionId, txSuccess);
            }

        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    /**
     * List bookmarks, optionally filtered by category and/or address.
     */
    public Response listBookmarks(String category, String addressStr) {
        return listBookmarks(category, addressStr, null);
    }

    @McpTool(path = "/list_bookmarks", description = "List bookmarks with optional filter. On programs with multiple address spaces (e.g., embedded targets), prefix addresses with the space name (mem:1000) to avoid ambiguous resolution.", category = "program")
    public Response listBookmarks(
            @Param(value = "category", description = "Category filter (omit to return all categories)", defaultValue = "") String category,
            @Param(value = "address", paramType = "address", defaultValue = "",
                   description = "Address filter (omit to return all addresses). Accepts 0x<hex> (default space) or <space>:<hex> "
                               + "(e.g., mem:1000, code:ff00). Note: some programs — particularly "
                               + "embedded/microcontroller targets — are not address-space-agnostic; "
                               + "use get_address_spaces to discover spaces before assuming a plain hex "
                               + "address is unambiguous.") String addressStr,
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        try {
            BookmarkManager bookmarkManager = program.getBookmarkManager();
            List<Map<String, Object>> bookmarks = new ArrayList<>();

            // If specific address provided, get bookmarks at that address
            if (addressStr != null && !addressStr.isEmpty()) {
                Address addr = ServiceUtils.parseAddress(program, addressStr);
                if (addr == null) {
                    return Response.err(ServiceUtils.getLastParseError());
                }

                Bookmark[] bms = bookmarkManager.getBookmarks(addr);
                for (Bookmark bm : bms) {
                    if (category == null || category.isEmpty() || bm.getCategory().equals(category)) {
                        Map<String, Object> bmItem = new LinkedHashMap<>();
                        bmItem.putAll(ServiceUtils.addressToJson(bm.getAddress(), program));
                        bmItem.put("category", bm.getCategory());
                        bmItem.put("comment", bm.getComment());
                        bmItem.put("type", bm.getTypeString());
                        bookmarks.add(bmItem);
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
                            Map<String, Object> bmItem = new LinkedHashMap<>();
                            bmItem.putAll(ServiceUtils.addressToJson(bm.getAddress(), program));
                            bmItem.put("category", bm.getCategory());
                            bmItem.put("comment", bm.getComment());
                            bmItem.put("type", bm.getTypeString());
                            bookmarks.add(bmItem);
                        }
                    }
                }
            }

            return Response.ok(JsonHelper.mapOf(
                "success", true,
                "bookmarks", bookmarks,
                "count", bookmarks.size()
            ));

        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    /**
     * Delete a bookmark at an address with optional category filter.
     */
    public Response deleteBookmark(String addressStr, String category) {
        return deleteBookmark(addressStr, category, null);
    }

    @McpTool(path = "/delete_bookmark", method = "POST", description = "Delete a bookmark. On programs with multiple address spaces (e.g., embedded targets), prefix addresses with the space name (mem:1000) to avoid ambiguous resolution.", category = "program")
    public Response deleteBookmark(
            @Param(value = "address", paramType = "address", source = ParamSource.BODY,
                   description = "Address in the program. Accepts 0x<hex> (default space) or <space>:<hex> "
                               + "(e.g., mem:1000, code:ff00). Note: some programs — particularly "
                               + "embedded/microcontroller targets — are not address-space-agnostic; "
                               + "use get_address_spaces to discover spaces before assuming a plain hex "
                               + "address is unambiguous.") String addressStr,
            @Param(value = "category", source = ParamSource.BODY, defaultValue = "") String category,
            @Param(value = "program", description = "Target program name", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        if (addressStr == null || addressStr.isEmpty()) {
            return Response.err("Address is required");
        }

        try {
            Address addr = ServiceUtils.parseAddress(program, addressStr);
            if (addr == null) {
                return Response.err(ServiceUtils.getLastParseError());
            }

            BookmarkManager bookmarkManager = program.getBookmarkManager();

            int transactionId = program.startTransaction("Delete bookmark at " + addressStr);
            boolean txSuccess = false;
            try {
                int deleted = 0;
                Bookmark[] bms = bookmarkManager.getBookmarks(addr);

                for (Bookmark bm : bms) {
                    if (category == null || category.isEmpty() || bm.getCategory().equals(category)) {
                        bookmarkManager.removeBookmark(bm);
                        deleted++;
                    }
                }

                txSuccess = true;
                Map<String, Object> delResult = new LinkedHashMap<>();
                delResult.put("success", true);
                delResult.put("deleted", deleted);
                delResult.putAll(ServiceUtils.addressToJson(addr, program));
                return Response.ok(delResult);

            } catch (Exception e) {
                throw e;
            } finally {
                program.endTransaction(transactionId, txSuccess);
            }

        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    /**
     * Run a Ghidra script with enhanced output capture and JSON response.
     * Locates the script in standard directories, executes it, and returns structured results.
     */
    public Response runGhidraScriptWithCapture(String scriptName, String scriptArgs, int timeoutSeconds, boolean captureOutput) {
        return runGhidraScriptWithCapture(scriptName, scriptArgs, timeoutSeconds, captureOutput, null);
    }

    @McpTool(path = "/run_ghidra_script", method = "POST", description = "Execute script with output capture and timeout", category = "program")
    public Response runGhidraScriptWithCapture(
            @Param(value = "script_name", source = ParamSource.BODY) String scriptName,
            @Param(value = "args", source = ParamSource.BODY, defaultValue = "") String scriptArgs,
            @Param(value = "timeout_seconds", source = ParamSource.BODY, defaultValue = "300") int timeoutSeconds,
            @Param(value = "capture_output", source = ParamSource.BODY, defaultValue = "true") boolean captureOutput,
            @Param(value = "program", description = "Target program name", defaultValue = "") String programName) {
        if (scriptName == null || scriptName.isEmpty()) {
            return Response.err("Script name is required");
        }

        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

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
                return Response.err("Script '" + filename + "' not found. Searched: " + searched);
            }

            // Execute the script via the existing execution method
            long startTime = System.currentTimeMillis();
            Response scriptResponse = runGhidraScript(scriptFile.getAbsolutePath(), scriptArgs);
            double executionTime = (System.currentTimeMillis() - startTime) / 1000.0;

            // Extract output text from the Response
            String output = scriptResponse.toJson();
            boolean succeeded = output.contains("SCRIPT COMPLETED SUCCESSFULLY");

            return Response.ok(JsonHelper.mapOf(
                "success", succeeded,
                "script_name", scriptName,
                "script_path", scriptFile.getAbsolutePath(),
                "execution_time_seconds", Double.parseDouble(String.format("%.2f", executionTime)),
                "console_output", output
            ));

        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
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

    // ========================================================================
    // Image Base Operations
    // ========================================================================

    @McpTool(path = "/set_image_base", method = "POST", description = "Set the base address of the program (rebases all addresses)", category = "program")
    public Response setImageBase(
            @Param(value = "address", source = ParamSource.BODY, description = "New base address (e.g. 0x08000000)") String addressStr,
            @Param(value = "program", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        if (addressStr == null || addressStr.isEmpty()) {
            return Response.err("address parameter required");
        }

        final AtomicReference<Map<String, Object>> resultData = new AtomicReference<>();
        final AtomicReference<String> errorMsg = new AtomicReference<>();

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Set image base");
                boolean txSuccess = false;
                try {
                    Address oldBase = program.getImageBase();
                    Address newBase = ServiceUtils.parseAddress(program, addressStr);
                    if (newBase == null) {
                        errorMsg.set("Invalid address: " + addressStr);
                        return;
                    }
                    program.setImageBase(newBase, true);
                    txSuccess = true;

                    // Trigger re-analysis since all addresses shifted
                    boolean reanalyzing = false;
                    try {
                        AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
                        mgr.reAnalyzeAll(null);
                        mgr.startAnalysis(ghidra.util.task.TaskMonitor.DUMMY);
                        reanalyzing = true;
                    } catch (Exception ae) {
                        Msg.warn(this, "Re-analysis after rebase failed: " + ae.getMessage());
                    }

                    resultData.set(JsonHelper.mapOf(
                        "success", true,
                        "old_base", oldBase.toString(),
                        "new_base", newBase.toString(),
                        "analyzing", reanalyzing,
                        "message", "Image base changed from " + oldBase + " to " + newBase
                    ));
                } catch (Throwable e) {
                    String msg = e.getMessage() != null ? e.getMessage() : e.toString();
                    errorMsg.set(msg);
                    Msg.error(this, "Error setting image base", e);
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

        return resultData.get() != null ? Response.ok(resultData.get()) : Response.err("Unknown failure");
    }
}

