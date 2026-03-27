/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.xebyte.headless;

import com.xebyte.core.ProgramProvider;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.util.importer.AutoImporter;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.LoadResults;
import ghidra.base.project.GhidraProject;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectData;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TaskMonitor;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Headless mode implementation of ProgramProvider.
 *
 * Manages programs directly without relying on GUI services like ProgramManager.
 * Programs can be loaded from files or Ghidra project folders.
 */
public class HeadlessProgramProvider implements ProgramProvider {

    private final Map<String, Program> openPrograms = new ConcurrentHashMap<>();
    private volatile Program currentProgram;
    private final TaskMonitor monitor;
    private Project project;
    private GhidraProject ghidraProject;  // For headless project management

    /**
     * Create a new HeadlessProgramProvider.
     */
    public HeadlessProgramProvider() {
        this.monitor = new ConsoleTaskMonitor();
    }

    /**
     * Create a HeadlessProgramProvider with an existing Ghidra project.
     *
     * @param project The Ghidra project to use
     */
    public HeadlessProgramProvider(Project project) {
        this();
        this.project = project;
    }

    @Override
    public Program getCurrentProgram() {
        return currentProgram;
    }

    @Override
    public Program getProgram(String name) {
        if (name == null || name.trim().isEmpty()) {
            return getCurrentProgram();
        }

        String searchName = name.trim();

        // Try exact name match first
        Program exact = openPrograms.get(searchName);
        if (exact != null) {
            return exact;
        }

        // Try case-insensitive match
        for (Map.Entry<String, Program> entry : openPrograms.entrySet()) {
            if (entry.getKey().equalsIgnoreCase(searchName)) {
                return entry.getValue();
            }
        }

        // Try partial match
        for (Map.Entry<String, Program> entry : openPrograms.entrySet()) {
            if (entry.getKey().toLowerCase().contains(searchName.toLowerCase())) {
                return entry.getValue();
            }
        }

        return null;
    }

    @Override
    public Program[] getAllOpenPrograms() {
        return openPrograms.values().toArray(new Program[0]);
    }

    @Override
    public void setCurrentProgram(Program program) {
        if (program != null) {
            this.currentProgram = program;
            // Ensure it's in our map
            openPrograms.put(program.getName(), program);
        }
    }

    /**
     * Load a program from a binary file.
     *
     * @param file The binary file to import
     * @return The loaded Program, or null on failure
     */
    public Program loadProgramFromFile(File file) {
        if (!file.exists()) {
            Msg.error(this, "File not found: " + file.getAbsolutePath());
            return null;
        }

        try {
            MessageLog log = new MessageLog();
            LoadResults<Program> loadResults = AutoImporter.importByUsingBestGuess(
                file,
                null,  // project (null for standalone)
                "/",   // folder path
                this,  // consumer
                log,
                monitor
            );

            Program program = null;
            if (loadResults != null) {
                program = loadResults.getPrimaryDomainObject();
            }

            if (program != null) {
                openPrograms.put(program.getName(), program);
                if (currentProgram == null) {
                    currentProgram = program;
                }
                Msg.info(this, "Loaded program: " + program.getName() +
                    " (" + file.getAbsolutePath() + ")");
            } else {
                Msg.error(this, "Failed to load program from: " + file.getAbsolutePath());
                if (!log.toString().isEmpty()) {
                    Msg.error(this, "Import log: " + log.toString());
                }
            }

            return program;
        } catch (Exception e) {
            Msg.error(this, "Error loading program from file: " + file.getAbsolutePath(), e);
            return null;
        }
    }

    /**
     * Load a program from a Ghidra project.
     *
     * @param projectPath Path to the program within the project (e.g., "/D2Client.dll")
     * @return The loaded Program, or null on failure
     */
    public Program loadProgramFromProject(String projectPath) {
        if (project == null) {
            Msg.error(this, "No project available. Use loadProject() first or provide a project in constructor.");
            return null;
        }

        try {
            ProjectData projectData = project.getProjectData();
            DomainFile domainFile = projectData.getFile(projectPath);

            if (domainFile == null) {
                Msg.error(this, "Program not found in project: " + projectPath);
                return null;
            }

            Program program = (Program) domainFile.getDomainObject(this, true, false, monitor);

            if (program != null) {
                openPrograms.put(program.getName(), program);
                if (currentProgram == null) {
                    currentProgram = program;
                }
                Msg.info(this, "Loaded program from project: " + program.getName());
            }

            return program;
        } catch (Exception e) {
            Msg.error(this, "Error loading program from project: " + projectPath, e);
            return null;
        }
    }

    /**
     * Close a specific program.
     *
     * @param program The program to close
     */
    public void closeProgram(Program program) {
        if (program == null) {
            return;
        }

        openPrograms.remove(program.getName());

        if (currentProgram == program) {
            // Switch to another open program, or null if none
            currentProgram = openPrograms.isEmpty() ? null :
                openPrograms.values().iterator().next();
        }

        try {
            program.release(this);
        } catch (Exception e) {
            Msg.warn(this, "Error releasing program: " + e.getMessage());
        }
    }

    /**
     * Close all open programs.
     */
    public void closeAllPrograms() {
        for (Program program : openPrograms.values()) {
            try {
                program.release(this);
            } catch (Exception e) {
                Msg.warn(this, "Error releasing program " + program.getName() + ": " + e.getMessage());
            }
        }
        openPrograms.clear();
        currentProgram = null;
    }

    /**
     * Get the task monitor for this provider.
     *
     * @return The TaskMonitor
     */
    public TaskMonitor getMonitor() {
        return monitor;
    }

    /**
     * Set the Ghidra project for loading programs.
     *
     * @param project The project to use
     */
    public void setProject(Project project) {
        this.project = project;
    }

    /**
     * Get the current project.
     *
     * @return The current project, or null if none set
     */
    @Override
    public Project getProject() {
        return project;
    }

    @Override
    public Program openFromProject(String path) {
        return loadProgramFromProject(path);
    }

    /**
     * List all available programs in the current project.
     *
     * @return Array of program paths in the project
     */
    public String[] listProjectPrograms() {
        if (project == null) {
            return new String[0];
        }

        try {
            ProjectData projectData = project.getProjectData();
            DomainFolder rootFolder = projectData.getRootFolder();
            return listFolderContents(rootFolder, "").toArray(new String[0]);
        } catch (Exception e) {
            Msg.error(this, "Error listing project programs", e);
            return new String[0];
        }
    }

    private List<String> listFolderContents(DomainFolder folder, String path) {
        List<String> results = new ArrayList<>();

        try {
            // Add files in this folder
            for (DomainFile file : folder.getFiles()) {
                results.add(path + "/" + file.getName());
            }

            // Recurse into subfolders
            for (DomainFolder subfolder : folder.getFolders()) {
                results.addAll(listFolderContents(subfolder, path + "/" + subfolder.getName()));
            }
        } catch (Exception e) {
            Msg.warn(this, "Error reading folder: " + path);
        }

        return results;
    }

    /**
     * Open a Ghidra project from a .gpr file path.
     *
     * @param projectPath Path to the .gpr file (e.g., "/projects/MyProject.gpr")
     * @return true if project was opened successfully
     */
    public boolean openProject(String projectPath) {
        try {
            File projectFile = new File(projectPath);

            // Handle both .gpr file path and directory path
            File projectDir;
            String projectName;

            if (projectPath.endsWith(".gpr")) {
                projectDir = projectFile.getParentFile();
                projectName = projectFile.getName().replace(".gpr", "");
            } else {
                // Assume it's a directory containing the project
                projectDir = projectFile;
                // Look for .gpr file in the directory
                File[] gprFiles = projectDir.listFiles((dir, name) -> name.endsWith(".gpr"));
                if (gprFiles == null || gprFiles.length == 0) {
                    Msg.error(this, "No .gpr file found in: " + projectPath);
                    return false;
                }
                projectName = gprFiles[0].getName().replace(".gpr", "");
            }

            if (!projectDir.exists()) {
                Msg.error(this, "Project directory not found: " + projectDir.getAbsolutePath());
                return false;
            }

            // Close existing project if any
            if (project != null) {
                closeProject();
            }

            // Use GhidraProject API (designed for headless/scripting use)
            // Use restore=true to bypass ownership checks (different user in Docker)
            ghidraProject = GhidraProject.openProject(projectDir.getAbsolutePath(), projectName, true);
            project = ghidraProject.getProject();

            if (project != null) {
                Msg.info(this, "Opened project: " + projectName + " from " + projectDir.getAbsolutePath());
                return true;
            } else {
                Msg.error(this, "Failed to open project: " + projectPath);
                return false;
            }
        } catch (Exception e) {
            Msg.error(this, "Error opening project: " + projectPath, e);
            return false;
        }
    }

    /**
     * Close the current project.
     */
    public void closeProject() {
        if (ghidraProject != null) {
            try {
                // Close all programs from this project first
                closeAllPrograms();
                ghidraProject.close();
                Msg.info(this, "Closed project");
            } catch (Exception e) {
                Msg.warn(this, "Error closing project: " + e.getMessage());
            }
            ghidraProject = null;
            project = null;
        } else if (project != null) {
            try {
                closeAllPrograms();
                project.close();
                Msg.info(this, "Closed project");
            } catch (Exception e) {
                Msg.warn(this, "Error closing project: " + e.getMessage());
            }
            project = null;
        }
    }

    /**
     * List all programs available in the current project.
     *
     * @return List of ProjectFileInfo objects with program details
     */
    public List<ProjectFileInfo> listProjectFiles() {
        List<ProjectFileInfo> files = new ArrayList<>();

        if (project == null) {
            return files;
        }

        try {
            ProjectData projectData = project.getProjectData();
            DomainFolder rootFolder = projectData.getRootFolder();
            collectProjectFiles(rootFolder, "", files);
        } catch (Exception e) {
            Msg.error(this, "Error listing project files", e);
        }

        return files;
    }

    private void collectProjectFiles(DomainFolder folder, String path, List<ProjectFileInfo> results) {
        try {
            for (DomainFile file : folder.getFiles()) {
                String filePath = path.isEmpty() ? "/" + file.getName() : path + "/" + file.getName();
                results.add(new ProjectFileInfo(
                    file.getName(),
                    filePath,
                    file.getContentType(),
                    file.isReadOnly()
                ));
            }

            for (DomainFolder subfolder : folder.getFolders()) {
                String subPath = path.isEmpty() ? "/" + subfolder.getName() : path + "/" + subfolder.getName();
                collectProjectFiles(subfolder, subPath, results);
            }
        } catch (Exception e) {
            Msg.warn(this, "Error reading folder: " + path);
        }
    }

    /**
     * Information about a file in a Ghidra project.
     */
    public static class ProjectFileInfo {
        public final String name;
        public final String path;
        public final String contentType;
        public final boolean readOnly;

        public ProjectFileInfo(String name, String path, String contentType, boolean readOnly) {
            this.name = name;
            this.path = path;
            this.contentType = contentType;
            this.readOnly = readOnly;
        }
    }

    /**
     * Check if a project is currently open.
     *
     * @return true if a project is open
     */
    public boolean hasProject() {
        return project != null;
    }

    /**
     * Get the name of the current project.
     *
     * @return Project name or null if no project is open
     */
    public String getProjectName() {
        return project != null ? project.getName() : null;
    }

    /**
     * Run auto-analysis on a program.
     *
     * @param program The program to analyze
     * @return AnalysisResult with statistics about the analysis
     */
    public AnalysisResult runAnalysis(Program program) {
        if (program == null) {
            return new AnalysisResult(false, "No program specified", 0, 0, 0);
        }

        long startTime = System.currentTimeMillis();
        int functionsBefore = program.getFunctionManager().getFunctionCount();
        
        try {
            // Get the auto analysis manager for this program
            AutoAnalysisManager analysisManager = AutoAnalysisManager.getAnalysisManager(program);
            
            // Start a transaction for the analysis
            int transactionId = program.startTransaction("Auto Analysis");
            boolean success = false;
            
            try {
                // Analyze all addresses in the program
                AddressSetView addresses = program.getMemory().getLoadedAndInitializedAddressSet();
                
                // Initialize analysis options (use defaults)
                analysisManager.initializeOptions();
                
                // Schedule analysis for the entire program
                analysisManager.reAnalyzeAll(addresses);
                
                // Wait for analysis to complete
                analysisManager.startAnalysis(monitor);
                
                success = true;
            } finally {
                program.endTransaction(transactionId, success);
            }
            
            long duration = System.currentTimeMillis() - startTime;
            int functionsAfter = program.getFunctionManager().getFunctionCount();
            int newFunctions = functionsAfter - functionsBefore;
            
            Msg.info(this, "Analysis completed in " + duration + "ms. " +
                "Functions: " + functionsBefore + " -> " + functionsAfter + 
                " (+" + newFunctions + ")");
            
            return new AnalysisResult(true, "Analysis completed successfully", 
                duration, functionsAfter, newFunctions);
                
        } catch (Exception e) {
            long duration = System.currentTimeMillis() - startTime;
            Msg.error(this, "Analysis failed: " + e.getMessage(), e);
            return new AnalysisResult(false, "Analysis failed: " + e.getMessage(), 
                duration, program.getFunctionManager().getFunctionCount(), 0);
        }
    }

    /**
     * Result of running analysis on a program.
     */
    public static class AnalysisResult {
        public final boolean success;
        public final String message;
        public final long durationMs;
        public final int totalFunctions;
        public final int newFunctions;

        public AnalysisResult(boolean success, String message, long durationMs,
                              int totalFunctions, int newFunctions) {
            this.success = success;
            this.message = message;
            this.durationMs = durationMs;
            this.totalFunctions = totalFunctions;
            this.newFunctions = newFunctions;
        }
    }

    /**
     * Creates a new Ghidra project.
     *
     * @param parentDir The parent directory for the new project
     * @param name The name of the new project
     * @return true if the project was created successfully
     */
    public boolean createProject(String parentDir, String name) {
        try {
            File dir = new File(parentDir);
            if (!dir.exists()) {
                Msg.error(this, "Parent directory not found: " + parentDir);
                return false;
            }
            if (project != null) {
                closeProject();
            }
            ghidraProject = GhidraProject.createProject(parentDir, name, false);
            project = ghidraProject.getProject();
            Msg.info(this, "Created project: " + name + " in " + parentDir);
            return project != null;
        } catch (Exception e) {
            Msg.error(this, "Error creating project: " + e.getMessage(), e);
            return false;
        }
    }

    /**
     * Deletes a Ghidra project by path.
     *
     * @param projectPath Path to the .gpr file or project directory
     * @return true if the project was deleted successfully
     */
    public boolean deleteProject(String projectPath) {
        try {
            File projectFile = new File(projectPath);
            File projectDir;
            String projectName;
            if (projectPath.endsWith(".gpr")) {
                projectDir = projectFile.getParentFile();
                projectName = projectFile.getName().replace(".gpr", "");
            } else {
                projectDir = projectFile.getParentFile() != null ? projectFile.getParentFile() : projectFile;
                projectName = projectFile.getName();
            }
            // Close if this is the currently open project
            if (project != null && projectName.equals(project.getName())) {
                closeProject();
            }
            ghidra.framework.model.ProjectLocator locator =
                new ghidra.framework.model.ProjectLocator(projectDir.getAbsolutePath(), projectName);
            // Delete project files (marker file + project directory)
            java.io.File markerFile = locator.getMarkerFile();
            java.io.File projectDirFile = locator.getProjectDir();
            if (markerFile.exists()) markerFile.delete();
            deleteRecursive(projectDirFile);
            Msg.info(this, "Deleted project: " + projectName);
            return true;
        } catch (Exception e) {
            Msg.error(this, "Error deleting project: " + e.getMessage(), e);
            return false;
        }
    }

    /**
     * Scan a directory for .gpr files and return a list of ProjectInfo objects.
     *
     * @param searchDir The directory to search, or null/empty for the user home directory
     * @return List of ProjectInfo objects representing found projects
     */
    public List<ProjectInfo> listProjects(String searchDir) {
        List<ProjectInfo> result = new ArrayList<>();
        try {
            File dir = searchDir != null && !searchDir.isEmpty() ? new File(searchDir) : new File(System.getProperty("user.home"));
            if (!dir.exists() || !dir.isDirectory()) {
                return result;
            }
            scanForProjects(dir, result, 0, 3);
        } catch (Exception e) {
            Msg.error(this, "Error listing projects: " + e.getMessage(), e);
        }
        return result;
    }

    private void scanForProjects(File dir, List<ProjectInfo> result, int depth, int maxDepth) {
        if (depth > maxDepth) return;
        File[] files = dir.listFiles();
        if (files == null) return;
        for (File f : files) {
            if (f.isFile() && f.getName().endsWith(".gpr")) {
                String name = f.getName().replace(".gpr", "");
                boolean active = project != null && name.equals(project.getName());
                result.add(new ProjectInfo(name, f.getAbsolutePath(), active));
            } else if (f.isDirectory() && depth < maxDepth) {
                scanForProjects(f, result, depth + 1, maxDepth);
            }
        }
    }

    /**
     * Create a folder inside the current project.
     *
     * @param folderPath The path of the folder to create (e.g., "/subfolder/nested")
     * @return true if the folder was created successfully
     */
    public boolean createFolder(String folderPath) {
        if (project == null) {
            Msg.error(this, "No project open");
            return false;
        }
        try {
            ProjectData projectData = project.getProjectData();
            DomainFolder root = projectData.getRootFolder();
            // Split path and create each segment
            String[] parts = folderPath.replaceAll("^/+", "").split("/");
            DomainFolder current = root;
            for (String part : parts) {
                if (part.isEmpty()) continue;
                DomainFolder existing = current.getFolder(part);
                if (existing != null) {
                    current = existing;
                } else {
                    current = current.createFolder(part);
                }
            }
            Msg.info(this, "Created folder: " + folderPath);
            return true;
        } catch (Exception e) {
            Msg.error(this, "Error creating folder: " + e.getMessage(), e);
            return false;
        }
    }

    /**
     * Move a domain file to another folder within the current project.
     *
     * @param filePath The project-relative path of the file to move
     * @param destFolderPath The project-relative path of the destination folder
     * @return true if the file was moved successfully
     */
    public boolean moveFile(String filePath, String destFolderPath) {
        if (project == null) {
            Msg.error(this, "No project open");
            return false;
        }
        try {
            ProjectData projectData = project.getProjectData();
            DomainFile domainFile = projectData.getFile(filePath);
            if (domainFile == null) {
                Msg.error(this, "File not found: " + filePath);
                return false;
            }
            DomainFolder destFolder = projectData.getFolder(destFolderPath);
            if (destFolder == null) {
                Msg.error(this, "Destination folder not found: " + destFolderPath);
                return false;
            }
            domainFile.moveTo(destFolder);
            Msg.info(this, "Moved " + filePath + " to " + destFolderPath);
            return true;
        } catch (Exception e) {
            Msg.error(this, "Error moving file: " + e.getMessage(), e);
            return false;
        }
    }

    /**
     * Move a domain folder to another parent folder within the current project.
     *
     * @param sourcePath The project-relative path of the folder to move
     * @param destParentPath The project-relative path of the destination parent folder
     * @return true if the folder was moved successfully
     */
    public boolean moveFolder(String sourcePath, String destParentPath) {
        if (project == null) {
            Msg.error(this, "No project open");
            return false;
        }
        try {
            ProjectData projectData = project.getProjectData();
            DomainFolder sourceFolder = projectData.getFolder(sourcePath);
            if (sourceFolder == null) {
                Msg.error(this, "Source folder not found: " + sourcePath);
                return false;
            }
            DomainFolder destParent = projectData.getFolder(destParentPath);
            if (destParent == null) {
                Msg.error(this, "Destination parent not found: " + destParentPath);
                return false;
            }
            sourceFolder.moveTo(destParent);
            Msg.info(this, "Moved folder " + sourcePath + " to " + destParentPath);
            return true;
        } catch (Exception e) {
            Msg.error(this, "Error moving folder: " + e.getMessage(), e);
            return false;
        }
    }

    /**
     * Delete a domain file from the current project.
     *
     * @param filePath The project-relative path of the file to delete
     * @return true if the file was deleted successfully
     */
    public boolean deleteProjectFile(String filePath) {
        if (project == null) {
            Msg.error(this, "No project open");
            return false;
        }
        try {
            ProjectData projectData = project.getProjectData();
            DomainFile domainFile = projectData.getFile(filePath);
            if (domainFile == null) {
                Msg.error(this, "File not found: " + filePath);
                return false;
            }
            // Close it if currently open
            String fileName = domainFile.getName();
            Program openProg = openPrograms.get(fileName);
            if (openProg != null) {
                closeProgram(openProg);
            }
            domainFile.delete();
            Msg.info(this, "Deleted file: " + filePath);
            return true;
        } catch (Exception e) {
            Msg.error(this, "Error deleting file: " + e.getMessage(), e);
            return false;
        }
    }

    /**
     * List available analyzers for a program.
     *
     * @param program The program to list analyzers for
     * @return List of AnalyzerInfo objects describing each analyzer
     */
    public List<AnalyzerInfo> listAnalyzers(Program program) {
        List<AnalyzerInfo> result = new ArrayList<>();
        if (program == null) return result;
        try {
            ghidra.framework.options.Options opts = program.getOptions(Program.ANALYSIS_PROPERTIES);
            List<String> names = opts.getOptionNames();
            for (String name : names) {
                try {
                    boolean enabled = opts.getBoolean(name, false);
                    result.add(new AnalyzerInfo(name, "", enabled, ""));
                } catch (Exception ignored) {
                    // Option exists but is not a boolean (e.g. string option)
                }
            }
        } catch (Exception e) {
            Msg.error(this, "Error listing analyzers: " + e.getMessage(), e);
        }
        return result;
    }

    /**
     * Enable or disable an analyzer for a program.
     *
     * @param program The program to configure
     * @param analyzerName The name of the analyzer
     * @param enabled Whether to enable or disable the analyzer
     * @return true if the analyzer was configured successfully
     */
    public boolean configureAnalyzer(Program program, String analyzerName, Boolean enabled) {
        if (program == null || analyzerName == null) return false;
        try {
            ghidra.framework.options.Options opts = program.getOptions(Program.ANALYSIS_PROPERTIES);
            if (!opts.contains(analyzerName)) {
                Msg.error(this, "Analyzer not found: " + analyzerName);
                return false;
            }
            int tx = program.startTransaction("Configure Analyzer");
            boolean txSuccess = false;
            try {
                if (enabled != null) {
                    opts.setBoolean(analyzerName, enabled);
                }
                txSuccess = true;
                Msg.info(this, "Configured analyzer: " + analyzerName + " enabled=" + enabled);
                return true;
            } catch (Exception e) {
                throw e;
            } finally {
                program.endTransaction(tx, txSuccess);
            }
        } catch (Exception e) {
            Msg.error(this, "Error configuring analyzer: " + e.getMessage(), e);
            return false;
        }
    }

    /**
     * Information about a Ghidra project found on disk.
     */
    public static class ProjectInfo {
        public final String name;
        public final String path;
        public final boolean active;

        public ProjectInfo(String name, String path, boolean active) {
            this.name = name;
            this.path = path;
            this.active = active;
        }
    }

    private void deleteRecursive(java.io.File f) {
        if (f == null || !f.exists()) return;
        if (f.isDirectory()) {
            java.io.File[] children = f.listFiles();
            if (children != null) for (java.io.File child : children) deleteRecursive(child);
        }
        f.delete();
    }

    /**
     * Information about a Ghidra analyzer.
     */
    public static class AnalyzerInfo {
        public final String name;
        public final String description;
        public final boolean enabled;
        public final String priority;

        public AnalyzerInfo(String name, String description, boolean enabled, String priority) {
            this.name = name;
            this.description = description;
            this.enabled = enabled;
            this.priority = priority;
        }
    }
}
