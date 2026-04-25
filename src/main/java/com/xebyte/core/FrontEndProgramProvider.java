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
package com.xebyte.core;

import ghidra.app.services.ProgramManager;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectData;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TaskMonitor;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * FrontEnd mode implementation of ProgramProvider.
 *
 * Opens programs on-demand from the active Ghidra project's DomainFiles.
 * When a CodeBrowser has a program open, returns that shared instance
 * (Ghidra's domain object cache ensures the same Program object).
 * When no CodeBrowser is open, opens programs directly from the project.
 */
public class FrontEndProgramProvider implements ProgramProvider {

    private final PluginTool tool;
    private final Map<String, Program> openPrograms = new ConcurrentHashMap<>();
    private final Map<String, String> pathToName = new ConcurrentHashMap<>(); // project path -> cache key
    private volatile Program currentProgram;
    private final TaskMonitor monitor;
    private final Object consumer; // DomainObject consumer for release tracking

    /**
     * Create a FrontEndProgramProvider for the given tool.
     *
     * @param tool The Ghidra PluginTool (FrontEnd tool)
     * @param consumer The consumer object for DomainObject tracking (typically the plugin instance)
     */
    public FrontEndProgramProvider(PluginTool tool, Object consumer) {
        this.tool = tool;
        this.consumer = consumer;
        this.monitor = new ConsoleTaskMonitor();
    }

    @Override
    public Program getCurrentProgram() {
        // Check all running CodeBrowsers for a current program
        for (ProgramManager pm : findAllCodeBrowserProgramManagers()) {
            Program cbProgram = pm.getCurrentProgram();
            if (cbProgram != null) {
                return cbProgram;
            }
        }
        // Fall back to our internally tracked current program
        return currentProgram;
    }

    @Override
    public Program getProgram(String name) {
        if (name == null || name.trim().isEmpty()) {
            return getCurrentProgram();
        }

        String searchName = name.trim();

        // 1. Check path-based cache first (handles multi-version same-name DLLs)
        if (searchName.startsWith("/")) {
            String cacheKey = pathToName.get(searchName);
            if (cacheKey != null) {
                Program cached = openPrograms.get(cacheKey);
                if (cached != null) {
                    return cached;
                }
            }
        }

        // 2. Check all running CodeBrowsers for this program
        List<Program> cbPrograms = collectCodeBrowserPrograms();
        for (Program prog : cbPrograms) {
            if (prog.getName().equalsIgnoreCase(searchName)) {
                return prog;
            }
        }
        // Partial match on CodeBrowser programs
        for (Program prog : cbPrograms) {
            if (prog.getName().toLowerCase().contains(searchName.toLowerCase())) {
                return prog;
            }
        }

        // 3. Check our cache (only for non-path lookups to avoid collisions)
        if (!searchName.startsWith("/")) {
            Program cached = openPrograms.get(searchName);
            if (cached != null) {
                return cached;
            }
            // Case-insensitive cache lookup
            for (Map.Entry<String, Program> entry : openPrograms.entrySet()) {
                if (entry.getKey().equalsIgnoreCase(searchName)) {
                    return entry.getValue();
                }
            }
        }

        // 4. Try to open from project by name or path
        return openFromProject(searchName);
    }

    @Override
    public Program[] getAllOpenPrograms() {
        // Collect programs from ALL CodeBrowser instances (deduped by identity)
        List<Program> allPrograms = collectCodeBrowserPrograms();

        // Add our cached programs that aren't already in the list
        // Deduplicate by object identity only — same-named programs from
        // different versions (e.g., /Vanilla/1.00/D2Common.dll vs /Vanilla/1.13d/D2Common.dll)
        // must both appear in the list
        for (Program prog : openPrograms.values()) {
            boolean alreadyListed = false;
            for (Program existing : allPrograms) {
                if (existing == prog) {
                    alreadyListed = true;
                    break;
                }
            }
            if (!alreadyListed) {
                allPrograms.add(prog);
            }
        }

        return allPrograms.toArray(new Program[0]);
    }

    @Override
    public void setCurrentProgram(Program program) {
        this.currentProgram = program;

        // Set current in the CodeBrowser that actually has this program open
        if (program != null) {
            for (ProgramManager pm : findAllCodeBrowserProgramManagers()) {
                for (Program p : pm.getAllOpenPrograms()) {
                    if (p == program || p.getName().equals(program.getName())) {
                        pm.setCurrentProgram(program);
                        return;
                    }
                }
            }
        }
    }

    /**
     * Collect programs from all running CodeBrowser instances, deduplicating
     * by object identity and name.
     *
     * @return Mutable list of unique programs across all CodeBrowsers
     */
    private List<Program> collectCodeBrowserPrograms() {
        List<Program> allPrograms = new ArrayList<>();
        for (ProgramManager pm : findAllCodeBrowserProgramManagers()) {
            for (Program prog : pm.getAllOpenPrograms()) {
                // Deduplicate by object identity only — not by name,
                // since multiple versions of the same DLL are distinct programs
                boolean alreadyListed = false;
                for (Program existing : allPrograms) {
                    if (existing == prog) {
                        alreadyListed = true;
                        break;
                    }
                }
                if (!alreadyListed) {
                    allPrograms.add(prog);
                }
            }
        }
        return allPrograms;
    }

    /**
     * Open a program from the active project by name or path.
     *
     * @param nameOrPath Program name (e.g., "D2Common.dll") or project path (e.g., "/LoD/1.00/D2Common.dll")
     * @return The opened program, or null if not found
     */
    public Program openFromProject(String nameOrPath) {
        Project project = tool.getProject();
        if (project == null) {
            Msg.warn(this, "No active project");
            return null;
        }

        ProjectData projectData = project.getProjectData();
        if (projectData == null) {
            return null;
        }

        DomainFile domainFile = null;

        // Try as absolute path first
        if (nameOrPath.startsWith("/")) {
            domainFile = projectData.getFile(nameOrPath);
        }

        // If not found by path, search recursively by name
        if (domainFile == null) {
            domainFile = findFileByName(projectData.getRootFolder(), nameOrPath);
        }

        if (domainFile == null) {
            Msg.info(this, "File not found in project: " + nameOrPath);
            return null;
        }

        String projectPath = domainFile.getPathname();
        // Use project path as unique cache key (handles multiple versions of same DLL)
        String cacheKey = projectPath;

        try {
            // getDomainObject returns the SAME instance if already open in CodeBrowser
            // This is the key to seamless integration — shared domain objects
            Program program = (Program) domainFile.getDomainObject(consumer, false, false, monitor);

            // Release previous consumer reference if overwriting a cache entry
            // to prevent reference count leaks on the DomainObject
            Program previousProgram = openPrograms.get(cacheKey);
            if (previousProgram != null && previousProgram != program) {
                try {
                    previousProgram.release(consumer);
                    Msg.info(this, "Released previous cached program for: " + cacheKey);
                } catch (Exception ex) {
                    Msg.warn(this, "Error releasing previous program " + cacheKey + ": " + ex.getMessage());
                }
            }

            openPrograms.put(cacheKey, program);
            pathToName.put(projectPath, cacheKey);
            // Also map the input path if different from project path
            if (!nameOrPath.equals(projectPath)) {
                pathToName.put(nameOrPath, cacheKey);
            }
            if (currentProgram == null) {
                currentProgram = program;
            }
            Msg.info(this, "Opened program from project: " + program.getName() +
                " (" + projectPath + ")");
            return program;
        } catch (Exception e) {
            Msg.error(this, "Failed to open program: " + nameOrPath + " — " + e.getMessage());
            // Try read-only as fallback
            try {
                Program program = (Program) domainFile.getImmutableDomainObject(consumer, DomainFile.DEFAULT_VERSION, monitor);

                // Release previous consumer reference if overwriting
                Program previousProgram = openPrograms.get(cacheKey);
                if (previousProgram != null && previousProgram != program) {
                    try {
                        previousProgram.release(consumer);
                    } catch (Exception ex) {
                        Msg.warn(this, "Error releasing previous program " + cacheKey + ": " + ex.getMessage());
                    }
                }

                openPrograms.put(cacheKey, program);
                pathToName.put(projectPath, cacheKey);
                if (!nameOrPath.equals(projectPath)) {
                    pathToName.put(nameOrPath, cacheKey);
                }
                if (currentProgram == null) {
                    currentProgram = program;
                }
                Msg.info(this, "Opened program read-only: " + program.getName());
                return program;
            } catch (Exception e2) {
                Msg.error(this, "Failed to open program even read-only: " + nameOrPath + " — " + e2.getMessage());
                return null;
            }
        }
    }

    /**
     * Search for a file by name recursively in the project folder tree.
     */
    private DomainFile findFileByName(DomainFolder folder, String name) {
        if (folder == null) {
            return null;
        }

        // Check files in this folder
        try {
            for (DomainFile file : folder.getFiles()) {
                if (file.getName().equalsIgnoreCase(name)) {
                    return file;
                }
            }

            // Recurse into subfolders
            for (DomainFolder subfolder : folder.getFolders()) {
                DomainFile found = findFileByName(subfolder, name);
                if (found != null) {
                    return found;
                }
            }
        } catch (Exception e) {
            Msg.warn(this, "Error searching folder " + folder.getPathname() + ": " + e.getMessage());
        }

        return null;
    }

    /**
     * Find ProgramManagers from ALL running CodeBrowser tool instances.
     * When multiple CodeBrowsers are open (e.g., user double-clicks multiple
     * programs in FrontEnd), each has its own ProgramManager.
     *
     * @return List of ProgramManagers from all running CodeBrowsers (may be empty)
     */
    private List<ProgramManager> findAllCodeBrowserProgramManagers() {
        List<ProgramManager> managers = new ArrayList<>();

        Project project = tool.getProject();
        if (project == null) {
            return managers;
        }

        try {
            ghidra.framework.model.ToolManager tm = project.getToolManager();
            if (tm == null) {
                return managers;
            }

            for (PluginTool runningTool : tm.getRunningTools()) {
                ProgramManager pm = runningTool.getService(ProgramManager.class);
                if (pm != null) {
                    managers.add(pm);
                }
            }
        } catch (Exception e) {
            // ToolManager may not be available in all contexts
        }

        return managers;
    }

    /**
     * Release all programs opened by this provider.
     * Called during plugin dispose.
     */
    public void releaseAll() {
        for (Map.Entry<String, Program> entry : openPrograms.entrySet()) {
            try {
                Program program = entry.getValue();
                program.release(consumer);
                Msg.info(this, "Released program: " + entry.getKey());
            } catch (Exception e) {
                Msg.warn(this, "Error releasing program " + entry.getKey() + ": " + e.getMessage());
            }
        }
        openPrograms.clear();
        pathToName.clear();
        currentProgram = null;
    }

    /**
     * Release a cached program opened directly by this provider.
     *
     * @param nameOrPath Program name or project path
     * @return true if a cached program reference was released
     */
    public boolean releaseCachedProgram(String nameOrPath) {
        if (nameOrPath == null || nameOrPath.trim().isEmpty()) {
            return false;
        }

        String search = nameOrPath.trim();
        List<String> keys = new ArrayList<>();
        String directKey = pathToName.get(search);
        if (directKey != null) {
            keys.add(directKey);
        }
        keys.add(search);

        for (Map.Entry<String, Program> entry : openPrograms.entrySet()) {
            Program program = entry.getValue();
            if (program.getName().equalsIgnoreCase(search) ||
                    (program.getDomainFile() != null &&
                            program.getDomainFile().getPathname().equalsIgnoreCase(search))) {
                keys.add(entry.getKey());
            }
        }

        boolean released = false;
        for (String key : new ArrayList<>(keys)) {
            Program program = openPrograms.remove(key);
            if (program == null) {
                continue;
            }
            try {
                program.release(consumer);
                released = true;
                if (program == currentProgram) {
                    currentProgram = null;
                }
                Msg.info(this, "Released cached program: " + key);
            } catch (Exception e) {
                Msg.warn(this, "Error releasing cached program " + key + ": " + e.getMessage());
            }
        }

        pathToName.entrySet().removeIf(entry -> keys.contains(entry.getValue()) ||
                entry.getKey().equalsIgnoreCase(search));
        return released;
    }

    /**
     * Get the underlying PluginTool.
     *
     * @return The PluginTool
     */
    public PluginTool getTool() {
        return tool;
    }
}
