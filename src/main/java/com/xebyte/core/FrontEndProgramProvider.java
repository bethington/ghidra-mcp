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
    // Per-cache-key last-access time (System.nanoTime). Drives LRU eviction so the
    // on-demand program cache stays bounded — without a cap it accumulated a consumer
    // reference per distinct program and, when a long run documented dozens of DLLs,
    // held them all in memory until Ghidra ran out and dropped offline for hours.
    private final Map<String, Long> lastAccessNanos = new ConcurrentHashMap<>();
    private volatile Program currentProgram;
    private final TaskMonitor monitor;
    private final Object consumer; // DomainObject consumer for release tracking

    /**
     * Max on-demand programs held open at once. Above this, the least-recently-accessed
     * cached program is released (the actively-used program stays recent and is never the
     * victim). CodeBrowser-open programs are resolved before the cache and never counted
     * here. Tunable via GHIDRA_MCP_MAX_CACHED_PROGRAMS; ~5-8 is safe (20+ crashes Ghidra).
     */
    private static final int MAX_CACHED_PROGRAMS = resolveMaxCachedPrograms();

    private static int resolveMaxCachedPrograms() {
        String raw = System.getenv("GHIDRA_MCP_MAX_CACHED_PROGRAMS");
        if (raw != null && !raw.isBlank()) {
            try {
                return Math.max(2, Integer.parseInt(raw.trim()));
            } catch (NumberFormatException ignored) {
                // fall through to default
            }
        }
        return 8;
    }

    /** Record an access so an in-use program stays out of the LRU eviction set. */
    private void touch(String cacheKey) {
        if (cacheKey != null) {
            lastAccessNanos.put(cacheKey, System.nanoTime());
        }
    }

    /**
     * Pick the least-recently-accessed cache key whose Program is not protected, or null
     * when nothing is evictable. Pure (no side effects) so it can be unit-tested offline.
     */
    public static String pickLruVictim(Map<String, Program> programs,
                                       Map<String, Long> accessNanos,
                                       java.util.Set<Program> protectedPrograms) {
        String victim = null;
        long oldest = Long.MAX_VALUE;
        for (Map.Entry<String, Program> e : programs.entrySet()) {
            if (protectedPrograms.contains(e.getValue())) {
                continue;
            }
            long t = accessNanos.getOrDefault(e.getKey(), 0L);
            if (t < oldest) {
                oldest = t;
                victim = e.getKey();
            }
        }
        return victim;
    }

    /**
     * Release least-recently-accessed cached programs until the cache is at or below
     * {@link #MAX_CACHED_PROGRAMS}. Never evicts the just-opened program or the current
     * program. Releasing our consumer reference frees the program's memory when no
     * CodeBrowser holds it (the common dashboard case); if a CodeBrowser does, the release
     * is a harmless ref-count decrement.
     */
    private void evictExcessPrograms(Program justOpened) {
        java.util.Set<Program> protectedPrograms = new java.util.HashSet<>();
        if (justOpened != null) protectedPrograms.add(justOpened);
        Program cur = currentProgram;
        if (cur != null) protectedPrograms.add(cur);

        while (openPrograms.size() > MAX_CACHED_PROGRAMS) {
            String victimKey = pickLruVictim(openPrograms, lastAccessNanos, protectedPrograms);
            if (victimKey == null) {
                break; // everything left is protected
            }
            Program victim = openPrograms.remove(victimKey);
            lastAccessNanos.remove(victimKey);
            pathToName.values().removeIf(v -> v.equals(victimKey));
            if (victim == null) {
                continue;
            }
            try {
                victim.release(consumer);
                Msg.info(this, "Evicted idle cached program (cap " + MAX_CACHED_PROGRAMS
                        + ", " + openPrograms.size() + " remain): " + victimKey);
            } catch (Exception ex) {
                Msg.warn(this, "Error releasing evicted program " + victimKey + ": "
                        + ex.getMessage());
            }
        }
    }

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
        // Resolve the Program first (existing logic), then apply the
        // optional project-folder scope guard. The guard is OFF by default
        // (env var GHIDRA_MCP_PROJECT_FOLDER unset) so general users see no
        // behavior change. Only when the user opts in via the env var does
        // a Program whose DomainFile path is outside the configured prefix
        // get treated as not-found (returns null).
        Program resolved = getProgramInternal(name);
        if (resolved == null) return null;
        SecurityConfig sc = SecurityConfig.getInstance();
        if (!sc.hasProjectFolderScope()) return resolved;
        DomainFile df = resolved.getDomainFile();
        String path = df != null ? df.getPathname() : null;
        if (sc.isPathInProjectScope(path)) return resolved;
        Msg.warn(this,
            "Project-folder scope guard: refusing program at '" + path
            + "' (request='" + name + "', scope='" + sc.getProjectFolderScope() + "')");
        return null;
    }

    /**
     * Existing program-resolution logic. Renamed from getProgram() so the
     * public entry point can apply the project-folder scope guard around it
     * without restructuring the resolution cascade.
     */
    private Program getProgramInternal(String name) {
        if (name == null || name.trim().isEmpty()) {
            return getCurrentProgram();
        }

        String searchName = name.trim();

        // 1. Check all running CodeBrowsers for this program FIRST.
        //
        // This must precede the path/name caches. The cache can hold an
        // orphaned Program whose underlying DomainFile was severed by a
        // checkout/checkin cycle or project refresh; in that case the
        // CodeBrowser will hold a different Program object for the same
        // DomainFile path. Returning the cached orphan would route writes to
        // a ghost Program — saves silently fail with "Location does not exist
        // for a save operation!" and the user's CodeBrowser shows none of
        // the applied changes (see Recover_OrphanedProgramSaveAs.java for
        // the recovery procedure that motivated this fix).
        List<Program> cbPrograms = collectCodeBrowserPrograms();

        // 1a. Path match — only when an absolute project path is given. This
        // is the precise check: identical DomainFile pathname implies the
        // CodeBrowser has the live Program for the requested file.
        if (searchName.startsWith("/")) {
            for (Program prog : cbPrograms) {
                DomainFile df = prog.getDomainFile();
                if (df != null && searchName.equals(df.getPathname())) {
                    return prog;
                }
            }
        }

        // 1b. Exact name match (program filename)
        for (Program prog : cbPrograms) {
            if (prog.getName().equalsIgnoreCase(searchName)) {
                return prog;
            }
        }
        // 1c. Partial name match
        for (Program prog : cbPrograms) {
            if (prog.getName().toLowerCase().contains(searchName.toLowerCase())) {
                return prog;
            }
        }

        // 2. Path-based cache (only when no CodeBrowser has the program).
        // Validate the cached entry is still usable; skip if closed.
        if (searchName.startsWith("/")) {
            String cacheKey = pathToName.get(searchName);
            if (cacheKey != null) {
                Program cached = openPrograms.get(cacheKey);
                if (cached != null && !cached.isClosed()) {
                    touch(cacheKey);
                    return cached;
                }
            }
        }

        // 3. Name-based cache (avoid path-form collisions)
        if (!searchName.startsWith("/")) {
            Program cached = openPrograms.get(searchName);
            if (cached != null && !cached.isClosed()) {
                touch(searchName);
                return cached;
            }
            // Case-insensitive cache lookup
            for (Map.Entry<String, Program> entry : openPrograms.entrySet()) {
                if (entry.getKey().equalsIgnoreCase(searchName)) {
                    Program p = entry.getValue();
                    if (p != null && !p.isClosed()) {
                        touch(entry.getKey());
                        return p;
                    }
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
            touch(cacheKey);
            evictExcessPrograms(program);
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
                touch(cacheKey);
                evictExcessPrograms(program);
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
        lastAccessNanos.clear();
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
            lastAccessNanos.remove(key);
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
