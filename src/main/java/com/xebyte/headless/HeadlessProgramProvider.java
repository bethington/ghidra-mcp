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
import ghidra.app.plugin.core.archive.HeadlessArchiveBridge;
import ghidra.app.util.importer.AutoImporter;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.Loaded;
import ghidra.app.util.opinion.LoadResults;
import ghidra.base.project.GhidraProject;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectData;
import ghidra.framework.model.ProjectLocator;
import ghidra.framework.model.ProjectManager;
import ghidra.framework.project.DefaultProjectManager;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.lang.LanguageService;
import ghidra.program.model.listing.Program;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TaskMonitor;

import java.io.File;
import java.util.ArrayList;
import java.util.LinkedHashMap;
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

    /**
     * Whether a program with exactly this name is currently loaded in memory.
     *
     * <p>Unlike {@link #getProgram(String)} this does <em>not</em> fall back to
     * partial matching — overwrite protection must key off the precise
     * destination name, not a fuzzy substring hit. Exact and case-insensitive
     * matches both count as "open".
     */
    private boolean isProgramOpen(String name) {
        return exactOpenProgram(name) != null;
    }

    /**
     * Exact (then case-insensitive) lookup of a loaded program by name.
     *
     * <p>Unlike {@link #getProgram(String)} this never falls back to fuzzy
     * substring matching — callers that resolve a precise destination
     * (overwrite protection, GZF export) must not silently act on a similarly
     * named program.
     *
     * @return the matching open Program, or {@code null} when none matches
     */
    private Program exactOpenProgram(String name) {
        if (name == null || name.isEmpty()) {
            return null;
        }
        Program exact = openPrograms.get(name);
        if (exact != null) {
            return exact;
        }
        for (Map.Entry<String, Program> entry : openPrograms.entrySet()) {
            if (entry.getKey().equalsIgnoreCase(name)) {
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
            registerProgram(program);
        }
    }

    /**
     * Track a newly-opened Program in {@link #openPrograms}, releasing any
     * prior different instance held under the same name.
     * <p>
     * {@code Program.getName()} is just the leaf filename (e.g.
     * {@code D2Client.dll}), so importing two versions of the same binary —
     * or the same filename from two folders — would otherwise overwrite the
     * earlier map entry without {@code release()}ing it. The orphaned
     * Program's DomainObject consumer reference and DB buffers then stay
     * live for the JVM's lifetime, invisibly accumulating toward the
     * ~5-open-program crash ceiling.
     */
    private void registerProgram(Program program) {
        String name = program.getName();
        Program prior = openPrograms.put(name, program);
        if (prior != null && prior != program) {
            Msg.warn(this, "Program name collision on '" + name
                + "' — releasing previously-tracked instance to avoid a leak. "
                + "Consider closing the earlier program explicitly before "
                + "loading another with the same filename.");
            try {
                prior.release(this);
            } catch (Exception e) {
                Msg.warn(this, "Error releasing displaced program '" + name
                    + "': " + e.getMessage());
            }
            if (currentProgram == prior) {
                currentProgram = program;
            }
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
            // When a project is open, prefer opening an existing DomainFile with
            // the same name (idempotent re-load) over re-importing — AutoImporter
            // would otherwise throw DuplicateNameException on subsequent calls.
            if (project != null) {
                Program existing = openExistingByName(file.getName());
                if (existing != null) {
                    Msg.info(this, "Reopened existing program from project: "
                        + existing.getName() + " (" + file.getAbsolutePath() + ")");
                    return existing;
                }
            }

            MessageLog log = new MessageLog();
            LoadResults<Program> loadResults = AutoImporter.importByUsingBestGuess(
                file,
                project,  // pass active project so the DomainFile has a real location
                          // (was null → DomainFileProxy → df.save() throws
                          // "Location does not exist for a save operation!")
                "/",   // folder path (ignored when project is null → in-memory)
                this,  // consumer
                log,
                monitor
            );

            // AutoImporter returns Loaded<T> wrappers whose DomainFile is still a
            // transient proxy until save() materialises them into the project tree.
            // Without this step, /save_all_programs later throws ReadOnlyException:
            // "Location does not exist for a save operation!".
            if (loadResults != null && project != null) {
                loadResults.save(monitor);
            }

            Program program = null;
            if (loadResults != null) {
                program = loadResults.getPrimaryDomainObject();
            }

            if (program != null) {
                registerProgram(program);
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
     * Load a raw binary with an explicit language / compiler spec.
     *
     * Used for firmware blobs and other raw images where AutoImporter's best-guess
     * format detection has no header to latch onto (e.g. ARM Cortex-M .mem dumps).
     * Mirrors {@link #loadProgramFromFile(File)} for openPrograms / currentProgram
     * bookkeeping so subsequent /list_functions, /decompile_function, etc. resolve
     * the result transparently.
     *
     * @param file         The raw binary file
     * @param languageId   Ghidra language ID, e.g. "ARM:LE:32:Cortex"
     * @param compilerSpecId Optional compiler-spec ID; empty/null falls back to the language default
     * @return The loaded Program, or null on failure
     */
    public Program loadProgramFromFileWithLanguage(File file, String languageId, String compilerSpecId) {
        if (!file.exists()) {
            Msg.error(this, "File not found: " + file.getAbsolutePath());
            return null;
        }
        if (languageId == null || languageId.trim().isEmpty()) {
            Msg.error(this, "loadProgramFromFileWithLanguage requires a non-empty languageId");
            return null;
        }
        // Normalize before constructing IDs: a doc-copied " ARM:LE:32:Cortex "
        // passes the non-empty check above but fails the LanguageID lookup.
        languageId = languageId.trim();
        String normalizedCompilerSpecId =
            (compilerSpecId == null) ? "" : compilerSpecId.trim();

        try {
            // Same idempotency guard as loadProgramFromFile: if a project is
            // open and a same-named DomainFile already exists, reopen it
            // rather than re-importing (which would throw DuplicateNameException).
            if (project != null) {
                Program existing = openExistingByName(file.getName());
                if (existing != null) {
                    Msg.info(this, "Reopened existing raw binary from project: "
                        + existing.getName() + " (" + file.getAbsolutePath() + ")");
                    return existing;
                }
            }

            LanguageService langService = DefaultLanguageService.getLanguageService();
            Language language = langService.getLanguage(new LanguageID(languageId));

            CompilerSpec compilerSpec;
            if (!normalizedCompilerSpecId.isEmpty()) {
                compilerSpec = language.getCompilerSpecByID(new CompilerSpecID(normalizedCompilerSpecId));
            } else {
                compilerSpec = language.getDefaultCompilerSpec();
            }

            MessageLog log = new MessageLog();
            Loaded<Program> loaded = AutoImporter.importAsBinary(
                file,
                project, // pass active project so the DomainFile has a real location
                         // (was null → DomainFileProxy → df.save() throws
                         // "Location does not exist for a save operation!")
                "/",    // folder path (ignored when project is null → in-memory)
                language,
                compilerSpec,
                this,   // consumer
                log,
                monitor
            );

            // Materialise the Loaded into the project tree — see twin block in
            // loadProgramFromFile for the full rationale.
            if (loaded != null && project != null) {
                loaded.save(monitor);
            }

            Program program = null;
            if (loaded != null) {
                program = loaded.getDomainObject(this);
            }

            if (program != null) {
                registerProgram(program);
                if (currentProgram == null) {
                    currentProgram = program;
                }
                Msg.info(this, "Loaded raw binary: " + program.getName()
                    + " (" + file.getAbsolutePath() + ") as " + languageId);
            } else {
                Msg.error(this, "Failed to load raw binary from: " + file.getAbsolutePath());
                if (!log.toString().isEmpty()) {
                    Msg.error(this, "Import log: " + log.toString());
                }
            }

            return program;
        } catch (Exception e) {
            Msg.error(this, "Error loading raw binary from file: " + file.getAbsolutePath()
                + " (language=" + languageId + ")", e);
            return null;
        }
    }

    /**
     * Look up a program already imported into the open project by file name and
     * return an opened {@link Program} backed by its {@link DomainFile}.
     *
     * <p>Used by {@link #loadProgramFromFile(File)} and
     * {@link #loadProgramFromFileWithLanguage(File, String, String)} to make
     * repeated load calls idempotent — re-importing under the same name would
     * otherwise throw {@code DuplicateNameException}.
     *
     * @param name DomainFile name (typically {@code file.getName()})
     * @return the opened Program if an entry exists in the project tree, or
     *         {@code null} when no project is open or no match is found
     */
    private Program openExistingByName(String name) {
        if (project == null || name == null || name.isEmpty()) return null;
        try {
            // Hot path: already opened in this session.
            Program cached = openPrograms.get(name);
            if (cached != null) return cached;

            // Idempotency is scoped to the import location (root): the loaders
            // always import under folder "/", so a recursive search could reopen
            // a same-named program from a different folder and break the
            // intended "reload the file I just imported" contract.
            ProjectData pd = project.getProjectData();
            DomainFile df = pd.getFile("/" + name);
            if (df == null) return null;

            Program program = (Program) df.getDomainObject(this, true, false, monitor);
            if (program != null) {
                openPrograms.put(program.getName(), program);
                if (currentProgram == null) {
                    currentProgram = program;
                }
            }
            return program;
        } catch (Exception e) {
            Msg.warn(this, "openExistingByName failed for '" + name + "': " + e.getMessage());
            return null;
        }
    }

    /**
     * Load a program from a Ghidra project.
     *
     * Back-compat wrapper: returns just the Program (null on failure).
     * Callers that want diagnostics on failure should use
     * {@link #loadProgramFromProjectDetailed(String)} which returns a
     * {@link ProgramLoadResult} with structured failure information.
     *
     * @param projectPath Path to the program within the project (e.g., "/D2Client.dll")
     * @return The loaded Program, or null on failure
     */
    public Program loadProgramFromProject(String projectPath) {
        return loadProgramFromProjectDetailed(projectPath).program;
    }

    /**
     * Load a program from a Ghidra project with structured diagnostics.
     *
     * Discussion #119 surfaced the recurring "checkout succeeded, can't open"
     * pattern: users connect a headless Docker container to a remote Ghidra
     * server, run /server/version_control/checkout (which acquires the
     * server-side lock on the standalone {@link GhidraServerManager}
     * connection), then call /load_program_from_project and get a flat
     * "Program not found" error. The usual root cause is one of:
     *
     *   1. The locally-open project is a standalone project, not a shared
     *      project bound to the server. /server/version_control/checkout
     *      operates on the GhidraServerManager's standalone connection,
     *      which doesn't sync content to a non-shared local project.
     *
     *   2. The path doesn't match the project's folder hierarchy (case,
     *      leading slash, server folder layout vs container folder layout).
     *
     *   3. The project IS shared but the file hasn't been pulled to the
     *      local cache yet — opening it triggers the server fetch but the
     *      first call can fail if the server is unreachable.
     *
     * This method returns a structured result so the endpoint handler can
     * surface what actually went wrong rather than the legacy bare null.
     */
    public ProgramLoadResult loadProgramFromProjectDetailed(String projectPath) {
        if (project == null) {
            return ProgramLoadResult.failure(
                "No project open. Call /open_project first, pointing at the .gpr "
                + "or project directory you want to work against.");
        }

        ProjectData projectData;
        try {
            projectData = project.getProjectData();
        } catch (Exception e) {
            return ProgramLoadResult.failure(
                "Could not access project data: " + e.getMessage());
        }

        DomainFile domainFile;
        try {
            domainFile = projectData.getFile(projectPath);
        } catch (Exception e) {
            return ProgramLoadResult.failure(
                "Path lookup failed: " + e.getMessage());
        }

        if (domainFile == null) {
            // Build a diagnostic with the project's actual file layout so the
            // user can see what's available instead of guessing.
            List<String> available = new ArrayList<>();
            try {
                collectProgramPaths(projectData.getRootFolder(), "", available, 50);
            } catch (Exception e) {
                // Best-effort — diagnostic shouldn't itself fail.
            }

            String serverHint = describeServerBinding(projectData);
            return ProgramLoadResult.notFound(projectPath, available, serverHint);
        }

        try {
            Program program = (Program) domainFile.getDomainObject(this, true, false, monitor);
            if (program == null) {
                String serverHint = describeServerBinding(projectData);
                return ProgramLoadResult.failure(
                    "domainFile.getDomainObject returned null for: " + projectPath
                    + (serverHint.isEmpty() ? "" : " (" + serverHint + ")"));
            }
            registerProgram(program);
            if (currentProgram == null) {
                currentProgram = program;
            }
            Msg.info(this, "Loaded program from project: " + program.getName());
            return ProgramLoadResult.success(program);
        } catch (Exception e) {
            String serverHint = describeServerBinding(projectData);
            Msg.error(this, "Error loading program from project: " + projectPath, e);
            return ProgramLoadResult.failure(
                "Open failed (" + e.getClass().getSimpleName() + "): " + e.getMessage()
                + (serverHint.isEmpty() ? "" : ". " + serverHint));
        }
    }

    /** Walk the project tree collecting *Program* paths, capped at maxResults. */
    private void collectProgramPaths(DomainFolder folder, String pathPrefix, List<String> out, int maxResults) {
        if (out.size() >= maxResults) return;
        try {
            for (DomainFile file : folder.getFiles()) {
                if (out.size() >= maxResults) return;
                if ("Program".equals(file.getContentType())) {
                    out.add(pathPrefix + "/" + file.getName());
                }
            }
            for (DomainFolder subfolder : folder.getFolders()) {
                if (out.size() >= maxResults) return;
                collectProgramPaths(subfolder, pathPrefix + "/" + subfolder.getName(), out, maxResults);
            }
        } catch (Exception ignore) {
            // best-effort
        }
    }

    /**
     * Describe whether the open project is server-bound, for inclusion in
     * error diagnostics. Empty string when not server-bound (the standalone
     * case). Used by both {@link #loadProgramFromProjectDetailed} and
     * {@link #getProjectServerInfo} so the description is consistent.
     */
    private String describeServerBinding(ProjectData projectData) {
        try {
            ghidra.framework.client.RepositoryAdapter repo = projectData.getRepository();
            if (repo == null) {
                return "Project is local-only (not bound to a Ghidra Server). "
                    + "If you intended a server-checked-out file, the local project "
                    + "must be a shared project — create one via Ghidra GUI or "
                    + "`analyzeHeadless -connect ghidra://host:port/repo` and "
                    + "mount it into this container, then reopen it via "
                    + "/open_project.";
            }
            // Only RepositoryAdapter.getName() is touched here — the
            // server host:port lives behind getServer().getServerInfo(),
            // whose return type differs across Ghidra 12.0.x point builds
            // (String on some, ServerInfo on others) and broke the CI
            // build. The repo name + "bound to a server" is the
            // diagnostic the operator actually needs; they configured the
            // host:port themselves.
            return "Project is bound to a Ghidra Server (repo '" + repo.getName() + "')";
        } catch (Exception e) {
            return "Server binding probe failed: " + e.getClass().getSimpleName();
        }
    }

    /**
     * Server-binding info for the open project, or {@code null} when no
     * project is open. Exposed to the management service so /get_project_info
     * can surface "is this project shared?" without re-implementing the
     * probe.
     */
    public ServerBindingInfo getProjectServerInfo() {
        if (project == null) return null;
        try {
            ghidra.framework.client.RepositoryAdapter repo = project.getProjectData().getRepository();
            if (repo == null) {
                return new ServerBindingInfo(false, null, null);
            }
            // serverInfo (host:port) is intentionally left null — see
            // describeServerBinding: getServer().getServerInfo()'s return
            // type isn't stable across Ghidra 12.0.x point builds. The
            // serverBound flag + repo name are the load-bearing fields.
            return new ServerBindingInfo(true, null, repo.getName());
        } catch (Exception e) {
            return new ServerBindingInfo(false, null, null);
        }
    }

    /** Structured result from {@link #loadProgramFromProjectDetailed}. */
    public static class ProgramLoadResult {
        public final boolean success;
        public final Program program;          // null on failure
        public final String error;             // null on success
        public final List<String> availablePaths; // null unless notFound
        public final String serverHint;        // null unless server-relevant

        private ProgramLoadResult(boolean success, Program program, String error,
                                  List<String> availablePaths, String serverHint) {
            this.success = success;
            this.program = program;
            this.error = error;
            this.availablePaths = availablePaths;
            this.serverHint = serverHint;
        }

        public static ProgramLoadResult success(Program program) {
            return new ProgramLoadResult(true, program, null, null, null);
        }

        public static ProgramLoadResult failure(String error) {
            return new ProgramLoadResult(false, null, error, null, null);
        }

        public static ProgramLoadResult notFound(String requestedPath, List<String> available, String serverHint) {
            String msg = "Program not found in project: " + requestedPath;
            if (available != null && !available.isEmpty()) {
                msg += " (project contains " + available.size() + " program file(s); first few: "
                    + String.join(", ", available.subList(0, Math.min(5, available.size()))) + ")";
            } else if (available != null) {
                msg += " (project has no program files)";
            }
            return new ProgramLoadResult(false, null, msg, available, serverHint);
        }
    }

    /** Shared-project / server binding state for {@link #getProjectServerInfo}. */
    public static class ServerBindingInfo {
        public final boolean serverBound;
        public final String serverInfo;  // host:port string, or null when not bound
        public final String repoName;    // repo name on the server, or null

        public ServerBindingInfo(boolean serverBound, String serverInfo, String repoName) {
            this.serverBound = serverBound;
            this.serverInfo = serverInfo;
            this.repoName = repoName;
        }
    }

    /**
     * Close a specific program.
     *
     * @param program The program to close
     */
    @Override
    public boolean closeProgram(Program program) {
        if (program == null) {
            return false;
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
        return true;
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
     * Check a program back in to the shared Ghidra Server, creating a new
     * server version. This closes the #119 gap: GhidraServerManager.checkinFile
     * cannot commit (RepositoryAdapter exposes no checkin), so a checkin must
     * run through DomainFile.checkin() on the open shared project.
     *
     * Any pending edits on the open DomainObject are saved into the local
     * project database, then the object is released BEFORE checkin. Releasing
     * first matters: checking in while the program is still open forces
     * keepCheckedOut=true regardless of the handler (Ghidra logs "File
     * currently open - must keep checked-out"), so keepCheckedOut=false only
     * actually drops the server checkout once the object is closed.
     *
     * @param path            project path of the file (e.g. "/scratch/writetest");
     *                        null/empty uses the current program's own file
     * @param comment         checkin comment (also used for the pre-checkin save)
     * @param keepCheckedOut  keep the file checked out after the new version lands
     * @return result map with status/version_before/version/version_bumped, or error
     */
    public Map<String, Object> checkinProgram(String path, String comment, boolean keepCheckedOut) {
        Map<String, Object> out = new LinkedHashMap<>();
        if (project == null) {
            out.put("success", false);
            out.put("error", "No project open. Call /open_project first.");
            return out;
        }
        if (comment == null) {
            comment = "";
        }

        ProjectData projectData;
        try {
            projectData = project.getProjectData();
        } catch (Exception e) {
            out.put("success", false);
            out.put("error", "Could not access project data: " + e.getMessage());
            return out;
        }

        Program prog;
        DomainFile file;
        if (path == null || path.isEmpty()) {
            prog = currentProgram;
            if (prog == null) {
                out.put("success", false);
                out.put("error", "No current program open; supply 'path'.");
                return out;
            }
            file = prog.getDomainFile();
            path = file.getPathname();
        } else {
            try {
                file = projectData.getFile(path);
            } catch (Exception e) {
                out.put("success", false);
                out.put("error", "Path lookup failed: " + e.getMessage());
                return out;
            }
            if (file == null) {
                out.put("success", false);
                out.put("error", "File not found in project: " + path);
                return out;
            }
            // Only treat a same-named open program as ours if its DomainFile matches.
            Program candidate = openPrograms.get(file.getName());
            prog = (candidate != null && file.equals(candidate.getDomainFile())) ? candidate : null;
        }

        if (!file.isVersioned()) {
            out.put("success", false);
            out.put("error", "File is not under version control: " + path
                + " (add it first, or check out a versioned file)");
            return out;
        }
        if (!file.isCheckedOut()) {
            out.put("success", false);
            out.put("error", "File is not checked out: " + path);
            return out;
        }

        try {
            // Save pending edits into the local project DB, then release the
            // open object so the checkout can be dropped on checkin.
            if (prog != null) {
                try {
                    if (prog.isChanged()) {
                        prog.save(comment.isEmpty() ? "checkin" : comment, monitor);
                    }
                } catch (Exception e) {
                    out.put("success", false);
                    out.put("error", "Save before checkin failed: " + e.getMessage());
                    return out;
                }
                closeProgram(prog);
            }

            int versionBefore = file.getVersion();
            final String cmt = comment;
            final boolean keep = keepCheckedOut;
            file.checkin(new ghidra.framework.data.CheckinHandler() {
                public boolean keepCheckedOut() { return keep; }
                public String getComment() { return cmt; }
                public boolean createKeepFile() { return false; }
            }, monitor);
            int versionAfter = file.getVersion();

            out.put("success", true);
            out.put("status", "checked_in");
            out.put("path", path);
            out.put("version_before", versionBefore);
            out.put("version", versionAfter);
            out.put("version_bumped", versionAfter > versionBefore);
            out.put("checked_out", file.isCheckedOut());
            out.put("comment", comment);
            out.put("keep_checked_out", keepCheckedOut);
            Msg.info(this, "Checked in " + path + " (v" + versionBefore + " -> v" + versionAfter + ")");
            return out;
        } catch (Exception e) {
            Msg.error(this, "Checkin failed for " + path, e);
            out.put("success", false);
            out.put("error", "Checkin failed (" + e.getClass().getSimpleName() + "): " + e.getMessage());
            return out;
        }
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
    public Project getProject() {
        return project;
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

            // Go through the low-level ProjectManager so we can pass
            // resetOwner=true. GhidraProject.openProject(..., restore=true) only
            // toggles restoreDefault and hard-codes resetOwner=false, leaving
            // project.prp pinned to whichever username originally created the
            // project. That breaks .tar.gz round-trips between hosts (or between
            // a container running as root and a standalone Ghidra GUI). With
            // resetOwner=true, project.prp is rewritten to the current user on
            // every open.
            ProjectLocator locator = new ProjectLocator(projectDir.getAbsolutePath(), projectName);
            ProjectManager pm = new HeadlessProjectManager();
            ghidraProject = null;
            project = pm.openProject(locator, /*restoreDefault*/ true, /*resetOwner*/ true);

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

    // ========================================================================
    // GZF export / import (Ghidra packed-database format)
    // ========================================================================

    /**
     * Resolve a DomainFile in the open project by exact path or by leading-slash
     * path. When neither matches, fall back to a bare program-name search across
     * all folders. Returns null when no project is open or when no match is
     * found.
     *
     * @throws AmbiguousProgramException when a bare name matches files in more
     *     than one folder \u2014 the caller must supply a full project path to
     *     disambiguate rather than have us guess the wrong program.
     */
    private DomainFile findDomainFile(String programIdent) throws AmbiguousProgramException {
        if (project == null || programIdent == null || programIdent.isEmpty()) return null;
        List<DomainFile> matches = new ArrayList<>();
        try {
            ProjectData pd = project.getProjectData();
            DomainFile f = pd.getFile(programIdent);
            if (f != null) return f;
            if (!programIdent.startsWith("/")) {
                f = pd.getFile("/" + programIdent);
                if (f != null) return f;
            }
            collectByName(pd.getRootFolder(), programIdent, matches);
        } catch (Exception e) {
            Msg.warn(this, "findDomainFile failed for '" + programIdent + "': " + e.getMessage());
            return null;
        }
        if (matches.isEmpty()) return null;
        if (matches.size() > 1) {
            throw new AmbiguousProgramException(programIdent, matches.size());
        }
        return matches.get(0);
    }

    private void collectByName(DomainFolder folder, String name, List<DomainFile> out) {
        try {
            for (DomainFile f : folder.getFiles()) {
                if (name.equals(f.getName())) out.add(f);
            }
            for (DomainFolder sub : folder.getFolders()) {
                collectByName(sub, name, out);
            }
        } catch (Exception ignore) {
            // best-effort
        }
    }

    /**
     * Raised when a bare program name matches files in multiple project folders,
     * so resolving it would have to guess which one the caller meant.
     */
    private static final class AmbiguousProgramException extends Exception {
        AmbiguousProgramException(String ident, int matchCount) {
            super("'" + ident + "' is ambiguous: " + matchCount
                + " programs share this filename in different project folders. "
                + "Pass a full project path (e.g. /folder/" + ident + ") to disambiguate.");
        }
    }

    /**
     * Resolve a DomainFolder by path, optionally creating missing intermediate folders.
     * Returns null when no project is open or when {@code createMissing} is false and the
     * folder doesn't exist.
     */
    private DomainFolder resolveFolder(String folderPath, boolean createMissing) {
        if (project == null) return null;
        String p = (folderPath == null || folderPath.isEmpty()) ? "/" : folderPath;
        if (!p.startsWith("/")) p = "/" + p;
        try {
            ProjectData pd = project.getProjectData();
            DomainFolder existing = pd.getFolder(p);
            if (existing != null) return existing;
            if (!createMissing) return null;
            DomainFolder cur = pd.getRootFolder();
            for (String part : p.split("/")) {
                if (part.isEmpty()) continue;
                if (part.equals(".") || part.equals("..")) {
                    Msg.warn(this, "resolveFolder rejecting traversal segment '"
                        + part + "' in '" + folderPath + "'");
                    return null;
                }
                DomainFolder next = cur.getFolder(part);
                if (next == null) next = cur.createFolder(part);
                cur = next;
            }
            return cur;
        } catch (Exception e) {
            Msg.warn(this, "resolveFolder failed for '" + folderPath + "': " + e.getMessage());
            return null;
        }
    }

    /**
     * Export a program to a GZF (packed-database) file on disk.
     *
     * <p>Lookup order:
     * <ol>
     *   <li>An in-memory program (loaded via {@code /load_program} or
     *       {@code /load_program_from_project}) — packed via
     *       {@link ghidra.framework.data.DomainObjectAdapterDB#saveToPackedFile}.
     *       This captures the live RAM state including any analyst edits.</li>
     *   <li>A project DomainFile (not currently loaded) — packed via
     *       {@link DomainFile#packFile}. This is the on-disk state.</li>
     * </ol>
     */
    public ExportResult exportProgramToGzf(String programIdent, File output) {
        if (programIdent == null || programIdent.isEmpty()) {
            return ExportResult.failure("program identifier required");
        }
        if (output == null) {
            return ExportResult.failure("output path required");
        }
        File parent = output.getParentFile();
        if (parent == null || !parent.isDirectory()) {
            return ExportResult.failure("output parent directory does not exist: "
                + (parent == null ? "<none>" : parent.getAbsolutePath()));
        }
        if (output.exists()) {
            return ExportResult.failure("output file already exists: " + output.getAbsolutePath());
        }

        // Prefer the live in-memory program — it includes unsaved analyst edits.
        // Exact match only: getProgram()'s fuzzy substring fallback could pack
        // the wrong program when several open names overlap.
        Program live = exactOpenProgram(programIdent);
        if (live != null) {
            try {
                live.saveToPackedFile(output, monitor);
                return ExportResult.success(live.getName(), output.getAbsolutePath(), output.length());
            } catch (Exception e) {
                Msg.error(this, "saveToPackedFile failed for '" + programIdent + "'", e);
                return ExportResult.failure("saveToPackedFile failed ("
                    + e.getClass().getSimpleName() + "): " + e.getMessage());
            }
        }

        // Fallback: the program isn't loaded but lives in the open project.
        if (project == null) {
            return ExportResult.failure("Program not loaded and no project open. "
                + "Call /load_program (file) or /open_project + /load_program_from_project first.");
        }
        DomainFile df;
        try {
            df = findDomainFile(programIdent);
        } catch (AmbiguousProgramException e) {
            return ExportResult.failure(e.getMessage());
        }
        if (df == null) {
            return ExportResult.failure("Program not found in open programs or project: " + programIdent);
        }
        try {
            df.packFile(output, monitor);
            return ExportResult.success(df.getName(), output.getAbsolutePath(), output.length());
        } catch (Exception e) {
            Msg.error(this, "packFile failed for '" + programIdent + "'", e);
            return ExportResult.failure("packFile failed (" + e.getClass().getSimpleName()
                + "): " + e.getMessage());
        }
    }

    /**
     * Import a GZF (packed-database) file into the open project under {@code targetFolder/targetName}.
     *
     * <p>Missing intermediate folders are created. When {@code targetName} is null or empty the
     * GZF file's basename (sans {@code .gzf}) is used. When the destination already contains a
     * file with the chosen name, the operation either deletes-and-replaces (when {@code overwrite}
     * is true) or fails with a structured error.
     */
    public ImportResult importProgramFromGzf(File gzf, String targetFolder, String targetName, boolean overwrite) {
        // Validate the caller-controlled destination name up front, before any
        // project/file work, so it's reachable in offline tests and a separator
        // or traversal segment never reaches resolveFolder/createFile.
        if (targetName != null && !targetName.isEmpty()) {
            String invalid = HeadlessPaths.validateFilename(targetName);
            if (invalid != null) {
                return ImportResult.failure("invalid target_name: " + invalid);
            }
        }
        if (project == null) {
            return ImportResult.failure("No project open. Call /open_project first.");
        }
        if (gzf == null || !gzf.isFile()) {
            return ImportResult.failure("gzf file not found: "
                + (gzf == null ? "<null>" : gzf.getAbsolutePath()));
        }
        if (!gzf.getName().toLowerCase().endsWith(".gzf")) {
            return ImportResult.failure("not a .gzf file: " + gzf.getName());
        }
        DomainFolder folder = resolveFolder(targetFolder, true);
        if (folder == null) {
            return ImportResult.failure("could not resolve target_folder: " + targetFolder);
        }
        String chosenName = (targetName == null || targetName.isEmpty())
            ? gzf.getName().replaceFirst("(?i)\\.gzf$", "")
            : targetName;
        try {
            DomainFile existing = folder.getFile(chosenName);
            if (existing != null && !overwrite) {
                return ImportResult.failure("program already exists at "
                    + folder.getPathname() + "/" + chosenName
                    + " (pass overwrite=true to replace).");
            }
            // Enforce the "won't overwrite a loaded program" contract up front,
            // before touching the project tree. Relying on FileInUseException
            // from setName/delete would leave the file half-renamed depending
            // on Ghidra's locking, so check the open-program bookkeeping first
            // and fail with a clear structured error that mutates nothing.
            if (existing != null && isProgramOpen(chosenName)) {
                return ImportResult.failure("cannot overwrite '"
                    + folder.getPathname() + "/" + chosenName
                    + "': program is currently loaded in memory. "
                    + "Close or switch away from it before re-importing.");
            }
            // Recoverable overwrite: move the original aside first and only
            // delete it once the new file is created. If createFile fails
            // (corrupt .gzf, I/O error) the original is renamed back, so the
            // overwrite is never destructive on a failed import.
            DomainFile backup = null;
            if (existing != null) {
                String backupName = chosenName + ".bak-" + System.currentTimeMillis();
                existing.setName(backupName);
                backup = existing;
            }
            try {
                DomainFile created = folder.createFile(chosenName, gzf, monitor);
                if (backup != null) {
                    backup.delete();
                }
                return ImportResult.success(folder.getPathname(), created.getName(), created.getContentType());
            } catch (Exception e) {
                if (backup != null) {
                    try {
                        backup.setName(chosenName);
                    } catch (Exception restoreEx) {
                        Msg.error(this, "failed to restore '" + chosenName
                            + "' after import failure (backup left at " + backup.getName() + ")", restoreEx);
                    }
                }
                throw e;
            }
        } catch (Exception e) {
            Msg.error(this, "GZF import failed for '" + gzf.getAbsolutePath() + "'", e);
            return ImportResult.failure("import failed (" + e.getClass().getSimpleName()
                + "): " + e.getMessage());
        }
    }

    /**
     * Archive the currently open project to a Ghidra-native {@code .gar} file.
     *
     * <p>Unlike {@link #exportProgramToGzf}, this captures the entire project
     * (all programs, folders, tool settings, version-control metadata) in a
     * format that Ghidra's GUI can re-import via <em>File &rarr; Restore Project</em>.
     */
    public ArchiveResult archiveCurrentProject(File garFile) {
        if (project == null) {
            return ArchiveResult.failure("No project open. Call /open_project first.");
        }
        if (garFile == null) {
            return ArchiveResult.failure("output path required");
        }
        File parent = garFile.getParentFile();
        if (parent == null || !parent.isDirectory()) {
            return ArchiveResult.failure("output parent directory does not exist: "
                + (parent == null ? "<none>" : parent.getAbsolutePath()));
        }
        if (garFile.exists()) {
            return ArchiveResult.failure("output file already exists: " + garFile.getAbsolutePath());
        }
        if (!garFile.getName().toLowerCase().endsWith(HeadlessArchiveBridge.ARCHIVE_EXTENSION)) {
            return ArchiveResult.failure("output must end in " + HeadlessArchiveBridge.ARCHIVE_EXTENSION
                + ": " + garFile.getName());
        }
        try {
            HeadlessArchiveBridge.archive(project, garFile, monitor);
            return ArchiveResult.success(project.getName(), garFile.getAbsolutePath(), garFile.length());
        } catch (Exception e) {
            Msg.error(this, "archive failed for project '" + project.getName() + "'", e);
            return ArchiveResult.failure("archive failed (" + e.getClass().getSimpleName()
                + "): " + e.getMessage());
        }
    }

    /**
     * Restore a Ghidra {@code .gar} archive into a fresh on-disk project.
     *
     * <p>Any currently-open project is closed first. The new project is created
     * at {@code parentDir/projectName.rep} + {@code projectName.gpr}; the
     * restored project is <em>not</em> re-opened automatically \u2014 callers
     * should follow up with {@link #openProject} so that owner reset and the
     * usual project-open bookkeeping run via the same code path as a
     * user-driven open.
     */
    public RestoreResult restoreProject(File garFile, String parentDir, String projectName) {
        if (garFile == null || !garFile.isFile()) {
            return RestoreResult.failure("gar file not found: "
                + (garFile == null ? "<null>" : garFile.getAbsolutePath()));
        }
        if (!garFile.getName().toLowerCase().endsWith(HeadlessArchiveBridge.ARCHIVE_EXTENSION)) {
            return RestoreResult.failure("not a " + HeadlessArchiveBridge.ARCHIVE_EXTENSION
                + " file: " + garFile.getName());
        }
        if (parentDir == null || parentDir.isEmpty()) {
            return RestoreResult.failure("parent_dir required");
        }
        if (projectName == null || projectName.isEmpty()) {
            return RestoreResult.failure("project_name required");
        }
        String invalidName = HeadlessPaths.validateFilename(projectName);
        if (invalidName != null) {
            return RestoreResult.failure("invalid project_name: " + invalidName);
        }
        File parent = new File(parentDir);
        if (!parent.isDirectory()) {
            return RestoreResult.failure("parent_dir is not a directory: " + parent.getAbsolutePath());
        }
        ProjectLocator locator = new ProjectLocator(parent.getAbsolutePath(), projectName);
        if (!HeadlessPaths.isWithin(parent, locator.getProjectDir())) {
            return RestoreResult.failure("project_name escapes parent_dir: " + projectName);
        }
        if (locator.getProjectDir().exists() || locator.getMarkerFile().exists()) {
            return RestoreResult.failure("destination project already exists: "
                + locator.toString());
        }
        if (project != null) {
            closeProject();
        }
        try {
            HeadlessArchiveBridge.restore(garFile, locator, monitor);
            return RestoreResult.success(projectName, locator.getProjectDir().getAbsolutePath());
        } catch (Exception e) {
            Msg.error(this, "restore failed for '" + garFile.getAbsolutePath() + "'", e);
            return RestoreResult.failure("restore failed (" + e.getClass().getSimpleName()
                + "): " + e.getMessage());
        }
    }

    /** Structured result for {@link #archiveCurrentProject}. */
    public static class ArchiveResult {
        public final boolean success;
        public final String error;          // null on success
        public final String projectName;    // null on failure
        public final String outputPath;     // null on failure
        public final long sizeBytes;        // 0 on failure

        private ArchiveResult(boolean success, String error, String projectName, String outputPath, long sizeBytes) {
            this.success = success;
            this.error = error;
            this.projectName = projectName;
            this.outputPath = outputPath;
            this.sizeBytes = sizeBytes;
        }

        public static ArchiveResult success(String projectName, String outputPath, long sizeBytes) {
            return new ArchiveResult(true, null, projectName, outputPath, sizeBytes);
        }

        public static ArchiveResult failure(String error) {
            return new ArchiveResult(false, error, null, null, 0L);
        }
    }

    /** Structured result for {@link #restoreProject}. */
    public static class RestoreResult {
        public final boolean success;
        public final String error;          // null on success
        public final String projectName;    // null on failure
        public final String projectDir;     // null on failure

        private RestoreResult(boolean success, String error, String projectName, String projectDir) {
            this.success = success;
            this.error = error;
            this.projectName = projectName;
            this.projectDir = projectDir;
        }

        public static RestoreResult success(String projectName, String projectDir) {
            return new RestoreResult(true, null, projectName, projectDir);
        }

        public static RestoreResult failure(String error) {
            return new RestoreResult(false, error, null, null);
        }
    }

    /** Structured result for {@link #exportProgramToGzf}. */
    public static class ExportResult {
        public final boolean success;
        public final String error;          // null on success
        public final String programName;    // null on failure
        public final String outputPath;     // null on failure
        public final long sizeBytes;        // 0 on failure

        private ExportResult(boolean success, String error, String programName, String outputPath, long sizeBytes) {
            this.success = success;
            this.error = error;
            this.programName = programName;
            this.outputPath = outputPath;
            this.sizeBytes = sizeBytes;
        }

        public static ExportResult success(String programName, String outputPath, long sizeBytes) {
            return new ExportResult(true, null, programName, outputPath, sizeBytes);
        }

        public static ExportResult failure(String error) {
            return new ExportResult(false, error, null, null, 0L);
        }
    }

    /** Structured result for {@link #importProgramFromGzf}. */
    public static class ImportResult {
        public final boolean success;
        public final String error;          // null on success
        public final String folderPath;     // null on failure
        public final String programName;    // null on failure
        public final String contentType;    // null on failure

        private ImportResult(boolean success, String error, String folderPath, String programName, String contentType) {
            this.success = success;
            this.error = error;
            this.folderPath = folderPath;
            this.programName = programName;
            this.contentType = contentType;
        }

        public static ImportResult success(String folderPath, String programName, String contentType) {
            return new ImportResult(true, null, folderPath, programName, contentType);
        }

        public static ImportResult failure(String error) {
            return new ImportResult(false, error, null, null, null);
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

    /**
     * Concrete handle on {@link DefaultProjectManager} \u2014 its constructor is
     * protected so we cannot instantiate it directly. Mirrors the inner class
     * used by Ghidra's own headless analyzer.
     */
    private static final class HeadlessProjectManager extends DefaultProjectManager {
        HeadlessProjectManager() {
            super();
        }
    }
}
