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

import com.xebyte.core.AmbiguousProgramException;
import com.xebyte.core.ProgramProvider;
import com.xebyte.core.ProjectProgramProvider;
import com.xebyte.core.WriteTx;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.plugin.core.archive.HeadlessArchiveBridge;
import ghidra.base.project.GhidraProject;
import ghidra.framework.client.RepositoryAdapter;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectData;
import ghidra.framework.model.ProjectLocator;
import ghidra.framework.model.ProjectManager;
import ghidra.framework.project.DefaultProjectManager;
import ghidra.framework.store.LockException;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Headless mode implementation of ProgramProvider.
 *
 * Manages programs directly without relying on GUI services like ProgramManager.
 * Programs can be loaded from files or Ghidra project folders.
 */
public class HeadlessProgramProvider extends ProjectProgramProvider {

    private Project project;
    private GhidraProject ghidraProject;  // For headless project management

    /**
     * Create a new HeadlessProgramProvider.
     */
    public HeadlessProgramProvider() {
        // okToUpgrade: headless may upgrade a program's stored format on open. The GUI
        // may not -- an upgrade needs an exclusive checkout it must not take silently.
        super(null, true);
    }

    @Override
    protected Project project() {
        return project;
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
        // Headless has no GUI focus. Exactly one open program is unambiguous;
        // zero or many leaves nothing honest to return — inventing sticky
        // "current" state is what made a 17-program survey return one binary's
        // numbers seventeen times (headless never reassigned after the first load,
        // and /switch_program is not even registered headless).
        Program[] open = getAllOpenPrograms();
        return (open != null && open.length == 1) ? open[0] : null;
    }

    @Override
    public void setCurrentProgram(Program program) {
        // Explicit no-op: headless has no current-program concept. GUI providers
        // implement this against ProgramManager / CodeBrowser focus; pretending
        // here would reintroduce sticky omit-program state with no way to steer it.
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
     * <p>Also satisfies {@link ProgramProvider#getProject()}, which is how the
     * shared {@code @McpTool} project endpoints in {@code com.xebyte.core}
     * reach ProjectData without a PluginTool. Keep it public and keep the
     * signature — dropping it would silently make {@code /move_file},
     * {@code /move_folder} and friends GUI-only again.
     *
     * @return The current project, or null if none set
     */
    @Override
    public Project getProject() {
        return project;
    }

    /**
     * Result of {@link #openProject(String, GhidraServerManager)}. Structured so a
     * malformed {@code ghidra://} URL surfaces as an error instead of a boolean
     * false that looked like "file not found".
     */
    public static final class OpenProjectResult {
        public final boolean success;
        public final String error;
        public final String projectName;
        public final boolean shared;
        public final String repository;
        public final String localProjectDir;

        private OpenProjectResult(boolean success, String error, String projectName,
                                  boolean shared, String repository, String localProjectDir) {
            this.success = success;
            this.error = error;
            this.projectName = projectName;
            this.shared = shared;
            this.repository = repository;
            this.localProjectDir = localProjectDir;
        }

        public static OpenProjectResult ok(String projectName, boolean shared,
                                           String repository, String localProjectDir) {
            return new OpenProjectResult(true, null, projectName, shared, repository, localProjectDir);
        }

        public static OpenProjectResult fail(String error) {
            return new OpenProjectResult(false, error, null, false, null, null);
        }
    }

    /**
     * Open a local {@code .gpr} or a shared Ghidra Server repository URL.
     *
     * <p>When {@code projectPath} is a {@code ghidra://} URL, opens (or creates)
     * a persistent shared project bound to that repository. A plain filesystem
     * path keeps the pre-existing local {@code .gpr} behaviour exactly.
     *
     * @param projectPath {@code .gpr}/directory path, or {@code ghidra://host[:port]/repo}
     * @param serverManager required for URL opens (connected adapter + credentials)
     */
    public OpenProjectResult openProject(String projectPath, GhidraServerManager serverManager) {
        if (projectPath == null || projectPath.isBlank()) {
            return OpenProjectResult.fail("Project path required");
        }
        // Any ghidra: string must parse as a server URL or fail — never fall
        // through to the local .gpr branch (that would mkdir a project named
        // after the URL string).
        if (SharedProjectLocator.isGhidraUrl(projectPath)) {
            return openSharedProject(projectPath.trim(), serverManager);
        }
        return openLocalProject(projectPath.trim());
    }

    /**
     * Open a Ghidra project from a .gpr file path (local-only).
     *
     * @param projectPath Path to the .gpr file (e.g., "/projects/MyProject.gpr")
     * @return true if project was opened successfully
     */
    public boolean openProject(String projectPath) {
        return openProject(projectPath, null).success;
    }

    private OpenProjectResult openLocalProject(String projectPath) {
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
                    return OpenProjectResult.fail("No .gpr file found in: " + projectPath);
                }
                projectName = gprFiles[0].getName().replace(".gpr", "");
            }

            if (!projectDir.exists()) {
                Msg.error(this, "Project directory not found: " + projectDir.getAbsolutePath());
                return OpenProjectResult.fail(
                        "Project directory not found: " + projectDir.getAbsolutePath());
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
                return OpenProjectResult.ok(projectName, false, null, projectDir.getAbsolutePath());
            }
            Msg.error(this, "Failed to open project: " + projectPath);
            return OpenProjectResult.fail("Failed to open project: " + projectPath);
        } catch (LockException e) {
            // Two JVMs cannot share one project dir — fail loud, don't corrupt.
            Msg.error(this, "Project locked (another Ghidra instance holds it): " + projectPath, e);
            return OpenProjectResult.fail(
                    "Project locked by another Ghidra instance: " + e.getMessage());
        } catch (Exception e) {
            Msg.error(this, "Error opening project: " + projectPath, e);
            return OpenProjectResult.fail(
                    "Error opening project: " + e.getMessage());
        }
    }

    /**
     * Open-or-create a shared project bound to a Ghidra Server repository.
     *
     * <p>Same door as local open: the agent writes, so we need a real local
     * {@code .rep} for working copies — not a transient URL view.
     */
    private OpenProjectResult openSharedProject(String ghidraUrl, GhidraServerManager serverManager) {
        if (serverManager == null) {
            return OpenProjectResult.fail(
                    "Opening a ghidra:// URL requires the headless server manager "
                            + "(credentials via GHIDRA_SERVER_USER/PASSWORD, then /server/connect)");
        }

        final SharedProjectLocator.Parsed parsed;
        try {
            parsed = SharedProjectLocator.parseServerUrl(ghidraUrl);
        } catch (IllegalArgumentException e) {
            return OpenProjectResult.fail(e.getMessage());
        }

        final Path projectParent;
        try {
            projectParent = SharedProjectLocator.resolveProjectDir(parsed);
            Files.createDirectories(projectParent);
        } catch (IllegalArgumentException e) {
            return OpenProjectResult.fail(e.getMessage());
        } catch (Exception e) {
            return OpenProjectResult.fail(
                    "Cannot create shared project directory: " + e.getMessage());
        }

        final RepositoryAdapter repo;
        try {
            serverManager.ensureConnectedTo(parsed.host(), parsed.port());
            repo = serverManager.openRepository(parsed.repo());
            if (repo == null) {
                return OpenProjectResult.fail("Repository not found: " + parsed.repo());
            }
        } catch (Exception e) {
            return OpenProjectResult.fail(
                    "Server connection failed for " + parsed.host() + ":" + parsed.port()
                            + ": " + e.getMessage());
        }

        if (project != null) {
            closeProject();
        }

        // Parent is keyed by host_port_repo; project name stays the repo name
        // so DomainFile paths match what analyzeHeadless imported.
        ProjectLocator locator =
                new ProjectLocator(projectParent.toAbsolutePath().toString(), parsed.repo());
        ProjectManager pm = new HeadlessProjectManager();
        ghidraProject = null;

        try {
            if (locator.exists() || pm.projectExists(locator)) {
                project = pm.openProject(locator, /*restoreDefault*/ true, /*resetOwner*/ true);
                Msg.info(this, "Opened shared project '" + parsed.repo()
                        + "' from " + projectParent);
            } else {
                // false = durable project (GUI "New Shared Project"), not transient.
                project = pm.createProject(locator, repo, false);
                Msg.info(this, "Created shared project '" + parsed.repo()
                        + "' at " + projectParent);
            }
        } catch (LockException e) {
            return OpenProjectResult.fail(
                    "Shared project directory locked by another Ghidra instance at "
                            + projectParent + ": " + e.getMessage()
                            + " (each JVM needs its own GHIDRA_MCP_SHARED_PROJECT_DIR)");
        } catch (Exception e) {
            Msg.error(this, "Failed to open/create shared project for " + ghidraUrl, e);
            return OpenProjectResult.fail(
                    "Failed to open/create shared project: " + e.getMessage());
        }

        if (project == null) {
            return OpenProjectResult.fail("ProjectManager returned null for " + ghidraUrl);
        }
        return OpenProjectResult.ok(
                parsed.repo(), true, parsed.repo(), projectParent.toAbsolutePath().toString());
    }

    /**
     * Close the current project.
     */
    public void closeProject() {
        if (ghidraProject != null) {
            try {
                // Close all programs from this project first
                releaseAll();
                ghidraProject.close();
                Msg.info(this, "Closed project");
            } catch (Exception e) {
                Msg.warn(this, "Error closing project: " + e.getMessage());
            }
            ghidraProject = null;
            project = null;
        } else if (project != null) {
            try {
                releaseAll();
                project.close();
                Msg.info(this, "Closed project");
            } catch (Exception e) {
                Msg.warn(this, "Error closing project: " + e.getMessage());
            }
            project = null;
        }
    }

    // ========================================================================
    // GZF export / import (Ghidra packed-database format)
    // ========================================================================

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
        Program live = openProgramNamed(programIdent);
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
            if (existing != null && openProgramNamed(chosenName) != null) {
                return ImportResult.failure("cannot overwrite '"
                    + folder.getPathname() + "/" + chosenName
                    + "': program is currently loaded in memory. "
                    + "Close or switch away from it before re-importing.");
            }
            // Recoverable overwrite: move the original aside first and only
            // delete it once the new file is created. If createFile fails
            // (corrupt .gzf, I/O error) the original is renamed back, so the
            // overwrite is never destructive on a failed import.
            // setName returns the renamed file. The handle it was called on still names
            // the old path, which the import is about to take: deleting through it
            // deleted the new import and kept the backup, while reporting success.
            DomainFile backup = null;
            if (existing != null) {
                backup = existing.setName(chosenName + ".bak-" + System.currentTimeMillis());
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
            WriteTx tx = WriteTx.begin(program, "Auto Analysis");
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
                tx.end(success);
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
            // Deleting it: nothing to save for.
            closeProgramByPath(filePath);
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
            WriteTx tx = WriteTx.begin(program, "Configure Analyzer");
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
                tx.end(txSuccess);
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
