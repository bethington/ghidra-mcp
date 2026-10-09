package com.xebyte.core;

import ghidra.app.plugin.core.archive.ArchiveBridge;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectData;
import ghidra.framework.model.ProjectLocator;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TaskMonitor;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

/**
 * Moving programs and whole projects in and out of the open project as files: GZF for one
 * program, GAR for the project. The same code serves the GUI and headless, since both
 * providers hold a {@link Project}.
 */
public class ProjectLifecycle {

    private final ProjectProgramProvider provider;
    private final TaskMonitor monitor = new ConsoleTaskMonitor();

    public ProjectLifecycle(ProjectProgramProvider provider) {
        this.provider = provider;
    }

    private Project project() {
        return provider.getProject();
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
        if (project() == null) return null;
        String p = (folderPath == null || folderPath.isEmpty()) ? "/" : folderPath;
        if (!p.startsWith("/")) p = "/" + p;
        try {
            ProjectData pd = project().getProjectData();
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
     *   <li>An open program — packed via
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
        Program live = provider.openProgramNamed(programIdent);
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
        if (project() == null) {
            return ExportResult.failure("Program not open and no project open. "
                + "Call /open_project or /open_program first.");
        }
        DomainFile df;
        try {
            df = provider.findDomainFile(programIdent);
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
            String invalid = SafePaths.validateFilename(targetName);
            if (invalid != null) {
                return ImportResult.failure("invalid target_name: " + invalid);
            }
        }
        if (project() == null) {
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
            if (existing != null && provider.openProgramNamed(chosenName) != null) {
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

    /** Names of the open programs whose in-memory state differs from what the archive would capture. */
    private List<String> unsavedPrograms() {
        List<String> names = new ArrayList<>();
        for (Program program : provider.getAllOpenPrograms()) {
            if (program.isChanged()) {
                names.add(program.getName());
            }
        }
        return names;
    }

    /**
     * Archive the currently open project to a Ghidra-native {@code .gar} file.
     *
     * <p>Unlike {@link #exportProgramToGzf}, this captures the entire project
     * (all programs, folders, tool settings, version-control metadata) in a
     * format that Ghidra's GUI can re-import via <em>File &rarr; Restore Project</em>.
     */
    public ArchiveResult archiveCurrentProject(File garFile) {
        if (project() == null) {
            return ArchiveResult.failure("No project open. Call /open_project first.");
        }
        List<String> unsaved = unsavedPrograms();
        if (!unsaved.isEmpty()) {
            return ArchiveResult.failure("programs with unsaved changes would be missing from the archive: "
                + String.join(", ", unsaved) + ". Save them first (save_program / save_all_programs).");
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
        if (!garFile.getName().toLowerCase().endsWith(ArchiveBridge.ARCHIVE_EXTENSION)) {
            return ArchiveResult.failure("output must end in " + ArchiveBridge.ARCHIVE_EXTENSION
                + ": " + garFile.getName());
        }
        try {
            ArchiveBridge.archive(project(), garFile, monitor);
            return ArchiveResult.success(project().getName(), garFile.getAbsolutePath(), garFile.length());
        } catch (Exception e) {
            Msg.error(this, "archive failed for project '" + project().getName() + "'", e);
            return ArchiveResult.failure("archive failed (" + e.getClass().getSimpleName()
                + "): " + e.getMessage());
        }
    }

    /**
     * Restore a Ghidra {@code .gar} archive into a fresh on-disk project.
     *
     * <p>The open project is left alone: the restore writes a new directory. The new project is created
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
        if (!garFile.getName().toLowerCase().endsWith(ArchiveBridge.ARCHIVE_EXTENSION)) {
            return RestoreResult.failure("not a " + ArchiveBridge.ARCHIVE_EXTENSION
                + " file: " + garFile.getName());
        }
        if (parentDir == null || parentDir.isEmpty()) {
            return RestoreResult.failure("parent_dir required");
        }
        if (projectName == null || projectName.isEmpty()) {
            return RestoreResult.failure("project_name required");
        }
        String invalidName = SafePaths.validateFilename(projectName);
        if (invalidName != null) {
            return RestoreResult.failure("invalid project_name: " + invalidName);
        }
        File parent = new File(parentDir);
        if (!parent.isDirectory()) {
            return RestoreResult.failure("parent_dir is not a directory: " + parent.getAbsolutePath());
        }
        ProjectLocator locator = new ProjectLocator(parent.getAbsolutePath(), projectName);
        if (!SafePaths.isWithin(parent, locator.getProjectDir())) {
            return RestoreResult.failure("project_name escapes parent_dir: " + projectName);
        }
        if (locator.getProjectDir().exists() || locator.getMarkerFile().exists()) {
            return RestoreResult.failure("destination project already exists: "
                + locator.toString());
        }
        try {
            ArchiveBridge.restore(garFile, locator, monitor);
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
}
