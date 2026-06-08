/* ###
 * IP: GHIDRA (vendor extension shipped with reverse-box)
 *
 * Bridge to Ghidra's package-private project archive / restore tasks.
 *
 * Lives in {@code ghidra.app.plugin.core.archive} on purpose so we can
 * instantiate {@link ArchiveTask} and {@link RestoreTask}, whose constructors
 * are package-private. Ghidra 12.1 does not use JPMS, so a class compiled
 * against the same package name has package-scope access at runtime.
 *
 * <p><b>Convention exception:</b> ghidra-mcp normally keeps all its code
 * under {@code com.xebyte} (see vendor {@code CLAUDE.md}). This class is the
 * single justified exception — package-private access cannot be granted to
 * an outside package. It carries no {@code @McpTool} annotation, so
 * {@code AnnotationScanner} ignores it; the HTTP surface stays in
 * {@code com.xebyte.headless.HeadlessManagementService} which calls into
 * here via {@code HeadlessProgramProvider}.
 */
package ghidra.app.plugin.core.archive;

import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectLocator;
import ghidra.util.task.TaskMonitor;

import java.io.File;
import java.io.IOException;

/**
 * Static facade exposing Ghidra's native {@code .gar} create / restore
 * capability to headless callers (no {@code PluginTool} required).
 */
public final class HeadlessArchiveBridge {

    /** Ghidra's canonical archive extension (kept here for callers). */
    public static final String ARCHIVE_EXTENSION = ArchivePlugin.ARCHIVE_EXTENSION;

    private HeadlessArchiveBridge() {
        // static-only
    }

    /**
     * Archive the given open project to {@code garFile}.
     *
     * <p>Project must be open (Ghidra's {@link ArchiveTask} reads the live
     * {@link Project} for its name and on-disk location). The caller is
     * responsible for flushing pending {@code DomainObject} edits via
     * {@code /save_all_programs} beforehand \u2014 the task snapshots disk
     * state only.
     *
     * @throws Exception forwarded from {@link ArchiveTask#run(TaskMonitor)}
     */
    public static void archive(Project project, File garFile, TaskMonitor monitor) throws Exception {
        if (project == null) {
            throw new IllegalArgumentException("project required");
        }
        if (garFile == null) {
            throw new IllegalArgumentException("garFile required");
        }
        ArchiveTask task = new ArchiveTask(project, garFile);
        task.run(monitor);
    }

    /**
     * Restore a {@code .gar} archive into a fresh on-disk project at
     * {@code destLocator}.
     *
     * <p>{@link RestoreTask} is built with a {@code null} {@link ArchivePlugin}
     * because headless mode has no {@code PluginTool}. Its
     * {@link RestoreTask#run(TaskMonitor)} extracts the archive and writes the
     * project marker file, then attempts a GUI auto-open
     * ({@code plugin.getTool()…openProject(…)}) on the Swing thread. That step
     * cannot work headlessly, but Ghidra wraps it in its own
     * {@code try/catch (Exception)} that logs "Failed to open newly restored
     * project" and swallows the failure — so {@code run()} returns normally and
     * the restore (extraction + marker file) is already complete. The single
     * error log line on the success path is benign and originates inside
     * Ghidra, not here.
     *
     * <p>Rather than depend on that swallowed-exception behaviour remaining
     * stable across Ghidra versions, we assert the real post-condition
     * afterwards: the project must exist on disk, otherwise we fail loud.
     * Headless callers then re-open the restored project through their own
     * {@code /open_project} path.
     *
     * @throws IOException when the archive did not materialise a project on disk
     * @throws Exception forwarded from {@link RestoreTask#run(TaskMonitor)}
     */
    public static void restore(File garFile, ProjectLocator destLocator, TaskMonitor monitor) throws Exception {
        if (garFile == null || !garFile.isFile()) {
            throw new IllegalArgumentException("garFile must be an existing file: " + garFile);
        }
        if (destLocator == null) {
            throw new IllegalArgumentException("destLocator required");
        }
        RestoreTask task = new RestoreTask(destLocator, garFile, null);
        task.run(monitor);
        // Verify the project actually landed on disk instead of trusting that
        // run() completed — the GUI auto-open failure above is swallowed by
        // Ghidra, so a genuinely failed extraction must be caught here.
        if (!destLocator.getMarkerFile().exists() && !destLocator.getProjectDir().exists()) {
            throw new IOException("restore did not materialise a project at " + destLocator
                + " (archive may be invalid or extraction failed)");
        }
    }
}

