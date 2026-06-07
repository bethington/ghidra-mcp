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
     * <p>{@link RestoreTask} normally fires {@code openRestoredProject} via
     * its {@link ArchivePlugin} reference at the end of its run. We pass
     * {@code null} for the plugin and intercept that lambda with a
     * subclass override so headless callers can decide when (and via which
     * code path) to open the restored project.
     *
     * @throws Exception forwarded from {@link RestoreTask#run(TaskMonitor)}
     */
    public static void restore(File garFile, ProjectLocator destLocator, TaskMonitor monitor) throws Exception {
        if (garFile == null || !garFile.isFile()) {
            throw new IllegalArgumentException("garFile must be an existing file: " + garFile);
        }
        if (destLocator == null) {
            throw new IllegalArgumentException("destLocator required");
        }
        RestoreTask task = new HeadlessRestoreTask(destLocator, garFile);
        task.run(monitor);
    }

    /**
     * Restore task variant that suppresses the GUI auto-open callback at
     * the end of {@link RestoreTask#run(TaskMonitor)} \u2014 the base
     * class would invoke {@code plugin.openProject(...)} on the (null)
     * {@link ArchivePlugin} and NPE. Headless callers re-open through
     * their own {@code /open_project} path, which already resets
     * {@code project.prp} owner to the current user.
     */
    private static final class HeadlessRestoreTask extends RestoreTask {
        HeadlessRestoreTask(ProjectLocator destLocator, File archiveFile) {
            super(destLocator, archiveFile, null);
        }
    }
}
