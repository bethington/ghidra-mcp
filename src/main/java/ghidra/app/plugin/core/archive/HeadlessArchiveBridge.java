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
     * <p>We construct {@link RestoreTask} with a {@code null}
     * {@link ArchivePlugin} because there is no {@code PluginTool} in
     * headless mode. {@link RestoreTask#run(TaskMonitor)} extracts the
     * archive and writes the project marker file <em>before</em> its final
     * {@code openRestoredProject()} step, which on the Swing thread
     * dereferences the (null) plugin to auto-open the project in a
     * front-end tool. That dereference throws a {@code NullPointerException},
     * but {@code RestoreTask} catches it and only logs it — the restore
     * itself (extraction + marker file) is already complete. The net effect
     * is exactly what a headless caller wants: the project is materialised on
     * disk and the GUI auto-open is skipped. Headless callers re-open through
     * their own {@code /open_project} path.
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
        RestoreTask task = new RestoreTask(destLocator, garFile, null);
        task.run(monitor);
    }
}

