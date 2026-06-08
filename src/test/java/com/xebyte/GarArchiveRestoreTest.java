package com.xebyte;

import com.xebyte.headless.HeadlessProgramProvider;
import com.xebyte.headless.HeadlessProgramProvider.ArchiveResult;
import com.xebyte.headless.HeadlessProgramProvider.RestoreResult;
import org.junit.Test;

import java.io.File;
import java.nio.file.Files;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * Offline contract tests for the GAR archive/restore endpoints added in
 * PR #264 ({@code /archive_project}, {@code /restore_project}).
 *
 * <p>Every validation branch in {@code restoreProject} runs <em>before</em> any
 * project or {@link HeadlessArchiveBridge} call, so a fresh
 * {@link HeadlessProgramProvider} (no project open) reaches all of them without
 * a live Ghidra project. These pin the path-safety and argument contract so a
 * caller cannot escape {@code parent_dir} or smuggle a traversal
 * {@code project_name}. JUnit 4 to match the sibling security tests.
 */
public class GarArchiveRestoreTest {

    private static HeadlessProgramProvider provider() {
        return new HeadlessProgramProvider();
    }

    /** A real, existing {@code .gar} file so gar-existence/extension checks pass. */
    private static File tempGar() throws Exception {
        File gar = Files.createTempFile("gar-test", ".gar").toFile();
        gar.deleteOnExit();
        return gar;
    }

    // -------------------------------------------------------------------
    // restoreProject — argument validation
    // -------------------------------------------------------------------

    @Test
    public void restoreRejectsNullGar() {
        RestoreResult res = provider().restoreProject(null, "/tmp", "proj");
        assertFalse(res.success);
        assertTrue(res.error, res.error.contains("gar file not found"));
    }

    @Test
    public void restoreRejectsMissingGar() {
        File missing = new File("/tmp/does-not-exist-" + System.nanoTime() + ".gar");
        RestoreResult res = provider().restoreProject(missing, "/tmp", "proj");
        assertFalse(res.success);
        assertTrue(res.error, res.error.contains("gar file not found"));
    }

    @Test
    public void restoreRejectsWrongExtension() throws Exception {
        File txt = Files.createTempFile("gar-test", ".txt").toFile();
        txt.deleteOnExit();
        RestoreResult res = provider().restoreProject(txt, "/tmp", "proj");
        assertFalse(res.success);
        assertTrue(res.error, res.error.contains("not a"));
    }

    @Test
    public void restoreRejectsMissingParentDir() throws Exception {
        RestoreResult res = provider().restoreProject(tempGar(), null, "proj");
        assertFalse(res.success);
        assertTrue(res.error, res.error.contains("parent_dir required"));
    }

    @Test
    public void restoreRejectsMissingProjectName() throws Exception {
        File parent = Files.createTempDirectory("gar-parent").toFile();
        parent.deleteOnExit();
        RestoreResult res = provider().restoreProject(tempGar(), parent.getAbsolutePath(), "");
        assertFalse(res.success);
        assertTrue(res.error, res.error.contains("project_name required"));
    }

    @Test
    public void restoreRejectsTraversalProjectName() throws Exception {
        File parent = Files.createTempDirectory("gar-parent").toFile();
        parent.deleteOnExit();
        RestoreResult res = provider().restoreProject(tempGar(), parent.getAbsolutePath(), "../evil");
        assertFalse(res.success);
        assertTrue(res.error, res.error.contains("invalid project_name"));
    }

    @Test
    public void restoreRejectsSeparatorProjectName() throws Exception {
        File parent = Files.createTempDirectory("gar-parent").toFile();
        parent.deleteOnExit();
        RestoreResult res = provider().restoreProject(tempGar(), parent.getAbsolutePath(), "a/b");
        assertFalse(res.success);
        assertTrue(res.error, res.error.contains("invalid project_name"));
    }

    @Test
    public void restoreRejectsParentDirThatIsAFile() throws Exception {
        File notADir = Files.createTempFile("gar-notadir", ".tmp").toFile();
        notADir.deleteOnExit();
        RestoreResult res = provider().restoreProject(tempGar(), notADir.getAbsolutePath(), "proj");
        assertFalse(res.success);
        assertTrue(res.error, res.error.contains("not a directory"));
    }

    // -------------------------------------------------------------------
    // archiveCurrentProject — no project open
    // -------------------------------------------------------------------

    @Test
    public void archiveRejectsWhenNoProjectOpen() {
        ArchiveResult res = provider().archiveCurrentProject(new File("/tmp/out.gar"));
        assertFalse(res.success);
        assertNotNull(res.error);
        assertTrue(res.error, res.error.contains("No project open"));
    }
}
