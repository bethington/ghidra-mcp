package com.xebyte.offline;

import com.xebyte.headless.HeadlessProgramProvider;
import com.xebyte.headless.HeadlessProgramProvider.LocalProjectRef;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.stream.Stream;

import static org.junit.Assert.*;

/**
 * The decision table of {@link HeadlessProgramProvider#resolveLocalProject}: which
 * project a caller's local path names, or why it names none (#656).
 *
 * <p>Pure filesystem: a "project" here is an empty {@code <name>.gpr} file beside an
 * empty {@code <name>.rep} directory, which is the layout Ghidra writes. The real
 * create -> reopen round trip against Ghidra's project code is
 * {@code HeadlessCreateProjectGhidraTest}.
 */
public class LocalProjectPathResolutionTest {

    private Path tmp;

    @Before
    public void setUp() throws IOException {
        tmp = Files.createTempDirectory("local-project-paths");
    }

    @After
    public void tearDown() throws IOException {
        try (Stream<Path> walk = Files.walk(tmp)) {
            walk.sorted(Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
        }
    }

    private File project(File parent, String name) throws IOException {
        assertTrue(parent.isDirectory() || parent.mkdirs());
        File gpr = new File(parent, name + ".gpr");
        assertTrue(gpr.createNewFile());
        assertTrue(new File(parent, name + ".rep").mkdir());
        return gpr;
    }

    private static void assertResolves(LocalProjectRef ref, File expectedGpr) {
        assertTrue("expected success, got: " + ref.error, ref.ok());
        assertEquals(expectedGpr.getAbsoluteFile(), ref.markerFile().getAbsoluteFile());
    }

    @Test
    public void gprPathResolvesToItself() throws IOException {
        File gpr = project(tmp.toFile(), "Alpha");
        assertResolves(HeadlessProgramProvider.resolveLocalProject(gpr.getPath()), gpr);
    }

    @Test
    public void repDirectoryResolvesToItsMarker() throws IOException {
        File gpr = project(tmp.toFile(), "Alpha");
        File rep = new File(tmp.toFile(), "Alpha.rep");
        assertResolves(HeadlessProgramProvider.resolveLocalProject(rep.getPath()), gpr);
    }

    /** What /create_project returned before #656 and what ProjectLocator.toString() prints. */
    @Test
    public void extensionlessLocatorResolvesWhenTheGprExists() throws IOException {
        File gpr = project(tmp.toFile(), "Alpha");
        File locator = new File(tmp.toFile(), "Alpha");
        assertFalse("the locator form is not on disk", locator.exists());
        assertResolves(HeadlessProgramProvider.resolveLocalProject(locator.getPath()), gpr);
    }

    @Test
    public void directoryWithOneProjectResolvesToIt() throws IOException {
        File gpr = project(tmp.toFile(), "Alpha");
        assertResolves(HeadlessProgramProvider.resolveLocalProject(tmp.toString()), gpr);
    }

    @Test
    public void directoryWithSeveralProjectsIsRefusedWithEveryCandidateNamed() throws IOException {
        File alpha = project(tmp.toFile(), "Alpha");
        File beta = project(tmp.toFile(), "Beta");
        LocalProjectRef ref = HeadlessProgramProvider.resolveLocalProject(tmp.toString());
        assertFalse("must not pick the first .gpr listFiles returned", ref.ok());
        assertTrue(ref.error, ref.error.contains("holds 2 Ghidra projects"));
        assertTrue(ref.error, ref.error.contains(alpha.getPath()));
        assertTrue(ref.error, ref.error.contains(beta.getPath()));
    }

    @Test
    public void pathThatIsBothALocatorAndAProjectDirectoryIsRefused() throws IOException {
        File outer = project(tmp.toFile(), "Work");
        File inner = project(new File(tmp.toFile(), "Work"), "Inner");
        LocalProjectRef ref = HeadlessProgramProvider.resolveLocalProject(
            new File(tmp.toFile(), "Work").getPath());
        assertFalse(ref.ok());
        assertTrue(ref.error, ref.error.contains("Ambiguous"));
        assertTrue(ref.error, ref.error.contains(outer.getPath()));
        assertTrue(ref.error, ref.error.contains(inner.getPath()));
    }

    @Test
    public void directoryHoldingNoProjectIsRefused() throws IOException {
        File empty = new File(tmp.toFile(), "empty");
        assertTrue(empty.mkdir());
        LocalProjectRef ref = HeadlessProgramProvider.resolveLocalProject(empty.getPath());
        assertFalse(ref.ok());
        assertTrue(ref.error, ref.error.startsWith("No .gpr file found in:"));
    }

    @Test
    public void locatorDirectoryWithoutGprsStillResolvesToTheSiblingProject() throws IOException {
        // A plain directory that happens to share the project's name holds no projects,
        // so the locator reading is the only one -- no ambiguity to refuse.
        File gpr = project(tmp.toFile(), "Alpha");
        assertTrue(new File(tmp.toFile(), "Alpha").mkdir());
        assertResolves(HeadlessProgramProvider.resolveLocalProject(
            new File(tmp.toFile(), "Alpha").getPath()), gpr);
    }

    @Test
    public void missingProjectsAreNotFound() {
        LocalProjectRef gpr = HeadlessProgramProvider.resolveLocalProject(
            new File(tmp.toFile(), "Ghost.gpr").getPath());
        assertFalse(gpr.ok());
        assertTrue(gpr.error, gpr.error.startsWith("Project not found:"));

        LocalProjectRef locator = HeadlessProgramProvider.resolveLocalProject(
            new File(tmp.toFile(), "Ghost").getPath());
        assertFalse(locator.ok());
        assertTrue(locator.error, locator.error.startsWith("Project not found:"));
    }

    @Test
    public void blankPathIsRefused() {
        assertFalse(HeadlessProgramProvider.resolveLocalProject("  ").ok());
        assertFalse(HeadlessProgramProvider.resolveLocalProject(null).ok());
    }
}
