package com.xebyte.offline;

import com.xebyte.headless.HeadlessPaths;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

/**
 * Offline unit tests for {@link HeadlessPaths} — the path-traversal guard
 * shared by the headless GZF/GAR endpoints ({@code /export_program},
 * {@code /archive_project}, {@code /import_program}, {@code /restore_project}).
 *
 * <p>These pin the security contract flagged on PR #264: caller-supplied
 * names must be plain filenames and the resolved output must stay inside its
 * target directory. Pure logic, no Ghidra — runs in the {@code offline} tier.
 * JUnit 4 to match the other PR-introduced security tests
 * ({@code GzfExportImportTest}, {@code GarArchiveRestoreTest}).
 */
public class HeadlessPathsTest {

    // -------------------------------------------------------------------
    // validateFilename
    // -------------------------------------------------------------------

    @Test
    public void testValidateAcceptsPlainName() {
        assertNull("plain name is safe", HeadlessPaths.validateFilename("D2Common.gzf"));
        assertNull("dots inside name are fine", HeadlessPaths.validateFilename("my.prog.v1.gzf"));
        assertNull("leading dot is fine", HeadlessPaths.validateFilename(".hidden"));
    }

    @Test
    public void testValidateRejectsEmpty() {
        assertNotNull("null rejected", HeadlessPaths.validateFilename(null));
        assertNotNull("empty rejected", HeadlessPaths.validateFilename(""));
    }

    @Test
    public void testValidateRejectsForwardSlash() {
        String err = HeadlessPaths.validateFilename("sub/dir.gzf");
        assertNotNull("forward slash rejected", err);
        assertTrue("message names separators", err.contains("separator"));
    }

    @Test
    public void testValidateRejectsBackslash() {
        assertNotNull("backslash rejected", HeadlessPaths.validateFilename("sub\\dir.gzf"));
    }

    @Test
    public void testValidateRejectsTraversal() {
        // Traversal is checked before the separator check, so pure-traversal
        // forms are categorised as traversal even though they also carry a
        // separator. The error message must say "traversal", not "separator".
        String bare = HeadlessPaths.validateFilename("..");
        assertNotNull("bare .. rejected", bare);
        assertTrue("bare .. categorised as traversal", bare.contains("traversal"));

        String fwd = HeadlessPaths.validateFilename("../escape");
        assertNotNull("../ rejected", fwd);
        assertTrue("../ categorised as traversal", fwd.contains("traversal"));

        String back = HeadlessPaths.validateFilename("..\\escape");
        assertNotNull("..\\ rejected", back);
        assertTrue("..\\ categorised as traversal", back.contains("traversal"));
    }

    @Test
    public void testValidateRejectsTrailingTraversalSegment() {
        // A ".." segment at the END (after a separator) is traversal too, and
        // must be caught as traversal even though the substring "../" / "..\\"
        // never appears.
        String fwd = HeadlessPaths.validateFilename("a/..");
        assertNotNull("a/.. rejected", fwd);
        assertTrue("a/.. categorised as traversal", fwd.contains("traversal"));

        String back = HeadlessPaths.validateFilename("a\\..");
        assertNotNull("a\\.. rejected", back);
        assertTrue("a\\.. categorised as traversal", back.contains("traversal"));

        String mid = HeadlessPaths.validateFilename("a/../b");
        assertNotNull("a/../b rejected", mid);
        assertTrue("a/../b categorised as traversal", mid.contains("traversal"));
    }

    @Test
    public void testValidateAllowsDoubleDotInsideName() {
        // ".." only matters as a path segment; embedded in a name it is fine.
        assertNull("a..b is a safe plain name", HeadlessPaths.validateFilename("a..b.gzf"));
    }

    @Test
    public void testValidateRejectsAbsolutePath() {
        assertNotNull("absolute path rejected", HeadlessPaths.validateFilename("/etc/passwd"));
    }

    // -------------------------------------------------------------------
    // safeBasename
    // -------------------------------------------------------------------

    @Test
    public void testBasenameStripsProjectPath() {
        assertEquals("D2Common.dll",
            HeadlessPaths.safeBasename("/Vanilla/1.13d/D2Common.dll"));
    }

    @Test
    public void testBasenameStripsBackslashPath() {
        assertEquals("prog.exe",
            HeadlessPaths.safeBasename("C:\\work\\prog.exe"));
    }

    @Test
    public void testBasenamePassesThroughPlainName() {
        assertEquals("myprog", HeadlessPaths.safeBasename("myprog"));
    }

    @Test
    public void testBasenameFallsBackOnEmptyOrDotted() {
        assertEquals("program", HeadlessPaths.safeBasename(null));
        assertEquals("program", HeadlessPaths.safeBasename(""));
        assertEquals("program", HeadlessPaths.safeBasename("/"));
        assertEquals("program", HeadlessPaths.safeBasename("path/.."));
    }

    // -------------------------------------------------------------------
    // isWithin
    // -------------------------------------------------------------------

    @Test
    public void testIsWithinAcceptsChild() throws IOException {
        File dir = Files.createTempDirectory("hp-test").toFile();
        dir.deleteOnExit();
        assertTrue("plain child contained", HeadlessPaths.isWithin(dir, new File(dir, "out.gzf")));
    }

    @Test
    public void testIsWithinAcceptsDirItself() throws IOException {
        File dir = Files.createTempDirectory("hp-test").toFile();
        dir.deleteOnExit();
        assertTrue("dir equals itself", HeadlessPaths.isWithin(dir, dir));
    }

    @Test
    public void testIsWithinRejectsTraversalEscape() throws IOException {
        File dir = Files.createTempDirectory("hp-test").toFile();
        dir.deleteOnExit();
        // new File(dir, "../evil") canonicalises to a sibling of dir.
        assertFalse("traversal escapes dir",
            HeadlessPaths.isWithin(dir, new File(dir, "../evil.gzf")));
    }

    @Test
    public void testIsWithinRejectsSiblingPrefixCollision() throws IOException {
        File base = Files.createTempDirectory("hp-test").toFile();
        base.deleteOnExit();
        File dir = new File(base, "exports");
        File sibling = new File(base, "exports-evil");
        assertTrue(dir.mkdir());
        assertTrue(sibling.mkdir());
        dir.deleteOnExit();
        sibling.deleteOnExit();
        // "exports-evil" shares the "exports" string prefix but is NOT under it.
        assertFalse("prefix-collision sibling rejected",
            HeadlessPaths.isWithin(dir, new File(sibling, "out.gzf")));
    }

    @Test
    public void testIsWithinRejectsNull() {
        assertFalse(HeadlessPaths.isWithin(null, new File("x")));
        assertFalse(HeadlessPaths.isWithin(new File("x"), null));
    }
}
