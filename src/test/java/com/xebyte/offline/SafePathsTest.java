package com.xebyte.offline;

import com.xebyte.core.SafePaths;
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
 * Offline unit tests for {@link SafePaths} — the path-traversal guard
 * shared by the headless GZF/GAR endpoints ({@code /export_program},
 * {@code /archive_project}, {@code /import_program}, {@code /restore_project}).
 *
 * <p>These pin the security contract flagged on PR #264: caller-supplied
 * names must be plain filenames and the resolved output must stay inside its
 * target directory. Pure logic, no Ghidra — runs in the {@code offline} tier.
 * JUnit 4 to match the other PR-introduced security tests
 * ({@code ProjectGzfTest}, {@code ProjectArchiveTest}).
 */
public class SafePathsTest {

    // -------------------------------------------------------------------
    // validateFilename
    // -------------------------------------------------------------------

    @Test
    public void testValidateAcceptsPlainName() {
        assertNull("plain name is safe", SafePaths.validateFilename("D2Common.gzf"));
        assertNull("dots inside name are fine", SafePaths.validateFilename("my.prog.v1.gzf"));
        assertNull("leading dot is fine", SafePaths.validateFilename(".hidden"));
    }

    @Test
    public void testValidateRejectsEmpty() {
        assertNotNull("null rejected", SafePaths.validateFilename(null));
        assertNotNull("empty rejected", SafePaths.validateFilename(""));
    }

    @Test
    public void testValidateRejectsForwardSlash() {
        String err = SafePaths.validateFilename("sub/dir.gzf");
        assertNotNull("forward slash rejected", err);
        assertTrue("message names separators", err.contains("separator"));
    }

    @Test
    public void testValidateRejectsBackslash() {
        assertNotNull("backslash rejected", SafePaths.validateFilename("sub\\dir.gzf"));
    }

    @Test
    public void testValidateRejectsTraversal() {
        // Traversal is checked before the separator check, so pure-traversal
        // forms are categorised as traversal even though they also carry a
        // separator. The error message must say "traversal", not "separator".
        String bare = SafePaths.validateFilename("..");
        assertNotNull("bare .. rejected", bare);
        assertTrue("bare .. categorised as traversal", bare.contains("traversal"));

        String fwd = SafePaths.validateFilename("../escape");
        assertNotNull("../ rejected", fwd);
        assertTrue("../ categorised as traversal", fwd.contains("traversal"));

        String back = SafePaths.validateFilename("..\\escape");
        assertNotNull("..\\ rejected", back);
        assertTrue("..\\ categorised as traversal", back.contains("traversal"));
    }

    @Test
    public void testValidateRejectsTrailingTraversalSegment() {
        // A ".." segment at the END (after a separator) is traversal too, and
        // must be caught as traversal even though the substring "../" / "..\\"
        // never appears.
        String fwd = SafePaths.validateFilename("a/..");
        assertNotNull("a/.. rejected", fwd);
        assertTrue("a/.. categorised as traversal", fwd.contains("traversal"));

        String back = SafePaths.validateFilename("a\\..");
        assertNotNull("a\\.. rejected", back);
        assertTrue("a\\.. categorised as traversal", back.contains("traversal"));

        String mid = SafePaths.validateFilename("a/../b");
        assertNotNull("a/../b rejected", mid);
        assertTrue("a/../b categorised as traversal", mid.contains("traversal"));
    }

    @Test
    public void testValidateAllowsDoubleDotInsideName() {
        // ".." only matters as a path segment; embedded in a name it is fine.
        assertNull("a..b is a safe plain name", SafePaths.validateFilename("a..b.gzf"));
    }

    @Test
    public void testValidateRejectsAbsolutePath() {
        assertNotNull("absolute path rejected", SafePaths.validateFilename("/etc/passwd"));
    }

    // -------------------------------------------------------------------
    // safeBasename
    // -------------------------------------------------------------------

    @Test
    public void testBasenameStripsProjectPath() {
        assertEquals("D2Common.dll",
            SafePaths.safeBasename("/Vanilla/1.13d/D2Common.dll"));
    }

    @Test
    public void testBasenameStripsBackslashPath() {
        assertEquals("prog.exe",
            SafePaths.safeBasename("C:\\work\\prog.exe"));
    }

    @Test
    public void testBasenamePassesThroughPlainName() {
        assertEquals("myprog", SafePaths.safeBasename("myprog"));
    }

    @Test
    public void testBasenameFallsBackOnEmptyOrDotted() {
        assertEquals("program", SafePaths.safeBasename(null));
        assertEquals("program", SafePaths.safeBasename(""));
        assertEquals("program", SafePaths.safeBasename("/"));
        assertEquals("program", SafePaths.safeBasename("path/.."));
    }

    // -------------------------------------------------------------------
    // isWithin
    // -------------------------------------------------------------------

    @Test
    public void testIsWithinAcceptsChild() throws IOException {
        File dir = Files.createTempDirectory("hp-test").toFile();
        dir.deleteOnExit();
        assertTrue("plain child contained", SafePaths.isWithin(dir, new File(dir, "out.gzf")));
    }

    @Test
    public void testIsWithinAcceptsDirItself() throws IOException {
        File dir = Files.createTempDirectory("hp-test").toFile();
        dir.deleteOnExit();
        assertTrue("dir equals itself", SafePaths.isWithin(dir, dir));
    }

    @Test
    public void testIsWithinRejectsTraversalEscape() throws IOException {
        File dir = Files.createTempDirectory("hp-test").toFile();
        dir.deleteOnExit();
        // new File(dir, "../evil") canonicalises to a sibling of dir.
        assertFalse("traversal escapes dir",
            SafePaths.isWithin(dir, new File(dir, "../evil.gzf")));
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
            SafePaths.isWithin(dir, new File(sibling, "out.gzf")));
    }

    @Test
    public void testIsWithinRejectsNull() {
        assertFalse(SafePaths.isWithin(null, new File("x")));
        assertFalse(SafePaths.isWithin(new File("x"), null));
    }
}
