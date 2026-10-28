package com.xebyte.offline;

import com.xebyte.core.ProgramScriptService;
import junit.framework.TestCase;

import java.io.File;
import java.nio.file.Files;
import java.util.List;

/**
 * {@code /run_script_inline} must not poison its own script directory.
 *
 * <p>Ghidra records "these files failed to compile" per script directory and keeps
 * replaying those errors — prefixed onto the output of every <em>later</em> script, and
 * surviving both deletion of the file and a Ghidra restart. The old cleanup only swept
 * {@code McpInline_*}, so a script that declared its own {@code public class Foo} left
 * {@code Foo.java} + {@code Foo.java_failed} behind permanently and corrupted every
 * subsequent inline run. Three such orphans were found blocking a real scripts directory.
 *
 * <p>Runs fully offline — pure filesystem, no Ghidra.
 */
public class InlineScriptCleanupTest extends TestCase {

    private File dir;

    @Override
    protected void setUp() throws Exception {
        dir = Files.createTempDirectory("mcp-scripts-test").toFile();
    }

    @Override
    protected void tearDown() {
        File[] leftovers = dir.listFiles();
        if (leftovers != null) {
            for (File f : leftovers) f.delete();
        }
        dir.delete();
    }

    private File write(String name, String body) throws Exception {
        File f = new File(dir, name);
        Files.writeString(f.toPath(), body);
        return f;
    }

    /** The regression: a caller-named script with an oracle must be swept. */
    public void testCallerNamedFailureIsRemoved() throws Exception {
        File script = write("Find830.java", "public class Find830 {}");
        File oracle = write("Find830.java_failed", "{\"error\":\"boom\"}");

        ProgramScriptService.purgeStaleInlineScripts(dir, System.currentTimeMillis());

        assertFalse("caller-named .java with an oracle must be deleted", script.exists());
        assertFalse("its oracle must be deleted too", oracle.exists());
    }

    /** The case that already worked; keep it working. */
    public void testGeneratedNameFailureIsRemoved() throws Exception {
        File script = write("McpInline_abc123.java", "public class McpInline_abc123 {}");
        File oracle = write("McpInline_abc123.java_failed", "fail");

        ProgramScriptService.purgeStaleInlineScripts(dir, System.currentTimeMillis());

        assertFalse(script.exists());
        assertFalse(oracle.exists());
    }

    /**
     * An operator's own script must never be deleted. Without an oracle there is no
     * evidence the service created it, and for a caller-chosen name there is no
     * provenance at all — so age alone must not condemn it.
     */
    public void testHandWrittenScriptIsNeverTouched() throws Exception {
        File mine = write("AnalyzeFlashBle.java", "public class AnalyzeFlashBle {}");
        assertTrue(mine.setLastModified(System.currentTimeMillis() - 400L * 24 * 3600 * 1000));

        ProgramScriptService.purgeStaleInlineScripts(dir, System.currentTimeMillis());

        assertTrue("a months-old hand-written script must survive", mine.exists());
    }

    /** A generated name with no oracle is crash-orphaned once it is old enough. */
    public void testCrashOrphanedGeneratedScriptIsRemovedWhenStale() throws Exception {
        File orphan = write("McpInline_dead.java", "public class McpInline_dead {}");
        long old = System.currentTimeMillis()
            - ProgramScriptService.INLINE_SCRIPT_ORPHAN_AGE_MS - 5_000L;
        assertTrue(orphan.setLastModified(old));

        ProgramScriptService.purgeStaleInlineScripts(dir, System.currentTimeMillis());

        assertFalse(orphan.exists());
    }

    /** A fresh generated file may belong to a concurrent run — leave it alone. */
    public void testFreshGeneratedScriptSurvives() throws Exception {
        File fresh = write("McpInline_live.java", "public class McpInline_live {}");

        ProgramScriptService.purgeStaleInlineScripts(dir, System.currentTimeMillis());

        assertTrue("a concurrent run's file must not be swept", fresh.exists());
    }

    /** An oracle whose script is already gone would otherwise accumulate forever. */
    public void testOrphanedOracleIsPurgedForAnyName() throws Exception {
        File oracle = write("SomeUserClass.java_failed", "stale");

        List<String> removed = ProgramScriptService.purgeStaleInlineScripts(
            dir, System.currentTimeMillis());

        assertFalse(oracle.exists());
        assertTrue(removed.contains("SomeUserClass.java_failed"));
    }

    /** Sweeping an empty or absent directory must not throw. */
    public void testEmptyAndMissingDirectoryAreSafe() {
        assertTrue(ProgramScriptService.purgeStaleInlineScripts(
            dir, System.currentTimeMillis()).isEmpty());
        assertTrue(ProgramScriptService.purgeStaleInlineScripts(
            new File(dir, "does-not-exist"), System.currentTimeMillis()).isEmpty());
    }
}
