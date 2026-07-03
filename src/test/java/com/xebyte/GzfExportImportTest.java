package com.xebyte;

import com.xebyte.headless.HeadlessProgramProvider;
import com.xebyte.headless.HeadlessProgramProvider.ExportResult;
import com.xebyte.headless.HeadlessProgramProvider.ImportResult;
import ghidra.program.model.listing.Program;
import org.junit.Test;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Pins the security- and correctness-sensitive contracts of the GZF
 * export/import paths flagged in PR #264 review:
 *
 * <ul>
 *   <li>{@code exportProgramToGzf} resolves the live program by an
 *       <em>exact</em> name, never a fuzzy substring match (so it can't pack
 *       the wrong program when open names overlap).</li>
 *   <li>{@code importProgramFromGzf} validates the caller-supplied
 *       {@code targetName} as a plain filename before touching the project
 *       tree, and an empty name bypasses validation (it is derived from the
 *       GZF basename downstream).</li>
 * </ul>
 */
public class GzfExportImportTest {

    @Test
    public void exportResolvesLiveProgramByExactNameNotSubstring() throws Exception {
        HeadlessProgramProvider provider = new HeadlessProgramProvider();

        // "D2Common.dll" contains "Common.dll" as a substring — the old fuzzy
        // getProgram() lookup could return it for the request "Common.dll".
        Program common = mock(Program.class);
        when(common.getName()).thenReturn("Common.dll");
        Program d2common = mock(Program.class);
        when(d2common.getName()).thenReturn("D2Common.dll");
        provider.setCurrentProgram(d2common);
        provider.setCurrentProgram(common);

        Path dir = Files.createTempDirectory("gzf-export-test");
        File out = new File(dir.toFile(), "out.gzf");

        ExportResult res = provider.exportProgramToGzf("Common.dll", out);

        assertTrue("export should succeed: " + res.error, res.success);
        assertEquals("must pack the exactly-named program, not the substring match",
            "Common.dll", res.programName);
    }

    @Test
    public void importRejectsTargetNameWithPathSeparator() {
        HeadlessProgramProvider provider = new HeadlessProgramProvider();

        ImportResult res = provider.importProgramFromGzf(null, "/", "a/b", false);

        assertFalse(res.success);
        assertNotNull(res.error);
        assertTrue("error should name the invalid target_name: " + res.error,
            res.error.contains("invalid target_name"));
    }

    @Test
    public void importRejectsTargetNameWithTraversalSegment() {
        HeadlessProgramProvider provider = new HeadlessProgramProvider();

        ImportResult res = provider.importProgramFromGzf(null, "/", "../escape", false);

        assertFalse(res.success);
        assertNotNull(res.error);
        assertTrue("error should name the invalid target_name: " + res.error,
            res.error.contains("invalid target_name"));
    }

    @Test
    public void importValidTargetNamePassesValidationThenChecksProject() {
        HeadlessProgramProvider provider = new HeadlessProgramProvider();

        // Valid name clears the up-front filename check, so the next failure is
        // the "no project open" guard — proving validation ran first and a good
        // name is not rejected.
        ImportResult res = provider.importProgramFromGzf(null, "/", "CleanName", false);

        assertFalse(res.success);
        assertNotNull(res.error);
        assertTrue("valid name should pass validation and hit the project guard: " + res.error,
            res.error.contains("No project open"));
    }

    @Test
    public void importEmptyTargetNameSkipsValidation() {
        HeadlessProgramProvider provider = new HeadlessProgramProvider();

        // An empty target_name is legal — the basename is derived downstream —
        // so it must not be rejected as an invalid filename.
        ImportResult res = provider.importProgramFromGzf(null, "/", "", false);

        assertFalse(res.success);
        assertNotNull(res.error);
        assertTrue("empty name must bypass validation and hit the project guard: " + res.error,
            res.error.contains("No project open"));
    }
}
