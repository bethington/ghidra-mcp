package com.xebyte.offline;

import com.xebyte.core.ProjectLifecycle;
import com.xebyte.headless.HeadlessProgramProvider;
import com.xebyte.core.ProjectLifecycle.ExportResult;
import com.xebyte.core.ProjectLifecycle.ImportResult;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectData;
import ghidra.program.model.listing.Program;
import org.junit.Test;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
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
 *
 * <p>Lives in {@code com.xebyte.offline} because that is the package CI's
 * {@code -Dtest} glob selects. From #264 until issue #483 this class sat in
 * {@code com.xebyte}, which no glob reaches, so its 5 assertions had never once
 * executed in CI. {@code tests/unit/test_ci_java_test_globs.py} now fails if a
 * test class lands outside a selected package again.
 */
public class ProjectGzfTest {

    @Test
    public void exportResolvesLiveProgramByExactNameNotSubstring() throws Exception {
        HeadlessProgramProvider provider = new HeadlessProgramProvider();
        ProjectLifecycle lifecycle = new ProjectLifecycle(provider);

        // "D2Common.dll" contains "Common.dll" as a substring — the old fuzzy
        // getProgram() lookup could return it for the request "Common.dll".
        Program common = mock(Program.class);
        when(common.getName()).thenReturn("Common.dll");
        Program d2common = mock(Program.class);
        when(d2common.getName()).thenReturn("D2Common.dll");
        provider.trackOpenProgram(d2common);
        provider.trackOpenProgram(common);

        Path dir = Files.createTempDirectory("gzf-export-test");
        File out = new File(dir.toFile(), "out.gzf");

        ExportResult res = lifecycle.exportProgramToGzf("Common.dll", out);

        assertTrue("export should succeed: " + res.error, res.success);
        assertEquals("must pack the exactly-named program, not the substring match",
            "Common.dll", res.programName);
    }

    @Test
    public void importRejectsTargetNameWithPathSeparator() {
        HeadlessProgramProvider provider = new HeadlessProgramProvider();
        ProjectLifecycle lifecycle = new ProjectLifecycle(provider);

        ImportResult res = lifecycle.importProgramFromGzf(null, "/", "a/b", false);

        assertFalse(res.success);
        assertNotNull(res.error);
        assertTrue("error should name the invalid target_name: " + res.error,
            res.error.contains("invalid target_name"));
    }

    @Test
    public void importRejectsTargetNameWithTraversalSegment() {
        HeadlessProgramProvider provider = new HeadlessProgramProvider();
        ProjectLifecycle lifecycle = new ProjectLifecycle(provider);

        ImportResult res = lifecycle.importProgramFromGzf(null, "/", "../escape", false);

        assertFalse(res.success);
        assertNotNull(res.error);
        assertTrue("error should name the invalid target_name: " + res.error,
            res.error.contains("invalid target_name"));
    }

    @Test
    public void importValidTargetNamePassesValidationThenChecksProject() {
        HeadlessProgramProvider provider = new HeadlessProgramProvider();
        ProjectLifecycle lifecycle = new ProjectLifecycle(provider);

        // Valid name clears the up-front filename check, so the next failure is
        // the "no project open" guard — proving validation ran first and a good
        // name is not rejected.
        ImportResult res = lifecycle.importProgramFromGzf(null, "/", "CleanName", false);

        assertFalse(res.success);
        assertNotNull(res.error);
        assertTrue("valid name should pass validation and hit the project guard: " + res.error,
            res.error.contains("No project open"));
    }

    @Test
    public void importEmptyTargetNameSkipsValidation() {
        HeadlessProgramProvider provider = new HeadlessProgramProvider();
        ProjectLifecycle lifecycle = new ProjectLifecycle(provider);

        // An empty target_name is legal — the basename is derived downstream —
        // so it must not be rejected as an invalid filename.
        ImportResult res = lifecycle.importProgramFromGzf(null, "/", "", false);

        assertFalse(res.success);
        assertNotNull(res.error);
        assertTrue("empty name must bypass validation and hit the project guard: " + res.error,
            res.error.contains("No project open"));
    }

    /**
     * Found re-importing a firmware copy: overwrite=true reported success and left only the
     * backup. setName returns the renamed file, and the handle it is called on keeps naming
     * the old path, which the new import then occupies, so deleting through it deleted the
     * import.
     */
    @Test
    public void anOverwriteDeletesTheBackupNotTheNewImport() throws Exception {
        Project project = mock(Project.class);
        ProjectData data = mock(ProjectData.class);
        DomainFolder folder = mock(DomainFolder.class);
        DomainFile existing = mock(DomainFile.class);
        DomainFile renamed = mock(DomainFile.class);
        DomainFile created = mock(DomainFile.class);
        when(project.getProjectData()).thenReturn(data);
        when(data.getFolder("/mg")).thenReturn(folder);
        when(folder.getPathname()).thenReturn("/mg");
        when(folder.getFile("fw")).thenReturn(existing);
        when(existing.setName(anyString())).thenReturn(renamed);
        when(folder.createFile(eq("fw"), any(File.class), any())).thenReturn(created);
        when(created.getName()).thenReturn("fw");
        when(created.getContentType()).thenReturn("Program");

        Path dir = Files.createTempDirectory("gzf-overwrite");
        File gzf = Files.createFile(dir.resolve("fw.gzf")).toFile();
        ImportResult res = new ProjectLifecycle(new HeadlessProgramProvider(project))
            .importProgramFromGzf(gzf, "/mg", "fw", true);

        assertTrue(res.error, res.success);
        verify(renamed).delete();
        verify(existing, never()).delete();
        verify(created, never()).delete();
    }
}
