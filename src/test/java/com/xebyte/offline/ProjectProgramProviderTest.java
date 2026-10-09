package com.xebyte.offline;

import com.xebyte.core.AmbiguousProgramException;
import com.xebyte.core.ProgramScriptService;
import com.xebyte.core.ProjectProgramProvider;
import com.xebyte.core.Response;
import com.xebyte.headless.HeadlessProgramProvider;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectData;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import org.junit.Test;

import java.util.List;
import java.util.Map;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.Mockito.*;

/**
 * The program model both servers now share: how a name resolves, and what closing does
 * with unsaved edits.
 *
 * <p>Before the two providers shared a base, headless resolved only bare names of
 * programs someone had explicitly opened (so {@code program=/fw/gnutrue} and any
 * unopened project file answered "Program not found"), {@code close_program save=true}
 * released without saving, and {@code switch_program} reported success while doing
 * nothing. The GUI's {@code save=false} still saved, through the cache release.
 */
public class ProjectProgramProviderTest {

    /** A provider over a mocked project; nothing GUI- or headless-specific. */
    private static class Fixture extends ProjectProgramProvider {
        final Project project;
        final ProjectData data;

        final List<DomainFile> files = new java.util.ArrayList<>();

        Fixture() {
            super(null, true);
            project = mock(Project.class);
            data = mock(ProjectData.class);
            when(project.getProjectData()).thenReturn(data);
            // One flat folder holding every file: enough for a search by name.
            DomainFolder root = mock(DomainFolder.class);
            when(root.getFiles()).thenAnswer(inv -> files.toArray(new DomainFile[0]));
            when(root.getFolders()).thenReturn(new DomainFolder[0]);
            when(data.getRootFolder()).thenReturn(root);
        }

        @Override
        protected Project project() {
            return project;
        }

        @Override
        public Program getCurrentProgram() {
            return null;
        }

        @Override
        public void setCurrentProgram(Program program) {
        }

        /** A project file at {@code path} whose open yields a fresh mocked program. */
        Program file(String path) throws Exception {
            Program p = programAt(path);
            DomainFile df = p.getDomainFile();
            when(df.getDomainObject(any(), anyBoolean(), anyBoolean(), any())).thenReturn(p);
            when(data.getFile(path)).thenReturn(df);
            files.add(df);
            return p;
        }
    }

    private static Program programAt(String path) {
        Program p = mock(Program.class);
        DomainFile df = mock(DomainFile.class);
        when(df.getPathname()).thenReturn(path);
        when(df.getName()).thenReturn(path.substring(path.lastIndexOf('/') + 1));
        when(p.getDomainFile()).thenReturn(df);
        when(p.getName()).thenReturn(path.substring(path.lastIndexOf('/') + 1));
        return p;
    }

    // ------------------------------------------------------------------ match

    @Test
    public void exactPathWinsOverSameNameElsewhere() {
        Program v1 = programAt("/1.10/D2Common.dll");
        Program v2 = programAt("/1.13d/D2Common.dll");
        assertSame(v2, ProjectProgramProvider.match(List.of(v1, v2), "/1.13d/D2Common.dll"));
    }

    @Test
    public void bareNameShared_byTwoVersionsIsAmbiguousNotAGuess() {
        Program v1 = programAt("/1.10/D2Common.dll");
        Program v2 = programAt("/1.13d/D2Common.dll");
        try {
            ProjectProgramProvider.match(List.of(v1, v2), "D2Common.dll");
            fail("two programs share the name; picking one sends writes to a guess");
        } catch (AmbiguousProgramException e) {
            assertEquals(List.of("/1.10/D2Common.dll", "/1.13d/D2Common.dll"), e.candidates());
            assertTrue(e.getMessage(), e.getMessage().contains("full project path"));
        }
    }

    @Test
    public void exactNameBeatsASubstringNeighbour() {
        Program gnu = programAt("/fw/gnu");
        Program gnutrue = programAt("/fw/gnutrue");
        assertSame(gnu, ProjectProgramProvider.match(List.of(gnutrue, gnu), "gnu"));
    }

    @Test
    public void substringOnlyWhenUnique() {
        Program a = programAt("/fw/gnutrue");
        Program b = programAt("/fw/gnufalse");
        assertSame(a, ProjectProgramProvider.match(List.of(a), "true"));
        assertThrows(AmbiguousProgramException.class,
            () -> ProjectProgramProvider.match(List.of(a, b), "gnu"));
    }

    @Test
    public void pathNeverSubstringMatches() {
        Program orig = programAt("/Mods/D2Common.dll.orig");
        assertNull(ProjectProgramProvider.match(List.of(orig), "/Mods/D2Common.dll"));
    }

    // -------------------------------------------------------------- resolution

    @Test
    public void unopenedProjectFileOpensOnDemandByPath() throws Exception {
        Fixture f = new Fixture();
        Program p = f.file("/fw/gnutrue");
        assertSame(p, f.getProgram("/fw/gnutrue"));
        assertEquals(1, f.getAllOpenPrograms().length);
        // ...and a second lookup is served from the cache, not re-opened.
        assertSame(p, f.getProgram("gnutrue"));
        verify(p.getDomainFile(), times(1)).getDomainObject(any(), anyBoolean(), anyBoolean(), any());
    }

    @Test
    public void projectFileBeatsASubstringOfAnOpenProgram() throws Exception {
        Fixture f = new Fixture();
        Program gnutrue = f.file("/gnutrue");
        Program gnu = f.file("/gnu");
        assertSame(gnutrue, f.getProgram("/gnutrue"));
        assertSame("'gnu' names the file gnu, not the open gnutrue", gnu, f.getProgram("gnu"));
    }

    @Test
    public void aBareNameTwoProjectFilesShareIsAmbiguousEvenWithOneOpen() throws Exception {
        // Found live: with /fw/gnutrue open, "gnutrue" silently meant it, although
        // /other/gnutrue sits in the same project. What is open must not decide.
        Fixture f = new Fixture();
        f.file("/fw/gnutrue");
        f.file("/other/gnutrue");
        f.getProgram("/fw/gnutrue");

        AmbiguousProgramException e =
            assertThrows(AmbiguousProgramException.class, () -> f.getProgram("gnutrue"));
        assertEquals(List.of("/fw/gnutrue", "/other/gnutrue"), e.candidates());
    }

    @Test
    public void aRootFileGetsNoPriorityOverASameNamedOneDeeper() throws Exception {
        Fixture f = new Fixture();
        f.file("/x");
        f.file("/sub/x");
        assertThrows(AmbiguousProgramException.class, () -> f.getProgram("x"));
    }

    @Test
    public void unknownNameIsNull() {
        assertNull(new Fixture().getProgram("nope"));
    }

    // ----------------------------------------------------------------- closing

    @Test
    public void closeWithSaveSavesUnsavedEdits() throws Exception {
        Fixture f = new Fixture();
        Program p = f.file("/fw/a");
        f.getProgram("/fw/a");
        when(p.isChanged()).thenReturn(true);

        assertTrue(f.closeProgram(p, true));
        verify(p.getDomainFile()).save(any(TaskMonitor.class));
        verify(p).release(any());
        assertEquals(0, f.getAllOpenPrograms().length);
    }

    @Test
    public void closeWithoutSaveDiscards() throws Exception {
        Fixture f = new Fixture();
        Program p = f.file("/fw/a");
        f.getProgram("/fw/a");
        when(p.isChanged()).thenReturn(true);

        assertTrue(f.releaseCachedProgram("/fw/a", false));
        verify(p.getDomainFile(), never()).save(any(TaskMonitor.class));
        verify(p).release(any());
    }

    @Test
    public void closeByPathIsExact() throws Exception {
        Fixture f = new Fixture();
        Program target = f.file("/Mods/D2Common.dll");
        Program orig = f.file("/Mods/D2Common.dll.orig");
        f.getProgram("/Mods/D2Common.dll");
        f.getProgram("/Mods/D2Common.dll.orig");

        assertTrue(f.closeProgramByPath("/Mods/D2Common.dll"));
        verify(target).release(any());
        verify(orig, never()).release(any());
        assertArrayEquals(new Program[] {orig}, f.getAllOpenPrograms());
    }

    // --------------------------------------------------------------- switching

    @Test
    public void headlessSwitchAmongSeveralSaysItDidNotSwitch() {
        HeadlessProgramProvider provider = new HeadlessProgramProvider();
        provider.trackOpenProgram(programAt("/a.dll"));
        provider.trackOpenProgram(programAt("/b.dll"));

        Response r = new ProgramScriptService(provider, new NoopThreadingStrategy()).switchProgram("b.dll");

        assertTrue("headless keeps no current program, so success would be a lie: " + r,
            r instanceof Response.Err);
        assertTrue(r.toString(), r.toString().contains("program=\\\"/b.dll\\\"")
            || r.toString().contains("program=\"/b.dll\""));
    }

    @Test
    public void switchToAnAmbiguousNameIsRefused() {
        HeadlessProgramProvider provider = new HeadlessProgramProvider();
        provider.trackOpenProgram(programAt("/1.10/D2Common.dll"));
        provider.trackOpenProgram(programAt("/1.13d/D2Common.dll"));

        Response r = new ProgramScriptService(provider, new NoopThreadingStrategy()).switchProgram("D2Common.dll");

        assertTrue(r instanceof Response.Err);
        assertTrue(r.toString(), r.toString().contains("ambiguous"));
    }

    // ------------------------------------------------- open / import / checkin

    private static Map<String, Object> body(Response r) {
        assertTrue("expected Ok: " + r, r instanceof Response.Ok);
        @SuppressWarnings("unchecked")
        Map<String, Object> m = (Map<String, Object>) ((Response.Ok) r).data();
        return m;
    }

    @Test
    public void openProgramNotFoundCarriesDiagnostics() throws Exception {
        Fixture f = new Fixture();
        when(f.project.getName()).thenReturn("proj");
        DomainFolder root = mock(DomainFolder.class);
        DomainFile real = mock(DomainFile.class);
        when(real.getContentType()).thenReturn("Program");
        when(real.getPathname()).thenReturn("/fw/gnutrue");
        when(root.getFiles()).thenReturn(new DomainFile[] {real});
        when(root.getFolders()).thenReturn(new DomainFolder[0]);
        when(f.data.getRootFolder()).thenReturn(root);

        Map<String, Object> out = body(new ProgramScriptService(f, new NoopThreadingStrategy())
            .openProgramFromProject("/fw/gnutrue.typo", false));

        assertEquals(false, out.get("success"));
        @SuppressWarnings("unchecked")
        Map<String, Object> diagnostics = (Map<String, Object>) out.get("diagnostics");
        assertEquals(List.of("/fw/gnutrue"), diagnostics.get("available_program_paths"));
        assertEquals(false, diagnostics.get("project_server_bound"));
    }

    @Test
    public void openProgramWithNoProjectSaysSo() {
        Fixture f = new Fixture() {
            @Override
            protected Project project() {
                return null;
            }
        };
        Response r = new ProgramScriptService(f, new NoopThreadingStrategy()).openProgramFromProject("/a", false);
        assertTrue(r.toString(), r instanceof Response.Err && r.toString().contains("/open_project"));
    }

    @Test
    public void importOfAFileTheFolderAlreadyHoldsOpensItInstead() throws Exception {
        Fixture f = new Fixture();
        Program existing = f.file("/fw/blob.bin");
        DomainFolder folder = mock(DomainFolder.class);
        DomainFile existingFile = existing.getDomainFile();
        when(folder.getFile("blob.bin")).thenReturn(existingFile);
        when(f.data.getFolder("/fw")).thenReturn(folder);

        ProjectProgramProvider.Imported imported =
            f.importFile(new java.io.File("/nonexistent/blob.bin"), "/fw", "", "");

        assertTrue("a second import must not re-import (duplicate name)", imported.reusedExisting());
        assertSame(existing, imported.program());
        assertArrayEquals(new Program[] {existing}, f.getAllOpenPrograms());
    }

    @Test
    public void projectInfoIsTheSameShapeWithoutAGui() throws Exception {
        Fixture f = new Fixture();
        when(f.project.getName()).thenReturn("proj");
        when(f.data.getFileCount()).thenReturn(3);
        f.file("/fw/a");
        f.getProgram("/fw/a");

        Map<String, Object> out = body(new ProgramScriptService(f, new NoopThreadingStrategy()).getProjectInfo());

        assertEquals(true, out.get("has_project"));
        assertEquals("proj", out.get("project_name"));
        assertEquals(3, out.get("file_count"));
        assertEquals(false, out.get("project_server_bound"));
        assertEquals(List.of("/fw/a"), out.get("open_programs"));
        assertFalse("running_tools is GUI-only", out.containsKey("running_tools"));
    }
}
