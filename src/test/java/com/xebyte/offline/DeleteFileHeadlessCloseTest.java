package com.xebyte.offline;

import com.xebyte.core.ProgramScriptService;
import com.xebyte.core.ProjectProgramProvider;
import com.xebyte.core.Response;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectData;
import ghidra.program.model.listing.Program;
import org.junit.Test;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * /delete_file must close exactly the file it deletes, on either server.
 *
 * <p>The close-before-delete step once went through closeProgram(path, false), whose
 * matcher fell back to a SUBSTRING test and closed every hit: deleting
 * /Mods/D2Common.dll also closed /Mods/D2Common.dll.orig and silently discarded its
 * unsaved edits, while the response still reported success. It now releases by exact
 * path through the provider both servers share.
 */
public class DeleteFileHeadlessCloseTest {

    /** The shared provider with no GUI layer: what the headless server runs. */
    private static final class HeadlessLikeProvider extends ProjectProgramProvider {
        final Project project;

        HeadlessLikeProvider(Project project) {
            super(null, true);
            this.project = project;
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
    }

    private static Program programAt(String path) {
        Program p = mock(Program.class);
        DomainFile df = mock(DomainFile.class);
        when(df.getPathname()).thenReturn(path);
        when(p.getDomainFile()).thenReturn(df);
        when(p.getName()).thenReturn(path.substring(path.lastIndexOf('/') + 1));
        return p;
    }

    @Test
    public void deleteClosesOnlyTheExactPathNotSubstringNeighbours() throws Exception {
        String target = "/Mods/D2Common.dll";
        DomainFile targetFile = mock(DomainFile.class);
        ProjectData data = mock(ProjectData.class);
        when(data.getFile(target)).thenReturn(targetFile);
        Project project = mock(Project.class);
        when(project.getProjectData()).thenReturn(data);

        HeadlessLikeProvider provider = new HeadlessLikeProvider(project);
        Program victim = programAt(target);
        Program neighbour = programAt("/Mods/D2Common.dll.orig");   // path CONTAINS the target
        provider.trackOpenProgram(neighbour);
        provider.trackOpenProgram(victim);

        ProgramScriptService scripts = new ProgramScriptService(provider, new NoopThreadingStrategy());
        Response r = scripts.deleteFile(target);

        assertTrue("delete should succeed: " + r, r instanceof Response.Ok);
        verify(targetFile).delete();
        verify(victim).release(any());
        verify(neighbour, never()).release(any());
        assertArrayEquals("a program whose path merely contains the target must survive",
                          new Program[] {neighbour}, provider.getAllOpenPrograms());
    }

    @Test
    public void deleteWithNothingOpenClosesNothing() throws Exception {
        String target = "/solo.exe";
        DomainFile targetFile = mock(DomainFile.class);
        ProjectData data = mock(ProjectData.class);
        when(data.getFile(target)).thenReturn(targetFile);
        Project project = mock(Project.class);
        when(project.getProjectData()).thenReturn(data);

        HeadlessLikeProvider provider = new HeadlessLikeProvider(project);
        Program bystander = programAt("/other/solo.exe.bak");
        provider.trackOpenProgram(bystander);

        Response r = new ProgramScriptService(provider, new NoopThreadingStrategy()).deleteFile(target);

        assertTrue(r instanceof Response.Ok);
        verify(targetFile).delete();
        verify(bystander, never()).release(any());
        assertEquals("nothing matched exactly, so nothing may be closed", 1, provider.getAllOpenPrograms().length);
    }
}
