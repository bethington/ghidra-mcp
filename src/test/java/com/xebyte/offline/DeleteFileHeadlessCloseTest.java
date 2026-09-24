package com.xebyte.offline;

import com.xebyte.core.ProgramProvider;
import com.xebyte.core.ProgramScriptService;
import com.xebyte.core.Response;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectData;
import ghidra.program.model.listing.Program;
import org.junit.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

/**
 * Headless /delete_file must close exactly the file it deletes.
 *
 * <p>With no PluginTool (the headless case) the close-before-delete step once
 * went through closeProgram(path, false), whose matcher falls back to a
 * SUBSTRING test and closes every hit. The headless provider's close is a bare
 * release with no save, so deleting /Mods/D2Common.dll also closed
 * /Mods/D2Common.dll.orig and silently discarded its unsaved edits -- while the
 * response still reported success. The GUI branch always matched the exact
 * path; this pins the headless branch to the same rule.
 */
public class DeleteFileHeadlessCloseTest {

    /** A provider that is none of the GUI provider types, so no PluginTool resolves. */
    private static final class HeadlessLikeProvider implements ProgramProvider {
        final List<Program> open = new ArrayList<>();
        final List<Program> closed = new ArrayList<>();
        final Project project;

        HeadlessLikeProvider(Project project) { this.project = project; }

        @Override public Program getCurrentProgram() { return open.isEmpty() ? null : open.get(0); }
        @Override public Program getProgram(String name) { return null; }
        @Override public Program[] getAllOpenPrograms() { return open.toArray(new Program[0]); }
        @Override public void setCurrentProgram(Program program) { }
        @Override public boolean closeProgram(Program program) {
            open.remove(program);
            closed.add(program);
            return true;
        }
        @Override public Project getProject() { return project; }
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
        provider.open.add(neighbour);
        provider.open.add(victim);

        ProgramScriptService scripts = new ProgramScriptService(provider, new NoopThreadingStrategy());
        Response r = scripts.deleteFile(target);

        assertTrue("delete should succeed: " + r, r instanceof Response.Ok);
        verify(targetFile).delete();
        assertTrue("the deleted file's program must be closed", provider.closed.contains(victim));
        assertFalse("a program whose path merely contains the target must survive",
                    provider.closed.contains(neighbour));
        assertTrue(provider.open.contains(neighbour));
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
        provider.open.add(programAt("/other/solo.exe.bak"));

        Response r = new ProgramScriptService(provider, new NoopThreadingStrategy()).deleteFile(target);

        assertTrue(r instanceof Response.Ok);
        verify(targetFile).delete();
        assertTrue("nothing matched exactly, so nothing may be closed", provider.closed.isEmpty());
    }
}
