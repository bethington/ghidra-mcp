package com.xebyte.core;

import ghidra.app.script.GhidraState;
import ghidra.framework.model.Project;
import ghidra.program.model.listing.Program;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertSame;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Found live: a headless run_script_inline whose script called
 * {@code getState().getProject().getProjectData()} died with a NullPointerException, because
 * the headless script state was built with no project; the caller saw only "the server
 * reported failure" and concluded scripts may not open project files.
 */
public class ScriptRunStateTest {

    @Test
    public void aHeadlessScriptSeesTheServersProject() {
        Project project = mock(Project.class);
        ProgramProvider provider = mock(ProgramProvider.class);
        when(provider.getProject()).thenReturn(project);
        ProgramScriptService scripts = new ProgramScriptService(provider, mock(ThreadingStrategy.class));

        GhidraState state = scripts.scriptState(null, mock(Program.class), null);
        assertSame(project, state.getProject());
    }

    @Test
    public void aFailureNamesTheExceptionAndTheScriptsLine() {
        NullPointerException npe = new NullPointerException("Cannot invoke \"Project.getProjectData()\"");
        npe.setStackTrace(new StackTraceElement[] {
            new StackTraceElement("SyncLabels2", "run", "SyncLabels2.java", 15),
            new StackTraceElement("ghidra.app.script.GhidraScript", "executeNormal", "GhidraScript.java", 460)});
        assertEquals("NullPointerException: Cannot invoke \"Project.getProjectData()\" (SyncLabels2.java:15)",
            ProgramScriptService.failureReason(new RuntimeException("wrapped", npe), "SyncLabels2.java"));
    }

    @Test
    public void aFailureOutsideTheScriptStillNamesTheException() {
        IllegalStateException e = new IllegalStateException("compile failed");
        e.setStackTrace(new StackTraceElement[] {
            new StackTraceElement("ghidra.app.script.JavaScriptProvider", "getScriptInstance", "JavaScriptProvider.java", 90)});
        assertEquals("IllegalStateException: compile failed",
            ProgramScriptService.failureReason(e, "Broken.java"));
    }
}
