package com.xebyte.core;

import com.xebyte.headless.DirectThreadingStrategy;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import org.junit.Test;

import java.util.List;
import java.util.Map;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Found live (stealth RE session, reproduced against a Ghidra Server): saving a program with
 * no unsaved changes still wrote its file, so a versioned file checked out with no edits read
 * modified_since_checkout=true after a save, and the next check-in carried an empty version.
 */
public class SaveWhenUnchangedTest {

    private static Program program(String path, boolean changed) {
        DomainFile df = mock(DomainFile.class);
        when(df.getPathname()).thenReturn(path);
        when(df.isInWritableProject()).thenReturn(true);
        Program p = mock(Program.class);
        when(p.getName()).thenReturn(path.substring(1));
        when(p.getDomainFile()).thenReturn(df);
        when(p.isChanged()).thenReturn(changed);
        when(p.canSave()).thenReturn(true);
        return p;
    }

    private static ProgramScriptService scripts(Program... open) {
        ProgramProvider provider = mock(ProgramProvider.class);
        when(provider.getAllOpenPrograms()).thenReturn(open);
        when(provider.getCurrentProgram()).thenReturn(open[0]);
        when(provider.resolveProgram(any())).thenReturn(open[0]);
        when(provider.getProgram(any())).thenReturn(open[0]);
        return new ProgramScriptService(provider, new DirectThreadingStrategy());
    }

    @Test
    @SuppressWarnings("unchecked")
    public void saveProgramDoesNotWriteAProgramWithNothingToSave() throws Exception {
        Program clean = program("/fw/a", false);

        Response r = scripts(clean).saveCurrentProgram("/fw/a");

        Map<String, Object> out = (Map<String, Object>) ((Response.Ok) r).data();
        assertEquals(false, out.get("saved"));
        verify(clean.getDomainFile(), never()).save(any(TaskMonitor.class));
    }

    @Test
    @SuppressWarnings("unchecked")
    public void saveAllWritesOnlyChangedProgramsAndListsTheRest() throws Exception {
        Program clean = program("/fw/a", false);
        Program dirty = program("/fw/b", true);

        Response r = scripts(clean, dirty).saveAllOpenPrograms();

        Map<String, Object> out = (Map<String, Object>) ((Response.Ok) r).data();
        assertEquals(1, out.get("saved_count"));
        assertEquals(List.of("/fw/a"), out.get("unchanged"));
        assertEquals(List.of(), out.get("errors"));
        verify(clean.getDomainFile(), never()).save(any(TaskMonitor.class));
        verify(dirty.getDomainFile()).save(any(TaskMonitor.class));
    }
}
