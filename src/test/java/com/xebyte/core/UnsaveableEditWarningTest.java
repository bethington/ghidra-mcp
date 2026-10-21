package com.xebyte.core;

import com.xebyte.headless.DirectThreadingStrategy;
import ghidra.framework.data.DomainFileProxy;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.listing.Program;
import org.junit.After;
import org.junit.Test;

import java.util.List;
import java.util.Map;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

/**
 * Found live on a shared project: a versioned file that is not checked out opens as an
 * in-memory copy, every edit tool reported success on it, and the edits vanished on close.
 * Edits now say so, and a save names the cause instead of "Location does not exist for a
 * save operation!".
 */
public class UnsaveableEditWarningTest {

    @After
    public void clear() {
        ServiceUtils.clearResolvedProgramName();
    }

    private static Program program(DomainFile df, boolean canSave, boolean changed) {
        Program p = mock(Program.class);
        when(p.getName()).thenReturn("fw");
        when(p.getDomainFile()).thenReturn(df);
        when(p.canSave()).thenReturn(canSave);
        when(p.isChanged()).thenReturn(changed);
        return p;
    }

    private static DomainFileProxy proxy(String path) {
        DomainFileProxy proxy = mock(DomainFileProxy.class);
        when(proxy.getPathname()).thenReturn(path);
        return proxy;
    }

    @Test
    public void aSaveableProgramHasNoReason() {
        assertNull(ProgramSaves.unsaveableReason(program(mock(DomainFile.class), true, true)));
        assertNull(ProgramSaves.unsaveableReason(null));
    }

    @Test
    public void aCopyOfAVersionedFileNamesTheCheckoutAsTheRemedy() {
        String reason = ProgramSaves.unsaveableReason(program(proxy("/fw/a"), false, false));
        assertTrue(reason, reason.startsWith("/fw/a is not checked out"));
        assertTrue(reason, reason.contains("/server/version_control/checkout"));
    }

    @Test
    public void aReadOnlyProjectFileSaysThat() {
        DomainFile df = mock(DomainFile.class);
        when(df.getPathname()).thenReturn("/fw/a");
        assertEquals("/fw/a cannot be saved: its project file is read-only.",
            ProgramSaves.unsaveableReason(program(df, false, false)));
    }

    @Test
    @SuppressWarnings("unchecked")
    public void anEditToAnUnsaveableProgramCarriesTheWarningAlongsideExistingOnes() {
        ServiceUtils.recordResolvedProgram(program(proxy("/fw/a"), false, true));

        Response out = AnnotationScanner.warnIfUnsaveable(Response.ok(Map.of(
            "status", "success", "warnings", List.of("name misses the convention"))));

        Map<String, Object> data = (Map<String, Object>) ((Response.Ok) out).data();
        assertEquals("success", data.get("status"));
        List<Object> warnings = (List<Object>) data.get("warnings");
        assertEquals(2, warnings.size());
        assertEquals("name misses the convention", warnings.get(0));
        assertTrue(String.valueOf(warnings.get(1)).startsWith("/fw/a is not checked out"));
    }

    @Test
    public void nothingIsAddedWhenTheProgramCanSaveOrNothingChanged() {
        Response ok = Response.ok(Map.of("status", "success"));

        ServiceUtils.recordResolvedProgram(program(mock(DomainFile.class), true, true));
        assertSame(ok, AnnotationScanner.warnIfUnsaveable(ok));

        ServiceUtils.recordResolvedProgram(program(proxy("/fw/a"), false, false));
        assertSame("a write that changed nothing loses nothing", ok, AnnotationScanner.warnIfUnsaveable(ok));

        ServiceUtils.clearResolvedProgramName();
        assertSame(ok, AnnotationScanner.warnIfUnsaveable(ok));
    }

    /**
     * Found live: close_program(save=true) on an edited copy reported success while Ghidra
     * logged "Unsaved changes LOST".
     */
    @Test
    public void closingWithSaveRefusesWhenTheEditsCannotBeSaved() {
        Program copy = program(proxy("/fw/a"), false, true);
        ProgramProvider provider = mock(ProgramProvider.class);
        when(provider.getAllOpenPrograms()).thenReturn(new Program[] {copy});
        ProgramScriptService scripts = new ProgramScriptService(provider, new DirectThreadingStrategy());

        Response refused = scripts.closeProgram("/fw/a", true);

        assertTrue(refused.toJson(), refused instanceof Response.Err);
        assertTrue(refused.toJson(), refused.toJson().contains("save=false"));
        verify(provider, never()).closeProgram(any(), anyBoolean());

        scripts.closeProgram("/fw/a", false);
        verify(provider).closeProgram(copy, false);
    }

    @Test
    public void aFailedWriteIsLeftAsItIs() {
        ServiceUtils.recordResolvedProgram(program(proxy("/fw/a"), false, true));
        Response err = Response.err("nope");
        assertSame(err, AnnotationScanner.warnIfUnsaveable(err));
    }
}
