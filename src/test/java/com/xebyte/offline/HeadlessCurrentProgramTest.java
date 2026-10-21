package com.xebyte.offline;

import com.xebyte.headless.HeadlessProgramProvider;
import ghidra.program.model.listing.Program;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Headless has no current-program field — getCurrentProgram is derived from
 * the open set so it cannot go stale across loads the way the old mutable
 * field did (17-program survey returned one binary's numbers seventeen times).
 */
public class HeadlessCurrentProgramTest {

    private static Program named(String name) {
        Program p = mock(Program.class);
        when(p.getName()).thenReturn(name);
        return p;
    }

    @Test
    public void soleOpenProgramIsCurrent() {
        HeadlessProgramProvider provider = new HeadlessProgramProvider();
        Program a = named("a.dll");
        provider.trackOpenProgram(a);
        assertSame(a, provider.getCurrentProgram());
    }

    @Test
    public void twoOpenProgramsYieldsNullCurrent() {
        HeadlessProgramProvider provider = new HeadlessProgramProvider();
        provider.trackOpenProgram(named("a.dll"));
        provider.trackOpenProgram(named("b.dll"));
        assertNull(provider.getCurrentProgram());
    }

    @Test
    public void noneOpenYieldsNullCurrent() {
        assertNull(new HeadlessProgramProvider().getCurrentProgram());
    }

    @Test
    public void setCurrentProgramIsNoOpAndDoesNotCreateState() {
        HeadlessProgramProvider provider = new HeadlessProgramProvider();
        Program a = named("a.dll");
        Program b = named("b.dll");
        provider.trackOpenProgram(a);
        provider.trackOpenProgram(b);
        // Must not invent sticky current among many opens.
        provider.setCurrentProgram(b);
        assertNull(provider.getCurrentProgram());
        // And must not register a program that was never tracked via load/track.
        HeadlessProgramProvider empty = new HeadlessProgramProvider();
        empty.setCurrentProgram(a);
        assertNull(empty.getCurrentProgram());
        assertEquals(0, empty.getAllOpenPrograms().length);
    }

    @Test
    public void closingDownToOneRestoresSoleCurrent() {
        HeadlessProgramProvider provider = new HeadlessProgramProvider();
        Program a = named("a.dll");
        Program b = named("b.dll");
        provider.trackOpenProgram(a);
        provider.trackOpenProgram(b);
        assertNull(provider.getCurrentProgram());
        provider.closeProgram(a, false);
        assertSame(b, provider.getCurrentProgram());
    }
}
