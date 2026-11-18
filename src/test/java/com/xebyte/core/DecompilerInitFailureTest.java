package com.xebyte.core;

import ghidra.app.decompiler.DecompInterface;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import org.junit.Test;

import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * #654: when the native decompiler cannot start, {@code DecompInterface.openProgram}
 * returns {@code false} and leaves the reason in {@code getLastMessage()}. The result
 * used to be ignored, the half-open interface's first decompile came back cancelled,
 * and every endpoint reported "cancelled". These pin the reason all the way to what a
 * caller reads -- and that it never says "cancelled".
 */
public class DecompilerInitFailureTest {

    private static final String GHIDRA_REASON =
        "Could not find decompiler executable decompile for os linux_arm_64";

    private static Program program(String name) {
        Program program = mock(Program.class);
        when(program.getName()).thenReturn(name);
        return program;
    }

    private static DecompInterface failingInterface(String lastMessage) {
        DecompInterface decomp = mock(DecompInterface.class);
        when(decomp.openProgram(any(Program.class))).thenReturn(false);
        when(decomp.getLastMessage()).thenReturn(lastMessage);
        return decomp;
    }

    @Test
    public void openFailureThrowsWithGhidrasReasonAndDisposes() {
        DecompInterface decomp = failingInterface(GHIDRA_REASON);

        DecompilerInitException e = assertThrows(DecompilerInitException.class,
            () -> ServiceUtils.openOrThrow(decomp, program("calc.exe")));

        assertEquals("Decompiler failed to initialise for calc.exe: " + GHIDRA_REASON,
            e.getMessage());
        assertEquals(GHIDRA_REASON, e.reason());
        assertFalse(e.getMessage().toLowerCase().contains("cancel"));
        verify(decomp).dispose();
    }

    @Test
    public void openFailureWithNoMessageStillNamesTheLikelyCause() {
        DecompInterface decomp = failingInterface("   ");

        DecompilerInitException e = assertThrows(DecompilerInitException.class,
            () -> ServiceUtils.openOrThrow(decomp, program("calc.exe")));

        assertTrue(e.getMessage(), e.getMessage().startsWith("Decompiler failed to initialise"));
        assertTrue(e.getMessage(), e.getMessage().contains("native decompiler"));
        assertNull(e.reason());
        verify(decomp).dispose();
    }

    @Test
    public void openThatThrowsIsDisposedAndRethrown() {
        DecompInterface decomp = mock(DecompInterface.class);
        when(decomp.openProgram(any(Program.class))).thenThrow(new IllegalStateException("boom"));

        IllegalStateException e = assertThrows(IllegalStateException.class,
            () -> ServiceUtils.openOrThrow(decomp, program("calc.exe")));

        assertEquals("boom", e.getMessage());
        verify(decomp).dispose();
    }

    @Test
    public void successfulOpenReturnsTheInterfaceUndisposed() {
        DecompInterface decomp = mock(DecompInterface.class);
        when(decomp.openProgram(any(Program.class))).thenReturn(true);

        assertSame(decomp, ServiceUtils.openOrThrow(decomp, program("calc.exe")));
        verify(decomp, never()).dispose();
    }

    /** force_decompile and every uncaught path render the exception through this. */
    @Test
    public void failureMessageCarriesTheReason() {
        String msg = ServiceUtils.failureMessage(
            new DecompilerInitException("calc.exe", GHIDRA_REASON));
        assertTrue(msg, msg.contains("failed to initialise"));
        assertTrue(msg, msg.contains(GHIDRA_REASON));
    }

    /**
     * get_functions: the request's decompiler records the init failure, reports it for
     * every entry, and does not respawn a doomed process per entry.
     */
    @Test
    public void requestScopedDecompilerReportsInitFailureOnceForTheRequest() {
        AtomicInteger opens = new AtomicInteger();
        RequestScopedDecompiler decompiler = new RequestScopedDecompiler(() -> {
            opens.incrementAndGet();
            return ServiceUtils.openOrThrow(failingInterface(GHIDRA_REASON), program("calc.exe"));
        }, 30);

        Function first = function("first");
        Function second = function("second");

        assertNull(decompiler.decompile(first));
        assertNull(decompiler.decompile(second));
        assertEquals("a native decompiler that cannot start is opened once per request",
            1, opens.get());

        String error = FunctionFacts.decompileError(decompiler.decompile(second), decompiler);
        assertTrue(error, error.startsWith("Decompiler failed to initialise"));
        assertTrue(error, error.contains(GHIDRA_REASON));
        assertNotEquals("cancelled", error);
        assertNotEquals("decompiler unavailable", error);
        decompiler.close();
    }

    @Test
    public void decompileErrorWithoutAReasonKeepsTheOldWording() {
        FunctionFacts.Decompiler none = f -> null;
        assertEquals("decompiler unavailable", FunctionFacts.decompileError(null, none));
    }

    /** analyze_* composites, analyze_dataflow and get_function_pcode read this. */
    @Test
    public void decompileAttemptPrefersTheInitFailure() {
        String reason = new DecompilerInitException("calc.exe", GHIDRA_REASON).getMessage();
        FunctionService.DecompileAttempt attempt = new FunctionService.DecompileAttempt(null, reason);
        assertFalse(attempt.completed());
        assertEquals(reason, attempt.failureReason());
        assertEquals("decompiler unavailable",
            new FunctionService.DecompileAttempt(null, null).failureReason());
    }

    private static Function function(String name) {
        Function f = mock(Function.class);
        Address entry = mock(Address.class);
        when(f.getEntryPoint()).thenReturn(entry);
        when(f.getName()).thenReturn(name);
        return f;
    }
}
