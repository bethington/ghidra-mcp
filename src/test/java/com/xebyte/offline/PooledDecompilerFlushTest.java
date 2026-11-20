package com.xebyte.offline;

import com.xebyte.core.tree.FunctionBlock;
import ghidra.app.decompiler.DecompInterface;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import org.junit.Test;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * A decompiler reused across a sweep or reconcile caches the function and symbol data it has
 * read and never re-reads it. It must flush when the program changed since it last ran, or a
 * block decompiled after a rename shows the callee's old name, and must not flush otherwise,
 * or every function in a sweep pays for re-reading what the last one already loaded.
 */
public class PooledDecompilerFlushTest {

    @Test
    public void flushesOnlyAfterTheProgramChanged() {
        Program program = mock(Program.class);
        Function func = mock(Function.class);
        when(func.getProgram()).thenReturn(program);
        DecompInterface decomp = mock(DecompInterface.class);

        when(program.getModificationNumber()).thenReturn(10L);
        FunctionBlock.decompileCurrent(decomp, func, 5, TaskMonitor.DUMMY);
        FunctionBlock.decompileCurrent(decomp, func, 5, TaskMonitor.DUMMY);
        verify(decomp, never()).flushCache();

        when(program.getModificationNumber()).thenReturn(11L);
        FunctionBlock.decompileCurrent(decomp, func, 5, TaskMonitor.DUMMY);
        FunctionBlock.decompileCurrent(decomp, func, 5, TaskMonitor.DUMMY);
        verify(decomp, times(1)).flushCache();
        verify(decomp, times(4)).decompileFunction(func, 5, TaskMonitor.DUMMY);
    }

    @Test
    public void eachDecompilerTracksItsOwnLastRun() {
        Program program = mock(Program.class);
        Function func = mock(Function.class);
        when(func.getProgram()).thenReturn(program);
        when(program.getModificationNumber()).thenReturn(1L);
        DecompInterface first = mock(DecompInterface.class);
        FunctionBlock.decompileCurrent(first, func, 5, TaskMonitor.DUMMY);

        when(program.getModificationNumber()).thenReturn(2L);
        DecompInterface second = mock(DecompInterface.class);
        FunctionBlock.decompileCurrent(second, func, 5, TaskMonitor.DUMMY);
        verify(second, never()).flushCache();

        FunctionBlock.decompileCurrent(first, func, 5, TaskMonitor.DUMMY);
        verify(first, times(1)).flushCache();
    }
}
