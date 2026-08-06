package com.xebyte.offline;

import com.xebyte.core.WriteTx;
import ghidra.framework.model.TransactionInfo;
import ghidra.program.model.listing.Program;
import junit.framework.TestCase;

import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The one behaviour that matters: a nested write must never roll back.
 *
 * <p>Ghidra nests by counting entries on a single transaction, so
 * {@code endTransaction(id, false)} from an inner scope marks the whole
 * transaction aborted and discards the outer owner's work with it. Measured
 * during this project's experiments: a probe's own rollback threw away a rename,
 * two comments and a struct made by the enclosing script transaction.
 */
public class WriteTxTest extends TestCase {

    private Program programWithoutTransaction() {
        Program program = mock(Program.class);
        when(program.getCurrentTransactionInfo()).thenReturn(null);
        when(program.startTransaction(anyString())).thenReturn(7);
        return program;
    }

    private Program programWithOpenTransaction() {
        Program program = mock(Program.class);
        when(program.getCurrentTransactionInfo()).thenReturn(mock(TransactionInfo.class));
        when(program.startTransaction(anyString())).thenReturn(9);
        return program;
    }

    public void testOwnedTransactionCommits() {
        Program program = programWithoutTransaction();
        WriteTx tx = WriteTx.begin(program, "Rename");
        assertFalse(tx.joined());
        assertEquals(7, tx.id());
        tx.end(true);
        verify(program).endTransaction(7, true);
    }

    public void testOwnedTransactionRollsBack() {
        Program program = programWithoutTransaction();
        WriteTx.begin(program, "Rename").end(false);
        verify(program).endTransaction(7, false);
    }

    public void testJoinsInsteadOfNesting() {
        Program program = programWithOpenTransaction();
        WriteTx tx = WriteTx.begin(program, "Rename");
        assertTrue(tx.joined());
        assertEquals(WriteTx.JOINED, tx.id());
        verify(program, never()).startTransaction(anyString());
    }

    public void testNestedFailureDoesNotRollBackTheAmbientTransaction() {
        Program program = programWithOpenTransaction();
        WriteTx.begin(program, "Rename").end(false);
        // The whole point: no endTransaction at all, so the outer owner's
        // transaction survives to be committed or undone as one unit.
        verify(program, never()).endTransaction(anyInt(), anyBoolean());
    }

    public void testEndIsIdempotent() {
        Program program = programWithoutTransaction();
        WriteTx tx = WriteTx.begin(program, "Rename");
        tx.end(true);
        tx.end(false);
        verify(program, times(1)).endTransaction(anyInt(), anyBoolean());
        verify(program).endTransaction(7, true);
    }

    public void testNullProgramIsInert() {
        WriteTx tx = WriteTx.begin(null, "Rename");
        assertTrue(tx.joined());
        tx.end(false);  // must not throw
    }
}
