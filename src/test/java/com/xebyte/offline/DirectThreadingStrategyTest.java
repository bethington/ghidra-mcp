package com.xebyte.offline;

import com.xebyte.headless.DirectThreadingStrategy;
import ghidra.program.model.listing.Program;
import org.junit.Test;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Found on a live headless server: after a burst of parallel renames, every later rename
 * timed out while comments, saves and check-ins still worked. A thread dump showed the
 * write lock owned by an idle pool thread: ending a transaction threw, and the unlock sat
 * after it in the same finally block.
 */
public class DirectThreadingStrategyTest {

    @Test
    public void aFailureEndingTheTransactionStillReleasesTheWriteLock() throws Exception {
        DirectThreadingStrategy strategy = new DirectThreadingStrategy();
        Program program = mock(Program.class);
        when(program.startTransaction(anyString())).thenReturn(1);
        doThrow(new IllegalStateException("transaction already ended"))
            .when(program).endTransaction(anyInt(), anyBoolean());

        try {
            strategy.executeWrite(program, "first", () -> null);
            fail("the end-of-transaction failure must reach the caller");
        } catch (IllegalStateException expected) {
            // the lock must be free all the same
        }

        // Another thread must be able to write; before the fix this blocked forever.
        Program other = mock(Program.class);
        when(other.startTransaction(anyString())).thenReturn(2);
        CompletableFuture<String> second = CompletableFuture.supplyAsync(() -> {
            try {
                return strategy.executeWrite(other, "second", () -> "written");
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
        assertEquals("written", second.get(5, TimeUnit.SECONDS));
    }
}
