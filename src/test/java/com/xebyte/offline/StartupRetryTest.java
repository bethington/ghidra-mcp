package com.xebyte.offline;

import com.xebyte.headless.StartupRetry;
import org.junit.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class StartupRetryTest {

    private final List<Long> slept = new ArrayList<>();

    @Test
    public void retriesUntilTheServerAccepts() {
        AtomicInteger attempts = new AtomicInteger();
        assertTrue(StartupRetry.run(() -> attempts.incrementAndGet() == 3, () -> false, slept::add));
        assertEquals(3, attempts.get());
        assertEquals(List.of(5_000L, 10_000L, 20_000L), slept);
    }

    @Test
    public void backoffIsCapped() {
        AtomicInteger attempts = new AtomicInteger();
        StartupRetry.run(() -> attempts.incrementAndGet() == 8, () -> false, slept::add);
        assertEquals(StartupRetry.MAX_DELAY_MILLIS, (long) slept.get(slept.size() - 1));
    }

    /** A project opened by hand in the meantime must not be closed and reopened. */
    @Test
    public void stopsWithoutAttemptingOnceSomethingElseOpenedIt() {
        AtomicInteger attempts = new AtomicInteger();
        assertFalse(StartupRetry.run(() -> attempts.incrementAndGet() > 0, () -> true, slept::add));
        assertEquals(0, attempts.get());
    }
}
