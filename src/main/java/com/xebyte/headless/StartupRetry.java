package com.xebyte.headless;

import java.util.function.BooleanSupplier;
import java.util.function.LongConsumer;

/** Retry with a capped backoff until an attempt succeeds or the work is no longer needed. */
public final class StartupRetry {

    public static final long FIRST_DELAY_MILLIS = 5_000;
    public static final long MAX_DELAY_MILLIS = 60_000;

    private StartupRetry() {}

    /**
     * @param attempt   true once it has succeeded
     * @param satisfied checked before each attempt; true means stop, success or not
     * @param sleeper   waits the given milliseconds
     * @return whether an attempt succeeded
     */
    public static boolean run(BooleanSupplier attempt, BooleanSupplier satisfied, LongConsumer sleeper) {
        long delay = FIRST_DELAY_MILLIS;
        while (true) {
            sleeper.accept(delay);
            if (satisfied.getAsBoolean()) {
                return false;
            }
            if (attempt.getAsBoolean()) {
                return true;
            }
            delay = Math.min(delay * 2, MAX_DELAY_MILLIS);
        }
    }

    static void sleep(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
