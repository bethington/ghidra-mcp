package com.xebyte.core;

/**
 * A tool's own "cannot do that" (no function at the address, nothing defined there), thrown
 * from inside {@link ThreadingStrategy#executeWrite} to roll the transaction back and become
 * the error response. Unlike a failure, it is the caller's input, so the strategies do not
 * log it as an error, and it carries no stack trace.
 */
public final class Refusal extends RuntimeException {
    public Refusal(String message) {
        super(message, null, false, false);
    }

    /** True for a Refusal, or one a reflective call wrapped (a tool invoked inside a dry run). */
    public static boolean is(Throwable t) {
        return t instanceof Refusal || (t != null && t.getCause() instanceof Refusal);
    }
}
