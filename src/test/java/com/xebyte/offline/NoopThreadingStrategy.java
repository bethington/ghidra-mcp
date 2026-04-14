package com.xebyte.offline;

import com.xebyte.core.ThreadingStrategy;
import ghidra.program.model.listing.Program;

import java.util.concurrent.Callable;

/**
 * Test stub for {@link ThreadingStrategy} that throws if invoked.
 *
 * Offline tests construct services purely so the annotation scanner can
 * reflect on them. If a test accidentally triggers a real service call
 * (e.g. a method that runs work inside {@code executeRead}), we want a
 * loud failure rather than a silent hang or NPE.
 */
public class NoopThreadingStrategy implements ThreadingStrategy {

    @Override
    public <T> T executeRead(Callable<T> action) {
        throw new UnsupportedOperationException(
            "NoopThreadingStrategy.executeRead invoked — an offline test triggered "
          + "real service logic. Offline tests should only reflect on services, "
          + "not call their methods.");
    }

    @Override
    public <T> T executeWrite(Program program, String txName, Callable<T> action) {
        throw new UnsupportedOperationException(
            "NoopThreadingStrategy.executeWrite invoked — an offline test triggered "
          + "real service logic. Offline tests should only reflect on services, "
          + "not call their methods.");
    }

    @Override
    public boolean isHeadless() {
        return true;
    }
}
