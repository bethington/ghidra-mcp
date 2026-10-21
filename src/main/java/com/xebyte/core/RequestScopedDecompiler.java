package com.xebyte.core;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;

import java.util.HashMap;
import java.util.Map;
import java.util.function.Supplier;

/**
 * One decompiler for the length of one request, plus that request's results by entry point.
 *
 * <p>Opening a {@link DecompInterface} is the expensive part of a decompile: measured ~238 ms
 * per function with a fresh interface against 5.7-10 ms reusing one (#575). A bulk
 * {@code /get_functions} call decompiles up to 20 targets plus up to
 * {@code call_context_limit} callers of each, so opening one per decompile cost dozens to
 * 100+ process starts for a single request. This opens the interface on the first decompile
 * that needs it (a fields= subset that decompiles nothing opens none) and reuses it until
 * {@link #close()}.
 *
 * <p>Results are cached by entry point, so a caller shared by several targets -- or a target
 * that is also another target's caller -- is decompiled once per request. Every decompile
 * here uses the same options, so a cached result is exactly what a second decompile would
 * have produced; {@code DecompInterface.decompileFunction} flushes the native cache after each
 * function, so reuse does not carry state from one function into the next either. A failure
 * is cached too: retrying it in the same request would spend the same timeout to fail again.
 *
 * <p>A decompile that does not complete -- a timeout, a crashed or unstartable process, an
 * exception -- disposes the interface, and the next decompile opens a fresh one. Ghidra
 * restarts a dead process itself in most of those cases, but "most" is not a contract, and a
 * half-dead interface failing every later entry in a bulk call is the one outcome worse than
 * paying for one reopen.
 *
 * <p>Not thread-safe, like the {@link DecompInterface} it wraps: create it, use it and close
 * it on the request thread. Nothing here is shared between requests, so nothing outlives a
 * change to the program between them.
 */
final class RequestScopedDecompiler implements FunctionFacts.Decompiler, AutoCloseable {

    private final Supplier<DecompInterface> opener;
    private final int timeoutSeconds;
    private final Map<Address, DecompileResults> byEntry = new HashMap<>();
    private DecompInterface decomp;

    /**
     * @param opener returns a configured interface already opened on the program, as
     *               {@link ServiceUtils#createConfiguredDecompiler} does
     */
    RequestScopedDecompiler(Supplier<DecompInterface> opener, int timeoutSeconds) {
        this.opener = opener;
        this.timeoutSeconds = timeoutSeconds;
    }

    @Override
    public DecompileResults decompile(Function function) {
        Address entry = function.getEntryPoint();
        if (byEntry.containsKey(entry)) {
            return byEntry.get(entry);
        }
        DecompileResults results = null;
        try {
            if (decomp == null) {
                decomp = opener.get();
            }
            results = decomp.decompileFunction(function, timeoutSeconds, new ConsoleTaskMonitor());
        } catch (Exception e) {
            Msg.warn(this, "Single-attempt decompile failed for " + function.getName() + ": "
                + e.getMessage());
        }
        if (results == null || !results.decompileCompleted()) {
            // Do not let this interface decide whether the next entry decompiles.
            disposeInterface();
        }
        byEntry.put(entry, results);
        return results;
    }

    @Override
    public void close() {
        disposeInterface();
        byEntry.clear();
    }

    private void disposeInterface() {
        if (decomp != null) {
            try {
                decomp.dispose();
            } catch (Exception ignored) {
                // Disposal of a dead process can throw; it is gone either way.
            }
            decomp = null;
        }
    }
}
