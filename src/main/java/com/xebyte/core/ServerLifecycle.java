package com.xebyte.core;

import java.util.Map;

/**
 * What ending the process means for one server. {@link ServerLifecycleService} does the
 * part both servers share (save every open program, answer, then stop); this is the rest.
 */
public interface ServerLifecycle {

    /** Runs before anything is saved. The GUI answers Ghidra's own prompts for the duration. */
    default void prepare() {}

    /** Further state to save, by name, reported beside the programs. The GUI's debugger traces. */
    default Map<String, Object> saveExtras() {
        return Map.of();
    }

    /** End the process. Called after the response has gone out. */
    void exit();
}
