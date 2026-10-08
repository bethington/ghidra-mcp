package com.xebyte.core;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * {@code /exit_ghidra}, the same on both servers: save every open program, say what was
 * saved, and stop the process half a second later so the answer reaches the caller.
 *
 * <p>The two servers each had this. The GUI saved and reported; headless exited and left
 * the saving to its shutdown hook, after the caller had already been told it was done.
 */
public class ServerLifecycleService {

    /** Long enough for the HTTP response to be flushed before the process goes away. */
    private static final long EXIT_DELAY_MS = 500;

    private final ProgramScriptService programs;
    private final ServerLifecycle lifecycle;

    public ServerLifecycleService(ProgramScriptService programs, ServerLifecycle lifecycle) {
        this.programs = programs;
        this.lifecycle = lifecycle;
    }

    @McpTool(path = "/exit_ghidra", dryRun = false, method = "POST",
            description = "Save every open program (and, in the GUI, debugger traces), then stop the "
                + "server process. The response reports what was saved. Nothing can be called after it.",
            category = "program", access = ToolAccess.DESTRUCTIVE)
    public Response exit() {
        try {
            lifecycle.prepare();
            Map<String, Object> save = new LinkedHashMap<>();
            save.put("programs", programs.saveAllOpenPrograms().asEmbeddable());
            save.putAll(lifecycle.saveExtras());

            Thread stopper = new Thread(() -> {
                try {
                    Thread.sleep(EXIT_DELAY_MS);
                } catch (InterruptedException ignored) {
                    Thread.currentThread().interrupt();
                }
                lifecycle.exit();
            }, "GhidraMCP-exit");
            stopper.setDaemon(false);
            stopper.start();

            Map<String, Object> out = new LinkedHashMap<>();
            out.put("success", true);
            out.put("message", "Saved all open programs; exiting");
            out.put("save", save);
            return Response.ok(out);
        } catch (Throwable e) {
            return Response.err(e.getMessage() != null ? e.getMessage() : e.toString());
        }
    }
}
