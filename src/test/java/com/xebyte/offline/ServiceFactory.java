package com.xebyte.offline;

import com.xebyte.core.CoreServices;
import com.xebyte.core.DebuggerService;
import com.xebyte.core.ProgramProvider;
import com.xebyte.core.PromptPolicyService;
import com.xebyte.core.ThreadingStrategy;
import com.xebyte.headless.GhidraServerManager;
import com.xebyte.headless.HeadlessManagementService;
import com.xebyte.headless.HeadlessProgramProvider;

/**
 * Builds every service either server exposes -- {@link CoreServices} plus the GUI's and
 * the headless server's own -- with stub collaborators, so the result is safe to scan
 * offline.
 */
public final class ServiceFactory {

    private ServiceFactory() {}

    /** Build all services wired with stub collaborators, ready for scanning. */
    public static Object[] buildAllServices() {
        ProgramProvider provider = new StubProgramProvider();
        ThreadingStrategy ts = new NoopThreadingStrategy();
        // The shared set both servers build, plus every server's own additions: the
        // union is what the catalog describes, and what the parity tests scan.
        return CoreServices.build(provider, ts).plus(
            new HeadlessManagementService(new HeadlessProgramProvider(), new GhidraServerManager()),
            // PluginTool is only used at runtime; the scanner reflects on signatures.
            new DebuggerService(provider, ts, null),
            new PromptPolicyService());
    }

    /** Convenience: build a {@link StubProgramProvider}. */
    public static ProgramProvider stubProvider() {
        return new StubProgramProvider();
    }
}
