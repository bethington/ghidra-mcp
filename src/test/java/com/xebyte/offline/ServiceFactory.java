package com.xebyte.offline;

import com.xebyte.core.AnnotationScanner;
import com.xebyte.core.CoreServices;
import com.xebyte.core.DebuggerService;
import com.xebyte.core.DocumentationApplyService;
import com.xebyte.core.GuiToolService;
import com.xebyte.core.ManualToolDescriptors;
import com.xebyte.core.ProgramProvider;
import com.xebyte.core.ProjectLifecycleService;
import com.xebyte.core.ProjectServerSession;
import com.xebyte.core.ServerLifecycleService;
import com.xebyte.core.PromptPolicyService;
import com.xebyte.core.ThreadingStrategy;
import com.xebyte.core.VersionControlService;
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
        CoreServices core = CoreServices.build(provider, ts);
        return core.plus(
            new HeadlessManagementService(new HeadlessProgramProvider(), new GhidraServerManager()),
            // PluginTool is only used at runtime; the scanner reflects on signatures.
            new DebuggerService(provider, ts, null),
            new PromptPolicyService(),
            new VersionControlService(provider, new ProjectServerSession(provider)),
            new ServerLifecycleService(core.programScript(), () -> { }),
            new ProjectLifecycleService(new HeadlessProgramProvider()),
            // Like DebuggerService, only reflected on: a PluginTool is a runtime concern.
            new GuiToolService(null),
            new DocumentationApplyService(provider, core.function(), core.comment(), core.symbolLabel(), core.analysis(), null));
    }

    /** Convenience: build a {@link StubProgramProvider}. */
    public static ProgramProvider stubProvider() {
        return new StubProgramProvider();
    }

    /**
     * The GUI plugin's {@code buildScanner()} service set, for offline dumps of
     * {@code /mcp/schema} (see {@code DumpMcpSchemaSnapTest}).
     */
    public static AnnotationScanner buildGuiScanner() {
        ProgramProvider provider = stubProvider();
        ThreadingStrategy ts = new NoopThreadingStrategy();
        CoreServices core = CoreServices.build(provider, ts);
        AnnotationScanner scanner = new AnnotationScanner(provider, ts,
            core.plus(
                new DebuggerService(provider, ts, null),
                new PromptPolicyService(),
                new ProjectLifecycleService(new HeadlessProgramProvider()),
                new VersionControlService(provider, new ProjectServerSession(provider)),
                new ServerLifecycleService(core.programScript(), () -> { }),
                new GuiToolService(null),
                new DocumentationApplyService(provider, core.function(), core.comment(), core.symbolLabel(),
                    core.analysis(), null)));
        ManualToolDescriptors.addAll(scanner, ManualToolDescriptors.SHARED_ROUTES);
        return scanner;
    }
}
