package com.xebyte.core;

import ghidra.app.services.DebuggerLogicalBreakpointService;
import ghidra.app.services.DebuggerStaticMappingService;
import ghidra.app.services.DebuggerTargetService;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.app.services.TraceRmiLauncherService;
import ghidra.debug.api.ValStr;
import ghidra.debug.api.target.ActionName;
import ghidra.debug.api.target.Target;
import ghidra.debug.api.tracermi.LaunchParameter;
import ghidra.debug.api.tracermi.TraceRmiLaunchOffer;
import ghidra.debug.api.tracermi.TraceRmiLaunchOffer.LaunchConfigurator;
import ghidra.debug.api.tracermi.TraceRmiLaunchOffer.LaunchResult;
import ghidra.debug.api.tracermi.TraceRmiLaunchOffer.RelPrompt;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.framework.model.Project;
import ghidra.framework.model.ToolManager;
import ghidra.framework.model.ToolTemplate;
import ghidra.framework.model.Workspace;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeImpl;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.Trace;
import ghidra.trace.model.TraceExecutionState;
import ghidra.trace.model.breakpoint.TraceBreakpointKind;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.model.memory.TraceMemoryManager;
import ghidra.trace.model.memory.TraceMemorySpace;
import ghidra.trace.model.modules.TraceModule;
import ghidra.trace.model.stack.TraceStack;
import ghidra.trace.model.stack.TraceStackFrame;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TaskMonitor;

import javax.swing.SwingUtilities;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

/**
 * MCP endpoints for driving Ghidra's built-in debugger.
 *
 * <p>The GhidraMCPPlugin runs in the FrontEnd tool, which does NOT have
 * debugger services. This service finds a running CodeBrowser/Debugger tool
 * via {@link ToolManager#getRunningTools()} — the same pattern used by
 * {@link FrontEndProgramProvider} for ProgramManager access.</p>
 *
 * <p>The user must have a CodeBrowser open with the Debugger view active
 * (Window → Debugger). The AI then uses these endpoints to control the
 * debug session while the user sees everything in Ghidra's synchronized UI.</p>
 */
@McpToolGroup(value = "debugger",
        description = "Live debugging: attach, breakpoints, step, registers, memory. " +
                "Requires a CodeBrowser with Debugger view open.")
public class DebuggerService {

    private static final long ACTION_TIMEOUT_MS = 15_000;
    private static final int MAX_MEMORY_READ = 4096;
    // A step action's Future completes once the RMI command is accepted, but the
    // trace's own execution-state model catches up to STOPPED asynchronously --
    // a few ms later. An immediate next step called in that window races
    // Ghidra's own state check and fails with DebuggeeRunningException even
    // though the debuggee is, from the caller's perspective, already stopped.
    // Confirmed live 2026-07-26: back-to-back step_into then step_over.
    private static final long STEP_SETTLE_TIMEOUT_MS = 3_000;
    private static final long STEP_SETTLE_POLL_MS = 25;
    // DebuggerStaticMappingService's automatic static<->dynamic module mapping
    // settles independently of, and slower than, the module list / thread /
    // PC settling above. Confirmed live 2026-07-26: a static_to_dynamic call
    // made immediately after launch (even once RIP has already settled into
    // the launched image, per STEP_SETTLE above) can 404 with "No mapping
    // found", while the identical call against the identical address
    // succeeds several seconds later with no other change -- reproduced
    // across multiple fresh single-trace sessions, so this is a genuine
    // settle window, not trace/program bookkeeping left over from a prior
    // launch. Bounded retry is safe here (unlike the step-action retry
    // above): this is a pure read/lookup with no execution-state side
    // effects to risk.
    private static final long MAPPING_SETTLE_TIMEOUT_MS = 10_000;
    private static final long MAPPING_SETTLE_POLL_MS = 250;
    // DebuggerLogicalBreakpointService correlates raw trace breakpoints
    // (placed synchronously by target.placeBreakpoint(), used by
    // setBreakpoint()) into "logical" breakpoints asynchronously; removeBreakpoint()
    // looks addresses up through that service, not the raw trace breakpoint
    // list. Confirmed live 2026-07-26: a remove_breakpoint call for an
    // address whose set_breakpoint call just returned success can 404 with
    // "No breakpoint at ..." because the logical-breakpoint index hasn't
    // caught up yet. Same settle-and-retry shape as MAPPING_SETTLE above.
    private static final long BREAKPOINT_INDEX_SETTLE_TIMEOUT_MS = 5_000;
    private static final long BREAKPOINT_INDEX_SETTLE_POLL_MS = 200;

    private final ProgramProvider programProvider;
    private final PluginTool frontEndTool;

    /** Cached reference to the tool that has debugger services. */
    private volatile PluginTool cachedDebuggerTool;

    public DebuggerService(ProgramProvider programProvider,
                           ThreadingStrategy threadingStrategy,
                           PluginTool frontEndTool) {
        this.programProvider = programProvider;
        this.frontEndTool = frontEndTool;
    }

    // ========================================================================
    // Tool discovery
    // ========================================================================

    /**
     * Find a running tool that has DebuggerTraceManagerService loaded.
     * Mirrors FrontEndProgramProvider's ToolManager pattern.
     */
    private PluginTool findDebuggerTool() {
        Project project = frontEndTool.getProject();
        if (project == null) return null;
        ToolManager tm = project.getToolManager();
        if (tm == null) return null;
        try {
            for (PluginTool tool : tm.getRunningTools()) {
                if (tool.getService(DebuggerTraceManagerService.class) != null) {
                    return tool;
                }
            }
        } catch (Exception e) {
            Msg.warn(this, "Error scanning for debugger tool: " + e.getMessage());
        }
        return null;
    }

    private PluginTool startDebuggerTool() {
        Project project = frontEndTool.getProject();
        if (project == null) return null;
        ToolManager tm = project.getToolManager();
        if (tm == null) return null;
        try {
            Workspace workspace = tm.getActiveWorkspace();
            if (workspace == null) return null;
            for (String templateName : List.of("Debugger", "CodeBrowser")) {
                ToolTemplate template = project.getLocalToolChest().getToolTemplate(templateName);
                if (template == null) {
                    continue;
                }
                AtomicReference<PluginTool> launched = new AtomicReference<>();
                AtomicReference<Exception> launchError = new AtomicReference<>();
                Runnable launcher = () -> {
                    try {
                        launched.set(workspace.runTool(template));
                    } catch (Exception e) {
                        launchError.set(e);
                    }
                };
                if (SwingUtilities.isEventDispatchThread()) {
                    launcher.run();
                } else {
                    SwingUtilities.invokeAndWait(launcher);
                }
                if (launchError.get() != null) {
                    throw launchError.get();
                }
                PluginTool tool = launched.get();
                if (tool == null) {
                    continue;
                }
                for (int i = 0; i < 20; i++) {
                    if (tool.getService(DebuggerTraceManagerService.class) != null) {
                        return tool;
                    }
                    Thread.sleep(250);
                }
            }
        } catch (Exception e) {
            Msg.warn(this, "Failed to launch debugger tool: " + e.getMessage());
        }
        return null;
    }

    private PluginTool getDebuggerTool() {
        PluginTool cached = cachedDebuggerTool;
        if (cached != null) {
            try {
                if (cached.getService(DebuggerTraceManagerService.class) != null) {
                    return cached;
                }
            } catch (Exception e) {
                // Tool gone, re-scan
            }
            cachedDebuggerTool = null;
        }
        PluginTool found = findDebuggerTool();
        cachedDebuggerTool = found;
        return found;
    }

    private PluginTool getOrStartDebuggerTool(int timeoutSeconds) throws TimeoutException {
        PluginTool tool = getDebuggerTool();
        if (tool != null) {
            return tool;
        }
        CompletableFuture<PluginTool> future = CompletableFuture.supplyAsync(this::startDebuggerTool);
        try {
            tool = future.get(Math.max(1, timeoutSeconds), TimeUnit.SECONDS);
        } catch (TimeoutException e) {
            future.cancel(true);
            throw e;
        } catch (Exception e) {
            Msg.warn(this, "Failed to auto-start debugger tool: " + e.getMessage());
            return null;
        }
        cachedDebuggerTool = tool;
        return tool;
    }

    private <T> T getService(Class<T> serviceClass) {
        PluginTool tool = getDebuggerTool();
        if (tool == null) return null;
        return tool.getService(serviceClass);
    }

    private Response noDebugger() {
        return Response.err("Debugger not active and GhidraMCP could not auto-start a " +
                "Debugger tool. Open the Debugger tool or enable Window > Debugger in CodeBrowser, " +
                "then attach to your target process.");
    }

    private Response noTrace() {
        return Response.err("No active debug trace. Attach to a process first via the " +
                "Debugger's connection panel or debugger_launch.");
    }

    private Response noTarget() {
        return Response.err("No live target connection. The trace exists but the target " +
                "is not connected. Re-attach to the process.");
    }

    // ========================================================================
    // Helper: get current trace context
    // ========================================================================

    private record TraceContext(
            PluginTool tool,
            DebuggerTraceManagerService traceMgr,
            Trace trace,
            DebuggerCoordinates coords,
            TracePlatform platform,
            TraceThread thread,
            long snap
    ) {}

    private TraceContext getContext() {
        PluginTool tool = getDebuggerTool();
        if (tool == null) return null;
        DebuggerTraceManagerService traceMgr =
                tool.getService(DebuggerTraceManagerService.class);
        if (traceMgr == null) return null;
        Trace trace = traceMgr.getCurrentTrace();
        if (trace == null) return null;
        DebuggerCoordinates coords = traceMgr.getCurrent();
        TracePlatform platform = coords.getPlatform();
        if (platform == null) {
            platform = trace.getPlatformManager().getHostPlatform();
        }
        return new TraceContext(tool, traceMgr, trace, coords,
                platform, coords.getThread(), coords.getSnap());
    }

    private Target getTarget(TraceContext ctx) {
        DebuggerTargetService targetSvc =
                ctx.tool.getService(DebuggerTargetService.class);
        if (targetSvc == null) return null;
        return targetSvc.getTarget(ctx.trace);
    }

    private Address parseAddress(Trace trace, String addrStr) {
        if (addrStr == null || addrStr.isEmpty()) return null;
        String normalized = addrStr.startsWith("0x")
                ? addrStr.substring(2) : addrStr;
        AddressFactory factory = trace.getBaseAddressFactory();
        return factory.getAddress(normalized);
    }

    // ========================================================================
    // Session management
    // ========================================================================

    private TraceRmiLaunchOffer selectLaunchOffer(Collection<TraceRmiLaunchOffer> offers,
                                                  String preferredOffer) {
        List<TraceRmiLaunchOffer> candidates = offers.stream()
                .filter(TraceRmiLaunchOffer::supportsImage)
                .toList();
        if (candidates.isEmpty()) {
            candidates = List.copyOf(offers);
        }
        if (preferredOffer != null && !preferredOffer.isBlank()) {
            String needle = preferredOffer.trim().toLowerCase(Locale.ROOT);
            for (TraceRmiLaunchOffer offer : candidates) {
                if (offer.getTitle().equalsIgnoreCase(preferredOffer) ||
                        offer.getConfigName().equalsIgnoreCase(preferredOffer)) {
                    return offer;
                }
            }
            for (TraceRmiLaunchOffer offer : candidates) {
                if (offer.getTitle().toLowerCase(Locale.ROOT).contains(needle) ||
                        offer.getConfigName().toLowerCase(Locale.ROOT).contains(needle)) {
                    return offer;
                }
            }
        }
        for (TraceRmiLaunchOffer offer : candidates) {
            if ("dbgeng".equalsIgnoreCase(offer.getTitle()) ||
                    offer.getConfigName().toLowerCase(Locale.ROOT).contains("local-dbgeng")) {
                return offer;
            }
        }
        return candidates.isEmpty() ? null : candidates.get(0);
    }

    private ValStr<?> decodeLaunchValue(LaunchParameter<?> param, String value) {
        return param.decode(value);
    }

    private void setLaunchArgument(Map<String, ValStr<?>> args,
                                   Map<String, LaunchParameter<?>> parameters,
                                   String name,
                                   String value) {
        LaunchParameter<?> param = parameters.get(name);
        if (param != null) {
            args.put(name, decodeLaunchValue(param, value));
        }
    }

    private List<Map<String, Object>> describeLaunchParameters(TraceRmiLaunchOffer offer) {
        List<Map<String, Object>> result = new ArrayList<>();
        for (Map.Entry<String, LaunchParameter<?>> entry : offer.getParameters().entrySet()) {
            LaunchParameter<?> param = entry.getValue();
            Map<String, Object> info = new LinkedHashMap<>();
            info.put("name", entry.getKey());
            info.put("display", param.display());
            info.put("type", param.type().getSimpleName());
            info.put("required", param.required());
            info.put("default", param.defaultValue() != null ? param.defaultValue().str() : null);
            result.add(info);
        }
        return result;
    }

    private Map<String, Target.ActionEntry> collectTargetActions(Target target,
                                                                 ActionName actionName) {
        return target.collectActions(actionName, null,
                Target.ObjectArgumentPolicy.CURRENT_AND_RELATED);
    }

    private void invokeTargetAction(Target.ActionEntry action) throws Exception {
        if (action.requiresPrompt()) {
            throw new IllegalStateException("Action requires a Ghidra UI prompt: " +
                    action.display());
        }
        action.invokeAsync(false).get(ACTION_TIMEOUT_MS, TimeUnit.MILLISECONDS);
    }

    /**
     * Poll the current thread's execution state until it settles out of
     * RUNNING (or the timeout elapses). Call before a step action that
     * immediately follows another step/resume, to close the async window
     * described at STEP_SETTLE_TIMEOUT_MS's declaration.
     */
    private void waitForNotRunning(TraceContext ctx, Target target) throws InterruptedException {
        if (target == null || ctx.thread() == null) return;
        long deadline = System.currentTimeMillis() + STEP_SETTLE_TIMEOUT_MS;
        while (System.currentTimeMillis() < deadline) {
            TraceExecutionState state = target.getThreadExecutionState(ctx.thread());
            if (state != TraceExecutionState.RUNNING) {
                return;
            }
            Thread.sleep(STEP_SETTLE_POLL_MS);
        }
    }

    /**
     * Invoke a step-family action, retrying once after waiting out the
     * RUNNING->STOPPED settle window if Ghidra's own state check rejects the
     * first attempt with DebuggeeRunningException.
     */
    private void invokeStepAction(TraceContext ctx, Target target, Target.ActionEntry action)
            throws Exception {
        waitForNotRunning(ctx, target);
        try {
            invokeTargetAction(action);
        } catch (Exception e) {
            if (isDebuggeeRunningException(e)) {
                waitForNotRunning(ctx, target);
                invokeTargetAction(action);
            } else {
                throw e;
            }
        }
    }

    private boolean isDebuggeeRunningException(Throwable e) {
        for (Throwable cur = e; cur != null; cur = cur.getCause()) {
            if (cur.getClass().getSimpleName().equals("DebuggeeRunningException")) {
                return true;
            }
        }
        return false;
    }

    @McpTool(path = "/debugger/launch", method = "POST",
            description = "Launch an executable through Ghidra's Trace RMI debugger launcher")
    public Response launch(
            @Param(value = "executable_path", source = ParamSource.BODY,
                    description = "Absolute path to the executable to launch") String executablePath,
            @Param(value = "args", source = ParamSource.BODY, defaultValue = "",
                    description = "Command-line arguments to pass to the executable") String args,
            @Param(value = "cwd", source = ParamSource.BODY, defaultValue = "",
                    description = "Working directory hint for launchers that expose one") String cwd,
            @Param(value = "timeout_seconds", source = ParamSource.BODY, defaultValue = "60",
                    description = "Maximum seconds to wait for the debugger trace") int timeoutSeconds,
            @Param(value = "program", source = ParamSource.BODY, defaultValue = "",
                    description = "Program path/name to use for static mapping") String programName,
            @Param(value = "offer", source = ParamSource.BODY, defaultValue = "",
                    description = "Optional launcher title or config name, e.g. dbgeng") String preferredOffer,
            @Param(value = "python_executable", source = ParamSource.BODY, defaultValue = "",
                    description = "Optional Python executable for Python-backed debugger launchers") String pythonExecutable) {
        PluginTool tool;
        try {
            // Cold-start of the Debugger tool template takes longer than 20s
            // when its plugin set hasn't been instantiated yet in this process.
            // Subsequent /debugger/launch calls hit the cached tool instantly.
            tool = getOrStartDebuggerTool(60);
        } catch (TimeoutException e) {
            return Response.err("Timed out while auto-starting Ghidra's Debugger tool. " +
                    "Open the Debugger tool manually, then retry debugger_launch.");
        }
        if (tool == null) return noDebugger();

        TraceRmiLauncherService launcherSvc =
                tool.getService(TraceRmiLauncherService.class);
        if (launcherSvc == null) {
            return Response.err("Trace RMI launcher service not available. Open CodeBrowser, " +
                    "enable Window > Debugger, and make sure the debugger launcher plugins are loaded.");
        }

        try {
            ghidra.program.model.listing.Program program =
                    programProvider.resolveProgram(programName);
            Collection<TraceRmiLaunchOffer> offers = launcherSvc.getOffers(program);
            if (offers.isEmpty()) {
                return Response.err("No debugger launch offers are available for " +
                        (program != null ? program.getName() : "the current program") +
                        ". Install/enable a backend such as Ghidra's dbgeng agent and " +
                        "open the executable in CodeBrowser first.");
            }

            TraceRmiLaunchOffer offer = selectLaunchOffer(offers, preferredOffer);
            if (offer == null) {
                return Response.err("No debugger launch offer could be selected. Available offers: " +
                        offers.stream().map(TraceRmiLaunchOffer::getTitle).collect(Collectors.joining(", ")));
            }

            LaunchParameter<?> imageParam = offer.imageParameter();
            if (imageParam == null) {
                return Response.err("Selected launcher '" + offer.getTitle() +
                        "' does not expose an image/executable parameter. Available parameters: " +
                        offer.getParameters().keySet());
            }

            int waitSeconds = Math.max(1, timeoutSeconds);
            ConsoleTaskMonitor monitor = new ConsoleTaskMonitor();
            CompletableFuture<LaunchResult> future = CompletableFuture.supplyAsync(() ->
                    offer.launchProgram(monitor, new LaunchConfigurator() {
                        @Override
                        public Map<String, ValStr<?>> configureLauncher(
                                TraceRmiLaunchOffer launchOffer,
                                Map<String, ValStr<?>> launchArgs,
                                RelPrompt relPrompt) {
                            Map<String, ValStr<?>> configured = new LinkedHashMap<>(launchArgs);
                            configured.put(imageParam.name(), decodeLaunchValue(imageParam, executablePath));
                            if (args != null && !args.isBlank()) {
                                setLaunchArgument(configured, launchOffer.getParameters(), "args", args);
                                setLaunchArgument(configured, launchOffer.getParameters(), "env:OPT_TARGET_ARGS", args);
                            }
                            if (cwd != null && !cwd.isBlank()) {
                                setLaunchArgument(configured, launchOffer.getParameters(), "cwd", cwd);
                                setLaunchArgument(configured, launchOffer.getParameters(), "env:CWD", cwd);
                                setLaunchArgument(configured, launchOffer.getParameters(), "env:OPT_CWD", cwd);
                                setLaunchArgument(configured, launchOffer.getParameters(), "env:OPT_TARGET_DIR", cwd);
                            }
                            if (pythonExecutable != null && !pythonExecutable.isBlank()) {
                                setLaunchArgument(configured, launchOffer.getParameters(),
                                        "env:OPT_PYTHON_EXE", pythonExecutable);
                            }
                            return configured;
                        }
                    }));

            LaunchResult result;
            try {
                result = future.get(waitSeconds, TimeUnit.SECONDS);
            } catch (TimeoutException e) {
                monitor.cancel();
                return Response.err("Debugger launch timed out after " + waitSeconds +
                        "s waiting for a Trace RMI connection. Check the launcher terminal, " +
                        "Python debugger dependencies, and dbgeng/WinDbg installation.");
            }

            if (result.exception() != null) {
                return Response.err("Debugger launch failed using '" + offer.getTitle() + "': " +
                        result.exception().getMessage() +
                        ". Check Ghidra's launcher terminal and debugger backend setup.");
            }
            if (result.trace() == null) {
                return Response.err("Debugger launch did not produce an active trace using '" +
                        offer.getTitle() + "'. Check Ghidra's launcher terminal for backend errors.");
            }

            // launchProgram() opens the trace but does not make it the trace
            // manager's "current" trace when driven programmatically (that
            // normally happens via the launch UI's own action handling).
            // Every other debugger_* tool reads getCurrentTrace(), so without
            // this, they'd all report "no active debug trace" despite a live
            // session existing.
            DebuggerTraceManagerService traceMgr =
                    tool.getService(DebuggerTraceManagerService.class);
            if (traceMgr != null) {
                Trace launchedTrace = result.trace();
                Runnable activator = () -> traceMgr.activateTrace(launchedTrace);
                if (SwingUtilities.isEventDispatchThread()) {
                    activator.run();
                } else {
                    SwingUtilities.invokeAndWait(activator);
                }
            }

            // The target's module list, current-thread selection, and initial
            // stack all arrive over Trace RMI asynchronously after
            // launchProgram() returns -- confirmed live: querying immediately
            // gives an empty module list, a null current thread, and "no
            // stack data", but the same calls succeed moments later with no
            // other change. Poll briefly so a successful launch response
            // actually means "ready to query", not just "trace object
            // exists".
            //
            // "hasModules" alone is not enough: dbgeng's WOW64 initial-
            // breakpoint stop lands in ntdll (a system DLL whose load address
            // is randomized once per Windows boot, not per launch -- observed
            // identical across separate launches in the same session) before
            // the launcher's own auto-continue-to-entry has run. Confirmed
            // live 2026-07-26: querying right after "module present" can
            // still see RIP sitting in ntdll rather than the launched image,
            // which fails every dynamic-address tool downstream (
            // dynamic_to_static "not in any loaded module", set_breakpoint/
            // read_memory operating on a meaningless address). The real
            // settle condition is "current PC is inside the launched image's
            // own range", not just "the image's module object exists" --
            // wait for that, with a longer budget than the plain module/
            // thread check since the auto-continue is itself async. This is
            // deliberately passive (never issues our own resume): the
            // launcher may or may not set a breakpoint at entry, and
            // resuming blind risks running the target to completion
            // uncontrolled -- exactly the taskkill-proof zombie failure mode
            // this project has hit before (see feedback_graceful_ghidra_
            // lifecycle memory). If the image's own entry is never reached
            // within the budget, fall through anyway with whatever settled
            // (module+thread present) -- best effort, not a hard guarantee.
            String exeBaseName = executablePath.replace('/', '\\');
            int lastSep = exeBaseName.lastIndexOf('\\');
            if (lastSep >= 0) {
                exeBaseName = exeBaseName.substring(lastSep + 1);
            }
            String exeBaseNameLower = exeBaseName.toLowerCase(Locale.ROOT);

            Trace launchedTrace = result.trace();
            for (int i = 0; i < 75; i++) {
                long snap = traceMgr != null ? traceMgr.getCurrent().getSnap() : 0;
                TraceModule targetModule = launchedTrace.getModuleManager().getAllModules().stream()
                        .filter(m -> m.getName(snap).toLowerCase(Locale.ROOT).endsWith(exeBaseNameLower))
                        .findFirst().orElse(null);
                TraceThread curThread = traceMgr != null ? traceMgr.getCurrentThread() : null;
                boolean hasThread = curThread != null;
                boolean pcSettled = false;
                if (targetModule != null && curThread != null) {
                    AddressRange targetRange = targetModule.getRange(snap);
                    TraceStack stack = launchedTrace.getStackManager()
                            .getLatestStack(curThread, snap);
                    Address pc = (stack != null && stack.getDepth(snap) > 0)
                            ? stack.getFrame(snap, 0, false).getProgramCounter(snap) : null;
                    pcSettled = targetRange != null && pc != null && targetRange.contains(pc);
                }
                if (pcSettled || (i >= 25 && targetModule != null && hasThread)) {
                    break;
                }
                Thread.sleep(200);
            }

            // static_to_dynamic / dynamic_to_static depend on
            // DebuggerStaticMappingService already having a static<->dynamic
            // mapping for this trace. The GUI normally builds one lazily
            // (auto-map-by-module-identity, or the user's own "Map
            // Identically" action) on some schedule of its own -- confirmed
            // live 2026-07-26: querying static_to_dynamic even 10s after a
            // programmatic launch can still 404 with "No mapping found",
            // with no further progress no matter how long you wait. Since we
            // already know exactly which program this trace corresponds to
            // (the same `program` used to select launch offers above),
            // establish the identity mapping ourselves rather than wait on
            // whatever triggers the GUI's own version of this. Best-effort:
            // a mapping conflict (e.g. a prior mapping already exists from an
            // earlier launch of the same program) is not fatal to the launch.
            if (program != null) {
                DebuggerStaticMappingService launchMappingSvc =
                        tool.getService(DebuggerStaticMappingService.class);
                if (launchMappingSvc != null) {
                    try {
                        launchMappingSvc.addIdentityMapping(
                                launchedTrace, program, Lifespan.nowOn(0), true);
                    } catch (Exception e) {
                        Msg.warn(this, "Could not establish static<->dynamic identity mapping for "
                                + program.getName() + ": " + e.getMessage());
                    }
                }
            }

            Map<String, Object> response = new LinkedHashMap<>();
            response.put("status", "launched");
            response.put("offer_title", offer.getTitle());
            response.put("offer_config_name", offer.getConfigName());
            response.put("trace_name", result.trace().getName());
            response.put("executable_path", executablePath);
            response.put("args", args);
            response.put("program", program != null ? program.getName() : null);
            return Response.ok(response);
        } catch (Exception e) {
            return Response.err("Debugger launch failed: " + e.getMessage());
        }
    }

    @McpTool(path = "/debugger/status",
            description = "Get debugger status: active trace, thread, execution state, module count")
    public Response getStatus() {
        PluginTool tool = getDebuggerTool();
        if (tool == null) return noDebugger();

        DebuggerTraceManagerService traceMgr =
                tool.getService(DebuggerTraceManagerService.class);
        if (traceMgr == null) return noDebugger();

        Map<String, Object> status = new LinkedHashMap<>();
        status.put("debugger_active", true);

        Trace trace = traceMgr.getCurrentTrace();
        if (trace == null) {
            status.put("trace_active", false);
            status.put("open_traces", traceMgr.getOpenTraces().size());
            return Response.ok(status);
        }

        status.put("trace_active", true);
        status.put("trace_name", trace.getName());
        status.put("open_traces", traceMgr.getOpenTraces().size());

        DebuggerCoordinates coords = traceMgr.getCurrent();
        status.put("snap", coords.getSnap());

        TraceThread thread = coords.getThread();
        if (thread != null) {
            status.put("thread", thread.getName(coords.getSnap()));
        }

        // Check target/execution state
        DebuggerTargetService targetSvc =
                tool.getService(DebuggerTargetService.class);
        if (targetSvc != null) {
            Target target = targetSvc.getTarget(trace);
            if (target != null && target.isValid()) {
                status.put("target_connected", true);
                status.put("target_description", target.describe());
                if (thread != null) {
                    TraceExecutionState execState =
                            target.getThreadExecutionState(thread);
                    status.put("execution_state",
                            execState != null ? execState.name() : "UNKNOWN");
                }
            } else {
                status.put("target_connected", false);
            }
        }

        // Module count
        try {
            Collection<? extends TraceModule> modules =
                    trace.getModuleManager().getAllModules();
            status.put("module_count", modules.size());
        } catch (Exception e) {
            status.put("module_count", 0);
        }

        return Response.ok(status);
    }

    @McpTool(path = "/debugger/traces",
            description = "List all open debug traces")
    public Response listTraces() {
        PluginTool tool = getDebuggerTool();
        if (tool == null) return noDebugger();

        DebuggerTraceManagerService traceMgr =
                tool.getService(DebuggerTraceManagerService.class);
        if (traceMgr == null) return noDebugger();

        Trace current = traceMgr.getCurrentTrace();
        List<Map<String, Object>> traces = new ArrayList<>();
        for (Trace t : traceMgr.getOpenTraces()) {
            Map<String, Object> info = new LinkedHashMap<>();
            info.put("name", t.getName());
            info.put("current", t == current);
            try {
                info.put("module_count",
                        t.getModuleManager().getAllModules().size());
                info.put("thread_count",
                        t.getThreadManager().getAllThreads().size());
            } catch (Exception e) {
                // Non-critical
            }
            traces.add(info);
        }
        return Response.ok(traces);
    }

    // ========================================================================
    // Execution control
    // ========================================================================

    @McpTool(path = "/debugger/resume", method = "POST",
            description = "Resume execution of the debugged process")
    public Response resume() {
        TraceContext ctx = getContext();
        if (ctx == null) return noTrace();
        Target target = getTarget(ctx);
        if (target == null) return noTarget();

        try {
            Map<String, Target.ActionEntry> actions =
                    collectTargetActions(target, ActionName.RESUME);
            if (actions.isEmpty()) {
                return Response.err("Resume action not available in current state");
            }
            // Execute the first available resume action
            Target.ActionEntry action = actions.values().iterator().next();
            invokeTargetAction(action);
            return Response.ok(Map.of("status", "resumed"));
        } catch (Exception e) {
            return Response.err("Resume failed: " + e.getMessage());
        }
    }

    @McpTool(path = "/debugger/interrupt", method = "POST",
            description = "Interrupt (break into) the running target")
    public Response interrupt() {
        TraceContext ctx = getContext();
        if (ctx == null) return noTrace();
        Target target = getTarget(ctx);
        if (target == null) return noTarget();

        try {
            Map<String, Target.ActionEntry> actions =
                    collectTargetActions(target, ActionName.INTERRUPT);
            if (actions.isEmpty()) {
                return Response.err("Interrupt action not available in current state");
            }
            Target.ActionEntry action = actions.values().iterator().next();
            invokeTargetAction(action);
            return Response.ok(Map.of("status", "interrupted"));
        } catch (Exception e) {
            return Response.err("Interrupt failed: " + e.getMessage());
        }
    }

    @McpTool(path = "/debugger/step_into", method = "POST",
            description = "Single-step into the next instruction (follows calls)")
    public Response stepInto() {
        TraceContext ctx = getContext();
        if (ctx == null) return noTrace();
        Target target = getTarget(ctx);
        if (target == null) return noTarget();

        try {
            Map<String, Target.ActionEntry> actions =
                    collectTargetActions(target, ActionName.STEP_INTO);
            if (actions.isEmpty()) {
                return Response.err("Step into not available in current state");
            }
            Target.ActionEntry action = actions.values().iterator().next();
            invokeStepAction(ctx, target, action);
            return Response.ok(Map.of("status", "stepped"));
        } catch (Exception e) {
            return Response.err("Step into failed: " + e.getMessage());
        }
    }

    @McpTool(path = "/debugger/step_over", method = "POST",
            description = "Step over the next instruction (does not follow calls)")
    public Response stepOver() {
        TraceContext ctx = getContext();
        if (ctx == null) return noTrace();
        Target target = getTarget(ctx);
        if (target == null) return noTarget();

        try {
            Map<String, Target.ActionEntry> actions =
                    collectTargetActions(target, ActionName.STEP_OVER);
            if (actions.isEmpty()) {
                return Response.err("Step over not available in current state");
            }
            Target.ActionEntry action = actions.values().iterator().next();
            invokeStepAction(ctx, target, action);
            return Response.ok(Map.of("status", "stepped"));
        } catch (Exception e) {
            return Response.err("Step over failed: " + e.getMessage());
        }
    }

    @McpTool(path = "/debugger/step_out", method = "POST",
            description = "Step out of the current function (run to return)")
    public Response stepOut() {
        TraceContext ctx = getContext();
        if (ctx == null) return noTrace();
        Target target = getTarget(ctx);
        if (target == null) return noTarget();

        try {
            Map<String, Target.ActionEntry> actions =
                    collectTargetActions(target, ActionName.STEP_OUT);
            if (actions.isEmpty()) {
                return Response.err("Step out not available in current state");
            }
            Target.ActionEntry action = actions.values().iterator().next();
            invokeStepAction(ctx, target, action);
            return Response.ok(Map.of("status", "stepped_out"));
        } catch (Exception e) {
            return Response.err("Step out failed: " + e.getMessage());
        }
    }

    // ========================================================================
    // Breakpoints
    // ========================================================================

    @McpTool(path = "/debugger/set_breakpoint", method = "POST",
            description = "Set a software execution breakpoint at an address in the trace")
    public Response setBreakpoint(
            @Param(value = "address", paramType = "address",
                    description = "Address to break at (in trace address space)") String addressStr) {
        TraceContext ctx = getContext();
        if (ctx == null) return noTrace();
        Target target = getTarget(ctx);
        if (target == null) return noTarget();

        Address addr = parseAddress(ctx.trace, addressStr);
        if (addr == null) {
            return Response.err("Invalid address: " + addressStr);
        }

        try {
            AddressRange range = new AddressRangeImpl(addr, 1);
            target.placeBreakpoint(range,
                    Set.of(TraceBreakpointKind.SW_EXECUTE),
                    "MCP breakpoint", "");
            return Response.ok(Map.of(
                    "address", addr.toString(),
                    "type", "SW_EXECUTE",
                    "status", "set"));
        } catch (Exception e) {
            return Response.err("Failed to set breakpoint: " + e.getMessage());
        }
    }

    @McpTool(path = "/debugger/remove_breakpoint", method = "POST",
            description = "Remove a breakpoint at an address")
    public Response removeBreakpoint(
            @Param(value = "address", paramType = "address",
                    description = "Address of breakpoint to remove") String addressStr) {
        TraceContext ctx = getContext();
        if (ctx == null) return noTrace();

        DebuggerLogicalBreakpointService bpSvc =
                ctx.tool.getService(DebuggerLogicalBreakpointService.class);
        if (bpSvc == null) {
            return Response.err("Breakpoint service not available");
        }

        Address addr = parseAddress(ctx.trace, addressStr);
        if (addr == null) {
            return Response.err("Invalid address: " + addressStr);
        }

        try {
            Set<ghidra.debug.api.breakpoint.LogicalBreakpoint> atAddr = Set.of();
            long deadline = System.currentTimeMillis() + BREAKPOINT_INDEX_SETTLE_TIMEOUT_MS;
            while (true) {
                NavigableMap<Address, Set<ghidra.debug.api.breakpoint.LogicalBreakpoint>> bpMap =
                        bpSvc.getBreakpoints(ctx.trace);
                atAddr = bpMap.getOrDefault(addr, Set.of());
                if (!atAddr.isEmpty() || System.currentTimeMillis() >= deadline) {
                    break;
                }
                Thread.sleep(BREAKPOINT_INDEX_SETTLE_POLL_MS);
            }
            if (atAddr.isEmpty()) {
                return Response.err("No breakpoint at " + addr);
            }
            CompletableFuture<Void> future =
                    bpSvc.deleteAll(atAddr, ctx.trace);
            future.get(ACTION_TIMEOUT_MS, TimeUnit.MILLISECONDS);
            return Response.ok(Map.of("address", addr.toString(), "status", "removed"));
        } catch (Exception e) {
            return Response.err("Failed to remove breakpoint: " + e.getMessage());
        }
    }

    @McpTool(path = "/debugger/list_breakpoints",
            description = "List all breakpoints in the current trace")
    public Response listBreakpoints() {
        TraceContext ctx = getContext();
        if (ctx == null) return noTrace();

        DebuggerLogicalBreakpointService bpSvc =
                ctx.tool.getService(DebuggerLogicalBreakpointService.class);
        if (bpSvc == null) {
            return Response.err("Breakpoint service not available");
        }

        try {
            List<Map<String, Object>> result = new ArrayList<>();
            NavigableMap<Address, Set<ghidra.debug.api.breakpoint.LogicalBreakpoint>> bpMap =
                    bpSvc.getBreakpoints(ctx.trace);
            for (Map.Entry<Address, Set<ghidra.debug.api.breakpoint.LogicalBreakpoint>> entry :
                    bpMap.entrySet()) {
                for (ghidra.debug.api.breakpoint.LogicalBreakpoint bp : entry.getValue()) {
                    Map<String, Object> bpInfo = new LinkedHashMap<>();
                    bpInfo.put("address", entry.getKey().toString());
                    bpInfo.put("name", bp.getName());
                    bpInfo.put("kinds", bp.getKinds().stream()
                            .map(Enum::name).collect(Collectors.toList()));
                    bpInfo.put("state", bp.computeState().name());
                    result.add(bpInfo);
                }
            }
            return Response.ok(result);
        } catch (Exception e) {
            return Response.err("Failed to list breakpoints: " + e.getMessage());
        }
    }

    // ========================================================================
    // State inspection
    // ========================================================================

    @McpTool(path = "/debugger/registers",
            description = "Read CPU registers from the current debug trace snapshot. " +
                    "Shows general-purpose registers (EAX-EDI, EIP, ESP, EFLAGS for x86)")
    public Response getRegisters() {
        TraceContext ctx = getContext();
        if (ctx == null) return noTrace();

        if (ctx.thread == null) {
            return Response.err("No active thread in trace");
        }

        try {
            Language lang = ctx.platform.getLanguage();
            TraceMemoryManager memMgr = ctx.trace.getMemoryManager();
            TraceMemorySpace regSpace =
                    memMgr.getMemoryRegisterSpace(ctx.thread, false);

            if (regSpace == null) {
                // Try to force a register read from target
                Target target = getTarget(ctx);
                if (target != null) {
                    Set<Register> baseRegs = new LinkedHashSet<>();
                    for (Register r : lang.getRegisters()) {
                        if (r.isBaseRegister() && !r.isHidden()) {
                            baseRegs.add(r);
                        }
                    }
                    target.readRegisters(ctx.platform, ctx.thread,
                            0, baseRegs);
                    regSpace = memMgr.getMemoryRegisterSpace(ctx.thread, false);
                }
                if (regSpace == null) {
                    return Response.err("Register space not available for current thread");
                }
            }

            Map<String, String> regs = new LinkedHashMap<>();
            for (Register reg : lang.getRegisters()) {
                if (!reg.isBaseRegister() || reg.isHidden()) continue;
                // Focus on useful registers, skip huge vector registers
                if (reg.getBitLength() > 64) continue;
                try {
                    RegisterValue val = regSpace.getValue(ctx.snap, reg);
                    if (val != null && val.hasValue()) {
                        BigInteger v = val.getUnsignedValue();
                        String hex = reg.getBitLength() <= 32
                                ? String.format("0x%08X", v.longValue())
                                : String.format("0x%016X", v.longValue());
                        regs.put(reg.getName(), hex);
                    }
                } catch (Exception e) {
                    // Skip unreadable registers
                }
            }
            return Response.ok(regs);
        } catch (Exception e) {
            return Response.err("Failed to read registers: " + e.getMessage());
        }
    }

    @McpTool(path = "/debugger/read_memory",
            description = "Read memory from the debugged process. Returns hex dump and DWORD interpretation.")
    public Response readMemory(
            @Param(value = "address", paramType = "address",
                    description = "Start address to read from") String addressStr,
            @Param(value = "size", defaultValue = "64",
                    description = "Number of bytes to read (max 4096)") int size) {
        TraceContext ctx = getContext();
        if (ctx == null) return noTrace();

        Address addr = parseAddress(ctx.trace, addressStr);
        if (addr == null) {
            return Response.err("Invalid address: " + addressStr);
        }

        int readSize = Math.min(size, MAX_MEMORY_READ);

        try {
            // Try to read from the trace first (cached data)
            TraceMemoryManager memMgr = ctx.trace.getMemoryManager();
            ByteBuffer buf = ByteBuffer.allocate(readSize);
            int bytesRead = memMgr.getBytes(ctx.snap, addr, buf);

            if (bytesRead == 0) {
                // Try forcing a read from the live target
                Target target = getTarget(ctx);
                if (target != null) {
                    AddressSet addrSet = new AddressSet(addr, addr.add(readSize - 1));
                    target.readMemory(addrSet, new ConsoleTaskMonitor());
                    buf.clear();
                    bytesRead = memMgr.getBytes(ctx.snap, addr, buf);
                }
            }

            byte[] data = new byte[bytesRead];
            buf.flip();
            buf.get(data);

            // Format as hex dump
            StringBuilder hexStr = new StringBuilder();
            for (byte b : data) hexStr.append(String.format("%02x", b & 0xFF));

            // Format as DWORDs (little-endian)
            List<String> dwords = new ArrayList<>();
            for (int i = 0; i + 3 < data.length; i += 4) {
                long val = (data[i] & 0xFFL) | ((data[i + 1] & 0xFFL) << 8)
                        | ((data[i + 2] & 0xFFL) << 16) | ((data[i + 3] & 0xFFL) << 24);
                dwords.add(String.format("0x%08X", val));
            }

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("address", addr.toString());
            result.put("size", bytesRead);
            result.put("hex", hexStr.toString());
            result.put("dwords", dwords);
            return Response.ok(result);
        } catch (Exception e) {
            return Response.err("Failed to read memory: " + e.getMessage());
        }
    }

    @McpTool(path = "/debugger/stack_trace",
            description = "Get the call stack backtrace for the current thread")
    public Response getStackTrace(
            @Param(value = "depth", defaultValue = "20",
                    description = "Maximum stack frames to return") int depth) {
        TraceContext ctx = getContext();
        if (ctx == null) return noTrace();

        if (ctx.thread == null) {
            return Response.err("No active thread");
        }

        try {
            TraceStack stack = ctx.trace.getStackManager()
                    .getLatestStack(ctx.thread, ctx.snap);

            if (stack == null) {
                return Response.err("No stack data available. The target may need to " +
                        "be interrupted first.");
            }

            List<Map<String, Object>> frames = new ArrayList<>();
            int frameCount = stack.getDepth(ctx.snap);
            for (int i = 0; i < Math.min(frameCount, depth); i++) {
                TraceStackFrame frame = stack.getFrame(ctx.snap, i, false);
                if (frame == null) continue;

                Map<String, Object> info = new LinkedHashMap<>();
                info.put("level", i);
                Address pc = frame.getProgramCounter(ctx.snap);
                if (pc != null) {
                    info.put("address", pc.toString());
                    // Symbol resolution is best-effort via module+offset
                    try {
                        for (TraceModule mod : ctx.trace.getModuleManager().getAllModules()) {
                            AddressRange modRange = mod.getRange(ctx.snap);
                            if (modRange != null && modRange.contains(pc)) {
                                long offset = pc.subtract(modRange.getMinAddress());
                                info.put("symbol", mod.getName(ctx.snap)
                                        + "+0x" + Long.toHexString(offset));
                                break;
                            }
                        }
                    } catch (Exception e) {
                        // Skip
                    }
                }
                frames.add(info);
            }
            return Response.ok(frames);
        } catch (Exception e) {
            return Response.err("Failed to get stack trace: " + e.getMessage());
        }
    }

    @McpTool(path = "/debugger/modules",
            description = "List modules (DLLs/EXEs) loaded in the debugged process")
    public Response listModules() {
        TraceContext ctx = getContext();
        if (ctx == null) return noTrace();

        try {
            Collection<? extends TraceModule> modules =
                    ctx.trace.getModuleManager().getAllModules();
            long snap = ctx.snap;
            List<Map<String, Object>> result = new ArrayList<>();
            for (TraceModule mod : modules) {
                Map<String, Object> info = new LinkedHashMap<>();
                info.put("name", mod.getName(snap));
                Address base = mod.getBase(snap);
                if (base != null) {
                    info.put("base", base.toString());
                }
                try {
                    info.put("path", mod.getPath());
                } catch (Exception e) {
                    // Path may not be available
                }
                AddressRange range = mod.getRange(snap);
                if (range != null) {
                    info.put("size", String.format("0x%X", range.getLength()));
                }
                result.add(info);
            }
            return Response.ok(result);
        } catch (Exception e) {
            return Response.err("Failed to list modules: " + e.getMessage());
        }
    }

    // ========================================================================
    // Address translation
    // ========================================================================

    @McpTool(path = "/debugger/static_to_dynamic",
            description = "Translate a static Ghidra program address to a runtime " +
                    "dynamic address in the current trace")
    public Response staticToDynamic(
            @Param(value = "address", paramType = "address",
                    description = "Static address from a Ghidra program") String addressStr,
            @Param(value = "program", defaultValue = "",
                    description = "Program name for context") String programName) {
        TraceContext ctx = getContext();
        if (ctx == null) return noTrace();

        DebuggerStaticMappingService mappingSvc =
                ctx.tool.getService(DebuggerStaticMappingService.class);
        if (mappingSvc == null) {
            return Response.err("Static mapping service not available");
        }

        try {
            ghidra.program.model.listing.Program program =
                    programProvider.resolveProgram(programName);
            if (program == null) {
                return Response.err("Program not found: " + programName);
            }

            Address staticAddr = program.getAddressFactory().getAddress(
                    addressStr.startsWith("0x") ? addressStr.substring(2) : addressStr);
            if (staticAddr == null) {
                return Response.err("Invalid address: " + addressStr);
            }

            ghidra.program.util.ProgramLocation staticLoc =
                    new ghidra.program.util.ProgramLocation(program, staticAddr);

            ghidra.program.util.ProgramLocation dynLoc = null;
            long mappingDeadline = System.currentTimeMillis() + MAPPING_SETTLE_TIMEOUT_MS;
            while (true) {
                dynLoc = mappingSvc.getDynamicLocationFromStatic(
                        ctx.trace.getFixedProgramView(ctx.snap), staticLoc);
                if (dynLoc != null || System.currentTimeMillis() >= mappingDeadline) {
                    break;
                }
                Thread.sleep(MAPPING_SETTLE_POLL_MS);
            }

            if (dynLoc == null) {
                return Response.err("No mapping found for " + addressStr +
                        ". Ensure modules are loaded and mapped in the debugger.");
            }

            return Response.ok(Map.of(
                    "static_address", staticAddr.toString(),
                    "dynamic_address", dynLoc.getAddress().toString(),
                    "program", program.getName()));
        } catch (Exception e) {
            return Response.err("Address translation failed: " + e.getMessage());
        }
    }

    @McpTool(path = "/debugger/dynamic_to_static",
            description = "Translate a runtime dynamic address from the current trace " +
                    "back to a static Ghidra program address")
    public Response dynamicToStatic(
            @Param(value = "address", paramType = "address",
                    description = "Dynamic address from the trace") String addressStr) {
        TraceContext ctx = getContext();
        if (ctx == null) return noTrace();

        DebuggerStaticMappingService mappingSvc =
                ctx.tool.getService(DebuggerStaticMappingService.class);
        if (mappingSvc == null) {
            return Response.err("Static mapping service not available");
        }

        try {
            Address dynAddr = parseAddress(ctx.trace, addressStr);
            if (dynAddr == null) {
                return Response.err("Invalid address: " + addressStr);
            }

            // Compute static address by finding the module and using its mapping.
            // Walk loaded modules in the trace to find which contains this address,
            // then look up the corresponding program's image base.
            TraceModule containingMod = null;
            for (TraceModule mod : ctx.trace.getModuleManager().getAllModules()) {
                AddressRange range = mod.getRange(ctx.snap);
                if (range != null && range.contains(dynAddr)) {
                    containingMod = mod;
                    break;
                }
            }

            if (containingMod == null) {
                return Response.err("Dynamic address " + addressStr
                        + " not in any loaded module");
            }

            long offset = dynAddr.subtract(containingMod.getBase(ctx.snap));
            return Response.ok(Map.of(
                    "dynamic_address", dynAddr.toString(),
                    "module", containingMod.getName(ctx.snap),
                    "offset", String.format("0x%X", offset),
                    "note", "Use the module name and offset to find the " +
                            "corresponding address in the Ghidra program"));
        } catch (Exception e) {
            return Response.err("Address translation failed: " + e.getMessage());
        }
    }

    // ========================================================================
    // Launch / Attach (via Trace RMI launcher system)
    // ========================================================================

    @McpTool(path = "/debugger/launch_offers",
            description = "List available debugger launch/attach options for the current program")
    public Response listLaunchOffers(
            @Param(value = "program", defaultValue = "",
                    description = "Program to get offers for") String programName) {
        PluginTool tool = getDebuggerTool();
        if (tool == null) return noDebugger();

        TraceRmiLauncherService launcherSvc =
                tool.getService(TraceRmiLauncherService.class);
        if (launcherSvc == null) {
            return Response.err("Launcher service not available");
        }

        try {
            ghidra.program.model.listing.Program program =
                    programProvider.resolveProgram(programName);
            if (program == null) {
                return Response.err("No program available. Open a program first.");
            }

            var offers = launcherSvc.getOffers(program);
            List<Map<String, Object>> result = new ArrayList<>();
            for (var offer : offers) {
                Map<String, Object> info = new LinkedHashMap<>();
                info.put("title", offer.getTitle());
                info.put("description", offer.getDescription());
                info.put("icon", offer.getIcon() != null
                        ? offer.getIcon().toString() : null);
                info.put("config_name", offer.getConfigName());
                info.put("supports_image", offer.supportsImage());
                info.put("requires_image", offer.requiresImage());
                info.put("parameters", describeLaunchParameters(offer));
                result.add(info);
            }
            return Response.ok(result);
        } catch (Exception e) {
            return Response.err("Failed to list launch offers: " + e.getMessage());
        }
    }
}
