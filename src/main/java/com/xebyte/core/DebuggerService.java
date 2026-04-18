package com.xebyte.core;

import ghidra.app.services.DebuggerLogicalBreakpointService;
import ghidra.app.services.DebuggerStaticMappingService;
import ghidra.app.services.DebuggerTargetService;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.app.services.TraceRmiLauncherService;
import ghidra.debug.api.target.ActionName;
import ghidra.debug.api.target.Target;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.framework.model.Project;
import ghidra.framework.model.ToolManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeImpl;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
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

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
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

    private <T> T getService(Class<T> serviceClass) {
        PluginTool tool = getDebuggerTool();
        if (tool == null) return null;
        return tool.getService(serviceClass);
    }

    private Response noDebugger() {
        return Response.err("Debugger not active. Open a CodeBrowser and enable the Debugger " +
                "(Window > Debugger), then attach to your target process.");
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
                    target.collectActions(ActionName.RESUME, null, null);
            if (actions.isEmpty()) {
                return Response.err("Resume action not available in current state");
            }
            // Execute the first available resume action
            Target.ActionEntry action = actions.values().iterator().next();
            action.run(true);
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
                    target.collectActions(ActionName.INTERRUPT, null, null);
            if (actions.isEmpty()) {
                return Response.err("Interrupt action not available in current state");
            }
            Target.ActionEntry action = actions.values().iterator().next();
            action.run(true);
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
                    target.collectActions(ActionName.STEP_INTO, null, null);
            if (actions.isEmpty()) {
                return Response.err("Step into not available in current state");
            }
            Target.ActionEntry action = actions.values().iterator().next();
            action.run(true);
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
                    target.collectActions(ActionName.STEP_OVER, null, null);
            if (actions.isEmpty()) {
                return Response.err("Step over not available in current state");
            }
            Target.ActionEntry action = actions.values().iterator().next();
            action.run(true);
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
                    target.collectActions(ActionName.STEP_OUT, null, null);
            if (actions.isEmpty()) {
                return Response.err("Step out not available in current state");
            }
            Target.ActionEntry action = actions.values().iterator().next();
            action.run(true);
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
            NavigableMap<Address, Set<ghidra.debug.api.breakpoint.LogicalBreakpoint>> bpMap =
                    bpSvc.getBreakpoints(ctx.trace);
            Set<ghidra.debug.api.breakpoint.LogicalBreakpoint> atAddr =
                    bpMap.getOrDefault(addr, Set.of());
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

            ghidra.program.util.ProgramLocation dynLoc =
                    mappingSvc.getDynamicLocationFromStatic(
                            ctx.trace.getFixedProgramView(ctx.snap), staticLoc);

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
                result.add(info);
            }
            return Response.ok(result);
        } catch (Exception e) {
            return Response.err("Failed to list launch offers: " + e.getMessage());
        }
    }
}
