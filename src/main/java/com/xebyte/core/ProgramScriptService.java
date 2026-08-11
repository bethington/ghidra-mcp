package com.xebyte.core;

import ghidra.app.services.ProgramManager;
import ghidra.framework.options.OptionType;
import ghidra.framework.options.Options;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.OverlayAddressSpace;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.util.IntPropertyMap;
import ghidra.program.model.util.LongPropertyMap;
import ghidra.program.model.util.ObjectPropertyMap;
import ghidra.program.model.util.PropertyMap;
import ghidra.program.model.util.PropertyMapManager;
import ghidra.program.model.util.StringPropertyMap;
import ghidra.program.model.util.VoidPropertyMap;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.util.importer.AutoImporter;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.LoadResults;
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TimeoutTaskMonitor;

import javax.swing.SwingUtilities;
import java.io.*;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Service for program management, script execution, memory, and bookmark operations.
 * Extracted from GhidraMCPPlugin as part of v4.0.0 refactor.
 */
@McpToolGroup(value = "program", description = "Program management, script execution, memory read, bookmarks, save")
public class ProgramScriptService {

    private static final int MAX_SCRIPT_TIMEOUT_SECONDS = 1800;

    private final ProgramProvider programProvider;
    private final ThreadingStrategy threadingStrategy;
    private static final String AUTO_ANALYSIS_COMPLETION_MESSAGE = "Auto-analysis completed";
    private static final Object SCRIPT_BUNDLE_HOST_LOCK = new Object();

    /**
     * Upper bound on the OSGi build/activate output echoed back in an error
     * response. Verbose compiler failures can run to many KB of repeated
     * diagnostics; beyond this we keep only the tail (where the actual error
     * usually is) and prepend a truncation notice.
     */
    private static final int MAX_BUILD_OUTPUT_CHARS = 16 * 1024;

    /**
     * Return {@code text} unchanged when it fits within {@code maxChars};
     * otherwise return its last {@code maxChars} characters prefixed with a
     * notice naming how many characters were dropped.
     */
    private static String boundTail(String text, int maxChars) {
        if (text.length() <= maxChars) {
            return text;
        }
        int dropped = text.length() - maxChars;
        return "[... truncated " + dropped + " characters; showing last "
                + maxChars + " ...]\n" + text.substring(dropped);
    }

    public ProgramScriptService(ProgramProvider programProvider, ThreadingStrategy threadingStrategy) {
        this.programProvider = programProvider;
        this.threadingStrategy = threadingStrategy;
    }

    private static void ensureScriptBundleHostInitialized(File scriptDirectory) {
        synchronized (SCRIPT_BUNDLE_HOST_LOCK) {
            if (ghidra.app.script.GhidraScriptUtil.getBundleHost() == null) {
                // In GUI mode GhidraScriptMgrPlugin owns this lifecycle. The
                // headless MCP server has no script-manager plugin, but Java
                // scripts still need the OSGi bundle host before
                // JavaScriptProvider can compile/load script classes.
                ghidra.app.script.GhidraScriptUtil.acquireBundleHostReference();
            }
            ghidra.app.script.GhidraScriptUtil.getBundleHost()
                    .enable(new generic.jar.ResourceFile(scriptDirectory));
        }
    }

    /**
     * Retrieve the PluginTool from the ProgramProvider if it is a GuiProgramProvider/FrontEndProgramProvider.
     * Returns null when running headless.
     */
    private PluginTool getToolFromProvider() {
        if (programProvider instanceof GuiProgramProvider gpp) {
            return gpp.getTool();
        }
        if (programProvider instanceof FrontEndProgramProvider fpp) {
            return fpp.getTool();
        }
        if (programProvider instanceof MultiToolProgramProvider mtp) {
            return mtp.getActiveTool();
        }
        return null;
    }

    private boolean runAutoAnalysisAndPersistFlags(Program program, boolean force) {
        if (program == null) {
            return false;
        }
        try {
            AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
            // Ghidra's analyzers mutate the program DB, which requires an
            // open transaction. The GUI analysis-task framework opens one
            // for you; a direct mgr.startAnalysis() from the bridge does
            // NOT. Without this wrapper FunctionStartAnalyzer (and any
            // other writing analyzer) throws db.NoTransactionException
            // ("Transaction has not been started") on any program that
            // isn't already fully analyzed — the program-open path then
            // fails. Confirmed root cause of #209. The markProgram* option
            // writes go inside the same transaction since they mutate the
            // program too; persistProgram (save) runs AFTER the
            // transaction is closed.
            int txId = program.startTransaction("GhidraMCP auto-analysis");
            boolean txOk = false;
            try {
                ghidra.program.util.GhidraProgramUtilities.markProgramNotToAskToAnalyze(program);
                if (force) {
                    mgr.reAnalyzeAll(null);
                }
                mgr.startAnalysis(ghidra.util.task.TaskMonitor.DUMMY);
                // Through the guarded helper, never mgr.waitForAnalysis
                // directly -- see awaitAnyPendingAnalysis. An unguarded call
                // here is one of the two paths that wedged all three HTTP
                // threads for 7.8 CPU-hours on 2026-08-11.
                awaitAnyPendingAnalysis(program);
                ghidra.program.util.GhidraProgramUtilities.markProgramAnalyzed(program);
                txOk = true;
            } finally {
                program.endTransaction(txId, txOk);
            }
            persistProgram(program, AUTO_ANALYSIS_COMPLETION_MESSAGE);
            return true;
        } catch (Exception e) {
            Msg.warn(this, "Auto-analysis failed: " + e.getMessage());
            try {
                suppressAnalysisPrompt(program);
            } catch (Exception ignored) {
                // Preserve the original analysis failure in the log.
            }
            return false;
        }
    }

    private void suppressAnalysisPrompt(Program program) throws IOException, ghidra.util.exception.CancelledException {
        ghidra.program.util.GhidraProgramUtilities.markProgramNotToAskToAnalyze(program);
        persistProgram(program, "Suppress analysis prompt");
    }

    private void persistProgram(Program program, String reason)
            throws IOException, ghidra.util.exception.CancelledException {
        if (program == null || !program.canSave()) {
            return;
        }
        program.flushEvents();
        saveWithRetry(program, () -> program.save(reason, ghidra.util.task.TaskMonitor.DUMMY));
    }

    @FunctionalInterface
    private interface ThrowingSave {
        void run() throws IOException, ghidra.util.exception.CancelledException;
    }

    /**
     * Save a program, retrying if the attempt races Ghidra's own
     * auto-analysis transaction management.
     *
     * <p>{@link AutoAnalysisManager} registers its own
     * {@code DomainObjectListener} on every program and schedules a
     * background "Auto Analysis" task whenever the program changes (a
     * rename, a signature edit, a new function) -- entirely independent of
     * any analysis this class explicitly starts. If that background task's
     * transaction is still open when a save runs, the save throws
     * {@code IOException: Unable to lock due to active transaction}.
     * Confirmed via Ghidra's own application.log: the same stack trace,
     * through {@code saveCurrentProgram}, recurring since at least
     * 2026-07-08 -- weeks before any code path here explicitly triggered
     * analysis, so it is not specific to this class's own analysis calls.</p>
     *
     * <p>Waiting for {@link AutoAnalysisManager#waitForAnalysis} to return
     * first narrows the window but does not close it: Ghidra logs the task
     * as complete and this save's lock failure in the same instant, meaning
     * the completion notification and the background task's own transaction
     * teardown are not perfectly synchronized with each other. A short
     * backoff-and-retry on that specific message is the pragmatic fix for a
     * race that waiting alone cannot fully eliminate.</p>
     */
    private void saveWithRetry(Program program, ThrowingSave saveAction)
            throws IOException, ghidra.util.exception.CancelledException {
        final int maxAttempts = 4;
        for (int attempt = 1; attempt <= maxAttempts; attempt++) {
            awaitAnyPendingAnalysis(program);
            try {
                saveAction.run();
                return;
            } catch (IOException e) {
                String msg = e.getMessage();
                boolean isLockRace = msg != null && msg.contains("Unable to lock due to active transaction");
                if (!isLockRace || attempt == maxAttempts) {
                    throw e;
                }
                Msg.warn(this, "Save raced Ghidra's own auto-analysis transaction (attempt "
                        + attempt + "/" + maxAttempts + "), retrying: " + msg);
                try {
                    Thread.sleep(150L * attempt);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    throw e;
                }
            }
        }
    }

    /**
     * Re-entrancy guard for {@link AutoAnalysisManager#waitForAnalysis}.
     *
     * <p>{@code waitForAnalysis(null, monitor)} can re-enter ITSELF. Measured
     * from a live thread dump on 2026-08-11, after Ghidra had been
     * unresponsive for hours:</p>
     *
     * <pre>
     *   AutoAnalysisManager.scheduleWorker(1350)
     *     -&gt; waitForAnalysis(518)
     *       -&gt; analysisWorkerCallback(523)
     *         -&gt; AnalysisWorkerCommand.applyTo(1694)
     *           -&gt; applyToWithTransaction
     *             -&gt; scheduleWorker(1350)   ... and round again
     * </pre>
     *
     * <p>All THREE GhidraMCP-HTTP threads -- the entire pool -- were stuck in
     * that loop, 317 frames deep, having burned ~9,400 CPU-seconds EACH
     * (7.8 CPU-hours between them). They never return, so the pool is
     * permanently consumed and every one of the 253 endpoints times out. The
     * symptom presents as "Ghidra is slow", not as an error, and the only
     * recovery is a restart.</p>
     *
     * <p>A thread that is already inside a wait does not need to start
     * another one: the outer call is still going to wait for the same
     * analysis to finish. So a nested call on the same thread returns
     * immediately and the recursion cannot form. This is deliberately the
     * smallest fix that provably terminates -- it changes no semantics for
     * the outer wait, and if it is wrong the failure mode is a save racing
     * analysis, which {@code saveWithRetry} already handles and which is
     * vastly preferable to a wedged server.</p>
     */
    // Package-visible on purpose: FrontEndProgramProvider shares this ONE
    // guard. Two separate ThreadLocals would not guard each other, and the
    // recursion can cross both classes on a single thread.
    static final ThreadLocal<Boolean> IN_ANALYSIS_WAIT =
            ThreadLocal.withInitial(() -> Boolean.FALSE);

    private void awaitAnyPendingAnalysis(Program program) {
        if (Boolean.TRUE.equals(IN_ANALYSIS_WAIT.get())) {
            // Already waiting further up this same thread's stack. Starting
            // another wait here is what forms the infinite recursion above.
            return;
        }
        IN_ANALYSIS_WAIT.set(Boolean.TRUE);
        try {
            AutoAnalysisManager.getAnalysisManager(program)
                    .waitForAnalysis(null, ghidra.util.task.TaskMonitor.DUMMY);
        } catch (Exception e) {
            // Best-effort: let the save call itself surface any real failure
            // rather than mask it with a wait-side error here.
            Msg.warn(this, "awaitAnyPendingAnalysis failed, proceeding to save anyway: " + e.getMessage());
        } finally {
            IN_ANALYSIS_WAIT.set(Boolean.FALSE);
        }
    }

    // ========================================================================
    // Program Metadata
    // ========================================================================

    /**
     * Get metadata about the current program including name, architecture,
     * memory layout, function count, and symbol count.
     */
    public Response getMetadata() {
        return getMetadata(null);
    }

    @McpTool(path = "/get_metadata", description = "Get program metadata", category = "program")
    public Response getMetadata(
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        long totalSize = 0;
        int blockCount = 0;
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            totalSize += block.getSize();
            blockCount++;
        }

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("program_name", program.getName());
        out.put("executable_path", program.getExecutablePath());
        out.put("architecture", program.getLanguage().getProcessor().toString());
        out.put("compiler", program.getCompilerSpec().getCompilerSpecID().toString());
        out.put("language", program.getLanguage().getLanguageID().toString());
        out.put("endian", program.getLanguage().isBigEndian() ? "big" : "little");
        out.put("address_size_bits", program.getAddressFactory().getDefaultAddressSpace().getSize());
        out.put("base_address", program.getImageBase().toString(false));
        out.put("memory_blocks", blockCount);
        out.put("total_memory_size", totalSize);
        out.put("function_count", program.getFunctionManager().getFunctionCount());
        out.put("symbol_count", program.getSymbolTable().getNumSymbols());
        return Response.ok(out);
    }

    // ========================================================================
    // Program Options (typed key -> value settings grouped by category)
    // ========================================================================

    /** Standard address-parameter description shared by property-map tools. */
    private static final String ADDRESS_PARAM_DESC =
            "Address in the program. Accepts 0x<hex> (default space) or <space>:<hex> "
          + "(e.g., mem:1000, code:ff00). Note: some programs — particularly "
          + "embedded/microcontroller targets — are not address-space-agnostic; "
          + "use get_address_spaces to discover spaces before assuming a plain hex "
          + "address is unambiguous.";

    /**
     * List every program option group (e.g. "Program Information", "Analyzers",
     * "Decompiler", "Disassembler"). Each group is a namespace of typed key→value
     * settings; use {@code get_program_options} to read a group's entries.
     */
    @McpTool(path = "/list_option_groups",
             description = "List program option groups (e.g. 'Program Information', 'Analyzers', 'Decompiler'). Each group holds typed key→value settings; use get_program_options to read a group's entries.",
             category = "program")
    public Response listOptionGroups(
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        try {
            List<Map<String, Object>> groups = new ArrayList<>();
            for (String groupName : program.getOptionsNames()) {
                Options opts = program.getOptions(groupName);
                groups.add(JsonHelper.mapOf(
                    "name", groupName,
                    "option_count", opts.getOptionNames().size()));
            }
            return Response.ok(JsonHelper.mapOf(
                "groups", groups,
                "count", groups.size(),
                "program", program.getName()));
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    /**
     * Read every option in a single group with its type, current value, default,
     * and description. Values are rendered as strings via
     * {@link Options#getValueAsString(String)} so every option type is legible.
     */
    @McpTool(path = "/get_program_options",
             description = "Read all options in a program option group with types, current values, defaults, and descriptions. Use list_option_groups to discover group names.",
             category = "program")
    public Response getProgramOptions(
            @Param(value = "group", description = "Option group name from list_option_groups (e.g. 'Program Information', 'Analyzers').") String group,
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        if (group == null || group.isEmpty()) {
            return Response.err("group is required (use list_option_groups to discover group names)");
        }
        if (!program.getOptionsNames().contains(group)) {
            return Response.err("No such option group: '" + group + "'. Use list_option_groups to see available groups.");
        }

        try {
            Options opts = program.getOptions(group);
            List<Map<String, Object>> options = new ArrayList<>();
            for (String name : opts.getOptionNames()) {
                Map<String, Object> entry = new LinkedHashMap<>();
                entry.put("name", name);
                OptionType type = opts.getType(name);
                entry.put("type", type != null ? type.name() : "NO_TYPE");
                // getValueAsString returns null for CUSTOM_TYPE options (e.g.
                // "Analysis Times.Times"), and the JSON writer drops null-valued
                // keys -- so the entry silently lost `value` entirely for that
                // one type while every other entry carried it. A key the shape
                // promises must always be present, so fall back to the stored
                // object's own rendering before giving up on an empty string.
                entry.put("value", optionValueString(opts, name, false));
                entry.put("default_value", optionValueString(opts, name, true));
                entry.put("is_default", opts.isDefaultValue(name));
                entry.put("registered", opts.isRegistered(name));
                String desc = opts.getDescription(name);
                if (desc != null && !desc.isEmpty()) {
                    entry.put("description", desc);
                }
                options.add(entry);
            }
            return Response.ok(JsonHelper.mapOf(
                "group", group,
                "options", options,
                "count", options.size(),
                "program", program.getName()));
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    /**
     * Render an option's value (or default) as a string that is never null.
     *
     * <p>{@link Options#getValueAsString} and {@link Options#getDefaultValueAsString}
     * both return null for option types they cannot stringify -- CUSTOM_TYPE in
     * practice. Because the JSON writer omits null-valued keys, that turned into
     * an entry missing {@code value} altogether while its siblings had one, so a
     * caller iterating options had to special-case a key the shape promises.
     * Falling back to the stored object's own {@code toString} keeps the key
     * present and usually carries real information; empty string is the last
     * resort, meaning "present but not representable".
     */
    private static String optionValueString(Options opts, String name, boolean wantDefault) {
        String value = wantDefault ? opts.getDefaultValueAsString(name) : opts.getValueAsString(name);
        if (value != null) {
            return value;
        }
        try {
            Object raw = wantDefault ? opts.getDefaultValue(name) : opts.getObject(name, null);
            if (raw != null) {
                return String.valueOf(raw);
            }
        } catch (Exception ignored) {
            // A custom option whose accessor throws is still an option we must
            // list; degrade to empty rather than failing the whole group.
        }
        return "";
    }

    /**
     * Set (or create) a typed option in a group. When the option already exists
     * its current type is reused; otherwise the caller supplies {@code type}.
     * Supported types: string, int, long, double, float, boolean. The value is
     * parsed BEFORE the write transaction so parse errors surface cleanly.
     * Persists to the database on the next {@code save_program}.
     */
    @McpTool(path = "/set_program_option", method = "POST",
             description = "Set a typed program option. If the option already exists its type is reused; otherwise pass type (string|int|long|double|float|boolean). New/custom options are created on demand. Call save_program to persist.",
             category = "program")
    public Response setProgramOption(
            @Param(value = "group", source = ParamSource.BODY, description = "Option group name (e.g. 'Program Information'). Use list_option_groups to discover names.") String group,
            @Param(value = "name", source = ParamSource.BODY, description = "Option name within the group.") String name,
            @Param(value = "value", source = ParamSource.BODY, description = "New value as a string; parsed according to the option type.") String value,
            @Param(value = "type", source = ParamSource.BODY, defaultValue = "",
                   description = "Value type: string|int|long|double|float|boolean. Optional when the option already exists (its current type is reused); defaults to string for a brand-new option.") String type,
            @Param(value = "program", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        if (group == null || group.isEmpty()) return Response.err("group is required");
        if (name == null || name.isEmpty()) return Response.err("name is required");
        if (value == null) return Response.err("value is required");
        if (!program.getOptionsNames().contains(group)) {
            return Response.err("No such option group: '" + group + "'. Use list_option_groups to see available groups.");
        }

        Options opts = program.getOptions(group);

        // Resolve the value type: explicit arg wins; otherwise infer from an
        // existing option; otherwise default to string.
        String resolved = (type == null) ? "" : type.trim().toLowerCase();
        if (resolved.isEmpty()) {
            if (opts.contains(name)) {
                resolved = optionTypeKeyword(opts.getType(name));
                if (resolved == null) {
                    return Response.err("Option '" + name + "' has type "
                        + opts.getType(name) + " which cannot be set via this tool. "
                        + "Settable types: string, int, long, double, float, boolean.");
                }
            } else {
                resolved = "string";
            }
        }

        // Parse the value outside the transaction so a bad number is a clean error.
        final Object parsed;
        try {
            switch (resolved) {
                case "string":  parsed = value; break;
                case "int":     parsed = Integer.parseInt(value.trim()); break;
                case "long":    parsed = Long.parseLong(value.trim()); break;
                case "double":  parsed = Double.parseDouble(value.trim()); break;
                case "float":   parsed = Float.parseFloat(value.trim()); break;
                case "boolean": parsed = Boolean.parseBoolean(value.trim()); break;
                default:
                    return Response.err("Unsupported type '" + resolved
                        + "'. Use one of: string, int, long, double, float, boolean.");
            }
        } catch (NumberFormatException nfe) {
            return Response.err("Value '" + value + "' is not a valid " + resolved + ": " + nfe.getMessage());
        }

        final String finalType = resolved;
        try {
            threadingStrategy.executeWrite(program, "Set Program Option", () -> {
                switch (finalType) {
                    case "string":  opts.setString(name, (String) parsed); break;
                    case "int":     opts.setInt(name, (Integer) parsed); break;
                    case "long":    opts.setLong(name, (Long) parsed); break;
                    case "double":  opts.setDouble(name, (Double) parsed); break;
                    case "float":   opts.setFloat(name, (Float) parsed); break;
                    case "boolean": opts.setBoolean(name, (Boolean) parsed); break;
                }
                return null;
            });
        } catch (Exception e) {
            return Response.err("Failed to set option: " + e.getMessage());
        }

        return Response.ok(JsonHelper.mapOf(
            "success", true,
            "group", group,
            "name", name,
            "type", finalType,
            "value", opts.getValueAsString(name),
            "note", "Call save_program to persist this change to the database.",
            "program", program.getName()));
    }

    /**
     * Remove an option from a group. Built-in registered options may be
     * re-created with default values by Ghidra; this is mainly for clearing
     * custom options previously written via {@code set_program_option}.
     */
    @McpTool(path = "/remove_program_option", method = "POST",
             description = "Remove an option from a program option group. Built-in registered options may be re-created with defaults by Ghidra; primarily for clearing custom options. Call save_program to persist.",
             category = "program")
    public Response removeProgramOption(
            @Param(value = "group", source = ParamSource.BODY, description = "Option group name.") String group,
            @Param(value = "name", source = ParamSource.BODY, description = "Option name to remove.") String name,
            @Param(value = "program", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        if (group == null || group.isEmpty()) return Response.err("group is required");
        if (name == null || name.isEmpty()) return Response.err("name is required");
        if (!program.getOptionsNames().contains(group)) {
            return Response.err("No such option group: '" + group + "'. Use list_option_groups to see available groups.");
        }

        Options opts = program.getOptions(group);
        if (!opts.contains(name)) {
            return Response.ok(JsonHelper.mapOf(
                "success", false,
                "message", "No option named '" + name + "' in group '" + group + "'",
                "program", program.getName()));
        }

        try {
            threadingStrategy.executeWrite(program, "Remove Program Option", () -> {
                opts.removeOption(name);
                return null;
            });
        } catch (Exception e) {
            return Response.err("Failed to remove option: " + e.getMessage());
        }

        return Response.ok(JsonHelper.mapOf(
            "success", true,
            "group", group,
            "name", name,
            "note", "Call save_program to persist this change to the database.",
            "program", program.getName()));
    }

    // ========================================================================
    // Property Maps (typed per-address key -> value stores)
    // ========================================================================

    /**
     * List all user-defined property maps. Each map has a name, a value type
     * (int / long / string / object / void), and the count of addresses that
     * currently hold a value.
     */
    @McpTool(path = "/list_property_maps",
             description = "List user-defined property maps — typed per-address key→value stores. Each map reports its name, value type (int|long|string|object|void), and the number of addresses holding a value.",
             category = "program")
    public Response listPropertyMaps(
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        try {
            PropertyMapManager mgr = program.getUsrPropertyManager();
            List<Map<String, Object>> maps = new ArrayList<>();
            Iterator<String> it = mgr.propertyManagers();
            while (it.hasNext()) {
                String mapName = it.next();
                PropertyMap<?> map = mgr.getPropertyMap(mapName);
                maps.add(JsonHelper.mapOf(
                    "name", mapName,
                    "value_type", propertyMapValueType(map),
                    "size", map != null ? map.getSize() : 0));
            }
            return Response.ok(JsonHelper.mapOf(
                "property_maps", maps,
                "count", maps.size(),
                "program", program.getName()));
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    /**
     * Create a new user property map. Types: int, long, string, void
     * (address-presence tag). Store arbitrary structured per-address data by
     * using a string map holding JSON.
     */
    @McpTool(path = "/create_property_map", method = "POST",
             description = "Create a user property map to store typed values keyed by address. Types: int, long, string, void (address-presence tag). Use a string map holding JSON to store arbitrary structured per-address data. Call save_program to persist.",
             category = "program")
    public Response createPropertyMap(
            @Param(value = "name", source = ParamSource.BODY, description = "Unique map name.") String name,
            @Param(value = "type", source = ParamSource.BODY, defaultValue = "string",
                   description = "Value type: int, long, string, or void.") String type,
            @Param(value = "program", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        if (name == null || name.isEmpty()) return Response.err("name is required");
        final String kind = (type == null || type.isEmpty()) ? "string" : type.trim().toLowerCase();
        if (!Set.of("int", "long", "string", "void").contains(kind)) {
            return Response.err("Unsupported map type '" + kind + "'. Use one of: int, long, string, void.");
        }

        PropertyMapManager mgr = program.getUsrPropertyManager();
        if (mgr.getPropertyMap(name) != null) {
            return Response.err("Property map '" + name + "' already exists.");
        }

        try {
            threadingStrategy.executeWrite(program, "Create Property Map", () -> {
                switch (kind) {
                    case "int":    mgr.createIntPropertyMap(name); break;
                    case "long":   mgr.createLongPropertyMap(name); break;
                    case "string": mgr.createStringPropertyMap(name); break;
                    case "void":   mgr.createVoidPropertyMap(name); break;
                }
                return null;
            });
        } catch (Exception e) {
            return Response.err("Failed to create property map: " + e.getMessage());
        }

        return Response.ok(JsonHelper.mapOf(
            "success", true,
            "name", name,
            "value_type", kind,
            "note", "Call save_program to persist this change to the database.",
            "program", program.getName()));
    }

    /**
     * Delete an entire user property map and all its values.
     */
    @McpTool(path = "/delete_property_map", method = "POST",
             description = "Delete a user property map and all values it holds. Call save_program to persist.",
             category = "program")
    public Response deletePropertyMap(
            @Param(value = "name", source = ParamSource.BODY, description = "Map name to delete.") String name,
            @Param(value = "program", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        if (name == null || name.isEmpty()) return Response.err("name is required");
        PropertyMapManager mgr = program.getUsrPropertyManager();
        if (mgr.getPropertyMap(name) == null) {
            return Response.ok(JsonHelper.mapOf(
                "success", false,
                "message", "No property map named '" + name + "'",
                "program", program.getName()));
        }

        final AtomicBoolean removed = new AtomicBoolean(false);
        try {
            threadingStrategy.executeWrite(program, "Delete Property Map", () -> {
                removed.set(mgr.removePropertyMap(name));
                return null;
            });
        } catch (Exception e) {
            return Response.err("Failed to delete property map: " + e.getMessage());
        }

        return Response.ok(JsonHelper.mapOf(
            "success", removed.get(),
            "name", name,
            "note", "Call save_program to persist this change to the database.",
            "program", program.getName()));
    }

    /**
     * Set a value at an address in a property map. The value is coerced to the
     * map's declared type. {@code void} maps ignore the value and simply tag the
     * address. Object maps cannot be written here (they require a registered
     * {@link ghidra.util.Saveable} type). The map must already exist.
     */
    @McpTool(path = "/set_property", method = "POST",
             description = "Set a value at an address in a property map. The value is coerced to the map's type (int/long/string); 'void' maps ignore the value and just tag the address. Create the map first with create_property_map. Call save_program to persist.",
             category = "program")
    public Response setProperty(
            @Param(value = "map", source = ParamSource.BODY, description = "Property map name (from list_property_maps).") String mapName,
            @Param(value = "address", paramType = "address", source = ParamSource.BODY, description = ADDRESS_PARAM_DESC) String addressStr,
            @Param(value = "value", source = ParamSource.BODY, defaultValue = "",
                   description = "Value to store, as a string; parsed per the map's type. Ignored for 'void' maps.") String value,
            @Param(value = "program", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        if (mapName == null || mapName.isEmpty()) return Response.err("map is required");
        if (addressStr == null || addressStr.isEmpty()) return Response.err("address is required");

        PropertyMap<?> map = program.getUsrPropertyManager().getPropertyMap(mapName);
        if (map == null) {
            return Response.err("No property map named '" + mapName + "'. Create it with create_property_map.");
        }
        Address address = ServiceUtils.parseAddress(program, addressStr);
        if (address == null) {
            return Response.err(ServiceUtils.getLastParseError());
        }

        if (map instanceof ObjectPropertyMap) {
            return Response.err("Object property maps cannot be written via MCP (they require a registered Saveable type).");
        }

        // Parse numeric values outside the transaction for clean error reporting.
        final Object parsed;
        try {
            if (map instanceof IntPropertyMap) {
                if (value == null || value.isEmpty()) return Response.err("value is required for an int property map");
                parsed = Integer.parseInt(value.trim());
            } else if (map instanceof LongPropertyMap) {
                if (value == null || value.isEmpty()) return Response.err("value is required for a long property map");
                parsed = Long.parseLong(value.trim());
            } else if (map instanceof StringPropertyMap) {
                if (value == null) return Response.err("value is required for a string property map");
                parsed = value;
            } else {
                parsed = null; // void map — presence only
            }
        } catch (NumberFormatException nfe) {
            return Response.err("Value '" + value + "' is not valid for map '" + mapName + "': " + nfe.getMessage());
        }

        try {
            threadingStrategy.executeWrite(program, "Set Property", () -> {
                if (map instanceof IntPropertyMap ip) {
                    ip.add(address, (Integer) parsed);
                } else if (map instanceof LongPropertyMap lp) {
                    lp.add(address, (Long) parsed);
                } else if (map instanceof StringPropertyMap sp) {
                    sp.add(address, (String) parsed);
                } else if (map instanceof VoidPropertyMap vp) {
                    vp.add(address);
                }
                return null;
            });
        } catch (Exception e) {
            return Response.err("Failed to set property: " + e.getMessage());
        }

        return Response.ok(JsonHelper.mapOf(
            "success", true,
            "map", mapName,
            "address", address.toString(),
            "value_type", propertyMapValueType(map),
            "value", parsed,
            "note", "Call save_program to persist this change to the database.",
            "program", program.getName()));
    }

    /**
     * Read the value stored at an address in a property map. Returns
     * {@code has_value=false} with a null value when the address holds no
     * property. Object-map values are rendered via {@code toString()}.
     */
    @McpTool(path = "/get_property",
             description = "Read the value stored at an address in a property map. Returns has_value=false and a null value when the address holds no property.",
             category = "program")
    public Response getProperty(
            @Param(value = "map", description = "Property map name (from list_property_maps).") String mapName,
            @Param(value = "address", paramType = "address", description = ADDRESS_PARAM_DESC) String addressStr,
            @Param(value = "program", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        if (mapName == null || mapName.isEmpty()) return Response.err("map is required");
        if (addressStr == null || addressStr.isEmpty()) return Response.err("address is required");

        PropertyMap<?> map = program.getUsrPropertyManager().getPropertyMap(mapName);
        if (map == null) {
            return Response.err("No property map named '" + mapName + "'.");
        }
        Address address = ServiceUtils.parseAddress(program, addressStr);
        if (address == null) {
            return Response.err(ServiceUtils.getLastParseError());
        }

        try {
            boolean hasValue = map.hasProperty(address);
            Object value = hasValue ? renderPropertyValue(map.get(address)) : null;
            return Response.ok(JsonHelper.mapOf(
                "map", mapName,
                "address", address.toString(),
                "has_value", hasValue,
                "value_type", propertyMapValueType(map),
                "value", value,
                "program", program.getName()));
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    /**
     * Remove the value stored at a single address in a property map.
     */
    @McpTool(path = "/remove_property", method = "POST",
             description = "Remove the value stored at a single address in a property map. Call save_program to persist.",
             category = "program")
    public Response removeProperty(
            @Param(value = "map", source = ParamSource.BODY, description = "Property map name.") String mapName,
            @Param(value = "address", paramType = "address", source = ParamSource.BODY, description = ADDRESS_PARAM_DESC) String addressStr,
            @Param(value = "program", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        if (mapName == null || mapName.isEmpty()) return Response.err("map is required");
        if (addressStr == null || addressStr.isEmpty()) return Response.err("address is required");

        PropertyMap<?> map = program.getUsrPropertyManager().getPropertyMap(mapName);
        if (map == null) {
            return Response.err("No property map named '" + mapName + "'.");
        }
        Address address = ServiceUtils.parseAddress(program, addressStr);
        if (address == null) {
            return Response.err(ServiceUtils.getLastParseError());
        }

        final AtomicBoolean removed = new AtomicBoolean(false);
        try {
            threadingStrategy.executeWrite(program, "Remove Property", () -> {
                removed.set(map.remove(address));
                return null;
            });
        } catch (Exception e) {
            return Response.err("Failed to remove property: " + e.getMessage());
        }

        return Response.ok(JsonHelper.mapOf(
            "success", removed.get(),
            "map", mapName,
            "address", address.toString(),
            "note", "Call save_program to persist this change to the database.",
            "program", program.getName()));
    }

    /**
     * List (address, value) entries stored in a property map with pagination.
     * Optionally restrict to an inclusive address range via {@code start}/{@code end}.
     */
    @McpTool(path = "/list_properties",
             description = "List (address, value) entries stored in a property map, with pagination. Optionally restrict to an inclusive address range with start/end.",
             category = "program")
    public Response listProperties(
            @Param(value = "map", description = "Property map name (from list_property_maps).") String mapName,
            @Param(value = "start", paramType = "address", defaultValue = "", description = "Optional inclusive start address of a range filter.") String startStr,
            @Param(value = "end", paramType = "address", defaultValue = "", description = "Optional inclusive end address of a range filter (requires start).") String endStr,
            @Param(value = "offset", defaultValue = "0", description = "Number of entries to skip.") int offset,
            @Param(value = "limit", defaultValue = "100", description = "Maximum number of entries to return.") int limit,
            @Param(value = "program", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        if (mapName == null || mapName.isEmpty()) return Response.err("map is required");
        PropertyMap<?> map = program.getUsrPropertyManager().getPropertyMap(mapName);
        if (map == null) {
            return Response.err("No property map named '" + mapName + "'.");
        }
        if (offset < 0) offset = 0;
        if (limit <= 0) limit = 100;

        try {
            AddressIterator it;
            boolean hasStart = startStr != null && !startStr.isEmpty();
            boolean hasEnd = endStr != null && !endStr.isEmpty();
            if (hasStart != hasEnd) {
                return Response.err("Provide both start and end to filter by range, or neither.");
            }
            if (hasStart) {
                Address start = ServiceUtils.parseAddress(program, startStr);
                if (start == null) return Response.err("start: " + ServiceUtils.getLastParseError());
                Address end = ServiceUtils.parseAddress(program, endStr);
                if (end == null) return Response.err("end: " + ServiceUtils.getLastParseError());
                it = map.getPropertyIterator(start, end);
            } else {
                it = map.getPropertyIterator();
            }

            List<Map<String, Object>> entries = new ArrayList<>();
            int skipped = 0;
            while (it.hasNext()) {
                Address addr = it.next();
                if (skipped < offset) {
                    skipped++;
                    continue;
                }
                if (entries.size() >= limit) break;
                entries.add(JsonHelper.mapOf(
                    "address", addr.toString(),
                    "value", renderPropertyValue(map.get(addr))));
            }
            return Response.ok(JsonHelper.mapOf(
                "map", mapName,
                "value_type", propertyMapValueType(map),
                "entries", entries,
                "count", entries.size(),
                "total", map.getSize(),
                "offset", offset,
                "limit", limit,
                "program", program.getName()));
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    /** Map an {@link OptionType} to the keyword accepted by set_program_option, or null if unsettable. */
    private static String optionTypeKeyword(OptionType type) {
        if (type == null) return null;
        switch (type) {
            case STRING_TYPE:  return "string";
            case INT_TYPE:     return "int";
            case LONG_TYPE:    return "long";
            case DOUBLE_TYPE:  return "double";
            case FLOAT_TYPE:   return "float";
            case BOOLEAN_TYPE: return "boolean";
            default:           return null;
        }
    }

    /** Classify a property map by its concrete value type. */
    private static String propertyMapValueType(PropertyMap<?> map) {
        if (map instanceof IntPropertyMap)    return "int";
        if (map instanceof LongPropertyMap)   return "long";
        if (map instanceof StringPropertyMap) return "string";
        if (map instanceof VoidPropertyMap)   return "void";
        if (map instanceof ObjectPropertyMap) return "object";
        return "unknown";
    }

    /** Render a stored property value for JSON: Saveable objects become their toString(). */
    private static Object renderPropertyValue(Object raw) {
        if (raw instanceof ghidra.util.Saveable) {
            return raw.toString();
        }
        return raw;
    }

    // ========================================================================
    // Program Management
    // ========================================================================

    /**
     * Save the currently active program to its domain file.
     */
    public Response saveCurrentProgram() {
        return saveCurrentProgram(null);
    }

    @McpTool(path = "/save_program", description = "Save current program", category = "program")
    public Response saveCurrentProgram(
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        final AtomicReference<Map<String, Object>> resultData = new AtomicReference<>();
        final AtomicReference<String> errorMsg = new AtomicReference<>();

        try {
            SwingUtilities.invokeAndWait(() -> {
                try {
                    ghidra.framework.model.DomainFile df = program.getDomainFile();
                    if (df == null) {
                        errorMsg.set("Program has no domain file");
                        return;
                    }
                    saveWithRetry(program, () -> df.save(new ConsoleTaskMonitor()));
                    resultData.set(JsonHelper.mapOf(
                        "success", true,
                        "program", program.getName(),
                        "message", "Program saved successfully"
                    ));
                } catch (Throwable e) {
                    String msg = e.getMessage() != null ? e.getMessage() : e.toString();
                    errorMsg.set(msg);
                    Msg.error(this, "Error saving program", e);
                }
            });

            if (errorMsg.get() != null) {
                return Response.err(errorMsg.get());
            }
        } catch (Throwable e) {
            String msg = e.getMessage() != null ? e.getMessage() : e.toString();
            return Response.err(msg);
        }

        return resultData.get() != null ? Response.ok(resultData.get()) : Response.err("Unknown failure");
    }

    /**
     * Save every currently open program. This is intended for automation paths
     * such as deploy shutdown where Ghidra would otherwise prompt for each
     * modified domain object on exit.
     */
    @McpTool(path = "/save_all_programs", description = "Save all open programs", category = "program")
    public Response saveAllOpenPrograms() {
        Program[] programs = programProvider.getAllOpenPrograms();
        if (programs == null || programs.length == 0) {
            return Response.ok(JsonHelper.mapOf(
                "success", true,
                "saved_count", 0,
                "open_program_count", 0,
                "programs", List.of(),
                "errors", List.of(),
                "message", "No open programs to save"
            ));
        }

        final AtomicReference<List<Map<String, Object>>> saved = new AtomicReference<>(new ArrayList<>());
        final AtomicReference<List<Map<String, Object>>> errors = new AtomicReference<>(new ArrayList<>());

        Runnable saveTask = () -> {
            Set<Program> seen = Collections.newSetFromMap(new IdentityHashMap<>());
            for (Program program : programs) {
                if (program == null || !seen.add(program)) {
                    continue;
                }

                Map<String, Object> info = new LinkedHashMap<>();
                info.put("program", program.getName());
                try {
                    ghidra.framework.model.DomainFile df = program.getDomainFile();
                    if (df == null) {
                        info.put("error", "Program has no domain file");
                        errors.get().add(info);
                        continue;
                    }
                    info.put("path", df.getPathname());
                    // A DomainFile that is not in a writable project is a proxy
                    // (no on-disk location) \u2014 calling save() on it throws the
                    // cryptic "Location does not exist for a save operation!".
                    // Surface a specific message so callers know to re-load
                    // with an active project open.
                    if (!df.isInWritableProject()) {
                        info.put("error",
                            "Program is not attached to a writable project "
                            + "(transient DomainFileProxy); re-load it with a "
                            + "project open before saving.");
                        errors.get().add(info);
                        continue;
                    }
                    saveWithRetry(program, () -> df.save(new ConsoleTaskMonitor()));
                    saved.get().add(info);
                } catch (Throwable e) {
                    info.put("error", e.getMessage() != null ? e.getMessage() : e.toString());
                    errors.get().add(info);
                    Msg.error(this, "Error saving program " + program.getName(), e);
                }
            }
        };

        try {
            if (SwingUtilities.isEventDispatchThread()) {
                saveTask.run();
            } else {
                SwingUtilities.invokeAndWait(saveTask);
            }
        } catch (Throwable e) {
            return Response.err("Failed to save all programs: " +
                    (e.getMessage() != null ? e.getMessage() : e.toString()));
        }

        return Response.ok(JsonHelper.mapOf(
            "success", errors.get().isEmpty(),
            "saved_count", saved.get().size(),
            "open_program_count", programs.length,
            "programs", saved.get(),
            "errors", errors.get()
        ));
    }

    /**
     * List all currently open programs in Ghidra.
     */
    @McpTool(path = "/list_open_programs", description = "List all open programs. If more than one program is listed, always pass the program name explicitly in subsequent tool calls — omitting it will silently target the active program, which may not be the intended one.", category = "program")
    public Response listOpenPrograms() {
        Program[] programs = programProvider.getAllOpenPrograms();
        if (programs == null || programs.length == 0) {
            return Response.ok(JsonHelper.mapOf("programs", List.of(), "count", 0, "current_program", ""));
        }

        Program currentProgram = programProvider.resolveProgram(null);

        List<Map<String, Object>> programList = new ArrayList<>();
        for (Program prog : programs) {
            int physicalSpaceCount = ServiceUtils.getPhysicalSpaceCount(prog);
            int overlaySpaceCount  = ServiceUtils.getOverlaySpaceCount(prog);
            programList.add(JsonHelper.mapOf(
                "name", prog.getName(),
                "path", prog.getDomainFile().getPathname(),
                "is_current", prog == currentProgram,
                "executable_path", prog.getExecutablePath() != null ? prog.getExecutablePath() : "",
                "language", prog.getLanguageID().getIdAsString(),
                "compiler", prog.getCompilerSpec().getCompilerSpecID().getIdAsString(),
                "image_base", prog.getImageBase().toString(),
                "memory_size", prog.getMemory().getSize(),
                "function_count", prog.getFunctionManager().getFunctionCount(),
                // Physical-space ambiguity (true on 8051/AVR with separate
                // CODE/RAM spaces). Overlays do NOT make plain hex ambiguous,
                // so this stays false on single-RAM programs with overlays.
                "has_multiple_address_spaces", physicalSpaceCount > 1,
                "has_overlay_spaces",          overlaySpaceCount > 0,
                "overlay_space_count",         overlaySpaceCount
            ));
        }

        return Response.ok(JsonHelper.mapOf(
            "programs", programList,
            "count", programs.length,
            "current_program", currentProgram != null ? currentProgram.getName() : ""
        ));
    }

    @McpTool(path = "/close_program", method = "POST",
             description = "Close an open program by project path or name. Never prompts interactively: "
                         + "unsaved changes are saved first by default (save=true) or silently discarded "
                         + "(save=false) before closing, so this cannot block the caller on a GUI "
                         + "confirmation dialog the way Ghidra's own close normally would.", category = "program")
    public Response closeProgram(
            @Param(value = "name", source = ParamSource.BODY,
                    description = "Program name or project path") String name,
            @Param(value = "save", source = ParamSource.BODY, defaultValue = "true",
                    description = "Save unsaved changes before closing (default true). false discards them. "
                                + "Either way the close proceeds without prompting.") boolean save) {
        if (name == null || name.trim().isEmpty()) {
            return Response.err("Program name or path is required");
        }

        String search = name.trim();
        AtomicInteger closedCount = new AtomicInteger(0);
        AtomicReference<String> error = new AtomicReference<>();

        try {
            SwingUtilities.invokeAndWait(() -> {
                try {
                    for (ProgramManager pm : findAllProgramManagers()) {
                        for (Program program : pm.getAllOpenPrograms()) {
                            if (!programMatches(program, search)) {
                                continue;
                            }
                            if (save && program.isChanged()) {
                                ghidra.framework.model.DomainFile df = program.getDomainFile();
                                if (df != null && df.isInWritableProject()) {
                                    saveWithRetry(program, () -> df.save(new ConsoleTaskMonitor()));
                                }
                            }
                            // ignoreChanges=true unconditionally: we have already
                            // decided the fate of any unsaved edits above (saved,
                            // or deliberately left to be discarded), so Ghidra must
                            // never fall back to its own interactive "Save
                            // changes?" dialog here -- that call blocks the Swing
                            // event thread (and with it every other MCP request,
                            // since they all funnel through invokeAndWait) until a
                            // human clicks it, which is exactly the hang this
                            // parameter exists to prevent.
                            pm.closeProgram(program, true);
                            closedCount.incrementAndGet();
                        }
                    }
                } catch (Exception e) {
                    error.set(e.getMessage() != null ? e.getMessage() : e.toString());
                }
            });
        } catch (Exception e) {
            return Response.err("Failed to close program: " +
                    (e.getMessage() != null ? e.getMessage() : e.toString()));
        }

        if (closedCount.get() == 0) {
            for (Program program : programProvider.getAllOpenPrograms()) {
                if (programMatches(program, search) && programProvider.closeProgram(program)) {
                    closedCount.incrementAndGet();
                }
            }
        }

        if (error.get() != null) {
            return Response.err("Failed to close program: " + error.get());
        }

        boolean releasedCache = false;
        if (programProvider instanceof FrontEndProgramProvider fpp) {
            releasedCache = fpp.releaseCachedProgram(search);
        }

        return Response.ok(JsonHelper.mapOf(
            "success", true,
            "closed_count", closedCount.get(),
            "released_cache", releasedCache,
            "name", search
        ));
    }

    public Response getAddressSpaces() {
        return getAddressSpaces(null);
    }

    /**
     * List the program's address spaces. Returns physical RAM/CODE spaces plus
     * overlay spaces (marked is_overlay). Excludes pseudo-spaces (EXTERNAL, STACK,
     * etc.). Useful for embedded/microcontroller and overlay-bearing targets where
     * plain hex addresses may be ambiguous.
     */
    @McpTool(path = "/get_address_spaces",
             description = "List all physical address spaces in the program. On programs with multiple "
                         + "address spaces (e.g., embedded targets), use the returned space names to "
                         + "prefix addresses (e.g., mem:1000, code:ff00) for unambiguous resolution. "
                         + "Also check addressable_unit_size: a value > 1 means the space is word-addressed "
                         + "(e.g., AVR code space uses 2-byte words). MCP tools and Ghidra both use word "
                         + "addresses natively for such spaces — code:001478 is word 0x1478, not byte 0x1478. "
                         + "Do NOT multiply or divide addresses seen in Ghidra output; use them as-is. "
                         + "Overlay spaces are also listed, each marked is_overlay=true with its "
                         + "overlayed_space (base). Address an overlay location as <overlay>::<hex> "
                         + "(e.g., cli.Initial::00010000) — overlay names are case-sensitive.",
             category = "program")
    public Response getAddressSpaces(
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        List<Map<String, Object>> spaces = buildAddressSpacesList(program);
        spaces.addAll(buildOverlaySpacesList(program));
        return Response.ok(JsonHelper.mapOf("address_spaces", spaces, "count", spaces.size()));
    }

    private List<Map<String, Object>> buildAddressSpacesList(Program program) {
        List<Map<String, Object>> spaces = new ArrayList<>();
        AddressSpace defaultSpace = program.getAddressFactory().getDefaultAddressSpace();
        for (AddressSpace space : program.getAddressFactory().getAddressSpaces()) {
            if (space.isOverlaySpace()) continue;
            int type = space.getType();
            if (type != AddressSpace.TYPE_RAM && type != AddressSpace.TYPE_CODE) continue;
            long maxOff = space.getMaxAddress().getOffset();
            long minOff = space.getMinAddress().getOffset();
            // Safe unsigned size: (maxOff - minOff + 1) overflows for full 64-bit spaces (maxOff == -1L)
            long size = maxOff - minOff + 1;
            if (size == 0 && Long.compareUnsigned(maxOff, minOff) > 0) {
                size = Long.MAX_VALUE; // Full 64-bit space; clamp to avoid emitting 0
            }
            int unitSize = space.getAddressableUnitSize();
            // size_bytes: guard against overflow when size is clamped or unitSize > 1
            long sizeBytes = (size == Long.MAX_VALUE || unitSize <= 0)
                    ? Long.MAX_VALUE
                    : size * unitSize;
            spaces.add(JsonHelper.mapOf(
                "name",                  space.getName(),
                "start",                 space.getMinAddress().toString(false),
                "end",                   space.getMaxAddress().toString(false),
                "size",                  size,
                "addressable_unit_size", unitSize,
                "size_bytes",            sizeBytes,
                "address_size_bits",     space.getSize(),
                "is_default",            space == defaultSpace,
                "is_overlay",            Boolean.FALSE
            ));
        }
        return spaces;
    }

    /**
     * Build JSON entries for the program's overlay address spaces, each marked
     * is_overlay=true with the name of the physical space it overlays. Kept
     * SEPARATE from buildAddressSpacesList so get_current_program_info's
     * has_multiple_address_spaces flag continues to reflect PHYSICAL ambiguity only.
     */
    private List<Map<String, Object>> buildOverlaySpacesList(Program program) {
        List<Map<String, Object>> spaces = new ArrayList<>();
        for (AddressSpace space : program.getAddressFactory().getAddressSpaces()) {
            if (!space.isOverlaySpace()) continue;
            String base = "";
            if (space instanceof OverlayAddressSpace) {
                AddressSpace overlayed = ((OverlayAddressSpace) space).getOverlayedSpace();
                if (overlayed != null) base = overlayed.getName();
            }
            int unitSize = space.getAddressableUnitSize();
            spaces.add(JsonHelper.mapOf(
                "name",                  space.getName(),
                "start",                 space.getMinAddress().toString(false),
                "end",                   space.getMaxAddress().toString(false),
                "addressable_unit_size", unitSize,
                "address_size_bits",     space.getSize(),
                "is_overlay",            Boolean.TRUE,
                "overlayed_space",       base
            ));
        }
        return spaces;
    }

    /**
     * Get detailed information about the currently active program.
     */
    public Response getCurrentProgramInfo() {
        return getCurrentProgramInfo(null);
    }

    @McpTool(path = "/get_current_program_info", description = "Get detailed info about the active program. When multiple programs are open, call this first to confirm which program will receive tool calls that omit the program argument.", category = "program")
    public Response getCurrentProgramInfo(
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        List<Map<String, Object>> addressSpaces = buildAddressSpacesList(program);
        boolean multiSpace = addressSpaces.size() > 1;
        List<Map<String, Object>> overlaySpaces = buildOverlaySpacesList(program);
        // Combine for the address_spaces array so overlays are visible here too
        // (matches /get_address_spaces). multiSpace is computed BEFORE the
        // append so it continues to reflect physical ambiguity only.
        addressSpaces.addAll(overlaySpaces);

        Map<String, Object> info = new java.util.LinkedHashMap<>();
        info.put("name", program.getName());
        info.put("path", program.getDomainFile().getPathname());
        info.put("executable_path", program.getExecutablePath() != null ? program.getExecutablePath() : "");
        info.put("executable_format", program.getExecutableFormat());
        info.put("language", program.getLanguageID().getIdAsString());
        info.put("compiler", program.getCompilerSpec().getCompilerSpecID().getIdAsString());
        info.put("address_size", program.getAddressFactory().getDefaultAddressSpace().getSize());
        info.put("image_base", program.getImageBase().toString());
        info.put("min_address", program.getMinAddress() != null ? program.getMinAddress().toString() : "null");
        info.put("max_address", program.getMaxAddress() != null ? program.getMaxAddress().toString() : "null");
        info.put("memory_size", program.getMemory().getSize());
        info.put("function_count", program.getFunctionManager().getFunctionCount());
        info.put("symbol_count", program.getSymbolTable().getNumSymbols());
        info.put("data_type_count", program.getDataTypeManager().getDataTypeCount(true));
        info.put("creation_date", program.getCreationDate() != null ? program.getCreationDate().toString() : "unknown");
        info.put("memory_block_count", program.getMemory().getBlocks().length);
        info.put("address_spaces", addressSpaces);
        info.put("has_multiple_address_spaces", multiSpace);
        info.put("has_overlay_spaces", !overlaySpaces.isEmpty());
        info.put("overlay_space_count", overlaySpaces.size());
        if (multiSpace) {
            info.put("address_space_warning",
                "This program has multiple physical address spaces. Plain hex addresses will resolve "
                + "to the default space and may be incorrect. Use <space>:<hex> format (e.g., mem:1000) "
                + "or call get_address_spaces first.");
        } else if (!overlaySpaces.isEmpty()) {
            info.put("address_space_warning",
                "This program has overlay address spaces. Overlay addresses must be qualified as "
                + "<overlay>::<hex> (e.g., " + overlaySpaces.get(0).get("name") + "::<hex>) — overlay "
                + "names are case-sensitive. Plain hex resolves to the default physical space.");
        }
        return Response.ok(info);
    }

    /**
     * Switch MCP context to a different open program by name.
     */
    @McpTool(path = "/switch_program", description = "Switch MCP context to a different program", category = "program")
    public Response switchProgram(
            @Param(value = "program", description = "Program name to switch to") String programName) {
        if (programName == null || programName.trim().isEmpty()) {
            return Response.err("Program name is required");
        }

        Program[] programs = programProvider.getAllOpenPrograms();
        if (programs == null || programs.length == 0) {
            return Response.err("No programs are currently open");
        }

        Program targetProgram = null;

        // Find program by name (case-insensitive match)
        for (Program prog : programs) {
            if (prog.getName().equalsIgnoreCase(programName.trim())) {
                targetProgram = prog;
                break;
            }
        }

        // If not found by exact name, try partial match on path
        if (targetProgram == null) {
            for (Program prog : programs) {
                if (prog.getDomainFile().getPathname().toLowerCase().contains(programName.toLowerCase())) {
                    targetProgram = prog;
                    break;
                }
            }
        }

        if (targetProgram == null) {
            List<String> availablePrograms = new ArrayList<>();
            for (Program prog : programs) {
                availablePrograms.add(prog.getName());
            }
            return Response.ok(JsonHelper.mapOf(
                "error", "Program not found: " + programName,
                "available_programs", availablePrograms
            ));
        }

        // Switch to the target program
        programProvider.setCurrentProgram(targetProgram);

        return Response.ok(JsonHelper.mapOf(
            "success", true,
            "switched_to", targetProgram.getName(),
            "path", targetProgram.getDomainFile().getPathname()
        ));
    }

    /**
     * List all files in the current Ghidra project.
     */
    @McpTool(path = "/list_project_files", description = "List files in the current project", category = "program")
    public Response listProjectFiles(
            @Param(value = "folder", description = "Project folder path") String folderPath) {
        PluginTool tool = getToolFromProvider();
        if (tool == null) {
            return Response.err("Project listing requires GUI mode (PluginTool not available)");
        }

        ghidra.framework.model.Project project = tool.getProject();
        if (project == null) {
            return Response.err("No project is currently open");
        }

        ghidra.framework.model.ProjectData projectData = project.getProjectData();
        ghidra.framework.model.DomainFolder rootFolder = projectData.getRootFolder();

        // If folder path specified, navigate to it
        ghidra.framework.model.DomainFolder targetFolder = rootFolder;
        if (folderPath != null && !folderPath.trim().isEmpty() && !folderPath.equals("/")) {
            // Navigate through path segments (handles nested folders like "LoD/1.07")
            String cleanPath = folderPath.startsWith("/") ? folderPath.substring(1) : folderPath;
            String[] pathParts = cleanPath.split("/");
            for (String part : pathParts) {
                if (part.isEmpty()) continue;
                ghidra.framework.model.DomainFolder nextFolder = targetFolder.getFolder(part);
                if (nextFolder == null) {
                    return Response.err("Folder not found: " + folderPath);
                }
                targetFolder = nextFolder;
            }
        }

        // List subfolders
        ghidra.framework.model.DomainFolder[] subfolders = targetFolder.getFolders();
        List<String> folderNames = new ArrayList<>();
        for (ghidra.framework.model.DomainFolder subfolder : subfolders) {
            folderNames.add(subfolder.getName());
        }

        // List files in folder
        ghidra.framework.model.DomainFile[] files = targetFolder.getFiles();
        List<Map<String, Object>> fileList = new ArrayList<>();
        for (ghidra.framework.model.DomainFile file : files) {
            fileList.add(JsonHelper.mapOf(
                "name", file.getName(),
                "path", file.getPathname(),
                "content_type", file.getContentType(),
                "version", file.getVersion(),
                "is_read_only", file.isReadOnly(),
                "is_versioned", file.isVersioned()
            ));
        }

        return Response.ok(JsonHelper.mapOf(
            "project_name", project.getName(),
            "current_folder", targetFolder.getPathname(),
            "folders", folderNames,
            "files", fileList
        ));
    }

    @McpTool(path = "/create_folder", method = "POST", description = "Create a folder in the project", category = "project")
    public Response createFolder(
            @Param(value = "path", source = ParamSource.BODY, description = "Project folder path to create") String folderPath,
            @Param(value = "program", description = "Target program name", defaultValue = "") String programName) {
        PluginTool tool = getToolFromProvider();
        if (tool == null) {
            return Response.err("Folder creation requires GUI mode (PluginTool not available)");
        }
        ghidra.framework.model.Project project = tool.getProject();
        if (project == null) {
            return Response.err("No project is currently open");
        }
        if (folderPath == null || folderPath.trim().isEmpty() || folderPath.equals("/")) {
            return Response.err("path parameter is required");
        }
        // Containment: honor GHIDRA_MCP_PROJECT_FOLDER for this mutating op.
        // No-op when no scope is set (default).
        if (!SecurityConfig.getInstance().isPathInProjectScope(folderPath)) {
            return Response.err("Access denied: path is outside the configured project scope.");
        }

        try {
            ghidra.framework.model.DomainFolder current = project.getProjectData().getRootFolder();
            String cleanPath = folderPath.startsWith("/") ? folderPath.substring(1) : folderPath;
            for (String part : cleanPath.split("/")) {
                if (part.isEmpty()) continue;
                ghidra.framework.model.DomainFolder next = current.getFolder(part);
                if (next == null) {
                    next = current.createFolder(part);
                }
                current = next;
            }
            return Response.ok(JsonHelper.mapOf("success", true, "folder", current.getPathname()));
        } catch (Exception e) {
            return Response.err("Failed to create folder: " + e.getMessage());
        }
    }

    @McpTool(path = "/delete_file", method = "POST", description = "Delete a file from the project", category = "project")
    public Response deleteFile(
            @Param(value = "filePath", source = ParamSource.BODY, description = "Project file path to delete") String filePath) {
        PluginTool tool = getToolFromProvider();
        if (tool == null) {
            return Response.err("File deletion requires GUI mode (PluginTool not available)");
        }
        ghidra.framework.model.Project project = tool.getProject();
        if (project == null) {
            return Response.err("No project is currently open");
        }
        if (filePath == null || filePath.trim().isEmpty()) {
            return Response.err("filePath parameter is required");
        }
        // Containment: a destructive op must honor GHIDRA_MCP_PROJECT_FOLDER.
        // The read side (FrontEndProgramProvider) already scopes which programs
        // are returned; without this check a caller could delete files outside
        // the configured scope. No-op when no scope is set (default).
        if (!SecurityConfig.getInstance().isPathInProjectScope(filePath)) {
            return Response.err("Access denied: path is outside the configured project scope.");
        }

        try {
            ghidra.framework.model.DomainFile domainFile = project.getProjectData().getFile(filePath);
            if (domainFile == null) {
                return Response.ok(JsonHelper.mapOf("success", true, "deleted", false, "filePath", filePath));
            }
            closeOpenProgramForFile(tool, filePath);
            domainFile.delete();
            return Response.ok(JsonHelper.mapOf("success", true, "deleted", true, "filePath", filePath));
        } catch (Exception e) {
            return Response.err("Failed to delete file: " + e.getMessage());
        }
    }

    /**
     * Resolve the active project across GUI, FrontEnd and headless modes.
     *
     * <p>GUI/FrontEnd reach it through the PluginTool; headless has no tool at
     * all and answers via {@link ProgramProvider#getProject()}. Project-level
     * tools must go through here rather than {@code getToolFromProvider()},
     * which returns null headless and would make them GUI-only.
     */
    private ghidra.framework.model.Project resolveProject() {
        PluginTool tool = getToolFromProvider();
        if (tool != null && tool.getProject() != null) {
            return tool.getProject();
        }
        return programProvider.getProject();
    }

    /** True if any open program is backed by the given project file path. */
    private boolean isProgramOpenForPath(String filePath) {
        for (Program prog : programProvider.getAllOpenPrograms()) {
            ghidra.framework.model.DomainFile df = prog.getDomainFile();
            if (df != null && df.getPathname().equalsIgnoreCase(filePath)) {
                return true;
            }
        }
        return false;
    }

    @McpTool(path = "/move_file", method = "POST",
             description = "Move a program file to a different folder in the project, preserving all "
                         + "analysis and documentation. Refuses when the program has unsaved changes "
                         + "-- call save_program first -- rather than discarding them. A program that "
                         + "is open but clean is closed, moved, then reopened at its new path.",
             category = "project")
    public Response moveFile(
            @Param(value = "filePath", source = ParamSource.BODY,
                   description = "Project file path to move, e.g. /Vanilla/1.00/D2Server.dll") String filePath,
            @Param(value = "destFolder", source = ParamSource.BODY,
                   description = "Destination project folder path, e.g. /Mods/PD2-S12") String destFolder) {
        ghidra.framework.model.Project project = resolveProject();
        if (project == null) {
            return Response.err("No project is currently open");
        }
        if (filePath == null || filePath.trim().isEmpty()) {
            return Response.err("filePath parameter is required");
        }
        if (destFolder == null || destFolder.trim().isEmpty()) {
            return Response.err("destFolder parameter is required");
        }
        // Containment: a move is a delete from one scope plus a create in
        // another, so BOTH ends must sit inside GHIDRA_MCP_PROJECT_FOLDER.
        // Checking only the source would let a caller relocate a scoped file
        // straight out of scope. No-op when no scope is set (default).
        if (!SecurityConfig.getInstance().isPathInProjectScope(filePath)
                || !SecurityConfig.getInstance().isPathInProjectScope(destFolder)) {
            return Response.err("Access denied: path is outside the configured project scope.");
        }

        try {
            ghidra.framework.model.ProjectData projectData = project.getProjectData();
            ghidra.framework.model.DomainFile domainFile = projectData.getFile(filePath);
            if (domainFile == null) {
                return Response.err("File not found: " + filePath);
            }
            ghidra.framework.model.DomainFolder dest = projectData.getFolder(destFolder);
            if (dest == null) {
                return Response.err("Destination folder not found: " + destFolder);
            }
            ghidra.framework.model.DomainFolder parent = domainFile.getParent();
            if (parent != null && parent.getPathname().equals(dest.getPathname())) {
                return Response.ok(JsonHelper.mapOf(
                        "success", true, "moved", false,
                        "reason", "already in destination folder",
                        "filePath", domainFile.getPathname()));
            }
            if (dest.getFile(domainFile.getName()) != null) {
                return Response.err("Destination already contains a file named " + domainFile.getName()
                        + " -- rename or remove it first");
            }
            // Never move on top of unsaved work. moveTo() would either fail or
            // strand edits the caller still believes are pending, and saving on
            // their behalf is equally wrong: an unreviewed autosave is not a
            // side effect "move" should have. Refuse, and say what to do.
            if (domainFile.isChanged()) {
                return Response.err("Program has unsaved changes: call save_program "
                        + "(or close_program) before moving " + filePath);
            }

            boolean wasOpen = isProgramOpenForPath(filePath);
            if (wasOpen) {
                // Ghidra refuses to move a file that is open in a tool. It is
                // clean (checked above), so save=false discards nothing.
                closeProgram(filePath, false);
                // The close can swap the DomainFile instance out from under us.
                domainFile = projectData.getFile(filePath);
                if (domainFile == null) {
                    return Response.err("File vanished while closing it: " + filePath);
                }
            }
            // moveTo returns the RELOCATED DomainFile. The receiver keeps
            // reporting its old pathname, so reading getPathname() off it
            // reports a destination the file is not at -- measured live: a
            // successful move to /Mods/PD2-S12 still answered
            // "to": "/Vanilla/1.00/D2Server.dll". Anything chaining on that
            // path then operates on a file that no longer exists there.
            ghidra.framework.model.DomainFile movedFile = domainFile.moveTo(dest);
            String newPath = movedFile != null ? movedFile.getPathname()
                    : dest.getPathname() + "/" + domainFile.getName();
            boolean reopened = false;
            if (wasOpen) {
                reopened = openProgramFromProject(newPath, false) instanceof Response.Ok;
            }
            return Response.ok(JsonHelper.mapOf(
                    "success", true, "moved", true,
                    "from", filePath, "to", newPath,
                    "was_open", wasOpen, "reopened", reopened));
        } catch (Exception e) {
            return Response.err("Failed to move file: " + e.getMessage());
        }
    }

    @McpTool(path = "/move_folder", method = "POST",
             description = "Move a project folder (and everything under it) into another folder. "
                         + "Refuses to move a folder into itself or into its own descendant, which "
                         + "would orphan the subtree.",
             category = "project")
    public Response moveFolder(
            @Param(value = "sourcePath", source = ParamSource.BODY,
                   description = "Project folder path to move, e.g. /Vanilla/1.00") String sourcePath,
            @Param(value = "destPath", source = ParamSource.BODY,
                   description = "Destination parent folder path, e.g. /Mods") String destPath) {
        ghidra.framework.model.Project project = resolveProject();
        if (project == null) {
            return Response.err("No project is currently open");
        }
        if (sourcePath == null || sourcePath.trim().isEmpty()) {
            return Response.err("sourcePath parameter is required");
        }
        if (destPath == null || destPath.trim().isEmpty()) {
            return Response.err("destPath parameter is required");
        }
        if (!SecurityConfig.getInstance().isPathInProjectScope(sourcePath)
                || !SecurityConfig.getInstance().isPathInProjectScope(destPath)) {
            return Response.err("Access denied: path is outside the configured project scope.");
        }

        try {
            ghidra.framework.model.ProjectData projectData = project.getProjectData();
            ghidra.framework.model.DomainFolder source = projectData.getFolder(sourcePath);
            if (source == null) {
                return Response.err("Source folder not found: " + sourcePath);
            }
            if (source.getParent() == null) {
                return Response.err("Cannot move the project root folder");
            }
            ghidra.framework.model.DomainFolder dest = projectData.getFolder(destPath);
            if (dest == null) {
                return Response.err("Destination folder not found: " + destPath);
            }
            // A folder cannot become its own ancestor. Ghidra's own error for
            // this is opaque, and the subtree is unreachable afterwards, so
            // catch it here where we can say what actually went wrong.
            String sourcePrefix = source.getPathname().endsWith("/")
                    ? source.getPathname() : source.getPathname() + "/";
            if (dest.getPathname().equals(source.getPathname())
                    || dest.getPathname().startsWith(sourcePrefix)) {
                return Response.err("Cannot move " + source.getPathname()
                        + " into itself or its own descendant " + dest.getPathname());
            }
            if (dest.getFolder(source.getName()) != null) {
                return Response.err("Destination already contains a folder named " + source.getName());
            }
            // Same trap as move_file: moveTo returns the RELOCATED folder and
            // the receiver keeps reporting its old pathname. Report the handle
            // Ghidra hands back, never the one we called through.
            ghidra.framework.model.DomainFolder movedFolder = source.moveTo(dest);
            String newPath = movedFolder != null ? movedFolder.getPathname()
                    : dest.getPathname() + "/" + source.getName();
            return Response.ok(JsonHelper.mapOf(
                    "success", true, "moved", true,
                    "from", sourcePath, "to", newPath));
        } catch (Exception e) {
            return Response.err("Failed to move folder: " + e.getMessage());
        }
    }

    private void closeOpenProgramForFile(PluginTool tool, String filePath) {
        if (programProvider instanceof MultiToolProgramProvider mtp) {
            mtp.closeProgramByPath(filePath);
            return;
        }
        // Close paths must NEVER spawn a CodeBrowser — there is nothing useful
        // we can close in a fresh tool. findExistingProgramManager returns null
        // if no CodeBrowser is running, in which case there is also nothing
        // open to close, so we just return.
        ProgramManager pm = findExistingProgramManager(tool);
        if (pm == null) {
            return;
        }
        for (Program prog : programProvider.getAllOpenPrograms()) {
            if (prog.getDomainFile() != null
                    && prog.getDomainFile().getPathname().equalsIgnoreCase(filePath)) {
                // ignoreChanges=true: this only runs to clear the way for
                // delete_file's delete() call right after, so there is
                // nothing worth saving. false would risk Ghidra's own
                // interactive "Save changes?" dialog, which blocks the Swing
                // event thread -- and with it every other MCP request -- until
                // a human dismisses it.
                pm.closeProgram(prog, true);
                return;
            }
        }
    }

    /**
     * Open a program from the current project by path.
     */
    public Response openProgramFromProject(String path) {
        return openProgramFromProject(path, false);
    }

    @McpTool(path = "/open_program", description = "Open a program from the current project", category = "program")
    public Response openProgramFromProject(
            @Param(value = "path", description = "Program path in project") String path,
            @Param(value = "auto_analyze", defaultValue = "false", description = "Run auto-analysis") boolean autoAnalyze) {
        if (path == null || path.trim().isEmpty()) {
            return Response.err("Program path is required");
        }

        PluginTool tool = getToolFromProvider();
        if (tool == null) {
            return Response.err("Opening programs requires GUI mode (PluginTool not available)");
        }

        ghidra.framework.model.Project project = tool.getProject();
        if (project == null) {
            return Response.err("No project is currently open");
        }

        ghidra.framework.model.ProjectData projectData = project.getProjectData();
        ghidra.framework.model.DomainFile domainFile = projectData.getFile(path);

        if (domainFile == null) {
            return Response.err("File not found in project: " + path);
        }

        // Check if already open
        Program[] openPrograms = programProvider.getAllOpenPrograms();
        for (Program prog : openPrograms) {
            if (prog.getDomainFile().getPathname().equals(path)) {
                // Already open, just switch to it
                try {
                    suppressAnalysisPrompt(prog);
                } catch (Exception e) {
                    Msg.warn(this, "Failed to save analysis prompt flags: " + e.getMessage());
                }
                programProvider.setCurrentProgram(prog);
                return Response.ok(JsonHelper.mapOf(
                    "success", true,
                    "message", "Program already open, switched to it",
                    "name", prog.getName(),
                    "path", path
                ));
            }
        }

        // Open the program
        try {
            // Find a ProgramManager from an existing CodeBrowser, or launch one
            ProgramManager pm = findOrCreateProgramManager(tool);
            if (pm == null) {
                return Response.err("Could not find or create a CodeBrowser tool");
            }

            Program program = (Program) domainFile.getDomainObject(
                tool, false, false, ghidra.util.task.TaskMonitor.DUMMY);
            if (program == null) {
                return Response.err("Failed to open program: " + path);
            }

            // getDomainObject registered US (tool) as a consumer. ProgramManager
            // takes its OWN consumer in openProgram below, so ours must be handed
            // back -- otherwise the DomainObject keeps a consumer forever and the
            // DomainFile stays permanently "in use": undoCheckout then fails with
            // "<name> is in use" and keeps failing until Ghidra restarts, while
            // close_program reports success with released_cache=false because
            // neither the ProgramManager nor the provider cache holds the stray
            // reference. Measured 2026-08-10: 140 exclusive checkouts stranded on
            // a shared project by a read-only verification sweep, clearable only
            // by restarting Ghidra.
            try {
                ghidra.program.util.GhidraProgramUtilities.markProgramNotToAskToAnalyze(program);

                boolean analyzed = false;
                if (autoAnalyze) {
                    analyzed = runAutoAnalysisAndPersistFlags(program, true);
                } else {
                    try {
                        suppressAnalysisPrompt(program);
                    } catch (Exception e) {
                        Msg.warn(this, "Failed to save analysis prompt flags: " + e.getMessage());
                    }
                }

                // Capture before releasing: after the release our only guarantee
                // that the Program is still alive is the ProgramManager's consumer.
                String programName = program.getName();
                int functionCount = program.getFunctionManager().getFunctionCount();

                // Open after the analysis flags are persisted so CodeBrowser does not prompt.
                Program finalProgram = program;
                SwingUtilities.invokeAndWait(() -> {
                    pm.openProgram(finalProgram);
                    pm.setCurrentProgram(finalProgram);
                });

                return Response.ok(JsonHelper.mapOf(
                    "success", true,
                    "message", "Program opened successfully",
                    "name", programName,
                    "path", path,
                    "auto_analyzed", analyzed,
                    "function_count", functionCount
                ));
            } finally {
                // Unconditional: on the failure paths nothing else holds the
                // program, so releasing is both correct and the only way the
                // checkout can ever be undone.
                program.release(tool);
            }
        } catch (Exception e) {
            return Response.err("Failed to open program: " + describeOpenFailure(e, path));
        }
    }

    /**
     * Turn an open failure into something the caller can act on.
     *
     * <p>A program built against an older SLEIGH language revision opens read-ONLY
     * but refuses a read-write open, surfacing here as a bare
     * {@code "Minor language change 4.6 -> 4.7"}. That names the symptom and not
     * the cure, and this code path cannot perform the cure itself: every
     * FrontEnd-side open passes {@code okToUpgrade=false}, and an upgrade also
     * needs an exclusive checkout. Point at the tool that does both.
     */
    public static String describeOpenFailure(Exception e, String path) {
        String message = e.getMessage() != null ? e.getMessage() : e.toString();
        if (message.contains("language change") || message.contains("older version of Ghidra")) {
            return message
                + " -- " + path + " was built against an older SLEIGH language revision than this"
                + " Ghidra ships, so it can only be opened read-only until it is upgraded."
                + " An upgrade requires an exclusive checkout and cannot be done from here."
                + " Run: python scripts/upgrade_project_language.py --apply --folder "
                + parentFolderOf(path);
        }
        return message;
    }

    private static String parentFolderOf(String path) {
        if (path == null) {
            return "/";
        }
        int lastSlash = path.lastIndexOf('/');
        return lastSlash > 0 ? path.substring(0, lastSlash) : "/";
    }

    // ========================================================================
    // Import & Analysis

    @McpTool(path = "/import_file", method = "POST",
            description = "Import a binary file from disk into the current Ghidra project and open it. "
                + "For raw firmware binaries, specify language (e.g. 'ARM:LE:32:Cortex') and optionally compiler_spec (e.g. 'default').",
            category = "program")
    public Response importFile(
            @Param(value = "file_path", source = ParamSource.BODY, description = "Absolute path to the binary file on disk") String filePath,
            @Param(value = "project_folder", source = ParamSource.BODY, defaultValue = "/", description = "Destination folder in the Ghidra project") String projectFolder,
            @Param(value = "language", source = ParamSource.BODY, defaultValue = "", description = "Language ID for raw binaries (e.g. 'ARM:LE:32:Cortex', 'x86:LE:64:default'). If omitted, auto-detect.") String languageId,
            @Param(value = "compiler_spec", source = ParamSource.BODY, defaultValue = "", description = "Compiler spec ID (e.g. 'default', 'gcc', 'windows'). If omitted, uses language default.") String compilerSpecId,
            @Param(value = "auto_analyze", source = ParamSource.BODY, defaultValue = "true", description = "Start auto-analysis after import") boolean autoAnalyze) {

        if (filePath == null || filePath.trim().isEmpty()) {
            return Response.err("file_path is required");
        }

        // Enforce GHIDRA_MCP_FILE_ROOT (when configured) for this filesystem-path endpoint,
        // matching the headless import path. No-op when the root is unset (paths accepted
        // as-is), so default localhost behavior is unchanged.
        SecurityConfig security = SecurityConfig.getInstance();
        java.nio.file.Path resolved = security.resolveWithinFileRoot(filePath);
        if (resolved == null) {
            return Response.err("Path is outside the allowed file root ("
                    + security.getFileRoot() + "): " + filePath);
        }

        File file = resolved.toFile();
        if (!file.exists()) {
            return Response.err("File not found: " + filePath);
        }

        PluginTool tool = getToolFromProvider();
        if (tool == null) {
            return Response.err("Import requires GUI mode (PluginTool not available)");
        }

        ghidra.framework.model.Project project = tool.getProject();
        if (project == null) {
            return Response.err("No project is currently open");
        }

        boolean hasLanguage = languageId != null && !languageId.isEmpty();

        try {
            MessageLog log = new MessageLog();
            Program program;

            if (hasLanguage) {
                // Resolve language and compiler spec
                ghidra.program.model.lang.LanguageService langService =
                    ghidra.program.util.DefaultLanguageService.getLanguageService();
                ghidra.program.model.lang.Language language = langService.getLanguage(
                    new ghidra.program.model.lang.LanguageID(languageId));

                ghidra.program.model.lang.CompilerSpec compilerSpec;
                if (compilerSpecId != null && !compilerSpecId.isEmpty()) {
                    compilerSpec = language.getCompilerSpecByID(
                        new ghidra.program.model.lang.CompilerSpecID(compilerSpecId));
                } else {
                    compilerSpec = language.getDefaultCompilerSpec();
                }

                // Import as raw binary with explicit language/compiler spec
                ghidra.app.util.opinion.Loaded<Program> loaded = AutoImporter.importAsBinary(
                    file, project, projectFolder, language, compilerSpec,
                    this, log, ghidra.util.task.TaskMonitor.DUMMY);

                if (loaded == null) {
                    return Response.err("Import failed: no results. Log: " + log);
                }
                // getDomainObject(consumer) registers us as a consumer so the program stays open
                program = loaded.getDomainObject(this);
                if (program == null) {
                    return Response.err("Import failed: no primary program. Log: " + log);
                }
                // Save to project folder (creates DomainFile)
                loaded.save(ghidra.util.task.TaskMonitor.DUMMY);
            } else {
                // Auto-detect format
                LoadResults<Program> loadResults = AutoImporter.importByUsingBestGuess(
                    file, project, projectFolder,
                    this, log, ghidra.util.task.TaskMonitor.DUMMY);

                if (loadResults == null) {
                    return Response.err("Import failed: no load spec found. Specify 'language' for raw binaries. Log: " + log);
                }
                program = loadResults.getPrimaryDomainObject();
                if (program == null) {
                    return Response.err("Import failed: no primary program. Log: " + log);
                }
                // Save to project folder before releasing (prevents "Database is closed")
                loadResults.save(ghidra.util.task.TaskMonitor.DUMMY);
            }

            // NOTE: do NOT call markProgramNotToAskToAnalyze here, ahead of the
            // branches below. It mutates the program DB, and AutoAnalysisManager's
            // own DomainObjectListener reacts to *any* program change by scheduling
            // a background "Auto Analysis" task (the same mechanism documented on
            // saveWithRetry above) -- confirmed root cause of a real, intermittent
            // bug: that premature background pass could already be "actively
            // running" by the time runAutoAnalysisAndPersistFlags below called its
            // own startAnalysis(), which per its own javadoc is then a no-op
            // ("if actively running... return immediately"), leaving
            // waitForAnalysis() to wait on whatever partial pass Ghidra's own
            // listener decided to run instead of the real one. Reproduced live:
            // a fresh import came back with function_count 9 instead of 530, with
            // analyzed:true and no error anywhere. Both branches below already set
            // this flag themselves, inside their own transaction, so the call here
            // was pure redundant risk with no benefit.

            boolean autoAnalyzed = false;
            if (autoAnalyze) {
                // force=true (reAnalyzeAll first): unconditionally re-queues every
                // analyzer regardless of anything Ghidra's own listeners may have
                // already scheduled, closing the race described above. Matches
                // /reanalyze, which has never shown this symptom.
                autoAnalyzed = runAutoAnalysisAndPersistFlags(program, true);
            } else {
                try {
                    suppressAnalysisPrompt(program);
                } catch (Exception e) {
                    Msg.warn(this, "Failed to save analysis prompt flags: " + e.getMessage());
                }
            }

            // Open after the analysis flags are persisted so CodeBrowser does not prompt.
            ProgramManager pm = findOrCreateProgramManager(tool);
            if (pm == null) {
                return Response.err("Could not find or create a CodeBrowser tool");
            }

            Program finalProgram = program;
            SwingUtilities.invokeAndWait(() -> {
                pm.openProgram(finalProgram);
                pm.setCurrentProgram(finalProgram);
            });

            return Response.ok(JsonHelper.mapOf(
                "success", true,
                "name", program.getName(),
                "path", program.getDomainFile().getPathname(),
                "language", program.getLanguageID().getIdAsString(),
                "analyzing", false,
                "auto_analyzed", autoAnalyzed
            ));
        } catch (Exception e) {
            String msg = e.getMessage();
            if (msg == null || msg.isEmpty()) {
                msg = e.getClass().getName();
                // Include cause if available
                if (e.getCause() != null) {
                    msg += ": " + (e.getCause().getMessage() != null
                        ? e.getCause().getMessage() : e.getCause().getClass().getName());
                }
            }
            Msg.error(this, "Import failed", e);
            return Response.err("Import failed: " + msg);
        }
    }

    @McpTool(path = "/reanalyze", method = "POST", description = "Trigger full auto-analysis on a program", category = "program")
    public Response reanalyze(
            @Param(value = "program", defaultValue = "", description = "Program name (default: current program)") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        try {
            boolean analyzed = runAutoAnalysisAndPersistFlags(program, true);
            return Response.ok(JsonHelper.mapOf(
                "success", analyzed,
                "name", program.getName(),
                "analyzing", false,
                "message", analyzed ? AUTO_ANALYSIS_COMPLETION_MESSAGE + " for " + program.getName()
                    : "Auto-analysis failed for " + program.getName()
            ));
        } catch (Exception e) {
            return Response.err("Failed to start analysis: " + e.getMessage());
        }
    }

    @McpTool(path = "/analysis_status", description = "Get auto-analysis status for open programs", category = "program")
    public Response analysisStatus(
            @Param(value = "program", description = "Program name (omit for all open programs)") String programName) {

        Program[] allPrograms = programProvider.getAllOpenPrograms();
        if (allPrograms == null || allPrograms.length == 0) {
            return Response.err("No programs are currently open");
        }

        List<Map<String, Object>> results = new ArrayList<>();
        for (Program prog : allPrograms) {
            if (programName != null && !programName.isEmpty() && !programMatches(prog, programName)) {
                continue;
            }
            boolean analyzing = false;
            boolean analyzed = false;
            boolean shouldAskToAnalyze = false;
            try {
                AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(prog);
                analyzing = mgr.isAnalyzing();
                analyzed = ghidra.program.util.GhidraProgramUtilities.isAnalyzed(prog);
                shouldAskToAnalyze = ghidra.program.util.GhidraProgramUtilities.shouldAskToAnalyze(prog);
            } catch (Exception e) {
                // May not have an analysis manager in headless mode
            }
            results.add(JsonHelper.mapOf(
                "name", prog.getName(),
                "analyzing", analyzing,
                "analyzed", analyzed,
                "should_ask_to_analyze", shouldAskToAnalyze,
                "function_count", prog.getFunctionManager().getFunctionCount()
            ));
        }

        if (programName != null && !programName.isEmpty() && results.isEmpty()) {
            return Response.err("Program not found: " + programName);
        }

        if (results.size() == 1) {
            return Response.ok(results.get(0));
        }
        return Response.ok(JsonHelper.mapOf("programs", results));
    }

    private boolean programMatches(Program prog, String programName) {
        if (prog == null || programName == null || programName.isEmpty()) {
            return true;
        }
        String searchName = programName.trim();
        if (prog.getName().equalsIgnoreCase(searchName)) {
            return true;
        }
        if (prog.getDomainFile() != null) {
            String path = prog.getDomainFile().getPathname();
            return path.equalsIgnoreCase(searchName) || path.toLowerCase().contains(searchName.toLowerCase());
        }
        return false;
    }

    // ========================================================================
    // Script Execution
    private List<ProgramManager> findAllProgramManagers() {
        List<ProgramManager> managers = new ArrayList<>();
        Set<PluginTool> seen = Collections.newSetFromMap(new IdentityHashMap<>());

        PluginTool activeTool = getToolFromProvider();
        if (activeTool != null) {
            seen.add(activeTool);
            ProgramManager pm = activeTool.getService(ProgramManager.class);
            if (pm != null) {
                managers.add(pm);
            }

            try {
                ghidra.framework.model.Project project = activeTool.getProject();
                if (project != null) {
                    ghidra.framework.model.ToolManager tm = project.getToolManager();
                    if (tm != null) {
                        for (PluginTool runningTool : tm.getRunningTools()) {
                            if (!seen.add(runningTool)) {
                                continue;
                            }
                            ProgramManager runningPm = runningTool.getService(ProgramManager.class);
                            if (runningPm != null) {
                                managers.add(runningPm);
                            }
                        }
                    }
                }
            } catch (Exception e) {
                Msg.warn(this, "Error scanning for ProgramManager services: " + e.getMessage());
            }
        }

        if (programProvider instanceof MultiToolProgramProvider mtp) {
            ProgramManager pm = mtp.findProgramManager();
            if (pm != null && !managers.contains(pm)) {
                managers.add(pm);
            }
        }
        return managers;
    }

    /**
     * Find an existing ProgramManager without spawning a new CodeBrowser.
     * Returns null when no CodeBrowser is currently running and exposing
     * ProgramManager. Use this from close paths and other operations that
     * have nothing useful to do in a freshly-spawned empty tool.
     */
    private ProgramManager findExistingProgramManager(PluginTool tool) {
        ProgramManager pm = tool.getService(ProgramManager.class);
        if (pm != null) return pm;

        if (programProvider instanceof MultiToolProgramProvider mtp) {
            pm = mtp.findProgramManager();
            if (pm != null) return pm;
        }

        ghidra.framework.model.Project project = tool.getProject();
        if (project == null) return null;
        ghidra.framework.model.ToolManager tm = project.getToolManager();
        if (tm == null) return null;
        try {
            for (PluginTool running : tm.getRunningTools()) {
                if (running == tool) continue;
                ProgramManager rpm = running.getService(ProgramManager.class);
                if (rpm != null) return rpm;
            }
        } catch (Exception e) {
            Msg.warn(this, "Error scanning running tools for ProgramManager: " + e.getMessage());
        }
        return null;
    }

    /**
     * Find an existing ProgramManager or launch a new CodeBrowser to get one.
     *
     * <p>Resolution order matters for window hygiene: when GhidraMCPPlugin lives
     * in the FrontEnd tool, the FrontEnd has no ProgramManager and the
     * MultiToolProgramProvider check is only relevant to that provider — never
     * the case under FrontEndProgramProvider. Without scanning running tools
     * first, every /open_program and /import_file call would fall through to
     * ws.runTool and accumulate a fresh CodeBrowser per call. The scan reuses
     * any existing CodeBrowser so additional programs open as tabs in it.
     */
    private ProgramManager findOrCreateProgramManager(PluginTool tool) {
        ProgramManager pm = findExistingProgramManager(tool);
        if (pm != null) return pm;

        // No CodeBrowser is up — spawn one. This should be rare in practice;
        // it covers genuinely-headless-style sessions where no GUI tool is up.
        ghidra.framework.model.Project project = tool.getProject();
        try {
            if (project != null) {
                ghidra.framework.model.ToolManager tm = project.getToolManager();
                if (tm != null) {
                    ghidra.framework.model.ToolTemplate template =
                        project.getLocalToolChest().getToolTemplate("CodeBrowser");
                    if (template != null) {
                        ghidra.framework.model.Workspace ws = tm.getActiveWorkspace();
                        PluginTool newTool = ws.runTool(template);
                        if (newTool != null) {
                            pm = newTool.getService(ProgramManager.class);
                            if (pm != null) return pm;
                        }
                    }
                }
            }
        } catch (Exception e) {
            Msg.warn(this, "Failed to launch CodeBrowser: " + e.getMessage());
        }

        return null;
    }

    // ========================================================================

    /**
     * Execute a Ghidra script by path with optional arguments.
     *
     * @param scriptPath Path to the script file
     * @param scriptArgs Optional space-separated arguments for the script
     * @return Script output or error message
     */
    public Response runGhidraScript(String scriptPath, String scriptArgs) {
        return runGhidraScript(scriptPath, scriptArgs, (String) null);
    }

    // Removed from MCP schema — use run_ghidra_script instead (has output capture + timeout)
    public Response runGhidraScript(
            @Param(value = "script_path", source = ParamSource.BODY) String scriptPath,
            @Param(value = "args", source = ParamSource.BODY, defaultValue = "") String scriptArgs,
            @Param(value = "program", description = "Target program name", defaultValue = "") String programName) {
        return runGhidraScript(scriptPath, scriptArgs, programName, 0);
    }

    public Response runGhidraScript(String scriptPath, String scriptArgs, String programName, int timeoutSeconds) {
        // Defense in depth: the script-execution gate belongs on the sink, not
        // only on the callers. runGhidraScriptWithCapture already checks this
        // before delegating here; enforcing it again means no current or future
        // caller (including any re-wired /run_script route) can reach arbitrary
        // Ghidra script execution with GHIDRA_MCP_ALLOW_SCRIPTS unset.
        if (!SecurityConfig.getInstance().areScriptsAllowed()) {
            return Response.err("Script execution disabled. Set GHIDRA_MCP_ALLOW_SCRIPTS=1 "
                + "(and GHIDRA_MCP_AUTH_TOKEN if exposing beyond loopback) to enable. "
                + "runGhidraScript executes any script resolvable via the Ghidra script path.");
        }
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        final StringBuilder resultMsg = new StringBuilder();
        final AtomicBoolean success = new AtomicBoolean(false);
        final ByteArrayOutputStream outputCapture = new ByteArrayOutputStream();
        final PrintStream originalOut = System.out;
        final PrintStream originalErr = System.err;

        // Track whether we copied the script (for cleanup)
        final File[] copiedScript = {null};

        // Holders so the catch block can surface OSGi build/activate output
        // captured into scriptWriter before a failure. The PrintWriter holder
        // lets the failure path flush buffered output into the StringWriter
        // before reading it, otherwise the captured text can be truncated.
        final StringWriter[] scriptWriterHolder = {null};
        final PrintWriter[] scriptPrintWriterHolder = {null};
        final TimeoutTaskMonitor[] scriptMonitorHolder = {null};

        // Get the PluginTool for script state (GUI mode only)
        final PluginTool pluginTool = getToolFromProvider();

        try {
            SwingUtilities.invokeAndWait(() -> {
                StringWriter scriptWriter = new StringWriter();
                try {
                    // Capture console output
                    PrintStream captureStream = new PrintStream(outputCapture);
                    System.setOut(captureStream);
                    System.setErr(captureStream);

                    resultMsg.append("=== GHIDRA SCRIPT EXECUTION ===\n");
                    resultMsg.append("Script: ").append(scriptPath).append("\n");
                    resultMsg.append("Program: ").append(program.getName()).append("\n");
                    resultMsg.append("Time: ").append(new Date().toString()).append("\n\n");

                    // Resolve script file - search standard locations
                    File ghidraScriptsDir = new File(System.getProperty("user.home"), "ghidra_scripts");
                    String[] possiblePaths = {
                        scriptPath,  // Absolute or relative path as-is
                        new File(ghidraScriptsDir, scriptPath).getPath(),
                        new File(ghidraScriptsDir, new File(scriptPath).getName()).getPath(),
                        "./ghidra_scripts/" + scriptPath,
                        "./ghidra_scripts/" + new File(scriptPath).getName()
                    };

                    File resolvedFile = null;
                    for (String p : possiblePaths) {
                        try {
                            File candidate = new File(p);
                            if (candidate.exists() && candidate.isFile()) {
                                resolvedFile = candidate;
                                break;
                            }
                        } catch (Exception e) {
                            // Continue
                        }
                    }

                    if (resolvedFile == null) {
                        resultMsg.append("ERROR: Script file not found. Searched:\n");
                        for (String p : possiblePaths) {
                            resultMsg.append("  - ").append(p).append("\n");
                        }
                        return;
                    }

                    // Issue #2 fix: If the script is NOT already in ~/ghidra_scripts/,
                    // copy it there so Ghidra's OSGi class loader can find the source bundle.
                    File scriptFileForExecution = resolvedFile;
                    try {
                        ghidraScriptsDir.mkdirs();
                        String canonicalScriptsDir = ghidraScriptsDir.getCanonicalPath();
                        String canonicalResolved = resolvedFile.getCanonicalPath();
                        if (!canonicalResolved.startsWith(canonicalScriptsDir + File.separator)) {
                            // Copy to ~/ghidra_scripts/
                            File dest = new File(ghidraScriptsDir, resolvedFile.getName());
                            java.nio.file.Files.copy(resolvedFile.toPath(), dest.toPath(),
                                java.nio.file.StandardCopyOption.REPLACE_EXISTING);
                            scriptFileForExecution = dest;
                            copiedScript[0] = dest;
                            resultMsg.append("Copied to: ").append(dest.getAbsolutePath()).append("\n");
                        }
                    } catch (Exception e) {
                        resultMsg.append("Warning: Could not copy script to ~/ghidra_scripts/: ").append(e.getMessage()).append("\n");
                    }

                    try {
                        ensureScriptBundleHostInitialized(scriptFileForExecution.getParentFile());
                    } catch (Exception e) {
                        resultMsg.append("ERROR: Could not initialize Ghidra script bundle host for: ")
                                .append(scriptFileForExecution.getParentFile().getAbsolutePath())
                                .append("\n")
                                .append(e.getClass().getSimpleName())
                                .append(": ")
                                .append(e.getMessage())
                                .append("\n");
                        return;
                    }

                    generic.jar.ResourceFile scriptFile = new generic.jar.ResourceFile(scriptFileForExecution);

                    resultMsg.append("Found script: ").append(scriptFile.getAbsolutePath()).append("\n");
                    resultMsg.append("Size: ").append(scriptFile.length()).append(" bytes\n\n");

                    // Get script provider
                    ghidra.app.script.GhidraScriptProvider provider = ghidra.app.script.GhidraScriptUtil.getProvider(scriptFile);
                    if (provider == null) {
                        resultMsg.append("ERROR: No script provider found for: ").append(scriptFile.getName()).append("\n");
                        if (scriptFile.getName().toLowerCase(java.util.Locale.ROOT).endsWith(".py")) {
                            resultMsg.append("Ghidra 12.1 ships Jython as an optional extension. ")
                                    .append("Install the Jython extension from File > Install Extensions, ")
                                    .append("restart Ghidra, then refresh Script Manager before running .py scripts.\n");
                        }
                        return;
                    }

                    resultMsg.append("Script provider: ").append(provider.getClass().getSimpleName()).append("\n");

                    // Create script instance
                    PrintWriter scriptPrintWriter = new PrintWriter(scriptWriter);
                    scriptWriterHolder[0] = scriptWriter;
                    scriptPrintWriterHolder[0] = scriptPrintWriter;

                    ghidra.app.script.GhidraScript script = provider.getScriptInstance(scriptFile, scriptPrintWriter);
                    if (script == null) {
                        resultMsg.append("ERROR: Failed to create script instance\n");
                        return;
                    }

                    // Set up script state
                    ghidra.program.util.ProgramLocation location = new ghidra.program.util.ProgramLocation(program, program.getMinAddress());
                    ghidra.app.script.GhidraState scriptState;
                    if (pluginTool != null) {
                        scriptState = new ghidra.app.script.GhidraState(pluginTool, pluginTool.getProject(), program, location, null, null);
                    } else {
                        scriptState = new ghidra.app.script.GhidraState(null, null, program, location, null, null);
                    }

                    ghidra.util.task.TaskMonitor scriptMonitor;
                    if (timeoutSeconds > 0) {
                        TimeoutTaskMonitor timeoutMonitor = TimeoutTaskMonitor.timeoutIn(
                                timeoutSeconds,
                                TimeUnit.SECONDS,
                                new ConsoleTaskMonitor());
                        scriptMonitorHolder[0] = timeoutMonitor;
                        scriptMonitor = timeoutMonitor;
                    }
                    else {
                        scriptMonitor = new ConsoleTaskMonitor();
                    }

                    script.set(scriptState, scriptMonitor, scriptPrintWriter);

                    // Issue #1 + #5 fix: Parse and set script args BEFORE execution,
                    // so getScriptArgs() returns them instead of falling through to askString()
                    String[] args = new String[0];
                    if (scriptArgs != null && !scriptArgs.trim().isEmpty()) {
                        args = scriptArgs.trim().split("\\s+");
                        script.setScriptArgs(args);
                        resultMsg.append("Script args: ").append(Arrays.toString(args)).append("\n");
                    }

                    resultMsg.append("\n--- SCRIPT OUTPUT ---\n");

                    // Execute the script
                    script.runScript(scriptFile.getName(), args);

                    // Get script output
                    String scriptOutput = scriptWriter.toString();
                    if (!scriptOutput.isEmpty()) {
                        resultMsg.append(scriptOutput).append("\n");
                    }

                    success.set(true);
                    resultMsg.append("\n=== SCRIPT COMPLETED SUCCESSFULLY ===\n");

                } catch (Exception e) {
                    String scriptOutput = scriptWriter.toString();
                    if (!scriptOutput.isEmpty()) {
                        resultMsg.append("\n--- SCRIPT BUILD OUTPUT ---\n");
                        resultMsg.append(scriptOutput).append("\n");
                    }
                    resultMsg.append("\n=== SCRIPT EXECUTION ERROR ===\n");
                    resultMsg.append("Error: ").append(e.getClass().getSimpleName()).append(": ").append(e.getMessage()).append("\n");

                    StringWriter sw = new StringWriter();
                    PrintWriter pw = new PrintWriter(sw);
                    e.printStackTrace(pw);
                    resultMsg.append("Stack trace:\n").append(sw.toString()).append("\n");

                    // Surface any build/activate output that was captured into the
                    // script writer before the failure (e.g. OSGi/Felix compile
                    // errors from JavaScriptProvider.activateAll()). Flush the
                    // PrintWriter first so buffered text reaches the StringWriter,
                    // and bound the result so a verbose compiler failure can't
                    // blow up the response payload.
                    try {
                        PrintWriter pw2 = scriptPrintWriterHolder[0];
                        if (pw2 != null) {
                            pw2.flush();
                        }
                        StringWriter sw2 = scriptWriterHolder[0];
                        if (sw2 != null) {
                            String capturedBuild = sw2.toString();
                            if (!capturedBuild.isEmpty()) {
                                resultMsg.append("--- BUILD/ACTIVATE OUTPUT ---\n")
                                        .append(boundTail(capturedBuild, MAX_BUILD_OUTPUT_CHARS))
                                        .append("\n");
                            }
                        }
                    } catch (Throwable ignore) { /* scriptWriter may be unavailable */ }

                    Msg.error(this, "Script execution failed: " + scriptPath, e);
                } finally {
                    if (scriptMonitorHolder[0] != null) {
                        scriptMonitorHolder[0].cancel();
                    }
                    // Restore original output streams
                    System.setOut(originalOut);
                    System.setErr(originalErr);

                    // Append any captured console output
                    String capturedOutput = outputCapture.toString();
                    if (!capturedOutput.isEmpty()) {
                        resultMsg.append("\n--- CONSOLE OUTPUT ---\n");
                        resultMsg.append(capturedOutput).append("\n");
                    }

                    // Clean up copied script
                    if (copiedScript[0] != null) {
                        if (!copiedScript[0].delete()) {
                            copiedScript[0].deleteOnExit();
                        }
                    }
                }
            });
        } catch (Exception e) {
            resultMsg.append("ERROR: Failed to execute on Swing thread: ").append(e.getMessage()).append("\n");
            Msg.error(this, "Failed to execute on Swing thread", e);
        }

        return Response.ok(JsonHelper.mapOf(
                "success", success.get(),
                "console_output", resultMsg.toString()));
    }

    @McpTool(path = "/run_script_inline", method = "POST", description = "Execute inline Ghidra script code. Pass the full Java source as the 'code' body parameter. Gated by GHIDRA_MCP_ALLOW_SCRIPTS=1 (v5.4.1+).", category = "program")
    public Response runScriptInline(
            @Param(value = "code", source = ParamSource.BODY) String code,
            @Param(value = "args", source = ParamSource.BODY, defaultValue = "") String args,
            @Param(value = "program", description = "Target program name", defaultValue = "") String programName) {
        if (!SecurityConfig.getInstance().areScriptsAllowed()) {
            return Response.err("Script execution disabled. Set GHIDRA_MCP_ALLOW_SCRIPTS=1 "
                + "(and GHIDRA_MCP_AUTH_TOKEN if exposing beyond loopback) to enable. "
                + "/run_script_inline executes arbitrary Java against the Ghidra process.");
        }
        if (code == null || code.trim().isEmpty()) {
            return Response.err("code parameter required");
        }

        // Use unique class name per invocation so Ghidra recompiles each time.
        // If user provides their own class, extract its name for the filename.
        String className = "McpInline_" + Long.toHexString(System.nanoTime());
        java.util.regex.Matcher m = java.util.regex.Pattern
            .compile("public\\s+class\\s+(\\w+)").matcher(code);
        if (m.find()) {
            className = m.group(1);
        }

        // Write to ~/ghidra_scripts/ so OSGi classloader can find the source bundle
        File scriptsDir = new File(System.getProperty("user.home"), "ghidra_scripts");
        scriptsDir.mkdirs();

        // Pre-cleanup: remove stale McpInline_*.java files so Ghidra's per-directory
        // build state doesn't contaminate this run's output with old failures.
        //
        // Three cases handled:
        //  1. Oracle exists (McpInline_*.java_failed)  → confirmed failure from a
        //     previous run; delete both the .java and the oracle immediately.
        //  2. No oracle, file older than 60 s          → crash-orphaned (server died
        //     before the oracle could be written); delete as a safe fallback.
        //  3. No oracle, file is fresh                 → likely a concurrent parallel
        //     agent; leave it alone.
        // Also purge any orphaned oracles whose .java has already been deleted.
        long now = System.currentTimeMillis();
        File[] staleJava = scriptsDir.listFiles(
            (d, n) -> n.startsWith("McpInline_") && n.endsWith(".java"));
        if (staleJava != null) {
            for (File stale : staleJava) {
                File oracle = new File(scriptsDir, stale.getName() + "_failed");
                if (oracle.exists()) {
                    oracle.delete();
                    stale.delete();
                } else if (now - stale.lastModified() > 60_000L) {
                    stale.delete();
                }
            }
        }
        File[] orphanOracles = scriptsDir.listFiles(
            (d, n) -> n.startsWith("McpInline_") && n.endsWith(".java_failed"));
        if (orphanOracles != null) {
            for (File o : orphanOracles) {
                String javaName = o.getName().substring(0, o.getName().length() - "_failed".length());
                if (!new File(scriptsDir, javaName).exists()) o.delete();
            }
        }

        File tempScript = new File(scriptsDir, className + ".java");

        // Capture response so the finally block can decide success vs failure.
        Response[] responseHolder = {null};

        try {
            // If code doesn't contain a class definition, wrap it.
            // Hoist any import statements to file level so they don't land inside run().
            String scriptCode = code;
            if (!code.contains("extends GhidraScript")) {
                StringBuilder topImports = new StringBuilder("import ghidra.app.script.GhidraScript;\n");
                StringBuilder body = new StringBuilder();
                for (String line : code.split("\n", -1)) {
                    String stripped = line.stripLeading();
                    if (stripped.startsWith("import ") && stripped.endsWith(";")) {
                        topImports.append(stripped).append("\n");
                    } else {
                        body.append(line).append("\n");
                    }
                }
                scriptCode = topImports
                    + "public class " + className + " extends GhidraScript {\n"
                    + "    @Override\n"
                    + "    public void run() throws Exception {\n"
                    + body
                    + "    }\n"
                    + "}\n";
            }

            java.nio.file.Files.writeString(tempScript.toPath(), scriptCode);
            responseHolder[0] = runGhidraScript(tempScript.getAbsolutePath(), args, programName);
            return responseHolder[0];
        } catch (Exception e) {
            return Response.err("Failed to create inline script: " + e.getMessage());
        } finally {
            if (!tempScript.exists()) {
                // File was never written or was already cleaned up — nothing to do.
            } else {
                boolean succeeded = false;
                if (responseHolder[0] instanceof Response.Ok ok && ok.data() instanceof Map<?, ?> dataMap) {
                    succeeded = Boolean.TRUE.equals(dataMap.get("success"));
                }
                if (succeeded) {
                    // Clean run: remove the source file immediately.
                    if (!tempScript.delete()) tempScript.deleteOnExit();
                } else {
                    // Failed run: leave .java on disk for next run's pre-cleanup to remove
                    // (which will clear Ghidra's build-state entry for it), and write an
                    // oracle so that cleanup is instant rather than time-delayed.
                    try {
                        File oracle = new File(scriptsDir, className + ".java_failed");
                        String failureInfo = responseHolder[0] != null
                            ? responseHolder[0].toJson()
                            : "exception before script execution";
                        java.nio.file.Files.writeString(oracle.toPath(), failureInfo);
                    } catch (Exception oracleEx) {
                        // Oracle write failed; fall back to immediate deletion so the file
                        // doesn't linger forever without a matching oracle.
                        if (!tempScript.delete()) tempScript.deleteOnExit();
                    }
                }
            }
        }
    }

    /**
     * List available Ghidra scripts.
     *
     * @param filter Optional filter string to match script names
     * @return JSON list of available scripts
     */
    @McpTool(path = "/list_scripts", description = "List available Ghidra scripts", category = "program")
    public Response listGhidraScripts(
            @Param(value = "filter", description = "Script name filter", defaultValue = "") String filter) {
        final AtomicReference<Map<String, Object>> resultData = new AtomicReference<>();
        final AtomicReference<String> errorMsg = new AtomicReference<>();

        try {
            SwingUtilities.invokeAndWait(() -> {
                try {
                    resultData.set(JsonHelper.mapOf(
                        "note", "Script listing requires Ghidra GUI access",
                        "filter", filter != null ? filter : "none",
                        "instructions", List.of(
                            "To view available scripts:",
                            "1. Open Ghidra's Script Manager (Window -> Script Manager)",
                            "2. Browse scripts by category",
                            "3. Use the search filter at the top"
                        ),
                        "common_script_locations", List.of(
                            "<ghidra_install>/Ghidra/Features/*/ghidra_scripts/",
                            "<user_home>/ghidra_scripts/"
                        )
                    ));
                } catch (Exception e) {
                    errorMsg.set(e.getMessage());
                    Msg.error(this, "Error in list scripts handler", e);
                }
            });
        } catch (Exception e) {
            return Response.err("Failed to execute on Swing thread: " + e.getMessage());
        }

        if (errorMsg.get() != null) {
            return Response.err(errorMsg.get());
        }
        return resultData.get() != null ? Response.ok(resultData.get()) : Response.err("Unknown failure");
    }

    // ========================================================================
    // Memory Operations
    // ========================================================================

    /**
     * Read memory at a specific address.
     */
    @McpTool(path = "/read_memory", description = "Read raw memory bytes. Always pass the 'program' argument to target the correct binary — especially when multiple programs are open. On programs with multiple address spaces (e.g., embedded targets), prefix addresses with the space name (mem:1000) to avoid ambiguous resolution.", category = "program")
    public Response readMemory(
            @Param(value = "address", paramType = "address",
                   description = "Address in the program. Accepts 0x<hex> (default space) or <space>:<hex> "
                               + "(e.g., mem:1000, code:ff00). Note: some programs — particularly "
                               + "embedded/microcontroller targets — are not address-space-agnostic; "
                               + "use get_address_spaces to discover spaces before assuming a plain hex "
                               + "address is unambiguous.") String addressStr,
            @Param(value = "length", defaultValue = "16", description = "Number of bytes") int length,
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        try {
            ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
            if (pe.hasError()) return pe.error();
            Program program = pe.program();

            Address address = ServiceUtils.parseAddress(program, addressStr);
            if (address == null) {
                return Response.err(ServiceUtils.getLastParseError());
            }

            Memory memory = program.getMemory();
            int MAX_READ_BYTES = 16 * 1024 * 1024; // 16 MB safety limit
            if (length <= 0 || length > MAX_READ_BYTES) {
                return Response.err("length must be between 1 and " + MAX_READ_BYTES + " bytes");
            }
            byte[] bytes = new byte[length];

            int bytesRead = memory.getBytes(address, bytes);

            List<Integer> dataList = new ArrayList<>();
            StringBuilder hexStr = new StringBuilder();
            for (int i = 0; i < bytesRead; i++) {
                dataList.add(bytes[i] & 0xFF);
                hexStr.append(String.format("%02x", bytes[i] & 0xFF));
            }

            Map<String, Object> memResult = new LinkedHashMap<>();
            memResult.putAll(ServiceUtils.addressToJson(address, program));
            memResult.put("length", bytesRead);
            memResult.put("data", dataList);
            memResult.put("hex", hexStr.toString());
            return Response.ok(memResult);

        } catch (Exception e) {
            return Response.err("Failed to read memory: " + e.getMessage());
        }
    }

    /**
     * Create an uninitialized memory block (e.g., for MMIO/peripheral regions).
     */
    public Response createMemoryBlock(String name, String addressStr, long size,
                                     boolean read, boolean write, boolean execute,
                                     boolean isVolatile, String comment) {
        return createMemoryBlock(name, addressStr, size, read, write, execute, isVolatile, comment, null);
    }

    @McpTool(path = "/create_memory_block", method = "POST", description = "Create a new memory block. On programs with multiple address spaces (e.g., embedded targets), prefix addresses with the space name (mem:1000) to avoid ambiguous resolution.", category = "program")
    public Response createMemoryBlock(
            @Param(value = "name", source = ParamSource.BODY) String name,
            @Param(value = "address", paramType = "address", source = ParamSource.BODY,
                   description = "Address in the program. Accepts 0x<hex> (default space) or <space>:<hex> "
                               + "(e.g., mem:1000, code:ff00). Note: some programs — particularly "
                               + "embedded/microcontroller targets — are not address-space-agnostic; "
                               + "use get_address_spaces to discover spaces before assuming a plain hex "
                               + "address is unambiguous.") String addressStr,
            @Param(value = "size", source = ParamSource.BODY, defaultValue = "0") long size,
            @Param(value = "read", source = ParamSource.BODY, defaultValue = "true") boolean read,
            @Param(value = "write", source = ParamSource.BODY, defaultValue = "true") boolean write,
            @Param(value = "execute", source = ParamSource.BODY, defaultValue = "false") boolean execute,
            @Param(value = "volatile", source = ParamSource.BODY, defaultValue = "false") boolean isVolatile,
            @Param(value = "comment", source = ParamSource.BODY, defaultValue = "") String comment,
            @Param(value = "program", description = "Target program name", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        if (name == null || name.isEmpty()) {
            return Response.err("name parameter required");
        }
        if (addressStr == null || addressStr.isEmpty()) {
            return Response.err("address parameter required");
        }
        if (size <= 0) {
            return Response.err("size must be positive");
        }

        // Resolve address before entering EDT lambda
        Address addr = ServiceUtils.parseAddress(program, addressStr);
        if (addr == null) {
            return Response.err(ServiceUtils.getLastParseError());
        }

        final AtomicReference<Map<String, Object>> resultData = new AtomicReference<>();
        final AtomicReference<String> errorMsg = new AtomicReference<>();

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Create memory block");
                boolean txSuccess = false;
                try {
                    // Check for overlap with existing blocks
                    Address end = addr.add(size - 1);
                    for (MemoryBlock existing : program.getMemory().getBlocks()) {
                        if (existing.contains(addr) || existing.contains(end) ||
                            (addr.compareTo(existing.getStart()) <= 0 && end.compareTo(existing.getEnd()) >= 0)) {
                            errorMsg.set("Address range overlaps with existing block '" + existing.getName() +
                                         "' (" + existing.getStart() + " - " + existing.getEnd() + ")");
                            return;
                        }
                    }

                    MemoryBlock block = program.getMemory().createUninitializedBlock(
                        name, addr, size, false);

                    block.setRead(read);
                    block.setWrite(write);
                    block.setExecute(execute);
                    block.setVolatile(isVolatile);
                    if (comment != null && !comment.isEmpty()) {
                        block.setComment(comment);
                    }

                    txSuccess = true;

                    String permissions = (read ? "r" : "-") + (write ? "w" : "-") + (execute ? "x" : "-");
                    resultData.set(JsonHelper.mapOf(
                        "success", true,
                        "name", name,
                        "start", block.getStart().toString(),
                        "end", block.getEnd().toString(),
                        "size", block.getSize(),
                        "permissions", permissions,
                        "volatile", isVolatile,
                        "message", "Memory block '" + name + "' created at " + addr
                    ));
                } catch (Throwable e) {
                    String msg = e.getMessage() != null ? e.getMessage() : e.toString();
                    errorMsg.set(msg);
                    Msg.error(this, "Error creating memory block", e);
                } finally {
                    program.endTransaction(tx, txSuccess);
                }
            });

            if (errorMsg.get() != null) {
                return Response.err(errorMsg.get());
            }
        } catch (Throwable e) {
            String msg = e.getMessage() != null ? e.getMessage() : e.toString();
            return Response.err("Failed to execute on Swing thread: " + msg);
        }

        return resultData.get() != null ? Response.ok(resultData.get()) : Response.err("Unknown failure");
    }

    // ========================================================================
    // Bookmark Operations
    // ========================================================================

    /**
     * Set a bookmark at an address with category and comment.
     * Creates or updates the bookmark if one already exists at the address with the same category.
     */
    public Response setBookmark(String addressStr, String category, String comment) {
        return setBookmark(addressStr, category, comment, null);
    }

    @McpTool(path = "/set_bookmark", method = "POST", description = "Create or update a bookmark. On programs with multiple address spaces (e.g., embedded targets), prefix addresses with the space name (mem:1000) to avoid ambiguous resolution.", category = "program")
    public Response setBookmark(
            @Param(value = "address", paramType = "address", source = ParamSource.BODY,
                   description = "Address in the program. Accepts 0x<hex> (default space) or <space>:<hex> "
                               + "(e.g., mem:1000, code:ff00). Note: some programs — particularly "
                               + "embedded/microcontroller targets — are not address-space-agnostic; "
                               + "use get_address_spaces to discover spaces before assuming a plain hex "
                               + "address is unambiguous.") String addressStr,
            @Param(value = "category", source = ParamSource.BODY, defaultValue = "") String category,
            @Param(value = "comment", source = ParamSource.BODY, defaultValue = "") String comment,
            @Param(value = "program", description = "Target program name", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        if (addressStr == null || addressStr.isEmpty()) {
            return Response.err("Address is required");
        }
        if (category == null || category.isEmpty()) {
            category = "Note";  // Default category
        }
        if (comment == null) {
            comment = "";
        }

        try {
            Address addr = ServiceUtils.parseAddress(program, addressStr);
            if (addr == null) {
                return Response.err(ServiceUtils.getLastParseError());
            }

            BookmarkManager bookmarkManager = program.getBookmarkManager();
            final String finalCategory = category;
            final String finalComment = comment;

            int transactionId = program.startTransaction("Set bookmark at " + addressStr);
            boolean txSuccess = false;
            try {
                // Check if bookmark already exists at this address with this category
                Bookmark existing = bookmarkManager.getBookmark(addr, BookmarkType.NOTE, finalCategory);
                if (existing != null) {
                    // Remove existing to update
                    bookmarkManager.removeBookmark(existing);
                }

                // Create new bookmark
                bookmarkManager.setBookmark(addr, BookmarkType.NOTE, finalCategory, finalComment);
                txSuccess = true;

                Map<String, Object> bmResult = new LinkedHashMap<>();
                bmResult.put("success", true);
                bmResult.putAll(ServiceUtils.addressToJson(addr, program));
                bmResult.put("category", finalCategory);
                bmResult.put("comment", finalComment);
                return Response.ok(bmResult);

            } catch (Exception e) {
                throw e;
            } finally {
                program.endTransaction(transactionId, txSuccess);
            }

        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    /**
     * List bookmarks, optionally filtered by category and/or address.
     */
    public Response listBookmarks(String category, String addressStr) {
        return listBookmarks(category, addressStr, null);
    }

    @McpTool(path = "/list_bookmarks", description = "List bookmarks with optional filter. On programs with multiple address spaces (e.g., embedded targets), prefix addresses with the space name (mem:1000) to avoid ambiguous resolution.", category = "program")
    public Response listBookmarks(
            @Param(value = "category", description = "Category filter (omit to return all categories)", defaultValue = "") String category,
            @Param(value = "address", paramType = "address", defaultValue = "",
                   description = "Address filter (omit to return all addresses). Accepts 0x<hex> (default space) or <space>:<hex> "
                               + "(e.g., mem:1000, code:ff00). Note: some programs — particularly "
                               + "embedded/microcontroller targets — are not address-space-agnostic; "
                               + "use get_address_spaces to discover spaces before assuming a plain hex "
                               + "address is unambiguous.") String addressStr,
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        try {
            BookmarkManager bookmarkManager = program.getBookmarkManager();
            List<Map<String, Object>> bookmarks = new ArrayList<>();

            // If specific address provided, get bookmarks at that address
            if (addressStr != null && !addressStr.isEmpty()) {
                Address addr = ServiceUtils.parseAddress(program, addressStr);
                if (addr == null) {
                    return Response.err(ServiceUtils.getLastParseError());
                }

                Bookmark[] bms = bookmarkManager.getBookmarks(addr);
                for (Bookmark bm : bms) {
                    if (category == null || category.isEmpty() || bm.getCategory().equals(category)) {
                        Map<String, Object> bmItem = new LinkedHashMap<>();
                        bmItem.putAll(ServiceUtils.addressToJson(bm.getAddress(), program));
                        bmItem.put("category", bm.getCategory());
                        bmItem.put("comment", bm.getComment());
                        bmItem.put("type", bm.getTypeString());
                        bookmarks.add(bmItem);
                    }
                }
            } else {
                // Iterate all bookmarks
                BookmarkType[] types = bookmarkManager.getBookmarkTypes();
                for (BookmarkType type : types) {
                    Iterator<Bookmark> iter = bookmarkManager.getBookmarksIterator(type.getTypeString());
                    while (iter.hasNext()) {
                        Bookmark bm = iter.next();
                        if (category == null || category.isEmpty() || bm.getCategory().equals(category)) {
                            Map<String, Object> bmItem = new LinkedHashMap<>();
                            bmItem.putAll(ServiceUtils.addressToJson(bm.getAddress(), program));
                            bmItem.put("category", bm.getCategory());
                            bmItem.put("comment", bm.getComment());
                            bmItem.put("type", bm.getTypeString());
                            bookmarks.add(bmItem);
                        }
                    }
                }
            }

            return Response.ok(JsonHelper.mapOf(
                "success", true,
                "bookmarks", bookmarks,
                "count", bookmarks.size()
            ));

        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    /**
     * Delete a bookmark at an address with optional category filter.
     */
    public Response deleteBookmark(String addressStr, String category) {
        return deleteBookmark(addressStr, category, null);
    }

    @McpTool(path = "/delete_bookmark", method = "POST", description = "Delete a bookmark. On programs with multiple address spaces (e.g., embedded targets), prefix addresses with the space name (mem:1000) to avoid ambiguous resolution.", category = "program")
    public Response deleteBookmark(
            @Param(value = "address", paramType = "address", source = ParamSource.BODY,
                   description = "Address in the program. Accepts 0x<hex> (default space) or <space>:<hex> "
                               + "(e.g., mem:1000, code:ff00). Note: some programs — particularly "
                               + "embedded/microcontroller targets — are not address-space-agnostic; "
                               + "use get_address_spaces to discover spaces before assuming a plain hex "
                               + "address is unambiguous.") String addressStr,
            @Param(value = "category", source = ParamSource.BODY, defaultValue = "") String category,
            @Param(value = "program", description = "Target program name", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        if (addressStr == null || addressStr.isEmpty()) {
            return Response.err("Address is required");
        }

        try {
            Address addr = ServiceUtils.parseAddress(program, addressStr);
            if (addr == null) {
                return Response.err(ServiceUtils.getLastParseError());
            }

            BookmarkManager bookmarkManager = program.getBookmarkManager();

            int transactionId = program.startTransaction("Delete bookmark at " + addressStr);
            boolean txSuccess = false;
            try {
                int deleted = 0;
                Bookmark[] bms = bookmarkManager.getBookmarks(addr);

                for (Bookmark bm : bms) {
                    if (category == null || category.isEmpty() || bm.getCategory().equals(category)) {
                        bookmarkManager.removeBookmark(bm);
                        deleted++;
                    }
                }

                txSuccess = true;
                Map<String, Object> delResult = new LinkedHashMap<>();
                delResult.put("success", true);
                delResult.put("deleted", deleted);
                delResult.putAll(ServiceUtils.addressToJson(addr, program));
                return Response.ok(delResult);

            } catch (Exception e) {
                throw e;
            } finally {
                program.endTransaction(transactionId, txSuccess);
            }

        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    /**
     * Run a Ghidra script with enhanced output capture and JSON response.
     * Locates the script in standard directories, executes it, and returns structured results.
     */
    public Response runGhidraScriptWithCapture(String scriptName, String scriptArgs, int timeoutSeconds, boolean captureOutput) {
        return runGhidraScriptWithCapture(scriptName, scriptArgs, timeoutSeconds, captureOutput, null);
    }

    @McpTool(path = "/run_ghidra_script", method = "POST", description = "Execute script with output capture and timeout. Gated by GHIDRA_MCP_ALLOW_SCRIPTS=1 (v5.4.1+).", category = "program")
    public Response runGhidraScriptWithCapture(
            @Param(value = "script_name", source = ParamSource.BODY) String scriptName,
            @Param(value = "args", source = ParamSource.BODY, defaultValue = "") String scriptArgs,
            @Param(value = "timeout_seconds", source = ParamSource.BODY, defaultValue = "300") int timeoutSeconds,
            @Param(value = "capture_output", source = ParamSource.BODY, defaultValue = "true") boolean captureOutput,
            @Param(value = "program", description = "Target program name", defaultValue = "") String programName) {
        if (!SecurityConfig.getInstance().areScriptsAllowed()) {
            return Response.err("Script execution disabled. Set GHIDRA_MCP_ALLOW_SCRIPTS=1 "
                + "(and GHIDRA_MCP_AUTH_TOKEN if exposing beyond loopback) to enable. "
                + "/run_ghidra_script executes any script resolvable via the Ghidra script path.");
        }
        if (scriptName == null || scriptName.isEmpty()) {
            return Response.err("Script name is required");
        }
        if (timeoutSeconds <= 0 || timeoutSeconds > MAX_SCRIPT_TIMEOUT_SECONDS) {
            return Response.err("timeout_seconds must be between 1 and " + MAX_SCRIPT_TIMEOUT_SECONDS + " seconds");
        }

        // Fail fast with a clear "program not found" error before doing
        // the script-file search. The Program object isn't used in this
        // method directly — the 3-arg runGhidraScript call at the end
        // re-resolves it from programName via the same helper, which is
        // where currentProgram-via-GhidraState binding actually happens.
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();

        try {
            // Locate the script file - search Ghidra's standard script directories
            java.io.File scriptFile = null;
            String filename = scriptName;
            boolean hasExtension = scriptName.contains(".");

            String[] searchDirs = {
                System.getProperty("user.home") + "/ghidra_scripts",
                System.getProperty("user.dir") + "/ghidra_scripts",
                "./ghidra_scripts"
            };

            String[] extensions = hasExtension ? new String[]{""} : new String[]{".java", ".py", ""};

            for (String dirPath : searchDirs) {
                if (dirPath == null) continue;
                for (String ext : extensions) {
                    java.io.File candidate = new java.io.File(dirPath, filename + ext);
                    if (candidate.exists()) {
                        scriptFile = candidate;
                        break;
                    }
                }
                if (scriptFile != null) break;
            }

            // Also try as absolute path
            if (scriptFile == null) {
                java.io.File candidate = new java.io.File(scriptName);
                if (candidate.exists()) {
                    scriptFile = candidate;
                }
            }

            if (scriptFile == null) {
                StringBuilder searched = new StringBuilder();
                for (String dir : searchDirs) {
                    if (dir != null) searched.append(dir).append(", ");
                }
                return Response.err("Script '" + filename + "' not found. Searched: " + searched);
            }

            // Execute the script via the existing execution method.
            //
            // The 3-arg overload (line ~1133) threads programName through
            // ServiceUtils.getProgramOrError -> GhidraState -> the script's
            // currentProgram global. The 2-arg overload below drops the
            // program info, so the script executes against whatever
            // currentProgram happens to be in the session (typically the
            // GUI's focused CodeBrowser). Prior to v5.11.5 this method
            // called the 2-arg form even though it had just resolved the
            // operator's requested program at line 1891 — a real bug
            // surfaced by community report (Copilot review on #207):
            // "It is fixed for run_script_inline but not fixed for
            //  run_ghidra_script, which always runs for the current program."
            long startTime = System.currentTimeMillis();
            Response scriptResponse = runGhidraScript(
                    scriptFile.getAbsolutePath(), scriptArgs, programName, timeoutSeconds);
            double executionTime = (System.currentTimeMillis() - startTime) / 1000.0;

            // Extract the structured result from runGhidraScript's own response
            // rather than string-matching its serialized JSON.
            boolean succeeded = false;
            String output = scriptResponse.toJson();
            if (scriptResponse instanceof Response.Ok ok && ok.data() instanceof Map<?, ?> dataMap) {
                succeeded = Boolean.TRUE.equals(dataMap.get("success"));
                Object consoleOutput = dataMap.get("console_output");
                if (consoleOutput != null) output = consoleOutput.toString();
            } else if (scriptResponse instanceof Response.Err err) {
                output = err.message();
            }

            return Response.ok(JsonHelper.mapOf(
                "success", succeeded,
                "script_name", scriptName,
                "script_path", scriptFile.getAbsolutePath(),
                "execution_time_seconds", Double.parseDouble(String.format("%.2f", executionTime)),
                "console_output", output
            ));

        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    // ========================================================================
    // Image Base Operations
    // ========================================================================

    @McpTool(path = "/set_image_base", method = "POST", description = "Set the base address of the program (rebases all addresses)", category = "program")
    public Response setImageBase(
            @Param(value = "address", source = ParamSource.BODY, description = "New base address (e.g. 0x08000000)") String addressStr,
            @Param(value = "program", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        if (addressStr == null || addressStr.isEmpty()) {
            return Response.err("address parameter required");
        }

        final AtomicReference<Map<String, Object>> resultData = new AtomicReference<>();
        final AtomicReference<String> errorMsg = new AtomicReference<>();

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Set image base");
                boolean txSuccess = false;
                try {
                    Address oldBase = program.getImageBase();
                    Address newBase = ServiceUtils.parseAddress(program, addressStr);
                    if (newBase == null) {
                        errorMsg.set("Invalid address: " + addressStr);
                        return;
                    }
                    program.setImageBase(newBase, true);
                    txSuccess = true;

                    // Trigger re-analysis since all addresses shifted
                    boolean reanalyzing = false;
                    try {
                        AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
                        mgr.reAnalyzeAll(null);
                        mgr.startAnalysis(ghidra.util.task.TaskMonitor.DUMMY);
                        reanalyzing = true;
                    } catch (Exception ae) {
                        Msg.warn(this, "Re-analysis after rebase failed: " + ae.getMessage());
                    }

                    resultData.set(JsonHelper.mapOf(
                        "success", true,
                        "old_base", oldBase.toString(),
                        "new_base", newBase.toString(),
                        "analyzing", reanalyzing,
                        "message", "Image base changed from " + oldBase + " to " + newBase
                    ));
                } catch (Throwable e) {
                    String msg = e.getMessage() != null ? e.getMessage() : e.toString();
                    errorMsg.set(msg);
                    Msg.error(this, "Error setting image base", e);
                } finally {
                    program.endTransaction(tx, txSuccess);
                }
            });

            if (errorMsg.get() != null) {
                return Response.err(errorMsg.get());
            }
        } catch (Throwable e) {
            String msg = e.getMessage() != null ? e.getMessage() : e.toString();
            return Response.err("Failed to execute on Swing thread: " + msg);
        }

        return resultData.get() != null ? Response.ok(resultData.get()) : Response.err("Unknown failure");
    }
}
