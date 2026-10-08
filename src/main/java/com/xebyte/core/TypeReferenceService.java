package com.xebyte.core;

import ghidra.app.services.DataTypeReference;
import ghidra.app.services.DataTypeReferenceFinder;
import ghidra.app.services.FieldMatcher;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TimeoutTaskMonitor;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Precise "which functions use this type / field" lookup for resource invalidation.
 *
 * <p>Wraps Ghidra's {@link DataTypeReferenceFinder} (the same engine behind the GUI
 * "Find Uses of" action). Measured ~3.4 s whole-type / ~3.6 s field-level across
 * 25k functions on the test project — expensive enough to keep off the EDT, cheap
 * enough that a struct edit can invalidate exactly the affected function URIs
 * instead of every URI the session has ever read.
 *
 * <p><b>Threading:</b> runs on the calling HTTP worker thread. Do <em>not</em> wrap
 * this in {@code threadingStrategy.executeRead} — in GUI mode that is
 * {@code SwingThreadingStrategy}, which hops <em>onto</em> the EDT and is the
 * opposite of what is needed.
 *
 * @since 7.1.0
 */
public class TypeReferenceService {

    private static final int DEFAULT_TIMEOUT_SECONDS = 10;
    private static final int MAX_TIMEOUT_SECONDS = 60;
    private static final int MAX_FUNCTIONS = 512;

    private final ProgramProvider programProvider;

    public TypeReferenceService(ProgramProvider programProvider) {
        this.programProvider = programProvider;
    }

    @McpTool(path = "/find_type_users",
        description = "Functions whose decompilation references a data type (or one of its "
            + "fields). Used by resource invalidation after struct/enum edits so only the "
            + "affected function URIs are refreshed. Runs off the EDT with a hard timeout; "
            + "a timeout returns the partial set with timed_out=true rather than failing.",
        category = "datatype", access = ToolAccess.READ_ONLY)
    public Response findTypeUsers(
            @Param(value = "type_name",
                   aliases = {"name", "data_type", "datatype"},
                   description = "Data type name (resolved across all categories).") String typeName,
            @Param(value = "field", defaultValue = "",
                   aliases = {"field_name"},
                   description = "Optional field name. When set, only references to that "
                               + "field are returned (FieldMatcher).") String fieldName,
            @Param(value = "timeout_seconds", defaultValue = "10",
                   description = "Hard timeout for the finder (1–60). Default 10.") int timeoutSeconds,
            @Param(value = "program", defaultValue = "",
                   description = "Target program name (omit for the active program).") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        if (typeName == null || typeName.isBlank()) {
            return Response.err("type_name is required");
        }

        DataTypeManager dtm = program.getDataTypeManager();
        DataType dataType = ServiceUtils.findDataTypeByNameInAllCategories(dtm, typeName.trim());
        if (dataType == null) {
            return Response.err("Data type not found: " + typeName);
        }

        List<DataTypeReferenceFinder> finders =
            ClassSearcher.getInstances(DataTypeReferenceFinder.class);
        if (finders.isEmpty()) {
            return Response.err("No DataTypeReferenceFinder implementation is available");
        }
        DataTypeReferenceFinder finder = finders.get(0);

        int timeout = timeoutSeconds;
        if (timeout < 1) timeout = DEFAULT_TIMEOUT_SECONDS;
        if (timeout > MAX_TIMEOUT_SECONDS) timeout = MAX_TIMEOUT_SECONDS;

        String field = fieldName == null ? "" : fieldName.trim();
        TimeoutTaskMonitor monitor = TimeoutTaskMonitor.timeoutIn(timeout, TimeUnit.SECONDS);

        // LinkedHashMap preserves first-seen order; key = entry address string.
        Map<String, Map<String, Object>> byFunction = new LinkedHashMap<>();
        AtomicInteger refCount = new AtomicInteger();
        long started = System.currentTimeMillis();
        boolean cancelled = false;

        try {
            if (!field.isEmpty()) {
                FieldMatcher matcher = new FieldMatcher(dataType, field);
                finder.findReferences(program, matcher, ref -> collect(ref, byFunction, refCount), monitor);
            } else {
                finder.findReferences(program, dataType, ref -> collect(ref, byFunction, refCount), monitor);
            }
        } catch (CancelledException e) {
            cancelled = true;
        }

        long elapsed = System.currentTimeMillis() - started;
        boolean timedOut = monitor.didTimeout() || cancelled;

        List<Map<String, Object>> functions = new ArrayList<>(byFunction.values());
        boolean truncated = functions.size() > MAX_FUNCTIONS;
        if (truncated) {
            functions = functions.subList(0, MAX_FUNCTIONS);
        }

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("type_name", dataType.getName());
        out.put("type_path", dataType.getPathName());
        if (!field.isEmpty()) {
            out.put("field", field);
        }
        out.put("functions", functions);
        out.put("count", functions.size());
        out.put("total_functions", byFunction.size());
        out.put("total_refs", refCount.get());
        out.put("truncated", truncated);
        out.put("timed_out", timedOut);
        out.put("elapsed_ms", elapsed);
        out.put("timeout_seconds", timeout);
        return Response.ok(out);
    }

    private static void collect(DataTypeReference ref,
            Map<String, Map<String, Object>> byFunction, AtomicInteger refCount) {
        if (ref == null) return;
        refCount.incrementAndGet();
        Function func = ref.getFunction();
        if (func == null) return;
        String key = func.getEntryPoint().toString(false);
        if (byFunction.containsKey(key)) return;
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("name", func.getName());
        row.put("address", key);
        if (ref.getAddress() != null) {
            row.put("sample_address", ref.getAddress().toString(false));
        }
        // Ghidra 12.1.3 renamed this type (LocationReferenceContext ->
        // docking.widgets.search.SearchLocationContext) and moved packages.
        // Both expose getPlainText(), so `var` keeps one source compiling
        // against 12.1.2 and 12.1.3 alike.
        var ctx = ref.getContext();
        if (ctx != null) {
            String text = ctx.getPlainText();
            if (text != null && !text.isBlank()) {
                row.put("sample_line", text);
            }
        }
        byFunction.put(key, row);
    }
}
