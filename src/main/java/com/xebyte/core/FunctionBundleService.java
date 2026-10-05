package com.xebyte.core;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/**
 * One read that answers everything an agent asks about a function.
 *
 * <p>Reviewing a single function used to cost five round trips —
 * {@code decompile_function} + {@code get_function_variables} +
 * {@code get_function_callers} + {@code get_comment} + {@code get_function_xrefs} — and
 * every write forced the agent to re-read to see its effect. This endpoint collapses that
 * into one call backed by **one** decompilation, which matters because the plugin has no
 * decompiler cache: each decompile builds and disposes a fresh {@code DecompInterface}, so
 * two bundled reads composed from existing endpoints would decompile the same function
 * twice.
 *
 * <p>It also carries {@code call_context} — a window of the caller's actual decompiled
 * source centred on the call, three lines by default, because the line that decides whether
 * the call happens and the line that consumes its result are usually the ones next to it.
 * That is the context a reader wants without paying for a separate read per caller, and it
 * costs one decompile per *unique* caller (~43 ms measured), so it is deduped and capped.
 * Widening the window costs nothing extra — the caller is already decompiled.
 *
 * <p>Deliberately excluded: completeness scoring. {@code /analyze_function_completeness}
 * decompiles again, and a second decompile would defeat the point of this endpoint. Call
 * that tool directly when a score is wanted.
 *
 * <p>Threading: the whole bundle is built on the calling HTTP worker thread with no
 * {@code threadingStrategy} wrapper, following {@link CommentService}. In GUI mode
 * {@code SwingThreadingStrategy} hops onto the EDT, and decompiling several callers there
 * would stall the UI for hundreds of milliseconds; Ghidra's program database is safe for
 * concurrent reads, so the hop buys nothing here.
 *
 * @since 7.1.0
 */
public class FunctionBundleService {

    /** Bulk cap matches {@code decompile_function(functions=)} — one decompile budget per entry. */
    private static final int MAX_FUNCTIONS = 20;
    /** Widest call-site window. Past this a reader should just read the caller's bundle. */
    private static final int MAX_CALL_CONTEXT_LINES = 21;

    private final ProgramProvider programProvider;
    private final ThreadingStrategy threadingStrategy;
    private final FunctionService functionService;

    public FunctionBundleService(ProgramProvider programProvider,
            ThreadingStrategy threadingStrategy, FunctionService functionService) {
        this.programProvider = programProvider;
        this.threadingStrategy = threadingStrategy;
        this.functionService = functionService;
    }

    @McpTool(path = "/get_functions",
        description = "Everything about one or many functions in a single call. Pass "
            + "functions= as a comma-separated list of names or addresses for bulk mode "
            + "(up to 20); omit it and pass function=/name=/address= for one. Pass fields= "
            + "as a comma-separated subset to skip work you do not need — omitted or empty "
            + "returns everything. When the requested fields need no decompiled text (e.g. "
            + "fields=callers,callees,signature,labels,entry_point), the target function is "
            + "NOT decompiled (238 ms cold / 5–10 ms warm per function); only decompiled_code "
            + "(and call_context when enabled) pays that cost. Decompiled text renders EOL "
            + "comments (// style), so comments written with set_comment are visible in the "
            + "code. Replaces get_function_by_address, get_function_variables, "
            + "get_function_xrefs, decompile_function, and the former "
            + "get_function_callers/callees/labels/signature tools. Completeness scoring is "
            + "NOT included — call analyze_function_completeness for that.",
        category = "function", access = ToolAccess.READ_ONLY)
    public Response getFunctions(
            @Param(value = "function", paramType = Param.FUNCTION_REF, defaultValue = "",
                   description = "Single mode: function name or address (0x<hex> or "
                               + "<space>:<hex>). Ignored when functions= is set.") String functionRef,
            @Param(value = "functions", defaultValue = "",
                   description = "Bulk mode: comma-separated function references (names or "
                               + "addresses). When set, function= is ignored. Returns a map "
                               + "keyed by the reference asked for.") String functionsParam,
            @Param(value = "fields", defaultValue = "",
                   description = "Comma-separated subset: signature, classification, return_type, "
                               + "entry_point, body_start, body_end, decompiled_code, "
                               + "plate_comment, comments, labels, tags, parameters, locals, callers, "
                               + "call_context, callees, xrefs, disassembly, jump_targets, refs (the absolute "
                               + "addresses the function uses: data references, the values of "
                               + "literal-pool words, and the memory the decompiled code reads and "
                               + "writes, so a register reached as base + offset is listed by its "
                               + "own address; a pool value is written value<word; asking for refs "
                               + "decompiles). "
                               + "Omit or leave empty for the full bundle.") String fieldsParam,
            @Param(value = "include_call_context", defaultValue = "true",
                   description = "Include each caller's decompiled call-site line. Costs one "
                               + "decompilation per unique caller (~43ms); set false for the "
                               + "cheapest possible bundle. Ignored unless call_context is "
                               + "requested (explicitly or via an empty fields=).") boolean includeCallContext,
            @Param(value = "call_context_limit", defaultValue = "6",
                   description = "Maximum number of UNIQUE callers to decompile for call "
                               + "context.") int callContextLimit,
            @Param(value = "call_context_lines", defaultValue = "3",
                   aliases = {"call_context_window"},
                   description = "Lines of the caller's decompilation to return per call site, "
                               + "centred on the call. 1 is the call line alone; the default 3 "
                               + "adds the line above and below, which is usually where the "
                               + "guard and the use of the result live. Clamped to 1-21; costs "
                               + "no extra decompilation.") int callContextLines,
            @Param(value = "include_disasm", defaultValue = "false",
                   description = "Include the raw instruction listing. Off by default: it roughly "
                               + "doubles the payload and agents rarely read it.") boolean includeDisasm,
            @Param(value = "program", defaultValue = "",
                   description = "Target program name (omit to use the active program — always "
                               + "specify when multiple programs are open)") String programName) {

        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        Set<String> fields;
        try {
            fields = parseFields(fieldsParam);
            if (fields != null && fields.isEmpty()) {
                fields = null;
            }
        } catch (IllegalArgumentException e) {
            return Response.err(e.getMessage());
        }

        final int ctxLimit = Math.max(0, callContextLimit);
        final int ctxLines = Math.clamp(callContextLines, 1, MAX_CALL_CONTEXT_LINES);
        final Set<String> resolvedFields = fields;

        if (functionsParam != null && !functionsParam.isBlank()) {
            return getFunctionsBulk(program, functionsParam, resolvedFields, includeCallContext,
                ctxLimit, ctxLines, includeDisasm);
        }

        if (functionRef == null || functionRef.isEmpty()) {
            return Response.err("function name or address required (or pass functions= for bulk)");
        }

        ServiceUtils.FunctionOrError lookup = ServiceUtils.getFunctionOrError(program, functionRef);
        if (lookup.hasError()) return lookup.error();
        Function func = lookup.function();

        try {
            return Response.ok(buildBundle(program, func, resolvedFields, includeCallContext,
                ctxLimit, ctxLines, includeDisasm));
        } catch (Exception e) {
            String msg = e.getMessage() != null ? e.getMessage() : e.toString();
            return Response.err("Failed to build bundle for " + func.getName() + ": " + msg);
        }
    }

    private Response getFunctionsBulk(Program program, String functionsParam, Set<String> fields,
            boolean includeCallContext, int callContextLimit, int callContextLines,
            boolean includeDisasm) {
        String[] refs = functionsParam.split(",");
        Map<String, Object> out = new LinkedHashMap<>();
        Map<String, Object> functions = new LinkedHashMap<>();
        int requested = 0;
        int resolved = 0;

        for (String raw : refs) {
            if (requested >= MAX_FUNCTIONS) {
                break;
            }
            String funcRef = raw.trim();
            if (funcRef.isEmpty()) {
                continue;
            }
            requested++;
            ServiceUtils.FunctionOrError lookup = ServiceUtils.getFunctionOrError(program, funcRef);
            if (lookup.hasError()) {
                functions.put(funcRef, new LinkedHashMap<>(Map.of("error", lookup.message())));
                continue;
            }
            Function func = lookup.function();
            try {
                functions.put(funcRef, buildBundle(program, func, fields, includeCallContext,
                    callContextLimit, callContextLines, includeDisasm));
                resolved++;
            } catch (Exception e) {
                String msg = e.getMessage() != null ? e.getMessage() : e.toString();
                Map<String, Object> err = new LinkedHashMap<>();
                err.put("error", "Failed to build bundle for " + func.getName() + ": " + msg);
                functions.put(funcRef, err);
            }
        }

        if (requested == 0) {
            return Response.err("functions parameter is required for bulk mode");
        }

        out.put("functions", functions);
        out.put("count", resolved);
        out.put("requested", requested);
        if (refs.length > MAX_FUNCTIONS || requested > MAX_FUNCTIONS) {
            out.put("truncated", true);
            out.put("max_functions", MAX_FUNCTIONS);
        }
        return Response.ok(out);
    }

    private static Set<String> parseFields(String fieldsParam) {
        if (fieldsParam == null || fieldsParam.isBlank()) {
            return null;
        }
        Set<String> fields = new LinkedHashSet<>();
        for (String part : fieldsParam.split(",")) {
            String token = part.trim().toLowerCase();
            if (token.isEmpty()) {
                continue;
            }
            if (!FunctionFacts.FIELDS.contains(token)) {
                throw new IllegalArgumentException("Unknown field: " + part.trim()
                    + ". Valid fields: " + String.join(", ", FunctionFacts.FIELDS));
            }
            fields.add(token);
        }
        return fields.isEmpty() ? null : fields;
    }

    private Map<String, Object> buildBundle(Program program, Function func,
            Set<String> fields, boolean includeCallContext, int callContextLimit,
            int callContextLines, boolean includeDisasm) {
        return FunctionFacts.build(program, func,
            new FunctionFacts.Options(fields, includeCallContext, callContextLimit, callContextLines,
                includeDisasm),
            f -> functionService.decompileFunctionNoRetry(f, program, FunctionFacts::configureDecompiler));
    }

    /** Whether a {@code fields=} subset pays for target decompilation. */
    public static boolean requiresTargetDecompile(Set<String> fields) {
        return FunctionFacts.requiresTargetDecompile(fields);
    }
}
