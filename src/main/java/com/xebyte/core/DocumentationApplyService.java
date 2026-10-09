package com.xebyte.core;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * {@code /apply_documentation}: document one function, or many, in one call.
 *
 * <p>The one tool for writing a function's documentation. It takes the fields
 * {@code get_function_documentation} exports, so an export applies back unchanged
 * (with {@code target_address} naming where), plus the fields the individual tools take
 * (prototype, variable types and renames). Each entry runs goto, rename, signature,
 * variables, comments, labels and a completeness score, each optional and independent: a
 * failure in one step is reported and does not stop the ones after it. Order matters in
 * one place: the signature goes BEFORE the comments, because setting a prototype wipes the
 * plate comment.
 *
 * <p>Pass the entry's fields at the top level for one function, or {@code entries[]}
 * for many. Every step works on the other tools' {@link Response}s, so it runs on headless
 * too; only {@code goto} needs a window.
 */
public class DocumentationApplyService {

    private final ProgramProvider programProvider;
    private final FunctionService functions;
    private final CommentService comments;
    private final SymbolLabelService symbols;
    private final AnalysisService analysis;
    /** Moves a CodeBrowser to an address, or null when there is no window (headless). */
    private final java.util.function.Function<String, Response> navigator;

    public DocumentationApplyService(ProgramProvider programProvider, FunctionService functions,
            CommentService comments, SymbolLabelService symbols, AnalysisService analysis,
            java.util.function.Function<String, Response> navigator) {
        this.programProvider = programProvider;
        this.functions = functions;
        this.comments = comments;
        this.symbols = symbols;
        this.analysis = analysis;
        this.navigator = navigator;
    }

    @McpTool(path = "/apply_documentation", method = "POST",
            description = "Apply documentation to ONE function (fields at the top level) OR MANY "
                + "(entries=[{address, ...}, ...]). Per function, every step is optional and "
                + "independent and the response reports each one: rename, signature, variable types and "
                + "renames, comments, labels, then a completeness score. It accepts what "
                + "get_function_documentation exports (with target_address), so documentation copied "
                + "between versions applies as it is. The signature is applied before the comments on "
                + "purpose, because setting a prototype wipes the plate comment.",
            category = "analysis", access = ToolAccess.WRITE)
    public Response applyDocumentation(
            @Param(value = "address", paramType = Param.ADDRESS, source = ParamSource.BODY,
                   defaultValue = "", aliases = {"target_address"},
                   description = "Function entry address, as 0x<hex> or <space>:<hex> (single mode). Every "
                               + "step is applied to the function at this address. Omit when using "
                               + "entries[].") String address,
            @Param(value = "entries", source = ParamSource.BODY, defaultValue = "[]",
                   description = "Bulk mode: array of objects, each taking the same fields as the top "
                               + "level (address, name, prototype, ...). When non-empty, the top-level "
                               + "fields are ignored and the response lists one result per entry. One "
                               + "entry failing does not stop the rest.") List<Map<String, Object>> functionEntries,
            @Param(value = "goto", source = ParamSource.BODY, defaultValue = "false",
                   description = "True navigates the CodeBrowser to the function before anything else. "
                               + "Needs a window, so it fails on a headless server.") boolean gotoFirst,
            @Param(value = "name", source = ParamSource.BODY, defaultValue = "",
                   aliases = {"function_name"},
                   description = "New function name. Omit or leave empty to skip the rename step.") String name,
            @Param(value = "prototype", source = ParamSource.BODY, defaultValue = "",
                   description = "Full C signature. Exclusive with return_type. Applied BEFORE the comment "
                               + "step on purpose.") String prototype,
            @Param(value = "calling_convention", source = ParamSource.BODY, defaultValue = "",
                   description = "Calling convention, e.g. __stdcall. Goes with the prototype when there is "
                               + "one, and is applied on its own otherwise.") String callingConvention,
            @Param(value = "return_type", source = ParamSource.BODY, defaultValue = "",
                   description = "Return type name, for when there is no prototype. A type that does not "
                               + "resolve is reported, not skipped; undefined* is skipped, as in an export.") String returnType,
            @Param(value = "params", source = ParamSource.BODY, defaultValue = "[]",
                   aliases = {"parameters"},
                   description = "Array of {ordinal, name, type} as get_function_documentation exports "
                               + "them. A generic name (param_N) and an undefined type are skipped, so an "
                               + "export applies back without reverting anything. Reported under "
                               + "variable_renames and variable_types.") List<Map<String, Object>> parameters,
            @Param(value = "variable_types", source = ParamSource.BODY,
                   description = "Object mapping a variable's CURRENT name to its new type. Each is applied "
                               + "on its own; the step reports set/failed counts plus per-variable errors.")
                Map<String, String> variableTypes,
            @Param(value = "variable_renames", source = ParamSource.BODY,
                   description = "Object mapping each variable's CURRENT name to its new name.")
                Map<String, String> variableRenames,
            @Param(value = "plate_comment", source = ParamSource.BODY, defaultValue = "",
                   description = "Plate comment for the function. Pass real multi-line text: an escaped "
                               + "newline sequence is stored as those two literal characters, not as a "
                               + "line break. Empty is skipped; clear one with set_comment.") String plateComment,
            @Param(value = "comments", source = ParamSource.BODY, defaultValue = "[]",
                   description = "Array of {address | relative_offset, pre_comment, eol_comment}: PRE (the "
                               + "decompiler's line above) and EOL (the listing's trailing) comments. "
                               + "relative_offset counts from the function entry, as the export writes it. "
                               + "An empty string clears that comment.") List<Map<String, Object>> commentEntries,
            @Param(value = "labels", source = ParamSource.BODY, defaultValue = "[]",
                   description = "Array of {address | relative_offset, name}. A label already there with "
                               + "that name is left alone.") List<Map<String, Object>> labels,
            @Param(value = "tags", source = ParamSource.BODY, defaultValue = "",
                   description = "Comma-separated function tags to attach (in an entry, a string or an "
                               + "array of names). A tag that does not exist is created. Tags are only "
                               + "added here; remove one with remove_function_tag.") String tags,
            @Param(value = "tag_comments", source = ParamSource.BODY,
                   description = "Object mapping a tag name to its description, used for a tag this call "
                               + "creates; an existing tag keeps its description.")
                Map<String, String> tagComments,
            @Param(value = "score", source = ParamSource.BODY, defaultValue = "",
                   description = "True appends a compact completeness score to each function. Default: true "
                               + "for one function, false for entries[], where it costs a decompile "
                               + "each.") Boolean score,
            @Param(value = "program", defaultValue = "",
                   description = "Target program name or project path. Every step runs against it. Omit "
                               + "to use the active program; always specify it on a headless server or "
                               + "when several programs are open.") String programName) {

        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) {
            return pe.error();
        }
        Program program = pe.program();

        if (functionEntries != null && !functionEntries.isEmpty()) {
            return applyMany(program, programName, functionEntries, score);
        }
        if (address == null || address.trim().isEmpty()) {
            return Response.err("address parameter is required (or pass entries[] for bulk)");
        }
        Map<String, Object> entry = new LinkedHashMap<>();
        entry.put("address", address);
        entry.put("goto", gotoFirst);
        entry.put("name", name);
        entry.put("prototype", prototype);
        entry.put("calling_convention", callingConvention);
        entry.put("return_type", returnType);
        entry.put("params", parameters);
        entry.put("variable_types", variableTypes);
        entry.put("variable_renames", variableRenames);
        entry.put("plate_comment", plateComment);
        entry.put("comments", commentEntries);
        entry.put("labels", labels);
        entry.put("tags", tags);
        entry.put("tag_comments", tagComments);
        Map<String, Object> out = applyOne(program, programName, entry, score == null || score);
        out.put("program", program.getName());
        return Response.ok(out);
    }

    private Response applyMany(Program program, String programName, List<Map<String, Object>> entries,
            Boolean score) {
        List<Map<String, Object>> results = new ArrayList<>();
        int failed = 0;
        for (Map<String, Object> entry : entries) {
            Map<String, Object> result = applyOne(program, programName, entry,
                entry.get("score") instanceof Boolean own ? own : score != null && score);
            if (!((List<?>) result.get("errors")).isEmpty()) {
                failed++;
            }
            results.add(result);
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("program", program.getName());
        out.put("count", results.size());
        out.put("succeeded", results.size() - failed);
        out.put("failed", failed);
        out.put("results", results);
        return Response.ok(out);
    }

    /** One function's documentation: {@code entry} uses the same keys as the tool's top level. */
    private Map<String, Object> applyOne(Program program, String programName, Map<String, Object> entry,
            boolean score) {
        String address = text(entry, "address");
        Map<String, Object> steps = new LinkedHashMap<>();
        List<String> errors = new ArrayList<>();
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("address", address);
        out.put("steps", steps);
        out.put("errors", errors);

        if (address == null) {
            errors.add("address is required");
            return out;
        }
        ServiceUtils.FunctionOrError resolved = ServiceUtils.getFunctionOrError(program, address);
        if (resolved.function() == null) {
            errors.add(resolved.message());
            return out;
        }
        Function target = resolved.function();

        if (Boolean.TRUE.equals(entry.get("goto"))) {
            steps.put("goto", step("goto", navigator == null
                ? Response.err("goto needs a CodeBrowser window; this server has none")
                : navigator.apply(address), errors));
        }
        String name = text(entry, "name");
        if (name == null) {
            name = text(entry, "function_name");
        }
        if (name != null) {
            steps.put("rename", step("rename",
                functions.renameFunctionByAddress(address, name, programName), errors));
        }
        applySignature(program, target, address, programName, entry, steps, errors);

        Map<String, String> types = new LinkedHashMap<>(stringMap(entry.get("variable_types")));
        Map<String, String> renames = new LinkedHashMap<>(stringMap(entry.get("variable_renames")));
        addParameterChanges(target, list(entry.containsKey("params") ? entry.get("params") : entry.get("parameters")),
            types, renames);
        if (!types.isEmpty()) {
            steps.put("variable_types", applyVariableTypes(address, types, programName, errors));
        }
        if (!renames.isEmpty()) {
            Response renamed = functions.batchRenameVariables(address, renames, true, programName);
            steps.put("variable_renames", counted("variable_renames", renamed, errors,
                Map.of("variables_renamed", "renamed", "variables_failed", "failed")));
        }
        applyComments(program, target, address, programName, entry, steps, errors);
        applyLabels(program, target, programName, list(entry.get("labels")), steps, errors);
        applyTags(address, programName, entry, steps, errors);

        if (score) {
            // Compact: the caller already has the workflow guidance in its prompt.
            Response scored = analysis.analyzeFunctionCompleteness(address, true, programName);
            out.put("completeness", scored instanceof Response.Err e
                ? Map.of("error", e.message()) : scored.asEmbeddable());
        }
        return out;
    }

    // ---------------------------------------------------------------- steps

    private void applySignature(Program program, Function target, String address, String programName,
            Map<String, Object> entry, Map<String, Object> steps, List<String> errors) {
        String prototype = text(entry, "prototype");
        // An export of an undocumented function says "undefined": nothing to apply.
        String returnType = text(entry, "return_type");
        if (returnType != null && returnType.startsWith("undefined")) {
            returnType = null;
        }
        String convention = text(entry, "calling_convention");
        if (prototype != null && returnType != null) {
            errors.add("signature: give prototype or return_type, not both");
            return;
        }
        if (prototype != null) {
            FunctionService.PrototypeResult result =
                functions.setFunctionPrototype(address, prototype, convention, programName);
            Map<String, Object> outcome = new LinkedHashMap<>();
            outcome.put("success", result.isSuccess());
            if (!result.isSuccess()) {
                outcome.put("error", result.getErrorMessage());
                errors.add("prototype: " + result.getErrorMessage());
            }
            steps.put("prototype", outcome);
        } else if (returnType != null || convention != null) {
            steps.put("signature", setReturnTypeAndConvention(program, target, returnType, convention, errors));
        }
    }

    private static Map<String, Object> setReturnTypeAndConvention(Program program, Function target,
            String returnType, String convention, List<String> errors) {
        Map<String, Object> entry = new LinkedHashMap<>();
        String failed = null;
        WriteTx tx = WriteTx.begin(program, "Set Function Signature");
        try {
            if (returnType != null) {
                DataType type = ServiceUtils.resolveDataType(program.getDataTypeManager(), returnType);
                if (type == null) {
                    failed = "Could not resolve return type '" + returnType + "'";
                } else {
                    target.setReturnType(type, SourceType.USER_DEFINED);
                }
            }
            if (failed == null && convention != null) {
                target.setCallingConvention(convention);
            }
        } catch (Exception e) {
            failed = e.getMessage() != null ? e.getMessage() : e.toString();
        } finally {
            tx.end(failed == null);
        }
        entry.put("success", failed == null);
        if (failed != null) {
            entry.put("error", failed);
            errors.add("signature: " + failed);
        }
        return entry;
    }

    /**
     * Turns the exported {@code parameters} into type and rename changes, keyed by the
     * parameter's current name. Placeholders ({@code param_N}, {@code undefined*}) are
     * skipped, and an explicit variable_types / variable_renames entry for the same
     * variable wins.
     */
    private static void addParameterChanges(Function target, List<Map<String, Object>> parameters,
            Map<String, String> types, Map<String, String> renames) {
        Parameter[] current = target.getParameters();
        for (Map<String, Object> p : parameters) {
            if (!(p.get("ordinal") instanceof Number n) || n.intValue() < 0 || n.intValue() >= current.length) {
                continue;
            }
            String was = current[n.intValue()].getName();
            String newType = text(p, "type");
            if (newType != null && !newType.startsWith("undefined")) {
                types.putIfAbsent(was, newType);
            }
            String newName = text(p, "name");
            if (newName != null && !newName.startsWith("param_") && !newName.equals(was)) {
                renames.putIfAbsent(was, newName);
            }
        }
    }

    private void applyComments(Program program, Function target, String address, String programName,
            Map<String, Object> entry, Map<String, Object> steps, List<String> errors) {
        List<Map<String, String>> pre = new ArrayList<>();
        List<Map<String, String>> eol = new ArrayList<>();
        for (Map<String, Object> c : list(entry.get("comments"))) {
            String at = locate(target, c);
            if (at == null) {
                errors.add("comments: entry has no address or relative_offset");
                continue;
            }
            if (c.get("pre_comment") instanceof String text) {
                pre.add(Map.of("address", at, "comment", text));
            }
            if (c.get("eol_comment") instanceof String text) {
                eol.add(Map.of("address", at, "comment", text));
            }
        }
        String plate = text(entry, "plate_comment");
        if (plate == null && pre.isEmpty() && eol.isEmpty()) {
            return;
        }
        Response written = comments.batchSetComments(address, pre, eol, plate, programName);
        Map<String, Object> result = counted("comments", written, errors, Map.of(
            "decompiler_comments_set", "pre", "disassembly_comments_set", "eol"));
        if (data(written).get("plate_comment_set") == Boolean.TRUE) {
            result.put("plate", true);
        }
        steps.put("comments", result);
    }

    private void applyLabels(Program program, Function target, String programName,
            List<Map<String, Object>> labels, Map<String, Object> steps, List<String> errors) {
        List<Map<String, String>> wanted = new ArrayList<>();
        int unchanged = 0;
        for (Map<String, Object> label : labels) {
            String at = locate(target, label);
            String name = text(label, "name");
            if (at == null || name == null) {
                errors.add("labels: entry needs a name and an address or relative_offset");
                continue;
            }
            Address where = ServiceUtils.parseAddress(program, at);
            if (where != null && hasLabel(program, where, name)) {
                unchanged++;
            } else {
                wanted.add(Map.of("address", at, "name", name));
            }
        }
        if (wanted.isEmpty() && unchanged == 0) {
            return;
        }
        Response created = wanted.isEmpty() ? Response.ok(Map.of())
            : symbols.batchCreateLabels(wanted, programName);
        Map<String, Object> result = step("labels", created, errors);
        result.put("created", wanted.size());
        result.put("unchanged", unchanged);
        steps.put("labels", result);
    }

    private void applyTags(String address, String programName, Map<String, Object> entry,
            Map<String, Object> steps, List<String> errors) {
        String names = entry.get("tags") instanceof List<?> list
            ? list.stream().map(String::valueOf).collect(java.util.stream.Collectors.joining(","))
            : text(entry, "tags");
        if (names == null || names.isBlank()) {
            return;
        }
        Response attached = functions.addFunctionTag(address, names, stringMap(entry.get("tag_comments")),
            List.of(), programName);
        steps.put("tags", counted("tags", attached, errors, Map.of(
            "added", "added", "already_present", "already_present", "created", "created")));
    }

    private static boolean hasLabel(Program program, Address at, String name) {
        for (Symbol symbol : program.getSymbolTable().getSymbols(at)) {
            if (symbol.getSymbolType() == SymbolType.LABEL && symbol.getName().equals(name)) {
                return true;
            }
        }
        return false;
    }

    /** An entry's address: its own, or {@code relative_offset} from the function entry. */
    private static String locate(Function target, Map<String, Object> item) {
        String own = text(item, "address");
        if (own != null) {
            return own;
        }
        return item.get("relative_offset") instanceof Number offset
            ? target.getEntryPoint().add(offset.longValue()).toString(true) : null;
    }

    // ------------------------------------------------------------- entry values

    /** A non-empty string value, or null: absent, null and empty all mean "skip this step". */
    private static String text(Map<String, Object> map, String key) {
        return map.get(key) instanceof String s && !s.isEmpty() ? s : null;
    }

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> list(Object value) {
        return value instanceof List<?> l ? (List<Map<String, Object>>) l : List.of();
    }

    private static Map<String, String> stringMap(Object value) {
        Map<String, String> out = new LinkedHashMap<>();
        if (value instanceof Map<?, ?> m) {
            m.forEach((k, v) -> out.put(String.valueOf(k), String.valueOf(v)));
        }
        return out;
    }

    // ---------------------------------------------------------------- steps

    private Map<String, Object> applyVariableTypes(String address, Map<String, String> types,
            String programName, List<String> errors) {
        int set = 0;
        List<String> failures = new ArrayList<>();
        for (Map.Entry<String, String> e : types.entrySet()) {
            String failed = failure(functions.setLocalVariableType(address, e.getKey(), e.getValue(), programName));
            if (failed == null) {
                set++;
            } else {
                failures.add(e.getKey() + ": " + abbreviate(failed));
            }
        }
        Map<String, Object> entry = new LinkedHashMap<>();
        entry.put("success", failures.isEmpty());
        entry.put("set", set);
        entry.put("failed", failures.size());
        if (!failures.isEmpty()) {
            entry.put("errors", failures);
            errors.addAll(failures);
        }
        return entry;
    }

    /** A step's outcome: success, plus the error when it failed (also collected in {@code errors}). */
    private static Map<String, Object> step(String label, Response response, List<String> errors) {
        String failed = failure(response);
        Map<String, Object> entry = new LinkedHashMap<>();
        entry.put("success", failed == null);
        if (failed != null) {
            entry.put("error", failed);
            errors.add(label + ": " + failed);
        }
        return entry;
    }

    /** {@link #step} plus named counts lifted from the tool's own result map. */
    private static Map<String, Object> counted(String label, Response response, List<String> errors,
            Map<String, String> countKeys) {
        Map<String, Object> entry = step(label, response, errors);
        Map<String, Object> data = data(response);
        countKeys.forEach((from, to) -> {
            if (data.containsKey(from)) {
                entry.put(to, data.get(from));
            }
        });
        return entry;
    }

    // -------------------------------------------------------------- outcomes

    @SuppressWarnings("unchecked")
    private static Map<String, Object> data(Response response) {
        return response instanceof Response.Ok ok && ok.data() instanceof Map<?, ?> m
            ? (Map<String, Object>) m : Map.of();
    }

    /**
     * Why a tool's response is a failure, or null when it succeeded. An {@code Err} is one;
     * so is an {@code Ok} whose payload says it did not work, which several tools return
     * for a rejected request ({@code error}, {@code success: false}, {@code status:
     * rejected}).
     */
    static String failure(Response response) {
        if (response instanceof Response.Err err) {
            return err.message();
        }
        if (response instanceof Response.Text text) {
            return text.content() != null && text.content().startsWith("Error") ? text.content() : null;
        }
        Map<String, Object> data = data(response);
        if (data.get("error") != null) {
            return String.valueOf(data.get("error"));
        }
        boolean rejected = "rejected".equals(data.get("status")) || "error".equals(data.get("status"));
        if (Boolean.FALSE.equals(data.get("success")) || rejected) {
            Object why = data.getOrDefault("message", data.get("status"));
            return why != null ? String.valueOf(why) : "failed";
        }
        return null;
    }

    /** At most 100 characters, cut on a code point boundary, never inside a surrogate pair. */
    private static String abbreviate(String text) {
        return text.codePointCount(0, text.length()) <= 100
            ? text : text.substring(0, text.offsetByCodePoints(0, 100));
    }
}
