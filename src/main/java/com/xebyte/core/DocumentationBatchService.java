package com.xebyte.core;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

/**
 * {@code /batch_apply_documentation}: document a function in one call.
 *
 * <p>Orchestrates goto, rename, prototype, variable types, variable renames, comments and
 * a completeness score, each optional and each independent: a failure in one step is
 * reported and does not stop the ones after it. Order matters in one place: the prototype
 * goes BEFORE the comments, because setting a prototype wipes the plate comment.
 *
 * <p>This was a GUI hand route that built its answer by searching the other tools' JSON
 * text for "Success" and pulling counts out with {@code indexOf}. It works on their
 * {@link Response}s instead, so it also runs on headless; only the {@code goto} step needs
 * a window.
 */
public class DocumentationBatchService {

    private final FunctionService functions;
    private final CommentService comments;
    private final AnalysisService analysis;
    /** Moves a CodeBrowser to an address, or null when there is no window (headless). */
    private final Function<String, Response> navigator;

    public DocumentationBatchService(FunctionService functions, CommentService comments,
            AnalysisService analysis, Function<String, Response> navigator) {
        this.functions = functions;
        this.comments = comments;
        this.analysis = analysis;
        this.navigator = navigator;
    }

    @McpTool(path = "/batch_apply_documentation", method = "POST",
            description = "Apply all documentation to a function in one call: rename, prototype, variable "
                + "types, variable renames and comments, then a compact completeness score. Every step is "
                + "optional and independent, and the response reports each one. The prototype is applied "
                + "before the comments on purpose, because setting a prototype wipes the plate comment.",
            category = "analysis", access = ToolAccess.WRITE)
    public Response batchApplyDocumentation(
            @Param(value = "address", paramType = Param.ADDRESS, source = ParamSource.BODY,
                   description = "Function entry address, as 0x<hex> or <space>:<hex>. Required: every step "
                               + "is applied to the function at this address.") String address,
            @Param(value = "goto", source = ParamSource.BODY, defaultValue = "false",
                   description = "True navigates the CodeBrowser to address before anything else. Needs a "
                               + "window, so it fails on a headless server.") boolean gotoFirst,
            @Param(value = "name", source = ParamSource.BODY, defaultValue = "",
                   description = "New function name. Omit or leave empty to skip the rename step.") String name,
            @Param(value = "prototype", source = ParamSource.BODY, defaultValue = "",
                   description = "Full C signature. Applied BEFORE the comment step on purpose.") String prototype,
            @Param(value = "calling_convention", source = ParamSource.BODY, defaultValue = "",
                   description = "Convention for the prototype step, e.g. __stdcall. Read only when "
                               + "prototype is also given.") String callingConvention,
            @Param(value = "variable_types", source = ParamSource.BODY,
                   description = "Object mapping variable name to new type. Each is applied on its own; "
                               + "the step reports set/failed counts plus per-variable errors.")
                Map<String, String> variableTypes,
            @Param(value = "variable_renames", source = ParamSource.BODY,
                   description = "Object mapping each variable's CURRENT name to its new name.")
                Map<String, String> variableRenames,
            @Param(value = "plate_comment", source = ParamSource.BODY, defaultValue = "",
                   description = "Plate comment for the function. Pass real multi-line text: an escaped "
                               + "newline sequence is stored as those two literal characters, not as a "
                               + "line break.") String plateComment,
            @Param(value = "decompiler_comments", source = ParamSource.BODY, defaultValue = "[]",
                   description = "Array of {address, comment} objects setting PRE comments. Each entry "
                               + "carries its own address; the top-level address is the function entry "
                               + "only.") List<Map<String, String>> decompilerComments,
            @Param(value = "disassembly_comments", source = ParamSource.BODY, defaultValue = "[]",
                   description = "Array of {address, comment} objects setting EOL comments. Each entry "
                               + "carries its own address.") List<Map<String, String>> disassemblyComments,
            @Param(value = "score", source = ParamSource.BODY, defaultValue = "true",
                   description = "True (the default) appends a compact completeness score.") boolean score,
            @Param(value = "program", defaultValue = "",
                   description = "Target program name or project path. Every step runs against it. Omit "
                               + "to use the active program; always specify it on a headless server or "
                               + "when several programs are open.") String programName) {

        if (address == null || address.trim().isEmpty()) {
            return Response.err("address parameter is required");
        }

        Map<String, Object> steps = new LinkedHashMap<>();
        List<String> errors = new ArrayList<>();

        if (gotoFirst) {
            steps.put("goto", step("goto", navigator == null
                ? Response.err("goto needs a CodeBrowser window; this server has none")
                : navigator.apply(address), errors));
        }
        if (name != null && !name.isEmpty()) {
            steps.put("rename", step("rename",
                functions.renameFunctionByAddress(address, name, programName), errors));
        }
        if (prototype != null && !prototype.isEmpty()) {
            FunctionService.PrototypeResult result = functions.setFunctionPrototype(address, prototype,
                callingConvention == null || callingConvention.isEmpty() ? null : callingConvention,
                programName);
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("success", result.isSuccess());
            if (!result.isSuccess()) {
                entry.put("error", result.getErrorMessage());
                errors.add("prototype: " + result.getErrorMessage());
            }
            steps.put("prototype", entry);
        }
        if (variableTypes != null && !variableTypes.isEmpty()) {
            steps.put("variable_types", applyVariableTypes(address, variableTypes, programName, errors));
        }
        if (variableRenames != null && !variableRenames.isEmpty()) {
            Response renamed = functions.batchRenameVariables(address, variableRenames, true, programName);
            steps.put("variable_renames", counted("variable_renames", renamed, errors,
                Map.of("variables_renamed", "renamed", "variables_failed", "failed")));
        }
        boolean hasComments = plateComment != null && !plateComment.isEmpty()
            || decompilerComments != null && !decompilerComments.isEmpty()
            || disassemblyComments != null && !disassemblyComments.isEmpty();
        if (hasComments) {
            Response written = comments.batchSetComments(address, decompilerComments, disassemblyComments,
                plateComment == null || plateComment.isEmpty() ? null : plateComment, programName);
            Map<String, Object> entry = counted("comments", written, errors, Map.of(
                "decompiler_comments_set", "decompiler", "disassembly_comments_set", "disassembly"));
            if (data(written).get("plate_comment_set") == Boolean.TRUE) {
                entry.put("plate", true);
            }
            steps.put("comments", entry);
        }

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("address", address);
        out.put("steps", steps);
        if (score) {
            // Compact: the caller already has the workflow guidance in its prompt.
            Response scored = analysis.analyzeFunctionCompleteness(address, true, programName);
            out.put("completeness", scored instanceof Response.Err e
                ? Map.of("error", e.message()) : scored.asEmbeddable());
        }
        out.put("errors", errors);
        return Response.ok(out);
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
