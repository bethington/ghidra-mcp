package com.xebyte.offline;

import junit.framework.TestCase;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Regression: {@code /run_ghidra_script} honors the {@code program}
 * parameter end-to-end.
 *
 * <p>Community report (Copilot review on #207, surfaced again 2026-05-23):
 * <em>"It is fixed for run_script_inline but not fixed for
 * run_ghidra_script, which always runs for the current program."</em>
 *
 * <p>The API signature has always accepted a {@code program} @Param. The
 * bug was that {@code runGhidraScriptWithCapture} resolved the requested
 * program into a local {@code Program program} variable, then invoked the
 * <strong>2-argument</strong> {@code runGhidraScript(scriptPath, args)}
 * overload — which drops the program and falls back to whatever
 * {@code currentProgram} is in the session context (typically the focused
 * CodeBrowser). The 3-argument overload
 * {@code runGhidraScript(scriptPath, args, programName)} threads the name
 * through {@code ServiceUtils.getProgramOrError} → {@code GhidraState}
 * → the script's {@code currentProgram} global, which is what the
 * operator actually wants.
 *
 * <p>This test is intentionally a source-level static check rather than
 * an integration test: the underlying behavior depends on Ghidra's
 * GhidraScript runtime + a live tool + multiple loaded programs, none
 * of which we can stand up cheaply in CI. A grep-based assertion is
 * cheap, deterministic, and would catch any regression where someone
 * changes the call back to the 2-arg form.
 */
public class RunGhidraScriptProgramPropagationTest extends TestCase {

    private static final Path SOURCE = Paths.get(
            "src", "main", "java", "com", "xebyte", "core",
            "ProgramScriptService.java");

    private String readSource() throws IOException {
        return new String(Files.readAllBytes(SOURCE), StandardCharsets.UTF_8);
    }

    /** Extract the body of the {@code @McpTool(path = "/<path>", ...)}-
     *  annotated method, walking forward from the annotation to the
     *  next opening brace + brace-matching. Anchoring on @McpTool
     *  disambiguates from any backward-compat overloads of the same
     *  Java method name. */
    private String extractAnnotatedMethodBody(String src, String mcpPath) {
        Pattern p = Pattern.compile(
                "@McpTool\\s*\\(\\s*path\\s*=\\s*\"" +
                        Pattern.quote(mcpPath) + "\"",
                Pattern.MULTILINE);
        Matcher m = p.matcher(src);
        if (!m.find()) {
            throw new AssertionError(
                    "Could not locate @McpTool path=\"" + mcpPath + "\"");
        }
        // Walk forward to the first '{' that opens the body, then brace-match.
        int i = src.indexOf('{', m.end());
        if (i < 0) throw new AssertionError("No body opener for " + mcpPath);
        int depth = 1;
        int j = i + 1;
        while (j < src.length() && depth > 0) {
            char c = src.charAt(j++);
            if (c == '{') depth++;
            else if (c == '}') depth--;
        }
        return src.substring(i, j);
    }

    public void testRunGhidraScriptWithCaptureForwardsProgramName() throws IOException {
        String src = readSource();
        String body = extractAnnotatedMethodBody(src, "/run_ghidra_script");

        // The 3-arg runGhidraScript call must be present and must include
        // programName. We require the literal `programName` token because
        // the @Param is named that way and it's the parameter the operator
        // actually controls.
        Pattern threeArgCall = Pattern.compile(
                "runGhidraScript\\s*\\(\\s*[^,]+,\\s*[^,]+,\\s*programName\\s*\\)",
                Pattern.MULTILINE | Pattern.DOTALL);
        assertTrue(
                "runGhidraScriptWithCapture must call the 3-arg runGhidraScript "
                        + "and pass `programName` as the third argument — without it, "
                        + "the script executes against the session currentProgram "
                        + "instead of the operator's requested program.",
                threeArgCall.matcher(body).find());
    }

    public void testRunGhidraScriptWithCaptureDoesNotCallTwoArgOverload() throws IOException {
        String src = readSource();
        String body = extractAnnotatedMethodBody(src, "/run_ghidra_script");

        // Detect the historical bug shape: runGhidraScript(scriptFile..., scriptArgs)
        // with NO third argument. We're lenient about whitespace + newlines
        // inside the parens but strict about the comma count.
        Pattern twoArgCall = Pattern.compile(
                "runGhidraScript\\s*\\([^()]*,[^,()]+\\)",
                Pattern.MULTILINE);
        Matcher m = twoArgCall.matcher(body);
        while (m.find()) {
            String call = m.group();
            // A 2-arg call has exactly one comma at the top level inside parens.
            // (3-arg has 2.) Bail if we see one.
            int commas = 0;
            int depth = 0;
            for (int k = 0; k < call.length(); k++) {
                char c = call.charAt(k);
                if (c == '(') depth++;
                else if (c == ')') depth--;
                else if (c == ',' && depth == 1) commas++;
            }
            if (commas == 1) {
                fail("Found a 2-arg runGhidraScript(...) call inside "
                        + "runGhidraScriptWithCapture: " + call
                        + " — this drops the operator's program parameter. "
                        + "Use the 3-arg form with programName.");
            }
        }
    }

    public void testRunGhidraScriptWithCaptureValidatesProgramEarly() throws IOException {
        String src = readSource();
        String body = extractAnnotatedMethodBody(src, "/run_ghidra_script");

        // We want the fail-fast `pe.hasError()` check so a missing program
        // surfaces a clean error before we burn time searching for the
        // script file. This is the existing UX contract; if a refactor
        // ever drops the early check, the user gets a worse error later.
        assertTrue(
                "runGhidraScriptWithCapture should call ServiceUtils.getProgramOrError "
                        + "and short-circuit on pe.hasError() before doing the script search.",
                body.contains("getProgramOrError")
                        && body.contains("pe.hasError()"));
    }
}
