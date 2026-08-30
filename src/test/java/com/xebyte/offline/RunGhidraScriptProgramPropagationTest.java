package com.xebyte.offline;

import junit.framework.TestCase;

import java.io.IOException;
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
 *
 * <p>The source is read through {@link ProjectSource}, which anchors on the
 * project root instead of the working directory and normalises line endings
 * to LF. Before that, this class asserted against literals containing
 * {@code "\n"}, so it failed on any checkout made with Git for Windows'
 * default {@code core.autocrlf=true} — reported as a broken test suite by two
 * separate outside contributors (#447, #448).
 */
public class RunGhidraScriptProgramPropagationTest extends TestCase {

    private String readSource() throws IOException {
        return ProjectSource.readMainSource("core", "ProgramScriptService.java");
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

        // The 4-arg runGhidraScript call must be present and must include
        // programName plus timeoutSeconds. We require the literal `programName` token because
        // the @Param is named that way and it's the parameter the operator
        // actually controls.
        Pattern timeoutAwareCall = Pattern.compile(
                "runGhidraScript\\s*\\(\\s*[^,]+,\\s*[^,]+,\\s*programName\\s*,\\s*timeoutSeconds\\s*\\)",
                Pattern.MULTILINE | Pattern.DOTALL);
        assertTrue(
                "runGhidraScriptWithCapture must call the timeout-aware runGhidraScript "
                        + "and pass `programName` plus `timeoutSeconds` — without it, "
                        + "the script executes against the session currentProgram "
                        + "instead of the operator's requested program.",
                timeoutAwareCall.matcher(body).find());
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

    public void testRunGhidraScriptInitializesAndRefreshesHeadlessScriptBundleBeforeProviderLookup()
            throws IOException {
        String src = readSource();

        assertTrue(
                "ProgramScriptService needs an explicit headless script bundle "
                        + "host initializer because the GUI Script Manager is not "
                        + "present in the headless MCP sidecar.",
                src.contains("ensureScriptBundleHostInitialized"));
        assertTrue(
                "The headless script bundle initializer must enable the final "
                        + "script source directory after the script file exists; "
                        + "otherwise Ghidra can retain a placeholder bundle and "
                        + "JavaScriptProvider cannot find the OSGi bundle.",
                src.contains(".enable(new generic.jar.ResourceFile(scriptDirectory))"));

        // Whitespace-tolerant: the previous form was a literal containing
        // "\n" plus exactly twelve spaces, which broke on a CRLF checkout and
        // would also break on any reformat of the declaration.
        int methodStart = HardeningWiringTest.indexOfScriptPathOverload(src);
        assertTrue("Could not locate the runGhidraScript overload declaring the "
                + "script_path @Param", methodStart >= 0);

        int initCall = src.indexOf("ensureScriptBundleHostInitialized("
                + "scriptFileForExecution.getParentFile())", methodStart);
        int copyWarning = src.indexOf("Warning: Could not copy script to ~/ghidra_scripts/", methodStart);
        int initError = src.indexOf("ERROR: Could not initialize Ghidra script bundle host for:", methodStart);
        int providerLookup = src.indexOf("GhidraScriptUtil.getProvider", methodStart);

        assertTrue(
                "runGhidraScript must initialize and refresh GhidraScriptUtil's "
                        + "BundleHost for the final script directory before "
                        + "resolving JavaScriptProvider; otherwise headless Java "
                        + "scripts fail before execution.",
                initCall >= 0 && providerLookup >= 0 && initCall < providerLookup);
        assertTrue(
                "Script bundle initialization failures must have their own "
                        + "diagnostic instead of being mislabeled as copy "
                        + "warnings.",
                copyWarning >= 0 && initError >= 0 && copyWarning < initCall
                        && initCall < initError && initError < providerLookup);
    }
}
