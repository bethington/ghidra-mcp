package com.xebyte.offline;

import com.xebyte.core.ProgramScriptService;
import com.xebyte.core.Response;
import com.xebyte.core.SecurityConfig;
import com.xebyte.core.ThreadingStrategy;
import junit.framework.TestCase;

/**
 * Validation + guard coverage for ProgramScriptService (~2.3K LOC, previously only the
 * run-script propagation offline test). Exercises required-param guards, GUI-mode guards
 * (no PluginTool under the stub provider), and the script-execution security gate — all
 * before any program access, so they run offline.
 */
public class ProgramScriptServiceValidationTest extends TestCase {

    private ProgramScriptService scripts;

    @Override
    protected void setUp() {
        ThreadingStrategy ts = new NoopThreadingStrategy();
        scripts = new ProgramScriptService(ServiceFactory.stubProvider(), ts);
    }

    public void testCloseProgramRequiresName() {
        Response r = scripts.closeProgram("");
        assertTrue(r instanceof Response.Err);
        assertTrue(((Response.Err) r).message().contains("Program name or path is required"));
    }

    public void testSwitchProgramRequiresName() {
        Response r = scripts.switchProgram("");
        assertTrue(r instanceof Response.Err);
        assertTrue(((Response.Err) r).message().contains("Program name is required"));
    }

    public void testOpenProgramFromProjectRequiresPath() {
        Response r = scripts.openProgramFromProject("");
        assertTrue(r instanceof Response.Err);
        assertTrue(((Response.Err) r).message().contains("Program path is required"));
    }

    public void testImportFileRequiresFilePath() {
        Response r = scripts.importFile("", "/", "", "", true);
        assertTrue(r instanceof Response.Err);
        assertTrue(((Response.Err) r).message().contains("file_path is required"));
    }

    public void testListProjectFilesRequiresGuiMode() {
        // Stub provider exposes no PluginTool, so the GUI-only guard must fire.
        Response r = scripts.listProjectFiles("/");
        assertTrue(r instanceof Response.Err);
        assertTrue(((Response.Err) r).message().contains("requires GUI mode"));
    }

    public void testRunScriptInlineGatedByDefault() {
        // Security gate: arbitrary-code execution is off unless GHIDRA_MCP_ALLOW_SCRIPTS is set.
        // Assert the gate only in the (default) disabled state so the test is env-independent.
        if (!SecurityConfig.getInstance().areScriptsAllowed()) {
            Response r = scripts.runScriptInline("System.out.println(1);", "", "");
            assertTrue(r instanceof Response.Err);
            assertTrue(((Response.Err) r).message().contains("Script execution disabled"));
        }
    }
}
