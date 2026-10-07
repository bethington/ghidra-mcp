package com.xebyte.offline;

import com.xebyte.core.ProgramScriptService;
import com.xebyte.core.Response;
import com.xebyte.core.SecurityConfig;
import junit.framework.TestCase;

import java.io.IOException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Source-level regression tests pinning the v5.17 pre-release hardening in
 * place. These are deliberately grep-style static checks (same rationale as
 * {@link RunGhidraScriptProgramPropagationTest}): the behaviors depend on a
 * live HTTP server, a browser, a Unix domain socket, or a configured
 * {@code GHIDRA_MCP_PROJECT_FOLDER} — none of which stand up cheaply in CI —
 * but a wiring regression (someone deleting a guard during a refactor) is
 * exactly the failure mode that a cheap source assertion catches.
 *
 * <p>Sources are read through {@link ProjectSource}, which anchors on the
 * project root rather than the working directory and normalises line endings.
 * See that class for why: this test and
 * {@code RunGhidraScriptProgramPropagationTest} were the two that failed on a
 * CRLF checkout, which is what Git for Windows produces by default.
 */
public class HardeningWiringTest extends TestCase {

    private static String read(String... parts) throws IOException {
        return ProjectSource.readMainSource(parts);
    }

    /**
     * McpHttpServer's guard -- which every route on every transport of both the
     * headless server and the GUI plugin goes through -- must apply the
     * cross-origin guard (on TCP) and the bearer token before the handler runs.
     */
    public void testMcpHttpServerGuardsEveryRoute() throws IOException {
        String src = read("core", "McpHttpServer.java");
        assertTrue("guard must call rejectCrossOriginRequest",
                src.contains("rejectCrossOriginRequest("));
        assertTrue("guard must check matchesBearerAuth",
                src.contains("matchesBearerAuth("));
        int authIdx = src.indexOf("matchesBearerAuth(");
        int handleIdx = src.indexOf("handler.handle(exchange)");
        assertTrue("Bearer check must precede handler.handle()",
                authIdx > 0 && handleIdx > 0 && authIdx < handleIdx);
        assertTrue("UDS routes must be registered through the guard",
                src.contains("uds.createContext(path, guard(handler, false))"));
        assertTrue("TCP routes must be registered through the guard",
                src.contains("guard(handler, true)"));
    }

    /** Destructive project ops must honor the project-scope containment guard. */
    public void testDestructiveOpsEnforceProjectScope() throws IOException {
        String src = read("core", "ProgramScriptService.java");
        String delete = body(src, "/delete_file");
        String create = body(src, "/create_folder");
        assertTrue("deleteFile must call isPathInProjectScope",
                delete.contains("isPathInProjectScope("));
        assertTrue("createFolder must call isPathInProjectScope",
                create.contains("isPathInProjectScope("));
    }

    /**
     * The script-execution gate must live on the sink (the 3-arg
     * runGhidraScript), not only on the callers, so no route can bypass it.
     *
     * <p>Behavioural check: with {@code GHIDRA_MCP_ALLOW_SCRIPTS} unset the
     * sink must refuse, and it must refuse <em>before</em> resolving the
     * program — which is why a deliberately nonexistent program name is
     * passed. If the gate ever moved after program resolution, the stub
     * provider would produce a "program not found" error instead and this
     * assertion would fail. That is a strictly stronger statement than the
     * source ordering check below, which stays as the backstop for the case
     * where a developer has scripts enabled in their environment.
     */
    public void testRunGhidraScriptSinkRefusesBeforeResolvingProgram() {
        if (SecurityConfig.getInstance().areScriptsAllowed()) {
            // GHIDRA_MCP_ALLOW_SCRIPTS is set in this environment, so the gate
            // is deliberately open and its refusal cannot be observed. The
            // source-level ordering check below still runs.
            return;
        }
        ProgramScriptService scripts = new ProgramScriptService(
                ServiceFactory.stubProvider(), new NoopThreadingStrategy());
        Response r = scripts.runGhidraScript(
                "AnyScript.java", "", "no-such-program-should-never-resolve", 0);
        assertTrue("Sink must return an error when scripts are disabled",
                r instanceof Response.Err);
        String msg = ((Response.Err) r).message();
        assertTrue("The 3-arg/4-arg runGhidraScript sink must refuse with the "
                        + "script-execution gate message before it resolves the "
                        + "requested program — got: " + msg,
                msg.contains("Script execution disabled"));
    }

    /**
     * Source backstop for the same property: the {@code areScriptsAllowed()}
     * gate must textually precede program resolution inside the sink. Kept
     * because the behavioural test above cannot observe the gate when a
     * developer has {@code GHIDRA_MCP_ALLOW_SCRIPTS} set.
     */
    public void testRunGhidraScriptSinkIsGated() throws IOException {
        String src = read("core", "ProgramScriptService.java");
        int sig = indexOfScriptPathOverload(src);
        assertTrue("Could not locate the runGhidraScript overload declaring the "
                + "script_path @Param", sig >= 0);
        // The areScriptsAllowed() gate must appear early in the method body,
        // before the program is resolved.
        int gate = src.indexOf("areScriptsAllowed()", sig);
        int resolve = src.indexOf("getProgramOrError", sig);
        assertTrue("runGhidraScript sink must check areScriptsAllowed()", gate >= 0);
        assertTrue("Gate must precede program resolution", gate < resolve);
    }

    /**
     * Locate the {@code runGhidraScript} overload whose first parameter is the
     * {@code script_path} {@code @Param}. Whitespace-tolerant on purpose: the
     * previous form was a literal containing {@code "\n"} plus exactly twelve
     * spaces, so it broke both on a CRLF checkout and on any reformat of the
     * declaration.
     *
     * @return offset of the declaration, or -1
     */
    static int indexOfScriptPathOverload(String src) {
        Matcher m = SCRIPT_PATH_OVERLOAD.matcher(src);
        return m.find() ? m.start() : -1;
    }

    static final Pattern SCRIPT_PATH_OVERLOAD = Pattern.compile(
            "public\\s+Response\\s+runGhidraScript\\s*\\(\\s*"
                    + "@Param\\s*\\(\\s*value\\s*=\\s*\"script_path\"",
            Pattern.MULTILINE | Pattern.DOTALL);

    /** The dead, ungated /run_script route must stay unregistered.
     *  (The old dead EndpointRegistry router was removed in 7.0.0.) */
    public void testRunScriptRouteNotRegistered() throws IOException {
        String plugin = read("GhidraMCPPlugin.java");
        assertFalse("GhidraMCPPlugin must not register the ungated /run_script route",
                plugin.contains("createContext(\"/run_script\""));
    }

    /** Request bodies must be bounded on every transport. */
    public void testRequestBodiesAreBounded() throws IOException {
        assertTrue("JsonHelper.parseBody must bound the read via readNBytes",
                read("core", "JsonHelper.java").contains("readNBytes"));
        assertTrue("GUI hand-coded routes must read bodies through the bounded JsonHelper.parseBody",
                read("GhidraMCPPlugin.java").contains("JsonHelper.parseBody("));
        assertTrue("McpHttpServer must reject an oversized Content-Length (413)",
                read("core", "McpHttpServer.java").contains("exceedsMaxBody"));
        assertTrue("UDS must reject oversized Content-Length (413)",
                read("core", "UdsHttpServer.java").contains("MAX_REQUEST_BODY_BYTES"));
    }

    /**
     * Top-level uncaught-exception handlers must not echo raw exception text
     * to the client (path / class-name disclosure). Deliberate per-endpoint
     * validation messages are unaffected.
     */
    public void testTopLevelErrorsAreGeneric() throws IOException {
        assertTrue("McpHttpServer guard catch must return a generic message",
                read("core", "McpHttpServer.java")
                        .contains("Internal server error. See the Ghidra application log"));
    }

    /** Headless filesystem endpoints must honor GHIDRA_MCP_FILE_ROOT. */
    public void testHeadlessFsEndpointsEnforceFileRoot() throws IOException {
        String src = read("headless", "HeadlessManagementService.java");
        // create_project, export_program, import_program, archive_project all
        // route their path input through the containment helper.
        int helperUses = countOccurrences(src, "resolveWithinRootOrLog(");
        assertTrue("Expected create/export/import/archive to each call "
                + "resolveWithinRootOrLog (>=4 uses incl. helper def), found " + helperUses,
                helperUses >= 5);
    }

    /** /open_project takes a filesystem path on both servers, so both contain it. */
    public void testOpenProjectEnforcesFileRootOnBothServers() throws IOException {
        String headless = body(read("headless", "HeadlessManagementService.java"), "/open_project");
        assertTrue("headless /open_project must resolve a local path within the file root",
                headless.contains("resolveWithinRootOrLog("));
        assertTrue("a ghidra:// URL is a repository, not a filesystem path",
                headless.contains("ghidra://"));
        String gui = read("GhidraMCPPlugin.java");
        int at = gui.indexOf("private String openProject(String projectPath, boolean headless");
        assertTrue("GUI openProject not found", at >= 0);
        assertTrue("GUI /open_project must resolve the path within the file root",
                gui.substring(at, at + 2500).contains("resolveWithinFileRoot("));
    }

    /** A scoped server must not check in outside its scope either. */
    public void testCheckinEnforcesProjectFolderScope() throws IOException {
        String src = read("core", "ProjectVersionControl.java");
        int lookup = src.indexOf("private FileOrError file(String path)");
        assertTrue("the file lookup must exist", lookup >= 0);
        int scope = src.indexOf("isPathInProjectScope(", lookup);
        assertTrue("every operation that names a file goes through file(), which must apply the scope",
                scope > lookup && scope < src.indexOf("getFile(normalized)", lookup));
        assertTrue("the folder walks must skip files outside the scope too",
                src.split("isPathInProjectScope\\(", -1).length >= 4);
    }

    private static int countOccurrences(String s, String sub) {
        int n = 0, i = 0;
        while ((i = s.indexOf(sub, i)) >= 0) { n++; i += sub.length(); }
        return n;
    }

    /** Extract a method body by walking forward from its @McpTool path. */
    private static String body(String src, String mcpPath) {
        int at = src.indexOf("path = \"" + mcpPath + "\"");
        assertTrue("Could not find @McpTool path=\"" + mcpPath + "\"", at >= 0);
        int open = src.indexOf('{', at);
        int depth = 1, j = open + 1;
        while (j < src.length() && depth > 0) {
            char c = src.charAt(j++);
            if (c == '{') depth++;
            else if (c == '}') depth--;
        }
        return src.substring(open, j);
    }
}
