package com.xebyte.offline;

import junit.framework.TestCase;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Source-level regression tests pinning the v5.17 pre-release hardening in
 * place. These are deliberately grep-style static checks (same rationale as
 * {@link RunGhidraScriptProgramPropagationTest}): the behaviors depend on a
 * live HTTP server, a browser, a Unix domain socket, or a configured
 * {@code GHIDRA_MCP_PROJECT_FOLDER} — none of which stand up cheaply in CI —
 * but a wiring regression (someone deleting a guard during a refactor) is
 * exactly the failure mode that a cheap source assertion catches.
 */
public class HardeningWiringTest extends TestCase {

    private static String read(String... parts) throws IOException {
        Path p = Paths.get("src", "main", "java", "com", "xebyte");
        for (String s : parts) p = p.resolve(s);
        return new String(Files.readAllBytes(p), StandardCharsets.UTF_8);
    }

    /** The TCP request wrapper must invoke the cross-origin guard. */
    public void testTcpSafeHandlerCallsCrossOriginGuard() throws IOException {
        String src = read("GhidraMCPPlugin.java");
        assertTrue("safeHandler must call rejectCrossOriginRequest",
                src.contains("rejectCrossOriginRequest("));
    }

    /** The headless request wrapper must invoke the cross-origin guard. */
    public void testHeadlessSafeContextCallsCrossOriginGuard() throws IOException {
        String src = read("headless", "GhidraMCPHeadlessServer.java");
        assertTrue("safeContext must call rejectCrossOriginRequest",
                src.contains("rejectCrossOriginRequest("));
    }

    /**
     * The UDS dispatch loop must enforce the bearer token before invoking the
     * handler — otherwise a configured token silently doesn't apply on the
     * socket transport.
     */
    public void testUdsDispatchEnforcesBearerAuth() throws IOException {
        String src = read("core", "UdsHttpServer.java");
        assertTrue("UDS dispatch must check matchesBearerAuth",
                src.contains("matchesBearerAuth("));
        assertTrue("UDS dispatch must exempt only health paths",
                src.contains("isAuthExemptPath("));
        // The auth check must sit before the handler is invoked, not after.
        int authIdx = src.indexOf("matchesBearerAuth(");
        int handleIdx = src.indexOf("handler.handle(exchange)");
        assertTrue("Bearer check must precede handler.handle()",
                authIdx > 0 && handleIdx > 0 && authIdx < handleIdx);
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
     */
    public void testRunGhidraScriptSinkIsGated() throws IOException {
        String src = read("core", "ProgramScriptService.java");
        int sig = src.indexOf("public Response runGhidraScript(\n"
                + "            @Param(value = \"script_path\"");
        assertTrue("Could not locate 3-arg runGhidraScript", sig >= 0);
        // The areScriptsAllowed() gate must appear early in the method body,
        // before the program is resolved.
        int gate = src.indexOf("areScriptsAllowed()", sig);
        int resolve = src.indexOf("getProgramOrError", sig);
        assertTrue("runGhidraScript sink must check areScriptsAllowed()", gate >= 0);
        assertTrue("Gate must precede program resolution", gate < resolve);
    }

    /** The dead, ungated /run_script route must stay unregistered. */
    public void testRunScriptRouteNotRegistered() throws IOException {
        String src = read("core", "EndpointRegistry.java");
        assertFalse("EndpointRegistry must not register the ungated /run_script route",
                src.contains("post(\"/run_script\""));
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
