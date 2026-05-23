package com.xebyte.offline;

import junit.framework.TestCase;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Source-level invariants for the GUI-side {@code /open_project} route.
 *
 * <p>The headless server has had {@code /open_project} since v4.x. The
 * GUI plugin gained its own implementation as part of Option C — a
 * "GUI but no CodeBrowser" mode where automation can point Ghidra at a
 * project programmatically and decide separately whether to spawn a
 * CodeBrowser. The GUI handler accepts an optional {@code headless}
 * boolean (default true) and an optional {@code program} path used only
 * when {@code headless == false}.
 *
 * <p>These are static-analysis checks rather than integration tests
 * because opening + switching projects requires a live FrontEnd tool
 * with a real {@code .gpr} on disk — state CI can't stand up.
 */
public class OpenProjectGuiEndpointTest extends TestCase {

    private String readUtf8(String relativePath) throws IOException {
        return new String(
                Files.readAllBytes(Paths.get(relativePath)),
                StandardCharsets.UTF_8);
    }

    public void testPluginRegistersOpenProjectRoute() throws IOException {
        String src = readUtf8("src/main/java/com/xebyte/GhidraMCPPlugin.java");
        Pattern p = Pattern.compile(
                "server\\.createContext\\s*\\(\\s*\"/open_project\"",
                Pattern.MULTILINE);
        assertTrue(
                "GhidraMCPPlugin.java must register a route handler for "
                        + "/open_project so the GUI server exposes the same tool "
                        + "name the headless server does.",
                p.matcher(src).find());
    }

    public void testOpenProjectHandlerReadsHeadlessAndProgramParams() throws IOException {
        String src = readUtf8("src/main/java/com/xebyte/GhidraMCPPlugin.java");
        // The route registration block should parse the body, default
        // `headless` to true (option C semantics), and forward the
        // optional `program` to launchCodeBrowser when the user asked
        // for a non-headless open.
        Pattern routeBlock = Pattern.compile(
                "server\\.createContext\\(\\s*\"/open_project\"[\\s\\S]*?openProject\\s*\\(",
                Pattern.MULTILINE);
        Matcher m = routeBlock.matcher(src);
        assertTrue("Expected /open_project route block to call openProject(...)",
                m.find());
        String block = src.substring(m.start(), Math.min(src.length(), m.end() + 200));

        assertTrue(
                "Route must read the `headless` body param (with true as the default).",
                block.contains("\"headless\""));
        assertTrue(
                "Default for headless must be true so existing automation "
                        + "doesn't spontaneously start launching CodeBrowsers.",
                block.contains("== null")
                        || block.contains("getOrDefault"));
        assertTrue(
                "Route must read the optional `program` param so non-headless "
                        + "opens can auto-launch CodeBrowser for a specific file.",
                block.contains("\"program\""));
    }

    public void testOpenProjectHelperRunsOnEDT() throws IOException {
        String src = readUtf8("src/main/java/com/xebyte/GhidraMCPPlugin.java");
        // Find the private helper.
        Pattern decl = Pattern.compile(
                "private\\s+String\\s+openProject\\s*\\(\\s*String[^)]*\\)\\s*\\{",
                Pattern.MULTILINE);
        Matcher m = decl.matcher(src);
        assertTrue(
                "GhidraMCPPlugin must declare a private openProject(String, boolean, String) helper.",
                m.find());

        int braceStart = m.end() - 1;
        int depth = 1;
        int j = braceStart + 1;
        while (j < src.length() && depth > 0) {
            char c = src.charAt(j++);
            if (c == '{') depth++;
            else if (c == '}') depth--;
        }
        String body = src.substring(braceStart, j);

        assertTrue(
                "openProject must invoke ProjectManager.openProject(locator, ...) "
                        + "— that's the canonical API for opening into the FrontEnd.",
                body.contains("pm.openProject(locator"));
        assertTrue(
                "openProject must run the open/close on the EDT — FrontEnd "
                        + "state updates expect Swing.",
                body.contains("SwingUtilities.invokeAndWait"));
        assertTrue(
                "openProject must call AppInfo.setActiveProject so the FrontEnd "
                        + "UI reflects the new project.",
                body.contains("AppInfo.setActiveProject"));
        assertTrue(
                "openProject must short-circuit when the requested project is "
                        + "already the active one — silent re-open would needlessly "
                        + "close and reopen the same project, dropping CodeBrowser state.",
                body.contains("already_open"));
    }

    public void testCatalogIncludesOpenProjectParams() throws IOException {
        String catalog = readUtf8("tests/endpoints.json");
        // The catalog has a single /open_project entry shared with the
        // headless server. The GUI side added two optional params
        // (`headless`, `program`) — the entry must list both so the
        // bridge schema and parity test see them.
        Pattern entry = Pattern.compile(
                "\\{\\s*\"path\"\\s*:\\s*\"/open_project\"[^}]*?\"params\"\\s*:\\s*\\[(?<params>[^\\]]*)\\]",
                Pattern.DOTALL);
        Matcher m = entry.matcher(catalog);
        assertTrue("tests/endpoints.json must list /open_project.", m.find());
        String params = m.group("params");
        assertTrue(
                "/open_project params must include 'path' (required, both modes).",
                params.contains("\"path\""));
        assertTrue(
                "/open_project params must include 'headless' (GUI mode adds it).",
                params.contains("\"headless\""));
        assertTrue(
                "/open_project params must include 'program' (GUI mode optional auto-launch).",
                params.contains("\"program\""));
    }
}
