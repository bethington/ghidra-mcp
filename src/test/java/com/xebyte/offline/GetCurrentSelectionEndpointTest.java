package com.xebyte.offline;

import junit.framework.TestCase;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Regression: the {@code /get_current_selection} GUI-only endpoint exists.
 *
 * <p>Community report (@I-Knight-I on issue #153, 2026-05-22): the
 * "where am I?" tool family was incomplete — {@code /get_current_address}
 * and {@code /get_current_function} were registered (hand-registered in
 * the GUI plugin, GUI-only), but the third sibling expected by AI
 * clients, {@code /get_current_selection}, didn't exist.
 *
 * <p>These tests pin three invariants at the source level (no live
 * Ghidra needed):
 *
 * <ol>
 *   <li>{@code GhidraMCPPlugin.java} registers a route handler for
 *       {@code /get_current_selection} via {@code server.createContext}.</li>
 *   <li>A private helper {@code getCurrentSelection()} exists alongside
 *       the existing {@code getCurrentAddress()} / {@code getCurrentFunction()}
 *       helpers and uses {@code CodeViewerService.getCurrentSelection()} —
 *       the canonical Ghidra API for the listing's highlight state.</li>
 *   <li>{@code tests/endpoints.json} catalogs the endpoint so the
 *       parity test counts it and downstream tooling (bridge schema
 *       generation, docs) sees it.</li>
 * </ol>
 *
 * <p>Static-analysis tests rather than integration because exercising
 * the real path requires a CodeBrowser with a live selection — a
 * GUI-only context that CI can't stand up.
 */
public class GetCurrentSelectionEndpointTest extends TestCase {

    private String readUtf8(String relativePath) throws IOException {
        return new String(
                Files.readAllBytes(Paths.get(relativePath)),
                StandardCharsets.UTF_8);
    }

    public void testPluginRegistersGetCurrentSelectionRoute() throws IOException {
        String src = readUtf8("src/main/java/com/xebyte/GhidraMCPPlugin.java");
        Pattern p = Pattern.compile(
                "server\\.createContext\\s*\\(\\s*\"/get_current_selection\"",
                Pattern.MULTILINE);
        assertTrue(
                "GhidraMCPPlugin.java must register a route handler for "
                        + "/get_current_selection (filed by @I-Knight-I on issue #153)",
                p.matcher(src).find());
    }

    public void testGetCurrentSelectionHelperUsesCodeViewerService() throws IOException {
        String src = readUtf8("src/main/java/com/xebyte/GhidraMCPPlugin.java");
        // Find the helper declaration.
        Pattern decl = Pattern.compile(
                "private\\s+String\\s+getCurrentSelection\\s*\\(\\s*\\)\\s*\\{",
                Pattern.MULTILINE);
        Matcher m = decl.matcher(src);
        assertTrue(
                "GhidraMCPPlugin must declare a private getCurrentSelection() helper "
                        + "to mirror getCurrentAddress() / getCurrentFunction().",
                m.find());

        // Extract the body via brace matching.
        int braceStart = m.end() - 1; // the '{' we matched
        int depth = 1;
        int j = braceStart + 1;
        while (j < src.length() && depth > 0) {
            char c = src.charAt(j++);
            if (c == '{') depth++;
            else if (c == '}') depth--;
        }
        String body = src.substring(braceStart, j);

        assertTrue(
                "getCurrentSelection() must read from "
                        + "CodeViewerService.getCurrentSelection() — that's the "
                        + "canonical Ghidra API for the listing's highlight state.",
                body.contains("service.getCurrentSelection()"));

        // The route is GUI-only; mirror the same "Code viewer service not
        // available" prose as the sibling tools so AI clients can fall
        // through with one error path.
        assertTrue(
                "getCurrentSelection() must return the same 'Code viewer service "
                        + "not available' string the sibling current_* tools return when "
                        + "no CodeBrowser is up — one error shape for AI clients.",
                body.contains("Code viewer service not available"));
    }

    public void testCatalogIncludesGetCurrentSelection() throws IOException {
        String catalog = readUtf8("tests/endpoints.json");
        assertTrue(
                "tests/endpoints.json must list /get_current_selection so the "
                        + "AnnotationScanner parity + bridge schema see it.",
                catalog.contains("\"path\": \"/get_current_selection\""));
        // It must NOT take a `program` param — selection is a UI concept
        // that belongs to whatever the CodeBrowser is currently showing,
        // so a `program=` query parameter would be misleading.
        Pattern entry = Pattern.compile(
                "\\{\\s*\"path\"\\s*:\\s*\"/get_current_selection\"[^}]*?\"params\"\\s*:\\s*\\[\\s*\\]",
                Pattern.DOTALL);
        assertTrue(
                "The /get_current_selection catalog entry must declare "
                        + "params: [] — selection is a UI-state read, no program arg.",
                entry.matcher(catalog).find());
    }
}
