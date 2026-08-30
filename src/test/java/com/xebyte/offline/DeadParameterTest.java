package com.xebyte.offline;

import junit.framework.TestCase;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * A parameter the server advertises must be a parameter the server reads.
 *
 * <p>An inert parameter is worse than a missing one. A missing parameter is
 * absent from {@code /mcp/schema}, so a model never reaches for it. An inert
 * one appears in the schema as a real switch: the model sets it, the call
 * succeeds, and the model then reasons about a result it believes it
 * configured. Nothing in the response says otherwise.
 *
 * <p>Found live on 2026-08-30 by a parameter-documentation sweep, which turned
 * up nine such parameters across six endpoints -- among them
 * {@code capture_output} on {@code /run_ghidra_script} (output was always
 * returned), {@code force_individual} on {@code /rename_variables} (the batch
 * path ran regardless, including for an in-tree caller that explicitly asked
 * for individual mode), and {@code host}/{@code port} on
 * {@code /server/connect} (vestiges of a connection model replaced by
 * {@code GHIDRA_SERVER_HOST}/{@code GHIDRA_SERVER_PORT}). Prompt-level care
 * had not caught any of them in the years they were live, which is the case
 * for enforcing it in the test layer instead.
 *
 * <p>The check is deliberately crude and therefore cheap: for every
 * {@code @McpTool} method, each {@code @Param}'s Java identifier must appear
 * at least once in that method's body. It cannot tell a parameter that is read
 * from one that is read and then ignored, but it catches the whole class of
 * "declared and never mentioned again", which is what all nine were.
 *
 * <p>Pure source-text -- no Ghidra runtime or program required.
 */
public class DeadParameterTest extends TestCase {

    /** Root of the annotated service sources. */
    private static final Path SRC = Paths.get("src", "main", "java", "com", "xebyte");

    /**
     * Files scanned for {@code @McpTool} methods but exempt from the body
     * check, because their {@code @McpTool} occurrences are not real tools.
     */
    private static final Set<String> EXEMPT_FILES = Set.of(
        // The annotation's own definition. Its javadoc carries a worked
        // /list_methods example whose parameters have no method body at all.
        "McpTool.java"
    );

    /**
     * Parameters that are genuinely declared and never read, each with the
     * reason it is tolerated rather than fixed. These are a real backlog, not
     * a dumping ground: every entry is an endpoint whose schema currently
     * advertises a control that does nothing. An addition to this list should
     * be a deliberate, argued decision -- the default answer to a new dead
     * parameter is to wire it up or to delete it.
     *
     * <p>Keyed {@code <tool path>#<parameter name>}.
     */
    private static final Map<String, String> KNOWN_INERT = new LinkedHashMap<>();
    static {
        KNOWN_INERT.put("/list_data_items_by_xrefs#format",
            "Documented no-op: kept so older callers that still pass format=text do not break. "
                + "Every response is JSON regardless. Removal is a breaking change with no benefit.");
        KNOWN_INERT.put("/find_next_undefined_function#criteria",
            "Never implemented. The endpoint scans forward from an address with fixed criteria. "
                + "Wiring it needs a decision about what the criteria vocabulary is.");
        KNOWN_INERT.put("/search_functions_enhanced#calling_convention",
            "Never implemented as a filter, though every sibling filter on this tool is. "
                + "This one is cheap to wire and should be.");
        KNOWN_INERT.put("/get_valid_data_types#category",
            "Never implemented. The endpoint returns the full built-in type vocabulary unfiltered.");
        KNOWN_INERT.put("/import_data_types#format",
            "Only C source is parseable (via Ghidra's CParser); the parameter anticipates other "
                + "formats that do not exist. Either validate it or remove it.");
        KNOWN_INERT.put("/create_folder#program",
            "Boilerplate 'program' on a project-level operation. Creating a folder does not involve "
                + "a program; the parameter was copied onto the signature and never used.");
    }

    /** One {@code @Param} found on one {@code @McpTool} method. */
    private record Param(String file, String toolPath, String paramName, String identifier) {
        String key() {
            return toolPath + "#" + paramName;
        }

        @Override
        public String toString() {
            return key() + " (Java identifier '" + identifier + "' in " + file + ")";
        }
    }

    private static final Pattern MCP_TOOL = Pattern.compile("@McpTool\\s*\\(");
    private static final Pattern PARAM = Pattern.compile("@Param\\s*\\(");
    private static final Pattern TOOL_PATH = Pattern.compile("path\\s*=\\s*\"([^\"]+)\"");
    private static final Pattern PARAM_VALUE = Pattern.compile("value\\s*=\\s*\"([^\"]+)\"");
    private static final Pattern FIRST_STRING = Pattern.compile("\"([^\"]+)\"");
    /** Trailing part of a parameter declaration: {@code <type> <identifier>} then , or ). */
    private static final Pattern DECLARATION = Pattern.compile(
        "\\A\\s*(?:final\\s+)?[\\w.<>\\[\\],\\s?]+?\\s+(\\w+)\\s*[,)]");

    /**
     * Index of the delimiter closing the one that opens at {@code start}.
     *
     * @param s     text to scan
     * @param start index of the opening delimiter
     * @param open  opening delimiter
     * @param close closing delimiter
     * @return index of the matching close, or -1 if unbalanced
     */
    private static int matchClose(String s, int start, char open, char close) {
        int depth = 0;
        for (int i = start; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == open) {
                depth++;
            } else if (c == close) {
                depth--;
                if (depth == 0) return i;
            }
        }
        return -1;
    }

    /**
     * Every {@code @Param} on every {@code @McpTool} method whose identifier is
     * never mentioned again inside that method's body.
     *
     * @return the inert parameters found, in source order
     * @throws IOException if a source file cannot be read
     */
    private static List<Param> findInertParams() throws IOException {
        List<Param> inert = new ArrayList<>();
        List<Path> files;
        try (Stream<Path> walk = Files.walk(SRC)) {
            files = walk.filter(p -> p.toString().endsWith(".java"))
                        .filter(p -> !EXEMPT_FILES.contains(p.getFileName().toString()))
                        .sorted()
                        .toList();
        }

        for (Path file : files) {
            String src = new String(Files.readAllBytes(file), StandardCharsets.UTF_8);
            Matcher tools = MCP_TOOL.matcher(src);
            while (tools.find()) {
                int annClose = matchClose(src, tools.end() - 1, '(', ')');
                if (annClose < 0) continue;
                String annotation = src.substring(tools.start(), annClose + 1);
                Matcher pathMatcher = TOOL_PATH.matcher(annotation);
                String toolPath = pathMatcher.find() ? pathMatcher.group(1) : "<unknown>";

                int sigOpen = src.indexOf('(', annClose);
                if (sigOpen < 0) continue;
                int sigClose = matchClose(src, sigOpen, '(', ')');
                if (sigClose < 0) continue;
                String signature = src.substring(sigOpen, sigClose + 1);

                int bodyOpen = src.indexOf('{', sigClose);
                if (bodyOpen < 0) continue;
                int bodyClose = matchClose(src, bodyOpen, '{', '}');
                if (bodyClose < 0) continue;
                String body = src.substring(bodyOpen, bodyClose + 1);

                Matcher params = PARAM.matcher(signature);
                while (params.find()) {
                    int pClose = matchClose(signature, params.end() - 1, '(', ')');
                    if (pClose < 0) continue;
                    String annotationArgs = signature.substring(params.end(), pClose + 1);
                    Matcher decl = DECLARATION.matcher(signature.substring(pClose + 1));
                    if (!decl.find()) continue;
                    String identifier = decl.group(1);

                    Matcher named = PARAM_VALUE.matcher(annotationArgs);
                    String paramName;
                    if (named.find()) {
                        paramName = named.group(1);
                    } else {
                        Matcher first = FIRST_STRING.matcher(annotationArgs);
                        paramName = first.find() ? first.group(1) : identifier;
                    }

                    if (!Pattern.compile("\\b" + Pattern.quote(identifier) + "\\b").matcher(body).find()) {
                        inert.add(new Param(file.getFileName().toString(), toolPath, paramName, identifier));
                    }
                }
            }
        }
        return inert;
    }

    /**
     * No {@code @McpTool} parameter may be declared and then never read, unless
     * it is a named, justified entry in {@link #KNOWN_INERT}.
     *
     * @throws IOException if a source file cannot be read
     */
    public void testNoUndeclaredDeadParameters() throws IOException {
        List<String> unexpected = new ArrayList<>();
        for (Param p : findInertParams()) {
            if (!KNOWN_INERT.containsKey(p.key())) {
                unexpected.add(p.toString());
            }
        }

        assertTrue(
            "These parameters are advertised in /mcp/schema but never read by the method that "
                + "declares them. A model will set them and then reason about a result it believes "
                + "it configured. Wire each one up, or remove it from the signature (and regenerate "
                + "tests/endpoints.json plus the README API reference). If it must stay inert, add it "
                + "to DeadParameterTest.KNOWN_INERT with the reason:\n  "
                + String.join("\n  ", unexpected),
            unexpected.isEmpty());
    }

    /**
     * A {@link #KNOWN_INERT} entry must still be inert. When one is finally
     * wired up, its entry has to go -- otherwise the allowlist quietly grants
     * a permanent exemption to a parameter that no longer needs one, and the
     * next parameter to go dead on that endpoint inherits the pass.
     *
     * @throws IOException if a source file cannot be read
     */
    public void testKnownInertListHasNoStaleEntries() throws IOException {
        Set<String> stillInert = new LinkedHashSet<>();
        for (Param p : findInertParams()) {
            stillInert.add(p.key());
        }

        List<String> stale = new ArrayList<>();
        for (String key : KNOWN_INERT.keySet()) {
            if (!stillInert.contains(key)) stale.add(key);
        }

        assertTrue(
            "These parameters are listed in DeadParameterTest.KNOWN_INERT but are now read by their "
                + "method -- someone wired them up. Delete the entries so the allowlist keeps "
                + "describing reality:\n  " + String.join("\n  ", stale),
            stale.isEmpty());
    }

    /**
     * The three parameters wired up on 2026-08-30 must stay wired. Each was
     * live in the schema for years while doing nothing, so a regression here is
     * silent by nature -- callers keep setting the flag and keep getting the
     * old behaviour.
     *
     * @throws IOException if a source file cannot be read
     */
    public void testParametersWiredUpStayWired() throws IOException {
        Set<String> inert = new LinkedHashSet<>();
        for (Param p : findInertParams()) {
            inert.add(p.key());
        }

        for (String key : List.of(
                "/run_ghidra_script#capture_output",
                "/rename_variables#force_individual")) {
            assertFalse(
                key + " has gone inert again. It was wired up specifically because advertising a "
                    + "switch that does nothing misleads every caller that sets it.",
                inert.contains(key));
        }
    }

    /**
     * {@code /server/version_control/add} must pass the caller's
     * {@code keepCheckedOut} to Ghidra rather than a hardcoded {@code false}.
     *
     * <p>Not covered by the scan above: the route is registered with
     * {@code createContext}, not {@code @McpTool}, so its parameters live in
     * {@link com.xebyte.core.ManualToolDescriptors} instead of an annotation.
     *
     * @throws IOException if the source cannot be read
     */
    public void testAddToVersionControlHonorsKeepCheckedOut() throws IOException {
        String src = new String(
            Files.readAllBytes(SRC.resolve("GhidraMCPPlugin.java")), StandardCharsets.UTF_8);

        assertTrue(
            "The /server/version_control/add handler must read the keepCheckedOut parameter it "
                + "advertises in ManualToolDescriptors.",
            src.contains("addToVersionControl(filePath, comment, keepCheckedOut)"));

        assertFalse(
            "addToVersionControl must not hardcode keepCheckedOut=false -- that is exactly the bug "
                + "this test exists for. Pass the caller's value through to DomainFile.",
            src.contains("file.addToVersionControl(comment, false,"));

        assertTrue(
            "addToVersionControl must pass the caller's flag to DomainFile.addToVersionControl.",
            src.contains("file.addToVersionControl(comment, keepCheckedOut,"));
    }

    /**
     * Parameters removed on 2026-08-30 must not come back. Each promised
     * behaviour that does not exist anywhere in the codebase, so a
     * well-meaning re-add would restore the original misleading schema rather
     * than the behaviour.
     *
     * @throws IOException if a source file cannot be read
     */
    public void testRemovedParametersAreNotReintroduced() throws IOException {
        Map<String, String> banned = new LinkedHashMap<>();
        banned.put("include_assembly_patterns",
            "/analyze_data_region does no assembly analysis. Use /get_assembly_context.");
        banned.put("analyze_loop_bounds",
            "/detect_array_bounds does a fixed xref scan; there is no loop-bound analysis to toggle.");
        banned.put("analyze_indexing",
            "/detect_array_bounds does a fixed xref scan; there is no indexing analysis to toggle.");
        banned.put("include_patterns",
            "/get_assembly_context always reports detected patterns; it was a required parameter "
                + "that did nothing.");

        List<Path> files;
        try (Stream<Path> walk = Files.walk(SRC)) {
            files = walk.filter(p -> p.toString().endsWith(".java")).sorted().toList();
        }

        List<String> found = new ArrayList<>();
        for (Path file : files) {
            String src = new String(Files.readAllBytes(file), StandardCharsets.UTF_8);
            for (Map.Entry<String, String> e : banned.entrySet()) {
                if (src.contains("@Param(value = \"" + e.getKey() + "\"")) {
                    found.add(file.getFileName() + ": " + e.getKey() + " -- " + e.getValue());
                }
            }
        }

        assertTrue(
            "These parameters were removed because nothing implemented them. Re-adding the "
                + "declaration without the behaviour restores the original bug:\n  "
                + String.join("\n  ", found),
            found.isEmpty());
    }

    /**
     * {@code /server/connect} takes no parameters. It reports the open project
     * in GUI mode, and in headless mode connects using the host and port
     * {@code GhidraServerManager} read from the environment at construction --
     * both {@code final} fields, set before any request arrives.
     *
     * @throws IOException if a source file cannot be read
     */
    public void testServerConnectAdvertisesNoHostOrPort() throws IOException {
        String src = new String(
            Files.readAllBytes(SRC.resolve("core").resolve("ManualToolDescriptors.java")),
            StandardCharsets.UTF_8);

        int idx = src.indexOf("\"/server/connect\"");
        assertTrue("/server/connect descriptor not found in ManualToolDescriptors", idx >= 0);
        int end = src.indexOf(");", idx);
        String descriptor = src.substring(idx, end < 0 ? src.length() : end);

        assertFalse(
            "/server/connect advertises a 'host' parameter, but neither handler reads one: "
                + "GhidraServerManager.connect() takes no arguments and its host field is final, "
                + "initialised from GHIDRA_SERVER_HOST at construction.",
            descriptor.contains("\"host\""));
        assertFalse(
            "/server/connect advertises a 'port' parameter, but neither handler reads one: "
                + "GhidraServerManager.connect() takes no arguments and its port field is final, "
                + "initialised from GHIDRA_SERVER_PORT at construction.",
            descriptor.contains("\"port\""));
    }
}
