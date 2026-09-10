package com.xebyte.offline;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.xebyte.core.AnnotationScanner;
import com.xebyte.core.ManualToolDescriptors;
import com.xebyte.core.ProgramProvider;
import junit.framework.TestCase;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Lock in parity between the runtime annotation scan and
 * {@code tests/endpoints.json} — the authoritative catalog that
 * {@code CLAUDE.md} points at as the public tool inventory.
 *
 * <p>When a developer adds a new {@code @McpTool} but forgets to update
 * {@code tests/endpoints.json} (or vice versa) the catalog silently drifts.
 * This test fails fast so the drift is caught at {@code mvn test} time
 * instead of after a release.
 *
 * <p>Runs fully offline — no Ghidra HTTP server required. This is part of
 * issue #112 (offline CI fixtures).
 */
public class EndpointsJsonParityTest extends TestCase {

    private static final String CATALOG_PATH = "tests/endpoints.json";

    /** Loaded endpoint descriptors from the JSON catalog, keyed by path. */
    private Map<String, CatalogEntry> catalog;

    /** Annotation-scanned endpoints. */
    private AnnotationScanner scanner;

    @Override
    protected void setUp() throws IOException {
        catalog = loadCatalog();
        ProgramProvider provider = ServiceFactory.stubProvider();
        scanner = new AnnotationScanner(provider, ServiceFactory.buildAllServices());
    }

    /**
     * Every annotation-scanned endpoint must appear in
     * {@code tests/endpoints.json}.
     *
     * <p>This catches the "added a tool but forgot the catalog" regression.
     */
    public void testEveryScannedEndpointIsInCatalog() {
        List<String> missing = new ArrayList<>();
        for (AnnotationScanner.ToolDescriptor tool : scanner.getDescriptors()) {
            if (!catalog.containsKey(tool.path())) {
                missing.add(tool.method() + " " + tool.path());
            }
        }

        // Print a help message with the exact JSON to add — the biggest friction
        // with parity failures is figuring out what to paste where.
        if (!missing.isEmpty()) {
            StringBuilder msg = new StringBuilder();
            msg.append(missing.size()).append(" annotation-scanned endpoint(s) missing from ")
               .append(CATALOG_PATH).append(":\n");
            for (String m : missing) {
                msg.append("  - ").append(m).append("\n");
            }
            msg.append("\nAdd entries to tests/endpoints.json with matching method/path/category/params.");
            fail(msg.toString());
        }
    }

    /**
     * For every scanned endpoint present in the catalog, the HTTP method must match.
     * A path mismatch between GET and POST means one side is wrong and dynamic
     * bridge registration will hit the wrong verb at runtime.
     */
    public void testCatalogMethodMatchesScannedMethod() {
        List<String> mismatches = new ArrayList<>();
        for (AnnotationScanner.ToolDescriptor tool : scanner.getDescriptors()) {
            CatalogEntry entry = catalog.get(tool.path());
            if (entry == null) continue;  // reported by the other test
            if (!entry.method.equalsIgnoreCase(tool.method())) {
                mismatches.add(tool.path() + " — scanned: " + tool.method()
                    + ", catalog: " + entry.method);
            }
        }
        assertTrue("HTTP method mismatches between @McpTool and endpoints.json: " + mismatches,
            mismatches.isEmpty());
    }

    /**
     * Every declared {@code @Param} in a scanned endpoint must appear in the
     * catalog entry's {@code params} array (or the catalog entry can be missing
     * params entirely, treated as "not yet documented"). Extra catalog params
     * are allowed — sometimes the catalog documents positional aliases.
     *
     * <p>This catches the "added a new param to an existing tool but forgot
     * to update the catalog" regression.
     */
    public void testCatalogParamsIncludeScannedParams() {
        List<String> missing = new ArrayList<>();
        for (AnnotationScanner.ToolDescriptor tool : scanner.getDescriptors()) {
            CatalogEntry entry = catalog.get(tool.path());
            if (entry == null || entry.params.isEmpty()) continue;
            Set<String> catalogParams = new HashSet<>(entry.params);
            for (AnnotationScanner.ParamDescriptor p : tool.params()) {
                if (!catalogParams.contains(p.name())) {
                    missing.add(tool.path() + " missing '" + p.name() + "' in catalog params " + entry.params);
                }
            }
        }
        // Report as a soft-fail list, but still fail — easy to miss otherwise.
        assertTrue("Scanned params missing from endpoints.json:\n  "
            + String.join("\n  ", missing), missing.isEmpty());
    }

    /**
     * The catalog's {@code category} must match the category the scanner resolves.
     *
     * <p>This is the tool GROUP the bridge lazy-loads by. The bridge never reads
     * {@code tests/endpoints.json} — it groups on the {@code category} field of
     * {@code /mcp/schema}, which the annotation scan produces. Nothing compared the
     * two until this test, and 63 of 219 scanned entries had drifted: the catalog
     * still carried a pre-tool-group verb taxonomy ({@code getter}, {@code rename},
     * {@code decompile}, {@code search}, {@code script}, {@code utility}) whose names
     * no {@code load_tool_group} call can resolve, so the catalog implied that
     * {@code decompile_function}, {@code rename_function}, {@code search_functions}
     * and 24 other tools sit outside the default groups when they do not.
     *
     * <p>The annotation is authoritative by construction: it is the only side the
     * runtime reads. To move a tool between groups, change {@code @McpTool.category}
     * or the class's {@code @McpToolGroup}, then regenerate the catalog.
     */
    public void testCatalogCategoryMatchesScannedCategory() {
        List<String> mismatches = new ArrayList<>();
        for (AnnotationScanner.ToolDescriptor tool : scanner.getDescriptors()) {
            CatalogEntry entry = catalog.get(tool.path());
            if (entry == null) continue;  // reported by testEveryScannedEndpointIsInCatalog
            String scanned = tool.category() == null ? "" : tool.category();
            if (!entry.category.equals(scanned)) {
                mismatches.add("  " + tool.path()
                    + " — catalog: '" + entry.category + "', annotation: '" + scanned + "'");
            }
        }
        if (!mismatches.isEmpty()) {
            java.util.Collections.sort(mismatches);
            fail(mismatches.size() + " endpoint(s) whose " + CATALOG_PATH
                + " category disagrees with the @McpTool/@McpToolGroup annotation.\n"
                + "The annotation wins: it is what /mcp/schema publishes and what the "
                + "bridge lazy-loads tool groups by.\n"
                + "Fix with: mvn test -Dtest=RegenerateEndpointsJson -Dregenerate=true\n"
                + "(then: python -m tools.gen_readme_api_reference --write)\n"
                + String.join("\n", mismatches));
        }
    }

    /**
     * Hand-registered routes get their schema entry from {@link ManualToolDescriptors},
     * not from an annotation — so that registry, not the catalog, is their runtime
     * group. The two are seeded from each other and must not diverge.
     */
    public void testCatalogCategoryMatchesManualDescriptorCategory() {
        List<String> mismatches = new ArrayList<>();
        for (Map.Entry<String, AnnotationScanner.ToolDescriptor> e
                : ManualToolDescriptors.descriptors().entrySet()) {
            CatalogEntry entry = catalog.get(e.getKey());
            if (entry == null) continue;
            String manual = e.getValue().category() == null ? "" : e.getValue().category();
            if (!entry.category.equals(manual)) {
                mismatches.add("  " + e.getKey()
                    + " — catalog: '" + entry.category + "', ManualToolDescriptors: '" + manual + "'");
            }
        }
        if (!mismatches.isEmpty()) {
            java.util.Collections.sort(mismatches);
            fail(mismatches.size() + " hand-registered route(s) whose " + CATALOG_PATH
                + " category disagrees with ManualToolDescriptors:\n"
                + String.join("\n", mismatches));
        }
    }

    /**
     * The catalog's top-level {@code categories} map must describe exactly the
     * categories its endpoints actually use — no undescribed category, and no
     * described category with nothing in it.
     *
     * <p>The map was the last place the dead verb taxonomy was still documented as
     * though it were real: it listed {@code decompile}/{@code rename}/{@code search}/
     * {@code script} (no runtime group has those names) while omitting
     * {@code malware}, {@code symbol}, {@code function}, {@code xref},
     * {@code documentation}, {@code headless} and {@code debugger}, which are
     * loadable groups holding most of the server's tools.
     */
    public void testCategoriesMapMatchesCategoriesInUse() throws IOException {
        String raw = Files.readString(Paths.get(CATALOG_PATH));
        JsonObject root = new Gson().fromJson(raw, JsonObject.class);
        Set<String> described = root.has("categories")
            ? root.getAsJsonObject("categories").keySet()
            : Set.of();

        Set<String> used = new java.util.TreeSet<>();
        for (CatalogEntry e : catalog.values()) {
            if (!e.category.isEmpty()) used.add(e.category);
        }

        Set<String> undescribed = new java.util.TreeSet<>(used);
        undescribed.removeAll(described);
        Set<String> unused = new java.util.TreeSet<>(described);
        unused.removeAll(used);

        assertTrue("Categories used by endpoints but missing from the top-level"
            + " 'categories' map in " + CATALOG_PATH + ": " + undescribed,
            undescribed.isEmpty());
        assertTrue("Categories described in the top-level 'categories' map of "
            + CATALOG_PATH + " that no endpoint uses (stale taxonomy): " + unused,
            unused.isEmpty());
    }

    /**
     * The catalog's {@code total_endpoints} field must match the actual length
     * of its {@code endpoints} array. Drift here usually means a hand-edit
     * added or removed an entry without updating the count.
     */
    public void testCatalogTotalEndpointsIsConsistent() throws IOException {
        String raw = Files.readString(Paths.get(CATALOG_PATH));
        JsonObject root = new Gson().fromJson(raw, JsonObject.class);
        int declared = root.get("total_endpoints").getAsInt();
        int actual = root.getAsJsonArray("endpoints").size();
        assertEquals(
            "tests/endpoints.json total_endpoints (" + declared + ") "
              + "disagrees with endpoints array length (" + actual + ")",
            declared, actual);
    }

    /**
     * Reverse parity: every entry in {@code tests/endpoints.json} must correspond to a
     * route that still exists in the source. Otherwise a removed/renamed tool leaves a
     * stale catalog entry that the forward test (scanned ⊆ catalog) can never catch, and
     * the advertised tool count drifts upward.
     *
     * <p>A path is considered live if its quoted literal ({@code "/foo"}) appears anywhere
     * in the plugin sources — covering every registration mechanism (@McpTool, direct
     * {@code createContext}, the EndpointRegistry, server/tool/mcp routes). A catalog path
     * present in no source file is a genuine orphan.
     */
    public void testNoOrphanCatalogEntries() throws IOException {
        String allSrc = readAllJavaSources(Paths.get("src", "main", "java", "com", "xebyte"));
        List<String> orphans = new ArrayList<>();
        for (String path : catalog.keySet()) {
            if (!allSrc.contains("\"" + path + "\"")) {
                orphans.add(path);
            }
        }
        if (!orphans.isEmpty()) {
            java.util.Collections.sort(orphans);
            StringBuilder msg = new StringBuilder();
            msg.append(orphans.size()).append(" orphaned catalog entr(y/ies) in ")
               .append(CATALOG_PATH)
               .append(" — no matching route literal in source (removed/renamed tool). ")
               .append("Delete the stale entry (and update total_endpoints) or fix its path:\n");
            for (String o : orphans) {
                msg.append("  - ").append(o).append("\n");
            }
            fail(msg.toString());
        }
    }

    private static String readAllJavaSources(Path root) throws IOException {
        StringBuilder sb = new StringBuilder();
        try (java.util.stream.Stream<Path> paths = Files.walk(root)) {
            for (Path p : (Iterable<Path>) paths.filter(f -> f.toString().endsWith(".java"))::iterator) {
                sb.append(Files.readString(p)).append('\n');
            }
        }
        return sb.toString();
    }

    // ------------------------------------------------------------------
    // Catalog loader
    // ------------------------------------------------------------------

    private static final class CatalogEntry {
        final String path;
        final String method;
        final String category;
        final List<String> params;

        CatalogEntry(String path, String method, String category, List<String> params) {
            this.path = path;
            this.method = method;
            this.category = category;
            this.params = params;
        }
    }

    private static Map<String, CatalogEntry> loadCatalog() throws IOException {
        Path p = Paths.get(CATALOG_PATH);
        if (!Files.exists(p)) {
            throw new IOException(
                "Expected catalog file " + CATALOG_PATH + " relative to project root. "
              + "mvn test runs with working dir = project root; if you're running from "
              + "a different dir, cd to the project root first.");
        }
        String raw = Files.readString(p);
        JsonObject root = new Gson().fromJson(raw, JsonObject.class);
        JsonArray arr = root.getAsJsonArray("endpoints");

        Map<String, CatalogEntry> map = new HashMap<>();
        for (JsonElement el : arr) {
            JsonObject obj = el.getAsJsonObject();
            String path = obj.get("path").getAsString();
            String method = obj.has("method") ? obj.get("method").getAsString() : "GET";
            String category = obj.has("category") ? obj.get("category").getAsString() : "";
            List<String> params = new ArrayList<>();
            if (obj.has("params") && obj.get("params").isJsonArray()) {
                for (JsonElement pe : obj.getAsJsonArray("params")) {
                    params.add(pe.getAsString());
                }
            }
            map.put(path, new CatalogEntry(path, method, category, params));
        }
        return map;
    }
}
