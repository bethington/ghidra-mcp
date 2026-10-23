package com.xebyte.offline;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.xebyte.core.AnnotationScanner;
import com.xebyte.core.ToolAccess;
import junit.framework.TestCase;

import java.util.ArrayList;
import java.util.List;

/**
 * Unit coverage for {@link RegenerateEndpointsJson#mergeEntry}.
 *
 * <p>The param list is DERIVED from the scanner (names plus declared aliases),
 * not accumulated from the catalog. The old union kept every catalog-only name,
 * which made the list grow-only: a parameter deleted from an {@code @McpTool}
 * was advertised forever, and hand-registered extras were preserved only by
 * accident of that same rule. The regenerator now takes hand-registered routes
 * from {@link com.xebyte.core.ManualToolDescriptors} instead, so the catalog can
 * both gain and LOSE parameters truthfully.
 */
public class RegenerateEndpointsJsonMergeTest extends TestCase {

    private static AnnotationScanner.ToolDescriptor tool(String... paramNames) {
        List<AnnotationScanner.ParamDescriptor> params = new ArrayList<>();
        for (String n : paramNames) {
            params.add(new AnnotationScanner.ParamDescriptor(n, "String", "BODY", false, null, "", "string", false, java.util.List.of()));
        }
        return new AnnotationScanner.ToolDescriptor("/open_project", "POST", "scanner description",
                "headless", null, ToolAccess.WRITE, params);
    }

    private static JsonObject entry(String description, String category, String... paramNames) {
        JsonObject obj = new JsonObject();
        obj.addProperty("path", "/open_project");
        obj.addProperty("method", "POST");
        obj.addProperty("category", category);
        JsonArray params = new JsonArray();
        for (String n : paramNames) {
            params.add(n);
        }
        obj.add("params", params);
        obj.addProperty("description", description);
        return obj;
    }

    private static List<String> paramsOf(JsonObject entry) {
        List<String> names = new ArrayList<>();
        for (JsonElement el : entry.getAsJsonArray("params")) {
            names.add(el.getAsString());
        }
        return names;
    }

    public void testCatalogOnlyParamsAreDroppedWhenTheScannerKnowsTheTool() {
        // /open_project's headless/program now arrive via ManualToolDescriptors,
        // which the regenerator feeds to the scanner. A name present ONLY in the
        // catalog is therefore stale by definition and must not survive -- that
        // is what let a removed parameter be advertised indefinitely.
        RegenerateEndpointsJson.MergeResult result = RegenerateEndpointsJson.mergeEntry(
                tool("path"), entry("Open a project", "headless", "path", "headless", "program"));
        assertEquals(List.of("path"), paramsOf(result.entry));
        assertTrue(result.retainedCatalogParams.isEmpty());
    }

    public void testAliasesAreAuthoritativeParams() {
        // Aliases are argument names the handler genuinely accepts, so they belong
        // in the catalog by derivation rather than by being remembered.
        List<AnnotationScanner.ParamDescriptor> params = new ArrayList<>();
        params.add(new AnnotationScanner.ParamDescriptor(
                "function", "String", "BODY", false, null, "", "string", false,
                List.of("address", "name")));
        AnnotationScanner.ToolDescriptor withAliases = new AnnotationScanner.ToolDescriptor(
                "/open_project", "POST", "d", "headless", null, ToolAccess.WRITE, params);
        RegenerateEndpointsJson.MergeResult result =
                RegenerateEndpointsJson.mergeEntry(withAliases, entry("d", "headless", "function"));
        assertEquals(List.of("function", "address", "name"), paramsOf(result.entry));
    }

    public void testScannerOrderWinsOnOverlap() {
        RegenerateEndpointsJson.MergeResult result = RegenerateEndpointsJson.mergeEntry(
                tool("a", "b"), entry("d", "c", "b", "x"));
        assertEquals(List.of("a", "b"), paramsOf(result.entry));
        // "x" exists only in the catalog and the scanner has params, so it is
        // stale rather than an extra to preserve.
        assertTrue(result.retainedCatalogParams.isEmpty());
    }

    public void testDuplicateNamesEmittedOnce() {
        RegenerateEndpointsJson.MergeResult result = RegenerateEndpointsJson.mergeEntry(
                tool("path", "path"), entry("d", "c", "headless", "headless"));
        assertEquals(List.of("path"), paramsOf(result.entry));
        assertTrue(result.retainedCatalogParams.isEmpty());
    }

    public void testNoExistingEntryUsesScannerParams() {
        RegenerateEndpointsJson.MergeResult result = RegenerateEndpointsJson.mergeEntry(tool("path"), null);
        assertEquals(List.of("path"), paramsOf(result.entry));
        assertTrue(result.retainedCatalogParams.isEmpty());
        assertEquals("scanner description", result.entry.get("description").getAsString());
        assertEquals("headless", result.entry.get("category").getAsString());
    }

    public void testNoExistingEntryDeduplicatesScannerParams() {
        RegenerateEndpointsJson.MergeResult result = RegenerateEndpointsJson.mergeEntry(
                tool("path", "path"), null);
        assertEquals(List.of("path"), paramsOf(result.entry));
        assertTrue(result.retainedCatalogParams.isEmpty());
    }

    public void testExistingEntryWithoutParamsArray() {
        JsonObject existing = entry("d", "c");
        existing.remove("params");
        RegenerateEndpointsJson.MergeResult result = RegenerateEndpointsJson.mergeEntry(tool("path"), existing);
        assertEquals(List.of("path"), paramsOf(result.entry));
        assertTrue(result.retainedCatalogParams.isEmpty());
    }

    public void testNonEmptyDescriptionPreserved() {
        RegenerateEndpointsJson.MergeResult result = RegenerateEndpointsJson.mergeEntry(
                tool("path"), entry("hand-authored", "project", "path"));
        assertEquals("hand-authored", result.entry.get("description").getAsString());
    }

    /**
     * The category is the tool GROUP the bridge lazy-loads by, and only the
     * annotation scan can say what it is. A catalog value that disagrees is drift,
     * not a hand-authored correction, so the scanner overwrites it — unlike the
     * description, which stays editorial.
     */
    public void testCatalogCategoryNeverOverridesScanner() {
        RegenerateEndpointsJson.MergeResult result = RegenerateEndpointsJson.mergeEntry(
                tool("path"), entry("hand-authored", "project", "path"));
        assertEquals("headless", result.entry.get("category").getAsString());
    }

    /** The dead pre-tool-group vocabulary must not survive a regeneration. */
    public void testStaleVerbCategoryIsReplaced() {
        RegenerateEndpointsJson.MergeResult result = RegenerateEndpointsJson.mergeEntry(
                tool("path"), entry("hand-authored", "getter", "path"));
        assertEquals("headless", result.entry.get("category").getAsString());
    }

    public void testEmptyDescriptionAndCategoryFallBackToScanner() {
        RegenerateEndpointsJson.MergeResult result = RegenerateEndpointsJson.mergeEntry(
                tool("path"), entry("", "", "path"));
        assertEquals("scanner description", result.entry.get("description").getAsString());
        assertEquals("headless", result.entry.get("category").getAsString());
    }

    public void testAbsentDescriptionAndCategoryFallBackToScanner() {
        JsonObject existing = entry("d", "c", "path");
        existing.remove("description");
        existing.remove("category");
        RegenerateEndpointsJson.MergeResult result = RegenerateEndpointsJson.mergeEntry(tool("path"), existing);
        assertEquals("scanner description", result.entry.get("description").getAsString());
        assertEquals("headless", result.entry.get("category").getAsString());
    }

    public void testRetainedNamesOnlyWhenScannerKnowsNothing() {
        // Retention is the last resort for a route with no descriptor at all --
        // not a way for the catalog to outvote the scanner.
        RegenerateEndpointsJson.MergeResult result = RegenerateEndpointsJson.mergeEntry(
                tool("path"), entry("d", "c", "program", "headless", "path"));
        assertEquals(List.of("path"), paramsOf(result.entry));
        assertTrue(result.retainedCatalogParams.isEmpty());

        RegenerateEndpointsJson.MergeResult noScannerParams = RegenerateEndpointsJson.mergeEntry(
                tool(), entry("d", "c", "program", "headless"));
        assertEquals(List.of("program", "headless"), paramsOf(noScannerParams.entry));
        assertEquals(List.of("program", "headless"), noScannerParams.retainedCatalogParams);
    }

    public void testExistingEntryNotMutated() {
        JsonObject existing = entry("d", "c", "path", "headless");
        String before = existing.toString();
        RegenerateEndpointsJson.mergeEntry(tool("path"), existing);
        assertEquals(before, existing.toString());
    }

    // ------------------------------------------------------------------
    // `servers` — which of the two HTTP servers registers the route.
    // Derived by tools/audit_server_scope.py, not by this scanner: the
    // scanner here reflects over the UNION of both servers' services and
    // cannot attribute a tool back to a server. So the only correct
    // behaviour is to carry the field through untouched. Dropping it would
    // silently unstamp all 253 entries on every regeneration.
    // ------------------------------------------------------------------

    private static JsonObject withServers(JsonObject obj, String... servers) {
        JsonArray arr = new JsonArray();
        for (String s : servers) {
            arr.add(s);
        }
        obj.add("servers", arr);
        return obj;
    }

    private static List<String> serversOf(JsonObject entry) {
        List<String> out = new ArrayList<>();
        if (!entry.has("servers")) {
            return out;
        }
        for (JsonElement el : entry.getAsJsonArray("servers")) {
            out.add(el.getAsString());
        }
        return out;
    }

    public void testServersPreservedFromCatalog() {
        JsonObject existing = withServers(entry("d", "headless", "path"), "gui", "headless");
        RegenerateEndpointsJson.MergeResult result =
                RegenerateEndpointsJson.mergeEntry(tool("path"), existing);
        assertEquals(List.of("gui", "headless"), serversOf(result.entry));
    }

    public void testSingleServerScopePreserved() {
        JsonObject existing = withServers(entry("d", "headless", "path"), "headless");
        RegenerateEndpointsJson.MergeResult result =
                RegenerateEndpointsJson.mergeEntry(tool("path"), existing);
        assertEquals(List.of("headless"), serversOf(result.entry));
    }

    public void testNoServersFieldWhenCatalogHasNone() {
        // A brand-new endpoint has no catalog entry to preserve from. It must
        // NOT be invented here -- it is left absent so
        // tests/unit/test_audit_server_scope.py's "unstamped" assertion fires
        // and the operator re-runs the audit script.
        RegenerateEndpointsJson.MergeResult result =
                RegenerateEndpointsJson.mergeEntry(tool("path"), null);
        assertFalse(result.entry.has("servers"));
    }

    public void testServersSitsBetweenParamsAndDescription() {
        // Field order is load-bearing only for diff stability, but an unstable
        // order would churn all 253 entries every time the two writers alternate.
        JsonObject existing = withServers(entry("d", "headless", "path"), "gui");
        RegenerateEndpointsJson.MergeResult result =
                RegenerateEndpointsJson.mergeEntry(tool("path"), existing);
        assertEquals(
                List.of("path", "method", "category", "params", "servers", "description"),
                new ArrayList<>(result.entry.keySet()));
    }
}
