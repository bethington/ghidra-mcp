package com.xebyte.offline;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.xebyte.core.AnnotationScanner;
import junit.framework.TestCase;

import java.util.ArrayList;
import java.util.List;

/**
 * Unit coverage for {@link RegenerateEndpointsJson#mergeEntry}: the params ordered-set union
 * that keeps catalog-only params (hand-registered route extras like /open_project's
 * headless/program — or stale annotation names, which linger visibly for manual cleanup)
 * instead of clobbering them from the scanner.
 */
public class RegenerateEndpointsJsonMergeTest extends TestCase {

    private static AnnotationScanner.ToolDescriptor tool(String... paramNames) {
        List<AnnotationScanner.ParamDescriptor> params = new ArrayList<>();
        for (String n : paramNames) {
            params.add(new AnnotationScanner.ParamDescriptor(n, "String", "BODY", false, null, "", "string", false));
        }
        return new AnnotationScanner.ToolDescriptor("/open_project", "POST", "scanner description",
                "headless", null, params);
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

    public void testOpenProjectCatalogExtrasKept() {
        RegenerateEndpointsJson.MergeResult result = RegenerateEndpointsJson.mergeEntry(
                tool("path"), entry("Open a project", "headless", "path", "headless", "program"));
        assertEquals(List.of("path", "headless", "program"), paramsOf(result.entry));
        assertEquals(List.of("headless", "program"), result.retainedCatalogParams);
    }

    public void testScannerOrderWinsOnOverlap() {
        RegenerateEndpointsJson.MergeResult result = RegenerateEndpointsJson.mergeEntry(
                tool("a", "b"), entry("d", "c", "b", "x"));
        assertEquals(List.of("a", "b", "x"), paramsOf(result.entry));
        assertEquals(List.of("x"), result.retainedCatalogParams);
    }

    public void testDuplicateNamesEmittedOnce() {
        RegenerateEndpointsJson.MergeResult result = RegenerateEndpointsJson.mergeEntry(
                tool("path", "path"), entry("d", "c", "headless", "headless"));
        assertEquals(List.of("path", "headless"), paramsOf(result.entry));
        assertEquals(List.of("headless"), result.retainedCatalogParams);
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

    public void testNonEmptyDescriptionAndCategoryPreserved() {
        RegenerateEndpointsJson.MergeResult result = RegenerateEndpointsJson.mergeEntry(
                tool("path"), entry("hand-authored", "project", "path"));
        assertEquals("hand-authored", result.entry.get("description").getAsString());
        assertEquals("project", result.entry.get("category").getAsString());
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

    public void testRetainedNamesKeepExistingOrder() {
        RegenerateEndpointsJson.MergeResult result = RegenerateEndpointsJson.mergeEntry(
                tool("path"), entry("d", "c", "program", "headless", "path"));
        assertEquals(List.of("path", "program", "headless"), paramsOf(result.entry));
        assertEquals(List.of("program", "headless"), result.retainedCatalogParams);
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
