package com.xebyte.offline;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.xebyte.core.AnnotationScanner;
import com.xebyte.core.EndpointDef;
import com.xebyte.core.ProgramProvider;
import junit.framework.TestCase;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Pure-reflection tests for {@link AnnotationScanner}.
 *
 * <p>These tests run fully offline — no Ghidra HTTP server, no loaded program.
 * They catch regressions in the annotation layer itself: a method missing
 * {@code @McpTool}, a duplicate path, malformed schema JSON, or the scanner
 * silently dropping an endpoint after a refactor.
 *
 * <p>This is the "Tier 0" of the offline testing strategy from issue #112 —
 * it doesn't need a {@code FixtureProgramProvider} at all, because the
 * scanner never invokes handlers; it only reads annotations.
 */
public class AnnotationScannerOfflineTest extends TestCase {

    private AnnotationScanner scanner;

    @Override
    protected void setUp() {
        ProgramProvider provider = ServiceFactory.stubProvider();
        scanner = new AnnotationScanner(provider, ServiceFactory.buildAllServices());
    }

    /** Scanner must discover a meaningful number of endpoints — empty means a wiring regression. */
    public void testScannerDiscoversEndpoints() {
        List<EndpointDef> endpoints = scanner.getEndpoints();
        assertNotNull("Scanner returned null endpoint list", endpoints);
        assertFalse("Scanner discovered zero endpoints — all services may have lost their @McpTool annotations",
            endpoints.isEmpty());

        // Sanity floor: v5.3.2 ships ~150+ annotation-scanned tools. Anything
        // well below that indicates an entire service class was dropped.
        assertTrue(
            "Expected at least 100 annotation-scanned endpoints, got " + endpoints.size()
                + ". A service class may have been dropped from ServiceFactory.",
            endpoints.size() >= 100);
    }

    /** Every endpoint path must be well-formed: non-null, leading slash, no whitespace. */
    public void testEndpointPathsAreWellFormed() {
        List<String> bad = new ArrayList<>();
        for (EndpointDef ep : scanner.getEndpoints()) {
            String path = ep.path();
            if (path == null || path.isEmpty()) {
                bad.add("<null-or-empty>");
                continue;
            }
            if (!path.startsWith("/")) {
                bad.add(path + " (missing leading slash)");
            }
            if (path.contains(" ") || path.contains("\t")) {
                bad.add(path + " (contains whitespace)");
            }
        }
        assertTrue("Malformed endpoint paths: " + bad, bad.isEmpty());
    }

    /** Paths must be unique — duplicate paths mean {@code createContext} collisions at runtime. */
    public void testNoDuplicatePaths() {
        Set<String> seen = new HashSet<>();
        Set<String> dupes = new HashSet<>();
        for (EndpointDef ep : scanner.getEndpoints()) {
            if (!seen.add(ep.path())) {
                dupes.add(ep.path());
            }
        }
        assertTrue(
            "Duplicate @McpTool paths would cause runtime createContext collisions: " + dupes,
            dupes.isEmpty());
    }

    /** Every endpoint must declare a valid HTTP method. */
    public void testEveryEndpointHasValidMethod() {
        List<String> bad = new ArrayList<>();
        for (EndpointDef ep : scanner.getEndpoints()) {
            String m = ep.method();
            if (!"GET".equalsIgnoreCase(m) && !"POST".equalsIgnoreCase(m)) {
                bad.add(ep.path() + " -> " + m);
            }
        }
        assertTrue("Endpoints with non-GET/POST method: " + bad, bad.isEmpty());
    }

    /** {@link AnnotationScanner#generateSchema} must produce parseable JSON. */
    public void testGenerateSchemaIsValidJson() {
        String schema = scanner.generateSchema();
        assertNotNull("generateSchema returned null", schema);
        assertFalse("generateSchema returned empty string", schema.isEmpty());

        JsonObject root;
        try {
            root = new Gson().fromJson(schema, JsonObject.class);
        } catch (RuntimeException e) {
            fail("generateSchema() produced invalid JSON: " + e.getMessage()
                + "\nFirst 500 chars: " + schema.substring(0, Math.min(500, schema.length())));
            return;
        }
        assertNotNull("Schema root is null", root);

        // Top-level shape: { "tools": [...], "count": N }
        assertTrue("Schema missing 'tools' array", root.has("tools"));
        assertTrue("Schema missing 'count' field", root.has("count"));

        JsonArray tools = root.getAsJsonArray("tools");
        int count = root.get("count").getAsInt();
        assertEquals("Schema count field disagrees with tools array length",
            tools.size(), count);
    }

    /**
     * Every tool descriptor in the schema must have the fields the Python bridge
     * depends on: path, method, params. Missing any of these breaks dynamic tool
     * registration in {@code bridge_mcp_ghidra.py}.
     */
    public void testSchemaToolDescriptorsHaveRequiredFields() {
        String schema = scanner.generateSchema();
        JsonObject root = new Gson().fromJson(schema, JsonObject.class);
        JsonArray tools = root.getAsJsonArray("tools");

        List<String> broken = new ArrayList<>();
        for (JsonElement el : tools) {
            JsonObject tool = el.getAsJsonObject();
            String path = tool.has("path") ? tool.get("path").getAsString() : "<no-path>";
            if (!tool.has("path")) broken.add(path + " (missing path)");
            if (!tool.has("method")) broken.add(path + " (missing method)");
            if (!tool.has("params")) broken.add(path + " (missing params)");
            if (tool.has("params") && !tool.get("params").isJsonArray()) {
                broken.add(path + " (params not an array)");
            }
        }
        assertTrue("Schema tool descriptors missing required fields: " + broken, broken.isEmpty());
    }

    /**
     * Every declared param in the schema must itself have a name, type, source,
     * and required flag. The Python bridge uses these to decide query-vs-body
     * encoding and to report the tool's signature to the AI client.
     */
    public void testSchemaParamDescriptorsHaveRequiredFields() {
        String schema = scanner.generateSchema();
        JsonObject root = new Gson().fromJson(schema, JsonObject.class);
        JsonArray tools = root.getAsJsonArray("tools");

        List<String> broken = new ArrayList<>();
        for (JsonElement el : tools) {
            JsonObject tool = el.getAsJsonObject();
            String path = tool.get("path").getAsString();
            JsonArray params = tool.getAsJsonArray("params");
            for (JsonElement pel : params) {
                JsonObject param = pel.getAsJsonObject();
                String name = param.has("name") ? param.get("name").getAsString() : "<no-name>";
                String where = path + "::" + name;
                if (!param.has("name")) broken.add(where + " (missing name)");
                if (!param.has("type")) broken.add(where + " (missing type)");
                if (!param.has("source")) broken.add(where + " (missing source)");
                if (!param.has("required")) broken.add(where + " (missing required)");
            }
        }
        assertTrue("Schema param descriptors missing required fields: " + broken, broken.isEmpty());
    }
}
