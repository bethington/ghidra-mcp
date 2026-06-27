package com.xebyte.offline;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.xebyte.core.AnnotationScanner;
import com.xebyte.core.EndpointDef;
import com.xebyte.core.McpTool;
import com.xebyte.core.Param;
import com.xebyte.core.ParamSource;
import com.xebyte.core.ProgramProvider;
import com.xebyte.core.Response;
import junit.framework.TestCase;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
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

    /**
     * Boxed Integer/Boolean params with {@code defaultValue} must return the
     * parsed default — not {@code null} — when no value is supplied, for both
     * QUERY and BODY sources.
     *
     * <p>This is a regression test for H13: the {@code Integer.class} and
     * {@code Boolean.class} branches in {@code resolveQueryParam} /
     * {@code resolveBodyParam} were ignoring {@code hasDef}/{@code def} and
     * returning {@code null}, unlike the primitive {@code int}/{@code boolean}
     * branches which already honored it.
     */
    public void testBoxedParamHonorsDefaultValue() throws Exception {
        BoxedDefaultFixture fixture = new BoxedDefaultFixture();
        AnnotationScanner fixtureScanner = new AnnotationScanner(fixture);
        List<EndpointDef> endpoints = fixtureScanner.getEndpoints();

        // Find GET (QUERY source) and POST (BODY source) handlers
        EndpointDef getEndpoint = null;
        EndpointDef postEndpoint = null;
        for (EndpointDef ep : endpoints) {
            if ("/test_boxed_query".equals(ep.path())) getEndpoint = ep;
            if ("/test_boxed_body".equals(ep.path()))  postEndpoint = ep;
        }
        assertNotNull("GET fixture endpoint not found", getEndpoint);
        assertNotNull("POST fixture endpoint not found", postEndpoint);

        // Invoke GET handler with no query parameters
        Map<String, String> emptyQuery = Collections.emptyMap();
        Map<String, Object> emptyBody  = Collections.emptyMap();
        getEndpoint.handler().handle(emptyQuery, emptyBody);

        assertEquals("QUERY: boxed Integer with defaultValue=\"0\" and absent value should return 0",
            Integer.valueOf(0), fixture.lastLength);
        assertEquals("QUERY: boxed Boolean with defaultValue=\"true\" and absent value should return Boolean.TRUE",
            Boolean.TRUE, fixture.lastStrict);

        // Invoke POST handler with no body parameters
        postEndpoint.handler().handle(emptyQuery, emptyBody);

        assertEquals("BODY: boxed Integer with defaultValue=\"5\" and absent value should return 5",
            Integer.valueOf(5), fixture.lastBodyLength);
        assertEquals("BODY: boxed Boolean with defaultValue=\"false\" and absent value should return Boolean.FALSE",
            Boolean.FALSE, fixture.lastBodyStrict);
    }

    /**
     * Tiny fixture service scanned by {@link #testBoxedParamHonorsDefaultValue}.
     * The two {@code @McpTool} methods capture their resolved arguments so the test
     * can assert the values without needing to parse the Response JSON.
     */
    static class BoxedDefaultFixture {

        // Captured by the QUERY handler
        volatile Integer lastLength;
        volatile Boolean lastStrict;

        // Captured by the BODY handler
        volatile Integer lastBodyLength;
        volatile Boolean lastBodyStrict;

        @McpTool(path = "/test_boxed_query", method = "GET",
                 description = "Fixture: boxed Integer/Boolean via QUERY source")
        public Response queryBoxed(
                @Param(value = "length", defaultValue = "0") Integer length,
                @Param(value = "strict", defaultValue = "true") Boolean strict) {
            lastLength = length;
            lastStrict = strict;
            return Response.ok("ok");
        }

        @McpTool(path = "/test_boxed_body", method = "POST",
                 description = "Fixture: boxed Integer/Boolean via BODY source")
        public Response bodyBoxed(
                @Param(value = "length", source = ParamSource.BODY, defaultValue = "5") Integer length,
                @Param(value = "strict", source = ParamSource.BODY, defaultValue = "false") Boolean strict) {
            lastBodyLength = length;
            lastBodyStrict = strict;
            return Response.ok("ok");
        }
    }
}
