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
import ghidra.program.model.listing.Program;
import junit.framework.TestCase;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

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
     * Regression test: a boxed param declared with an EMPTY {@code defaultValue}
     * must resolve to {@code null} ("unset"), not to a concrete value.
     *
     * <p>This is the counterpart to the H13 fix above, which overcorrected. H13
     * changed the boxed branches to {@code hasDef ? Boolean.valueOf(def) : null},
     * but {@code hasDef} is true for {@code defaultValue = ""} (it only tests
     * against the {@code NO_DEFAULT} sentinel), and {@code Boolean.valueOf("")}
     * is {@code false}. Every nullable tri-state filter in the codebase is
     * declared exactly that way — e.g. {@code has_custom_name}, {@code is_thunk},
     * {@code is_external} on {@code /search_functions_enhanced}. The effect was
     * that OMITTING such a filter silently applied it as {@code == false}:
     * {@code search_functions_enhanced} with a name_pattern and no other args
     * returned zero results for every user-named function, reporting a
     * well-formed empty list rather than an error.
     *
     * <p>{@code Integer} was unaffected only by accident — {@code Integer.valueOf("")}
     * throws {@code NumberFormatException}, which that branch already catches and
     * turns into {@code null}. {@code Boolean.valueOf} never throws, so the Boolean
     * branch failed silently. Both are asserted here so the behaviour is pinned
     * explicitly rather than resting on a parse failure.
     */
    public void testBoxedParamWithEmptyDefaultResolvesToNull() throws Exception {
        BoxedDefaultFixture fixture = new BoxedDefaultFixture();
        AnnotationScanner fixtureScanner = new AnnotationScanner(fixture);

        EndpointDef getEndpoint = null;
        EndpointDef postEndpoint = null;
        for (EndpointDef ep : fixtureScanner.getEndpoints()) {
            if ("/test_empty_default_query".equals(ep.path())) getEndpoint = ep;
            if ("/test_empty_default_body".equals(ep.path()))  postEndpoint = ep;
        }
        assertNotNull("GET empty-default fixture endpoint not found", getEndpoint);
        assertNotNull("POST empty-default fixture endpoint not found", postEndpoint);

        Map<String, String> emptyQuery = Collections.emptyMap();
        Map<String, Object> emptyBody  = Collections.emptyMap();

        fixture.lastOptFilter = Boolean.TRUE;   // poison, so a no-op write is visible
        fixture.lastOptCount  = Integer.valueOf(-1);
        getEndpoint.handler().handle(emptyQuery, emptyBody);
        assertNull("QUERY: boxed Boolean with defaultValue=\"\" and absent value must be null (unset), "
            + "not false — otherwise an omitted tri-state filter is applied as '== false'",
            fixture.lastOptFilter);
        assertNull("QUERY: boxed Integer with defaultValue=\"\" and absent value must be null",
            fixture.lastOptCount);

        fixture.lastBodyOptFilter = Boolean.TRUE;
        fixture.lastBodyOptCount  = Integer.valueOf(-1);
        postEndpoint.handler().handle(emptyQuery, emptyBody);
        assertNull("BODY: boxed Boolean with defaultValue=\"\" and absent value must be null (unset), not false",
            fixture.lastBodyOptFilter);
        assertNull("BODY: boxed Integer with defaultValue=\"\" and absent value must be null",
            fixture.lastBodyOptCount);
    }

    /**
     * An EXPLICIT value must still win over the empty default, in both directions —
     * the fix must not make these params unsettable.
     */
    public void testBoxedParamWithEmptyDefaultStillHonorsExplicitValue() throws Exception {
        BoxedDefaultFixture fixture = new BoxedDefaultFixture();
        AnnotationScanner fixtureScanner = new AnnotationScanner(fixture);

        EndpointDef getEndpoint = null;
        EndpointDef postEndpoint = null;
        for (EndpointDef ep : fixtureScanner.getEndpoints()) {
            if ("/test_empty_default_query".equals(ep.path())) getEndpoint = ep;
            if ("/test_empty_default_body".equals(ep.path())) postEndpoint = ep;
        }
        assertNotNull("GET empty-default fixture endpoint not found", getEndpoint);
        assertNotNull("POST empty-default fixture endpoint not found", postEndpoint);

        Map<String, String> query = new HashMap<>();
        query.put("opt_filter", "true");
        query.put("opt_count", "7");
        getEndpoint.handler().handle(query, Collections.emptyMap());
        assertEquals("Explicit true must survive the empty default",
            Boolean.TRUE, fixture.lastOptFilter);
        assertEquals("Explicit 7 must survive the empty default",
            Integer.valueOf(7), fixture.lastOptCount);

        query.put("opt_filter", "false");
        getEndpoint.handler().handle(query, Collections.emptyMap());
        assertEquals("Explicit false must be distinguishable from unset",
            Boolean.FALSE, fixture.lastOptFilter);

        Map<String, Object> body = new HashMap<>();
        body.put("opt_filter", Boolean.TRUE);
        body.put("opt_count", Integer.valueOf(9));
        postEndpoint.handler().handle(Collections.emptyMap(), body);
        assertEquals("BODY: explicit true must survive the empty default",
            Boolean.TRUE, fixture.lastBodyOptFilter);
        assertEquals("BODY: explicit 9 must survive the empty default",
            Integer.valueOf(9), fixture.lastBodyOptCount);

        body.put("opt_filter", Boolean.FALSE);
        postEndpoint.handler().handle(Collections.emptyMap(), body);
        assertEquals("BODY: explicit false must be distinguishable from unset",
            Boolean.FALSE, fixture.lastBodyOptFilter);
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

        // Captured by the empty-default handlers
        volatile Boolean lastOptFilter;
        volatile Integer lastOptCount;
        volatile Boolean lastBodyOptFilter;
        volatile Integer lastBodyOptCount;

        @McpTool(path = "/test_empty_default_query", method = "GET",
                 description = "Fixture: boxed params with an EMPTY defaultValue via QUERY source")
        public Response queryEmptyDefault(
                @Param(value = "opt_filter", defaultValue = "") Boolean optFilter,
                @Param(value = "opt_count", defaultValue = "") Integer optCount) {
            lastOptFilter = optFilter;
            lastOptCount = optCount;
            return Response.ok("ok");
        }

        @McpTool(path = "/test_empty_default_body", method = "POST",
                 description = "Fixture: boxed params with an EMPTY defaultValue via BODY source")
        public Response bodyEmptyDefault(
                @Param(value = "opt_filter", source = ParamSource.BODY, defaultValue = "") Boolean optFilter,
                @Param(value = "opt_count", source = ParamSource.BODY, defaultValue = "") Integer optCount) {
            lastBodyOptFilter = optFilter;
            lastBodyOptCount = optCount;
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

    /**
     * Regression test for the 2026-08-09 incident: a raw-HTTP caller that follows this
     * project's own "POST params go in the JSON body" convention (CLAUDE.md "Code
     * Conventions") and puts {@code dry_run} in the body got a REAL write with a
     * response that still looked like a preview. Root cause: the dry-run gate at
     * {@code AnnotationScanner.createHandler} checked only {@code query.get("dry_run")},
     * never the parsed body map, so body-supplied dry_run was silently ignored and the
     * rollback-wrapped branch never ran. Confirmed live against /batch_set_comments,
     * where it overwrote a verified-good plate comment before being caught and reverted.
     *
     * <p>This exercises the real dry-run wrapper end-to-end: a mocked {@link Program}
     * stands in for the transaction the wrapper starts/rolls back, and the fixture's
     * write method itself is invoked either way (the wrapper can only undo Ghidra
     * transaction state, not arbitrary Java side effects) -- what distinguishes a
     * genuine dry run is that {@code endTransaction} is called with {@code commit=false}.
     */
    public void testDryRunHonoredFromJsonBody() throws Exception {
        DryRunWriteFixture fixture = new DryRunWriteFixture();
        Program program = mock(Program.class);
        when(program.startTransaction(org.mockito.ArgumentMatchers.anyString())).thenReturn(42);

        ProgramProvider provider = mock(ProgramProvider.class);
        when(provider.getProgram("Test.dll")).thenReturn(program);

        AnnotationScanner fixtureScanner = new AnnotationScanner(provider, new Object[] { fixture });
        EndpointDef endpoint = null;
        for (EndpointDef ep : fixtureScanner.getEndpoints()) {
            if ("/test_dry_run_write".equals(ep.path())) endpoint = ep;
        }
        assertNotNull("Fixture endpoint not found", endpoint);

        // dry_run supplied ONLY in the JSON body -- exactly the shape that was silently
        // ignored before the fix (query still carries "program" so the wrapper CAN
        // resolve a Program to roll back on; only dry_run itself is body-only).
        Map<String, String> query = new HashMap<>();
        query.put("program", "Test.dll");
        Map<String, Object> body = new HashMap<>();
        body.put("dry_run", Boolean.TRUE);
        endpoint.handler().handle(query, body);

        assertTrue("Fixture method must still be invoked under dry-run (only the transaction is rolled back)",
            fixture.invoked);
        verify(program).endTransaction(anyInt(), eq(false));

        // Control: no dry_run anywhere -> real invocation, no dry-run rollback wrapper.
        Program program2 = mock(Program.class);
        ProgramProvider provider2 = mock(ProgramProvider.class);
        when(provider2.getProgram("Test.dll")).thenReturn(program2);
        DryRunWriteFixture fixture2 = new DryRunWriteFixture();
        AnnotationScanner fixtureScanner2 = new AnnotationScanner(provider2, new Object[] { fixture2 });
        EndpointDef endpoint2 = null;
        for (EndpointDef ep : fixtureScanner2.getEndpoints()) {
            if ("/test_dry_run_write".equals(ep.path())) endpoint2 = ep;
        }
        endpoint2.handler().handle(query, Collections.emptyMap());
        assertTrue("Fixture method must be invoked on a real (non-dry-run) call", fixture2.invoked);
        verify(program2, never()).endTransaction(anyInt(), eq(false));
    }

    /** Tiny fixture service scanned by {@link #testDryRunHonoredFromJsonBody}. */
    static class DryRunWriteFixture {
        volatile boolean invoked;

        @McpTool(path = "/test_dry_run_write", method = "POST",
                 description = "Fixture: a write endpoint used to prove dry_run routing")
        public Response write(
                @Param(value = "program", defaultValue = "") String program) {
            invoked = true;
            return Response.ok("wrote");
        }
    }
}

