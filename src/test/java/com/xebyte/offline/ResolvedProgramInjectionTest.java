package com.xebyte.offline;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.xebyte.core.AnnotationScanner;
import com.xebyte.core.EndpointDef;
import com.xebyte.core.JsonHelper;
import com.xebyte.core.McpTool;
import com.xebyte.core.Param;
import com.xebyte.core.ProgramProvider;
import com.xebyte.core.Response;
import com.xebyte.core.ServiceUtils;
import com.xebyte.core.ToolAccess;
import ghidra.program.model.listing.Program;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Request-scoped {@code "program"} injection on annotation-driven responses.
 *
 * <p>A 17-program survey once produced seventeen identical readings because
 * payloads never named what they described. Injection at the AnnotationScanner
 * chokepoint closes that — but HTTP threads are pooled, so an uncleared
 * ThreadLocal would stamp request N+1 with request N's program name. The leak
 * test below is the centrepiece: without clear-on-entry and clear-in-finally,
 * it fails.
 */
public class ResolvedProgramInjectionTest {

    private static final Gson GSON = new Gson();

    @Before
    @After
    public void clearHolder() {
        ServiceUtils.clearResolvedProgramName();
    }

    private static Program named(String name) {
        Program p = mock(Program.class);
        when(p.getName()).thenReturn(name);
        return p;
    }

    private static EndpointDef endpoint(AnnotationScanner scanner, String path) {
        for (EndpointDef ep : scanner.getEndpoints()) {
            if (path.equals(ep.path())) {
                return ep;
            }
        }
        fail("endpoint not found: " + path);
        return null;
    }

    private static JsonObject asObject(Response response) {
        String json = response.toJson();
        assertTrue("expected JSON object, got: " + json, json.startsWith("{"));
        return GSON.fromJson(json, JsonObject.class);
    }

    // ------------------------------------------------------------------
    // Centrepiece: cross-request leak on a pooled thread
    // ------------------------------------------------------------------

    /**
     * Two sequential handler invocations on the SAME thread. The first resolves
     * a program; the second resolves none. If the ThreadLocal leaks, the second
     * response falsely claims it acted on the first's program — the same
     * survey-confusion bug wearing an authoritative label.
     */
    @Test
    public void secondRequestOnSameThread_mustNotInheritProgramLabel() throws Exception {
        Program alpha = named("alpha.dll");
        ProgramProvider provider = mock(ProgramProvider.class);
        when(provider.getCurrentProgram()).thenReturn(alpha);
        when(provider.getAllOpenPrograms()).thenReturn(new Program[] { alpha });
        when(provider.getProgram("alpha.dll")).thenReturn(alpha);

        Fixture fixture = new Fixture(provider);
        AnnotationScanner scanner = new AnnotationScanner(provider, new Object[] { fixture });
        EndpointDef resolves = endpoint(scanner, "/test_resolves_program");
        EndpointDef noResolve = endpoint(scanner, "/test_no_program_resolve");

        Map<String, String> emptyQuery = Collections.emptyMap();
        Map<String, Object> emptyBody = Collections.emptyMap();

        Response first = resolves.handler().handle(emptyQuery, emptyBody);
        JsonObject firstJson = asObject(first);
        assertEquals("first response must name the program it resolved",
                "alpha.dll", firstJson.get("program").getAsString());
        assertEquals(42, firstJson.get("count").getAsInt());

        // Same thread, no resolution — must not carry a program field at all.
        Response second = noResolve.handler().handle(emptyQuery, emptyBody);
        JsonObject secondJson = asObject(second);
        assertFalse(
                "pooled-thread leak: second response inherited first request's program name",
                secondJson.has("program"));
        assertFalse(
                "pooled-thread leak: second response inherited program_name",
                secondJson.has("program_name"));
        assertEquals("ok", secondJson.get("status").getAsString());
        assertNull("holder must be empty after handler returns",
                ServiceUtils.peekResolvedProgramName());
    }

    // ------------------------------------------------------------------
    // Injection behaviour
    // ------------------------------------------------------------------

    @Test
    public void objectPayload_getsProgramInjected() throws Exception {
        Program beta = named("beta.dll");
        ProgramProvider provider = mock(ProgramProvider.class);
        when(provider.getCurrentProgram()).thenReturn(beta);
        when(provider.getAllOpenPrograms()).thenReturn(new Program[] { beta });
        when(provider.getProgram("beta.dll")).thenReturn(beta);

        Fixture fixture = new Fixture(provider);
        AnnotationScanner scanner = new AnnotationScanner(provider, new Object[] { fixture });
        EndpointDef ep = endpoint(scanner, "/test_resolves_program");

        JsonObject json = asObject(ep.handler().handle(Collections.emptyMap(), Collections.emptyMap()));
        assertEquals("beta.dll", json.get("program").getAsString());
        assertEquals(42, json.get("count").getAsInt());
    }

    @Test
    public void existingProgramKey_isNotOverwritten() throws Exception {
        Program real = named("real.dll");
        ProgramProvider provider = mock(ProgramProvider.class);
        when(provider.getCurrentProgram()).thenReturn(real);
        when(provider.getAllOpenPrograms()).thenReturn(new Program[] { real });

        Fixture fixture = new Fixture(provider);
        AnnotationScanner scanner = new AnnotationScanner(provider, new Object[] { fixture });
        EndpointDef ep = endpoint(scanner, "/test_already_has_program");

        JsonObject json = asObject(ep.handler().handle(Collections.emptyMap(), Collections.emptyMap()));
        assertEquals("hand-authored.dll", json.get("program").getAsString());
        assertFalse(json.has("program_name"));
    }

    @Test
    public void existingProgramNameKey_skipsInjectionEntirely() throws Exception {
        Program real = named("real.dll");
        ProgramProvider provider = mock(ProgramProvider.class);
        when(provider.getCurrentProgram()).thenReturn(real);
        when(provider.getAllOpenPrograms()).thenReturn(new Program[] { real });

        Fixture fixture = new Fixture(provider);
        AnnotationScanner scanner = new AnnotationScanner(provider, new Object[] { fixture });
        EndpointDef ep = endpoint(scanner, "/test_already_has_program_name");

        JsonObject json = asObject(ep.handler().handle(Collections.emptyMap(), Collections.emptyMap()));
        assertEquals("metadata.dll", json.get("program_name").getAsString());
        assertFalse("must not also inject program when program_name is present",
                json.has("program"));
    }

    @Test
    public void arrayPayload_isUntouched() throws Exception {
        Program real = named("real.dll");
        ProgramProvider provider = mock(ProgramProvider.class);
        when(provider.getCurrentProgram()).thenReturn(real);
        when(provider.getAllOpenPrograms()).thenReturn(new Program[] { real });

        Fixture fixture = new Fixture(provider);
        AnnotationScanner scanner = new AnnotationScanner(provider, new Object[] { fixture });
        EndpointDef ep = endpoint(scanner, "/test_array_payload");

        String json = ep.handler().handle(Collections.emptyMap(), Collections.emptyMap()).toJson();
        assertTrue("array payload must stay an array: " + json, json.startsWith("["));
        JsonArray arr = GSON.fromJson(json, JsonArray.class);
        assertEquals(2, arr.size());
        assertEquals("a", arr.get(0).getAsString());
    }

    @Test
    public void scalarPayload_isUntouched() throws Exception {
        Program real = named("real.dll");
        ProgramProvider provider = mock(ProgramProvider.class);
        when(provider.getCurrentProgram()).thenReturn(real);
        when(provider.getAllOpenPrograms()).thenReturn(new Program[] { real });

        Fixture fixture = new Fixture(provider);
        AnnotationScanner scanner = new AnnotationScanner(provider, new Object[] { fixture });
        EndpointDef ep = endpoint(scanner, "/test_scalar_payload");

        String json = ep.handler().handle(Collections.emptyMap(), Collections.emptyMap()).toJson();
        assertEquals("7", json);
    }

    @Test
    public void textPayload_isUntouched() throws Exception {
        Program real = named("real.dll");
        ProgramProvider provider = mock(ProgramProvider.class);
        when(provider.getCurrentProgram()).thenReturn(real);
        when(provider.getAllOpenPrograms()).thenReturn(new Program[] { real });

        Fixture fixture = new Fixture(provider);
        AnnotationScanner scanner = new AnnotationScanner(provider, new Object[] { fixture });
        EndpointDef ep = endpoint(scanner, "/test_text_payload");

        String json = ep.handler().handle(Collections.emptyMap(), Collections.emptyMap()).toJson();
        assertEquals("{\"raw\":true,\"items\":[1]}", json);
        assertFalse("Text responses must not be rewritten", json.contains("\"program\""));
    }

    @Test
    public void errorResponse_keepsMessage_noProgramField() throws Exception {
        ProgramProvider provider = mock(ProgramProvider.class);
        when(provider.getCurrentProgram()).thenReturn(null);
        when(provider.getAllOpenPrograms()).thenReturn(new Program[0]);

        Fixture fixture = new Fixture(provider);
        AnnotationScanner scanner = new AnnotationScanner(provider, new Object[] { fixture });
        EndpointDef ep = endpoint(scanner, "/test_resolves_program");

        Response response = ep.handler().handle(Collections.emptyMap(), Collections.emptyMap());
        assertTrue(response instanceof Response.Err);
        JsonObject json = asObject(response);
        assertTrue(json.has("error"));
        assertFalse(json.has("program"));
    }

    /**
     * Fixture service: some tools resolve via the chokepoint, one deliberately
     * does not — that is what the leak test needs on the second call.
     */
    public static final class Fixture {
        private final ProgramProvider provider;

        Fixture(ProgramProvider provider) {
            this.provider = provider;
        }

        @McpTool(path = "/test_resolves_program", method = "GET",
                description = "Fixture: resolves a program, returns object without program key",
                access = ToolAccess.READ_ONLY)
        public Response resolves(
                @Param(value = "program", defaultValue = "") String programName) {
            ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(provider, programName);
            if (pe.hasError()) return pe.error();
            return Response.ok(JsonHelper.mapOf("count", 42));
        }

        @McpTool(path = "/test_no_program_resolve", method = "GET",
                description = "Fixture: never resolves a program",
                access = ToolAccess.READ_ONLY)
        public Response noResolve() {
            return Response.ok(JsonHelper.mapOf("status", "ok"));
        }

        @McpTool(path = "/test_already_has_program", method = "GET",
                description = "Fixture: object already carries program",
                access = ToolAccess.READ_ONLY)
        public Response alreadyHasProgram(
                @Param(value = "program", defaultValue = "") String programName) {
            ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(provider, programName);
            if (pe.hasError()) return pe.error();
            return Response.ok(JsonHelper.mapOf("program", "hand-authored.dll", "ok", true));
        }

        @McpTool(path = "/test_already_has_program_name", method = "GET",
                description = "Fixture: object already carries program_name",
                access = ToolAccess.READ_ONLY)
        public Response alreadyHasProgramName(
                @Param(value = "program", defaultValue = "") String programName) {
            ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(provider, programName);
            if (pe.hasError()) return pe.error();
            return Response.ok(JsonHelper.mapOf("program_name", "metadata.dll", "ok", true));
        }

        @McpTool(path = "/test_array_payload", method = "GET",
                description = "Fixture: array payload",
                access = ToolAccess.READ_ONLY)
        public Response arrayPayload(
                @Param(value = "program", defaultValue = "") String programName) {
            ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(provider, programName);
            if (pe.hasError()) return pe.error();
            return Response.ok(List.of("a", "b"));
        }

        @McpTool(path = "/test_scalar_payload", method = "GET",
                description = "Fixture: scalar payload",
                access = ToolAccess.READ_ONLY)
        public Response scalarPayload(
                @Param(value = "program", defaultValue = "") String programName) {
            ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(provider, programName);
            if (pe.hasError()) return pe.error();
            return Response.ok(7);
        }

        @McpTool(path = "/test_text_payload", method = "GET",
                description = "Fixture: Response.Text JSON object",
                access = ToolAccess.READ_ONLY)
        @SuppressWarnings("deprecation")
        public Response textPayload(
                @Param(value = "program", defaultValue = "") String programName) {
            ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(provider, programName);
            if (pe.hasError()) return pe.error();
            return Response.text("{\"raw\":true,\"items\":[1]}");
        }
    }
}
