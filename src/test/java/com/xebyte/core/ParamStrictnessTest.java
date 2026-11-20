package com.xebyte.core;

import org.junit.Test;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertTrue;

/**
 * Integers bind exactly and object arrays hold only objects; neither silently becomes
 * a different value.
 */
public class ParamStrictnessTest {

    private static final String LIMIT_PATH = "/probe_limit";
    private static final String ITEMS_PATH = "/probe_items";
    private static final int DEFAULT_LIMIT = 100;

    public static class Probe {
        @McpTool(path = LIMIT_PATH, description = "probe", category = "listing", access = ToolAccess.READ_ONLY)
        public Response limit(
                @Param(value = "limit", defaultValue = "100") int limit,
                @Param(value = "required") int required) {
            return Response.ok(JsonHelper.mapOf("limit", limit, "required", required));
        }

        @McpTool(path = ITEMS_PATH, method = "POST", description = "probe", category = "listing", access = ToolAccess.READ_ONLY)
        public Response items(
                @Param(value = "items", source = ParamSource.BODY, defaultValue = "[]") List<Map<String, String>> items) {
            return Response.ok(JsonHelper.mapOf("count", items.size()));
        }
    }

    private static Response call(String path, Map<String, String> query, Map<String, Object> body) throws Exception {
        EndpointDef endpoint = new AnnotationScanner(new Probe()).getEndpoints().stream()
            .filter(e -> e.path().equals(path)).findFirst().orElseThrow();
        return endpoint.handler().handle(query, body);
    }

    @Test
    public void anEmptyQueryValueFallsBackToTheDefault() throws Exception {
        Response response = call(LIMIT_PATH, Map.of("limit", "", "required", "1"), Map.of());

        assertTrue(response.toJson(), response instanceof Response.Ok);
        assertTrue(response.toJson(), response.toJson().contains("\"limit\":" + DEFAULT_LIMIT));
    }

    @Test
    public void aFractionalValueIsRejected() throws Exception {
        Response response = call(LIMIT_PATH, Map.of("limit", "1.5", "required", "1"), Map.of());

        assertTrue(response.toJson(), response instanceof Response.Err);
    }

    @Test
    public void anOutOfRangeValueIsRejected() throws Exception {
        Response response = call(LIMIT_PATH, Map.of("limit", "4294967296", "required", "1"), Map.of());

        assertTrue(response.toJson(), response instanceof Response.Err);
    }

    @Test
    public void aMissingRequiredIntegerIsRejected() throws Exception {
        Response response = call(LIMIT_PATH, Map.of(), Map.of());

        assertTrue(response.toJson(), response instanceof Response.Err);
    }

    @Test
    public void anObjectArrayEntryThatIsNotAnObjectIsRejected() throws Exception {
        List<Object> items = Arrays.asList(Map.of("a", "b"), 42);

        Response response = call(ITEMS_PATH, Map.of(), Map.of("items", items));

        assertTrue(response.toJson(), response instanceof Response.Err);
        assertTrue(response.toJson(), response.toJson().contains("Item 1"));
    }
}
