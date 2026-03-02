package com.xebyte.core;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpServer;

import java.io.ByteArrayInputStream;
import java.io.OutputStream;
import java.lang.reflect.Method;
import java.lang.reflect.Parameter;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * Reflection engine that scans service instances for {@link McpTool} annotations
 * and builds both HTTP dispatch handlers and the MCP tool schema.
 * Replaces the hand-wired {@code EndpointRegistry}.
 */
public final class AnnotationScanner {

    private AnnotationScanner() {}

    // ==================================================================================
    // Data records
    // ==================================================================================

    public record ParamDef(
        String name, String description, String jsonType,
        boolean required, String defaultValue, Class<?> javaType
    ) {}

    public record ToolDef(
        String path, String httpMethod, String toolName,
        String description, String category, Method method,
        Object serviceInstance, List<ParamDef> params
    ) {}

    // ==================================================================================
    // Scan
    // ==================================================================================

    /** Scan one or more service instances for @McpTool methods. */
    public static List<ToolDef> scan(Object... services) {
        List<ToolDef> defs = new ArrayList<>();
        for (Object svc : services) {
            String category = svc.getClass().getSimpleName().toLowerCase().replaceAll("service$", "");
            for (Method m : svc.getClass().getMethods()) {
                McpTool ann = m.getAnnotation(McpTool.class);
                if (ann == null) continue;
                List<ParamDef> params = extractParams(m);
                String toolName = pathToToolName(ann.value());
                defs.add(new ToolDef(
                    ann.value(), ann.method().name(), toolName,
                    ann.description(), category, m, svc, params));
            }
        }
        return defs;
    }

    private static List<ParamDef> extractParams(Method m) {
        List<ParamDef> params = new ArrayList<>();
        for (Parameter p : m.getParameters()) {
            Param ann = p.getAnnotation(Param.class);
            if (ann == null) continue;
            String jsonType = ann.type();
            if ("string".equals(jsonType)) {
                jsonType = inferJsonType(p.getType());
            }
            params.add(new ParamDef(
                ann.value(), ann.description(), jsonType,
                ann.required(), ann.defaultValue(), p.getType()));
        }
        return params;
    }

    private static String inferJsonType(Class<?> type) {
        if (type == int.class || type == Integer.class || type == long.class || type == Long.class)
            return "integer";
        if (type == boolean.class || type == Boolean.class)
            return "boolean";
        if (type == double.class || type == Double.class || type == float.class || type == Float.class)
            return "number";
        if (Map.class.isAssignableFrom(type))
            return "object";
        if (List.class.isAssignableFrom(type))
            return "array";
        return "string";
    }

    static String pathToToolName(String path) {
        return path.startsWith("/") ? path.substring(1) : path;
    }

    // ==================================================================================
    // HTTP Registration
    // ==================================================================================

    /** Transport-agnostic endpoint registrar. */
    @FunctionalInterface
    public interface ContextRegistrar {
        void createContext(String path, java.util.function.Consumer<HttpExchange> handler);
    }

    /** Register all scanned tools on a Sun HttpServer (wraps exchanges with adapter). */
    public static void registerHttp(HttpServer server, List<ToolDef> defs) {
        registerHttp((path, handler) ->
            server.createContext(path, exchange ->
                handler.accept(new SunHttpExchangeAdapter(exchange))), defs);
    }

    /** Register all scanned tools using a transport-agnostic registrar. */
    public static void registerHttp(ContextRegistrar registrar, List<ToolDef> defs) {
        for (ToolDef def : defs) {
            registrar.createContext(def.path(), exchange -> {
                try {
                    Object[] args = resolveArgs(def, exchange);
                    Object result = def.method().invoke(def.serviceInstance(), args);
                    Response response;
                    if (result instanceof Response r) {
                        response = r;
                    } else {
                        response = Response.ok(result);
                    }
                    sendResponse(exchange, response.toJson());
                } catch (Exception e) {
                    Throwable cause = e.getCause() != null ? e.getCause() : e;
                    String msg = cause.getMessage() != null ? cause.getMessage() : cause.getClass().getSimpleName();
                    sendResponse(exchange, JsonHelper.errorJson(msg));
                }
            });
        }
    }

    /** Send a JSON/text response. Public so ServerManager can use it for inline endpoints. */
    public static void sendResponse(HttpExchange exchange, String json) {
        try {
            byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
            Headers headers = exchange.getResponseHeaders();
            headers.set("Content-Type", "text/plain; charset=utf-8");
            headers.set("Connection", "keep-alive");
            exchange.sendResponseHeaders(200, bytes.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(bytes);
                os.flush();
            }
        } catch (Exception e) {
            // Response already partially sent or connection closed
        }
    }

    /** Resolve method arguments from HTTP request based on param annotations and HTTP method. */
    private static Object[] resolveArgs(ToolDef def, HttpExchange exchange) throws Exception {
        boolean isPost = "POST".equals(def.httpMethod());
        boolean hasBodyParam = def.params().stream().anyMatch(p -> "_body".equals(p.name()));

        Map<String, Object> jsonParams = null;
        Map<String, String> queryParams = null;
        String rawJsonBody = null;

        if (isPost) {
            byte[] bodyBytes = exchange.getRequestBody().readAllBytes();
            String bodyStr = new String(bodyBytes, StandardCharsets.UTF_8);

            if (hasBodyParam) {
                rawJsonBody = bodyStr;
            }

            String contentType = exchange.getRequestHeaders().getFirst("Content-Type");
            if (contentType != null && contentType.contains("application/json")) {
                if (!bodyStr.isBlank()) {
                    jsonParams = JsonHelper.parseBody(new ByteArrayInputStream(bodyBytes));
                } else {
                    jsonParams = new HashMap<>();
                }
            } else {
                // Form-encoded POST — parse as query string, but also try JSON
                if (!bodyStr.isBlank()) {
                    if (bodyStr.trim().startsWith("{")) {
                        jsonParams = JsonHelper.parseBody(new ByteArrayInputStream(bodyBytes));
                    } else {
                        queryParams = parseQueryString(bodyStr);
                    }
                } else {
                    queryParams = new HashMap<>();
                }
            }
        }

        // Always parse URL query params (for ?program= on POST endpoints)
        Map<String, String> urlQueryParams = parseQueryString(
            exchange.getRequestURI().getRawQuery());

        // Merge URL query params as fallback
        if (queryParams == null && jsonParams == null) {
            queryParams = urlQueryParams;
        }

        Object[] args = new Object[def.params().size()];
        for (int i = 0; i < def.params().size(); i++) {
            ParamDef p = def.params().get(i);
            if ("_body".equals(p.name()) && rawJsonBody != null) {
                args[i] = rawJsonBody;
            } else {
                args[i] = extractParamValue(p, queryParams, jsonParams, urlQueryParams);
            }
        }
        return args;
    }

    private static Map<String, String> parseQueryString(String query) {
        Map<String, String> params = new LinkedHashMap<>();
        if (query == null || query.isBlank()) return params;
        for (String pair : query.split("&")) {
            int eq = pair.indexOf('=');
            if (eq > 0) {
                String key = URLDecoder.decode(pair.substring(0, eq), StandardCharsets.UTF_8);
                String val = URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8);
                params.put(key, val);
            }
        }
        return params;
    }

    @SuppressWarnings("unchecked")
    private static Object extractParamValue(ParamDef p,
            Map<String, String> queryParams,
            Map<String, Object> jsonParams,
            Map<String, String> urlQueryParams) {
        // Get raw value: try JSON body first, then form params, then URL query
        Object raw = null;
        if (jsonParams != null) {
            raw = jsonParams.get(p.name());
        }
        if (raw == null && queryParams != null) {
            raw = queryParams.get(p.name());
        }
        if (raw == null && urlQueryParams != null) {
            raw = urlQueryParams.get(p.name());
        }

        // Apply default if null
        if (raw == null && !p.defaultValue().isEmpty()) {
            raw = p.defaultValue();
        }

        Class<?> type = p.javaType();

        if (raw == null) {
            if (type == int.class) return 0;
            if (type == long.class) return 0L;
            if (type == boolean.class) return false;
            if (type == double.class) return 0.0;
            if (type == float.class) return 0.0f;
            return null;
        }

        if (type == String.class) {
            if (raw instanceof String) return raw;
            if (raw instanceof Map || raw instanceof List) return JsonHelper.toJson(raw);
            return raw.toString();
        }

        if (type == int.class || type == Integer.class) {
            if (raw instanceof Number n) return n.intValue();
            try { return Integer.parseInt(raw.toString()); }
            catch (NumberFormatException e) {
                if (!p.defaultValue().isEmpty()) return Integer.parseInt(p.defaultValue());
                return 0;
            }
        }

        if (type == long.class || type == Long.class) {
            if (raw instanceof Number n) return n.longValue();
            try { return Long.parseLong(raw.toString()); }
            catch (NumberFormatException e) { return 0L; }
        }

        if (type == boolean.class || type == Boolean.class) {
            if (raw instanceof Boolean b) return b;
            return "true".equalsIgnoreCase(raw.toString());
        }

        if (type == double.class || type == Double.class) {
            if (raw instanceof Number n) return n.doubleValue();
            try { return Double.parseDouble(raw.toString()); }
            catch (NumberFormatException e) { return 0.0; }
        }

        if (type == Integer.class) {
            // Nullable Integer
            if (raw instanceof Number n) return n.intValue();
            try { return Integer.parseInt(raw.toString()); }
            catch (NumberFormatException e) { return null; }
        }

        if (type == Boolean.class) {
            // Nullable Boolean
            if (raw instanceof Boolean b) return b;
            return Boolean.parseBoolean(raw.toString());
        }

        if (Map.class.isAssignableFrom(type)) {
            if (raw instanceof Map) return raw;
            if (raw instanceof String s) return JsonHelper.parseJson(s);
            return null;
        }

        if (List.class.isAssignableFrom(type)) {
            if (raw instanceof List) return raw;
            return null;
        }

        return raw;
    }

    // ==================================================================================
    // MCP Schema generation
    // ==================================================================================

    /** Generate /mcp/schema JSON from scanned tools. */
    public static String toSchemaJson(List<ToolDef> defs) {
        List<Map<String, Object>> tools = new ArrayList<>();
        for (ToolDef def : defs) {
            Map<String, Object> tool = new LinkedHashMap<>();
            tool.put("name", def.toolName());
            tool.put("description", def.description());
            tool.put("endpoint", def.path());
            tool.put("http_method", def.httpMethod());
            tool.put("category", def.category());
            tool.put("input_schema", buildInputSchema(def));
            tools.add(tool);
        }
        return JsonHelper.toJson(tools);
    }

    private static Map<String, Object> buildInputSchema(ToolDef def) {
        Map<String, Object> schema = new LinkedHashMap<>();
        schema.put("type", "object");

        Map<String, Object> properties = new LinkedHashMap<>();
        List<String> required = new ArrayList<>();

        for (ParamDef p : def.params()) {
            if ("_body".equals(p.name())) continue;
            Map<String, Object> prop = new LinkedHashMap<>();
            prop.put("type", p.jsonType());
            if (!p.description().isEmpty()) {
                prop.put("description", p.description());
            }
            if (!p.defaultValue().isEmpty()) {
                prop.put("default", convertDefault(p.defaultValue(), p.jsonType()));
            }
            properties.put(p.name(), prop);
            if (p.required()) {
                required.add(p.name());
            }
        }

        schema.put("properties", properties);
        if (!required.isEmpty()) {
            schema.put("required", required);
        }
        return schema;
    }

    private static Object convertDefault(String value, String jsonType) {
        return switch (jsonType) {
            case "integer" -> {
                try { yield Integer.parseInt(value); }
                catch (NumberFormatException e) { yield value; }
            }
            case "number" -> {
                try { yield Double.parseDouble(value); }
                catch (NumberFormatException e) { yield value; }
            }
            case "boolean" -> Boolean.parseBoolean(value);
            default -> value;
        };
    }
}
