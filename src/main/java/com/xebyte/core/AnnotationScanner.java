package com.xebyte.core;

import java.lang.reflect.Method;
import java.lang.reflect.Parameter;
import java.util.*;

/**
 * Reflection engine that scans service instances for {@link McpTool} annotations
 * and builds both HTTP dispatch handlers and the MCP tool schema.
 * Replaces the {@code Ep} sealed interface and {@code EndpointRegistrar.sharedEndpoints()}.
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
        String description, Method method,
        Object serviceInstance, List<ParamDef> params
    ) {}

    // ==================================================================================
    // Scan
    // ==================================================================================

    /** Scan one or more service instances for @McpTool methods. */
    public static List<ToolDef> scan(Object... services) {
        List<ToolDef> defs = new ArrayList<>();
        for (Object svc : services) {
            for (Method m : svc.getClass().getMethods()) {
                McpTool ann = m.getAnnotation(McpTool.class);
                if (ann == null) continue;
                List<ParamDef> params = extractParams(m);
                String toolName = pathToToolName(ann.value());
                defs.add(new ToolDef(
                    ann.value(), ann.method().name(), toolName,
                    ann.description(), m, svc, params));
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
            // Auto-detect type from Java type if annotation says "string" (default)
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

    /** Convert HTTP path like "/rename_function" to tool name "rename_function". */
    static String pathToToolName(String path) {
        return path.startsWith("/") ? path.substring(1) : path;
    }

    // ==================================================================================
    // HTTP Registration
    // ==================================================================================

    /** Register all scanned tools as HTTP endpoints on the given server. */
    public static void registerHttp(EndpointRegistrar.ContextRegistrar registrar, List<ToolDef> defs) {
        for (ToolDef def : defs) {
            registrar.createContext(def.path(), EndpointRegistrar.safeHandler(exchange -> {
                Object[] args = resolveArgs(def, exchange);
                Object result = def.method().invoke(def.serviceInstance(), args);
                if (result instanceof Response r) {
                    EndpointRegistrar.sendResponse(exchange, r);
                } else {
                    EndpointRegistrar.sendResponse(exchange, Response.ok(result));
                }
            }));
        }
    }

    /** Resolve method arguments from HTTP request based on param annotations and HTTP method. */
    private static Object[] resolveArgs(ToolDef def, HttpExchange exchange) throws Exception {
        boolean isPost = "POST".equals(def.httpMethod());

        // Special case: "_body" param means pass entire JSON body as string
        boolean hasBodyParam = def.params().stream().anyMatch(p -> "_body".equals(p.name()));

        // Determine if this is a JSON POST (has non-string params like Map/List, or _body, or any param)
        boolean isJsonPost = isPost && (hasBodyParam || def.params().stream().anyMatch(p ->
            "object".equals(p.jsonType()) || "array".equals(p.jsonType())));
        // For POST with all-string params, use form-encoded; for JSON body params, use JSON parsing
        Map<String, Object> jsonParams = null;
        Map<String, String> queryOrFormParams = null;
        String rawJsonBody = null;

        if (isJsonPost) {
            if (hasBodyParam) {
                // Read raw body for _body param
                byte[] bodyBytes = exchange.getRequestBody().readAllBytes();
                rawJsonBody = new String(bodyBytes, java.nio.charset.StandardCharsets.UTF_8);
                // Also parse it as JSON for mixed cases
                if (!rawJsonBody.isBlank()) {
                    jsonParams = JsonHelper.parseBody(new java.io.ByteArrayInputStream(bodyBytes));
                } else {
                    jsonParams = new HashMap<>();
                }
            } else {
                jsonParams = EndpointRegistrar.parseJsonParams(exchange);
            }
        } else if (isPost) {
            // Check if content type is JSON
            String contentType = exchange.getRequestHeaders().getFirst("Content-Type");
            if (contentType != null && contentType.contains("application/json")) {
                jsonParams = EndpointRegistrar.parseJsonParams(exchange);
            } else {
                queryOrFormParams = EndpointRegistrar.parsePostParams(exchange);
            }
        } else {
            queryOrFormParams = EndpointRegistrar.parseQueryParams(exchange);
        }

        Object[] args = new Object[def.params().size()];
        for (int i = 0; i < def.params().size(); i++) {
            ParamDef p = def.params().get(i);
            if ("_body".equals(p.name()) && rawJsonBody != null) {
                args[i] = rawJsonBody;
            } else {
                args[i] = extractParamValue(p, queryOrFormParams, jsonParams);
            }
        }
        return args;
    }

    /** Extract a single parameter value from the request, converting types as needed. */
    @SuppressWarnings("unchecked")
    private static Object extractParamValue(ParamDef p,
            Map<String, String> queryOrFormParams,
            Map<String, Object> jsonParams) {
        // Get raw value from whichever map is available
        Object raw;
        if (jsonParams != null) {
            raw = jsonParams.get(p.name());
        } else if (queryOrFormParams != null) {
            raw = queryOrFormParams.get(p.name());
        } else {
            raw = null;
        }

        // Apply default if null
        if (raw == null && !p.defaultValue().isEmpty()) {
            raw = p.defaultValue();
        }

        // Convert to target Java type
        Class<?> type = p.javaType();

        if (raw == null) {
            // Return primitive defaults
            if (type == int.class) return 0;
            if (type == long.class) return 0L;
            if (type == boolean.class) return false;
            if (type == double.class) return 0.0;
            if (type == float.class) return 0.0f;
            return null;
        }

        // String target
        if (type == String.class) {
            if (raw instanceof String) return raw;
            // For complex objects passed as string params (coerce to JSON)
            if (raw instanceof Map || raw instanceof List) return JsonHelper.toJson(raw);
            return raw.toString();
        }

        // Integer target
        if (type == int.class || type == Integer.class) {
            if (raw instanceof Number n) return n.intValue();
            try { return Integer.parseInt(raw.toString()); }
            catch (NumberFormatException e) {
                if (!p.defaultValue().isEmpty()) return Integer.parseInt(p.defaultValue());
                return 0;
            }
        }

        // Long target
        if (type == long.class || type == Long.class) {
            if (raw instanceof Number n) return n.longValue();
            try { return Long.parseLong(raw.toString()); }
            catch (NumberFormatException e) { return 0L; }
        }

        // Boolean target
        if (type == boolean.class || type == Boolean.class) {
            if (raw instanceof Boolean b) return b;
            return Boolean.parseBoolean(raw.toString());
        }

        // Double target
        if (type == double.class || type == Double.class) {
            if (raw instanceof Number n) return n.doubleValue();
            try { return Double.parseDouble(raw.toString()); }
            catch (NumberFormatException e) { return 0.0; }
        }

        // Map target (for batch operations)
        if (Map.class.isAssignableFrom(type)) {
            if (raw instanceof Map) return raw;
            return null;
        }

        // List target (for batch arrays)
        if (List.class.isAssignableFrom(type)) {
            if (raw instanceof List) return raw;
            return null;
        }

        // Fallback: try to return as-is
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
            // _body is an internal convention (raw JSON passthrough), not a user-facing param
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
