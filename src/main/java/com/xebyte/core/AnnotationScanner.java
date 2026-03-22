package com.xebyte.core;

import java.lang.annotation.Annotation;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Parameter;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Discovers {@link McpTool}-annotated methods on service instances via reflection
 * and generates {@link EndpointDef} records for HTTP registration plus JSON schemas
 * for dynamic MCP tool discovery.
 *
 * <h3>Usage</h3>
 * <pre>{@code
 * AnnotationScanner scanner = new AnnotationScanner(
 *     listingService, functionService, commentService, ...);
 *
 * // Register discovered endpoints
 * for (EndpointDef ep : scanner.getEndpoints()) {
 *     server.createContext(ep.path(), ...);
 * }
 *
 * // Generate JSON schema for /mcp/schema
 * String schema = scanner.generateSchema();
 * }</pre>
 *
 * @since 4.3.0
 */
public class AnnotationScanner {

    private static final Logger LOG = Logger.getLogger(AnnotationScanner.class.getName());
    private static final String NO_DEFAULT = Param.NO_DEFAULT;

    private final List<EndpointDef> endpoints = new ArrayList<>();
    private final List<ToolDescriptor> descriptors = new ArrayList<>();

    /**
     * Scan the given service instances for {@link McpTool}-annotated methods.
     *
     * @param services service objects to scan (e.g., ListingService, FunctionService, ...)
     */
    public AnnotationScanner(Object... services) {
        for (Object service : services) {
            scanService(service);
        }
        // Sort by path for deterministic ordering
        endpoints.sort(Comparator.comparing(EndpointDef::path));
        descriptors.sort(Comparator.comparing(ToolDescriptor::path));
    }

    /** Returns all discovered endpoints. */
    public List<EndpointDef> getEndpoints() {
        return Collections.unmodifiableList(endpoints);
    }

    /** Returns all tool descriptors (for schema generation). */
    public List<ToolDescriptor> getDescriptors() {
        return Collections.unmodifiableList(descriptors);
    }

    /** Generate a JSON schema string describing all discovered tools. */
    public String generateSchema() {
        StringBuilder sb = new StringBuilder();
        sb.append("{\"tools\": [");
        for (int i = 0; i < descriptors.size(); i++) {
            if (i > 0) sb.append(", ");
            sb.append(descriptors.get(i).toJson());
        }
        sb.append("], \"count\": ").append(descriptors.size()).append("}");
        return sb.toString();
    }

    // ==================================================================
    // Scanning
    // ==================================================================

    private void scanService(Object service) {
        for (Method method : service.getClass().getDeclaredMethods()) {
            McpTool tool = method.getAnnotation(McpTool.class);
            if (tool == null) continue;

            try {
                method.setAccessible(true);
                ParamBinding[] bindings = buildBindings(method);
                EndpointDef.EndpointHandler handler = createHandler(service, method, tool, bindings);
                endpoints.add(new EndpointDef(tool.path(), tool.method(), handler));
                descriptors.add(buildDescriptor(tool, method, bindings));
                LOG.fine("Registered annotated endpoint: " + tool.method() + " " + tool.path());
            } catch (Exception e) {
                LOG.log(Level.WARNING, "Failed to register " + tool.path() + ": " + e.getMessage(), e);
            }
        }
    }

    private ParamBinding[] buildBindings(Method method) {
        Parameter[] params = method.getParameters();
        Annotation[][] paramAnnotations = method.getParameterAnnotations();
        ParamBinding[] bindings = new ParamBinding[params.length];

        for (int i = 0; i < params.length; i++) {
            Param param = findParamAnnotation(paramAnnotations[i]);
            if (param != null) {
                bindings[i] = new ParamBinding(param, params[i].getType());
            }
        }
        return bindings;
    }

    private static Param findParamAnnotation(Annotation[] annotations) {
        for (Annotation ann : annotations) {
            if (ann instanceof Param p) return p;
        }
        return null;
    }

    // ==================================================================
    // Handler creation
    // ==================================================================

    private EndpointDef.EndpointHandler createHandler(Object service, Method method,
            McpTool tool, ParamBinding[] bindings) {
        return (query, body) -> {
            try {
                Object[] args = new Object[bindings.length];
                for (int i = 0; i < bindings.length; i++) {
                    if (bindings[i] != null) {
                        args[i] = resolveParam(bindings[i], query, body);
                    }
                }
                return (Response) method.invoke(service, args);
            } catch (InvocationTargetException e) {
                Throwable cause = e.getCause();
                String msg = cause != null ? cause.getMessage() : e.getMessage();
                LOG.log(Level.WARNING, "Error in " + tool.path() + ": " + msg, cause != null ? cause : e);
                return Response.err("Error in " + tool.path() + ": " + msg);
            } catch (Exception e) {
                LOG.log(Level.WARNING, "Invocation error for " + tool.path() + ": " + e.getMessage(), e);
                return Response.err("Error invoking " + tool.path() + ": " + e.getMessage());
            }
        };
    }

    // ==================================================================
    // Parameter resolution
    // ==================================================================

    private static Object resolveParam(ParamBinding binding, Map<String, String> query,
            Map<String, Object> body) {
        if (binding.param.source() == ParamSource.QUERY) {
            return resolveQueryParam(binding, query);
        } else {
            return resolveBodyParam(binding, body);
        }
    }

    private static Object resolveQueryParam(ParamBinding binding, Map<String, String> query) {
        String value = query.get(binding.param.value());
        Class<?> type = binding.javaType;
        String def = binding.param.defaultValue();
        boolean hasDef = !NO_DEFAULT.equals(def);

        if (type == String.class) {
            if (value != null) return value;
            return hasDef ? (def.isEmpty() ? null : def) : null;

        } else if (type == int.class) {
            int defaultVal = hasDef ? parseIntSafe(def, 0) : 0;
            if (value == null || value.isEmpty()) return defaultVal;
            return parseIntSafe(value, defaultVal);

        } else if (type == Integer.class) {
            if (value == null || value.isEmpty()) return null;
            try { return Integer.parseInt(value); } catch (NumberFormatException e) { return null; }

        } else if (type == boolean.class) {
            boolean defaultVal = hasDef && Boolean.parseBoolean(def);
            if (value == null || value.isEmpty()) return defaultVal;
            return "true".equalsIgnoreCase(value);

        } else if (type == Boolean.class) {
            if (value == null || value.isEmpty()) return null;
            return Boolean.parseBoolean(value);

        } else if (type == double.class) {
            double defaultVal = hasDef ? parseDoubleSafe(def, 0.0) : 0.0;
            if (value == null || value.isEmpty()) return defaultVal;
            return parseDoubleSafe(value, defaultVal);

        } else if (type == long.class) {
            long defaultVal = hasDef ? parseLongSafe(def, 0L) : 0L;
            if (value == null || value.isEmpty()) return defaultVal;
            return parseLongSafe(value, defaultVal);
        }
        return value;
    }

    @SuppressWarnings("unchecked")
    private static Object resolveBodyParam(ParamBinding binding, Map<String, Object> body) {
        Object raw = body.get(binding.param.value());
        Class<?> type = binding.javaType;
        String def = binding.param.defaultValue();
        boolean hasDef = !NO_DEFAULT.equals(def);

        // Special: fieldsJson conversion (serialize complex objects to JSON string)
        if (binding.param.fieldsJson()) {
            return convertFieldsJson(raw);
        }

        if (type == String.class) {
            if (raw != null) return String.valueOf(raw);
            return hasDef ? (def.isEmpty() ? null : def) : null;

        } else if (type == int.class) {
            int defaultVal = hasDef ? parseIntSafe(def, 0) : 0;
            return JsonHelper.getInt(raw, defaultVal);

        } else if (type == Integer.class) {
            if (raw == null) return null;
            return JsonHelper.getInt(raw, 0);

        } else if (type == long.class) {
            long defaultVal = hasDef ? parseLongSafe(def, 0L) : 0L;
            if (raw == null) return defaultVal;
            if (raw instanceof Number n) return n.longValue();
            try { return Long.parseLong(String.valueOf(raw)); }
            catch (NumberFormatException e) { return defaultVal; }

        } else if (type == boolean.class) {
            boolean defaultVal = hasDef && Boolean.parseBoolean(def);
            if (raw == null) return defaultVal;
            if (raw instanceof Boolean b) return b;
            return "true".equalsIgnoreCase(String.valueOf(raw));

        } else if (type == Boolean.class) {
            if (raw == null) return null;
            if (raw instanceof Boolean b) return b;
            return Boolean.parseBoolean(String.valueOf(raw));

        } else if (type == double.class) {
            double defaultVal = hasDef ? parseDoubleSafe(def, 0.0) : 0.0;
            if (raw == null) return defaultVal;
            if (raw instanceof Number n) return n.doubleValue();
            return parseDoubleSafe(String.valueOf(raw), defaultVal);

        } else if (type == Map.class) {
            return convertStringMap(body, binding.param.value());

        } else if (type == List.class) {
            return ServiceUtils.convertToMapList(raw);

        } else if (type == Object.class) {
            return raw;
        }
        return raw;
    }

    // ==================================================================
    // Type conversion helpers
    // ==================================================================

    private static String convertFieldsJson(Object obj) {
        if (obj == null) return null;
        if (obj instanceof String s) return s;
        if (obj instanceof List<?> list) return ServiceUtils.serializeListToJson(list);
        if (obj instanceof Map<?, ?>) return ServiceUtils.serializeMapToJson((Map<?, ?>) obj);
        return obj.toString();
    }

    @SuppressWarnings("unchecked")
    private static Map<String, String> convertStringMap(Map<String, Object> body, String key) {
        Object obj = body.get(key);
        if (obj instanceof Map) return (Map<String, String>) obj;
        if (obj instanceof String s) {
            Map<String, String> result = new HashMap<>();
            Map<String, Object> parsed = JsonHelper.parseJson(s);
            parsed.forEach((k, v) -> result.put(k, v != null ? String.valueOf(v) : null));
            return result;
        }
        return new HashMap<>();
    }

    private static int parseIntSafe(String s, int def) {
        try { return Integer.parseInt(s); } catch (NumberFormatException e) { return def; }
    }

    private static long parseLongSafe(String s, long def) {
        try { return Long.parseLong(s); } catch (NumberFormatException e) { return def; }
    }

    private static double parseDoubleSafe(String s, double def) {
        try { return Double.parseDouble(s); } catch (NumberFormatException e) { return def; }
    }

    // ==================================================================
    // Schema generation
    // ==================================================================

    private ToolDescriptor buildDescriptor(McpTool tool, Method method, ParamBinding[] bindings) {
        List<ParamDescriptor> params = new ArrayList<>();
        for (ParamBinding binding : bindings) {
            if (binding == null) continue;
            params.add(new ParamDescriptor(
                binding.param.value(),
                jsonType(binding.javaType, binding.param.fieldsJson()),
                binding.param.source().name().toLowerCase(),
                !NO_DEFAULT.equals(binding.param.defaultValue()),
                NO_DEFAULT.equals(binding.param.defaultValue()) ? null : binding.param.defaultValue(),
                binding.param.description(),
                binding.param.paramType()    // NEW
            ));
        }
        return new ToolDescriptor(tool.path(), tool.method(), tool.description(), tool.category(), params);
    }

    private static String jsonType(Class<?> type, boolean fieldsJson) {
        if (type == String.class) return fieldsJson ? "json" : "string";
        if (type == int.class || type == Integer.class) return "integer";
        if (type == long.class || type == Long.class) return "integer";
        if (type == boolean.class || type == Boolean.class) return "boolean";
        if (type == double.class || type == Double.class) return "number";
        if (type == Map.class) return "object";
        if (type == List.class) return "array";
        if (type == Object.class) return "any";
        return "string";
    }

    // ==================================================================
    // Descriptor records
    // ==================================================================

    /** Describes an MCP tool for schema generation. */
    public record ToolDescriptor(String path, String method, String description,
            String category, List<ParamDescriptor> params) {

        /** Serialize to JSON. */
        public String toJson() {
            StringBuilder sb = new StringBuilder();
            sb.append("{\"path\": ").append(jsonStr(path));
            sb.append(", \"method\": ").append(jsonStr(method));
            if (description != null && !description.isEmpty()) {
                sb.append(", \"description\": ").append(jsonStr(description));
            }
            if (category != null && !category.isEmpty()) {
                sb.append(", \"category\": ").append(jsonStr(category));
            }
            sb.append(", \"params\": [");
            for (int i = 0; i < params.size(); i++) {
                if (i > 0) sb.append(", ");
                sb.append(params.get(i).toJson());
            }
            sb.append("]}");
            return sb.toString();
        }
    }

    /** Describes a tool parameter for schema generation. */
    public record ParamDescriptor(String name, String type, String source,
            boolean optional, String defaultValue, String description, String paramType) {

        /** Serialize to JSON. */
        public String toJson() {
            StringBuilder sb = new StringBuilder();
            sb.append("{\"name\": ").append(jsonStr(name));
            sb.append(", \"type\": ").append(jsonStr(type));
            sb.append(", \"source\": ").append(jsonStr(source));
            sb.append(", \"required\": ").append(!optional);
            if (defaultValue != null) {
                sb.append(", \"default\": ").append(jsonStr(defaultValue));
            }
            if (description != null && !description.isEmpty()) {
                sb.append(", \"description\": ").append(jsonStr(description));
            }
            if (paramType != null && !paramType.isEmpty()) {
                sb.append(", \"param_type\": ").append(jsonStr(paramType));
            }
            sb.append("}");
            return sb.toString();
        }
    }

    private static String jsonStr(String s) {
        if (s == null) return "null";
        return "\"" + ServiceUtils.escapeJson(s) + "\"";
    }

    // ==================================================================
    // Internal binding record
    // ==================================================================

    private record ParamBinding(Param param, Class<?> javaType) {}
}
