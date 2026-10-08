package com.xebyte.core;

import java.util.*;

/**
 * Declarative endpoint definition for shared registration between GUI and headless modes.
 *
 * @param path        HTTP path (e.g., "/find_functions")
 * @param method      HTTP method ("GET" or "POST")
 * @param handler     Lambda that processes the request and returns a Response
 * @param description Human-readable description (for schema generation)
 * @param params      Parameter schema descriptors (for schema generation)
 */
public record EndpointDef(String path, String method, EndpointHandler handler,
                          String description, List<ParamDef> params) {

    /** Backward-compatible constructor without schema metadata. */
    public EndpointDef(String path, String method, EndpointHandler handler) {
        this(path, method, handler, "", List.of());
    }

    /** Functional interface for endpoint handlers. */
    @FunctionalInterface
    public interface EndpointHandler {
        /**
         * Handle an HTTP request.
         *
         * @param query Query parameters from the URL (GET params)
         * @param body  Parsed JSON body (POST params), empty map for GET requests
         * @return Response to send back to the client
         * @throws Exception Any exception is caught by the safe handler wrapper
         */
        Response handle(Map<String, String> query, Map<String, Object> body) throws Exception;
    }

    /**
     * Parameter schema descriptor for schema generation.
     *
     * @param name         Parameter name
     * @param type         JSON Schema type (string, integer, boolean, number, object, array)
     * @param source       Where the param comes from (query or body)
     * @param required     Whether the parameter is required
     * @param defaultValue Default value (null if none)
     * @param description  Human-readable description
     */
    public record ParamDef(String name, String type, String source,
                           boolean required, String defaultValue, String description) {

        /** Map form used by {@link #toJson()} and by the parent endpoint schema. */
        public Map<String, Object> toMap() {
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("name", name);
            out.put("type", type);
            out.put("source", source);
            out.put("required", required);
            if (defaultValue != null) {
                out.put("default", defaultValue);
            }
            if (description != null && !description.isEmpty()) {
                out.put("description", description);
            }
            return out;
        }

        /** Serialize to JSON via Gson (field order matches the former hand-built string). */
        public String toJson() {
            return JsonHelper.toJson(toMap());
        }
    }

    /** Serialize endpoint schema to JSON via Gson. */
    public String schemaJson() {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("path", path);
        out.put("method", method);
        if (description != null && !description.isEmpty()) {
            out.put("description", description);
        }
        List<Map<String, Object>> paramMaps = new ArrayList<>();
        for (ParamDef p : params) {
            paramMaps.add(p.toMap());
        }
        out.put("params", paramMaps);
        return JsonHelper.toJson(out);
    }
}
