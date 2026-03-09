package com.xebyte.core;

import java.util.*;

/**
 * Declarative endpoint definition for shared registration between GUI and headless modes.
 *
 * @param path        HTTP path (e.g., "/list_functions")
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

        /** Serialize to JSON. */
        public String toJson() {
            StringBuilder sb = new StringBuilder();
            sb.append("{\"name\": \"").append(ServiceUtils.escapeJson(name)).append("\"");
            sb.append(", \"type\": \"").append(type).append("\"");
            sb.append(", \"source\": \"").append(source).append("\"");
            sb.append(", \"required\": ").append(required);
            if (defaultValue != null) {
                sb.append(", \"default\": \"").append(ServiceUtils.escapeJson(defaultValue)).append("\"");
            }
            if (description != null && !description.isEmpty()) {
                sb.append(", \"description\": \"").append(ServiceUtils.escapeJson(description)).append("\"");
            }
            sb.append("}");
            return sb.toString();
        }
    }

    /** Serialize endpoint schema to JSON. */
    public String schemaJson() {
        StringBuilder sb = new StringBuilder();
        sb.append("{\"path\": \"").append(ServiceUtils.escapeJson(path)).append("\"");
        sb.append(", \"method\": \"").append(method).append("\"");
        if (description != null && !description.isEmpty()) {
            sb.append(", \"description\": \"").append(ServiceUtils.escapeJson(description)).append("\"");
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
