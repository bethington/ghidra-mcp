package com.xebyte.core;

import com.sun.net.httpserver.Headers;
import ghidra.util.Msg;

import java.io.IOException;
import java.io.OutputStream;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.function.Consumer;

/**
 * HTTP infrastructure utilities: context registration, param parsing, response sending.
 * Endpoint dispatch is handled by {@link AnnotationScanner}.
 */
public final class EndpointRegistrar {

    private EndpointRegistrar() {}

    /**
     * Abstraction for registering an HTTP context handler on a server.
     * GUI uses UdsHttpServer, headless uses com.sun.net.httpserver.HttpServer.
     */
    @FunctionalInterface
    public interface ContextRegistrar {
        void createContext(String path, Consumer<HttpExchange> handler);
    }

    // ==================================================================================
    // Param parsing
    // ==================================================================================

    public static Map<String, String> parseQueryParams(HttpExchange exchange) {
        Map<String, String> result = new HashMap<>();
        String query = exchange.getRequestURI().getQuery();
        if (query != null) {
            for (String p : query.split("&")) {
                String[] kv = p.split("=", 2);
                if (kv.length == 2) {
                    try {
                        result.put(
                            URLDecoder.decode(kv[0], StandardCharsets.UTF_8),
                            URLDecoder.decode(kv[1], StandardCharsets.UTF_8));
                    } catch (Exception e) {
                        // skip malformed param
                    }
                }
            }
        }
        return result;
    }

    public static Map<String, String> parsePostParams(HttpExchange exchange) throws IOException {
        byte[] body = exchange.getRequestBody().readAllBytes();
        String bodyStr = new String(body, StandardCharsets.UTF_8);
        Map<String, String> params = new HashMap<>();
        for (String pair : bodyStr.split("&")) {
            String[] kv = pair.split("=", 2);
            if (kv.length == 2) {
                try {
                    params.put(
                        URLDecoder.decode(kv[0], StandardCharsets.UTF_8),
                        URLDecoder.decode(kv[1], StandardCharsets.UTF_8));
                } catch (Exception e) {
                    // skip malformed param
                }
            }
        }
        return params;
    }

    public static Map<String, Object> parseJsonParams(HttpExchange exchange) throws IOException {
        return JsonHelper.parseBody(exchange.getRequestBody());
    }

    // ==================================================================================
    // Response sending
    // ==================================================================================

    public static void sendResponse(HttpExchange exchange, Response response) throws IOException {
        String body = switch (response) {
            case Response.Ok(var data)     -> JsonHelper.toJson(data);
            case Response.Err(var message) -> JsonHelper.toJson(Map.of("error", message));
            case Response.Text(var text)   -> text;
        };
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        Headers headers = exchange.getResponseHeaders();
        headers.set("Content-Type", "text/plain; charset=utf-8");
        exchange.sendResponseHeaders(200, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
            os.flush();
        }
    }

    // ==================================================================================
    // Safe handler wrapper
    // ==================================================================================

    @FunctionalInterface
    public interface CheckedHandler { void handle(HttpExchange ex) throws Exception; }

    public static Consumer<HttpExchange> safeHandler(CheckedHandler handler) {
        return exchange -> {
            try {
                handler.handle(exchange);
            } catch (Throwable e) {
                try {
                    String msg = e.getMessage() != null ? e.getMessage() : e.toString();
                    sendResponse(exchange, new Response.Err(msg));
                } catch (Throwable ignored) {
                    Msg.error(EndpointRegistrar.class, "Failed to send error response", ignored);
                }
            }
        };
    }

    // ==================================================================================
    // Static param helpers
    // ==================================================================================

    public static int getInt(Map<String, ?> map, String key, int defaultValue) {
        Object v = map != null ? map.get(key) : null;
        if (v == null) return defaultValue;
        if (v instanceof Number) return ((Number) v).intValue();
        try { return Integer.parseInt(v.toString()); } catch (NumberFormatException e) { return defaultValue; }
    }

    public static double getDouble(Map<String, ?> map, String key, double defaultValue) {
        Object v = map != null ? map.get(key) : null;
        if (v == null) return defaultValue;
        if (v instanceof Number) return ((Number) v).doubleValue();
        try { return Double.parseDouble(v.toString()); } catch (NumberFormatException e) { return defaultValue; }
    }

    public static boolean getBool(Map<String, ?> map, String key, boolean defaultValue) {
        Object v = map != null ? map.get(key) : null;
        if (v == null) return defaultValue;
        if (v instanceof Boolean) return (Boolean) v;
        return Boolean.parseBoolean(v.toString());
    }

    public static String getStr(Map<String, ?> map, String key) {
        Object v = map != null ? map.get(key) : null;
        return v != null ? v.toString() : null;
    }

    /** Coerce a parsed JSON value (String, List, Map) to a JSON string for service methods that accept raw JSON. */
    public static String coerceToJsonString(Object obj) {
        if (obj == null) return null;
        if (obj instanceof String) return (String) obj;
        return JsonHelper.toJson(obj);
    }

    public static int parseIntOrDefault(String val, int defaultValue) {
        if (val == null) return defaultValue;
        try { return Integer.parseInt(val); } catch (NumberFormatException e) { return defaultValue; }
    }

    /** Convert Object (potentially List) to List<Map<String, String>> for batch operations. */
    @SuppressWarnings("unchecked")
    public static List<Map<String, String>> convertToMapList(Object obj) {
        if (obj == null) return null;
        if (obj instanceof List) {
            List<Object> objList = (List<Object>) obj;
            List<Map<String, String>> result = new ArrayList<>();
            for (Object item : objList) {
                if (item instanceof Map) {
                    result.add((Map<String, String>) item);
                }
            }
            return result;
        }
        return null;
    }

    public static String objectToCommaSeparated(Object obj) {
        if (obj == null) return "";
        if (obj instanceof List) {
            StringBuilder sb = new StringBuilder();
            for (Object item : (List<?>) obj) {
                if (item != null) {
                    if (sb.length() > 0) sb.append(",");
                    sb.append(item.toString());
                }
            }
            return sb.toString();
        }
        return obj.toString();
    }
}
