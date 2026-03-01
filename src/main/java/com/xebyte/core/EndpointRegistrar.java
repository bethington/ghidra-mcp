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
 * Shared endpoint dispatch infrastructure.
 * Registers {@link Ep} entries against any server that provides a {@link ContextRegistrar}.
 * Extracted from EndpointRouter so both GUI and headless can share the same dispatch logic.
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
    // Bulk registration
    // ==================================================================================

    public static void registerAll(ContextRegistrar registrar, List<Ep> table) {
        for (Ep ep : table) {
            register(registrar, ep);
        }
    }

    // ==================================================================================
    // Single endpoint dispatch — exhaustive switch on Ep variants
    // ==================================================================================

    public static void register(ContextRegistrar registrar, Ep ep) {
        switch (ep) {
            case Ep.Get0(var path, var fn)                                     -> get0(registrar, path, fn);
            case Ep.Get1(var path, var p1, var fn)                             -> get1(registrar, path, p1, fn);
            case Ep.Get2(var path, var p1, var p2, var fn)                     -> get2(registrar, path, p1, p2, fn);
            case Ep.Get3(var path, var p1, var p2, var p3, var fn)             -> get3(registrar, path, p1, p2, p3, fn);
            case Ep.Get4(var path, var p1, var p2, var p3, var p4, var fn)     -> get4(registrar, path, p1, p2, p3, p4, fn);
            case Ep.GetPage(var path, var fn)                                  -> getPage(registrar, path, fn);
            case Ep.GetPage1(var path, var pn, var fn)                         -> getPage1(registrar, path, pn, fn);
            case Ep.GetPage1R(var path, var pn, var fn)                        -> getPage1r(registrar, path, pn, fn);
            case Ep.GetPageNP(var path, var fn)                                -> getPageNP(registrar, path, fn);
            case Ep.GetPage1NP(var path, var pn, var fn)                       -> getPage1NP(registrar, path, pn, fn);
            case Ep.GetQuery(var path, var fn)                                 -> getWithQuery(registrar, path, fn);
            case Ep.Post1(var path, var p1, var fn)                            -> post1(registrar, path, p1, fn);
            case Ep.Post2(var path, var p1, var p2, var fn)                    -> post2(registrar, path, p1, p2, fn);
            case Ep.Post3(var path, var p1, var p2, var p3, var fn)            -> post3(registrar, path, p1, p2, p3, fn);
            case Ep.Json1(var path, var p1, var fn)                            -> json1(registrar, path, p1, fn);
            case Ep.Json2(var path, var p1, var p2, var fn)                    -> json2(registrar, path, p1, p2, fn);
            case Ep.Json3(var path, var p1, var p2, var p3, var fn)            -> json3(registrar, path, p1, p2, p3, fn);
            case Ep.Json4(var path, var p1, var p2, var p3, var p4, var fn)    -> json4(registrar, path, p1, p2, p3, p4, fn);
            case Ep.JsonPost(var path, var fn)                                 -> jsonPost(registrar, path, fn);
        }
    }

    // ==================================================================================
    // Handler helpers — each wires a specific Ep pattern to param parsing + dispatch
    // ==================================================================================

    private static void getPage(ContextRegistrar r, String path, Ep.PageFn fn) {
        r.createContext(path, safeHandler(ex -> {
            Map<String,String> q = parseQueryParams(ex);
            sendResponse(ex, fn.apply(parseIntOrDefault(q.get("offset"),0), parseIntOrDefault(q.get("limit"),100), q.get("program")));
        }));
    }

    private static void getPage1(ContextRegistrar r, String path, String pName, Ep.PageFn1 fn) {
        r.createContext(path, safeHandler(ex -> {
            Map<String,String> q = parseQueryParams(ex);
            sendResponse(ex, fn.apply(q.get(pName), parseIntOrDefault(q.get("offset"),0), parseIntOrDefault(q.get("limit"),100), q.get("program")));
        }));
    }

    private static void getPage1r(ContextRegistrar r, String path, String pName, Ep.PageFn1R fn) {
        r.createContext(path, safeHandler(ex -> {
            Map<String,String> q = parseQueryParams(ex);
            sendResponse(ex, fn.apply(parseIntOrDefault(q.get("offset"),0), parseIntOrDefault(q.get("limit"),100), q.get(pName), q.get("program")));
        }));
    }

    private static void get0(ContextRegistrar r, String path, Ep.Fn0 fn) {
        r.createContext(path, safeHandler(ex -> sendResponse(ex, fn.apply())));
    }

    private static void get1(ContextRegistrar r, String path, String p1, Ep.Fn1 fn) {
        r.createContext(path, safeHandler(ex -> sendResponse(ex, fn.apply(parseQueryParams(ex).get(p1)))));
    }

    private static void get2(ContextRegistrar r, String path, String p1, String p2, Ep.Fn2 fn) {
        r.createContext(path, safeHandler(ex -> {
            Map<String,String> q = parseQueryParams(ex);
            sendResponse(ex, fn.apply(q.get(p1), q.get(p2)));
        }));
    }

    private static void get3(ContextRegistrar r, String path, String p1, String p2, String p3, Ep.Fn3 fn) {
        r.createContext(path, safeHandler(ex -> {
            Map<String,String> q = parseQueryParams(ex);
            sendResponse(ex, fn.apply(q.get(p1), q.get(p2), q.get(p3)));
        }));
    }

    private static void get4(ContextRegistrar r, String path, String p1, String p2, String p3, String p4, Ep.Fn4 fn) {
        r.createContext(path, safeHandler(ex -> {
            Map<String,String> q = parseQueryParams(ex);
            sendResponse(ex, fn.apply(q.get(p1), q.get(p2), q.get(p3), q.get(p4)));
        }));
    }

    private static void getPageNP(ContextRegistrar r, String path, Ep.PageFn0 fn) {
        r.createContext(path, safeHandler(ex -> {
            Map<String,String> q = parseQueryParams(ex);
            sendResponse(ex, fn.apply(parseIntOrDefault(q.get("offset"),0), parseIntOrDefault(q.get("limit"),100)));
        }));
    }

    private static void getPage1NP(ContextRegistrar r, String path, String pName, Ep.PageFn1NP fn) {
        r.createContext(path, safeHandler(ex -> {
            Map<String,String> q = parseQueryParams(ex);
            sendResponse(ex, fn.apply(q.get(pName), parseIntOrDefault(q.get("offset"),0), parseIntOrDefault(q.get("limit"),100)));
        }));
    }

    private static void getWithQuery(ContextRegistrar r, String path, Ep.QueryHandler fn) {
        r.createContext(path, safeHandler(ex -> sendResponse(ex, fn.apply(parseQueryParams(ex)))));
    }

    private static void post1(ContextRegistrar r, String path, String p1, Ep.Fn1 fn) {
        r.createContext(path, safeHandler(ex -> sendResponse(ex, fn.apply(parsePostParams(ex).get(p1)))));
    }

    private static void post2(ContextRegistrar r, String path, String p1, String p2, Ep.Fn2 fn) {
        r.createContext(path, safeHandler(ex -> {
            Map<String,String> p = parsePostParams(ex);
            sendResponse(ex, fn.apply(p.get(p1), p.get(p2)));
        }));
    }

    private static void post3(ContextRegistrar r, String path, String p1, String p2, String p3, Ep.Fn3 fn) {
        r.createContext(path, safeHandler(ex -> {
            Map<String,String> p = parsePostParams(ex);
            sendResponse(ex, fn.apply(p.get(p1), p.get(p2), p.get(p3)));
        }));
    }

    private static void json1(ContextRegistrar r, String path, String p1, Ep.Fn1 fn) {
        r.createContext(path, safeHandler(ex -> sendResponse(ex, fn.apply((String) parseJsonParams(ex).get(p1)))));
    }

    private static void json2(ContextRegistrar r, String path, String p1, String p2, Ep.Fn2 fn) {
        r.createContext(path, safeHandler(ex -> {
            Map<String,Object> j = parseJsonParams(ex);
            sendResponse(ex, fn.apply((String) j.get(p1), (String) j.get(p2)));
        }));
    }

    private static void json3(ContextRegistrar r, String path, String p1, String p2, String p3, Ep.Fn3 fn) {
        r.createContext(path, safeHandler(ex -> {
            Map<String,Object> j = parseJsonParams(ex);
            sendResponse(ex, fn.apply((String) j.get(p1), (String) j.get(p2), (String) j.get(p3)));
        }));
    }

    private static void json4(ContextRegistrar r, String path, String p1, String p2, String p3, String p4, Ep.Fn4 fn) {
        r.createContext(path, safeHandler(ex -> {
            Map<String,Object> j = parseJsonParams(ex);
            sendResponse(ex, fn.apply((String) j.get(p1), (String) j.get(p2), (String) j.get(p3), (String) j.get(p4)));
        }));
    }

    private static void jsonPost(ContextRegistrar r, String path, Ep.JsonHandler fn) {
        r.createContext(path, safeHandler(ex -> sendResponse(ex, fn.apply(parseJsonParams(ex)))));
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
    private interface CheckedHandler { void handle(HttpExchange ex) throws Exception; }

    private static Consumer<HttpExchange> safeHandler(CheckedHandler handler) {
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
