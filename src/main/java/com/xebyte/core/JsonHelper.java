package com.xebyte.core;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Gson-backed JSON utilities replacing hand-built StringBuilder JSON.
 * Thread-safe: Gson instances are immutable and reusable across threads.
 */
public final class JsonHelper {

    private static final Gson GSON = new GsonBuilder()
            .disableHtmlEscaping()
            .create();

    private JsonHelper() {}

    /** Serialize any object to JSON string. */
    public static String toJson(Object obj) {
        return GSON.toJson(obj);
    }

    /** Build a LinkedHashMap from alternating key-value pairs (preserves field order). */
    public static Map<String, Object> mapOf(Object... kvPairs) {
        if (kvPairs.length % 2 != 0) {
            throw new IllegalArgumentException("mapOf requires even number of arguments");
        }
        Map<String, Object> map = new LinkedHashMap<>();
        for (int i = 0; i < kvPairs.length; i += 2) {
            map.put(String.valueOf(kvPairs[i]), kvPairs[i + 1]);
        }
        return map;
    }

    /** Create a standard error JSON response: {"error": "message"} */
    public static String errorJson(String message) {
        return GSON.toJson(Map.of("error", message != null ? message : "Unknown error"));
    }

    /** Parse JSON from an InputStream (for HTTP request bodies). */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> parseBody(InputStream input) {
        try (InputStreamReader reader = new InputStreamReader(input, StandardCharsets.UTF_8)) {
            Map<String, Object> result = GSON.fromJson(reader, LinkedHashMap.class);
            return result != null ? result : new LinkedHashMap<>();
        } catch (Exception e) {
            return new LinkedHashMap<>();
        }
    }

    /** Parse a JSON string into a Map. */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> parseJson(String json) {
        try {
            Map<String, Object> result = GSON.fromJson(json, LinkedHashMap.class);
            return result != null ? result : new LinkedHashMap<>();
        } catch (Exception e) {
            return new LinkedHashMap<>();
        }
    }

    /**
     * Safely extract an int from a parsed JSON map value.
     * Gson parses JSON numbers as Double by default; this handles Double, Integer, Long, and String.
     */
    public static int getInt(Object obj, int defaultValue) {
        if (obj instanceof Number n) return n.intValue();
        if (obj instanceof String s) {
            try { return Integer.parseInt(s); } catch (NumberFormatException e) { return defaultValue; }
        }
        return defaultValue;
    }

    /**
     * Convert parsed JSON list of objects to List<Map<String, String>> for legacy callers.
     * Gson returns nested objects as LinkedTreeMap<String, Object>; this converts values to strings.
     */
    public static java.util.List<Map<String, String>> toMapStringList(Object obj) {
        if (!(obj instanceof java.util.List<?> list)) return null;
        java.util.List<Map<String, String>> result = new java.util.ArrayList<>();
        for (Object item : list) {
            if (item instanceof Map<?, ?> map) {
                Map<String, String> strMap = new LinkedHashMap<>();
                map.forEach((k, v) -> strMap.put(String.valueOf(k), v != null ? String.valueOf(v) : null));
                result.add(strMap);
            }
        }
        return result;
    }

    /**
     * Convert a parsed JSON array element to List<Map<String, String>>.
     */
    public static List<Map<String, String>> toMapStringList(JsonElement jsonElement) {
        if (jsonElement == null || !jsonElement.isJsonArray()) return null;
        List<Map<String, String>> result = new ArrayList<>();
        for (JsonElement item : jsonElement.getAsJsonArray()) {
            if (item != null && item.isJsonObject()) {
                Map<String, Object> rawMap = GSON.fromJson(item, LinkedHashMap.class);
                Map<String, String> strMap = new LinkedHashMap<>();
                rawMap.forEach((k, v) -> strMap.put(String.valueOf(k), v != null ? String.valueOf(v) : null));
                result.add(strMap);
            }
        }
        return result;
    }
}
