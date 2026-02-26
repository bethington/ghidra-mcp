package com.xebyte.core;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * Centralized JSON serialization for HTTP responses and error payloads.
 * Single place for JSON format and escaping.
 */
public final class JsonHelper {

    private static final Gson GSON = new GsonBuilder().create();

    private JsonHelper() {}

    /** Expose the shared Gson instance for toJsonTree() etc. */
    public static Gson gson() {
        return GSON;
    }

    /** Serialize any object to JSON (lists, maps, primitives, JsonElements). */
    public static String toJson(Object o) {
        return GSON.toJson(o);
    }

    /** Parse a JSON object from a request body InputStream. Returns empty map for blank input. */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> parseBody(InputStream body) throws IOException {
        String s = new String(body.readAllBytes(), StandardCharsets.UTF_8);
        if (s.isBlank()) return new HashMap<>();
        Map<String, Object> m = GSON.fromJson(s, Map.class);
        return m != null ? m : new HashMap<>();
    }

    /** Build a JSON object with a single "error" key. Used by safeHandler and validation. */
    public static String errorJson(String message) {
        return GSON.toJson(Collections.singletonMap("error", message != null ? message : "Unknown error"));
    }
}
