package com.xebyte.core;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Centralized JSON serialization for HTTP responses and error payloads.
 * Single place for JSON format and escaping.
 */
public final class JsonHelper {

    private static final Gson GSON = new GsonBuilder().create();

    private JsonHelper() {}

    /** Serialize any object to JSON (lists, maps, primitives). */
    public static String toJson(Object o) {
        if (o == null) return "null";
        // Anonymous inner classes (new Object() { ... }) can't be reflectively accessed
        // by Gson in OSGi environments. Convert them to Maps first.
        if (isAnonymousObject(o)) {
            return GSON.toJson(anonymousToMap(o));
        }
        return GSON.toJson(o);
    }

    /** Check if an object is an anonymous class extending Object directly. */
    private static boolean isAnonymousObject(Object o) {
        Class<?> clazz = o.getClass();
        return clazz.isAnonymousClass() && clazz.getSuperclass() == Object.class;
    }

    /** Reflect an anonymous Object's declared fields into a LinkedHashMap. */
    private static Map<String, Object> anonymousToMap(Object o) {
        Map<String, Object> map = new LinkedHashMap<>();
        for (Field f : o.getClass().getDeclaredFields()) {
            if (f.isSynthetic()) continue;  // Skip compiler-generated fields (this$0 etc.)
            try {
                f.setAccessible(true);
                map.put(f.getName(), f.get(o));
            } catch (Exception ignored) {}
        }
        return map;
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
