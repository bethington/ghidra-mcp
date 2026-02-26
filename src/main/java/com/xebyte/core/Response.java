package com.xebyte.core;

/**
 * Sealed response type for all endpoint handlers.
 * Provides type-safe distinction between success data, errors, and raw text.
 */
public sealed interface Response {
    /** Structured data — will be serialized to JSON via Gson. */
    record Ok(Object data) implements Response {}
    /** Error message — serialized as {"error": "..."}. */
    record Err(String message) implements Response {}
    /** Raw text — passed through as-is (DOT graphs, hex dumps, newline-delimited lists). */
    record Text(String content) implements Response {}

    /** Convenience factory for Ok responses. */
    static Ok ok(Object data) { return new Ok(data); }
    /** Convenience factory for Err responses. */
    static Err err(String message) { return new Err(message != null ? message : "Unknown error"); }
    /** Convenience factory for Text responses. */
    static Text text(String content) { return new Text(content); }
}
