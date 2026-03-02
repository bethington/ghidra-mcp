package com.xebyte.core;

/**
 * Type-safe response from service methods.
 * Replaces raw String returns with structured data.
 *
 * Ok   - success, data serialized via Gson
 * Err  - error, rendered as {"error": "message"}
 * Text - raw text passthrough (for plain-text/paginated endpoints)
 */
public sealed interface Response permits Response.Ok, Response.Err, Response.Text {

    /** Serialize this response to a JSON/text string for HTTP output. */
    String toJson();

    /** Success response with structured data (serialized via Gson). */
    record Ok(Object data) implements Response {
        @Override
        public String toJson() {
            return JsonHelper.toJson(data);
        }
    }

    /** Error response: {"error": "message"}. */
    record Err(String message) implements Response {
        @Override
        public String toJson() {
            return JsonHelper.errorJson(message);
        }
    }

    /** Raw text passthrough (for plain-text, paginated lists, pre-formatted JSON). */
    record Text(String content) implements Response {
        @Override
        public String toJson() {
            return content;
        }
    }

    // Factory methods
    static Response ok(Object data) { return new Ok(data); }
    static Response err(String message) { return new Err(message); }
    static Response text(String content) { return new Text(content); }
}
