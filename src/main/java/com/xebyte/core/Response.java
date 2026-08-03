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

    /**
     * Success response for a write with no structured payload:
     * {@code {"status": "success", "message": "..."}}.
     *
     * <p>Write tools used to return a bare English sentence, which made a
     * successful write indistinguishable from an error at the type level and
     * forced callers to pattern-match prose. See
     * {@code docs/project-management/MCP_RESPONSE_CONTRACT.md}.
     */
    static Response success(String message) {
        java.util.Map<String, Object> out = new java.util.LinkedHashMap<>();
        out.put("status", "success");
        out.put("message", message);
        return new Ok(out);
    }

    /**
     * Raw passthrough. Reserved for content that is <em>already</em> serialized
     * JSON.
     *
     * @deprecated Never use this for human-formatted text -- that violates the
     *     response contract, and it is the mechanism by which 33 tools drifted
     *     away from it before 7.0.0. Use {@link #ok}, {@link #success}, or
     *     {@link #err}.
     */
    @Deprecated
    static Response text(String content) { return new Text(content); }
}
