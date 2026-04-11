package com.xebyte.core;

import java.lang.annotation.*;

/**
 * Marks a service method as an MCP tool endpoint.
 * Used by {@link AnnotationScanner} to discover endpoints via reflection
 * and generate JSON schemas for dynamic tool discovery.
 *
 * <p>Example:
 * <pre>{@code
 * @McpTool(path = "/list_methods", method = "GET",
 *          description = "List all function names with pagination")
 * public Response getAllFunctionNames(
 *     @Param(value = "offset", defaultValue = "0") int offset,
 *     @Param(value = "limit", defaultValue = "100") int limit,
 *     @Param("program") String programName) { ... }
 * }</pre>
 *
 * @since 4.3.0
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface McpTool {

    /** HTTP path for this endpoint (e.g., "/list_methods"). */
    String path();

    /** HTTP method: "GET" or "POST". */
    String method() default "GET";

    /** Human-readable description of what this tool does. */
    String description() default "";

    /** Tool category for grouping (e.g., "listing", "function", "analysis"). */
    String category() default "";

    /**
     * Whether this endpoint should be exposed via /mcp/schema as part of the
     * documented MCP tool surface.
     */
    boolean documented() default true;
}
