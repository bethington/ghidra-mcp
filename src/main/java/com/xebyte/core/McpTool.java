package com.xebyte.core;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marks a service method as an MCP tool endpoint.
 * At startup, reflection scans for this annotation to build both
 * HTTP dispatch and the /mcp/schema JSON for the Python bridge.
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.METHOD)
public @interface McpTool {
    /** HTTP path, e.g. "/rename_function". */
    String value();
    /** Tool description for MCP schema (shown to AI). */
    String description();
    /** HTTP method. */
    Method method() default Method.GET;

    enum Method { GET, POST }
}
