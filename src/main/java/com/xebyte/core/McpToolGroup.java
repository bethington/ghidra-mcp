package com.xebyte.core;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Declares the MCP tool group for all @McpTool methods in a service class.
 * Used by the bridge to support on-demand group loading.
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
public @interface McpToolGroup {
    /** Group name (e.g. "function", "datatype"). */
    String value();
}
