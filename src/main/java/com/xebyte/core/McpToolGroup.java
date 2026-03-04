package com.xebyte.core;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Class-level annotation that assigns all {@link McpTool} methods in a service
 * to a named tool group (category). Used by the bridge to support lazy loading:
 * only core tools are registered on connect; the rest are loaded on demand via
 * {@code load_tool_group("function")}.
 *
 * <p>If not present, the category defaults to the class name with "Service"
 * stripped and lowercased (e.g., {@code FunctionService} → {@code "function"}).
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
public @interface McpToolGroup {
    /** The group/category name (e.g. "function", "listing", "comment"). */
    String value();

    /** Short description of what tools in this group do (shown to AI agents). */
    String description() default "";
}
