package com.xebyte.core;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Annotates a service method parameter with its HTTP/MCP name and metadata.
 * Used by {@link AnnotationScanner} to build JSON Schema for MCP tools
 * and to extract parameters from HTTP requests.
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.PARAMETER)
public @interface Param {
    /** Parameter name as seen by HTTP query/body and MCP schema. */
    String value();
    /** Description for MCP schema (shown to AI). */
    String description() default "";
    /** JSON Schema type: string, integer, boolean, number, array, object. */
    String type() default "string";
    /** Whether the parameter is required. */
    boolean required() default true;
    /** Default value (empty = no default). */
    String defaultValue() default "";
}
