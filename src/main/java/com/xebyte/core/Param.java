package com.xebyte.core;

import java.lang.annotation.*;

/**
 * Declares HTTP parameter binding for an MCP tool method parameter.
 * Used by {@link AnnotationScanner} to extract and convert HTTP request
 * parameters to Java method arguments.
 *
 * <p>Type conversion is automatic based on the Java parameter type:
 * <ul>
 *   <li>{@code String} — raw string value</li>
 *   <li>{@code int} / {@code Integer} — parsed integer (Integer is nullable)</li>
 *   <li>{@code long} — parsed long</li>
 *   <li>{@code boolean} / {@code Boolean} — parsed boolean (Boolean is nullable)</li>
 *   <li>{@code double} — parsed double</li>
 *   <li>{@code Map<String,String>} — parsed string map from body</li>
 *   <li>{@code List<Map<String,String>>} — parsed map list from body</li>
 *   <li>{@code Object} — raw body value (no conversion)</li>
 * </ul>
 *
 * @since 4.3.0
 */
@Target(ElementType.PARAMETER)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface Param {

    /** No-default sentinel value. Parameters without defaults use this internally. */
    String NO_DEFAULT = "\0NONE";

    /** Parameter name as it appears in the HTTP query string or JSON body. */
    String value();

    /** Where the parameter comes from: query string or JSON body. */
    ParamSource source() default ParamSource.QUERY;

    /**
     * Default value as a string. Use for optional parameters.
     * Leave as default ({@link #NO_DEFAULT}) for required parameters.
     * Parsed according to the Java parameter type.
     */
    String defaultValue() default "\0NONE";

    /**
     * When true, the body value is serialized to a JSON string representation.
     * Handles String pass-through, List serialization, and Map serialization.
     * Only applicable when {@code source = BODY} and Java type is {@code String}.
     */
    boolean fieldsJson() default false;

    /** Human-readable description of this parameter. */
    String description() default "";
}
