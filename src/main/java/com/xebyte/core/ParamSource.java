package com.xebyte.core;

/**
 * Specifies where an HTTP parameter value is extracted from.
 *
 * @since 4.3.0
 */
public enum ParamSource {

    /** Extract from URL query string ({@code ?key=value&...}). */
    QUERY,

    /** Extract from JSON request body. */
    BODY
}
