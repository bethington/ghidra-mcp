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

    /** {@link #paramType()} for a parameter that is only ever a memory address. */
    String ADDRESS = "address";

    /**
     * {@link #paramType()} for a parameter that names a function by name OR by address.
     * Resolved by {@code ServiceUtils.getFunctionOrError}. It implies the standard alias
     * spellings ({@code address}, {@code name}, {@code function_address},
     * {@code function_name}, {@code function}, minus the parameter's own name), so no
     * endpoint lists them. Aliases declared explicitly are tried first.
     */
    String FUNCTION_REF = "function_ref";

    /**
     * Semantic type hint for this parameter, propagated to /mcp/schema.
     * {@link #ADDRESS} marks parameters that carry memory addresses, which the bridge
     * normalises before dispatch. {@link #FUNCTION_REF} marks name-or-address function
     * references, which the bridge passes through untouched: a name is not an address,
     * and rewriting it (the bridge once prefixed "0x") makes the function unfindable.
     */
    String paramType() default "";

    /**
     * Alternative names for this parameter. The canonical name ({@link #value()}) is advertised
     * in /mcp/schema and should be preferred by new callers. At runtime, the parameter resolver
     * accepts any alias listed here as an alternative spelling, enabling backward compatibility
     * when standardizing inconsistent parameter names across endpoints.
     *
     * <p>Example: {@code @Param(value="function_address", aliases={"address"})}
     * will accept both {@code function_address=} and {@code address=} in HTTP requests.
     *
     * <p>Resolution order:
     * <ol>
     *   <li>Canonical name ({@link #value()})</li>
     *   <li>Aliases in declaration order</li>
     *   <li>Default value (if defined) or null</li>
     * </ol>
     */
    String[] aliases() default {};

    /**
     * Whether an empty string is a meaningful value for this parameter.
     *
     * <p>The MCP bridge drops {@code ""} arguments by default, because some
     * clients send every schema default on every call and an empty selector
     * would otherwise be treated as "present but blank" and rejected.
     *
     * <p>That default is wrong for parameters where empty <em>is</em> the
     * intent — clearing a comment is the motivating case: {@code set_comment}
     * with {@code comment: ""} means "remove it", but the argument was being
     * dropped before it reached Java, so the tool answered "Comment text is
     * required" and clearing was unreachable through MCP.
     *
     * <p>Set this to {@code true} only where empty carries meaning, and make
     * sure the handler distinguishes empty from absent.
     */
    boolean allowEmpty() default false;
}
