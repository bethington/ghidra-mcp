package com.xebyte.core;

/**
 * Runtime policy for naming-convention enforcement.
 *
 * <p>The default is intentionally strict to preserve the v5.6.0 behavior:
 * {@code rename_function_by_address} rejects low-quality function names before
 * mutating the program. GUI users can disable the hard reject layer through
 * Tool Options when the built-in heuristic does not match their naming
 * convention. Warning-only validation still runs in that mode.
 */
public final class NamingPolicy {

    private static final NamingPolicy INSTANCE = new NamingPolicy();
    private static final boolean DEFAULT_STRICT_FUNCTION_NAMES = true;

    private volatile boolean strictFunctionNames;
    private volatile String source;

    private NamingPolicy() {
        this.strictFunctionNames = DEFAULT_STRICT_FUNCTION_NAMES;
        this.source = "default";
    }

    public static NamingPolicy getInstance() {
        return INSTANCE;
    }

    public static boolean defaultStrictFunctionNames() {
        return DEFAULT_STRICT_FUNCTION_NAMES;
    }

    public synchronized void setStrictFunctionNames(boolean strictFunctionNames, String source) {
        this.strictFunctionNames = strictFunctionNames;
        this.source = source != null && !source.isBlank() ? source : "runtime";
    }

    public boolean isStrictFunctionNames() {
        return strictFunctionNames;
    }

    public String getSource() {
        return source;
    }

}
