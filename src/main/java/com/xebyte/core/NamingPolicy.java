package com.xebyte.core;

/**
 * Runtime policy for naming-convention enforcement.
 *
 * <p>The default is intentionally strict to preserve the v5.6.0 behavior:
 * rename endpoints reject low-quality function/global names before mutating
 * the program. GUI users can disable the hard reject layer through Tool
 * Options when the built-in heuristic does not match their naming convention.
 * Warning-only validation still runs in that mode.
 */
public final class NamingPolicy {

    private static final NamingPolicy INSTANCE = new NamingPolicy();
    private static final boolean DEFAULT_STRICT_NAMING_ENFORCEMENT = true;

    private volatile boolean strictNamingEnforcement;
    private volatile String source;

    private NamingPolicy() {
        this.strictNamingEnforcement = DEFAULT_STRICT_NAMING_ENFORCEMENT;
        this.source = "default";
    }

    public static NamingPolicy getInstance() {
        return INSTANCE;
    }

    public static boolean defaultStrictNamingEnforcement() {
        return DEFAULT_STRICT_NAMING_ENFORCEMENT;
    }

    public synchronized void setStrictNamingEnforcement(boolean strictNamingEnforcement, String source) {
        this.strictNamingEnforcement = strictNamingEnforcement;
        this.source = source != null && !source.isBlank() ? source : "runtime";
    }

    public boolean isStrictNamingEnforcement() {
        return strictNamingEnforcement;
    }

    public String getSource() {
        return source;
    }

}
