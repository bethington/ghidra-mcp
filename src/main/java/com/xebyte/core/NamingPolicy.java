package com.xebyte.core;

import java.nio.file.Path;

/**
 * Runtime policy for naming-convention enforcement.
 *
 * <p>The default is intentionally strict to preserve the v5.6.0 behavior:
 * rename endpoints reject low-quality function/global names before mutating
 * the program. GUI users can disable the hard reject layer through Tool
 * Options when the built-in heuristic does not match their naming convention.
 * Warning-only validation still runs in that mode.
 *
 * <p>v5.11.2 expansion: the policy now carries a full {@link ConventionConfig}
 * loaded from {@code .ghidra-mcp/conventions.json} in the Ghidra project
 * root (see {@link ConventionConfigLoader}). The {@code strictNamingEnforcement}
 * boolean is now a derived view of that config's mode — kept for backward
 * compatibility with the existing call sites and the Ghidra Tool Option
 * checkbox. The boolean setter overrides the config mode so the GUI toggle
 * still works even when a project ships its own config file.
 */
public final class NamingPolicy {

    private static final NamingPolicy INSTANCE = new NamingPolicy();
    private static final boolean DEFAULT_STRICT_NAMING_ENFORCEMENT = true;

    private volatile ConventionConfig config;
    private volatile String source;

    /**
     * Per-request mode override set by an MCP endpoint that accepts a
     * {@code strict_mode} query parameter. Threads that didn't set an
     * override see the global config mode. Cleared in a finally block by
     * the entrypoint so it never leaks across requests.
     */
    private final ThreadLocal<ConventionConfig.Mode> requestOverride =
            new ThreadLocal<>();

    private NamingPolicy() {
        this.config = ConventionConfig.defaults();
        this.source = "default";
    }

    public static NamingPolicy getInstance() {
        return INSTANCE;
    }

    public static boolean defaultStrictNamingEnforcement() {
        return DEFAULT_STRICT_NAMING_ENFORCEMENT;
    }

    /** Active config — never null. */
    public ConventionConfig getConfig() {
        return config;
    }

    /**
     * Replace the active config wholesale. Used by the loader at startup and
     * by the Ghidra Tool Option listener; tests can call it directly to
     * sandbox a config.
     */
    public synchronized void setConfig(ConventionConfig newConfig, String source) {
        this.config = newConfig != null ? newConfig : ConventionConfig.defaults();
        this.source = source != null && !source.isBlank() ? source : "runtime";
    }

    /**
     * Convenience: keep the legacy boolean setter working for the existing
     * Ghidra Tool Option. Flipping the boolean preserves all other config
     * sections — only the mode changes.
     */
    public synchronized void setStrictNamingEnforcement(boolean strictNamingEnforcement, String source) {
        ConventionConfig current = this.config;
        ConventionConfig.Mode mode = strictNamingEnforcement
                ? ConventionConfig.Mode.ENFORCE
                : ConventionConfig.Mode.WARN;
        this.config = new ConventionConfig(
                mode,
                current.functionNaming(),
                current.hungarian(),
                current.globalNaming(),
                current.plateComments()
        );
        this.source = source != null && !source.isBlank() ? source : "runtime";
    }

    public boolean isStrictNamingEnforcement() {
        return getEffectiveMode() == ConventionConfig.Mode.ENFORCE;
    }

    /**
     * The mode that applies to the current request: the thread-local
     * override if one is set, otherwise the global config mode. Validators
     * call this through {@link #isStrictNamingEnforcement()}; entrypoints
     * that want to introspect the override directly can use this.
     */
    public ConventionConfig.Mode getEffectiveMode() {
        ConventionConfig.Mode override = requestOverride.get();
        return override != null ? override : config.getMode();
    }

    /**
     * Override the active mode for the duration of the current request.
     * The caller MUST clear the override in a finally block — see
     * {@link #clearRequestModeOverride()} — or the override leaks to the
     * next request handled by the same HTTP thread.
     */
    public void setRequestModeOverride(ConventionConfig.Mode mode) {
        if (mode == null) {
            requestOverride.remove();
        } else {
            requestOverride.set(mode);
        }
    }

    /** Clear any thread-local mode override. Idempotent. */
    public void clearRequestModeOverride() {
        requestOverride.remove();
    }

    /**
     * Try-with-resources helper for per-call strict-mode overrides.
     *
     * <p>Endpoints that accept a {@code strict_mode} query parameter wrap
     * their body in {@code try (var ignored = NamingPolicy.getInstance()
     * .scopedRequestMode(strictModeArg)) { ... }}. When {@code strictMode}
     * is null/blank/unrecognized, the helper is a no-op and the call sees
     * the global config. When set, the override is pinned on this thread
     * for the duration of the try block and cleared on close — even if
     * the body throws.
     */
    public AutoCloseable scopedRequestMode(String strictMode) {
        ConventionConfig.Mode mode = ConventionConfig.Mode.parse(strictMode, null);
        if (mode == null) {
            return () -> {}; // no-op
        }
        setRequestModeOverride(mode);
        return this::clearRequestModeOverride;
    }

    /**
     * Whether write endpoints should rewrite struct field names to match the
     * built-in Hungarian-prefix convention.
     *
     * <p>This intentionally follows the strict naming option: users who disable
     * the built-in convention should be able to preserve names chosen by their
     * agent, including snake_case fields.
     */
    public boolean shouldAutoFixStructFieldPrefixes() {
        if (!config.isStrict()) return false;
        return config.hungarian().autoFixStructFields();
    }

    public String getSource() {
        return source;
    }

    /**
     * Load {@code .ghidra-mcp/conventions.json} from {@code projectRoot} and
     * replace the active config with the result. Falls back to defaults if
     * the file is missing or malformed; the returned LoadResult carries any
     * error message so the caller can surface it via Msg.warn.
     */
    public ConventionConfigLoader.LoadResult refreshFromProjectRoot(Path projectRoot) {
        ConventionConfigLoader.LoadResult result =
                ConventionConfigLoader.loadFromProjectRoot(projectRoot);
        String src = result.resolvedFrom() != null
                ? "project:" + result.resolvedFrom()
                : "default";
        setConfig(result.config(), src);
        return result;
    }
}
