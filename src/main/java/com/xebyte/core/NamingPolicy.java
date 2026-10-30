package com.xebyte.core;

import com.xebyte.core.settings.SettingKey;
import ghidra.program.model.listing.Program;

/**
 * Runtime policy for naming-convention enforcement.
 *
 * <p>The active {@link ConventionConfig} is built from {@code naming.*}
 * settings for the program the current request acts on (see
 * {@link ServiceUtils#peekResolvedProgram()}), memoized until settings
 * change or the program changes. Tests may pin a config with
 * {@link #setConfig(ConventionConfig, String)}.
 */
public final class NamingPolicy {

    private static final NamingPolicy INSTANCE = new NamingPolicy();
    private static final boolean DEFAULT_STRICT_NAMING_ENFORCEMENT = true;

    private volatile SettingsService settingsService;
    private volatile ConventionConfig testOverride;
    private volatile String testSource = "default";

    /** The last built config and what it was built for, replaced as one unit. */
    private record Built(long generation, String programKey, ConventionConfig config) {}

    private volatile Built built = new Built(-1, "", ConventionConfig.defaults());

    /**
     * Per-request mode override set by an MCP endpoint that accepts a
     * {@code strict_mode} query parameter. Cleared in a finally block by
     * the entrypoint so it never leaks across requests.
     */
    private final ThreadLocal<ConventionConfig.Mode> requestOverride =
            new ThreadLocal<>();

    private NamingPolicy() {}

    public static NamingPolicy getInstance() {
        return INSTANCE;
    }

    public static boolean defaultStrictNamingEnforcement() {
        return DEFAULT_STRICT_NAMING_ENFORCEMENT;
    }

    /** Resolve settings through {@code settings} (both servers call this at startup). */
    public void useSettings(SettingsService settings) {
        this.settingsService = settings;
        invalidateCache();
    }

    /** Active config for the current request's program — never null. */
    public ConventionConfig getConfig() {
        if (testOverride != null) {
            return testOverride;
        }
        SettingsService settings = settingsService;
        if (settings == null) {
            return built.config();
        }
        Program program = ServiceUtils.peekResolvedProgram();
        String programKey = programKey(program);
        long generation = settings.settingsGeneration();
        Built last = built;
        if (last.generation() == generation && last.programKey().equals(programKey)) {
            return last.config();
        }
        Built fresh = new Built(generation, programKey,
            ConventionConfig.fromSettings(key -> settings.value(key, program)));
        built = fresh;
        return fresh.config();
    }

    /**
     * Replace the active config for tests. Pass {@code null} config to clear
     * the override and return to settings-backed resolution.
     */
    public synchronized void setConfig(ConventionConfig newConfig, String source) {
        if (newConfig == null) {
            testOverride = null;
            invalidateCache();
        } else {
            testOverride = newConfig;
        }
        this.testSource = source != null && !source.isBlank() ? source : "runtime";
    }

    public boolean isStrictNamingEnforcement() {
        return getEffectiveMode() == ConventionConfig.Mode.ENFORCE;
    }

    /**
     * The mode that applies to the current request: the thread-local
     * override if one is set, otherwise the resolved config mode.
     */
    public ConventionConfig.Mode getEffectiveMode() {
        ConventionConfig.Mode override = requestOverride.get();
        return override != null ? override : getConfig().getMode();
    }

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
     * Per-call strict-mode override. When {@code naming.override} is {@code deny},
     * lowering strictness below the resolved {@code naming.mode} refuses the call.
     */
    public AutoCloseable scopedRequestMode(String strictMode) {
        ConventionConfig.Mode mode = ConventionConfig.Mode.parse(strictMode, null);
        if (mode == null) {
            return () -> {};
        }
        ConventionConfig config = getConfig();
        ConventionConfig.Mode baseMode = config.getMode();
        if (rank(mode) < rank(baseMode) && namingOverrideDenies()) {
            throw new Refusal("strict_mode=" + mode.wireName()
                + " is below this project's naming mode (" + baseMode.wireName() + ").");
        }
        setRequestModeOverride(mode);
        return this::clearRequestModeOverride;
    }

    /**
     * Whether write endpoints should rewrite struct field names to match the
     * built-in Hungarian-prefix convention.
     */
    public boolean shouldAutoFixStructFieldPrefixes() {
        if (!getConfig().isStrict()) {
            return false;
        }
        return getConfig().hungarian().autoFixStructFields();
    }

    public String getSource() {
        return testOverride != null ? testSource : (settingsService != null ? "settings" : "default");
    }

    private void invalidateCache() {
        built = new Built(-1, "", ConventionConfig.defaults());
    }

    private static String programKey(Program program) {
        if (program == null || program.getDomainFile() == null) {
            return "";
        }
        return program.getDomainFile().getPathname();
    }

    private boolean namingOverrideDenies() {
        if (settingsService == null) {
            return false;
        }
        Program program = ServiceUtils.peekResolvedProgram();
        Object raw = settingsService.value("naming.override", program);
        return raw instanceof String s && "deny".equalsIgnoreCase(s.trim());
    }

    private static int rank(ConventionConfig.Mode mode) {
        return SettingKey.namingModeRank(mode.wireName());
    }
}
