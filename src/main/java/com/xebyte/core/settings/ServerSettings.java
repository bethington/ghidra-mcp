package com.xebyte.core.settings;

import java.util.Map;

/**
 * The server scope: the process environment over the standard {@code .env} files, read once.
 * Values that only the operator sets come from here; the per-call resolution of every other
 * scope goes through {@code SettingsService}.
 */
public final class ServerSettings {

    private static volatile ScopeStore store = live();

    private ServerSettings() {}

    private static ScopeStore live() {
        return ScopeStore.server(System.getenv(), DotEnv.loadStandard());
    }

    public static ScopeStore store() {
        return store;
    }

    /** Hermetic tests: replace what {@link #value(String)} reads. */
    public static void useForTests(Map<String, String> env, Map<String, String> dotenv) {
        store = ScopeStore.server(env, dotenv);
    }

    /** Back to the live environment after a test. */
    public static void resetForTests() {
        store = live();
    }

    public static Object value(String key) {
        return SettingsResolver.resolve(SettingsRegistry.DEFAULT.get(key), Map.of(Scope.SERVER, store)).value();
    }

    public static String string(String key) {
        return (String) value(key);
    }

    public static long intValue(String key) {
        return (Long) value(key);
    }
}
