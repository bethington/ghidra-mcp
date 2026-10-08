package com.xebyte.core.settings;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/** The raw values one scope holds. */
public interface ScopeStore {

    Optional<String> read(SettingKey key);

    /** Store a raw value; refuses with a {@link SettingRefusedException} if this scope is read-only. */
    void write(SettingKey key, String raw);

    void remove(SettingKey key);

    /**
     * The server scope: each key's derived variable in the process environment, else in the
     * {@code .env} files. Read-only.
     */
    static ScopeStore server(Map<String, String> processEnv, Map<String, String> dotEnv) {
        return new ScopeStore() {
            @Override
            public Optional<String> read(SettingKey key) {
                String name = key.envName();
                String v = processEnv.get(name);
                if (v != null) {
                    return Optional.of(v);
                }
                return Optional.ofNullable(dotEnv.get(name));
            }

            @Override
            public void write(SettingKey key, String raw) {
                throw new SettingRefusedException(
                    key.key() + "'s server value is fixed for the life of this server process.");
            }

            @Override
            public void remove(SettingKey key) {
                write(key, null);
            }
        };
    }

    /** Values held in memory: tests, and a call's own arguments. */
    static ScopeStore memory(Map<String, String> initial) {
        Map<String, String> values = new ConcurrentHashMap<>(initial);
        return new ScopeStore() {
            @Override
            public Optional<String> read(SettingKey key) {
                return Optional.ofNullable(values.get(key.key()));
            }

            @Override
            public void write(SettingKey key, String raw) {
                values.put(key.key(), raw);
            }

            @Override
            public void remove(SettingKey key) {
                values.remove(key.key());
            }
        };
    }
}
