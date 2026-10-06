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

    /** The server's environment, read through each key's derived variable name. Read-only. */
    static ScopeStore env(Map<String, String> env) {
        return new ScopeStore() {
            @Override
            public Optional<String> read(SettingKey key) {
                return Optional.ofNullable(env.get(key.envName()));
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
