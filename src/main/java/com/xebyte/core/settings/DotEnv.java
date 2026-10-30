package com.xebyte.core.settings;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;

/** {@code NAME=value} files; {@code #} comments, optional quotes around a value. */
public final class DotEnv {

    private DotEnv() {}

    /** {@code user.dir/.env} then {@code user.home/.env}; first file wins per name. */
    public static Map<String, String> loadStandard() {
        Map<String, String> out = new HashMap<>();
        loadInto(Paths.get(System.getProperty("user.dir"), ".env"), out);
        loadInto(Paths.get(System.getProperty("user.home"), ".env"), out);
        return out;
    }

    /** Parse one file into {@code out}; existing entries are not overwritten. */
    public static void loadInto(Path path, Map<String, String> out) {
        try {
            if (!Files.exists(path) || !Files.isRegularFile(path)) {
                return;
            }
            for (String line : Files.readAllLines(path)) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#")) {
                    continue;
                }
                int eq = line.indexOf('=');
                if (eq <= 0) {
                    continue;
                }
                String key = line.substring(0, eq).trim();
                String value = line.substring(eq + 1).trim();
                if (value.length() >= 2
                        && ((value.startsWith("\"") && value.endsWith("\""))
                            || (value.startsWith("'") && value.endsWith("'")))) {
                    value = value.substring(1, value.length() - 1);
                }
                out.putIfAbsent(key, value);
            }
        } catch (IOException ignored) {
            // unreadable file — skip
        }
    }
}
