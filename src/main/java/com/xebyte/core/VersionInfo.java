package com.xebyte.core;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

/**
 * Build identity, read from {@code version.properties} (filtered by the build).
 *
 * <p>Both servers report it. It used to be package-private in the GUI plugin, out of
 * the headless server's reach, so headless hard-coded its version with a "-headless"
 * suffix, which a version bump had to remember to rewrite.
 */
public final class VersionInfo {

    private static String version = "unknown";
    private static String appName = "GhidraMCP";
    private static String ghidraVersion = "unknown";
    private static String buildTimestamp = "dev";
    private static String buildNumber = "0";

    static {
        // Under the package path, not the classpath root: a root-level
        // version.properties from another Ghidra module resolved first (v5.4.2).
        try (InputStream input = VersionInfo.class.getResourceAsStream("/com/xebyte/version.properties")) {
            if (input != null) {
                Properties props = new Properties();
                props.load(input);
                version = props.getProperty("app.version", version);
                appName = props.getProperty("app.name", appName);
                ghidraVersion = props.getProperty("ghidra.version", ghidraVersion);
                buildTimestamp = props.getProperty("build.timestamp", buildTimestamp);
                buildNumber = props.getProperty("build.number", buildNumber);
            }
        } catch (IOException e) {
            // defaults above
        }
    }

    private VersionInfo() {}

    public static String getVersion() {
        return version;
    }

    public static String getAppName() {
        return appName;
    }

    public static String getGhidraVersion() {
        return ghidraVersion;
    }

    public static String getBuildTimestamp() {
        return buildTimestamp;
    }

    public static String getBuildNumber() {
        return buildNumber;
    }

    public static String getFullVersion() {
        return version + " (build " + buildNumber + ", " + buildTimestamp + ")";
    }
}
