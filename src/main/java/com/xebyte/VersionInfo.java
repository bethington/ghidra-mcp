package com.xebyte;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

/**
 * Version information loaded from properties file (populated by Maven during build).
 */
public class VersionInfo {
    private static String VERSION = "2.0.0";
    private static String APP_NAME = "GhidraMCP";
    private static String BUILD_TIMESTAMP = "dev";
    private static String BUILD_NUMBER = "0";
    private static final int ENDPOINT_COUNT = 133;

    static {
        try (InputStream input = VersionInfo.class
                .getResourceAsStream("/version.properties")) {
            if (input != null) {
                Properties props = new Properties();
                props.load(input);
                VERSION = props.getProperty("app.version", "2.0.0");
                APP_NAME = props.getProperty("app.name", "GhidraMCP");
                BUILD_TIMESTAMP = props.getProperty("build.timestamp", "dev");
                BUILD_NUMBER = props.getProperty("build.number", "0");
            }
        } catch (IOException e) {
            // Use defaults if file not found
        }
    }

    public static String getVersion() { return VERSION; }
    public static String getAppName() { return APP_NAME; }
    public static String getBuildTimestamp() { return BUILD_TIMESTAMP; }
    public static String getBuildNumber() { return BUILD_NUMBER; }
    public static int getEndpointCount() { return ENDPOINT_COUNT; }
    public static String getFullVersion() {
        return VERSION + " (build " + BUILD_NUMBER + ", " + BUILD_TIMESTAMP + ")";
    }
}
