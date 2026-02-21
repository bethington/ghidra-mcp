/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.xebyte.headless;

import ghidra.framework.client.ClientUtil;
import ghidra.framework.client.RepositoryAdapter;
import ghidra.framework.client.RepositoryServerAdapter;

import java.io.IOException;

/**
 * Manages connections to a shared Ghidra repository server.
 *
 * Provides connectivity to a Ghidra server for centralized analysis storage
 * and team collaboration. Configuration is driven by environment variables:
 *
 * <ul>
 *   <li>GHIDRA_SERVER_HOST - Server hostname (default: localhost)</li>
 *   <li>GHIDRA_SERVER_PORT - Server port (default: 13100)</li>
 *   <li>GHIDRA_SERVER_USER - Service account username (optional)</li>
 * </ul>
 */
public class GhidraServerManager {

    private static final String DEFAULT_HOST = "localhost";
    private static final int DEFAULT_PORT = 13100;

    private final String host;
    private final int port;
    private final String user;

    private RepositoryServerAdapter serverAdapter;
    private volatile boolean connected = false;
    private String lastError;

    public GhidraServerManager() {
        this.host = getEnvOrDefault("GHIDRA_SERVER_HOST", DEFAULT_HOST);
        this.port = parsePort(System.getenv("GHIDRA_SERVER_PORT"), DEFAULT_PORT);
        this.user = System.getenv("GHIDRA_SERVER_USER");
    }

    public GhidraServerManager(String host, int port, String user) {
        this.host = (host != null && !host.isEmpty()) ? host : DEFAULT_HOST;
        this.port = port > 0 ? port : DEFAULT_PORT;
        this.user = user;
    }

    /**
     * Connect to the configured Ghidra server.
     *
     * @return JSON string with connection result
     */
    public synchronized String connect() {
        if (connected && serverAdapter != null && serverAdapter.isConnected()) {
            return "{\"status\": \"already_connected\", \"host\": \"" + escapeJson(host)
                    + "\", \"port\": " + port + "}";
        }

        try {
            serverAdapter = ClientUtil.getRepositoryServer(host, port);
            serverAdapter.connect();
            connected = serverAdapter.isConnected();
            lastError = null;

            if (connected) {
                System.out.println("Connected to Ghidra server at " + host + ":" + port);
                return "{\"status\": \"connected\", \"host\": \"" + escapeJson(host)
                        + "\", \"port\": " + port + "}";
            } else {
                lastError = "Connection returned but server reports not connected";
                return "{\"status\": \"error\", \"error\": \"" + escapeJson(lastError) + "\"}";
            }
        } catch (Exception e) {
            connected = false;
            lastError = e.getMessage();
            System.err.println("Failed to connect to Ghidra server at " + host + ":" + port
                    + " - " + e.getMessage());
            return "{\"status\": \"error\", \"error\": \"" + escapeJson(lastError)
                    + "\", \"host\": \"" + escapeJson(host) + "\", \"port\": " + port + "}";
        }
    }

    /**
     * Disconnect from the Ghidra server.
     *
     * @return JSON string with disconnect result
     */
    public synchronized String disconnect() {
        if (!connected || serverAdapter == null) {
            return "{\"status\": \"not_connected\"}";
        }

        try {
            serverAdapter.disconnect();
            connected = false;
            serverAdapter = null;
            lastError = null;
            System.out.println("Disconnected from Ghidra server");
            return "{\"status\": \"disconnected\"}";
        } catch (Exception e) {
            lastError = e.getMessage();
            connected = false;
            serverAdapter = null;
            return "{\"status\": \"error\", \"error\": \"" + escapeJson(lastError) + "\"}";
        }
    }

    /**
     * Get the current connection status.
     *
     * @return JSON string with connection status details
     */
    public String getStatus() {
        StringBuilder sb = new StringBuilder();
        sb.append("{");
        sb.append("\"connected\": ").append(connected);
        sb.append(", \"host\": \"").append(escapeJson(host)).append("\"");
        sb.append(", \"port\": ").append(port);

        if (user != null && !user.isEmpty()) {
            sb.append(", \"user\": \"").append(escapeJson(user)).append("\"");
        }

        if (connected && serverAdapter != null) {
            sb.append(", \"server_connected\": ").append(serverAdapter.isConnected());
        }

        if (lastError != null) {
            sb.append(", \"last_error\": \"").append(escapeJson(lastError)).append("\"");
        }

        sb.append("}");
        return sb.toString();
    }

    /**
     * List available repositories on the connected server.
     *
     * @return JSON string with repository list
     */
    public String listRepositories() {
        if (!connected || serverAdapter == null) {
            return "{\"error\": \"Not connected to server. Use /server/connect first.\"}";
        }

        if (!serverAdapter.isConnected()) {
            connected = false;
            return "{\"error\": \"Server connection lost. Reconnect with /server/connect.\"}";
        }

        try {
            String[] repoNames = serverAdapter.getRepositoryNames();
            StringBuilder sb = new StringBuilder();
            sb.append("{\"repositories\": [");
            for (int i = 0; i < repoNames.length; i++) {
                if (i > 0) sb.append(", ");
                sb.append("\"").append(escapeJson(repoNames[i])).append("\"");
            }
            sb.append("], \"count\": ").append(repoNames.length).append("}");
            return sb.toString();
        } catch (IOException e) {
            lastError = e.getMessage();
            return "{\"error\": \"Failed to list repositories: " + escapeJson(e.getMessage()) + "\"}";
        }
    }

    public boolean isConnected() {
        return connected && serverAdapter != null && serverAdapter.isConnected();
    }

    public String getHost() {
        return host;
    }

    public int getPort() {
        return port;
    }

    public String getUser() {
        return user;
    }

    public RepositoryServerAdapter getServerAdapter() {
        return serverAdapter;
    }

    private static String getEnvOrDefault(String name, String defaultValue) {
        String value = System.getenv(name);
        return (value != null && !value.isEmpty()) ? value : defaultValue;
    }

    private static int parsePort(String value, int defaultPort) {
        if (value == null || value.isEmpty()) {
            return defaultPort;
        }
        try {
            int port = Integer.parseInt(value);
            return port > 0 ? port : defaultPort;
        } catch (NumberFormatException e) {
            return defaultPort;
        }
    }

    private String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }
}
