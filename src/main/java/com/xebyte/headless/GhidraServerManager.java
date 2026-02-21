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
import ghidra.framework.client.ClientAuthenticator;
import ghidra.framework.client.RepositoryServerAdapter;
import ghidra.framework.remote.AnonymousCallback;
import ghidra.framework.remote.SSHSignatureCallback;

import javax.security.auth.callback.*;
import java.io.IOException;
import java.net.Authenticator;

/**
 * Manages connections to a shared Ghidra repository server.
 *
 * Provides connectivity to a Ghidra server for centralized analysis storage
 * and team collaboration. Configuration is driven by environment variables:
 *
 * <ul>
 *   <li>GHIDRA_SERVER_HOST - Server hostname (default: localhost)</li>
 *   <li>GHIDRA_SERVER_PORT - Server port (default: 13100)</li>
 *   <li>GHIDRA_SERVER_USER - Service account username (required for auth)</li>
 *   <li>GHIDRA_SERVER_PASSWORD - Service account password (required for auth)</li>
 * </ul>
 */
public class GhidraServerManager {

    private static final String DEFAULT_HOST = "localhost";
    private static final int DEFAULT_PORT = 13100;

    private final String host;
    private final int port;
    private final String user;
    private final char[] password;

    private RepositoryServerAdapter serverAdapter;
    private volatile boolean connected = false;
    private String lastError;
    private static volatile boolean authenticatorRegistered = false;

    public GhidraServerManager() {
        this.host = getEnvOrDefault("GHIDRA_SERVER_HOST", DEFAULT_HOST);
        this.port = parsePort(System.getenv("GHIDRA_SERVER_PORT"), DEFAULT_PORT);
        this.user = System.getenv("GHIDRA_SERVER_USER");
        String pwd = System.getenv("GHIDRA_SERVER_PASSWORD");
        this.password = (pwd != null) ? pwd.toCharArray() : null;
        
        // Register our custom authenticator
        registerAuthenticator();
    }

    public GhidraServerManager(String host, int port, String user, String password) {
        this.host = (host != null && !host.isEmpty()) ? host : DEFAULT_HOST;
        this.port = port > 0 ? port : DEFAULT_PORT;
        this.user = user;
        this.password = (password != null) ? password.toCharArray() : null;
        
        registerAuthenticator();
    }

    /**
     * Register custom authenticator for headless server connections.
     */
    private synchronized void registerAuthenticator() {
        if (authenticatorRegistered) {
            return;
        }
        
        if (user != null && password != null) {
            try {
                ClientUtil.setClientAuthenticator(new GhidraMCPAuthenticator(user, password));
                authenticatorRegistered = true;
                System.out.println("Registered GhidraMCP authenticator for user: " + user);
            } catch (Exception e) {
                System.err.println("Failed to register authenticator: " + e.getMessage());
            }
        } else {
            System.out.println("No credentials configured - server connection will use anonymous/default auth");
        }
    }

    /**
     * Connect to the configured Ghidra server.
     *
     * @return JSON string with connection result
     */
    public synchronized String connect() {
        if (connected && serverAdapter != null && serverAdapter.isConnected()) {
            return "{\"status\": \"already_connected\", \"host\": \"" + escapeJson(host)
                    + "\", \"port\": " + port + ", \"user\": \"" + escapeJson(user) + "\"}";
        }

        // Verify credentials are configured
        if (user == null || password == null) {
            lastError = "Credentials not configured. Set GHIDRA_SERVER_USER and GHIDRA_SERVER_PASSWORD";
            return "{\"status\": \"error\", \"error\": \"" + escapeJson(lastError) + "\"}";
        }

        try {
            System.out.println("Connecting to Ghidra server at " + host + ":" + port + " as " + user);
            serverAdapter = ClientUtil.getRepositoryServer(host, port);
            serverAdapter.connect();
            connected = serverAdapter.isConnected();
            lastError = null;

            if (connected) {
                System.out.println("Connected to Ghidra server at " + host + ":" + port + " as " + user);
                return "{\"status\": \"connected\", \"host\": \"" + escapeJson(host)
                        + "\", \"port\": " + port + ", \"user\": \"" + escapeJson(user) + "\"}";
            } else {
                lastError = "Connection returned but server reports not connected";
                return "{\"status\": \"error\", \"error\": \"" + escapeJson(lastError) + "\"}";
            }
        } catch (Exception e) {
            connected = false;
            lastError = e.getMessage();
            System.err.println("Failed to connect to Ghidra server at " + host + ":" + port
                    + " - " + e.getMessage());
            e.printStackTrace();
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
        
        sb.append(", \"credentials_configured\": ").append(user != null && password != null);

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

    /**
     * Custom authenticator for headless Ghidra server connections.
     * Implements ClientAuthenticator to provide credentials without GUI interaction.
     */
    private static class GhidraMCPAuthenticator implements ClientAuthenticator {
        private final String username;
        private final char[] password;

        public GhidraMCPAuthenticator(String username, char[] password) {
            this.username = username;
            this.password = password;
        }

        @Override
        public boolean isSSHKeyAvailable() {
            return false;
        }

        @Override
        public boolean processSSHSignatureCallbacks(String serverName, NameCallback nameCb,
                SSHSignatureCallback sshCb) {
            // SSH key authentication not supported in this implementation
            return false;
        }

        @Override
        public boolean processPasswordCallbacks(String title, String serverType, String serverName,
                boolean nameEditable, NameCallback nameCb, PasswordCallback passCb, 
                ChoiceCallback choiceCb, AnonymousCallback anonymousCb, String loginError) {
            try {
                // Set the username
                if (nameCb != null) {
                    nameCb.setName(username);
                }
                
                // Set the password
                if (passCb != null) {
                    passCb.setPassword(password);
                }
                
                // Accept default choice if present
                if (choiceCb != null) {
                    choiceCb.setSelectedIndex(choiceCb.getDefaultChoice());
                }
                
                // Don't use anonymous access since we have credentials
                if (anonymousCb != null) {
                    anonymousCb.setAnonymousAccessRequested(false);
                }
                
                System.out.println("GhidraMCP authenticator provided credentials for user: " + username);
                return true;
            } catch (Exception e) {
                System.err.println("Password callback failed: " + e.getMessage());
                return false;
            }
        }

        @Override
        public boolean promptForReconnect(java.awt.Component parent, String message) {
            // In headless mode, always attempt reconnect
            System.out.println("Reconnect requested: " + message);
            return true;
        }

        @Override
        public char[] getNewPassword(java.awt.Component parent, String serverInfo, String user) {
            // Password change not supported in headless mode
            return null;
        }

        @Override
        public Authenticator getAuthenticator() {
            // Return null - we handle authentication via callbacks
            return null;
        }

        @Override
        public char[] getKeyStorePassword(String keystorePath, boolean passwordError) {
            // KeyStore password not used - return null
            // This is called when Ghidra needs to access a keystore for PKI authentication
            return null;
        }
    }
}
