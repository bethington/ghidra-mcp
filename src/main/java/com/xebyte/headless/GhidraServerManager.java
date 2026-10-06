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

import com.xebyte.core.GhidraMCPAuthenticator;
import com.xebyte.core.Response;
import com.xebyte.core.ServerSession;
import ghidra.framework.client.ClientUtil;
import ghidra.framework.client.RepositoryAdapter;
import ghidra.framework.client.RepositoryServerAdapter;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
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
 *   <li>GHIDRA_SERVER_USER - Service account username (required for auth)</li>
 *   <li>GHIDRA_SERVER_PASSWORD - Service account password (required for auth)</li>
 * </ul>
 */
public class GhidraServerManager implements ServerSession {

    private static final String DEFAULT_HOST = "localhost";
    private static final int DEFAULT_PORT = 13100;

    private final String host;
    private final int port;
    private volatile String user;
    private volatile char[] password;

    private RepositoryServerAdapter serverAdapter;
    private final Map<String, RepositoryAdapter> repositoryCache = new HashMap<>();
    private volatile boolean connected = false;
    private String lastError;
    /** Open project — DomainFile VC ops need this, not RepositoryAdapter alone. */

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

    /** Register the credentials the environment configured, if it configured any. */
    private void registerAuthenticator() {
        if (user == null || password == null) {
            System.out.println("No credentials configured - server connection will use anonymous/default auth");
            return;
        }
        try {
            GhidraMCPAuthenticator.register(user, password);
            System.out.println("Registered GhidraMCP authenticator for user: " + user);
        } catch (Exception e) {
            System.err.println("Failed to register authenticator: " + e.getMessage());
        }
    }

    @Override
    public synchronized void useCredentials(String username, char[] newPassword) {
        this.user = username;
        this.password = newPassword;
        registerAuthenticator();
    }

    /**
     * Connect with the credentials the environment configured. Already connected is
     * reported, not repeated.
     */
    @Override
    public synchronized Response connect() {
        if (connected && serverAdapter != null && serverAdapter.isConnected()) {
            return Response.ok(connection("already_connected"));
        }

        if (user == null || password == null) {
            lastError = "Credentials not configured. Set GHIDRA_SERVER_USER and GHIDRA_SERVER_PASSWORD";
            return Response.err(lastError);
        }

        try {
            System.out.println("Connecting to Ghidra server at " + host + ":" + port + " as " + user);
            serverAdapter = ClientUtil.getRepositoryServer(host, port);
            serverAdapter.connect();
            connected = serverAdapter.isConnected();
            lastError = null;

            if (connected) {
                System.out.println("Connected to Ghidra server at " + host + ":" + port + " as " + user);
                return Response.ok(connection("connected"));
            }
            lastError = "Connection returned but server reports not connected";
            return Response.err(lastError);
        } catch (Exception e) {
            connected = false;
            lastError = e.getMessage();
            System.err.println("Failed to connect to Ghidra server at " + host + ":" + port
                    + " - " + e.getMessage());
            e.printStackTrace();
            return Response.err(lastError + " (" + host + ":" + port + ")");
        }
    }

    private Map<String, Object> connection(String status) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("status", status);
        out.put("host", host);
        out.put("port", port);
        out.put("user", user);
        return out;
    }

    @Override
    public synchronized Response disconnect() {
        if (!connected || serverAdapter == null) {
            return Response.ok(Map.of("status", "not_connected"));
        }

        try {
            serverAdapter.disconnect();
            System.out.println("Disconnected from Ghidra server");
            lastError = null;
            return Response.ok(Map.of("status", "disconnected"));
        } catch (Exception e) {
            lastError = e.getMessage();
            return Response.err(lastError);
        } finally {
            connected = false;
            serverAdapter = null;
            repositoryCache.clear();
        }
    }

    @Override
    public Map<String, Object> status() {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("connected", connected);
        out.put("host", host);
        out.put("port", port);
        if (user != null && !user.isEmpty()) {
            out.put("user", user);
        }
        out.put("credentials_configured", user != null && password != null);
        if (connected && serverAdapter != null) {
            out.put("server_connected", serverAdapter.isConnected());
        }
        if (lastError != null) {
            out.put("last_error", lastError);
        }
        return out;
    }

    @Override
    public RepositoryServerAdapter server() {
        return isConnected() ? serverAdapter : null;
    }

    /**
     * Get or create a RepositoryAdapter for the specified repository.
     */
    private RepositoryAdapter getRepository(String repoName) throws IOException {
        if (!connected || serverAdapter == null) {
            throw new IOException("Not connected to server");
        }
        
        RepositoryAdapter repo = repositoryCache.get(repoName);
        if (repo == null || !repo.isConnected()) {
            repo = serverAdapter.getRepository(repoName);
            if (repo != null) {
                repo.connect();
                repositoryCache.put(repoName, repo);
            }
        }
        return repo;
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

    /**
     * Wire the open-project handle so version-control endpoints can resolve
     * {@link DomainFile}s. Called once from {@code GhidraMCPHeadlessServer} startup.
     */

    /**
     * Ensure a live {@link RepositoryServerAdapter} for the given host:port.
     * Reuses the existing connection when it matches; refuses a host/port
     * mismatch rather than silently talking to the wrong server.
     */
    public synchronized RepositoryServerAdapter ensureConnectedTo(String targetHost, int targetPort)
            throws IOException {
        if (targetHost == null || targetHost.isBlank()) {
            throw new IOException("server host required");
        }
        if (targetPort <= 0) {
            throw new IOException("server port must be positive: " + targetPort);
        }
        if (isConnected()) {
            if (!host.equalsIgnoreCase(targetHost) || port != targetPort) {
                throw new IOException("Already connected to " + host + ":" + port
                        + " but URL targets " + targetHost + ":" + targetPort
                        + ". /server/disconnect first, or set GHIDRA_SERVER_HOST/PORT to match.");
            }
            return serverAdapter;
        }
        if (!host.equalsIgnoreCase(targetHost) || port != targetPort) {
            throw new IOException("URL targets " + targetHost + ":" + targetPort
                    + " but GHIDRA_SERVER_HOST/PORT is " + host + ":" + port
                    + ". Align the env vars (or reconnect) before /open_project.");
        }
        connect();
        if (!isConnected()) {
            throw new IOException(lastError != null ? lastError : "connect failed");
        }
        return serverAdapter;
    }

    /**
     * Open (and cache) a repository on the connected server.
     */
    public synchronized RepositoryAdapter openRepository(String repoName) throws IOException {
        return getRepository(repoName);
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

}
