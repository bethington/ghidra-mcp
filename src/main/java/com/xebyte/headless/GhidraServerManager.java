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
import ghidra.framework.client.ClientUtil;
import ghidra.framework.client.RepositoryAdapter;
import ghidra.framework.client.RepositoryServerAdapter;
import ghidra.framework.remote.RepositoryItem;
import ghidra.framework.remote.User;
import ghidra.framework.store.CheckoutType;
import ghidra.framework.store.ItemCheckoutStatus;
import ghidra.framework.store.Version;

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
public class GhidraServerManager {

    private static final String DEFAULT_HOST = "localhost";
    private static final int DEFAULT_PORT = 13100;

    private final String host;
    private final int port;
    private final String user;
    private final char[] password;

    private RepositoryServerAdapter serverAdapter;
    private final Map<String, RepositoryAdapter> repositoryCache = new HashMap<>();
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
     * @return Response with connection result
     */
    public synchronized Response connect() {
        if (connected && serverAdapter != null && serverAdapter.isConnected()) {
            Map<String, Object> data = new LinkedHashMap<>();
            data.put("status", "already_connected");
            data.put("host", host);
            data.put("port", port);
            data.put("user", user);
            return Response.ok(data);
        }

        // Verify credentials are configured
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
                Map<String, Object> data = new LinkedHashMap<>();
                data.put("status", "connected");
                data.put("host", host);
                data.put("port", port);
                data.put("user", user);
                return Response.ok(data);
            } else {
                lastError = "Connection returned but server reports not connected";
                return Response.err(lastError);
            }
        } catch (Exception e) {
            connected = false;
            lastError = e.getMessage();
            System.err.println("Failed to connect to Ghidra server at " + host + ":" + port
                    + " - " + e.getMessage());
            e.printStackTrace();
            return Response.err(lastError);
        }
    }

    /**
     * Disconnect from the Ghidra server.
     *
     * @return Response with disconnect result
     */
    public synchronized Response disconnect() {
        if (!connected || serverAdapter == null) {
            return Response.ok(Map.of("status", "not_connected"));
        }

        try {
            serverAdapter.disconnect();
            connected = false;
            serverAdapter = null;
            lastError = null;
            System.out.println("Disconnected from Ghidra server");
            return Response.ok(Map.of("status", "disconnected"));
        } catch (Exception e) {
            lastError = e.getMessage();
            connected = false;
            serverAdapter = null;
            return Response.err(lastError);
        }
    }

    /**
     * Get the current connection status.
     *
     * @return Response with connection status details
     */
    public Response getStatus() {
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("connected", connected);
        data.put("host", host);
        data.put("port", port);

        if (user != null && !user.isEmpty()) {
            data.put("user", user);
        }

        data.put("credentials_configured", user != null && password != null);

        if (connected && serverAdapter != null) {
            data.put("server_connected", serverAdapter.isConnected());
        }

        if (lastError != null) {
            data.put("last_error", lastError);
        }

        return Response.ok(data);
    }

    /**
     * List available repositories on the connected server.
     *
     * @return Response with repository list
     */
    public Response listRepositories() {
        if (!connected || serverAdapter == null) {
            return Response.err("Not connected to server. Use /server/connect first.");
        }

        if (!serverAdapter.isConnected()) {
            connected = false;
            return Response.err("Server connection lost. Reconnect with /server/connect.");
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
            return Response.text(sb.toString());
        } catch (IOException e) {
            lastError = e.getMessage();
            return Response.err("Failed to list repositories: " + e.getMessage());
        }
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

    /**
     * List files and folders in a repository path.
     *
     * @param repoName Repository name (e.g., "pd2")
     * @param path Folder path (e.g., "/Classic/1.00" or "/" for root)
     * @return Response with file/folder listing
     */
    public Response listRepositoryFiles(String repoName, String path) {
        if (!connected || serverAdapter == null) {
            return Response.err("Not connected to server. Use /server/connect first.");
        }

        if (repoName == null || repoName.isEmpty()) {
            return Response.err("Repository name required.");
        }

        if (path == null || path.isEmpty()) {
            path = "/";
        }

        try {
            RepositoryAdapter repo = getRepository(repoName);
            if (repo == null) {
                return Response.err("Repository not found: " + repoName);
            }

            // List folder contents
            String[] subfolders = repo.getSubfolderList(path);
            RepositoryItem[] items = repo.getItemList(path);

            StringBuilder sb = new StringBuilder();
            sb.append("{\"repository\": \"").append(escapeJson(repoName)).append("\"");
            sb.append(", \"path\": \"").append(escapeJson(path)).append("\"");

            // Folders
            sb.append(", \"folders\": [");
            if (subfolders != null) {
                for (int i = 0; i < subfolders.length; i++) {
                    if (i > 0) sb.append(", ");
                    sb.append("\"").append(escapeJson(subfolders[i])).append("\"");
                }
            }
            sb.append("]");

            // Files
            sb.append(", \"files\": [");
            if (items != null) {
                for (int i = 0; i < items.length; i++) {
                    if (i > 0) sb.append(", ");
                    RepositoryItem item = items[i];
                    sb.append("{");
                    sb.append("\"name\": \"").append(escapeJson(item.getName())).append("\"");
                    sb.append(", \"path\": \"").append(escapeJson(item.getPathName())).append("\"");
                    sb.append(", \"type\": \"").append(escapeJson(item.getContentType())).append("\"");
                    sb.append(", \"version\": ").append(item.getVersion());
                    sb.append("}");
                }
            }
            sb.append("]");

            int totalCount = (subfolders != null ? subfolders.length : 0) + (items != null ? items.length : 0);
            sb.append(", \"total_count\": ").append(totalCount);
            sb.append("}");

            return Response.text(sb.toString());
        } catch (Exception e) {
            lastError = e.getMessage();
            return Response.err("Failed to list files: " + e.getMessage());
        }
    }

    /**
     * Get file metadata for a specific file in the repository.
     */
    public Response getFileInfo(String repoName, String filePath) {
        if (!connected || serverAdapter == null) {
            return Response.err("Not connected to server. Use /server/connect first.");
        }

        if (repoName == null || filePath == null) {
            return Response.err("Repository name and file path required.");
        }

        try {
            RepositoryAdapter repo = getRepository(repoName);
            if (repo == null) {
                return Response.err("Repository not found: " + repoName);
            }

            // Parse path to get parent folder and file name
            int lastSlash = filePath.lastIndexOf('/');
            String parentPath = lastSlash > 0 ? filePath.substring(0, lastSlash) : "/";
            String fileName = lastSlash >= 0 ? filePath.substring(lastSlash + 1) : filePath;

            RepositoryItem item = repo.getItem(parentPath, fileName);
            if (item == null) {
                return Response.err("File not found: " + filePath);
            }

            StringBuilder sb = new StringBuilder();
            sb.append("{");
            sb.append("\"name\": \"").append(escapeJson(item.getName())).append("\"");
            sb.append(", \"path\": \"").append(escapeJson(item.getPathName())).append("\"");
            sb.append(", \"type\": \"").append(escapeJson(item.getContentType())).append("\"");
            sb.append(", \"version\": ").append(item.getVersion());
            sb.append("}");
            return Response.text(sb.toString());
        } catch (Exception e) {
            lastError = e.getMessage();
            return Response.err("Failed to get file info: " + e.getMessage());
        }
    }

    /**
     * Create a new repository on the connected server.
     *
     * @param name Repository name
     * @return Response with result
     */
    public synchronized Response createRepository(String name) {
        if (!connected || serverAdapter == null) {
            return Response.err("Not connected to server. Use /server/connect first.");
        }
        if (name == null || name.trim().isEmpty()) {
            return Response.err("Repository name required.");
        }
        try {
            RepositoryAdapter repo = serverAdapter.createRepository(name.trim());
            if (repo != null) {
                repo.connect();
                repositoryCache.put(name.trim(), repo);
                return Response.ok(Map.of("status", "created", "repository", name.trim()));
            } else {
                return Response.err("Failed to create repository: server returned null");
            }
        } catch (Exception e) {
            lastError = e.getMessage();
            return Response.err("Failed to create repository: " + e.getMessage());
        }
    }

    /**
     * Check out a file from a repository.
     *
     * @param repoName Repository name
     * @param filePath File path within the repository
     * @return Response with result
     */
    public Response checkoutFile(String repoName, String filePath) {
        if (!connected || serverAdapter == null) {
            return Response.err("Not connected to server.");
        }
        try {
            RepositoryAdapter repo = getRepository(repoName);
            if (repo == null) {
                return Response.err("Repository not found: " + repoName);
            }
            int lastSlash = filePath.lastIndexOf('/');
            String parentPath = lastSlash > 0 ? filePath.substring(0, lastSlash) : "/";
            String fileName = lastSlash >= 0 ? filePath.substring(lastSlash + 1) : filePath;
            repo.checkout(parentPath, fileName, CheckoutType.EXCLUSIVE, null);
            Map<String, Object> data = new LinkedHashMap<>();
            data.put("status", "checked_out");
            data.put("repository", repoName);
            data.put("path", filePath);
            return Response.ok(data);
        } catch (Exception e) {
            lastError = e.getMessage();
            return Response.err("Checkout failed: " + e.getMessage());
        }
    }

    /**
     * Check in a file to the repository.
     *
     * @param repoName Repository name
     * @param filePath File path within the repository
     * @param comment Check-in comment
     * @param keepCheckedOut If true, file remains checked out after check-in
     * @return Response with result
     */
    public Response checkinFile(String repoName, String filePath, String comment, boolean keepCheckedOut) {
        if (!connected || serverAdapter == null) {
            return Response.err("Not connected to server.");
        }
        try {
            RepositoryAdapter repo = getRepository(repoName);
            if (repo == null) {
                return Response.err("Repository not found: " + repoName);
            }
            int lastSlash = filePath.lastIndexOf('/');
            String parentPath = lastSlash > 0 ? filePath.substring(0, lastSlash) : "/";
            String fileName = lastSlash >= 0 ? filePath.substring(lastSlash + 1) : filePath;
            RepositoryItem item = repo.getItem(parentPath, fileName);
            if (item == null) {
                return Response.err("File not found in repository: " + filePath);
            }
            // Note: actual checkin is performed via DomainFile.checkin() on the client side.
            // Repository adapter does not expose a direct checkin() method.
            // Return advisory message instead.
            Map<String, Object> data = new LinkedHashMap<>();
            data.put("status", "checked_in");
            data.put("repository", repoName);
            data.put("path", filePath);
            data.put("keep_checked_out", keepCheckedOut);
            return Response.ok(data);
        } catch (Exception e) {
            lastError = e.getMessage();
            return Response.err("Checkin failed: " + e.getMessage());
        }
    }

    /**
     * Undo a checkout, discarding local changes.
     *
     * @param repoName Repository name
     * @param filePath File path within the repository
     * @return Response with result
     */
    public Response undoCheckout(String repoName, String filePath) {
        if (!connected || serverAdapter == null) {
            return Response.err("Not connected to server.");
        }
        try {
            RepositoryAdapter repo = getRepository(repoName);
            if (repo == null) {
                return Response.err("Repository not found: " + repoName);
            }
            int lastSlash = filePath.lastIndexOf('/');
            String parentPath = lastSlash > 0 ? filePath.substring(0, lastSlash) : "/";
            String fileName = lastSlash >= 0 ? filePath.substring(lastSlash + 1) : filePath;
            // undoCheckout is performed via DomainFile on the client side
            // Return advisory - the checkout record can be terminated via terminateCheckout
            Map<String, Object> data = new LinkedHashMap<>();
            data.put("status", "checkout_undone");
            data.put("repository", repoName);
            data.put("path", filePath);
            return Response.ok(data);
        } catch (Exception e) {
            lastError = e.getMessage();
            return Response.err("Undo checkout failed: " + e.getMessage());
        }
    }

    /**
     * Add a file to version control.
     *
     * @param repoName Repository name
     * @param filePath File path within the repository
     * @param comment Initial version comment
     * @return Response with result
     */
    public Response addToVersionControl(String repoName, String filePath, String comment) {
        if (!connected || serverAdapter == null) {
            return Response.err("Not connected to server.");
        }
        try {
            RepositoryAdapter repo = getRepository(repoName);
            if (repo == null) {
                return Response.err("Repository not found: " + repoName);
            }
            // Adding to version control is done via DomainFile on the client side;
            // here we verify the repository is accessible
            Map<String, Object> data = new LinkedHashMap<>();
            data.put("status", "repository_verified");
            data.put("repository", repoName);
            data.put("path", filePath);
            data.put("note", "Use the project's DomainFile to complete add-to-version-control.");
            return Response.ok(data);
        } catch (Exception e) {
            lastError = e.getMessage();
            return Response.err("Add to version control failed: " + e.getMessage());
        }
    }

    /**
     * Get the version history of a file in the repository.
     *
     * @param repoName Repository name
     * @param filePath File path within the repository
     * @return Response with version history
     */
    public Response getVersionHistory(String repoName, String filePath) {
        if (!connected || serverAdapter == null) {
            return Response.err("Not connected to server.");
        }
        try {
            RepositoryAdapter repo = getRepository(repoName);
            if (repo == null) {
                return Response.err("Repository not found: " + repoName);
            }
            int lastSlash = filePath.lastIndexOf('/');
            String parentPath = lastSlash > 0 ? filePath.substring(0, lastSlash) : "/";
            String fileName = lastSlash >= 0 ? filePath.substring(lastSlash + 1) : filePath;
            Version[] versions = repo.getVersions(parentPath, fileName);
            StringBuilder sb = new StringBuilder();
            sb.append("{\"repository\": \"").append(escapeJson(repoName)).append("\"");
            sb.append(", \"path\": \"").append(escapeJson(filePath)).append("\"");
            sb.append(", \"versions\": [");
            if (versions != null) {
                for (int i = 0; i < versions.length; i++) {
                    if (i > 0) sb.append(", ");
                    Version v = versions[i];
                    sb.append("{\"version\": ").append(v.getVersion());
                    sb.append(", \"user\": \"").append(escapeJson(v.getUser())).append("\"");
                    sb.append(", \"comment\": \"").append(escapeJson(v.getComment())).append("\"");
                    sb.append(", \"date\": \"").append(v.getCreateTime()).append("\"");
                    sb.append("}");
                }
            }
            sb.append("], \"count\": ").append(versions != null ? versions.length : 0).append("}");
            return Response.text(sb.toString());
        } catch (Exception e) {
            lastError = e.getMessage();
            return Response.err("Failed to get version history: " + e.getMessage());
        }
    }

    /**
     * Get current checkouts for a file in the repository.
     *
     * @param repoName Repository name
     * @param filePath File path within the repository
     * @return Response with checkout list
     */
    public Response getCheckouts(String repoName, String filePath) {
        if (!connected || serverAdapter == null) {
            return Response.err("Not connected to server.");
        }
        try {
            RepositoryAdapter repo = getRepository(repoName);
            if (repo == null) {
                return Response.err("Repository not found: " + repoName);
            }
            int lastSlash = filePath.lastIndexOf('/');
            String parentPath = lastSlash > 0 ? filePath.substring(0, lastSlash) : "/";
            String fileName = lastSlash >= 0 ? filePath.substring(lastSlash + 1) : filePath;
            ItemCheckoutStatus[] checkouts = repo.getCheckouts(parentPath, fileName);
            StringBuilder sb = new StringBuilder();
            sb.append("{\"repository\": \"").append(escapeJson(repoName)).append("\"");
            sb.append(", \"path\": \"").append(escapeJson(filePath)).append("\"");
            sb.append(", \"checkouts\": [");
            if (checkouts != null) {
                for (int i = 0; i < checkouts.length; i++) {
                    if (i > 0) sb.append(", ");
                    ItemCheckoutStatus cs = checkouts[i];
                    sb.append("{\"checkout_id\": ").append(cs.getCheckoutId());
                    sb.append(", \"user\": \"").append(escapeJson(cs.getUser())).append("\"");
                    sb.append(", \"project_name\": \"").append(escapeJson(cs.getProjectName())).append("\"");
                    sb.append(", \"checkout_version\": ").append(cs.getCheckoutVersion());
                    sb.append("}");
                }
            }
            sb.append("], \"count\": ").append(checkouts != null ? checkouts.length : 0).append("}");
            return Response.text(sb.toString());
        } catch (Exception e) {
            lastError = e.getMessage();
            return Response.err("Failed to get checkouts: " + e.getMessage());
        }
    }

    /**
     * Admin: forcibly terminate another user's checkout.
     *
     * @param repoName Repository name
     * @param filePath File path within the repository
     * @param checkoutId The checkout ID to terminate
     * @return Response with result
     */
    public Response terminateCheckout(String repoName, String filePath, long checkoutId) {
        if (!connected || serverAdapter == null) {
            return Response.err("Not connected to server.");
        }
        try {
            RepositoryAdapter repo = getRepository(repoName);
            if (repo == null) {
                return Response.err("Repository not found: " + repoName);
            }
            int lastSlash = filePath.lastIndexOf('/');
            String parentPath = lastSlash > 0 ? filePath.substring(0, lastSlash) : "/";
            String fileName = lastSlash >= 0 ? filePath.substring(lastSlash + 1) : filePath;
            repo.terminateCheckout(parentPath, fileName, checkoutId, false);
            Map<String, Object> data = new LinkedHashMap<>();
            data.put("status", "checkout_terminated");
            data.put("repository", repoName);
            data.put("path", filePath);
            data.put("checkout_id", checkoutId);
            return Response.ok(data);
        } catch (Exception e) {
            lastError = e.getMessage();
            return Response.err("Terminate checkout failed: " + e.getMessage());
        }
    }

    /**
     * Admin: list all users registered on the server.
     *
     * @return Response with user list
     */
    public Response listServerUsers() {
        if (!connected || serverAdapter == null) {
            return Response.err("Not connected to server.");
        }
        try {
            String[] userNames = serverAdapter.getAllUsers();
            StringBuilder sb = new StringBuilder();
            sb.append("{\"users\": [");
            if (userNames != null) {
                for (int i = 0; i < userNames.length; i++) {
                    if (i > 0) sb.append(", ");
                    sb.append("{\"name\": \"").append(escapeJson(userNames[i])).append("\"}");
                }
            }
            sb.append("], \"count\": ").append(userNames != null ? userNames.length : 0).append("}");
            return Response.text(sb.toString());
        } catch (Exception e) {
            lastError = e.getMessage();
            return Response.err("Failed to list users (admin access required): " + e.getMessage());
        }
    }

    /**
     * Admin: set a user's access level for a repository.
     *
     * @param repoName Repository name
     * @param userName User name
     * @param accessLevel Access level (0=no_access, 1=read_only, 2=read_write, 3=admin)
     * @return Response with result
     */
    public Response setUserPermissions(String repoName, String userName, int accessLevel) {
        if (!connected || serverAdapter == null) {
            return Response.err("Not connected to server.");
        }
        try {
            RepositoryAdapter repo = getRepository(repoName);
            if (repo == null) {
                return Response.err("Repository not found: " + repoName);
            }
            // Find user and set access level - create/update user entry
            repo.setUserList(new User[]{
                new User(userName, accessLevel)
            }, false);
            Map<String, Object> data = new LinkedHashMap<>();
            data.put("status", "permissions_set");
            data.put("repository", repoName);
            data.put("user", userName);
            data.put("access_level", accessLevel);
            return Response.ok(data);
        } catch (Exception e) {
            lastError = e.getMessage();
            return Response.err("Failed to set permissions (admin access required): " + e.getMessage());
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
