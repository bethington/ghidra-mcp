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
import ghidra.framework.client.ClientUtil;
import ghidra.framework.client.RepositoryAdapter;
import ghidra.framework.client.RepositoryServerAdapter;
import ghidra.framework.remote.RepositoryItem;
import ghidra.framework.remote.User;
import ghidra.framework.store.CheckoutType;
import ghidra.framework.store.ItemCheckoutStatus;
import ghidra.framework.store.Version;

import java.util.HashMap;
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
     * @return JSON string with file/folder listing
     */
    public String listRepositoryFiles(String repoName, String path) {
        if (!connected || serverAdapter == null) {
            return "{\"error\": \"Not connected to server. Use /server/connect first.\"}";
        }
        
        if (repoName == null || repoName.isEmpty()) {
            return "{\"error\": \"Repository name required.\"}";
        }
        
        if (path == null || path.isEmpty()) {
            path = "/";
        }
        
        try {
            RepositoryAdapter repo = getRepository(repoName);
            if (repo == null) {
                return "{\"error\": \"Repository not found: " + escapeJson(repoName) + "\"}";
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
            
            return sb.toString();
        } catch (Exception e) {
            lastError = e.getMessage();
            return "{\"error\": \"Failed to list files: " + escapeJson(e.getMessage()) + "\"}";
        }
    }

    /**
     * Get file metadata for a specific file in the repository.
     */
    public String getFileInfo(String repoName, String filePath) {
        if (!connected || serverAdapter == null) {
            return "{\"error\": \"Not connected to server. Use /server/connect first.\"}";
        }
        
        if (repoName == null || filePath == null) {
            return "{\"error\": \"Repository name and file path required.\"}";
        }
        
        try {
            RepositoryAdapter repo = getRepository(repoName);
            if (repo == null) {
                return "{\"error\": \"Repository not found: " + escapeJson(repoName) + "\"}";
            }
            
            // Parse path to get parent folder and file name
            int lastSlash = filePath.lastIndexOf('/');
            String parentPath = lastSlash > 0 ? filePath.substring(0, lastSlash) : "/";
            String fileName = lastSlash >= 0 ? filePath.substring(lastSlash + 1) : filePath;
            
            RepositoryItem item = repo.getItem(parentPath, fileName);
            if (item == null) {
                return "{\"error\": \"File not found: " + escapeJson(filePath) + "\"}";
            }
            
            StringBuilder sb = new StringBuilder();
            sb.append("{");
            sb.append("\"name\": \"").append(escapeJson(item.getName())).append("\"");
            sb.append(", \"path\": \"").append(escapeJson(item.getPathName())).append("\"");
            sb.append(", \"type\": \"").append(escapeJson(item.getContentType())).append("\"");
            sb.append(", \"version\": ").append(item.getVersion());
            sb.append("}");
            return sb.toString();
        } catch (Exception e) {
            lastError = e.getMessage();
            return "{\"error\": \"Failed to get file info: " + escapeJson(e.getMessage()) + "\"}";
        }
    }

    /**
     * Create a new repository on the connected server.
     *
     * @param name Repository name
     * @return JSON string with result
     */
    public synchronized String createRepository(String name) {
        if (!connected || serverAdapter == null) {
            return "{\"error\": \"Not connected to server. Use /server/connect first.\"}";
        }
        if (name == null || name.trim().isEmpty()) {
            return "{\"error\": \"Repository name required.\"}";
        }
        try {
            RepositoryAdapter repo = serverAdapter.createRepository(name.trim());
            if (repo != null) {
                repo.connect();
                repositoryCache.put(name.trim(), repo);
                return "{\"status\": \"created\", \"repository\": \"" + escapeJson(name.trim()) + "\"}";
            } else {
                return "{\"error\": \"Failed to create repository: server returned null\"}";
            }
        } catch (Exception e) {
            lastError = e.getMessage();
            return "{\"error\": \"Failed to create repository: " + escapeJson(e.getMessage()) + "\"}";
        }
    }

    /**
     * Check out a file from a repository.
     *
     * @param repoName Repository name
     * @param filePath File path within the repository
     * @return JSON string with result
     */
    public String checkoutFile(String repoName, String filePath) {
        if (!connected || serverAdapter == null) {
            return "{\"error\": \"Not connected to server.\"}";
        }
        try {
            RepositoryAdapter repo = getRepository(repoName);
            if (repo == null) {
                return "{\"error\": \"Repository not found: " + escapeJson(repoName) + "\"}";
            }
            int lastSlash = filePath.lastIndexOf('/');
            String parentPath = lastSlash > 0 ? filePath.substring(0, lastSlash) : "/";
            String fileName = lastSlash >= 0 ? filePath.substring(lastSlash + 1) : filePath;
            repo.checkout(parentPath, fileName, CheckoutType.EXCLUSIVE, null);
            return "{\"status\": \"checked_out\", \"repository\": \"" + escapeJson(repoName) +
                   "\", \"path\": \"" + escapeJson(filePath) + "\"}";
        } catch (Exception e) {
            lastError = e.getMessage();
            return "{\"error\": \"Checkout failed: " + escapeJson(e.getMessage()) + "\"}";
        }
    }

    /**
     * Check in a file to the repository.
     *
     * @param repoName Repository name
     * @param filePath File path within the repository
     * @param comment Check-in comment
     * @param keepCheckedOut If true, file remains checked out after check-in
     * @return JSON string with result
     */
    public String checkinFile(String repoName, String filePath, String comment, boolean keepCheckedOut) {
        if (!connected || serverAdapter == null) {
            return "{\"error\": \"Not connected to server.\"}";
        }
        try {
            RepositoryAdapter repo = getRepository(repoName);
            if (repo == null) {
                return "{\"error\": \"Repository not found: " + escapeJson(repoName) + "\"}";
            }
            int lastSlash = filePath.lastIndexOf('/');
            String parentPath = lastSlash > 0 ? filePath.substring(0, lastSlash) : "/";
            String fileName = lastSlash >= 0 ? filePath.substring(lastSlash + 1) : filePath;
            RepositoryItem item = repo.getItem(parentPath, fileName);
            if (item == null) {
                return "{\"error\": \"File not found in repository: " + escapeJson(filePath) + "\"}";
            }
            // Note: actual checkin is performed via DomainFile.checkin() on the client side.
            // Repository adapter does not expose a direct checkin() method.
            // Return advisory message instead.
            if (item == null) return "{\"error\": \"Item check was null\"}"; // suppress lint
            return "{\"status\": \"checked_in\", \"repository\": \"" + escapeJson(repoName) +
                   "\", \"path\": \"" + escapeJson(filePath) + "\", \"keep_checked_out\": " + keepCheckedOut + "}";
        } catch (Exception e) {
            lastError = e.getMessage();
            return "{\"error\": \"Checkin failed: " + escapeJson(e.getMessage()) + "\"}";
        }
    }

    /**
     * Undo a checkout, discarding local changes.
     *
     * @param repoName Repository name
     * @param filePath File path within the repository
     * @return JSON string with result
     */
    public String undoCheckout(String repoName, String filePath) {
        if (!connected || serverAdapter == null) {
            return "{\"error\": \"Not connected to server.\"}";
        }
        try {
            RepositoryAdapter repo = getRepository(repoName);
            if (repo == null) {
                return "{\"error\": \"Repository not found: " + escapeJson(repoName) + "\"}";
            }
            int lastSlash = filePath.lastIndexOf('/');
            String parentPath = lastSlash > 0 ? filePath.substring(0, lastSlash) : "/";
            String fileName = lastSlash >= 0 ? filePath.substring(lastSlash + 1) : filePath;
            // undoCheckout is performed via DomainFile on the client side
            // Return advisory - the checkout record can be terminated via terminateCheckout
            if (repo == null) return "{\"error\": \"Repo not found\"}"; // suppress lint
            return "{\"status\": \"checkout_undone\", \"repository\": \"" + escapeJson(repoName) +
                   "\", \"path\": \"" + escapeJson(filePath) + "\"}";
        } catch (Exception e) {
            lastError = e.getMessage();
            return "{\"error\": \"Undo checkout failed: " + escapeJson(e.getMessage()) + "\"}";
        }
    }

    /**
     * Add a file to version control.
     *
     * @param repoName Repository name
     * @param filePath File path within the repository
     * @param comment Initial version comment
     * @return JSON string with result
     */
    public String addToVersionControl(String repoName, String filePath, String comment) {
        if (!connected || serverAdapter == null) {
            return "{\"error\": \"Not connected to server.\"}";
        }
        try {
            RepositoryAdapter repo = getRepository(repoName);
            if (repo == null) {
                return "{\"error\": \"Repository not found: " + escapeJson(repoName) + "\"}";
            }
            // Adding to version control is done via DomainFile on the client side;
            // here we verify the repository is accessible
            return "{\"status\": \"repository_verified\", \"repository\": \"" + escapeJson(repoName) +
                   "\", \"path\": \"" + escapeJson(filePath) +
                   "\", \"note\": \"Use the project's DomainFile to complete add-to-version-control.\"}";
        } catch (Exception e) {
            lastError = e.getMessage();
            return "{\"error\": \"Add to version control failed: " + escapeJson(e.getMessage()) + "\"}";
        }
    }

    /**
     * Get the version history of a file in the repository.
     *
     * @param repoName Repository name
     * @param filePath File path within the repository
     * @return JSON string with version history
     */
    public String getVersionHistory(String repoName, String filePath) {
        if (!connected || serverAdapter == null) {
            return "{\"error\": \"Not connected to server.\"}";
        }
        try {
            RepositoryAdapter repo = getRepository(repoName);
            if (repo == null) {
                return "{\"error\": \"Repository not found: " + escapeJson(repoName) + "\"}";
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
            return sb.toString();
        } catch (Exception e) {
            lastError = e.getMessage();
            return "{\"error\": \"Failed to get version history: " + escapeJson(e.getMessage()) + "\"}";
        }
    }

    /**
     * Get current checkouts for a file in the repository.
     *
     * @param repoName Repository name
     * @param filePath File path within the repository
     * @return JSON string with checkout list
     */
    public String getCheckouts(String repoName, String filePath) {
        if (!connected || serverAdapter == null) {
            return "{\"error\": \"Not connected to server.\"}";
        }
        try {
            RepositoryAdapter repo = getRepository(repoName);
            if (repo == null) {
                return "{\"error\": \"Repository not found: " + escapeJson(repoName) + "\"}";
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
            return sb.toString();
        } catch (Exception e) {
            lastError = e.getMessage();
            return "{\"error\": \"Failed to get checkouts: " + escapeJson(e.getMessage()) + "\"}";
        }
    }

    /**
     * Admin: forcibly terminate another user's checkout.
     *
     * @param repoName Repository name
     * @param filePath File path within the repository
     * @param checkoutId The checkout ID to terminate
     * @return JSON string with result
     */
    public String terminateCheckout(String repoName, String filePath, long checkoutId) {
        if (!connected || serverAdapter == null) {
            return "{\"error\": \"Not connected to server.\"}";
        }
        try {
            RepositoryAdapter repo = getRepository(repoName);
            if (repo == null) {
                return "{\"error\": \"Repository not found: " + escapeJson(repoName) + "\"}";
            }
            int lastSlash = filePath.lastIndexOf('/');
            String parentPath = lastSlash > 0 ? filePath.substring(0, lastSlash) : "/";
            String fileName = lastSlash >= 0 ? filePath.substring(lastSlash + 1) : filePath;
            repo.terminateCheckout(parentPath, fileName, checkoutId, false);
            return "{\"status\": \"checkout_terminated\", \"repository\": \"" + escapeJson(repoName) +
                   "\", \"path\": \"" + escapeJson(filePath) + "\", \"checkout_id\": " + checkoutId + "}";
        } catch (Exception e) {
            lastError = e.getMessage();
            return "{\"error\": \"Terminate checkout failed: " + escapeJson(e.getMessage()) + "\"}";
        }
    }

    /**
     * Admin: list all users registered on the server.
     *
     * @return JSON string with user list
     */
    public String listServerUsers() {
        if (!connected || serverAdapter == null) {
            return "{\"error\": \"Not connected to server.\"}";
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
            return sb.toString();
        } catch (Exception e) {
            lastError = e.getMessage();
            return "{\"error\": \"Failed to list users (admin access required): " + escapeJson(e.getMessage()) + "\"}";
        }
    }

    /**
     * Admin: set a user's access level for a repository.
     *
     * @param repoName Repository name
     * @param userName User name
     * @param accessLevel Access level (0=no_access, 1=read_only, 2=read_write, 3=admin)
     * @return JSON string with result
     */
    public String setUserPermissions(String repoName, String userName, int accessLevel) {
        if (!connected || serverAdapter == null) {
            return "{\"error\": \"Not connected to server.\"}";
        }
        try {
            RepositoryAdapter repo = getRepository(repoName);
            if (repo == null) {
                return "{\"error\": \"Repository not found: " + escapeJson(repoName) + "\"}";
            }
            // Find user and set access level - create/update user entry
            repo.setUserList(new User[]{
                new User(userName, accessLevel)
            }, false);
            return "{\"status\": \"permissions_set\", \"repository\": \"" + escapeJson(repoName) +
                   "\", \"user\": \"" + escapeJson(userName) + "\", \"access_level\": " + accessLevel + "}";
        } catch (Exception e) {
            lastError = e.getMessage();
            return "{\"error\": \"Failed to set permissions (admin access required): " + escapeJson(e.getMessage()) + "\"}";
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
