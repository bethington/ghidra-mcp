package com.xebyte.core;

import ghidra.framework.client.RepositoryServerAdapter;

import java.util.Map;

/**
 * The Ghidra Server connection {@link VersionControlService}'s server-level routes talk to.
 *
 * <p>Headless owns its connection: it connects with credentials from the environment
 * ({@code GhidraServerManager}). The GUI has none of its own, because its open project
 * already carries one ({@link ProjectServerSession}). What the routes do with the
 * connection (list repositories, browse, administer users) is the same either way, so it
 * is written once, against this.
 */
public interface ServerSession {

    /** The connected server, or null when there is no connection. */
    RepositoryServerAdapter server();

    /** Establish the connection, or report the one that already exists. */
    Response connect();

    Response disconnect();

    /** Whether a server is connected, and what is known about it. */
    Map<String, Object> status();

    /**
     * Use these credentials from now on. Registers them with Ghidra's client, and, for a
     * session that connects itself, remembers them for the next connect.
     */
    void useCredentials(String username, char[] password);
}
