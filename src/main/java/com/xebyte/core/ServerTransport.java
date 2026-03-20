package com.xebyte.core;

import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpHandler;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.concurrent.Executor;

/**
 * Abstracts the transport layer for the GhidraMCP HTTP server.
 * Implementations control how the server binds and listens for connections.
 *
 * <p>Current implementations:
 * <ul>
 *   <li>{@link TcpTransport} — Standard TCP socket (default)</li>
 * </ul>
 *
 * <p>This abstraction enables future transport implementations (e.g., Unix Domain
 * Sockets on Linux/macOS) without changing the plugin or endpoint registration code.
 *
 * @since 4.3.0
 */
public interface ServerTransport {

    /**
     * Create and return an HttpServer bound to this transport's address.
     *
     * @param backlog the maximum number of queued incoming connections (0 for system default)
     * @return a configured but not yet started HttpServer
     * @throws IOException if the server cannot be created or the address is already in use
     */
    HttpServer createServer(int backlog) throws IOException;

    /**
     * A human-readable description of the transport binding (e.g., "127.0.0.1:8089").
     */
    String describe();

    /**
     * The port number this transport uses, or -1 if not applicable.
     */
    int port();
}
