package com.xebyte.core;

import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.net.InetSocketAddress;

/**
 * TCP socket transport — the default transport for GhidraMCP.
 * Binds an {@link HttpServer} to a TCP address and port.
 *
 * @since 4.3.0
 */
public final class TcpTransport implements ServerTransport {

    private final String host;
    private final int port;

    /**
     * Create a TCP transport bound to the given host and port.
     *
     * @param host the bind address (e.g., "127.0.0.1")
     * @param port the TCP port number
     */
    public TcpTransport(String host, int port) {
        this.host = host;
        this.port = port;
    }

    /**
     * Create a TCP transport bound to localhost on the given port.
     *
     * @param port the TCP port number
     */
    public TcpTransport(int port) {
        this("127.0.0.1", port);
    }

    @Override
    public HttpServer createServer(int backlog) throws IOException {
        return HttpServer.create(new InetSocketAddress(host, port), backlog);
    }

    @Override
    public String describe() {
        return host + ":" + port;
    }

    @Override
    public int port() {
        return port;
    }
}
