package com.xebyte.core;

import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

/**
 * Manages the lifecycle of the GhidraMCP HTTP server: create, start, stop, restart.
 * Encapsulates transport selection, executor configuration, and thread-safe state management.
 *
 * <p>Decouples server lifecycle from both the GUI plugin and headless server,
 * allowing either to use any {@link ServerTransport} implementation without
 * code changes.
 *
 * <p>Usage:
 * <pre>{@code
 *   ServerLifecycle lifecycle = new ServerLifecycle(new TcpTransport(8089));
 *   lifecycle.setExecutor(Executors.newFixedThreadPool(10));
 *   lifecycle.start(server -> {
 *       server.createContext("/path", handler);
 *   });
 *   // later...
 *   lifecycle.stop();
 * }</pre>
 *
 * @since 4.3.0
 */
public final class ServerLifecycle {

    /** Possible states of the server. */
    public enum State { STOPPED, STARTING, RUNNING, STOPPING }

    private final ServerTransport transport;
    private final AtomicReference<State> state = new AtomicReference<>(State.STOPPED);
    private volatile HttpServer server;
    private Executor executor;
    private int stopDelay = 1;

    /**
     * Create a lifecycle manager for the given transport.
     *
     * @param transport the transport binding to use
     */
    public ServerLifecycle(ServerTransport transport) {
        this.transport = transport;
    }

    /**
     * Set the executor for handling HTTP requests. Call before {@link #start}.
     * If null, the JDK default (single-threaded) executor is used.
     *
     * @param executor the request executor, or null for default
     * @return this lifecycle for chaining
     */
    public ServerLifecycle setExecutor(Executor executor) {
        this.executor = executor;
        return this;
    }

    /**
     * Set the graceful stop delay in seconds (default: 1).
     *
     * @param seconds seconds to wait for in-flight requests during stop
     * @return this lifecycle for chaining
     */
    public ServerLifecycle setStopDelay(int seconds) {
        this.stopDelay = seconds;
        return this;
    }

    /**
     * Create the server, invoke the endpoint registrar, and start listening.
     *
     * @param registrar callback that registers endpoint handlers on the server
     * @throws IOException if the server cannot be created
     * @throws IllegalStateException if the server is already running
     */
    public void start(Consumer<HttpServer> registrar) throws IOException {
        if (!state.compareAndSet(State.STOPPED, State.STARTING)) {
            throw new IllegalStateException("Server is already " + state.get());
        }
        try {
            HttpServer httpServer = transport.createServer(0);
            httpServer.setExecutor(executor);
            registrar.accept(httpServer);
            httpServer.start();
            this.server = httpServer;
            state.set(State.RUNNING);
        } catch (Exception e) {
            state.set(State.STOPPED);
            if (e instanceof IOException) throw (IOException) e;
            throw new IOException("Failed to start server", e);
        }
    }

    /**
     * Stop the server gracefully.
     */
    public void stop() {
        if (!state.compareAndSet(State.RUNNING, State.STOPPING)) {
            return; // Already stopped or stopping
        }
        try {
            if (server != null) {
                server.stop(stopDelay);
                try { Thread.sleep(100); } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
                server = null;
            }
        } finally {
            state.set(State.STOPPED);
        }
    }

    /**
     * Stop and restart the server with the same registrar.
     *
     * @param registrar callback that registers endpoint handlers
     * @throws IOException if the server cannot be restarted
     */
    public void restart(Consumer<HttpServer> registrar) throws IOException {
        stop();
        // Brief pause to allow port release
        try { Thread.sleep(500); } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        start(registrar);
    }

    /** Current state of the server. */
    public State getState() {
        return state.get();
    }

    /** Whether the server is currently running. */
    public boolean isRunning() {
        return state.get() == State.RUNNING;
    }

    /** The transport this lifecycle manages. */
    public ServerTransport getTransport() {
        return transport;
    }

    /**
     * Get the underlying HttpServer, or null if not running.
     * Primarily for registering additional contexts after start.
     */
    public HttpServer getServer() {
        return server;
    }
}
