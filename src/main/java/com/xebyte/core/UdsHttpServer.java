package com.xebyte.core;

import com.sun.net.httpserver.Headers;
import ghidra.util.Msg;

import java.io.*;
import java.net.StandardProtocolFamily;
import java.net.URI;
import java.nio.channels.Channels;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.net.UnixDomainSocketAddress;

/**
 * Minimal HTTP/1.1 server over Unix domain sockets (Java 16+).
 *
 * Supports the same {@code createContext(path, handler)} pattern as
 * {@link com.sun.net.httpserver.HttpServer}, but uses a
 * {@link UdsHttpExchange} instead of the Sun-internal HttpExchange.
 *
 * Only enough HTTP is implemented to handle GhidraMCP's request patterns:
 * GET with query params, POST with URL-encoded or JSON body, and simple
 * text/JSON responses.
 */
public class UdsHttpServer {

    @FunctionalInterface
    public interface Handler {
        void handle(HttpExchange exchange) throws IOException;
    }

    private final Path socketPath;
    private ServerSocketChannel serverChannel;
    private ExecutorService executor;
    private final Map<String, Handler> contexts = new ConcurrentHashMap<>();
    private volatile boolean running;

    public UdsHttpServer(Path socketPath) {
        this.socketPath = socketPath;
    }

    public void createContext(String path, Handler handler) {
        contexts.put(path, handler);
    }

    public void removeContext(String path) {
        contexts.remove(path);
    }

    public Path getSocketPath() {
        return socketPath;
    }

    public void start() throws IOException {
        // Clean up stale socket file
        Files.deleteIfExists(socketPath);

        // Create parent directories
        Files.createDirectories(socketPath.getParent());

        serverChannel = ServerSocketChannel.open(StandardProtocolFamily.UNIX);
        serverChannel.bind(UnixDomainSocketAddress.of(socketPath));

        executor = Executors.newCachedThreadPool(r -> {
            Thread t = new Thread(r, "GhidraMCP-UDS-Worker");
            t.setDaemon(true);
            return t;
        });

        running = true;

        Thread acceptThread = new Thread(this::acceptLoop, "GhidraMCP-UDS-Accept");
        acceptThread.setDaemon(true);
        acceptThread.start();

        Msg.info(this, "UDS HTTP server listening on " + socketPath);
    }

    public void stop() {
        running = false;
        try {
            if (serverChannel != null) {
                serverChannel.close();
            }
        } catch (IOException e) {
            Msg.warn(this, "Error closing server channel: " + e.getMessage());
        }
        if (executor != null) {
            executor.shutdown();
            try {
                if (!executor.awaitTermination(5, TimeUnit.SECONDS)) {
                    executor.shutdownNow();
                }
            } catch (InterruptedException e) {
                executor.shutdownNow();
                Thread.currentThread().interrupt();
            }
        }
        try {
            Files.deleteIfExists(socketPath);
        } catch (IOException e) {
            Msg.warn(this, "Could not delete socket file: " + e.getMessage());
        }
        Msg.info(this, "UDS HTTP server stopped");
    }

    private void acceptLoop() {
        while (running) {
            try {
                SocketChannel client = serverChannel.accept();
                executor.submit(() -> handleConnection(client));
            } catch (IOException e) {
                if (running) {
                    Msg.error(this, "Accept error: " + e.getMessage());
                }
                // If !running, the channel was closed intentionally
            }
        }
    }

    private void handleConnection(SocketChannel channel) {
        try (channel) {
            InputStream in = new BufferedInputStream(Channels.newInputStream(channel));
            OutputStream out = new BufferedOutputStream(Channels.newOutputStream(channel));

            // Parse request line: "GET /path?query HTTP/1.1\r\n"
            String requestLine = readLine(in);
            if (requestLine == null || requestLine.isEmpty()) {
                return;
            }

            String[] parts = requestLine.split(" ", 3);
            if (parts.length < 2) {
                sendError(out, 400, "Bad request line");
                return;
            }
            String method = parts[0];
            String rawPath = parts[1];

            // Parse headers
            Headers headers = new Headers();
            String headerLine;
            while ((headerLine = readLine(in)) != null && !headerLine.isEmpty()) {
                int colonIdx = headerLine.indexOf(':');
                if (colonIdx > 0) {
                    String name = headerLine.substring(0, colonIdx).trim();
                    String value = headerLine.substring(colonIdx + 1).trim();
                    headers.add(name, value);
                }
            }

            // Read body if Content-Length present
            int contentLength = 0;
            String clHeader = headers.getFirst("Content-Length");
            if (clHeader == null) clHeader = headers.getFirst("content-length");
            if (clHeader != null) {
                try {
                    contentLength = Integer.parseInt(clHeader.trim());
                } catch (NumberFormatException ignored) {
                }
            }

            byte[] body = new byte[0];
            if (contentLength > 0) {
                body = in.readNBytes(contentLength);
            }

            // Build URI — the raw path from the request line is already encoded
            URI uri = URI.create("http://localhost" + rawPath);
            String path = uri.getPath();

            // Route to handler (longest prefix match)
            Handler handler = contexts.get(path);
            if (handler == null) {
                // Try prefix matching
                String bestMatch = null;
                for (String ctx : contexts.keySet()) {
                    if (path.startsWith(ctx)) {
                        if (bestMatch == null || ctx.length() > bestMatch.length()) {
                            bestMatch = ctx;
                        }
                    }
                }
                if (bestMatch != null) {
                    handler = contexts.get(bestMatch);
                }
            }

            if (handler == null) {
                sendError(out, 404, "No handler for " + path);
                return;
            }

            ByteArrayInputStream bodyStream = new ByteArrayInputStream(body);
            UdsHttpExchange exchange = new UdsHttpExchange(method, uri, headers, bodyStream, out);

            try {
                handler.handle(exchange);
            } finally {
                exchange.close();
            }

        } catch (IOException e) {
            Msg.error(this, "Connection error: " + e.getMessage());
        } catch (Exception e) {
            Msg.error(this, "Handler error: " + e.getMessage(), e);
        }
    }

    /**
     * Read a line terminated by \r\n from the input stream.
     * Returns null on EOF.
     */
    private String readLine(InputStream in) throws IOException {
        StringBuilder sb = new StringBuilder(128);
        int prev = -1;
        int c;
        while ((c = in.read()) != -1) {
            if (c == '\n' && prev == '\r') {
                // Remove trailing \r
                sb.setLength(sb.length() - 1);
                return sb.toString();
            }
            sb.append((char) c);
            prev = c;
        }
        return sb.length() > 0 ? sb.toString() : null;
    }

    private void sendError(OutputStream out, int code, String message) throws IOException {
        String body = "{\"error\": \"" + message.replace("\"", "\\\"") + "\"}";
        byte[] bodyBytes = body.getBytes(StandardCharsets.UTF_8);
        String response = "HTTP/1.1 " + code + " Error\r\n" +
                "Content-Type: application/json\r\n" +
                "Content-Length: " + bodyBytes.length + "\r\n" +
                "Connection: close\r\n" +
                "\r\n";
        out.write(response.getBytes(StandardCharsets.US_ASCII));
        out.write(bodyBytes);
        out.flush();
    }
}
