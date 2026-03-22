package com.xebyte.core;

import com.sun.net.httpserver.Headers;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;

/**
 * Adapts Unix domain socket channel I/O to an interface compatible with
 * {@link com.sun.net.httpserver.HttpExchange}, so existing handler code
 * works with minimal changes.
 *
 * This is intentionally NOT a subclass of HttpExchange (which is tightly
 * coupled to com.sun.net.httpserver internals). Instead, the ServerManager
 * handler lambdas accept this type directly.
 */
public class UdsHttpExchange implements HttpExchange {

    private final String method;
    private final URI requestUri;
    private final Headers requestHeaders;
    private final InputStream requestBody;
    private final OutputStream rawOutput;

    private Headers responseHeaders = new Headers();
    private ByteArrayOutputStream responseBuffer;
    private boolean headersSent = false;
    private int responseCode = 200;

    public UdsHttpExchange(String method, URI requestUri, Headers requestHeaders,
                           InputStream requestBody, OutputStream rawOutput) {
        this.method = method;
        this.requestUri = requestUri;
        this.requestHeaders = requestHeaders;
        this.requestBody = requestBody;
        this.rawOutput = rawOutput;
    }

    public String getRequestMethod() {
        return method;
    }

    public URI getRequestURI() {
        return requestUri;
    }

    public Headers getRequestHeaders() {
        return requestHeaders;
    }

    public InputStream getRequestBody() {
        return requestBody;
    }

    public Headers getResponseHeaders() {
        return responseHeaders;
    }

    /**
     * Send response headers. The length parameter follows the same convention
     * as {@link com.sun.net.httpserver.HttpExchange#sendResponseHeaders}:
     * positive = exact content length, 0 = chunked (we buffer), -1 = no body.
     */
    public void sendResponseHeaders(int code, long length) throws IOException {
        this.responseCode = code;
        this.headersSent = true;

        if (length == -1) {
            // No body — write headers immediately and close
            writeHeaders(0);
        } else {
            // We'll write headers once we have the body
            responseBuffer = new ByteArrayOutputStream((int) Math.max(length, 256));
        }
    }

    /**
     * Returns a stream that collects the response body.
     * The actual write happens in {@link #close()}.
     */
    public OutputStream getResponseBody() {
        if (responseBuffer == null) {
            responseBuffer = new ByteArrayOutputStream(256);
        }
        return responseBuffer;
    }

    @Override
    public void close() throws IOException {
        try {
            if (requestBody != null) {
                requestBody.close();
            }
            if (responseBuffer != null) {
                byte[] body = responseBuffer.toByteArray();
                writeHeaders(body.length);
                rawOutput.write(body);
            } else if (!headersSent) {
                // No sendResponseHeaders called — send empty 200
                writeHeaders(0);
            }
            rawOutput.flush();
        } finally {
            rawOutput.close();
        }
    }

    private void writeHeaders(int contentLength) throws IOException {
        StringBuilder sb = new StringBuilder();
        sb.append("HTTP/1.1 ").append(responseCode).append(" ")
          .append(reasonPhrase(responseCode)).append("\r\n");
        sb.append("Content-Length: ").append(contentLength).append("\r\n");
        sb.append("Connection: close\r\n");

        for (var entry : responseHeaders.entrySet()) {
            for (String val : entry.getValue()) {
                sb.append(entry.getKey()).append(": ").append(val).append("\r\n");
            }
        }
        sb.append("\r\n");
        rawOutput.write(sb.toString().getBytes(StandardCharsets.US_ASCII));
    }

    private static String reasonPhrase(int code) {
        return switch (code) {
            case 200 -> "OK";
            case 400 -> "Bad Request";
            case 404 -> "Not Found";
            case 500 -> "Internal Server Error";
            default -> "OK";
        };
    }
}
