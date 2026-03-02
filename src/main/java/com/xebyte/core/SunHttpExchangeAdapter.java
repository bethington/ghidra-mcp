package com.xebyte.core;

import com.sun.net.httpserver.Headers;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;

/**
 * Wraps {@link com.sun.net.httpserver.HttpExchange} as a {@link HttpExchange}.
 * Thin delegation so headless server (which uses Sun HTTP) can share dispatch
 * infrastructure with the GUI plugin (which uses UDS).
 */
public class SunHttpExchangeAdapter implements HttpExchange {

    private final com.sun.net.httpserver.HttpExchange delegate;

    public SunHttpExchangeAdapter(com.sun.net.httpserver.HttpExchange delegate) {
        this.delegate = delegate;
    }

    @Override public String getRequestMethod()   { return delegate.getRequestMethod(); }
    @Override public URI getRequestURI()          { return delegate.getRequestURI(); }
    @Override public Headers getRequestHeaders()  { return delegate.getRequestHeaders(); }
    @Override public InputStream getRequestBody() { return delegate.getRequestBody(); }
    @Override public Headers getResponseHeaders() { return delegate.getResponseHeaders(); }

    @Override
    public void sendResponseHeaders(int code, long length) throws IOException {
        delegate.sendResponseHeaders(code, length);
    }

    @Override
    public OutputStream getResponseBody() {
        return delegate.getResponseBody();
    }

    @Override
    public void close() throws IOException {
        delegate.close();
    }
}
