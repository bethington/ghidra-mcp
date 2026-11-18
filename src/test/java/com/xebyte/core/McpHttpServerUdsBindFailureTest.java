package com.xebyte.core;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.Map;
import java.util.stream.Stream;

import static org.junit.Assert.*;

/**
 * #657: {@code startUds} assigned the {@code uds} field before {@code start()} bound,
 * so a failed bind left it non-null. {@code start()}'s "nothing came up" check never
 * fired, {@code socketPath()} returned a dead path, and the headless server printed
 * "Serving on" it and stayed up in socket-only mode with no listener at all.
 *
 * <p>The bind is made to fail portably by putting a non-empty DIRECTORY where the
 * socket file goes: {@code UdsHttpServer.start()} begins by deleting a stale socket
 * there, which cannot delete a non-empty directory -- the failure happens inside
 * {@code start()}, after the old code had already assigned the field.
 */
public class McpHttpServerUdsBindFailureTest {

    private Path socketDir;
    private McpHttpServer server;

    @Before
    public void blockTheSocketPath() throws IOException {
        socketDir = Files.createTempDirectory("ghidra-mcp-uds-fail");
        Path blocker = socketDir.resolve("ghidra-" + ProcessHandle.current().pid() + ".sock");
        Files.createDirectories(blocker);
        Files.writeString(blocker.resolve("keep"), "not a socket");
        server = new McpHttpServer("headless", Map::of);
        server.setSocketDirForTest(socketDir);
    }

    @After
    public void cleanUp() throws IOException {
        if (server != null) {
            server.stop();
        }
        try (Stream<Path> walk = Files.walk(socketDir)) {
            walk.sorted(Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
        }
    }

    @Test
    public void socketOnlyStartFailsWhenTheSocketDoesNotBind() {
        IOException e = assertThrows(IOException.class, () -> server.start(
            new McpHttpServer.Config(true, false, "127.0.0.1", 0, 1, 2)));

        assertTrue("the failure names the socket path: " + e.getMessage(),
            e.getMessage().contains(socketDir.toString()));
        assertNull(server.socketPath());
        assertFalse(server.isRunning());
    }

    @Test
    public void tcpSurvivesAndOnlyTcpIsReportedWhenTheSocketDoesNotBind() throws IOException {
        server.start(new McpHttpServer.Config(true, true, "127.0.0.1", 0, 1, 2));

        assertNull("a socket that did not bind must not be advertised", server.socketPath());
        assertTrue("TCP bound a real port", server.tcpPort() > 0);
        assertTrue(server.isRunning());
    }

    @Test
    public void socketBindsWhenThePathIsFree() throws IOException {
        Path blocker = socketDir.resolve("ghidra-" + ProcessHandle.current().pid() + ".sock");
        Files.delete(blocker.resolve("keep"));
        Files.delete(blocker);

        try {
            server.start(new McpHttpServer.Config(true, false, "127.0.0.1", 0, 1, 2));
        } catch (IOException e) {
            // AF_UNIX is unavailable on Windows before 10 1803; nothing here to test then.
            org.junit.Assume.assumeNoException(e);
        }
        assertEquals(blocker, server.socketPath());
        assertTrue(server.isRunning());
    }
}
