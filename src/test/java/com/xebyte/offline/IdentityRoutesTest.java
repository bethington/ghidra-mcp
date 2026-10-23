package com.xebyte.offline;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.xebyte.core.AnnotationScanner;
import com.xebyte.core.McpHttpServer;
import com.xebyte.core.ProgramProvider;
import com.xebyte.core.VersionInfo;
import ghidra.program.model.listing.Program;
import org.junit.Test;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

/**
 * Both servers answer "who are you, and are you alive" identically, bar server_kind.
 *
 * <p>They used not to share a single identity route: /check_connection was plain text
 * in a different format on each, /health existed only headless and /mcp/health only on
 * the GUI, and the headless version was a hard-coded "7.0.0-headless". The doctor tool
 * told the two apart by sniffing English, and the integration suite's liveness probe
 * (/mcp/health) saw every headless server as down.
 */
public class IdentityRoutesTest {

    private static JsonObject get(int port, String path) throws Exception {
        HttpResponse<String> r = HttpClient.newHttpClient().send(
            HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + path)).GET().build(),
            HttpResponse.BodyHandlers.ofString());
        assertEquals(path, 200, r.statusCode());
        return JsonParser.parseString(r.body()).getAsJsonObject();
    }

    /** The three identity routes of a server of this kind with one current program. */
    private static Map<String, JsonObject> identity(String kind) throws Exception {
        Program current = mock(Program.class);
        when(current.getName()).thenReturn("a.dll");
        return identity(kind, current);
    }

    private static Map<String, JsonObject> identity(String kind, Program current) throws Exception {
        ProgramProvider provider = mock(ProgramProvider.class);
        when(provider.getCurrentProgram()).thenReturn(current);
        when(provider.getAllOpenPrograms())
            .thenReturn(current != null ? new Program[] {current} : new Program[0]);

        McpHttpServer server = new McpHttpServer(kind, Map::of);
        server.endpoints(new AnnotationScanner(provider));
        server.start(new McpHttpServer.Config(false, true, "127.0.0.1", 0, 1, 2));
        try {
            int port = server.tcpPort();
            return Map.of(
                "/check_connection", get(port, "/check_connection"),
                "/mcp/health", get(port, "/mcp/health"),
                "/mcp/instance_info", get(port, "/mcp/instance_info"));
        } finally {
            server.stop();
        }
    }

    @Test
    public void bothKindsAnswerTheSameShapeAndSayWhichTheyAre() throws Exception {
        Map<String, JsonObject> gui = identity("gui");
        Map<String, JsonObject> headless = identity("headless");
        for (String path : gui.keySet()) {
            assertEquals(path + " must have the same fields on both servers",
                new TreeSet<>(gui.get(path).keySet()), new TreeSet<>(headless.get(path).keySet()));
            assertEquals(path, "gui", gui.get(path).get("server_kind").getAsString());
            assertEquals(path, "headless", headless.get(path).get("server_kind").getAsString());
        }
    }

    @Test
    public void checkConnectionIsJsonNamingTheBuildAndProgram() throws Exception {
        JsonObject c = identity("headless").get("/check_connection");
        assertEquals(Set.of("status", "server_kind", "version", "program"), c.keySet());
        assertEquals("ok", c.get("status").getAsString());
        assertEquals(VersionInfo.getVersion(), c.get("version").getAsString());
        assertFalse("never the old hard-coded suffix", c.get("version").getAsString().endsWith("-headless"));
        assertEquals("a.dll", c.get("program").getAsString());
    }

    @Test
    public void withNoCurrentProgramTheProgramFieldIsAbsent() throws Exception {
        // Null fields are omitted across the API, so "no program" is an absent key.
        JsonObject c = identity("headless", null).get("/check_connection");
        assertEquals(Set.of("status", "server_kind", "version"), c.keySet());
    }

    @Test
    public void instanceInfoCarriesKindVersionAndItsOwnPort() throws Exception {
        JsonObject info = identity("headless").get("/mcp/instance_info");
        assertEquals(VersionInfo.getVersion(), info.get("version").getAsString());
        assertTrue(info.has("endpoint_count"));
        assertTrue("port 0 must report the port actually bound", info.get("tcp_port").getAsInt() > 0);
    }
}
