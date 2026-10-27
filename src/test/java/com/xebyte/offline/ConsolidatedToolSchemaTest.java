package com.xebyte.offline;

import com.google.gson.*;
import com.xebyte.core.*;
import org.junit.Test;
import java.net.URI;
import java.net.http.*;
import java.nio.file.*;
import java.util.*;
import static org.junit.Assert.*;

/** The consolidated surface as actually served over HTTP by this build. */
public class ConsolidatedToolSchemaTest {
    @Test public void servedGuiSchemaUsesOnlyConsolidatedTools() throws Exception {
        AnnotationScanner scanner = ServiceFactory.buildGuiScanner();
        McpHttpServer server = new McpHttpServer("gui", Map::of);
        server.endpoints(scanner);
        try {
            server.start(new McpHttpServer.Config(false, true, "127.0.0.1", 0, 1, 2));
            HttpResponse<String> response = HttpClient.newHttpClient().send(
                HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + server.tcpPort() + "/mcp/schema")).GET().build(),
                HttpResponse.BodyHandlers.ofString());
            assertEquals(200, response.statusCode());
            JsonObject schema = JsonParser.parseString(response.body()).getAsJsonObject();
            Set<String> paths = new HashSet<>();
            for (JsonElement tool : schema.getAsJsonArray("tools")) {
                paths.add(tool.getAsJsonObject().get("path").getAsString());
            }
            assertTrue(paths.contains("/set_equate"));
            for (String retired : List.of("/list_equates", "/apply_equate", "/remove_equate",
                    "/rename_equate", "/list_decompiler_variables", "/apply_local_variable")) {
                assertFalse("retired tool still advertised: " + retired, paths.contains(retired));
            }
            assertFalse(paths.contains("/decompile_tree_refresh"));
            Path output = Path.of(System.getProperty("project.basedir"), "build", "generated", "gui-schema.json");
            Files.createDirectories(output.getParent());
            Files.writeString(output, response.body());
        } finally {
            server.stop();
        }
    }
}
