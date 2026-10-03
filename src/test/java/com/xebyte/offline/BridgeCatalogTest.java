package com.xebyte.offline;

import com.google.gson.GsonBuilder;
import com.google.gson.JsonParser;
import com.xebyte.core.AnnotationScanner;
import com.xebyte.core.ManualToolDescriptors;
import com.xebyte.core.PromptPolicyService;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import junit.framework.TestCase;

/** The wheel's offline MCP contract is generated from the extension descriptors. */
public class BridgeCatalogTest extends TestCase {
    public void testBundledCatalogMatchesDescriptors() throws Exception {
        var services = new ArrayList<Object>(Arrays.asList(ServiceFactory.buildAllServices()));
        services.add(new PromptPolicyService());
        var scanner = new AnnotationScanner(ServiceFactory.stubProvider(), services.toArray());
        ManualToolDescriptors.addAll(scanner, ManualToolDescriptors.knownPaths().toArray(String[]::new));
        var schema = JsonParser.parseString(scanner.generateSchema());
        Path path = Path.of("python/bridge_mcp_ghidra/tool_catalog.json");
        if (Boolean.getBoolean("updateBridgeCatalog")) {
            Files.writeString(path, new GsonBuilder().setPrettyPrinting().disableHtmlEscaping()
                .create().toJson(schema) + "\n");
        }
        assertTrue("Generate catalog: mvn -Dtest=BridgeCatalogTest -DupdateBridgeCatalog=true test", Files.exists(path));
        assertEquals("Bundled bridge catalog is stale", schema, JsonParser.parseString(Files.readString(path)));
    }
}
