package com.xebyte.offline;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.xebyte.core.AnnotationScanner;
import com.xebyte.core.ManualToolDescriptors;
import junit.framework.TestCase;

import java.util.HashSet;
import java.util.Set;

/**
 * /mcp/schema advertises each path exactly once.
 *
 * <p>When the GUI's two transports were collapsed onto one scanner, the plugin's
 * buildScanner() added the hand-coded routes' descriptors and ServerManager added
 * them again to the same scanner, so every hand-coded route appeared twice in the
 * schema. The scanner now ignores a descriptor for a path it already has; this
 * pins both the double-add and the annotated-and-hand-described overlap.
 */
public class SchemaNoDuplicatePathsTest extends TestCase {

    private static Set<String> duplicatePaths(AnnotationScanner scanner) {
        JsonObject schema = JsonParser.parseString(scanner.generateSchema()).getAsJsonObject();
        Set<String> seen = new HashSet<>();
        Set<String> dups = new HashSet<>();
        for (JsonElement tool : schema.getAsJsonArray("tools")) {
            String path = tool.getAsJsonObject().get("path").getAsString();
            if (!seen.add(path)) {
                dups.add(path);
            }
        }
        return dups;
    }

    public void testSharedRoutesAddedTwiceAreListedOnce() {
        AnnotationScanner scanner = new AnnotationScanner(
            ServiceFactory.stubProvider(), ServiceFactory.buildAllServices());
        ManualToolDescriptors.addAll(scanner, ManualToolDescriptors.SHARED_ROUTES);
        ManualToolDescriptors.addAll(scanner, ManualToolDescriptors.SHARED_ROUTES);
        assertEquals(Set.of(), duplicatePaths(scanner));
    }

    public void testAnnotatedDescriptorWinsOverHandDescribedOne() {
        // The catalog regenerator scans both servers' services together, so a route
        // that is an @McpTool on one server and hand-coded on the other meets itself.
        AnnotationScanner scanner = new AnnotationScanner(
            ServiceFactory.stubProvider(), ServiceFactory.buildAllServices());
        int before = scanner.getDescriptors().size();
        ManualToolDescriptors.addAll(scanner, ManualToolDescriptors.knownPaths());
        assertEquals(Set.of(), duplicatePaths(scanner));
        assertTrue("manual descriptors for new paths must still be added",
            scanner.getDescriptors().size() > before);

        // ...and the one entry keeps both servers' parameters: /open_project is
        // annotated headless, while the GUI's hand-coded route adds two of its own.
        Set<String> openProjectParams = new HashSet<>();
        for (AnnotationScanner.ToolDescriptor d : scanner.getDescriptors()) {
            if (d.path().equals("/open_project")) {
                d.params().forEach(p -> openProjectParams.add(p.name()));
            }
        }
        assertTrue(openProjectParams.toString(),
            openProjectParams.containsAll(Set.of("path", "headless", "program")));
    }
}
