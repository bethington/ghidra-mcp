package com.xebyte.offline;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.xebyte.core.AnnotationScanner;
import com.xebyte.core.ProgramProvider;
import junit.framework.TestCase;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * One-shot regenerator for {@code tests/endpoints.json}.
 *
 * <p>Normally skipped. Run only when the catalog has drifted and you want
 * to rewrite it from the annotation scanner (the source of truth):
 *
 * <pre>{@code
 *   mvn test -Dtest=RegenerateEndpointsJson -Dregenerate=true
 * }</pre>
 *
 * <p>Merge rules:
 * <ul>
 *   <li>For every {@code @McpTool}-scanned endpoint: write/overwrite the entry
 *       with scanner data (path, method, params, category). Description is
 *       preserved from the existing catalog if present; otherwise taken from
 *       the scanner.</li>
 *   <li>For every existing catalog entry that is NOT annotation-scanned
 *       (e.g. hand-registered routes like {@code /check_connection} or
 *       {@code /server/checkouts}): kept verbatim.</li>
 *   <li>Output is sorted by path for a stable diff.</li>
 * </ul>
 */
public class RegenerateEndpointsJson extends TestCase {

    private static final String CATALOG_PATH = "tests/endpoints.json";

    public void testRegenerateIfRequested() throws IOException {
        if (!"true".equalsIgnoreCase(System.getProperty("regenerate"))) {
            // Skipped by default — normal mvn test runs don't rewrite the catalog.
            return;
        }

        // 1. Load existing catalog preserving top-level metadata.
        String raw = Files.readString(Paths.get(CATALOG_PATH));
        JsonObject root = new Gson().fromJson(raw, JsonObject.class);

        Map<String, JsonObject> existingByPath = new LinkedHashMap<>();
        for (JsonElement el : root.getAsJsonArray("endpoints")) {
            JsonObject obj = el.getAsJsonObject();
            existingByPath.put(obj.get("path").getAsString(), obj);
        }

        // 2. Scan services for annotation-backed endpoints.
        ProgramProvider provider = ServiceFactory.stubProvider();
        AnnotationScanner scanner = new AnnotationScanner(provider, ServiceFactory.buildAllServices());

        // 3. Merge. Keyed by path so hand-registered entries survive untouched.
        Map<String, JsonObject> merged = new TreeMap<>(existingByPath);

        int added = 0;
        int updated = 0;
        for (AnnotationScanner.ToolDescriptor tool : scanner.getDescriptors()) {
            JsonObject existing = merged.get(tool.path());
            JsonObject next = new JsonObject();
            next.addProperty("path", tool.path());
            next.addProperty("method", tool.method());

            // Category: prefer existing if set (some hand-curated entries have
            // more specific categories than the default class name).
            String category;
            if (existing != null && existing.has("category")
                    && !existing.get("category").getAsString().isEmpty()) {
                category = existing.get("category").getAsString();
            } else {
                category = tool.category() != null ? tool.category() : "";
            }
            next.addProperty("category", category);

            // Params list = scanner's param names in declaration order.
            JsonArray params = new JsonArray();
            for (AnnotationScanner.ParamDescriptor p : tool.params()) {
                params.add(p.name());
            }
            next.add("params", params);

            // Description: prefer existing non-empty description (they are
            // hand-authored and more informative than the @McpTool description),
            // fall back to scanner description.
            String description;
            if (existing != null && existing.has("description")
                    && !existing.get("description").getAsString().isEmpty()) {
                description = existing.get("description").getAsString();
            } else {
                description = tool.description() != null ? tool.description() : "";
            }
            next.addProperty("description", description);

            if (existing == null) {
                added++;
            } else if (!existing.toString().equals(next.toString())) {
                updated++;
            }
            merged.put(tool.path(), next);
        }

        // 4. Build output: preserve top-level metadata, replace endpoints array.
        JsonArray outArr = new JsonArray();
        List<String> sortedPaths = new ArrayList<>(merged.keySet());
        for (String p : sortedPaths) {
            outArr.add(merged.get(p));
        }

        // Preserve ordering of top-level fields: version, description, total_endpoints, categories, endpoints.
        JsonObject out = new JsonObject();
        if (root.has("version")) out.add("version", root.get("version"));
        if (root.has("description")) out.add("description", root.get("description"));
        out.addProperty("total_endpoints", outArr.size());
        if (root.has("categories")) out.add("categories", root.get("categories"));
        out.add("endpoints", outArr);

        // 5. Pretty-print (Gson default is 2-space indent) and write.
        Gson pretty = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();
        String json = pretty.toJson(out);
        Path target = Paths.get(CATALOG_PATH);
        Files.writeString(target, json + "\n");

        System.out.println("\nRegenerated " + CATALOG_PATH + ":");
        System.out.println("  total entries: " + outArr.size());
        System.out.println("  added from scanner: " + added);
        System.out.println("  updated from scanner: " + updated);
        System.out.println("  preserved (hand-registered): "
            + (outArr.size() - scanner.getDescriptors().size()));
    }
}
