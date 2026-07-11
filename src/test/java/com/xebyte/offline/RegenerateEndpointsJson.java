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
import java.util.LinkedHashSet;
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
 *       with scanner data (path, method). Description and category are
 *       preserved from the existing catalog if non-empty; otherwise taken from
 *       the scanner. Params are an ordered-set union: scanner names in
 *       declaration order, then catalog-only names in their existing order,
 *       each emitted once (case-sensitive comparison). Catalog-only names may
 *       be hand-registered route extras (e.g. {@code /open_project}'s
 *       {@code headless}/{@code program}) or stale annotation names — they
 *       linger until removed by hand, and the run summary lists them per path
 *       for manual review. Silent loss is the failure mode this prevents.</li>
 *   <li>For every existing catalog entry that is NOT annotation-scanned
 *       (e.g. hand-registered routes like {@code /check_connection} or
 *       {@code /server/checkouts}): kept verbatim.</li>
 *   <li>Output is sorted by path for a stable diff.</li>
 * </ul>
 */
public class RegenerateEndpointsJson extends TestCase {

    private static final String CATALOG_PATH = "tests/endpoints.json";

    /** Result of merging one scanned tool with its existing catalog entry. */
    static final class MergeResult {
        final JsonObject entry;
        final List<String> retainedCatalogParams;

        MergeResult(JsonObject entry, List<String> retainedCatalogParams) {
            this.entry = entry;
            this.retainedCatalogParams = List.copyOf(retainedCatalogParams);
        }
    }

    /**
     * Build the regenerated catalog entry for one scanned tool. Pure: never mutates
     * {@code existing}, never prints. Params are the ordered-set union of scanner names
     * (declaration order) and catalog-only names (existing order); the latter are also
     * returned so the caller can report them.
     */
    static MergeResult mergeEntry(AnnotationScanner.ToolDescriptor tool, JsonObject existing) {
        JsonObject next = new JsonObject();
        next.addProperty("path", tool.path());
        next.addProperty("method", tool.method());

        String category;
        if (existing != null && existing.has("category")
                && !existing.get("category").getAsString().isEmpty()) {
            category = existing.get("category").getAsString();
        } else {
            category = tool.category() != null ? tool.category() : "";
        }
        next.addProperty("category", category);

        LinkedHashSet<String> names = new LinkedHashSet<>();
        for (AnnotationScanner.ParamDescriptor p : tool.params()) {
            names.add(p.name());
        }
        List<String> retained = new ArrayList<>();
        if (existing != null && existing.has("params")) {
            for (JsonElement el : existing.getAsJsonArray("params")) {
                String name = el.getAsString();
                if (names.add(name)) {
                    retained.add(name);
                }
            }
        }
        JsonArray params = new JsonArray();
        for (String name : names) {
            params.add(name);
        }
        next.add("params", params);

        String description;
        if (existing != null && existing.has("description")
                && !existing.get("description").getAsString().isEmpty()) {
            description = existing.get("description").getAsString();
        } else {
            description = tool.description() != null ? tool.description() : "";
        }
        next.addProperty("description", description);

        return new MergeResult(next, retained);
    }

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
        Map<String, List<String>> keptByPath = new LinkedHashMap<>();
        for (AnnotationScanner.ToolDescriptor tool : scanner.getDescriptors()) {
            // Look up the original catalog entry, not `merged`: if two descriptors ever shared a
            // path, merging against `merged` would self-union the first descriptor's output and
            // report its params as catalog-only.
            JsonObject existing = existingByPath.get(tool.path());
            MergeResult result = mergeEntry(tool, existing);

            if (existing == null) {
                added++;
            } else if (!existing.toString().equals(result.entry.toString())) {
                updated++;
            }
            if (!result.retainedCatalogParams.isEmpty()) {
                keptByPath.put(tool.path(), result.retainedCatalogParams);
            }
            merged.put(tool.path(), result.entry);
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
        for (Map.Entry<String, List<String>> e : keptByPath.entrySet()) {
            System.out.println("  kept catalog-only params: " + e.getKey() + " " + e.getValue());
        }
    }
}
