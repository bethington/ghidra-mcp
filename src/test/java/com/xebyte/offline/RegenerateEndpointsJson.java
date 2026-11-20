package com.xebyte.offline;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.xebyte.core.AnnotationScanner;
import com.xebyte.core.ManualToolDescriptors;
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
 *       with scanner data (path, method, category). The description is
 *       preserved from the existing catalog if non-empty; otherwise taken from
 *       the scanner. The category is NOT preserved — it names the tool group the
 *       bridge lazy-loads by, and only the annotation scan can say what that is.
 *       Params are an ordered-set union: scanner names in
 *       declaration order, then catalog-only names in their existing order,
 *       each emitted once (case-sensitive comparison). Catalog-only names may
 *       be hand-registered route extras (e.g. {@code /open_project}'s
 *       {@code headless}/{@code program}) or stale annotation names — they
 *       linger until removed by hand, and the run summary lists them per path
 *       for manual review. Silent loss is the failure mode this prevents. The
 *       {@code servers} field (which of the two HTTP servers registers the route) is
 *       preserved verbatim -- this regenerator scans the union of both servers'
 *       services and structurally cannot re-derive it; see
 *       {@code tools/audit_server_scope.py}, and re-run it after adding an
 *       endpoint so the new entry gets stamped.</li>
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

        // Category comes from the scanner, ALWAYS — never preserved from the catalog.
        // The category is not editorial metadata like the description: it is the tool
        // GROUP the bridge lazy-loads by, and the bridge reads it from /mcp/schema,
        // which the annotation scan produces. Preserving the catalog's value here is
        // what let 63 of 219 entries drift into a dead pre-tool-group vocabulary
        // (getter/rename/decompile/search/script) that no `load_tool_group` call can
        // ever name. To change a tool's group, change its @McpTool/@McpToolGroup
        // annotation; the catalog follows.
        next.addProperty("category", tool.category() != null ? tool.category() : "");

        LinkedHashSet<String> names = new LinkedHashSet<>();
        for (AnnotationScanner.ParamDescriptor p : tool.params()) {
            names.add(p.name());
            // Aliases are accepted argument names, so they belong in the catalog.
            // Without them the additive merge below was the ONLY thing keeping
            // e.g. /decompile_function's `address` listed -- which meant the merge
            // could never drop a genuinely removed parameter either.
            names.addAll(p.aliases());
        }
        List<String> retained = new ArrayList<>();
        // Only fall back to the catalog when the scanner knows of no params at
        // all: a hand-registered route with no descriptor to speak for it.
        // Retaining unconditionally makes the list grow-only, so a parameter
        // deleted from an @McpTool would be advertised forever (measured: the
        // `program` argument removed from /get_ui_cursor kept coming back).
        if (names.isEmpty() && existing != null && existing.has("params")) {
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

        // `servers` records which of the two HTTP servers actually registers this
        // route (see tools/audit_server_scope.py). It is carried through verbatim
        // rather than recomputed: the scanner this regenerator runs has no idea
        // which server would have constructed the service it just reflected over
        // -- it scans the union of both. Dropping it here would silently unstamp
        // 253 entries on every regeneration, so the field is preserved and
        // `tests/unit/test_audit_server_scope.py` fails if it goes stale. A newly
        // added endpoint arrives here with no `servers` at all; re-run
        // `python -m tools.audit_server_scope --write` after regenerating.
        if (existing != null && existing.has("servers")) {
            next.add("servers", existing.get("servers"));
        }

        String description;
        if (existing != null && existing.has("description")
                && !existing.get("description").getAsString().isEmpty()) {
            description = existing.get("description").getAsString();
        } else {
            description = tool.description() != null ? tool.description() : "";
        }
        next.addProperty("description", description);

        // Catalog keeps internal endpoints (bridge still calls them); schema omits them.
        if (tool.internal()) {
            next.addProperty("internal", true);
        }

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
        // Hand-registered routes are a SECOND authoritative source: /open_project,
        // for instance, is an @McpTool taking only `path` AND a GUI route taking
        // `path, headless, program`. Without these descriptors the regenerator sees
        // half the parameters and the catalog's own entries were the only record of
        // the rest -- which is why the param merge had to be grow-only, and why a
        // deleted parameter could never be removed.
        ManualToolDescriptors.addAll(scanner, ManualToolDescriptors.knownPaths());

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
