package com.xebyte.core.vuln;

import com.xebyte.core.JsonHelper;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionTag;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.regex.Pattern;

/**
 * Loads the baked-in vuln_catalog.json resource, optionally merges a user
 * override file (entries with the same id replace the default), and resolves
 * a Function to the catalog entries it matches via import-name ∪ regex ∪ tag.
 */
public final class SinkCatalog {

    private static final String RESOURCE = "/com/xebyte/vuln_catalog.json";
    private static final String[] ARG_ROLE_KEYS =
        {"fmt_arg", "size_arg", "dst_arg", "cmd_arg", "out_arg"};

    private final Map<String, CatalogEntry> byId = new LinkedHashMap<>();
    private final Map<String, Pattern> regexCache;
    private final String status;

    private SinkCatalog(List<CatalogEntry> entries, String status) {
        for (CatalogEntry e : entries) byId.put(e.id(), e);
        Map<String, Pattern> rc = new HashMap<>();
        StringBuilder badRe = null;
        for (CatalogEntry e : byId.values()) {
            for (String r : e.matchRegex()) {
                if (rc.containsKey(r)) continue;
                try { rc.put(r, Pattern.compile(r)); }
                catch (java.util.regex.PatternSyntaxException ex) {
                    if (badRe == null) badRe = new StringBuilder();
                    if (badRe.length() > 0) badRe.append("; ");
                    badRe.append("regex '" + r + "': " + ex.getDescription());
                }
            }
        }
        this.regexCache = Map.copyOf(rc);
        if (badRe != null) {
            status = (status == null ? "" : status + "; ") + "invalid regex skipped — " + badRe;
        }
        this.status = status;
    }

    public static SinkCatalog load(String overridePath) {
        List<CatalogEntry> entries = new ArrayList<>();
        String warn = null;
        try (InputStream in = SinkCatalog.class.getResourceAsStream(RESOURCE)) {
            if (in == null) throw new IllegalStateException("missing resource " + RESOURCE);
            String json = new String(in.readAllBytes(), StandardCharsets.UTF_8);
            entries.addAll(parse(json));
        } catch (Exception e) {
            throw new IllegalStateException("failed to load baked-in vuln catalog: " + e.getMessage(), e);
        }
        if (overridePath != null && !overridePath.isBlank()) {
            try {
                String json = Files.readString(Path.of(overridePath), StandardCharsets.UTF_8);
                List<CatalogEntry> over = parse(json);
                Map<String, CatalogEntry> merged = new LinkedHashMap<>();
                for (CatalogEntry e : entries) merged.put(e.id(), e);
                for (CatalogEntry e : over)    merged.put(e.id(), e);
                entries = new ArrayList<>(merged.values());
            } catch (Exception e) {
                warn = "override '" + overridePath + "' ignored: " + e.getMessage();
            }
        }
        return new SinkCatalog(entries, warn);
    }

    public static String defaultOverridePath() {
        String env = System.getenv("GHIDRA_MCP_VULN_CATALOG");
        if (env != null && !env.isBlank()) return env;
        String home = System.getProperty("user.home");
        if (home == null) return null;
        Path p = Path.of(home, ".ghidra-mcp", "vuln_catalog.json");
        return Files.isReadable(p) ? p.toString() : null;
    }

    public String status()                  { return status; }
    public CatalogEntry byId(String id)      { return byId.get(id); }
    public Collection<CatalogEntry> all()    { return java.util.Collections.unmodifiableCollection(byId.values()); }
    public List<CatalogEntry> sinks()        { return filterKind("sink"); }
    public List<CatalogEntry> sources()      { return filterKind("source"); }

    public List<CatalogEntry> resolve(Function f) {
        if (f == null) return List.of();
        if (f.isThunk()) {
            Function real = f.getThunkedFunction(true);
            if (real != null) f = real;
        }
        String name = f.getName();
        Set<String> tags = new HashSet<>();
        for (FunctionTag t : f.getTags()) tags.add(t.getName());

        List<CatalogEntry> hits = new ArrayList<>();
        for (CatalogEntry e : byId.values()) {
            if (contains(e.matchImport(), name))            { hits.add(e); continue; }
            if (matchesAnyRegex(e.matchRegex(), name))       { hits.add(e); continue; }
            if (!Collections.disjoint(tags, e.matchTag()))   { hits.add(e); continue; }
        }
        return hits;
    }

    private List<CatalogEntry> filterKind(String kind) {
        List<CatalogEntry> out = new ArrayList<>();
        for (CatalogEntry e : byId.values()) if (e.kind().equals(kind)) out.add(e);
        return out;
    }

    private static boolean contains(List<String> list, String name) {
        if (list == null) return false;
        for (String s : list) if (s.equalsIgnoreCase(name)) return true;
        return false;
    }

    private boolean matchesAnyRegex(List<String> regexes, String name) {
        if (regexes == null) return false;
        for (String r : regexes) {
            Pattern p = regexCache.get(r);
            if (p != null && p.matcher(name).find()) return true;
        }
        return false;
    }

    @SuppressWarnings("unchecked")
    private static List<CatalogEntry> parse(String json) {
        Map<String, Object> root = JsonHelper.parseJson(json);
        if (root.isEmpty()) throw new IllegalArgumentException("empty or invalid catalog JSON");
        List<CatalogEntry> out = new ArrayList<>();
        out.addAll(parseList((List<Map<String, Object>>) root.getOrDefault("sinks",   List.of()), "sink"));
        out.addAll(parseList((List<Map<String, Object>>) root.getOrDefault("sources", List.of()), "source"));
        return out;
    }

    @SuppressWarnings("unchecked")
    private static List<CatalogEntry> parseList(List<Map<String, Object>> rows, String kind) {
        List<CatalogEntry> out = new ArrayList<>();
        for (Map<String, Object> row : rows) {
            Object idObj = row.get("id");
            if (idObj == null) continue;
            String id = String.valueOf(idObj);
            Object clsObj = row.get("class");
            if (clsObj == null) continue;
            String cls = String.valueOf(clsObj);
            Map<String, Integer> roles = new LinkedHashMap<>();
            for (String k : ARG_ROLE_KEYS) {
                Object v = row.get(k);
                if (v instanceof Number n) roles.put(k, n.intValue());
            }
            boolean retOut = Boolean.TRUE.equals(row.get("return"));
            Map<String, Object> match = (Map<String, Object>) row.getOrDefault("match", Map.of());
            out.add(new CatalogEntry(id, kind, cls, Map.copyOf(roles), retOut,
                List.copyOf(strList(match.get("import"))),
                List.copyOf(strList(match.get("regex"))),
                List.copyOf(strList(match.get("tag")))));
        }
        return out;
    }

    @SuppressWarnings("unchecked")
    private static List<String> strList(Object o) {
        if (o instanceof String s) return List.of(s);
        if (o instanceof List<?> l) {
            List<String> out = new ArrayList<>(l.size());
            for (Object x : l) out.add(String.valueOf(x));
            return out;
        }
        return List.of();
    }
}
