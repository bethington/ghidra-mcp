# VulnAnalysisService (Phase 1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `com.xebyte.core.vuln` package that surfaces intra-function vulnerability candidates from decompiler PCode — a source/sink catalog, four pattern detectors (format-string, unbounded-copy, int-overflow→alloc, command-injection), attack-surface enumeration, and a Finding/bookmark output schema.

**Architecture:** New service `VulnAnalysisService` (3 `@McpTool` endpoints) backed by `SinkCatalog` (JSON resource + user override, matches by import-name ∪ regex ∪ tag), `PcodeQuery` (static PCode helpers), a `VulnDetector` interface, and four small detector classes. The service decompiles a function once, resolves every `CALL` against the catalog into `SinkCallSite`s, and hands the relevant sites to each detector. Findings are returned as JSON and optionally written as `SEVR/<class>` Ghidra bookmarks.

**Tech Stack:** Java 21, Ghidra 12.x decompiler API (`HighFunction`/`PcodeOpAST`/`Varnode`), Gson (via `JsonHelper`), JUnit4 + Mockito, Gradle (Maven pins 12.1 — unusable on this 12.0.4 box).

**Spec:** `docs/superpowers/specs/2026-06-17-vuln-analysis-service-design.md`

---

## Environment notes (read before any task)

- **Java tests via Gradle, NOT Maven.** This box has Ghidra 12.0.4; the pom pins 12.1. Run tests with:
  `./gradlew test --tests '<pattern>' -PGHIDRA_INSTALL_DIR=$GHIDRA_INSTALL_DIR --console=plain`
- **No existing test mocks `HighFunction`/`PcodeOp`/`Varnode`.** Detector unit tests build minimal mock chains (a `PcodeOp` CALL whose `getInput(i)` returns mocked `Varnode`s with stubbed `getDef()`/`isConstant()`). This is feasible — each detector touches a bounded set of methods.
- **JSON parsing:** use `JsonHelper.parseJson(String) → Map<String,Object>` (Gson-backed, `JsonHelper.java:62`).
- **Resource loading:** `SinkCatalog.class.getResourceAsStream("/com/xebyte/vuln_catalog.json")` (pattern at `GhidraMCPPlugin.java:126`).
- **Service registration:** add to varargs at `GhidraMCPPlugin.java:635-639` and the headless equivalent (grep `new AnnotationScanner(` under `src/main/java/com/xebyte/headless/`).

## File Structure

| File | Responsibility | Task |
| --- | --- | --- |
| `src/main/java/com/xebyte/core/vuln/Finding.java` | Result record | 1 |
| `src/main/java/com/xebyte/core/vuln/CatalogEntry.java` | One catalog row (id, class, arg positions, match rules) | 1 |
| `src/main/java/com/xebyte/core/vuln/SinkCallSite.java` | Resolved `(PcodeOp call, CatalogEntry sink, Function callee, Address addr)` | 1 |
| `src/main/java/com/xebyte/core/vuln/VulnDetector.java` | Interface: `id()`, `sinkClasses()`, `scan(...)` | 1 |
| `src/main/resources/com/xebyte/vuln_catalog.json` | Baked-in default catalog | 2 |
| `src/main/java/com/xebyte/core/vuln/SinkCatalog.java` | Load resource + override; `resolve(Function)`; `sources()`/`sinks()` | 2 |
| `src/main/java/com/xebyte/core/vuln/PcodeQuery.java` | Static PCode helpers | 3 |
| `src/main/java/com/xebyte/core/vuln/detectors/FormatStringDetector.java` | `class:"format"` — non-constant fmt arg | 4 |
| `src/main/java/com/xebyte/core/vuln/detectors/CommandInjectionDetector.java` | `class:"exec"` — non-constant cmd arg | 4 |
| `src/main/java/com/xebyte/core/vuln/detectors/UnboundedCopyDetector.java` | `class:"copy"` — unchecked size into bounded dest | 5 |
| `src/main/java/com/xebyte/core/vuln/detectors/IntegerOverflowAllocDetector.java` | `class:"alloc"` — MULT/ADD into size w/o check | 6 |
| `src/main/java/com/xebyte/core/vuln/VulnAnalysisService.java` | 3 `@McpTool` endpoints, `scanFunction`, bookmark writer | 7-8 |
| `src/main/java/com/xebyte/GhidraMCPPlugin.java` (modify) | Register service in scanner varargs | 9 |
| `src/main/java/com/xebyte/headless/*` (modify) | Register service in headless scanner | 9 |
| `tests/endpoints.json` (regen) | 3 new endpoints | 9 |
| `tests/integration/test_vuln_endpoints.py` | Auto-skipping live tests | 10 |
| `fun-doc/benchmark/src/vuln_*.c` + `truth/vuln_*.truth.yaml` | Fixture sources w/ planted bugs | 10 |
| `src/test/java/com/xebyte/offline/vuln/*Test.java` | Per-component offline tests | 1-8 |

---

## Task 1: Package skeleton — records + detector interface

**Files:**
- Create: `src/main/java/com/xebyte/core/vuln/Finding.java`
- Create: `src/main/java/com/xebyte/core/vuln/CatalogEntry.java`
- Create: `src/main/java/com/xebyte/core/vuln/SinkCallSite.java`
- Create: `src/main/java/com/xebyte/core/vuln/VulnDetector.java`
- Test: `src/test/java/com/xebyte/offline/vuln/FindingTest.java`

- [ ] **Step 1: Write the failing test**

```java
package com.xebyte.offline.vuln;

import com.xebyte.core.vuln.Finding;
import com.xebyte.core.JsonHelper;
import org.junit.Test;
import java.util.List;
import java.util.Map;
import static org.junit.Assert.*;

public class FindingTest {
    @Test
    public void finding_toJson_emitsAllFields() {
        Finding f = new Finding("format_string", "format", "cli.Initial::00010000",
            "HandleRequest", "printf", "high",
            List.of("arg0 <- param_1 (non-constant)"),
            "format argument reaches printf without constant-only def chain");
        Map<String, Object> j = f.toJson();
        assertEquals("format_string", j.get("detector_id"));
        assertEquals("format", j.get("vuln_class"));
        assertEquals("cli.Initial::00010000", j.get("address"));
        assertEquals("HandleRequest", j.get("function"));
        assertEquals("printf", j.get("sink"));
        assertEquals("high", j.get("confidence"));
        assertEquals(1, ((List<?>) j.get("evidence")).size());
        assertTrue(((String) j.get("why")).contains("printf"));
    }
}
```

- [ ] **Step 2: Verify FAIL (does not compile — package missing)**
Run: `./gradlew test --tests 'com.xebyte.offline.vuln.FindingTest' -PGHIDRA_INSTALL_DIR=$GHIDRA_INSTALL_DIR --console=plain`
Expected: compile error `package com.xebyte.core.vuln does not exist`.

- [ ] **Step 3: Create `Finding.java`**

```java
package com.xebyte.core.vuln;

import com.xebyte.core.JsonHelper;
import java.util.List;
import java.util.Map;

/** One vulnerability-candidate result. Immutable. */
public record Finding(
        String detectorId,
        String vulnClass,
        String address,
        String function,
        String sink,
        String confidence,
        List<String> evidence,
        String why) {

    public Map<String, Object> toJson() {
        return JsonHelper.mapOf(
            "detector_id", detectorId,
            "vuln_class",  vulnClass,
            "address",     address,
            "function",    function,
            "sink",        sink,
            "confidence",  confidence,
            "evidence",    evidence,
            "why",         why
        );
    }
}
```

- [ ] **Step 4: Create `CatalogEntry.java`**

```java
package com.xebyte.core.vuln;

import java.util.List;
import java.util.Map;

/**
 * One row from vuln_catalog.json. {@code kind} is "sink" or "source".
 * {@code argRoles} maps role name → 0-based call-arg index ("fmt_arg", "size_arg",
 * "dst_arg", "cmd_arg", "out_arg"); a missing role means not applicable.
 * {@code returnIsOutput} marks sources whose output is the return value (e.g. getenv).
 */
public record CatalogEntry(
        String id,
        String kind,
        String vulnClass,
        Map<String, Integer> argRoles,
        boolean returnIsOutput,
        List<String> matchImport,
        List<String> matchRegex,
        List<String> matchTag) {

    public Integer arg(String role) { return argRoles.get(role); }
}
```

- [ ] **Step 5: Create `SinkCallSite.java`**

```java
package com.xebyte.core.vuln;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.PcodeOp;

/** A CALL/CALLIND site whose callee resolved to a catalog entry. */
public record SinkCallSite(PcodeOp call, CatalogEntry entry, Function callee, Address callAddr) {}
```

- [ ] **Step 6: Create `VulnDetector.java`**

```java
package com.xebyte.core.vuln;

import ghidra.program.model.pcode.HighFunction;
import java.util.List;
import java.util.Set;

/**
 * One intra-function vulnerability pattern matcher. The service pre-resolves
 * every CALL in the HighFunction against the catalog and passes only the
 * SinkCallSites whose entry.vulnClass() ∈ sinkClasses() to scan(...).
 */
public interface VulnDetector {
    /** Stable id, snake_case (e.g. "format_string"). */
    String id();
    /** Human one-liner shown by list_vuln_detectors. */
    String description();
    /** Catalog vulnClass values this detector consumes (e.g. {"format"}). */
    Set<String> sinkClasses();
    /** Run the detector over the pre-resolved call sites. Never returns null. */
    List<Finding> scan(HighFunction hf, List<SinkCallSite> sites);
}
```

- [ ] **Step 7: Verify PASS**
Run: `./gradlew test --tests 'com.xebyte.offline.vuln.FindingTest' -PGHIDRA_INSTALL_DIR=$GHIDRA_INSTALL_DIR --console=plain`
Expected: BUILD SUCCESSFUL, 1 test passed.

- [ ] **Step 8: Commit**
```bash
git add src/main/java/com/xebyte/core/vuln/ src/test/java/com/xebyte/offline/vuln/FindingTest.java
git commit -m "feat(vuln): package skeleton — Finding, CatalogEntry, SinkCallSite, VulnDetector

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

## Task 2: SinkCatalog — JSON resource, loader, override merge, resolve

**Files:**
- Create: `src/main/resources/com/xebyte/vuln_catalog.json`
- Create: `src/main/java/com/xebyte/core/vuln/SinkCatalog.java`
- Test: `src/test/java/com/xebyte/offline/vuln/SinkCatalogTest.java`

- [ ] **Step 1: Write `vuln_catalog.json`** (the full default — copy verbatim from the spec's catalog block)

Create `src/main/resources/com/xebyte/vuln_catalog.json` with EXACTLY the JSON shown in the spec's "Catalog" section (the `{"sinks":[...], "sources":[...]}` document with `memcpy`/`strcpy`/`printf`/`system`/`malloc` sinks and `recv`/`fread`/`getenv`/`argv` sources). Validate with `python -c "import json; json.load(open('src/main/resources/com/xebyte/vuln_catalog.json')); print('OK')"`.

- [ ] **Step 2: Write failing tests**

```java
package com.xebyte.offline.vuln;

import com.xebyte.core.vuln.SinkCatalog;
import com.xebyte.core.vuln.CatalogEntry;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionTag;
import org.junit.Test;
import java.util.List;
import java.util.Set;
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class SinkCatalogTest {

    @Test
    public void load_bakedInResource_parsesAllEntries() {
        SinkCatalog cat = SinkCatalog.load(null); // null override → resource only
        assertNull(cat.status());                  // no warning
        assertTrue(cat.sinks().size() >= 5);
        assertTrue(cat.sources().size() >= 4);
        CatalogEntry memcpy = cat.byId("memcpy");
        assertNotNull(memcpy);
        assertEquals("copy", memcpy.vulnClass());
        assertEquals(Integer.valueOf(2), memcpy.arg("size_arg"));
        assertEquals(Integer.valueOf(0), memcpy.arg("dst_arg"));
    }

    @Test
    public void resolve_byImportName_matchesExternal() {
        SinkCatalog cat = SinkCatalog.load(null);
        Function f = mock(Function.class);
        when(f.isExternal()).thenReturn(true);
        when(f.getName()).thenReturn("memcpy");
        when(f.getTags()).thenReturn(Set.of());
        List<CatalogEntry> hits = cat.resolve(f);
        assertTrue(hits.stream().anyMatch(e -> e.id().equals("memcpy")));
    }

    @Test
    public void resolve_byRegex_matchesRenamedInternal() {
        SinkCatalog cat = SinkCatalog.load(null);
        Function f = mock(Function.class);
        when(f.isExternal()).thenReturn(false);
        when(f.getName()).thenReturn("Crt_MemCpy_Fast");
        when(f.getTags()).thenReturn(Set.of());
        List<CatalogEntry> hits = cat.resolve(f);
        assertTrue(hits.stream().anyMatch(e -> e.id().equals("memcpy")));
    }

    @Test
    public void resolve_byTag_matchesTaggedFunction() {
        SinkCatalog cat = SinkCatalog.load(null);
        Function f = mock(Function.class);
        FunctionTag tag = mock(FunctionTag.class);
        when(tag.getName()).thenReturn("SINK_FORMAT");
        when(f.isExternal()).thenReturn(false);
        when(f.getName()).thenReturn("FUN_00401234");
        when(f.getTags()).thenReturn(Set.of(tag));
        List<CatalogEntry> hits = cat.resolve(f);
        assertTrue(hits.stream().anyMatch(e -> e.id().equals("printf")));
    }

    @Test
    public void resolve_noMatch_returnsEmpty() {
        SinkCatalog cat = SinkCatalog.load(null);
        Function f = mock(Function.class);
        when(f.isExternal()).thenReturn(false);
        when(f.getName()).thenReturn("DoBusinessLogic");
        when(f.getTags()).thenReturn(Set.of());
        assertTrue(cat.resolve(f).isEmpty());
    }

    @Test
    public void load_overrideMerges_userEntryWinsOnId() throws Exception {
        java.io.File tmp = java.io.File.createTempFile("vuln_cat_override", ".json");
        tmp.deleteOnExit();
        java.nio.file.Files.writeString(tmp.toPath(),
            "{\"sinks\":[{\"id\":\"memcpy\",\"class\":\"copy\",\"size_arg\":3,\"dst_arg\":1," +
            "\"match\":{\"tag\":[\"MY_MEMCPY\"]}}]}");
        SinkCatalog cat = SinkCatalog.load(tmp.getAbsolutePath());
        CatalogEntry e = cat.byId("memcpy");
        assertEquals(Integer.valueOf(3), e.arg("size_arg"));   // override wins
        assertNotNull(cat.byId("strcpy"));                      // baked-in still present
    }

    @Test
    public void load_malformedOverride_fallsBackWithStatus() throws Exception {
        java.io.File tmp = java.io.File.createTempFile("vuln_cat_bad", ".json");
        tmp.deleteOnExit();
        java.nio.file.Files.writeString(tmp.toPath(), "{not json");
        SinkCatalog cat = SinkCatalog.load(tmp.getAbsolutePath());
        assertNotNull(cat.byId("memcpy"));                      // baked-in survives
        assertNotNull(cat.status());
        assertTrue(cat.status().contains("override"));
    }
}
```

- [ ] **Step 3: Verify FAIL**
Run: `./gradlew test --tests 'com.xebyte.offline.vuln.SinkCatalogTest' -PGHIDRA_INSTALL_DIR=$GHIDRA_INSTALL_DIR --console=plain`
Expected: compile error (`SinkCatalog` missing).

- [ ] **Step 4: Implement `SinkCatalog.java`**

```java
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
    private final Map<String, Pattern> regexCache = new HashMap<>();
    private final String status; // null when clean

    private SinkCatalog(List<CatalogEntry> entries, String status) {
        for (CatalogEntry e : entries) byId.put(e.id(), e);
        this.status = status;
    }

    /** Load default catalog, then merge {@code overridePath} if non-null/readable. */
    public static SinkCatalog load(String overridePath) {
        List<CatalogEntry> entries = new ArrayList<>();
        String warn = null;
        // 1) baked-in resource (must succeed)
        try (InputStream in = SinkCatalog.class.getResourceAsStream(RESOURCE)) {
            if (in == null) throw new IllegalStateException("missing resource " + RESOURCE);
            String json = new String(in.readAllBytes(), StandardCharsets.UTF_8);
            entries.addAll(parse(json));
        } catch (Exception e) {
            throw new IllegalStateException("failed to load baked-in vuln catalog: " + e.getMessage(), e);
        }
        // 2) optional override — merge by id (override wins)
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

    /** Resolve override path: $GHIDRA_MCP_VULN_CATALOG, else ~/.ghidra-mcp/vuln_catalog.json. */
    public static String defaultOverridePath() {
        String env = System.getenv("GHIDRA_MCP_VULN_CATALOG");
        if (env != null && !env.isBlank()) return env;
        String home = System.getProperty("user.home");
        Path p = Path.of(home, ".ghidra-mcp", "vuln_catalog.json");
        return Files.isReadable(p) ? p.toString() : null;
    }

    public String status()                  { return status; }
    public CatalogEntry byId(String id)      { return byId.get(id); }
    public Collection<CatalogEntry> all()    { return byId.values(); }
    public List<CatalogEntry> sinks()        { return filterKind("sink"); }
    public List<CatalogEntry> sources()      { return filterKind("source"); }

    /** Return every entry that matches {@code f} via import-name ∪ regex ∪ tag. */
    public List<CatalogEntry> resolve(Function f) {
        if (f == null) return List.of();
        String name = f.getName();
        Set<String> tags = new HashSet<>();
        for (FunctionTag t : f.getTags()) tags.add(t.getName());
        boolean external = f.isExternal();

        List<CatalogEntry> hits = new ArrayList<>();
        for (CatalogEntry e : byId.values()) {
            if (external && contains(e.matchImport(), name))            { hits.add(e); continue; }
            if (matchesAnyRegex(e.matchRegex(), name))                   { hits.add(e); continue; }
            if (!Collections.disjoint(tags, e.matchTag()))               { hits.add(e); continue; }
        }
        return hits;
    }

    // ---- internals ----

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
            Pattern p = regexCache.computeIfAbsent(r, Pattern::compile);
            if (p.matcher(name).matches()) return true;
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
            String id = String.valueOf(row.get("id"));
            String cls = String.valueOf(row.get("class"));
            Map<String, Integer> roles = new LinkedHashMap<>();
            for (String k : ARG_ROLE_KEYS) {
                Object v = row.get(k);
                if (v instanceof Number n) roles.put(k, n.intValue());
            }
            boolean retOut = Boolean.TRUE.equals(row.get("return"));
            Map<String, Object> match = (Map<String, Object>) row.getOrDefault("match", Map.of());
            out.add(new CatalogEntry(id, kind, cls, roles, retOut,
                strList(match.get("import")), strList(match.get("regex")), strList(match.get("tag"))));
        }
        return out;
    }

    @SuppressWarnings("unchecked")
    private static List<String> strList(Object o) {
        if (o instanceof List<?> l) {
            List<String> out = new ArrayList<>(l.size());
            for (Object x : l) out.add(String.valueOf(x));
            return out;
        }
        return List.of();
    }
}
```

- [ ] **Step 5: Verify PASS**
Run: `./gradlew test --tests 'com.xebyte.offline.vuln.SinkCatalogTest' -PGHIDRA_INSTALL_DIR=$GHIDRA_INSTALL_DIR --console=plain`
Expected: BUILD SUCCESSFUL, 7 tests passed. If `JsonHelper.parseJson` returns `{}` for malformed input rather than throwing, the `parse(...)` empty-check throws — confirm `load_malformedOverride_*` passes via the `catch` → `warn` path.

- [ ] **Step 6: Commit**
```bash
git add src/main/resources/com/xebyte/vuln_catalog.json src/main/java/com/xebyte/core/vuln/SinkCatalog.java src/test/java/com/xebyte/offline/vuln/SinkCatalogTest.java
git commit -m "feat(vuln): SinkCatalog — baked-in JSON, override merge, import/regex/tag resolve

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

## Task 3: PcodeQuery — static PCode helpers

**Files:**
- Create: `src/main/java/com/xebyte/core/vuln/PcodeQuery.java`
- Test: `src/test/java/com/xebyte/offline/vuln/PcodeQueryTest.java`

- [ ] **Step 1: Write failing tests for the bounded helpers**

These mock only the methods each helper touches: `PcodeOp.getOpcode()/getInput(i)/getNumInputs()`, `Varnode.getDef()/isConstant()/getOffset()`. (`HighFunction`-dependent helpers — `hasDominatingCompare`, `destBufferSize` — are tested in Task 5/6 alongside their detectors with the same mock harness; here we cover the foundation.)

```java
package com.xebyte.offline.vuln;

import com.xebyte.core.vuln.PcodeQuery;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import org.junit.Test;
import java.util.Set;
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class PcodeQueryTest {

    private Varnode constVn(long v) {
        Varnode vn = mock(Varnode.class);
        when(vn.isConstant()).thenReturn(true);
        when(vn.getOffset()).thenReturn(v);
        when(vn.getDef()).thenReturn(null);
        return vn;
    }

    private Varnode definedBy(PcodeOp op) {
        Varnode vn = mock(Varnode.class);
        when(vn.isConstant()).thenReturn(false);
        when(vn.getDef()).thenReturn(op);
        return vn;
    }

    private PcodeOp op(int opcode, Varnode... inputs) {
        PcodeOp p = mock(PcodeOp.class);
        when(p.getOpcode()).thenReturn(opcode);
        when(p.getNumInputs()).thenReturn(inputs.length);
        for (int i = 0; i < inputs.length; i++) when(p.getInput(i)).thenReturn(inputs[i]);
        return p;
    }

    @Test
    public void argVarnode_returnsCallInputAtIndexPlusOne() {
        Varnode tgt = mock(Varnode.class);
        Varnode a0 = mock(Varnode.class);
        Varnode a1 = mock(Varnode.class);
        PcodeOp call = op(PcodeOp.CALL, tgt, a0, a1);
        assertSame(a0, PcodeQuery.argVarnode(call, 0));
        assertSame(a1, PcodeQuery.argVarnode(call, 1));
        assertNull(PcodeQuery.argVarnode(call, 2));
    }

    @Test
    public void reachesConstantOnly_trueForConstThroughCopyCast() {
        Varnode k = constVn(0x1000);
        PcodeOp copy = op(PcodeOp.COPY, k);
        Varnode v1 = definedBy(copy);
        PcodeOp cast = op(PcodeOp.CAST, v1);
        Varnode v2 = definedBy(cast);
        assertTrue(PcodeQuery.reachesConstantOnly(v2, 16));
    }

    @Test
    public void reachesConstantOnly_falseWhenDefChainHitsCallOrInput() {
        // param-like: non-constant, no def
        Varnode param = mock(Varnode.class);
        when(param.isConstant()).thenReturn(false);
        when(param.getDef()).thenReturn(null);
        assertFalse(PcodeQuery.reachesConstantOnly(param, 16));

        PcodeOp call = op(PcodeOp.CALL, mock(Varnode.class));
        Varnode ret = definedBy(call);
        assertFalse(PcodeQuery.reachesConstantOnly(ret, 16));
    }

    @Test
    public void definingOps_collectsTransitiveProducers() {
        Varnode k = constVn(4);
        PcodeOp mul = op(PcodeOp.INT_MULT, k, k);
        Varnode prod = definedBy(mul);
        PcodeOp add = op(PcodeOp.INT_ADD, prod, constVn(8));
        Varnode sum = definedBy(add);
        Set<PcodeOp> ops = PcodeQuery.definingOps(sum, 16);
        assertTrue(ops.contains(add));
        assertTrue(ops.contains(mul));
    }

    @Test
    public void definingOps_respectsMaxStepsAndCycles() {
        // self-cycle via COPY (degenerate) — must terminate
        PcodeOp copy = mock(PcodeOp.class);
        Varnode v = mock(Varnode.class);
        when(v.isConstant()).thenReturn(false);
        when(v.getDef()).thenReturn(copy);
        when(copy.getOpcode()).thenReturn(PcodeOp.COPY);
        when(copy.getNumInputs()).thenReturn(1);
        when(copy.getInput(0)).thenReturn(v);
        Set<PcodeOp> ops = PcodeQuery.definingOps(v, 8);
        assertTrue(ops.size() <= 8);
    }
}
```

- [ ] **Step 2: Verify FAIL**
Run: `./gradlew test --tests 'com.xebyte.offline.vuln.PcodeQueryTest' -PGHIDRA_INSTALL_DIR=$GHIDRA_INSTALL_DIR --console=plain`
Expected: compile error.

- [ ] **Step 3: Implement `PcodeQuery.java`**

```java
package com.xebyte.core.vuln;

import ghidra.program.model.data.DataType;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Static PCode query helpers shared by all VulnDetectors. Intra-function only:
 * walks stop at CALL/CALLIND/CALLOTHER, MULTIEQUAL (phi), constants, and inputs
 * (no def). Mirrors the termination rules of AnalysisService.analyze_dataflow.
 */
public final class PcodeQuery {
    private PcodeQuery() {}

    /** 0-based call argument: input(0) is the call target, args start at input(1). */
    public static Varnode argVarnode(PcodeOp call, int idx) {
        if (call == null || idx < 0) return null;
        int slot = idx + 1;
        return slot < call.getNumInputs() ? call.getInput(slot) : null;
    }

    /**
     * True iff the backward def-chain from {@code v} reaches only constants
     * through transparent ops (COPY/CAST/INT_ZEXT/INT_SEXT/PTRSUB-into-const).
     * False on any input (no-def), CALL*, LOAD, MULTIEQUAL, or step exhaustion.
     */
    public static boolean reachesConstantOnly(Varnode v, int maxSteps) {
        if (v == null) return false;
        Deque<Varnode> work = new ArrayDeque<>();
        Set<Varnode> seen = new LinkedHashSet<>();
        work.push(v);
        int steps = 0;
        while (!work.isEmpty()) {
            if (steps++ > maxSteps) return false;
            Varnode cur = work.pop();
            if (!seen.add(cur)) continue;
            if (cur.isConstant()) continue;
            PcodeOp def = cur.getDef();
            if (def == null) return false; // input/parameter — not provably constant
            switch (def.getOpcode()) {
                case PcodeOp.COPY:
                case PcodeOp.CAST:
                case PcodeOp.INT_ZEXT:
                case PcodeOp.INT_SEXT:
                    work.push(def.getInput(0));
                    break;
                case PcodeOp.PTRSUB:
                case PcodeOp.PTRADD:
                case PcodeOp.INT_ADD:
                    // address-of-constant-data: all inputs must themselves be constant
                    for (int i = 0; i < def.getNumInputs(); i++) work.push(def.getInput(i));
                    break;
                default:
                    return false; // CALL*, LOAD, MULTIEQUAL, arithmetic-on-unknown, ...
            }
        }
        return true;
    }

    /**
     * Transitive set of producing PcodeOps reachable backward from {@code v},
     * stopping at constants/inputs/CALL*/MULTIEQUAL or {@code maxSteps}. Includes
     * every visited def op (not the terminals).
     */
    public static Set<PcodeOp> definingOps(Varnode v, int maxSteps) {
        Set<PcodeOp> ops = new LinkedHashSet<>();
        if (v == null) return ops;
        Deque<Varnode> work = new ArrayDeque<>();
        Set<Varnode> seen = new LinkedHashSet<>();
        work.push(v);
        int steps = 0;
        while (!work.isEmpty() && steps++ < maxSteps) {
            Varnode cur = work.pop();
            if (!seen.add(cur) || cur.isConstant()) continue;
            PcodeOp def = cur.getDef();
            if (def == null) continue;
            int oc = def.getOpcode();
            if (oc == PcodeOp.CALL || oc == PcodeOp.CALLIND || oc == PcodeOp.CALLOTHER
                    || oc == PcodeOp.MULTIEQUAL) {
                ops.add(def);
                continue; // boundary — record but don't recurse
            }
            ops.add(def);
            for (int i = 0; i < def.getNumInputs(); i++) {
                Varnode in = def.getInput(i);
                if (in != null) work.push(in);
            }
        }
        return ops;
    }

    /** True iff any op in the def chain of {@code v} is a CALL/CALLIND. */
    public static boolean defChainHasCall(Varnode v, int maxSteps) {
        for (PcodeOp op : definingOps(v, maxSteps)) {
            int oc = op.getOpcode();
            if (oc == PcodeOp.CALL || oc == PcodeOp.CALLIND) return true;
        }
        return false;
    }

    /** True iff {@code v}'s backward walk reaches a no-def (function input/parameter). */
    public static boolean defChainHasInput(Varnode v, int maxSteps) {
        if (v == null) return false;
        Deque<Varnode> work = new ArrayDeque<>();
        Set<Varnode> seen = new LinkedHashSet<>();
        work.push(v);
        int steps = 0;
        while (!work.isEmpty() && steps++ < maxSteps) {
            Varnode cur = work.pop();
            if (!seen.add(cur) || cur.isConstant()) continue;
            PcodeOp def = cur.getDef();
            if (def == null) return true;
            int oc = def.getOpcode();
            if (oc == PcodeOp.CALL || oc == PcodeOp.CALLIND || oc == PcodeOp.CALLOTHER
                    || oc == PcodeOp.MULTIEQUAL) continue;
            for (int i = 0; i < def.getNumInputs(); i++) {
                Varnode in = def.getInput(i);
                if (in != null) work.push(in);
            }
        }
        return false;
    }

    /**
     * True iff {@code definingOps(v)} contains an INT_LESS/INT_SLESS/INT_LESSEQUAL/
     * INT_SLESSEQUAL/INT_EQUAL whose inputs share a producer with {@code v}. This is
     * a coarse "has a bound check on the size" test for Phase 1 — not a true CFG
     * dominance check (deferred to Phase 2).
     */
    public static boolean hasDominatingCompare(Varnode v, HighFunction hf, int maxSteps) {
        Set<PcodeOp> defs = definingOps(v, maxSteps);
        var it = hf.getPcodeOps();
        while (it.hasNext()) {
            PcodeOp op = it.next();
            switch (op.getOpcode()) {
                case PcodeOp.INT_LESS:
                case PcodeOp.INT_SLESS:
                case PcodeOp.INT_LESSEQUAL:
                case PcodeOp.INT_SLESSEQUAL:
                case PcodeOp.INT_EQUAL:
                    for (int i = 0; i < op.getNumInputs(); i++) {
                        Varnode in = op.getInput(i);
                        if (in == null) continue;
                        if (in.equals(v)) return true;
                        PcodeOp d = in.getDef();
                        if (d != null && defs.contains(d)) return true;
                    }
                    break;
                default:
            }
        }
        return false;
    }

    /**
     * Best-effort byte size of the buffer {@code dst} points at. Returns the
     * HighVariable's DataType length when the dst is a stack local / typed
     * pointer target; -1 when unknown.
     */
    public static int destBufferSize(Varnode dst, HighFunction hf) {
        if (dst == null) return -1;
        HighVariable hv = dst.getHigh();
        if (hv == null) return -1;
        DataType dt = hv.getDataType();
        if (dt == null) return -1;
        // For T* the interesting size is sizeof(T); for T[N] it's N*sizeof(T).
        DataType target = dt;
        try {
            // ghidra.program.model.data.Pointer / Array — resolved reflectively to
            // avoid a hard import; both expose getDataType()/getLength().
            if (dt.getClass().getSimpleName().contains("Pointer")) {
                Object inner = dt.getClass().getMethod("getDataType").invoke(dt);
                if (inner instanceof DataType idt) target = idt;
            }
        } catch (Exception ignored) {}
        int len = target.getLength();
        return len > 0 ? len : -1;
    }

    /** Human label for evidence lines. */
    public static String describe(Varnode v) {
        if (v == null) return "<null>";
        if (v.isConstant()) return "0x" + Long.toHexString(v.getOffset());
        HighVariable hv = v.getHigh();
        if (hv != null && hv.getName() != null) return hv.getName();
        return v.toString();
    }

    public static String mnemonic(PcodeOp op) {
        try { return op != null ? op.getMnemonic() : "<null>"; }
        catch (Exception e) { return "op#" + (op != null ? op.getOpcode() : -1); }
    }
}
```

**Implementation note:** `hasDominatingCompare` is intentionally a Phase-1
approximation (def-chain overlap, not CFG dominance). The Javadoc says so;
do NOT spend effort on a real dominator tree here. `destBufferSize` uses
reflective `Pointer.getDataType()` to avoid a hard `instanceof` on a Ghidra
class that moved packages between 11.x and 12.x — if reflection feels wrong,
replace with a direct `if (dt instanceof ghidra.program.model.data.Pointer p)`
after confirming the import compiles on 12.0.4.

- [ ] **Step 4: Verify PASS**
Run: `./gradlew test --tests 'com.xebyte.offline.vuln.PcodeQueryTest' -PGHIDRA_INSTALL_DIR=$GHIDRA_INSTALL_DIR --console=plain`
Expected: BUILD SUCCESSFUL, 5 tests passed.

- [ ] **Step 5: Commit**
```bash
git add src/main/java/com/xebyte/core/vuln/PcodeQuery.java src/test/java/com/xebyte/offline/vuln/PcodeQueryTest.java
git commit -m "feat(vuln): PcodeQuery — static intra-function PCode helpers

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

## Task 4: FormatStringDetector + CommandInjectionDetector

These share machinery (non-constant arg → catalog sink); they differ only in
`sinkClasses()` and the arg-role key. Implement together.

**Files:**
- Create: `src/main/java/com/xebyte/core/vuln/detectors/FormatStringDetector.java`
- Create: `src/main/java/com/xebyte/core/vuln/detectors/CommandInjectionDetector.java`
- Test: `src/test/java/com/xebyte/offline/vuln/NonConstArgDetectorTest.java`

- [ ] **Step 1: Write failing tests**

```java
package com.xebyte.offline.vuln;

import com.xebyte.core.vuln.*;
import com.xebyte.core.vuln.detectors.FormatStringDetector;
import com.xebyte.core.vuln.detectors.CommandInjectionDetector;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import org.junit.Test;
import java.util.List;
import java.util.Map;
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class NonConstArgDetectorTest {

    private SinkCallSite site(String entryId, String vulnClass, String roleKey,
                              int argIdx, Varnode argVn) {
        CatalogEntry e = new CatalogEntry(entryId, "sink", vulnClass,
            Map.of(roleKey, argIdx), false, List.of(), List.of(), List.of());
        Varnode tgt = mock(Varnode.class);
        PcodeOp call = mock(PcodeOp.class);
        when(call.getOpcode()).thenReturn(PcodeOp.CALL);
        when(call.getNumInputs()).thenReturn(argIdx + 2);
        when(call.getInput(0)).thenReturn(tgt);
        when(call.getInput(argIdx + 1)).thenReturn(argVn);
        Address addr = mock(Address.class);
        when(addr.toString()).thenReturn("00401000");
        Function callee = mock(Function.class);
        when(callee.getName()).thenReturn(entryId);
        return new SinkCallSite(call, e, callee, addr);
    }

    private Varnode constArg() {
        Varnode v = mock(Varnode.class);
        when(v.isConstant()).thenReturn(true);
        when(v.getDef()).thenReturn(null);
        return v;
    }

    private Varnode paramArg() {
        // non-constant, no def → function input
        Varnode v = mock(Varnode.class);
        when(v.isConstant()).thenReturn(false);
        when(v.getDef()).thenReturn(null);
        return v;
    }

    private HighFunction hf(String fnName) {
        HighFunction hf = mock(HighFunction.class);
        Function f = mock(Function.class);
        when(f.getName()).thenReturn(fnName);
        when(hf.getFunction()).thenReturn(f);
        return hf;
    }

    @Test
    public void formatString_constantFmt_emitsNothing() {
        var d = new FormatStringDetector();
        var s = site("printf", "format", "fmt_arg", 0, constArg());
        assertTrue(d.scan(hf("F"), List.of(s)).isEmpty());
    }

    @Test
    public void formatString_paramFmt_emitsHighConfidence() {
        var d = new FormatStringDetector();
        var s = site("printf", "format", "fmt_arg", 0, paramArg());
        List<Finding> out = d.scan(hf("F"), List.of(s));
        assertEquals(1, out.size());
        assertEquals("format_string", out.get(0).detectorId());
        assertEquals("high", out.get(0).confidence());
        assertEquals("printf", out.get(0).sink());
    }

    @Test
    public void commandInjection_paramCmd_emitsFinding() {
        var d = new CommandInjectionDetector();
        var s = site("system", "exec", "cmd_arg", 0, paramArg());
        List<Finding> out = d.scan(hf("F"), List.of(s));
        assertEquals(1, out.size());
        assertEquals("command_injection", out.get(0).detectorId());
        assertEquals("exec", out.get(0).vulnClass());
    }

    @Test
    public void detector_ignoresSitesOutsideItsClass() {
        var d = new FormatStringDetector();
        // a "copy" site handed to the format detector — must be ignored
        var s = site("memcpy", "copy", "size_arg", 2, paramArg());
        assertTrue(d.scan(hf("F"), List.of(s)).isEmpty());
    }
}
```

- [ ] **Step 2: Verify FAIL**
Run: `./gradlew test --tests 'com.xebyte.offline.vuln.NonConstArgDetectorTest' -PGHIDRA_INSTALL_DIR=$GHIDRA_INSTALL_DIR --console=plain`
Expected: compile error.

- [ ] **Step 3: Implement `FormatStringDetector.java`**

```java
package com.xebyte.core.vuln.detectors;

import com.xebyte.core.vuln.*;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.Varnode;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/** Flags non-constant format-argument reaching a format sink. */
public final class FormatStringDetector implements VulnDetector {
    private static final int MAX_STEPS = 32;

    @Override public String id()           { return "format_string"; }
    @Override public String description()  { return "Non-constant value reaches the format-string argument of a printf/scanf/syslog-family sink."; }
    @Override public Set<String> sinkClasses() { return Set.of("format"); }

    @Override
    public List<Finding> scan(HighFunction hf, List<SinkCallSite> sites) {
        List<Finding> out = new ArrayList<>();
        String fn = hf.getFunction() != null ? hf.getFunction().getName() : "<unknown>";
        for (SinkCallSite s : sites) {
            if (!sinkClasses().contains(s.entry().vulnClass())) continue;
            Integer idx = s.entry().arg("fmt_arg");
            if (idx == null) continue;
            Varnode fmt = PcodeQuery.argVarnode(s.call(), idx);
            if (fmt == null) continue;
            if (PcodeQuery.reachesConstantOnly(fmt, MAX_STEPS)) continue; // safe
            boolean fromInput = PcodeQuery.defChainHasInput(fmt, MAX_STEPS)
                             || PcodeQuery.defChainHasCall(fmt, MAX_STEPS);
            String conf = fromInput ? "high" : "medium";
            out.add(new Finding(id(), "format", s.callAddr().toString(), fn,
                s.entry().id(), conf,
                List.of("fmt_arg = " + PcodeQuery.describe(fmt) + " (non-constant)"),
                "Non-constant format string reaches " + s.entry().id() + " at " + s.callAddr()));
        }
        return out;
    }
}
```

- [ ] **Step 4: Implement `CommandInjectionDetector.java`**

```java
package com.xebyte.core.vuln.detectors;

import com.xebyte.core.vuln.*;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.Varnode;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/** Flags non-constant command argument reaching an exec sink. */
public final class CommandInjectionDetector implements VulnDetector {
    private static final int MAX_STEPS = 32;

    @Override public String id()           { return "command_injection"; }
    @Override public String description()  { return "Non-constant value reaches the command argument of system/popen/exec*/CreateProcess*/ShellExecute*."; }
    @Override public Set<String> sinkClasses() { return Set.of("exec"); }

    @Override
    public List<Finding> scan(HighFunction hf, List<SinkCallSite> sites) {
        List<Finding> out = new ArrayList<>();
        String fn = hf.getFunction() != null ? hf.getFunction().getName() : "<unknown>";
        for (SinkCallSite s : sites) {
            if (!sinkClasses().contains(s.entry().vulnClass())) continue;
            Integer idx = s.entry().arg("cmd_arg");
            if (idx == null) continue;
            Varnode cmd = PcodeQuery.argVarnode(s.call(), idx);
            if (cmd == null) continue;
            if (PcodeQuery.reachesConstantOnly(cmd, MAX_STEPS)) continue;
            boolean fromInput = PcodeQuery.defChainHasInput(cmd, MAX_STEPS)
                             || PcodeQuery.defChainHasCall(cmd, MAX_STEPS);
            String conf = fromInput ? "high" : "medium";
            out.add(new Finding(id(), "exec", s.callAddr().toString(), fn,
                s.entry().id(), conf,
                List.of("cmd_arg = " + PcodeQuery.describe(cmd) + " (non-constant)"),
                "Non-constant command reaches " + s.entry().id() + " at " + s.callAddr()));
        }
        return out;
    }
}
```

- [ ] **Step 5: Verify PASS**
Run: `./gradlew test --tests 'com.xebyte.offline.vuln.NonConstArgDetectorTest' -PGHIDRA_INSTALL_DIR=$GHIDRA_INSTALL_DIR --console=plain`
Expected: BUILD SUCCESSFUL, 4 tests passed.

- [ ] **Step 6: Commit**
```bash
git add src/main/java/com/xebyte/core/vuln/detectors/ src/test/java/com/xebyte/offline/vuln/NonConstArgDetectorTest.java
git commit -m "feat(vuln): FormatString + CommandInjection detectors

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

## Task 5: UnboundedCopyDetector

**Files:**
- Create: `src/main/java/com/xebyte/core/vuln/detectors/UnboundedCopyDetector.java`
- Test: `src/test/java/com/xebyte/offline/vuln/UnboundedCopyDetectorTest.java`

- [ ] **Step 1: Write failing tests**

```java
package com.xebyte.offline.vuln;

import com.xebyte.core.vuln.*;
import com.xebyte.core.vuln.detectors.UnboundedCopyDetector;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.*;
import org.junit.Test;
import java.util.*;
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class UnboundedCopyDetectorTest {

    private HighFunction hfNoCompares(String name) {
        HighFunction hf = mock(HighFunction.class);
        Function f = mock(Function.class);
        when(f.getName()).thenReturn(name);
        when(hf.getFunction()).thenReturn(f);
        // hasDominatingCompare scans hf.getPcodeOps(); empty iterator → no compares
        when(hf.getPcodeOps()).thenAnswer(inv -> Collections.emptyIterator());
        return hf;
    }

    private Varnode boundedDst(int size) {
        Varnode v = mock(Varnode.class);
        HighVariable hv = mock(HighVariable.class);
        DataType dt = mock(DataType.class);
        when(dt.getLength()).thenReturn(size);
        when(hv.getDataType()).thenReturn(dt);
        when(v.getHigh()).thenReturn(hv);
        return v;
    }

    private Varnode constVn(long k) {
        Varnode v = mock(Varnode.class);
        when(v.isConstant()).thenReturn(true);
        when(v.getOffset()).thenReturn(k);
        when(v.getDef()).thenReturn(null);
        return v;
    }

    private Varnode paramVn() {
        Varnode v = mock(Varnode.class);
        when(v.isConstant()).thenReturn(false);
        when(v.getDef()).thenReturn(null);
        return v;
    }

    private SinkCallSite copySite(Integer sizeArg, Varnode dst, Varnode src, Varnode size) {
        Map<String, Integer> roles = new LinkedHashMap<>();
        roles.put("dst_arg", 0);
        if (sizeArg != null) roles.put("size_arg", sizeArg);
        CatalogEntry e = new CatalogEntry(sizeArg == null ? "strcpy" : "memcpy",
            "sink", "copy", roles, false, List.of(), List.of(), List.of());
        PcodeOp call = mock(PcodeOp.class);
        when(call.getOpcode()).thenReturn(PcodeOp.CALL);
        int n = sizeArg == null ? 3 : 4; // tgt + dst + src [+ size]
        when(call.getNumInputs()).thenReturn(n);
        when(call.getInput(0)).thenReturn(mock(Varnode.class));
        when(call.getInput(1)).thenReturn(dst);
        when(call.getInput(2)).thenReturn(src);
        if (sizeArg != null) when(call.getInput(3)).thenReturn(size);
        Address a = mock(Address.class); when(a.toString()).thenReturn("00401000");
        Function callee = mock(Function.class); when(callee.getName()).thenReturn(e.id());
        return new SinkCallSite(call, e, callee, a);
    }

    @Test
    public void strcpy_intoBoundedLocal_fromNonConst_flags() {
        var d = new UnboundedCopyDetector();
        var s = copySite(null, boundedDst(64), paramVn(), null);
        var out = d.scan(hfNoCompares("F"), List.of(s));
        assertEquals(1, out.size());
        assertEquals("unbounded_copy", out.get(0).detectorId());
    }

    @Test
    public void memcpy_constSizeWithinDest_safe() {
        var d = new UnboundedCopyDetector();
        var s = copySite(2, boundedDst(64), paramVn(), constVn(32));
        assertTrue(d.scan(hfNoCompares("F"), List.of(s)).isEmpty());
    }

    @Test
    public void memcpy_paramSizeNoCompare_intoBoundedDest_flags() {
        var d = new UnboundedCopyDetector();
        var s = copySite(2, boundedDst(64), paramVn(), paramVn());
        var out = d.scan(hfNoCompares("F"), List.of(s));
        assertEquals(1, out.size());
    }

    @Test
    public void memcpy_unknownDestSize_doesNotFlag() {
        var d = new UnboundedCopyDetector();
        Varnode dst = mock(Varnode.class); when(dst.getHigh()).thenReturn(null);
        var s = copySite(2, dst, paramVn(), paramVn());
        assertTrue("unknown dest size → can't claim overflow", d.scan(hfNoCompares("F"), List.of(s)).isEmpty());
    }
}
```

- [ ] **Step 2: Verify FAIL**
`./gradlew test --tests 'com.xebyte.offline.vuln.UnboundedCopyDetectorTest' -PGHIDRA_INSTALL_DIR=$GHIDRA_INSTALL_DIR --console=plain`

- [ ] **Step 3: Implement `UnboundedCopyDetector.java`**

```java
package com.xebyte.core.vuln.detectors;

import com.xebyte.core.vuln.*;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.Varnode;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/** Flags copies into a bounded destination without an adequate length guard. */
public final class UnboundedCopyDetector implements VulnDetector {
    private static final int MAX_STEPS = 48;

    @Override public String id()           { return "unbounded_copy"; }
    @Override public String description()  { return "memcpy/strcpy-family call writes into a bounded buffer without a dominating size check or with a non-constant length."; }
    @Override public Set<String> sinkClasses() { return Set.of("copy"); }

    @Override
    public List<Finding> scan(HighFunction hf, List<SinkCallSite> sites) {
        List<Finding> out = new ArrayList<>();
        String fn = hf.getFunction() != null ? hf.getFunction().getName() : "<unknown>";
        for (SinkCallSite s : sites) {
            if (!sinkClasses().contains(s.entry().vulnClass())) continue;
            Integer dstIdx = s.entry().arg("dst_arg");
            if (dstIdx == null) continue;
            Varnode dst = PcodeQuery.argVarnode(s.call(), dstIdx);
            int destSize = PcodeQuery.destBufferSize(dst, hf);
            if (destSize <= 0) continue; // can't reason about overflow without a known bound

            Integer sizeIdx = s.entry().arg("size_arg");
            if (sizeIdx == null) {
                // strcpy-family: any non-constant source into a bounded dest is a candidate
                Varnode src = PcodeQuery.argVarnode(s.call(), dstIdx + 1);
                if (src != null && !PcodeQuery.reachesConstantOnly(src, MAX_STEPS)) {
                    out.add(finding(s, fn, "high",
                        List.of("dest size = " + destSize + " bytes",
                                "src = " + PcodeQuery.describe(src) + " (unbounded, non-constant)"),
                        "Unbounded string copy into " + destSize + "-byte buffer via " + s.entry().id()));
                }
                continue;
            }

            Varnode size = PcodeQuery.argVarnode(s.call(), sizeIdx);
            if (size == null) continue;
            if (size.isConstant()) {
                long k = size.getOffset();
                if (k <= destSize) continue; // provably safe
                out.add(finding(s, fn, "high",
                    List.of("dest size = " + destSize + " bytes", "length constant = " + k),
                    "Constant-length copy of " + k + " bytes into " + destSize + "-byte buffer via " + s.entry().id()));
                continue;
            }
            if (PcodeQuery.hasDominatingCompare(size, hf, MAX_STEPS)) continue; // a check exists
            out.add(finding(s, fn, "medium",
                List.of("dest size = " + destSize + " bytes",
                        "length = " + PcodeQuery.describe(size) + " (non-constant, no observed bound check)"),
                "Length-unchecked copy into " + destSize + "-byte buffer via " + s.entry().id()));
        }
        return out;
    }

    private Finding finding(SinkCallSite s, String fn, String conf, List<String> ev, String why) {
        return new Finding(id(), "copy", s.callAddr().toString(), fn, s.entry().id(), conf, ev, why);
    }
}
```

- [ ] **Step 4: Verify PASS** (4 tests). **Step 5: Commit**
```bash
git add src/main/java/com/xebyte/core/vuln/detectors/UnboundedCopyDetector.java src/test/java/com/xebyte/offline/vuln/UnboundedCopyDetectorTest.java
git commit -m "feat(vuln): UnboundedCopyDetector

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

## Task 6: IntegerOverflowAllocDetector

**Files:**
- Create: `src/main/java/com/xebyte/core/vuln/detectors/IntegerOverflowAllocDetector.java`
- Test: `src/test/java/com/xebyte/offline/vuln/IntegerOverflowAllocDetectorTest.java`

- [ ] **Step 1: Write failing tests**

```java
package com.xebyte.offline.vuln;

import com.xebyte.core.vuln.*;
import com.xebyte.core.vuln.detectors.IntegerOverflowAllocDetector;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.*;
import org.junit.Test;
import java.util.*;
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class IntegerOverflowAllocDetectorTest {

    private HighFunction hfNoCompares() {
        HighFunction hf = mock(HighFunction.class);
        Function f = mock(Function.class); when(f.getName()).thenReturn("F");
        when(hf.getFunction()).thenReturn(f);
        when(hf.getPcodeOps()).thenAnswer(inv -> Collections.emptyIterator());
        return hf;
    }

    private Varnode constVn(long k) {
        Varnode v = mock(Varnode.class);
        when(v.isConstant()).thenReturn(true); when(v.getOffset()).thenReturn(k);
        when(v.getDef()).thenReturn(null); return v;
    }
    private Varnode paramVn() {
        Varnode v = mock(Varnode.class);
        when(v.isConstant()).thenReturn(false); when(v.getDef()).thenReturn(null); return v;
    }
    private Varnode definedBy(PcodeOp op) {
        Varnode v = mock(Varnode.class);
        when(v.isConstant()).thenReturn(false); when(v.getDef()).thenReturn(op); return v;
    }
    private PcodeOp op(int oc, Varnode... in) {
        PcodeOp p = mock(PcodeOp.class);
        when(p.getOpcode()).thenReturn(oc); when(p.getNumInputs()).thenReturn(in.length);
        for (int i=0;i<in.length;i++) when(p.getInput(i)).thenReturn(in[i]); return p;
    }

    private SinkCallSite allocSite(Varnode size) {
        CatalogEntry e = new CatalogEntry("malloc","sink","alloc",
            Map.of("size_arg",0), false, List.of(), List.of(), List.of());
        PcodeOp call = mock(PcodeOp.class);
        when(call.getOpcode()).thenReturn(PcodeOp.CALL);
        when(call.getNumInputs()).thenReturn(2);
        when(call.getInput(0)).thenReturn(mock(Varnode.class));
        when(call.getInput(1)).thenReturn(size);
        Address a = mock(Address.class); when(a.toString()).thenReturn("00401000");
        Function callee = mock(Function.class); when(callee.getName()).thenReturn("malloc");
        return new SinkCallSite(call, e, callee, a);
    }

    @Test
    public void mult_paramTimesConst_intoMalloc_noCheck_flags() {
        PcodeOp mul = op(PcodeOp.INT_MULT, paramVn(), constVn(16));
        var s = allocSite(definedBy(mul));
        var out = new IntegerOverflowAllocDetector().scan(hfNoCompares(), List.of(s));
        assertEquals(1, out.size());
        assertEquals("integer_overflow_alloc", out.get(0).detectorId());
    }

    @Test
    public void mult_constTimesConst_safe() {
        PcodeOp mul = op(PcodeOp.INT_MULT, constVn(8), constVn(16));
        var s = allocSite(definedBy(mul));
        assertTrue(new IntegerOverflowAllocDetector().scan(hfNoCompares(), List.of(s)).isEmpty());
    }

    @Test
    public void plainParamSize_noArith_doesNotFlag() {
        var s = allocSite(paramVn());
        assertTrue("no MULT/ADD → not an overflow pattern",
            new IntegerOverflowAllocDetector().scan(hfNoCompares(), List.of(s)).isEmpty());
    }
}
```

- [ ] **Step 2: Verify FAIL**, then **Step 3: Implement**

```java
package com.xebyte.core.vuln.detectors;

import com.xebyte.core.vuln.*;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import java.util.*;

/** Flags allocator size derived from non-constant INT_MULT/INT_ADD without an overflow guard. */
public final class IntegerOverflowAllocDetector implements VulnDetector {
    private static final int MAX_STEPS = 48;

    @Override public String id()           { return "integer_overflow_alloc"; }
    @Override public String description()  { return "Allocator size is INT_MULT/INT_ADD of a non-constant input with no observed overflow check."; }
    @Override public Set<String> sinkClasses() { return Set.of("alloc"); }

    @Override
    public List<Finding> scan(HighFunction hf, List<SinkCallSite> sites) {
        List<Finding> out = new ArrayList<>();
        String fn = hf.getFunction() != null ? hf.getFunction().getName() : "<unknown>";
        for (SinkCallSite s : sites) {
            if (!sinkClasses().contains(s.entry().vulnClass())) continue;
            Integer idx = s.entry().arg("size_arg");
            if (idx == null) continue;
            Varnode size = PcodeQuery.argVarnode(s.call(), idx);
            if (size == null || size.isConstant()) continue;

            PcodeOp risky = null;
            for (PcodeOp op : PcodeQuery.definingOps(size, MAX_STEPS)) {
                int oc = op.getOpcode();
                if (oc != PcodeOp.INT_MULT && oc != PcodeOp.INT_ADD) continue;
                boolean allConst = true;
                for (int i = 0; i < op.getNumInputs(); i++) {
                    Varnode in = op.getInput(i);
                    if (in == null || !in.isConstant()) { allConst = false; break; }
                }
                if (!allConst) { risky = op; break; }
            }
            if (risky == null) continue;
            if (PcodeQuery.hasDominatingCompare(size, hf, MAX_STEPS)) continue;

            out.add(new Finding(id(), "alloc", s.callAddr().toString(), fn,
                s.entry().id(), "medium",
                List.of("size = " + PcodeQuery.describe(size),
                        PcodeQuery.mnemonic(risky) + " on non-constant input feeds allocator"),
                "Allocator size derived via " + PcodeQuery.mnemonic(risky)
                    + " without an overflow check at " + s.callAddr()));
        }
        return out;
    }
}
```

- [ ] **Step 4: Verify PASS** (3 tests). **Step 5: Commit**
```bash
git add src/main/java/com/xebyte/core/vuln/detectors/IntegerOverflowAllocDetector.java src/test/java/com/xebyte/offline/vuln/IntegerOverflowAllocDetectorTest.java
git commit -m "feat(vuln): IntegerOverflowAllocDetector

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

## Task 7: VulnAnalysisService — `scanFunction`, `detect_vuln_patterns`, `list_vuln_detectors`

**Files:**
- Create: `src/main/java/com/xebyte/core/vuln/VulnAnalysisService.java`
- Test: `src/test/java/com/xebyte/offline/vuln/VulnAnalysisServiceTest.java`

- [ ] **Step 1: Write failing tests (offline shape — mocked Program with no functions)**

```java
package com.xebyte.offline.vuln;

import com.xebyte.core.ProgramProvider;
import com.xebyte.core.Response;
import com.xebyte.core.vuln.VulnAnalysisService;
import com.xebyte.core.FunctionService;
import com.xebyte.offline.NoopThreadingStrategy;
import ghidra.program.model.listing.*;
import org.junit.Test;
import java.util.*;
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class VulnAnalysisServiceTest {

    private VulnAnalysisService svc(Program p) {
        ProgramProvider pp = mock(ProgramProvider.class);
        when(pp.getCurrentProgram()).thenReturn(p);
        FunctionService fs = mock(FunctionService.class);
        return new VulnAnalysisService(pp, new NoopThreadingStrategy(), fs);
    }

    @Test
    @SuppressWarnings("unchecked")
    public void listVulnDetectors_returnsAllFour() {
        Response r = svc(mock(Program.class)).listVulnDetectors("");
        Map<String,Object> body = (Map<String,Object>) ((Response.Ok) r).data();
        List<?> ds = (List<?>) body.get("detectors");
        assertEquals(4, ds.size());
        assertNotNull(body.get("catalog"));
    }

    @Test
    @SuppressWarnings("unchecked")
    public void detectVulnPatterns_noFunctions_returnsEmptyWithNote() {
        Program p = mock(Program.class);
        FunctionManager fm = mock(FunctionManager.class);
        when(p.getFunctionManager()).thenReturn(fm);
        when(fm.getFunctions(true)).thenReturn(
            (FunctionIterator) mock(FunctionIterator.class,
                inv -> { if (inv.getMethod().getName().equals("hasNext")) return false; return null; }));
        Response r = svc(p).detectVulnPatterns("", "", "", false, 0);
        Map<String,Object> body = (Map<String,Object>) ((Response.Ok) r).data();
        assertEquals(0, ((List<?>) body.get("findings")).size());
        assertEquals(0, ((Number) body.get("scanned_functions")).intValue());
    }
}
```

**Note:** confirm `Response.Ok` record + `.data()` accessor (`grep -n "record Ok" src/main/java/com/xebyte/core/Response.java`); adapt if it's `body()`/`payload()`. Confirm `NoopThreadingStrategy` is public in `com.xebyte.offline` (it is — sibling tests use it).

- [ ] **Step 2: Verify FAIL** (compile error).

- [ ] **Step 3: Implement `VulnAnalysisService.java`**

```java
package com.xebyte.core.vuln;

import com.xebyte.core.*;
import com.xebyte.core.vuln.detectors.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import java.util.*;

/**
 * Intra-function vulnerability pattern scanning. Decompiles a function once,
 * resolves every CALL/CALLIND against the SinkCatalog into SinkCallSites, and
 * hands the relevant sites to each registered VulnDetector.
 */
public final class VulnAnalysisService {

    private final ProgramProvider programProvider;
    private final ThreadingStrategy threading;
    private final FunctionService functionService;
    private final SinkCatalog catalog;
    private final List<VulnDetector> detectors;

    public VulnAnalysisService(ProgramProvider pp, ThreadingStrategy ts, FunctionService fs) {
        this.programProvider = pp;
        this.threading = ts;
        this.functionService = fs;
        this.catalog = SinkCatalog.load(SinkCatalog.defaultOverridePath());
        this.detectors = List.of(
            new FormatStringDetector(),
            new CommandInjectionDetector(),
            new UnboundedCopyDetector(),
            new IntegerOverflowAllocDetector()
        );
    }

    @McpTool(path = "/list_vuln_detectors", category = "security",
             description = "List registered vulnerability-pattern detectors and the active source/sink catalog "
                         + "(including any user override). Use this to discover detector ids for detect_vuln_patterns "
                         + "and the SINK_*/SOURCE_* tag names the catalog recognizes.")
    public Response listVulnDetectors(
            @Param(value = "program", defaultValue = "",
                   description = "Target program name (omit for active program)") String programName) {
        List<Map<String,Object>> ds = new ArrayList<>();
        for (VulnDetector d : detectors) {
            ds.add(JsonHelper.mapOf("id", d.id(), "description", d.description(),
                                    "sink_classes", new ArrayList<>(d.sinkClasses())));
        }
        Map<String,Object> cat = JsonHelper.mapOf(
            "sink_count",   catalog.sinks().size(),
            "source_count", catalog.sources().size(),
            "status",       catalog.status() == null ? "ok" : catalog.status());
        return Response.ok(JsonHelper.mapOf("detectors", ds, "catalog", cat));
    }

    @McpTool(path = "/detect_vuln_patterns", category = "security",
             description = "Scan one function (or, if 'function' is empty, every function in the program up to "
                         + "max_functions) for intra-function vulnerability patterns using PCode: format-string, "
                         + "unbounded-copy, integer-overflow-into-alloc, command-injection. Returns findings with "
                         + "address, sink, confidence, evidence, and a one-line 'why'. Set write_bookmarks=true to "
                         + "drop SEVR/<class> bookmarks at each finding. Sinks are matched by import name, function-"
                         + "name regex, or Ghidra function tag (SINK_*); use list_vuln_detectors to see the catalog.")
    public Response detectVulnPatterns(
            @Param(value = "function", defaultValue = "",
                   description = "Function name or entry address. Empty = scan whole program.") String functionRef,
            @Param(value = "classes", defaultValue = "",
                   description = "Comma-separated detector ids (e.g. 'format_string,unbounded_copy'). Empty = all.") String classesCsv,
            @Param(value = "program", defaultValue = "",
                   description = "Target program name (omit for active program)") String programName,
            @Param(value = "write_bookmarks", defaultValue = "false",
                   description = "When true, write a SEVR/<class> bookmark at each finding's address.") boolean writeBookmarks,
            @Param(value = "max_functions", defaultValue = "0",
                   description = "Cap on functions scanned in whole-program mode (0 = no cap).") int maxFunctions) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        Set<String> wanted = new LinkedHashSet<>();
        for (String s : classesCsv.split(",")) { s = s.strip(); if (!s.isEmpty()) wanted.add(s); }
        List<VulnDetector> active = new ArrayList<>();
        for (VulnDetector d : detectors) if (wanted.isEmpty() || wanted.contains(d.id())) active.add(d);

        List<Finding> findings = new ArrayList<>();
        int scanned = 0, decompFail = 0;

        if (!functionRef.isBlank()) {
            Function f = ServiceUtils.findFunction(program, functionRef);
            if (f == null) return Response.err("Function not found: " + functionRef);
            ScanResult r = scanFunction(program, f, active);
            findings.addAll(r.findings); scanned = 1; decompFail = r.decompFailed ? 1 : 0;
        } else {
            FunctionIterator it = program.getFunctionManager().getFunctions(true);
            while (it.hasNext()) {
                if (maxFunctions > 0 && scanned >= maxFunctions) break;
                Function f = it.next();
                if (f.isExternal() || f.isThunk()) continue;
                ScanResult r = scanFunction(program, f, active);
                findings.addAll(r.findings);
                if (r.decompFailed) decompFail++;
                scanned++;
            }
        }

        if (writeBookmarks && !findings.isEmpty()) {
            writeBookmarks(program, findings);
        }

        List<Map<String,Object>> fjson = new ArrayList<>();
        for (Finding f : findings) fjson.add(f.toJson());
        Map<String,Object> out = JsonHelper.mapOf(
            "findings",           fjson,
            "scanned_functions",  scanned,
            "decompile_failures", decompFail,
            "detectors_run",      active.stream().map(VulnDetector::id).toList(),
            "catalog_status",     catalog.status() == null ? "ok" : catalog.status());
        if (findings.isEmpty() && !anySinksResolved(program)) {
            out = new LinkedHashMap<>(out);
            out.put("note", "no catalog sinks resolved — consider tagging functions with SINK_* / SOURCE_*");
        }
        return Response.ok(out);
    }

    // ---- core ----

    private record ScanResult(List<Finding> findings, boolean decompFailed) {}

    private ScanResult scanFunction(Program program, Function f, List<VulnDetector> active) {
        var dr = functionService.decompileFunctionNoRetry(f, program);
        if (dr == null || !dr.decompileCompleted() || dr.getHighFunction() == null) {
            return new ScanResult(List.of(), true);
        }
        HighFunction hf = dr.getHighFunction();
        FunctionManager fm = program.getFunctionManager();

        // Resolve every CALL/CALLIND once
        List<SinkCallSite> sites = new ArrayList<>();
        var ops = hf.getPcodeOps();
        while (ops.hasNext()) {
            PcodeOpAST op = ops.next();
            int oc = op.getOpcode();
            if (oc != PcodeOp.CALL && oc != PcodeOp.CALLIND) continue;
            Function callee = resolveCallee(op, fm);
            if (callee == null) continue;
            for (CatalogEntry e : catalog.resolve(callee)) {
                if (!"sink".equals(e.kind())) continue;
                Address addr = op.getSeqnum() != null ? op.getSeqnum().getTarget() : f.getEntryPoint();
                sites.add(new SinkCallSite(op, e, callee, addr));
            }
        }
        if (sites.isEmpty()) return new ScanResult(List.of(), false);

        List<Finding> all = new ArrayList<>();
        for (VulnDetector d : active) {
            List<SinkCallSite> mine = new ArrayList<>();
            for (SinkCallSite s : sites) if (d.sinkClasses().contains(s.entry().vulnClass())) mine.add(s);
            if (!mine.isEmpty()) all.addAll(d.scan(hf, mine));
        }
        return new ScanResult(all, false);
    }

    private Function resolveCallee(PcodeOp op, FunctionManager fm) {
        if (op.getNumInputs() == 0) return null;
        Varnode tgt = op.getInput(0);
        if (tgt == null || !tgt.isAddress()) return null;
        Function f = fm.getFunctionAt(tgt.getAddress());
        // Follow one level of thunk so external imports resolve to their real name.
        if (f != null && f.isThunk()) {
            Function real = f.getThunkedFunction(true);
            if (real != null) return real;
        }
        return f;
    }

    private boolean anySinksResolved(Program program) {
        FunctionIterator it = program.getFunctionManager().getFunctions(true);
        while (it.hasNext()) {
            if (!catalog.resolve(it.next()).isEmpty()) return true;
        }
        return false;
    }

    private void writeBookmarks(Program program, List<Finding> findings) {
        threading.executeWrite(program, "SEVR bookmarks", () -> {
            BookmarkManager bm = program.getBookmarkManager();
            for (Finding f : findings) {
                Address a = ServiceUtils.parseAddress(program, f.address());
                if (a == null) continue;
                String cat = "SEVR/" + f.vulnClass();
                Bookmark old = bm.getBookmark(a, BookmarkType.ANALYSIS, cat);
                if (old != null) bm.removeBookmark(old);
                bm.setBookmark(a, BookmarkType.ANALYSIS, cat, f.detectorId() + ": " + f.why());
            }
            return null;
        });
    }
}
```

**Implementation notes:** verify `ThreadingStrategy.executeWrite(Program, String, Callable)` signature (`grep -n "executeWrite" src/main/java/com/xebyte/core/ThreadingStrategy.java`). If it's `(Program, String, Runnable)` or wraps the transaction itself differently, adapt the `writeBookmarks` body to match the existing pattern at `ProgramScriptService.java:1792-1807` (start/end transaction explicitly). Confirm `ServiceUtils.findFunction(Program, String)` exists (`grep -n "findFunction" src/main/java/com/xebyte/core/ServiceUtils.java`); if not, use the same `FunctionRef`/name+address resolution sibling tools use.

- [ ] **Step 4: Verify PASS** (2 tests). **Step 5: Commit**
```bash
git add src/main/java/com/xebyte/core/vuln/VulnAnalysisService.java src/test/java/com/xebyte/offline/vuln/VulnAnalysisServiceTest.java
git commit -m "feat(vuln): VulnAnalysisService — scanFunction, detect_vuln_patterns, list_vuln_detectors

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

## Task 8: `enumerate_attack_surface`

**Files:**
- Modify: `src/main/java/com/xebyte/core/vuln/VulnAnalysisService.java` (add endpoint)
- Test: extend `VulnAnalysisServiceTest.java`

- [ ] **Step 1: Write failing test** (mocked source-tagged function + one caller)

```java
    @Test
    @SuppressWarnings("unchecked")
    public void enumerateAttackSurface_groupsBySourceClass() {
        Program p = mock(Program.class);
        FunctionManager fm = mock(FunctionManager.class);
        when(p.getFunctionManager()).thenReturn(fm);
        ghidra.program.model.symbol.ReferenceManager rm =
            mock(ghidra.program.model.symbol.ReferenceManager.class);
        when(p.getReferenceManager()).thenReturn(rm);

        // One source function tagged SOURCE_NETWORK, one caller of it.
        Function recv = mock(Function.class);
        ghidra.program.model.listing.FunctionTag tag =
            mock(ghidra.program.model.listing.FunctionTag.class);
        when(tag.getName()).thenReturn("SOURCE_NETWORK");
        when(recv.getTags()).thenReturn(java.util.Set.of(tag));
        when(recv.getName()).thenReturn("MyRecv");
        ghidra.program.model.address.Address recvEntry =
            mock(ghidra.program.model.address.Address.class);
        when(recv.getEntryPoint()).thenReturn(recvEntry);

        Function caller = mock(Function.class);
        when(caller.getName()).thenReturn("HandlePacket");
        when(caller.getTags()).thenReturn(java.util.Set.of());

        // FunctionManager iteration: just recv (caller discovered via refs)
        FunctionIterator fit = mock(FunctionIterator.class);
        when(fit.hasNext()).thenReturn(true, false);
        when(fit.next()).thenReturn(recv);
        when(fm.getFunctions(true)).thenReturn(fit);

        // ReferenceManager: one call ref from caller → recv
        ghidra.program.model.symbol.Reference ref =
            mock(ghidra.program.model.symbol.Reference.class);
        ghidra.program.model.symbol.RefType rt = mock(ghidra.program.model.symbol.RefType.class);
        when(rt.isCall()).thenReturn(true);
        when(ref.getReferenceType()).thenReturn(rt);
        ghidra.program.model.address.Address fromAddr =
            mock(ghidra.program.model.address.Address.class);
        when(ref.getFromAddress()).thenReturn(fromAddr);
        when(fm.getFunctionContaining(fromAddr)).thenReturn(caller);
        ghidra.program.model.symbol.ReferenceIterator rit =
            mock(ghidra.program.model.symbol.ReferenceIterator.class);
        when(rit.hasNext()).thenReturn(true, false);
        when(rit.next()).thenReturn(ref);
        when(rm.getReferencesTo(recvEntry)).thenReturn(rit);
        // Caller has no further callers (BFS stops)
        when(caller.getEntryPoint()).thenReturn(mock(ghidra.program.model.address.Address.class));
        when(rm.getReferencesTo(caller.getEntryPoint())).thenReturn(
            mock(ghidra.program.model.symbol.ReferenceIterator.class,
                inv -> { if (inv.getMethod().getName().equals("hasNext")) return false; return null; }));

        Response r = svc(p).enumerateAttackSurface(2, "");
        Map<String,Object> body = (Map<String,Object>) ((Response.Ok) r).data();
        Map<String,Object> groups = (Map<String,Object>) body.get("by_source_class");
        assertTrue(groups.containsKey("network"));
        List<?> netFns = (List<?>) groups.get("network");
        assertTrue(netFns.stream().anyMatch(m -> "HandlePacket".equals(((Map<?,?>)m).get("name"))));
    }
```

- [ ] **Step 2: Verify FAIL**, then **Step 3: Implement** (add to `VulnAnalysisService`)

```java
    @McpTool(path = "/enumerate_attack_surface", category = "security",
             description = "Enumerate the program's attack surface: every function within max_depth call-graph hops "
                         + "of a catalog SOURCE (network/file/env/cli/ipc), grouped by source class. Sources are "
                         + "matched by import name, function-name regex, or SOURCE_* tag — tag custom RTOS receive/"
                         + "ioctl handlers with SOURCE_NETWORK etc. to include them.")
    public Response enumerateAttackSurface(
            @Param(value = "max_depth", defaultValue = "3",
                   description = "BFS depth in the callers-of graph from each source.") int maxDepth,
            @Param(value = "program", defaultValue = "",
                   description = "Target program name (omit for active program)") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();
        FunctionManager fm = program.getFunctionManager();
        ghidra.program.model.symbol.ReferenceManager rm = program.getReferenceManager();

        // class → reachable functions (name, address, hops, via_source_id)
        Map<String, List<Map<String,Object>>> byClass = new LinkedHashMap<>();
        int sourceCount = 0;

        FunctionIterator it = fm.getFunctions(true);
        while (it.hasNext()) {
            Function f = it.next();
            List<CatalogEntry> hits = catalog.resolve(f);
            for (CatalogEntry e : hits) {
                if (!"source".equals(e.kind())) continue;
                sourceCount++;
                bfsCallers(program, fm, rm, f, e, maxDepth, byClass);
            }
        }

        return Response.ok(JsonHelper.mapOf(
            "by_source_class", byClass,
            "source_count",    sourceCount,
            "max_depth",       maxDepth,
            "catalog_status",  catalog.status() == null ? "ok" : catalog.status()));
    }

    private void bfsCallers(Program program, FunctionManager fm,
            ghidra.program.model.symbol.ReferenceManager rm,
            Function source, CatalogEntry entry, int maxDepth,
            Map<String, List<Map<String,Object>>> byClass) {
        Set<Function> seen = new HashSet<>();
        Deque<Map.Entry<Function,Integer>> q = new ArrayDeque<>();
        q.add(Map.entry(source, 0));
        List<Map<String,Object>> bucket =
            byClass.computeIfAbsent(entry.vulnClass(), k -> new ArrayList<>());
        while (!q.isEmpty()) {
            var cur = q.poll();
            Function fn = cur.getKey(); int depth = cur.getValue();
            if (!seen.add(fn)) continue;
            if (depth > 0) { // don't list the source itself as surface
                Map<String,Object> row = new LinkedHashMap<>(
                    ServiceUtils.addressToJson(fn.getEntryPoint(), program));
                row.put("name", fn.getName());
                row.put("hops", depth);
                row.put("via_source", entry.id());
                bucket.add(row);
            }
            if (depth >= maxDepth) continue;
            var refs = rm.getReferencesTo(fn.getEntryPoint());
            while (refs.hasNext()) {
                var ref = refs.next();
                if (!ref.getReferenceType().isCall()) continue;
                Function caller = fm.getFunctionContaining(ref.getFromAddress());
                if (caller != null && !seen.contains(caller)) q.add(Map.entry(caller, depth + 1));
            }
        }
    }
```

- [ ] **Step 4: Verify PASS** (3 tests total in `VulnAnalysisServiceTest`). **Step 5: Commit**
```bash
git add src/main/java/com/xebyte/core/vuln/VulnAnalysisService.java src/test/java/com/xebyte/offline/vuln/VulnAnalysisServiceTest.java
git commit -m "feat(vuln): enumerate_attack_surface — BFS callers-of from catalog sources

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

## Task 9: Service registration + endpoints.json

**Files:**
- Modify: `src/main/java/com/xebyte/GhidraMCPPlugin.java:~635`
- Modify: headless registration (find via `grep -rn "new AnnotationScanner(" src/main/java/com/xebyte/headless/`)
- Modify: `tests/endpoints.json` (regen)

- [ ] **Step 1: Wire into GUI scanner.** In `GhidraMCPPlugin.java`, locate the `new AnnotationScanner(programProvider, ...)` call (~line 635). Just before it, construct the new service (it needs `FunctionService` — confirm the local variable name from the surrounding constructions):

```java
VulnAnalysisService vulnAnalysisService =
    new VulnAnalysisService(programProvider, threadingStrategy, functionService);
```

Add `import com.xebyte.core.vuln.VulnAnalysisService;` to the file's imports. Then append `, vulnAnalysisService` to the scanner's varargs list (after `promptPolicyService`).

- [ ] **Step 2: Wire into headless scanner.** Run `grep -rn "new AnnotationScanner(" src/main/java/com/xebyte/headless/` to find the equivalent construction; mirror the same pattern there. If headless builds its services via a different factory, follow that file's existing pattern exactly.

- [ ] **Step 3: Build + offline parity.** `./gradlew test --tests 'com.xebyte.offline.*' -PGHIDRA_INSTALL_DIR=$GHIDRA_INSTALL_DIR --console=plain` — `EndpointsJsonParityTest` will FAIL because 3 new `@McpTool`s aren't in `tests/endpoints.json`.

- [ ] **Step 4: Regenerate catalog.** Maven is unusable on this box; check whether the regenerator runs under Gradle: `./gradlew test --tests 'com.xebyte.offline.RegenerateEndpointsJson' -PGHIDRA_INSTALL_DIR=$GHIDRA_INSTALL_DIR -Dregenerate=true --console=plain`. If that doesn't pick up the system property, fall back to running the class directly via `./gradlew -q javaexec ...` or — last resort — hand-add 3 entries to `tests/endpoints.json` matching neighboring entry shape (`path`, `method`, `category`, `description`). Then re-run parity → PASS.

- [ ] **Step 5: Commit**
```bash
git add src/main/java/com/xebyte/GhidraMCPPlugin.java src/main/java/com/xebyte/headless/ tests/endpoints.json
git commit -m "feat(vuln): register VulnAnalysisService and add 3 endpoints to catalog

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

## Task 10: Integration scaffold + fixture sources

**Files:**
- Create: `tests/integration/test_vuln_endpoints.py`
- Create: `fun-doc/benchmark/src/vuln_format.c`, `vuln_copy.c`, `vuln_alloc.c`, `vuln_exec.c`
- Create: `fun-doc/benchmark/truth/vuln_*.truth.yaml` (one per source)

- [ ] **Step 1: Add auto-skipping integration test**

```python
import json
import pytest


class TestVulnEndpoints:
    """detect_vuln_patterns / list_vuln_detectors / enumerate_attack_surface.
    Auto-skips when the live program has no resolvable sinks (e.g. stripped
    firmware with nothing tagged yet)."""

    def test_list_vuln_detectors(self, http_client):
        r = http_client.get("/list_vuln_detectors")
        assert r.status_code == 200
        body = json.loads(r.text)
        ids = {d["id"] for d in body["detectors"]}
        assert {"format_string", "unbounded_copy",
                "integer_overflow_alloc", "command_injection"} <= ids
        assert "catalog" in body

    def test_detect_vuln_patterns_whole_program(self, http_client):
        r = http_client.get("/detect_vuln_patterns",
                            params={"max_functions": "200"})
        assert r.status_code == 200
        body = json.loads(r.text)
        assert "findings" in body and "scanned_functions" in body
        if body.get("note", "").startswith("no catalog sinks resolved"):
            pytest.skip("no sinks in this program — tag SINK_*/SOURCE_* first")
        # Findings may legitimately be empty on a clean binary; just assert shape.
        for f in body["findings"]:
            assert {"detector_id", "vuln_class", "address",
                    "function", "sink", "confidence", "why"} <= set(f)

    def test_enumerate_attack_surface(self, http_client):
        r = http_client.get("/enumerate_attack_surface",
                            params={"max_depth": "2"})
        assert r.status_code == 200
        body = json.loads(r.text)
        assert "by_source_class" in body
```

Append the class to `tests/integration/test_vuln_endpoints.py` with the same module-level `pytestmark = [pytest.mark.readonly, pytest.mark.usefixtures("require_server")]` header used by `test_readonly_endpoints.py` (copy lines ~40-44 of that file). Verify collection: `python -m pytest tests/integration/test_vuln_endpoints.py --collect-only -q`.

- [ ] **Step 2: Add fixture C sources** under `fun-doc/benchmark/src/`. Each is a tiny standalone TU with one obviously-vulnerable function and one safe twin so the detector's negative case is covered too.

`vuln_format.c`:
```c
#include <stdio.h>
void Vuln_FormatFromArg(const char *user) { printf(user); }
void Safe_FormatLiteral(const char *user) { printf("%s", user); }
```

`vuln_copy.c`:
```c
#include <string.h>
void Vuln_CopyToStack(const char *src) { char buf[32]; strcpy(buf, src); }
void Safe_CopyBounded(const char *src) { char buf[32]; strncpy(buf, src, sizeof buf - 1); buf[31]=0; }
void Vuln_MemcpyUnchecked(const char *src, unsigned n) { char buf[64]; memcpy(buf, src, n); }
```

`vuln_alloc.c`:
```c
#include <stdlib.h>
void *Vuln_AllocMul(unsigned count) { return malloc(count * 16); }
void *Safe_AllocConst(void) { return malloc(128); }
```

`vuln_exec.c`:
```c
#include <stdlib.h>
int Vuln_ExecArg(const char *cmd) { return system(cmd); }
int Safe_ExecLiteral(void) { return system("/bin/true"); }
```

- [ ] **Step 3: Add ground-truth YAML** under `fun-doc/benchmark/truth/` (match the existing `*.truth.yaml` schema in that directory — open one to copy its keys). Each lists the expected detector id + function name for the `Vuln_*` functions and asserts the `Safe_*` twins produce no finding.

- [ ] **Step 4: Commit** (do NOT rebuild `Benchmark.dll` here — that needs the VC6 toolchain per CLAUDE.md; the C/YAML are checked in for when that pipeline runs):
```bash
git add tests/integration/test_vuln_endpoints.py fun-doc/benchmark/src/vuln_*.c fun-doc/benchmark/truth/vuln_*.truth.yaml
git commit -m "test(vuln): integration scaffold + fixture C sources with planted patterns

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

## Task 11: (Last, low-risk) Switch `analyze_dataflow` to call shared `PcodeQuery.describe/mnemonic`

**Files:**
- Modify: `src/main/java/com/xebyte/core/AnalysisService.java:~4874-4895`

- [ ] **Step 1:** Read the two private helpers `describeVarnode(Varnode)` and `mnemonic(PcodeOp)` in `AnalysisService.java` (~4874-4895). Replace their BODIES with one-line delegations:

```java
private static String describeVarnode(Varnode vn) { return com.xebyte.core.vuln.PcodeQuery.describe(vn); }
private static String mnemonic(PcodeOp op)        { return com.xebyte.core.vuln.PcodeQuery.mnemonic(op); }
```

Do NOT touch `traceBackward`/`traceForward` themselves. This removes ~30 lines of duplication without behavior change.

- [ ] **Step 2:** Run the full offline suite: `./gradlew test --tests 'com.xebyte.offline.*' -PGHIDRA_INSTALL_DIR=$GHIDRA_INSTALL_DIR --console=plain`. Expected PASS. If ANY `analyze_dataflow`-adjacent test changes output, **revert this task** and accept the duplication — note it in the commit message. Spec permits this.

- [ ] **Step 3: Commit**
```bash
git add src/main/java/com/xebyte/core/AnalysisService.java
git commit -m "refactor(vuln): delegate AnalysisService describeVarnode/mnemonic to PcodeQuery

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

## Self-Review

**Spec coverage:**
- `com.xebyte.core.vuln` package, records, interface → Task 1. ✓
- `vuln_catalog.json` baked-in + `$GHIDRA_MCP_VULN_CATALOG` / `~/.ghidra-mcp` override + import∪regex∪tag resolve → Task 2. ✓
- `PcodeQuery` helpers (`argVarnode`, `reachesConstantOnly`, `definingOps`, `hasDominatingCompare`, `destBufferSize`, `describe`, `mnemonic`) → Task 3. ✓
- Four detectors → Tasks 4-6. ✓
- 3 endpoints + bookmark write + `decompile_failures`/`catalog_status`/`note` → Tasks 7-8. ✓
- AnnotationScanner registration (GUI + headless) + endpoints.json → Task 9. ✓
- Offline tests per component, catalog schema test, integration test, fixture C → Tasks 1-10. ✓
- `analyze_dataflow` shared-helper rewire (no behavior change) → Task 11 (escape-hatch documented). ✓
- Address output via `ServiceUtils.addressToJson` (overlay-aware) → Task 8 `bfsCallers` row build; Task 7 emits `addr.toString()` (callAddr is already an `Address` — acceptable; the `Finding.address` field is the human/feed-back string).

**Placeholder scan:** Three "verify the real API and adapt" instructions remain (Task 7 `Response.Ok.data()` / `ThreadingStrategy.executeWrite` / `ServiceUtils.findFunction`; Task 9 headless scanner location + Gradle regen flag; Task 10 truth-YAML schema). Each is paired with the exact `grep` to run and the fallback. These are not blanks — they're discoverable-in-repo facts that depend on names I cannot hard-code without risking drift.

**Type consistency:** `Finding`, `CatalogEntry`, `SinkCallSite`, `VulnDetector`, `PcodeQuery` method names are identical across all tasks. `arg("size_arg")` etc. consistent with `ARG_ROLE_KEYS`. Detector ids (`format_string`, `command_injection`, `unbounded_copy`, `integer_overflow_alloc`) match between Tasks 4-6, Task 7's registry, and Task 10's integration test.
