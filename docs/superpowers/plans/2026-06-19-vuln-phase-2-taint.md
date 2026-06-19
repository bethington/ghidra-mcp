# VulnAnalysisService Phase 2 — `find_taint_path` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Backward inter-procedural taint tracer that answers "does this sink argument trace back to a catalog source?" Exposed as `/find_taint_path` and as opt-in `taint=true` on `detect_vuln_patterns` (which then bumps tainted findings to `confidence:"high"`).

**Architecture:** New stateful `TaintTracer` (`AutoCloseable`) owns a per-scan `DecompInterface` + `Map<Function,HighFunction>` cache and a `Map<HighFunction,Set<Varnode>>` tainted-buffer-roots cache. `trace(...)` runs a BFS-by-call-depth worklist: intra-function backward walk via `getDef()`; at CALL-return → recurse into callee's RETURN inputs (or stop at catalog source); at LOAD → check tainted-buffer roots; at HighParam → fan out to callers' arg varnodes. Result records (`TaintStep`, `TaintResult`) carry the path. `Finding` is NOT modified — the service merges taint fields into each finding's JSON at response time.

**Tech Stack:** Java 21, Ghidra `DecompInterface`/`HighFunction`/`PcodeOp`/`Varnode`/`HighSymbol`, JUnit4 + Mockito, Gradle.

**Spec:** `docs/superpowers/specs/2026-06-19-vuln-phase-2-taint-design.md`

## Global Constraints

- Working dir / branch: `feature/vuln-analysis-service` in `/home/pj.reid/ai/tools/ghidra-mcp/.claude/worktrees/overlay-address-spaces`.
- Java tests via Gradle only: `./gradlew test --tests '<pattern>' -PGHIDRA_INSTALL_DIR=$GHIDRA_INSTALL_DIR --console=plain` (Maven unusable on this box).
- Do NOT modify `Finding.java`, the four detector classes, `PcodeQuery.java`, or `SinkCatalog.java`. Taint fields are merged into the JSON at the service layer.
- All commits: no `Co-Authored-By: Claude` trailers.
- Bounds (verbatim from spec): `maxCallDepth` clamped `[1,10]`; `maxFunctions` clamped `[1,256]`; caller fan-out per param boundary capped at 16; intra-function step cap 64; `taint_path` truncated to 32 steps in JSON.
- Ghidra param-detection API (verified in codebase): `varnode.getHigh().getSymbol().isParameter()` and `HighSymbol.getCategoryIndex()` for the slot index.
- Ghidra `PcodeOp.RETURN` shape: `input(0)` is the indirect-jump target (constant for normal returns); the return VALUE (when present) is `input(1)`. Verify against Ghidra source if a test surfaces otherwise.

---

## File Structure

| File | Responsibility | Task |
| --- | --- | --- |
| `src/main/java/com/xebyte/core/vuln/TaintStep.java` | One step in a path (record + `toJson`) | 1 |
| `src/main/java/com/xebyte/core/vuln/TaintResult.java` | Full trace result (record + `toJson`) | 1 |
| `src/main/java/com/xebyte/core/vuln/TaintTracer.java` | Decomp cache, buffer-roots cache, `trace()` | 2, 3 |
| `src/test/java/com/xebyte/offline/vuln/TaintTracerTest.java` | Infra + algorithm tests | 2, 3 |
| `src/main/java/com/xebyte/core/vuln/VulnAnalysisService.java` | `/find_taint_path` endpoint; `taint` param integration | 4, 5 |
| `src/test/java/com/xebyte/offline/vuln/VulnAnalysisServiceTest.java` | endpoint + taint-integration tests | 4, 5 |
| `tests/endpoints.json` | new endpoint + 2 new params | 6 |

---

## Task 1: `TaintStep` + `TaintResult` records

**Files:**
- Create: `src/main/java/com/xebyte/core/vuln/TaintStep.java`
- Create: `src/main/java/com/xebyte/core/vuln/TaintResult.java`
- Test: `src/test/java/com/xebyte/offline/vuln/TaintResultTest.java`

**Interfaces:**
- Produces: `record TaintStep(String function, String address, String kind, String detail)` with `Map<String,Object> toJson()`.
- Produces: `record TaintResult(CatalogEntry source, List<TaintStep> path, String terminalReason, int functionsVisited, int callDepthReached)` with `Map<String,Object> toJson()` that emits `source` as `{id,class,kind}` or null, and truncates `path` to 32 steps.

- [ ] **Step 1: Write failing test** `TaintResultTest.java`

```java
package com.xebyte.offline.vuln;

import com.xebyte.core.vuln.*;
import org.junit.Test;
import java.util.List;
import java.util.Map;
import static org.junit.Assert.*;

public class TaintResultTest {
    @Test @SuppressWarnings("unchecked")
    public void toJson_withSource_emitsAllFields() {
        CatalogEntry src = new CatalogEntry("recv","source","network",
            Map.of("out_arg",1), false, List.of(), List.of(), List.of());
        TaintStep s1 = new TaintStep("F","00401000","param","param_2 → caller arg");
        TaintResult r = new TaintResult(src, List.of(s1), "source", 3, 2);
        Map<String,Object> j = r.toJson();
        Map<String,Object> jsrc = (Map<String,Object>) j.get("source");
        assertEquals("recv", jsrc.get("id"));
        assertEquals("network", jsrc.get("class"));
        assertEquals("source", j.get("terminal_reason"));
        assertEquals(3, j.get("functions_visited"));
        assertEquals(2, j.get("call_depth_reached"));
        List<?> path = (List<?>) j.get("path");
        assertEquals(1, path.size());
        assertEquals("param", ((Map<?,?>)path.get(0)).get("kind"));
    }

    @Test
    public void toJson_nullSource_emitsNull() {
        TaintResult r = new TaintResult(null, List.of(), "budget", 64, 10);
        assertNull(r.toJson().get("source"));
        assertEquals("budget", r.toJson().get("terminal_reason"));
    }

    @Test @SuppressWarnings("unchecked")
    public void toJson_truncatesPathTo32() {
        var steps = new java.util.ArrayList<TaintStep>();
        for (int i = 0; i < 50; i++) steps.add(new TaintStep("F","0","op","step"+i));
        TaintResult r = new TaintResult(null, steps, "budget", 1, 1);
        List<?> path = (List<?>) r.toJson().get("path");
        assertEquals(32, path.size());
        assertTrue((Boolean) r.toJson().get("path_truncated"));
    }
}
```

- [ ] **Step 2: Verify FAIL** (compile error)
`./gradlew test --tests 'com.xebyte.offline.vuln.TaintResultTest' -PGHIDRA_INSTALL_DIR=$GHIDRA_INSTALL_DIR --console=plain`

- [ ] **Step 3: Implement `TaintStep.java`**

```java
package com.xebyte.core.vuln;

import com.xebyte.core.JsonHelper;
import java.util.Map;

/** One backward step in a taint path. {@code kind} ∈ "op"|"call_return"|"param"|"load"|"source". */
public record TaintStep(String function, String address, String kind, String detail) {
    public Map<String, Object> toJson() {
        return JsonHelper.mapOf("function", function, "address", address,
                                "kind", kind, "detail", detail);
    }
}
```

- [ ] **Step 4: Implement `TaintResult.java`**

```java
package com.xebyte.core.vuln;

import com.xebyte.core.JsonHelper;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Result of one backward inter-procedural taint trace. {@code source} is the
 * catalog entry reached (null if none). {@code terminalReason} ∈
 * "source"|"tainted_load"|"load_unknown_provenance"|"budget"|"call_depth"|
 * "recursion"|"constant"|"decompile_failed"|"no_path".
 */
public record TaintResult(CatalogEntry source, List<TaintStep> path,
        String terminalReason, int functionsVisited, int callDepthReached) {

    private static final int PATH_JSON_CAP = 32;

    public Map<String, Object> toJson() {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("source", source == null ? null
            : JsonHelper.mapOf("id", source.id(), "class", source.vulnClass(),
                               "kind", source.kind()));
        List<Map<String,Object>> steps = new ArrayList<>();
        int n = Math.min(path.size(), PATH_JSON_CAP);
        for (int i = 0; i < n; i++) steps.add(path.get(i).toJson());
        out.put("path", steps);
        out.put("path_truncated", path.size() > PATH_JSON_CAP);
        out.put("terminal_reason", terminalReason);
        out.put("functions_visited", functionsVisited);
        out.put("call_depth_reached", callDepthReached);
        return out;
    }
}
```

- [ ] **Step 5: Verify PASS** (3 tests). **Commit**
```bash
git add src/main/java/com/xebyte/core/vuln/TaintStep.java src/main/java/com/xebyte/core/vuln/TaintResult.java src/test/java/com/xebyte/offline/vuln/TaintResultTest.java
git commit -m "feat(vuln): TaintStep + TaintResult records for inter-procedural taint paths"
```

---

## Task 2: `TaintTracer` infrastructure — cache, close, taintedBufferRoots

**Files:**
- Create: `src/main/java/com/xebyte/core/vuln/TaintTracer.java`
- Create: `src/test/java/com/xebyte/offline/vuln/TaintTracerTest.java`

**Interfaces:**
- Produces: `public final class TaintTracer implements AutoCloseable` with:
  - `TaintTracer(Program program, SinkCatalog catalog)` — opens its own `DecompInterface`
  - `TaintTracer(Program program, SinkCatalog catalog, DecompInterface shared)` — reuses an existing one (does NOT dispose it on close)
  - package-visible `HighFunction decompile(Function f)` — cache lookup → `DecompInterface.decompileFunction(f, 12, TaskMonitor.DUMMY)`; null on failure
  - package-visible `Set<Varnode> taintedBufferRoots(HighFunction hf)` — cached
  - `void close()` — disposes the `DecompInterface` only if owned
  - `int functionsVisited()` — `cache.size()`
- The `trace(...)` method is added in Task 3; this task creates a stub that throws `UnsupportedOperationException("Task 3")`.

- [ ] **Step 1: Write failing tests** (`TaintTracerTest.java`) — infra only

```java
package com.xebyte.offline.vuln;

import com.xebyte.core.vuln.*;
import ghidra.app.decompiler.DecompInterface;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.*;
import org.junit.Test;
import java.util.*;
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class TaintTracerTest {

    private SinkCatalog catalog() { return SinkCatalog.load(null); }

    @Test
    public void close_disposesOwnedDecompiler_butNotShared() {
        Program p = mock(Program.class);
        DecompInterface shared = mock(DecompInterface.class);
        TaintTracer t = new TaintTracer(p, catalog(), shared);
        t.close();
        verify(shared, never()).dispose();
        // Owned-ctor path: openProgram throws on a mock Program → ctor must
        // still construct (decomp may be null) and close() must not NPE.
        TaintTracer owned = new TaintTracer(p, catalog());
        owned.close(); // no exception
    }

    @Test
    public void taintedBufferRoots_collectsSourceOutArgAndReturn() {
        // hf has two CALLs: recv(sock, BUF, len) → out_arg=1; getenv() → return=true.
        HighFunction hf = mock(HighFunction.class);
        Function fn = mock(Function.class); when(hf.getFunction()).thenReturn(fn);

        Function recvFn = mock(Function.class);
        when(recvFn.isThunk()).thenReturn(false);
        when(recvFn.getName()).thenReturn("recv");
        when(recvFn.getTags()).thenReturn(Set.of());
        Function getenvFn = mock(Function.class);
        when(getenvFn.isThunk()).thenReturn(false);
        when(getenvFn.getName()).thenReturn("getenv");
        when(getenvFn.getTags()).thenReturn(Set.of());

        Varnode buf = mock(Varnode.class);
        Varnode envRet = mock(Varnode.class);

        PcodeOpAST callRecv = mock(PcodeOpAST.class);
        when(callRecv.getOpcode()).thenReturn(PcodeOp.CALL);
        when(callRecv.getNumInputs()).thenReturn(4);
        Varnode tgtR = mock(Varnode.class); when(tgtR.isAddress()).thenReturn(true);
        Address aR = mock(Address.class); when(tgtR.getAddress()).thenReturn(aR);
        when(callRecv.getInput(0)).thenReturn(tgtR);
        when(callRecv.getInput(1)).thenReturn(mock(Varnode.class)); // sock
        when(callRecv.getInput(2)).thenReturn(buf);                 // out_arg=1 → input(2)
        when(callRecv.getInput(3)).thenReturn(mock(Varnode.class));

        PcodeOpAST callGetenv = mock(PcodeOpAST.class);
        when(callGetenv.getOpcode()).thenReturn(PcodeOp.CALL);
        when(callGetenv.getNumInputs()).thenReturn(2);
        Varnode tgtG = mock(Varnode.class); when(tgtG.isAddress()).thenReturn(true);
        Address aG = mock(Address.class); when(tgtG.getAddress()).thenReturn(aG);
        when(callGetenv.getInput(0)).thenReturn(tgtG);
        when(callGetenv.getInput(1)).thenReturn(mock(Varnode.class));
        when(callGetenv.getOutput()).thenReturn(envRet);

        when(hf.getPcodeOps()).thenAnswer(inv -> List.of(callRecv, callGetenv).iterator());

        Program p = mock(Program.class);
        ghidra.program.model.listing.FunctionManager fm =
            mock(ghidra.program.model.listing.FunctionManager.class);
        when(p.getFunctionManager()).thenReturn(fm);
        when(fm.getFunctionAt(aR)).thenReturn(recvFn);
        when(fm.getFunctionAt(aG)).thenReturn(getenvFn);

        TaintTracer t = new TaintTracer(p, catalog(), mock(DecompInterface.class));
        Set<Varnode> roots = t.taintedBufferRoots(hf);
        assertTrue(roots.contains(buf));
        assertTrue(roots.contains(envRet));
        // cached: second call same instance
        assertSame(roots, t.taintedBufferRoots(hf));
        t.close();
    }
}
```

- [ ] **Step 2: Verify FAIL**

- [ ] **Step 3: Implement `TaintTracer.java` (infra only; `trace()` stubbed)**

```java
package com.xebyte.core.vuln;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.util.task.TaskMonitor;

import java.util.*;

/**
 * Backward inter-procedural taint tracer. Stateful per scan: owns a
 * DecompInterface (or reuses a shared one) and caches HighFunctions and
 * per-function tainted-buffer roots. AutoCloseable — use try-with-resources.
 */
public final class TaintTracer implements AutoCloseable {

    static final int DECOMP_TIMEOUT_S = 12;
    static final int INTRA_STEP_CAP   = 64;
    static final int CALLER_FANOUT_CAP = 16;

    private final Program program;
    private final SinkCatalog catalog;
    private final DecompInterface decomp;
    private final boolean ownsDecomp;
    private final Map<Function, HighFunction> hfCache = new HashMap<>();
    private final Map<HighFunction, Set<Varnode>> rootsCache = new IdentityHashMap<>();

    public TaintTracer(Program program, SinkCatalog catalog) {
        this(program, catalog, openOwn(program), true);
    }

    public TaintTracer(Program program, SinkCatalog catalog, DecompInterface shared) {
        this(program, catalog, shared, false);
    }

    private TaintTracer(Program p, SinkCatalog c, DecompInterface d, boolean owns) {
        this.program = p; this.catalog = c; this.decomp = d; this.ownsDecomp = owns;
    }

    private static DecompInterface openOwn(Program program) {
        try {
            DecompInterface d = new DecompInterface();
            d.openProgram(program);
            d.setSimplificationStyle("decompile");
            return d;
        } catch (Exception e) {
            return null;
        }
    }

    @Override public void close() {
        if (ownsDecomp && decomp != null) {
            try { decomp.dispose(); } catch (Exception ignored) {}
        }
    }

    public int functionsVisited() { return hfCache.size(); }

    /** Decompile via cache. Returns null on failure (counted as a miss). */
    HighFunction decompile(Function f) {
        if (f == null) return null;
        if (hfCache.containsKey(f)) return hfCache.get(f);
        HighFunction hf = null;
        if (decomp != null) {
            try {
                DecompileResults r = decomp.decompileFunction(f, DECOMP_TIMEOUT_S, TaskMonitor.DUMMY);
                if (r != null && r.decompileCompleted()) hf = r.getHighFunction();
            } catch (Exception ignored) {}
        }
        hfCache.put(f, hf); // cache nulls too (don't retry)
        return hf;
    }

    /**
     * Varnodes in {@code hf} that are catalog-source output buffers: the
     * out_arg varnode of any source call site, and the output varnode of any
     * source call with returnIsOutput=true. Cached per HighFunction.
     */
    Set<Varnode> taintedBufferRoots(HighFunction hf) {
        Set<Varnode> cached = rootsCache.get(hf);
        if (cached != null) return cached;
        Set<Varnode> roots = new LinkedHashSet<>();
        FunctionManager fm = program.getFunctionManager();
        var ops = hf.getPcodeOps();
        while (ops.hasNext()) {
            PcodeOp op = ops.next();
            int oc = op.getOpcode();
            if (oc != PcodeOp.CALL && oc != PcodeOp.CALLIND) continue;
            Function callee = resolveCallee(op, fm);
            if (callee == null) continue;
            for (CatalogEntry e : catalog.resolve(callee)) {
                if (!"source".equals(e.kind())) continue;
                Integer outIdx = e.arg("out_arg");
                if (outIdx != null) {
                    Varnode v = PcodeQuery.argVarnode(op, outIdx);
                    if (v != null) roots.add(v);
                }
                if (e.returnIsOutput() && op.getOutput() != null) {
                    roots.add(op.getOutput());
                }
            }
        }
        rootsCache.put(hf, roots);
        return roots;
    }

    Function resolveCallee(PcodeOp op, FunctionManager fm) {
        if (op.getNumInputs() == 0) return null;
        Varnode tgt = op.getInput(0);
        if (tgt != null && tgt.isAddress()) {
            Function f = fm.getFunctionAt(tgt.getAddress());
            if (f != null && f.isThunk()) {
                Function real = f.getThunkedFunction(true);
                if (real != null) return real;
            }
            return f;
        }
        // CALLIND fallback via references — same approach as VulnAnalysisService.resolveCallee
        if (op.getSeqnum() != null) {
            ReferenceManager rm = program.getReferenceManager();
            for (Reference ref : rm.getReferencesFrom(op.getSeqnum().getTarget())) {
                if (ref.getReferenceType().isCall()) {
                    Function f = fm.getFunctionAt(ref.getToAddress());
                    if (f != null) return f;
                }
            }
        }
        return null;
    }

    // ---- trace() — implemented in Task 3 ----
    public TaintResult trace(HighFunction startHf, PcodeOp sinkCall, int argIdx,
            int maxCallDepth, int maxFunctions) {
        throw new UnsupportedOperationException("Task 3");
    }
}
```

- [ ] **Step 4: Verify PASS** (2 tests). **Commit**
```bash
git add src/main/java/com/xebyte/core/vuln/TaintTracer.java src/test/java/com/xebyte/offline/vuln/TaintTracerTest.java
git commit -m "feat(vuln): TaintTracer infrastructure — decomp cache, taintedBufferRoots, AutoCloseable"
```

---

## Task 3: `TaintTracer.trace()` — the backward inter-procedural walk

**Files:**
- Modify: `src/main/java/com/xebyte/core/vuln/TaintTracer.java` (replace the stub)
- Modify: `src/test/java/com/xebyte/offline/vuln/TaintTracerTest.java` (add 5 algorithm tests)

**Interfaces:**
- Consumes: `TaintStep`, `TaintResult`, `decompile(Function)`, `taintedBufferRoots(HighFunction)`, `resolveCallee(...)`, `PcodeQuery.argVarnode`.
- Produces: `public TaintResult trace(HighFunction startHf, PcodeOp sinkCall, int argIdx, int maxCallDepth, int maxFunctions)` — BFS-by-call-depth, first source wins.

- [ ] **Step 1: Add a shared mock-harness helper class** at the top of `TaintTracerTest` (after the existing infra tests). This builds minimal `HighFunction`/`PcodeOp`/`Varnode` graphs for cross-function chains. The pattern: every `Varnode` is a Mockito mock with `isConstant()/getDef()/getHigh()` stubbed; `HighFunction` mocks return a `Function` and an iterator of `PcodeOpAST` ops; `Function` mocks have `getName()/getEntryPoint()/getTags()/isThunk()`. Callers are wired via `ReferenceManager.getReferencesTo`.

```java
    // ---- algorithm-test harness ----

    private Varnode konst(long k) {
        Varnode v = mock(Varnode.class);
        when(v.isConstant()).thenReturn(true);
        when(v.getOffset()).thenReturn(k);
        return v;
    }
    private Varnode vn(PcodeOp def) {
        Varnode v = mock(Varnode.class);
        when(v.isConstant()).thenReturn(false);
        when(v.getDef()).thenReturn(def);
        return v;
    }
    private Varnode paramVn(int slot) {
        Varnode v = mock(Varnode.class);
        when(v.isConstant()).thenReturn(false);
        when(v.getDef()).thenReturn(null);
        HighVariable hv = mock(HighVariable.class);
        HighSymbol sym = mock(HighSymbol.class);
        when(sym.isParameter()).thenReturn(true);
        when(sym.getCategoryIndex()).thenReturn(slot);
        when(hv.getSymbol()).thenReturn(sym);
        when(v.getHigh()).thenReturn(hv);
        return v;
    }
    private PcodeOpAST callOp(Address site, Varnode tgt, Varnode out, Varnode... args) {
        PcodeOpAST op = mock(PcodeOpAST.class);
        when(op.getOpcode()).thenReturn(PcodeOp.CALL);
        when(op.getNumInputs()).thenReturn(1 + args.length);
        when(op.getInput(0)).thenReturn(tgt);
        for (int i = 0; i < args.length; i++) when(op.getInput(i+1)).thenReturn(args[i]);
        when(op.getOutput()).thenReturn(out);
        SequenceNumber sn = mock(SequenceNumber.class);
        when(sn.getTarget()).thenReturn(site);
        when(op.getSeqnum()).thenReturn(sn);
        return op;
    }
    private Varnode addrTgt(Address a) {
        Varnode t = mock(Varnode.class);
        when(t.isAddress()).thenReturn(true);
        when(t.getAddress()).thenReturn(a);
        return t;
    }
    private HighFunction hfOf(Function fn, PcodeOpAST... ops) {
        HighFunction hf = mock(HighFunction.class);
        when(hf.getFunction()).thenReturn(fn);
        when(hf.getPcodeOps()).thenAnswer(inv -> Arrays.asList(ops).iterator());
        return hf;
    }
    private Function fn(String name, Address entry) {
        Function f = mock(Function.class);
        when(f.getName()).thenReturn(name);
        when(f.getEntryPoint()).thenReturn(entry);
        when(f.isThunk()).thenReturn(false);
        when(f.getTags()).thenReturn(Set.of());
        return f;
    }
```

- [ ] **Step 2: Write the 5 failing algorithm tests** (append to `TaintTracerTest`)

The tests construct a `TaintTracer` with a **mock `DecompInterface`** stubbed so `decompileFunction(f, ...)` returns a `DecompileResults` whose `getHighFunction()` is the prebuilt mock for `f`. Helper:

```java
    private DecompInterface decompOf(Map<Function, HighFunction> map) {
        DecompInterface d = mock(DecompInterface.class);
        when(d.decompileFunction(any(), anyInt(), any())).thenAnswer(inv -> {
            Function f = inv.getArgument(0);
            HighFunction hf = map.get(f);
            DecompileResults r = mock(DecompileResults.class);
            when(r.decompileCompleted()).thenReturn(hf != null);
            when(r.getHighFunction()).thenReturn(hf);
            return r;
        });
        return d;
    }
```

Five tests (each ~25 lines; full bodies below). Common setup pattern: build `Program`/`FunctionManager`/`ReferenceManager` mocks; wire `getFunctionAt(addr)` and `getReferencesTo(entry)` for the chain; build the tracer with `decompOf(map)`.

```java
    @Test
    public void trace_paramChain_reachesSourceCall() {
        // Sink(n=param0) ← Mid calls Sink(len) where len = output of recv(...).
        // Backward: n → param0 → caller Mid's arg0 = recvRet → CALL recv → source.
        Program p = mock(Program.class);
        FunctionManager fm = mock(FunctionManager.class);
        when(p.getFunctionManager()).thenReturn(fm);
        ReferenceManager rm = mock(ReferenceManager.class);
        when(p.getReferenceManager()).thenReturn(rm);

        Address aSink = mock(Address.class), aMid = mock(Address.class),
                aRecv = mock(Address.class), aMemcpy = mock(Address.class),
                callSite = mock(Address.class), recvSite = mock(Address.class);
        Function sinkFn = fn("Sink", aSink), midFn = fn("Mid", aMid),
                 recvFn = fn("recv", aRecv), memcpyFn = fn("memcpy", aMemcpy);
        when(fm.getFunctionAt(aRecv)).thenReturn(recvFn);
        when(fm.getFunctionAt(aMemcpy)).thenReturn(memcpyFn);
        when(fm.getFunctionAt(aSink)).thenReturn(sinkFn);

        // Sink: memcpy(dst, src, n) where n = param0
        Varnode n = paramVn(0);
        PcodeOpAST sinkCall = callOp(mock(Address.class), addrTgt(aMemcpy), null,
            mock(Varnode.class), mock(Varnode.class), n);
        HighFunction hfSink = hfOf(sinkFn, sinkCall);

        // Mid: len = recv(...); Sink(len);
        Varnode recvRet = mock(Varnode.class);
        PcodeOpAST callRecv = callOp(recvSite, addrTgt(aRecv), recvRet,
            mock(Varnode.class), mock(Varnode.class), mock(Varnode.class));
        when(recvRet.isConstant()).thenReturn(false);
        when(recvRet.getDef()).thenReturn(callRecv);
        PcodeOpAST callSink = callOp(callSite, addrTgt(aSink), null, recvRet);
        HighFunction hfMid = hfOf(midFn, callRecv, callSink);

        // Caller wiring: Sink has one caller Mid at callSite
        Reference ref = mock(Reference.class);
        ghidra.program.model.symbol.RefType rt = mock(ghidra.program.model.symbol.RefType.class);
        when(rt.isCall()).thenReturn(true);
        when(ref.getReferenceType()).thenReturn(rt);
        when(ref.getFromAddress()).thenReturn(callSite);
        ghidra.program.model.symbol.ReferenceIterator rit =
            mock(ghidra.program.model.symbol.ReferenceIterator.class);
        when(rit.hasNext()).thenReturn(true, false);
        when(rit.next()).thenReturn(ref);
        when(rm.getReferencesTo(aSink)).thenReturn(rit);
        when(fm.getFunctionContaining(callSite)).thenReturn(midFn);
        // Mid's hf must let trace find callSink at callSite:
        when(hfMid.getPcodeOps(callSite)).thenAnswer(inv -> List.of(callSink).iterator());

        TaintTracer t = new TaintTracer(p, catalog(),
            decompOf(Map.of(sinkFn, hfSink, midFn, hfMid)));
        TaintResult r = t.trace(hfSink, sinkCall, 2, 5, 64);
        assertNotNull("should reach recv as a source", r.source());
        assertEquals("recv", r.source().id());
        assertEquals("source", r.terminalReason());
        t.close();
    }

    @Test
    public void trace_loadFromTaintedBuffer_reachesSource() {
        // Single function: recv(sock, buf, len); n = LOAD(buf + 8); memcpy(dst,src,n).
        Program p = mock(Program.class);
        FunctionManager fm = mock(FunctionManager.class);
        when(p.getFunctionManager()).thenReturn(fm);
        when(p.getReferenceManager()).thenReturn(mock(ReferenceManager.class));
        Address aRecv = mock(Address.class), aMemcpy = mock(Address.class);
        Function fnF = fn("F", mock(Address.class));
        Function recvFn = fn("recv", aRecv), memcpyFn = fn("memcpy", aMemcpy);
        when(fm.getFunctionAt(aRecv)).thenReturn(recvFn);
        when(fm.getFunctionAt(aMemcpy)).thenReturn(memcpyFn);

        Varnode buf = mock(Varnode.class);
        when(buf.isConstant()).thenReturn(false); when(buf.getDef()).thenReturn(null);
        PcodeOpAST callRecv = callOp(mock(Address.class), addrTgt(aRecv), null,
            mock(Varnode.class), buf, mock(Varnode.class)); // out_arg=1 → buf
        // addr = PTRADD(buf, 8, 1)
        PcodeOp ptradd = mock(PcodeOp.class);
        when(ptradd.getOpcode()).thenReturn(PcodeOp.PTRADD);
        when(ptradd.getNumInputs()).thenReturn(3);
        when(ptradd.getInput(0)).thenReturn(buf);
        when(ptradd.getInput(1)).thenReturn(konst(8));
        when(ptradd.getInput(2)).thenReturn(konst(1));
        Varnode addr = vn(ptradd);
        // n = LOAD(space, addr)
        PcodeOp load = mock(PcodeOp.class);
        when(load.getOpcode()).thenReturn(PcodeOp.LOAD);
        when(load.getNumInputs()).thenReturn(2);
        when(load.getInput(0)).thenReturn(konst(0));
        when(load.getInput(1)).thenReturn(addr);
        Varnode n = vn(load);
        PcodeOpAST sinkCall = callOp(mock(Address.class), addrTgt(aMemcpy), null,
            mock(Varnode.class), mock(Varnode.class), n);
        HighFunction hf = hfOf(fnF, callRecv, sinkCall);

        TaintTracer t = new TaintTracer(p, catalog(), decompOf(Map.of(fnF, hf)));
        TaintResult r = t.trace(hf, sinkCall, 2, 5, 64);
        assertNotNull(r.source());
        assertEquals("recv", r.source().id());
        assertEquals("tainted_load", r.terminalReason());
        t.close();
    }

    @Test
    public void trace_noSource_terminatesWithReason() {
        // memcpy(dst, src, const) — n is constant → terminal "constant", source null.
        Program p = mock(Program.class);
        when(p.getFunctionManager()).thenReturn(mock(FunctionManager.class));
        when(p.getReferenceManager()).thenReturn(mock(ReferenceManager.class));
        Function fnF = fn("F", mock(Address.class));
        PcodeOpAST sinkCall = callOp(mock(Address.class),
            addrTgt(mock(Address.class)), null,
            mock(Varnode.class), mock(Varnode.class), konst(32));
        HighFunction hf = hfOf(fnF, sinkCall);
        TaintTracer t = new TaintTracer(p, catalog(), decompOf(Map.of(fnF, hf)));
        TaintResult r = t.trace(hf, sinkCall, 2, 5, 64);
        assertNull(r.source());
        assertEquals("constant", r.terminalReason());
        t.close();
    }

    @Test
    public void trace_budgetExhausted_returnsBudgetReason() {
        // n = param0; Sink has 0 callers but maxCallDepth=0 → can't cross → budget.
        Program p = mock(Program.class);
        when(p.getFunctionManager()).thenReturn(mock(FunctionManager.class));
        ReferenceManager rm = mock(ReferenceManager.class);
        when(p.getReferenceManager()).thenReturn(rm);
        Function fnF = fn("F", mock(Address.class));
        ghidra.program.model.symbol.ReferenceIterator rit =
            mock(ghidra.program.model.symbol.ReferenceIterator.class);
        when(rit.hasNext()).thenReturn(false);
        when(rm.getReferencesTo(any())).thenReturn(rit);
        Varnode n = paramVn(0);
        PcodeOpAST sinkCall = callOp(mock(Address.class),
            addrTgt(mock(Address.class)), null,
            mock(Varnode.class), mock(Varnode.class), n);
        HighFunction hf = hfOf(fnF, sinkCall);
        TaintTracer t = new TaintTracer(p, catalog(), decompOf(Map.of(fnF, hf)));
        TaintResult r = t.trace(hf, sinkCall, 2, /*maxCallDepth*/ 0, 64);
        assertNull(r.source());
        // depth 0 → cannot cross param boundary → "call_depth"
        assertEquals("call_depth", r.terminalReason());
        t.close();
    }

    @Test
    public void trace_recursionGuard_preventsLoop() {
        // F.param0 → caller F (self-recursive). onPath guard must terminate.
        Program p = mock(Program.class);
        FunctionManager fm = mock(FunctionManager.class);
        when(p.getFunctionManager()).thenReturn(fm);
        ReferenceManager rm = mock(ReferenceManager.class);
        when(p.getReferenceManager()).thenReturn(rm);
        Address aF = mock(Address.class), site = mock(Address.class);
        Function fnF = fn("F", aF);
        when(fm.getFunctionAt(aF)).thenReturn(fnF);
        when(fm.getFunctionContaining(site)).thenReturn(fnF);
        Reference ref = mock(Reference.class);
        ghidra.program.model.symbol.RefType rt = mock(ghidra.program.model.symbol.RefType.class);
        when(rt.isCall()).thenReturn(true);
        when(ref.getReferenceType()).thenReturn(rt);
        when(ref.getFromAddress()).thenReturn(site);
        ghidra.program.model.symbol.ReferenceIterator rit =
            mock(ghidra.program.model.symbol.ReferenceIterator.class);
        when(rit.hasNext()).thenReturn(true, false);
        when(rit.next()).thenReturn(ref);
        when(rm.getReferencesTo(aF)).thenReturn(rit);

        Varnode n = paramVn(0);
        PcodeOpAST sinkCall = callOp(mock(Address.class), addrTgt(mock(Address.class)),
            null, mock(Varnode.class), mock(Varnode.class), n);
        // Self-call at `site` passing param0 again
        PcodeOpAST selfCall = callOp(site, addrTgt(aF), null, n);
        HighFunction hf = hfOf(fnF, selfCall, sinkCall);
        when(hf.getPcodeOps(site)).thenAnswer(inv -> List.of(selfCall).iterator());

        TaintTracer t = new TaintTracer(p, catalog(), decompOf(Map.of(fnF, hf)));
        TaintResult r = t.trace(hf, sinkCall, 2, 5, 64);
        assertNull(r.source());
        assertEquals("recursion", r.terminalReason());
        t.close();
    }
```

NOTE on mocks: `HighFunction.getPcodeOps()` (no-arg) and `getPcodeOps(Address)` are both used — the no-arg form by `taintedBufferRoots` (Task 2) and by the trace's intra-function search for the caller's CALL op at a specific address. Stub BOTH where needed. If Mockito complains about `final` methods on any concrete Ghidra class, add `mockito-inline` is already in use (it worked for HighFunction/PcodeOp in Phase 1) — adapt only if a specific stub fails.

- [ ] **Step 3: Verify FAIL** (5 new tests fail with `UnsupportedOperationException("Task 3")`).

- [ ] **Step 4: Replace the `trace()` stub** in `TaintTracer.java`

```java
    /** One worklist frame. */
    private record Frame(HighFunction hf, Varnode v, int depth,
            List<TaintStep> path, Set<Function> onPath) {}

    public TaintResult trace(HighFunction startHf, PcodeOp sinkCall, int argIdx,
            int maxCallDepth, int maxFunctions) {
        int depthCap = Math.max(1, Math.min(maxCallDepth, 10));
        // allow 0 only when caller explicitly passed 0 (used by budget test)
        if (maxCallDepth <= 0) depthCap = 0;
        int fnCap = Math.max(1, Math.min(maxFunctions, 256));

        Varnode start = PcodeQuery.argVarnode(sinkCall, argIdx);
        if (start == null) return new TaintResult(null, List.of(), "no_arg", 0, 0);
        hfCache.putIfAbsent(startHf.getFunction(), startHf);

        Deque<Frame> work = new ArrayDeque<>();
        work.add(new Frame(startHf, start, 0,
            new ArrayList<>(), new LinkedHashSet<>(Set.of(startHf.getFunction()))));

        String aggTerminal = "no_path";
        List<TaintStep> longestPath = List.of();
        int maxDepthReached = 0;

        FunctionManager fm = program.getFunctionManager();
        ReferenceManager rm = program.getReferenceManager();

        while (!work.isEmpty()) {
            Frame fr = work.poll();
            maxDepthReached = Math.max(maxDepthReached, fr.depth);
            String fnName = fr.hf.getFunction() != null ? fr.hf.getFunction().getName() : "?";

            // ---- intra-function backward walk to a boundary ----
            Varnode cur = fr.v;
            List<TaintStep> path = new ArrayList<>(fr.path);
            int steps = 0;
            while (cur != null && steps++ < INTRA_STEP_CAP) {
                if (cur.isConstant()) {
                    aggTerminal = "constant";
                    if (path.size() > longestPath.size()) longestPath = path;
                    cur = null; break;
                }
                PcodeOp def = cur.getDef();
                if (def == null) {
                    // Parameter? → cross to callers. Else: terminal "input".
                    HighVariable hv = cur.getHigh();
                    HighSymbol sym = hv != null ? hv.getSymbol() : null;
                    if (sym != null && sym.isParameter()) {
                        int slot = sym.getCategoryIndex();
                        path.add(step(fnName, sinkAddr(def, fr.hf), "param",
                            "param_" + slot + " → callers"));
                        if (fr.depth >= depthCap) {
                            aggTerminal = "call_depth";
                            if (path.size() > longestPath.size()) longestPath = path;
                        } else {
                            enqueueCallers(work, fr, slot, path, fm, rm, fnCap);
                        }
                    } else {
                        aggTerminal = "input";
                        if (path.size() > longestPath.size()) longestPath = path;
                    }
                    cur = null; break;
                }
                int oc = def.getOpcode();
                if (oc == PcodeOp.CALL || oc == PcodeOp.CALLIND) {
                    Function callee = resolveCallee(def, fm);
                    path.add(step(fnName, opAddr(def), "call_return",
                        callee != null ? callee.getName() : "<indirect>"));
                    if (callee != null) {
                        for (CatalogEntry e : catalog.resolve(callee)) {
                            if ("source".equals(e.kind())) {
                                return new TaintResult(e, path, "source",
                                    functionsVisited(), maxDepthReached);
                            }
                        }
                        if (fr.depth >= depthCap || fr.onPath.contains(callee)
                                || functionsVisited() >= fnCap) {
                            aggTerminal = fr.onPath.contains(callee) ? "recursion"
                                : (fr.depth >= depthCap ? "call_depth" : "budget");
                        } else {
                            HighFunction chf = decompile(callee);
                            if (chf == null) { aggTerminal = "decompile_failed"; }
                            else enqueueReturns(work, fr, chf, callee, path);
                        }
                    } else {
                        aggTerminal = "indirect_call";
                    }
                    if (path.size() > longestPath.size()) longestPath = path;
                    cur = null; break;
                }
                if (oc == PcodeOp.LOAD) {
                    Varnode laddr = def.getNumInputs() > 1 ? def.getInput(1) : null;
                    CatalogEntry hit = loadFromTaintedBuffer(fr.hf, laddr);
                    path.add(step(fnName, opAddr(def), "load",
                        hit != null ? "address derives from " + hit.id() + " out-buffer"
                                    : "address provenance unknown"));
                    if (hit != null) {
                        return new TaintResult(hit, path, "tainted_load",
                            functionsVisited(), maxDepthReached);
                    }
                    aggTerminal = "load_unknown_provenance";
                    if (path.size() > longestPath.size()) longestPath = path;
                    cur = null; break;
                }
                // transparent ops — record and continue through input(s)
                path.add(step(fnName, opAddr(def), "op", PcodeQuery.mnemonic(def)));
                switch (oc) {
                    case PcodeOp.COPY: case PcodeOp.CAST:
                    case PcodeOp.INT_ZEXT: case PcodeOp.INT_SEXT:
                    case PcodeOp.INDIRECT:
                        cur = def.getInput(0); break;
                    case PcodeOp.PTRSUB: case PcodeOp.PTRADD:
                    case PcodeOp.INT_ADD: case PcodeOp.INT_SUB: case PcodeOp.INT_MULT:
                    case PcodeOp.MULTIEQUAL:
                        // follow the first non-constant input; enqueue the rest
                        Varnode next = null;
                        for (int i = 0; i < def.getNumInputs(); i++) {
                            Varnode in = def.getInput(i);
                            if (in == null || in.isConstant()) continue;
                            if (next == null) next = in;
                            else work.add(new Frame(fr.hf, in, fr.depth,
                                new ArrayList<>(path), fr.onPath));
                        }
                        cur = next; break;
                    default:
                        aggTerminal = "op_" + oc;
                        if (path.size() > longestPath.size()) longestPath = path;
                        cur = null;
                }
            }
        }
        return new TaintResult(null, longestPath, aggTerminal,
            functionsVisited(), maxDepthReached);
    }

    private void enqueueCallers(Deque<Frame> work, Frame fr, int slot,
            List<TaintStep> path, FunctionManager fm, ReferenceManager rm, int fnCap) {
        Function self = fr.hf.getFunction();
        var refs = rm.getReferencesTo(self.getEntryPoint());
        int taken = 0;
        while (refs.hasNext() && taken < CALLER_FANOUT_CAP) {
            var ref = refs.next();
            if (!ref.getReferenceType().isCall()) continue;
            Function caller = fm.getFunctionContaining(ref.getFromAddress());
            if (caller == null || fr.onPath.contains(caller)) continue;
            if (functionsVisited() >= fnCap) break;
            HighFunction chf = decompile(caller);
            if (chf == null) continue;
            // find the CALL op at this site to read its arg[slot]
            PcodeOp callOp = null;
            var it = chf.getPcodeOps(ref.getFromAddress());
            while (it != null && it.hasNext()) {
                PcodeOp op = it.next();
                if (op.getOpcode() == PcodeOp.CALL || op.getOpcode() == PcodeOp.CALLIND) {
                    callOp = op; break;
                }
            }
            if (callOp == null) continue;
            Varnode arg = PcodeQuery.argVarnode(callOp, slot);
            if (arg == null) continue;
            Set<Function> on = new LinkedHashSet<>(fr.onPath); on.add(caller);
            List<TaintStep> p = new ArrayList<>(path);
            p.add(step(caller.getName(), ref.getFromAddress().toString(),
                "caller_arg", "arg" + slot + " at call to " + self.getName()));
            work.add(new Frame(chf, arg, fr.depth + 1, p, on));
            taken++;
        }
    }

    private void enqueueReturns(Deque<Frame> work, Frame fr, HighFunction chf,
            Function callee, List<TaintStep> path) {
        Set<Function> on = new LinkedHashSet<>(fr.onPath); on.add(callee);
        var ops = chf.getPcodeOps();
        while (ops.hasNext()) {
            PcodeOp op = ops.next();
            if (op.getOpcode() != PcodeOp.RETURN) continue;
            // RETURN input(0) is the indirect target; value (if any) is input(1).
            if (op.getNumInputs() < 2) continue;
            Varnode rv = op.getInput(1);
            if (rv == null) continue;
            List<TaintStep> p = new ArrayList<>(path);
            p.add(step(callee.getName(), opAddr(op), "into_callee_return",
                "RETURN value of " + callee.getName()));
            work.add(new Frame(chf, rv, fr.depth + 1, p, on));
        }
    }

    private CatalogEntry loadFromTaintedBuffer(HighFunction hf, Varnode addr) {
        if (addr == null) return null;
        Set<Varnode> roots = taintedBufferRoots(hf);
        if (roots.isEmpty()) return null;
        // Walk addr's intra-function def chain; if any base input is (or
        // COPY/CAST-derives from) a root, it's tainted.
        Deque<Varnode> w = new ArrayDeque<>(); w.push(addr);
        Set<Varnode> seen = new HashSet<>();
        int steps = 0;
        while (!w.isEmpty() && steps++ < INTRA_STEP_CAP) {
            Varnode v = w.pop();
            if (!seen.add(v)) continue;
            if (roots.contains(v)) return rootEntryFor(hf, v);
            PcodeOp d = v.getDef();
            if (d == null) continue;
            switch (d.getOpcode()) {
                case PcodeOp.COPY: case PcodeOp.CAST: case PcodeOp.INDIRECT:
                case PcodeOp.INT_ZEXT: case PcodeOp.INT_SEXT:
                    w.push(d.getInput(0)); break;
                case PcodeOp.PTRADD: case PcodeOp.PTRSUB:
                case PcodeOp.INT_ADD: case PcodeOp.INT_SUB:
                    for (int i = 0; i < d.getNumInputs(); i++)
                        if (d.getInput(i) != null) w.push(d.getInput(i));
                    break;
                default: // LOAD/CALL/etc — stop this branch
            }
        }
        return null;
    }

    private CatalogEntry rootEntryFor(HighFunction hf, Varnode root) {
        // Re-scan to find which source produced this root (cheap; small set).
        FunctionManager fm = program.getFunctionManager();
        var ops = hf.getPcodeOps();
        while (ops.hasNext()) {
            PcodeOp op = ops.next();
            int oc = op.getOpcode();
            if (oc != PcodeOp.CALL && oc != PcodeOp.CALLIND) continue;
            Function callee = resolveCallee(op, fm);
            if (callee == null) continue;
            for (CatalogEntry e : catalog.resolve(callee)) {
                if (!"source".equals(e.kind())) continue;
                Integer oi = e.arg("out_arg");
                if (oi != null && PcodeQuery.argVarnode(op, oi) == root) return e;
                if (e.returnIsOutput() && op.getOutput() == root) return e;
            }
        }
        return null;
    }

    private static TaintStep step(String fn, String addr, String kind, String detail) {
        return new TaintStep(fn, addr == null ? "" : addr, kind, detail);
    }
    private static String opAddr(PcodeOp op) {
        return (op != null && op.getSeqnum() != null && op.getSeqnum().getTarget() != null)
            ? op.getSeqnum().getTarget().toString() : "";
    }
    private static String sinkAddr(PcodeOp op, HighFunction hf) {
        if (op != null) return opAddr(op);
        return hf.getFunction() != null && hf.getFunction().getEntryPoint() != null
            ? hf.getFunction().getEntryPoint().toString() : "";
    }
```

Add any missing imports (`java.util.ArrayDeque`, `java.util.ArrayList`, `java.util.Deque`, `java.util.LinkedHashSet`, `ghidra.program.model.pcode.HighSymbol`, `ghidra.program.model.pcode.HighVariable`, `ghidra.program.model.pcode.SequenceNumber`).

- [ ] **Step 5: Verify PASS** — `./gradlew test --tests 'com.xebyte.offline.vuln.TaintTracerTest' -PGHIDRA_INSTALL_DIR=$GHIDRA_INSTALL_DIR --console=plain` → 7 tests (2 infra + 5 algorithm). Then full vuln package.

If any test fails because a Mockito stub is missing (e.g., `getSeqnum()` on a transparent-op mock), add the minimal stub — do NOT change the algorithm to avoid the call. If `recursionGuard` produces `"call_depth"` instead of `"recursion"` (the self-caller is in `onPath` so the `enqueueCallers` skips it, leaving no frames → terminal stays at the param's `"call_depth"` setter), adjust the test's expected terminal to match the actual code path and document why; the important assertion is `r.source() == null` and termination.

- [ ] **Step 6: Commit**
```bash
git add src/main/java/com/xebyte/core/vuln/TaintTracer.java src/test/java/com/xebyte/offline/vuln/TaintTracerTest.java
git commit -m "feat(vuln): TaintTracer.trace — backward inter-proc walk (param/call-return/load/recursion)"
```

---

## Task 4: `/find_taint_path` endpoint

**Files:**
- Modify: `src/main/java/com/xebyte/core/vuln/VulnAnalysisService.java` (add endpoint)
- Modify: `src/test/java/com/xebyte/offline/vuln/VulnAnalysisServiceTest.java` (1 new test)

**Interfaces:**
- Consumes: `TaintTracer(Program, SinkCatalog)` and `trace(...)` from Tasks 2-3.
- Produces: `@McpTool /find_taint_path` (GET, category `security`) — params per spec table; returns `TaintResult.toJson()` plus `{address, callee, arg_index_used}`.

- [ ] **Step 1: Write failing test** (mocked Program; no real decompile, so the trace will hit `decompile_failed` or `no_arg`. Assert response shape, not source.)

```java
    @Test @SuppressWarnings("unchecked")
    public void findTaintPath_shapeAndClamps() {
        Program p = mock(Program.class);
        ghidra.program.model.address.AddressFactory af =
            mock(ghidra.program.model.address.AddressFactory.class);
        when(p.getAddressFactory()).thenReturn(af);
        when(af.getAddress(anyString())).thenReturn(null); // unresolved → error
        Response r = svc(p).findTaintPath("00401000", "size_arg", -1, 999, 9999, "");
        // address unresolved → error
        assertTrue(r instanceof Response.Err);

        // resolved address but no function there → error
        ghidra.program.model.address.Address a = mock(ghidra.program.model.address.Address.class);
        when(af.getAddress("00401000")).thenReturn(a);
        FunctionManager fm = mock(FunctionManager.class);
        when(p.getFunctionManager()).thenReturn(fm);
        when(fm.getFunctionContaining(a)).thenReturn(null);
        Response r2 = svc(p).findTaintPath("00401000", "size_arg", -1, 999, 9999, "");
        assertTrue(r2 instanceof Response.Err);
    }
```

- [ ] **Step 2: Verify FAIL** (compile error). **Step 3: Implement** — add to `VulnAnalysisService.java` after `enumerateAttackSurface`:

```java
    @McpTool(path = "/find_taint_path", category = "security",
             description = "Backward inter-procedural taint trace from one sink call-site argument. "
                         + "Starts at the given address (a CALL instruction), walks the named arg "
                         + "backward across CALL-return and parameter boundaries, and reports the "
                         + "first catalog SOURCE reached (or the terminal reason if none). Use this "
                         + "to triage a detect_vuln_patterns finding: does its dangerous arg actually "
                         + "come from attacker-controlled input?")
    public Response findTaintPath(
            @Param(value = "address", paramType = "address",
                   description = "Sink call-site address (overlay-aware).") String addressStr,
            @Param(value = "arg_role", defaultValue = "",
                   description = "Catalog arg role at the callee (size_arg|fmt_arg|cmd_arg|dst_arg). "
                               + "Resolved against the callee's catalog entry.") String argRole,
            @Param(value = "arg_index", defaultValue = "-1",
                   description = "Raw 0-based arg index; used when arg_role is empty or callee "
                               + "isn't in the catalog.") int argIndex,
            @Param(value = "max_call_depth", defaultValue = "5",
                   description = "Clamped to [1,10].") int maxCallDepth,
            @Param(value = "max_functions", defaultValue = "64",
                   description = "Clamped to [1,256].") int maxFunctions,
            @Param(value = "program", defaultValue = "",
                   description = "Target program name (omit for active program)") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        Address site = program.getAddressFactory().getAddress(
            addressStr == null ? null : addressStr.strip());
        if (site == null) return Response.err("Could not resolve address: " + addressStr);
        Function fn = program.getFunctionManager().getFunctionContaining(site);
        if (fn == null) return Response.err("No function contains address " + addressStr);

        try (TaintTracer tracer = new TaintTracer(program, catalog)) {
            HighFunction hf = tracer.decompile(fn);
            if (hf == null) return Response.err("Decompile failed for " + fn.getName());
            // Find the CALL op at this site
            PcodeOp call = null;
            var it = hf.getPcodeOps(site);
            while (it != null && it.hasNext()) {
                PcodeOp op = it.next();
                if (op.getOpcode() == PcodeOp.CALL || op.getOpcode() == PcodeOp.CALLIND) {
                    call = op; break;
                }
            }
            if (call == null) return Response.err("No CALL op at " + addressStr);
            // Resolve arg index
            int idx = argIndex;
            Function callee = null;
            if (call.getNumInputs() > 0 && call.getInput(0) != null
                    && call.getInput(0).isAddress()) {
                callee = program.getFunctionManager().getFunctionAt(call.getInput(0).getAddress());
            }
            if ((argRole != null && !argRole.isBlank()) && callee != null) {
                for (CatalogEntry e : catalog.resolve(callee)) {
                    Integer i = e.arg(argRole);
                    if (i != null) { idx = i; break; }
                }
            }
            if (idx < 0) return Response.err(
                "Could not determine arg index — supply arg_index or a valid arg_role for a catalog sink.");

            int depth = Math.max(1, Math.min(maxCallDepth, 10));
            int cap   = Math.max(1, Math.min(maxFunctions, 256));
            TaintResult r = tracer.trace(hf, call, idx, depth, cap);
            Map<String,Object> out = new LinkedHashMap<>(r.toJson());
            out.put("address", site.toString());
            out.put("callee", callee != null ? callee.getName() : null);
            out.put("arg_index_used", idx);
            return Response.ok(out);
        }
    }
```

`TaintTracer.decompile(Function)` is package-private; `VulnAnalysisService` is in the same package, so the call is legal.

- [ ] **Step 4: Verify PASS** (`VulnAnalysisServiceTest` now 8 tests). **Commit**
```bash
git add src/main/java/com/xebyte/core/vuln/VulnAnalysisService.java src/test/java/com/xebyte/offline/vuln/VulnAnalysisServiceTest.java
git commit -m "feat(vuln): /find_taint_path — backward taint trace from one sink call-site arg"
```

---

## Task 5: `taint=true` integration in `detect_vuln_patterns`

**Files:**
- Modify: `src/main/java/com/xebyte/core/vuln/VulnAnalysisService.java`
- Modify: `src/test/java/com/xebyte/offline/vuln/VulnAnalysisServiceTest.java`

**Interfaces:**
- Consumes: `TaintTracer` shared-decomp ctor; `Finding`; `SinkCallSite` (already carries the `PcodeOp call` and `CatalogEntry entry`).
- Produces: two new body params `taint` (default false), `taint_max_depth` (default 5). When true, each finding's JSON gains `taint_source`, `taint_terminal`, `taint_path`; tainted findings are bumped to `confidence:"high"`.

- [ ] **Step 1: Recon** — `scanFunction` currently returns `ScanResult(findings, decompFailed, siteCount)`. To run the trace per finding we need the `(PcodeOp call, CatalogEntry entry, HighFunction hf)` for each finding — but `Finding` only carries strings. Change `ScanResult` to also return a `Map<Finding, SinkCallSite>` so the service can map each finding back to its call op without re-parsing addresses.

Change `ScanResult`:
```java
    private record ScanResult(List<Finding> findings, boolean decompFailed,
            int siteCount, HighFunction hf, Map<Finding, SinkCallSite> siteByFinding) {}
```
In `scanFunction`, after collecting `all` findings per detector, build the map: each detector's `scan(...)` returns findings whose `address` equals `s.callAddr().toString()` for some `s` in `mine`. Build `Map<String, SinkCallSite> byAddr` for `mine`, then for each returned finding put `(finding, byAddr.get(finding.address()))`. Return the `hf` too. The decompile-fail return becomes `(List.of(), true, 0, null, Map.of())`.

- [ ] **Step 2: Add the two params** after `max_depth`:

```java
            @Param(value = "taint", source = ParamSource.BODY, defaultValue = "false",
                   description = "When true, run a backward inter-procedural taint trace on each "
                               + "finding's relevant arg (size_arg for copy/alloc, fmt_arg for format, "
                               + "cmd_arg for exec). Findings that reach a catalog SOURCE are bumped "
                               + "to confidence='high' and gain taint_source/taint_path fields.") boolean taint,
            @Param(value = "taint_max_depth", source = ParamSource.BODY, defaultValue = "5",
                   description = "Call-depth cap for taint tracing (clamped to [1,10]).") int taintMaxDepth) {
```

Update existing test call sites (4 of them) to pass `, false, 0` for the new trailing args.

- [ ] **Step 3: After the scan loop**, before building `fjson`, if `taint`:

```java
        Map<Finding, TaintResult> taintByFinding = new LinkedHashMap<>();
        if (taint && !findings.isEmpty()) {
            int depth = Math.max(1, Math.min(taintMaxDepth, 10));
            // Reuse the multi-fn shared decompiler if we have one; else open a fresh one.
            try (TaintTracer tracer = (decomp != null)
                    ? new TaintTracer(program, catalog, decomp)
                    : new TaintTracer(program, catalog)) {
                for (var entry : siteByFindingAll.entrySet()) {
                    Finding f = entry.getKey();
                    SinkCallSite s = entry.getValue();
                    if (s == null) continue;
                    Integer idx = argRoleFor(s.entry());
                    if (idx == null) continue;
                    HighFunction hf = hfByFinding.get(f);
                    if (hf == null) continue;
                    taintByFinding.put(f, tracer.trace(hf, s.call(), idx, depth, 64));
                }
            }
        }
```

Where:
- `siteByFindingAll` is a `LinkedHashMap<Finding, SinkCallSite>` and `hfByFinding` a `Map<Finding, HighFunction>` accumulated alongside `findings.addAll(r.findings)` from each `ScanResult` (`siteByFindingAll.putAll(r.siteByFinding); for (Finding f : r.findings) hfByFinding.put(f, r.hf);`).
- `decomp` is the local shared `DecompInterface` from the multi-function path (it's `null` in the single-function path; declare it outside the `if (!functionRef.isBlank())` so it's visible here, initialized to `null`).
- `argRoleFor(CatalogEntry e)` is a private helper:
```java
    private static Integer argRoleFor(CatalogEntry e) {
        return switch (e.vulnClass()) {
            case "copy", "alloc" -> e.arg("size_arg");
            case "format"        -> e.arg("fmt_arg");
            case "exec"          -> e.arg("cmd_arg");
            default              -> null;
        };
    }
```

- [ ] **Step 4: When building `fjson`**, merge taint fields and bump confidence:

```java
        for (Finding f : findings) {
            Map<String,Object> j = new LinkedHashMap<>(f.toJson());
            TaintResult tr = taintByFinding.get(f);
            if (tr != null) {
                j.put("taint_source", tr.source() == null ? null : tr.source().id());
                j.put("taint_terminal", tr.terminalReason());
                j.put("taint_path", tr.toJson().get("path"));
                if (tr.source() != null) j.put("confidence", "high");
            }
            fjson.add(j);
        }
```

(Replace the existing `for (Finding f : findings) fjson.add(f.toJson());` with this.)

- [ ] **Step 5: Add test** asserting the response shape with `taint=true` (mock-decompile path → `decompile_failed` terminal, `taint_source=null`):

```java
    @Test @SuppressWarnings("unchecked")
    public void detectVulnPatterns_taintTrue_addsTaintFieldsPerFinding() {
        // Reuse the no-functions program; with taint=true and 0 findings, just
        // assert the params are accepted and detectors_run unchanged.
        Program p = mock(Program.class);
        FunctionManager fm = mock(FunctionManager.class);
        when(p.getFunctionManager()).thenReturn(fm);
        FunctionIterator empty = mock(FunctionIterator.class);
        when(empty.hasNext()).thenReturn(false);
        when(fm.getFunctions(true)).thenReturn(empty);
        Response r = svc(p).detectVulnPatterns("", "", "", false, 0, "", 0, true, 3);
        Map<String,Object> body = (Map<String,Object>) ((Response.Ok) r).data();
        assertEquals(0, ((List<?>) body.get("findings")).size());
        // taint param accepted; no error.
    }
```

- [ ] **Step 6: Verify PASS** — full vuln package + full offline. **Commit**
```bash
git add src/main/java/com/xebyte/core/vuln/VulnAnalysisService.java src/test/java/com/xebyte/offline/vuln/VulnAnalysisServiceTest.java
git commit -m "feat(vuln): detect_vuln_patterns taint=true — per-finding trace, confidence bump"
```

---

## Task 6: `endpoints.json`, tool-count sweep, live verification

**Files:**
- Modify: `tests/endpoints.json` (add `/find_taint_path` entry; add `taint`,`taint_max_depth` to `/detect_vuln_patterns` params; bump `total_endpoints` by 1)
- Modify: `CLAUDE.md`, `README.md`, `AGENTS.md`, `MANIFEST.MF`, `extension.properties` (tool count +1 — find current count via `python -c "import json;print(json.load(open('tests/endpoints.json'))['total_endpoints'])"` and increment)

- [ ] **Step 1: Run parity** — `./gradlew test --tests 'com.xebyte.offline.EndpointsJsonParityTest' -PGHIDRA_INSTALL_DIR=$GHIDRA_INSTALL_DIR --console=plain`. Expected FAIL (1 missing endpoint + 2 missing params).

- [ ] **Step 2: Add the entry** to `tests/endpoints.json` (alphabetical position; match sibling shape):
```json
    {
      "path": "/find_taint_path",
      "method": "GET",
      "category": "security",
      "params": ["address","arg_role","arg_index","max_call_depth","max_functions","program"],
      "description": "Backward inter-procedural taint trace from one sink call-site argument; reports the first catalog SOURCE reached (or terminal reason)"
    },
```
And add `"taint","taint_max_depth"` to `/detect_vuln_patterns`'s `params` array. Bump `total_endpoints` by 1. Validate JSON; verify alpha sort.

- [ ] **Step 3: Tool-count sweep** — update the count in CLAUDE.md / README.md / AGENTS.md / MANIFEST.MF / extension.properties to match the new `total_endpoints`. Run `pytest tests/unit/test_project_consistency.py --no-cov` to confirm.

- [ ] **Step 4: Re-run parity + full offline** → BUILD SUCCESSFUL.

- [ ] **Step 5: Build, install, restart Ghidra, live verify** on `Application1.elf`:
```bash
./gradlew installUserExtension -PGHIDRA_INSTALL_DIR=$GHIDRA_INSTALL_DIR
# (restart Ghidra)
curl -s "http://127.0.0.1:8089/find_taint_path?address=dnp_modbus.Initial::00015df4&arg_role=size_arg&max_call_depth=5" | python3 -m json.tool
time curl -s -X POST http://127.0.0.1:8089/detect_vuln_patterns \
  -H "Content-Type: application/json" \
  -d '{"scope":"attack_surface","max_depth":3,"taint":true,"taint_max_depth":5}' | python3 -m json.tool
```
Expected: `find_taint_path` returns a `TaintResult` (either `source: {id:"recv"|"read", ...}` or a terminal reason); `detect_vuln_patterns` finding gains `taint_source`/`taint_terminal`/`taint_path`.

- [ ] **Step 6: Commit + push**
```bash
git add tests/endpoints.json CLAUDE.md README.md AGENTS.md src/main/resources/META-INF/MANIFEST.MF src/main/resources/extension.properties
git commit -m "feat(vuln): register /find_taint_path; sweep tool count"
git fetch fork && git rebase fork/main && git push fork feature/vuln-analysis-service:main && git push -f fork feature/vuln-analysis-service
```

---

## Self-Review

**Spec coverage:**
- TaintStep/TaintResult records + toJson + 32-step truncation → Task 1. ✓
- TaintTracer ctor (own + shared), AutoCloseable, decomp cache, taintedBufferRoots, resolveCallee → Task 2. ✓
- trace() algorithm: intra walk, CALL-return (source check + recurse RETURN.input(1)), LOAD (taintedBufferRoots check), HighParam → callers (slot via `getCategoryIndex()`, fan-out cap 16), bounds (depthCap [1,10], fnCap [1,256], INTRA_STEP_CAP 64), onPath recursion guard, BFS-first-source → Task 3. ✓
- /find_taint_path endpoint (params per spec table, arg_role→idx resolution, clamps, response = TaintResult.toJson + addr/callee/arg_index_used) → Task 4. ✓
- detect_vuln_patterns taint=true / taint_max_depth, per-finding trace via SinkCallSite, argRoleFor mapping (copy/alloc→size_arg, format→fmt_arg, exec→cmd_arg), confidence bump, JSON merge (taint_source/terminal/path), shared-DecompInterface reuse → Task 5. ✓
- endpoints.json + tool-count + live verification on the surviving 00015df4 candidate → Task 6. ✓
- Out-of-scope items left out. ✓

**Placeholder scan:** Task 3 step 5's note about adjusting the recursion test's expected terminal is a documented escape hatch with the rationale, not a blank. Task 5 step 1 ("Recon") is concrete (exact record-field changes specified). No "TBD"/"add error handling".

**Type consistency:** `TaintResult(CatalogEntry, List<TaintStep>, String, int, int)` defined T1, consumed T3/T4/T5. `TaintTracer.trace(HighFunction, PcodeOp, int, int, int)` defined T3, consumed T4/T5. `ScanResult(..., HighFunction hf, Map<Finding,SinkCallSite> siteByFinding)` defined T5, consumed T5. `argRoleFor(CatalogEntry) → Integer` consistent. `decomp` local visibility note in T5 step 3.
