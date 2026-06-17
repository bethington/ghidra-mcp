package com.xebyte.core.vuln;

import com.xebyte.core.FunctionService;
import com.xebyte.core.JsonHelper;
import com.xebyte.core.McpTool;
import com.xebyte.core.Param;
import com.xebyte.core.ProgramProvider;
import com.xebyte.core.Response;
import com.xebyte.core.ServiceUtils;
import com.xebyte.core.ThreadingStrategy;
import com.xebyte.core.vuln.detectors.CommandInjectionDetector;
import com.xebyte.core.vuln.detectors.FormatStringDetector;
import com.xebyte.core.vuln.detectors.IntegerOverflowAllocDetector;
import com.xebyte.core.vuln.detectors.UnboundedCopyDetector;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Intra-function vulnerability pattern scanning. Decompiles a function once,
 * resolves every CALL/CALLIND against the {@link SinkCatalog} into
 * {@link SinkCallSite}s, and hands the relevant sites to each registered
 * {@link VulnDetector}. Phase 1: intra-function only (no inter-procedural
 * taint propagation).
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
        List<Map<String, Object>> ds = new ArrayList<>();
        for (VulnDetector d : detectors) {
            ds.add(JsonHelper.mapOf(
                "id",           d.id(),
                "description",  d.description(),
                "sink_classes", new ArrayList<>(d.sinkClasses())));
        }
        Map<String, Object> cat = JsonHelper.mapOf(
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
                         + "name regex, or Ghidra function tag (SINK_*); use list_vuln_detectors to see the catalog. "
                         + "Set 'detectors' to a comma-separated list of detector ids to limit the scan.")
    public Response detectVulnPatterns(
            @Param(value = "function", defaultValue = "",
                   description = "Function name or entry address. Empty = scan whole program.") String functionRef,
            @Param(value = "detectors", defaultValue = "",
                   description = "Comma-separated detector ids (e.g. 'format_string,unbounded_copy'). Empty = all.") String detectorsCsv,
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
        for (String s : detectorsCsv.split(",")) {
            s = s.strip();
            if (!s.isEmpty()) wanted.add(s);
        }
        List<VulnDetector> active = new ArrayList<>();
        for (VulnDetector d : detectors) {
            if (wanted.isEmpty() || wanted.contains(d.id())) active.add(d);
        }
        if (!wanted.isEmpty()) {
            Set<String> known = new HashSet<>();
            for (VulnDetector d : detectors) known.add(d.id());
            List<String> unknown = new ArrayList<>();
            for (String w : wanted) if (!known.contains(w)) unknown.add(w);
            if (!unknown.isEmpty()) {
                return Response.err("Unknown detector id(s): " + String.join(", ", unknown)
                    + ". Known: " + String.join(", ", known) + ".");
            }
        }

        List<Finding> findings = new ArrayList<>();
        int scanned = 0;
        int decompFail = 0;
        int totalSites = 0;

        if (!functionRef.isBlank()) {
            Function f = resolveFunction(program, functionRef);
            if (f == null) return Response.err("Function not found: " + functionRef);
            ScanResult r = scanFunction(program, f, active);
            findings.addAll(r.findings);
            scanned = 1;
            decompFail = r.decompFailed ? 1 : 0;
            totalSites += r.siteCount;
        } else {
            // TODO(perf): reuse one DecompInterface across the loop instead of spawning per function via decompileFunctionNoRetry.
            FunctionIterator it = program.getFunctionManager().getFunctions(true);
            while (it.hasNext()) {
                if (maxFunctions > 0 && scanned >= maxFunctions) break;
                Function f = it.next();
                if (f.isExternal() || f.isThunk()) continue;
                ScanResult r = scanFunction(program, f, active);
                findings.addAll(r.findings);
                if (r.decompFailed) decompFail++;
                totalSites += r.siteCount;
                scanned++;
            }
        }

        if (writeBookmarks && !findings.isEmpty()) {
            writeBookmarks(program, findings);
        }

        List<Map<String, Object>> fjson = new ArrayList<>();
        for (Finding f : findings) fjson.add(f.toJson());

        List<String> ran = new ArrayList<>();
        for (VulnDetector d : active) ran.add(d.id());

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("findings",           fjson);
        out.put("scanned_functions",  scanned);
        out.put("decompile_failures", decompFail);
        out.put("detectors_run",      ran);
        out.put("catalog_status",     catalog.status() == null ? "ok" : catalog.status());
        if (scanned > 0 && totalSites == 0) {
            out.put("note", "no catalog sinks resolved — consider tagging functions with SINK_* "
                          + "(e.g. SINK_COPY_SIZED, SINK_FORMAT, SINK_EXEC, SINK_ALLOC) or check "
                          + "list_vuln_detectors for the active catalog.");
        }
        return Response.ok(out);
    }

    @McpTool(path = "/enumerate_attack_surface", category = "security",
             description = "Enumerate the program's attack surface: every function within max_depth "
                         + "call-graph hops of a catalog SOURCE (network/file/env/cli/ipc), grouped by "
                         + "source class. Sources are matched by import name, function-name regex, or "
                         + "SOURCE_* tag — tag custom RTOS receive/ioctl handlers with SOURCE_NETWORK "
                         + "etc. to include them.")
    public Response enumerateAttackSurface(
            @Param(value = "max_depth", defaultValue = "3",
                   description = "BFS depth in the callers-of graph from each source (clamped to [0,8]).") int maxDepth,
            @Param(value = "program", defaultValue = "",
                   description = "Target program name (omit for active program)") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();
        int depth = Math.max(0, Math.min(maxDepth, 8));
        FunctionManager fm = program.getFunctionManager();
        ReferenceManager rm = program.getReferenceManager();

        Map<String, List<Map<String, Object>>> byClass = new LinkedHashMap<>();
        Map<Function, Set<String>> seenSourceClasses = new HashMap<>();
        int sourceCount = 0;

        // Unlike detect_vuln_patterns, do NOT skip externals/thunks here: import
        // thunks ARE where caller refs land, and catalog.resolve() follows the
        // thunk to match the source entry.
        FunctionIterator it = fm.getFunctions(true);
        while (it.hasNext()) {
            Function f = it.next();
            boolean isSourceFn = false;
            for (CatalogEntry e : catalog.resolve(f)) {
                if (!"source".equals(e.kind())) continue;
                isSourceFn = true;
                Set<String> done = seenSourceClasses.computeIfAbsent(f, k -> new HashSet<>());
                if (!done.add(e.vulnClass())) continue; // already BFS'd this (f, class) pair
                bfsCallers(program, fm, rm, f, e, depth, byClass);
            }
            if (isSourceFn) sourceCount++;
        }

        return Response.ok(JsonHelper.mapOf(
            "by_source_class", byClass,
            "source_count",    sourceCount,
            "max_depth",       depth,
            "catalog_status",  catalog.status() == null ? "ok" : catalog.status()));
    }

    private void bfsCallers(Program program, FunctionManager fm, ReferenceManager rm,
            Function source, CatalogEntry entry, int maxDepth,
            Map<String, List<Map<String, Object>>> byClass) {
        Set<Function> seen = new HashSet<>();
        Deque<Map.Entry<Function, Integer>> q = new ArrayDeque<>();
        q.add(Map.entry(source, 0));
        List<Map<String, Object>> bucket =
            byClass.computeIfAbsent(entry.vulnClass(), k -> new ArrayList<>());
        while (!q.isEmpty()) {
            var cur = q.poll();
            Function fn = cur.getKey();
            int depth = cur.getValue();
            if (!seen.add(fn)) continue;
            if (depth > 0) {
                Map<String, Object> row = new LinkedHashMap<>(
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

    // ---- core ----

    private record ScanResult(List<Finding> findings, boolean decompFailed, int siteCount) {}

    private ScanResult scanFunction(Program program, Function f, List<VulnDetector> active) {
        DecompileResults dr = functionService.decompileFunctionNoRetry(f, program);
        if (dr == null || !dr.decompileCompleted() || dr.getHighFunction() == null) {
            return new ScanResult(List.of(), true, 0);
        }
        HighFunction hf = dr.getHighFunction();

        List<SinkCallSite> sites = new ArrayList<>();
        Iterator<PcodeOpAST> ops = hf.getPcodeOps();
        while (ops.hasNext()) {
            PcodeOpAST op = ops.next();
            int oc = op.getOpcode();
            if (oc != PcodeOp.CALL && oc != PcodeOp.CALLIND) continue;
            Function callee = resolveCallee(op, program);
            if (callee == null) continue;
            for (CatalogEntry e : catalog.resolve(callee)) {
                if (!"sink".equals(e.kind())) continue;
                Address addr = op.getSeqnum() != null ? op.getSeqnum().getTarget() : f.getEntryPoint();
                sites.add(new SinkCallSite(op, e, callee, addr));
            }
        }
        if (sites.isEmpty()) return new ScanResult(List.of(), false, 0);

        List<Finding> all = new ArrayList<>();
        for (VulnDetector d : active) {
            List<SinkCallSite> mine = new ArrayList<>();
            for (SinkCallSite s : sites) {
                if (d.sinkClasses().contains(s.entry().vulnClass())) mine.add(s);
            }
            if (!mine.isEmpty()) all.addAll(d.scan(hf, mine));
        }
        return new ScanResult(all, false, sites.size());
    }

    private Function resolveCallee(PcodeOp op, Program program) {
        if (op.getNumInputs() == 0) return null;
        FunctionManager fm = program.getFunctionManager();
        Varnode tgt = op.getInput(0);
        Function f = null;
        if (tgt != null && tgt.isAddress()) {
            f = fm.getFunctionAt(tgt.getAddress());
        }
        // CALLIND or unresolved direct: use the call-site reference (Ghidra
        // populates COMPUTED_CALL refs for IAT/PLT slots).
        if (f == null && op.getSeqnum() != null) {
            Address site = op.getSeqnum().getTarget();
            for (Reference ref : program.getReferenceManager().getReferencesFrom(site)) {
                if (ref.getReferenceType().isCall()) {
                    f = fm.getFunctionAt(ref.getToAddress());
                    if (f != null) break;
                }
            }
        }
        // SinkCatalog.resolve already follows thunks; no need to unwrap here (M3).
        return f;
    }

    /**
     * Resolve a function by address-or-name. Uses {@code AddressFactory.getAddress}
     * directly (overlay-safe: accepts {@code name::offset}) rather than
     * {@code ServiceUtils.parseAddress}, which on this branch lowercases overlay
     * space names.
     */
    // TODO(overlay-address-spaces): collapse into ServiceUtils.resolveFunction once that branch merges; the local AddressFactory path is only needed while parseAddress lowercases overlay names on main.
    private Function resolveFunction(Program program, String ref) {
        String r = ref.strip();
        try {
            Address a = program.getAddressFactory().getAddress(r);
            if (a != null) {
                Function f = program.getFunctionManager().getFunctionContaining(a);
                if (f != null) return f;
            }
        } catch (Exception ignored) {
            // not an address — fall through to name match
        }
        // Name fallback via SymbolTable (indexed) instead of O(n) FunctionIterator.
        for (ghidra.program.model.symbol.Symbol s :
                program.getSymbolTable().getSymbols(ref.strip())) {
            if (s.getSymbolType() == ghidra.program.model.symbol.SymbolType.FUNCTION) {
                Function f = program.getFunctionManager().getFunctionAt(s.getAddress());
                if (f != null) return f;
            }
        }
        return null;
    }

    /**
     * Drop SEVR/{@code <class>} bookmarks at each finding's address. Address
     * resolution intentionally bypasses {@code ServiceUtils.parseAddress} —
     * see {@link #resolveFunction} for the overlay-safety rationale.
     */
    private void writeBookmarks(Program program, List<Finding> findings) {
        threading.executeWriteUnchecked(program, "SEVR bookmarks", () -> {
            BookmarkManager bm = program.getBookmarkManager();
            for (Finding f : findings) {
                Address a;
                try {
                    a = program.getAddressFactory().getAddress(f.address());
                } catch (Exception e) {
                    continue;
                }
                if (a == null) continue;
                String cat = "SEVR/" + f.vulnClass();
                Bookmark old = bm.getBookmark(a, BookmarkType.ANALYSIS, cat);
                if (old != null) bm.removeBookmark(old);
                bm.setBookmark(a, BookmarkType.ANALYSIS, cat, f.detectorId() + ": " + f.why());
            }
        });
    }
}
