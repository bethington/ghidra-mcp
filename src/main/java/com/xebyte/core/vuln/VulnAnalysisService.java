package com.xebyte.core.vuln;

import com.xebyte.core.FunctionService;
import com.xebyte.core.JsonHelper;
import com.xebyte.core.McpTool;
import com.xebyte.core.Param;
import com.xebyte.core.ParamSource;
import com.xebyte.core.ProgramProvider;
import com.xebyte.core.Response;
import com.xebyte.core.ServiceUtils;
import com.xebyte.core.ThreadingStrategy;
import com.xebyte.core.vuln.detectors.CommandInjectionDetector;
import com.xebyte.core.vuln.detectors.FormatStringDetector;
import com.xebyte.core.vuln.detectors.IntegerOverflowAllocDetector;
import com.xebyte.core.vuln.detectors.UnboundedCopyDetector;
import ghidra.app.decompiler.DecompInterface;
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
import ghidra.util.task.TaskMonitor;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collection;
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

    @McpTool(path = "/detect_vuln_patterns", method = "POST", category = "security",
             description = "Scan one function (or, if 'function' is empty, every function in the program up to "
                         + "max_functions) for intra-function vulnerability patterns using PCode: format-string, "
                         + "unbounded-copy, integer-overflow-into-alloc, command-injection. Returns findings with "
                         + "address, sink, confidence, evidence, and a one-line 'why'. Set write_bookmarks=true to "
                         + "drop SEVR/<class> bookmarks at each finding. Sinks are matched by import name, function-"
                         + "name regex, or Ghidra function tag (SINK_*); use list_vuln_detectors to see the catalog. "
                         + "Set 'detectors' to a comma-separated list of detector ids to limit the scan.")
    public Response detectVulnPatterns(
            @Param(value = "function", source = ParamSource.BODY, defaultValue = "",
                   description = "Function name or entry address. Empty = scan whole program.") String functionRef,
            @Param(value = "detectors", source = ParamSource.BODY, defaultValue = "",
                   description = "Comma-separated detector ids (e.g. 'format_string,unbounded_copy'). Empty = all.") String detectorsCsv,
            @Param(value = "program", defaultValue = "",
                   description = "Target program name (omit for active program)") String programName,
            @Param(value = "write_bookmarks", source = ParamSource.BODY, defaultValue = "false",
                   description = "When true, write a SEVR/<class> bookmark at each finding's address.") boolean writeBookmarks,
            @Param(value = "max_functions", source = ParamSource.BODY, defaultValue = "0",
                   description = "Cap on functions scanned in whole-program mode (0 = no cap).") int maxFunctions,
            @Param(value = "scope", source = ParamSource.BODY, defaultValue = "",
                   description = "'' (default) = whole program / single function. "
                               + "'attack_surface' = scan only functions reachable (callers-of) "
                               + "within max_depth hops of any catalog SOURCE. Ignored when "
                               + "'function' is non-empty (single-function takes precedence).") String scope,
            @Param(value = "max_depth", source = ParamSource.BODY, defaultValue = "3",
                   description = "BFS depth for scope=attack_surface (clamped to [0,8]).") int maxDepth) {

        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        // AnnotationScanner treats @Param(defaultValue = "") on a String as
        // "optional → null when absent" (see resolveBodyParam). Normalize here.
        if (functionRef == null)  functionRef = "";
        if (detectorsCsv == null) detectorsCsv = "";
        if (scope == null)        scope = "";

        Set<String> wanted = new LinkedHashSet<>();
        for (String s : detectorsCsv.split(",")) {
            s = s.strip();
            if (!s.isEmpty()) wanted.add(s);
        }
        List<VulnDetector> active = new ArrayList<>();
        for (VulnDetector d : detectors) if (wanted.isEmpty() || wanted.contains(d.id())) active.add(d);

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
        int scanned = 0, decompFail = 0, totalSites = 0;
        Integer surfaceCount = null;

        if (!functionRef.isBlank()) {
            // Single function — keep the simple no-retry helper.
            Function f = ServiceUtils.resolveFunction(program, functionRef);
            if (f == null) return Response.err("Function not found: " + functionRef);
            ScanResult r = scanFunction(program, f, active, null);
            findings.addAll(r.findings); scanned = 1;
            decompFail = r.decompFailed ? 1 : 0; totalSites = r.siteCount;
        } else {
            // Multi-function: choose target set, then share one DecompInterface.
            Collection<Function> targets;
            if ("attack_surface".equalsIgnoreCase(scope)) {
                int depth = Math.max(0, Math.min(maxDepth, 8));
                Set<Function> surface = collectAttackSurfaceFunctions(program, depth);
                surfaceCount = surface.size();
                targets = surface;
            } else {
                List<Function> all = new ArrayList<>();
                FunctionIterator it = program.getFunctionManager().getFunctions(true);
                while (it.hasNext()) {
                    Function f = it.next();
                    if (f.isExternal() || f.isThunk()) continue;
                    all.add(f);
                    if (maxFunctions > 0 && all.size() >= maxFunctions) break;
                }
                targets = all;
            }

            DecompInterface decomp = openDecompiler(program);
            try {
                for (Function f : targets) {
                    if (f.isExternal() || f.isThunk()) continue;
                    ScanResult r = scanFunction(program, f, active, decomp);
                    findings.addAll(r.findings);
                    if (r.decompFailed) decompFail++;
                    totalSites += r.siteCount;
                    scanned++;
                    if (maxFunctions > 0 && scanned >= maxFunctions) break;
                }
            } finally {
                if (decomp != null) try { decomp.dispose(); } catch (Exception ignored) {}
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
        if (surfaceCount != null) {
            out.put("scope", "attack_surface");
            out.put("attack_surface_function_count", surfaceCount);
        }
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
            Map<String, Object> out = new LinkedHashMap<>(r.toJson());
            out.put("address", site.toString());
            out.put("callee", callee != null ? callee.getName() : null);
            out.put("arg_index_used", idx);
            return Response.ok(out);
        }
    }

    // keep in sync with collectAttackSurfaceFunctions
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

    /**
     * Unique set of functions reachable (callers-of, BFS) within {@code maxDepth}
     * hops from any catalog SOURCE. Same traversal as enumerateAttackSurface but
     * without per-class bucketing or row JSON — used by detect_vuln_patterns
     * scope="attack_surface" to decide what to scan.
     */
    // keep in sync with bfsCallers
    private Set<Function> collectAttackSurfaceFunctions(Program program, int maxDepth) {
        FunctionManager fm = program.getFunctionManager();
        ReferenceManager rm = program.getReferenceManager();
        Set<Function> surface = new LinkedHashSet<>();
        Map<Function, Set<String>> seenSourceClasses = new HashMap<>();

        FunctionIterator it = fm.getFunctions(true);
        while (it.hasNext()) {
            Function f = it.next();
            for (CatalogEntry e : catalog.resolve(f)) {
                if (!"source".equals(e.kind())) continue;
                Set<String> done = seenSourceClasses.computeIfAbsent(f, k -> new HashSet<>());
                if (!done.add(e.vulnClass())) continue;
                // BFS callers-of from this source, collecting depth>0 functions.
                Set<Function> seen = new HashSet<>();
                Deque<Map.Entry<Function, Integer>> q = new ArrayDeque<>();
                q.add(Map.entry(f, 0));
                while (!q.isEmpty()) {
                    var cur = q.poll();
                    Function fn = cur.getKey(); int depth = cur.getValue();
                    if (!seen.add(fn)) continue;
                    if (depth > 0) surface.add(fn);
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
        }
        return surface;
    }

    // ---- core ----

    private record ScanResult(List<Finding> findings, boolean decompFailed, int siteCount) {}

    private DecompInterface openDecompiler(Program program) {
        try {
            DecompInterface d = new DecompInterface();
            d.openProgram(program);
            d.setSimplificationStyle("decompile");
            return d;
        } catch (Exception e) {
            return null; // Fall back to per-call decompileFunctionNoRetry.
        }
    }

    private static final int DECOMP_TIMEOUT_SECONDS = 12;

    private ScanResult scanFunction(Program program, Function f,
            List<VulnDetector> active, DecompInterface sharedDecomp) {
        DecompileResults dr;
        if (sharedDecomp != null) {
            try {
                dr = sharedDecomp.decompileFunction(f, DECOMP_TIMEOUT_SECONDS, TaskMonitor.DUMMY);
            } catch (Exception e) {
                dr = null;
            }
        } else {
            dr = functionService.decompileFunctionNoRetry(f, program);
        }
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
     * Drop SEVR/{@code <class>} bookmarks at each finding's address.
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
