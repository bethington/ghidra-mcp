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

import java.util.ArrayList;
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
        for (String s : classesCsv.split(",")) {
            s = s.strip();
            if (!s.isEmpty()) wanted.add(s);
        }
        List<VulnDetector> active = new ArrayList<>();
        for (VulnDetector d : detectors) {
            if (wanted.isEmpty() || wanted.contains(d.id())) active.add(d);
        }

        List<Finding> findings = new ArrayList<>();
        int scanned = 0;
        int decompFail = 0;

        if (!functionRef.isBlank()) {
            Function f = resolveFunction(program, functionRef);
            if (f == null) return Response.err("Function not found: " + functionRef);
            ScanResult r = scanFunction(program, f, active);
            findings.addAll(r.findings);
            scanned = 1;
            decompFail = r.decompFailed ? 1 : 0;
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
        return Response.ok(out);
    }

    // ---- core ----

    private record ScanResult(List<Finding> findings, boolean decompFailed) {}

    private ScanResult scanFunction(Program program, Function f, List<VulnDetector> active) {
        DecompileResults dr = functionService.decompileFunctionNoRetry(f, program);
        if (dr == null || !dr.decompileCompleted() || dr.getHighFunction() == null) {
            return new ScanResult(List.of(), true);
        }
        HighFunction hf = dr.getHighFunction();
        FunctionManager fm = program.getFunctionManager();

        List<SinkCallSite> sites = new ArrayList<>();
        Iterator<PcodeOpAST> ops = hf.getPcodeOps();
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
            for (SinkCallSite s : sites) {
                if (d.sinkClasses().contains(s.entry().vulnClass())) mine.add(s);
            }
            if (!mine.isEmpty()) all.addAll(d.scan(hf, mine));
        }
        return new ScanResult(all, false);
    }

    private Function resolveCallee(PcodeOp op, FunctionManager fm) {
        if (op.getNumInputs() == 0) return null;
        Varnode tgt = op.getInput(0);
        if (tgt == null || !tgt.isAddress()) return null;
        Function f = fm.getFunctionAt(tgt.getAddress());
        if (f != null && f.isThunk()) {
            Function real = f.getThunkedFunction(true);
            if (real != null) return real;
        }
        return f;
    }

    /**
     * Resolve a function by address-or-name. Uses {@code AddressFactory.getAddress}
     * directly (overlay-safe: accepts {@code name::offset}) rather than
     * {@code ServiceUtils.parseAddress}, which on this branch lowercases overlay
     * space names.
     */
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
        FunctionIterator it = program.getFunctionManager().getFunctions(true);
        while (it.hasNext()) {
            Function f = it.next();
            if (f.getName().equalsIgnoreCase(r)) return f;
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
