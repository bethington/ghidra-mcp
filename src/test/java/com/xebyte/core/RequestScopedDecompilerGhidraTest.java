package com.xebyte.core;

import com.xebyte.headless.DirectThreadingStrategy;
import ghidra.GhidraApplicationLayout;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import org.junit.After;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.File;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.Assert.*;
import static org.junit.Assume.assumeTrue;

/**
 * {@code /get_functions} opens one decompiler per call, not one per decompile (#575).
 *
 * <p>Before this, every target and every call_context caller went through
 * {@code decompileFunctionNoRetry}, which opens and disposes a {@code DecompInterface} each
 * time: a 20-function bulk read with call context opened one per target plus one per
 * (target, caller) pair. These tests count the opens through the service's opener seam,
 * prove the output is the same as the per-function path's, and prove a decompile that
 * fails mid-call -- the interface left unusable -- does not take the rest of the call with it.
 */
public class RequestScopedDecompilerGhidraTest {

    private static final int TARGETS = 20;
    private static final int CALLERS = 10;
    private static final long TARGET_BASE = 0x401000L;
    private static final long CALLER_BASE = 0x401200L;

    private final List<ProgramBuilder> builders = new ArrayList<>();

    @BeforeClass
    public static void initializeGhidra() throws Exception {
        String installDir = System.getenv("GHIDRA_INSTALL_DIR");
        assumeTrue("GHIDRA_INSTALL_DIR is required for real Ghidra tests",
            installDir != null && !installDir.isBlank());
        if (!Application.isInitialized()) {
            ApplicationConfiguration configuration = new ApplicationConfiguration();
            configuration.setInitializeLogging(false);
            Application.initializeApplication(new GhidraApplicationLayout(new File(installDir)),
                configuration);
        }
    }

    @After
    public void tearDown() {
        for (ProgramBuilder b : builders) {
            b.dispose();
        }
    }

    // ------------------------------------------------------------------
    // Fixture
    // ------------------------------------------------------------------

    private static String hex(long a) {
        return "0x" + Long.toHexString(a);
    }

    private static String target(int i) {
        return hex(TARGET_BASE + 0x10L * i);
    }

    private static String caller(int j) {
        return hex(CALLER_BASE + 0x20L * j);
    }

    /** CALL rel32 from {@code site} to {@code dest}, as bytes. */
    private static String call(long site, long dest) {
        int rel = (int) (dest - (site + 5));
        return String.format("e8 %02x %02x %02x %02x ",
            rel & 0xff, (rel >> 8) & 0xff, (rel >> 16) & 0xff, (rel >>> 24) & 0xff);
    }

    /**
     * Twenty leaf targets ({@code MOV EAX,i ; RET}) and ten callers, caller j calling targets
     * j, j+10 and j+1 -- so every caller serves three targets, and a request that decompiles
     * per (target, caller) pair decompiles each caller three times.
     */
    private Program program() throws Exception {
        ProgramBuilder builder = new ProgramBuilder("request-decompiler", ProgramBuilder._X86, this);
        builders.add(builder);
        builder.createMemory(".text", hex(TARGET_BASE), 0x400);
        List<String> entries = new ArrayList<>();
        for (int i = 0; i < TARGETS; i++) {
            builder.setBytes(target(i), String.format("b8 %02x 00 00 00 c3", i));
            entries.add(target(i));
        }
        for (int j = 0; j < CALLERS; j++) {
            long site = CALLER_BASE + 0x20L * j;
            StringBuilder code = new StringBuilder();
            for (int t : new int[] {j, j + 10, (j + 1) % TARGETS}) {
                code.append(call(site, TARGET_BASE + 0x10L * t));
                site += 5;
            }
            code.append("c3");
            builder.setBytes(caller(j), code.toString());
            entries.add(caller(j));
        }
        ProgramDB program = builder.getProgram();
        AddressSet range = new AddressSet(builder.addr(hex(TARGET_BASE)),
            builder.addr(hex(TARGET_BASE + 0x3ff)));
        builder.withTransaction(() -> {
            for (String entry : entries) {
                new DisassembleCommand(builder.addr(entry), range, true)
                    .applyTo(program, TaskMonitor.DUMMY);
            }
        });
        for (String entry : entries) {
            builder.createFunction(entry);
        }
        return program;
    }

    private static ProgramProvider providerFor(Program program) {
        return new ProgramProvider() {
            @Override public Program getCurrentProgram() { return program; }
            @Override public Program getProgram(String name) { return program; }
            @Override public Program[] getAllOpenPrograms() { return new Program[] {program}; }
            @Override public void setCurrentProgram(Program p) { }
        };
    }

    /**
     * A real configured decompiler that counts its decompiles, and that can be told one
     * function kills it: from that decompile on, every call on this instance fails, the way
     * an interface whose process died mid-call does.
     */
    private static final class Probe extends DecompInterface {
        private final AtomicInteger decompiles;
        private final Long poisonEntry;
        private boolean dead;

        Probe(AtomicInteger decompiles, Long poisonEntry) {
            this.decompiles = decompiles;
            this.poisonEntry = poisonEntry;
        }

        @Override
        public synchronized DecompileResults decompileFunction(Function func, int timeoutSecs,
                TaskMonitor monitor) {
            decompiles.incrementAndGet();
            if (poisonEntry != null && func.getEntryPoint().getOffset() == poisonEntry) {
                dead = true;
            }
            if (dead) {
                TaskMonitorAdapter cancelled = new TaskMonitorAdapter(true);
                cancelled.cancel();
                return super.decompileFunction(func, timeoutSecs, cancelled);
            }
            return super.decompileFunction(func, timeoutSecs, monitor);
        }
    }

    private record Counted(FunctionBundleService service, AtomicInteger opens,
                           AtomicInteger decompiles) {}

    private static Counted counted(Program program, Long poisonEntry) {
        AtomicInteger opens = new AtomicInteger();
        AtomicInteger decompiles = new AtomicInteger();
        ProgramProvider provider = providerFor(program);
        DirectThreadingStrategy threading = new DirectThreadingStrategy();
        FunctionBundleService service = new FunctionBundleService(provider, threading,
            new FunctionService(provider, threading), p -> {
                opens.incrementAndGet();
                // Configured exactly as createConfiguredDecompiler + configureDecompiler do.
                Probe probe = new Probe(decompiles, poisonEntry);
                ghidra.app.decompiler.DecompileOptions opts =
                    new ghidra.app.decompiler.DecompileOptions();
                opts.grabFromProgram(p);
                FunctionFacts.configureDecompiler(opts);
                probe.setOptions(opts);
                probe.setSimplificationStyle("decompile");
                probe.openProgram(p);
                return probe;
            });
        return new Counted(service, opens, decompiles);
    }

    private static String allTargets() {
        List<String> refs = new ArrayList<>();
        for (int i = 0; i < TARGETS; i++) refs.add(target(i));
        return String.join(",", refs);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> data(Response r) {
        assertTrue("expected a structured response, got " + r.toJson(), r instanceof Response.Ok);
        return (Map<String, Object>) ((Response.Ok) r).data();
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Map<String, Object>> bulk(FunctionBundleService service,
            Program program, String fields) {
        Map<String, Object> out = data(service.getFunctions(null, allTargets(), fields, true, 6, 3,
            false, program, ""));
        return (Map<String, Map<String, Object>>) out.get("functions");
    }

    /** What get_functions returned before #575: a fresh decompiler for every decompile. */
    private static Map<String, Map<String, Object>> perFunctionPath(Program program,
            String fieldsCsv) {
        java.util.Set<String> fields = fieldsCsv.isEmpty() ? null
            : new java.util.LinkedHashSet<>(List.of(fieldsCsv.split(",")));
        FunctionService functions = new FunctionService(providerFor(program),
            new DirectThreadingStrategy());
        Map<String, Map<String, Object>> out = new LinkedHashMap<>();
        for (int i = 0; i < TARGETS; i++) {
            Function f = program.getFunctionManager()
                .getFunctionAt(program.getAddressFactory().getAddress(target(i)));
            out.put(target(i), FunctionFacts.build(program, f,
                new FunctionFacts.Options(fields, true, 6, 3, false),
                g -> functions.decompileFunctionNoRetry(g, program,
                    FunctionFacts::configureDecompiler)));
        }
        return out;
    }

    // ------------------------------------------------------------------
    // Tests
    // ------------------------------------------------------------------

    @Test
    public void aBulkCallWithCallContextOpensExactlyOneDecompiler() throws Exception {
        Program program = program();
        Counted c = counted(program, null);
        Map<String, Map<String, Object>> functions =
            bulk(c.service(), program, "decompiled_code,call_context");

        assertEquals(functions.toString(), TARGETS, functions.size());
        for (Map.Entry<String, Map<String, Object>> e : functions.entrySet()) {
            assertNotNull(e.getKey() + " was not decompiled: " + e.getValue(),
                e.getValue().get("decompiled_code"));
            assertTrue(e.getKey() + " has callers, so it must have call context: " + e.getValue(),
                e.getValue().get("call_context") instanceof List<?> l && !l.isEmpty());
        }
        assertEquals("one get_functions call must open one decompiler", 1, c.opens().get());
        // Each function once: 20 targets + 10 callers, although the callers serve 30
        // (target, caller) pairs between them.
        assertEquals("a function shared across entries must be decompiled once per call",
            TARGETS + CALLERS, c.decompiles().get());
    }

    @Test
    public void singleModeOpensOneDecompilerForTheTargetAndItsCallers() throws Exception {
        Program program = program();
        Counted c = counted(program, null);
        Function f = program.getFunctionManager()
            .getFunctionAt(program.getAddressFactory().getAddress(target(1)));
        Map<String, Object> out = data(c.service().getFunctions(f, "",
            "decompiled_code,call_context", true, 6, 3, false, program, ""));
        assertNotNull(out.toString(), out.get("decompiled_code"));
        assertEquals(out.toString(), 2, ((List<?>) out.get("call_context")).size());
        assertEquals(1, c.opens().get());
        assertEquals(3, c.decompiles().get());
    }

    @Test
    public void aSubsetThatDecompilesNothingOpensNoDecompiler() throws Exception {
        Program program = program();
        Counted c = counted(program, null);
        bulk(c.service(), program, "signature,callers,callees");
        assertEquals(0, c.opens().get());
    }

    /** Same bundle, field for field, as the per-decompile path it replaces. */
    @Test
    public void theBundlesAreIdenticalToThePerFunctionPath() throws Exception {
        Program program = program();
        for (String fields : new String[] {"decompiled_code,call_context", ""}) {
            Map<String, Map<String, Object>> expected = perFunctionPath(program, fields);
            Map<String, Map<String, Object>> actual = bulk(
                new FunctionBundleService(providerFor(program), new DirectThreadingStrategy(),
                    new FunctionService(providerFor(program), new DirectThreadingStrategy())),
                program, fields);
            assertEquals("fields=" + fields, expected, actual);
        }
    }

    /**
     * Target 5's decompile kills the interface. It reports its own failure; every entry
     * after it still decompiles, on a reopened interface, call context included.
     */
    @Test
    public void aDecompileThatKillsTheInterfaceDoesNotFailTheRestOfTheCall() throws Exception {
        Program program = program();
        long poison = TARGET_BASE + 0x10L * 5;
        Counted c = counted(program, poison);
        Map<String, Map<String, Object>> functions =
            bulk(c.service(), program, "decompiled_code,call_context");

        Map<String, Object> failed = functions.get(target(5));
        assertEquals(failed.toString(), Boolean.TRUE, failed.get("decompile_failed"));
        assertNull(failed.toString(), failed.get("decompiled_code"));
        for (int i = 0; i < TARGETS; i++) {
            if (i == 5) continue;
            Map<String, Object> entry = functions.get(target(i));
            assertNotNull(target(i) + " must decompile after the failure: " + entry,
                entry.get("decompiled_code"));
            for (Object site : (List<?>) entry.get("call_context")) {
                assertTrue(target(i) + "'s call context lost its caller's line: " + site,
                    ((Map<?, ?>) site).containsKey("line_number"));
            }
        }
        assertEquals("the failure must cost exactly one reopen", 2, c.opens().get());
    }
}
