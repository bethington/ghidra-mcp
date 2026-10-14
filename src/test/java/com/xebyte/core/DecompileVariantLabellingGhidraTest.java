package com.xebyte.core;

import com.xebyte.headless.DirectThreadingStrategy;
import ghidra.GhidraApplicationLayout;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import org.junit.After;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.*;
import static org.junit.Assume.assumeTrue;

/**
 * The variant label and check, exercised through the real endpoints on real programs.
 *
 * <p>{@code DecompiledOutputIsStampedTest} proves from source text that every site handing
 * back decompiler C calls the stamp. It cannot prove what a caller receives: that the stamp
 * lands in the response rather than in a map nobody returns, that {@code get_functions} bulk
 * mode stamps every entry, that a contradicted {@code variant=} is refused before the bulk
 * dispatch rather than after it, or that the composites withhold only their pseudocode. The
 * live integration suite covers that, but only after a deploy. This covers it in CI, against
 * Ghidra's own language table and decompiler, on an x86 program (one decoder, so no
 * advisory) and a PowerPC one (ten decoders, VLE among them, so the advisory rides along).
 */
public class DecompileVariantLabellingGhidraTest {

    private static final String X86_CALLEE = "0x401000";
    private static final String X86_CALLER = "0x401010";
    private static final String PPC_FUNC = "0x10000";

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
    // Fixtures
    // ------------------------------------------------------------------

    /** The services as the server wires them, over one program. */
    private record Services(Program program, FunctionService functions,
                            FunctionBundleService bundles, AnalysisService analysis) {}

    private static Services servicesFor(Program program) {
        ProgramProvider provider = new ProgramProvider() {
            @Override public Program getCurrentProgram() { return program; }
            @Override public Program getProgram(String name) { return program; }
            @Override public Program[] getAllOpenPrograms() { return new Program[] {program}; }
            @Override public void setCurrentProgram(Program p) { }
        };
        DirectThreadingStrategy threading = new DirectThreadingStrategy();
        FunctionService functions = new FunctionService(provider, threading);
        return new Services(program, functions,
            new FunctionBundleService(provider, threading, functions),
            new AnalysisService(provider, threading, functions));
    }

    /** Disassemble from each entry point; flow from one does not reach the next. */
    private ProgramDB build(ProgramBuilder builder, String end, String... entries) throws Exception {
        builders.add(builder);
        ProgramDB program = builder.getProgram();
        AddressSet range = new AddressSet(builder.addr(entries[0]), builder.addr(end));
        builder.withTransaction(() -> {
            for (String entry : entries) {
                new DisassembleCommand(builder.addr(entry), range, true)
                    .applyTo(program, TaskMonitor.DUMMY);
            }
        });
        return program;
    }

    /**
     * x86 at 32 bits: {@code default} and {@code System Management Mode} are two variant rows
     * over one {@code x86.sla}, so this is the program the advisory must stay quiet on -- the
     * case a mandatory parameter broke for every PE and ELF.
     */
    private Services x86() throws Exception {
        ProgramBuilder builder = new ProgramBuilder("variant-x86", ProgramBuilder._X86, this);
        builder.createMemory(".text", "0x401000", 0x100);
        // callee: MOV EAX,1 ; RET
        builder.setBytes(X86_CALLEE, "b8 01 00 00 00 c3");
        // caller: CALL callee ; RET   (rel32 = 0x401000 - 0x401015)
        builder.setBytes(X86_CALLER, "e8 eb ff ff ff c3");
        ProgramDB program = build(builder, "0x401015", X86_CALLEE, X86_CALLER);
        builder.createFunction(X86_CALLEE);
        builder.createFunction(X86_CALLER);
        return servicesFor(program);
    }

    /** PowerPC/BE/32: eleven variants over ten decoders, VLE among them. */
    private Services powerPc() throws Exception {
        ProgramBuilder builder = new ProgramBuilder("variant-ppc", ProgramBuilder._PPC_32, this);
        builder.createMemory(".text", PPC_FUNC, 0x100);
        // li r3,1 ; blr
        builder.setBytes(PPC_FUNC, "38 60 00 01 4e 80 00 20");
        ProgramDB program = build(builder, "0x10007", PPC_FUNC);
        builder.createFunction(PPC_FUNC);
        return servicesFor(program);
    }

    /** A real variant of this program's processor that the program is NOT loaded under. */
    private static String otherVariant(Program program) {
        String loaded = ServiceUtils.loadedVariant(program);
        for (String name : ServiceUtils.languageVariantNames(program)) {
            if (!name.equalsIgnoreCase(loaded)) return name;
        }
        fail("no second variant for " + program.getLanguageID() + "; this test needs one");
        return null;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> data(Response r) {
        assertTrue("expected a structured response, got " + r.toJson(), r instanceof Response.Ok);
        Object d = ((Response.Ok) r).data();
        assertTrue("expected a JSON object, got " + r.toJson(), d instanceof Map);
        return (Map<String, Object>) d;
    }

    private static Response getFunctions(Services s, String function, String functions,
                                         String fields, String variant) {
        return s.bundles().getFunctions(function, functions, fields, true, 6, 3, false, "",
            variant);
    }

    private static void assertStamped(Program program, Map<String, Object> out) {
        assertEquals(out.toString(), program.getLanguageID().getIdAsString(),
            out.get("language_id"));
        assertEquals(out.toString(), program.getLanguage().getLanguageDescription().getVariant(),
            out.get("variant"));
    }

    private static void assertRefused(Response r, String error) {
        Map<String, Object> out = data(r);
        assertEquals(out.toString(), "rejected", out.get("status"));
        assertEquals(out.toString(), error, out.get("error"));
        assertFalse("a refusal must not carry pseudocode: " + out,
            out.containsKey("decompiled_code") || out.containsKey("decompiled")
                || out.containsKey("functions"));
    }

    // ------------------------------------------------------------------
    // get_functions
    // ------------------------------------------------------------------

    @Test
    public void decompiledCodeIsStampedAndQuietOnASingleDecoderProcessor() throws Exception {
        Services s = x86();
        Map<String, Object> out = data(getFunctions(s, X86_CALLEE, "", "decompiled_code", ""));
        assertNotNull("the decompile itself must have worked for this to mean anything: " + out,
            out.get("decompiled_code"));
        assertStamped(s.program(), out);
        assertFalse("x86 is one decoder; the advisory must stay off: " + out,
            out.containsKey("variant_ambiguous"));
        assertFalse(out.toString(), out.containsKey("variant_candidates"));
        assertFalse(out.toString(), out.containsKey("variant_notice"));
    }

    /** The label travels with decompiler output, not with every read of a function. */
    @Test
    public void aBundleWithNoDecompilerOutputCarriesNoStamp() throws Exception {
        Services s = x86();
        Map<String, Object> out = data(getFunctions(s, X86_CALLEE, "", "signature,callers", ""));
        assertFalse(out.toString(), out.containsKey("decompiled_code"));
        assertFalse(out.toString(), out.containsKey("language_id"));
    }

    /** call_context is the CALLER's decompiled C, so it is labelled like the target's own. */
    @Test
    public void callContextAloneIsStamped() throws Exception {
        Services s = x86();
        Map<String, Object> out = data(getFunctions(s, X86_CALLEE, "", "call_context", ""));
        Object context = out.get("call_context");
        assertTrue("the caller should have been decompiled for its call site: " + out,
            context instanceof List<?> list && !list.isEmpty());
        assertStamped(s.program(), out);
    }

    @Test
    @SuppressWarnings("unchecked")
    public void bulkModeStampsEveryEntryAndKeepsTheStampOutOfTheFunctionMap() throws Exception {
        Services s = x86();
        Map<String, Object> out = data(getFunctions(s, "",
            X86_CALLEE + "," + X86_CALLER, "decompiled_code", ""));
        Map<String, Object> functions = (Map<String, Object>) out.get("functions");
        assertNotNull(out.toString(), functions);
        assertEquals(functions.toString(), 2, functions.size());
        // The function map is keyed by references the caller chose; the stamp's reserved
        // names must never share that namespace.
        assertFalse(functions.toString(), functions.containsKey("language_id"));
        assertFalse(functions.toString(), functions.containsKey("variant"));
        for (Map.Entry<String, Object> e : functions.entrySet()) {
            Map<String, Object> entry = (Map<String, Object>) e.getValue();
            assertNotNull(e.getKey() + " was not decompiled: " + entry, entry.get("decompiled_code"));
            assertStamped(s.program(), entry);
        }
    }

    @Test
    public void namingTheLoadedVariantIsAcceptedInEitherSpelling() throws Exception {
        Services s = x86();
        String loaded = ServiceUtils.loadedVariant(s.program());
        String languageId = s.program().getLanguageID().getIdAsString();
        for (String claim : new String[] {loaded, loaded.toUpperCase(), languageId}) {
            Map<String, Object> out = data(getFunctions(s, X86_CALLEE, "", "decompiled_code", claim));
            assertNotNull("variant=" + claim + " is true and must be answered: " + out,
                out.get("decompiled_code"));
            assertStamped(s.program(), out);
        }
    }

    /**
     * A contradicted claim is refused wherever it is made: single mode, bulk mode, and a read
     * asking for no C at all -- every field get_functions returns is decoded under the
     * program's own language, so none of them answers the question the caller asked.
     */
    @Test
    public void aContradictedVariantIsRefusedInEveryMode() throws Exception {
        Services s = x86();
        String other = otherVariant(s.program());
        assertRefused(getFunctions(s, X86_CALLEE, "", "decompiled_code", other), "variant_mismatch");
        assertRefused(getFunctions(s, "", X86_CALLEE + "," + X86_CALLER, "decompiled_code", other),
            "variant_mismatch");
        assertRefused(getFunctions(s, X86_CALLEE, "", "signature", other), "variant_mismatch");
        assertRefused(getFunctions(s, X86_CALLEE, "", "",
            "PowerPC:BE:32:default"), "variant_mismatch");
        assertRefused(getFunctions(s, X86_CALLEE, "", "decompiled_code", "NotARealVariant"),
            "unknown_variant");
    }

    @Test
    public void theRefusalNamesTheLoadedVariantAndTheRemedy() throws Exception {
        Services s = x86();
        Map<String, Object> out = data(getFunctions(s, X86_CALLEE, "", "decompiled_code",
            otherVariant(s.program())));
        assertEquals(out.toString(), ServiceUtils.loadedVariant(s.program()), out.get("loaded_variant"));
        assertTrue(out.toString(), String.valueOf(out.get("suggestion")).contains("import_file(language="));
        assertTrue(out.toString(), out.get("available_variants") instanceof List<?>);
    }

    // ------------------------------------------------------------------
    // force_decompile
    // ------------------------------------------------------------------

    @Test
    public void forceDecompileIsStampedAndChecked() throws Exception {
        Services s = x86();
        Map<String, Object> out = data(s.functions().forceDecompile(X86_CALLEE, "", ""));
        assertNotNull(out.toString(), out.get("decompiled"));
        assertStamped(s.program(), out);

        out = data(s.functions().forceDecompile(X86_CALLEE, "",
            ServiceUtils.loadedVariant(s.program())));
        assertNotNull(out.toString(), out.get("decompiled"));

        assertRefused(s.functions().forceDecompile(X86_CALLEE, "", otherVariant(s.program())),
            "variant_mismatch");
    }

    /** The internal overloads skip the check -- they never state a belief -- but not the label. */
    @Test
    public void internalCallersAreStampedButNeverChecked() throws Exception {
        Services s = x86();
        assertStamped(s.program(), data(s.functions().forceDecompile(X86_CALLEE)));
        assertStamped(s.program(), data(s.functions().decompileFunctionByAddress(X86_CALLEE)));

        @SuppressWarnings("unchecked")
        Map<String, Object> bulk = data(s.functions().batchDecompileFunctions(X86_CALLEE));
        assertStamped(s.program(), bulk);
        assertTrue(bulk.toString(), bulk.get("functions") instanceof Map<?, ?> m
            && m.containsKey(X86_CALLEE) && !m.containsKey("language_id"));
    }

    // ------------------------------------------------------------------
    // Composites
    // ------------------------------------------------------------------

    @Test
    public void compositesStampTheirPseudocode() throws Exception {
        Services s = x86();
        Map<String, Object> doc = data(s.analysis().analyzeForDocumentation(X86_CALLEE, "", ""));
        assertNotNull(doc.toString(), doc.get("decompiled_code"));
        assertStamped(s.program(), doc);

        Map<String, Object> complete = data(s.analysis().analyzeFunctionComplete(X86_CALLEE,
            false, false, false, false, false, false, "", ""));
        assertNotNull(complete.toString(), complete.get("decompiled_code"));
        assertStamped(s.program(), complete);
    }

    /**
     * A caller refused by get_functions must not get the same C one tool over. Only the
     * pseudocode is held back; the rest of the analysis still answers.
     */
    @Test
    public void compositesWithholdOnlyThePseudocodeOnAContradictedVariant() throws Exception {
        Services s = x86();
        String other = otherVariant(s.program());
        for (Map<String, Object> out : List.of(
                data(s.analysis().analyzeForDocumentation(X86_CALLEE, "", other)),
                data(s.analysis().analyzeFunctionComplete(X86_CALLEE,
                    false, false, false, false, false, false, "", other)))) {
            assertFalse("pseudocode escaped the check: " + out, out.containsKey("decompiled_code"));
            assertFalse(out.toString(), out.containsKey("language_id"));
            assertTrue(out.toString(), out.get("decompiled_code_withheld") instanceof Map<?, ?> w
                && "variant_mismatch".equals(w.get("error")));
            assertNotEquals("the rest of the composite must still answer: " + out,
                "rejected", out.get("status"));
        }
    }

    // ------------------------------------------------------------------
    // get_language_metadata
    // ------------------------------------------------------------------

    @Test
    @SuppressWarnings("unchecked")
    public void languageMetadataEnumeratesTheChoiceItAdvisesOn() throws Exception {
        Services s = x86();
        Map<String, Object> out = data(s.analysis().getLanguageMetadata(false, false, ""));
        assertEquals(out.toString(), Boolean.FALSE, out.get("variant_ambiguous"));
        assertEquals(out.toString(), Boolean.FALSE, out.get("variant_enumeration_failed"));
        List<Map<String, Object>> variants = (List<Map<String, Object>>) out.get("available_variants");
        assertTrue(out.toString(), variants.size() > 1);
        assertEquals(variants.toString(), 1,
            variants.stream().filter(v -> Boolean.TRUE.equals(v.get("loaded"))).count());
        for (Map<String, Object> v : variants) {
            assertEquals("x86 at 32 bits is one decoder: " + variants, "x86.sla", v.get("decoder"));
        }
    }

    // ------------------------------------------------------------------
    // A processor where the loader really did guess
    // ------------------------------------------------------------------

    @Test
    @SuppressWarnings("unchecked")
    public void aMultiDecoderProcessorCarriesTheAdvisoryAlongsideTheCode() throws Exception {
        Services s = powerPc();
        Map<String, Object> out = data(getFunctions(s, PPC_FUNC, "", "decompiled_code", ""));
        assertNotNull(out.toString(), out.get("decompiled_code"));
        assertStamped(s.program(), out);
        assertEquals(out.toString(), Boolean.TRUE, out.get("variant_ambiguous"));
        List<String> candidates = (List<String>) out.get("variant_candidates");
        assertTrue(out.toString(), candidates.stream().anyMatch(c -> c.contains("VLE")));
        String notice = String.valueOf(out.get("variant_notice"));
        assertTrue(notice, notice.contains("'" + ServiceUtils.loadedVariant(s.program()) + "'"));
        assertTrue(notice, notice.contains("import_file(language="));

        Map<String, Object> bulk = data(getFunctions(s, "", PPC_FUNC, "decompiled_code", ""));
        Map<String, Object> entry = (Map<String, Object>)
            ((Map<String, Object>) bulk.get("functions")).get(PPC_FUNC);
        assertEquals(entry.toString(), Boolean.TRUE, entry.get("variant_ambiguous"));
    }

    /** The case all of this exists for: VLE named against a classic-PowerPC program. */
    @Test
    public void namingVleAgainstAClassicPowerPcProgramIsRefused() throws Exception {
        Services s = powerPc();
        String vle = ServiceUtils.languageVariantNames(s.program()).stream()
            .filter(v -> v.contains("VLE")).findFirst().orElseThrow();
        assertRefused(getFunctions(s, PPC_FUNC, "", "decompiled_code", vle), "variant_mismatch");
        assertRefused(s.functions().forceDecompile(PPC_FUNC, "", vle), "variant_mismatch");
    }
}
