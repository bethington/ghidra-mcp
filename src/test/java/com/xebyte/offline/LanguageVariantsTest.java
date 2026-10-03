package com.xebyte.offline;

import com.xebyte.core.LanguageVariants;
import com.xebyte.core.LanguageVariants.Rejection;
import junit.framework.TestCase;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

/**
 * Pure-logic tests for the decompile variant labelling and mismatch check.
 *
 * <p>The rules under test:
 * <ul>
 *   <li>Omitting {@code variant=} is always allowed. The caller stated no belief,
 *       so there is nothing to contradict; the response is labelled instead.</li>
 *   <li>Naming a variant the program is not loaded under is refused, never
 *       answered — the caller volunteered a belief the program contradicts.</li>
 *   <li>The ambiguity advisory fires on the number of distinct SLEIGH
 *       <em>decoders</em> a bucket holds, not the number of variant rows.</li>
 * </ul>
 *
 * <p>The variant lists and {@code .sla} names below were read off Ghidra 12.1.2's
 * {@code .ldefs} files, not invented for the test. Measured across the whole
 * install: 30 of 83 processor/endian/size buckets hold more than one variant row,
 * but only 19 hold more than one decoder (96 of 177 non-deprecated languages
 * rather than 124). All three x86 buckets are in the difference — which is why
 * ordinary PE and ELF work sees a label and not a question — and PowerPC/BE/32
 * is not, which is the case the whole feature exists for.
 *
 * <p>No Ghidra, no HTTP. The Ghidra-facing half (enumerating a processor's real
 * variants and their decoders) lives in {@code ServiceUtils.languageVariantChoices}
 * and is covered live by the {@code get_language_metadata} integration tests.
 */
public class LanguageVariantsTest extends TestCase {

    /**
     * The PowerPC / big-endian / 32-bit-address bucket, read off Ghidra 12.1.2's
     * {@code ppc.ldefs} rather than invented. Eleven entries, and five of them
     * carry {@code :64:} in their language id while declaring {@code size="32"}:
     * the id's middle field is the instruction set, the bucket key is the ADDRESS
     * size. That is why classic PowerPC and VLE land in the same bucket, which is
     * the whole point.
     */
    private static final List<String> PPC_BE_32 = Arrays.asList(
            "default", "4xx", "64-32addr", "MPC8270", "PowerISA-64-32addr",
            "PowerISA-Altivec-64-32addr", "PowerISA-VLE-64-32addr",
            "PowerISA-VLE-Altivec-64-32addr", "PowerQUICC-III",
            "PowerQUICC-III-e500", "PowerQUICC-III-e500mc");

    /**
     * The decoders those eleven load: ten distinct {@code .sla} files, with
     * {@code ppc_32_be.sla} shared by {@code default} and {@code MPC8270}. A real
     * choice between real decoders, so the advisory fires.
     */
    private static final List<String> PPC_BE_32_DECODERS = Arrays.asList(
            "ppc_32_be.sla", "ppc_32_4xx_be.sla", "ppc_64_be.sla", "ppc_32_be.sla",
            "ppc_64_isa_be.sla", "ppc_64_isa_altivec_be.sla", "ppc_64_isa_vle_be.sla",
            "ppc_64_isa_altivec_vle_be.sla", "ppc_32_quicciii_be.sla",
            "ppc_32_e500_be.sla", "ppc_32_e500mc_be.sla");

    /** Ghidra 12.1.2's VLE variant for a 32-bit-address PowerPC image. */
    private static final String PPC_VLE = "PowerISA-VLE-64-32addr";
    private static final String PPC_VLE_ID = "PowerPC:BE:64:VLE-32addr";

    /** RISCV / little / 64: genuinely one variant in 12.1.2. */
    private static final List<String> RISCV_LE_64 = Arrays.asList("default");

    /**
     * x86 LE 32: two variant rows, ONE decoder. {@code default} and
     * {@code System Management Mode} are both {@code x86.sla}; they differ in
     * processor spec ({@code x86.pspec} vs {@code x86-16.pspec}). This is the
     * bucket that made the mandatory-parameter version untenable — it is every
     * 32-bit Windows binary anyone opens.
     */
    private static final List<String> X86_LE_32 =
            Arrays.asList("default", "System Management Mode");
    private static final List<String> X86_LE_32_DECODERS =
            Arrays.asList("x86.sla", "x86.sla");

    /**
     * MIPS / little / 64: four rows, one {@code mips64le.sla}. The honest limit
     * of the decoder proxy — {@code mips64micro.pspec} sets the {@code RELP}
     * context variable, so these really do decode differently. They are a mode no
     * loader auto-selects, and the unconditional stamp is what covers them.
     */
    private static final List<String> MIPS_LE_64_DECODERS =
            Arrays.asList("mips64le.sla", "mips64le.sla", "mips64le.sla", "mips64le.sla");

    /** ARM / little / 32, for checking the advisory does not talk about PowerPC. */
    private static final List<String> ARM_LE_32 = Arrays.asList(
            "v4", "v4t", "v5", "v5t", "v6", "v7", "v8", "v8T", "v8-m", "Cortex");

    // ---------- omitting the parameter is always allowed ----------

    public void testOmittedVariantProceedsOnAnUnambiguousProcessor() {
        assertNull(LanguageVariants.check("RISCV:LE:64:default", "default", RISCV_LE_64, ""));
        assertNull(LanguageVariants.check("RISCV:LE:64:default", "default", RISCV_LE_64, null));
    }

    /**
     * The case that used to be refused. A caller asking for pseudocode without
     * naming a dialect gets pseudocode, labelled with the dialect that produced
     * it. Requiring the name instead bought nothing: the refusal had to enumerate
     * the legal values to be answerable, so it named the answer, and the caller
     * echoed it back without checking anything.
     */
    public void testOmittedVariantProceedsOnAnAmbiguousProcessorToo() {
        assertNull(LanguageVariants.check("PowerPC:BE:32:default", "default", PPC_BE_32, ""));
        assertNull(LanguageVariants.check("PowerPC:BE:32:default", "default", PPC_BE_32, null));
        assertNull(LanguageVariants.check("PowerPC:BE:32:default", "default", PPC_BE_32, "   "));
    }

    public void testNoRequiredVariantErrorCodeExists() {
        // The gate's error code is gone, not merely unreachable. A constant kept
        // "just in case" is how a removed rule comes back by accident.
        for (java.lang.reflect.Field f : LanguageVariants.class.getFields()) {
            assertFalse("VARIANT_REQUIRED should no longer exist: " + f.getName(),
                    "VARIANT_REQUIRED".equals(f.getName()));
        }
    }

    // ---------- a named variant is checked ----------

    public void testMatchingSelectionProceeds() {
        assertNull(LanguageVariants.check(PPC_VLE_ID, PPC_VLE, PPC_BE_32, PPC_VLE));
    }

    public void testSelectionIsCaseAndWhitespaceInsensitive() {
        assertNull(LanguageVariants.check(PPC_VLE_ID, PPC_VLE, PPC_BE_32,
                PPC_VLE.toUpperCase(Locale.ROOT)));
        assertNull(LanguageVariants.check(PPC_VLE_ID, PPC_VLE, PPC_BE_32, "  " + PPC_VLE + " "));
    }

    public void testMultiWordVariantRoundTrips() {
        assertNull(LanguageVariants.check("x86:LE:32:System Management Mode",
                "System Management Mode", X86_LE_32, "System Management Mode"));
    }

    /**
     * Asking for VLE on a program loaded as classic PowerPC is refused rather
     * than answered. The decompiler decodes with the language the program was
     * imported under and cannot be asked for another, so answering would return
     * classic-PowerPC C under a VLE label — worse than no answer, because the
     * label makes it look checked. This is the half of the original design that
     * was never ceremony: the caller volunteered the claim.
     */
    public void testRequestingADifferentVariantIsRefusedNotIgnored() {
        Rejection r = LanguageVariants.check("PowerPC:BE:32:default", "default", PPC_BE_32, PPC_VLE);
        assertNotNull(r);
        assertEquals(LanguageVariants.VARIANT_MISMATCH, r.error());
        assertTrue(r.message().contains("different question"));
        assertTrue(r.suggestion().contains("variant=default"));
        assertTrue(r.suggestion().contains("import_file(language=...)"));
    }

    /** Both ways out have to be named, or the refusal leaves the caller stuck. */
    public void testMismatchSuggestionNamesBothRemedies() {
        Rejection r = LanguageVariants.check("PowerPC:BE:32:default", "default", PPC_BE_32, PPC_VLE);
        assertTrue(r.suggestion().contains("import_file(language=...)"));
        assertTrue(r.suggestion().contains("Set Language"));
        // Omitting the parameter is now a legal way out, and the suggestion says so.
        assertTrue(r.suggestion().contains("omitting variant="));
    }

    /**
     * A caller asking for VLE on a RISC-V program has mistaken which program it
     * is talking to. Catching that here is far cheaper than downstream, and it is
     * worth catching even though RISC-V offers no choice at all.
     */
    public void testSingleVariantStillRejectsAForeignVariant() {
        Rejection r = LanguageVariants.check("RISCV:LE:64:default", "default", RISCV_LE_64, "VLE");
        assertNotNull(r);
        assertEquals(LanguageVariants.UNKNOWN_VARIANT, r.error());
        assertTrue(r.message().contains("default"));
    }

    public void testSingleVariantAcceptsTheCorrectSelection() {
        assertNull(LanguageVariants.check("RISCV:LE:64:default", "default", RISCV_LE_64, "default"));
    }

    // ---------- full language id spelling ----------

    public void testFullLanguageIdIsAcceptedWhenItMatches() {
        assertNull(LanguageVariants.check(PPC_VLE_ID, PPC_VLE, PPC_BE_32, PPC_VLE_ID));
        assertNull(LanguageVariants.check(PPC_VLE_ID, PPC_VLE, PPC_BE_32, "powerpc:be:64:vle-32addr"));
    }

    /**
     * A full id is compared whole. Matching only its variant column would let
     * {@code PowerPC:BE:64:default} satisfy a 32-bit program, which is a bigger
     * mistake than the one being guarded against.
     */
    public void testFullLanguageIdWithADifferentSizeIsRejected() {
        Rejection r = LanguageVariants.check("PowerPC:BE:32:default", "default",
                PPC_BE_32, "PowerPC:BE:64:default");
        assertNotNull(r);
        assertEquals(LanguageVariants.VARIANT_MISMATCH, r.error());
        assertTrue(r.message().contains("PowerPC:BE:64:default"));
        assertTrue(r.message().contains("PowerPC:BE:32:default"));
    }

    /**
     * The suggestion echoes the caller's own spelling, not the id's last colon
     * segment. {@code variantToken("PowerPC:BE:64:VLE-32addr")} is
     * {@code VLE-32addr}, which is NOT a variant name Ghidra 12.1.2 offers — the
     * picker calls it {@code PowerISA-VLE-64-32addr} — so echoing the token back
     * told the caller to go and make real a thing {@code import_file} would
     * reject.
     */
    public void testFullIdMismatchSuggestionQuotesWhatTheCallerActuallySent() {
        Rejection r = LanguageVariants.check("PowerPC:BE:32:default", "default",
                PPC_BE_32, PPC_VLE_ID);
        assertNotNull(r);
        assertTrue("suggestion should name the full requested id",
                r.suggestion().contains(PPC_VLE_ID));
        assertFalse("suggestion must not invent the bare token as a variant name",
                r.suggestion().contains("'" + LanguageVariants.variantToken(PPC_VLE_ID) + "'"));
    }

    // ---------- the advisory counts decoders, not rows ----------

    /**
     * The measurement that unblocked this. Both x86 rows load {@code x86.sla};
     * the eleven PowerPC rows load ten different decoders. Counting rows made
     * every 32-bit Windows binary ambiguous, which is what made a mandatory
     * parameter a hard break for the most-called tool in the catalog.
     */
    public void testAmbiguityIsDecidedByDecoderNotByVariantCount() {
        assertFalse("x86 32-bit is two configurations of one decoder",
                LanguageVariants.isAmbiguous(X86_LE_32_DECODERS));
        assertTrue("PowerPC BE 32 really does offer different decoders",
                LanguageVariants.isAmbiguous(PPC_BE_32_DECODERS));
    }

    /**
     * The honest limit, pinned so nobody "fixes" it by accident: MIPS/64's four
     * rows share one decoder and select microMIPS/mips16e/R6 through pspec
     * context instead, so they decode differently while this test says they do
     * not. Widening the rule to catch them re-admits x86, which is the trade
     * being made; the unconditional stamp is what covers the gap.
     */
    public void testSameDecoderDifferentProcessorSpecIsNotFlagged() {
        assertFalse(LanguageVariants.isAmbiguous(MIPS_LE_64_DECODERS));
    }

    public void testSingleDecoderAndEmptyInputAreUnambiguous() {
        assertFalse(LanguageVariants.isAmbiguous(Arrays.asList("x86.sla")));
        assertFalse(LanguageVariants.isAmbiguous(Collections.<String>emptyList()));
        assertFalse(LanguageVariants.isAmbiguous(null));
    }

    public void testDecoderComparisonIgnoresBlanksAndCase() {
        assertFalse(LanguageVariants.isAmbiguous(
                Arrays.asList("ARM7_le.sla", "  ", null, "arm7_LE.sla")));
        assertTrue(LanguageVariants.isAmbiguous(
                Arrays.asList("ARM7_le.sla", "", "ARM8_le.sla")));
    }

    // ---------- the advisory text ----------

    public void testAdvisoryNamesEveryCandidateAndTheLoadedOne() {
        String notice = LanguageVariants.ambiguityNotice(PPC_BE_32, "default");
        assertTrue(notice.contains("11 SLEIGH variants"));
        for (String variant : PPC_BE_32) {
            assertTrue("candidate missing from advisory: " + variant, notice.contains(variant));
        }
        assertTrue(notice.contains("'default'"));
    }

    public void testAdvisoryNamesBothRemedies() {
        String notice = LanguageVariants.ambiguityNotice(PPC_BE_32, "default");
        assertTrue(notice.contains("import_file(language=...)"));
        assertTrue(notice.contains("Set Language"));
    }

    /**
     * The message is built from the candidates it was given. An earlier revision
     * hard-coded the PowerPC/VLE example into every refusal, so an ARM caller was
     * told about a processor it was not using.
     */
    public void testAdvisoryDoesNotTalkAboutPowerPCOnAnArmProgram() {
        String notice = LanguageVariants.ambiguityNotice(ARM_LE_32, "Cortex");
        assertFalse("advisory hard-codes PowerPC", notice.contains("PowerPC"));
        assertTrue(notice.contains("Cortex"));
        assertTrue(notice.contains("10 SLEIGH variants"));
    }

    public void testAdvisoryUnionsALoadedVariantTheEnumerationMissed() {
        String notice = LanguageVariants.ambiguityNotice(Arrays.asList("v7", "v8"), "vendorX");
        assertTrue(notice.contains("vendorX"));
        assertTrue(notice.contains("3 SLEIGH variants"));
    }

    // ---------- languages the enumeration cannot see ----------

    /**
     * Deprecated languages are excluded from Ghidra's enumeration, and a
     * processor module can be uninstalled after a program was imported with it.
     * The loaded variant is unioned in so such a program is never refused for
     * naming its own variant.
     */
    public void testLoadedVariantMissingFromTheEnumerationIsStillLegal() {
        assertNull(LanguageVariants.check("Custom:BE:32:vendorX", "vendorX",
                Collections.<String>emptyList(), "vendorX"));
        assertNull(LanguageVariants.check("Custom:BE:32:vendorX", "vendorX",
                Collections.<String>emptyList(), ""));
    }

    public void testVariantNamesUnionsTheLoadedVariant() {
        assertEquals(Arrays.asList("a", "b", "c"),
                LanguageVariants.variantNames(Arrays.asList("a", "b"), "c"));
    }

    public void testVariantNamesDoesNotDuplicateTheLoadedVariant() {
        assertEquals(Arrays.asList("a", "b"),
                LanguageVariants.variantNames(Arrays.asList("a", "b"), "B"));
    }

    public void testVariantNamesDropsBlanks() {
        List<String> noisy = new ArrayList<>(Arrays.asList("a", "", null, "   "));
        assertEquals(Arrays.asList("a"), LanguageVariants.variantNames(noisy, "a"));
    }

    // ---------- helpers ----------

    public void testLooksLikeLanguageId() {
        assertFalse(LanguageVariants.looksLikeLanguageId(PPC_VLE));
        assertTrue(LanguageVariants.looksLikeLanguageId(PPC_VLE_ID));
    }

    public void testVariantToken() {
        assertEquals("VLE-32addr", LanguageVariants.variantToken(PPC_VLE_ID));
        assertEquals(PPC_VLE, LanguageVariants.variantToken(" " + PPC_VLE + " "));
        assertEquals("", LanguageVariants.variantToken(null));
    }

    public void testNormalizeHandlesNull() {
        assertEquals("", LanguageVariants.normalize(null));
        assertEquals(PPC_VLE, LanguageVariants.normalize("  " + PPC_VLE + "  "));
    }
}
