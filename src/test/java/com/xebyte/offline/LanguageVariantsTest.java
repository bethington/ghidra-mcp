package com.xebyte.offline;

import com.xebyte.core.LanguageVariants;
import com.xebyte.core.LanguageVariants.Rejection;
import junit.framework.TestCase;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

/**
 * Pure-logic tests for the decompile variant gate.
 *
 * <p>The rule under test: a processor that offers more than one SLEIGH variant
 * at the program's endian and size must have one named before any decompiler
 * output is handed back. PowerPC is the motivating case — {@code default} and
 * {@code PowerISA-VLE-64-32addr} (VLE) decode the same bytes into different
 * instruction streams, and the wrong choice produces C that is syntactically
 * perfect and wholly fictional, with nothing in the output to say so.
 *
 * <p>The variant lists below were read off Ghidra 12.1.2's {@code .ldefs} files,
 * not invented for the test: a 32-bit big-endian PowerPC program really does sit
 * in a bucket of eleven, and 32-bit x86 really does sit in a bucket of two
 * ({@code default} and {@code System Management Mode}) - which is why this gate
 * fires on ordinary Windows binaries and not only on embedded targets. Across the
 * whole install, 30 of 83 processor/endian/size buckets offer a choice, covering
 * 124 of 177 non-deprecated languages.
 *
 * <p>No Ghidra, no HTTP. The Ghidra-facing half (enumerating a processor's real
 * variants) lives in {@code ServiceUtils.languageVariantChoices} and is covered
 * live by the {@code get_language_metadata} integration tests.
 */
public class LanguageVariantsTest extends TestCase {

    /**
     * The PowerPC / big-endian / 32-bit-address bucket, read off Ghidra 12.1.2's
     * {@code ppc.ldefs} rather than invented. Eleven entries, and five of them
     * carry {@code :64:} in their language id while declaring {@code size="32"}:
     * the id's middle field is the instruction set, the bucket key is the ADDRESS
     * size. That is why classic PowerPC and VLE land in the same bucket, which is
     * the whole point - it is the choice a caller has to make.
     */
    private static final List<String> PPC_BE_32 = Arrays.asList(
            "default", "4xx", "64-32addr", "MPC8270", "PowerISA-64-32addr",
            "PowerISA-Altivec-64-32addr", "PowerISA-VLE-64-32addr",
            "PowerISA-VLE-Altivec-64-32addr", "PowerQUICC-III",
            "PowerQUICC-III-e500", "PowerQUICC-III-e500mc");

    /** Ghidra 12.1.2's VLE variant for a 32-bit-address PowerPC image. */
    private static final String PPC_VLE = "PowerISA-VLE-64-32addr";
    private static final String PPC_VLE_ID = "PowerPC:BE:64:VLE-32addr";

    /**
     * RISCV / little / 64: genuinely one variant in 12.1.2, so the gate must stay
     * silent. x86 would NOT do as the example here - even {@code x86:LE:64} has
     * two ({@code default} and {@code compat32}).
     */
    private static final List<String> RISCV_LE_64 = Arrays.asList("default");

    /** x86 LE 32: two variants, so the gate applies to ordinary PE/ELF work. */
    private static final List<String> X86_LE_32 =
            Arrays.asList("default", "System Management Mode");

    // ---------- unambiguous processors stay frictionless ----------

    public void testSingleVariantProceedsWithoutSelection() {
        assertNull(LanguageVariants.check("RISCV:LE:64:default", "default", RISCV_LE_64, ""));
        assertNull(LanguageVariants.check("RISCV:LE:64:default", "default", RISCV_LE_64, null));
    }

    public void testSingleVariantAcceptsTheCorrectSelection() {
        assertNull(LanguageVariants.check("RISCV:LE:64:default", "default", RISCV_LE_64, "default"));
    }

    /**
     * A caller asking for VLE on a RISC-V program has mistaken which program it
     * is talking to. Catching that here is far cheaper than downstream.
     */
    public void testSingleVariantStillRejectsAForeignVariant() {
        Rejection r = LanguageVariants.check("RISCV:LE:64:default", "default", RISCV_LE_64, "VLE");
        assertNotNull(r);
        assertEquals(LanguageVariants.UNKNOWN_VARIANT, r.error());
        assertTrue(r.message().contains("default"));
    }

    // ---------- ambiguous processors must be told which dialect ----------

    public void testMultiVariantRefusesAnUnspecifiedSelection() {
        Rejection r = LanguageVariants.check("PowerPC:BE:32:default", "default", PPC_BE_32, "");
        assertNotNull(r);
        assertEquals(LanguageVariants.VARIANT_REQUIRED, r.error());
    }

    /** The refusal has to be answerable from itself, or it is just an outage. */
    public void testRequiredRefusalNamesEveryCandidate() {
        Rejection r = LanguageVariants.check("PowerPC:BE:32:default", "default", PPC_BE_32, "");
        assertTrue(r.message().contains("11 language variants"));
        for (String variant : PPC_BE_32) {
            assertTrue("candidate missing from refusal: " + variant,
                    r.message().contains(variant));
        }
    }

    public void testRequiredRefusalNamesTheLoadedVariantAndTheRemedy() {
        Rejection r = LanguageVariants.check("PowerPC:BE:32:default", "default", PPC_BE_32, "");
        assertTrue(r.suggestion().contains("loaded as 'default'"));
        assertTrue(r.suggestion().contains("PowerPC:BE:32:default"));
        // A refusal that names only the symptom leaves the caller stuck; both
        // routes out of a genuinely wrong variant have to be stated.
        assertTrue(r.suggestion().contains("import_file(language="));
        assertTrue(r.suggestion().contains("Set Language"));
    }

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

    public void testOrdinaryX86ThirtyTwoBitIsAmbiguous() {
        assertTrue(LanguageVariants.isAmbiguous(X86_LE_32, "default"));
        assertFalse(LanguageVariants.isAmbiguous(RISCV_LE_64, "default"));
    }

    // ---------- the mistake this gate exists to catch ----------

    /**
     * Asking for VLE on a program loaded as classic PowerPC is refused rather
     * than answered. The decompiler decodes with the language the program was
     * imported under and cannot be asked for another, so answering would return
     * classic-PowerPC C under a VLE label — worse than no answer, because the
     * label makes it look checked.
     */
    public void testRequestingADifferentVariantIsRefusedNotIgnored() {
        Rejection r = LanguageVariants.check("PowerPC:BE:32:default", "default", PPC_BE_32, PPC_VLE);
        assertNotNull(r);
        assertEquals(LanguageVariants.VARIANT_MISMATCH, r.error());
        assertTrue(r.message().contains("different question"));
        assertTrue(r.suggestion().contains("variant=default"));
        assertTrue(r.suggestion().contains("import_file(language=...)"));
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

    // ---------- languages the enumeration cannot see ----------

    /**
     * Deprecated languages are excluded from Ghidra's enumeration, and a
     * processor module can be uninstalled after a program was imported with it.
     * The loaded variant is unioned in so such a program is never refused with no
     * legal answer available.
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
        assertEquals(Arrays.asList("a"),
                LanguageVariants.variantNames(Arrays.asList("a", "", null, "   "), "a"));
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
