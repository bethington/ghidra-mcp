package com.xebyte.core;

import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.File;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.Assert.*;
import static org.junit.Assume.assumeTrue;

/**
 * The decoder rule, checked against Ghidra's real language table rather than
 * against a reading of its {@code .ldefs} files.
 *
 * <p>Everything about the variant advisory rests on one claim: that two
 * variants in the same processor/endian/size bucket can be told apart by the
 * SLEIGH decoder they load, and that doing so puts x86 on the quiet side and
 * PowerPC on the loud side. That claim was established by parsing the
 * {@code .ldefs} with a script and by reading {@code SleighLanguageProvider}'s
 * source. Neither is a test, and neither notices when a Ghidra upgrade moves
 * the ground: a release that gave {@code System Management Mode} its own
 * {@code .sla} would make {@code variant_ambiguous} fire on every 32-bit
 * Windows binary again -- which is precisely the regression that blocked this
 * work the first time -- and nothing would report it.
 *
 * <p>So this asks Ghidra directly, through the same
 * {@link ServiceUtils#languageVariantChoices} the endpoints call:
 *
 * <ul>
 *   <li>{@code getSlaFile()} is actually populated, for every row in a bucket.
 *       If it ever returns null the fallback treats each row as its own decoder
 *       and the advisory fires everywhere, silently.</li>
 *   <li>x86 at 32 and 64 bits enumerates more than one variant and exactly one
 *       decoder, so it is NOT flagged.</li>
 *   <li>PowerPC/BE/32 enumerates many decoders and IS flagged, with VLE among
 *       the candidates.</li>
 * </ul>
 *
 * <p>Deliberately asserts shapes and relations, not exact counts: pinning
 * "eleven PowerPC variants" would turn a routine Ghidra upgrade into a red
 * build for no defect. The one thing worth pinning exactly is the x86 decoder
 * count, because that is the number the design trades on.
 */
public class LanguageVariantDecoderGhidraTest {

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

    private static Set<String> decodersOf(List<ServiceUtils.VariantChoice> choices) {
        Set<String> decoders = new LinkedHashSet<>();
        for (ServiceUtils.VariantChoice c : choices) decoders.add(c.decoder());
        return decoders;
    }

    private interface ProgramCheck {
        void run(ProgramDB program, List<ServiceUtils.VariantChoice> choices);
    }

    /** Build a throwaway program under {@code languageId} and inspect its bucket. */
    private static void withProgram(String name, String languageId, ProgramCheck check)
            throws Exception {
        ProgramBuilder builder = new ProgramBuilder(name, languageId, null);
        try {
            ProgramDB program = builder.getProgram();
            List<ServiceUtils.VariantChoice> choices =
                ServiceUtils.languageVariantChoices(program);
            assertFalse("no variants enumerated for " + languageId, choices.isEmpty());
            assertFalse("enumeration failed for " + languageId,
                ServiceUtils.variantEnumerationFailed(program));
            check.run(program, choices);
        } finally {
            builder.dispose();
        }
    }

    /**
     * The load-bearing fact. {@code SleighLanguageProvider} sets the
     * {@code .sla} on every description it builds and throws without one, so a
     * blank here means the cast in {@code ServiceUtils.decoderOf} stopped
     * matching -- after which every row falls back to its own language id, every
     * bucket looks multi-decoder, and the advisory goes off everywhere.
     */
    @Test
    public void everyCandidateCarriesARealDecoder() throws Exception {
        for (String languageId : new String[] {
                ProgramBuilder._X86, ProgramBuilder._X64, ProgramBuilder._PPC_32,
                ProgramBuilder._ARM }) {
            withProgram("decoder-populated", languageId, (program, choices) -> {
                for (ServiceUtils.VariantChoice c : choices) {
                    assertNotNull(languageId + " / " + c.variant() + " has no decoder",
                        c.decoder());
                    assertFalse(languageId + " / " + c.variant() + " has a blank decoder",
                        c.decoder().isBlank());
                    assertTrue(languageId + " / " + c.variant()
                            + " fell back to its language id instead of a .sla: " + c.decoder(),
                        c.decoder().endsWith(".sla") || c.decoder().endsWith(".slaspec"));
                }
            });
        }
    }

    /**
     * 32-bit x86 offers {@code default} and {@code System Management Mode} and
     * loads one {@code x86.sla} for both. This is the measurement the whole
     * optional-parameter design turns on: counting variant rows made every
     * ordinary PE and ELF ambiguous.
     */
    @Test
    public void x86OffersSeveralVariantsAndExactlyOneDecoder() throws Exception {
        withProgram("x86-bucket", ProgramBuilder._X86, (program, choices) -> {
            assertTrue("x86:LE:32 should enumerate more than one variant row, got " + choices,
                choices.size() > 1);
            assertEquals("x86:LE:32 should load exactly one decoder, got " + decodersOf(choices),
                1, decodersOf(choices).size());
            assertFalse("x86 must not be flagged ambiguous -- that is the regression "
                    + "that blocked the mandatory-variant design",
                ServiceUtils.variantAmbiguous(program));
        });
    }

    /** Same at 64 bits, where the second row is {@code compat32}. */
    @Test
    public void x86_64OffersSeveralVariantsAndExactlyOneDecoder() throws Exception {
        withProgram("x64-bucket", ProgramBuilder._X64, (program, choices) -> {
            assertTrue("x86:LE:64 should enumerate more than one variant row, got " + choices,
                choices.size() > 1);
            assertEquals("x86:LE:64 should load exactly one decoder, got " + decodersOf(choices),
                1, decodersOf(choices).size());
            assertFalse(ServiceUtils.variantAmbiguous(program));
        });
    }

    /**
     * The case the feature exists for. Classic PowerPC and VLE decode the same
     * bytes into different instruction streams and load different decoders, so
     * this bucket must be flagged and VLE must be offered as a candidate.
     */
    @Test
    public void powerPcBe32IsFlaggedAndOffersVle() throws Exception {
        withProgram("ppc-bucket", ProgramBuilder._PPC_32, (program, choices) -> {
            assertTrue("PowerPC:BE:32 should load more than one decoder, got "
                    + decodersOf(choices), decodersOf(choices).size() > 1);
            assertTrue("PowerPC:BE:32 must be flagged ambiguous",
                ServiceUtils.variantAmbiguous(program));

            boolean vle = false;
            for (ServiceUtils.VariantChoice c : choices) {
                if (c.variant() != null && c.variant().toUpperCase().contains("VLE")) {
                    vle = true;
                    break;
                }
            }
            assertTrue("VLE must be among the PowerPC candidates, got " + choices, vle);
        });
    }

    /**
     * The advisory and the metadata endpoint read the same bucket, so they
     * cannot disagree about whether a choice exists -- two views of one question
     * with different answers is the bug class this repository keeps finding.
     */
    @Test
    public void renderedCandidatesAgreeWithTheAmbiguityFlag() throws Exception {
        for (String languageId : new String[] { ProgramBuilder._X86, ProgramBuilder._PPC_32 }) {
            withProgram("rendered", languageId, (program, choices) -> {
                List<Map<String, Object>> rendered =
                    ServiceUtils.languageVariantsAsJson(program);
                assertEquals(choices.size(), rendered.size());

                int loaded = 0;
                Set<String> decoders = new LinkedHashSet<>();
                for (Map<String, Object> row : rendered) {
                    assertNotNull(languageId + ": rendered row has no decoder",
                        row.get("decoder"));
                    assertFalse(languageId + ": decoder rendered as a path, not a name",
                        String.valueOf(row.get("decoder")).contains("/")
                            || String.valueOf(row.get("decoder")).contains("\\"));
                    decoders.add(String.valueOf(row.get("decoder")));
                    if (Boolean.TRUE.equals(row.get("loaded"))) loaded++;
                }
                assertEquals(languageId + ": exactly one candidate is the loaded one",
                    1, loaded);
                assertEquals(languageId + ": the flag must follow the rendered decoders",
                    decoders.size() > 1, ServiceUtils.variantAmbiguous(program));
            });
        }
    }

    /**
     * The stamp is unconditional and the advisory is not. A field that is always
     * present and almost always false is one readers learn to skip, so on an
     * unambiguous processor the advisory keys must be absent rather than false.
     */
    @Test
    public void theStampIsUnconditionalAndTheAdvisoryIsNot() throws Exception {
        withProgram("stamp-x86", ProgramBuilder._X86, (program, choices) -> {
            Map<String, Object> out = new java.util.LinkedHashMap<>();
            ServiceUtils.putLanguageSelection(out, program);
            assertEquals(ProgramBuilder._X86, out.get("language_id"));
            assertEquals("default", out.get("variant"));
            assertFalse("x86 must not carry the advisory",
                out.containsKey("variant_ambiguous"));
            assertFalse(out.containsKey("variant_candidates"));
            assertFalse(out.containsKey("variant_notice"));
        });

        withProgram("stamp-ppc", ProgramBuilder._PPC_32, (program, choices) -> {
            Map<String, Object> out = new java.util.LinkedHashMap<>();
            ServiceUtils.putLanguageSelection(out, program);
            assertEquals(ProgramBuilder._PPC_32, out.get("language_id"));
            assertEquals(Boolean.TRUE, out.get("variant_ambiguous"));

            Object candidates = out.get("variant_candidates");
            assertTrue(candidates instanceof List);
            assertTrue(((List<?>) candidates).size() > 1);
            assertTrue(((List<?>) candidates).contains(out.get("variant")));

            String notice = String.valueOf(out.get("variant_notice"));
            assertTrue("the advisory must name the loaded variant",
                notice.contains(String.valueOf(out.get("variant"))));
            assertTrue("the advisory must name a remedy",
                notice.contains("import_file(language=...)"));
        });
    }

    /**
     * A caller that names the loaded variant is accepted; one that names a real
     * sibling is refused. Checked here rather than only in the offline decision
     * table because here the candidate list is Ghidra's, not a fixture's.
     */
    @Test
    public void namingASiblingVariantIsRefusedAgainstTheRealTable() throws Exception {
        withProgram("mismatch-ppc", ProgramBuilder._PPC_32, (program, choices) -> {
            assertNull("the loaded variant must be accepted",
                ServiceUtils.variantRejectionData(program, "default"));
            assertNull("omitting the variant must be accepted",
                ServiceUtils.variantRejectionData(program, ""));

            String sibling = null;
            for (ServiceUtils.VariantChoice c : choices) {
                if (!"default".equalsIgnoreCase(c.variant())) {
                    sibling = c.variant();
                    break;
                }
            }
            assertNotNull("PowerPC should have a sibling variant to ask for", sibling);

            Map<String, Object> rejection = ServiceUtils.variantRejectionData(program, sibling);
            assertNotNull("naming a sibling variant must be refused", rejection);
            assertEquals(LanguageVariants.VARIANT_MISMATCH, rejection.get("error"));
            assertEquals("rejected", rejection.get("status"));
            assertTrue(String.valueOf(rejection.get("suggestion")).contains("import_file"));
        });
    }
}
