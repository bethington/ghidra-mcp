package com.xebyte.offline;

import junit.framework.TestCase;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * Every response that carries decompiler-produced C must stamp the language
 * that produced it.
 *
 * <p>Pseudocode with no record of the dialect that decoded it cannot be audited
 * after the fact, which is how a VLE-image-opened-as-classic-PowerPC mistake
 * survives review: the decompiler reports success, the C reads plausibly, and
 * nothing in the payload says which of eleven dialects produced it.
 *
 * <p>Until this test existed the rule was enforced by a sentence in CLAUDE.md
 * and by nobody. That is not hypothetical, twice over. {@code decompileFunctionByName}
 * returned {@code {name, address, decompiled}} with no stamp for the whole of
 * the work that introduced the stamp, found only by reading every
 * {@code getDecompiledFunction().getC()} in the tree by hand. And when
 * {@code /get_functions} replaced {@code /decompile_function}, the C moved into
 * {@code FunctionFacts} -- a file the first version of this test did not scan,
 * because it listed the two files it knew about. A ratchet that names its files
 * is a ratchet the next file walks past, so this one reads all of them.
 *
 * <p>Two sets are ratcheted, both in BOTH directions:
 * <ul>
 *   <li>{@link #PRODUCERS}: every method that obtains decompiler C at all, with
 *       what it does with it. A new one fails until someone decides whether it
 *       hands the C to a caller; a removed one fails so the list cannot outlive
 *       the code.</li>
 *   <li>The emitters: every method that puts C into a response under a
 *       pseudocode key. Each must call the stamp ahead of the C.</li>
 * </ul>
 *
 * <p>Source text is read rather than behaviour exercised because the point is
 * to catch the emitter that nothing calls yet -- a runtime test can only check
 * the paths something already reaches. What a caller actually receives is
 * pinned by {@code com.xebyte.core.DecompileVariantLabellingGhidraTest}.
 */
public class DecompiledOutputIsStampedTest extends TestCase {

    /** The stamp. Anything handing back C has to call it. */
    private static final String STAMP = "putLanguageSelection";

    /** What a method that obtains decompiler C does with it. */
    private enum Role {
        /** Puts it in a response under a pseudocode key; must stamp first. */
        EMITS,
        /** Builds C for the named emitter, whose stamp covers it. */
        FEEDS_FACTS_BUILD,
        /**
         * Returns it under keys the CALLER chose (function references), so no
         * pseudocode key exists to scan for. Must stamp an envelope and nest the
         * results under {@code functions}.
         */
        CALLER_KEYED_BULK,
        /** Decompiles only to derive a score or a usage map; hands back no C. */
        INTERNAL
    }

    /**
     * Every method that obtains decompiler C, as {@code File#method}. Keep
     * sorted; the assertion is on the whole map.
     */
    private static final Map<String, Role> PRODUCERS = new TreeMap<>(Map.of(
        "AnalysisService#analyzeForDocumentation", Role.EMITS,
        "AnalysisService#analyzeFunctionComplete", Role.EMITS,
        "AnalysisService#analyzeFunctionCompleteness", Role.INTERNAL,
        "DataTypeService#analyzeStructFieldUsage", Role.INTERNAL,
        "FunctionFacts#build", Role.EMITS,
        "FunctionFacts#collectCallContext", Role.FEEDS_FACTS_BUILD,
        "FunctionService#batchDecompileFunctions", Role.CALLER_KEYED_BULK,
        "FunctionService#decompileFunctionByAddress", Role.EMITS,
        "FunctionService#forceDecompileAt", Role.EMITS));

    /** Where decompiler C comes from: the whole function, or its token markup. */
    private static final Pattern PRODUCES_C = Pattern.compile(
        "getDecompiledFunction\\(\\)\\s*\\.getC\\(\\)|getCCodeMarkup\\(\\)");

    /** The response keys that carry pseudocode out of the server. */
    private static final Pattern EMITS_C = Pattern.compile(
        "\\.put\\(\"(decompiled|decompiled_code|call_context)\"\\s*,");

    /** A method declaration at class-body indent, which is where this codebase puts them. */
    private static final Pattern METHOD_DECL = Pattern.compile(
        "^ {4}(?:public|private|protected|static)[^;=]*\\b(\\w+)\\s*\\(");

    /**
     * Strip {@code //} comments so prose about the stamp cannot satisfy the
     * check. Not a Java parser: it only has to stop a comment counting as a
     * call, and a {@code //} inside a string literal would at worst hide real
     * code from the scan, which fails loudly rather than passing quietly.
     */
    private static String stripLineComments(String source) {
        StringBuilder out = new StringBuilder(source.length());
        for (String line : source.split("\n", -1)) {
            int idx = line.indexOf("//");
            out.append(idx >= 0 ? line.substring(0, idx) : line).append('\n');
        }
        return out.toString();
    }

    private record SourceFile(String name, String text) {}

    /** Every main source file, newlines normalised and line comments stripped. */
    private static List<SourceFile> mainSources() throws IOException {
        List<SourceFile> files = new ArrayList<>();
        try (Stream<Path> walk = Files.walk(ProjectSource.mainSourceRoot())) {
            for (Path p : walk.filter(f -> f.toString().endsWith(".java")).sorted().toList()) {
                String name = p.getFileName().toString().replace(".java", "");
                files.add(new SourceFile(name, stripLineComments(ProjectSource.read(p))));
            }
        }
        assertTrue("found no main sources under " + ProjectSource.mainSourceRoot(),
            files.size() > 20);
        return files;
    }

    /** Where the method enclosing {@code offset} starts, or -1. */
    private static int enclosingMethodStart(String source, int offset) {
        int lineStart = source.lastIndexOf('\n', offset - 1) + 1;
        while (lineStart > 0) {
            int lineEnd = source.indexOf('\n', lineStart);
            if (METHOD_DECL.matcher(source.substring(lineStart, lineEnd)).find()) return lineStart;
            lineStart = source.lastIndexOf('\n', lineStart - 2) + 1;
        }
        return -1;
    }

    private record Site(String file, String method, String source, int methodStart, int offset) {
        String id() {
            return file + "#" + method;
        }

        /** The method's text from its declaration up to this site. */
        String bodyBefore() {
            return source.substring(methodStart, offset);
        }
    }

    private static List<Site> sites(Pattern pattern) throws IOException {
        List<Site> sites = new ArrayList<>();
        for (SourceFile f : mainSources()) {
            Matcher m = pattern.matcher(f.text());
            while (m.find()) {
                int start = enclosingMethodStart(f.text(), m.start());
                assertTrue(f.name() + ": could not find the method enclosing offset " + m.start()
                    + " -- the declaration style this scan relies on changed, and an "
                    + "unrecognised method is an unchecked one", start >= 0);
                String declLine = f.text().substring(start, f.text().indexOf('\n', start));
                Matcher decl = METHOD_DECL.matcher(declLine);
                assertTrue(declLine, decl.find());
                sites.add(new Site(f.name(), decl.group(1), f.text(), start, m.start()));
            }
        }
        return sites;
    }

    private static Set<String> ids(List<Site> sites) {
        Set<String> out = new TreeSet<>();
        for (Site s : sites) out.add(s.id());
        return out;
    }

    private static Set<String> withRole(Role role) {
        Set<String> out = new TreeSet<>();
        PRODUCERS.forEach((id, r) -> {
            if (r == role) out.add(id);
        });
        return out;
    }

    /**
     * The producer ratchet. Anything that obtains decompiler C has to be declared
     * here, which is the moment someone has to decide whether it reaches a caller.
     */
    public void testTheSetOfMethodsObtainingDecompilerCIsTheExpectedOne() throws IOException {
        assertEquals("the set of methods that obtain decompiler C changed. Declare a new one "
            + "in PRODUCERS with what it does with the C -- if it hands it to a caller, stamp "
            + "it with ServiceUtils." + STAMP + " -- and delete the line of one you removed. "
            + "Do not widen this to a prefix match.",
            PRODUCERS.keySet(), ids(sites(PRODUCES_C)));
    }

    /**
     * The emitter ratchet: exactly the producers declared EMITS put C under a
     * pseudocode key. A declared emitter that stopped emitting, or an INTERNAL
     * producer that started, both fail here.
     */
    public void testTheEmittersAreExactlyTheProducersDeclaredAsEmitting() throws IOException {
        assertEquals("the methods putting decompiler C into a response under decompiled / "
            + "decompiled_code / call_context are not the ones PRODUCERS declares EMITS",
            withRole(Role.EMITS), ids(sites(EMITS_C)));
    }

    /** Each emission is preceded, inside its own method, by the stamp. */
    public void testEveryEmitterStampsTheLanguageBeforeHandingBackC() throws IOException {
        List<String> unstamped = new ArrayList<>();
        for (Site s : sites(EMITS_C)) {
            if (!s.bodyBefore().contains(STAMP)) unstamped.add(s.id() + " @" + s.offset());
        }
        assertEquals("these hand back decompiler C without stamping the language that "
            + "produced it: " + unstamped, List.of(), unstamped);
    }

    /**
     * call_context is the CALLER's decompiled C, built in a helper. The helper
     * must actually feed the stamped emitter, or its C escapes some other way.
     */
    public void testTheCallContextHelperFeedsTheStampedBuilder() throws IOException {
        String facts = stripLineComments(ProjectSource.readMainSource("core", "FunctionFacts.java"));
        int build = facts.indexOf("public static Map<String, Object> build(");
        assertTrue("FunctionFacts.build not found", build > 0);
        int callSite = facts.indexOf("collectCallContext(", build);
        int stamp = facts.indexOf(STAMP, build);
        assertTrue("FunctionFacts.build no longer calls collectCallContext", callSite > 0);
        assertTrue("FunctionFacts.build must stamp before it gathers call_context",
            stamp > 0 && stamp < callSite);
        for (String id : withRole(Role.FEEDS_FACTS_BUILD)) {
            assertTrue(id + " is declared to feed FunctionFacts#build",
                id.startsWith("FunctionFacts#"));
        }
    }

    /**
     * Bulk results keyed by caller-chosen references cannot carry the stamp's
     * reserved names beside them, so the stamp goes on an envelope and the
     * results under {@code functions}. Checked for the internal bulk helper and
     * for get_functions' own bulk mode, whose entries come from the stamped
     * FunctionFacts.build.
     */
    public void testBulkResultsAreNestedUnderAStampedEnvelopeOrStampedEntries() throws IOException {
        for (Site s : sites(PRODUCES_C)) {
            if (PRODUCERS.get(s.id()) != Role.CALLER_KEYED_BULK) continue;
            assertTrue(s.id() + " must stamp its envelope before decompiling",
                s.bodyBefore().contains(STAMP));
            int end = s.source().indexOf("\n    }\n", s.offset());
            String rest = s.source().substring(s.offset(), end);
            assertTrue(s.id() + " must nest its results under \"functions\" -- a flat map puts "
                + "the stamp's reserved names in the same namespace as caller-chosen function "
                + "references", rest.contains("put(\"functions\""));
        }

        String bundles = stripLineComments(
            ProjectSource.readMainSource("core", "FunctionBundleService.java"));
        int bulk = bundles.indexOf("private Response getFunctionsBulk(");
        assertTrue("get_functions' bulk path moved; this check stopped covering it", bulk > 0);
        String bulkBody = bundles.substring(bulk, bundles.indexOf("\n    }\n", bulk));
        assertTrue("get_functions bulk must nest results under \"functions\"",
            bulkBody.contains("out.put(\"functions\""));
        assertTrue("get_functions bulk entries must come from buildBundle, i.e. FunctionFacts.build",
            bulkBody.contains("buildBundle("));
        int builder = bundles.indexOf("private Map<String, Object> buildBundle(");
        assertTrue(bundles.substring(builder, bundles.indexOf("\n    }\n", builder))
            .contains("FunctionFacts.build("));
    }

    /**
     * The scoring-only decompilers are pinned as handing back no pseudocode, so
     * that exclusion stays a decision rather than an oversight. If one starts
     * returning C, the emitter ratchet above fires; this names the reason.
     */
    public void testScoringOnlyDecompilersStillReturnNoPseudocode() throws IOException {
        Set<String> emitters = ids(sites(EMITS_C));
        for (String id : withRole(Role.INTERNAL)) {
            assertFalse(id + " now returns pseudocode, but it is declared a "
                + "decompile-internally-only endpoint. Either stamp it and declare it EMITS, "
                + "or stop returning C.", emitters.contains(id));
        }
    }
}
