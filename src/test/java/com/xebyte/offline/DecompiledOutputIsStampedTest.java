package com.xebyte.offline;

import junit.framework.TestCase;

import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

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
 * and by nobody. That is not hypothetical: {@code decompileFunctionByName}
 * returned {@code {name, address, decompiled}} with no stamp for the whole of
 * the work that introduced the stamp, and was found only by reading every
 * {@code getDecompiledFunction().getC()} in the tree by hand. Nothing routes to
 * it today -- the GUI plugin's wrapper is private and unused, and the headless
 * server registers through {@code AnnotationScanner} rather than through its
 * handler's by-name branch -- so no test failed and no endpoint misbehaved. It
 * was simply an unlabelled C-returning method sitting ready for the next person
 * to wire up.
 *
 * <p>The site list is a ratchet in BOTH directions. A new emitter fails here
 * until it is added, which forces someone to look at whether it is stamped; a
 * removed one fails too, so the list cannot outlive the code. Source text is
 * read rather than behaviour exercised because the point is to catch the
 * emitter that nothing calls yet -- a runtime test can only check the paths
 * something already reaches, which is exactly the blind spot that let this one
 * through.
 */
public class DecompiledOutputIsStampedTest extends TestCase {

    /** The stamp. Anything handing back C has to call it. */
    private static final String STAMP = "putLanguageSelection";

    /**
     * Every site where a response map receives decompiler C, as
     * {@code File#method}. Keep sorted; the assertion is on the whole set.
     */
    private static final Set<String> EXPECTED_SITES = new TreeSet<>(List.of(
        "AnalysisService#analyzeForDocumentation",
        "AnalysisService#analyzeFunctionComplete",
        "FunctionService#decompileAt",
        "FunctionService#decompileFunctionByName",
        "FunctionService#forceDecompileAt"));

    /** The response keys that carry pseudocode out of the server. */
    private static final Pattern EMITS_C = Pattern.compile(
        "\\.put\\(\"(decompiled|decompiled_code)\"\\s*,");

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

    /** Newlines normalised first: a Windows checkout is CRLF and `\n` needles miss it. */
    private static String source(String fileName) throws IOException {
        return stripLineComments(ProjectSource.normalizeNewlines(
            ProjectSource.readMainSource("core", fileName)));
    }

    /** The name of the method enclosing {@code offset}, searching backwards. */
    private static String enclosingMethod(String source, int offset) {
        String[] lines = source.substring(0, offset).split("\n", -1);
        for (int i = lines.length - 1; i >= 0; i--) {
            Matcher m = METHOD_DECL.matcher(lines[i]);
            if (m.find()) return m.group(1);
        }
        return null;
    }

    /** Where the enclosing method starts, so the stamp is looked for inside it. */
    private static int enclosingMethodStart(String source, int offset) {
        String head = source.substring(0, offset);
        String[] lines = head.split("\n", -1);
        int consumed = head.length();
        for (int i = lines.length - 1; i >= 0; i--) {
            consumed -= lines[i].length() + (i == lines.length - 1 ? 0 : 1);
            if (METHOD_DECL.matcher(lines[i]).find()) return Math.max(consumed, 0);
        }
        return 0;
    }

    private record Site(String file, String method, int offset) {
        String id() {
            return file.replace(".java", "") + "#" + method;
        }
    }

    private static List<Site> emitters() throws IOException {
        List<Site> sites = new ArrayList<>();
        for (String file : new String[] { "FunctionService.java", "AnalysisService.java" }) {
            String src = source(file);
            Matcher m = EMITS_C.matcher(src);
            while (m.find()) {
                String method = enclosingMethod(src, m.start());
                assertNotNull(file + ": could not find the method enclosing offset " + m.start()
                    + " -- the declaration style this scan relies on changed, and an "
                    + "unrecognised method is an unchecked one", method);
                sites.add(new Site(file, method, m.start()));
            }
        }
        return sites;
    }

    /**
     * The ratchet. A new C-returning site has to be declared here, which is the
     * moment someone has to decide whether it is stamped.
     */
    public void testTheSetOfPseudocodeEmittersIsTheExpectedOne() throws IOException {
        Set<String> found = new TreeSet<>();
        for (Site s : emitters()) found.add(s.id());
        assertEquals("the set of places that hand decompiler C back to a caller changed. "
            + "If you added one, stamp it with ServiceUtils." + STAMP + " and add it here; "
            + "if you removed one, delete its line. Do not widen this to a prefix match.",
            EXPECTED_SITES, found);
    }

    /** Each emitter calls the stamp inside its own method, ahead of the C. */
    public void testEveryEmitterStampsTheLanguageBeforeHandingBackC() throws IOException {
        List<String> unstamped = new ArrayList<>();
        for (Site s : emitters()) {
            String src = source(s.file());
            int methodStart = enclosingMethodStart(src, s.offset());
            String body = src.substring(methodStart, s.offset());
            if (!body.contains(STAMP)) unstamped.add(s.id());
        }
        assertEquals("these hand back decompiler C without stamping the language that "
            + "produced it: " + unstamped, List.of(), unstamped);
    }

    /**
     * Bulk mode is checked separately because its per-function values go in
     * under a caller-supplied key, so the scan above cannot see them. The stamp
     * sits on the envelope, and the results are nested under {@code functions}
     * so the stamp's reserved names never share a namespace with function
     * references the caller chose.
     */
    public void testBulkModeStampsTheEnvelopeAndNestsItsResults() throws IOException {
        String src = source("FunctionService.java");
        int start = src.indexOf("private Response batchDecompileAt(");
        assertTrue("batchDecompileAt not found -- bulk decompile moved and this check "
            + "stopped covering it", start > 0);
        int end = src.indexOf("\n    public Response batchDecompileFunctions(String functionsParam)",
            start);
        assertTrue("could not bound batchDecompileAt", end > start);
        String body = src.substring(start, end);

        assertTrue("bulk decompile must stamp its envelope: functions= was the one decompile "
            + "path handing back C with nothing on it", body.contains(STAMP));
        assertTrue("bulk results must be nested under \"functions\" -- a flat map puts the "
            + "stamp's reserved names in the same namespace as caller-chosen function "
            + "references", body.contains("put(\"functions\""));
    }

    /**
     * Endpoints that decompile only to derive a score or a field-usage map hand
     * back no pseudocode, so they are deliberately NOT stamped. Pinned so the
     * exclusion stays a decision rather than an oversight: if one of them starts
     * returning C, the ratchet above fires.
     */
    public void testScoringOnlyDecompilersStillReturnNoPseudocode() throws IOException {
        Set<String> scoringOnly = new LinkedHashSet<>(List.of(
            "analyzeFunctionCompleteness", "analyzeStructFieldUsage"));
        for (Site s : emitters()) {
            assertFalse(s.id() + " now returns pseudocode, but it is listed as a "
                + "decompile-internally-only endpoint. Either stamp it and move it, or "
                + "stop returning C.", scoringOnly.contains(s.method()));
        }
    }
}
