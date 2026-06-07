package com.xebyte.offline;

import com.xebyte.core.BinaryComparisonService;
import com.xebyte.core.BinaryComparisonService.FunctionSignature;
import junit.framework.TestCase;

/**
 * Functional coverage for BinaryComparisonService.computeSimilarity — the pure scoring core
 * behind find_similar_functions / bulk_fuzzy_match / diff_functions (previously no behavioral
 * tests). Uses constructed FunctionSignatures so it runs offline with no Ghidra.
 */
public class BinaryComparisonServiceTest extends TestCase {

    private static FunctionSignature sig(int insn, int bb, int edges, int calls,
                                         String... callees) {
        FunctionSignature s = new FunctionSignature();
        s.instructionCount = insn;
        s.basicBlockCount = bb;
        s.edgeCount = edges;
        s.callCount = calls;
        s.cyclomaticComplexity = edges - bb + 2;
        for (String c : callees) s.calleeNames.add(c);
        return s;
    }

    public void testIdenticalSignaturesScoreAtLeastAsHighAsDifferent() {
        FunctionSignature a = sig(100, 12, 16, 5, "malloc", "free", "memcpy");
        FunctionSignature aCopy = sig(100, 12, 16, 5, "malloc", "free", "memcpy");
        FunctionSignature different = sig(3, 1, 0, 0, "exit");

        double same = BinaryComparisonService.computeSimilarity(a, aCopy);
        double diff = BinaryComparisonService.computeSimilarity(a, different);

        // Sanity: scores are well-defined probabilities (also catches NaN).
        assertTrue("same score out of range: " + same, same >= 0.0 && same <= 1.0);
        assertTrue("diff score out of range: " + diff, diff >= 0.0 && diff <= 1.0);
        // Identical signatures must be at least as similar as clearly different ones.
        assertTrue("identical (" + same + ") should be >= different (" + diff + ")", same >= diff);
        // And identical signatures should be strongly similar.
        assertTrue("identical signatures should score high, got " + same, same >= 0.9);
    }

    public void testSymmetry() {
        FunctionSignature a = sig(50, 8, 10, 3, "foo", "bar");
        FunctionSignature b = sig(40, 6, 8, 2, "foo", "baz");
        double ab = BinaryComparisonService.computeSimilarity(a, b);
        double ba = BinaryComparisonService.computeSimilarity(b, a);
        assertEquals("similarity should be symmetric", ab, ba, 1e-9);
    }
}
