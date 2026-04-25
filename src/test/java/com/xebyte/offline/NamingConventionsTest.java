package com.xebyte.offline;

import com.xebyte.core.NamingConventions;
import com.xebyte.core.NamingConventions.NameQualityResult;
import junit.framework.TestCase;

import java.util.Arrays;
import java.util.List;

/**
 * Pure-logic tests for the verb-tier specificity rules and token-subset
 * near-duplicate detection added 2026-04-25 via the Q1-Q6 quality conversation.
 *
 * <p>These tests pin the contract that backs the {@code rename_function_by_address}
 * validator gate (Q1 D, Q4 A) and the new scorer deductions (Q6 B). No Ghidra,
 * no HTTP — just the static methods on {@link NamingConventions}.
 */
public class NamingConventionsTest extends TestCase {

    // ---------- tokenizeFunctionName ----------

    public void testTokenizeBasicPascalCase() {
        assertEquals(Arrays.asList("Get", "Player", "Health"),
                NamingConventions.tokenizeFunctionName("GetPlayerHealth"));
    }

    public void testTokenizeStripsModulePrefix() {
        assertEquals(Arrays.asList("Compile", "Txt", "Data", "Table"),
                NamingConventions.tokenizeFunctionName("DATATBLS_CompileTxtDataTable"));
    }

    public void testTokenizeSingleToken() {
        assertEquals(Arrays.asList("Process"),
                NamingConventions.tokenizeFunctionName("Process"));
    }

    public void testTokenizeNullAndEmpty() {
        assertTrue(NamingConventions.tokenizeFunctionName(null).isEmpty());
        assertTrue(NamingConventions.tokenizeFunctionName("").isEmpty());
    }

    public void testTokenizeNonPascalCaseReturnsEmpty() {
        assertTrue(NamingConventions.tokenizeFunctionName("processData").isEmpty());
    }

    public void testTokenizeRejectsNamesWithInternalUnderscores() {
        // Validates the PASCAL_CASE pattern check (Copilot review feedback):
        // names that have a module prefix stripped but still contain underscores
        // in the main part are not valid PascalCase and must not tokenize.
        assertTrue(NamingConventions.tokenizeFunctionName("DATATBLS_Compile_Table").isEmpty());
        assertTrue(NamingConventions.tokenizeFunctionName("Compile_Table").isEmpty());
    }

    public void testTokenizeRejectsLowercaseAfterPrefix() {
        // "DATATBLS_compileTable" is invalid: the part after the prefix
        // doesn't start with uppercase.
        assertTrue(NamingConventions.tokenizeFunctionName("DATATBLS_compileTable").isEmpty());
    }

    public void testTokenizeKeepsDigitRunsAttachedToWord() {
        // Copilot review feedback: confirm the documented behavior — digits
        // stay glued to the preceding word rather than starting a new token.
        // 'Utf8DecodeBlock' -> [Utf8, Decode, Block] (Utf8 is one token).
        assertEquals(java.util.Arrays.asList("Utf8", "Decode", "Block"),
                NamingConventions.tokenizeFunctionName("Utf8DecodeBlock"));
    }

    // ---------- getVerbTier ----------

    public void testTier1VerbsClassified() {
        assertEquals(1, NamingConventions.getVerbTier("Calculate"));
        assertEquals(1, NamingConventions.getVerbTier("Validate"));
        assertEquals(1, NamingConventions.getVerbTier("Decode"));
    }

    public void testTier2VerbsClassified() {
        assertEquals(2, NamingConventions.getVerbTier("Get"));
        assertEquals(2, NamingConventions.getVerbTier("Set"));
        assertEquals(2, NamingConventions.getVerbTier("Send"));
    }

    public void testTier3VerbsClassified() {
        assertEquals(3, NamingConventions.getVerbTier("Process"));
        assertEquals(3, NamingConventions.getVerbTier("Handle"));
        assertEquals(3, NamingConventions.getVerbTier("Manage"));
        assertEquals(3, NamingConventions.getVerbTier("Do"));
    }

    public void testUnknownVerbReturnsZero() {
        assertEquals(0, NamingConventions.getVerbTier("Frobnicate"));
        assertEquals(0, NamingConventions.getVerbTier(null));
    }

    // ---------- weak nouns + specifier counting ----------

    public void testWeakNounsRecognized() {
        assertTrue(NamingConventions.isWeakNoun("Data"));
        assertTrue(NamingConventions.isWeakNoun("Info"));
        assertTrue(NamingConventions.isWeakNoun("Stuff"));
        assertTrue(NamingConventions.isWeakNoun("Helper"));
        assertFalse(NamingConventions.isWeakNoun("Player"));
        assertFalse(NamingConventions.isWeakNoun("Packet"));
        assertFalse(NamingConventions.isWeakNoun(null));
    }

    public void testCountSpecifiersExcludesWeakNouns() {
        // GetPlayerHealth: tokens [Get, Player, Health]; verb=Get; specifiers={Player,Health}=2
        assertEquals(2, NamingConventions.countSpecifierTokens("GetPlayerHealth"));
        // ProcessData: tokens [Process, Data]; verb=Process; specifiers={} (Data is weak)
        assertEquals(0, NamingConventions.countSpecifierTokens("ProcessData"));
        // ProcessNetworkPacket: 2 strong specifiers
        assertEquals(2, NamingConventions.countSpecifierTokens("ProcessNetworkPacket"));
        // GetData: 0 specifiers (Data weak)
        assertEquals(0, NamingConventions.countSpecifierTokens("GetData"));
        // Single-token name has 0 specifiers
        assertEquals(0, NamingConventions.countSpecifierTokens("Process"));
    }

    // ---------- checkFunctionNameQuality (Q2 + Q4 hard-reject path) ----------

    public void testTier3WithFewerThanTwoSpecifiersRejected() {
        NameQualityResult r = NamingConventions.checkFunctionNameQuality("ProcessData");
        assertFalse(r.ok);
        assertEquals("vague_verb", r.issue);
        assertNotNull(r.suggestion);
    }

    public void testTier3WithTwoSpecifiersAccepted() {
        assertTrue(NamingConventions.checkFunctionNameQuality("ProcessNetworkPacket").ok);
    }

    public void testTier3OneSpecifierRejected() {
        NameQualityResult r = NamingConventions.checkFunctionNameQuality("HandleInput");
        assertFalse(r.ok);
        assertEquals("vague_verb", r.issue);
    }

    public void testTier1WithOneSpecifierAccepted() {
        assertTrue(NamingConventions.checkFunctionNameQuality("CalculateDamage").ok);
        assertTrue(NamingConventions.checkFunctionNameQuality("AllocateBuffer").ok);
    }

    public void testTier2WithWeakNounOnlyRejected() {
        // GetData: Tier 2 verb + only weak-noun specifier — flagged as weak_noun_only.
        NameQualityResult r = NamingConventions.checkFunctionNameQuality("GetData");
        assertFalse(r.ok);
        assertEquals("weak_noun_only", r.issue);
    }

    public void testTier0VerbWithWeakNounOnlyRejected() {
        // Copilot review feedback: a Tier-0 (unknown) verb with only weak nouns
        // (e.g., 'FrobnicateData') was previously slipping through. The class
        // doc says Tier 0 follows Tier 2 semantics; the weak_noun_only check
        // now covers it.
        NameQualityResult r = NamingConventions.checkFunctionNameQuality("FrobnicateData");
        assertFalse(r.ok);
        assertEquals("weak_noun_only", r.issue);
    }

    public void testTier0VerbWithStrongSpecifierAccepted() {
        // Sanity check: an unknown verb with a non-weak specifier still passes.
        assertTrue(NamingConventions.checkFunctionNameQuality("FrobnicatePacket").ok);
    }

    public void testSingleTokenNameRejected() {
        NameQualityResult r = NamingConventions.checkFunctionNameQuality("Get");
        assertFalse(r.ok);
        assertEquals("missing_specifier", r.issue);
    }

    public void testNamesWithModulePrefixHonorTierRules() {
        // Module prefix is stripped before tier check.
        assertTrue(NamingConventions.checkFunctionNameQuality("DATATBLS_CompileTxtDataTable").ok);
        // But the underlying main part still must pass the rules.
        NameQualityResult r = NamingConventions.checkFunctionNameQuality("NET_ProcessData");
        assertFalse(r.ok);
        assertEquals("vague_verb", r.issue);
    }

    public void testAutoGeneratedNamesExempt() {
        // FUN_xxx names get a separate (heavier) deduction; quality check is
        // a no-op for them so it doesn't double-fire.
        assertTrue(NamingConventions.checkFunctionNameQuality("FUN_6fcab220").ok);
    }

    public void testNullAndEmptyHandled() {
        assertTrue(NamingConventions.checkFunctionNameQuality(null).ok);
        assertTrue(NamingConventions.checkFunctionNameQuality("").ok);
    }

    public void testRejectionMessageIncludesActionableSuggestion() {
        NameQualityResult r = NamingConventions.checkFunctionNameQuality("ProcessData");
        assertNotNull(r.suggestion);
        // The suggestion must give the model concrete guidance, not just say "no".
        assertTrue(r.suggestion.length() > 30);
    }

    // ---------- findTokenSubsetCollision (Q3 + Q4) ----------

    public void testCandidateSubsetOfExistingFlagged() {
        List<String> existing = Arrays.asList("SendStateUpdateCommand", "GetPlayerHealth");
        String collision = NamingConventions.findTokenSubsetCollision(
                "SendStateUpdate", existing);
        assertEquals("SendStateUpdateCommand", collision);
    }

    public void testExistingSubsetOfCandidateFlagged() {
        // Reverse direction: candidate is a strict superset of existing.
        List<String> existing = Arrays.asList("SendStateUpdate", "GetSize");
        String collision = NamingConventions.findTokenSubsetCollision(
                "SendStateUpdateCommand", existing);
        assertEquals("SendStateUpdate", collision);
    }

    public void testDifferentLastTokensNotFlagged() {
        // GetItemPrice vs GetItemValue — neither is a subset of the other.
        List<String> existing = Arrays.asList("GetItemPrice", "GetItemTier");
        assertNull(NamingConventions.findTokenSubsetCollision("GetItemValue", existing));
    }

    public void testSameTokensDifferentOrderNotFlagged() {
        // Order matters — same set of tokens but different order = same set,
        // and same-set with same size doesn't match strict subset semantics.
        // GetSize vs SizeGet would have same set {Get,Size}; we return null
        // because it's an exact set match, not a strict subset.
        List<String> existing = Arrays.asList("GetSize");
        assertNull(NamingConventions.findTokenSubsetCollision("SizeGet", existing));
    }

    public void testExactDuplicateNotFlaggedByThisHelper() {
        // findTokenSubsetCollision is only for NEAR-duplicates; exact equals
        // is filtered out (Ghidra has its own collision handling at API).
        List<String> existing = Arrays.asList("GetSize");
        assertNull(NamingConventions.findTokenSubsetCollision("GetSize", existing));
    }

    public void testDifferentModulePrefixesNotFlagged() {
        // NET_SendUpdate and STAT_SendUpdate live in different prefix
        // namespaces — token-subset detection is scoped to same prefix only.
        List<String> existing = Arrays.asList("NET_SendStateUpdateCommand");
        assertNull(NamingConventions.findTokenSubsetCollision(
                "STAT_SendStateUpdate", existing));
    }

    public void testEmptyExistingListNoCollision() {
        assertNull(NamingConventions.findTokenSubsetCollision("ProcessNetworkPacket",
                Arrays.asList()));
    }

    public void testNullCandidateHandled() {
        assertNull(NamingConventions.findTokenSubsetCollision(null,
                Arrays.asList("GetSize")));
    }

    // ---------- extractModulePrefix ----------

    public void testExtractPrefixForUppercaseUnderscoreName() {
        assertEquals("DATATBLS", NamingConventions.extractModulePrefix("DATATBLS_CompileTable"));
        assertEquals("NET", NamingConventions.extractModulePrefix("NET_SendPacket"));
    }

    public void testExtractPrefixReturnsNullForPlainName() {
        assertNull(NamingConventions.extractModulePrefix("GetPlayerHealth"));
        assertNull(NamingConventions.extractModulePrefix("FUN_6fcab220"));
        assertNull(NamingConventions.extractModulePrefix(null));
    }
}
