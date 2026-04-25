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

    // ---------- checkGlobalNameQuality (v5.7.0 — Q4 design) ----------
    //
    // Validator backing rename_data / rename_global_variable / set_global.

    public void testGlobalNameMissingGPrefixRejected() {
        NamingConventions.GlobalNameResult r =
                NamingConventions.checkGlobalNameQuality("dwActiveState", "uint");
        assertFalse(r.ok);
        assertEquals("missing_g_prefix", r.issue);
    }

    public void testGlobalNameAutoGeneratedRemnantRejected() {
        // Lazy "rename" that just keeps an auto-generated stem — we want
        // meaningful content, not a reshuffled DAT_ / PTR_ prefix.
        for (String n : new String[]{
                "g_DAT_6fdf64d8", "g_PTR_DAT_1234", "g_FUN_6fcab220",
                "g_LAB_1234abcd", "g_SUB_aabbccdd",
                "g_dw_6fdf64d8"
        }) {
            NamingConventions.GlobalNameResult r =
                    NamingConventions.checkGlobalNameQuality(n, "uint");
            assertFalse("Expected reject for: " + n, r.ok);
            assertEquals("auto_generated_remnant", r.issue);
        }
    }

    public void testGlobalNameMissingHungarianRejected() {
        // g_ prefix present but no recognized Hungarian after it.
        NamingConventions.GlobalNameResult r =
                NamingConventions.checkGlobalNameQuality("g_ActiveState", "uint");
        assertFalse(r.ok);
        assertEquals("missing_hungarian_prefix", r.issue);
    }

    public void testGlobalNameShortDescriptorRejected() {
        // g_dwX = 1-char descriptor after Hungarian.
        NamingConventions.GlobalNameResult r =
                NamingConventions.checkGlobalNameQuality("g_dwX", "uint");
        assertFalse(r.ok);
        assertEquals("short_descriptor", r.issue);
    }

    public void testGlobalNameLowercaseAfterHungarianRejected() {
        // 'g_dwactiveState' — lowercase after Hungarian. extractHungarianPrefix
        // requires the char after the prefix to be uppercase, so this surfaces
        // as missing_hungarian_prefix (the prefix isn't recognized).
        NamingConventions.GlobalNameResult r =
                NamingConventions.checkGlobalNameQuality("g_dwactiveState", "uint");
        assertFalse(r.ok);
        assertEquals("missing_hungarian_prefix", r.issue);
    }

    public void testGlobalNameHungarianTypeMismatchRejected() {
        // p prefix on a non-pointer type — flagged via validateHungarianPrefix.
        NamingConventions.GlobalNameResult r =
                NamingConventions.checkGlobalNameQuality("g_pUnitCount", "uint");
        assertFalse(r.ok);
        assertEquals("prefix_type_mismatch", r.issue);
    }

    public void testGlobalNameWithMatchingTypeAccepted() {
        // dw + uint = match (pure uint check)
        assertTrue(NamingConventions.checkGlobalNameQuality("g_dwActiveQuestState", "uint").ok);
        // p + ptr-typed = match
        assertTrue(NamingConventions.checkGlobalNameQuality("g_pUnitList", "UnitAny *").ok);
        // sz + char* = match
        assertTrue(NamingConventions.checkGlobalNameQuality("g_szPlayerName", "char *").ok);
    }

    public void testGlobalNamePlaceholderConventionAccepted() {
        // The CLAUDE.md "underclaim with placeholder" pattern explicitly
        // allows g_dwField<offset> and g_pUnk<offset>. Validator must not
        // reject those — only the obvious laziness patterns.
        assertTrue(NamingConventions.checkGlobalNameQuality("g_dwField1D0", "uint").ok);
        assertTrue(NamingConventions.checkGlobalNameQuality("g_pUnk20", "void *").ok);
        assertTrue(NamingConventions.checkGlobalNameQuality("g_nValue04", "int").ok);
    }

    public void testGlobalNameWithoutTypeOnlyChecksNamePart() {
        // typeName=null skips Hungarian-vs-type check; structural rules still fire.
        assertTrue(NamingConventions.checkGlobalNameQuality("g_dwSomeValue", null).ok);
        assertFalse(NamingConventions.checkGlobalNameQuality("nope", null).ok);
        assertFalse(NamingConventions.checkGlobalNameQuality("g_DAT_1234", null).ok);
    }

    public void testGlobalNameAutoGeneratedExempt() {
        // Auto-generated names (DAT_xxx, etc.) bypass quality check entirely
        // — they get the unrenamed_globals deduction at the scoring layer.
        assertTrue(NamingConventions.checkGlobalNameQuality("DAT_6fdf64d8", "uint").ok);
        assertTrue(NamingConventions.checkGlobalNameQuality("PTR_DAT_6fdf64d8", "void *").ok);
    }

    public void testGlobalNameNullAndEmptyHandled() {
        assertTrue(NamingConventions.checkGlobalNameQuality(null, "uint").ok);
        assertTrue(NamingConventions.checkGlobalNameQuality("", "uint").ok);
    }
}
