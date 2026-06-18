package com.xebyte.offline;

import com.xebyte.core.NamingConventions;
import com.xebyte.core.NamingConventions.NameQualityResult;
import com.xebyte.core.NamingPolicy;
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

    public void testPointerPrefixWithStructTypeSuggestsAddingAsterisk() {
        // The dominant production-friction pattern: model passes a struct
        // typeName without asterisk for a pointer-prefix name. Suggestion
        // must explicitly tell them to add `*` and quote the exact replacement
        // type so they can copy-paste.
        NamingConventions.GlobalNameResult r =
                NamingConventions.checkGlobalNameQuality("g_pDialogJoinMultiplayer", "DialogResource");
        assertFalse(r.ok);
        assertEquals("prefix_type_mismatch", r.issue);
        assertNotNull(r.suggestion);
        assertTrue("suggestion must include the literal pointer type for copy-paste, was: " + r.suggestion,
                r.suggestion.contains("DialogResource *"));
        assertTrue("suggestion must reference type_name= to land in the right slot",
                r.suggestion.contains("type_name="));
    }

    public void testDoublePointerPrefixSuggestsDoubleAsterisk() {
        // pp prefix with single-pointer type — should suggest `**`, not `*`.
        NamingConventions.GlobalNameResult r =
                NamingConventions.checkGlobalNameQuality("g_ppRoomTable", "Room");
        assertFalse(r.ok);
        assertEquals("prefix_type_mismatch", r.issue);
        assertTrue("pp prefix should suggest **, was: " + r.suggestion,
                r.suggestion.contains("Room **"));
    }

    public void testNonPointerMismatchKeepsGenericSuggestion() {
        // dw prefix on a struct type — not a pointer mismatch, so the
        // pointer-aware shortcut shouldn't fire. Validator should fall back
        // to the generic "rename or correct the type" suggestion without
        // suggesting a spurious asterisk.
        NamingConventions.GlobalNameResult r =
                NamingConventions.checkGlobalNameQuality("g_dwSomeStruct", "DialogResource");
        assertFalse(r.ok);
        assertEquals("prefix_type_mismatch", r.issue);
        assertFalse("non-pointer mismatch must not suggest adding *, was: " + r.suggestion,
                r.suggestion.contains("DialogResource *"));
    }

    public void testPointerPrefixWithExistingPointerTypePasses() {
        // Sanity: when type_name already has *, no rejection.
        assertTrue(NamingConventions.checkGlobalNameQuality("g_pDialogJoinMultiplayer", "DialogResource *").ok);
        assertTrue(NamingConventions.checkGlobalNameQuality("g_ppRoomTable", "Room **").ok);
    }

    public void testGenericDescriptorCommonWords() {
        // Common-words bucket — should fire as soft warning.
        assertTrue(NamingConventions.isGenericDescriptor("Data"));
        assertTrue(NamingConventions.isGenericDescriptor("Buffer"));
        assertTrue(NamingConventions.isGenericDescriptor("Flag"));
        assertTrue(NamingConventions.isGenericDescriptor("Value"));
        assertTrue(NamingConventions.isGenericDescriptor("Result"));
        assertTrue(NamingConventions.isGenericDescriptor("Status"));
        assertTrue(NamingConventions.isGenericDescriptor("Handle"));
        assertTrue(NamingConventions.isGenericDescriptor("Context"));
        // Trailing digits (Flag1, Buffer3) still flag — strip digits, then
        // check the underlying word.
        assertTrue(NamingConventions.isGenericDescriptor("Flag1"));
        assertTrue(NamingConventions.isGenericDescriptor("Buffer42"));
    }

    public void testGenericDescriptorGibberishGuard() {
        // Gibberish bucket — model-hallucination catch.
        assertTrue(NamingConventions.isGenericDescriptor("Foo"));
        assertTrue(NamingConventions.isGenericDescriptor("Bar"));
        assertTrue(NamingConventions.isGenericDescriptor("Test"));
        assertTrue(NamingConventions.isGenericDescriptor("Sample"));
        assertTrue(NamingConventions.isGenericDescriptor("Thing"));
    }

    public void testGenericDescriptorPlaceholderExempt() {
        // Placeholder convention from CLAUDE.md / step-globals.md must NOT
        // fire — these are explicitly the *correct* name when semantic
        // role is uncertain.
        assertFalse(NamingConventions.isGenericDescriptor("Field1D0"));
        assertFalse(NamingConventions.isGenericDescriptor("Unk20"));
        assertFalse(NamingConventions.isGenericDescriptor("Value04"));
        assertFalse(NamingConventions.isGenericDescriptor("FieldA8"));
    }

    public void testGenericDescriptorMeaningfulNamesPass() {
        // Real descriptors should not flag.
        assertFalse(NamingConventions.isGenericDescriptor("ActiveQuestState"));
        assertFalse(NamingConventions.isGenericDescriptor("UnitList"));
        assertFalse(NamingConventions.isGenericDescriptor("DifficultyLevels"));
        assertFalse(NamingConventions.isGenericDescriptor("PlayerName"));
        assertFalse(NamingConventions.isGenericDescriptor(""));
        assertFalse(NamingConventions.isGenericDescriptor(null));
    }

    public void testIdaReservedPrefixDetection() {
        // IDA's reserved auto-name prefixes must be flagged — reusing
        // them in user names breaks downstream tools.
        assertTrue(NamingConventions.hasIdaReservedPrefix("sub_402011"));
        assertTrue(NamingConventions.hasIdaReservedPrefix("loc_414e"));
        assertTrue(NamingConventions.hasIdaReservedPrefix("byte_6fdf6000"));
        assertTrue(NamingConventions.hasIdaReservedPrefix("dword_6fdf6004"));
        assertTrue(NamingConventions.hasIdaReservedPrefix("stru_6fdf6010"));
        assertTrue(NamingConventions.hasIdaReservedPrefix("var_8"));
        // Case-insensitive.
        assertTrue(NamingConventions.hasIdaReservedPrefix("SUB_402011"));
        // Real names don't fire.
        assertFalse(NamingConventions.hasIdaReservedPrefix("g_dwActiveQuestState"));
        assertFalse(NamingConventions.hasIdaReservedPrefix("ExceptionList"));
        assertFalse(NamingConventions.hasIdaReservedPrefix(""));
        assertFalse(NamingConventions.hasIdaReservedPrefix(null));
        // Substring match shouldn't fire — must be at start.
        assertFalse(NamingConventions.hasIdaReservedPrefix("g_dw_var_offset"));
    }

    public void testOsCanonicalGlobalNamesAreExempt() {
        // TIB / TEB members applied by Ghidra's PE loader. Renaming
        // these to g_* form is wrong; the validator must NOT flag them.
        assertTrue(NamingConventions.isOsCanonicalGlobalName("ExceptionList"));
        assertTrue(NamingConventions.isOsCanonicalGlobalName("StackBase"));
        assertTrue(NamingConventions.isOsCanonicalGlobalName("FiberData"));
        assertTrue(NamingConventions.isOsCanonicalGlobalName("Self"));
        // Case-insensitive match.
        assertTrue(NamingConventions.isOsCanonicalGlobalName("exceptionlist"));
        assertTrue(NamingConventions.isOsCanonicalGlobalName("EXCEPTIONLIST"));
        // Non-OS names not affected.
        assertFalse(NamingConventions.isOsCanonicalGlobalName("g_dwActiveQuestState"));
        assertFalse(NamingConventions.isOsCanonicalGlobalName("dwFlags"));
        assertFalse(NamingConventions.isOsCanonicalGlobalName(null));
        assertFalse(NamingConventions.isOsCanonicalGlobalName(""));

        // checkGlobalNameQuality short-circuits to ok for OS labels —
        // even though they don't start with g_, they're not flagged.
        assertTrue(NamingConventions.checkGlobalNameQuality("ExceptionList", "void *").ok);
        assertTrue(NamingConventions.checkGlobalNameQuality("StackBase", "void *").ok);
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

    // ---------- checkGlobalPlateComment (Q6 design) ----------
    //
    // Shared helper used by both audit_global (issue detection) and
    // set_global (pre-flight rejection). These tests pin the contract.

    public void testPlateCommentNullAccepted() {
        // Null plate-comment is the caller's concern — the helper returns
        // null (= ok) so audit_global / set_global can decide whether
        // missing-vs-bad plate is the right error code.
        assertNull(NamingConventions.checkGlobalPlateComment(null));
    }

    public void testPlateCommentEmptyAccepted() {
        // Empty/whitespace-only treated like null — helper returns null.
        assertNull(NamingConventions.checkGlobalPlateComment(""));
        assertNull(NamingConventions.checkGlobalPlateComment("   "));
        assertNull(NamingConventions.checkGlobalPlateComment("\n\n  \t"));
    }

    public void testPlateCommentFourWordSummaryAccepted() {
        assertNull(NamingConventions.checkGlobalPlateComment(
                "Bitmap of currently-active quests for the player."));
        assertNull(NamingConventions.checkGlobalPlateComment(
                "Pointer to the head of the linked unit list."));
        // Exactly 4 words is the boundary — accepted.
        assertNull(NamingConventions.checkGlobalPlateComment(
                "Active player quest mask"));
    }

    public void testPlateCommentTooShortRejected() {
        // 1, 2, 3 words on the first line — all rejected.
        for (String c : new String[]{
                "counter",
                "global counter",
                "the active flag",
                "TODO: figure out"
        }) {
            String[] result = NamingConventions.checkGlobalPlateComment(c);
            assertNotNull("Expected reject for: " + c, result);
            assertEquals("plate_comment_too_short", result[0]);
            assertEquals(c.trim(), result[1]);
        }
    }

    public void testPlateCommentMultilineUsesFirstLine() {
        // A valid first line passes regardless of subsequent content.
        assertNull(NamingConventions.checkGlobalPlateComment(
                "Bitmap of currently-active quests for the player.\n\n"
                + "Used by: ProcessQuestUpdate\n"
                + "Layout: 32 bits, low 16 = act 1-2"));
        // A short first line fails even when later lines have content.
        String[] result = NamingConventions.checkGlobalPlateComment(
                "global counter\nUsed by: TickPlayer\nLayout: dword");
        assertNotNull(result);
        assertEquals("plate_comment_too_short", result[0]);
        assertEquals("global counter", result[1]);
    }

    public void testPlateCommentWordSplitHandlesPunctuation() {
        // Word-split is whitespace-based; punctuation glued to a word counts
        // as one token. "Bitmap of, the, player" = 4 tokens — accepted.
        assertNull(NamingConventions.checkGlobalPlateComment("Bitmap of, the, player"));
    }

    // ---------- longestPlateLineLength (plate_line_too_long support) ----------
    //
    // Audit emits a soft `plate_line_too_long` issue when any line in a
    // plate comment exceeds PLATE_LINE_CLIP_THRESHOLD (80) — Ghidra's
    // listing column truncates past that. Threshold lives in
    // NamingConventions so the rule has one source of truth; tests pin
    // the line-walk behavior.

    public void testLongestPlateLineLengthEmptyAndNull() {
        assertEquals(0, NamingConventions.longestPlateLineLength(null));
        assertEquals(0, NamingConventions.longestPlateLineLength(""));
    }

    public void testLongestPlateLineLengthSingleLine() {
        String line = "Pointer to the unit list head";
        assertEquals(line.length(),
                NamingConventions.longestPlateLineLength(line));
    }

    public void testLongestPlateLineLengthMultilineReturnsMax() {
        // Three lines of differing lengths — returns the longest.
        String plate =
                "Bitmap of currently-active quests for the player.\n"  // 49
                + "\n"                                                 // 0
                + "Set by: ProcessQuestUpdate, InitQuestState\n"       // 41
                + "Read by: RenderQuestLog";                           // 22
        assertEquals(49, NamingConventions.longestPlateLineLength(plate));
    }

    public void testLongestPlateLineLengthCatchesOverlongXrefList() {
        // Real-world scenario from the g_dwStoredVersion incident:
        // unwrapped `Set by: A, B, C, ... 19 names` blows past 80
        // chars. The audit must surface this as `plate_line_too_long`.
        String overlong = "Set by: SNetCreateLadderGame, "
                + "SetActiveGameUnitContext, ProcessEntityStateChangeEvents, "
                + "SomethingElseLong, AndAnotherOne";
        int len = NamingConventions.longestPlateLineLength(overlong);
        assertTrue("expected overlong line, got " + len + " chars",
                len > NamingConventions.PLATE_LINE_CLIP_THRESHOLD);
    }

    public void testLongestPlateLineLengthAcceptsWrappedShape() {
        // The canonical wrapped shape from step-globals.md — every line
        // under threshold (with margin). This exercise ensures the
        // recommended wrap actually gets the soft issue to clear.
        String wrapped =
                "Stored game version used for network protocol compatibility checks.\n"
                + "\n"
                + "Set by:\n"
                + "  SNetCreateLadderGame, SetActiveGameUnitContext,\n"
                + "  ProcessEntityStateChangeEvents\n"
                + "Read by:\n"
                + "  SNetCreateLadderGame, BroadcastGameStateToPlayers,\n"
                + "  ProcessEntityStateChangeEvents, RetrieveDataByTypeWithBuffer";
        int len = NamingConventions.longestPlateLineLength(wrapped);
        assertTrue("wrapped plate should fit in clip threshold; got " + len,
                len <= NamingConventions.PLATE_LINE_CLIP_THRESHOLD);
    }

    public void testPlateLineClipThresholdValue() {
        // Pin the threshold — changing it requires updating the prompt
        // wrap-target guidance in step-globals.md.
        assertEquals(80, NamingConventions.PLATE_LINE_CLIP_THRESHOLD);
    }

    // ---------- struct-field naming policy ----------

    public void testStructFieldPolicyAutoFixesWhenStrictNamingEnabled() {
        NamingPolicy policy = NamingPolicy.getInstance();
        boolean originalValue = policy.isStrictNamingEnforcement();
        String originalSource = policy.getSource();

        try {
            policy.setStrictNamingEnforcement(true, "test");
            assertEquals("dwItem_count",
                    NamingConventions.applyStructFieldNamingPolicy("item_count", "uint"));
            assertEquals("pNext_item",
                    NamingConventions.applyStructFieldNamingPolicy("next_item", "void *"));
        } finally {
            policy.setStrictNamingEnforcement(originalValue, originalSource);
        }
    }

    public void testStructFieldPolicyPreservesNamesWhenStrictNamingDisabled() {
        NamingPolicy policy = NamingPolicy.getInstance();
        boolean originalValue = policy.isStrictNamingEnforcement();
        String originalSource = policy.getSource();

        try {
            policy.setStrictNamingEnforcement(false, "test");
            assertEquals("item_count",
                    NamingConventions.applyStructFieldNamingPolicy("item_count", "uint"));
            assertEquals("next_item",
                    NamingConventions.applyStructFieldNamingPolicy("next_item", "void *"));
            assertEquals("is_enabled",
                    NamingConventions.applyStructFieldNamingPolicy("is_enabled", "bool"));
        } finally {
            policy.setStrictNamingEnforcement(originalValue, originalSource);
        }
    }

    // ---------- autoFixFieldPrefix — pointer-family prefix derivation and preservation ----------

    public void testAutoFixFieldPrefix_preservesSpecificPointerPrefixes() {
        // Caller already supplied a more-specific pointer-family prefix → return unchanged
        assertEquals("ppNext",       NamingConventions.autoFixFieldPrefix("ppNext",       "Node **"));
        assertEquals("pfnCallback",  NamingConventions.autoFixFieldPrefix("pfnCallback",  "void (*)(int)"));
        assertEquals("aItems",       NamingConventions.autoFixFieldPrefix("aItems",       "int[16]"));
    }

    public void testAutoFixFieldPrefix_derivesSpecificPointerPrefixes() {
        // No prefix supplied → derive the specific one, not bare 'p'
        assertEquals("ppNext",    NamingConventions.autoFixFieldPrefix("Next",    "Node **"));
        assertEquals("pfnHandler",NamingConventions.autoFixFieldPrefix("Handler", "int (*)(void)"));
        assertEquals("aBuf",      NamingConventions.autoFixFieldPrefix("Buf",     "char[256]"));
        // Single pointer still gets 'p' (regression guard)
        assertEquals("pData",     NamingConventions.autoFixFieldPrefix("Data",    "void *"));
    }

    public void testAutoGeneratedGlobal_recognizesGhidraStringLabels() {
        // ascii string labels: s_<sanitized-text>_<addr>
        assertTrue(NamingConventions.isAutoGeneratedGlobalName("s_PlayerName_6fdf64d8"));
        assertTrue(NamingConventions.isAutoGeneratedGlobalName("s_Hello_World!_00401000"));
        // unicode string labels: u_<text>_<addr>
        assertTrue(NamingConventions.isAutoGeneratedGlobalName("u_Welcome_00401020"));
        // pure-hex body still matches (regression)
        assertTrue(NamingConventions.isAutoGeneratedGlobalName("s_6fdf64d8"));
        assertTrue(NamingConventions.isAutoGeneratedGlobalName("DAT_00401000"));
        // user-named globals must NOT match
        assertFalse(NamingConventions.isAutoGeneratedGlobalName("g_pPlayerData"));
        assertFalse(NamingConventions.isAutoGeneratedGlobalName("s_userDefinedNoAddrSuffix"));
    }
}
