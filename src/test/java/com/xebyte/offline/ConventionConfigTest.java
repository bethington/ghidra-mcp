package com.xebyte.offline;

import com.xebyte.core.ConventionConfig;
import com.xebyte.core.ConventionConfigLoader;
import com.xebyte.core.NamingConventions;
import com.xebyte.core.NamingPolicy;
import junit.framework.TestCase;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Tests for the v5.11.2 user-configurable convention layer.
 *
 * <p>Three things to pin:
 *
 * <ol>
 *   <li>Defaults reproduce the pre-v5.11.2 hardcoded behavior — no project
 *       config file means no behavior change.</li>
 *   <li>The JSON loader correctly translates each section's knobs into
 *       runtime behavior (verbs add/remove, weak-noun overrides, plate
 *       comment toggle, global-prefix toggle, etc).</li>
 *   <li>The per-call {@code strict_mode} override is thread-local and
 *       cleared when the AutoCloseable closes, so no leak across requests
 *       on a reused HTTP thread.</li>
 * </ol>
 *
 * <p>Each test snapshots and restores the singleton config — they share
 * the same JVM and a poisoned policy would cascade.
 */
public class ConventionConfigTest extends TestCase {

    private ConventionConfig savedConfig;
    private String savedSource;

    @Override
    protected void setUp() {
        savedConfig = NamingPolicy.getInstance().getConfig();
        savedSource = NamingPolicy.getInstance().getSource();
    }

    @Override
    protected void tearDown() {
        NamingPolicy.getInstance().setConfig(savedConfig, savedSource);
        NamingPolicy.getInstance().clearRequestModeOverride();
    }

    // ---------- Defaults preserve historical behavior ----------

    public void testDefaultsMatchHardcodedBehavior() {
        ConventionConfig cfg = ConventionConfig.defaults();
        assertEquals(ConventionConfig.Mode.ENFORCE, cfg.getMode());
        assertEquals(8, cfg.functionNaming().minLength());
        assertTrue(cfg.hungarian().autoFixStructFields());
        assertTrue(cfg.globalNaming().validate());
        assertTrue(cfg.globalNaming().requireGPrefix());
        assertEquals(2, cfg.globalNaming().minDescriptorLength());
        assertTrue(cfg.plateComments().validate());
        assertEquals(4, cfg.plateComments().minFirstLineWords());
        assertEquals(
                List.of("Algorithm", "Parameters", "Returns"),
                cfg.plateComments().requiredSections()
        );
    }

    public void testLoaderReturnsDefaultsWhenFileMissing() throws IOException {
        Path tmp = Files.createTempDirectory("ghidra-mcp-test");
        try {
            ConventionConfigLoader.LoadResult result =
                    ConventionConfigLoader.loadFromProjectRoot(tmp);
            assertTrue(result.usedDefaults());
            assertNull(result.error());
            assertEquals(ConventionConfig.Mode.ENFORCE, result.config().getMode());
        } finally {
            Files.deleteIfExists(tmp);
        }
    }

    public void testLoaderHandlesNullProjectRoot() {
        ConventionConfigLoader.LoadResult result =
                ConventionConfigLoader.loadFromProjectRoot(null);
        assertTrue(result.usedDefaults());
        assertNull(result.error());
    }

    // ---------- JSON parsing ----------

    public void testParseStrictModeOff() {
        String json = "{\"strict_mode\": \"off\"}";
        ConventionConfigLoader.LoadResult result = ConventionConfigLoader.parse(json, null);
        assertEquals(ConventionConfig.Mode.OFF, result.config().getMode());
    }

    public void testParseStrictModeWarn() {
        String json = "{\"strict_mode\": \"warn\"}";
        ConventionConfigLoader.LoadResult result = ConventionConfigLoader.parse(json, null);
        assertEquals(ConventionConfig.Mode.WARN, result.config().getMode());
    }

    public void testParseUnknownStrictModeFallsBackToEnforce() {
        String json = "{\"strict_mode\": \"gibberish\"}";
        ConventionConfigLoader.LoadResult result = ConventionConfigLoader.parse(json, null);
        assertEquals(ConventionConfig.Mode.ENFORCE, result.config().getMode());
    }

    public void testParseMalformedJsonFallsThroughToDefaults() {
        // JsonHelper.parseJson swallows Gson exceptions and returns an
        // empty map — project convention is "broken config = defaults"
        // rather than crashing the plugin start. Pin that behavior here
        // so a future tightening doesn't silently regress the UX.
        String json = "{this is not json";
        ConventionConfigLoader.LoadResult result = ConventionConfigLoader.parse(json, null);
        assertEquals(ConventionConfig.Mode.ENFORCE, result.config().getMode());
        assertEquals(8, result.config().functionNaming().minLength());
    }

    public void testParseFunctionNamingAddsAndRemovesVerbs() {
        String json = "{\"function_naming\": {"
                + " \"verbs_add\": [\"Sniff\", \"Inject\"],"
                + " \"verbs_remove\": [\"Process\"],"
                + " \"min_length\": 12,"
                + " \"verb_tier_overrides\": {\"Process\": 1, \"Render\": 3},"
                + " \"weak_nouns_add\": [\"Foo\"],"
                + " \"weak_nouns_remove\": [\"Data\"]"
                + "}}";
        ConventionConfigLoader.LoadResult result = ConventionConfigLoader.parse(json, null);
        ConventionConfig.FunctionNamingRules fn = result.config().functionNaming();
        assertEquals(12, fn.minLength());
        assertTrue(fn.verbsAdd().contains("Sniff"));
        assertTrue(fn.verbsAdd().contains("Inject"));
        assertTrue(fn.verbsRemove().contains("Process"));
        assertEquals(Integer.valueOf(1), fn.verbTierOverrides().get("Process"));
        assertEquals(Integer.valueOf(3), fn.verbTierOverrides().get("Render"));
        assertTrue(fn.weakNounsAdd().contains("Foo"));
        assertTrue(fn.weakNounsRemove().contains("Data"));
    }

    public void testParseOutOfRangeTierOverrideEmitsWarningAndDropsEntry() {
        String json = "{\"function_naming\": {"
                + " \"verb_tier_overrides\": {\"Sniff\": 7, \"Inject\": 2}"
                + "}}";
        ConventionConfigLoader.LoadResult result = ConventionConfigLoader.parse(json, null);
        ConventionConfig.FunctionNamingRules fn = result.config().functionNaming();
        // Out-of-range tier dropped; warning surfaced.
        assertNull(fn.verbTierOverrides().get("Sniff"));
        assertEquals(Integer.valueOf(2), fn.verbTierOverrides().get("Inject"));
        assertFalse(result.warnings().isEmpty());
    }

    public void testParsePlateCommentSectionsAreCustomizable() {
        String json = "{\"plate_comments\": {"
                + " \"validate\": true,"
                + " \"required_sections\": [\"Purpose\", \"InputOutput\"],"
                + " \"min_first_line_words\": 6"
                + "}}";
        ConventionConfigLoader.LoadResult result = ConventionConfigLoader.parse(json, null);
        ConventionConfig.PlateCommentRules pc = result.config().plateComments();
        assertTrue(pc.validate());
        assertEquals(List.of("Purpose", "InputOutput"), pc.requiredSections());
        assertEquals(6, pc.minFirstLineWords());
    }

    public void testParsePlateCommentValidationCanBeDisabled() {
        String json = "{\"plate_comments\": {\"validate\": false}}";
        ConventionConfigLoader.LoadResult result = ConventionConfigLoader.parse(json, null);
        assertFalse(result.config().plateComments().validate());
    }

    public void testParseGlobalNamingCanWaiveGPrefix() {
        String json = "{\"global_naming\": {\"require_g_prefix\": false}}";
        ConventionConfigLoader.LoadResult result = ConventionConfigLoader.parse(json, null);
        assertFalse(result.config().globalNaming().requireGPrefix());
    }

    public void testParseHungarianAutoFixCanBeDisabled() {
        String json = "{\"hungarian\": {\"auto_fix_struct_fields\": false}}";
        ConventionConfigLoader.LoadResult result = ConventionConfigLoader.parse(json, null);
        assertFalse(result.config().hungarian().autoFixStructFields());
    }

    public void testParseEmptyObjectGivesAllDefaults() {
        String json = "{}";
        ConventionConfigLoader.LoadResult result = ConventionConfigLoader.parse(json, null);
        ConventionConfig cfg = result.config();
        assertEquals(ConventionConfig.Mode.ENFORCE, cfg.getMode());
        assertEquals(8, cfg.functionNaming().minLength());
        assertTrue(cfg.plateComments().validate());
    }

    // ---------- File loading ----------

    public void testLoadFromProjectRootReadsConventionsJson() throws IOException {
        Path projectRoot = Files.createTempDirectory("ghidra-mcp-test");
        Path configDir = projectRoot.resolve(".ghidra-mcp");
        Files.createDirectories(configDir);
        Path configFile = configDir.resolve("conventions.json");
        Files.writeString(configFile, "{\"strict_mode\": \"off\"}");
        try {
            ConventionConfigLoader.LoadResult result =
                    ConventionConfigLoader.loadFromProjectRoot(projectRoot);
            assertTrue(result.loaded());
            assertEquals(ConventionConfig.Mode.OFF, result.config().getMode());
            assertEquals(configFile, result.resolvedFrom());
        } finally {
            Files.deleteIfExists(configFile);
            Files.deleteIfExists(configDir);
            Files.deleteIfExists(projectRoot);
        }
    }

    // ---------- NamingConventions consults the active config ----------

    public void testWeakNounAddMakesCustomTokenWeak() {
        ConventionConfig custom = new ConventionConfig(
                ConventionConfig.Mode.ENFORCE,
                new ConventionConfig.FunctionNamingRules(8,
                        Set.of(),                    // verbs_add
                        Set.of(),                    // verbs_remove
                        Map.of(),                    // tier overrides
                        Set.of("Widget"),            // weak_nouns_add
                        Set.of()),                   // weak_nouns_remove
                ConventionConfig.HungarianRules.defaults(),
                ConventionConfig.GlobalNamingRules.defaults(),
                ConventionConfig.PlateCommentRules.defaults());
        NamingPolicy.getInstance().setConfig(custom, "test");
        assertTrue(NamingConventions.isWeakNoun("Widget"));
        assertTrue(NamingConventions.isWeakNoun("Data"));   // built-in still wins
    }

    public void testWeakNounRemoveLifsBuiltInRestriction() {
        ConventionConfig custom = new ConventionConfig(
                ConventionConfig.Mode.ENFORCE,
                new ConventionConfig.FunctionNamingRules(8,
                        Set.of(), Set.of(), Map.of(),
                        Set.of(),
                        Set.of("Data")),             // weak_nouns_remove
                ConventionConfig.HungarianRules.defaults(),
                ConventionConfig.GlobalNamingRules.defaults(),
                ConventionConfig.PlateCommentRules.defaults());
        NamingPolicy.getInstance().setConfig(custom, "test");
        assertFalse(NamingConventions.isWeakNoun("Data"));  // now allowed
    }

    public void testVerbTierOverrideTakesPrecedence() {
        ConventionConfig custom = new ConventionConfig(
                ConventionConfig.Mode.ENFORCE,
                new ConventionConfig.FunctionNamingRules(8,
                        Set.of(), Set.of(),
                        Map.of("Process", 1),        // demote built-in Tier 3 verb
                        Set.of(), Set.of()),
                ConventionConfig.HungarianRules.defaults(),
                ConventionConfig.GlobalNamingRules.defaults(),
                ConventionConfig.PlateCommentRules.defaults());
        NamingPolicy.getInstance().setConfig(custom, "test");
        assertEquals(1, NamingConventions.getVerbTier("Process"));
        // Unconfigured verbs still flow through the built-in tier tables.
        assertEquals(2, NamingConventions.getVerbTier("Get"));
    }

    public void testPlateCommentValidationCanBeDisabled() {
        ConventionConfig custom = new ConventionConfig(
                ConventionConfig.Mode.ENFORCE,
                ConventionConfig.FunctionNamingRules.defaults(),
                ConventionConfig.HungarianRules.defaults(),
                ConventionConfig.GlobalNamingRules.defaults(),
                new ConventionConfig.PlateCommentRules(
                        false, List.of(), 4));
        NamingPolicy.getInstance().setConfig(custom, "test");
        // A 1-word plate that would normally be rejected now passes
        // because validation is off.
        assertNull(NamingConventions.checkGlobalPlateComment("Counter"));
    }

    public void testPlateCommentSectionsAreCustomizable() {
        ConventionConfig custom = new ConventionConfig(
                ConventionConfig.Mode.ENFORCE,
                ConventionConfig.FunctionNamingRules.defaults(),
                ConventionConfig.HungarianRules.defaults(),
                ConventionConfig.GlobalNamingRules.defaults(),
                new ConventionConfig.PlateCommentRules(
                        true, List.of("Purpose", "Notes"), 4));
        NamingPolicy.getInstance().setConfig(custom, "test");
        List<String> warnings = NamingConventions.validatePlateCommentStructure(
                "Some summary line\nPurpose: do a thing\nNotes: extra info");
        assertTrue("Expected no warnings; got " + warnings, warnings.isEmpty());

        warnings = NamingConventions.validatePlateCommentStructure(
                "Some summary line\nAlgorithm: foo\nParameters: bar\nReturns: baz");
        // None of the new required sections are present, even though all
        // three default sections are. Validator should complain about both
        // new required sections.
        assertEquals(2, warnings.size());
    }

    public void testGlobalNameValidationCanBeDisabled() {
        ConventionConfig custom = new ConventionConfig(
                ConventionConfig.Mode.ENFORCE,
                ConventionConfig.FunctionNamingRules.defaults(),
                ConventionConfig.HungarianRules.defaults(),
                new ConventionConfig.GlobalNamingRules(false, true, 2),
                ConventionConfig.PlateCommentRules.defaults());
        NamingPolicy.getInstance().setConfig(custom, "test");
        NamingConventions.GlobalNameResult result =
                NamingConventions.checkGlobalNameQuality("randomBadName", "int");
        assertTrue("validation disabled — expected ok()", result.ok);
    }

    public void testGlobalNamingCanWaiveGPrefix() {
        ConventionConfig custom = new ConventionConfig(
                ConventionConfig.Mode.ENFORCE,
                ConventionConfig.FunctionNamingRules.defaults(),
                ConventionConfig.HungarianRules.defaults(),
                new ConventionConfig.GlobalNamingRules(true, false, 2),
                ConventionConfig.PlateCommentRules.defaults());
        NamingPolicy.getInstance().setConfig(custom, "test");
        NamingConventions.GlobalNameResult result =
                NamingConventions.checkGlobalNameQuality("ItemList", "int");
        assertTrue("g_ prefix waived — expected ok()", result.ok);
    }

    // ---------- Per-call strict_mode override (thread-local) ----------

    public void testRequestOverrideTakesPrecedenceOverGlobalMode() {
        NamingPolicy policy = NamingPolicy.getInstance();
        policy.setConfig(ConventionConfig.defaults(), "test");
        assertTrue(policy.isStrictNamingEnforcement());

        policy.setRequestModeOverride(ConventionConfig.Mode.OFF);
        try {
            assertFalse("OFF override should suppress strict mode",
                    policy.isStrictNamingEnforcement());
            assertEquals(ConventionConfig.Mode.OFF, policy.getEffectiveMode());
        } finally {
            policy.clearRequestModeOverride();
        }
        // After clear, back to the global config.
        assertTrue(policy.isStrictNamingEnforcement());
    }

    public void testScopedRequestModeAutoclosable() throws Exception {
        NamingPolicy policy = NamingPolicy.getInstance();
        policy.setConfig(ConventionConfig.defaults(), "test");
        assertTrue(policy.isStrictNamingEnforcement());

        try (AutoCloseable ignored = policy.scopedRequestMode("off")) {
            assertFalse(policy.isStrictNamingEnforcement());
        }
        assertTrue("scope must clear override on close",
                policy.isStrictNamingEnforcement());
    }

    public void testScopedRequestModeNullArgIsNoOp() throws Exception {
        NamingPolicy policy = NamingPolicy.getInstance();
        policy.setConfig(ConventionConfig.defaults(), "test");
        try (AutoCloseable ignored = policy.scopedRequestMode(null)) {
            assertTrue("null strict_mode keeps the global setting",
                    policy.isStrictNamingEnforcement());
        }
        assertTrue(policy.isStrictNamingEnforcement());
    }

    public void testScopedRequestModeBlankArgIsNoOp() throws Exception {
        NamingPolicy policy = NamingPolicy.getInstance();
        policy.setConfig(ConventionConfig.defaults(), "test");
        try (AutoCloseable ignored = policy.scopedRequestMode("")) {
            assertTrue(policy.isStrictNamingEnforcement());
        }
    }

    public void testScopedRequestModeClearsEvenOnException() {
        NamingPolicy policy = NamingPolicy.getInstance();
        policy.setConfig(ConventionConfig.defaults(), "test");
        try {
            try (AutoCloseable ignored = policy.scopedRequestMode("off")) {
                assertFalse(policy.isStrictNamingEnforcement());
                throw new RuntimeException("simulated body failure");
            }
        } catch (Exception expected) {
            // Even though the body threw, the override must be cleared.
        }
        assertTrue("override must clear even when body throws",
                policy.isStrictNamingEnforcement());
    }
}
