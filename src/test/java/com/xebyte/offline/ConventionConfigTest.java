package com.xebyte.offline;

import com.xebyte.core.ConventionConfig;
import com.xebyte.core.NamingConventions;
import com.xebyte.core.NamingPolicy;
import junit.framework.TestCase;

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
 *   <li>Settings-backed configs translate each section's knobs into
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
