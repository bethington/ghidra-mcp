package com.xebyte.offline;

import com.xebyte.core.ConventionConfig;
import com.xebyte.core.NamingPolicy;
import junit.framework.TestCase;

/**
 * Pure-logic tests for the naming enforcement policy.
 */
public class NamingPolicyTest extends TestCase {

    public void testDefaultPreservesStrictBehavior() {
        assertTrue(NamingPolicy.defaultStrictNamingEnforcement());
    }

    public void testGlobalSettingCanBeUpdatedAndRestored() {
        NamingPolicy policy = NamingPolicy.getInstance();
        ConventionConfig originalConfig = policy.getConfig();
        String originalSource = policy.getSource();

        try {
            policy.setConfig(new ConventionConfig(
                ConventionConfig.Mode.WARN,
                ConventionConfig.FunctionNamingRules.defaults(),
                ConventionConfig.HungarianRules.defaults(),
                ConventionConfig.GlobalNamingRules.defaults(),
                ConventionConfig.PlateCommentRules.defaults()), "test");
            assertFalse(policy.isStrictNamingEnforcement());
            assertFalse(policy.shouldAutoFixStructFieldPrefixes());
            assertEquals("test", policy.getSource());

            policy.setConfig(ConventionConfig.defaults(), "test");
            assertTrue(policy.isStrictNamingEnforcement());
            assertTrue(policy.shouldAutoFixStructFieldPrefixes());
        } finally {
            policy.setConfig(originalConfig, originalSource);
        }
    }
}
