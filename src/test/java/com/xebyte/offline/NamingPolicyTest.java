package com.xebyte.offline;

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
        boolean originalValue = policy.isStrictNamingEnforcement();
        String originalSource = policy.getSource();

        try {
            policy.setStrictNamingEnforcement(false, "test");
            assertFalse(policy.isStrictNamingEnforcement());
            assertFalse(policy.shouldAutoFixStructFieldPrefixes());
            assertEquals("test", policy.getSource());

            policy.setStrictNamingEnforcement(true, "test");
            assertTrue(policy.isStrictNamingEnforcement());
            assertTrue(policy.shouldAutoFixStructFieldPrefixes());
        } finally {
            policy.setStrictNamingEnforcement(originalValue, originalSource);
        }
    }
}
