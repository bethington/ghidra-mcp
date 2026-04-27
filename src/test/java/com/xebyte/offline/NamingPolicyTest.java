package com.xebyte.offline;

import com.xebyte.core.NamingPolicy;
import junit.framework.TestCase;

/**
 * Pure-logic tests for the function-name enforcement policy.
 */
public class NamingPolicyTest extends TestCase {

    public void testDefaultPreservesStrictBehavior() {
        assertTrue(NamingPolicy.defaultStrictFunctionNames());
    }

    public void testGlobalSettingCanBeUpdatedAndRestored() {
        NamingPolicy policy = NamingPolicy.getInstance();
        boolean originalValue = policy.isStrictFunctionNames();
        String originalSource = policy.getSource();

        try {
            policy.setStrictFunctionNames(false, "test");
            assertFalse(policy.isStrictFunctionNames());
            assertEquals("test", policy.getSource());

            policy.setStrictFunctionNames(true, "test");
            assertTrue(policy.isStrictFunctionNames());
        } finally {
            policy.setStrictFunctionNames(originalValue, originalSource);
        }
    }
}
