package com.xebyte.core;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import junit.framework.TestCase;

/** Count parsing at the HTTP JSON boundary, without constructing a Ghidra program. */
public class ArrayClassificationCountTest extends TestCase {

    @SuppressWarnings("unchecked")
    private Map<String, Object> definition(String literal) {
        String json = "{\"type_definition\":{\"element_type\":\"byte\",\"count\":" + literal + "}}";
        Map<String, Object> body = JsonHelper.parseBody(
            new ByteArrayInputStream(json.getBytes(StandardCharsets.UTF_8)));
        return (Map<String, Object>) body.get("type_definition");
    }

    public void testHttpNumericCountIsNotReplacedWithOne() {
        Map<String, Object> def = definition("64");
        assertTrue(def.get("count") instanceof Double);
        assertEquals(64, DataTypeService.arrayClassificationCount(def));
    }

    public void testStringAndIntegerCountsRemainSupported() {
        assertEquals(64, DataTypeService.arrayClassificationCount(definition("\"64\"")));
        assertEquals(64, DataTypeService.arrayClassificationCount(Map.of("count", 64)));
    }

    public void testNonpositiveHttpCountsAreRejected() {
        for (String literal : new String[] {"0", "-2"}) {
            try {
                DataTypeService.arrayClassificationCount(definition(literal));
                fail("Nonpositive JSON count must be rejected: " + literal);
            } catch (IllegalArgumentException expected) {
                assertTrue(expected.getMessage().contains("must be positive"));
            }
        }
    }

    public void testMissingCountIsRejected() {
        try {
            DataTypeService.arrayClassificationCount(Map.of());
            fail("Missing count must be rejected");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().contains("must contain 'count'"));
        }
    }
}
