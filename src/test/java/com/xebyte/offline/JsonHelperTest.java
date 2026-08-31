package com.xebyte.offline;

import com.xebyte.core.JsonHelper;
import com.xebyte.core.ServiceUtils;
import junit.framework.TestCase;

import java.util.List;
import java.util.Map;

/**
 * getInt's String branch must tolerate a decimal-suffixed integer, because
 * that is exactly what it is handed by one real, reachable path through this
 * codebase's own JSON plumbing -- not a hypothetical.
 *
 * toMapStringList (both overloads) stringifies every value with
 * String.valueOf(Object). Gson parses JSON numbers as Double, so a JSON `16`
 * becomes Double(16.0), and String.valueOf(16.0) is "16.0". A caller reading
 * that value back with Integer.parseInt (the naive, "obviously correct"
 * choice getInt used before this fix) throws on the decimal point and the
 * exception is swallowed, silently returning the default instead of 16.
 *
 * Found live: EmulationService's read_memory_after, added alongside this
 * fix, took a JSON array field. Sent wrapped as {"regions": [...]} it went
 * through the DIRECT parse path (JsonHelper.parseJson(...).get("regions")),
 * which hands getInt a raw Double -- worked first try. Sent as a bare array
 * (documented as equally valid, and what every other caller of this shape in
 * the codebase does) it went through convertToMapList's STRING fallback,
 * which round-trips every field through toMapStringList first -- and the
 * identical integer field silently became 0. Same endpoint, same value,
 * different wire shape, one of the two silently wrong. That is the failure
 * mode this test exists to keep off this method for good.
 */
public class JsonHelperTest extends TestCase {

    public void testGetIntFromPlainString() {
        assertEquals(16, JsonHelper.getInt("16", 0));
    }

    public void testGetIntFromDouble() {
        assertEquals(16, JsonHelper.getInt(16.0, 0));
    }

    public void testGetIntFromInteger() {
        assertEquals(16, JsonHelper.getInt(16, 0));
    }

    public void testGetIntFromDecimalStringifiedDouble() {
        // The specific shape toMapStringList produces for a JSON integer
        // field reached through the bare-array fallback path.
        assertEquals(16, JsonHelper.getInt("16.0", 0));
    }

    public void testGetIntFromGarbageStringFallsBackToDefault() {
        assertEquals(-1, JsonHelper.getInt("not a number", -1));
    }

    public void testGetIntFromNullFallsBackToDefault() {
        assertEquals(-1, JsonHelper.getInt(null, -1));
    }

    /**
     * The end-to-end reproduction: a bare JSON array containing an integer
     * field, parsed the way ServiceUtils.convertToMapList's String fallback
     * actually parses one, must still hand getInt something it can read.
     */
    public void testBareArrayIntegerFieldSurvivesTheFallbackPath() {
        String json = "[{\"address\": \"0x408300\", \"length\": 16}]";
        List<Map<String, String>> regions = ServiceUtils.convertToMapList(json);
        assertNotNull(regions);
        assertEquals(1, regions.size());
        assertEquals(16, JsonHelper.getInt(regions.get(0).get("length"), 0));
    }
}
