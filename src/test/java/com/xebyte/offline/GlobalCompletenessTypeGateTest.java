package com.xebyte.offline;

import com.xebyte.core.DataTypeService;
import junit.framework.TestCase;

/**
 * Pure-logic tests for the global completeness type gate: a global with no
 * real type can never be considered 80% complete.
 *
 * <p>The core axis budget is name(25) + comment(25) + type(20) + bytes(15) =
 * 85, so before the gate an untyped global with a perfect name, plate comment
 * and byte formatting scored exactly 80.0 and banded COMPLETE_80 — claiming
 * "documented" for a value whose width and interpretation are still unknown.
 * These tests pin the ceiling and the band floor together, because the bug is
 * only visible where the two meet.
 */
public class GlobalCompletenessTypeGateTest extends TestCase {

    public void testCeilingSitsBelowTheLowestBandFloor() {
        // The whole point of the gate: capping AT 80 would still band.
        assertTrue(DataTypeService.GLOBAL_UNTYPED_CEILING < 80.0);
        assertNull(DataTypeService.globalBandForScore(DataTypeService.GLOBAL_UNTYPED_CEILING));
    }

    public void testTypedScoresPassThroughUntouched() {
        assertEquals(100.0, DataTypeService.applyGlobalTypeGate(100.0, false));
        assertEquals(80.0, DataTypeService.applyGlobalTypeGate(80.0, false));
        assertEquals(42.0, DataTypeService.applyGlobalTypeGate(42.0, false));
    }

    public void testUntypedIsCappedAtTheCeiling() {
        // 80.0 is the exact score the pre-gate rubric produced for an untyped
        // global that was perfect on every other core axis.
        assertEquals(DataTypeService.GLOBAL_UNTYPED_CEILING,
                DataTypeService.applyGlobalTypeGate(80.0, true));
        assertEquals(DataTypeService.GLOBAL_UNTYPED_CEILING,
                DataTypeService.applyGlobalTypeGate(100.0, true));
    }

    public void testUntypedBelowTheCeilingIsNotInflated() {
        // The gate is a ceiling, not another deduction — a poor untyped global
        // must keep its (lower) score.
        assertEquals(35.0, DataTypeService.applyGlobalTypeGate(35.0, true));
        assertEquals(0.0, DataTypeService.applyGlobalTypeGate(0.0, true));
    }

    public void testNoUntypedScoreCanReachAnyBand() {
        // Sweep the whole 0-100 range: no input, gated as untyped, may band.
        for (int i = 0; i <= 1000; i++) {
            double gated = DataTypeService.applyGlobalTypeGate(i / 10.0, true);
            assertNull("untyped score " + (i / 10.0) + " banded as "
                            + DataTypeService.globalBandForScore(gated),
                    DataTypeService.globalBandForScore(gated));
        }
    }

    public void testBandFloorsAreUnchangedForTypedGlobals() {
        assertEquals("COMPLETE_100", DataTypeService.globalBandForScore(100.0));
        assertEquals("COMPLETE_95", DataTypeService.globalBandForScore(95.0));
        assertEquals("COMPLETE_90", DataTypeService.globalBandForScore(90.0));
        assertEquals("COMPLETE_80", DataTypeService.globalBandForScore(80.0));
        assertNull(DataTypeService.globalBandForScore(79.9));
    }
}
