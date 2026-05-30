package com.xebyte.core;

import junit.framework.TestCase;

/**
 * Unit tests for struct resize helpers and demangler placeholder detection.
 */
public class DataTypeServiceStructResizeTest extends TestCase {

    public void testIsDemanglerPlaceholderRequiresDemanglerPathAndSizeOne() {
        assertTrue(DataTypeService.isDemanglerPlaceholder(1, "/Demangler/Foo"));
        assertFalse(DataTypeService.isDemanglerPlaceholder(1, "/Types/Foo"));
        assertFalse(DataTypeService.isDemanglerPlaceholder(4, "/Demangler/Foo"));
        assertFalse(DataTypeService.isDemanglerPlaceholder(1, null));
    }

    public void testValidateStructResizeAllowsGrow() {
        assertNull(DataTypeService.validateStructResize(120, "TestStruct", 240, false));
    }

    public void testValidateStructResizeRejectsShrinkWithoutForce() {
        String err = DataTypeService.validateStructResize(120, "TestStruct", 64, false);
        assertNotNull(err);
        assertTrue(err.contains("Cannot shrink"));
        assertTrue(err.contains("120"));
        assertTrue(err.contains("recreate_struct"));
    }

    public void testValidateStructResizeAllowsShrinkWithForce() {
        assertNull(DataTypeService.validateStructResize(120, "TestStruct", 64, true));
    }

    public void testValidateStructResizeRejectsNonPositiveSize() {
        String err = DataTypeService.validateStructResize(8, "TestStruct", 0, true);
        assertNotNull(err);
        assertTrue(err.contains("positive"));
    }
}
