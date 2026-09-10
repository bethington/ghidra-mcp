package com.xebyte.offline;

import junit.framework.TestCase;

import java.io.IOException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Regression tests for /set_variable_storage (#446).
 *
 * The endpoint shipped for several versions as a NO-OP: it read the current
 * storage, logged the request, set success = true and returned HTTP 200 with
 * {@code "status": "unsupported"}. A caller could not distinguish that from a
 * write that landed, which is the whole defect -- silently reporting success
 * for work never done is strictly worse than refusing.
 *
 * Applying storage needs a live Program (registers, stack space, a function
 * with variables), which does not stand up cheaply in CI, so the wiring half
 * of this uses the same source-assertion idiom as {@link HardeningWiringTest}.
 * The parsing half is exercised directly by reflection.
 */
public class VariableStorageWriteTest extends TestCase {

    private static String functionServiceSource() throws IOException {
        Path p = Paths.get("src", "main", "java", "com", "xebyte", "core", "FunctionService.java");
        return new String(Files.readAllBytes(p), StandardCharsets.UTF_8);
    }

    /** Extract just the setVariableStorage(4-arg) method body. */
    private static String setVariableStorageBody() throws IOException {
        String src = functionServiceSource();
        int start = src.indexOf("public Response setVariableStorage(");
        assertTrue("setVariableStorage(...) not found", start > 0);
        int end = src.indexOf("public Response setVariableStorage(String functionAddrStr", start + 1);
        assertTrue("the 3-arg overload should follow the annotated method", end > start);
        return src.substring(start, end);
    }

    // ---------------------------------------------------------------- wiring

    /**
     * The stub's tell was returning ok() with status "unsupported". If that
     * string comes back to this method, the no-op came back with it.
     */
    public void testDoesNotReportUnsupported() throws IOException {
        String body = setVariableStorageBody();
        assertFalse("set_variable_storage must not answer ok(status=unsupported); "
                        + "it either performs the write or returns an error",
                body.contains("\"unsupported\""));
    }

    /** The write itself: storage is applied through Variable.setDataType. */
    public void testAppliesStorageThroughSetDataType() throws IOException {
        String body = setVariableStorageBody();
        assertTrue("must apply storage via setDataType(type, storage, force, source)",
                body.contains("setDataType(currentType, newStorage, true, SourceType.USER_DEFINED)"));
    }

    /**
     * A parameter's storage is owned by the calling convention until custom
     * storage is enabled; without this the assignment is re-derived from the
     * .cspec and the caller gets the convention's answer, not theirs.
     */
    public void testEnablesCustomStorageForParameters() throws IOException {
        String body = setVariableStorageBody();
        assertTrue("must switch the function to custom variable storage for a parameter",
                body.contains("setCustomVariableStorage(true)"));
        assertTrue("must tell the caller the function-wide mode changed",
                body.contains("custom_storage_enabled"));
    }

    /**
     * The response must quote storage read back off the variable, not the
     * request echoed. Echoing the request is what made the stub look like it
     * worked.
     */
    public void testReadsStorageBackAfterWriting() throws IOException {
        String body = setVariableStorageBody();
        assertTrue("must re-read the variable after writing",
                body.contains("could not be read back after the write"));
        assertTrue("must compare what landed against what was asked for",
                body.contains("Storage did not take"));
    }

    /** Enabling custom storage rebuilds parameters, invalidating the handle. */
    public void testRefetchesVariableAfterEnablingCustomStorage() throws IOException {
        String body = setVariableStorageBody();
        int enable = body.indexOf("setCustomVariableStorage(true)");
        int refetch = body.indexOf("getAllVariables()", enable);
        assertTrue("must look the variable up again after enabling custom storage, "
                        + "because enabling it rebuilds the parameter objects",
                enable > 0 && refetch > enable);
    }

    // --------------------------------------------------------------- parsing

    private static int parseSignedInt(String text) throws Exception {
        Class<?> cls = Class.forName("com.xebyte.core.FunctionService");
        Method m = cls.getDeclaredMethod("parseSignedInt", String.class);
        m.setAccessible(true);
        return (Integer) m.invoke(null, text);
    }

    /**
     * Stack offsets are negative and Ghidra prints them in hex ("Stack[-0x10]").
     * Integer.parseInt cannot read "0x10" at all, so the naive parse would
     * reject the exact form this endpoint's own sibling emits.
     */
    public void testParsesNegativeHexStackOffsets() throws Exception {
        assertEquals(-16, parseSignedInt("-0x10"));
        assertEquals(-16, parseSignedInt("-16"));
        assertEquals(28, parseSignedInt("0x1c"));
        assertEquals(0, parseSignedInt("0"));
        assertEquals(-4, parseSignedInt("  -0x4  "));
    }

    /** A bad offset must raise, not silently resolve to zero. */
    public void testRejectsNonNumericOffset() throws Exception {
        try {
            parseSignedInt("ebp");
            fail("expected InvalidInputException for a non-numeric offset");
        } catch (Exception e) {
            Throwable cause = e.getCause() != null ? e.getCause() : e;
            assertTrue("should name the offending text, got: " + cause.getMessage(),
                    String.valueOf(cause.getMessage()).contains("ebp"));
        }
    }
}
