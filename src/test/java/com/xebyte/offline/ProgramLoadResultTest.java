package com.xebyte.offline;

import com.xebyte.headless.HeadlessProgramProvider.ProgramLoadResult;
import com.xebyte.headless.HeadlessProgramProvider.ServerBindingInfo;
import junit.framework.TestCase;

import java.util.Arrays;
import java.util.Collections;

/**
 * Unit tests for the structured diagnostic value classes added for
 * discussion #119 (headless + server-checkout open path).
 *
 * The full {@code loadProgramFromProjectDetailed} path needs a real Ghidra
 * Project to exercise, but the failure-result builders + server-binding
 * info are pure data and can be regressed offline. These tests pin the
 * shape so the endpoint response stays a contract the operator can rely
 * on — without them, a typo in {@code notFound()}'s message format would
 * break every error path's diagnostic without anyone noticing.
 */
public class ProgramLoadResultTest extends TestCase {

    // -------------------------------------------------------------------
    // ProgramLoadResult.success
    // -------------------------------------------------------------------

    public void testSuccessHasNoErrorAndCarriesProgram() {
        ProgramLoadResult r = ProgramLoadResult.success(null);  // null is ok for shape test
        assertTrue("success flag", r.success);
        assertNull("error must be null on success", r.error);
        assertNull("availablePaths null on success", r.availablePaths);
        assertNull("serverHint null on success", r.serverHint);
    }

    // -------------------------------------------------------------------
    // ProgramLoadResult.failure
    // -------------------------------------------------------------------

    public void testFailureCarriesErrorOnly() {
        ProgramLoadResult r = ProgramLoadResult.failure("boom");
        assertFalse("success flag false", r.success);
        assertNull("program null on failure", r.program);
        assertEquals("error stored verbatim", "boom", r.error);
        assertNull("availablePaths absent for generic failure", r.availablePaths);
        assertNull("serverHint absent for generic failure", r.serverHint);
    }

    // -------------------------------------------------------------------
    // ProgramLoadResult.notFound
    // -------------------------------------------------------------------

    public void testNotFoundMentionsRequestedPath() {
        ProgramLoadResult r = ProgramLoadResult.notFound(
            "/Vanilla/1.13d/D2Common.dll",
            Collections.emptyList(),
            null);
        assertFalse(r.success);
        assertTrue("error mentions requested path",
            r.error.contains("/Vanilla/1.13d/D2Common.dll"));
        assertTrue("error mentions empty-project case",
            r.error.contains("no program files"));
    }

    public void testNotFoundPreviewsFirstFiveAvailable() {
        ProgramLoadResult r = ProgramLoadResult.notFound(
            "/wrong/path",
            Arrays.asList(
                "/a/1.dll", "/a/2.dll", "/a/3.dll", "/a/4.dll", "/a/5.dll",
                "/a/6.dll", "/a/7.dll"
            ),
            null);
        assertFalse(r.success);
        // Total count surfaced
        assertTrue("count surfaced", r.error.contains("7 program file"));
        // First five included
        assertTrue("preview shows first available", r.error.contains("/a/1.dll"));
        assertTrue("preview shows fifth available", r.error.contains("/a/5.dll"));
        // Sixth NOT shown — preview capped at 5
        assertFalse("preview caps at five", r.error.contains("/a/6.dll"));
    }

    public void testNotFoundUnderFivePreviewsAll() {
        ProgramLoadResult r = ProgramLoadResult.notFound(
            "/wrong/path",
            Arrays.asList("/a/1.dll", "/a/2.dll"),
            null);
        assertTrue("count surfaced", r.error.contains("2 program file"));
        assertTrue("preview shows /a/1.dll", r.error.contains("/a/1.dll"));
        assertTrue("preview shows /a/2.dll", r.error.contains("/a/2.dll"));
    }

    public void testNotFoundCarriesAvailablePaths() {
        ProgramLoadResult r = ProgramLoadResult.notFound(
            "/wrong/path",
            Arrays.asList("/a/1.dll", "/a/2.dll"),
            "some hint");
        assertEquals("availablePaths preserved as-is", 2, r.availablePaths.size());
        assertEquals("/a/1.dll", r.availablePaths.get(0));
        assertEquals("serverHint preserved", "some hint", r.serverHint);
    }

    public void testNotFoundHandlesNullAvailableList() {
        // Edge case: collectProgramPaths threw and we passed null.
        // Shouldn't NPE in the formatter.
        ProgramLoadResult r = ProgramLoadResult.notFound(
            "/wrong/path",
            null,
            null);
        assertFalse(r.success);
        assertNotNull("error always populated", r.error);
        assertTrue(r.error.contains("/wrong/path"));
        // No paths case — neither "no program files" nor "contains N program"
        // should appear (it's the "no available list at all" branch).
        assertFalse(r.error.contains("no program files"));
        assertFalse(r.error.contains("program file(s)"));
    }

    // -------------------------------------------------------------------
    // ServerBindingInfo
    // -------------------------------------------------------------------

    public void testServerBindingInfoBound() {
        ServerBindingInfo b = new ServerBindingInfo(true, "10.0.10.30:13100", "diablo2");
        assertTrue(b.serverBound);
        assertEquals("10.0.10.30:13100", b.serverInfo);
        assertEquals("diablo2", b.repoName);
    }

    public void testServerBindingInfoUnbound() {
        ServerBindingInfo b = new ServerBindingInfo(false, null, null);
        assertFalse(b.serverBound);
        assertNull(b.serverInfo);
        assertNull(b.repoName);
    }
}
