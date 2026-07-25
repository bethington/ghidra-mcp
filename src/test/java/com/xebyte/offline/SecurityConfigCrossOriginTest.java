package com.xebyte.offline;

import com.xebyte.core.SecurityConfig;
import junit.framework.TestCase;

/**
 * Unit tests for the v5.17 anti-CSRF / DNS-rebinding guard and the
 * prefix-collision-safe project-scope matcher added to {@link SecurityConfig}.
 *
 * <p>The static predicates are pure and env-independent, so they are tested
 * directly. {@code rejectCrossOriginRequest} depends on whether an auth token
 * is configured in the JVM env; those assertions are guarded on
 * {@code !isAuthEnabled()} so the test passes whether or not a developer has
 * {@code GHIDRA_MCP_AUTH_TOKEN} exported (mirrors
 * {@code ProgramScriptServiceValidationTest#testRunScriptInlineGatedByDefault}).
 */
public class SecurityConfigCrossOriginTest extends TestCase {

    // ---- extractHost -----------------------------------------------------

    public void testExtractHostStripsPort() {
        assertEquals("127.0.0.1", SecurityConfig.extractHost("127.0.0.1:8089"));
        assertEquals("localhost", SecurityConfig.extractHost("localhost:5000"));
        assertEquals("evil.com", SecurityConfig.extractHost("evil.com:8089"));
    }

    public void testExtractHostBareHostname() {
        assertEquals("localhost", SecurityConfig.extractHost("localhost"));
        assertEquals("example.org", SecurityConfig.extractHost("EXAMPLE.ORG"));
    }

    public void testExtractHostIpv6Bracketed() {
        assertEquals("::1", SecurityConfig.extractHost("[::1]:8089"));
        assertEquals("::1", SecurityConfig.extractHost("[::1]"));
        assertEquals("fe80::1", SecurityConfig.extractHost("[fe80::1]:443"));
    }

    public void testExtractHostBareIpv6NotSplit() {
        // No brackets, multiple colons -> no port to strip, returned as-is.
        assertEquals("::1", SecurityConfig.extractHost("::1"));
    }

    public void testExtractHostNullEmpty() {
        assertNull(SecurityConfig.extractHost(null));
        assertNull(SecurityConfig.extractHost(""));
        assertNull(SecurityConfig.extractHost("   "));
    }

    // ---- isLoopbackHostHeader -------------------------------------------

    public void testLoopbackHostAccepted() {
        assertTrue(SecurityConfig.isLoopbackHostHeader("127.0.0.1:8089"));
        assertTrue(SecurityConfig.isLoopbackHostHeader("localhost:5000"));
        assertTrue(SecurityConfig.isLoopbackHostHeader("localhost"));
        assertTrue(SecurityConfig.isLoopbackHostHeader("[::1]:8089"));
        assertTrue(SecurityConfig.isLoopbackHostHeader("::1"));
    }

    public void testNonLoopbackHostRejected() {
        assertFalse(SecurityConfig.isLoopbackHostHeader("evil.com"));
        assertFalse(SecurityConfig.isLoopbackHostHeader("attacker.example:8089"));
        assertFalse(SecurityConfig.isLoopbackHostHeader("192.168.1.50:8089"));
        assertFalse(SecurityConfig.isLoopbackHostHeader("10.0.0.5"));
        // A hostname that merely contains "localhost" must not pass.
        assertFalse(SecurityConfig.isLoopbackHostHeader("localhost.evil.com"));
        assertFalse(SecurityConfig.isLoopbackHostHeader(null));
    }

    // ---- isLoopbackOriginHeader -----------------------------------------

    public void testLoopbackOriginAccepted() {
        assertTrue(SecurityConfig.isLoopbackOriginHeader("http://127.0.0.1:8089"));
        assertTrue(SecurityConfig.isLoopbackOriginHeader("http://localhost:5000"));
        assertTrue(SecurityConfig.isLoopbackOriginHeader("https://[::1]:8443"));
    }

    public void testNonLoopbackOriginRejected() {
        assertFalse(SecurityConfig.isLoopbackOriginHeader("http://evil.com"));
        assertFalse(SecurityConfig.isLoopbackOriginHeader("https://attacker.example:443"));
        // Opaque origin (sandboxed iframe / file://) is NOT loopback.
        assertFalse(SecurityConfig.isLoopbackOriginHeader("null"));
        assertFalse(SecurityConfig.isLoopbackOriginHeader("NULL"));
        assertFalse(SecurityConfig.isLoopbackOriginHeader(null));
        assertFalse(SecurityConfig.isLoopbackOriginHeader(""));
        // Prefix-collision attempt.
        assertFalse(SecurityConfig.isLoopbackOriginHeader("http://localhost.evil.com"));
    }

    // ---- rejectCrossOriginRequest (default no-token env) -----------------

    public void testCrossOriginGuardAllowsLoopback() {
        SecurityConfig sec = SecurityConfig.getInstance();
        if (sec.isAuthEnabled()) return;  // token set: guard is intentionally disabled
        assertNull(sec.rejectCrossOriginRequest("127.0.0.1:8089", null));
        assertNull(sec.rejectCrossOriginRequest("localhost:8089", "http://localhost:8089"));
        // Non-browser CLI client: no Host, no Origin.
        assertNull(sec.rejectCrossOriginRequest(null, null));
    }

    public void testCrossOriginGuardRejectsHostileOrigin() {
        SecurityConfig sec = SecurityConfig.getInstance();
        if (sec.isAuthEnabled()) return;
        // Classic CSRF: page on evil.com fetches 127.0.0.1 (Host looks loopback).
        assertNotNull(sec.rejectCrossOriginRequest("127.0.0.1:8089", "http://evil.com"));
    }

    public void testCrossOriginGuardRejectsRebindHost() {
        SecurityConfig sec = SecurityConfig.getInstance();
        if (sec.isAuthEnabled()) return;
        // DNS rebinding: attacker hostname resolves to 127.0.0.1, so Host is
        // the attacker domain.
        assertNotNull(sec.rejectCrossOriginRequest("attacker.example:8089", null));
    }

    // ---- pathWithinScope (prefix-collision safety) -----------------------

    public void testPathWithinScopeUnsetIsAllowAll() {
        assertTrue(SecurityConfig.pathWithinScope("/anything/at/all", null));
        assertTrue(SecurityConfig.pathWithinScope(null, null));
    }

    public void testPathWithinScopeExactAndChild() {
        assertTrue(SecurityConfig.pathWithinScope("/Mods/PD2-S12", "/Mods/PD2-S12"));
        assertTrue(SecurityConfig.pathWithinScope("/Mods/PD2-S12/Bnclient.dll", "/Mods/PD2-S12"));
    }

    public void testPathWithinScopeRejectsPrefixCollision() {
        // The whole point: a sibling that shares a string prefix must NOT match.
        assertFalse(SecurityConfig.pathWithinScope("/Mods/PD2-S12-OTHER/x.dll", "/Mods/PD2-S12"));
        assertFalse(SecurityConfig.pathWithinScope("/Vanilla/1.00/D2Common.dll", "/Mods/PD2-S12"));
    }
}
