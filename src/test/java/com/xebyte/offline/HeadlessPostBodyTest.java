package com.xebyte.offline;

import com.xebyte.headless.GhidraMCPHeadlessServer;
import org.junit.Test;

import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * Headless POST bodies keep their values intact. The JSON case was parsed by splitting
 * on commas and colons, so a checkin comment "fix, retry" was cut to "fix".
 */
public class HeadlessPostBodyTest {

    @Test
    public void aCommaInsideAValueSurvives() {
        Map<String, String> p = GhidraMCPHeadlessServer.parsePostBody(
            "{\"path\": \"/fw/a\", \"comment\": \"fix, retry: now\", \"keepCheckedOut\": true}");
        assertEquals("fix, retry: now", p.get("comment"));
        assertEquals("/fw/a", p.get("path"));
        assertEquals("true", p.get("keepCheckedOut"));
    }

    @Test
    public void wholeNumbersDoNotGainADecimalPoint() {
        assertEquals("42", GhidraMCPHeadlessServer.parsePostBody("{\"checkoutId\": 42}").get("checkoutId"));
    }

    @Test
    public void formBodiesAreDecoded() {
        Map<String, String> p = GhidraMCPHeadlessServer.parsePostBody("path=%2Ffw%2Fa&comment=a+b%2C+c");
        assertEquals("/fw/a", p.get("path"));
        assertEquals("a b, c", p.get("comment"));
    }

    @Test
    public void nullsAndEmptyBodiesGiveNoParams() {
        assertTrue(GhidraMCPHeadlessServer.parsePostBody("{\"a\": null}").isEmpty());
        assertTrue(GhidraMCPHeadlessServer.parsePostBody("   ").isEmpty());
        assertTrue(GhidraMCPHeadlessServer.parsePostBody(null).isEmpty());
    }
}
