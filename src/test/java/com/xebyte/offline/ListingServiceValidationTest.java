package com.xebyte.offline;

import com.xebyte.core.ListingService;
import com.xebyte.core.Response;
import junit.framework.TestCase;

/**
 * Coverage for ListingService (previously no behavioral tests). convert_number is a pure
 * utility (no program needed) and is exercised functionally; the program-scoped listers are
 * checked for graceful "No program loaded" degradation.
 */
public class ListingServiceValidationTest extends TestCase {

    private ListingService listing;

    @Override
    protected void setUp() {
        listing = new ListingService(ServiceFactory.stubProvider());
    }

    // --- convert_number: pure utility, works with no program ---

    public void testConvertNumberDecimalProducesHex() {
        Response r = listing.convertNumber("255", 4);
        assertTrue(r instanceof Response.Text);
        String out = ((Response.Text) r).content().toLowerCase();
        assertTrue("expected hex ff in conversion of 255, got: " + out, out.contains("ff"));
    }

    public void testConvertNumberHexInputAccepted() {
        Response r = listing.convertNumber("0x10", 4);
        assertTrue(r instanceof Response.Text);
        String out = ((Response.Text) r).content();
        assertTrue("expected decimal 16 in conversion of 0x10, got: " + out, out.contains("16"));
    }

    public void testConvertNumberEmptyReports() {
        Response r = listing.convertNumber("", 4);
        assertTrue(r instanceof Response.Text);
        assertTrue(((Response.Text) r).content().contains("No number provided"));
    }

    // --- program-scoped listers degrade gracefully with no program ---

    private static void assertNoProgram(Response r) {
        assertNotNull(r);
        assertTrue("expected 'No program loaded', got: " + r.toJson(),
                r.toJson().contains("No program loaded"));
    }

    public void testGetFunctionCountDegradesGracefully() {
        assertNoProgram(listing.getFunctionCount(""));
    }

    public void testSearchStringsDegradesGracefully() {
        assertNoProgram(listing.searchStrings("pattern", 4, "", 0, 100, ""));
    }

    public void testSearchFunctionsByNameDegradesGracefully() {
        assertNoProgram(listing.searchFunctionsByName("Foo", 0, 100, ""));
    }

    public void testListImportsDegradesGracefully() {
        assertNoProgram(listing.listImports(0, 100, ""));
    }
}
