package com.xebyte.offline;

import com.xebyte.core.ListingService;
import com.xebyte.core.ProgramProvider;
import com.xebyte.core.Response;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.ExternalLocationIterator;
import ghidra.program.model.symbol.ExternalManager;
import junit.framework.TestCase;

import java.util.List;
import java.util.Map;

import static org.mockito.Mockito.*;

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

    @SuppressWarnings("unchecked")
    public void testListExternalLocationsHandlesNullExternalAddress() {
        Program program = mock(Program.class);
        ExternalManager extMgr = mock(ExternalManager.class);
        ExternalLocation loc = mock(ExternalLocation.class);
        ExternalLocationIterator iter = mock(ExternalLocationIterator.class);
        ProgramProvider provider = mock(ProgramProvider.class);

        when(provider.getCurrentProgram()).thenReturn(program);
        when(program.getExternalManager()).thenReturn(extMgr);
        when(extMgr.getExternalLibraryNames()).thenReturn(new String[]{"liblog.so"});
        when(extMgr.getExternalLocations("liblog.so")).thenReturn(iter);
        when(iter.hasNext()).thenReturn(true, false);
        when(iter.next()).thenReturn(loc);
        when(loc.getLabel()).thenReturn("__android_log_write");
        when(loc.getAddress()).thenReturn(null);
        when(loc.getOriginalImportedName()).thenReturn("__android_log_write");

        ListingService svc = new ListingService(provider);
        Response r = svc.listExternalLocations(0, 10, "");

        assertTrue(r instanceof Response.Ok);
        List<Map<String, Object>> data = (List<Map<String, Object>>) ((Response.Ok) r).data();
        assertEquals(1, data.size());
        assertEquals("liblog.so", data.get(0).get("library"));
        assertEquals("__android_log_write", data.get(0).get("name"));
        assertTrue(data.get(0).containsKey("address"));
        assertNull(data.get(0).get("address"));
    }
}
