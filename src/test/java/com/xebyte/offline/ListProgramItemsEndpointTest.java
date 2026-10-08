package com.xebyte.offline;

import com.xebyte.core.ListingService;
import com.xebyte.core.ProgramProvider;
import com.xebyte.core.Response;
import com.xebyte.core.ServiceUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.ExternalLocationIterator;
import ghidra.program.model.symbol.ExternalManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import junit.framework.TestCase;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * {@code /list_program_items} replaces eight listing tools that returned eight
 * different top-level keys for the same pagination envelope.
 */
public class ListProgramItemsEndpointTest extends TestCase {

    private ListingService listing;

    @Override
    protected void setUp() {
        listing = new ListingService(ServiceFactory.stubProvider());
    }

    private static void assertNoProgram(Response r) {
        assertNotNull(r);
        assertTrue("expected 'No program loaded', got: " + r.toJson(),
                r.toJson().contains("No program loaded"));
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> okData(Response r) {
        assertTrue("expected Ok: " + r, r instanceof Response.Ok);
        return (Map<String, Object>) ((Response.Ok) r).data();
    }

    public void testMissingKindErrors() {
        Program program = mock(Program.class);
        ProgramProvider provider = mock(ProgramProvider.class);
        when(provider.getCurrentProgram()).thenReturn(program);
        ListingService svc = new ListingService(provider);
        Response r = svc.listProgramItems("", 0, 10, "");
        assertTrue(r instanceof Response.Err);
        assertTrue(((Response.Err) r).message().contains("kind parameter is required"));
    }

    public void testUnknownKindListsValidOnes() {
        Program program = mock(Program.class);
        ProgramProvider provider = mock(ProgramProvider.class);
        when(provider.getCurrentProgram()).thenReturn(program);
        ListingService svc = new ListingService(provider);
        Response r = svc.listProgramItems("libraries", 0, 10, "");
        assertTrue(r instanceof Response.Err);
        String msg = ((Response.Err) r).message();
        assertTrue(msg.contains("Unknown kind"));
        assertTrue(msg.contains("classes"));
        assertTrue(msg.contains("external_locations"));
    }

    public void testDegradesGracefullyWithNoProgram() {
        assertNoProgram(listing.listProgramItems("segments", 0, 10, ""));
    }

    public void testSegmentsShapeAndPagination() {
        Program program = mock(Program.class);
        Memory mem = mock(Memory.class);
        MemoryBlock block = mock(MemoryBlock.class);
        Address start = mock(Address.class);
        Address end = mock(Address.class);
        ProgramProvider provider = mock(ProgramProvider.class);

        when(provider.getCurrentProgram()).thenReturn(program);
        when(program.getMemory()).thenReturn(mem);
        when(mem.getBlocks()).thenReturn(new MemoryBlock[] { block });
        when(block.getName()).thenReturn(".text");
        when(block.getStart()).thenReturn(start);
        when(block.getEnd()).thenReturn(end);
        when(start.toString(false)).thenReturn("401000");
        when(end.toString(false)).thenReturn("402000");
        when(block.getSize()).thenReturn(0x1000L);
        when(block.isRead()).thenReturn(true);
        when(block.isWrite()).thenReturn(false);
        when(block.isExecute()).thenReturn(true);
        when(block.isInitialized()).thenReturn(true);

        ListingService svc = new ListingService(provider);
        Map<String, Object> page0 = okData(svc.listProgramItems("segments", 0, 1, ""));
        assertEquals("segments", page0.get("kind"));
        assertEquals(1, page0.get("total"));
        assertEquals(1, page0.get("count"));
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> items = (List<Map<String, Object>>) page0.get("items");
        assertEquals(1, items.size());
        assertEquals(".text", items.get(0).get("name"));
        assertTrue(items.get(0).containsKey("readable"));
        assertTrue(items.get(0).containsKey("executable"));

        Map<String, Object> page1 = okData(svc.listProgramItems("segments", 1, 1, ""));
        assertEquals(0, page1.get("count"));
        @SuppressWarnings("unchecked")
        List<?> empty = (List<?>) page1.get("items");
        assertTrue(empty.isEmpty());
    }

    public void testExternalLocationsNullAddress() {
        Program program = mock(Program.class);
        ExternalManager extMgr = mock(ExternalManager.class);
        ExternalLocation loc = mock(ExternalLocation.class);
        ExternalLocationIterator iter = mock(ExternalLocationIterator.class);
        ProgramProvider provider = mock(ProgramProvider.class);

        when(provider.getCurrentProgram()).thenReturn(program);
        when(program.getExternalManager()).thenReturn(extMgr);
        when(extMgr.getExternalLibraryNames()).thenReturn(new String[] { "liblog.so" });
        when(extMgr.getExternalLocations("liblog.so")).thenReturn(iter);
        when(iter.hasNext()).thenReturn(true, false);
        when(iter.next()).thenReturn(loc);
        when(loc.getLabel()).thenReturn("__android_log_write");
        when(loc.getAddress()).thenReturn(null);
        when(loc.getOriginalImportedName()).thenReturn("__android_log_write");

        ListingService svc = new ListingService(provider);
        Map<String, Object> data = okData(svc.listProgramItems("external_locations", 0, 10, ""));
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> items = (List<Map<String, Object>>) data.get("items");
        assertEquals(1, items.size());
        assertEquals("liblog.so", items.get(0).get("library"));
        assertNull(items.get(0).get("address"));
    }

    public void testAllDocumentedKindsPassValidation() {
        for (String kind : List.of("classes", "methods", "namespaces", "imports", "exports",
                "segments", "data_items", "external_locations")) {
            Response r = listing.listProgramItems(kind, 0, 10, "");
            // Reaching program resolution (not "Unknown kind") proves the switch accepted it.
            assertNoProgram(r);
        }
    }

    public void testRemovedEndpointsGoneFromSourceAndCatalog() throws IOException {
        String listing = ProjectSource.readMainSource("core", "ListingService.java");
        String catalog = ProjectSource.readProjectFile("tests/endpoints.json");
        for (String gone : new String[] {
                "/list_classes",
                "/list_methods",
                "/list_namespaces",
                "/list_imports",
                "/list_exports",
                "/list_segments",
                "/list_data_items",
                "/list_external_locations" }) {
            assertFalse("ListingService must not register " + gone,
                    listing.contains("path = \"" + gone + "\""));
            assertFalse("catalog must not list " + gone,
                    catalog.contains("\"path\": \"" + gone + "\""));
        }
        assertTrue("ListingService must declare /list_program_items",
                listing.contains("path = \"/list_program_items\""));
        assertTrue("catalog must list /list_program_items",
                catalog.contains("\"path\": \"/list_program_items\""));
    }
}
