package com.xebyte.offline;

import com.xebyte.core.ProgramProvider;
import com.xebyte.core.ProgramScriptService;
import com.xebyte.core.Response;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.ProgramBasedDataTypeManager;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.SymbolTable;
import junit.framework.TestCase;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Map;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * {@code /get_ui_cursor} replaces the four former current-* tools. Headless
 * has no GUI cursor — those facets report null + reason without failing the
 * whole {@code type=all} call; {@code type=program} still resolves.
 */
public class GetUiCursorEndpointTest extends TestCase {

    private static Program named(String name) {
        Program p = mock(Program.class);
        when(p.getName()).thenReturn(name);
        DomainFile df = mock(DomainFile.class);
        when(df.getPathname()).thenReturn("/" + name);
        when(p.getDomainFile()).thenReturn(df);
        when(p.getExecutablePath()).thenReturn("");
        when(p.getExecutableFormat()).thenReturn("ELF");
        when(p.getLanguageID()).thenReturn(new LanguageID("x86:LE:64:default"));
        CompilerSpec cs = mock(CompilerSpec.class);
        when(cs.getCompilerSpecID()).thenReturn(new CompilerSpecID("gcc"));
        when(p.getCompilerSpec()).thenReturn(cs);
        AddressFactory af = mock(AddressFactory.class);
        AddressSpace space = mock(AddressSpace.class);
        when(space.getSize()).thenReturn(64);
        when(space.isOverlaySpace()).thenReturn(false);
        when(af.getDefaultAddressSpace()).thenReturn(space);
        when(af.getAddressSpaces()).thenReturn(new AddressSpace[]{space});
        when(p.getAddressFactory()).thenReturn(af);
        Address base = mock(Address.class);
        when(base.toString()).thenReturn("00100000");
        when(p.getImageBase()).thenReturn(base);
        when(p.getMinAddress()).thenReturn(base);
        when(p.getMaxAddress()).thenReturn(base);
        Memory mem = mock(Memory.class);
        when(mem.getSize()).thenReturn(0x1000L);
        when(mem.getBlocks()).thenReturn(new ghidra.program.model.mem.MemoryBlock[0]);
        when(p.getMemory()).thenReturn(mem);
        FunctionManager fm = mock(FunctionManager.class);
        when(fm.getFunctionCount()).thenReturn(10);
        when(p.getFunctionManager()).thenReturn(fm);
        SymbolTable st = mock(SymbolTable.class);
        when(st.getNumSymbols()).thenReturn(20);
        when(p.getSymbolTable()).thenReturn(st);
        ProgramBasedDataTypeManager dtm = mock(ProgramBasedDataTypeManager.class);
        when(dtm.getDataTypeCount(true)).thenReturn(5);
        when(p.getDataTypeManager()).thenReturn(dtm);
        when(p.getCreationDate()).thenReturn(null);
        return p;
    }

    private static ProgramProvider mockProvider(Program current, Program... open) {
        ProgramProvider provider = mock(ProgramProvider.class);
        when(provider.getCurrentProgram()).thenReturn(current);
        when(provider.getAllOpenPrograms()).thenReturn(open);
        for (Program p : open) {
            when(provider.getProgram(p.getName())).thenReturn(p);
        }
        return provider;
    }

    public void testTypeProgramHeadlessReportsUnavailable() {
        // The focused program is DERIVED from the cursor, so with no GUI there is
        // no answer. It must not fall back to the sole open program: "which
        // program is focused" and "which program should I default to" are
        // different questions, and answering the second while asked the first is
        // how a caller ends up trusting the wrong program's data.
        Program a = named("alpha.dll");
        ProgramScriptService svc = new ProgramScriptService(
                mockProvider(a, a), new NoopThreadingStrategy());
        Response resp = svc.getUiCursor("program");
        assertTrue("headless has no focused program: " + resp, resp instanceof Response.Err);
        assertTrue(((Response.Err) resp).message().contains("Headless"));
    }

    public void testTypeAddressHeadlessReportsError() {
        Program a = named("alpha.dll");
        ProgramScriptService svc = new ProgramScriptService(
                mockProvider(a, a), new NoopThreadingStrategy());
        Response resp = svc.getUiCursor("address");
        assertTrue(resp instanceof Response.Err);
        assertTrue(((Response.Err) resp).message().contains("Headless"));
    }

    public void testTypeAllKeepsUnavailableFacetsNullWithReason() {
        Program a = named("alpha.dll");
        ProgramScriptService svc = new ProgramScriptService(
                mockProvider(a, a), new NoopThreadingStrategy());
        Response resp = svc.getUiCursor("all");
        assertTrue("type=all must not fail the whole call: " + resp, resp instanceof Response.Ok);
        @SuppressWarnings("unchecked")
        Map<String, Object> body = (Map<String, Object>) ((Response.Ok) resp).data();
        assertNull(body.get("address"));
        assertNotNull(body.get("address_unavailable"));
        assertNull(body.get("function"));
        assertNotNull(body.get("function_unavailable"));
        assertNull(body.get("selection"));
        assertNotNull(body.get("selection_unavailable"));
        assertNull(body.get("program"));
        assertNotNull(body.get("program_unavailable"));
    }

    public void testEachTypeAccepted() {
        Program a = named("alpha.dll");
        ProgramScriptService svc = new ProgramScriptService(
                mockProvider(a, a), new NoopThreadingStrategy());
        for (String type : new String[]{"address", "function", "selection", "program", "all", ""}) {
            Response resp = svc.getUiCursor(type);
            assertNotNull("type=" + type, resp);
            if ("all".equals(type) || type.isEmpty()) {
                assertTrue("type=" + type + " should succeed: " + resp, resp instanceof Response.Ok);
            }
        }
    }

    public void testRemovedEndpointsGoneFromSourceAndCatalog() throws IOException {
        String plugin = ProjectSource.readMainSource("GhidraMCPPlugin.java");
        String catalog = ProjectSource.readProjectFile("tests/endpoints.json");
        String service = ProjectSource.readMainSource("core", "ProgramScriptService.java");
        for (String gone : new String[]{
                "/get_current_address",
                "/get_current_function",
                "/get_current_selection",
                "/get_current_program_info"}) {
            assertFalse("plugin must not register " + gone, plugin.contains("\"" + gone + "\""));
            assertFalse("catalog must not list " + gone, catalog.contains("\"path\": \"" + gone + "\""));
        }
        assertTrue("ProgramScriptService must declare /get_ui_cursor",
                service.contains("path = \"/get_ui_cursor\""));
        assertTrue("catalog must list /get_ui_cursor",
                catalog.contains("\"path\": \"/get_ui_cursor\""));
    }
}
