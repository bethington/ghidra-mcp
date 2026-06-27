package com.xebyte.offline;

import com.xebyte.core.ProgramProvider;
import com.xebyte.core.ProgramScriptService;
import com.xebyte.core.Response;
import com.xebyte.core.ThreadingStrategy;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.OverlayAddressSpace;
import ghidra.program.model.listing.Program;
import org.junit.Test;

import java.util.List;
import java.util.Map;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

/**
 * Verifies that get_address_spaces also lists overlay spaces (marked is_overlay
 * with overlayed_space = the physical base space name), in addition to the
 * physical RAM/CODE spaces. The physical-only buildAddressSpacesList — shared with
 * get_current_program_info's has_multiple_address_spaces flag — must remain
 * unchanged; overlays are appended only in the endpoint method.
 */
public class AddressSpacesOverlayTest {

    private AddressSpace physical(String name, int type) {
        AddressSpace s = mock(AddressSpace.class);
        when(s.isOverlaySpace()).thenReturn(false);
        when(s.getType()).thenReturn(type);
        when(s.getName()).thenReturn(name);
        Address min = mock(Address.class);
        Address max = mock(Address.class);
        when(min.getOffset()).thenReturn(0L);
        when(max.getOffset()).thenReturn(0xffffffffL);
        when(min.toString(false)).thenReturn("00000000");
        when(max.toString(false)).thenReturn("ffffffff");
        when(s.getMinAddress()).thenReturn(min);
        when(s.getMaxAddress()).thenReturn(max);
        when(s.getAddressableUnitSize()).thenReturn(1);
        when(s.getSize()).thenReturn(32);
        return s;
    }

    private OverlayAddressSpace overlay(String name, AddressSpace base) {
        OverlayAddressSpace s = mock(OverlayAddressSpace.class);
        when(s.isOverlaySpace()).thenReturn(true);
        when(s.getName()).thenReturn(name);
        when(s.getOverlayedSpace()).thenReturn(base);
        Address min = mock(Address.class);
        Address max = mock(Address.class);
        when(min.getOffset()).thenReturn(0x10000L);
        when(max.getOffset()).thenReturn(0xaafffL);
        when(min.toString(false)).thenReturn("00010000");
        when(max.toString(false)).thenReturn("000aafff");
        when(s.getMinAddress()).thenReturn(min);
        when(s.getMaxAddress()).thenReturn(max);
        when(s.getAddressableUnitSize()).thenReturn(1);
        when(s.getSize()).thenReturn(32);
        return s;
    }

    @Test
    @SuppressWarnings("unchecked")
    public void getAddressSpaces_includesOverlaysMarked() {
        Program program = mock(Program.class);
        AddressFactory factory = mock(AddressFactory.class);
        AddressSpace ram = physical("ram", AddressSpace.TYPE_RAM);
        // OTHER-backed base space: not RAM/CODE, so it is NOT emitted as a
        // physical entry — but it must still resolve as an overlay's base name.
        AddressSpace other = physical("OTHER", AddressSpace.TYPE_OTHER);
        OverlayAddressSpace ov = overlay("cli.Initial", ram);
        OverlayAddressSpace shstrtab = overlay(".shstrtab", other);
        when(program.getAddressFactory()).thenReturn(factory);
        when(factory.getDefaultAddressSpace()).thenReturn(ram);
        when(factory.getAddressSpaces()).thenReturn(new AddressSpace[]{ram, other, ov, shstrtab});

        // Provider returns the mocked program for an empty (active-program) request.
        ProgramProvider provider = mock(ProgramProvider.class);
        when(provider.getCurrentProgram()).thenReturn(program);
        ThreadingStrategy ts = new NoopThreadingStrategy();

        ProgramScriptService svc = new ProgramScriptService(provider, ts);
        Response resp = svc.getAddressSpaces("");
        assertTrue("expected Response.Ok, got " + resp, resp instanceof Response.Ok);
        Map<String, Object> body = (Map<String, Object>) ((Response.Ok) resp).data();
        List<Map<String, Object>> spaces = (List<Map<String, Object>>) body.get("address_spaces");

        // ram (physical RAM) + cli.Initial (overlay) + .shstrtab (overlay).
        // OTHER is NOT emitted (not RAM/CODE) but backs the .shstrtab overlay.
        assertEquals(3, spaces.size());
        assertEquals(3, body.get("count"));

        Map<String, Object> overlayEntry = spaces.stream()
            .filter(m -> "cli.Initial".equals(m.get("name"))).findFirst().orElse(null);
        assertNotNull("overlay space must be listed", overlayEntry);
        assertEquals(Boolean.TRUE, overlayEntry.get("is_overlay"));
        assertEquals("ram", overlayEntry.get("overlayed_space"));

        // OTHER-backed overlay links to its OTHER base by name.
        Map<String, Object> otherOverlayEntry = spaces.stream()
            .filter(m -> ".shstrtab".equals(m.get("name"))).findFirst().orElse(null);
        assertNotNull("OTHER-backed overlay space must be listed", otherOverlayEntry);
        assertEquals(Boolean.TRUE, otherOverlayEntry.get("is_overlay"));
        assertEquals("OTHER", otherOverlayEntry.get("overlayed_space"));

        // The OTHER base itself is not surfaced as a physical entry.
        assertNull("OTHER base must not be emitted as a physical space",
            spaces.stream().filter(m -> "OTHER".equals(m.get("name"))).findFirst().orElse(null));

        // Physical ram entry is unperturbed by the overlay append AND now carries
        // the symmetric is_overlay=false flag (Fix 1) alongside its size_bytes.
        Map<String, Object> ramEntry = spaces.stream()
            .filter(m -> "ram".equals(m.get("name"))).findFirst().orElse(null);
        assertNotNull(ramEntry);
        assertNotNull("physical entry must retain size_bytes", ramEntry.get("size_bytes"));
        assertEquals(Boolean.FALSE, ramEntry.get("is_overlay"));
    }
}
