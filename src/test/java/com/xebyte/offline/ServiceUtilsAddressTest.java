package com.xebyte.offline;

import com.xebyte.core.ServiceUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import org.junit.Before;
import org.junit.Test;

import java.util.List;
import java.util.Map;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class ServiceUtilsAddressTest {

    private Program program;
    private AddressFactory factory;
    private AddressSpace ramSpace;
    private AddressSpace codeSpace;
    private Address mockAddr;

    @Before
    public void setUp() {
        program = mock(Program.class);
        factory = mock(AddressFactory.class);
        ramSpace = mock(AddressSpace.class);
        codeSpace = mock(AddressSpace.class);
        mockAddr = mock(Address.class);

        when(program.getAddressFactory()).thenReturn(factory);

        // ram space: TYPE_RAM, not overlay, is default
        when(ramSpace.getType()).thenReturn(AddressSpace.TYPE_RAM);
        when(ramSpace.isOverlaySpace()).thenReturn(false);
        when(ramSpace.getName()).thenReturn("ram");

        // code space: TYPE_CODE, not overlay
        when(codeSpace.getType()).thenReturn(AddressSpace.TYPE_CODE);
        when(codeSpace.isOverlaySpace()).thenReturn(false);
        when(codeSpace.getName()).thenReturn("code");

        when(factory.getAddressSpaces()).thenReturn(new AddressSpace[]{ramSpace, codeSpace});
        when(factory.getDefaultAddressSpace()).thenReturn(ramSpace);

        // Mock address behaviour
        when(mockAddr.toString(false)).thenReturn("00001000");
        when(mockAddr.toString()).thenReturn("ram:00001000");
        when(mockAddr.getAddressSpace()).thenReturn(ramSpace);
    }

    // --- parseAddress ---

    @Test
    public void parseAddress_plainHex_resolvesToDefault() {
        when(factory.getAddress("0x1000")).thenReturn(mockAddr);
        Address result = ServiceUtils.parseAddress(program, "0x1000");
        assertNotNull(result);
        assertNull(ServiceUtils.getLastParseError());
    }

    @Test
    public void parseAddress_segmentOffset_resolvesToNamedSpace() {
        Address codeAddr = mock(Address.class);
        when(codeAddr.getAddressSpace()).thenReturn(codeSpace);
        when(factory.getAddress("code:1000")).thenReturn(codeAddr);
        Address result = ServiceUtils.parseAddress(program, "code:1000");
        assertNotNull(result);
        assertEquals(codeSpace, result.getAddressSpace());
    }

    @Test
    public void parseAddress_unknownSpace_returnsNullWithHelpfulError() {
        when(factory.getAddress("foo:1000")).thenReturn(null);
        Address result = ServiceUtils.parseAddress(program, "foo:1000");
        assertNull(result);
        String err = ServiceUtils.getLastParseError();
        assertNotNull(err);
        assertTrue("Error should mention unknown space name", err.contains("foo"));
        assertTrue("Error should list available spaces", err.contains("ram") && err.contains("code"));
    }

    @Test
    public void parseAddress_semicolonDelimitedList_failsFastWithHint() {
        // Workers sometimes cram several addresses into the singular `address` field,
        // semicolon-joined, when they meant to use the batch-comments inner lists.
        Address result = ServiceUtils.parseAddress(program,
                "10020295;100202af;100202c4;100202ca");
        assertNull(result);
        String err = ServiceUtils.getLastParseError();
        assertNotNull(err);
        assertTrue("Should explain it's not a single location: " + err,
                err.contains("single location") || err.contains("not a list"));
        assertTrue("Should point at the batch-comments inner lists: " + err,
                err.contains("decompiler_comments") && err.contains("disassembly_comments"));
        // Must NOT have tried (and failed) to resolve it as one address.
        assertFalse("Should not emit the misleading space-suggestion error: " + err,
                err.contains("Try <space>:<hex>"));
    }

    @Test
    public void parseAddress_spacePrefixedList_failsFastNotUnknownSpace() {
        // Regression for the reported two-error loop: after the first error suggested
        // prepending the space, the retry "ram:..;ram:.." produced the contradictory
        // "Unknown address space 'ram'. Available: ram". It must now fail fast as a list.
        Address result = ServiceUtils.parseAddress(program,
                "ram:10020295;ram:100202af;ram:100202c4");
        assertNull(result);
        String err = ServiceUtils.getLastParseError();
        assertNotNull(err);
        assertTrue("Should be the list hint: " + err,
                err.contains("single location") || err.contains("not a list"));
        assertFalse("Must not contradict itself with Unknown address space: " + err,
                err.contains("Unknown address space"));
    }

    @Test
    public void parseAddress_knownSpaceBadOffset_blamesOffsetNotSpace() {
        // "ram:zzzz": ram IS a valid space, so the failure is the offset. The error must
        // not claim the space is unknown (the old contradictory message).
        when(factory.getAddress("ram:zzzz")).thenReturn(null);
        Address result = ServiceUtils.parseAddress(program, "ram:zzzz");
        assertNull(result);
        String err = ServiceUtils.getLastParseError();
        assertNotNull(err);
        assertTrue("Should blame the offset: " + err, err.contains("Could not resolve offset"));
        assertTrue("Should name the valid space: " + err, err.contains("ram"));
        assertFalse("Must not call a valid space unknown: " + err,
                err.contains("Unknown address space"));
    }

    @Test
    public void parseAddress_outOfRangePlainHex_returnsNullWithSuggestion() {
        when(factory.getAddress("0xfffffffff")).thenReturn(null);
        Address result = ServiceUtils.parseAddress(program, "0xfffffffff");
        assertNull(result);
        String err = ServiceUtils.getLastParseError();
        assertNotNull(err);
        assertTrue("Error should suggest space:offset format", err.contains(":"));
    }

    @Test
    public void parseAddress_unmappedButValidAddress_returnsNonNull() {
        // parseAddress does NOT check Memory.contains() — that's the caller's job
        Address unmappedAddr = mock(Address.class);
        when(factory.getAddress("0x9999")).thenReturn(unmappedAddr);
        Address result = ServiceUtils.parseAddress(program, "0x9999");
        assertNotNull("parseAddress must return non-null for factory-valid addresses", result);
    }

    @Test
    public void parseAddress_uppercaseSpaceWithHex_normalizesAndResolves() {
        // Batch endpoints pass raw user input like "MEM:1000" bypassing bridge sanitization.
        // parseAddress must lowercase the space name before calling AddressFactory.
        when(factory.getAddress("mem:1000")).thenReturn(mockAddr);
        Address result = ServiceUtils.parseAddress(program, "MEM:1000");
        assertNotNull("Uppercase space name must be normalized to lowercase", result);
        assertNull(ServiceUtils.getLastParseError());
    }

    @Test
    public void parseAddress_uppercaseSpaceWith0xOffset_stripsPrefix() {
        // Input like "MEM:0x1000" must become "mem:1000" before hitting AddressFactory.
        when(factory.getAddress("mem:1000")).thenReturn(mockAddr);
        Address result = ServiceUtils.parseAddress(program, "MEM:0x1000");
        assertNotNull("0x prefix in space:offset form must be stripped", result);
        assertNull(ServiceUtils.getLastParseError());
    }

    @Test
    public void parseAddress_lowercase0XVariant_stripsPrefix() {
        // "0X" (uppercase X) must also be stripped.
        when(factory.getAddress("code:FF00")).thenReturn(mockAddr);
        Address result = ServiceUtils.parseAddress(program, "Code:0XFF00");
        assertNotNull("0X (uppercase X) prefix must also be stripped", result);
        assertNull(ServiceUtils.getLastParseError());
    }

    @Test
    public void convertToMapList_acceptsStringifiedArrayPayload() {
        List<Map<String, String>> result = ServiceUtils.convertToMapList(
            "[{\"address\":\"0x401000\",\"comment\":\"alpha\"},{\"address\":\"0x401004\",\"comment\":\"beta\"}]"
        );

        assertNotNull(result);
        assertEquals(2, result.size());
        assertEquals("0x401000", result.get(0).get("address"));
        assertEquals("alpha", result.get(0).get("comment"));
        assertEquals("0x401004", result.get(1).get("address"));
        assertEquals("beta", result.get(1).get("comment"));
    }

    @Test
    public void convertToMapList_rejectsNonArrayJsonString() {
        List<Map<String, String>> result = ServiceUtils.convertToMapList(
            "{\"address\":\"0x401000\",\"comment\":\"alpha\"}"
        );

        assertNull(result);
    }

    // --- addressToJson ---

    @Test
    public void addressToJson_singleSpace_emitsOnlyAddressField() {
        // Only one physical space
        when(factory.getAddressSpaces()).thenReturn(new AddressSpace[]{ramSpace});
        Map<String, Object> result = ServiceUtils.addressToJson(mockAddr, program);
        assertEquals("00001000", result.get("address"));
        assertFalse("address_full must not be present for single-space", result.containsKey("address_full"));
        assertFalse("address_space must not be present for single-space", result.containsKey("address_space"));
    }

    @Test
    public void addressToJson_multiSpace_emitsEnrichedFields() {
        // Two physical spaces (setUp default)
        Map<String, Object> result = ServiceUtils.addressToJson(mockAddr, program);
        assertEquals("00001000", result.get("address"));
        assertEquals("ram:00001000", result.get("address_full"));
        assertEquals("ram", result.get("address_space"));
    }

    @Test
    public void addressToJson_nullProgram_emitsOnlyAddressField() {
        Map<String, Object> result = ServiceUtils.addressToJson(mockAddr, null);
        assertEquals("00001000", result.get("address"));
        assertFalse(result.containsKey("address_full"));
        assertFalse(result.containsKey("address_space"));
    }

    // --- getPhysicalSpaceCount ---

    @Test
    public void getPhysicalSpaceCount_filtersOverlayAndPseudoSpaces() {
        AddressSpace overlaySpace = mock(AddressSpace.class);
        when(overlaySpace.isOverlaySpace()).thenReturn(true);

        AddressSpace externalSpace = mock(AddressSpace.class);
        when(externalSpace.isOverlaySpace()).thenReturn(false);
        when(externalSpace.getType()).thenReturn(AddressSpace.TYPE_EXTERNAL);

        AddressSpace stackSpace = mock(AddressSpace.class);
        when(stackSpace.isOverlaySpace()).thenReturn(false);
        when(stackSpace.getType()).thenReturn(AddressSpace.TYPE_STACK);

        when(factory.getAddressSpaces()).thenReturn(
            new AddressSpace[]{ramSpace, codeSpace, overlaySpace, externalSpace, stackSpace});

        assertEquals(2, ServiceUtils.getPhysicalSpaceCount(program));
    }

    @Test
    public void getPhysicalSpaceCount_singlePhysicalSpace_returnsOne() {
        when(factory.getAddressSpaces()).thenReturn(new AddressSpace[]{ramSpace});
        assertEquals(1, ServiceUtils.getPhysicalSpaceCount(program));
    }
}
