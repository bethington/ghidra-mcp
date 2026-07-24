package com.xebyte.offline;

import com.xebyte.core.McpTool;
import com.xebyte.core.Param;
import com.xebyte.core.ParamSource;
import com.xebyte.core.ProgramProvider;
import com.xebyte.core.ProgramScriptService;
import com.xebyte.core.Response;
import com.xebyte.core.ThreadingStrategy;
import ghidra.framework.options.OptionType;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.IntPropertyMap;
import ghidra.program.model.util.LongPropertyMap;
import ghidra.program.model.util.ObjectPropertyMap;
import ghidra.program.model.util.PropertyMap;
import ghidra.program.model.util.PropertyMapManager;
import ghidra.program.model.util.StringPropertyMap;
import ghidra.program.model.util.VoidPropertyMap;
import junit.framework.TestCase;

import java.lang.reflect.Method;
import java.lang.reflect.Parameter;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Offline coverage for the 11 program-storage MCP endpoints added to
 * {@link ProgramScriptService} in v5.17.0 — {@code list_option_groups},
 * {@code get_program_options}, {@code set_program_option},
 * {@code remove_program_option}, {@code list_property_maps},
 * {@code create_property_map}, {@code delete_property_map}, {@code set_property},
 * {@code get_property}, {@code remove_property}, {@code list_properties}.
 *
 * <p>Those ~690 lines shipped with zero Java tests. The existing
 * {@link ProgramScriptServiceValidationTest} can't reach them: every one of these
 * handlers resolves the program via {@code ServiceUtils.getProgramOrError} BEFORE
 * validating its own arguments, so a {@link StubProgramProvider} (no program) short
 * circuits at "No program loaded" and none of the per-tool guards ever run. These
 * tests therefore drive a mocked {@link Program} — options table, property-map
 * manager, and address factory — which keeps them fully offline while still
 * exercising the real validation, type-coercion, and pagination logic.
 *
 * <p>The threading strategy runs callables inline AND records every write it was
 * asked to perform. That lets each rejection test assert something stronger than
 * "an error came back": it asserts no transaction was ever opened, which is the
 * actual contract ("the value is parsed BEFORE the write transaction so parse
 * errors surface cleanly").
 */
public class ProgramStorageEndpointsValidationTest extends TestCase {

    private static final String GROUP = "Program Information";
    private static final String UNKNOWN_GROUP = "No Such Group";
    private static final String GOOD_ADDR = "0x401000";
    private static final String BAD_ADDR = "zzzz";

    /**
     * Runs work inline (so real handler logic executes) while recording the
     * transaction names it was handed. Tests assert on {@code writes} to prove a
     * guard fired before any database transaction was opened.
     */
    private static final class RecordingThreadingStrategy implements ThreadingStrategy {
        final List<String> writes = new ArrayList<>();

        @Override
        public <T> T executeRead(Callable<T> action) throws Exception {
            return action.call();
        }

        @Override
        public <T> T executeWrite(Program program, String txName, Callable<T> action) throws Exception {
            writes.add(txName);
            return action.call();
        }

        @Override
        public boolean isHeadless() {
            return true;
        }
    }

    private Program program;
    private Options options;
    private PropertyMapManager propertyMaps;
    private AddressFactory addressFactory;
    private Address addr;
    private RecordingThreadingStrategy threading;
    private ProgramScriptService svc;

    @Override
    protected void setUp() {
        program = mock(Program.class);
        ProgramProvider provider = mock(ProgramProvider.class);
        threading = new RecordingThreadingStrategy();
        svc = new ProgramScriptService(provider, threading);

        when(provider.getCurrentProgram()).thenReturn(program);
        when(program.getName()).thenReturn("Test.exe");
        when(program.getOptionsNames()).thenReturn(List.of(GROUP, "Analyzers"));

        options = mock(Options.class);
        when(program.getOptions(GROUP)).thenReturn(options);
        when(options.getValueAsString(anyString())).thenReturn("<stubbed>");

        propertyMaps = mock(PropertyMapManager.class);
        when(program.getUsrPropertyManager()).thenReturn(propertyMaps);

        // Minimal single-space address factory so ServiceUtils.parseAddress can both
        // succeed (GOOD_ADDR) and fail with its rich hint (BAD_ADDR).
        addressFactory = mock(AddressFactory.class);
        AddressSpace ram = mock(AddressSpace.class);
        when(ram.getName()).thenReturn("ram");
        when(ram.getType()).thenReturn(AddressSpace.TYPE_RAM);
        when(ram.isOverlaySpace()).thenReturn(false);
        when(addressFactory.getAddressSpaces()).thenReturn(new AddressSpace[]{ram});
        when(addressFactory.getDefaultAddressSpace()).thenReturn(ram);
        when(program.getAddressFactory()).thenReturn(addressFactory);

        addr = mock(Address.class);
        when(addr.getAddressSpace()).thenReturn(ram);
        when(addr.toString()).thenReturn("00401000");
        when(addressFactory.getAddress(GOOD_ADDR)).thenReturn(addr);
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    private static String errOf(Response r) {
        assertNotNull("handler returned null instead of a Response", r);
        assertTrue("expected a structured error Response, got: " + r.toJson(), r instanceof Response.Err);
        return ((Response.Err) r).message();
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> okOf(Response r) {
        assertNotNull("handler returned null instead of a Response", r);
        assertTrue("expected Response.Ok, got: " + r.toJson(), r instanceof Response.Ok);
        return (Map<String, Object>) ((Response.Ok) r).data();
    }

    private void assertNoTransaction(String why) {
        assertTrue(why + " — no write transaction should have been opened, but got " + threading.writes,
                threading.writes.isEmpty());
    }

    /**
     * Stub {@code getUsrPropertyManager().getPropertyMap(name)}. Uses {@code doReturn}
     * because {@code PropertyMapManager.getPropertyMap} is declared as
     * {@code PropertyMap<?>}: the wildcard capture makes {@code when(...).thenReturn(intMap)}
     * uncompilable for any concrete map subtype.
     */
    private void stubMap(String name, PropertyMap<?> map) {
        doReturn(map).when(propertyMaps).getPropertyMap(name);
    }

    // ==================================================================
    // list_option_groups / get_program_options
    // ==================================================================

    public void testListOptionGroupsReportsPerGroupOptionCounts() {
        Options analyzers = mock(Options.class);
        when(program.getOptions("Analyzers")).thenReturn(analyzers);
        when(options.getOptionNames()).thenReturn(List.of("Executable Format", "Created With"));
        when(analyzers.getOptionNames()).thenReturn(List.of("Stack"));

        Map<String, Object> data = okOf(svc.listOptionGroups(""));
        assertEquals(2, data.get("count"));

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> groups = (List<Map<String, Object>>) data.get("groups");
        assertEquals(GROUP, groups.get(0).get("name"));
        assertEquals(2, groups.get(0).get("option_count"));
        assertEquals("Analyzers", groups.get(1).get("name"));
        assertEquals(1, groups.get(1).get("option_count"));
    }

    public void testGetProgramOptionsRequiresGroup() {
        String err = errOf(svc.getProgramOptions("", ""));
        assertTrue("should name the missing param and point at the discovery tool: " + err,
                err.contains("group is required") && err.contains("list_option_groups"));
    }

    public void testGetProgramOptionsRejectsUnknownGroup() {
        String err = errOf(svc.getProgramOptions(UNKNOWN_GROUP, ""));
        assertTrue("should echo the bad group name: " + err,
                err.contains("No such option group") && err.contains(UNKNOWN_GROUP));
    }

    public void testGetProgramOptionsRendersTypeValueAndDefault() {
        when(options.getOptionNames()).thenReturn(List.of("Executable Format"));
        when(options.getType("Executable Format")).thenReturn(OptionType.STRING_TYPE);
        when(options.getValueAsString("Executable Format")).thenReturn("PE");
        when(options.getDefaultValueAsString("Executable Format")).thenReturn("");
        when(options.isDefaultValue("Executable Format")).thenReturn(false);
        when(options.isRegistered("Executable Format")).thenReturn(true);
        when(options.getDescription("Executable Format")).thenReturn("Loader used");

        Map<String, Object> data = okOf(svc.getProgramOptions(GROUP, ""));
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> opts = (List<Map<String, Object>>) data.get("options");
        assertEquals(1, opts.size());
        Map<String, Object> entry = opts.get(0);
        assertEquals("STRING_TYPE", entry.get("type"));
        assertEquals("PE", entry.get("value"));
        assertEquals(Boolean.FALSE, entry.get("is_default"));
        assertEquals(Boolean.TRUE, entry.get("registered"));
        assertEquals("Loader used", entry.get("description"));
    }

    public void testGetProgramOptionsOmitsBlankDescriptionAndTolerdatesNullType() {
        // getType() returns null for options Ghidra has no registered type for; the
        // handler must fall back to "NO_TYPE" rather than NPE, and must not emit an
        // empty "description" key.
        when(options.getOptionNames()).thenReturn(List.of("Custom"));
        when(options.getType("Custom")).thenReturn(null);
        when(options.getDescription("Custom")).thenReturn("");

        Map<String, Object> data = okOf(svc.getProgramOptions(GROUP, ""));
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> opts = (List<Map<String, Object>>) data.get("options");
        assertEquals("NO_TYPE", opts.get(0).get("type"));
        assertFalse("blank descriptions must be omitted, not emitted as \"\"",
                opts.get(0).containsKey("description"));
    }

    // ==================================================================
    // set_program_option
    // ==================================================================

    public void testSetProgramOptionRequiresGroup() {
        assertEquals("group is required", errOf(svc.setProgramOption("", "k", "v", "string", "")));
        assertNoTransaction("blank group");
    }

    public void testSetProgramOptionRequiresName() {
        assertEquals("name is required", errOf(svc.setProgramOption(GROUP, "", "v", "string", "")));
        assertNoTransaction("blank name");
    }

    public void testSetProgramOptionRequiresValue() {
        // Null value (key absent from the JSON body) is rejected; empty string is a
        // legitimate string value and must NOT be caught by this guard.
        assertEquals("value is required", errOf(svc.setProgramOption(GROUP, "k", null, "string", "")));
        assertNoTransaction("null value");
    }

    public void testSetProgramOptionRejectsUnknownGroup() {
        String err = errOf(svc.setProgramOption(UNKNOWN_GROUP, "k", "v", "string", ""));
        assertTrue(err.contains("No such option group"));
        assertNoTransaction("unknown group");
    }

    public void testSetProgramOptionHandlesEveryDocumentedType() {
        // The tool documents string|int|long|double|float|boolean. Each must reach the
        // matching typed Options setter with a correctly parsed value — a plain
        // "did it return ok?" assertion would pass even if every branch called setString.
        assertTrue(svc.setProgramOption(GROUP, "s", "hello", "string", "") instanceof Response.Ok);
        verify(options).setString("s", "hello");

        assertTrue(svc.setProgramOption(GROUP, "i", "42", "int", "") instanceof Response.Ok);
        verify(options).setInt("i", 42);

        assertTrue(svc.setProgramOption(GROUP, "l", "9999999999", "long", "") instanceof Response.Ok);
        verify(options).setLong("l", 9999999999L);

        assertTrue(svc.setProgramOption(GROUP, "d", "2.5", "double", "") instanceof Response.Ok);
        verify(options).setDouble("d", 2.5d);

        assertTrue(svc.setProgramOption(GROUP, "f", "1.5", "float", "") instanceof Response.Ok);
        verify(options).setFloat("f", 1.5f);

        assertTrue(svc.setProgramOption(GROUP, "b", "true", "boolean", "") instanceof Response.Ok);
        verify(options).setBoolean("b", true);

        assertEquals("every accepted type must run inside a transaction",
                6, threading.writes.size());
        assertEquals("Set Program Option", threading.writes.get(0));
    }

    public void testSetProgramOptionTypeKeywordIsCaseAndWhitespaceInsensitive() {
        // resolved = type.trim().toLowerCase() — models sometimes send " Int ".
        Map<String, Object> data = okOf(svc.setProgramOption(GROUP, "i", " 42 ", "  INT  ", ""));
        assertEquals("int", data.get("type"));
        verify(options).setInt("i", 42);
    }

    public void testSetProgramOptionRejectsUnsupportedType() {
        String err = errOf(svc.setProgramOption(GROUP, "k", "v", "date", ""));
        assertTrue("must name the offending type and list the legal set: " + err,
                err.contains("Unsupported type 'date'") && err.contains("boolean"));
        assertNoTransaction("unsupported type");
    }

    public void testSetProgramOptionRejectsUnparseableNumber() {
        String err = errOf(svc.setProgramOption(GROUP, "k", "not-a-number", "int", ""));
        assertTrue("must report a parse failure, not leak a raw exception: " + err,
                err.contains("is not a valid int"));
        assertNoTransaction("bad number is rejected before the transaction opens");
    }

    public void testSetProgramOptionInfersTypeFromExistingOption() {
        // type omitted + option already exists -> reuse the option's current type.
        when(options.contains("existing")).thenReturn(true);
        when(options.getType("existing")).thenReturn(OptionType.BOOLEAN_TYPE);

        Map<String, Object> data = okOf(svc.setProgramOption(GROUP, "existing", "true", "", ""));
        assertEquals("boolean", data.get("type"));
        verify(options).setBoolean("existing", true);
        verify(options, never()).setString(anyString(), anyString());
    }

    public void testSetProgramOptionDefaultsToStringForBrandNewOption() {
        // type omitted + option does not exist -> string.
        when(options.contains("brand_new")).thenReturn(false);

        Map<String, Object> data = okOf(svc.setProgramOption(GROUP, "brand_new", "0x10", "", ""));
        assertEquals("string", data.get("type"));
        verify(options).setString("brand_new", "0x10");
    }

    public void testSetProgramOptionRejectsUnsettableExistingType() {
        // COLOR_TYPE (and the other UI types) have no optionTypeKeyword mapping; the
        // handler must explain rather than silently write the wrong type.
        when(options.contains("Color")).thenReturn(true);
        when(options.getType("Color")).thenReturn(OptionType.COLOR_TYPE);

        String err = errOf(svc.setProgramOption(GROUP, "Color", "#fff", "", ""));
        assertTrue("must say the type is unsettable and list what is: " + err,
                err.contains("cannot be set via this tool") && err.contains("Settable types"));
        assertNoTransaction("unsettable existing option type");
    }

    // ==================================================================
    // remove_program_option
    // ==================================================================

    public void testRemoveProgramOptionRequiresGroupAndName() {
        assertEquals("group is required", errOf(svc.removeProgramOption("", "k", "")));
        assertEquals("name is required", errOf(svc.removeProgramOption(GROUP, "", "")));
        assertNoTransaction("blank required params");
    }

    public void testRemoveProgramOptionRejectsUnknownGroup() {
        assertTrue(errOf(svc.removeProgramOption(UNKNOWN_GROUP, "k", "")).contains("No such option group"));
        assertNoTransaction("unknown group");
    }

    public void testRemoveProgramOptionMissingOptionIsSoftFailure() {
        // Absent option is not an error — it reports success=false so idempotent
        // cleanup scripts don't have to special-case it.
        when(options.contains("gone")).thenReturn(false);

        Map<String, Object> data = okOf(svc.removeProgramOption(GROUP, "gone", ""));
        assertEquals(Boolean.FALSE, data.get("success"));
        assertNoTransaction("missing option");
    }

    public void testRemoveProgramOptionRemovesExistingOption() {
        when(options.contains("custom")).thenReturn(true);

        Map<String, Object> data = okOf(svc.removeProgramOption(GROUP, "custom", ""));
        assertEquals(Boolean.TRUE, data.get("success"));
        verify(options).removeOption("custom");
        assertEquals(List.of("Remove Program Option"), threading.writes);
    }

    // ==================================================================
    // list_property_maps / create_property_map / delete_property_map
    // ==================================================================

    public void testListPropertyMapsClassifiesValueTypes() {
        IntPropertyMap intMap = mock(IntPropertyMap.class);
        VoidPropertyMap voidMap = mock(VoidPropertyMap.class);
        when(intMap.getSize()).thenReturn(7);
        when(voidMap.getSize()).thenReturn(0);
        when(propertyMaps.propertyManagers()).thenReturn(List.of("counts", "tags").iterator());
        stubMap("counts", intMap);
        stubMap("tags", voidMap);

        Map<String, Object> data = okOf(svc.listPropertyMaps(""));
        assertEquals(2, data.get("count"));
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> maps = (List<Map<String, Object>>) data.get("property_maps");
        assertEquals("int", maps.get(0).get("value_type"));
        assertEquals(7, maps.get(0).get("size"));
        assertEquals("void", maps.get(1).get("value_type"));
    }

    public void testCreatePropertyMapRequiresName() {
        assertEquals("name is required", errOf(svc.createPropertyMap("", "string", "")));
        assertNoTransaction("blank map name");
    }

    public void testCreatePropertyMapAcceptsEveryDocumentedType() throws Exception {
        // int/long/string/void are the four documented kinds; each must hit its own
        // PropertyMapManager factory method.
        assertTrue(svc.createPropertyMap("m_int", "int", "") instanceof Response.Ok);
        verify(propertyMaps).createIntPropertyMap("m_int");

        assertTrue(svc.createPropertyMap("m_long", "long", "") instanceof Response.Ok);
        verify(propertyMaps).createLongPropertyMap("m_long");

        assertTrue(svc.createPropertyMap("m_str", "string", "") instanceof Response.Ok);
        verify(propertyMaps).createStringPropertyMap("m_str");

        assertTrue(svc.createPropertyMap("m_void", "VOID", "") instanceof Response.Ok);
        verify(propertyMaps).createVoidPropertyMap("m_void");

        assertEquals(4, threading.writes.size());
    }

    public void testCreatePropertyMapDefaultsToString() throws Exception {
        Map<String, Object> data = okOf(svc.createPropertyMap("m", "", ""));
        assertEquals("string", data.get("value_type"));
        verify(propertyMaps).createStringPropertyMap("m");
    }

    public void testCreatePropertyMapRejectsObjectType() {
        // Object maps need a registered Saveable class, which MCP has no way to supply —
        // they're readable via list/get but cannot be created or written here.
        String err = errOf(svc.createPropertyMap("m_obj", "object", ""));
        assertTrue("must name the rejected type and list the supported ones: " + err,
                err.contains("Unsupported map type 'object'") && err.contains("void"));
        assertNoTransaction("object map type");
    }

    public void testCreatePropertyMapRejectsDuplicateName() {
        stubMap("dupe", mock(IntPropertyMap.class));

        assertTrue(errOf(svc.createPropertyMap("dupe", "int", "")).contains("already exists"));
        assertNoTransaction("duplicate map name");
    }

    public void testDeletePropertyMapRequiresName() {
        assertEquals("name is required", errOf(svc.deletePropertyMap("", "")));
        assertNoTransaction("blank map name");
    }

    public void testDeletePropertyMapMissingMapIsSoftFailure() {
        Map<String, Object> data = okOf(svc.deletePropertyMap("gone", ""));
        assertEquals(Boolean.FALSE, data.get("success"));
        assertNoTransaction("missing map");
    }

    public void testDeletePropertyMapReportsManagerResult() {
        // success mirrors PropertyMapManager.removePropertyMap, which is captured from
        // inside the transaction via an AtomicBoolean.
        stubMap("m", mock(StringPropertyMap.class));
        when(propertyMaps.removePropertyMap("m")).thenReturn(true);

        Map<String, Object> data = okOf(svc.deletePropertyMap("m", ""));
        assertEquals(Boolean.TRUE, data.get("success"));
        assertEquals(List.of("Delete Property Map"), threading.writes);
    }

    // ==================================================================
    // set_property
    // ==================================================================

    public void testSetPropertyRequiresMapAndAddress() {
        assertEquals("map is required", errOf(svc.setProperty("", GOOD_ADDR, "1", "")));
        assertEquals("address is required", errOf(svc.setProperty("m", "", "1", "")));
        assertNoTransaction("blank required params");
    }

    public void testSetPropertyRejectsUnknownMap() {
        String err = errOf(svc.setProperty("nope", GOOD_ADDR, "1", ""));
        assertTrue("must point at the creation tool: " + err,
                err.contains("No property map named 'nope'") && err.contains("create_property_map"));
        assertNoTransaction("unknown map");
    }

    public void testSetPropertyBadAddressReturnsCleanParseError() {
        stubMap("m", mock(IntPropertyMap.class));

        String err = errOf(svc.setProperty("m", BAD_ADDR, "1", ""));
        assertNotNull("parse errors must not surface as a null message", err);
        assertTrue("must be the ServiceUtils parse hint, not an exception: " + err,
                err.contains("could not be resolved") && err.contains(BAD_ADDR));
        assertNoTransaction("unparseable address");
    }

    public void testSetPropertyRejectsObjectMap() {
        ObjectPropertyMap<?> objMap = mock(ObjectPropertyMap.class);
        stubMap("obj", objMap);

        String err = errOf(svc.setProperty("obj", GOOD_ADDR, "x", ""));
        assertTrue("object maps are read-only over MCP: " + err,
                err.contains("Object property maps cannot be written"));
        assertNoTransaction("object map write");
    }

    public void testSetPropertyRequiresValueForTypedMaps() {
        stubMap("ints", mock(IntPropertyMap.class));
        stubMap("longs", mock(LongPropertyMap.class));

        assertEquals("value is required for an int property map",
                errOf(svc.setProperty("ints", GOOD_ADDR, "", "")));
        assertEquals("value is required for a long property map",
                errOf(svc.setProperty("longs", GOOD_ADDR, "", "")));
        assertNoTransaction("missing value for a typed map");
    }

    public void testSetPropertyRejectsUnparseableNumericValue() {
        stubMap("ints", mock(IntPropertyMap.class));

        String err = errOf(svc.setProperty("ints", GOOD_ADDR, "abc", ""));
        assertTrue("must blame the value and name the map: " + err,
                err.contains("Value 'abc' is not valid for map 'ints'"));
        assertNoTransaction("bad numeric value is rejected before the transaction opens");
    }

    public void testSetPropertyCoercesValueToMapType() {
        IntPropertyMap intMap = mock(IntPropertyMap.class);
        StringPropertyMap strMap = mock(StringPropertyMap.class);
        stubMap("ints", intMap);
        stubMap("strs", strMap);

        Map<String, Object> intData = okOf(svc.setProperty("ints", GOOD_ADDR, " 42 ", ""));
        assertEquals("int", intData.get("value_type"));
        assertEquals(Integer.valueOf(42), intData.get("value"));
        // Cast to Object: the service calls the generic PropertyMap.add(Address, Object)
        // overload (Integer -> Object needs no unboxing), not IntPropertyMap.add(Address, int).
        verify(intMap).add(addr, (Object) Integer.valueOf(42));

        Map<String, Object> strData = okOf(svc.setProperty("strs", GOOD_ADDR, " 42 ", ""));
        assertEquals("string", strData.get("value_type"));
        assertEquals("String maps must store the value verbatim, untrimmed", " 42 ", strData.get("value"));
        verify(strMap).add(addr, " 42 ");
    }

    public void testSetPropertyOnVoidMapIgnoresValue() {
        VoidPropertyMap voidMap = mock(VoidPropertyMap.class);
        stubMap("tags", voidMap);

        Map<String, Object> data = okOf(svc.setProperty("tags", GOOD_ADDR, "", ""));
        assertEquals("void", data.get("value_type"));
        assertNull("void maps store presence only", data.get("value"));
        verify(voidMap).add(addr);
        assertEquals(List.of("Set Property"), threading.writes);
    }

    // ==================================================================
    // get_property / remove_property
    // ==================================================================

    public void testGetPropertyRequiresMapAndAddress() {
        assertEquals("map is required", errOf(svc.getProperty("", GOOD_ADDR, "")));
        assertEquals("address is required", errOf(svc.getProperty("m", "", "")));
    }

    public void testGetPropertyRejectsUnknownMap() {
        assertTrue(errOf(svc.getProperty("nope", GOOD_ADDR, "")).contains("No property map named 'nope'"));
    }

    public void testGetPropertyBadAddressReturnsCleanParseError() {
        stubMap("m", mock(StringPropertyMap.class));

        String err = errOf(svc.getProperty("m", BAD_ADDR, ""));
        assertNotNull(err);
        assertTrue("must be the ServiceUtils parse hint: " + err, err.contains("could not be resolved"));
    }

    public void testGetPropertyReportsAbsentValueWithoutError() {
        StringPropertyMap strMap = mock(StringPropertyMap.class);
        stubMap("m", strMap);
        when(strMap.hasProperty(addr)).thenReturn(false);

        Map<String, Object> data = okOf(svc.getProperty("m", GOOD_ADDR, ""));
        assertEquals(Boolean.FALSE, data.get("has_value"));
        assertNull(data.get("value"));
        assertEquals("string", data.get("value_type"));
    }

    public void testGetPropertyReturnsStoredValue() {
        StringPropertyMap strMap = mock(StringPropertyMap.class);
        stubMap("m", strMap);
        when(strMap.hasProperty(addr)).thenReturn(true);
        when(strMap.get(addr)).thenReturn("stored");

        Map<String, Object> data = okOf(svc.getProperty("m", GOOD_ADDR, ""));
        assertEquals(Boolean.TRUE, data.get("has_value"));
        assertEquals("stored", data.get("value"));
        assertEquals("00401000", data.get("address"));
    }

    public void testRemovePropertyRequiresMapAndAddress() {
        assertEquals("map is required", errOf(svc.removeProperty("", GOOD_ADDR, "")));
        assertEquals("address is required", errOf(svc.removeProperty("m", "", "")));
        assertNoTransaction("blank required params");
    }

    public void testRemovePropertyRejectsUnknownMap() {
        assertTrue(errOf(svc.removeProperty("nope", GOOD_ADDR, "")).contains("No property map named 'nope'"));
        assertNoTransaction("unknown map");
    }

    public void testRemovePropertyBadAddressReturnsCleanParseError() {
        stubMap("m", mock(StringPropertyMap.class));

        String err = errOf(svc.removeProperty("m", BAD_ADDR, ""));
        assertNotNull(err);
        assertTrue("must be the ServiceUtils parse hint: " + err, err.contains("could not be resolved"));
        assertNoTransaction("unparseable address");
    }

    public void testRemovePropertyReportsMapResult() {
        StringPropertyMap strMap = mock(StringPropertyMap.class);
        stubMap("m", strMap);
        when(strMap.remove(addr)).thenReturn(true);

        Map<String, Object> data = okOf(svc.removeProperty("m", GOOD_ADDR, ""));
        assertEquals(Boolean.TRUE, data.get("success"));
        assertEquals(List.of("Remove Property"), threading.writes);
    }

    // ==================================================================
    // list_properties
    // ==================================================================

    public void testListPropertiesRequiresMap() {
        assertEquals("map is required", errOf(svc.listProperties("", "", "", 0, 100, "")));
    }

    public void testListPropertiesRejectsUnknownMap() {
        assertTrue(errOf(svc.listProperties("nope", "", "", 0, 100, ""))
                .contains("No property map named 'nope'"));
    }

    public void testListPropertiesRejectsHalfSpecifiedRange() {
        // start without end (or vice versa) is a caller mistake, not an empty filter.
        stubMap("m", mock(StringPropertyMap.class));

        assertEquals("Provide both start and end to filter by range, or neither.",
                errOf(svc.listProperties("m", GOOD_ADDR, "", 0, 100, "")));
        assertEquals("Provide both start and end to filter by range, or neither.",
                errOf(svc.listProperties("m", "", GOOD_ADDR, 0, 100, "")));
    }

    public void testListPropertiesReportsBadRangeEndpointsSeparately() {
        stubMap("m", mock(StringPropertyMap.class));

        String err = errOf(svc.listProperties("m", BAD_ADDR, GOOD_ADDR, 0, 100, ""));
        assertTrue("bad start must be labelled 'start:': " + err, err.startsWith("start:"));

        String err2 = errOf(svc.listProperties("m", GOOD_ADDR, BAD_ADDR, 0, 100, ""));
        assertTrue("bad end must be labelled 'end:': " + err2, err2.startsWith("end:"));
    }

    public void testListPropertiesPaginatesWithOffsetAndLimit() {
        StringPropertyMap strMap = mock(StringPropertyMap.class);
        Address a0 = mockAddress("00401000");
        Address a1 = mockAddress("00401004");
        Address a2 = mockAddress("00401008");
        AddressIterator it = mock(AddressIterator.class);
        when(it.hasNext()).thenReturn(true, true, true, false);
        when(it.next()).thenReturn(a0, a1, a2);
        when(strMap.getPropertyIterator()).thenReturn(it);
        when(strMap.get(a1)).thenReturn("second");
        when(strMap.getSize()).thenReturn(3);
        stubMap("m", strMap);

        Map<String, Object> data = okOf(svc.listProperties("m", "", "", 1, 1, ""));
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> entries = (List<Map<String, Object>>) data.get("entries");
        assertEquals("offset=1,limit=1 must yield exactly the second entry", 1, entries.size());
        assertEquals("00401004", entries.get(0).get("address"));
        assertEquals("second", entries.get(0).get("value"));
        assertEquals("total must be the map size, not the page size", 3, data.get("total"));
        assertEquals(1, data.get("count"));
    }

    public void testListPropertiesNormalizesNegativeOffsetAndNonPositiveLimit() {
        StringPropertyMap strMap = mock(StringPropertyMap.class);
        AddressIterator it = mock(AddressIterator.class);
        when(it.hasNext()).thenReturn(false);
        when(strMap.getPropertyIterator()).thenReturn(it);
        stubMap("m", strMap);

        Map<String, Object> data = okOf(svc.listProperties("m", "", "", -5, 0, ""));
        assertEquals("negative offset must clamp to 0", 0, data.get("offset"));
        assertEquals("non-positive limit must fall back to the 100 default", 100, data.get("limit"));
    }

    private static Address mockAddress(String rendered) {
        Address a = mock(Address.class);
        when(a.toString()).thenReturn(rendered);
        return a;
    }

    // ==================================================================
    // No-program degradation
    // ==================================================================

    public void testAllStorageEndpointsDegradeGracefullyWithoutAProgram() {
        // Every handler resolves the program first; with no program open each must
        // return a clean error rather than NPE. NoopThreadingStrategy would throw loudly
        // if any of them reached real transaction work.
        ProgramScriptService bare =
                new ProgramScriptService(ServiceFactory.stubProvider(), new NoopThreadingStrategy());
        Response[] responses = {
            bare.listOptionGroups(""),
            bare.getProgramOptions(GROUP, ""),
            bare.setProgramOption(GROUP, "k", "v", "string", ""),
            bare.removeProgramOption(GROUP, "k", ""),
            bare.listPropertyMaps(""),
            bare.createPropertyMap("m", "string", ""),
            bare.deletePropertyMap("m", ""),
            bare.setProperty("m", GOOD_ADDR, "1", ""),
            bare.getProperty("m", GOOD_ADDR, ""),
            bare.removeProperty("m", GOOD_ADDR, ""),
            bare.listProperties("m", "", "", 0, 100, ""),
        };
        for (Response r : responses) {
            assertNotNull("handler returned null instead of an error Response", r);
            assertTrue("expected a graceful 'No program loaded' error, got: " + r.toJson(),
                    r.toJson().contains("No program loaded"));
        }
    }

    // ==================================================================
    // Annotation contract
    // ==================================================================

    /** The 11 storage tools, as (method name, HTTP method, expected tool path). */
    private static final String[][] STORAGE_TOOLS = {
        {"listOptionGroups",    "GET",  "/list_option_groups"},
        {"getProgramOptions",   "GET",  "/get_program_options"},
        {"setProgramOption",    "POST", "/set_program_option"},
        {"removeProgramOption", "POST", "/remove_program_option"},
        {"listPropertyMaps",    "GET",  "/list_property_maps"},
        {"createPropertyMap",   "POST", "/create_property_map"},
        {"deletePropertyMap",   "POST", "/delete_property_map"},
        {"setProperty",         "POST", "/set_property"},
        {"getProperty",         "GET",  "/get_property"},
        {"removeProperty",      "POST", "/remove_property"},
        {"listProperties",      "GET",  "/list_properties"},
    };

    private static Method storageMethod(String name) {
        List<Method> matches = new ArrayList<>();
        for (Method m : ProgramScriptService.class.getDeclaredMethods()) {
            if (m.getName().equals(name) && m.isAnnotationPresent(McpTool.class)) {
                matches.add(m);
            }
        }
        assertEquals("expected exactly one @McpTool method named " + name, 1, matches.size());
        return matches.get(0);
    }

    public void testAllElevenStorageToolsAreRegistered() {
        for (String[] tool : STORAGE_TOOLS) {
            McpTool ann = storageMethod(tool[0]).getAnnotation(McpTool.class);
            assertEquals(tool[0] + " path", tool[2], ann.path());
            assertEquals(tool[0] + " http method", tool[1], ann.method());
            assertEquals(tool[0] + " category", "program", ann.category());
        }
    }

    public void testProgramParamIsAlwaysQuerySourcedAndOptional() {
        // Project convention (CLAUDE.md): "@Param(value = \"program\") defaults to
        // ParamSource.QUERY — POST endpoints must send program as a URL query param, not
        // in the JSON body." A BODY-sourced `program` here would silently retarget writes
        // at the active program.
        for (String[] tool : STORAGE_TOOLS) {
            Param programParam = null;
            for (Parameter p : storageMethod(tool[0]).getParameters()) {
                Param ann = p.getAnnotation(Param.class);
                if (ann != null && "program".equals(ann.value())) {
                    programParam = ann;
                }
            }
            assertNotNull(tool[0] + " must declare a `program` parameter", programParam);
            assertEquals(tool[0] + ": `program` must be QUERY-sourced",
                    ParamSource.QUERY, programParam.source());
            assertEquals(tool[0] + ": `program` must default to the active program",
                    "", programParam.defaultValue());
        }
    }

    public void testPostToolsCarryTheirPayloadInTheBody() {
        // Mirror image of the rule above: on a POST tool every parameter except
        // `program` must be BODY-sourced, otherwise the bridge builds a request the
        // handler can't read.
        for (String[] tool : STORAGE_TOOLS) {
            if (!"POST".equals(tool[1])) {
                continue;
            }
            for (Parameter p : storageMethod(tool[0]).getParameters()) {
                Param ann = p.getAnnotation(Param.class);
                assertNotNull(tool[0] + " has an unannotated parameter", ann);
                if ("program".equals(ann.value())) {
                    continue;
                }
                assertEquals(tool[0] + ": `" + ann.value() + "` must be BODY-sourced on a POST tool",
                        ParamSource.BODY, ann.source());
            }
        }
    }

    public void testAddressParamsCarryTheAddressTypeHint() {
        // paramType="address" is what makes the bridge sanitize addresses before
        // dispatch; without it the property tools get raw, unnormalized input.
        String[][] expected = {
            {"setProperty", "address"},
            {"getProperty", "address"},
            {"removeProperty", "address"},
            {"listProperties", "start"},
            {"listProperties", "end"},
        };
        for (String[] pair : expected) {
            Param found = null;
            for (Parameter p : storageMethod(pair[0]).getParameters()) {
                Param ann = p.getAnnotation(Param.class);
                if (ann != null && pair[1].equals(ann.value())) {
                    found = ann;
                }
            }
            assertNotNull(pair[0] + " must declare a `" + pair[1] + "` parameter", found);
            assertEquals(pair[0] + ": `" + pair[1] + "` must be paramType=address",
                    "address", found.paramType());
        }
    }
}
