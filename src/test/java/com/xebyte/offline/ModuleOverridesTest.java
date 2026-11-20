package com.xebyte.offline;

import com.xebyte.core.tree.ModuleOverrides;
import com.xebyte.core.tree.PartitionMeta;
import com.xebyte.core.partition.AddressBandPartitioner;
import com.xebyte.core.partition.Partition;
import com.xebyte.core.partition.PartitionCascade;
import com.xebyte.core.partition.PartitionContext;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.PropertyMapManager;
import ghidra.program.model.util.StringPropertyMap;
import org.junit.Before;
import org.junit.Test;

import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Override beats every partitioner (including the terminal band); empty string
 * unpins; missing map is not an error; pin survives a simulated resweep.
 */
public class ModuleOverridesTest {

    private Program program;
    private PropertyMapManager propMgr;
    private StringPropertyMap map;
    private Address entryA;
    private Address entryB;
    private Address entryC;

    @Before
    public void setUp() {
        program = mock(Program.class);
        propMgr = mock(PropertyMapManager.class);
        map = mock(StringPropertyMap.class);
        when(program.getUsrPropertyManager()).thenReturn(propMgr);
        when(program.getCurrentTransactionInfo()).thenReturn(null);
        when(program.startTransaction(anyString())).thenReturn(1);

        entryA = addr(0x1000);
        entryB = addr(0x2000);
        entryC = addr(0x3000);
    }

    @Test
    public void missingMapIsNotAnError() {
        when(propMgr.getStringPropertyMap(ModuleOverrides.MAP_NAME)).thenReturn(null);
        assertEquals(Optional.empty(), ModuleOverrides.slugFor(program, entryA));
    }

    @Test
    public void emptyStringUnpins() {
        when(propMgr.getStringPropertyMap(ModuleOverrides.MAP_NAME)).thenReturn(map);
        when(map.hasProperty(entryA)).thenReturn(true);
        when(map.getString(entryA)).thenReturn("c05");

        assertEquals(Optional.of("c05"), ModuleOverrides.slugFor(program, entryA));

        ModuleOverrides.set(program, entryA, "");
        verify(map).remove(entryA);
        verify(map, never()).add(eq(entryA), anyString());
    }

    @Test
    public void setCreatesMapWhenAbsentAndStoresSlug() throws Exception {
        when(propMgr.getStringPropertyMap(ModuleOverrides.MAP_NAME))
                .thenReturn(null)   // ensureMap first look
                .thenReturn(null);  // not used after create
        when(propMgr.createStringPropertyMap(ModuleOverrides.MAP_NAME)).thenReturn(map);

        ModuleOverrides.set(program, entryA, "driver_usb");
        verify(propMgr).createStringPropertyMap(ModuleOverrides.MAP_NAME);
        verify(map).add(entryA, "driver_usb");
        verify(program).endTransaction(1, true);
    }

    @Test
    public void overrideBeatsTerminalBandFallback() {
        // Three eligible functions; only A is pinned. After claimPinned + cascade
        // with address-band only, A must be in a pinned partition and absent from
        // every band — the band would otherwise claim everything.
        stubFunctions(List.of(
                functionAt(entryA, "Pinned"),
                functionAt(entryB, "BandOne"),
                functionAt(entryC, "BandTwo")));

        when(propMgr.getStringPropertyMap(ModuleOverrides.MAP_NAME)).thenReturn(map);
        when(map.hasProperty(entryA)).thenReturn(true);
        when(map.getString(entryA)).thenReturn("c05");
        when(map.hasProperty(entryB)).thenReturn(false);
        when(map.hasProperty(entryC)).thenReturn(false);

        PartitionContext ctx = new PartitionContext(program);
        assertEquals(3, ctx.size());

        List<Partition> pinned = ModuleOverrides.claimPinned(ctx);
        assertEquals(1, pinned.size());
        assertEquals("c05", pinned.get(0).slug());
        assertEquals(ModuleOverrides.METHOD, pinned.get(0).method());
        assertEquals(1.0, pinned.get(0).confidence(), 0.001);
        assertEquals(1, pinned.get(0).members().size());
        assertEquals("Pinned", pinned.get(0).members().get(0).getName());
        assertEquals(1, ctx.assignedCount());

        PartitionCascade.Result cascade = new PartitionCascade(
                List.of(new AddressBandPartitioner(20))).run(ctx);
        Set<String> bandNames = new HashSet<>();
        for (Partition p : cascade.partitions()) {
            assertFalse("band must not claim a pinned function",
                    ModuleOverrides.METHOD.equals(p.method()));
            for (Function f : p.members()) {
                bandNames.add(f.getName());
                assertFalse(f.getEntryPoint() == entryA
                        || f.getEntryPoint().getOffset() == entryA.getOffset());
            }
        }
        assertTrue(bandNames.contains("BandOne"));
        assertTrue(bandNames.contains("BandTwo"));
        assertFalse(bandNames.contains("Pinned"));
        assertEquals(3, ctx.assignedCount());

        // The partition tool reports this log as built; Map.of's order changed per JVM run.
        assertEquals(List.of("status", "expected_coverage", "reason", "partitions",
                "functions_placed", "pool_before"),
                List.copyOf(((java.util.Map<?, ?>) cascade.strategyLog().get("address-band")).keySet()));
    }

    @Test
    public void aTreeStoresTheStrategyLogInOneOrderWhateverOrderItWasBuiltIn() {
        // index/partitions.json and modules/index.md render it: a tree swept before a restart
        // differed from a fresh sweep after it, and a reconcile kept whatever order it read.
        java.util.Map<String, Object> scrambled = new java.util.LinkedHashMap<>();
        scrambled.put("address-band", new java.util.LinkedHashMap<>(java.util.Map.of(
                "pool_before", 12, "reason", "fallback", "functions_placed", 12, "status", "ran")));
        PartitionMeta meta = new PartitionMeta(12, 12, 12, 0, java.util.Map.of(), scrambled, List.of());

        assertEquals(List.of("status", "reason", "functions_placed", "pool_before"),
                List.copyOf(((java.util.Map<?, ?>) meta.strategyLog().get("address-band")).keySet()));
        assertEquals("12", ((java.util.Map<?, ?>) meta.strategyLog().get("address-band")).get("pool_before"));
    }

    @Test
    public void pinSurvivesSimulatedResweep() {
        // The map is on the program — a second claimPinned (as a resweep would)
        // sees the same override without re-writing it.
        stubFunctions(List.of(functionAt(entryA, "Pinned"), functionAt(entryB, "Other")));
        when(propMgr.getStringPropertyMap(ModuleOverrides.MAP_NAME)).thenReturn(map);
        when(map.hasProperty(entryA)).thenReturn(true);
        when(map.getString(entryA)).thenReturn("c05");
        when(map.hasProperty(entryB)).thenReturn(false);

        PartitionContext first = new PartitionContext(program);
        List<Partition> once = ModuleOverrides.claimPinned(first);
        assertEquals(1, once.size());
        assertEquals("c05", once.get(0).slug());

        PartitionContext second = new PartitionContext(program);
        List<Partition> again = ModuleOverrides.claimPinned(second);
        assertEquals(1, again.size());
        assertEquals("c05", again.get(0).slug());
        assertEquals(ModuleOverrides.METHOD, again.get(0).method());
        // Map was only read — resweep must not require re-pinning.
        verify(map, never()).add(any(), anyString());
    }

    // -------------------------------------------------------------------------

    private void stubFunctions(List<Function> functions) {
        FunctionManager fm = mock(FunctionManager.class);
        Listing listing = mock(Listing.class);
        when(program.getFunctionManager()).thenReturn(fm);
        when(program.getListing()).thenReturn(listing);

        when(fm.getFunctions(true)).thenAnswer(inv -> {
            Iterator<Function> it = functions.iterator();
            FunctionIterator fi = mock(FunctionIterator.class);
            when(fi.hasNext()).thenAnswer(i -> it.hasNext());
            when(fi.next()).thenAnswer(i -> it.next());
            return fi;
        });

        Instruction instr = mock(Instruction.class);
        for (Function f : functions) {
            when(listing.getInstructionAt(f.getEntryPoint())).thenReturn(instr);
        }
    }

    private Function functionAt(Address entry, String name) {
        Function f = mock(Function.class);
        when(f.getEntryPoint()).thenReturn(entry);
        when(f.getName()).thenReturn(name);
        when(f.isExternal()).thenReturn(false);
        when(f.isThunk()).thenReturn(false);
        when(f.getProgram()).thenReturn(program);
        return f;
    }

    private Address addr(long offset) {
        Address a = mock(Address.class);
        when(a.getOffset()).thenReturn(offset);
        when(a.toString(false)).thenReturn(String.format("%08x", offset));
        return a;
    }
}
