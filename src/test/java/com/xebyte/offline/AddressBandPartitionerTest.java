package com.xebyte.offline;

import com.xebyte.core.partition.AddressBandPartitioner;
import com.xebyte.core.partition.Applicability;
import com.xebyte.core.partition.Partition;
import com.xebyte.core.partition.PartitionContext;
import ghidra.program.model.listing.Function;
import org.junit.Test;

import java.util.List;
import java.util.stream.Collectors;

import static org.junit.Assert.*;

/**
 * Offline tests for {@link AddressBandPartitioner}.
 */
public class AddressBandPartitionerTest {

    @Test
    public void probeNotApplicableWhenNothingUnassigned() {
        PartitionContext ctx = fiveFunctions().context();
        ctx.markAssigned(List.of(0, 1, 2, 3, 4));

        Applicability a = new AddressBandPartitioner(20).probe(ctx);
        assertFalse(a.applicable());
        assertTrue(a.reason().contains("nothing left"));
    }

    @Test
    public void probeApplicableWheneverPoolRemains() {
        PartitionContext ctx = fiveFunctions().context();
        Applicability a = new AddressBandPartitioner(20).probe(ctx);
        assertTrue(a.applicable());
        assertEquals(1.0, a.expectedCoverage(), 0.0);
        assertTrue(a.reason().contains("fallback") || a.reason().contains("banded"));
    }

    @Test
    public void partitionBandsUnassignedByAddressOrder() {
        AddressBandPartitioner part = new AddressBandPartitioner(2);
        PartitionContext ctx = fiveFunctions().context();

        List<Partition> parts = part.partition(ctx);
        assertEquals(3, parts.size()); // 2+2+1
        assertEquals("address-band", parts.get(0).method());
        assertEquals("b000", parts.get(0).slug());
        assertEquals("b001", parts.get(1).slug());
        assertEquals("b002", parts.get(2).slug());
        assertEquals(List.of("f0", "f1"), names(parts.get(0)));
        assertEquals(List.of("f2", "f3"), names(parts.get(1)));
        assertEquals(List.of("f4"), names(parts.get(2)));
        assertEquals(0.1, parts.get(0).confidence(), 0.0);
        assertTrue(parts.get(0).evidence().get("note").toString().contains("address order"));
    }

    @Test
    public void partitionSkipsAlreadyAssignedIndices() {
        AddressBandPartitioner part = new AddressBandPartitioner(2);
        PartitionContext ctx = fiveFunctions().context();
        ctx.markAssigned(List.of(1, 3)); // leave 0,2,4

        List<Partition> parts = part.partition(ctx);
        assertEquals(2, parts.size()); // 2+1
        assertEquals(List.of("f0", "f2"), names(parts.get(0)));
        assertEquals(List.of("f4"), names(parts.get(1)));
    }

    private static PartitionFixtures.Builder fiveFunctions() {
        return PartitionFixtures.builder()
                .function("f0", 0x1000)
                .function("f1", 0x1020)
                .function("f2", 0x1040)
                .function("f3", 0x1060)
                .function("f4", 0x1080);
    }

    private static List<String> names(Partition p) {
        return p.members().stream().map(Function::getName).collect(Collectors.toList());
    }
}
