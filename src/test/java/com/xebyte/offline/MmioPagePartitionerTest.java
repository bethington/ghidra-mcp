package com.xebyte.offline;

import com.xebyte.core.partition.Applicability;
import com.xebyte.core.partition.MmioPagePartitioner;
import com.xebyte.core.partition.Partition;
import com.xebyte.core.partition.PartitionContext;
import ghidra.program.model.listing.Function;
import org.junit.Test;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.Assert.*;

/**
 * Offline tests for {@link MmioPagePartitioner}.
 */
public class MmioPagePartitionerTest {

    private final MmioPagePartitioner part = new MmioPagePartitioner();

    @Test
    public void probeNotApplicableWithoutHighConstants() {
        PartitionContext ctx = PartitionFixtures.builder()
                .function("a", 0x1000).withStrings("no pages")
                .function("b", 0x1020)
                .function("c", 0x1040)
                .context();

        Applicability a = part.probe(ctx);
        assertFalse(a.applicable());
        assertTrue(a.reason().toLowerCase().contains("no high")
                || a.reason().contains("discriminate"));
    }

    @Test
    public void probeNotApplicableWhenCandidatesAreScattered() {
        // Three hits on one rare page at opposite ends of a 50-function pool:
        // ubiquity 3/50 = 0.06 (kept), density 3/50 = 0.06 (below the driver floor).
        PartitionFixtures.Builder b = PartitionFixtures.builder();
        for (int i = 0; i < 50; i++) {
            b.function("f" + i, 0x1000L + i * 0x20L);
            if (i == 0 || i == 25 || i == 49) {
                b.withPages(0xC2L);
            }
        }
        PartitionContext ctx = b.context();

        Applicability a = part.probe(ctx);
        assertFalse(a.applicable());
        assertTrue(a.reason().contains("density") || a.reason().contains("clustered"));
    }

    @Test
    public void probeApplicableOnClusteredPeripheralPages() {
        PartitionContext ctx = clusteredDriver().context();
        Applicability a = part.probe(ctx);
        assertTrue(a.applicable());
        assertTrue(a.expectedCoverage() > 0);
        assertTrue(a.reason().contains("page-set") || a.reason().contains("peripheral"));
    }

    @Test
    public void partitionGroupsIdenticalPageSetsAndLeavesOthers() {
        PartitionContext ctx = clusteredDriver().context();
        List<Partition> parts = part.partition(ctx);

        assertFalse(parts.isEmpty());
        Partition driver = parts.get(0);
        assertEquals("mmio-page", driver.method());
        assertTrue(driver.slug().startsWith("m"));
        assertTrue(driver.evidence().containsKey("peripheral_pages"));
        assertEquals(Set.of("drv0", "drv1", "drv2"), names(driver));

        Set<String> claimed = parts.stream().flatMap(p -> names(p).stream()).collect(Collectors.toSet());
        assertFalse(claimed.contains("other"));
        assertFalse(claimed.contains("glue"));
    }

    @Test
    public void partitionIgnoresAlreadyAssignedFunctions() {
        PartitionContext ctx = clusteredDriver().context();
        ctx.markAssigned(List.of(0, 1));

        List<Partition> parts = part.partition(ctx);
        assertTrue(parts.isEmpty());
    }

    /**
     * Three adjacent functions sharing page {@code 0xC2}; fillers so ubiquity stays
     * at or under the 0.10 ceiling ({@code 3/30 == 0.10}, filter is strictly greater).
     */
    private static PartitionFixtures.Builder clusteredDriver() {
        PartitionFixtures.Builder b = PartitionFixtures.builder()
                .function("drv0", 0x1000).withPages(0xC2L)
                .function("drv1", 0x1020).withPages(0xC2L)
                .function("drv2", 0x1040).withPages(0xC2L)
                .function("other", 0x1060)
                .function("glue", 0x1080).withPages(0xAAL);
        for (int i = 0; i < 25; i++) {
            b.function("pad" + i, 0x2000L + i * 0x20L);
        }
        return b;
    }

    private static Set<String> names(Partition p) {
        return p.members().stream().map(Function::getName).collect(Collectors.toSet());
    }
}
