package com.xebyte.offline;

import com.xebyte.core.partition.AddressBandPartitioner;
import com.xebyte.core.partition.MmioPagePartitioner;
import com.xebyte.core.partition.Partition;
import com.xebyte.core.partition.PartitionCascade;
import com.xebyte.core.partition.PartitionContext;
import com.xebyte.core.partition.Partitioner;
import com.xebyte.core.partition.QualifiedNamePartitioner;
import org.junit.Test;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.Assert.*;

/**
 * Offline tests for {@link PartitionCascade}: precedence, overlap, strategy log,
 * and {@link PartitionCascade#buildChain}.
 */
public class PartitionCascadeTest {

    @Test
    public void buildChainDefaultReturnsFullPrecedenceOrder() {
        List<Partitioner> chain = PartitionCascade.buildChain(20, null);
        assertEquals(4, chain.size());
        assertEquals(List.of("qualified-name", "mmio-page", "literal-locality", "address-band"),
                chain.stream().map(Partitioner::name).collect(Collectors.toList()));
    }

    @Test
    public void buildChainEmptyCollectionMeansFullCascade() {
        List<Partitioner> chain = PartitionCascade.buildChain(15, List.of());
        assertEquals(4, chain.size());
        PartitionContext ctx = PartitionFixtures.builder()
                .function("a", 0x1000).context();
        assertTrue(chain.get(3).probe(ctx).reason().contains("15"));
    }

    @Test
    public void buildChainFiltersKnownNamesAndIgnoresUnknown() {
        List<Partitioner> chain = PartitionCascade.buildChain(20,
                List.of("address-band", "no-such-strategy", "mmio-page"));
        assertEquals(List.of("mmio-page", "address-band"),
                chain.stream().map(Partitioner::name).collect(Collectors.toList()));
    }

    @Test
    public void buildChainAllUnknownYieldsEmpty() {
        assertTrue(PartitionCascade.buildChain(20, List.of("rtti", "bogus")).isEmpty());
    }

    @Test
    public void runRecordsNotApplicableSkippedAndRan() {
        PartitionContext ctx = PartitionFixtures.builder()
                .function("foo_a", 0x1000).withStrings("Foo::alpha")
                .function("foo_b", 0x1020).withStrings("Foo::beta")
                .function("bar_a", 0x1040).withStrings("Bar::gamma")
                .function("bar_b", 0x1060).withStrings("Bar::delta")
                .function("rest", 0x1080)
                .context();

        PartitionCascade cascade = new PartitionCascade(List.of(
                new QualifiedNamePartitioner(),
                new MmioPagePartitioner(),
                new AddressBandPartitioner(2)));

        PartitionCascade.Result result = cascade.run(ctx);
        Map<String, Object> log = result.strategyLog();

        assertEquals("ran", status(log, "qualified-name"));
        assertEquals("not_applicable", status(log, "mmio-page"));
        assertEquals("ran", status(log, "address-band"));

        assertTrue(reason(log, "mmio-page").toLowerCase().contains("no high")
                || reason(log, "mmio-page").contains("discriminate")
                || reason(log, "mmio-page").contains("density"));

        assertEquals(5, result.totalFunctions());
        assertEquals(5, result.assignedFunctions());
        assertTrue(result.partitions().stream().anyMatch(p -> "qualified-name".equals(p.method())));
        assertTrue(result.partitions().stream().anyMatch(p -> "address-band".equals(p.method())));
    }

    @Test
    public void earlierStrategyWinsOnOverlapAndLaterSeesOnlyLeftovers() {
        PartitionContext ctx = PartitionFixtures.builder()
                .function("foo_a", 0x1000).withStrings("Foo::alpha")
                .function("foo_b", 0x1020).withStrings("Foo::beta")
                .function("bar_a", 0x1040).withStrings("Bar::gamma")
                .function("bar_b", 0x1060).withStrings("Bar::delta")
                .context();

        PartitionCascade cascade = new PartitionCascade(List.of(
                new QualifiedNamePartitioner(),
                new AddressBandPartitioner(1)));

        PartitionCascade.Result result = cascade.run(ctx);
        assertEquals("skipped", status(result.strategyLog(), "address-band"));
        assertTrue(reason(result.strategyLog(), "address-band").contains("nothing left"));

        Set<String> methods = result.partitions().stream()
                .map(Partition::method).collect(Collectors.toSet());
        assertEquals(Set.of("qualified-name"), methods);
        assertEquals(4, result.assignedFunctions());
    }

    @Test
    public void cascadeSortsByPrecedenceRegardlessOfConstructionOrder() {
        PartitionContext ctx = PartitionFixtures.builder()
                .function("a", 0x1000)
                .function("b", 0x1020)
                .function("c", 0x1040)
                .context();

        PartitionCascade cascade = new PartitionCascade(List.of(
                new AddressBandPartitioner(10),
                new QualifiedNamePartitioner()));

        PartitionCascade.Result result = cascade.run(ctx);
        assertEquals("not_applicable", status(result.strategyLog(), "qualified-name"));
        assertEquals("ran", status(result.strategyLog(), "address-band"));
        assertEquals(1, result.partitions().size());
        assertEquals("address-band", result.partitions().get(0).method());
    }

    @SuppressWarnings("unchecked")
    private static String status(Map<String, Object> log, String name) {
        Map<String, Object> entry = (Map<String, Object>) log.get(name);
        assertNotNull("missing log entry for " + name + ": " + log.keySet(), entry);
        return String.valueOf(entry.get("status"));
    }

    @SuppressWarnings("unchecked")
    private static String reason(Map<String, Object> log, String name) {
        Map<String, Object> entry = (Map<String, Object>) log.get(name);
        return String.valueOf(entry.get("reason"));
    }
}
