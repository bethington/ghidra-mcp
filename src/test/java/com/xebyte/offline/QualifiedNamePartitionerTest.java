package com.xebyte.offline;

import com.xebyte.core.partition.Applicability;
import com.xebyte.core.partition.Partition;
import com.xebyte.core.partition.PartitionContext;
import com.xebyte.core.partition.QualifiedNamePartitioner;
import ghidra.program.model.listing.Function;
import org.junit.Test;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.Assert.*;

/**
 * Offline tests for {@link QualifiedNamePartitioner}.
 */
public class QualifiedNamePartitionerTest {

    private final QualifiedNamePartitioner part = new QualifiedNamePartitioner();

    @Test
    public void probeNotApplicableWhenNoQualifiedNames() {
        PartitionContext ctx = PartitionFixtures.builder()
                .function("a", 0x1000).withStrings("plain log line without classes")
                .function("b", 0x1020).withStrings("another ordinary string")
                .context();

        Applicability a = part.probe(ctx);
        assertFalse(a.applicable());
        assertTrue(a.reason().contains("Class::Method"));
    }

    @Test
    public void probeNotApplicableBelowClassOrCoverageFloor() {
        // One class only — fails MIN_CLASSES even with several members.
        PartitionContext ctx = PartitionFixtures.builder()
                .function("a", 0x1000).withStrings("OnlyOne::alpha")
                .function("b", 0x1020).withStrings("OnlyOne::beta")
                .function("c", 0x1040).withStrings("OnlyOne::gamma")
                .context();

        Applicability a = part.probe(ctx);
        assertFalse(a.applicable());
        assertTrue(a.reason().contains("below the") || a.reason().contains("only"));
    }

    @Test
    public void probeApplicableOnDistinctClassMethodStrings() {
        PartitionContext ctx = twoClassProgram().context();
        Applicability a = part.probe(ctx);
        assertTrue(a.applicable());
        assertTrue(a.expectedCoverage() > 0);
        assertTrue(a.reason().contains("Class::Method") || a.reason().contains("distinct"));
    }

    @Test
    public void partitionGroupsByClassAndLeavesUnseededUnassigned() {
        PartitionContext ctx = twoClassProgram().context();
        List<Partition> parts = part.partition(ctx);

        assertEquals(2, parts.size());
        Partition foo = parts.stream().filter(p -> "Foo".equals(p.evidence().get("class_name")))
                .findFirst().orElseThrow();
        Partition bar = parts.stream().filter(p -> "Bar".equals(p.evidence().get("class_name")))
                .findFirst().orElseThrow();

        assertEquals("qualified-name", foo.method());
        assertTrue(foo.slug().startsWith("q"));
        assertEquals(Set.of("foo_a", "foo_b"), names(foo));
        assertEquals(Set.of("bar_a", "bar_b"), names(bar));
        assertEquals(Boolean.TRUE, foo.evidence().get("span_closed"));
        assertEquals(2, foo.evidence().get("seeded_from_strings"));

        Set<String> all = parts.stream().flatMap(p -> names(p).stream()).collect(Collectors.toSet());
        assertFalse(all.contains("lonely"));
    }

    @Test
    public void partitionSeesOnlyUnassignedFunctions() {
        PartitionContext ctx = twoClassProgram().context();
        ctx.markAssigned(List.of(0, 1));

        List<Partition> parts = part.partition(ctx);
        assertEquals(1, parts.size());
        assertEquals("Bar", parts.get(0).evidence().get("class_name"));
        assertEquals(Set.of("bar_a", "bar_b"), names(parts.get(0)));
    }

    private static PartitionFixtures.Builder twoClassProgram() {
        return PartitionFixtures.builder()
                .function("foo_a", 0x1000).withStrings("Foo::alpha called")
                .function("foo_b", 0x1020).withStrings("Foo::beta done")
                .function("bar_a", 0x1040).withStrings("Bar::gamma start")
                .function("bar_b", 0x1060).withStrings("Bar::delta end")
                .function("lonely", 0x1080).withStrings("no qualified name here");
    }

    private static Set<String> names(Partition p) {
        return p.members().stream().map(Function::getName).collect(Collectors.toSet());
    }
}
