package com.xebyte.offline;

import com.xebyte.core.partition.Applicability;
import com.xebyte.core.partition.LiteralLocalityPartitioner;
import com.xebyte.core.partition.Partition;
import com.xebyte.core.partition.PartitionContext;
import ghidra.program.model.listing.Function;
import org.junit.Test;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.Assert.*;

/**
 * Offline tests for {@link LiteralLocalityPartitioner}.
 *
 * <p>Applicability needs {@code MIN_SIGNAL_FUNCTIONS = 100} string-referencing
 * functions, so the positive cases build a 110-function mock program.
 */
public class LiteralLocalityPartitionerTest {

    private final LiteralLocalityPartitioner part = new LiteralLocalityPartitioner();

    @Test
    public void probeNotApplicableWithTooFewStringReferences() {
        PartitionFixtures.Builder b = PartitionFixtures.builder();
        for (int i = 0; i < 10; i++) {
            b.function("f" + i, 0x1000L + i * 0x20L)
                    .withStrings("word" + i + "token")
                    .withMedianStringAddr(0x60000000L + i * 100L);
        }
        PartitionContext ctx = b.context();

        Applicability a = part.probe(ctx);
        assertFalse(a.applicable());
        assertTrue(a.reason().contains("too few") || a.reason().contains("need 100"));
    }

    @Test
    public void probeApplicableWhenCoherentObjectOrderingIsVisible() {
        PartitionContext ctx = coherentProgram(110, /*cutAt*/ -1).context();
        Applicability a = part.probe(ctx);
        assertTrue(a.reason(), a.applicable());
        assertEquals(1.0, a.expectedCoverage(), 0.0);
        assertTrue(a.reason().contains("tighter") || a.reason().contains("signal"));
    }

    @Test
    public void partitionCutsOnLargeLiteralJumpsAndLeavesTinyRuns() {
        PartitionContext ctx = coherentProgram(110, /*cutAt*/ 60).context();
        assertTrue(part.probe(ctx).applicable());

        List<Partition> parts = part.partition(ctx);
        assertTrue("expected at least two compartments around the cut, got " + parts.size(),
                parts.size() >= 2);
        assertEquals("literal-locality", parts.get(0).method());
        assertTrue(parts.get(0).slug().startsWith("c"));
        assertTrue(parts.get(0).evidence().containsKey("boundary_threshold_bytes"));
        assertTrue(parts.get(0).evidence().containsKey("evidence_backed_members"));

        int placed = parts.stream().mapToInt(Partition::size).sum();
        assertTrue(placed >= 6);
        Set<String> allNames = ctx.functions().stream().map(Function::getName)
                .collect(Collectors.toSet());
        for (Partition p : parts) {
            for (Function f : p.members()) {
                assertTrue(allNames.contains(f.getName()));
            }
            assertTrue(p.size() >= 3);
        }
    }

    @Test
    public void partitionOnlyPlacesUnassignedFunctions() {
        PartitionContext ctx = coherentProgram(110, 60).context();
        List<Integer> firstBlock = new ArrayList<>();
        for (int i = 0; i < 60; i++) firstBlock.add(i);
        ctx.markAssigned(firstBlock);

        List<Partition> parts = part.partition(ctx);
        Set<String> claimed = new HashSet<>();
        for (Partition p : parts) {
            for (Function f : p.members()) claimed.add(f.getName());
        }
        for (int i = 0; i < 60; i++) {
            assertFalse("pre-assigned f" + i + " must not be re-placed",
                    claimed.contains("f" + i));
        }
        assertFalse(claimed.isEmpty());
    }

    /**
     * @param cutAt index at which string addresses jump by 1MB; {@code -1} means no jump
     */
    private static PartitionFixtures.Builder coherentProgram(int n, int cutAt) {
        PartitionFixtures.Builder b = PartitionFixtures.builder();
        long cursor = 0x60000000L;
        for (int i = 0; i < n; i++) {
            if (i == cutAt) {
                cursor += 1_000_000L;
            }
            b.function("f" + i, 0x1000L + i * 0x20L)
                    .withStrings("tok_" + i + "_word")
                    .withMedianStringAddr(cursor);
            cursor += 100L;
        }
        return b;
    }
}
