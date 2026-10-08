package com.xebyte.offline;

import com.xebyte.core.tree.TreeConfig;
import com.xebyte.core.tree.ExclusionEvaluator;
import com.xebyte.core.tree.ExclusionRule;
import com.xebyte.core.partition.Partition;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionTag;
import ghidra.program.model.listing.Program;
import org.junit.Before;
import org.junit.Test;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Offline tests for {@link ExclusionEvaluator}: each rule kind, includeOnly
 * precedence, PARTITION compartment drops, and configure-time range rejection.
 */
public class ExclusionEvaluatorTest {

    private Program program;
    private AddressFactory factory;
    private AddressSpace ramSpace;

    @Before
    public void setUp() {
        program = mock(Program.class);
        factory = mock(AddressFactory.class);
        ramSpace = mock(AddressSpace.class);
        when(ramSpace.getName()).thenReturn("ram");
        when(ramSpace.getType()).thenReturn(AddressSpace.TYPE_RAM);
        when(ramSpace.isOverlaySpace()).thenReturn(false);
        when(program.getAddressFactory()).thenReturn(factory);
        when(factory.getDefaultAddressSpace()).thenReturn(ramSpace);
        when(factory.getAddressSpaces()).thenReturn(new AddressSpace[]{ramSpace});
        when(factory.getAllAddressSpaces()).thenReturn(new AddressSpace[]{ramSpace});
    }

    @Test
    public void tagRuleMatchesExactCaseSensitive() {
        Function tagged = functionWithTags("LIB_CRT");
        Function other = functionWithTags("LIB_STL");
        Function bare = functionWithTags();

        ExclusionEvaluator ev = evaluator(
                List.of(ExclusionRule.parse("tag:LIB_CRT")), List.of());

        assertTrue(ev.matches(ExclusionRule.parse("tag:LIB_CRT"), tagged, "c01"));
        assertFalse(ev.matches(ExclusionRule.parse("tag:LIB_CRT"), other, "c01"));
        assertFalse(ev.matches(ExclusionRule.parse("tag:LIB_CRT"), bare, "c01"));
        // Case-sensitive: the FID tags are exact names.
        assertFalse(ev.matches(ExclusionRule.parse("tag:lib_crt"), tagged, "c01"));
    }

    @Test
    public void rangeRuleMatchesEntryPointContainment() {
        Address lo = addr(0x1000);
        Address mid = addr(0x1500);
        Address hi = addr(0x2000);
        Address outside = addr(0x3000);

        stubAddress("1000", lo);
        stubAddress("2000", hi);

        Function inside = functionAt(mid);
        Function atLo = functionAt(lo);
        Function atHi = functionAt(hi);
        Function out = functionAt(outside);

        ExclusionEvaluator ev = evaluator(
                List.of(ExclusionRule.parse("range:1000-2000")), List.of());

        ExclusionRule rule = ExclusionRule.parse("range:1000-2000");
        assertTrue(ev.matches(rule, inside, "c01"));
        assertTrue(ev.matches(rule, atLo, "c01"));
        assertTrue(ev.matches(rule, atHi, "c01"));
        assertFalse(ev.matches(rule, out, "c01"));
    }

    @Test
    public void partitionRuleMatchesSlugOnly() {
        Function f = functionAt(addr(0x1000));
        ExclusionRule rule = ExclusionRule.parse("partition:c07");
        ExclusionEvaluator ev = evaluator(List.of(rule), List.of());

        assertTrue(ev.matches(rule, f, "c07"));
        assertFalse(ev.matches(rule, f, "c08"));
        assertFalse(ev.matches(rule, f, null));
    }

    @Test
    public void includeOnlyAppliedBeforeExclusions() {
        Function keepAndDrop = functionWithTags("KEEP", "DROP");
        Function dropOnly = functionWithTags("DROP");
        Function keepOnly = functionWithTags("KEEP");
        Function neither = functionWithTags();

        ExclusionEvaluator ev = evaluator(
                List.of(ExclusionRule.parse("tag:DROP")),
                List.of(ExclusionRule.parse("tag:KEEP")));

        assertFalse("KEEP+DROP: exclusion still subtracts after include",
                ev.isInScope(keepAndDrop, "c01"));
        assertFalse(ev.isInScope(dropOnly, "c01"));
        assertTrue(ev.isInScope(keepOnly, "c01"));
        assertFalse("includeOnly miss drops before exclusions run",
                ev.isInScope(neither, "c01"));
    }

    @Test
    public void partitionExclusionDropsExactlyItsCompartment() {
        Function a = functionAt(addr(0x1000));
        Function b = functionAt(addr(0x2000));
        Function c = functionAt(addr(0x3000));

        Partition c07 = new Partition("c07", "address-band", 0.5,
                List.of(a, b), Map.of());
        Partition c08 = new Partition("c08", "address-band", 0.5,
                List.of(c), Map.of());

        ExclusionEvaluator ev = evaluator(
                List.of(ExclusionRule.parse("partition:c07")), List.of());
        ExclusionEvaluator.FilterResult result =
                ev.filterPartitions(List.of(c07, c08), 3);

        assertEquals(1, result.partitions().size());
        assertEquals("c08", result.partitions().get(0).slug());
        assertEquals(1, result.stats().functionsInScope());
        assertEquals(3, result.stats().eligibleFunctions());
        assertEquals(Integer.valueOf(2),
                result.stats().removedByRule().get("partition:c07"));
    }

    @Test
    public void malformedRangeRejectedAtCompileNotSilently() {
        when(factory.getAddress(any())).thenReturn(null);

        TreeConfig cfg = TreeConfig.defaults()
                .withExclusions(List.of(ExclusionRule.parse("range:zzzz-wwww")));
        try {
            ExclusionEvaluator.of(program, cfg);
            fail("expected IllegalArgumentException for unresolvable range");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().contains("range:"));
        }
    }

    @Test
    public void rangeSyntaxRejectedAtParseTime() {
        String[] bad = {"range:onlylo", "range:-1000", "range:1000-", "range:"};
        for (String spec : bad) {
            try {
                ExclusionRule.parse(spec);
                fail("expected parse failure for " + spec);
            } catch (IllegalArgumentException expected) {
                assertTrue(expected.getMessage().contains("range:"));
            }
        }
    }

    @Test
    public void startAfterEndRejectedAtCompile() {
        Address high = addr(0x2000);
        Address low = addr(0x1000);
        stubAddress("2000", high);
        stubAddress("1000", low);

        TreeConfig cfg = TreeConfig.defaults()
                .withExclusions(List.of(ExclusionRule.parse("range:2000-1000")));
        try {
            ExclusionEvaluator.of(program, cfg);
            fail("expected start-after-end rejection");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().contains("start is after end"));
        }
    }

    // --- helpers ---

    private ExclusionEvaluator evaluator(
            List<ExclusionRule> exclusions, List<ExclusionRule> includeOnly) {
        TreeConfig cfg = TreeConfig.defaults()
                .withExclusions(exclusions)
                .withIncludeOnly(includeOnly);
        return ExclusionEvaluator.of(program, cfg);
    }

    private void stubAddress(String hex, Address addr) {
        when(factory.getAddress(hex)).thenReturn(addr);
        when(factory.getAddress("0x" + hex)).thenReturn(addr);
    }

    private Address addr(long offset) {
        Address a = mock(Address.class);
        when(a.getOffset()).thenReturn(offset);
        when(a.toString(false)).thenReturn(Long.toHexString(offset));
        when(a.getAddressSpace()).thenReturn(ramSpace);
        when(a.compareTo(any(Address.class))).thenAnswer(inv -> {
            Address other = inv.getArgument(0);
            return Long.compare(offset, other.getOffset());
        });
        return a;
    }

    private Function functionAt(Address entry) {
        Function f = mock(Function.class);
        when(f.getEntryPoint()).thenReturn(entry);
        when(f.getTags()).thenReturn(Set.of());
        return f;
    }

    private Function functionWithTags(String... names) {
        Function f = functionAt(addr(0x1000));
        if (names.length == 0) {
            when(f.getTags()).thenReturn(Set.of());
            return f;
        }
        HashSet<FunctionTag> tags = new HashSet<>();
        for (String n : names) {
            FunctionTag t = mock(FunctionTag.class);
            when(t.getName()).thenReturn(n);
            tags.add(t);
        }
        when(f.getTags()).thenReturn(tags);
        return f;
    }
}
