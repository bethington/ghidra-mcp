package com.xebyte.offline;

import com.xebyte.core.tree.TreeConfig;
import com.xebyte.core.tree.ExclusionRule;
import org.junit.Test;

import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Offline tests for {@link TreeConfig} clamps and {@link ExclusionRule} parsing.
 */
public class TreeConfigTest {

    @Test
    public void parsesAllThreeExclusionKinds() {
        ExclusionRule tag = ExclusionRule.parse("tag:LIB_CRT");
        assertEquals(ExclusionRule.Kind.TAG, tag.kind());
        assertEquals("LIB_CRT", tag.value());

        ExclusionRule part = ExclusionRule.parse("partition:c07");
        assertEquals(ExclusionRule.Kind.PARTITION, part.kind());
        assertEquals("c07", part.value());

        ExclusionRule range = ExclusionRule.parse("range:6fdd0000-6fde0000");
        assertEquals(ExclusionRule.Kind.RANGE, range.kind());
        assertEquals("6fdd0000-6fde0000", range.value());
    }

    @Test
    public void malformedExclusionThrowsNamingAcceptedForms() {
        String[] bad = {
                "",
                "LIB_CRT",
                "name:Foo.*",
                "tag:",
                ":LIB_CRT",
                "range:onlylo",
                "regex:.*",
        };
        for (String spec : bad) {
            try {
                ExclusionRule.parse(spec);
                fail("expected IllegalArgumentException for: " + spec);
            } catch (IllegalArgumentException expected) {
                assertTrue(
                        "message must name accepted forms: " + expected.getMessage(),
                        expected.getMessage().contains("tag:")
                                && expected.getMessage().contains("partition:")
                                && expected.getMessage().contains("range:"));
            }
        }
    }

    @Test
    public void throttlePercentClampsToZeroThroughNinety() {
        assertEquals(0, TreeConfig.defaults().withThrottlePercent(-5).throttlePercent());
        assertEquals(90, TreeConfig.defaults().withThrottlePercent(150).throttlePercent());
        assertEquals(10, TreeConfig.defaults().throttlePercent());
        assertEquals(45, TreeConfig.builder().throttlePercent(45).build().throttlePercent());
    }

    @Test
    public void bandSizeFloorsAtOne() {
        assertEquals(1, TreeConfig.defaults().withBandSize(0).bandSize());
        assertEquals(1, TreeConfig.defaults().withBandSize(-9).bandSize());
        assertEquals(20, TreeConfig.defaults().bandSize());
        assertEquals(64, TreeConfig.builder().bandSize(64).build().bandSize());
    }

    @Test
    public void defaultsUseEmptyListsMeaningFullCascade() {
        TreeConfig cfg = TreeConfig.defaults();
        assertTrue(cfg.enabledStrategies().isEmpty());
        assertTrue(cfg.exclusions().isEmpty());
        assertTrue(cfg.includeOnly().isEmpty());
        assertEquals(30, cfg.decompileTimeoutSeconds());
        assertEquals(600, cfg.analysisWaitSeconds());
        assertEquals(32768, cfg.maxFileBytes());
        assertTrue(cfg.disassembleMissing());
    }

    @Test
    public void disassembleMissingDefaultsTrueAndRoundTrips() {
        assertTrue(TreeConfig.defaults().disassembleMissing());
        assertFalse(TreeConfig.builder().disassembleMissing(false).build().disassembleMissing());
        assertTrue(TreeConfig.defaults().withDisassembleMissing(false).withDisassembleMissing(true)
                .disassembleMissing());
    }

    @Test
    public void maxFileBytesFloorsAt4096AndDefaultsTo32768() {
        assertEquals(4096, TreeConfig.defaults().withMaxFileBytes(100).maxFileBytes());
        assertEquals(4096, TreeConfig.defaults().withMaxFileBytes(0).maxFileBytes());
        assertEquals(32768, TreeConfig.defaults().maxFileBytes());
        assertEquals(65536, TreeConfig.builder().maxFileBytes(65536).build().maxFileBytes());
    }

    @Test
    public void withersPreserveAndReplaceFields() {
        TreeConfig cfg = TreeConfig.defaults()
                .withExclusions(List.of(ExclusionRule.parse("tag:LIB_CRT")))
                .withIncludeOnly(List.of(ExclusionRule.parse("partition:c03")))
                .withEnabledStrategies(List.of("literal_locality"));
        assertEquals(1, cfg.exclusions().size());
        assertEquals(1, cfg.includeOnly().size());
        assertEquals(List.of("literal_locality"), cfg.enabledStrategies());
    }
}
