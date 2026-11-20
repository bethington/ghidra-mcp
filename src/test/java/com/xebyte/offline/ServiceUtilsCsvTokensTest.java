package com.xebyte.offline;

import com.xebyte.core.ServiceUtils;
import org.junit.Test;

import java.util.List;

import static org.junit.Assert.*;

/** Offline coverage for {@link ServiceUtils#csvTokens(String)}. */
public class ServiceUtilsCsvTokensTest {

    @Test
    public void nullAndBlankYieldEmpty() {
        assertEquals(List.of(), ServiceUtils.csvTokens(null));
        assertEquals(List.of(), ServiceUtils.csvTokens(""));
        assertEquals(List.of(), ServiceUtils.csvTokens("   "));
        assertEquals(List.of(), ServiceUtils.csvTokens("\t"));
    }

    @Test
    public void trimsAndSkipsBlankTokens() {
        assertEquals(List.of("a", "b", "c"), ServiceUtils.csvTokens("a, b, c"));
        assertEquals(List.of("a", "b"), ServiceUtils.csvTokens("a,,b"));
        assertEquals(List.of("a", "b"), ServiceUtils.csvTokens(" a , , b "));
        assertEquals(List.of("one"), ServiceUtils.csvTokens("one"));
    }

    @Test
    public void preservesInternalWhitespaceInsideAToken() {
        // Trim ends only; a token that is meaningful after trim is kept as-is.
        assertEquals(List.of("hello world"), ServiceUtils.csvTokens(" hello world "));
    }
}
