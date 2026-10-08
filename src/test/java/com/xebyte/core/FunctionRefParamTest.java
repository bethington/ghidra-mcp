package com.xebyte.core;

import org.junit.Test;

import java.lang.reflect.Method;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * A function-reference parameter carries the standard alias spellings without the
 * endpoint listing them. Twenty-six endpoints used to repeat the same four, in two
 * different orders, so a caller that sent two spellings got a different winner
 * depending on the endpoint.
 */
public class FunctionRefParamTest {

    @SuppressWarnings("unused")
    private static void endpoint(
            @Param(value = "function", paramType = Param.FUNCTION_REF) String function,
            @Param(value = "function_address", paramType = Param.FUNCTION_REF,
                   aliases = {"addr"}) String functionAddress,
            @Param(value = "address", paramType = Param.ADDRESS) String address,
            @Param(value = "name", aliases = {"label"}) String name) {
    }

    private static Param param(int index) throws Exception {
        Method m = FunctionRefParamTest.class.getDeclaredMethod(
            "endpoint", String.class, String.class, String.class, String.class);
        return m.getParameters()[index].getAnnotation(Param.class);
    }

    @Test
    public void aFunctionRefGetsTheStandardAliasesInOneOrder() throws Exception {
        assertArrayEquals(new String[] {"address", "name", "function_address", "function_name"},
            AnnotationScanner.effectiveAliases(param(0)));
    }

    @Test
    public void theParametersOwnNameIsNotItsOwnAlias() throws Exception {
        List<String> aliases = List.of(AnnotationScanner.effectiveAliases(param(1)));
        assertFalse(aliases.contains("function_address"));
        assertTrue(aliases.contains("function"));
    }

    @Test
    public void explicitAliasesComeFirst() throws Exception {
        assertArrayEquals(new String[] {"addr", "address", "name", "function_name", "function"},
            AnnotationScanner.effectiveAliases(param(1)));
    }

    @Test
    public void otherParamTypesKeepExactlyWhatTheyDeclare() throws Exception {
        assertArrayEquals(new String[0], AnnotationScanner.effectiveAliases(param(2)));
        assertArrayEquals(new String[] {"label"}, AnnotationScanner.effectiveAliases(param(3)));
    }

    @Test
    public void theRuntimeResolverAcceptsAnExpandedAlias() throws Exception {
        AnnotationScanner.ParamBinding binding = new AnnotationScanner.ParamBinding(param(0), String.class);
        assertTrue(AnnotationScanner.presentIn(binding, Map.of("function_name", "syna_helper")));
        assertTrue(AnnotationScanner.presentIn(binding, Map.of("name", "syna_helper")));
        assertFalse(AnnotationScanner.presentIn(binding, Map.of("unrelated", "x")));
    }
}
