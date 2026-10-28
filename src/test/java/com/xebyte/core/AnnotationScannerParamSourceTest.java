package com.xebyte.core;

import org.junit.Test;

import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.*;

/**
 * A parameter must be found wherever the caller actually put it.
 *
 * {@link Param#source()} defaults to {@link ParamSource#QUERY}. On a POST tool that
 * declares its other parameters as BODY, any parameter left at that default is
 * looked for in the query string only -- so a caller following this project's own
 * "POST params go in the body" convention has it silently dropped.
 *
 * For {@code program} the result is not a missing argument but a WRONG TARGET:
 * resolution falls through to the current program, and a write addressed to one
 * program lands in whichever happens to be active while the response still says
 * success. That is not hypothetical -- it put 16442 bookmarks describing one DLL
 * into another, with no error at any point.
 *
 * The same class of bug was already found and patched by hand for {@code dry_run},
 * where the query-only check meant a dry run performed a real write.
 */
public class AnnotationScannerParamSourceTest {

    /** Stands in for a POST tool: body-sourced work params, `program` left at the default. */
    @SuppressWarnings("unused")
    private void postLikeTool(
            @Param(value = "address", source = ParamSource.BODY) String address,
            @Param(value = "program", defaultValue = "") String program) {
    }

    private static AnnotationScanner.ParamBinding bindingFor(String name) throws Exception {
        Method m = AnnotationScannerParamSourceTest.class
                .getDeclaredMethod("postLikeTool", String.class, String.class);
        Annotation[][] anns = m.getParameterAnnotations();
        for (int i = 0; i < anns.length; i++) {
            for (Annotation a : anns[i]) {
                if (a instanceof Param p && p.value().equals(name)) {
                    return new AnnotationScanner.ParamBinding(p, m.getParameterTypes()[i]);
                }
            }
        }
        throw new IllegalArgumentException("no binding for " + name);
    }

    private static Map<String, String> query(String... kv) {
        Map<String, String> m = new HashMap<>();
        for (int i = 0; i < kv.length; i += 2) m.put(kv[i], kv[i + 1]);
        return m;
    }

    private static Map<String, Object> body(String... kv) {
        Map<String, Object> m = new HashMap<>();
        for (int i = 0; i < kv.length; i += 2) m.put(kv[i], kv[i + 1]);
        return m;
    }

    /** The regression: `program` in the JSON body must be seen, not silently dropped. */
    @Test
    public void queryDeclaredParamIsFoundInTheBody() throws Exception {
        Object resolved = AnnotationScanner.resolveParam(
                bindingFor("program"), query(), body("address", "0x1000", "program", "D2Common.dll"));
        assertEquals("a program named in the body must not fall through to the current program",
                "D2Common.dll", resolved);
    }

    /** The Python bridge synthesizes query params; that path must keep working. */
    @Test
    public void queryStillWins() throws Exception {
        Object resolved = AnnotationScanner.resolveParam(
                bindingFor("program"), query("program", "FromQuery.dll"), body("program", "FromBody.dll"));
        assertEquals("the declared source wins when it has a value",
                "FromQuery.dll", resolved);
    }

    /** Absent everywhere still means absent -- the fallback must not invent a value. */
    @Test
    public void missingEverywhereStaysNull() throws Exception {
        assertNull(AnnotationScanner.resolveParam(
                bindingFor("program"), query(), body("address", "0x1000")));
    }

    /** And the reverse direction: a BODY-declared param passed on the query string. */
    @Test
    public void bodyDeclaredParamIsFoundInTheQuery() throws Exception {
        Object resolved = AnnotationScanner.resolveParam(
                bindingFor("address"), query("address", "0x2000"), body());
        assertEquals("0x2000", resolved);
    }

    @Test
    public void presentInSeesNameAndNulls() throws Exception {
        AnnotationScanner.ParamBinding b = bindingFor("program");
        assertTrue(AnnotationScanner.presentIn(b, body("program", "X.dll")));
        assertFalse(AnnotationScanner.presentIn(b, body("other", "X.dll")));
        assertFalse(AnnotationScanner.presentIn(b, null));
    }
}
