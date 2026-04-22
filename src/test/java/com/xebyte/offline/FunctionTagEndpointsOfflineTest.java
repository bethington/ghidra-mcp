package com.xebyte.offline;

import com.xebyte.core.AnnotationScanner;
import com.xebyte.core.ProgramProvider;
import junit.framework.TestCase;

import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * Guard-rail for the v5.4.x function-tag endpoints added to
 * {@code FunctionService}. Locks in each tag tool's method, path, category, and
 * required-param set so a later refactor cannot silently drop one of them.
 *
 * <p>Runs fully offline — shares the existing {@link ServiceFactory} stub wiring.
 */
public class FunctionTagEndpointsOfflineTest extends TestCase {

    /** path -> expected (method, category, required params in any order). */
    private static final Map<String, Expected> EXPECTED = new LinkedHashMap<>();
    static {
        EXPECTED.put("/get_function_tags",
            new Expected("GET",  "function", "function", "program"));
        EXPECTED.put("/add_function_tag",
            new Expected("POST", "function", "function", "tags", "program"));
        EXPECTED.put("/remove_function_tag",
            new Expected("POST", "function", "function", "tags", "program"));
        EXPECTED.put("/list_function_tags",
            new Expected("GET",  "function", "offset", "limit", "program"));
        EXPECTED.put("/create_function_tag",
            new Expected("POST", "function", "name", "comment", "program"));
        EXPECTED.put("/delete_function_tag",
            new Expected("POST", "function", "name", "program"));
        EXPECTED.put("/set_function_tag_comment",
            new Expected("POST", "function", "name", "comment", "program"));
        EXPECTED.put("/search_functions_by_tag",
            new Expected("GET",  "function", "tag", "offset", "limit", "program"));
        EXPECTED.put("/batch_add_function_tags",
            new Expected("POST", "function", "assignments", "program"));
        EXPECTED.put("/batch_remove_function_tags",
            new Expected("POST", "function", "assignments", "program"));
    }

    private AnnotationScanner scanner;

    @Override
    protected void setUp() {
        ProgramProvider provider = ServiceFactory.stubProvider();
        scanner = new AnnotationScanner(provider, ServiceFactory.buildAllServices());
    }

    /** Each tag endpoint must be discovered by the scanner with the expected method + category. */
    public void testEveryTagEndpointIsScannedWithCorrectMethodAndCategory() {
        Map<String, AnnotationScanner.ToolDescriptor> byPath = new HashMap<>();
        for (AnnotationScanner.ToolDescriptor d : scanner.getDescriptors()) {
            byPath.put(d.path(), d);
        }

        for (Map.Entry<String, Expected> e : EXPECTED.entrySet()) {
            String path = e.getKey();
            Expected exp = e.getValue();
            AnnotationScanner.ToolDescriptor d = byPath.get(path);
            assertNotNull(path + " not discovered by AnnotationScanner", d);
            assertEquals(path + " method mismatch", exp.method, d.method());
            assertEquals(path + " category mismatch", exp.category, d.category());
        }
    }

    /**
     * Each tag endpoint must expose exactly the expected set of @Param names.
     * Catches drift where a param is renamed, added, or dropped.
     */
    public void testEveryTagEndpointExposesExpectedParams() {
        Map<String, AnnotationScanner.ToolDescriptor> byPath = new HashMap<>();
        for (AnnotationScanner.ToolDescriptor d : scanner.getDescriptors()) {
            byPath.put(d.path(), d);
        }

        for (Map.Entry<String, Expected> e : EXPECTED.entrySet()) {
            String path = e.getKey();
            Expected exp = e.getValue();
            AnnotationScanner.ToolDescriptor tool = byPath.get(path);
            assertNotNull(path + " not in scanner descriptors", tool);

            Set<String> actual = new TreeSet<>();
            for (AnnotationScanner.ParamDescriptor p : tool.params()) {
                actual.add(p.name());
            }
            Set<String> expected = new TreeSet<>(exp.params);
            assertEquals(path + " param set mismatch (expected " + expected
                + ", got " + actual + ")", expected, actual);
        }
    }

    private static final class Expected {
        final String method;
        final String category;
        final Set<String> params;

        Expected(String method, String category, String... params) {
            this.method = method;
            this.category = category;
            this.params = new LinkedHashSet<>(Arrays.asList(params));
        }
    }
}
