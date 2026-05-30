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
 * Locks method, path, category, and required-param sets for datatype and member-function MCP tools.
 */
public class DatatypeMcpToolsEndpointsOfflineTest extends TestCase {

    private static final Map<String, Expected> EXPECTED = new LinkedHashMap<>();

    static {
        EXPECTED.put("/set_function_this_type",
            new Expected("POST", "function", "function_address", "this_type", "program"));
        EXPECTED.put("/set_decompiler_variable_type",
            new Expected("POST", "function", "function_address", "new_type", "program", "variable_name"));
        EXPECTED.put("/set_parameter_type",
            new Expected("POST", "function", "function_address", "new_type", "parameter_name", "program"));
        EXPECTED.put("/resolve_duplicate_type",
            new Expected("POST", "datatype", "delete_demangler_stub", "program", "type_name"));
        EXPECTED.put("/modify_struct_field_type",
            new Expected("POST", "datatype", "field_name", "new_type", "program", "struct_name"));
        EXPECTED.put("/embed_struct_field",
            new Expected("POST", "datatype", "embedded_struct", "field_name", "parent_struct", "program"));
        EXPECTED.put("/create_struct",
            new Expected("POST", "datatype", "fields", "name", "program", "replace_placeholder"));
        EXPECTED.put("/delete_data_type",
            new Expected("POST", "datatype", "program", "resolve_demangler_duplicate", "type_name"));
        EXPECTED.put("/resize_struct",
            new Expected("POST", "datatype", "force", "name", "new_size", "preserve_fields", "program"));
        EXPECTED.put("/recreate_struct",
            new Expected("POST", "datatype", "fields", "force", "name", "program", "replace_placeholder", "size"));
    }

    private AnnotationScanner scanner;

    @Override
    protected void setUp() {
        ProgramProvider provider = ServiceFactory.stubProvider();
        scanner = new AnnotationScanner(provider, ServiceFactory.buildAllServices());
    }

    public void testEveryDatatypeMcpToolIsScannedWithCorrectMethodAndCategory() {
        Map<String, AnnotationScanner.ToolDescriptor> byPath = indexByPath();
        for (Map.Entry<String, Expected> e : EXPECTED.entrySet()) {
            String path = e.getKey();
            Expected exp = e.getValue();
            AnnotationScanner.ToolDescriptor d = byPath.get(path);
            assertNotNull(path + " not discovered by AnnotationScanner", d);
            assertEquals(path + " method mismatch", exp.method, d.method());
            assertEquals(path + " category mismatch", exp.category, d.category());
        }
    }

    public void testEveryDatatypeMcpToolExposesExpectedParams() {
        Map<String, AnnotationScanner.ToolDescriptor> byPath = indexByPath();
        for (Map.Entry<String, Expected> e : EXPECTED.entrySet()) {
            String path = e.getKey();
            Expected exp = e.getValue();
            AnnotationScanner.ToolDescriptor tool = byPath.get(path);
            assertNotNull(path + " not in scanner descriptors", tool);

            Set<String> actual = new TreeSet<>();
            for (AnnotationScanner.ParamDescriptor p : tool.params()) {
                actual.add(p.name());
            }
            assertEquals(path + " param set mismatch", exp.params, actual);
        }
    }

    private Map<String, AnnotationScanner.ToolDescriptor> indexByPath() {
        Map<String, AnnotationScanner.ToolDescriptor> byPath = new HashMap<>();
        for (AnnotationScanner.ToolDescriptor d : scanner.getDescriptors()) {
            byPath.put(d.path(), d);
        }
        return byPath;
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
