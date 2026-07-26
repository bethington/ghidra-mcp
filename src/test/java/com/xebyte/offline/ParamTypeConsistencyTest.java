package com.xebyte.offline;

import com.xebyte.core.AnnotationScanner;
import com.xebyte.core.ProgramProvider;
import junit.framework.TestCase;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/**
 * A parameter name must mean the same shape everywhere it appears.
 *
 * <p>The MCP schema derives each parameter's declared JSON type from its Java
 * type, so {@code String limitStr} and {@code int limit} publish different
 * schemas for the same logical parameter. Clients -- especially models --
 * generalize from one tool to the next: having learned {@code limit} is a
 * number, they pass a number everywhere, and the one tool that declared it a
 * string rejects the call with a validation error.
 *
 * <p>Found live on 2026-07-25 by the MCP conformance sweep:
 * {@code /get_function_variables} declared {@code limit} as {@code String}
 * while 36 sibling tools declared it {@code int}. Passing {@code limit=5}
 * succeeded on all 36 and failed on that one.
 *
 * <p>Offline: uses the annotation scanner only, no Ghidra program required.
 */
public class ParamTypeConsistencyTest extends TestCase {

    /**
     * Parameters whose type genuinely differs by tool, with the reason. Keep
     * this list short and justified -- each entry is a place where a caller
     * must special-case, so an addition should be a deliberate decision rather
     * than a convenient way to silence this test.
     */
    private static final Set<String> JUSTIFIED_EXCEPTIONS = new LinkedHashSet<>();
    static {
        // `addresses` is a comma-separated string in bulk mode but a JSON array
        // when supplied as a body parameter to the batch-shaped tools.
        JUSTIFIED_EXCEPTIONS.add("addresses");
        // `fields` / `variables` / `assignments` / `labels` are JSON structures
        // whose scanner type varies with how the service declares them.
        JUSTIFIED_EXCEPTIONS.add("fields");
        JUSTIFIED_EXCEPTIONS.add("variables");
        JUSTIFIED_EXCEPTIONS.add("assignments");
        JUSTIFIED_EXCEPTIONS.add("labels");
        JUSTIFIED_EXCEPTIONS.add("value");
    }

    private AnnotationScanner scanner;

    @Override
    protected void setUp() {
        ProgramProvider provider = ServiceFactory.stubProvider();
        scanner = new AnnotationScanner(provider, ServiceFactory.buildAllServices());
    }

    public void testSameParamNameHasSameDeclaredTypeEverywhere() {
        // param name -> declared type -> tools using that type
        Map<String, Map<String, List<String>>> byName = new TreeMap<>();
        for (AnnotationScanner.ToolDescriptor tool : scanner.getDescriptors()) {
            for (AnnotationScanner.ParamDescriptor p : tool.params()) {
                byName
                    .computeIfAbsent(p.name(), k -> new LinkedHashMap<>())
                    .computeIfAbsent(p.type(), k -> new ArrayList<>())
                    .add(tool.path());
            }
        }

        List<String> conflicts = new ArrayList<>();
        for (Map.Entry<String, Map<String, List<String>>> e : byName.entrySet()) {
            String param = e.getKey();
            Map<String, List<String>> types = e.getValue();
            if (types.size() < 2 || JUSTIFIED_EXCEPTIONS.contains(param)) {
                continue;
            }
            StringBuilder sb = new StringBuilder();
            sb.append("  parameter '").append(param).append("' is declared with ")
              .append(types.size()).append(" different types:\n");
            // Report the minority spellings first -- those are the outliers to fix.
            types.entrySet().stream()
                 .sorted((a, b) -> Integer.compare(a.getValue().size(), b.getValue().size()))
                 .forEach(t -> {
                     sb.append("      type=").append(t.getKey())
                       .append("  x").append(t.getValue().size()).append("  ");
                     List<String> paths = t.getValue();
                     sb.append(paths.size() <= 4
                             ? String.join(", ", paths)
                             : String.join(", ", paths.subList(0, 4)) + ", ...");
                     sb.append("\n");
                 });
            conflicts.add(sb.toString());
        }

        assertTrue(
            "Parameters must publish one consistent type across tools; a client that "
            + "learns the type from one tool will fail on the outlier.\n"
            + String.join("", conflicts),
            conflicts.isEmpty());
    }

    /** A parameter that means "how many results" should never be a string. */
    public void testCountLikeParamsAreNumeric() {
        List<String> offenders = new ArrayList<>();
        Set<String> countLike = new LinkedHashSet<>();
        countLike.add("limit");
        countLike.add("offset");
        countLike.add("max_results");
        countLike.add("count");
        countLike.add("timeout");

        for (AnnotationScanner.ToolDescriptor tool : scanner.getDescriptors()) {
            for (AnnotationScanner.ParamDescriptor p : tool.params()) {
                if (countLike.contains(p.name()) && !"integer".equals(p.type())) {
                    offenders.add("  " + tool.path() + " declares " + p.name()
                                  + " as " + p.type() + " (expected integer)");
                }
            }
        }
        assertTrue(
            "Count-like parameters must be integers so callers can pass numbers:\n"
            + String.join("\n", offenders),
            offenders.isEmpty());
    }
}
