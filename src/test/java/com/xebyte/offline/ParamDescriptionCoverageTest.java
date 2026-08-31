package com.xebyte.offline;

import com.xebyte.core.AnnotationScanner;
import com.xebyte.core.ManualToolDescriptors;
import com.xebyte.core.ProgramProvider;
import junit.framework.TestCase;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * Every parameter the server advertises in {@code /mcp/schema} must carry a
 * description.
 *
 * <p>Why this is a test and not a convention: the bridge builds each tool's
 * {@code inputSchema} from that schema, so a parameter with no description
 * reaches the model as a bare name and a type. The model then has to guess the
 * format it was already told server-side — whether an address wants a {@code 0x}
 * prefix, whether a count is bytes or elements, what a boolean does in its false
 * state. That guessing is the expensive half of a large tool surface, and it is
 * invisible from the Java side because nothing fails: the annotation compiles,
 * the endpoint works, and the schema is merely quieter than it should be.
 *
 * <p>Measured before this test existed (2026-08-30, at dev e4d293c): 239 of 674
 * {@code @Param} declarations on {@code @McpTool} methods had no description,
 * plus all 55 hand-registered parameters in {@link ManualToolDescriptors}.
 *
 * <p>Both halves are checked here because they are two different sources for the
 * same field: an annotated tool gets its text from
 * {@code @Param(description = ...)}, while a hand-registered route has no
 * annotation at all and gets it from {@link ManualToolDescriptors}. Closing only
 * one leaves the other free to regrow.
 */
public class ParamDescriptionCoverageTest extends TestCase {

    /** Every {@code @Param} on an {@code @McpTool} method must describe itself. */
    public void testAnnotatedParamsAllHaveDescriptions() {
        ProgramProvider provider = ServiceFactory.stubProvider();
        AnnotationScanner scanner = new AnnotationScanner(provider, ServiceFactory.buildAllServices());

        List<String> missing = collectMissing(scanner.getDescriptors());

        assertTrue("These @Param declarations reach /mcp/schema with no description, so the"
                + " bridge advertises them to the model as a bare name and type. Add"
                + " description = \"...\" to each, saying what the code actually does with the"
                + " value — the accepted format for an address, the unit for a count, what a"
                + " boolean does in BOTH states:\n  " + String.join("\n  ", missing),
            missing.isEmpty());
    }

    /**
     * Hand-registered routes have no annotation to carry a description, so
     * {@link ManualToolDescriptors} is the only place theirs can live.
     */
    public void testManualRouteParamsAllHaveDescriptions() {
        ProgramProvider provider = ServiceFactory.stubProvider();
        AnnotationScanner scanner = new AnnotationScanner(provider, new Object[] {});

        Set<String> paths = ManualToolDescriptors.knownPaths();
        ManualToolDescriptors.addAll(scanner, paths.toArray(new String[0]));

        List<String> missing = collectMissing(scanner.getDescriptors());

        assertTrue("These hand-registered parameters reach /mcp/schema with no description."
                + " They have no @Param annotation to carry one, so the text belongs in"
                + " ManualToolDescriptors.buildAll() as the second half of the name/description"
                + " pair:\n  " + String.join("\n  ", missing),
            missing.isEmpty());
    }

    private static List<String> collectMissing(List<AnnotationScanner.ToolDescriptor> descriptors) {
        List<String> missing = new ArrayList<>();
        for (AnnotationScanner.ToolDescriptor tool : descriptors) {
            for (AnnotationScanner.ParamDescriptor param : tool.params()) {
                String description = param.description();
                if (description == null || description.isBlank()) {
                    missing.add(tool.path() + " (" + param.name() + ")");
                }
            }
        }
        return missing;
    }
}
