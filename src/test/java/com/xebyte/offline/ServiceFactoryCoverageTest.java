package com.xebyte.offline;

import junit.framework.TestCase;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * Every class that declares an {@code @McpTool} must appear in
 * {@link ServiceFactory#buildAllServices()}.
 *
 * <p>Without this, a new tool silently escapes the two tests that are supposed to police
 * it: {@code ToolAccessClassificationTest} and {@code EndpointsJsonParityTest} both scan
 * only what {@code ServiceFactory} hands them, so a service that is missing there makes
 * those tests pass while checking nothing about it. {@code PromptPolicyService} sat in
 * exactly that blind spot — an annotated endpoint absent from the factory, therefore
 * unverified for access classification and catalog parity.
 *
 * <p>Runs fully offline: reads the source tree, reflects on the factory's output.
 */
public class ServiceFactoryCoverageTest extends TestCase {

    private static final Path SOURCE_ROOT = ProjectSource.mainSourceRoot();

    /** Matches a real annotation, not the javadoc examples in McpTool.java (those start with '*'). */
    private static final Pattern ANNOTATION = Pattern.compile("^\\s*@McpTool\\s*\\(");

    private static Set<String> classesDeclaringTools() throws IOException {
        Set<String> found = new TreeSet<>();
        try (Stream<Path> files = Files.walk(SOURCE_ROOT)) {
            for (Path file : (Iterable<Path>) files.filter(p -> p.toString().endsWith(".java"))::iterator) {
                String name = file.getFileName().toString();
                if (name.equals("McpTool.java")) continue;  // the annotation's own definition
                boolean declares = ProjectSource.read(file).lines()
                    .anyMatch(line -> ANNOTATION.matcher(line).find());
                if (declares) found.add(name.substring(0, name.length() - ".java".length()));
            }
        }
        return found;
    }

    public void testEveryAnnotatedServiceIsInServiceFactory() throws IOException {
        assertTrue("source root not found — is the test running from the project root? "
            + SOURCE_ROOT.toAbsolutePath(), Files.isDirectory(SOURCE_ROOT));

        Set<String> declared = classesDeclaringTools();
        assertFalse("scan found no @McpTool classes at all — the scan is broken",
            declared.isEmpty());

        Set<String> wired = new TreeSet<>();
        for (Object service : ServiceFactory.buildAllServices()) {
            wired.add(service.getClass().getSimpleName());
        }

        List<String> missing = new ArrayList<>();
        for (String cls : declared) {
            if (!wired.contains(cls)) missing.add(cls);
        }

        if (!missing.isEmpty()) {
            StringBuilder msg = new StringBuilder();
            msg.append(missing.size()).append(" class(es) declare @McpTool but are absent from ")
               .append("ServiceFactory.buildAllServices():\n");
            for (String cls : missing) msg.append("  - ").append(cls).append("\n");
            msg.append("\nWhile absent, their tools are invisible to ToolAccessClassificationTest\n")
               .append("and EndpointsJsonParityTest — those tests pass without checking them.\n")
               .append("Construct each one in ServiceFactory and add it to the returned array.");
            fail(msg.toString());
        }
    }
}
