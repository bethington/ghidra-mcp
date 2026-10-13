package com.xebyte.offline;

import com.xebyte.core.AnnotationScanner;
import com.xebyte.core.EndpointDef;
import com.xebyte.core.McpTool;
import com.xebyte.core.Param;
import com.xebyte.core.Response;
import ghidra.program.model.listing.Program;
import org.junit.Test;

import java.lang.reflect.Method;
import java.lang.reflect.Parameter;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * A tool that takes a {@code Program} never sees a missing one: the scanner resolves the
 * parameter and answers "No program loaded." itself. One test for every such tool, in place of
 * the per-tool "degrades gracefully" tests each service used to carry.
 */
public class EveryProgramToolRefusesWithoutAProgramTest {

    private static boolean isProgramToolParameter(Parameter parameter) {
        if (parameter.getType() != Program.class) {
            return false;
        }
        for (var ann : parameter.getAnnotations()) {
            if (ann instanceof Param p && "program".equals(p.value())) {
                return true;
            }
        }
        return false;
    }

    private static Set<String> programToolPaths() {
        Set<String> paths = new HashSet<>();
        for (Object service : ServiceFactory.buildAllServices()) {
            for (Method method : service.getClass().getDeclaredMethods()) {
                McpTool tool = method.getAnnotation(McpTool.class);
                if (tool == null) {
                    continue;
                }
                for (Parameter parameter : method.getParameters()) {
                    if (isProgramToolParameter(parameter)) {
                        paths.add(tool.path());
                        break;
                    }
                }
            }
        }
        return paths;
    }

    @Test
    public void everyProgramToolRefusesWithoutAProgram() throws Exception {
        AnnotationScanner scanner = ServiceFactory.buildGuiScanner();
        Set<String> programPaths = programToolPaths();
        int covered = 0;

        for (EndpointDef ep : scanner.getEndpoints()) {
            if (!programPaths.contains(ep.path())) {
                continue;
            }
            Response response = ep.handler().handle(Map.of(), Map.of());
            if (!(response instanceof Response.Err err)) {
                fail(ep.path() + " expected Err without a program, got: " + response.toJson());
            } else {
                assertTrue(ep.path() + " message must start with 'No program loaded', got: " + err.message(),
                        err.message().startsWith("No program loaded"));
            }
            covered++;
        }

        assertEquals("every Program-typed tool is registered and was checked", programPaths.size(), covered);
        assertTrue("the conversion covers most tools; " + covered + " is implausibly few", covered > 110);
    }
}
