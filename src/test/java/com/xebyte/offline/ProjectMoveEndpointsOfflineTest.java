package com.xebyte.offline;

import com.xebyte.core.AnnotationScanner;
import com.xebyte.core.ProgramProvider;
import com.xebyte.core.ParamSource;
import com.xebyte.core.Response;
import junit.framework.TestCase;

import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * Guard-rail for the project-organization endpoints on {@code ProgramScriptService}.
 *
 * <p>{@code /move_file} and {@code /move_folder} spent several releases in a
 * state that no existing test could see: hand-routed inside
 * {@code GhidraMCPHeadlessServer}, absent from the GUI/FrontEnd server
 * entirely, and listed in {@code tests/endpoints.json} via
 * {@code ManualToolDescriptors}. The catalog therefore advertised two tools
 * that a FrontEnd-mode {@code /mcp/schema} never served, so the Python bridge
 * never discovered them and every call 404'd with "No context found for
 * request". {@code EndpointsJsonParityTest} could not catch it — parity only
 * asserts that every {@code @McpTool} appears in the catalog, never that every
 * catalog entry is actually reachable.
 *
 * <p>These tests assert the tools are discovered by the {@link AnnotationScanner}
 * itself, which is what registers them in <em>all</em> modes. Runs fully
 * offline on the shared {@link ServiceFactory} stub wiring.
 */
public class ProjectMoveEndpointsOfflineTest extends TestCase {

    /** path -> expected (method, category, param names in any order). */
    private static final Map<String, Expected> EXPECTED = new LinkedHashMap<>();
    static {
        EXPECTED.put("/move_file",
            new Expected("POST", "project", "filePath", "destFolder"));
        EXPECTED.put("/move_folder",
            new Expected("POST", "project", "sourcePath", "destPath"));
        // Siblings that already worked; locked in here so a future refactor of
        // this group cannot quietly regress one of them the same way.
        EXPECTED.put("/create_folder",
            new Expected("POST", "project", "path", "program"));
        EXPECTED.put("/delete_file",
            new Expected("POST", "project", "filePath"));
    }

    private AnnotationScanner scanner;

    @Override
    protected void setUp() {
        ProgramProvider provider = ServiceFactory.stubProvider();
        scanner = new AnnotationScanner(provider, ServiceFactory.buildAllServices());
    }

    private Map<String, AnnotationScanner.ToolDescriptor> byPath() {
        Map<String, AnnotationScanner.ToolDescriptor> byPath = new HashMap<>();
        for (AnnotationScanner.ToolDescriptor d : scanner.getDescriptors()) {
            byPath.put(d.path(), d);
        }
        return byPath;
    }

    /**
     * The core regression: these must come from the scanner, not from a
     * hand-registered descriptor. Scanner discovery is what makes a tool live
     * in GUI, FrontEnd and headless mode alike.
     */
    public void testMoveEndpointsAreScannedWithCorrectMethodAndCategory() {
        Map<String, AnnotationScanner.ToolDescriptor> byPath = byPath();
        for (Map.Entry<String, Expected> e : EXPECTED.entrySet()) {
            String path = e.getKey();
            AnnotationScanner.ToolDescriptor d = byPath.get(path);
            assertNotNull(path + " not discovered by AnnotationScanner — it must be an "
                + "@McpTool method, not a manually routed context", d);
            assertEquals(path + " method mismatch", e.getValue().method, d.method());
            assertEquals(path + " category mismatch", e.getValue().category, d.category());
        }
    }

    /** Param names must match exactly — the bridge builds its tool schema from these. */
    public void testMoveEndpointsExposeExpectedParams() {
        Map<String, AnnotationScanner.ToolDescriptor> byPath = byPath();
        for (Map.Entry<String, Expected> e : EXPECTED.entrySet()) {
            String path = e.getKey();
            AnnotationScanner.ToolDescriptor tool = byPath.get(path);
            assertNotNull(path + " not in scanner descriptors", tool);

            Set<String> actual = new TreeSet<>();
            for (AnnotationScanner.ParamDescriptor p : tool.params()) {
                actual.add(p.name());
            }
            assertEquals(path + " param set mismatch",
                new TreeSet<>(e.getValue().params), actual);
        }
    }

    /**
     * Both move tools are POST-with-a-body. A param that defaulted to QUERY
     * would be dropped by any caller that sends JSON, which is the documented
     * convention hazard in CLAUDE.md.
     */
    public void testMoveParamsAreBodySourced() {
        Map<String, AnnotationScanner.ToolDescriptor> byPath = byPath();
        for (String path : new String[] {"/move_file", "/move_folder"}) {
            AnnotationScanner.ToolDescriptor tool = byPath.get(path);
            assertNotNull(path + " not in scanner descriptors", tool);
            for (AnnotationScanner.ParamDescriptor p : tool.params()) {
                assertEquals(path + " param '" + p.name() + "' must be body-sourced",
                    ParamSource.BODY.name().toLowerCase(), p.source().toLowerCase());
            }
        }
    }

    /**
     * {@code ProgramProvider.getProject()} is the seam that keeps these tools
     * working headless, where there is no PluginTool at all. The interface
     * default must stay null-returning so GUI providers fall through to the
     * tool, and the method must exist for HeadlessProgramProvider to override.
     */
    public void testProgramProviderExposesProjectSeam() throws Exception {
        assertNotNull("ProgramProvider.getProject() is missing — the shared project "
            + "endpoints would become GUI-only again",
            ProgramProvider.class.getMethod("getProject"));
        assertNull("Default ProgramProvider.getProject() must return null so GUI "
            + "providers fall back to their PluginTool",
            ServiceFactory.stubProvider().getProject());
    }

    /**
     * With no project resolvable (the stub provider has none and there is no
     * PluginTool offline), both tools must fail closed with an error rather
     * than throwing or reporting success.
     */
    public void testMoveFailsClosedWithoutAProject() {
        Object svc = null;
        for (Object candidate : ServiceFactory.buildAllServices()) {
            if (candidate.getClass().getSimpleName().equals("ProgramScriptService")) {
                svc = candidate;
                break;
            }
        }
        assertNotNull("ProgramScriptService not present in ServiceFactory wiring", svc);

        try {
            Response moved = (Response) svc.getClass()
                .getMethod("moveFile", String.class, String.class)
                .invoke(svc, "/Vanilla/1.00/D2Server.dll", "/Mods/PD2-S12");
            assertTrue("move_file must fail closed with Response.Err when no project is open, got: "
                + moved.toJson(), moved instanceof Response.Err);

            Response movedDir = (Response) svc.getClass()
                .getMethod("moveFolder", String.class, String.class)
                .invoke(svc, "/Vanilla/1.00", "/Mods");
            assertTrue("move_folder must fail closed with Response.Err when no project is open, got: "
                + movedDir.toJson(), movedDir instanceof Response.Err);
        } catch (Exception e) {
            fail("move tools must return an error Response, never throw: " + e);
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
