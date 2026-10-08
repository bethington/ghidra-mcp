package com.xebyte.offline;

import com.xebyte.core.AnnotationScanner;
import com.xebyte.core.ManualToolDescriptors;
import com.xebyte.core.ProgramProvider;
import com.xebyte.core.ToolAccess;
import junit.framework.TestCase;

import java.util.ArrayList;
import java.util.List;

/**
 * Every tool must declare what it does to state, and the schema must carry it.
 *
 * <p>This is not a style rule. The bridge turns {@code access} into MCP's
 * {@code readOnlyHint} / {@code destructiveHint}, and clients act on those:
 * Claude Code derives read-only-ness solely from {@code readOnlyHint} (absent ⇒
 * false) and, while planning, forces a permission prompt for every MCP tool that
 * is not read-only — a prompt no allow-rule can suppress, because the plan-mode
 * gate is evaluated before allow-rules and returns early. The same flag decides
 * whether calls may run concurrently. A tool left {@link ToolAccess#UNSPECIFIED}
 * is therefore one an agent cannot use unattended and cannot parallelise, which
 * is why this test fails rather than warns.
 *
 * <p>Runs fully offline — no Ghidra HTTP server required.
 */
public class ToolAccessClassificationTest extends TestCase {

    private AnnotationScanner scanner;

    @Override
    protected void setUp() {
        ProgramProvider provider = ServiceFactory.stubProvider();
        scanner = new AnnotationScanner(provider, ServiceFactory.buildAllServices());
    }

    /** No {@code @McpTool} may be left unclassified. */
    public void testEveryScannedToolDeclaresAccess() {
        List<String> unclassified = new ArrayList<>();
        for (AnnotationScanner.ToolDescriptor tool : scanner.getDescriptors()) {
            if (tool.access() == null || tool.access() == ToolAccess.UNSPECIFIED) {
                unclassified.add(tool.method() + " " + tool.path());
            }
        }
        if (!unclassified.isEmpty()) {
            StringBuilder msg = new StringBuilder();
            msg.append(unclassified.size()).append(" @McpTool method(s) do not declare access:\n");
            for (String u : unclassified) {
                msg.append("  - ").append(u).append("\n");
            }
            msg.append("\nAdd access = ToolAccess.READ_ONLY | WRITE | DESTRUCTIVE to each.\n")
               .append("READ_ONLY means the call changes nothing — not the program, not the\n")
               .append("project, not the host. When in doubt use WRITE: a wrong READ_ONLY lets\n")
               .append("the tool run unattended while an agent is still planning.");
            fail(msg.toString());
        }
    }

    /** The hand-registered routes in ManualToolDescriptors are held to the same rule. */
    public void testEveryManualDescriptorDeclaresAccess() {
        AnnotationScanner s = new AnnotationScanner(
            ServiceFactory.stubProvider(), ServiceFactory.buildAllServices());
        ManualToolDescriptors.addAll(s,
            ManualToolDescriptors.knownPaths().toArray(new String[0]));

        List<String> unclassified = new ArrayList<>();
        for (AnnotationScanner.ToolDescriptor tool : s.getDescriptors()) {
            if (tool.access() == null || tool.access() == ToolAccess.UNSPECIFIED) {
                unclassified.add(tool.method() + " " + tool.path());
            }
        }
        assertTrue("hand-registered routes missing an access value: " + unclassified,
            unclassified.isEmpty());
    }

    /** A classified tool serializes both hints; an unclassified one emits neither. */
    public void testSchemaJsonCarriesTheHints() {
        String json = scanner.generateSchema();
        assertTrue("schema should carry read_only flags", json.contains("\"read_only\": true"));
        assertTrue("schema should carry destructive flags", json.contains("\"destructive\": true"));

        AnnotationScanner.ToolDescriptor unspecified = new AnnotationScanner.ToolDescriptor(
            "/unclassified", "GET", "d", "cat", "", ToolAccess.UNSPECIFIED, List.of());
        String bare = unspecified.toJson();
        assertFalse("an unclassified tool must emit no hints", bare.contains("read_only"));
        assertFalse("an unclassified tool must emit no hints", bare.contains("destructive"));
    }

    /**
     * The mutating GETs are the reason access is declared rather than inferred
     * from the HTTP method. If any of these ever reads {@code READ_ONLY}, an
     * agent can retarget or overwrite a program without being asked.
     */
    public void testKnownMutatingGetsAreNotReadOnly() {
        List<String> mutatingGets = List.of(
            "/switch_program", "/save_program", "/save_all_programs", "/open_program",
            "/disassemble_bytes");
        List<String> wrong = new ArrayList<>();
        for (AnnotationScanner.ToolDescriptor tool : scanner.getDescriptors()) {
            if (mutatingGets.contains(tool.path()) && tool.access() == ToolAccess.READ_ONLY) {
                wrong.add(tool.path());
            }
        }
        assertTrue("these mutate and must never be READ_ONLY: " + wrong, wrong.isEmpty());
    }
}
