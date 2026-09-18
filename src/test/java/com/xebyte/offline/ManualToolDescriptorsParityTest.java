package com.xebyte.offline;

import com.xebyte.core.ManualToolDescriptors;
import junit.framework.TestCase;

import java.io.IOException;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Source-level regression pinning {@link ManualToolDescriptors} in sync with
 * the actual {@code createContext}/{@code safeContext} calls in the GUI and
 * headless servers.
 *
 * <p>Background: {@code /mcp/schema} is generated purely from {@code @McpTool}
 * reflection. Routes registered directly via {@code createContext}/
 * {@code safeContext} (utility/server/project/tool endpoints that predate the
 * annotation-scanner convention) were fully live and callable but invisible in
 * the schema — and therefore invisible to the Python bridge's dynamic tool
 * discovery — found via a live-schema-vs-catalog diff while investigating a
 * "272 vs 222 tools" release-notes discrepancy (v6.0.0).
 * {@link ManualToolDescriptors} closes that gap with a hand-maintained
 * registry sourced from {@code tests/endpoints.json}. These tests keep the
 * registry from silently drifting again in either direction: a new manual
 * route added without a descriptor (schema regresses to invisible), or a
 * descriptor left behind after its route is removed (schema advertises a
 * tool that 404s).
 *
 * <p>Pure source-text checks — no Ghidra runtime/classpath required, unlike
 * {@code EndpointsJsonParityTest} which needs a full service build.
 */
public class ManualToolDescriptorsParityTest extends TestCase {

    private static final Pattern GUI_CONTEXT = Pattern.compile(
        "(?:server|httpServer)\\.createContext\\(\\s*\"([^\"]+)\"");
    private static final Pattern HEADLESS_CONTEXT = Pattern.compile(
        "safeContext\\(\\s*\"([^\"]+)\"");

    /**
     * Routes registered via a literal createContext call that are
     * intentionally NOT in {@link ManualToolDescriptors} — pure runtime
     * introspection metadata, not meant to be discoverable/callable as an
     * MCP tool by an AI agent.
     */
    private static final Set<String> EXEMPT = Set.of(
        "/mcp/instance_info"
    );

    /** Anchored on the project root and LF-normalised — see {@link ProjectSource}. */
    private static String readSource(String... parts) throws IOException {
        return ProjectSource.readMainSource(parts);
    }

    private static Set<String> extractPaths(Pattern pattern, String src) {
        Set<String> out = new LinkedHashSet<>();
        Matcher m = pattern.matcher(src);
        while (m.find()) out.add(m.group(1));
        return out;
    }

    public void testEveryGuiManualRouteHasADescriptor() throws IOException {
        String src = readSource("GhidraMCPPlugin.java");
        Set<String> guiPaths = extractPaths(GUI_CONTEXT, src);
        Set<String> known = ManualToolDescriptors.knownPaths();

        for (String path : guiPaths) {
            if (EXEMPT.contains(path)) continue;
            assertTrue(
                "GUI registers \"" + path + "\" via createContext but "
                    + "ManualToolDescriptors has no entry for it -- the route is "
                    + "live but invisible in /mcp/schema. Add it to "
                    + "ManualToolDescriptors.buildAll().",
                known.contains(path));
        }
    }

    public void testEveryHeadlessManualRouteHasADescriptor() throws IOException {
        String src = readSource("headless", "GhidraMCPHeadlessServer.java");
        Set<String> headlessPaths = extractPaths(HEADLESS_CONTEXT, src);
        Set<String> known = ManualToolDescriptors.knownPaths();

        for (String path : headlessPaths) {
            if (EXEMPT.contains(path)) continue;
            assertTrue(
                "Headless registers \"" + path + "\" via safeContext but "
                    + "ManualToolDescriptors has no entry for it -- the route is "
                    + "live but invisible in /mcp/schema. Add it to "
                    + "ManualToolDescriptors.buildAll().",
                known.contains(path));
        }
    }

    public void testNoOrphanedDescriptors() throws IOException {
        String guiSrc = readSource("GhidraMCPPlugin.java");
        String headlessSrc = readSource("headless", "GhidraMCPHeadlessServer.java");
        Set<String> registered = new LinkedHashSet<>();
        registered.addAll(extractPaths(GUI_CONTEXT, guiSrc));
        registered.addAll(extractPaths(HEADLESS_CONTEXT, headlessSrc));

        for (String path : ManualToolDescriptors.knownPaths()) {
            assertTrue(
                "ManualToolDescriptors has an entry for \"" + path + "\" but "
                    + "neither server registers it via createContext/safeContext "
                    + "-- the schema would advertise a tool that 404s. Remove the "
                    + "stale entry from ManualToolDescriptors.buildAll().",
                registered.contains(path));
        }
    }

    /** Every descriptor must be wired into at least one server's addAll(...) call. */
    public void testEveryDescriptorIsWiredIntoAtLeastOneServer() throws IOException {
        String guiSrc = readSource("GhidraMCPPlugin.java");
        String headlessSrc = readSource("headless", "GhidraMCPHeadlessServer.java");
        for (String path : ManualToolDescriptors.knownPaths()) {
            String quoted = "\"" + path + "\"";
            assertTrue(
                "ManualToolDescriptors has an entry for \"" + path + "\" but it "
                    + "is not passed to ManualToolDescriptors.addAll(...) in "
                    + "either server -- it was registered in the map but never "
                    + "actually added to a live schema.",
                guiSrc.contains(quoted) || headlessSrc.contains(quoted));
        }
    }
}
