package com.xebyte.offline;

import com.xebyte.core.SecurityConfig;
import com.xebyte.headless.SharedProjectLocator;
import junit.framework.TestCase;

import java.nio.file.Path;

/**
 * Offline coverage for {@link SharedProjectLocator} — URL parse, local-path
 * branch selection, containment, and host+port+repo directory keys.
 *
 * <p>Does not open a real Ghidra project; that path needs a live server and
 * is left to the operator's acceptance loop.
 */
public class SharedProjectLocatorTest extends TestCase {

    public void testParseHostPortRepo() {
        SharedProjectLocator.Parsed p =
                SharedProjectLocator.parseServerUrl("ghidra://127.0.0.1:13100/firmware-shared");
        assertEquals("127.0.0.1", p.host());
        assertEquals(13100, p.port());
        assertEquals("firmware-shared", p.repo());
        assertEquals("127.0.0.1_13100_firmware-shared", p.directoryKey());
    }

    public void testParsePortLessDefaultsTo13100() {
        // analyzeHeadless and ClientUtil treat the bare form as port 13100.
        SharedProjectLocator.Parsed p =
                SharedProjectLocator.parseServerUrl("ghidra://127.0.0.1/firmware-shared");
        assertEquals("127.0.0.1", p.host());
        assertEquals(SharedProjectLocator.DEFAULT_SERVER_PORT, p.port());
        assertEquals("firmware-shared", p.repo());
        assertEquals("127.0.0.1_13100_firmware-shared", p.directoryKey());
    }

    public void testParseIgnoresPathBeyondRepo() {
        SharedProjectLocator.Parsed p =
                SharedProjectLocator.parseServerUrl("ghidra://host:13100/repo/folder/file");
        assertEquals("repo", p.repo());
        assertEquals("host", p.host());
    }

    public void testPlainPathIsLocalBranch() {
        assertTrue(SharedProjectLocator.isLocalProjectPath("/tmp/MyProject.gpr"));
        assertTrue(SharedProjectLocator.isLocalProjectPath("/projects/foo"));
        assertFalse(SharedProjectLocator.isLocalProjectPath(
                "ghidra://127.0.0.1:13100/firmware-shared"));
        assertFalse(SharedProjectLocator.isGhidraUrl("/tmp/MyProject.gpr"));
        assertTrue(SharedProjectLocator.isGhidraUrl(
                "ghidra://127.0.0.1/firmware-shared"));
    }

    public void testMalformedUrlIsErrorNotLocalCreate() {
        assertTrue("ghidra: prefix must take the URL branch",
                SharedProjectLocator.isGhidraUrl("ghidra://bad"));
        try {
            SharedProjectLocator.parseServerUrl("ghidra://bad");
            fail("expected IllegalArgumentException for missing repo");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().toLowerCase().contains("repository")
                    || expected.getMessage().toLowerCase().contains("missing"));
        }
        try {
            SharedProjectLocator.parseServerUrl("ghidra://host/");
            fail("expected IllegalArgumentException for empty repo");
        } catch (IllegalArgumentException expected) {
            // ok
        }
        try {
            // Local ghidra:/path must not silently become a shared-project create.
            SharedProjectLocator.parseServerUrl("ghidra:/tmp/MyProject");
            fail("expected IllegalArgumentException for local ghidra URL");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().contains("Server URL")
                    || expected.getMessage().toLowerCase().contains("expected"));
        }
    }

    public void testDirectoryKeyedByHostPortRepo() {
        SharedProjectLocator.Parsed a =
                SharedProjectLocator.parseServerUrl("ghidra://a.example:13100/repo");
        SharedProjectLocator.Parsed b =
                SharedProjectLocator.parseServerUrl("ghidra://b.example:13100/repo");
        assertFalse("different hosts must not share a project dir",
                a.directoryKey().equals(b.directoryKey()));

        SharedProjectLocator.Parsed sameHostDifferentPort =
                SharedProjectLocator.parseServerUrl("ghidra://a.example:13101/repo");
        assertFalse("different ports must not share a project dir",
                a.directoryKey().equals(sameHostDifferentPort.directoryKey()));
    }

    public void testResolveProjectDirUsesDefaultUnderHome() {
        SharedProjectLocator.Parsed p =
                SharedProjectLocator.parseServerUrl("ghidra://127.0.0.1:13100/firmware-shared");
        Path dir = SharedProjectLocator.resolveProjectDir(
                p, null, SecurityConfig.getInstance());
        assertTrue(dir.isAbsolute());
        assertEquals("127.0.0.1_13100_firmware-shared", dir.getFileName().toString());
        assertTrue(dir.toString().contains(".ghidra-mcp"));
        assertTrue(dir.toString().contains("shared-projects"));
    }

    public void testResolveProjectDirOverrideMustBeAbsolute() {
        SharedProjectLocator.Parsed p =
                SharedProjectLocator.parseServerUrl("ghidra://127.0.0.1:13100/firmware-shared");
        try {
            SharedProjectLocator.resolveProjectDir(p, "relative/shared", SecurityConfig.getInstance());
            fail("relative override must be rejected");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().contains("absolute"));
        }
    }

    public void testResolveProjectDirOverrideIsContainmentChecked() {
        SharedProjectLocator.Parsed p =
                SharedProjectLocator.parseServerUrl("ghidra://127.0.0.1:13100/firmware-shared");
        SecurityConfig security = SecurityConfig.getInstance();
        // When FILE_ROOT is unset, resolveWithinFileRoot returns the path as-is
        // (pre-v5.4.1). When it IS set, an escape must fail — probe both.
        if (!security.hasFileRoot()) {
            Path dir = SharedProjectLocator.resolveProjectDir(
                    p, "/tmp/ghidra-mcp-shared-test-root", security);
            assertEquals("127.0.0.1_13100_firmware-shared", dir.getFileName().toString());
            assertTrue(dir.startsWith(Path.of("/tmp/ghidra-mcp-shared-test-root")));
        } else {
            // Escape the configured root — must not silently accept.
            String outside = "/tmp/definitely-outside-file-root-" + System.nanoTime();
            try {
                SharedProjectLocator.resolveProjectDir(p, outside, security);
                fail("path outside GHIDRA_MCP_FILE_ROOT must be rejected");
            } catch (IllegalArgumentException expected) {
                assertTrue(expected.getMessage().contains("FILE_ROOT")
                        || expected.getMessage().contains("escapes"));
            }
        }
    }
}
