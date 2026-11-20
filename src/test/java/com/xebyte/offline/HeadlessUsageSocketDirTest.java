package com.xebyte.offline;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;

import com.xebyte.headless.GhidraMCPHeadlessServer;
import junit.framework.TestCase;

/**
 * The headless --help names every socket directory McpHttpServer.resolveSocketDir
 * can pick (#653): it used to name only $XDG_RUNTIME_DIR/ghidra-mcp/, while an
 * unset XDG_RUNTIME_DIR serves from $TMPDIR/ghidra-mcp-<user>/ instead.
 */
public class HeadlessUsageSocketDirTest extends TestCase {

    private static String usage() {
        PrintStream original = System.out;
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        try {
            System.setOut(new PrintStream(buffer, true, StandardCharsets.UTF_8));
            GhidraMCPHeadlessServer.printUsage();
        } finally {
            System.setOut(original);
        }
        return buffer.toString(StandardCharsets.UTF_8);
    }

    public void testUsageNamesXdgSocketDir() {
        assertTrue(usage().contains("$XDG_RUNTIME_DIR/ghidra-mcp/"));
    }

    public void testUsageNamesUserSuffixedFallbackDir() {
        String usage = usage();
        assertTrue(usage.contains("$TMPDIR/ghidra-mcp-<user>/"));
        assertTrue(usage.contains("java.io.tmpdir"));
        assertTrue(usage.contains("/tmp"));
    }

    public void testUsageNamesSocketFile() {
        assertTrue(usage().contains("ghidra-<pid>.sock"));
    }
}
