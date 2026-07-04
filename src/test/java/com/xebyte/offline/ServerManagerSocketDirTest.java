package com.xebyte.offline;

import java.nio.file.Path;

import com.xebyte.core.ServerManager;
import junit.framework.TestCase;

/**
 * Unit tests for ServerManager.resolveSocketDir — the UDS socket directory
 * resolution order: XDG_RUNTIME_DIR → TMPDIR → java.io.tmpdir → /tmp.
 *
 * The java.io.tmpdir step is the cross-drive Windows fix: TMPDIR is unset on
 * Windows and the literal "/tmp" is drive-relative (F:\tmp when Ghidra runs
 * from F:), which a bridge running from another drive never scans.
 * java.io.tmpdir honors %TEMP%, an absolute path both sides agree on.
 *
 * Pure-logic test, no Ghidra runtime required.
 */
public class ServerManagerSocketDirTest extends TestCase {

    public void testXdgRuntimeDirWins() {
        Path dir = ServerManager.resolveSocketDir(
            "/run/user/1000", "/custom/tmp", "/java/tmp", "alice");
        assertEquals(Path.of("/run/user/1000", "ghidra-mcp"), dir);
    }

    public void testTmpdirEnvBeatsJavaIoTmpdir() {
        Path dir = ServerManager.resolveSocketDir(
            null, "/custom/tmp", "/java/tmp", "alice");
        assertEquals(Path.of("/custom/tmp", "ghidra-mcp-alice"), dir);
    }

    public void testJavaIoTmpdirUsedWhenTmpdirUnset() {
        // The Windows case: XDG_RUNTIME_DIR and TMPDIR both unset,
        // java.io.tmpdir = %TEMP%. Must NOT fall through to the
        // drive-relative "/tmp" literal.
        Path dir = ServerManager.resolveSocketDir(
            null, null, "C:\\Users\\alice\\AppData\\Local\\Temp", "alice");
        assertEquals(
            Path.of("C:\\Users\\alice\\AppData\\Local\\Temp", "ghidra-mcp-alice"),
            dir);
    }

    public void testEmptyStringsTreatedAsUnset() {
        Path dir = ServerManager.resolveSocketDir("", "", "/java/tmp", "alice");
        assertEquals(Path.of("/java/tmp", "ghidra-mcp-alice"), dir);
    }

    public void testTmpLiteralIsLastResort() {
        Path dir = ServerManager.resolveSocketDir(null, null, null, "alice");
        assertEquals(Path.of("/tmp", "ghidra-mcp-alice"), dir);

        Path dirEmpty = ServerManager.resolveSocketDir(null, null, "", "alice");
        assertEquals(Path.of("/tmp", "ghidra-mcp-alice"), dirEmpty);
    }

    public void testNullOrEmptyUserFallsBackToUnknown() {
        Path dirNull = ServerManager.resolveSocketDir(null, null, "/java/tmp", null);
        assertEquals(Path.of("/java/tmp", "ghidra-mcp-unknown"), dirNull);

        Path dirEmpty = ServerManager.resolveSocketDir(null, null, "/java/tmp", "");
        assertEquals(Path.of("/java/tmp", "ghidra-mcp-unknown"), dirEmpty);
    }
}
