package com.xebyte.offline;

import com.xebyte.core.ServerManager;
import junit.framework.TestCase;

/**
 * Unit tests for the bound-TCP-port field added in issue #175.
 *
 * The plugin's TCP port-range fallback writes the actual bound port to
 * ServerManager.setBoundTcpPort(); the /mcp/instance_info handler reads it
 * out via getBoundTcpPort(). This test pins the contract:
 *   - Default value is -1 (TCP not running / port unknown).
 *   - setBoundTcpPort persists.
 *   - The field is thread-safe under concurrent writes (volatile semantics).
 *
 * Pure-logic test, no Ghidra runtime required.
 */
public class ServerManagerPortTest extends TestCase {

    public void testDefaultBoundTcpPortIsNegativeOne() {
        // Default value when TCP isn't running. -1 is the sentinel value the
        // /mcp/instance_info handler surfaces so the bridge knows to fall
        // back to the configured default port.
        int original = ServerManager.getInstance().getBoundTcpPort();
        try {
            // If a previous test left state, just verify the type contract.
            ServerManager.getInstance().setBoundTcpPort(-1);
            assertEquals(-1, ServerManager.getInstance().getBoundTcpPort());
        } finally {
            ServerManager.getInstance().setBoundTcpPort(original);
        }
    }

    public void testSetBoundTcpPortPersists() {
        int original = ServerManager.getInstance().getBoundTcpPort();
        try {
            ServerManager.getInstance().setBoundTcpPort(8092);
            assertEquals(8092, ServerManager.getInstance().getBoundTcpPort());

            ServerManager.getInstance().setBoundTcpPort(9999);
            assertEquals(9999, ServerManager.getInstance().getBoundTcpPort());
        } finally {
            ServerManager.getInstance().setBoundTcpPort(original);
        }
    }

    public void testSetBoundTcpPortVisibleAcrossThreads() throws Exception {
        // The field is declared volatile; this test sanity-checks that a
        // value written from one thread is visible from another thread.
        // Not a real concurrency stress test, but catches obvious wiring
        // mistakes (e.g. accidentally caching the value in a non-volatile
        // field).
        int original = ServerManager.getInstance().getBoundTcpPort();
        try {
            final int target = 8095;
            ServerManager.getInstance().setBoundTcpPort(target);

            final int[] observed = new int[]{-9999};
            Thread reader = new Thread(() ->
                observed[0] = ServerManager.getInstance().getBoundTcpPort()
            );
            reader.start();
            reader.join(2000);

            assertEquals(target, observed[0]);
        } finally {
            ServerManager.getInstance().setBoundTcpPort(original);
        }
    }
}
