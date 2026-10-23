/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.xebyte.offline;

import com.xebyte.core.ServerManager;
import junit.framework.TestCase;

/**
 * The bound TCP port is read from the listener, never remembered.
 *
 * <p>It used to live in a {@code volatile int} that the plugin set after
 * starting its own server and reset on stop, and these tests pinned the setter.
 * Two servers meant two places that had to agree; one place forgot on at least
 * one path (#196, a stale port left in {@code /mcp/instance_info}). With a
 * single {@link com.xebyte.core.McpHttpServer} owning both transports the
 * listener is the only thing that knows, so it is the only thing asked.
 */
public class ServerManagerPortTest extends TestCase {

    /**
     * -1 is the sentinel the {@code /mcp/instance_info} handler surfaces so the
     * bridge knows to fall back to the configured default port rather than
     * trusting a number nobody bound.
     */
    public void testPortIsNegativeOneWhileNothingIsListening() {
        assertFalse("no server should be running in an offline test",
            ServerManager.getInstance().isRunning());
        assertEquals(-1, ServerManager.getInstance().getBoundTcpPort());
    }

    /** Reading it twice cannot drift: there is no state to drift. */
    public void testPortIsDerivedNotStored() {
        ServerManager mgr = ServerManager.getInstance();
        assertEquals(mgr.getBoundTcpPort(), mgr.getBoundTcpPort());
        assertEquals(-1, mgr.getBoundTcpPort());
    }

    /** No listener means no socket either; both answer "not running" the same way. */
    public void testSocketPathIsNullWhileNothingIsListening() {
        assertNull(ServerManager.getInstance().getSocketPath());
    }
}
