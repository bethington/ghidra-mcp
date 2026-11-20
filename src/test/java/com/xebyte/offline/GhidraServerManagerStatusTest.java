package com.xebyte.offline;

import com.xebyte.headless.GhidraServerManager;
import ghidra.framework.client.ClientUtil;
import ghidra.framework.client.NotConnectedException;
import ghidra.framework.client.RepositoryServerAdapter;
import org.junit.Test;
import org.mockito.MockedStatic;

import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

/**
 * Measured on a host restart: the headless server's connect was refused while the Ghidra
 * Server was still starting, the project reconnected the shared adapter later, and
 * /server/status reported "connected": false with the old error for two days while every
 * checkout succeeded. Status must describe the adapter as it is, not as it last was.
 */
public class GhidraServerManagerStatusTest {

    @Test
    public void reconnectionThatBypassedConnectIsReported() throws Exception {
        RepositoryServerAdapter adapter = mock(RepositoryServerAdapter.class);
        when(adapter.connect()).thenThrow(new NotConnectedException("Not connected to repository server"));
        try (MockedStatic<ClientUtil> client = mockStatic(ClientUtil.class)) {
            client.when(() -> ClientUtil.getRepositoryServer(anyString(), anyInt())).thenReturn(adapter);
            GhidraServerManager manager = new GhidraServerManager("ghidra-server", 13100, "svc", "pw");

            manager.connect();
            Map<String, Object> refused = manager.status();
            assertEquals(false, refused.get("connected"));
            assertEquals("Not connected to repository server", refused.get("last_error"));

            when(adapter.isConnected()).thenReturn(true);
            Map<String, Object> reconnected = manager.status();
            assertEquals(true, reconnected.get("connected"));
            assertFalse("a past failure is not a current one", reconnected.containsKey("last_error"));
            assertTrue(manager.isConnected());
            assertSame(adapter, manager.server());
        }
    }

    @Test
    public void droppedConnectionIsReportedAsDisconnected() throws Exception {
        RepositoryServerAdapter adapter = mock(RepositoryServerAdapter.class);
        when(adapter.connect()).thenReturn(true);
        when(adapter.isConnected()).thenReturn(true);
        try (MockedStatic<ClientUtil> client = mockStatic(ClientUtil.class)) {
            client.when(() -> ClientUtil.getRepositoryServer(anyString(), anyInt())).thenReturn(adapter);
            GhidraServerManager manager = new GhidraServerManager("ghidra-server", 13100, "svc", "pw");
            manager.connect();
            assertEquals(true, manager.status().get("connected"));

            when(adapter.isConnected()).thenReturn(false);
            assertEquals(false, manager.status().get("connected"));
            assertFalse(manager.isConnected());
        }
    }
}
