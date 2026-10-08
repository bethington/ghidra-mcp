package com.xebyte.offline;

import com.xebyte.core.settings.ServerSettings;
import com.xebyte.core.settings.SettingsRegistry;
import com.xebyte.headless.GhidraServerManager;
import org.junit.After;
import org.junit.Test;

import java.util.Map;

import static org.junit.Assert.assertEquals;

public class GhidraServerManagerSettingsTest {

    private static final SettingsRegistry REG = SettingsRegistry.DEFAULT;

    @After
    public void tearDown() {
        ServerSettings.resetForTests();
    }

    @Test
    public void readsHostPortAndUserFromServerSettings() {
        ServerSettings.useForTests(Map.of(
            REG.get("ghidra_server.host").envName(), "ghidra.example",
            REG.get("ghidra_server.port").envName(), "14000",
            REG.get("ghidra_server.user").envName(), "svc-account"
        ), Map.of());

        GhidraServerManager manager = new GhidraServerManager();
        assertEquals("ghidra.example", manager.getHost());
        assertEquals(14000, manager.getPort());
        assertEquals("svc-account", manager.getUser());
    }
}
