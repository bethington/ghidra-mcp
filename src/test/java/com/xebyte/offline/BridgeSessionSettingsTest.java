package com.xebyte.offline;

import com.xebyte.core.Response;
import com.xebyte.core.SettingsService;
import com.xebyte.core.ProgramProvider;
import com.xebyte.core.settings.SettingsRegistry;
import org.junit.After;
import org.junit.Test;

import java.util.Map;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class BridgeSessionSettingsTest {

    private static final SettingsRegistry REG = SettingsRegistry.DEFAULT;

    @After
    public void tearDown() {
        com.xebyte.core.settings.ServerSettings.resetForTests();
    }

    @Test
    public void getSettingsOmitsSessionOnlyKeysButKeepsAuthToken() {
        ProgramProvider provider = mock(ProgramProvider.class);
        when(provider.getProject()).thenReturn(null);
        String tokenEnv = REG.get("auth.token").envName();
        SettingsService settings = new SettingsService(provider, Map.of(tokenEnv, "sekrit"));

        Response response = settings.getSettings("", "");
        assertTrue(response instanceof Response.Ok);
        String body = response.toJson();
        assertFalse(body.contains("bridge.server_url"));
        assertFalse(body.contains("bridge.log_level"));
        assertTrue(body.contains("auth.token"));
        assertFalse(body.contains("sekrit"));
    }
}
