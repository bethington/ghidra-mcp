package com.xebyte.offline;

import com.xebyte.core.Response;
import com.xebyte.core.SettingsService;
import com.xebyte.core.ProgramProvider;
import com.xebyte.core.settings.Scope;
import com.xebyte.core.settings.SettingKey;
import com.xebyte.core.settings.SettingRefusedException;
import com.xebyte.core.settings.SettingsRegistry;
import com.xebyte.core.settings.SettingsResolver;
import org.junit.After;
import org.junit.Test;

import java.util.Map;

import static org.junit.Assert.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class OperatorSettingsTest {

    private static final SettingsRegistry REG = SettingsRegistry.DEFAULT;

    @After
    public void tearDown() {
        com.xebyte.core.settings.ServerSettings.resetForTests();
    }

    @Test
    public void operatorKeysMatchRegistry() {
        assertKey("server.bind_address", SettingKey.Type.STRING, "", SettingKey.Kind.OPERATOR,
            "GHIDRA_MCP_SERVER_BIND_ADDRESS");
        assertKey("programs.max_cached", SettingKey.Type.INT, "8", SettingKey.Kind.OPERATOR,
            "GHIDRA_MCP_PROGRAMS_MAX_CACHED");
        assertKey("archive.url", SettingKey.Type.STRING, "", SettingKey.Kind.OPERATOR,
            "GHIDRA_MCP_ARCHIVE_URL");
        assertKey("project.shared_dir", SettingKey.Type.STRING, "", SettingKey.Kind.OPERATOR,
            "GHIDRA_MCP_PROJECT_SHARED_DIR");
        assertKey("ghidra_server.host", SettingKey.Type.STRING, "localhost", SettingKey.Kind.OPERATOR,
            "GHIDRA_MCP_GHIDRA_SERVER_HOST");
        assertKey("ghidra_server.port", SettingKey.Type.INT, "13100", SettingKey.Kind.OPERATOR,
            "GHIDRA_MCP_GHIDRA_SERVER_PORT");
        assertKey("ghidra_server.user", SettingKey.Type.STRING, "", SettingKey.Kind.OPERATOR,
            "GHIDRA_MCP_GHIDRA_SERVER_USER");
        assertKey("ghidra_server.password", SettingKey.Type.STRING, "", SettingKey.Kind.SECRET,
            "GHIDRA_MCP_GHIDRA_SERVER_PASSWORD");
    }

    private static void assertKey(String key, SettingKey.Type type, String defaultRaw,
            SettingKey.Kind kind, String envName) {
        SettingKey k = REG.get(key);
        assertEquals(type, k.type());
        assertEquals(defaultRaw, k.defaultRaw());
        assertEquals(kind, k.kind());
        assertEquals(envName, k.envName());
    }

    @Test
    public void setSettingRefusesOperatorKeysWithoutNamingOverride() {
        SettingKey k = REG.get("server.bind_address");
        SettingRefusedException project = assertThrows(SettingRefusedException.class,
            () -> SettingsResolver.checkWrite(k, Scope.PROJECT, "1.2.3.4",
                SettingsResolver.resolve(k, Map.of())));
        assertTrue(project.getMessage().contains("set by the operator, not through tools."));
        assertFalse(project.getMessage().contains("GHIDRA_MCP"));
        assertFalse(project.getMessage().contains("override"));

        SettingRefusedException local = assertThrows(SettingRefusedException.class,
            () -> SettingsResolver.checkWrite(k, Scope.LOCAL, "1.2.3.4",
                SettingsResolver.resolve(k, Map.of())));
        assertTrue(local.getMessage().contains("set by the operator, not through tools."));
    }

    @Test
    public void getSettingsShowsOperatorValueNotSecret() {
        ProgramProvider provider = mock(ProgramProvider.class);
        when(provider.getProject()).thenReturn(null);
        String bindEnv = REG.get("server.bind_address").envName();
        String tokenEnv = REG.get("auth.token").envName();
        SettingsService settings = new SettingsService(provider,
            Map.of(bindEnv, "10.0.0.1", tokenEnv, "sekrit"));

        Response response = settings.getSettings("", "");
        assertTrue(response instanceof Response.Ok);
        String body = response.toJson();
        assertTrue(body.contains("server.bind_address"));
        assertTrue(body.contains("10.0.0.1"));
        assertFalse(body.contains("sekrit"));
        assertTrue(body.contains("auth.token"));
    }
}
