package com.xebyte.offline;

import com.xebyte.core.SecurityConfig;
import com.xebyte.core.settings.DotEnv;
import com.xebyte.core.settings.Scope;
import com.xebyte.core.settings.ScopeStore;
import com.xebyte.core.settings.SettingsRegistry;
import org.junit.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static org.junit.Assert.*;

public class DotEnvTest {

    private static final SettingsRegistry REG = SettingsRegistry.DEFAULT;

    @Test
    public void processEnvironmentWinsOverDotEnv() {
        String name = REG.get("server.bind_address").envName();
        Optional<String> v = ScopeStore.server(
            Map.of(name, "from-env"),
            Map.of(name, "from-dotenv")).read(REG.get("server.bind_address"));
        assertEquals("from-env", v.orElse(""));
    }

    @Test
    public void firstDotEnvFileWinsPerName() throws Exception {
        Path dir = Files.createTempDirectory("dotenv-test");
        Path first = dir.resolve("first.env");
        Path second = dir.resolve("second.env");
        Files.writeString(first, "GHIDRA_MCP_SERVER_BIND_ADDRESS=first\n");
        Files.writeString(second, "GHIDRA_MCP_SERVER_BIND_ADDRESS=second\n");
        Map<String, String> out = new HashMap<>();
        DotEnv.loadInto(first, out);
        DotEnv.loadInto(second, out);
        assertEquals("first", out.get("GHIDRA_MCP_SERVER_BIND_ADDRESS"));
    }

    @Test
    public void commentsAndQuotesAreParsed() throws Exception {
        Path file = Files.createTempDirectory("dotenv-parse").resolve(".env");
        Files.writeString(file, """
            # comment
            GHIDRA_MCP_GHIDRA_SERVER_USER="quoted"
            GHIDRA_MCP_GHIDRA_SERVER_PASSWORD='pw'
            """);
        Map<String, String> out = new HashMap<>();
        DotEnv.loadInto(file, out);
        assertEquals("quoted", out.get("GHIDRA_MCP_GHIDRA_SERVER_USER"));
        assertEquals("pw", out.get("GHIDRA_MCP_GHIDRA_SERVER_PASSWORD"));
    }

    @Test
    public void retiredNamesInDotEnvAreRefused() {
        String refusal = SecurityConfig.retiredVariables(Map.<String, String>of(),
            Map.of("GHIDRA_SERVER_PASSWORD", "x"));
        assertNotNull(refusal);
        assertTrue(refusal.contains("GHIDRA_SERVER_PASSWORD (now GHIDRA_MCP_GHIDRA_SERVER_PASSWORD)"));
    }
}
