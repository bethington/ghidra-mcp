package com.xebyte.offline;

import com.xebyte.core.settings.Scope;
import com.xebyte.core.settings.ScopeStore;
import com.xebyte.core.settings.SettingKey;
import com.xebyte.core.settings.SettingRefusedException;
import com.xebyte.core.settings.SettingsRegistry;
import com.xebyte.core.settings.SettingsResolver;
import com.xebyte.core.settings.SettingsResolver.Resolution;
import org.junit.Test;

import java.util.EnumMap;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.*;

public class SettingsResolverTest {

    private static final SettingsRegistry REG = SettingsRegistry.DEFAULT;

    private static Map<Scope, ScopeStore> stores(Object... scopeKeyValue) {
        Map<Scope, ScopeStore> out = new EnumMap<>(Scope.class);
        for (int i = 0; i < scopeKeyValue.length; i += 3) {
            Scope scope = (Scope) scopeKeyValue[i];
            ScopeStore store = scope == Scope.SERVER
                ? ScopeStore.env(Map.of(REG.get((String) scopeKeyValue[i + 1]).envName(),
                    (String) scopeKeyValue[i + 2]))
                : ScopeStore.memory(Map.of((String) scopeKeyValue[i + 1], (String) scopeKeyValue[i + 2]));
            out.put(scope, store);
        }
        return out;
    }

    private static Resolution resolve(String key, Object... scopeKeyValue) {
        return SettingsResolver.resolve(REG.get(key), stores(scopeKeyValue));
    }

    @Test
    public void theDefaultStandsWhenNoScopeHasAValue() {
        Resolution r = resolve("tools.restore_loaded");
        assertEquals(true, r.value());
        assertEquals(Scope.DEFAULT, r.source());
    }

    @Test
    public void eachHigherScopeOverridesTheOnesBelow() {
        String k = "tools.require_program";
        assertEquals(Scope.SERVER, resolve(k, Scope.SERVER, k, "1").source());
        Resolution r = resolve(k, Scope.SERVER, k, "1", Scope.PROJECT, k, "false",
            Scope.LOCAL, k, "true", Scope.SESSION, k, "no");
        assertEquals(false, r.value());
        assertEquals(Scope.SESSION, r.source());
        assertEquals(List.of(Scope.DEFAULT, Scope.SERVER, Scope.PROJECT, Scope.LOCAL, Scope.SESSION),
            r.layers().stream().map(SettingsResolver.Layer::scope).toList());
    }

    @Test
    public void aScopeTheKeyDoesNotAllowIsNotConsulted() {
        // tools.last_loaded is LOCAL only
        Resolution r = resolve("tools.last_loaded", Scope.PROJECT, "tools.last_loaded", "memory");
        assertEquals(List.of(), r.value());
        assertEquals(Scope.DEFAULT, r.source());
    }

    @Test
    public void listDeltasAddAndRemoveFromTheScopeBelow() {
        String k = "tools.autoload";
        Resolution r = resolve(k, Scope.PROJECT, k, "+datatype,-program", Scope.SESSION, k, "+memory");
        assertEquals(List.of("listing", "function", "datatype", "memory"), r.value());
    }

    @Test
    public void aBareListReplacesTheScopeBelowAndAnEmptyOneClearsIt() {
        String k = "tools.autoload";
        assertEquals(List.of("datatype", "memory"),
            resolve(k, Scope.PROJECT, k, "+xref", Scope.LOCAL, k, "datatype,+memory").value());
        assertEquals(List.of(), resolve(k, Scope.LOCAL, k, "").value());
    }

    @Test
    public void anUnparseableValueIsIgnoredAndReported() {
        String k = "tools.restore_loaded";
        Resolution r = resolve(k, Scope.SERVER, k, "maybe");
        assertEquals(true, r.value());
        SettingsResolver.Layer bad = r.layers().get(1);
        assertFalse(bad.applied());
        assertTrue(bad.note(), bad.note().contains("boolean"));
    }

    @Test
    public void aGuardrailFromAnAgentScopeCanTightenButNotLoosen() {
        String k = "scripts.allow";
        Resolution loosened = resolve(k, Scope.PROJECT, k, "true");
        assertEquals(false, loosened.value());
        assertFalse(loosened.layers().get(1).applied());

        Resolution tightened = resolve(k, Scope.SERVER, k, "1", Scope.LOCAL, k, "false");
        assertEquals(false, tightened.value());
        assertEquals(Scope.LOCAL, tightened.source());
    }

    @Test
    public void aPathGuardrailOnlyNarrows() {
        String k = "project.folder_scope";
        assertEquals("/Mods/PD2",
            resolve(k, Scope.SERVER, k, "/Mods", Scope.PROJECT, k, "/Mods/PD2").value());
        assertEquals("/Mods",
            resolve(k, Scope.SERVER, k, "/Mods", Scope.PROJECT, k, "/Vanilla").value());
        assertEquals("/Mods",
            resolve(k, Scope.SERVER, k, "/Mods", Scope.PROJECT, k, "").value());
        // element-wise: /Mods2 is not inside /Mods
        assertEquals("/Mods",
            resolve(k, Scope.SERVER, k, "/Mods", Scope.LOCAL, k, "/Mods2").value());
        // nothing configured: anything narrows
        assertEquals("/Vanilla", resolve(k, Scope.PROJECT, k, "/Vanilla").value());
    }

    @Test
    public void unknownKeysAreRefusedWithTheKeysOfTheirArea() {
        SettingRefusedException e = assertThrows(SettingRefusedException.class,
            () -> REG.get("tools.autoloads"));
        assertTrue(e.getMessage(), e.getMessage().contains("tools.autoload"));
        assertFalse(e.getMessage(), e.getMessage().contains("scripts.allow"));
    }

    @Test
    public void writesToAScopeTheKeyDoesNotAllowAreRefused() {
        SettingKey k = REG.get("tools.last_loaded");
        SettingRefusedException e = assertThrows(SettingRefusedException.class,
            () -> SettingsResolver.checkWrite(k, Scope.PROJECT, "memory",
                SettingsResolver.resolve(k, Map.of())));
        assertTrue(e.getMessage(), e.getMessage().contains("Settable at: local"));
        assertThrows(SettingRefusedException.class, () -> SettingsResolver.checkWrite(
            k, Scope.SERVER, "memory", SettingsResolver.resolve(k, Map.of())));
    }

    @Test
    public void guardrailWritesMayOnlyTightenAndNeverNameTheOverride() {
        SettingKey k = REG.get("scripts.allow");
        Resolution allowed = SettingsResolver.resolve(k, stores(Scope.SERVER, "scripts.allow", "1"));
        SettingsResolver.checkWrite(k, Scope.PROJECT, "false", allowed);
        Resolution denied = SettingsResolver.resolve(k, Map.of());
        SettingRefusedException e = assertThrows(SettingRefusedException.class,
            () -> SettingsResolver.checkWrite(k, Scope.PROJECT, "true", denied));
        assertTrue(e.getMessage(), e.getMessage().contains("only be made stricter"));
        assertFalse(e.getMessage(), e.getMessage().contains("GHIDRA_MCP"));
        assertFalse(e.getMessage(), e.getMessage().toLowerCase().contains("environment"));
    }

    @Test
    public void secretsAreNeitherSetNorNamedForTheirOverride() {
        SettingKey k = REG.get("auth.token");
        SettingRefusedException e = assertThrows(SettingRefusedException.class,
            () -> SettingsResolver.checkWrite(k, Scope.SERVER, "x", SettingsResolver.resolve(k, Map.of())));
        assertFalse(e.getMessage(), e.getMessage().contains("GHIDRA_MCP"));
    }

    @Test
    public void wrongTypedWritesAreRefused() {
        SettingKey k = REG.get("tools.restore_loaded");
        assertThrows(SettingRefusedException.class, () -> SettingsResolver.checkWrite(
            k, Scope.LOCAL, "sometimes", SettingsResolver.resolve(k, Map.of())));
    }

    @Test
    public void aRetiredGuardrailVariableStopsTheServerRatherThanRunningUnconfined() {
        assertNull(com.xebyte.core.SecurityConfig.retiredVariables(Map.of("GHIDRA_MCP_FILES_ROOT", "/x")));
        String refusal = com.xebyte.core.SecurityConfig.retiredVariables(
            Map.of("GHIDRA_MCP_FILE_ROOT", "/x", "GHIDRA_MCP_PROJECT_FOLDER", "/Mods"));
        assertTrue(refusal, refusal.contains("GHIDRA_MCP_FILE_ROOT (now GHIDRA_MCP_FILES_ROOT)"));
        assertTrue(refusal, refusal.contains("GHIDRA_MCP_PROJECT_FOLDER (now GHIDRA_MCP_PROJECT_FOLDER_SCOPE)"));
        // every retired name points at the variable its registry key derives
        Map<String, String> retiredByKey = Map.of("scripts.allow", "GHIDRA_MCP_ALLOW_SCRIPTS",
            "files.root", "GHIDRA_MCP_FILE_ROOT", "project.folder_scope", "GHIDRA_MCP_PROJECT_FOLDER");
        retiredByKey.forEach((key, old) -> assertTrue(old, com.xebyte.core.SecurityConfig
            .retiredVariables(Map.of(old, "1")).contains("(now " + REG.get(key).envName() + ")")));
    }

    @Test
    public void envNamesDeriveFromTheKey() {
        assertEquals("GHIDRA_MCP_TOOLS_AUTOLOAD", REG.get("tools.autoload").envName());
        assertEquals("GHIDRA_MCP_PROJECT_FOLDER_SCOPE", REG.get("project.folder_scope").envName());
    }
}
