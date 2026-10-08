package com.xebyte.offline;

import com.xebyte.core.ConventionConfig;
import com.xebyte.core.NamingConventions;
import com.xebyte.core.NamingPolicy;
import com.xebyte.core.Refusal;
import com.xebyte.core.SettingsService;
import com.xebyte.core.ProgramProvider;
import com.xebyte.core.settings.Scope;
import com.xebyte.core.settings.ScopeStore;
import com.xebyte.core.settings.SettingKey;
import com.xebyte.core.settings.SettingRefusedException;
import com.xebyte.core.settings.SettingsRegistry;
import com.xebyte.core.settings.SettingsResolver;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.util.EnumMap;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class NamingSettingsTest {

    private static final SettingsRegistry REG = SettingsRegistry.DEFAULT;

    private ConventionConfig savedConfig;
    private String savedSource;

    @Before
    public void setUp() {
        savedConfig = NamingPolicy.getInstance().getConfig();
        savedSource = NamingPolicy.getInstance().getSource();
        NamingPolicy.getInstance().clearRequestModeOverride();
    }

    @After
    public void tearDown() {
        ProgramProvider none = mock(ProgramProvider.class);
        when(none.getProject()).thenReturn(null);
        NamingPolicy.getInstance().useSettings(new SettingsService(none));
        NamingPolicy.getInstance().setConfig(savedConfig, savedSource);
        NamingPolicy.getInstance().clearRequestModeOverride();
        com.xebyte.core.settings.ServerSettings.resetForTests();
    }

    @Test
    public void fromSettingsWithDefaultsMatchesBuiltInDefaults() {
        ConventionConfig built = ConventionConfig.fromSettings(key ->
            SettingsResolver.resolve(REG.get(key), Map.of()).value());
        assertConfigsEqual(ConventionConfig.defaults(), built);
    }

    @Test
    public void projectScopeVerbsAddMakesSniffPacketsPass() {
        Map<Scope, ScopeStore> stores = new EnumMap<>(Scope.class);
        stores.put(Scope.SERVER, ScopeStore.server(Map.of(), Map.of()));
        stores.put(Scope.PROJECT, ScopeStore.memory(Map.of("naming.function.verbs_add", "+Sniff")));
        ConventionConfig built = ConventionConfig.fromSettings(key ->
            SettingsResolver.resolve(REG.get(key), stores).value());
        NamingPolicy.getInstance().setConfig(built, "test");
        assertTrue(NamingConventions.validateFunctionName("SniffPackets", false).isEmpty());
    }

    @Test
    public void namingModeCannotBeLoosenedByAgentAtProjectScope() {
        SettingKey k = REG.get("naming.mode");
        Map<Scope, ScopeStore> stores = stores(Scope.SERVER, "naming.mode", "enforce");
        SettingsResolver.Resolution current = SettingsResolver.resolve(k, stores);
        SettingRefusedException e = assertThrows(SettingRefusedException.class,
            () -> SettingsResolver.checkWrite(k, Scope.PROJECT, "warn", current));
        assertTrue(e.getMessage().contains("only be made stricter"));
    }

    @Test
    public void operatorNamingKeyRefusedToSetSetting() {
        SettingKey k = REG.get("naming.function.min_length");
        SettingRefusedException e = assertThrows(SettingRefusedException.class,
            () -> SettingsResolver.checkWrite(k, Scope.PROJECT, "10",
                SettingsResolver.resolve(k, Map.of())));
        assertTrue(e.getMessage().contains("set by the operator, not through tools."));
        assertFalse(e.getMessage().toLowerCase().contains("environment"));
    }

    @Test
    public void namingOverrideDenyRefusesLowerStrictMode() {
        ProgramProvider provider = mock(ProgramProvider.class);
        when(provider.getProject()).thenReturn(null);
        String overrideEnv = REG.get("naming.override").envName();
        SettingsService settings = new SettingsService(provider, Map.of(overrideEnv, "deny"));
        NamingPolicy policy = NamingPolicy.getInstance();
        policy.useSettings(settings);
        policy.setConfig(null, null);
        Refusal r = assertThrows(Refusal.class, () -> {
            try (var ignored = policy.scopedRequestMode("warn")) {
                // body never runs
            }
        });
        assertTrue(r.getMessage().contains("strict_mode=warn"));
        assertTrue(r.getMessage().contains("naming mode (enforce)"));
        assertFalse(r.getMessage().toLowerCase().contains("override"));
        assertFalse(r.getMessage().toLowerCase().contains("deny"));
    }

    @Test
    public void namingOverrideAllowPermitsLowerStrictMode() throws Exception {
        NamingPolicy policy = NamingPolicy.getInstance();
        policy.setConfig(ConventionConfig.defaults(), "test");
        try (var ignored = policy.scopedRequestMode("warn")) {
            assertEquals(ConventionConfig.Mode.WARN, policy.getEffectiveMode());
        }
    }

    @Test
    public void perCallRaisingStrictModeAlwaysAllowed() throws Exception {
        ConventionConfig warnConfig = new ConventionConfig(
            ConventionConfig.Mode.WARN,
            ConventionConfig.FunctionNamingRules.defaults(),
            ConventionConfig.HungarianRules.defaults(),
            ConventionConfig.GlobalNamingRules.defaults(),
            ConventionConfig.PlateCommentRules.defaults());
        NamingPolicy policy = NamingPolicy.getInstance();
        policy.setConfig(warnConfig, "test");
        try (var ignored = policy.scopedRequestMode("enforce")) {
            assertTrue(policy.isStrictNamingEnforcement());
        }
    }

    @Test
    public void verbTierMalformedEntryIsIgnored() {
        ConventionConfig built = ConventionConfig.fromSettings(key -> {
            if ("naming.function.verb_tiers".equals(key)) {
                return List.of("badentry", "Sniff:2");
            }
            return SettingsResolver.resolve(REG.get(key), Map.of()).value();
        });
        assertEquals(Integer.valueOf(2), built.functionNaming().verbTierOverrides().get("Sniff"));
        assertNull(built.functionNaming().verbTierOverrides().get("badentry"));
    }

    private static Map<Scope, ScopeStore> stores(Object... scopeKeyValue) {
        Map<Scope, ScopeStore> out = new EnumMap<>(Scope.class);
        for (int i = 0; i < scopeKeyValue.length; i += 3) {
            Scope scope = (Scope) scopeKeyValue[i];
            String key = (String) scopeKeyValue[i + 1];
            String raw = (String) scopeKeyValue[i + 2];
            ScopeStore store = scope == Scope.SERVER
                ? ScopeStore.server(Map.of(REG.get(key).envName(), raw), Map.of())
                : ScopeStore.memory(Map.of(key, raw));
            out.put(scope, store);
        }
        return out;
    }

    private static void assertConfigsEqual(ConventionConfig expected, ConventionConfig actual) {
        assertEquals(expected.getMode(), actual.getMode());
        assertEquals(expected.functionNaming().minLength(), actual.functionNaming().minLength());
        assertEquals(expected.functionNaming().verbsAdd(), actual.functionNaming().verbsAdd());
        assertEquals(expected.functionNaming().verbsRemove(), actual.functionNaming().verbsRemove());
        assertEquals(expected.functionNaming().verbTierOverrides(), actual.functionNaming().verbTierOverrides());
        assertEquals(expected.functionNaming().weakNounsAdd(), actual.functionNaming().weakNounsAdd());
        assertEquals(expected.functionNaming().weakNounsRemove(), actual.functionNaming().weakNounsRemove());
        assertEquals(expected.hungarian().autoFixStructFields(), actual.hungarian().autoFixStructFields());
        assertEquals(expected.hungarian().extraPrefixes(), actual.hungarian().extraPrefixes());
        assertEquals(expected.globalNaming().validate(), actual.globalNaming().validate());
        assertEquals(expected.globalNaming().requireGPrefix(), actual.globalNaming().requireGPrefix());
        assertEquals(expected.globalNaming().minDescriptorLength(), actual.globalNaming().minDescriptorLength());
        assertEquals(expected.plateComments().validate(), actual.plateComments().validate());
        assertEquals(expected.plateComments().requiredSections(), actual.plateComments().requiredSections());
        assertEquals(expected.plateComments().minFirstLineWords(), actual.plateComments().minFirstLineWords());
    }
}
