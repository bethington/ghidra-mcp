package com.xebyte.core.settings;

import com.xebyte.core.settings.SettingKey.Kind;
import com.xebyte.core.settings.SettingKey.Merge;
import com.xebyte.core.settings.SettingKey.Type;

import java.util.Collection;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static com.xebyte.core.settings.Scope.LOCAL;
import static com.xebyte.core.settings.Scope.PROJECT;
import static com.xebyte.core.settings.Scope.SERVER;
import static com.xebyte.core.settings.Scope.SESSION;

/** Every setting the server and bridge know, in one place. */
public final class SettingsRegistry {

    /** The registry the servers use. */
    public static final SettingsRegistry DEFAULT = new SettingsRegistry(List.of(
        new SettingKey("tools.autoload", Type.LIST, "listing,function,program",
            EnumSet.of(SERVER, PROJECT, LOCAL, SESSION), Kind.PREFERENCE, Merge.LIST_DELTA, null,
            "Tool groups every new bridge session loads; +group/-group adjust the scope below."),
        new SettingKey("tools.restore_loaded", Type.BOOL, "true",
            EnumSet.of(SERVER, PROJECT, LOCAL, SESSION), Kind.PREFERENCE, Merge.OVERRIDE, null,
            "Whether a new bridge session also loads tools.last_loaded."),
        new SettingKey("tools.last_loaded", Type.LIST, "",
            EnumSet.of(LOCAL), Kind.PREFERENCE, Merge.OVERRIDE, null,
            "Tool groups the last bridge session had loaded beyond tools.autoload; the bridge "
                + "keeps it current."),
        new SettingKey("tools.require_program", Type.BOOL, "false",
            EnumSet.of(SERVER, PROJECT, LOCAL, SESSION), Kind.PREFERENCE, Merge.OVERRIDE, null,
            "Require an explicit program on every program-scoped tool call."),
        new SettingKey("scripts.allow", Type.BOOL, "false",
            EnumSet.of(SERVER, PROJECT, LOCAL), Kind.GUARDRAIL, Merge.OVERRIDE,
            SettingKey.FALSE_IS_STRICTER,
            "Whether run_ghidra_script and run_script_inline may run code."),
        new SettingKey("files.root", Type.STRING, "",
            EnumSet.of(SERVER, PROJECT, LOCAL), Kind.GUARDRAIL, Merge.OVERRIDE, SettingKey.PATH_WITHIN,
            "Directory that file paths given to tools must lie within; empty for none."),
        new SettingKey("project.folder_scope", Type.STRING, "",
            EnumSet.of(SERVER, PROJECT, LOCAL), Kind.GUARDRAIL, Merge.OVERRIDE, SettingKey.PATH_WITHIN,
            "Project folder that programs must lie within to be served; empty for none."),
        new SettingKey("auth.token", Type.STRING, "",
            EnumSet.of(SERVER), Kind.SECRET, Merge.OVERRIDE, null,
            "Bearer token HTTP clients must present; empty disables authentication.")));

    private final Map<String, SettingKey> keys = new LinkedHashMap<>();

    public SettingsRegistry(List<SettingKey> keys) {
        for (SettingKey k : keys) {
            if (this.keys.put(k.key(), k) != null) {
                throw new IllegalArgumentException("duplicate setting " + k.key());
            }
        }
    }

    public Collection<SettingKey> keys() {
        return keys.values();
    }

    /** The key, or a refusal that lists the keys sharing its area (or all of them). */
    public SettingKey get(String key) {
        SettingKey k = keys.get(key == null ? "" : key.trim());
        if (k != null) {
            return k;
        }
        String area = key == null ? "" : key.trim().split("\\.", 2)[0];
        List<String> near = keys.keySet().stream().filter(n -> n.startsWith(area + ".")).toList();
        throw new SettingRefusedException("Unknown setting '" + key + "'. Known: "
            + String.join(", ", near.isEmpty() ? keys.keySet() : near) + ".");
    }

    public List<SettingKey> withPrefix(String prefix) {
        String p = prefix == null ? "" : prefix.trim();
        return keys.values().stream()
            .filter(k -> p.isEmpty() || k.key().equals(p) || k.key().startsWith(p.endsWith(".") ? p : p + "."))
            .collect(Collectors.toList());
    }
}
