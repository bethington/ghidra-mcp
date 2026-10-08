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
            EnumSet.of(SERVER, SESSION), Kind.SECRET, Merge.OVERRIDE, null,
            "Bearer token HTTP clients must present; empty disables authentication. "
                + "The bridge sends its own value as the bearer token on outbound Ghidra calls."),
        new SettingKey("bridge.server_url", Type.STRING, "",
            EnumSet.of(SESSION), Kind.OPERATOR, Merge.OVERRIDE, null,
            "Ghidra HTTP URL for this bridge session; empty discovers instances or uses the default loopback port."),
        new SettingKey("bridge.max_concurrent_requests", Type.INT, "4",
            EnumSet.of(SESSION), Kind.OPERATOR, Merge.OVERRIDE, null,
            "Maximum Ghidra requests this bridge executes concurrently; values below 1 become 1."),
        new SettingKey("bridge.log_level", Type.STRING, "INFO",
            EnumSet.of(SESSION), Kind.OPERATOR, Merge.OVERRIDE, null,
            "Python logging level for this bridge process."),
        new SettingKey("bridge.lazy", Type.STRING, "",
            EnumSet.of(SESSION), Kind.OPERATOR, Merge.OVERRIDE, null,
            "Lazy tool loading for this bridge session; empty uses the transport default."),
        new SettingKey("bridge.project", Type.STRING, "",
            EnumSet.of(SESSION), Kind.OPERATOR, Merge.OVERRIDE, null,
            "Exact project name this bridge session connects to on startup; empty connects as without one."),
        new SettingKey("bridge.expose", Type.STRING, "full",
            EnumSet.of(SESSION), Kind.OPERATOR, Merge.OVERRIDE, null,
            "MCP surface this bridge session advertises: full (every tool), facade (five ghidra_* tools) or hybrid (both)."),
        new SettingKey("bridge.allowed_hosts", Type.LIST, "",
            EnumSet.of(SESSION), Kind.OPERATOR, Merge.OVERRIDE, null,
            "Extra hostnames allowed for HTTP/SSE DNS-rebinding and CORS checks (comma-separated)."),
        new SettingKey("bridge.inbound_token", Type.STRING, "",
            EnumSet.of(SESSION), Kind.SECRET, Merge.OVERRIDE, null,
            "Bearer token MCP HTTP clients must present to this bridge; empty disables inbound auth."),
        new SettingKey("bridge.rebind_protection", Type.BOOL, "true",
            EnumSet.of(SESSION), Kind.OPERATOR, Merge.OVERRIDE, null,
            "DNS-rebinding protection for wildcard HTTP binds; set false only on a wildcard bind to opt out."),
        new SettingKey("bridge.debugger_url", Type.STRING, "",
            EnumSet.of(SESSION), Kind.OPERATOR, Merge.OVERRIDE, null,
            "Loopback URL of an external WinDbg debugger server; setting it registers the 22 "
                + "debugger_* proxy tools, which are off by default."),
        new SettingKey("bridge.debugger_tools", Type.STRING, "",
            EnumSet.of(SESSION), Kind.OPERATOR, Merge.OVERRIDE, null,
            "Force the debugger_* proxy tools on (true, at `http://127.0.0.1:8099` when no URL is "
                + "set) or off (false, even with a URL); empty follows bridge.debugger_url."),
        new SettingKey("server.bind_address", Type.STRING, "",
            EnumSet.of(SERVER), Kind.OPERATOR, Merge.OVERRIDE, null,
            "When non-empty, also serve HTTP on TCP at this address (headless/Docker)."),
        new SettingKey("programs.max_cached", Type.INT, "8",
            EnumSet.of(SERVER), Kind.OPERATOR, Merge.OVERRIDE, null,
            "Maximum programs kept open in the provider cache; values below 2 become 2."),
        new SettingKey("archive.url", Type.STRING, "",
            EnumSet.of(SERVER), Kind.OPERATOR, Merge.OVERRIDE, null,
            "Documentation archive REST base URL; empty disables archive ingest."),
        new SettingKey("project.shared_dir", Type.STRING, "",
            EnumSet.of(SERVER), Kind.OPERATOR, Merge.OVERRIDE, null,
            "Root directory for persistent local shared-server projects; empty uses the default under the home directory."),
        new SettingKey("ghidra_server.host", Type.STRING, "localhost",
            EnumSet.of(SERVER), Kind.OPERATOR, Merge.OVERRIDE, null,
            "Ghidra Server hostname for shared-repository connections."),
        new SettingKey("ghidra_server.port", Type.INT, "13100",
            EnumSet.of(SERVER), Kind.OPERATOR, Merge.OVERRIDE, null,
            "Ghidra Server RMI port for shared-repository connections."),
        new SettingKey("ghidra_server.user", Type.STRING, "",
            EnumSet.of(SERVER), Kind.OPERATOR, Merge.OVERRIDE, null,
            "Ghidra Server username; empty uses the OS user."),
        new SettingKey("ghidra_server.password", Type.STRING, "",
            EnumSet.of(SERVER), Kind.SECRET, Merge.OVERRIDE, null,
            "Ghidra Server password for programmatic login; empty leaves server auth unset.")));

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
