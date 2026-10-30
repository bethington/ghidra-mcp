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
import static com.xebyte.core.settings.Scope.PROGRAM;
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
        new SettingKey("tree.strategies", Type.LIST, "",
            EnumSet.of(SERVER, PROJECT, LOCAL, PROGRAM), Kind.PREFERENCE, Merge.OVERRIDE, null,
            "Partition strategies for decompile_tree_create; empty means the full cascade."),
        new SettingKey("tree.band_size", Type.INT, "20",
            EnumSet.of(SERVER, PROJECT, LOCAL, PROGRAM), Kind.PREFERENCE, Merge.OVERRIDE, null,
            "Address-band width when bands apply in a decompilation tree."),
        new SettingKey("tree.max_file_bytes", Type.INT, "32768",
            EnumSet.of(SERVER, PROJECT, LOCAL, PROGRAM), Kind.PREFERENCE, Merge.OVERRIDE, null,
            "Read-budget bytes per .c file inside a tree compartment (floored at 4096)."),
        new SettingKey("tree.exclusions", Type.LIST, "",
            EnumSet.of(SERVER, PROJECT, LOCAL, PROGRAM), Kind.PREFERENCE, Merge.LIST_DELTA, null,
            "Exclusion specs (tag:/partition:/range:) for decompile_tree_create."),
        new SettingKey("tree.include_only", Type.LIST, "",
            EnumSet.of(SERVER, PROJECT, LOCAL, PROGRAM), Kind.PREFERENCE, Merge.LIST_DELTA, null,
            "Include-only specs (tag:/partition:/range:) for decompile_tree_create."),
        new SettingKey("tree.throttle_percent", Type.INT, "10",
            EnumSet.of(SERVER, PROJECT, LOCAL, PROGRAM), Kind.PREFERENCE, Merge.OVERRIDE, null,
            "Interactive yield 0..90 after each function during a tree sweep."),
        new SettingKey("tree.decompile_timeout_seconds", Type.INT, "30",
            EnumSet.of(SERVER, PROJECT, LOCAL, PROGRAM), Kind.PREFERENCE, Merge.OVERRIDE, null,
            "Per-function decompile budget during a tree sweep."),
        new SettingKey("tree.analysis_wait_seconds", Type.INT, "600",
            EnumSet.of(SERVER, PROJECT, LOCAL, PROGRAM), Kind.PREFERENCE, Merge.OVERRIDE, null,
            "Cap on waiting for auto-analysis before a tree sweep partitions."),
        new SettingKey("tree.disassemble_missing", Type.BOOL, "false",
            EnumSet.of(SERVER, PROJECT, LOCAL, PROGRAM), Kind.PREFERENCE, Merge.OVERRIDE, null,
            "Before a tree sweep, disassemble at function entries with no instruction; "
                + "writes the program, so off unless a scope or the create call turns it on."),
        new SettingKey("naming.mode", Type.STRING, "enforce",
            EnumSet.of(SERVER, PROJECT, LOCAL, PROGRAM), Kind.GUARDRAIL, Merge.OVERRIDE,
            SettingKey.NAMING_MODE_TIGHTENS,
            "Naming enforcement: off, warn, or enforce (reject low-quality names)."),
        new SettingKey("naming.override", Type.STRING, "allow",
            EnumSet.of(SERVER, PROJECT, LOCAL, PROGRAM), Kind.GUARDRAIL, Merge.OVERRIDE,
            SettingKey.NAMING_OVERRIDE_TIGHTENS,
            "Whether per-call strict_mode may be lower than naming.mode (allow or deny)."),
        new SettingKey("naming.function.min_length", Type.INT, "8",
            EnumSet.of(SERVER, PROJECT, LOCAL, PROGRAM), Kind.OPERATOR, Merge.OVERRIDE, null,
            "Minimum length for function names under the verb-tier rules."),
        new SettingKey("naming.function.verbs_add", Type.LIST, "",
            EnumSet.of(SERVER, PROJECT, LOCAL, PROGRAM), Kind.OPERATOR, Merge.LIST_DELTA, null,
            "Extra PascalCase verbs accepted in function names (+name to add, -name to remove)."),
        new SettingKey("naming.function.verbs_remove", Type.LIST, "",
            EnumSet.of(SERVER, PROJECT, LOCAL, PROGRAM), Kind.OPERATOR, Merge.LIST_DELTA, null,
            "Built-in verbs to drop from the whitelist (+name to add, -name to remove)."),
        new SettingKey("naming.function.verb_tiers", Type.LIST, "",
            EnumSet.of(SERVER, PROJECT, LOCAL, PROGRAM), Kind.OPERATOR, Merge.LIST_DELTA, null,
            "Verb tier overrides as Verb:tier entries (tier 1..3; +Verb:2 to add, -Verb to remove)."),
        new SettingKey("naming.function.weak_nouns_add", Type.LIST, "",
            EnumSet.of(SERVER, PROJECT, LOCAL, PROGRAM), Kind.OPERATOR, Merge.LIST_DELTA, null,
            "Tokens treated as weak nouns in function names (+token/-token)."),
        new SettingKey("naming.function.weak_nouns_remove", Type.LIST, "",
            EnumSet.of(SERVER, PROJECT, LOCAL, PROGRAM), Kind.OPERATOR, Merge.LIST_DELTA, null,
            "Built-in weak nouns to stop treating as weak (+token/-token)."),
        new SettingKey("naming.hungarian.auto_fix", Type.BOOL, "true",
            EnumSet.of(SERVER, PROJECT, LOCAL, PROGRAM), Kind.OPERATOR, Merge.OVERRIDE, null,
            "Rewrite struct field names to Hungarian prefixes on create/modify."),
        new SettingKey("naming.hungarian.prefixes", Type.LIST, "",
            EnumSet.of(SERVER, PROJECT, LOCAL, PROGRAM), Kind.OPERATOR, Merge.LIST_DELTA, null,
            "Extra type-to-prefix mappings as type:prefix entries (+type:prefix/-type to adjust)."),
        new SettingKey("naming.global.validate", Type.BOOL, "true",
            EnumSet.of(SERVER, PROJECT, LOCAL, PROGRAM), Kind.OPERATOR, Merge.OVERRIDE, null,
            "Run global symbol name quality checks on rename/set_global."),
        new SettingKey("naming.global.require_g_prefix", Type.BOOL, "true",
            EnumSet.of(SERVER, PROJECT, LOCAL, PROGRAM), Kind.OPERATOR, Merge.OVERRIDE, null,
            "Require g_ on documented globals."),
        new SettingKey("naming.global.min_descriptor_length", Type.INT, "2",
            EnumSet.of(SERVER, PROJECT, LOCAL, PROGRAM), Kind.OPERATOR, Merge.OVERRIDE, null,
            "Minimum length of the descriptor after g_ on globals."),
        new SettingKey("naming.plate.validate", Type.BOOL, "true",
            EnumSet.of(SERVER, PROJECT, LOCAL, PROGRAM), Kind.OPERATOR, Merge.OVERRIDE, null,
            "Validate plate comment structure on batch_set_comments and related tools."),
        new SettingKey("naming.plate.required_sections", Type.LIST, "Algorithm,Parameters,Returns",
            EnumSet.of(SERVER, PROJECT, LOCAL, PROGRAM), Kind.OPERATOR, Merge.OVERRIDE, null,
            "Section headings required in function plate comments."),
        new SettingKey("naming.plate.min_first_line_words", Type.INT, "4",
            EnumSet.of(SERVER, PROJECT, LOCAL, PROGRAM), Kind.OPERATOR, Merge.OVERRIDE, null,
            "Minimum word count on the plate comment summary line."),
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
