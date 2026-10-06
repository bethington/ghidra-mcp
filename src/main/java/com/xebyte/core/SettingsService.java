package com.xebyte.core;

import com.xebyte.core.settings.ProjectStores;
import com.xebyte.core.settings.Scope;
import com.xebyte.core.settings.ScopeStore;
import com.xebyte.core.settings.SettingKey;
import com.xebyte.core.settings.SettingRefusedException;
import com.xebyte.core.settings.SettingsRegistry;
import com.xebyte.core.settings.SettingsResolver;
import com.xebyte.core.settings.SettingsResolver.Resolution;
import ghidra.framework.model.Project;
import ghidra.program.model.listing.Program;

import java.util.ArrayList;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Reads and writes settings across scopes. The values are resolved here for the server's
 * scopes (default, server, project, local, program); the bridge layers its session on top
 * for the keys it consumes.
 *
 * @since 7.3.0
 */
public class SettingsService {

    private final ProgramProvider provider;
    private final Map<String, String> env;
    private final SettingsRegistry registry = SettingsRegistry.DEFAULT;

    private Project storesProject;
    private ScopeStore projectStore;
    private ScopeStore localStore;

    public SettingsService(ProgramProvider provider) {
        this(provider, System.getenv());
    }

    public SettingsService(ProgramProvider provider, Map<String, String> env) {
        this.provider = provider;
        this.env = env;
    }

    /** The stores for the open project (and a program, if given), built once per project. */
    synchronized Map<Scope, ScopeStore> stores(Program program) {
        Map<Scope, ScopeStore> out = new EnumMap<>(Scope.class);
        out.put(Scope.SERVER, ScopeStore.env(env));
        Project project = provider.getProject();
        if (project != storesProject) {
            storesProject = project;
            projectStore = project == null ? null : ProjectStores.shared(project);
            localStore = project == null ? null : ProjectStores.local(project);
        }
        if (projectStore != null) {
            out.put(Scope.PROJECT, projectStore);
            out.put(Scope.LOCAL, localStore);
        }
        if (program != null) {
            out.put(Scope.PROGRAM, ProjectStores.program(program));
        }
        return out;
    }

    /** The effective value of one key, for server code that consumes settings. */
    public Object value(String key, Program program) {
        return SettingsResolver.resolve(registry.get(key), stores(program)).value();
    }

    @McpTool(path = "/get_settings",
        description = "Every setting with its effective value, the scope it came from and the scopes "
            + "that also hold one. Scopes, lowest first: default, server, project (shared with everyone "
            + "using the project), local (this machine), program, session (the bridge's), call. "
            + "Guardrails are set by the server operator and can only be made stricter from here; "
            + "secrets show only whether they are set.",
        category = "program", access = ToolAccess.READ_ONLY)
    public Response getSettings(
            @Param(value = "prefix", defaultValue = "",
                   description = "Only keys under this prefix, e.g. 'tools'.") String prefix,
            @Param(value = "program", defaultValue = "",
                   description = "Include this program's own values (the program scope).") String programName) {
        try {
            Program program = null;
            if (programName != null && !programName.isBlank()) {
                ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(provider, programName);
                if (pe.hasError()) return pe.error();
                program = pe.program();
            }
            Map<Scope, ScopeStore> stores = stores(program);
            List<Map<String, Object>> rows = new ArrayList<>();
            for (SettingKey key : registry.withPrefix(prefix)) {
                rows.add(row(SettingsResolver.resolve(key, stores)));
            }
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("settings", rows);
            out.put("scopes_available", stores.keySet().stream().map(Scope::wireName).toList());
            return Response.ok(out);
        } catch (SettingRefusedException e) {
            return Response.err(e.getMessage());
        }
    }

    @McpTool(path = "/set_setting", method = "POST", dryRun = false,
        description = "Set or unset a setting at one scope: 'project' is shared with everyone using "
            + "the project (versioned with a shared one), 'local' stays on this machine, 'program' is "
            + "one program's. Returns the effective value afterwards. List settings take '+x,-y' to "
            + "adjust the scope below, or a plain list to replace it. Guardrails can only be made "
            + "stricter; secrets cannot be set here.",
        category = "program", access = ToolAccess.WRITE)
    public Response setSetting(
            @Param(value = "key", source = ParamSource.BODY,
                   description = "Setting key, e.g. 'tools.autoload'.") String key,
            @Param(value = "value", source = ParamSource.BODY, defaultValue = "",
                   description = "Raw value; ignored with unset=true.") String value,
            @Param(value = "scope", source = ParamSource.BODY, defaultValue = "local",
                   description = "project, local or program.") String scopeName,
            @Param(value = "unset", source = ParamSource.BODY, defaultValue = "false",
                   description = "Remove the value at this scope instead of setting one.") boolean unset,
            @Param(value = "program", defaultValue = "",
                   description = "Target program for scope=program.") String programName) {
        try {
            SettingKey k = registry.get(key);
            Scope scope = Scope.parse(scopeName);
            Program program = null;
            if (scope == Scope.PROGRAM) {
                ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(provider, programName);
                if (pe.hasError()) return pe.error();
                program = pe.program();
            }
            Map<Scope, ScopeStore> stores = stores(program);
            ScopeStore target = stores.get(scope);
            Resolution current = SettingsResolver.resolve(k, stores);
            if (unset) {
                SettingsResolver.checkScope(k, scope);
                checkUnsetKeepsGuardrail(k, scope, stores, current);
                requireStore(target, scope).remove(k);
            } else {
                SettingsResolver.checkWrite(k, scope, value, current);
                requireStore(target, scope).write(k, value);
            }
            Map<String, Object> out = row(SettingsResolver.resolve(k, stores));
            out.put("scope_written", scope.wireName());
            return Response.ok(out);
        } catch (SettingRefusedException e) {
            return Response.err(e.getMessage());
        }
    }

    private static ScopeStore requireStore(ScopeStore store, Scope scope) {
        if (store == null) {
            throw new SettingRefusedException("No " + scope.wireName() + " scope here: no project is open.");
        }
        return store;
    }

    /** Removing a stricter value is loosening too. */
    private static void checkUnsetKeepsGuardrail(SettingKey k, Scope scope, Map<Scope, ScopeStore> stores,
            Resolution current) {
        if (k.kind() != SettingKey.Kind.GUARDRAIL) {
            return;
        }
        Map<Scope, ScopeStore> without = new EnumMap<>(stores);
        ScopeStore inner = stores.get(scope);
        without.put(scope, new ScopeStore() {
            @Override public Optional<String> read(SettingKey key) {
                return key.equals(k) ? Optional.empty() : inner.read(key);
            }
            @Override public void write(SettingKey key, String raw) { inner.write(key, raw); }
            @Override public void remove(SettingKey key) { inner.remove(key); }
        });
        Object after = SettingsResolver.resolve(k, without).value();
        if (!k.tightens().test(current.value(), after)) {
            throw new SettingRefusedException(k.key() + " is a guardrail set by the server operator. "
                + "From here it can only be made stricter, and removing the " + scope.wireName()
                + " value would loosen it.");
        }
    }

    private static Map<String, Object> row(Resolution r) {
        SettingKey k = r.key();
        boolean secret = k.kind() == SettingKey.Kind.SECRET;
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("key", k.key());
        if (secret) {
            row.put("set", !"".equals(r.value()));
        } else {
            row.put("value", r.value());
        }
        row.put("source", r.source().wireName());
        row.put("kind", k.kind().name().toLowerCase());
        row.put("writer", k.writer());
        row.put("type", k.type().name().toLowerCase());
        row.put("scopes", k.scopes().stream().map(Scope::wireName).toList());
        row.put("description", k.description());
        if (r.layers().size() > 1) {
            List<Map<String, Object>> layers = new ArrayList<>();
            for (SettingsResolver.Layer l : r.layers()) {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("scope", l.scope().wireName());
                if (!secret) {
                    m.put("value", l.raw());
                }
                m.put("applied", l.applied());
                if (l.note() != null) {
                    m.put("note", l.note());
                }
                layers.add(m);
            }
            row.put("layers", layers);
        }
        return row;
    }
}
