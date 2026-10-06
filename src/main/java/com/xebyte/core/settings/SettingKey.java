package com.xebyte.core.settings;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.function.BiPredicate;

/**
 * One registered setting: its type, default, the scopes it may be set at, who may write it and
 * how scopes combine.
 *
 * @param key         dotted name, {@code area.setting} (at most {@code area.feature.setting})
 * @param type        how a raw string parses
 * @param defaultRaw  the default, in raw form
 * @param scopes      scopes a value may come from; {@link Scope#DEFAULT} is implied
 * @param kind        preference, guardrail or secret
 * @param merge       how a scope's value combines with the ones below it
 * @param tightens    guardrails only: {@code (current, candidate) -> candidate is at least as strict}
 * @param description one line for the generated key table and {@code get_settings}
 */
public record SettingKey(String key, Type type, String defaultRaw, Set<Scope> scopes, Kind kind,
        Merge merge, BiPredicate<Object, Object> tightens, String description) {

    public enum Type { BOOL, INT, STRING, LIST }

    /**
     * Preferences are the agent's to set. A guardrail is the operator's: values from scopes an
     * agent can write only ever tighten it. A secret is set and unset by the operator and never
     * read back.
     */
    public enum Kind { PREFERENCE, GUARDRAIL, SECRET }

    /**
     * {@code OVERRIDE}: the highest scope with a value wins. {@code LIST_DELTA}: a scope's
     * value of {@code +x,-y} adds and removes from what the scopes below produced, and a bare
     * {@code x,y} replaces it.
     */
    public enum Merge { OVERRIDE, LIST_DELTA }

    public SettingKey {
        scopes = scopes.isEmpty() ? EnumSet.noneOf(Scope.class) : EnumSet.copyOf(scopes);
        if (kind == Kind.GUARDRAIL && tightens == null) {
            throw new IllegalArgumentException(key + ": a guardrail needs a tightening rule");
        }
        if (merge == Merge.LIST_DELTA && type != Type.LIST) {
            throw new IllegalArgumentException(key + ": list-delta merge needs a list type");
        }
    }

    /** {@code GHIDRA_MCP_} + the key upper-cased with dots as underscores. */
    public String envName() {
        return "GHIDRA_MCP_" + key.toUpperCase(Locale.ROOT).replace('.', '_');
    }

    public String writer() {
        return kind == Kind.PREFERENCE ? "agent" : "operator";
    }

    public boolean allows(Scope scope) {
        return scope == Scope.DEFAULT || scopes.contains(scope);
    }

    /** Parse a raw value of this key's type; a list is comma-separated, blanks dropped. */
    public Object parse(String raw) {
        String v = raw == null ? "" : raw.trim();
        return switch (type) {
            case BOOL -> switch (v.toLowerCase(Locale.ROOT)) {
                case "1", "true", "yes", "on" -> true;
                case "0", "false", "no", "off", "" -> false;
                default -> throw new SettingRefusedException(
                    key + " is a boolean; '" + raw + "' is not one of true/false/1/0/yes/no/on/off.");
            };
            case INT -> {
                try {
                    yield v.isEmpty() ? 0L : Long.parseLong(v);
                } catch (NumberFormatException e) {
                    throw new SettingRefusedException(key + " is an integer; '" + raw + "' is not.");
                }
            }
            case STRING -> v;
            case LIST -> tokens(v);
        };
    }

    static List<String> tokens(String raw) {
        List<String> out = new ArrayList<>();
        for (String t : raw.split(",")) {
            if (!t.isBlank()) {
                out.add(t.trim());
            }
        }
        return out;
    }

    // ---------------------------------------------------------------- tightening rules

    /** For an {@code allow}-style boolean: {@code false} is the strict value. */
    public static final BiPredicate<Object, Object> FALSE_IS_STRICTER =
        (current, candidate) -> !(Boolean) candidate || (Boolean) current;

    /**
     * For a path that confines access, empty meaning unconfined: a candidate tightens when it
     * confines and lies within the current confinement.
     */
    public static final BiPredicate<Object, Object> PATH_WITHIN = (current, candidate) -> {
        String cur = (String) current;
        String cand = (String) candidate;
        if (cand.isEmpty()) {
            return cur.isEmpty();
        }
        // Path.startsWith compares whole elements, so /Mods does not contain /Mods2.
        return cur.isEmpty() || Path.of(cand).normalize().startsWith(Path.of(cur).normalize());
    };
}
