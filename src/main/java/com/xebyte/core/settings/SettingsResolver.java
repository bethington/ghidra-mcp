package com.xebyte.core.settings;

import com.xebyte.core.settings.SettingKey.Kind;
import com.xebyte.core.settings.SettingKey.Merge;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * Walks a key's scopes from the default up and reports the effective value, the scope it came
 * from, and every scope that held a value along the way ({@code git config --show-origin}).
 */
public final class SettingsResolver {

    /**
     * One scope's contribution.
     *
     * @param applied false when the value was ignored: unparseable, or a guardrail it would loosen
     */
    public record Layer(Scope scope, String raw, boolean applied, String note) {}

    public record Resolution(SettingKey key, Object value, Scope source, List<Layer> layers) {}

    private SettingsResolver() {}

    public static Resolution resolve(SettingKey key, Map<Scope, ScopeStore> stores) {
        Object value = key.parse(key.defaultRaw());
        Scope source = Scope.DEFAULT;
        List<Layer> layers = new ArrayList<>();
        layers.add(new Layer(Scope.DEFAULT, key.defaultRaw(), true, null));
        for (Scope scope : Scope.values()) {
            if (scope == Scope.DEFAULT || !key.allows(scope) || !stores.containsKey(scope)) {
                continue;
            }
            Optional<String> raw = stores.get(scope).read(key);
            if (raw.isEmpty()) {
                continue;
            }
            Object next;
            try {
                next = combine(key, value, raw.get());
            } catch (SettingRefusedException e) {
                layers.add(new Layer(scope, raw.get(), false, "ignored: " + e.getMessage()));
                continue;
            }
            if (loosens(key, scope, value, next)) {
                layers.add(new Layer(scope, raw.get(), false,
                    "ignored: a guardrail can only be made stricter above the server scope"));
                continue;
            }
            value = next;
            source = scope;
            layers.add(new Layer(scope, raw.get(), true, null));
        }
        return new Resolution(key, value, source, layers);
    }

    /**
     * Refuse a write an agent may not make: a scope the key does not allow, a secret, a value
     * that does not parse, or a guardrail value that would loosen what is in force.
     */
    public static void checkWrite(SettingKey key, Scope scope, String raw, Resolution current) {
        checkScope(key, scope);
        Object next = combine(key, current.value(), raw);
        if (loosens(key, scope, current.value(), next)) {
            throw new SettingRefusedException(key.key() + " is a guardrail set by the server operator. "
                + "From here it can only be made stricter, and '" + raw + "' would loosen it.");
        }
    }

    /** Refuse a write or unset at a scope an agent may not touch for this key. */
    public static void checkScope(SettingKey key, Scope scope) {
        if (key.kind() == Kind.SECRET) {
            throw new SettingRefusedException(
                key.key() + " is a secret held by the server operator; tools can neither read nor set it.");
        }
        if (!key.allows(scope) || scope == Scope.DEFAULT) {
            List<Scope> writable = key.scopes().stream()
                .filter(s -> s.ordinal() > Scope.SERVER.ordinal() && s != Scope.SESSION).toList();
            throw new SettingRefusedException(key.key() + " cannot be set at scope '" + scope.wireName()
                + "'. " + (writable.isEmpty() ? "It is not settable through tools."
                    : "Settable at: " + writable.stream().map(Scope::wireName)
                        .collect(Collectors.joining(", ")) + "."));
        }
        if (scope == Scope.SESSION) {
            throw new SettingRefusedException(
                key.key() + "'s session value belongs to the bridge session, not the server.");
        }
    }

    private static boolean loosens(SettingKey key, Scope scope, Object current, Object next) {
        return key.kind() == Kind.GUARDRAIL && scope.ordinal() > Scope.SERVER.ordinal()
            && !key.tightens().test(current, next);
    }

    private static Object combine(SettingKey key, Object current, String raw) {
        if (key.merge() == Merge.OVERRIDE) {
            return key.parse(raw);
        }
        return applyDelta(castList(current), raw);
    }

    /** {@code +x} adds, {@code -x} removes, and any bare name replaces the list below first. */
    static List<String> applyDelta(List<String> below, String raw) {
        List<String> tokens = SettingKey.tokens(raw);
        List<String> bare = tokens.stream().filter(t -> !t.startsWith("+") && !t.startsWith("-")).toList();
        List<String> out = new ArrayList<>(bare.isEmpty() && !tokens.isEmpty() ? below : bare);
        for (String t : tokens) {
            String name = t.substring(1).trim();
            if (t.startsWith("+") && !name.isEmpty() && !out.contains(name)) {
                out.add(name);
            } else if (t.startsWith("-")) {
                out.remove(name);
            }
        }
        return out;
    }

    @SuppressWarnings("unchecked")
    private static List<String> castList(Object value) {
        return (List<String>) value;
    }
}
