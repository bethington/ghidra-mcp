package com.xebyte.core;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * User-configurable naming-convention rules. Read from
 * {@code .ghidra-mcp/conventions.json} at the Ghidra project root by
 * {@link ConventionConfigLoader}, then held by {@link NamingPolicy} as the
 * single source of truth that {@link NamingConventions} validators consult.
 *
 * <p>Every field has a built-in default that reproduces the historical
 * hardcoded behavior, so projects with no config file get exactly the
 * pre-v5.11.2 enforcement. A project that wants to disable a specific
 * gate, add custom verbs, or swap the Hungarian prefix mapping flips just
 * the relevant section.
 *
 * <p>The schema is intentionally additive: most knobs are {@code _add} /
 * {@code _remove} pairs over the built-in sets rather than full
 * replacements. This lets a project nudge the convention ("we use
 * {@code Sniff} as a verb, drop {@code Process} from Tier 3") without
 * having to copy the entire 70-verb whitelist into their config file.
 *
 * <p>Immutable. Build via the static factory + JSON loader, replace
 * the {@link NamingPolicy} reference atomically when the file changes.
 */
public final class ConventionConfig {

    /** Strict mode behavior: enforce (reject), warn, or off (silent). */
    public enum Mode {
        ENFORCE,
        WARN,
        OFF;

        public static Mode parse(String value, Mode fallback) {
            if (value == null) return fallback;
            switch (value.trim().toLowerCase()) {
                case "enforce":
                case "strict":
                case "true":
                    return ENFORCE;
                case "warn":
                case "warning":
                    return WARN;
                case "off":
                case "false":
                case "disable":
                case "disabled":
                    return OFF;
                default:
                    return fallback;
            }
        }
    }

    private final Mode mode;
    private final FunctionNamingRules functionNaming;
    private final HungarianRules hungarian;
    private final GlobalNamingRules globalNaming;
    private final PlateCommentRules plateComments;

    public ConventionConfig(Mode mode,
                            FunctionNamingRules functionNaming,
                            HungarianRules hungarian,
                            GlobalNamingRules globalNaming,
                            PlateCommentRules plateComments) {
        this.mode = mode != null ? mode : Mode.ENFORCE;
        this.functionNaming = functionNaming != null ? functionNaming : FunctionNamingRules.defaults();
        this.hungarian = hungarian != null ? hungarian : HungarianRules.defaults();
        this.globalNaming = globalNaming != null ? globalNaming : GlobalNamingRules.defaults();
        this.plateComments = plateComments != null ? plateComments : PlateCommentRules.defaults();
    }

    /** Defaults match the v5.0–v5.11 hardcoded behavior. */
    public static ConventionConfig defaults() {
        return new ConventionConfig(
                Mode.ENFORCE,
                FunctionNamingRules.defaults(),
                HungarianRules.defaults(),
                GlobalNamingRules.defaults(),
                PlateCommentRules.defaults()
        );
    }

    public Mode getMode() { return mode; }
    public boolean isStrict() { return mode == Mode.ENFORCE; }
    public boolean isWarn() { return mode == Mode.WARN; }
    public boolean isOff() { return mode == Mode.OFF; }

    public FunctionNamingRules functionNaming() { return functionNaming; }
    public HungarianRules hungarian() { return hungarian; }
    public GlobalNamingRules globalNaming() { return globalNaming; }
    public PlateCommentRules plateComments() { return plateComments; }

    /** Per-section rules: function name validation. */
    public static final class FunctionNamingRules {
        private final int minLength;
        private final Set<String> verbsAdd;
        private final Set<String> verbsRemove;
        private final Map<String, Integer> verbTierOverrides;
        private final Set<String> weakNounsAdd;
        private final Set<String> weakNounsRemove;

        public FunctionNamingRules(int minLength,
                                   Set<String> verbsAdd,
                                   Set<String> verbsRemove,
                                   Map<String, Integer> verbTierOverrides,
                                   Set<String> weakNounsAdd,
                                   Set<String> weakNounsRemove) {
            this.minLength = minLength > 0 ? minLength : 8;
            this.verbsAdd = immutableSet(verbsAdd);
            this.verbsRemove = immutableSet(verbsRemove);
            this.verbTierOverrides = verbTierOverrides == null
                    ? Map.of()
                    : Map.copyOf(verbTierOverrides);
            this.weakNounsAdd = immutableSet(weakNounsAdd);
            this.weakNounsRemove = immutableSet(weakNounsRemove);
        }

        public static FunctionNamingRules defaults() {
            return new FunctionNamingRules(8, Set.of(), Set.of(), Map.of(), Set.of(), Set.of());
        }

        public int minLength() { return minLength; }
        public Set<String> verbsAdd() { return verbsAdd; }
        public Set<String> verbsRemove() { return verbsRemove; }
        public Map<String, Integer> verbTierOverrides() { return verbTierOverrides; }
        public Set<String> weakNounsAdd() { return weakNounsAdd; }
        public Set<String> weakNounsRemove() { return weakNounsRemove; }
    }

    /** Per-section rules: Hungarian notation behavior. */
    public static final class HungarianRules {
        private final boolean autoFixStructFields;
        private final Map<String, Set<String>> extraPrefixes;

        public HungarianRules(boolean autoFixStructFields,
                              Map<String, Set<String>> extraPrefixes) {
            this.autoFixStructFields = autoFixStructFields;
            if (extraPrefixes == null) {
                this.extraPrefixes = Map.of();
            } else {
                Map<String, Set<String>> copy = new LinkedHashMap<>();
                for (Map.Entry<String, Set<String>> entry : extraPrefixes.entrySet()) {
                    copy.put(entry.getKey(), immutableSet(entry.getValue()));
                }
                this.extraPrefixes = Collections.unmodifiableMap(copy);
            }
        }

        public static HungarianRules defaults() {
            return new HungarianRules(true, Map.of());
        }

        public boolean autoFixStructFields() { return autoFixStructFields; }
        public Map<String, Set<String>> extraPrefixes() { return extraPrefixes; }
    }

    /** Per-section rules: global symbol naming. */
    public static final class GlobalNamingRules {
        private final boolean validate;
        private final boolean requireGPrefix;
        private final int minDescriptorLength;

        public GlobalNamingRules(boolean validate, boolean requireGPrefix, int minDescriptorLength) {
            this.validate = validate;
            this.requireGPrefix = requireGPrefix;
            this.minDescriptorLength = minDescriptorLength > 0 ? minDescriptorLength : 2;
        }

        public static GlobalNamingRules defaults() {
            return new GlobalNamingRules(true, true, 2);
        }

        public boolean validate() { return validate; }
        public boolean requireGPrefix() { return requireGPrefix; }
        public int minDescriptorLength() { return minDescriptorLength; }
    }

    /** Per-section rules: plate comment structure. */
    public static final class PlateCommentRules {
        private final boolean validate;
        private final List<String> requiredSections;
        private final int minFirstLineWords;

        public PlateCommentRules(boolean validate,
                                 List<String> requiredSections,
                                 int minFirstLineWords) {
            this.validate = validate;
            this.requiredSections = requiredSections == null
                    ? List.of("Algorithm", "Parameters", "Returns")
                    : List.copyOf(requiredSections);
            this.minFirstLineWords = minFirstLineWords > 0 ? minFirstLineWords : 4;
        }

        public static PlateCommentRules defaults() {
            return new PlateCommentRules(
                    true,
                    List.of("Algorithm", "Parameters", "Returns"),
                    4
            );
        }

        public boolean validate() { return validate; }
        public List<String> requiredSections() { return requiredSections; }
        public int minFirstLineWords() { return minFirstLineWords; }
    }

    private static Set<String> immutableSet(Set<String> in) {
        if (in == null || in.isEmpty()) return Set.of();
        return Collections.unmodifiableSet(new LinkedHashSet<>(in));
    }
}
