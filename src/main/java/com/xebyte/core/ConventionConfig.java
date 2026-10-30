package com.xebyte.core;

import ghidra.util.Msg;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;

/**
 * User-configurable naming-convention rules. Built from {@code naming.*}
 * settings by {@link NamingPolicy}, which {@link NamingConventions} consults.
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

        /** Like {@link #parse} with a null fallback — unknown values return null. */
        public static Mode parseStrict(String value) {
            return parse(value, null);
        }

        /** Lowercase wire name for messages ({@code enforce}, {@code warn}, {@code off}). */
        public String wireName() {
            return name().toLowerCase();
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

    /**
     * Build a config from resolved settings values. Malformed list entries are
     * logged and skipped rather than failing the request.
     */
    public static ConventionConfig fromSettings(Function<String, Object> value) {
        Mode mode = Mode.parseStrict(asString(value.apply("naming.mode")));
        if (mode == null) {
            mode = Mode.ENFORCE;
        }
        return new ConventionConfig(
                mode,
                functionNamingFromSettings(value),
                hungarianFromSettings(value),
                globalNamingFromSettings(value),
                plateCommentsFromSettings(value));
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

    private static FunctionNamingRules functionNamingFromSettings(Function<String, Object> value) {
        FunctionNamingRules defaults = FunctionNamingRules.defaults();
        int minLength = asInt(value.apply("naming.function.min_length"), defaults.minLength());
        Set<String> verbsAdd = asStringSet(value.apply("naming.function.verbs_add"));
        Set<String> verbsRemove = asStringSet(value.apply("naming.function.verbs_remove"));
        Map<String, Integer> tierOverrides = verbTiersFromList(asStringList(value.apply("naming.function.verb_tiers")));
        Set<String> weakAdd = asStringSet(value.apply("naming.function.weak_nouns_add"));
        Set<String> weakRemove = asStringSet(value.apply("naming.function.weak_nouns_remove"));
        return new FunctionNamingRules(minLength, verbsAdd, verbsRemove, tierOverrides, weakAdd, weakRemove);
    }

    private static HungarianRules hungarianFromSettings(Function<String, Object> value) {
        boolean autoFix = asBool(value.apply("naming.hungarian.auto_fix"), true);
        Map<String, Set<String>> extra = prefixesFromList(asStringList(value.apply("naming.hungarian.prefixes")));
        return new HungarianRules(autoFix, extra);
    }

    private static GlobalNamingRules globalNamingFromSettings(Function<String, Object> value) {
        GlobalNamingRules defaults = GlobalNamingRules.defaults();
        boolean validate = asBool(value.apply("naming.global.validate"), defaults.validate());
        boolean requireG = asBool(value.apply("naming.global.require_g_prefix"), defaults.requireGPrefix());
        int minDescriptor = asInt(value.apply("naming.global.min_descriptor_length"), defaults.minDescriptorLength());
        return new GlobalNamingRules(validate, requireG, minDescriptor);
    }

    private static PlateCommentRules plateCommentsFromSettings(Function<String, Object> value) {
        PlateCommentRules defaults = PlateCommentRules.defaults();
        boolean validate = asBool(value.apply("naming.plate.validate"), defaults.validate());
        List<String> sections = asStringList(value.apply("naming.plate.required_sections"));
        if (sections.isEmpty()) {
            sections = defaults.requiredSections();
        }
        int minWords = asInt(value.apply("naming.plate.min_first_line_words"), defaults.minFirstLineWords());
        return new PlateCommentRules(validate, sections, minWords);
    }

    private static Map<String, Integer> verbTiersFromList(List<String> entries) {
        Map<String, Integer> out = new LinkedHashMap<>();
        for (String entry : entries) {
            if (entry == null || entry.isBlank()) {
                continue;
            }
            int colon = entry.indexOf(':');
            if (colon <= 0 || colon >= entry.length() - 1) {
                Msg.warn(ConventionConfig.class, "naming.function.verb_tiers entry '" + entry
                    + "' is not Verb:tier — ignored");
                continue;
            }
            String verb = entry.substring(0, colon).trim();
            String tierRaw = entry.substring(colon + 1).trim();
            int tier;
            try {
                tier = Integer.parseInt(tierRaw);
            } catch (NumberFormatException e) {
                Msg.warn(ConventionConfig.class, "naming.function.verb_tiers[" + verb + "] is not a number");
                continue;
            }
            if (tier < 1 || tier > 3) {
                Msg.warn(ConventionConfig.class, "naming.function.verb_tiers[" + verb + "] tier " + tier
                    + " out of range 1..3 — ignored");
                continue;
            }
            out.put(verb, tier);
        }
        return out;
    }

    private static Map<String, Set<String>> prefixesFromList(List<String> entries) {
        Map<String, Set<String>> out = new LinkedHashMap<>();
        for (String entry : entries) {
            if (entry == null || entry.isBlank()) {
                continue;
            }
            int colon = entry.indexOf(':');
            if (colon <= 0 || colon >= entry.length() - 1) {
                Msg.warn(ConventionConfig.class, "naming.hungarian.prefixes entry '" + entry
                    + "' is not type:prefix — ignored");
                continue;
            }
            String type = entry.substring(0, colon).trim();
            String prefix = entry.substring(colon + 1).trim();
            if (prefix.isEmpty() || type.isEmpty()) {
                continue;
            }
            out.computeIfAbsent(prefix, k -> new LinkedHashSet<>()).add(type);
        }
        Map<String, Set<String>> copy = new LinkedHashMap<>();
        for (Map.Entry<String, Set<String>> e : out.entrySet()) {
            copy.put(e.getKey(), immutableSet(e.getValue()));
        }
        return copy;
    }

    private static String asString(Object v) {
        return v instanceof String ? (String) v : null;
    }

    private static boolean asBool(Object v, boolean fallback) {
        if (v instanceof Boolean) {
            return (Boolean) v;
        }
        if (v instanceof String) {
            String s = ((String) v).trim().toLowerCase();
            if (s.equals("true")) {
                return true;
            }
            if (s.equals("false")) {
                return false;
            }
        }
        return fallback;
    }

    private static int asInt(Object v, int fallback) {
        if (v instanceof Number) {
            return ((Number) v).intValue();
        }
        if (v instanceof String) {
            try {
                return Integer.parseInt(((String) v).trim());
            } catch (NumberFormatException ignored) {
                // fall through
            }
        }
        return fallback;
    }

    @SuppressWarnings("unchecked")
    private static List<String> asStringList(Object v) {
        if (!(v instanceof List)) {
            return List.of();
        }
        List<String> out = new ArrayList<>();
        for (Object o : (List<?>) v) {
            if (o instanceof String) {
                out.add((String) o);
            }
        }
        return out;
    }

    private static Set<String> asStringSet(Object v) {
        return new LinkedHashSet<>(asStringList(v));
    }
}
