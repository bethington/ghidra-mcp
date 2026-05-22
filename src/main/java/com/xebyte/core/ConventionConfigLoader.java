package com.xebyte.core;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Reads {@code .ghidra-mcp/conventions.json} from a project root directory
 * and parses it into a {@link ConventionConfig}.
 *
 * <p>If the file is missing, malformed, or partially specified, the loader
 * falls back to defaults section-by-section — a project that only wants to
 * tweak one knob doesn't need to copy the whole schema. Errors are
 * surfaced via a {@link LoadResult} so callers can decide whether to
 * warn the user (via Ghidra's Msg log) or silently accept the fallback.
 *
 * <p>This class is package-public so {@link NamingPolicy} and tests can
 * drive it directly; production code should funnel through
 * {@link NamingPolicy#refreshFromProjectRoot(Path)}.
 */
public final class ConventionConfigLoader {

    /** Conventional path inside a project root. */
    public static final String CONFIG_RELATIVE_PATH = ".ghidra-mcp/conventions.json";

    private ConventionConfigLoader() {}

    public static final class LoadResult {
        private final ConventionConfig config;
        private final Path resolvedFrom;
        private final String error;
        private final List<String> warnings;

        LoadResult(ConventionConfig config, Path resolvedFrom, String error, List<String> warnings) {
            this.config = config;
            this.resolvedFrom = resolvedFrom;
            this.error = error;
            this.warnings = warnings == null ? List.of() : List.copyOf(warnings);
        }

        public ConventionConfig config() { return config; }
        public Path resolvedFrom() { return resolvedFrom; }
        public String error() { return error; }
        public List<String> warnings() { return warnings; }
        public boolean loaded() { return resolvedFrom != null && error == null; }
        public boolean usedDefaults() { return resolvedFrom == null; }
    }

    /**
     * Load the config from {@code <projectRoot>/.ghidra-mcp/conventions.json}.
     * Returns a result holding either the parsed config, or defaults +
     * an error describing why the file couldn't be used.
     */
    public static LoadResult loadFromProjectRoot(Path projectRoot) {
        if (projectRoot == null) {
            return new LoadResult(ConventionConfig.defaults(), null, null, List.of());
        }
        Path file = projectRoot.resolve(CONFIG_RELATIVE_PATH);
        if (!Files.isRegularFile(file)) {
            return new LoadResult(ConventionConfig.defaults(), null, null, List.of());
        }
        String text;
        try {
            text = Files.readString(file);
        } catch (IOException e) {
            return new LoadResult(
                    ConventionConfig.defaults(),
                    null,
                    "Failed to read " + file + ": " + e.getMessage(),
                    List.of()
            );
        }
        return parse(text, file);
    }

    /** Parse raw JSON. Public so tests can hit it without touching the filesystem. */
    public static LoadResult parse(String json, Path resolvedFrom) {
        Map<String, Object> root;
        try {
            root = JsonHelper.parseJson(json);
        } catch (RuntimeException e) {
            return new LoadResult(
                    ConventionConfig.defaults(),
                    null,
                    "Malformed JSON in conventions config: " + e.getMessage(),
                    List.of()
            );
        }
        if (root == null) {
            return new LoadResult(
                    ConventionConfig.defaults(),
                    null,
                    "Conventions config did not parse to an object",
                    List.of()
            );
        }

        List<String> warnings = new ArrayList<>();

        ConventionConfig.Mode mode = ConventionConfig.Mode.parse(
                asString(root.get("strict_mode")),
                ConventionConfig.Mode.ENFORCE
        );

        ConventionConfig.FunctionNamingRules fn = parseFunctionNaming(
                asObject(root.get("function_naming")), warnings);
        ConventionConfig.HungarianRules hu = parseHungarian(
                asObject(root.get("hungarian")), warnings);
        ConventionConfig.GlobalNamingRules gl = parseGlobalNaming(
                asObject(root.get("global_naming")), warnings);
        ConventionConfig.PlateCommentRules pc = parsePlateComments(
                asObject(root.get("plate_comments")), warnings);

        return new LoadResult(
                new ConventionConfig(mode, fn, hu, gl, pc),
                resolvedFrom,
                null,
                warnings
        );
    }

    private static ConventionConfig.FunctionNamingRules parseFunctionNaming(
            Map<String, Object> section, List<String> warnings) {
        if (section == null) return ConventionConfig.FunctionNamingRules.defaults();
        int minLength = asInt(section.get("min_length"), 8);
        Set<String> add = asStringSet(section.get("verbs_add"));
        Set<String> remove = asStringSet(section.get("verbs_remove"));
        Map<String, Integer> tierOverrides = asStringIntMap(
                section.get("verb_tier_overrides"), warnings);
        Set<String> weakAdd = asStringSet(section.get("weak_nouns_add"));
        Set<String> weakRemove = asStringSet(section.get("weak_nouns_remove"));
        return new ConventionConfig.FunctionNamingRules(
                minLength, add, remove, tierOverrides, weakAdd, weakRemove);
    }

    private static ConventionConfig.HungarianRules parseHungarian(
            Map<String, Object> section, List<String> warnings) {
        if (section == null) return ConventionConfig.HungarianRules.defaults();
        boolean autoFix = asBool(section.get("auto_fix_struct_fields"), true);
        Map<String, Set<String>> extra = new LinkedHashMap<>();
        Object rawExtra = section.get("extra_prefixes");
        if (rawExtra instanceof Map) {
            Map<?, ?> raw = (Map<?, ?>) rawExtra;
            for (Map.Entry<?, ?> entry : raw.entrySet()) {
                if (!(entry.getKey() instanceof String)) continue;
                Set<String> types = asStringSet(entry.getValue());
                if (!types.isEmpty()) {
                    extra.put((String) entry.getKey(), types);
                }
            }
        }
        return new ConventionConfig.HungarianRules(autoFix, extra);
    }

    private static ConventionConfig.GlobalNamingRules parseGlobalNaming(
            Map<String, Object> section, List<String> warnings) {
        if (section == null) return ConventionConfig.GlobalNamingRules.defaults();
        boolean validate = asBool(section.get("validate"), true);
        boolean requireG = asBool(section.get("require_g_prefix"), true);
        int minDescriptor = asInt(section.get("min_descriptor_length"), 2);
        return new ConventionConfig.GlobalNamingRules(validate, requireG, minDescriptor);
    }

    private static ConventionConfig.PlateCommentRules parsePlateComments(
            Map<String, Object> section, List<String> warnings) {
        if (section == null) return ConventionConfig.PlateCommentRules.defaults();
        boolean validate = asBool(section.get("validate"), true);
        Object rawSections = section.get("required_sections");
        List<String> sections;
        if (rawSections instanceof List) {
            sections = new ArrayList<>();
            for (Object o : (List<?>) rawSections) {
                if (o instanceof String) sections.add((String) o);
            }
        } else {
            sections = List.of("Algorithm", "Parameters", "Returns");
        }
        int minWords = asInt(section.get("min_first_line_words"), 4);
        return new ConventionConfig.PlateCommentRules(validate, sections, minWords);
    }

    // ---------- conversion helpers ----------

    private static String asString(Object v) {
        return v instanceof String ? (String) v : null;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> asObject(Object v) {
        return v instanceof Map ? (Map<String, Object>) v : null;
    }

    private static boolean asBool(Object v, boolean fallback) {
        if (v instanceof Boolean) return (Boolean) v;
        if (v instanceof String) {
            String s = ((String) v).trim().toLowerCase();
            if (s.equals("true")) return true;
            if (s.equals("false")) return false;
        }
        return fallback;
    }

    private static int asInt(Object v, int fallback) {
        if (v instanceof Number) return ((Number) v).intValue();
        if (v instanceof String) {
            try {
                return Integer.parseInt(((String) v).trim());
            } catch (NumberFormatException ignored) {
                // fall through
            }
        }
        return fallback;
    }

    private static Set<String> asStringSet(Object v) {
        if (!(v instanceof List)) return Set.of();
        Set<String> out = new LinkedHashSet<>();
        for (Object o : (List<?>) v) {
            if (o instanceof String) out.add((String) o);
        }
        return out;
    }

    private static Map<String, Integer> asStringIntMap(Object v, List<String> warnings) {
        if (!(v instanceof Map)) return Map.of();
        Map<String, Integer> out = new LinkedHashMap<>();
        for (Map.Entry<?, ?> entry : ((Map<?, ?>) v).entrySet()) {
            if (!(entry.getKey() instanceof String)) continue;
            String key = (String) entry.getKey();
            Object val = entry.getValue();
            int tier;
            if (val instanceof Number) {
                tier = ((Number) val).intValue();
            } else if (val instanceof String) {
                try {
                    tier = Integer.parseInt(((String) val).trim());
                } catch (NumberFormatException e) {
                    warnings.add("verb_tier_overrides[" + key + "] is not a number");
                    continue;
                }
            } else {
                warnings.add("verb_tier_overrides[" + key + "] is not a number");
                continue;
            }
            if (tier < 1 || tier > 3) {
                warnings.add("verb_tier_overrides[" + key + "] tier " + tier
                        + " out of range 1..3 — ignored");
                continue;
            }
            out.put(key, tier);
        }
        return out;
    }
}
