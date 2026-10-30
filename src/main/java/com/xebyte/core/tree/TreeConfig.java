package com.xebyte.core.tree;

import com.xebyte.core.JsonHelper;
import com.xebyte.core.settings.SettingKey;
import com.xebyte.core.settings.SettingsRegistry;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Immutable sweep / layout configuration for one tree.
 *
 * <p>Clamps on construction rather than rejecting silently: a caller that
 * asks for {@code throttlePercent=150} still gets a usable config (90), and
 * {@code bandSize=0} floors to 1 so partitioning never divides by zero.
 * {@code maxFileBytes} floors at {@link #MIN_MAX_FILE_BYTES} so a mis-set
 * budget cannot produce unreadable multi-megabyte compartment files.
 *
 * @param rootPath                 absolute tree root, or {@code null} to
 *                                 use the default under {@code java.io.tmpdir}
 * @param enabledStrategies        partition strategy names; empty = full cascade
 * @param bandSize                 address-band width when bands apply (floored at 1)
 * @param exclusions               drop matching functions after partitioning
 * @param includeOnly              when non-empty, keep only matches (applied first)
 * @param throttlePercent          interactive yield 0..90 (default 10)
 * @param decompileTimeoutSeconds  per-function decompile budget
 * @param analysisWaitSeconds      cap on waiting for auto-analysis before sweeping
 * @param maxFileBytes             Read-budget for each {@code .c} inside a
 *                                 compartment (default 32 KiB); changing it
 *                                 moves file paths → repartitioning
 * @param disassembleMissing       off by default; when true, the sweep
 *                                 disassembles entries with no instruction
 *                                 (PE {@code .pdata} stubs) via the threading strategy
 */
public record TreeConfig(
        String rootPath,
        List<String> enabledStrategies,
        int bandSize,
        List<ExclusionRule> exclusions,
        List<ExclusionRule> includeOnly,
        int throttlePercent,
        int decompileTimeoutSeconds,
        int analysisWaitSeconds,
        int maxFileBytes,
        boolean disassembleMissing) {

    /** Floor so a typo cannot recreate the 1.9 MB compartment-file bug. */
    public static final int MIN_MAX_FILE_BYTES = 4096;

    private static final SettingsRegistry REG = SettingsRegistry.DEFAULT;

    public TreeConfig {
        enabledStrategies = enabledStrategies == null
                ? List.of()
                : List.copyOf(enabledStrategies);
        exclusions = exclusions == null ? List.of() : List.copyOf(exclusions);
        includeOnly = includeOnly == null ? List.of() : List.copyOf(includeOnly);
        bandSize = Math.max(1, bandSize);
        throttlePercent = Math.clamp(throttlePercent, 0, 90);
        if (decompileTimeoutSeconds < 1) {
            decompileTimeoutSeconds = registryInt("tree.decompile_timeout_seconds");
        }
        if (analysisWaitSeconds < 1) {
            analysisWaitSeconds = registryInt("tree.analysis_wait_seconds");
        }
        if (maxFileBytes < MIN_MAX_FILE_BYTES) {
            maxFileBytes = MIN_MAX_FILE_BYTES;
        }
        if (rootPath != null && rootPath.isBlank()) {
            rootPath = null;
        }
    }

    /** Placeholder config matching registry defaults (not program-scoped overrides). */
    public static TreeConfig defaults() {
        return new TreeConfig(
                null,
                List.of(),
                registryInt("tree.band_size"),
                List.of(),
                List.of(),
                registryInt("tree.throttle_percent"),
                registryInt("tree.decompile_timeout_seconds"),
                registryInt("tree.analysis_wait_seconds"),
                registryInt("tree.max_file_bytes"),
                registryBool("tree.disassemble_missing"));
    }

    public static Builder builder() {
        return new Builder();
    }

    public Builder toBuilder() {
        return builder()
                .rootPath(rootPath)
                .enabledStrategies(enabledStrategies)
                .bandSize(bandSize)
                .exclusions(exclusions)
                .includeOnly(includeOnly)
                .throttlePercent(throttlePercent)
                .decompileTimeoutSeconds(decompileTimeoutSeconds)
                .analysisWaitSeconds(analysisWaitSeconds)
                .maxFileBytes(maxFileBytes)
                .disassembleMissing(disassembleMissing);
    }

    public TreeConfig withRootPath(String newRootPath) {
        return toBuilder().rootPath(newRootPath).build();
    }

    public boolean hasRuleKind(ExclusionRule.Kind kind) {
        for (ExclusionRule r : exclusions) {
            if (r.kind() == kind) {
                return true;
            }
        }
        for (ExclusionRule r : includeOnly) {
            if (r.kind() == kind) {
                return true;
            }
        }
        return false;
    }

    public Map<String, Object> toMap() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("root", rootPath);
        m.put("enabled_strategies", enabledStrategies);
        m.put("band_size", bandSize);
        m.put("max_file_bytes", maxFileBytes);
        m.put("exclusions", rulesToSpecs(exclusions));
        m.put("include_only", rulesToSpecs(includeOnly));
        m.put("throttle_percent", throttlePercent);
        m.put("decompile_timeout_seconds", decompileTimeoutSeconds);
        m.put("analysis_wait_seconds", analysisWaitSeconds);
        m.put("disassemble_missing", disassembleMissing);
        return m;
    }

    public static TreeConfig fromMap(Map<String, Object> disk, String rootPath) {
        Builder b = builder().rootPath(rootPath);
        Object strategies = disk.get("enabled_strategies");
        if (strategies instanceof List<?> list) {
            List<String> names = new ArrayList<>();
            for (Object o : list) {
                if (o != null) {
                    names.add(o.toString());
                }
            }
            b.enabledStrategies(names);
        }
        b.bandSize(JsonHelper.getInt(disk.get("band_size"), registryInt("tree.band_size")));
        b.maxFileBytes(JsonHelper.getInt(disk.get("max_file_bytes"), registryInt("tree.max_file_bytes")));
        b.throttlePercent(JsonHelper.getInt(disk.get("throttle_percent"), registryInt("tree.throttle_percent")));
        b.decompileTimeoutSeconds(JsonHelper.getInt(
                disk.get("decompile_timeout_seconds"), registryInt("tree.decompile_timeout_seconds")));
        b.analysisWaitSeconds(JsonHelper.getInt(
                disk.get("analysis_wait_seconds"), registryInt("tree.analysis_wait_seconds")));
        Object dm = disk.get("disassemble_missing");
        if (dm instanceof Boolean bool) {
            b.disassembleMissing(bool);
        } else if (dm instanceof String s && !s.isBlank()) {
            b.disassembleMissing(Boolean.parseBoolean(s.trim()));
        }
        b.exclusions(rulesFromDisk(disk.get("exclusions")));
        b.includeOnly(rulesFromDisk(disk.get("include_only")));
        return b.build();
    }

    private static List<String> rulesToSpecs(List<ExclusionRule> rules) {
        List<String> out = new ArrayList<>(rules.size());
        for (ExclusionRule r : rules) {
            out.add(r.toSpec());
        }
        return out;
    }

    private static List<ExclusionRule> rulesFromDisk(Object raw) {
        if (!(raw instanceof List<?> list) || list.isEmpty()) {
            return List.of();
        }
        List<ExclusionRule> out = new ArrayList<>();
        for (Object o : list) {
            if (o == null) {
                continue;
            }
            if (o instanceof Map<?, ?> m) {
                Object kind = m.get("kind");
                Object value = m.get("value");
                if (kind != null && value != null) {
                    out.add(ExclusionRule.parse(
                            kind.toString().toLowerCase(Locale.ROOT) + ":" + value));
                }
            } else {
                out.add(ExclusionRule.parse(o.toString()));
            }
        }
        return out;
    }

    static int registryInt(String key) {
        SettingKey k = REG.get(key);
        return ((Number) k.parse(k.defaultRaw())).intValue();
    }

    static boolean registryBool(String key) {
        SettingKey k = REG.get(key);
        return (Boolean) k.parse(k.defaultRaw());
    }

    public static final class Builder {
        private String rootPath;
        private List<String> enabledStrategies = List.of();
        private int bandSize = registryInt("tree.band_size");
        private List<ExclusionRule> exclusions = List.of();
        private List<ExclusionRule> includeOnly = List.of();
        private int throttlePercent = registryInt("tree.throttle_percent");
        private int decompileTimeoutSeconds = registryInt("tree.decompile_timeout_seconds");
        private int analysisWaitSeconds = registryInt("tree.analysis_wait_seconds");
        private int maxFileBytes = registryInt("tree.max_file_bytes");
        private boolean disassembleMissing = registryBool("tree.disassemble_missing");

        public Builder rootPath(String rootPath) {
            this.rootPath = rootPath;
            return this;
        }

        public Builder enabledStrategies(List<String> enabledStrategies) {
            this.enabledStrategies = enabledStrategies;
            return this;
        }

        public Builder bandSize(int bandSize) {
            this.bandSize = bandSize;
            return this;
        }

        public Builder exclusions(List<ExclusionRule> exclusions) {
            this.exclusions = exclusions;
            return this;
        }

        public Builder includeOnly(List<ExclusionRule> includeOnly) {
            this.includeOnly = includeOnly;
            return this;
        }

        public Builder throttlePercent(int throttlePercent) {
            this.throttlePercent = throttlePercent;
            return this;
        }

        public Builder decompileTimeoutSeconds(int decompileTimeoutSeconds) {
            this.decompileTimeoutSeconds = decompileTimeoutSeconds;
            return this;
        }

        public Builder analysisWaitSeconds(int analysisWaitSeconds) {
            this.analysisWaitSeconds = analysisWaitSeconds;
            return this;
        }

        public Builder maxFileBytes(int maxFileBytes) {
            this.maxFileBytes = maxFileBytes;
            return this;
        }

        public Builder disassembleMissing(boolean disassembleMissing) {
            this.disassembleMissing = disassembleMissing;
            return this;
        }

        public TreeConfig build() {
            return new TreeConfig(
                    rootPath,
                    enabledStrategies,
                    bandSize,
                    exclusions,
                    includeOnly,
                    throttlePercent,
                    decompileTimeoutSeconds,
                    analysisWaitSeconds,
                    maxFileBytes,
                    disassembleMissing);
        }
    }
}
