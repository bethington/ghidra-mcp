package com.xebyte.core.tree;

import java.util.List;

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
 * @param disassembleMissing       before partitioning, disassemble at entries
 *                                 with no instruction (PE {@code .pdata} stubs)
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

    public static final int DEFAULT_BAND_SIZE = 20;
    public static final int DEFAULT_THROTTLE_PERCENT = 10;
    public static final int DEFAULT_DECOMPILE_TIMEOUT_SECONDS = 30;
    public static final int DEFAULT_ANALYSIS_WAIT_SECONDS = 600;
    /** ~8K tokens — one comfortable agent Read. */
    public static final int DEFAULT_MAX_FILE_BYTES = 32768;
    /** Floor so a typo cannot recreate the 1.9 MB compartment-file bug. */
    public static final int MIN_MAX_FILE_BYTES = 4096;

    public TreeConfig {
        enabledStrategies = enabledStrategies == null
                ? List.of()
                : List.copyOf(enabledStrategies);
        exclusions = exclusions == null ? List.of() : List.copyOf(exclusions);
        includeOnly = includeOnly == null ? List.of() : List.copyOf(includeOnly);
        bandSize = Math.max(1, bandSize);
        throttlePercent = Math.clamp(throttlePercent, 0, 90);
        if (decompileTimeoutSeconds < 1) {
            decompileTimeoutSeconds = DEFAULT_DECOMPILE_TIMEOUT_SECONDS;
        }
        if (analysisWaitSeconds < 1) {
            analysisWaitSeconds = DEFAULT_ANALYSIS_WAIT_SECONDS;
        }
        if (maxFileBytes < MIN_MAX_FILE_BYTES) {
            maxFileBytes = MIN_MAX_FILE_BYTES;
        }
        if (rootPath != null && rootPath.isBlank()) {
            rootPath = null;
        }
    }

    /** Defaults: full cascade, no exclusions, band 20, throttle 10%, 32 KiB files. */
    public static TreeConfig defaults() {
        return new TreeConfig(
                null,
                List.of(),
                DEFAULT_BAND_SIZE,
                List.of(),
                List.of(),
                DEFAULT_THROTTLE_PERCENT,
                DEFAULT_DECOMPILE_TIMEOUT_SECONDS,
                DEFAULT_ANALYSIS_WAIT_SECONDS,
                DEFAULT_MAX_FILE_BYTES,
                true);
    }

    public static Builder builder() {
        return new Builder();
    }

    public TreeConfig withRootPath(String newRootPath) {
        return new TreeConfig(
                newRootPath, enabledStrategies, bandSize, exclusions, includeOnly,
                throttlePercent, decompileTimeoutSeconds, analysisWaitSeconds, maxFileBytes,
                disassembleMissing);
    }

    public TreeConfig withEnabledStrategies(List<String> strategies) {
        return new TreeConfig(
                rootPath, strategies, bandSize, exclusions, includeOnly,
                throttlePercent, decompileTimeoutSeconds, analysisWaitSeconds, maxFileBytes,
                disassembleMissing);
    }

    public TreeConfig withBandSize(int newBandSize) {
        return new TreeConfig(
                rootPath, enabledStrategies, newBandSize, exclusions, includeOnly,
                throttlePercent, decompileTimeoutSeconds, analysisWaitSeconds, maxFileBytes,
                disassembleMissing);
    }

    public TreeConfig withExclusions(List<ExclusionRule> rules) {
        return new TreeConfig(
                rootPath, enabledStrategies, bandSize, rules, includeOnly,
                throttlePercent, decompileTimeoutSeconds, analysisWaitSeconds, maxFileBytes,
                disassembleMissing);
    }

    public TreeConfig withIncludeOnly(List<ExclusionRule> rules) {
        return new TreeConfig(
                rootPath, enabledStrategies, bandSize, exclusions, rules,
                throttlePercent, decompileTimeoutSeconds, analysisWaitSeconds, maxFileBytes,
                disassembleMissing);
    }

    public TreeConfig withThrottlePercent(int percent) {
        return new TreeConfig(
                rootPath, enabledStrategies, bandSize, exclusions, includeOnly,
                percent, decompileTimeoutSeconds, analysisWaitSeconds, maxFileBytes,
                disassembleMissing);
    }

    public TreeConfig withMaxFileBytes(int bytes) {
        return new TreeConfig(
                rootPath, enabledStrategies, bandSize, exclusions, includeOnly,
                throttlePercent, decompileTimeoutSeconds, analysisWaitSeconds, bytes,
                disassembleMissing);
    }

    public TreeConfig withDisassembleMissing(boolean enabled) {
        return new TreeConfig(
                rootPath, enabledStrategies, bandSize, exclusions, includeOnly,
                throttlePercent, decompileTimeoutSeconds, analysisWaitSeconds, maxFileBytes,
                enabled);
    }

    public static final class Builder {
        private String rootPath;
        private List<String> enabledStrategies = List.of();
        private int bandSize = DEFAULT_BAND_SIZE;
        private List<ExclusionRule> exclusions = List.of();
        private List<ExclusionRule> includeOnly = List.of();
        private int throttlePercent = DEFAULT_THROTTLE_PERCENT;
        private int decompileTimeoutSeconds = DEFAULT_DECOMPILE_TIMEOUT_SECONDS;
        private int analysisWaitSeconds = DEFAULT_ANALYSIS_WAIT_SECONDS;
        private int maxFileBytes = DEFAULT_MAX_FILE_BYTES;
        private boolean disassembleMissing = true;

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
