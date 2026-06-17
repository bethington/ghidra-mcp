package com.xebyte.core.vuln;

import com.xebyte.core.JsonHelper;
import java.util.List;
import java.util.Map;

/**
 * One vulnerability-candidate result. Immutable.
 * {@code confidence} is one of "high" | "medium" | "low" (lowercase).
 * Detectors must use these exact literals — see VulnDetector implementations.
 */
public record Finding(
        String detectorId,
        String vulnClass,
        String address,
        String function,
        String sink,
        String confidence,
        List<String> evidence,
        String why) {

    public Map<String, Object> toJson() {
        return JsonHelper.mapOf(
            "detector_id", detectorId,
            "vuln_class",  vulnClass,
            "address",     address,
            "function",    function,
            "sink",        sink,
            "confidence",  confidence,
            "evidence",    evidence,
            "why",         why
        );
    }
}
