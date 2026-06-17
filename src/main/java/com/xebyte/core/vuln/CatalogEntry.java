package com.xebyte.core.vuln;

import java.util.List;
import java.util.Map;

/**
 * One row from vuln_catalog.json. {@code kind} is "sink" or "source".
 * {@code argRoles} maps role name → 0-based call-arg index ("fmt_arg", "size_arg",
 * "dst_arg", "cmd_arg", "out_arg"); a missing role means not applicable.
 * {@code returnIsOutput} marks sources whose output is the return value (e.g. getenv).
 */
public record CatalogEntry(
        String id,
        String kind,
        String vulnClass,
        Map<String, Integer> argRoles,
        boolean returnIsOutput,
        List<String> matchImport,
        List<String> matchRegex,
        List<String> matchTag) {

    public Integer arg(String role) { return argRoles.get(role); }
}
