package com.xebyte.core.vuln;

import com.xebyte.core.JsonHelper;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Result of one backward inter-procedural taint trace. {@code source} is the
 * catalog entry reached (null if none). {@code terminalReason} ∈
 * "source"|"tainted_load"|"load_unknown_provenance"|"budget"|"call_depth"|
 * "recursion"|"constant"|"decompile_failed"|"no_path".
 */
public record TaintResult(CatalogEntry source, List<TaintStep> path,
        String terminalReason, int functionsVisited, int callDepthReached) {

    private static final int PATH_JSON_CAP = 32;

    public Map<String, Object> toJson() {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("source", source == null ? null
            : JsonHelper.mapOf("id", source.id(), "class", source.vulnClass(),
                               "kind", source.kind()));
        List<Map<String,Object>> steps = new ArrayList<>();
        int n = Math.min(path.size(), PATH_JSON_CAP);
        for (int i = 0; i < n; i++) steps.add(path.get(i).toJson());
        out.put("path", steps);
        out.put("path_truncated", path.size() > PATH_JSON_CAP);
        out.put("terminal_reason", terminalReason);
        out.put("functions_visited", functionsVisited);
        out.put("call_depth_reached", callDepthReached);
        return out;
    }
}
