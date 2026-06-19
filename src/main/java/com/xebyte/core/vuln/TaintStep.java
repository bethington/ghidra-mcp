package com.xebyte.core.vuln;

import com.xebyte.core.JsonHelper;
import java.util.Map;

/** One backward step in a taint path. {@code kind} ∈ "op"|"call_return"|"param"|"load"|"source". */
public record TaintStep(String function, String address, String kind, String detail) {
    public Map<String, Object> toJson() {
        return JsonHelper.mapOf("function", function, "address", address,
                                "kind", kind, "detail", detail);
    }
}
