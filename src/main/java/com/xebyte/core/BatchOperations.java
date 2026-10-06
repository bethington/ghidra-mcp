package com.xebyte.core;

import ghidra.program.model.listing.Program;
import java.util.*;

final class BatchOperations {
    private BatchOperations() {}
    @FunctionalInterface interface Operation { Response apply(Map<String, String> item) throws Exception; }

    static Response run(Program program, ThreadingStrategy threading, String name,
                        List<Map<String, String>> items, Operation operation) {
        if (items == null || items.isEmpty() || items.size() > 1000)
            return Response.err("Batch must contain 1 to 1000 items");
        try {
            return threading.executeWrite(program, name, () -> {
                List<Object> results = new ArrayList<>();
                for (int index = 0; index < items.size(); index++) {
                    if (items.get(index) == null) throw new IllegalArgumentException("Item " + index + " must be an object");
                    Response response = operation.apply(items.get(index));
                    if (response instanceof Response.Err error)
                        throw new IllegalArgumentException("Item " + index + ": " + error.message());
                    if (response instanceof Response.Ok ok) {
                        if (ok.data() instanceof Map<?, ?> data
                                && (data.containsKey("error") || "rejected".equals(data.get("status")) || Boolean.FALSE.equals(data.get("success"))))
                            throw new IllegalArgumentException("Item " + index + ": " + response.toJson());
                        results.add(ok.data());
                    } else throw new IllegalArgumentException("Unexpected batch response at item " + index);
                }
                return Response.ok(JsonHelper.mapOf("status", "success", "count", results.size(), "results", results));
            });
        } catch (Exception e) { return Response.err(e.getMessage()); }
    }
}
