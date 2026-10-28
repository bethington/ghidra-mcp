package com.xebyte.offline;

import com.xebyte.core.Response;
import org.junit.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.*;

/** Offline coverage for {@link Response#success(String, Map)} / {@link Response#successWithWarnings}. */
public class ResponseSuccessExtrasTest {

    @Test
    public void plainSuccessIsStatusAndMessageOnly() {
        String json = Response.success("done").toJson();
        assertEquals("{\"status\":\"success\",\"message\":\"done\"}", json);
    }

    @Test
    public void extrasFollowStatusAndMessage() {
        Map<String, Object> extras = new LinkedHashMap<>();
        extras.put("name", "Foo");
        extras.put("size", 4);
        String json = Response.success("created", extras).toJson();
        assertEquals("{\"status\":\"success\",\"message\":\"created\",\"name\":\"Foo\",\"size\":4}", json);
    }

    @Test
    public void extrasCannotOverrideStatusOrMessage() {
        Map<String, Object> extras = new LinkedHashMap<>();
        extras.put("status", "nope");
        extras.put("message", "ignored");
        extras.put("ok", true);
        String json = Response.success("real", extras).toJson();
        assertEquals("{\"status\":\"success\",\"message\":\"real\",\"ok\":true}", json);
    }

    @Test
    public void warningsKeyOnlyWhenNonEmpty() {
        assertEquals("{\"status\":\"success\",\"message\":\"ok\"}",
                Response.successWithWarnings("ok", List.of()).toJson());
        assertEquals("{\"status\":\"success\",\"message\":\"ok\"}",
                Response.successWithWarnings("ok", null).toJson());
        assertEquals("{\"status\":\"success\",\"message\":\"ok\",\"warnings\":[\"a\"]}",
                Response.successWithWarnings("ok", List.of("a")).toJson());
    }
}
