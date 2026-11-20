package com.xebyte.offline;

import com.xebyte.core.Response;
import com.xebyte.core.ServiceUtils;
import org.junit.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.*;

/** Offline coverage for {@link ServiceUtils#paged} and {@link ServiceUtils#pagedWindow}. */
public class ServiceUtilsPagedTest {

    @Test
    public void pagedSlicesAndReportsTotal() {
        Response r = ServiceUtils.paged("tags", List.of("a", "b", "c"), 1, 1);
        @SuppressWarnings("unchecked")
        Map<String, Object> data = (Map<String, Object>) ((Response.Ok) r).data();
        assertEquals(List.of("b"), data.get("tags"));
        assertEquals(1, data.get("count"));
        assertEquals(1, data.get("offset"));
        assertEquals(1, data.get("limit"));
        assertEquals(3, data.get("total"));
    }

    @Test
    public void pagedClampsNegativeOffset() {
        Response r = ServiceUtils.paged("items", List.of("a", "b"), -3, 10);
        @SuppressWarnings("unchecked")
        Map<String, Object> data = (Map<String, Object>) ((Response.Ok) r).data();
        assertEquals(0, data.get("offset"));
        assertEquals(List.of("a", "b"), data.get("items"));
        assertEquals(2, data.get("count"));
    }

    @Test
    public void pagedNonPositiveLimitMeansNoLimitAndOmitsLimitKey() {
        Response r = ServiceUtils.paged("gaps", List.of("x", "y"), 0, 0);
        @SuppressWarnings("unchecked")
        Map<String, Object> data = (Map<String, Object>) ((Response.Ok) r).data();
        assertEquals(List.of("x", "y"), data.get("gaps"));
        assertEquals(2, data.get("count"));
        assertEquals(2, data.get("total"));
        assertFalse("unbounded pages omit limit", data.containsKey("limit"));

        Response neg = ServiceUtils.paged("gaps", List.of("x"), 0, -1);
        @SuppressWarnings("unchecked")
        Map<String, Object> negData = (Map<String, Object>) ((Response.Ok) neg).data();
        assertEquals(List.of("x"), negData.get("gaps"));
        assertFalse(negData.containsKey("limit"));
    }

    @Test
    public void pagedExtrasMergeAfterStandardKeys() {
        Map<String, Object> extras = new LinkedHashMap<>();
        extras.put("class_name", "CWindow");
        extras.put("class_namespace_exists", true);
        Response r = ServiceUtils.paged("members", List.of("m"), 0, 50, extras);
        @SuppressWarnings("unchecked")
        Map<String, Object> data = (Map<String, Object>) ((Response.Ok) r).data();
        assertEquals(List.of("m"), data.get("members"));
        assertEquals(1, data.get("count"));
        assertEquals(1, data.get("total"));
        assertEquals("CWindow", data.get("class_name"));
        assertEquals(true, data.get("class_namespace_exists"));
        assertEquals(List.of("members", "count", "offset", "limit", "total",
                "class_name", "class_namespace_exists"),
                List.copyOf(data.keySet()));
    }

    @Test
    public void pagedWindowUsesCallerTotalWithoutReSlicing() {
        Map<String, Object> extras = new LinkedHashMap<>();
        extras.put("map", "m");
        extras.put("value_type", "string");
        Response r = ServiceUtils.pagedWindow("entries", List.of("second"), 1, 1, 3, extras);
        @SuppressWarnings("unchecked")
        Map<String, Object> data = (Map<String, Object>) ((Response.Ok) r).data();
        assertEquals(List.of("second"), data.get("entries"));
        assertEquals(1, data.get("count"));
        assertEquals(1, data.get("offset"));
        assertEquals(1, data.get("limit"));
        assertEquals(3, data.get("total"));
        assertEquals("m", data.get("map"));
        assertEquals("string", data.get("value_type"));
    }

    @Test
    public void pagedWindowUnboundedOmitsLimit() {
        Response r = ServiceUtils.pagedWindow("entries", List.of("a", "b"), 0, 0, 2, null);
        @SuppressWarnings("unchecked")
        Map<String, Object> data = (Map<String, Object>) ((Response.Ok) r).data();
        assertEquals(2, data.get("count"));
        assertFalse(data.containsKey("limit"));
    }
}
