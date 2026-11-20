package com.xebyte.offline;

import com.xebyte.core.Response;
import com.xebyte.core.ServiceUtils;
import org.junit.Test;

import java.util.List;
import java.util.Map;

import static org.junit.Assert.*;

/** Offline coverage for {@link ServiceUtils#listed(String, List)}. */
public class ServiceUtilsListedTest {

    @Test
    public void listedIsNamedArrayPlusCount() {
        Response r = ServiceUtils.listed("items", List.of("a", "b"));
        assertTrue(r instanceof Response.Ok);
        @SuppressWarnings("unchecked")
        Map<String, Object> data = (Map<String, Object>) ((Response.Ok) r).data();
        assertEquals(List.of("a", "b"), data.get("items"));
        assertEquals(2, data.get("count"));
        assertEquals(2, data.size());
    }

    @Test
    public void listedEmpty() {
        Response r = ServiceUtils.listed("tools", List.of());
        @SuppressWarnings("unchecked")
        Map<String, Object> data = (Map<String, Object>) ((Response.Ok) r).data();
        assertEquals(List.of(), data.get("tools"));
        assertEquals(0, data.get("count"));
    }
}
