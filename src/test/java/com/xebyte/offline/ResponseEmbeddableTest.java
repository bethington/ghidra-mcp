package com.xebyte.offline;

import com.xebyte.core.JsonHelper;
import com.xebyte.core.Response;
import org.junit.Test;

import java.util.Map;

import static org.junit.Assert.assertEquals;

/**
 * A response nested inside another payload keeps its types. The exit routes embedded
 * the save result by re-parsing its JSON, and reported "saved_count": 4.0.
 */
public class ResponseEmbeddableTest {

    @Test
    public void okDataIsEmbeddedAsIsSoCountsStayIntegers() {
        Object nested = Response.ok(JsonHelper.mapOf("saved_count", 4)).asEmbeddable();
        assertEquals("{\"save\":{\"saved_count\":4}}", JsonHelper.toJson(Map.of("save", nested)));
    }

    @Test
    public void errBecomesAnErrorObject() {
        assertEquals(Map.of("error", "boom"), Response.err("boom").asEmbeddable());
    }
}
