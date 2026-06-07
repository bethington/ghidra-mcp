package com.xebyte.offline;

import com.xebyte.core.CommentService;
import com.xebyte.core.Response;
import com.xebyte.core.ThreadingStrategy;
import junit.framework.TestCase;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Graceful-degradation coverage for CommentService (previously no behavioral tests).
 * With no program loaded the comment tools must return a clean "No program loaded" error
 * instead of throwing.
 */
public class CommentServiceValidationTest extends TestCase {

    private CommentService comments;

    @Override
    protected void setUp() {
        ThreadingStrategy ts = new NoopThreadingStrategy();
        comments = new CommentService(ServiceFactory.stubProvider(), ts);
    }

    private static void assertNoProgram(Response r) {
        assertNotNull("method returned null instead of an error Response", r);
        assertTrue("expected a graceful 'No program loaded' error, got: " + r.toJson(),
                r.toJson().contains("No program loaded"));
    }

    public void testSetDecompilerCommentDegradesGracefully() {
        assertNoProgram(comments.setDecompilerComment("0x401000", "note"));
    }

    public void testSetDisassemblyCommentDegradesGracefully() {
        assertNoProgram(comments.setDisassemblyComment("0x401000", "note"));
    }

    public void testSetPlateCommentDegradesGracefully() {
        assertNoProgram(comments.setPlateComment("0x401000", "Summary of this function's behavior"));
    }

    public void testClearFunctionCommentsDegradesGracefully() {
        assertNoProgram(comments.clearFunctionComments("0x401000", true, true, true));
    }

    public void testBatchSetCommentsDegradesGracefully() {
        List<Map<String, String>> decompiler = new ArrayList<>();
        List<Map<String, String>> disassembly = new ArrayList<>();
        assertNoProgram(comments.batchSetComments("0x401000", decompiler, disassembly, null, ""));
    }

    public void testGetPlateCommentDegradesGracefully() {
        assertNoProgram(comments.getPlateComment("0x401000", ""));
    }
}
