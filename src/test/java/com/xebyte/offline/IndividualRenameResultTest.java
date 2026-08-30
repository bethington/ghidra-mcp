package com.xebyte.offline;

import com.xebyte.core.FunctionService;
import com.xebyte.core.Response;
import junit.framework.TestCase;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The individual variable-rename path must count what actually happened.
 *
 * <p>{@code batchRenameVariablesIndividual} decided whether a rename had
 * succeeded by comparing {@code renameVariableInFunction(...).toJson()} against
 * the bare string {@code "Variable renamed"}. That comparison was written when
 * the method returned raw text. It has never matched since the response
 * contract moved to structured envelopes: the method returns
 * {@code Response.success("Variable renamed")}, and its {@code toJson()} is
 * {@code {"status":"success","message":"Variable renamed"}}.
 *
 * <p>So every successful rename was counted as a failure, its success payload
 * was filed in {@code errors}, {@code variables_renamed} was always 0 -- and
 * {@code success} was hardcoded {@code true} on top, so the response
 * simultaneously claimed the operation worked and that every variable in it had
 * failed. This mattered more once {@code force_individual} was wired up, since
 * that flag routes callers here deliberately rather than only on a fallback.
 *
 * <p>These tests pin the discrimination itself, so a future refactor cannot
 * quietly reintroduce a string comparison against a serialized response.
 */
public class IndividualRenameResultTest extends TestCase {

    /**
     * The exact shape {@code renameVariableInFunction} returns on a plain
     * success.
     *
     * @return the success response
     */
    private static Response plainSuccess() {
        return Response.success("Variable renamed");
    }

    /**
     * The shape it returns when the new name trips Hungarian-notation
     * validation but the rename still happened.
     *
     * @return the success-with-warnings response
     */
    private static Response successWithWarning() {
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("status", "success");
        data.put("message", "Variable renamed");
        data.put("warnings", List.of("expected prefix 'dw' for type uint"));
        return Response.ok(data);
    }

    /**
     * The historical comparison is documented here as a fact, not a guess: it
     * cannot match, which is why the counting was wrong.
     */
    public void testSerializedSuccessNeverEqualsTheBareMessage() {
        assertFalse(
            "If this ever became true, the old string comparison would have worked and this "
                + "whole class of bug would not exist. It is false because Response.success wraps "
                + "the message in a status envelope.",
            plainSuccess().toJson().equals("Variable renamed"));

        assertTrue(
            "Response.success must serialize as a status envelope",
            plainSuccess().toJson().contains("\"status\""));
    }

    /** Both success shapes must be recognised as successes. */
    public void testBothSuccessShapesAreCountedAsSuccess() {
        assertTrue("plain Response.success must count as a completed rename",
            FunctionService.isVariableRenameSuccess(plainSuccess()));
        assertTrue("a rename that emitted a Hungarian warning still renamed the variable",
            FunctionService.isVariableRenameSuccess(successWithWarning()));
    }

    /** Failures, and anything unrecognised, must not be counted as successes. */
    public void testFailuresAreNotCountedAsSuccess() {
        assertFalse("an error response is not a rename",
            FunctionService.isVariableRenameSuccess(Response.err("Variable not found: local_8")));
        assertFalse("a non-success status is not a rename",
            FunctionService.isVariableRenameSuccess(
                Response.ok(Map.of("status", "skipped", "message", "Variable renamed"))));
        assertFalse("a payload that is not a map cannot be interpreted as a rename",
            FunctionService.isVariableRenameSuccess(Response.ok("Variable renamed")));
        assertFalse("null must not throw or count as success",
            FunctionService.isVariableRenameSuccess(null));
    }

    /**
     * Warnings must survive the batch, prefixed with the variable they belong
     * to. Dropping them loses the naming-convention feedback that is the point
     * of the validation layer.
     */
    public void testWarningsAreCollectedAndAttributed() {
        List<String> sink = new ArrayList<>();
        FunctionService.collectRenameWarnings(successWithWarning(), "local_8", sink);

        assertEquals("one warning expected", 1, sink.size());
        assertTrue("the warning must name the variable it came from: " + sink.get(0),
            sink.get(0).startsWith("local_8: "));
        assertTrue("the warning text must be preserved: " + sink.get(0),
            sink.get(0).contains("expected prefix 'dw'"));
    }

    /** Responses with no warnings must contribute nothing. */
    public void testNoWarningsCollectedFromPlainResponses() {
        List<String> sink = new ArrayList<>();
        FunctionService.collectRenameWarnings(plainSuccess(), "local_8", sink);
        FunctionService.collectRenameWarnings(Response.err("nope"), "local_c", sink);
        FunctionService.collectRenameWarnings(null, "local_10", sink);

        assertTrue("nothing to collect, so the sink stays empty: " + sink, sink.isEmpty());
    }
}
