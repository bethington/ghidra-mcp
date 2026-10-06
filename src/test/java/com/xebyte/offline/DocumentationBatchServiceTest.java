package com.xebyte.offline;

import com.xebyte.core.AnalysisService;
import com.xebyte.core.CommentService;
import com.xebyte.core.DocumentationBatchService;
import com.xebyte.core.FunctionService;
import com.xebyte.core.Response;
import org.junit.Test;
import org.mockito.InOrder;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

/**
 * /batch_apply_documentation on both servers. It was a GUI hand route that judged each
 * step by searching the other tools' JSON text for "Success" and pulled counts out with
 * indexOf; it now reads their Responses, which is also what lets it run headless.
 */
public class DocumentationBatchServiceTest {

    private final FunctionService functions = mock(FunctionService.class);
    private final CommentService comments = mock(CommentService.class);
    private final AnalysisService analysis = mock(AnalysisService.class);
    private static final String PROGRAM = "/fw/a";

    private DocumentationBatchService service(java.util.function.Function<String, Response> navigator) {
        when(analysis.analyzeFunctionCompleteness(anyString(), anyBoolean(), any()))
            .thenReturn(Response.ok(Map.of("effective_score", 88)));
        return new DocumentationBatchService(functions, comments, analysis, navigator);
    }

    private Response apply(DocumentationBatchService s, String name, String prototype,
            Map<String, String> types, Map<String, String> renames, String plate,
            List<Map<String, String>> pre, boolean gotoFirst) {
        return s.batchApplyDocumentation("0x1000", gotoFirst, name, prototype, "", types, renames,
            plate, pre, List.of(), true, PROGRAM);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> ok(Response r) {
        assertTrue(r.toString(), r instanceof Response.Ok);
        return (Map<String, Object>) ((Response.Ok) r).data();
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> step(Map<String, Object> out, String name) {
        return (Map<String, Object>) ((Map<String, Object>) out.get("steps")).get(name);
    }

    @Test
    public void theAddressIsRequired() {
        Response r = service(null).batchApplyDocumentation("  ", false, "", "", "", null, null, "", null, null, true, "");
        assertEquals("address parameter is required", ((Response.Err) r).message());
    }

    @Test
    public void theStepsRunInOrderAndThePrototypeComesBeforeTheComments() {
        when(functions.renameFunctionByAddress("0x1000", "Decode", PROGRAM)).thenReturn(Response.ok(Map.of("status", "success")));
        when(functions.setFunctionPrototype(eq("0x1000"), anyString(), any(), eq(PROGRAM)))
            .thenReturn(new FunctionService.PrototypeResult(true, null));
        when(comments.batchSetComments(anyString(), any(), any(), any(), eq(PROGRAM)))
            .thenReturn(Response.ok(Map.of("success", true, "plate_comment_set", true,
                "decompiler_comments_set", 1, "disassembly_comments_set", 0)));

        Map<String, Object> out = ok(apply(service(null), "Decode", "int Decode(void)", null, null,
            "plate", List.of(Map.of("address", "0x1004", "comment", "c")), false));

        InOrder order = inOrder(functions, comments, analysis);
        order.verify(functions).renameFunctionByAddress("0x1000", "Decode", PROGRAM);
        order.verify(functions).setFunctionPrototype(eq("0x1000"), eq("int Decode(void)"), any(), eq(PROGRAM));
        // setting a prototype wipes the plate comment, so comments must come after it
        order.verify(comments).batchSetComments(eq("0x1000"), any(), any(), eq("plate"), eq(PROGRAM));
        order.verify(analysis).analyzeFunctionCompleteness("0x1000", true, PROGRAM);
        assertEquals(List.of(), out.get("errors"));
        assertEquals(Map.of("effective_score", 88), out.get("completeness"));
        Map<String, Object> commentStep = step(out, "comments");
        assertEquals(true, commentStep.get("success"));
        assertEquals(true, commentStep.get("plate"));
        assertEquals("counts come from the tool's own result, as integers", 1, commentStep.get("decompiler"));
    }

    @Test
    public void aFailedStepIsReportedAndDoesNotStopTheOthers() {
        when(functions.renameFunctionByAddress(anyString(), anyString(), any()))
            .thenReturn(Response.ok(Map.of("status", "rejected", "message", "name too short")));
        when(comments.batchSetComments(anyString(), any(), any(), any(), any()))
            .thenReturn(Response.ok(Map.of("success", true)));

        Map<String, Object> out = ok(apply(service(null), "x", "", null, null, "plate", List.of(), false));

        assertEquals(false, step(out, "rename").get("success"));
        assertEquals("name too short", step(out, "rename").get("error"));
        assertEquals("the comment step still ran", true, step(out, "comments").get("success"));
        assertEquals(List.of("rename: name too short"), out.get("errors"));
    }

    @Test
    public void anErrResponseAndAnOkThatSaysItFailedAreBothFailures() {
        assertEquals("boom", failure(Response.err("boom")));
        assertEquals("nope", failure(Response.ok(Map.of("error", "nope"))));
        assertEquals("why", failure(Response.ok(Map.of("success", false, "message", "why"))));
        assertEquals("failed", failure(Response.ok(Map.of("success", false))));
        assertNull(failure(Response.ok(Map.of("success", true))));
        assertNull(failure(Response.ok(Map.of("status", "success"))));
        assertNull("a plain payload with no verdict is a success", failure(Response.ok(Map.of("x", 1))));
    }

    private static String failure(Response r) {
        // Through the public surface: a rename returning r, in a batch that only renames.
        FunctionService f = mock(FunctionService.class);
        when(f.renameFunctionByAddress(anyString(), anyString(), any())).thenReturn(r);
        AnalysisService a = mock(AnalysisService.class);
        DocumentationBatchService s = new DocumentationBatchService(f, mock(CommentService.class), a, null);
        Map<String, Object> out = ok(s.batchApplyDocumentation("0x1", false, "n", "", "", null, null, "",
            null, null, false, ""));
        return (String) step(out, "rename").get("error");
    }

    @Test
    public void variableTypesAreAppliedIndividuallyAndCounted() {
        when(functions.setLocalVariableType("0x1000", "a", "int", PROGRAM)).thenReturn(Response.ok(Map.of("status", "success")));
        when(functions.setLocalVariableType("0x1000", "b", "nosuch", PROGRAM)).thenReturn(Response.err("type not found"));

        Map<String, String> types = new LinkedHashMap<>();
        types.put("a", "int");
        types.put("b", "nosuch");
        Map<String, Object> out = ok(apply(service(null), "", "", types, null, "", List.of(), false));

        Map<String, Object> entry = step(out, "variable_types");
        assertEquals(false, entry.get("success"));
        assertEquals(1, entry.get("set"));
        assertEquals(1, entry.get("failed"));
        assertEquals(List.of("b: type not found"), entry.get("errors"));
    }

    @Test
    public void variableRenamesLiftTheirCountsFromTheToolsResult() {
        when(functions.batchRenameVariables("0x1000", Map.of("a", "b"), true, PROGRAM))
            .thenReturn(Response.ok(Map.of("success", true, "variables_renamed", 1, "variables_failed", 0)));
        Map<String, Object> out = ok(apply(service(null), "", "", null, Map.of("a", "b"), "", List.of(), false));
        Map<String, Object> entry = step(out, "variable_renames");
        assertEquals(true, entry.get("success"));
        assertEquals(1, entry.get("renamed"));
        assertEquals(0, entry.get("failed"));
    }

    @Test
    public void gotoNeedsAWindowAndSaysSoWhenThereIsNone() {
        Map<String, Object> out = ok(apply(service(null), "", "", null, null, "", List.of(), true));
        assertEquals(false, step(out, "goto").get("success"));
        assertTrue(String.valueOf(step(out, "goto").get("error")).contains("window"));
        assertEquals(1, ((List<?>) out.get("errors")).size());
    }

    @Test
    public void gotoUsesTheNavigatorWhenThereIsOne() {
        Map<String, Object> out = ok(apply(service(a -> Response.ok(Map.of("success", true))), "", "", null, null,
            "", List.of(), true));
        assertEquals(true, step(out, "goto").get("success"));
        assertEquals(List.of(), out.get("errors"));
    }

    @Test
    public void stepsNobodyAskedForAreAbsent() {
        Map<String, Object> out = ok(apply(service(null), "", "", null, null, "", List.of(), false));
        assertEquals(Map.of(), out.get("steps"));
        verifyNoInteractions(comments);
        verify(functions, never()).renameFunctionByAddress(anyString(), anyString(), any());
    }

    /** Without the program on every step a headless server, which has no current one, could not run any. */
    @Test
    public void everyStepRunsAgainstTheNamedProgram() {
        when(functions.renameFunctionByAddress(anyString(), anyString(), any())).thenReturn(Response.ok(Map.of()));
        when(functions.setFunctionPrototype(anyString(), anyString(), any(), any()))
            .thenReturn(new FunctionService.PrototypeResult(true, null));
        when(functions.setLocalVariableType(anyString(), anyString(), anyString(), any())).thenReturn(Response.ok(Map.of()));
        when(functions.batchRenameVariables(anyString(), any(), anyBoolean(), any())).thenReturn(Response.ok(Map.of()));
        when(comments.batchSetComments(anyString(), any(), any(), any(), any())).thenReturn(Response.ok(Map.of()));

        apply(service(null), "N", "int N(void)", Map.of("v", "int"), Map.of("a", "b"), "plate", List.of(), false);

        verify(functions).renameFunctionByAddress(anyString(), anyString(), eq(PROGRAM));
        verify(functions).setFunctionPrototype(anyString(), anyString(), any(), eq(PROGRAM));
        verify(functions).setLocalVariableType(anyString(), anyString(), anyString(), eq(PROGRAM));
        verify(functions).batchRenameVariables(anyString(), any(), anyBoolean(), eq(PROGRAM));
        verify(comments).batchSetComments(anyString(), any(), any(), any(), eq(PROGRAM));
        verify(analysis).analyzeFunctionCompleteness(anyString(), anyBoolean(), eq(PROGRAM));
    }
}
