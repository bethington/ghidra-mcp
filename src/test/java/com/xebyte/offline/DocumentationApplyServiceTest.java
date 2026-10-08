package com.xebyte.offline;

import com.xebyte.core.AnalysisService;
import com.xebyte.core.CommentService;
import com.xebyte.core.DocumentationApplyService;
import com.xebyte.core.FunctionService;
import com.xebyte.core.ProgramProvider;
import com.xebyte.core.Response;
import com.xebyte.core.SymbolLabelService;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.DefaultAddressFactory;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import org.junit.Before;
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
 * /apply_documentation on both servers: one function or many, from typed fields or from a
 * get_function_documentation export. It judges each step by the other tools' {@link
 * Response}s, which is also what lets it run headless.
 */
public class DocumentationApplyServiceTest {

    private static final String PROGRAM = "/fw/a";

    private final FunctionService functions = mock(FunctionService.class);
    private final CommentService comments = mock(CommentService.class);
    private final SymbolLabelService symbols = mock(SymbolLabelService.class);
    private final AnalysisService analysis = mock(AnalysisService.class);

    private final AddressSpace ram = new GenericAddressSpace("ram", 32, AddressSpace.TYPE_RAM, 0);
    private final AddressFactory factory = new DefaultAddressFactory(new AddressSpace[] {ram}, ram);
    private final Program program = mock(Program.class);
    private final FunctionManager functionManager = mock(FunctionManager.class);
    private final SymbolTable symbolTable = mock(SymbolTable.class);
    private final ProgramProvider provider = mock(ProgramProvider.class);
    private Function function;
    private Parameter first;

    @Before
    public void fixture() {
        when(provider.getProgram(PROGRAM)).thenReturn(program);
        when(program.getName()).thenReturn("a");
        when(program.getAddressFactory()).thenReturn(factory);
        when(program.getFunctionManager()).thenReturn(functionManager);
        when(program.getSymbolTable()).thenReturn(symbolTable);
        when(symbolTable.getSymbols(any(Address.class))).thenReturn(new Symbol[0]);
        // A name lookup that finds nothing: no symbol and no function by that name.
        SymbolIterator noSymbols = mock(SymbolIterator.class);
        when(symbolTable.getSymbols(anyString())).thenReturn(noSymbols);
        FunctionIterator noFunctions = mock(FunctionIterator.class);
        when(noFunctions.iterator()).thenReturn(noFunctions);
        when(functionManager.getFunctions(anyBoolean())).thenReturn(noFunctions);
        function = function("f", 0x1000, "param_1");
        when(analysis.analyzeFunctionCompleteness(anyString(), anyBoolean(), any()))
            .thenReturn(Response.ok(Map.of("effective_score", 88)));
        okEverything();
    }

    private Function function(String name, long entry, String paramName) {
        Function f = mock(Function.class);
        Address at = ram.getAddress(entry);
        when(f.getName()).thenReturn(name);
        when(f.getEntryPoint()).thenReturn(at);
        Parameter p = mock(Parameter.class);
        when(p.getName()).thenReturn(paramName);
        when(f.getParameters()).thenReturn(new Parameter[] {p});
        when(functionManager.getFunctionAt(at)).thenReturn(f);
        first = p;
        return f;
    }

    private void okEverything() {
        when(functions.renameFunctionByAddress(anyString(), anyString(), any())).thenReturn(Response.ok(Map.of()));
        when(functions.setFunctionPrototype(anyString(), anyString(), any(), any()))
            .thenReturn(new FunctionService.PrototypeResult(true, null));
        when(functions.setLocalVariableType(anyString(), anyString(), anyString(), any()))
            .thenReturn(Response.ok(Map.of()));
        when(functions.batchRenameVariables(anyString(), any(), anyBoolean(), any())).thenReturn(Response.ok(Map.of()));
        when(comments.batchSetComments(anyString(), any(), any(), any(), any())).thenReturn(Response.ok(Map.of()));
        when(symbols.batchCreateLabels(any(), any())).thenReturn(Response.ok(Map.of()));
    }

    private DocumentationApplyService service(java.util.function.Function<String, Response> navigator) {
        return new DocumentationApplyService(provider, functions, comments, symbols, analysis, navigator);
    }

    /** Single mode: the same call the tool receives, with every field a caller may leave out left out. */
    private Response applyOne(DocumentationApplyService s, Map<String, Object> fields, Boolean score) {
        return s.applyDocumentation(
            (String) fields.getOrDefault("address", "0x1000"), null,
            Boolean.TRUE.equals(fields.get("goto")),
            (String) fields.get("name"), (String) fields.get("prototype"),
            (String) fields.get("calling_convention"), (String) fields.get("return_type"),
            list(fields.get("parameters")), stringMap(fields.get("variable_types")),
            stringMap(fields.get("variable_renames")), (String) fields.get("plate_comment"),
            list(fields.get("comments")), list(fields.get("labels")),
            (String) fields.get("tags"), stringMap(fields.get("tag_comments")), score, PROGRAM);
    }

    private Response applyMany(List<Map<String, Object>> entries, Boolean score) {
        return service(null).applyDocumentation("", entries, false, null, null, null, null, null, null, null,
            null, null, null, null, null, score, PROGRAM);
    }

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> list(Object o) {
        return o == null ? null : (List<Map<String, Object>>) o;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, String> stringMap(Object o) {
        return o == null ? null : (Map<String, String>) o;
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

    // ---------------------------------------------------------------- one function

    @Test
    public void theAddressIsRequired() {
        Response r = service(null).applyDocumentation("  ", null, false, null, null, null, null, null, null,
            null, null, null, null, null, null, null, PROGRAM);
        assertTrue(((Response.Err) r).message().contains("address parameter is required"));
    }

    @Test
    public void aFunctionThatIsNotThereIsReportedAndNothingRuns() {
        Map<String, Object> out = ok(applyOne(service(null), Map.of("address", "0x9999", "name", "x"), false));
        assertEquals(1, ((List<?>) out.get("errors")).size());
        assertEquals(Map.of(), out.get("steps"));
        verifyNoInteractions(comments);
        verify(functions, never()).renameFunctionByAddress(anyString(), anyString(), any());
    }

    @Test
    public void theStepsRunInOrderAndTheSignatureComesBeforeTheComments() {
        when(comments.batchSetComments(anyString(), any(), any(), any(), eq(PROGRAM)))
            .thenReturn(Response.ok(Map.of("success", true, "plate_comment_set", true,
                "decompiler_comments_set", 1, "disassembly_comments_set", 0)));

        Map<String, Object> out = ok(applyOne(service(null), Map.of(
            "name", "Decode", "prototype", "int Decode(void)", "plate_comment", "plate",
            "comments", List.of(Map.of("address", "0x1004", "pre_comment", "c"))), null));

        InOrder order = inOrder(functions, comments, analysis);
        order.verify(functions).renameFunctionByAddress("0x1000", "Decode", PROGRAM);
        order.verify(functions).setFunctionPrototype(eq("0x1000"), eq("int Decode(void)"), any(), eq(PROGRAM));
        // setting a prototype wipes the plate comment, so comments must come after it
        order.verify(comments).batchSetComments(eq("0x1000"), any(), any(), eq("plate"), eq(PROGRAM));
        order.verify(analysis).analyzeFunctionCompleteness("0x1000", true, PROGRAM);
        assertEquals(List.of(), out.get("errors"));
        assertEquals("a", out.get("program"));
        assertEquals(Map.of("effective_score", 88), out.get("completeness"));
        Map<String, Object> commentStep = step(out, "comments");
        assertEquals(true, commentStep.get("plate"));
        assertEquals("counts come from the tool's own result, as integers", 1, commentStep.get("pre"));
    }

    @Test
    public void aFailedStepIsReportedAndDoesNotStopTheOthers() {
        when(functions.renameFunctionByAddress(anyString(), anyString(), any()))
            .thenReturn(Response.ok(Map.of("status", "rejected", "message", "name too short")));

        Map<String, Object> out = ok(applyOne(service(null), Map.of("name", "x", "plate_comment", "p"), false));

        assertEquals(false, step(out, "rename").get("success"));
        assertEquals("name too short", step(out, "rename").get("error"));
        assertEquals("the comment step still ran", true, step(out, "comments").get("success"));
        assertEquals(List.of("rename: name too short"), out.get("errors"));
    }

    @Test
    public void anErrResponseAndAnOkThatSaysItFailedAreBothFailures() {
        assertEquals("boom", renameFailure(Response.err("boom")));
        assertEquals("nope", renameFailure(Response.ok(Map.of("error", "nope"))));
        assertEquals("why", renameFailure(Response.ok(Map.of("success", false, "message", "why"))));
        assertEquals("failed", renameFailure(Response.ok(Map.of("success", false))));
        assertNull(renameFailure(Response.ok(Map.of("success", true))));
        assertNull(renameFailure(Response.ok(Map.of("status", "success"))));
        assertNull("a plain payload with no verdict is a success", renameFailure(Response.ok(Map.of("x", 1))));
    }

    private String renameFailure(Response r) {
        when(functions.renameFunctionByAddress(anyString(), anyString(), any())).thenReturn(r);
        Map<String, Object> out = ok(applyOne(service(null), Map.of("name", "n"), false));
        return (String) step(out, "rename").get("error");
    }

    @Test
    public void variableTypesAreAppliedIndividuallyAndCounted() {
        when(functions.setLocalVariableType("0x1000", "a", "int", PROGRAM)).thenReturn(Response.ok(Map.of("status", "success")));
        when(functions.setLocalVariableType("0x1000", "b", "nosuch", PROGRAM)).thenReturn(Response.err("type not found"));

        Map<String, String> types = new LinkedHashMap<>();
        types.put("a", "int");
        types.put("b", "nosuch");
        Map<String, Object> out = ok(applyOne(service(null), Map.of("variable_types", types), false));

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
        Map<String, Object> out = ok(applyOne(service(null), Map.of("variable_renames", Map.of("a", "b")), false));
        Map<String, Object> entry = step(out, "variable_renames");
        assertEquals(true, entry.get("success"));
        assertEquals(1, entry.get("renamed"));
        assertEquals(0, entry.get("failed"));
    }

    @Test
    public void gotoNeedsAWindowAndSaysSoWhenThereIsNone() {
        Map<String, Object> out = ok(applyOne(service(null), Map.of("goto", true), false));
        assertEquals(false, step(out, "goto").get("success"));
        assertTrue(String.valueOf(step(out, "goto").get("error")).contains("window"));
        assertEquals(1, ((List<?>) out.get("errors")).size());
    }

    @Test
    public void gotoUsesTheNavigatorWhenThereIsOne() {
        Map<String, Object> out = ok(applyOne(service(a -> Response.ok(Map.of("success", true))),
            Map.of("goto", true), false));
        assertEquals(true, step(out, "goto").get("success"));
        assertEquals(List.of(), out.get("errors"));
    }

    @Test
    public void stepsNobodyAskedForAreAbsent() {
        Map<String, Object> out = ok(applyOne(service(null), Map.of(), false));
        assertEquals(Map.of(), out.get("steps"));
        verifyNoInteractions(comments, symbols);
        verify(functions, never()).renameFunctionByAddress(anyString(), anyString(), any());
    }

    /** Without the program on every step a headless server, which has no current one, could not run any. */
    @Test
    public void everyStepRunsAgainstTheNamedProgram() {
        applyOne(service(null), Map.of("name", "N", "prototype", "int N(void)",
            "variable_types", Map.of("v", "int"), "variable_renames", Map.of("a", "b"),
            "plate_comment", "plate", "labels", List.of(Map.of("address", "0x1008", "name", "loop_top"))), true);

        verify(functions).renameFunctionByAddress(anyString(), anyString(), eq(PROGRAM));
        verify(functions).setFunctionPrototype(anyString(), anyString(), any(), eq(PROGRAM));
        verify(functions).setLocalVariableType(anyString(), anyString(), anyString(), eq(PROGRAM));
        verify(functions).batchRenameVariables(anyString(), any(), anyBoolean(), eq(PROGRAM));
        verify(comments).batchSetComments(anyString(), any(), any(), any(), eq(PROGRAM));
        verify(symbols).batchCreateLabels(any(), eq(PROGRAM));
        verify(analysis).analyzeFunctionCompleteness(anyString(), anyBoolean(), eq(PROGRAM));
    }

    @Test
    public void aPrototypeAndAReturnTypeAreExclusive() {
        Map<String, Object> out = ok(applyOne(service(null),
            Map.of("prototype", "int f(void)", "return_type", "int"), false));
        assertEquals(List.of("signature: give prototype or return_type, not both"), out.get("errors"));
        verify(functions, never()).setFunctionPrototype(anyString(), anyString(), any(), any());
    }

    // ------------------------------------------------- the get_function_documentation export

    @Test
    public void exportedParametersBecomeRenamesAndTypesKeyedByCurrentName() {
        Map<String, Object> out = ok(applyOne(service(null), Map.of("parameters", List.of(
            Map.of("ordinal", 0.0, "name", "pPlayer", "type", "Player *"))), false));

        verify(functions).setLocalVariableType("0x1000", "param_1", "Player *", PROGRAM);
        verify(functions).batchRenameVariables("0x1000", Map.of("param_1", "pPlayer"), true, PROGRAM);
        assertEquals(List.of(), out.get("errors"));
    }

    @Test
    public void exportedPlaceholdersAreSkippedSoAnExportAppliesBackWithoutRevertingAnything() {
        Map<String, Object> out = ok(applyOne(service(null), Map.of("parameters", List.of(
            Map.of("ordinal", 0.0, "name", "param_1", "type", "undefined4"))), false));

        assertEquals(Map.of(), out.get("steps"));
        verify(functions, never()).setLocalVariableType(anyString(), anyString(), anyString(), any());
        verify(functions, never()).batchRenameVariables(anyString(), any(), anyBoolean(), any());
    }

    @Test
    public void anExportedUndefinedReturnTypeIsSkippedEvenBesideAPrototype() {
        Map<String, Object> out = ok(applyOne(service(null),
            Map.of("return_type", "undefined", "prototype", "int f(void)"), false));

        assertEquals(List.of(), out.get("errors"));
        verify(functions).setFunctionPrototype(eq("0x1000"), eq("int f(void)"), any(), eq(PROGRAM));
    }

    @Test
    public void anExplicitVariableEntryBeatsTheSameParameterInTheExport() {
        applyOne(service(null), Map.of(
            "variable_renames", Map.of("param_1", "explicit"),
            "parameters", List.of(Map.of("ordinal", 0.0, "name", "fromExport", "type", "undefined4"))), false);

        verify(functions).batchRenameVariables("0x1000", Map.of("param_1", "explicit"), true, PROGRAM);
    }

    @Test
    public void relativeOffsetsResolveFromTheFunctionEntry() {
        applyOne(service(null), Map.of("comments", List.of(
            Map.of("relative_offset", 4.0, "pre_comment", "before", "eol_comment", "after"))), false);

        Map<String, String> pre = Map.of("address", "ram:00001004", "comment", "before");
        Map<String, String> eol = Map.of("address", "ram:00001004", "comment", "after");
        verify(comments).batchSetComments("0x1000", List.of(pre), List.of(eol), null, PROGRAM);
    }

    @Test
    public void aLabelAlreadyThereIsLeftAloneAndTheOthersAreCreated() {
        Symbol have = mock(Symbol.class);
        when(have.getName()).thenReturn("loop_top");
        when(have.getSymbolType()).thenReturn(SymbolType.LABEL);
        when(symbolTable.getSymbols(ram.getAddress(0x1008))).thenReturn(new Symbol[] {have});

        Map<String, Object> out = ok(applyOne(service(null), Map.of("labels", List.of(
            Map.of("relative_offset", 8.0, "name", "loop_top"),
            Map.of("relative_offset", 12.0, "name", "done"))), false));

        verify(symbols).batchCreateLabels(List.of(Map.of("address", "ram:0000100c", "name", "done")), PROGRAM);
        assertEquals(1, step(out, "labels").get("created"));
        assertEquals(1, step(out, "labels").get("unchanged"));
    }

    @Test
    public void anEntryNeedsAnAddressOrAnOffsetToPlaceAComment() {
        Map<String, Object> out = ok(applyOne(service(null),
            Map.of("comments", List.of(Map.of("pre_comment", "orphan"))), false));
        assertEquals(List.of("comments: entry has no address or relative_offset"), out.get("errors"));
        verifyNoInteractions(comments);
    }

    // ------------------------------------------------------------------------------ tags

    @Test
    public void tagsAreAttachedAndReportedWithWhatWasCreated() {
        when(functions.addFunctionTag(anyString(), anyString(), any(), any(), any()))
            .thenReturn(Response.ok(Map.of("status", "success", "added", List.of("crypto", "hot"),
                "already_present", List.of(), "created", List.of("crypto"))));

        Map<String, Object> out = ok(applyOne(service(null), Map.of("tags", "crypto,hot",
            "tag_comments", Map.of("crypto", "touches key material")), false));

        verify(functions).addFunctionTag("0x1000", "crypto,hot", Map.of("crypto", "touches key material"),
            List.of(), PROGRAM);
        assertEquals(List.of("crypto", "hot"), step(out, "tags").get("added"));
        assertEquals(List.of("crypto"), step(out, "tags").get("created"));
        assertEquals(List.of(), out.get("errors"));
    }

    @Test
    public void anEntryMayGiveItsTagsAsAnArray() {
        when(functions.addFunctionTag(anyString(), anyString(), any(), any(), any())).thenReturn(Response.ok(Map.of()));
        applyMany(List.of(Map.of("address", "0x1000", "tags", List.of("a", "b"))), false);
        verify(functions).addFunctionTag(eq("0x1000"), eq("a,b"), any(), any(), eq(PROGRAM));
    }

    @Test
    public void noTagsMeansNoTagStep() {
        Map<String, Object> out = ok(applyOne(service(null), Map.of("name", "n"), false));
        assertNull(step(out, "tags"));
        verify(functions, never()).addFunctionTag(anyString(), anyString(), any(), any(), any());
    }

    // ------------------------------------------------------------------ many functions

    @Test
    public void anArrayAppliesEachEntryAndOneFailingDoesNotStopTheRest() {
        function("g", 0x2000, "param_1");
        Map<String, Object> out = ok(applyMany(List.of(
            Map.of("address", "0x1000", "name", "One"),
            Map.of("address", "0x9999", "name", "Missing"),
            Map.of("address", "0x2000", "function_name", "Two")), null));

        assertEquals(3, out.get("count"));
        assertEquals(2, out.get("succeeded"));
        assertEquals(1, out.get("failed"));
        assertEquals(3, ((List<?>) out.get("results")).size());
        verify(functions).renameFunctionByAddress("0x1000", "One", PROGRAM);
        verify(functions).renameFunctionByAddress("0x2000", "Two", PROGRAM);
    }

    /** An entry in entries[] is an export, whose spelling for params is "parameters". */
    @Test
    public void anEntryTakesTheExportsSpellingForParameters() {
        applyMany(List.of(Map.of("address", "0x1000", "parameters", List.of(
            Map.of("ordinal", 0.0, "name", "pPlayer", "type", "Player *")))), false);

        verify(functions).batchRenameVariables("0x1000", Map.of("param_1", "pPlayer"), true, PROGRAM);
    }

    @Test
    public void bulkDoesNotScoreUnlessAsked() {
        applyMany(List.of(Map.of("address", "0x1000", "name", "One")), null);
        verifyNoInteractions(analysis);

        applyMany(List.of(Map.of("address", "0x1000", "name", "One")), true);
        verify(analysis).analyzeFunctionCompleteness("0x1000", true, PROGRAM);

        applyMany(List.of(Map.of("address", "0x1000", "name", "One", "score", true)), false);
        verify(analysis, times(2)).analyzeFunctionCompleteness("0x1000", true, PROGRAM);
    }

    @Test
    public void anUnknownProgramFailsTheWholeCall() {
        Response r = service(null).applyDocumentation("0x1000", null, false, null, null, null, null, null,
            null, null, null, null, null, null, null, null, "/fw/none");
        assertTrue(r instanceof Response.Err);
    }
}
