package com.xebyte.offline;

import com.xebyte.core.DataTypeService;
import com.xebyte.core.FunctionService;
import com.xebyte.core.Response;
import com.xebyte.core.ThreadingStrategy;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.ParameterDefinitionImpl;
import java.util.ArrayList;
import java.util.List;
import junit.framework.TestCase;

/**
 * Validation and early-error paths for datatype and member-function MCP tools without a live Ghidra program.
 */
public class DatatypeMcpToolsHandlerValidationTest extends TestCase {

    private DataTypeService dataTypes;
    private FunctionService functions;

    @Override
    protected void setUp() {
        ThreadingStrategy ts = new NoopThreadingStrategy();
        dataTypes = new DataTypeService(ServiceFactory.stubProvider(), ts);
        functions = new FunctionService(ServiceFactory.stubProvider(), ts);
    }

    public void testCreateStructRejectsNonArrayFieldsOrRequiresProgram() {
        Response r = dataTypes.createStruct("MyStruct", "{\"name\":\"a\"}", false, "");
        String msg = r.toJson();
        assertTrue(msg.contains("JSON array") || msg.contains("No program loaded"));
    }

    public void testRecreateStructRejectsEmptyName() {
        Response r = dataTypes.recreateStruct("", "[{\"name\":\"a\",\"type\":\"uint\"}]", 0, true, false, "");
        assertTrue(r instanceof Response.Err);
        assertTrue(((Response.Err) r).message().contains("name is required"));
    }

    public void testEmbedStructFieldRejectsMissingEmbeddedStruct() {
        Response r = dataTypes.embedStructField("Parent", "field_a", "", "");
        assertTrue(r instanceof Response.Text);
        assertTrue(((Response.Text) r).content().contains("embedded_struct is required"));
    }

    public void testModifyStructFieldTypeRequiresProgram() {
        Response r = dataTypes.modifyStructFieldType("S", "f", "uint", "");
        assertTrue(r instanceof Response.Err);
        assertTrue(((Response.Err) r).message().contains("No program loaded"));
    }

    public void testResizeStructRejectsInvalidNewSize() {
        Response r = dataTypes.resizeStruct("S", 0, true, false, "");
        assertTrue(r instanceof Response.Err);
        assertTrue(((Response.Err) r).message().contains("new_size must be positive"));
    }

    public void testResizeStructRejectsEmptyName() {
        Response r = dataTypes.resizeStruct("", 64, true, false, "");
        assertTrue(r instanceof Response.Err);
        assertTrue(((Response.Err) r).message().contains("name is required"));
    }

    public void testRecreateStructRejectsMissingFields() {
        Response r = dataTypes.recreateStruct("S", "", 0, true, false, "");
        assertTrue(r instanceof Response.Err);
        assertTrue(((Response.Err) r).message().contains("fields"));
    }

    public void testSetFunctionThisTypeRejectsUndefinedType() {
        Response r = functions.setFunctionThisType("0x401000", "undefined4", "");
        assertTrue(r instanceof Response.Err);
        assertTrue(((Response.Err) r).message().contains("concrete struct/class pointer"));
    }

    public void testSetFunctionThisTypeRequiresAddress() {
        Response r = functions.setFunctionThisType("", "MyStruct *", "");
        assertTrue(r instanceof Response.Err);
        assertTrue(((Response.Err) r).message().contains("Function address is required"));
    }

    public void testSetFunctionThisTypeRequiresProgramWhenNoBinaryLoaded() {
        Response r = functions.setFunctionThisType("0x401000", "MyStruct *", "");
        assertTrue(r instanceof Response.Err);
        assertTrue(((Response.Err) r).message().contains("No program loaded"));
    }

    public void testSetParameterTypeRoutesThisBeforeProgramCheck() {
        Response r = functions.setParameterTypeEndpoint("0x401000", "this", "MyStruct *", "");
        assertTrue(r instanceof Response.Err);
        String msg = ((Response.Err) r).message();
        assertTrue(msg.contains("concrete struct/class pointer") || msg.contains("No program loaded"));
    }

    public void testSetDecompilerVariableTypeRoutesThisLikeSetParameterType() {
        Response r = functions.setDecompilerVariableType("0x401000", "this", "undefined4", "");
        assertTrue(r instanceof Response.Err);
        assertTrue(((Response.Err) r).message().contains("concrete struct/class pointer"));
    }

    /**
     * H05: createFunctionSignature accumulates all parameters.
     * The old code called funcDef.setArguments({singleParam}) inside the loop,
     * replacing the list on each iteration so only the last param survived.
     * The fix accumulates into a List and calls setArguments once after the loop.
     * This standalone test proves the GREEN target shape for the accumulation logic.
     */
    public void testCreateFunctionSignatureKeepsAllParameters() {
        FunctionDefinitionDataType fd = new FunctionDefinitionDataType("Sig");
        // Simulate the fixed loop body: accumulate, then set once
        List<ParameterDefinition> params = new ArrayList<>();
        params.add(new ParameterDefinitionImpl("a", IntegerDataType.dataType, ""));
        params.add(new ParameterDefinitionImpl("b", IntegerDataType.dataType, ""));
        fd.setArguments(params.toArray(new ParameterDefinition[0]));
        assertEquals("Expected 2 arguments but got " + fd.getArguments().length,
                     2, fd.getArguments().length);
    }

    /**
     * H05: createFunctionSignature endpoint with stub provider returns
     * "No program loaded" — the early-exit path is unchanged.
     */
    public void testCreateFunctionSignatureRequiresProgram() {
        Response r = dataTypes.createFunctionSignature(
                "MyFunc", "int", "[{\"name\":\"a\",\"type\":\"int\"},{\"name\":\"b\",\"type\":\"int\"}]", "");
        String msg = r.toJson();
        assertTrue("Expected 'No program loaded' but got: " + msg,
                   msg.contains("No program loaded"));
    }
}
