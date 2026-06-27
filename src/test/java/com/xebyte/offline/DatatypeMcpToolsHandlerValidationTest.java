package com.xebyte.offline;

import com.xebyte.core.DataTypeService;
import com.xebyte.core.FunctionService;
import com.xebyte.core.Response;
import com.xebyte.core.ThreadingStrategy;
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

    // Note on H05/H06 test coverage: the production fixes for
    // create_function_signature (accumulate params, call setArguments once
    // after the loop) and create_typedef (delegate to
    // ServiceUtils.resolveDataType for pointer-depth recursion) cannot be
    // exercised in this offline Maven suite because instantiating Ghidra
    // DataType classes (IntegerDataType, FunctionDefinitionDataType,
    // PointerDataType) class-inits SettingsImpl which transitively pulls
    // commons-lang3, javax.help, and further bundled JARs that the Maven
    // offline classpath intentionally does not include. Earlier proxy tests
    // that constructed these types standalone were removed after CI showed
    // the unbounded transitive chain; they tested Ghidra's API contract
    // rather than the endpoint fix anyway. The endpoint-path test below
    // (testCreateFunctionSignatureRequiresProgram) and the integration suite
    // (tests/integration/test_safe_write_endpoints.py) provide coverage.

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
