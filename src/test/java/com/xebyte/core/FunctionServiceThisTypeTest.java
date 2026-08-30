package com.xebyte.core;

import com.xebyte.offline.ProjectSource;
import junit.framework.TestCase;

import java.io.IOException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Offline checks for {@code this} routing and pointer normalization helpers.
 *
 * <p>The source-text assertions below read through {@link ProjectSource} so
 * they neither depend on the working directory nor on how the checkout
 * materialised line endings — the failure mode that made two other tests look
 * broken to outside contributors (#447, #448).
 */
public class FunctionServiceThisTypeTest extends TestCase {

    private static String readFunctionServiceSource() throws IOException {
        return ProjectSource.readMainSource("core", "FunctionService.java");
    }

    public void testResolveThisPointerTypeReturnsNullWithoutDataTypeManager() {
        assertNull(FunctionService.resolveThisPointerType(null, "MyStruct"));
        assertNull(FunctionService.resolveThisPointerType(null, "  "));
        assertNull(FunctionService.resolveThisPointerType(null, ""));
    }

    public void testSetParameterTypeRoutesThisToSetFunctionThisType() throws IOException {
        String src = readFunctionServiceSource();
        Pattern block = Pattern.compile(
                "public Response setParameterTypeEndpoint\\([\\s\\S]*?\\n    \\}",
                Pattern.MULTILINE);
        Matcher m = block.matcher(src);
        assertTrue("setParameterTypeEndpoint body not found", m.find());
        String body = m.group();
        assertTrue(body.contains("\"this\".equals(parameterName)"));
        assertTrue(body.contains("setFunctionThisType"));
    }

    public void testSetDecompilerVariableTypeRoutesThis() throws IOException {
        String src = readFunctionServiceSource();
        Pattern block = Pattern.compile(
                "public Response setDecompilerVariableType\\([\\s\\S]*?\\n    \\}",
                Pattern.MULTILINE);
        Matcher m = block.matcher(src);
        assertTrue("setDecompilerVariableType body not found", m.find());
        String body = m.group();
        assertTrue(body.contains("\"this\".equals(variableName)"));
        assertTrue(body.contains("setFunctionThisType"));
    }

    public void testSetFunctionThisTypeUsesClassNamespaceAssociation() throws IOException {
        String src = readFunctionServiceSource();
        Pattern block = Pattern.compile(
                "public Response setFunctionThisType\\([\\s\\S]*?\\n    \\}",
                Pattern.MULTILINE);
        Matcher m = block.matcher(src);
        assertTrue("setFunctionThisType body not found", m.find());
        String body = m.group();
        // The auto-'this' is immutable; its type is derived from the function's parent Class
        // namespace (auto-storage). The proper implementation re-parents the function into a
        // GhidraClass rather than retyping the auto-parameter or using custom storage.
        assertTrue(body.contains("createClass") || body.contains("convertNamespaceToClass"));
        assertTrue(body.contains("setNamespace"));
        assertFalse("must not use custom variable storage", body.contains("setCustomVariableStorage"));
    }
}
