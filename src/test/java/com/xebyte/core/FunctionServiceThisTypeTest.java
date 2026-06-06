package com.xebyte.core;

import junit.framework.TestCase;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Offline checks for {@code this} routing and pointer normalization helpers.
 */
public class FunctionServiceThisTypeTest extends TestCase {

    public void testResolveThisPointerTypeReturnsNullWithoutDataTypeManager() {
        assertNull(FunctionService.resolveThisPointerType(null, "MyStruct"));
        assertNull(FunctionService.resolveThisPointerType(null, "  "));
        assertNull(FunctionService.resolveThisPointerType(null, ""));
    }

    public void testSetParameterTypeRoutesThisToSetFunctionThisType() throws IOException {
        String src = Files.readString(
                Paths.get("src/main/java/com/xebyte/core/FunctionService.java"),
                StandardCharsets.UTF_8);
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
        String src = Files.readString(
                Paths.get("src/main/java/com/xebyte/core/FunctionService.java"),
                StandardCharsets.UTF_8);
        Pattern block = Pattern.compile(
                "public Response setDecompilerVariableType\\([\\s\\S]*?\\n    \\}",
                Pattern.MULTILINE);
        Matcher m = block.matcher(src);
        assertTrue("setDecompilerVariableType body not found", m.find());
        String body = m.group();
        assertTrue(body.contains("\"this\".equals(variableName)"));
        assertTrue(body.contains("setFunctionThisType"));
    }

    public void testEndpointRegistryWiresSetParameterTypeEndpoint() throws IOException {
        String src = Files.readString(
                Paths.get("src/main/java/com/xebyte/core/EndpointRegistry.java"),
                StandardCharsets.UTF_8);
        assertTrue(src.contains("setParameterTypeEndpoint("));
    }

    public void testSetFunctionThisTypeUsesClassNamespaceAssociation() throws IOException {
        String src = Files.readString(
                Paths.get("src/main/java/com/xebyte/core/FunctionService.java"),
                StandardCharsets.UTF_8);
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
