package com.xebyte.offline;

import com.xebyte.core.FunctionService;
import junit.framework.TestCase;

/**
 * Offline tests for {@link FunctionService#extractCallingConvention(String)}.
 *
 * <p>Verifies that the regex-based helper only strips the calling-convention
 * token that sits between the return type and the function name (i.e. before
 * the first {@code '('}) so that conventions embedded inside callback
 * parameter types are preserved.
 */
public class FunctionServicePrototypeTest extends TestCase {

    // ---------- basic extraction ----------

    public void testExtractCallingConvention_ignoresConventionsInsideParams() {
        String[] r = FunctionService.extractCallingConvention(
                "int __stdcall Foo(void (__cdecl *cb)(int))");
        assertEquals("__stdcall", r[0]);
        assertEquals("int Foo(void (__cdecl *cb)(int))",
                r[1].replaceAll("\\s+", " ").trim());
    }

    public void testExtractCallingConvention_handlesNoConvention() {
        String[] r = FunctionService.extractCallingConvention("int Foo(int a)");
        assertEquals("", r[0]);
        assertEquals("int Foo(int a)", r[1]);
    }

    public void testExtractCallingConvention_singleConvention() {
        String[] r = FunctionService.extractCallingConvention("void __fastcall Bar()");
        assertEquals("__fastcall", r[0]);
        assertEquals("void Bar()", r[1].replaceAll("\\s+", " ").trim());
    }

    // ---------- each known convention ----------

    public void testExtractCallingConvention_cdecl() {
        String[] r = FunctionService.extractCallingConvention("int __cdecl Baz(int x)");
        assertEquals("__cdecl", r[0]);
        assertEquals("int Baz(int x)", r[1].replaceAll("\\s+", " ").trim());
    }

    public void testExtractCallingConvention_thiscall() {
        String[] r = FunctionService.extractCallingConvention("void __thiscall Method(int x)");
        assertEquals("__thiscall", r[0]);
        assertEquals("void Method(int x)", r[1].replaceAll("\\s+", " ").trim());
    }

    public void testExtractCallingConvention_vectorcall() {
        String[] r = FunctionService.extractCallingConvention("float __vectorcall Compute(float a)");
        assertEquals("__vectorcall", r[0]);
        assertEquals("float Compute(float a)", r[1].replaceAll("\\s+", " ").trim());
    }

    public void testExtractCallingConvention_stdcall() {
        String[] r = FunctionService.extractCallingConvention("void __stdcall Init()");
        assertEquals("__stdcall", r[0]);
        assertEquals("void Init()", r[1].replaceAll("\\s+", " ").trim());
    }

    // ---------- edge cases ----------

    public void testExtractCallingConvention_noParentheses() {
        // Bare return type + convention with no parameter list
        String[] r = FunctionService.extractCallingConvention("void __cdecl Fn");
        assertEquals("__cdecl", r[0]);
        assertEquals("void Fn", r[1].replaceAll("\\s+", " ").trim());
    }

    public void testExtractCallingConvention_emptyString() {
        String[] r = FunctionService.extractCallingConvention("");
        assertEquals("", r[0]);
        assertEquals("", r[1]);
    }

    public void testExtractCallingConvention_conventionOnlyInParams_notExtracted() {
        // Convention appears only inside params — should NOT be extracted
        String[] r = FunctionService.extractCallingConvention(
                "int Foo(void (__cdecl *cb)(int))");
        assertEquals("", r[0]);
        // Prototype should be returned unmodified
        assertEquals("int Foo(void (__cdecl *cb)(int))", r[1]);
    }
}
