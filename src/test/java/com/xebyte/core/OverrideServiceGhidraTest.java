package com.xebyte.core;

import com.xebyte.headless.DirectThreadingStrategy;
import com.xebyte.headless.HeadlessProgramProvider;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.listing.Function;
import org.junit.*;
import java.io.File;
import java.util.*;
import static org.junit.Assert.*;
import static org.junit.Assume.assumeTrue;

public class OverrideServiceGhidraTest {
    private ProgramBuilder builder;
    private ProgramDB program;
    private OverrideService service;

    @BeforeClass public static void initialize() throws Exception {
        String install = System.getenv("GHIDRA_INSTALL_DIR");
        assumeTrue(install != null && !install.isBlank());
        if (!Application.isInitialized()) {
            ApplicationConfiguration config = new ApplicationConfiguration();
            config.setInitializeLogging(false);
            Application.initializeApplication(new GhidraApplicationLayout(new File(install)), config);
        }
    }

    @Before public void setUp() throws Exception {
        builder = new ProgramBuilder("overrides", ProgramBuilder._X86, "windows", this);
        program = builder.getProgram();
        builder.createMemory(".text", "0x1000", 0x1100);
        builder.setBytes("0x1000", "e8 fb 0f 00 00 c3");
        builder.setBytes("0x2000", "c3");
        builder.setBytes("0x1020", "ff d0 c3");
        builder.disassemble("0x1000", 6);
        builder.disassemble("0x2000", 1);
        builder.disassemble("0x1020", 3);
        builder.createFunction("0x1000");
        builder.createFunction("0x2000");
        builder.createFunction("0x1020");
        HeadlessProgramProvider provider = new HeadlessProgramProvider();
        provider.setCurrentProgram(program);
        service = new OverrideService(provider, new DirectThreadingStrategy());
    }

    @After public void tearDown() { builder.dispose(); }

    private static void ok(Response response) { assertTrue(response.toJson(), response instanceof Response.Ok); }

    @Test public void stackOverridesIncludeZeroAndNegativeAndRemoveStale() throws Exception {
        assertTrue(service.getStackDepthChange("0x1000", "").toJson().contains("\"has_override\":false"));
        ok(service.setStackDepthChange("0x1000", 0, ""));
        assertTrue(service.getStackDepthChange("0x1000", "").toJson().contains("\"stack_depth_change\":0"));
        ok(service.setStackDepthChange("0x1000", -8, ""));
        assertTrue(service.getStackDepthChange("0x1000", "").toJson().contains("\"stack_depth_change\":-8"));
        builder.withTransaction(() -> program.getListing().clearCodeUnits(builder.addr("0x1000"), builder.addr("0x1004"), false));
        ok(service.removeStackDepthChange("0x1000", ""));
        assertTrue(service.getStackDepthChange("0x1000", "").toJson().contains("\"has_override\":false"));
        assertTrue(service.setStackDepthChange("0x1000", 4, "") instanceof Response.Err);
    }

    @Test public void callSiteReplacementIsLocalizedAndRejectsNonCalls() {
        Function caller = program.getFunctionManager().getFunctionAt(builder.addr("0x1000"));
        Function callee = program.getFunctionManager().getFunctionAt(builder.addr("0x2000"));
        String beforeCaller = caller.getSignature().getPrototypeString(true);
        String beforeCallee = callee.getSignature().getPrototypeString(true);
        ok(service.setCallSitePrototype("0x1000", "int __cdecl placeholder(char *buf, int n)", ""));
        assertTrue(service.getCallSitePrototype("0x1000", "").toJson().contains("char *"));
        ok(service.setCallSitePrototype("0x1000", "void __stdcall other(int count)", ""));
        String result = service.getCallSitePrototype("0x1000", "").toJson();
        assertTrue(result, result.contains("count"));
        assertFalse(result, result.contains("buf"));
        assertEquals(beforeCaller, caller.getSignature().getPrototypeString(true));
        assertEquals(beforeCallee, callee.getSignature().getPrototypeString(true));
        assertTrue(service.setCallSitePrototype("0x1005", "void x(void)", "") instanceof Response.Err);
        assertTrue(service.setCallSitePrototype("0x1000", "not a declaration", "") instanceof Response.Err);
        assertEquals(result, service.getCallSitePrototype("0x1000", "").toJson());
    }

    @Test public void conventionsAcceptAliasesAndDefaultWithoutChangingNameOrCustomStorage() throws Exception {
        Function function = program.getFunctionManager().getFunctionAt(builder.addr("0x1000"));
        String name = function.getName();
        ok(service.setFunctionCallingConvention("0x1000", "thiscall", ""));
        assertEquals("__thiscall", function.getCallingConventionName());
        builder.withTransaction(() -> function.setCustomVariableStorage(true));
        ok(service.setFunctionCallingConvention("0x1000", "cdecl", ""));
        assertTrue(function.hasCustomVariableStorage());
        assertEquals(name, function.getName());
        ok(service.setFunctionCallingConvention("0x1000", "default", ""));
        assertTrue(service.setFunctionCallingConvention("0x1001", "cdecl", "") instanceof Response.Err);
        assertTrue(service.setFunctionCallingConvention("0x1000", "unsupported", "") instanceof Response.Err);
    }

    @Test public void schemaExposesAllSixToolsWithProgramSelectors() {
        AnnotationScanner scanner = new AnnotationScanner(service);
        assertEquals(6, scanner.getEndpoints().size());
        String schema = scanner.generateSchema();
        assertTrue(schema.contains("set_stack_depth_change"));
        assertTrue(schema.contains("call_address"));
        assertTrue(schema.contains("program"));
    }

    @Test public void indirectCallVarargsAndSignedStackLimits() {
        ok(service.setCallSitePrototype("0x1020", "int indirect(char *format, ...)", ""));
        String result = service.getCallSitePrototype("0x1020", "").toJson();
        assertTrue(result, result.contains("..."));
        ok(service.setStackDepthChange("0x1000", Integer.MIN_VALUE, ""));
        assertTrue(service.getStackDepthChange("0x1000", "").toJson().contains("-2147483648"));
        ok(service.setStackDepthChange("0x1000", Integer.MAX_VALUE, ""));
        assertTrue(service.getStackDepthChange("0x1000", "").toJson().contains("2147483647"));
    }

    @Test public void httpStackDeltasRejectMissingFractionalAndOutOfRangeValues() throws Exception {
        EndpointDef endpoint = new AnnotationScanner(service).getEndpoints().stream()
            .filter(e -> e.path().equals("/set_stack_depth_change")).findFirst().orElseThrow();
        ok(service.setStackDepthChange("0x1000", -8, ""));
        for (Object value : Arrays.asList(null, "", "invalid", true, 1.5, 2147483648L, -2147483649L, 4294967296L)) {
            Map<String, Object> body = new HashMap<>();
            body.put("address", "0x1000");
            if (value != null) body.put("stack_depth_change", value);
            Response response = endpoint.handler().handle(Map.of(), body);
            assertTrue("value=" + value + ": " + response.toJson(), response instanceof Response.Err);
            assertTrue(service.getStackDepthChange("0x1000", "").toJson().contains("\"stack_depth_change\":-8"));
        }
        Response query = endpoint.handler().handle(Map.of("address", "0x1000", "stack_depth_change", "4294967296"), Map.of());
        assertTrue(query.toJson(), query instanceof Response.Err);
        ok(endpoint.handler().handle(Map.of(), Map.of("address", "0x1000", "stack_depth_change", -2147483648.0)));
        assertTrue(service.getStackDepthChange("0x1000", "").toJson().contains("-2147483648"));
    }
}
