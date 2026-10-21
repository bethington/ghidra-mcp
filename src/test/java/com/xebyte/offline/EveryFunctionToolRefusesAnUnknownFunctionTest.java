package com.xebyte.offline;

import com.xebyte.core.AnnotationScanner;
import com.xebyte.core.CoreServices;
import com.xebyte.core.DebuggerService;
import com.xebyte.core.DocumentationApplyService;
import com.xebyte.core.EndpointDef;
import com.xebyte.core.GuiToolService;
import com.xebyte.core.ManualToolDescriptors;
import com.xebyte.core.McpTool;
import com.xebyte.core.Param;
import com.xebyte.core.ParamSource;
import com.xebyte.core.ProgramProvider;
import com.xebyte.core.ProjectLifecycleService;
import com.xebyte.core.ProjectServerSession;
import com.xebyte.core.PromptPolicyService;
import com.xebyte.core.Response;
import com.xebyte.core.ServerLifecycleService;
import com.xebyte.core.ThreadingStrategy;
import com.xebyte.core.VersionControlService;
import com.xebyte.headless.HeadlessProgramProvider;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.DefaultAddressFactory;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import org.junit.Test;

import java.lang.reflect.Method;
import java.lang.reflect.Parameter;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Every tool with a {@link Function}-typed parameter refuses an unknown function reference
 * at the scanner, before the tool body runs.
 */
public class EveryFunctionToolRefusesAnUnknownFunctionTest {

    private static final String BAD = "nope";

    private record ToolRef(String path, Method method) {}

    private static boolean isFunctionToolParameter(Parameter parameter) {
        return parameter.getType() == Function.class
                && parameter.getAnnotation(Param.class) != null;
    }

    private static Set<ToolRef> functionTools() {
        Set<ToolRef> tools = new HashSet<>();
        for (Object service : ServiceFactory.buildAllServices()) {
            for (Method method : service.getClass().getDeclaredMethods()) {
                McpTool tool = method.getAnnotation(McpTool.class);
                if (tool == null) {
                    continue;
                }
                boolean hasFunction = false;
                for (Parameter parameter : method.getParameters()) {
                    if (isFunctionToolParameter(parameter)) {
                        hasFunction = true;
                        break;
                    }
                }
                if (hasFunction) {
                    tools.add(new ToolRef(tool.path(), method));
                }
            }
        }
        return tools;
    }

    private static AnnotationScanner scannerWithEmptyProgram(Program program) {
        ProgramProvider provider = new ProgramProvider() {
            @Override
            public Program getCurrentProgram() {
                return program;
            }

            @Override
            public Program getProgram(String name) {
                return program;
            }

            @Override
            public Program[] getAllOpenPrograms() {
                return new Program[] {program};
            }

            @Override
            public void setCurrentProgram(Program p) {
            }
        };
        ThreadingStrategy ts = new NoopThreadingStrategy();
        CoreServices core = CoreServices.build(provider, ts);
        AnnotationScanner scanner = new AnnotationScanner(provider, ts,
            core.plus(
                new DebuggerService(ts, null),
                new PromptPolicyService(),
                new ProjectLifecycleService(new HeadlessProgramProvider()),
                new VersionControlService(provider, new ProjectServerSession(provider)),
                new ServerLifecycleService(core.programScript(), () -> { }),
                new GuiToolService(null),
                new DocumentationApplyService(provider, core.function(), core.comment(), core.symbolLabel(),
                    core.analysis(), null)));
        ManualToolDescriptors.addAll(scanner, ManualToolDescriptors.SHARED_ROUTES);
        return scanner;
    }

    private static Program programWithNoFunctions() {
        AddressSpace ram = new GenericAddressSpace("ram", 32, AddressSpace.TYPE_RAM, 0);
        AddressFactory factory = new DefaultAddressFactory(new AddressSpace[] {ram}, ram);
        Program program = mock(Program.class);
        when(program.getName()).thenReturn("Test.exe");
        when(program.getAddressFactory()).thenReturn(factory);
        FunctionManager functionManager = mock(FunctionManager.class);
        SymbolTable symbolTable = mock(SymbolTable.class);
        SymbolIterator noSymbols = mock(SymbolIterator.class);
        when(noSymbols.hasNext()).thenReturn(false);
        FunctionIterator noFunctions = emptyFunctionIterator();
        when(symbolTable.getSymbols(anyString())).thenReturn(noSymbols);
        when(program.getFunctionManager()).thenReturn(functionManager);
        when(program.getSymbolTable()).thenReturn(symbolTable);
        when(functionManager.getFunctionAt(any())).thenReturn(null);
        when(functionManager.getFunctionContaining(any())).thenReturn(null);
        when(functionManager.getFunctions(anyBoolean())).thenReturn(noFunctions);
        return program;
    }

    private static FunctionIterator emptyFunctionIterator() {
        FunctionIterator it = mock(FunctionIterator.class);
        when(it.iterator()).thenReturn(it);
        when(it.hasNext()).thenReturn(false);
        return it;
    }

    private static void fillBadFunction(Method method, Map<String, String> query, Map<String, Object> body) {
        for (Parameter parameter : method.getParameters()) {
            if (!isFunctionToolParameter(parameter)) {
                continue;
            }
            Param p = parameter.getAnnotation(Param.class);
            if (p.source() == ParamSource.BODY) {
                body.put(p.value(), BAD);
            } else {
                query.put(p.value(), BAD);
            }
        }
        query.putIfAbsent("program", "");
    }

    @Test
    public void everyFunctionTypedToolRefusesAnUnknownFunction() throws Exception {
        Program program = programWithNoFunctions();
        AnnotationScanner scanner = scannerWithEmptyProgram(program);
        Set<ToolRef> tools = functionTools();
        Map<String, EndpointDef> byPath = new HashMap<>();
        for (EndpointDef ep : scanner.getEndpoints()) {
            byPath.put(ep.path(), ep);
        }
        int covered = 0;

        for (ToolRef ref : tools) {
            EndpointDef ep = byPath.get(ref.path());
            if (ep == null) {
                fail("registered tool missing endpoint: " + ref.path());
            }
            Map<String, String> query = new HashMap<>();
            Map<String, Object> body = new HashMap<>();
            fillBadFunction(ref.method(), query, body);
            Response response = ep.handler().handle(query, body);
            if (!(response instanceof Response.Err err)) {
                fail(ref.path() + " expected Err for unknown function, got: " + response.toJson());
            } else {
                assertTrue(ref.path() + " must surface a function resolution error, got: " + err.message(),
                        err.message().contains("Function not found")
                                || err.message().contains("is required"));
            }
            covered++;
        }

        assertEquals("every Function-typed tool was checked", tools.size(), covered);
        assertTrue("expected a substantial set of function tools, got " + covered, covered >= 27);
    }
}
