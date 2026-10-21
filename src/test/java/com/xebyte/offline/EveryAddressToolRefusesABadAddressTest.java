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
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
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
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Every tool with a required {@link Address} parameter refuses a bad address string
 * at the scanner, before the tool body runs.
 */
public class EveryAddressToolRefusesABadAddressTest {

    private static final String BAD = "zzz";

    private record ToolRef(String path, Method method) {}

    private static boolean isRequiredAddressParam(Parameter parameter) {
        if (parameter.getType() != Address.class) {
            return false;
        }
        Param p = parameter.getAnnotation(Param.class);
        if (p == null) {
            return false;
        }
        if (!"address".equals(p.paramType()) && !Param.ADDRESS.equals(p.paramType())) {
            return false;
        }
        return Param.NO_DEFAULT.equals(p.defaultValue());
    }

    private static Set<ToolRef> requiredAddressTools() {
        Set<ToolRef> tools = new HashSet<>();
        for (Object service : ServiceFactory.buildAllServices()) {
            for (Method method : service.getClass().getDeclaredMethods()) {
                McpTool tool = method.getAnnotation(McpTool.class);
                if (tool == null) {
                    continue;
                }
                boolean hasRequired = false;
                for (Parameter parameter : method.getParameters()) {
                    if (isRequiredAddressParam(parameter)) {
                        hasRequired = true;
                        break;
                    }
                }
                if (hasRequired) {
                    tools.add(new ToolRef(tool.path(), method));
                }
            }
        }
        return tools;
    }

    private static AnnotationScanner scannerWithProgram(Program program) {
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

    private static Program programWithRejectingFactory() {
        Program program = mock(Program.class);
        when(program.getName()).thenReturn("Test.exe");
        AddressFactory factory = mock(AddressFactory.class);
        AddressSpace ram = mock(AddressSpace.class);
        when(ram.getName()).thenReturn("ram");
        when(ram.getType()).thenReturn(AddressSpace.TYPE_RAM);
        when(ram.isOverlaySpace()).thenReturn(false);
        when(factory.getAddressSpaces()).thenReturn(new AddressSpace[] {ram});
        when(factory.getDefaultAddressSpace()).thenReturn(ram);
        when(program.getAddressFactory()).thenReturn(factory);
        when(factory.getAddress(BAD)).thenReturn(null);
        when(factory.getAddress("ram:" + BAD)).thenReturn(null);
        return program;
    }

    private static void fillBadAddress(Method method, Map<String, String> query, Map<String, Object> body) {
        for (Parameter parameter : method.getParameters()) {
            if (!isRequiredAddressParam(parameter)) {
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
    public void everyRequiredAddressToolRefusesABadAddress() throws Exception {
        Program program = programWithRejectingFactory();
        AnnotationScanner scanner = scannerWithProgram(program);
        Set<ToolRef> tools = requiredAddressTools();
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
            fillBadAddress(ref.method(), query, body);
            Response response = ep.handler().handle(query, body);
            if (!(response instanceof Response.Err err)) {
                fail(ref.path() + " expected Err for bad address, got: " + response.toJson());
            } else {
                assertTrue(ref.path() + " must surface a parse error, got: " + err.message(),
                        err.message().contains("could not be resolved")
                                || err.message().contains("Invalid address")
                                || err.message().contains("is required"));
            }
            covered++;
        }

        assertEquals("every required Address-typed tool was checked", tools.size(), covered);
        assertTrue("expected a substantial set of address tools, got " + covered, covered >= 30);
    }
}
