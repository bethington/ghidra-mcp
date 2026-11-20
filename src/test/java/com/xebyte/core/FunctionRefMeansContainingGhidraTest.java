package com.xebyte.core;

import com.xebyte.headless.DirectThreadingStrategy;
import com.xebyte.headless.HeadlessProgramProvider;
import com.xebyte.offline.ServiceFactory;
import ghidra.GhidraApplicationLayout;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.util.task.TaskMonitor;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.File;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.*;
import static org.junit.Assume.assumeTrue;

/**
 * Function-typed tool parameters resolve an interior address to the containing
 * function before the tool body runs.
 */
public class FunctionRefMeansContainingGhidraTest {

    private ProgramBuilder builder;
    private ProgramDB program;
    private Function target;
    private Address entry;
    private Address interior;
    private AnnotationScanner scanner;

    @BeforeClass
    public static void initializeGhidra() throws Exception {
        String installDir = System.getenv("GHIDRA_INSTALL_DIR");
        assumeTrue("GHIDRA_INSTALL_DIR is required for real Ghidra tests",
            installDir != null && !installDir.isBlank());
        if (!Application.isInitialized()) {
            ApplicationConfiguration configuration = new ApplicationConfiguration();
            configuration.setInitializeLogging(false);
            Application.initializeApplication(new GhidraApplicationLayout(new File(installDir)),
                configuration);
        }
    }

    @Before
    public void setUp() throws Exception {
        builder = new ProgramBuilder("fn-ref-interior", ProgramBuilder._X64, "gcc", this);
        program = builder.getProgram();
        builder.createMemory(".text", "0x1000", 0x200);

        // MOV EAX,1; NOP; NOP; RET  (interior sits on a NOP, not the entry)
        builder.setBytes("0x1000", "b8 01 00 00 00 90 90 c3");
        builder.withTransaction(() -> {
            DisassembleCommand command = new DisassembleCommand(builder.addr("0x1000"),
                new AddressSet(builder.addr("0x1000"), builder.addr("0x1007")), true);
            assertTrue(command.applyTo(program, TaskMonitor.DUMMY));
        });
        target = builder.createFunction("0x1000");
        entry = target.getEntryPoint();
        interior = builder.addr("0x1005");

        builder.withTransaction(() -> target.setComment("plate to clear"));

        HeadlessProgramProvider provider = new HeadlessProgramProvider();
        provider.trackOpenProgram(program);
        DirectThreadingStrategy threading = new DirectThreadingStrategy();
        CoreServices core = CoreServices.build(provider, threading);
        scanner = new AnnotationScanner(provider, threading, core.plus(ServiceFactory.buildAllServices()));
        ManualToolDescriptors.addAll(scanner, ManualToolDescriptors.SHARED_ROUTES);
    }

    @After
    public void tearDown() {
        if (builder != null) {
            builder.dispose();
        }
    }

    private Response dispatch(String path, Map<String, String> query, Map<String, Object> body) throws Exception {
        EndpointDef ep = scanner.getEndpoints().stream()
            .filter(e -> e.path().equals(path))
            .findFirst()
            .orElseThrow(() -> new AssertionError("missing endpoint: " + path));
        return ep.handler().handle(query, body);
    }

    @Test
    @SuppressWarnings("unchecked")
    public void disassembleFunctionResolvesInteriorAddressToContainingFunction() throws Exception {
        Map<String, String> query = new HashMap<>();
        query.put("program", program.getName());
        query.put("address", interior.toString());

        Response response = dispatch("/disassemble_function", query, Map.of());
        assertTrue(response.toJson(), response instanceof Response.Ok);
        Map<String, Object> data = (Map<String, Object>) ((Response.Ok) response).data();
        List<?> instructions = (List<?>) data.get("instructions");
        assertNotNull(instructions);
        assertTrue("interior ref should disassemble the whole function, not one instruction",
            instructions.size() >= 2);
        assertEquals("the response names the function it acted on",
            Map.of("name", target.getName(), "address", target.getEntryPoint().toString(false)),
            data.get("resolved_function"));
    }

    @Test
    public void clearFunctionCommentsResolvesInteriorAddressToContainingFunction() throws Exception {
        assertNotNull("fixture plate comment", target.getComment());

        Map<String, String> query = new HashMap<>();
        query.put("program", program.getName());
        Map<String, Object> body = new HashMap<>();
        body.put("function", interior.toString());

        Response response = dispatch("/clear_function_comments", query, body);
        assertTrue(response.toJson(), response instanceof Response.Ok);
        assertNull("plate should be cleared via interior function ref", target.getComment());
    }
}
