package com.xebyte.core;

import com.xebyte.headless.DirectThreadingStrategy;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.data.Array;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import static org.junit.Assert.*;
import static org.junit.Assume.assumeTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/** Exercise JSON binding, the real ARRAY write and rejected-write rollback. */
public class ArrayClassificationCountGhidraTest {

    private ProgramBuilder builder;
    private ProgramDB program;
    private EndpointDef endpoint;

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
        builder = new ProgramBuilder("array-classification-count", ProgramBuilder._X64, "gcc", this);
        program = builder.getProgram();
        builder.createMemory(".data", "0x4000", 0x100);
        ProgramProvider provider = mock(ProgramProvider.class);
        when(provider.getAllOpenPrograms()).thenReturn(new Program[] {program});
        when(provider.getCurrentProgram()).thenReturn(program);
        when(provider.getProgram(any())).thenReturn(program);
        when(provider.resolveProgram(any())).thenReturn(program);
        DirectThreadingStrategy strategy = new DirectThreadingStrategy();
        AnnotationScanner scanner = new AnnotationScanner(provider, strategy,
            new DataTypeService(provider, strategy));
        endpoint = scanner.getEndpoints().stream()
            .filter(e -> e.path().equals("/apply_data_classification")).findFirst().orElseThrow();
    }

    @After
    public void tearDown() {
        if (builder != null) {
            builder.dispose();
        }
    }

    private Response classify(String countLiteral) throws Exception {
        String json = "{\"address\":\"0x4000\",\"classification\":\"ARRAY\","
            + "\"type_definition\":{\"element_type\":\"byte\",\"count\":" + countLiteral + "}}";
        Map<String, Object> body = JsonHelper.parseBody(
            new ByteArrayInputStream(json.getBytes(StandardCharsets.UTF_8)));
        return endpoint.handler().handle(Map.of(), body);
    }

    private void assertArrayOf64(Response response) {
        assertTrue(response.toJson(), response instanceof Response.Ok);
        Data data = program.getListing().getDefinedDataAt(builder.addr("0x4000"));
        assertNotNull(data);
        assertTrue(data.getDataType() instanceof Array);
        assertEquals(64, ((Array) data.getDataType()).getNumElements());
        assertEquals(64, data.getLength());
        assertNull("The write must end its transaction", program.getCurrentTransactionInfo());
    }

    @Test
    public void numericJsonCountSetsTheActualArrayExtent() throws Exception {
        assertArrayOf64(classify("64"));
    }

    @Test
    public void stringCountRetainsItsExistingBehavior() throws Exception {
        assertArrayOf64(classify("\"64\""));
    }

    @Test
    public void nonpositiveNumericCountsRejectWithoutLeavingData() throws Exception {
        for (String literal : new String[] {"0", "-2"}) {
            Response response = classify(literal);
            assertTrue(response.toJson(), response instanceof Response.Err);
            assertTrue(response.toJson(), response.toJson().contains("must be positive"));
            assertNull(program.getListing().getDefinedDataAt(builder.addr("0x4000")));
            assertNull("A rejected write must end its transaction", program.getCurrentTransactionInfo());
        }
    }
}
