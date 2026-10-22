package com.xebyte.core;

import com.xebyte.headless.DirectThreadingStrategy;
import com.xebyte.headless.HeadlessProgramProvider;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.task.TaskMonitor;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.File;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.*;
import static org.junit.Assume.assumeTrue;

/**
 * {@code list_analyzers} reports every analyzer with its description on a program nothing has
 * analysed yet.
 *
 * <p>Analyzer descriptions are not stored in the program: the {@code AutoAnalysisManager}
 * registers them when it is created for the program. A freshly opened program has none, and an
 * agent sees no explanation for an analyzer an extension turned off on purpose.
 */
public class AnalyzerDescriptionsGhidraTest {

    private ProgramBuilder builder;
    private ProgramDB program;

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
        // A running Ghidra has searched for analyzers at startup; a test JVM has not.
        ClassSearcher.search(TaskMonitor.DUMMY);
    }

    @Before
    public void setUp() throws Exception {
        builder = new ProgramBuilder("analyzers", ProgramBuilder._X64, "gcc", this);
        program = builder.getProgram();
        builder.createMemory(".text", "0x1000", 0x100);
    }

    @After
    public void tearDown() {
        if (builder != null) {
            builder.dispose();
        }
    }

    private AnalysisService service() {
        HeadlessProgramProvider provider = new HeadlessProgramProvider();
        provider.trackOpenProgram(program);
        DirectThreadingStrategy threading = new DirectThreadingStrategy();
        return new AnalysisService(provider, threading, new FunctionService(provider, threading));
    }

    @Test
    @SuppressWarnings("unchecked")
    public void listAnalyzersDescribesStockAnalyzersOnAnUnanalysedProgram() {
        Response r = service().listAnalyzers(program);
        assertTrue(r.toJson(), r instanceof Response.Ok);
        List<Map<String, Object>> entries =
            (List<Map<String, Object>>) ((Map<String, Object>) ((Response.Ok) r).data()).get("analyzers");
        Map<String, Object> sharedReturn = entries.stream()
            .filter(e -> "Shared Return Calls".equals(e.get("name")))
            .findFirst()
            .orElseThrow(() -> new AssertionError("Shared Return Calls not listed: " + entries));
        Object description = sharedReturn.get("description");
        assertNotNull("no description for Shared Return Calls", description);
        assertFalse(description.toString().isBlank());
    }

    @Test
    public void configureAnalyzerDescribesTheAnalyzer() {
        Response r = service().configureAnalyzer("Shared Return Calls", null, program);
        assertTrue(r.toJson(), r instanceof Response.Ok);
        @SuppressWarnings("unchecked")
        Map<String, Object> body = (Map<String, Object>) ((Response.Ok) r).data();
        assertNotNull("no description in configure_analyzer", body.get("description"));
    }
}
