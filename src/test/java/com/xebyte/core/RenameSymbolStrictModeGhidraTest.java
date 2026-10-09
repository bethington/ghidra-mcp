package com.xebyte.core;

import com.xebyte.headless.DirectThreadingStrategy;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.symbol.Symbol;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.File;

import static org.junit.Assert.*;
import static org.junit.Assume.assumeTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * rename_symbol takes the same per-call strict_mode override rename_function does: a
 * convention miss is refused under enforce, with the reason and the override named, and
 * applied with a warning under warn.
 */
public class RenameSymbolStrictModeGhidraTest {

    private ProgramBuilder builder;
    private ProgramDB program;
    private SymbolLabelService symbols;

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
        builder = new ProgramBuilder("rename-symbol-strict", ProgramBuilder._X64, "gcc", this);
        program = builder.getProgram();
        builder.createMemory(".data", "0x4000", 0x100);
        builder.applyDataType("0x4010", new DWordDataType());
        ProgramProvider provider = mock(ProgramProvider.class);
        when(provider.getAllOpenPrograms()).thenReturn(new ghidra.program.model.listing.Program[] {program});
        when(provider.getCurrentProgram()).thenReturn(program);
        when(provider.getProgram(any())).thenReturn(program);
        when(provider.resolveProgram(any())).thenReturn(program);
        symbols = new SymbolLabelService(provider, new DirectThreadingStrategy());
    }

    @After
    public void tearDown() {
        if (builder != null) {
            builder.dispose();
        }
    }

    private String primaryName() {
        Symbol s = program.getSymbolTable().getPrimarySymbol(builder.addr("0x4010"));
        return s == null ? null : s.getName();
    }

    @Test
    public void enforceRefusesWithTheReasonAndTheOverride() {
        Response r = symbols.renameSymbol("0x4010", "counter", "data", "", "", "enforce");
        String json = r.toJson();
        assertTrue(json, json.contains("\"name_quality\""));
        assertTrue(json, json.contains("\"message\""));
        assertTrue(json, json.contains("strict_mode=warn"));
        assertNotEquals("counter", primaryName());
    }

    @Test
    public void warnAppliesTheNameAndReportsTheMiss() {
        Response r = symbols.renameSymbol("0x4010", "counter", "data", "", "", "warn");
        assertTrue(r.toJson(), r instanceof Response.Ok);
        assertFalse(r.toJson(), r.toJson().contains("\"status\":\"rejected\""));
        assertEquals("counter", primaryName());
    }

    @Test
    public void theOverrideDoesNotOutliveTheCall() {
        symbols.renameSymbol("0x4010", "counter", "data", "", "", "warn");
        Response r = symbols.renameSymbol("0x4010", "other", "data", "", "", "enforce");
        assertTrue(r.toJson(), r.toJson().contains("\"name_quality\""));
        assertEquals("counter", primaryName());
    }
}
