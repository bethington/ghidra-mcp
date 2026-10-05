package com.xebyte.core;

import ghidra.GhidraApplicationLayout;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.decompiler.DecompInterface;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
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
 * A register reached as base + offset is listed in {@code refs} by its own address.
 *
 * <p>The firmware shape: the base sits in a literal-pool word, the code loads it and writes
 * at an offset. No reference names {@code 0x40003c0c}; the C prints the base plus 0xc. Only
 * the decompiled p-code has the sum, once the pool word is read-only and the decompiler folds
 * it. Measured on the monsgeek firmware before this: nothing a function read returned named
 * {@code 0x40003c0c}.
 */
public class AddressRefsGhidraTest {

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
    }

    @Before
    public void setUp() throws Exception {
        builder = new ProgramBuilder("refs", ProgramBuilder._X64, "gcc", this);
        program = builder.getProgram();
        builder.createMemory(".text", "0x1000", 0x100);
        builder.createMemory(".rodata", "0x3000", 0x100);
        builder.createUninitializedMemory("PERIPH", "0x40003c00", 0x100);
        // MOV RAX,[0x3000]; MOV dword ptr [RAX+0xc],1; RET
        builder.setBytes("0x1000", "48 8b 04 25 00 30 00 00 c7 40 0c 01 00 00 00 c3");
        builder.setBytes("0x3000", "00 3c 00 40 00 00 00 00");
        builder.withTransaction(() -> {
            program.getMemory().getBlock(".rodata").setWrite(false);
            new DisassembleCommand(builder.addr("0x1000"),
                new AddressSet(builder.addr("0x1000"), builder.addr("0x100f")), true)
                .applyTo(program, TaskMonitor.DUMMY);
        });
        builder.createFunction("0x1000");
    }

    @After
    public void tearDown() {
        if (builder != null) {
            builder.dispose();
        }
    }

    @SuppressWarnings("unchecked")
    private List<String> refs() {
        Function func = program.getFunctionManager().getFunctionAt(builder.addr("0x1000"));
        Map<String, Object> facts = FunctionFacts.build(program, func,
            new FunctionFacts.Options(java.util.Set.of("refs"), false, 0, 3, false), f -> {
                DecompInterface d = ServiceUtils.createConfiguredDecompiler(program,
                    FunctionFacts::configureDecompiler);
                try {
                    return d.decompileFunction(f, 30, TaskMonitor.DUMMY);
                } finally {
                    d.dispose();
                }
            });
        return (List<String>) facts.get("refs");
    }

    @Test
    public void theRegisterAndThePoolValueAreRefsWithTheWordTheValueCameFrom() {
        List<String> refs = refs();
        assertTrue("the register itself, from the folded store: " + refs, refs.contains("0x40003c0c"));
        assertTrue("the base, with the pool word it was loaded from: " + refs,
            refs.contains("0x40003c00<0x00003000"));
        assertTrue("the pool word itself: " + refs, refs.contains("0x00003000"));
    }

    @Test
    public void aWritablePoolWordDoesNotFoldSoTheRegisterIsNotARef() throws Exception {
        builder.withTransaction(() -> program.getMemory().getBlock(".rodata").setWrite(true));
        List<String> refs = refs();
        assertFalse("a writable word can change at run time; the decompiler must not fold it: " + refs,
            refs.contains("0x40003c0c"));
    }
}
