package com.xebyte.core;

import com.xebyte.core.tree.BlockSplicer;
import com.xebyte.core.AddressKeys;
import com.xebyte.core.tree.TreeLayout;
import com.xebyte.core.tree.TreeFiles;
import com.xebyte.core.tree.FunctionBlock;
import ghidra.GhidraApplicationLayout;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.decompiler.DecompInterface;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.task.TaskMonitor;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.File;

import static org.junit.Assert.*;
import static org.junit.Assume.assumeTrue;

/**
 * Two functions at one offset, in the default space and an overlay, stay two functions in a
 * tree. Bare hex gave them one key: one by-address row, one file name, and a splice of
 * either could replace the other's block.
 */
public class OverlayAddressKeysGhidraTest {

    private ProgramBuilder builder;
    private ProgramDB program;
    private Function base;
    private Function overlay;

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
        builder = new ProgramBuilder("overlay", ProgramBuilder._X64, "gcc", this);
        program = builder.getProgram();
        builder.createMemory(".text", "0x1000", 0x100);
        MemoryBlock ovl = builder.createOverlayMemory("OVL", "0x1000", 0x100);
        Address ovlEntry = ovl.getStart();
        // MOV EAX,1; RET   and   MOV EAX,2; RET
        builder.setBytes("0x1000", "b8 01 00 00 00 c3");
        builder.withTransaction(() -> {
            try {
                program.getMemory().setBytes(ovlEntry, new byte[] {(byte) 0xb8, 2, 0, 0, 0, (byte) 0xc3});
            } catch (Exception e) {
                throw new AssertionError(e);
            }
            new DisassembleCommand(builder.addr("0x1000"), new AddressSet(builder.addr("0x1000"),
                builder.addr("0x1005")), true).applyTo(program, TaskMonitor.DUMMY);
            new DisassembleCommand(ovlEntry, new AddressSet(ovlEntry, ovlEntry.add(5)), true)
                .applyTo(program, TaskMonitor.DUMMY);
            try {
                program.getFunctionManager().createFunction("in_overlay", ovlEntry,
                    new AddressSet(ovlEntry, ovlEntry.add(5)), ghidra.program.model.symbol.SourceType.USER_DEFINED);
            } catch (Exception e) {
                throw new AssertionError(e);
            }
        });
        base = builder.createFunction("0x1000");
        overlay = program.getFunctionManager().getFunctionAt(ovlEntry);
        assertNotNull(overlay);
    }

    @After
    public void tearDown() {
        if (builder != null) {
            builder.dispose();
        }
    }

    @Test
    public void theDefaultSpaceStaysBareAndTheOverlayIsQualified() {
        assertEquals("00001000", AddressKeys.of(base));
        assertEquals("OVL:00001000", AddressKeys.of(overlay));
        assertSame(base, AddressKeys.function(program, "00001000"));
        assertSame(overlay, AddressKeys.function(program, "OVL:00001000"));
        assertEquals("a caller's spelling of the default space becomes the bare key",
            "00001000", AddressKeys.canonical(program, "0x1000"));
    }

    @Test
    public void bothBlocksLiveInOneFileAndEachIsFoundByItsOwnKey() {
        String a = block(base);
        String b = block(overlay);
        assertTrue(a, a.startsWith("// fn: FUN_00001000 @ 00001000 size="));
        assertTrue(b, b.startsWith("// fn: in_overlay @ OVL:00001000 size="));
        assertTrue("the resource URI carries the space: " + b,
            b.contains("/OVL:00001000\n"));
        assertEquals("OVL:00001000", TreeFiles.addressFromChunk(b));

        String file = a + "\n" + b;
        assertSame(null, BlockSplicer.findBlock(file, "00001001"));
        assertTrue(BlockSplicer.findBlock(file, "00001000").contains("FUN_00001000"));
        assertTrue(BlockSplicer.findBlock(file, "OVL:00001000").contains("in_overlay"));
    }

    @Test
    public void theyNeverShareAFileName() {
        assertEquals("0000000000001000.c", TreeLayout.compartmentFileName("00001000", 8));
        assertEquals("OVL_0000000000001000.c", TreeLayout.compartmentFileName("OVL:00001000", 8));
    }

    private String block(Function f) {
        DecompInterface decomp = ServiceUtils.createConfiguredDecompiler(program,
            FunctionFacts::configureDecompiler);
        try {
            return FunctionBlock.build(f, decomp, 30, TaskMonitor.DUMMY, "c00", "address-band",
                0.5, false, program.getName()).text();
        } finally {
            decomp.dispose();
        }
    }
}
