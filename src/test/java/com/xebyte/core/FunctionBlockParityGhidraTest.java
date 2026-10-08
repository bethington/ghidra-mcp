package com.xebyte.core;

import com.xebyte.core.tree.FunctionBlock;
import com.xebyte.core.tree.SweepJob;
import ghidra.GhidraApplicationLayout;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.decompiler.DecompInterface;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.File;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeTrue;

/**
 * The tree's blocks and {@code /get_functions} show the same fields with the same content.
 *
 * <p>Both are rendered from {@link FunctionFacts}, but through different decompilers: the
 * bundle builds a fresh one per call, a sweep reuses one across the program. This builds a
 * real program, renders a function's block through the sweep path, renders the same function
 * from a fresh decompile, and requires the two to be identical; and it requires every field
 * {@code /get_functions} can return to appear in a block, so a new field cannot be added to
 * one surface only.
 */
public class FunctionBlockParityGhidraTest {

    /** Facts field → the block header key that carries it. */
    private static final Map<String, String> FIELD_TO_HEADER = new LinkedHashMap<>();
    static {
        FIELD_TO_HEADER.put("signature", "signature");
        FIELD_TO_HEADER.put("classification", "classification");
        FIELD_TO_HEADER.put("return_type", "return_type");
        FIELD_TO_HEADER.put("entry_point", "fn");
        FIELD_TO_HEADER.put("body_start", "body");
        FIELD_TO_HEADER.put("body_end", "body");
        FIELD_TO_HEADER.put("decompiled_code", "body");
        FIELD_TO_HEADER.put("plate_comment", "plate");
        FIELD_TO_HEADER.put("comments", "comment");
        FIELD_TO_HEADER.put("labels", "label");
        FIELD_TO_HEADER.put("tags", "tags");
        FIELD_TO_HEADER.put("parameters", "param");
        FIELD_TO_HEADER.put("locals", "local");
        FIELD_TO_HEADER.put("callers", "callers");
        FIELD_TO_HEADER.put("callees", "calls");
        FIELD_TO_HEADER.put("xrefs", "xref");
        FIELD_TO_HEADER.put("jump_targets", "jump");
        FIELD_TO_HEADER.put("refs", "refs");
        // Rendered when present; not in a default tree (see FunctionBlock.TREE_FIELDS).
        FIELD_TO_HEADER.put("call_context", "context");
        FIELD_TO_HEADER.put("disassembly", "disasm");
    }

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
        builder = new ProgramBuilder("parity", ProgramBuilder._X64, "gcc", this);
        program = builder.getProgram();
        builder.createMemory(".text", "0x1000", 0x1100);
        // caller: CALL 0x2000; TEST EAX,EAX; JZ +5; MOV EAX,1; RET
        builder.setBytes("0x1000", "e8 fb 0f 00 00 85 c0 74 05 b8 01 00 00 00 c3");
        // callee: MOV EAX,[0x1800]; RET   (a data reference)
        builder.setBytes("0x2000", "8b 04 25 00 18 00 00 c3");
        builder.setBytes("0x1800", "00 30 00 00");
        builder.withTransaction(() -> {
            DisassembleCommand command = new DisassembleCommand(builder.addr("0x1000"),
                new AddressSet(builder.addr("0x1000"), builder.addr("0x100e")), true);
            command.applyTo(program, TaskMonitor.DUMMY);
            new DisassembleCommand(builder.addr("0x2000"),
                new AddressSet(builder.addr("0x2000"), builder.addr("0x2007")), true)
                .applyTo(program, TaskMonitor.DUMMY);
        });
        Function callee = builder.createFunction("0x2000");
        Function caller = builder.createFunction("0x1000");
        builder.withTransaction(() -> {
            try {
                annotate(caller, callee);
            } catch (Exception e) {
                throw new AssertionError(e);
            }
        });
    }

    private void annotate(Function caller, Function callee) throws Exception {
        {
            caller.setName("check_ready", SourceType.USER_DEFINED);
            callee.setName("read_status", SourceType.USER_DEFINED);
            caller.setComment("Checks readiness.\nAlgorithm: call read_status");
            caller.addTag("hal");
            program.getListing().setComment(builder.addr("0x1005"), CodeUnit.EOL_COMMENT, "zero means busy");
            program.getSymbolTable().createLabel(builder.addr("0x100e"), "done", SourceType.USER_DEFINED);
        }
    }

    @After
    public void tearDown() {
        if (builder != null) {
            builder.dispose();
        }
    }

    @Test
    public void aSweptBlockMatchesAFreshlyDecompiledBundleFieldForField() {
        for (String entry : new String[] {"0x1000", "0x2000"}) {
            Function func = program.getFunctionManager().getFunctionAt(builder.addr(entry));

            // The sweep's path: one pooled decompiler.
            DecompInterface pooled = ServiceUtils.createConfiguredDecompiler(program,
                FunctionFacts::configureDecompiler);
            String block;
            try {
                block = FunctionBlock.build(func, pooled, 30, TaskMonitor.DUMMY, "c00",
                    "address-band", 0.5, false, program.getName()).text();
            } finally {
                pooled.dispose();
            }

            // The bundle's path: a fresh decompiler for this one call.
            Map<String, Object> facts = FunctionFacts.build(program, func, FunctionBlock.TREE_FIELDS, f -> {
                DecompInterface fresh = ServiceUtils.createConfiguredDecompiler(program,
                    FunctionFacts::configureDecompiler);
                try {
                    return fresh.decompileFunction(f, 30, TaskMonitor.DUMMY);
                } finally {
                    fresh.dispose();
                }
            });

            Map<String, Object> parsed = FunctionBlock.parse(block);
            String body = String.valueOf(facts.get("decompiled_code"));
            String expected = FunctionBlock.render(facts, body, new FunctionBlock.Placement(
                "c00", "address-band", 0.5, false,
                java.time.Instant.parse(String.valueOf(parsed.get("dts"))),
                SweepJob.functionResourceUri(program.getName(), func.getEntryPoint().toString(false))));
            assertEquals("block for " + func.getName() + " must equal the bundle's facts rendered",
                expected, block);
        }
    }

    @Test
    public void everyBundleFieldHasAPlaceInTheBlock() {
        Set<String> unmapped = new java.util.TreeSet<>(FunctionFacts.FIELDS);
        unmapped.removeAll(FIELD_TO_HEADER.keySet());
        assertTrue("fields /get_functions returns that a tree block never shows: " + unmapped,
            unmapped.isEmpty());

        Function caller = program.getFunctionManager().getFunctionAt(builder.addr("0x1000"));
        DecompInterface pooled = ServiceUtils.createConfiguredDecompiler(program,
            FunctionFacts::configureDecompiler);
        Map<String, Object> parsed;
        try {
            parsed = FunctionBlock.parse(FunctionBlock.build(caller, pooled, 30, TaskMonitor.DUMMY,
                "c00", "address-band", 0.5, false, program.getName()).text());
        } finally {
            pooled.dispose();
        }
        for (String header : new String[] {"signature", "classification", "return_type", "body",
                "plate", "comment", "label", "tags", "calls", "jump"}) {
            assertTrue("block lacks " + header + ": " + parsed.keySet(), parsed.containsKey(header));
        }
        assertEquals("hal", parsed.get("tags"));
        assertTrue(String.valueOf(parsed.get("calls")).startsWith("read_status@"));
        assertTrue(String.valueOf(parsed.get("comment")), String.valueOf(parsed.get("comment")).contains("eol zero means busy"));
        assertTrue(String.valueOf(parsed.get("label")).contains("done"));
        assertTrue("the decompiled body shows the callee", String.valueOf(parsed.get("body")).contains("read_status"));

        Function callee = program.getFunctionManager().getFunctionAt(builder.addr("0x2000"));
        DecompInterface again = ServiceUtils.createConfiguredDecompiler(program,
            FunctionFacts::configureDecompiler);
        try {
            Map<String, Object> c = FunctionBlock.parse(FunctionBlock.build(callee, again, 30,
                TaskMonitor.DUMMY, "c00", "address-band", 0.5, false, program.getName()).text());
            assertTrue(String.valueOf(c.get("callers")).startsWith("check_ready@"));
            assertTrue(String.valueOf(c.get("refs")), String.valueOf(c.get("refs")).contains("0x00001800"));
            assertTrue(c.containsKey("xref"));
        } finally {
            again.dispose();
        }
    }
}
