package com.xebyte.core;

import com.xebyte.headless.DirectThreadingStrategy;
import com.xebyte.headless.HeadlessProgramProvider;
import ghidra.GhidraApplicationLayout;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.File;

import static org.junit.Assert.*;
import static org.junit.Assume.assumeTrue;

public class FunctionServiceClearFlowAndRepairGhidraTest {

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
        builder = new ProgramBuilder("clear-flow-repair", ProgramBuilder._X64, "gcc", this);
        program = builder.getProgram();
        builder.createMemory(".text", "0x1000", 0x1100);

        // CALL 0x2000; TEST EAX,EAX; MOV EAX,1; RET
        builder.setBytes("0x1000", "e8 fb 0f 00 00 85 c0 b8 01 00 00 00 c3");
        builder.setBytes("0x2000", "c3");
        builder.disassemble("0x2000", 1);
        Function target = builder.createFunction("0x2000");
        builder.withTransaction(() -> target.setNoReturn(true));

        builder.withTransaction(() -> {
            DisassembleCommand command = new DisassembleCommand(builder.addr("0x1000"),
                new AddressSet(builder.addr("0x1000"), builder.addr("0x100c")), true);
            assertTrue(command.getStatusMsg(), command.applyTo(program, TaskMonitor.DUMMY));
        });
        builder.createFunction("0x1000");
    }

    @After
    public void tearDown() {
        if (builder != null) {
            builder.dispose();
        }
    }

    @Test
    public void repairsFallthroughAfterCalleeChangesFromNoReturnToReturning() {
        Instruction call = program.getListing().getInstructionAt(builder.addr("0x1000"));
        assertEquals(FlowOverride.CALL_RETURN, call.getFlowOverride());
        assertNull(program.getListing().getInstructionAt(builder.addr("0x1005")));

        Function target = program.getFunctionManager().getFunctionAt(builder.addr("0x2000"));
        builder.withTransaction(() -> target.setNoReturn(false));

        HeadlessProgramProvider provider = new HeadlessProgramProvider();
        provider.setCurrentProgram(program);
        FunctionService service = new FunctionService(provider, new DirectThreadingStrategy());
        Response response = service.clearFlowAndRepair("0x1000", "0x100d", "");

        assertTrue(response.toJson(), response instanceof Response.Ok);
        assertNotNull("post-call fallthrough was not disassembled",
            program.getListing().getInstructionAt(builder.addr("0x1005")));
        Instruction repairedCall = program.getListing().getInstructionAt(builder.addr("0x1000"));
        assertNotNull("call instruction was not restored", repairedCall);
        assertEquals(FlowOverride.NONE, repairedCall.getFlowOverride());
    }

    @Test
    public void leavesCallReturnOverrideWhenTargetIsStillNoReturn() {
        HeadlessProgramProvider provider = new HeadlessProgramProvider();
        provider.setCurrentProgram(program);
        FunctionService service = new FunctionService(provider, new DirectThreadingStrategy());

        Response response = service.clearFlowAndRepair("0x1000", "0x100d", "");

        assertTrue(response.toJson(), response instanceof Response.Ok);
        Instruction call = program.getListing().getInstructionAt(builder.addr("0x1000"));
        assertNotNull("call instruction was not retained", call);
        assertEquals(FlowOverride.CALL_RETURN, call.getFlowOverride());
        assertNull(program.getListing().getInstructionAt(builder.addr("0x1005")));
        assertTrue(response.toJson(),
            response.toJson().contains("noreturn_call_boundaries_in_seed"));
        assertTrue(response.toJson(), response.toJson().contains("1005"));
    }

    @Test
    public void preservesCallReturnCreatedByNonReturningCallFixup() {
        Function target = program.getFunctionManager().getFunctionAt(builder.addr("0x2000"));
        builder.withTransaction(() -> {
            target.setNoReturn(false);
            target.setCallFixup("x86_return_thunk");
        });

        Response response = service().clearFlowAndRepair("0x1000", "0x100d", "");

        assertTrue(response.toJson(), response instanceof Response.Ok);
        Instruction call = program.getListing().getInstructionAt(builder.addr("0x1000"));
        assertNotNull(call);
        assertEquals(FlowOverride.CALL_RETURN, call.getFlowOverride());
    }

    @Test
    public void failedRedisassemblyRollsBackClearedCall() {
        Function target = program.getFunctionManager().getFunctionAt(builder.addr("0x2000"));
        builder.withTransaction(() -> {
            target.setNoReturn(false);
            program.getMemory().getBlock(".text").setExecute(false);
            program.getOptions(Program.DISASSEMBLER_PROPERTIES).setBoolean(
                Disassembler.RESTRICT_DISASSEMBLY_TO_EXECUTE_MEMORY_PROPERTY, true);
        });

        HeadlessProgramProvider provider = new HeadlessProgramProvider();
        provider.setCurrentProgram(program);
        FunctionService service = new FunctionService(provider, new DirectThreadingStrategy());
        Response response = service.clearFlowAndRepair("0x1000", "0x100d", "");

        assertTrue(response.toJson(), response instanceof Response.Err);
        Instruction call = program.getListing().getInstructionAt(builder.addr("0x1000"));
        assertNotNull("cleared call was not restored by transaction rollback", call);
        assertEquals(FlowOverride.CALL_RETURN, call.getFlowOverride());
        assertNull(program.getListing().getInstructionAt(builder.addr("0x1005")));
    }

    @Test
    public void refusesBeforeRepairWhenLaterNoReturnCallWouldDeleteDefinedContinuation() {
        configureTwoCallProgram(true);

        Function firstTarget = program.getFunctionManager().getFunctionAt(builder.addr("0x2000"));
        builder.withTransaction(() -> firstTarget.setNoReturn(false));

        Response response = service().clearFlowAndRepair("0x1000", "0x1011", "");

        assertTrue(response.toJson(), response instanceof Response.Err);
        assertTrue(response.toJson(), response.toJson().contains("1005"));
        assertTrue(response.toJson(), response.toJson().contains("2010"));
        assertEquals(FlowOverride.CALL_RETURN,
            program.getListing().getInstructionAt(builder.addr("0x1000")).getFlowOverride());
        assertNotNull(program.getListing().getInstructionAt(builder.addr("0x100a")));
    }

    @Test
    public void restoresCallerPastTwoCorrectedNoReturnCalleesInOneRepair() {
        configureTwoCallProgram(true);
        Function firstTarget = program.getFunctionManager().getFunctionAt(builder.addr("0x2000"));
        Function secondTarget = program.getFunctionManager().getFunctionAt(builder.addr("0x2010"));
        builder.withTransaction(() -> {
            firstTarget.setNoReturn(false);
            secondTarget.setNoReturn(false);
        });

        Response response = service().clearFlowAndRepair("0x1000", "0x1011", "");

        assertTrue(response.toJson(), response instanceof Response.Ok);
        assertEquals(FlowOverride.NONE,
            program.getListing().getInstructionAt(builder.addr("0x1000")).getFlowOverride());
        assertEquals(FlowOverride.NONE,
            program.getListing().getInstructionAt(builder.addr("0x1005")).getFlowOverride());
        assertNotNull(program.getListing().getInstructionAt(builder.addr("0x100a")));
        assertNotNull(program.getListing().getInstructionAt(builder.addr("0x100f")));
    }

    @Test
    public void refusesBeforeRepairWhenReturningCallWouldBecomeNoReturnDuringRedisassembly() {
        configureTwoCallProgram(false);
        Function secondTarget = program.getFunctionManager().getFunctionAt(builder.addr("0x2010"));
        builder.withTransaction(() -> secondTarget.setNoReturn(true));

        assertEquals(FlowOverride.NONE,
            program.getListing().getInstructionAt(builder.addr("0x1005")).getFlowOverride());
        Response response = service().clearFlowAndRepair("0x1000", "0x1011", "");

        assertTrue(response.toJson(), response instanceof Response.Err);
        assertTrue(response.toJson(), response.toJson().contains("1005"));
        assertTrue(response.toJson(), response.toJson().contains("2010"));
        assertNotNull(program.getListing().getInstructionAt(builder.addr("0x100a")));
        assertEquals(FlowOverride.NONE,
            program.getListing().getInstructionAt(builder.addr("0x1005")).getFlowOverride());
    }

    private void configureTwoCallProgram(boolean targetsStartNoReturn) {
        builder.dispose();
        try {
            builder = new ProgramBuilder("clear-flow-repair-two-calls", ProgramBuilder._X64,
                "gcc", this);
            program = builder.getProgram();
            builder.createMemory(".text", "0x1000", 0x1100);
            // CALL 0x2000; CALL 0x2010; MOV EAX,1; RET
            builder.setBytes("0x1000", "e8 fb 0f 00 00 e8 06 10 00 00 b8 01 00 00 00 c3");
            builder.setBytes("0x2000", "c3");
            builder.setBytes("0x2010", "c3");
            builder.disassemble("0x2000", 1);
            builder.disassemble("0x2010", 1);
            Function firstTarget = builder.createFunction("0x2000");
            Function secondTarget = builder.createFunction("0x2010");
            builder.withTransaction(() -> {
                firstTarget.setNoReturn(targetsStartNoReturn);
                secondTarget.setNoReturn(targetsStartNoReturn);
            });
            builder.withTransaction(() -> {
                DisassembleCommand command = new DisassembleCommand(builder.addr("0x1000"),
                    new AddressSet(builder.addr("0x1000"), builder.addr("0x100f")), true);
                assertTrue(command.getStatusMsg(), command.applyTo(program, TaskMonitor.DUMMY));
                if (targetsStartNoReturn) {
                    assertTrue(new DisassembleCommand(builder.addr("0x1005"), null, true)
                        .applyTo(program, TaskMonitor.DUMMY));
                    assertTrue(new DisassembleCommand(builder.addr("0x100a"), null, true)
                        .applyTo(program, TaskMonitor.DUMMY));
                }
            });
            builder.createFunction("0x1000");
        }
        catch (Exception e) {
            throw new AssertionError(e);
        }
    }

    private FunctionService service() {
        HeadlessProgramProvider provider = new HeadlessProgramProvider();
        provider.setCurrentProgram(program);
        return new FunctionService(provider, new DirectThreadingStrategy());
    }
}
