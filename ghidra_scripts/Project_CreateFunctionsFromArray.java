// Create Functions From Array
//
// Reads an array of function pointers starting at the current cursor address, disassembles each target, and creates functions. Useful for processing vtables and dispatch tables.
//
// Usage: Place cursor at the start of a pointer array, then run from Script Manager.
// Output: Creates functions at each address in the pointer array.
//
// @author Ben Ethington
// @category Diablo 2.Project
// @description Create functions from a function pointer array
// @menupath Diablo 2.Project.Create Functions From Array

import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.model.address.Address;

public class Project_CreateFunctionsFromArray extends GhidraScript {

    @Override
    public void run() throws Exception {
        Address base = currentAddress;

        for (int i = 0; i < 52; i++) {
            monitor.checkCanceled();
            int number = currentProgram.getMemory().getInt(base.add((long)i * 4));
            Address addr = currentProgram.getAddressFactory().getDefaultAddressSpace()
                .getAddress(Integer.toUnsignedLong(number));

            DisassembleCommand disCmd = new DisassembleCommand(addr, null, false);
            disCmd.applyTo(currentProgram, monitor);

            CreateFunctionCmd funcCmd = new CreateFunctionCmd(addr);
            funcCmd.applyTo(currentProgram);
        }
    }
}
