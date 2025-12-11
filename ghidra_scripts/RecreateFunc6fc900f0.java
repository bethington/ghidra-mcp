//Recreate function at 0x6fc900f0 with correct bounds
//@author GhidraMCP
//@category Repair

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.app.cmd.function.CreateFunctionCmd;

public class RecreateFunc6fc900f0 extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address startAddr = toAddr(0x6fc900f0L);
        Address endAddr = toAddr(0x6fc9013bL);  // After the second RET 8
        
        // Remove existing function if present
        Function existingFunc = getFunctionAt(startAddr);
        if (existingFunc != null) {
            println("Removing existing function: " + existingFunc.getName());
            removeFunction(existingFunc);
        }
        
        // Disassemble the range
        println("Disassembling from " + startAddr + " to " + endAddr);
        disassemble(startAddr);
        
        // Create function using CreateFunctionCmd for better analysis
        CreateFunctionCmd cmd = new CreateFunctionCmd(startAddr);
        cmd.applyTo(currentProgram, monitor);
        
        Function newFunc = getFunctionAt(startAddr);
        if (newFunc != null) {
            println("SUCCESS: Created function " + newFunc.getName());
            println("Entry: " + newFunc.getEntryPoint());
            println("Body: " + newFunc.getBody());
            
            // Print instruction count
            InstructionIterator iter = currentProgram.getListing().getInstructions(newFunc.getBody(), true);
            int count = 0;
            while (iter.hasNext()) {
                iter.next();
                count++;
            }
            println("Instruction count: " + count);
        } else {
            println("FAILED to create function");
        }
    }
}
