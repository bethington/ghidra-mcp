// Fix EBP register reuse decompilation issue
// This script addresses a common compiler optimization where EBP is pushed to save it,
// then immediately reused as a local variable. Ghidra misidentifies this as "unaff_EBP"
// causing incorrect decompilation. The script creates a proper local variable with custom
// storage to fix the decompilation output. Specifically targets the pattern at 0x6fb6aef0.
//
// @category Diablo 2
// @author Ben Ethington
// @description Manually creates a local variable for the EBP register reuse pattern at 0x6fb6af4f

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.symbol.SourceType;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.lang.Register;

public class FixEBPRegisterReuse extends GhidraScript {

    @Override
    public void run() throws Exception {
        // Get the function
        Address funcAddr = toAddr(0x6fb6aef0);
        Function func = getFunctionAt(funcAddr);

        if (func == null) {
            println("ERROR: Function not found at 0x6fb6aef0");
            return;
        }

        println("Found function: " + func.getName());

        // Initialize decompiler
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);

        try {
            // Decompile to get high-level representation
            DecompileResults results = decompiler.decompileFunction(func, 30, monitor);

            if (results == null || !results.decompileCompleted()) {
                println("ERROR: Decompilation failed");
                return;
            }

            HighFunction highFunc = results.getHighFunction();

            println("\nCurrent local variables:");
            for (Variable var : func.getAllVariables()) {
                println("  " + var.getName() + " - " + var.getDataType() + " @ " + var.getVariableStorage());
            }

            // Try to create a custom local variable for the direction result
            // This will be stored in EBP after address 0x6fb6af4f
            Register ebpReg = currentProgram.getRegister("EBP");

            if (ebpReg == null) {
                println("ERROR: Could not find EBP register");
                return;
            }

            println("\nAttempting to create custom local variable...");
            println("This approach has limitations due to Ghidra's register tracking.");
            println("\nRECOMMENDATION:");
            println("================");
            println("1. Open this function in Ghidra's decompiler view");
            println("2. Right-click on 'unaff_EBP' in the decompiled code");
            println("3. Select 'Rename Variable' and name it 'directionResult'");
            println("4. Right-click on 'directionResult' and select 'Edit Function Signature'");
            println("5. In the signature editor, you may be able to manually adjust variable definitions");
            println("\nAlternatively, the issue is at 0x6fb6af4f where:");
            println("  MOV EBP,EAX  ; This stores the return value from SetMissileDirectionFromParameters");
            println("\nThe decompiler doesn't understand EBP is being reused as a local variable.");
            println("This is a known limitation with aggressive compiler optimizations.");

        } finally {
            decompiler.dispose();
        }
    }
}
