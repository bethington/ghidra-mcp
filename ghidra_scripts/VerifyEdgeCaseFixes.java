// Verify edge case fixes for calling convention detection
// @author GhidraMCP
// @category Analysis
// @keybinding 
// @menupath Analysis.D2.Verify Edge Case Fixes
// @toolbar 

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;

public class VerifyEdgeCaseFixes extends GhidraScript {
    
    @Override
    public void run() throws Exception {
        println("========================================");
        println("EDGE CASE VERIFICATION");
        println("========================================");
        println("Testing functions identified with detection issues");
        println();
        
        // Test cases from EDGE_CASE_FINDINGS.md
        TestCase[] testCases = new TestCase[] {
            new TestCase(
                0x6fd6a3d0L,
                "GetUnitOrItemProperties",
                "__stdcall",
                7,
                "RET 0x1c with stack loads"
            ),
            new TestCase(
                0x6fd6e630L,
                "ValidateAndGetUnitLevel",
                "__stdcall",
                2,
                "RET 0x8 with stack loads"
            ),
            new TestCase(
                0x6fd6a5b0L,
                "CheckUnitStateBits",
                "__stdcall",
                1,
                "RET 0x4 with stack load"
            ),
            new TestCase(
                0x6fd6aa00L,
                "GenerateUnitPropertyByTypeAndIndex",
                "__stdcall",
                3,
                "RET 0x1c (should remain __stdcall)"
            )
        };
        
        int passed = 0;
        int failed = 0;
        
        for (TestCase test : testCases) {
            Address addr = toAddr(test.address);
            Function func = getFunctionAt(addr);
            
            if (func == null) {
                println("[SKIP] " + String.format("0x%08x", test.address) + 
                       " - Function not found");
                continue;
            }
            
            String actualConv = func.getCallingConventionName();
            int actualParams = func.getParameterCount();
            
            boolean convMatch = actualConv.equals(test.expectedConvention);
            boolean paramMatch = (actualParams == test.expectedParamCount);
            
            if (convMatch && paramMatch) {
                passed++;
                println("[PASS] " + func.getName() + " @ " + addr);
                println("       Convention: " + actualConv + " ✓");
                println("       Parameters: " + actualParams + " ✓");
                println("       Reason: " + test.reason);
            } else {
                failed++;
                println("[FAIL] " + func.getName() + " @ " + addr);
                println("       Expected: " + test.expectedConvention + 
                       " with " + test.expectedParamCount + " params");
                println("       Actual:   " + actualConv + 
                       " with " + actualParams + " params");
                println("       Reason: " + test.reason);
                
                // Show assembly for debugging
                println("       First 5 instructions:");
                InstructionIterator iter = currentProgram.getListing()
                    .getInstructions(addr, true);
                int count = 0;
                while (iter.hasNext() && count < 5) {
                    Instruction inst = iter.next();
                    println("         " + inst.getAddressString(false, true) + ": " + 
                           inst.toString());
                    count++;
                }
            }
            println();
        }
        
        println("========================================");
        println("RESULTS");
        println("========================================");
        println("Passed: " + passed + " / " + (passed + failed));
        println("Failed: " + failed + " / " + (passed + failed));
        
        if (failed == 0) {
            println("\n✓ All edge cases handled correctly!");
        } else {
            println("\n✗ Some edge cases still failing. Review detection logic.");
        }
    }
    
    private static class TestCase {
        long address;
        String name;
        String expectedConvention;
        int expectedParamCount;
        String reason;
        
        TestCase(long address, String name, String expectedConvention, 
                 int expectedParamCount, String reason) {
            this.address = address;
            this.name = name;
            this.expectedConvention = expectedConvention;
            this.expectedParamCount = expectedParamCount;
            this.reason = reason;
        }
    }
}
