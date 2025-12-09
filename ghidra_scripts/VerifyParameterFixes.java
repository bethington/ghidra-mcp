// Verify parameter and calling convention fixes for specific test functions
// @author GhidraMCP
// @category Analysis
// @keybinding 
// @menupath Analysis.D2.Verify Parameter Fixes
// @toolbar 

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.scalar.*;
import java.util.*;

public class VerifyParameterFixes extends GhidraScript {
    
    @Override
    public void run() throws Exception {
        println("========================================");
        println("VERIFY PARAMETER AND CONVENTION FIXES");
        println("========================================");
        println();
        
        // Test functions with known assembly patterns
        List<TestCase> testCases = new ArrayList<>();
        
        // Test case 1: GetLevelDataByIndex - should be __stdcall with 1 param
        testCases.add(new TestCase(
            "GetLevelDataByIndex",
            "0x6fd5c990", 
            "__stdcall",
            1,
            "RET 0x4"
        ));
        
        // Test case 2: GetSkillDataByIndex - need to find actual address
        testCases.add(new TestCase(
            "GetSkillDataByIndex",
            "0x6fd719a0",
            "__stdcall",
            4,
            "RET 0x10"
        ));
        
        // Test case 3: GenerateRandomNumberInRange - should be __fastcall
        testCases.add(new TestCase(
            "GenerateRandomNumberInRange",
            null,  // Will look up by name
            "__fastcall",
            2,
            "RET"
        ));
        
        // Test case 4: GenerateRandomNumberInRangeAlt - should be __d2regcall
        testCases.add(new TestCase(
            "GenerateRandomNumberInRangeAlt",
            null,
            "__d2regcall",
            2,
            "RET"
        ));
        
        // Test case 5: GeneratePathNodeGrid - should be __d2call
        testCases.add(new TestCase(
            "GeneratePathNodeGrid",
            "0x6fd5f220",
            "__d2call",
            1,
            "RET"
        ));
        
        int passed = 0;
        int failed = 0;
        
        for (TestCase test : testCases) {
            println("[TEST] " + test.functionName);
            
            Function func = null;
            
            // Find function
            if (test.address != null) {
                try {
                    Address addr = toAddr(test.address);
                    func = getFunctionAt(addr);
                } catch (Exception e) {
                    println("  ❌ Could not parse address: " + test.address);
                    failed++;
                    continue;
                }
            }
            
            if (func == null) {
                // Try finding by name
                func = getFirstFunction(test.functionName);
            }
            
            if (func == null) {
                println("  ❌ Function not found");
                failed++;
                continue;
            }
            
            // Verify calling convention
            String actualConvention = func.getCallingConventionName();
            boolean conventionMatches = actualConvention.equals(test.expectedConvention);
            
            // Verify parameter count
            int actualParamCount = func.getParameterCount();
            boolean paramCountMatches = actualParamCount == test.expectedParamCount;
            
            // Verify return instruction
            Instruction retInst = findReturnInstruction(func);
            boolean retMatches = false;
            int actualRetBytes = 0;
            
            if (retInst != null) {
                if (retInst.getNumOperands() > 0) {
                    try {
                        Object[] opObjs = retInst.getOpObjects(0);
                        if (opObjs != null && opObjs.length > 0 && opObjs[0] instanceof Scalar) {
                            actualRetBytes = (int)((Scalar)opObjs[0]).getValue();
                        }
                    } catch (Exception e) {
                        // No immediate
                    }
                }
                
                String retString = retInst.toString();
                retMatches = retString.contains(test.expectedRetPattern);
            }
            
            // Print results
            if (conventionMatches && paramCountMatches && retMatches) {
                println("  ✓ PASS");
                println("    Convention: " + actualConvention);
                println("    Parameters: " + actualParamCount);
                println("    Return: " + (actualRetBytes > 0 ? "RET 0x" + Integer.toHexString(actualRetBytes) : "RET"));
                passed++;
            } else {
                println("  ❌ FAIL");
                println("    Convention: " + actualConvention + 
                       (conventionMatches ? " ✓" : " ✗ (expected: " + test.expectedConvention + ")"));
                println("    Parameters: " + actualParamCount + 
                       (paramCountMatches ? " ✓" : " ✗ (expected: " + test.expectedParamCount + ")"));
                println("    Return: " + (actualRetBytes > 0 ? "RET 0x" + Integer.toHexString(actualRetBytes) : "RET") +
                       (retMatches ? " ✓" : " ✗ (expected: " + test.expectedRetPattern + ")"));
                failed++;
            }
            
            println();
        }
        
        println("========================================");
        println("VERIFICATION SUMMARY");
        println("========================================");
        println("Passed: " + passed);
        println("Failed: " + failed);
        println("Total: " + (passed + failed));
    }
    
    private Function getFirstFunction(String name) {
        FunctionManager funcManager = currentProgram.getFunctionManager();
        for (Function func : funcManager.getFunctions(true)) {
            if (func.getName().equals(name)) {
                return func;
            }
        }
        return null;
    }
    
    private Instruction findReturnInstruction(Function func) {
        Listing listing = currentProgram.getListing();
        InstructionIterator instIter = listing.getInstructions(func.getBody(), true);
        Instruction lastRet = null;
        
        while (instIter.hasNext()) {
            Instruction inst = instIter.next();
            if (inst.getMnemonicString().equalsIgnoreCase("RET")) {
                lastRet = inst;
            }
        }
        
        return lastRet;
    }
    
    private static class TestCase {
        String functionName;
        String address;
        String expectedConvention;
        int expectedParamCount;
        String expectedRetPattern;
        
        TestCase(String name, String addr, String convention, int paramCount, String retPattern) {
            this.functionName = name;
            this.address = addr;
            this.expectedConvention = convention;
            this.expectedParamCount = paramCount;
            this.expectedRetPattern = retPattern;
        }
    }
}
