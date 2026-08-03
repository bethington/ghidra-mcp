// D2 Loops And AI
//
// Detects and documents tight loops used for animation frame processing, AI decision making, monster behavior, and movement path calculation in Diablo II binaries.
//
// Usage: Run from Script Manager on any D2 binary.
// Output: Console listing of detected loops with characteristics and confidence scores.
//
// @author Ben Ethington
// @category Diablo 2.Analysis
// @description Detect animation loops and AI patterns in D2 code
// @menupath Diablo 2.Analysis.D2 Loops And AI

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import java.util.*;
import java.util.regex.*;

public class Analyze_D2LoopsAndAI extends GhidraScript {

    private static class LoopInfo {
        String type;
        Address start;
        Address end;
        List<String> characteristics;
        double confidence;
        String functionName;
        String functionAddress;
    }

    private Listing listing;
    private FunctionManager funcMgr;
    private List<LoopInfo> loopsFound = new ArrayList<>();

    private List<LoopInfo> detectLoops(Function func) {
        List<LoopInfo> loops = new ArrayList<>();
        Address entry = func.getEntryPoint();
        if (entry == null) return loops;

        AddressSetView body = func.getBody();
        Instruction instr = listing.getInstructionAt(entry);

        while (instr != null && body.contains(instr.getAddress())) {
            long addr = instr.getAddress().getOffset();
            if (instr.getMnemonicString().startsWith("J")) {
                Address[] flows = instr.getFlows();
                for (Address flowAddr : flows) {
                    long targetOffset = flowAddr.getOffset();
                    if (targetOffset < addr) {
                        String loopType = "Generic";
                        List<String> characteristics = new ArrayList<>();
                        // classify loop
                        Instruction current = instr.getPrevious();
                        int scanDepth = 0;
                        while (current != null && scanDepth < 50) {
                            scanDepth++;
                            String opStr = current.toString();
                            String opLower = opStr.toLowerCase();
                            if (opStr.contains("dwGfxFrame") || opLower.contains("frame")) {
                                characteristics.add("Animation Frame Update");
                                loopType = "AnimationFrame";
                            }
                            if (opStr.contains("dwFrameRemain") || opLower.contains("remain")) {
                                characteristics.add("Frame Counter Decrement");
                                if (!loopType.equals("AnimationFrame")) loopType = "FrameCounter";
                            }
                            if (opLower.contains("direction") || opLower.contains("dir")) {
                                characteristics.add("Direction Iteration");
                                loopType = "DirectionLoop";
                            }
                            if (opLower.contains("mode") || opLower.contains("state")) {
                                characteristics.add("State Machine");
                                if (loopType.equals("Generic")) loopType = "StateLoop";
                            }
                            if (opLower.contains("monster") || opLower.contains("ai")) {
                                characteristics.add("Monster/AI");
                                if (loopType.equals("Generic")) loopType = "AILoop";
                            }
                            if (opStr.contains("Next") || opStr.contains("pNext")) {
                                characteristics.add("List Iteration");
                                if (loopType.equals("Generic")) loopType = "ListLoop";
                            }
                            if (current.getMnemonicString().equals("CMP")) {
                                Matcher m = Pattern.compile("CMP.*?,\\s*(\\d+)").matcher(opStr);
                                if (m.find()) {
                                    int count = Integer.parseInt(m.group(1));
                                    if (count == 8 || count == 16) {
                                        characteristics.add(count + "-Direction Loop");
                                        loopType = "DirectionLoop";
                                    } else if (count == 4 || count == 32 || count == 64) {
                                        characteristics.add("Fixed Count: " + count);
                                    }
                                }
                            }
                            current = current.getPrevious();
                        }
                        LoopInfo li = new LoopInfo();
                        li.type = loopType;
                        li.start = flowAddr;
                        li.end = instr.getAddress();
                        li.characteristics = characteristics;
                        li.confidence = 0.8;
                        li.functionName = func.getName();
                        li.functionAddress = func.getEntryPoint().toString();
                        loops.add(li);
                    }
                }
            }
            instr = instr.getNext();
        }
        return loops;
    }

    private void printResults() {
        println("\n" + "=".repeat(80));
        println("DIABLO II LOOP AND AI ANALYSIS RESULTS");
        println("=".repeat(80) + "\n");

        if (loopsFound.isEmpty()) {
            println("[*] No significant loops detected in current analysis scope.\n");
            return;
        }

        Map<String, List<LoopInfo>> byType = new LinkedHashMap<>();
        for (LoopInfo loop : loopsFound) {
            byType.computeIfAbsent(loop.type, k -> new ArrayList<>()).add(loop);
        }

        for (Map.Entry<String, List<LoopInfo>> entry : new TreeMap<>(byType).entrySet()) {
            List<LoopInfo> loops = entry.getValue();
            println(entry.getKey() + ": " + loops.size() + " detected");
            println("-".repeat(80));
            loops.sort((a, b) -> Double.compare(b.confidence, a.confidence));
            int shown = Math.min(15, loops.size());
            for (int i = 0; i < shown; i++) {
                LoopInfo loop = loops.get(i);
                println("  Function: " + loop.functionName);
                println("  Address:  " + loop.functionAddress);
                println("  Loop:     " + loop.start + " -> " + loop.end);
                println("  Type:     " + loop.type);
                println(String.format("  Confidence: %.0f%%", loop.confidence * 100));
                println("  Characteristics:");
                for (String c : loop.characteristics) {
                    println("    - " + c);
                }
                println("");
            }
            if (loops.size() > 15) {
                println("  ... and " + (loops.size() - 15) + " more\n");
            }
        }

        println("=".repeat(80));
        println("SUMMARY: " + loopsFound.size() + " loops detected");
        println("=".repeat(80) + "\n");

        println("ANALYSIS NOTES:\n");
        println("Animation Frame Loops:");
        println("  - Process unit animation frames");
        println("  - Decrement dwFrameRemain counter");
        println("  - Often use tight inner loops for performance");
        println("  - Candidates for __d2call custom calling convention\n");
        println("Direction Loops:");
        println("  - Iterate over 8 or 16 directions");
        println("  - Used for damage spread, targeting, pathfinding");
        println("  - Usually fixed iteration count\n");
        println("Monster/AI Loops:");
        println("  - Process monster AI decisions");
        println("  - Update monster mode/state\n");
        println("List Iteration Loops:");
        println("  - Walk linked lists (monsters, items, etc.)");
        println("  - Check next pointer (pNext, pRoomNext, etc.)\n");
        println("Performance Optimization Opportunities:");
        println("  1. Use __d2call convention for loops with EBX parameters");
        println("  2. Consider loop unrolling for 8/16-direction iteration");
        println("  3. Cache frequently accessed pointers");
        println("  4. Minimize function calls inside loop bodies");
    }

    @Override
    public void run() throws Exception {
        if (currentProgram == null) {
            println("[X] No program loaded in Ghidra!");
            return;
        }

        listing = currentProgram.getListing();
        funcMgr = currentProgram.getFunctionManager();

        println("[*] Starting Diablo II loop analysis...");
        println("[*] Program: " + currentProgram.getName());

        int funcCount = 0;
        FunctionIterator funcs = funcMgr.getFunctions(true);
        int total = funcMgr.getFunctionCount();
        println("[*] Analyzing " + total + " functions for loops...");

        while (funcs.hasNext()) {
            monitor.checkCanceled();
            Function func = funcs.next();
            funcCount++;
            if (funcCount % 100 == 0) {
                println("Progress: " + funcCount + "/" + total);
            }
            List<LoopInfo> loops = detectLoops(func);
            loopsFound.addAll(loops);
        }

        printResults();

        println("[+] Analysis complete!");
        println("    Total functions scanned: " + funcCount);
        println("    Loops detected: " + loopsFound.size());

        if (!loopsFound.isEmpty()) {
            println("    Comments to apply: " + loopsFound.size());
            println("\n[*] Use MCP bridge to apply comments:");
            println("    batch_set_comments(function_address, decompiler_comments=comments)");
        }
    }
}
