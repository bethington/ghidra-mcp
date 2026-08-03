// Detect Calling Conventions
//
// Batch detects all functions using Diablo II custom calling conventions using assembly pattern analysis. Exports results as CSV or JSON with confidence levels.
//
// Usage: Run from Script Manager. Configure EXPORT_CSV/EXPORT_JSON flags in source.
// Output: Console listing and optional CSV/JSON export of detected conventions.
//
// @author Ben Ethington
// @category Diablo 2.Analysis
// @description Batch detect D2 custom calling conventions
// @menupath Diablo 2.Analysis.Detect Calling Conventions

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.regex.*;

public class Analyze_DetectCallingConventions extends GhidraScript {

    private static final boolean VERBOSE = true;
    private static final boolean EXPORT_CSV = false;
    private static final boolean EXPORT_JSON = true;
    private static final double CONFIDENCE_THRESHOLD = 0.75;

    private static class FunctionEntry {
        String address;
        String name;
        double confidence;

        FunctionEntry(String address, String name, double confidence) {
            this.address = address;
            this.name = name;
            this.confidence = confidence;
        }
    }

    private Map<String, List<FunctionEntry>> results = new LinkedHashMap<>();
    private Listing listing;
    private FunctionManager funcMgr;

    private void log(String msg) {
        if (VERBOSE) println("[D2ConvDetector] " + msg);
    }

    private boolean hasStandardPrologue(Function func) {
        Address entry = func.getEntryPoint();
        if (entry == null) return false;

        Instruction instr = listing.getInstructionAt(entry);
        if (instr == null) return false;

        List<Instruction> prologueInstrs = new ArrayList<>();
        for (int i = 0; i < 4 && instr != null; i++) {
            prologueInstrs.add(instr);
            instr = instr.getNext();
        }

        if (prologueInstrs.size() < 2) return false;

        Instruction first = prologueInstrs.get(0);
        Instruction second = prologueInstrs.get(1);

        String firstMnem = first.getMnemonicString();
        String firstOps = first.getNumOperands() > 0
            ? first.getDefaultOperandRepresentation(0).toUpperCase() : "";
        String secondMnem = second.getMnemonicString();
        String secondOp0 = second.getNumOperands() > 0
            ? second.getDefaultOperandRepresentation(0).toUpperCase() : "";
        String secondOp1 = second.getNumOperands() > 1
            ? second.getDefaultOperandRepresentation(1).toUpperCase() : "";

        boolean hasPushEbp = firstMnem.equals("PUSH") && firstOps.contains("EBP");
        boolean hasMovEbpEsp = secondMnem.equals("MOV") && secondOp0.contains("EBP") && secondOp1.contains("ESP");

        if (hasPushEbp && hasMovEbpEsp) return true;

        if (prologueInstrs.size() >= 4) {
            for (int i = 0; i < prologueInstrs.size() - 1; i++) {
                Instruction i1 = prologueInstrs.get(i);
                Instruction i2 = prologueInstrs.get(i + 1);
                if (i1.getMnemonicString().equals("MOV") && i2.getMnemonicString().equals("XOR")) {
                    String op1dest = i1.getNumOperands() > 0
                        ? i1.getDefaultOperandRepresentation(0).toUpperCase() : "";
                    String op2dest = i2.getNumOperands() > 0
                        ? i2.getDefaultOperandRepresentation(0).toUpperCase() : "";
                    String op2src = i2.getNumOperands() > 1
                        ? i2.getDefaultOperandRepresentation(1).toUpperCase() : "";
                    if (op1dest.contains("EAX") && op2dest.contains("EAX") && op2src.contains("EBP")) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    private double[] detectD2callCalleePattern(Function func) {
        Address entry = func.getEntryPoint();
        if (entry == null) return new double[]{0, 0};
        if (hasStandardPrologue(func)) return new double[]{0, 0};

        double confidence = 0.0;
        boolean usesEbxAsParam = false;
        boolean hasRetImmediate = false;
        boolean accessesStackParam = false;
        boolean savedEbx = false;

        Instruction instr = listing.getInstructionAt(entry);
        int count = 0;

        while (instr != null && count < 20) {
            count++;
            String mnemonic = instr.getMnemonicString();
            String opStr = instr.toString();

            if (mnemonic.equals("PUSH") && opStr.contains("EBX")) {
                savedEbx = true;
            } else if (mnemonic.equals("MOV") && opStr.contains("EBX")) {
                if (opStr.contains(",EBX") || opStr.contains("[EBX")) {
                    usesEbxAsParam = true;
                    confidence += 0.4;
                }
            }
            if ((opStr.contains("[EBX") || opStr.contains("EBX,"))
                    && (mnemonic.equals("MOV") || mnemonic.equals("CMP") || mnemonic.equals("TEST")
                        || mnemonic.equals("LEA") || mnemonic.equals("ADD"))) {
                usesEbxAsParam = true;
                confidence += 0.2;
            }
            if (opStr.contains("ESP") && (mnemonic.equals("MOV") || mnemonic.equals("LEA") || mnemonic.equals("PUSH"))) {
                if (opStr.contains("+0x") || opStr.contains("+ 0x")) {
                    Matcher m = Pattern.compile("\\+\\s*0x([0-9a-fA-F]+)").matcher(opStr);
                    if (m.find()) {
                        try {
                            int offset = Integer.parseInt(m.group(1), 16);
                            if (offset >= 4) {
                                accessesStackParam = true;
                                confidence += 0.2;
                            }
                        } catch (NumberFormatException ignored) {}
                    }
                }
            }
            instr = instr.getNext();
        }

        Instruction retInstr = getLastReturn(func);
        if (retInstr != null) {
            String retStr = retInstr.toString();
            if (Pattern.compile("RET\\s+0x[0-9a-fA-F]+").matcher(retStr).find()) {
                hasRetImmediate = true;
                confidence += 0.4;
            } else if (Pattern.compile("RET\\s*$").matcher(retStr).find()) {
                confidence -= 0.3;
            }
        }

        boolean detected = false;
        if (usesEbxAsParam && accessesStackParam && hasRetImmediate) {
            confidence = Math.min(0.95, confidence);
            detected = true;
        } else if (usesEbxAsParam && hasRetImmediate) {
            confidence = Math.min(0.75, confidence);
            detected = true;
        } else if (usesEbxAsParam && accessesStackParam) {
            confidence = Math.min(0.65, confidence);
            detected = true;
        }
        return new double[]{detected ? 1 : 0, confidence};
    }

    private double[] detectD2regcallPattern(Function func) {
        Address entry = func.getEntryPoint();
        if (entry == null) return new double[]{0, 0};
        if (hasStandardPrologue(func)) return new double[]{0, 0};

        double confidence = 0.0;
        Map<String, Boolean> usesRegs = new HashMap<>();
        Map<String, Boolean> savedRegs = new HashMap<>();
        usesRegs.put("EBX", false); usesRegs.put("EAX", false); usesRegs.put("ECX", false);
        savedRegs.put("EBX", false); savedRegs.put("EAX", false); savedRegs.put("ECX", false);
        boolean hasStackParams = false;
        boolean hasRetImmediate = false;

        Instruction instr = listing.getInstructionAt(entry);
        int count = 0;

        while (instr != null && count < 25) {
            count++;
            String mnemonic = instr.getMnemonicString();
            String opStr = instr.toString();

            if (mnemonic.equals("PUSH")) {
                for (String reg : new String[]{"EBX", "EAX", "ECX"}) {
                    if (opStr.contains(reg)) savedRegs.put(reg, true);
                }
            }
            for (String reg : new String[]{"EBX", "EAX", "ECX"}) {
                if (opStr.contains(reg) && !savedRegs.get(reg)) {
                    if ((mnemonic.equals("MOV") || mnemonic.equals("CMP") || mnemonic.equals("TEST")
                            || mnemonic.equals("LEA") || mnemonic.equals("ADD") || mnemonic.equals("SUB"))
                            && (opStr.contains("," + reg) || opStr.contains(reg + ",") || opStr.contains("[" + reg))) {
                        usesRegs.put(reg, true);
                        confidence += 0.25;
                    }
                }
            }
            if (opStr.contains("ESP") && (mnemonic.equals("MOV") || mnemonic.equals("PUSH") || mnemonic.equals("LEA"))) {
                if (opStr.contains("+0x") || opStr.contains("+ 0x")) {
                    Matcher m = Pattern.compile("\\+\\s*0x([0-9a-fA-F]+)").matcher(opStr);
                    if (m.find()) {
                        try {
                            int offset = Integer.parseInt(m.group(1), 16);
                            if (offset >= 4) {
                                hasStackParams = true;
                                confidence -= 0.5;
                            }
                        } catch (NumberFormatException ignored) {}
                    }
                }
            }
            instr = instr.getNext();
        }

        Instruction retInstr = getLastReturn(func);
        if (retInstr != null) {
            String retStr = retInstr.toString();
            if (Pattern.compile("RET\\s*$").matcher(retStr).find()) {
                confidence += 0.4;
            } else if (Pattern.compile("RET\\s+0x[0-9a-fA-F]+").matcher(retStr).find()) {
                hasRetImmediate = true;
                confidence -= 0.4;
            }
        }

        boolean allRegsUsed = usesRegs.values().stream().allMatch(v -> v);
        boolean detected = false;
        if (allRegsUsed && !hasStackParams && !hasRetImmediate) {
            confidence = Math.min(0.95, confidence);
            detected = true;
        } else if (allRegsUsed && !hasStackParams) {
            confidence = Math.min(0.75, confidence);
            detected = true;
        }
        return new double[]{detected ? 1 : 0, confidence};
    }

    private double[] detectD2mixcallPattern(Function func) {
        Address entry = func.getEntryPoint();
        if (entry == null) return new double[]{0, 0};
        if (hasStandardPrologue(func)) return new double[]{0, 0};

        double confidence = 0.0;
        boolean usesEax = false;
        boolean usesEsiAsParam = false;
        boolean savedEsi = false;
        boolean accessesStackParams = false;
        boolean hasRetImmediate = false;

        Instruction instr = listing.getInstructionAt(entry);
        int count = 0;

        while (instr != null && count < 25) {
            count++;
            String mnemonic = instr.getMnemonicString();
            String opStr = instr.toString();

            if (mnemonic.equals("PUSH") && opStr.contains("ESI")) savedEsi = true;

            if (opStr.contains("EAX") && (mnemonic.equals("MOV") || mnemonic.equals("CMP")
                    || mnemonic.equals("TEST") || mnemonic.equals("LEA") || mnemonic.equals("ADD"))) {
                if (opStr.contains(",EAX") || opStr.contains("EAX,") || opStr.contains("[EAX")) {
                    usesEax = true;
                    confidence += 0.3;
                }
            }
            if (opStr.contains("ESI") && !savedEsi) {
                if ((opStr.contains("[ESI") || opStr.contains("ESI,") || opStr.contains(",ESI"))
                        && (mnemonic.equals("MOV") || mnemonic.equals("CMP") || mnemonic.equals("TEST")
                            || mnemonic.equals("LEA") || mnemonic.equals("ADD") || mnemonic.equals("SUB"))) {
                    usesEsiAsParam = true;
                    confidence += 0.3;
                }
            }
            if (opStr.contains("ESP") && (mnemonic.equals("MOV") || mnemonic.equals("LEA") || mnemonic.equals("PUSH"))) {
                if (opStr.contains("+0x") || opStr.contains("+ 0x")) {
                    Matcher m = Pattern.compile("\\+\\s*0x([0-9a-fA-F]+)").matcher(opStr);
                    if (m.find()) {
                        try {
                            int offset = Integer.parseInt(m.group(1), 16);
                            if (offset >= 4) {
                                accessesStackParams = true;
                                confidence += 0.15;
                            }
                        } catch (NumberFormatException ignored) {}
                    }
                }
            }
            instr = instr.getNext();
        }

        Instruction retInstr = getLastReturn(func);
        if (retInstr != null) {
            String retStr = retInstr.toString();
            if (Pattern.compile("RET\\s+0x[0-9a-fA-F]+").matcher(retStr).find()) {
                hasRetImmediate = true;
                confidence += 0.35;
            } else {
                confidence -= 0.2;
            }
        }

        boolean detected = false;
        if (usesEax && usesEsiAsParam && accessesStackParams && hasRetImmediate) {
            confidence = Math.min(0.95, confidence);
            detected = true;
        } else if (usesEax && usesEsiAsParam && (accessesStackParams || hasRetImmediate)) {
            confidence = Math.min(0.70, confidence);
            detected = true;
        }
        return new double[]{detected ? 1 : 0, confidence};
    }

    private double[] detectD2edicallPattern(Function func) {
        Address entry = func.getEntryPoint();
        if (entry == null) return new double[]{0, 0};
        if (hasStandardPrologue(func)) return new double[]{0, 0};

        double confidence = 0.0;
        boolean usesEdiAsParam = false;
        boolean savedEdi = false;
        boolean accessesStackParams = false;
        boolean hasRetImmediate = false;

        Instruction instr = listing.getInstructionAt(entry);
        int count = 0;

        while (instr != null && count < 25) {
            count++;
            String mnemonic = instr.getMnemonicString();
            String opStr = instr.toString();

            if (mnemonic.equals("PUSH") && opStr.contains("EDI")) savedEdi = true;

            if (opStr.contains("EDI") && !savedEdi) {
                if ((opStr.contains("[EDI") || opStr.contains("EDI,") || opStr.contains(",EDI"))
                        && (mnemonic.equals("MOV") || mnemonic.equals("CMP") || mnemonic.equals("TEST")
                            || mnemonic.equals("LEA") || mnemonic.equals("ADD") || mnemonic.equals("SUB"))) {
                    usesEdiAsParam = true;
                    confidence += 0.4;
                }
            }
            if (opStr.contains("ESP") && (mnemonic.equals("MOV") || mnemonic.equals("LEA"))) {
                if (opStr.contains("+0x") || opStr.contains("+ 0x")) {
                    Matcher m = Pattern.compile("\\+\\s*0x([0-9a-fA-F]+)").matcher(opStr);
                    if (m.find()) {
                        try {
                            int offset = Integer.parseInt(m.group(1), 16);
                            if (offset >= 4) {
                                accessesStackParams = true;
                                confidence += 0.2;
                            }
                        } catch (NumberFormatException ignored) {}
                    }
                }
            }
            instr = instr.getNext();
        }

        Instruction retInstr = getLastReturn(func);
        if (retInstr != null) {
            String retStr = retInstr.toString();
            if (Pattern.compile("RET\\s+0x[0-9a-fA-F]+").matcher(retStr).find()) {
                hasRetImmediate = true;
                confidence += 0.35;
            } else {
                confidence -= 0.2;
            }
        }

        boolean detected = false;
        if (usesEdiAsParam && hasRetImmediate) {
            confidence = Math.min(0.90, confidence);
            detected = true;
        } else if (usesEdiAsParam && accessesStackParams) {
            confidence = Math.min(0.70, confidence);
            detected = true;
        }
        return new double[]{detected ? 1 : 0, confidence};
    }

    private Instruction getLastReturn(Function func) {
        try {
            AddressSetView body = func.getBody();
            Address lastAddr = body.getMaxAddress();
            Instruction instr = listing.getInstructionAt(lastAddr);
            while (instr != null) {
                if (instr.getMnemonicString().contains("RET")) return instr;
                instr = instr.getPrevious();
                if (instr == null || !body.contains(instr.getAddress())) break;
            }
        } catch (Exception ignored) {}
        return null;
    }

    private String analyzeCallerPattern(Instruction callInstr) {
        Instruction instr = callInstr.getPrevious();
        boolean foundMovEbx = false, foundMovEax = false, foundMovEcx = false;
        boolean foundMovEsi = false, foundMovEdi = false;
        int pushCount = 0;

        for (int i = 0; i < 10 && instr != null; i++) {
            String mnemonic = instr.getMnemonicString();
            String opStr = instr.toString();
            if (mnemonic.equals("MOV")) {
                if (opStr.contains("EBX,")) foundMovEbx = true;
                if (opStr.contains("EAX,")) foundMovEax = true;
                if (opStr.contains("ECX,")) foundMovEcx = true;
                if (opStr.contains("ESI,")) foundMovEsi = true;
                if (opStr.contains("EDI,")) foundMovEdi = true;
            }
            if (mnemonic.equals("PUSH")) pushCount++;
            instr = instr.getPrevious();
        }

        if (foundMovEdi && pushCount > 0) return "__d2edicall";
        if (foundMovEbx && foundMovEax && foundMovEcx && pushCount == 0) return "__d2regcall";
        if (foundMovEax && foundMovEsi) return "__d2mixcall";
        if (foundMovEbx && pushCount > 0) return "__d2call";
        return null;
    }

    private double[] analyzeCallers(Function func) {
        try {
            Set<Function> callers = func.getCallingFunctions(monitor);
            if (callers == null || callers.isEmpty()) return null;

            Map<String, Integer> votes = new HashMap<>();
            votes.put("__d2call", 0); votes.put("__d2regcall", 0);
            votes.put("__d2mixcall", 0); votes.put("__d2edicall", 0);

            int callerCount = 0;
            for (Function caller : callers) {
                if (callerCount >= 5) break;
                Address targetAddr = func.getEntryPoint();
                AddressSetView body = caller.getBody();
                Instruction instr = listing.getInstructionAt(body.getMinAddress());

                while (instr != null && body.contains(instr.getAddress())) {
                    if (instr.getMnemonicString().equals("CALL")) {
                        for (int i = 0; i < instr.getNumOperands(); i++) {
                            Object[] op = instr.getOpObjects(i);
                            if (op != null && op.length > 0 && op[0].toString().equals(targetAddr.toString())) {
                                String pattern = analyzeCallerPattern(instr);
                                if (pattern != null) {
                                    votes.merge(pattern, 1, Integer::sum);
                                }
                                callerCount++;
                                break;
                            }
                        }
                    }
                    instr = instr.getNext();
                }
            }

            if (callerCount == 0) return null;

            String best = votes.entrySet().stream()
                .max(Map.Entry.comparingByValue()).map(Map.Entry::getKey).orElse(null);
            if (best == null) return null;
            int voteCount = votes.get(best);
            if (voteCount >= 2) {
                double conf = Math.min(0.85, 0.5 + voteCount * 0.15);
                return new double[]{votes.entrySet().stream()
                    .max(Map.Entry.comparingByValue()).map(e -> (double)e.getValue()).orElse(0.0), conf,
                    best.equals("__d2call") ? 1 : best.equals("__d2regcall") ? 2
                        : best.equals("__d2mixcall") ? 3 : 4};
            }
        } catch (Exception ignored) {}
        return null;
    }

    private void classifyFunction(Function func) {
        String funcName = func.getName();
        String funcAddr = func.getEntryPoint().toString();

        if (func.getBody().getNumAddresses() < 5) return;
        if (funcName.startsWith("thunk_")) return;

        // Check callee patterns
        double[] d2call = detectD2callCalleePattern(func);
        double[] d2edicall = detectD2edicallPattern(func);
        double[] d2regcall = detectD2regcallPattern(func);
        double[] d2mixcall = detectD2mixcallPattern(func);

        String convention = null;
        double confidence = 0;

        if (d2call[0] > 0 && d2call[1] >= CONFIDENCE_THRESHOLD) {
            convention = "__d2call"; confidence = d2call[1];
        } else if (d2edicall[0] > 0 && d2edicall[1] >= CONFIDENCE_THRESHOLD) {
            convention = "__d2edicall"; confidence = d2edicall[1];
        } else if (d2regcall[0] > 0 && d2regcall[1] >= CONFIDENCE_THRESHOLD) {
            convention = "__d2regcall"; confidence = d2regcall[1];
        } else if (d2mixcall[0] > 0 && d2mixcall[1] >= CONFIDENCE_THRESHOLD) {
            convention = "__d2mixcall"; confidence = d2mixcall[1];
        } else {
            // Pick highest confidence
            double maxConf = Math.max(Math.max(d2call[1], d2edicall[1]),
                Math.max(d2regcall[1], d2mixcall[1]));
            if (maxConf > 0.4) {
                convention = "unknown"; confidence = maxConf;
            }
        }

        if (convention != null) {
            results.computeIfAbsent(convention, k -> new ArrayList<>())
                   .add(new FunctionEntry(funcAddr, funcName, confidence));
        }
    }

    private void printResults() {
        println("\n" + "=".repeat(70));
        println("DIABLO II CALLING CONVENTION DETECTION RESULTS");
        println("=".repeat(70) + "\n");

        int totalDetected = 0;
        for (String conv : new String[]{"__d2call", "__d2regcall", "__d2mixcall", "__d2edicall"}) {
            List<FunctionEntry> funcs = results.getOrDefault(conv, Collections.emptyList());
            println(conv + ": " + funcs.size() + " functions detected");
            println("-".repeat(70));
            funcs.sort((a, b) -> Double.compare(b.confidence, a.confidence));
            int shown = Math.min(20, funcs.size());
            for (int i = 0; i < shown; i++) {
                FunctionEntry e = funcs.get(i);
                println("  " + e.address + ": " + e.name);
                println(String.format("    Confidence: %.1f%%", e.confidence * 100));
            }
            if (funcs.size() > 20) println("  ... and " + (funcs.size() - 20) + " more");
            println("");
            totalDetected += funcs.size();
        }

        println("=".repeat(70));
        println("SUMMARY: " + totalDetected + " functions detected using custom conventions");
        println("=".repeat(70) + "\n");

        if (EXPORT_CSV) exportCsv();
        if (EXPORT_JSON) exportJson();
    }

    private void exportCsv() {
        String csvPath = System.getProperty("user.home") + "/Desktop/d2_conventions.csv";
        try (PrintWriter pw = new PrintWriter(new FileWriter(csvPath))) {
            pw.println("Convention,Address,Name,Confidence");
            for (Map.Entry<String, List<FunctionEntry>> entry : results.entrySet()) {
                for (FunctionEntry e : entry.getValue()) {
                    pw.printf("%s,%s,%s,%.2f%%%n",
                        entry.getKey(), e.address, e.name, e.confidence * 100);
                }
            }
            println("[+] Results exported to: " + csvPath);
        } catch (Exception ex) {
            println("[X] Failed to export CSV: " + ex.getMessage());
        }
    }

    private void exportJson() {
        String jsonPath = System.getProperty("user.home") + "/Desktop/d2_conventions.json";
        try (PrintWriter pw = new PrintWriter(new FileWriter(jsonPath))) {
            int totalDetected = results.values().stream().mapToInt(List::size).sum();
            pw.println("{");
            pw.println("  \"program_name\": \"" + currentProgram.getName() + "\",");
            pw.println("  \"confidence_threshold\": " + CONFIDENCE_THRESHOLD + ",");
            pw.println("  \"total_detected\": " + totalDetected + ",");
            pw.println("  \"by_convention\": {");

            boolean firstConv = true;
            for (Map.Entry<String, List<FunctionEntry>> entry : results.entrySet()) {
                if (!firstConv) pw.println(",");
                firstConv = false;
                pw.println("    \"" + entry.getKey() + "\": {");
                pw.println("      \"count\": " + entry.getValue().size() + ",");
                pw.println("      \"functions\": [");
                boolean firstFunc = true;
                for (FunctionEntry e : entry.getValue()) {
                    if (!firstFunc) pw.println(",");
                    firstFunc = false;
                    pw.printf("        {\"address\": \"%s\", \"name\": \"%s\", \"confidence\": %.4f}",
                        e.address, e.name.replace("\"", "\\\""), e.confidence);
                }
                pw.println("\n      ]");
                pw.print("    }");
            }
            pw.println("\n  }");
            pw.println("}");
            println("[+] JSON results exported to: " + jsonPath);
        } catch (Exception ex) {
            println("[X] Failed to export JSON: " + ex.getMessage());
        }
    }

    @Override
    public void run() throws Exception {
        if (currentProgram == null) {
            println("[X] No program loaded in Ghidra!");
            return;
        }

        listing = currentProgram.getListing();
        funcMgr = currentProgram.getFunctionManager();

        // Initialize results map
        results.put("__d2call", new ArrayList<>());
        results.put("__d2regcall", new ArrayList<>());
        results.put("__d2mixcall", new ArrayList<>());
        results.put("__d2edicall", new ArrayList<>());
        results.put("unknown", new ArrayList<>());

        println("[*] Starting Diablo II calling convention detection...");
        println("[*] Program: " + currentProgram.getName());

        int funcCount = 0;
        int detectedCount = 0;
        int total = funcMgr.getFunctionCount();
        log("Scanning " + total + " functions...");

        FunctionIterator funcs = funcMgr.getFunctions(true);
        while (funcs.hasNext()) {
            monitor.checkCanceled();
            Function func = funcs.next();
            funcCount++;

            if (funcCount % 100 == 0) {
                log("Progress: " + funcCount + "/" + total + " functions scanned");
            }

            int before = results.values().stream().mapToInt(List::size).sum();
            classifyFunction(func);
            int after = results.values().stream().mapToInt(List::size).sum();
            if (after > before) detectedCount++;
        }

        printResults();

        println("[+] Detection complete!");
        println("    Total functions scanned: " + funcCount);
        println("    Custom conventions detected: " + detectedCount);
    }
}
