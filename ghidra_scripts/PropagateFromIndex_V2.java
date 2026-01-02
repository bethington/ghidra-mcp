//Propagate documentation from hash index V2 using multi-phase matching with confidence scoring
//@author GhidraMCP
//@category Documentation
//@keybinding
//@menupath D2.1b - Propagate From Index V2 (Multi-Phase)
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.OperandType;
import ghidra.app.decompiler.*;
import ghidra.util.task.TaskMonitor;
import com.google.gson.*;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.security.*;
import java.math.BigInteger;

public class PropagateFromIndex_V2 extends GhidraScript {

    // Configuration - adjust these thresholds as needed
    private static final int CONFIDENCE_AUTO_APPLY = 100;      // Auto-apply (hash match only)
    private static final int CONFIDENCE_DOCUMENTED_MIN = 60;   // Min for documented functions
    private static final int CONFIDENCE_SUGGEST_MIN = 40;      // Min for suggestions (manual review)
    private static final int CONFIDENCE_REJECT = 40;           // Below this = reject
    private static final int CONFIDENCE_ALREADY_CORRECT = -1;  // Special: names already match

    private static final int MIN_INSTRUCTION_COUNT = 10;       // Skip tiny functions
    private static final int MIN_CALLEES_FOR_SIGNAL = 3;       // Minimum named callees for callee matching
    private static final int MIN_STRINGS_FOR_SIGNAL = 2;       // Minimum strings for string matching

    // Scoring weights
    private static final int SCORE_HASH_MATCH = 100;
    private static final int SCORE_CALLEE_MATCH = 40;
    private static final int SCORE_STRING_MATCH = 30;
    private static final int SCORE_SIGNATURE_MATCH = 20;
    private static final int SCORE_SIZE_SIMILAR = 10;

    // Index data
    private JsonObject indexData;
    private JsonObject hashIndex;
    private JsonObject calleeIndex;
    private JsonObject signatureIndex;

    // Statistics
    private int hashMatches = 0;
    private int calleeMatches = 0;
    private int signatureMatches = 0;
    private int totalPropagated = 0;
    private int totalSkipped = 0;
    private int totalSuggestions = 0;
    private int alreadyCorrect = 0;  // Names already match
    private int noMatchFound = 0;    // No hash/callee/signature match in index

    @Override
    public void run() throws Exception {
        // Load index file
        String homeDir = System.getProperty("user.home");
        File indexFile = new File(homeDir, "ghidra_function_hash_index_v2.json");

        if (!indexFile.exists()) {
            printerr("Index file not found: " + indexFile.getAbsolutePath());
            printerr("Please run 'Build Hash Index V2' first.");
            return;
        }

        println("Loading index from: " + indexFile.getAbsolutePath());
        String json = new String(Files.readAllBytes(indexFile.toPath()));
        indexData = JsonParser.parseString(json).getAsJsonObject();

        hashIndex = indexData.getAsJsonObject("functions_by_hash");
        calleeIndex = indexData.getAsJsonObject("functions_by_callees");
        signatureIndex = indexData.getAsJsonObject("functions_by_signature");

        if (hashIndex == null) {
            printerr("Invalid index format - missing functions_by_hash. Please rebuild with V2 indexer.");
            return;
        }

        println("Index loaded:");
        println("  - Hash entries: " + hashIndex.size());
        println("  - Callee entries: " + (calleeIndex != null ? calleeIndex.size() : 0));
        println("  - Signature entries: " + (signatureIndex != null ? signatureIndex.size() : 0));

        // Get current program info
        String programName = currentProgram.getName();
        println("\nProcessing: " + programName);

        // Collect ALL functions to process (not just FUN_*)
        FunctionManager funcManager = currentProgram.getFunctionManager();
        List<Function> functionsToProcess = new ArrayList<>();

        int totalFuncs = 0;
        int undocumentedCount = 0;
        int documentedCount = 0;
        FunctionIterator funcIter = funcManager.getFunctions(true);

        // Debug: Show first 10 function names to see what we're getting
        println("First 10 function names:");

        while (funcIter.hasNext() && !monitor.isCancelled()) {
            Function func = funcIter.next();
            String name = func.getName();
            totalFuncs++;

            // Show first 10 names for debugging
            if (totalFuncs <= 10) {
                println("  [" + totalFuncs + "] " + name + " at " + func.getEntryPoint());
            }

            // Skip thunks
            if (func.isThunk()) continue;

            // Process ALL functions (both documented and undocumented)
            functionsToProcess.add(func);

            if (name.startsWith("FUN_") || name.startsWith("thunk_FUN_")) {
                undocumentedCount++;
            } else {
                documentedCount++;
            }
        }

        println("Total functions scanned: " + totalFuncs);
        println("Functions to process: " + functionsToProcess.size());
        println("  - Undocumented (FUN_*): " + undocumentedCount);
        println("  - Already documented: " + documentedCount + "\n");

        // Process each function
        List<MatchResult> suggestions = new ArrayList<>();

        monitor.initialize(functionsToProcess.size());
        int processed = 0;

        for (Function func : functionsToProcess) {
            if (monitor.isCancelled()) break;

            monitor.setProgress(processed++);
            monitor.setMessage("Processing: " + func.getName());

            MatchResult result = findBestMatch(func, programName);

            if (result != null) {
                if (result.confidence == CONFIDENCE_ALREADY_CORRECT) {
                    // Names already match via hash - nothing to change
                    alreadyCorrect++;
                } else if (result.confidence >= CONFIDENCE_AUTO_APPLY) {
                    // Hash match - auto apply
                    applyMatch(func, result);
                    hashMatches++;
                    totalPropagated++;
                } else if (result.confidence >= CONFIDENCE_DOCUMENTED_MIN) {
                    // High confidence multi-phase match - auto apply
                    applyMatch(func, result);
                    if (result.matchType.contains("callee")) calleeMatches++;
                    else if (result.matchType.contains("signature")) signatureMatches++;
                    totalPropagated++;
                } else if (result.confidence >= CONFIDENCE_SUGGEST_MIN) {
                    // Medium confidence - add to suggestions
                    suggestions.add(result);
                    totalSuggestions++;
                } else {
                    totalSkipped++;
                }
            } else {
                // No match found in index
                noMatchFound++;
            }
        }

        // Print results
        println("\n========== PROPAGATION RESULTS ==========");
        println("Total propagated: " + totalPropagated);
        println("  - Hash matches: " + hashMatches);
        println("  - Callee matches: " + calleeMatches);
        println("  - Signature matches: " + signatureMatches);
        println("Already correct (hash match, same name): " + alreadyCorrect);
        println("No match in index: " + noMatchFound);
        println("Low confidence skipped: " + totalSkipped);
        println("Suggestions for review: " + totalSuggestions);

        // Write suggestions to file for manual review
        if (!suggestions.isEmpty()) {
            File suggestFile = new File(homeDir, "propagation_suggestions_" + programName + ".txt");
            try (PrintWriter writer = new PrintWriter(suggestFile)) {
                writer.println("# Suggested matches for manual review");
                writer.println("# Confidence threshold: " + CONFIDENCE_SUGGEST_MIN + "-" + (CONFIDENCE_DOCUMENTED_MIN - 1));
                writer.println("# Format: Address | CurrentName | SuggestedName | Confidence | MatchType | Evidence");
                writer.println();

                suggestions.sort((a, b) -> Integer.compare(b.confidence, a.confidence));

                for (MatchResult s : suggestions) {
                    writer.printf("%s | %s | %s | %d | %s | %s%n",
                        s.targetAddress, s.targetCurrentName, s.sourceName,
                        s.confidence, s.matchType, s.evidence);
                }
            }
            println("\nSuggestions written to: " + suggestFile.getAbsolutePath());
        }

        println("\n========== DONE ==========");
    }

    private MatchResult findBestMatch(Function func, String targetProgramName) {
        try {
            // Skip tiny functions
            int instCount = getInstructionCount(func);
            if (instCount < MIN_INSTRUCTION_COUNT) {
                return null;
            }

            String funcAddress = func.getEntryPoint().toString();
            String currentName = func.getName();
            boolean isCurrentlyDocumented = !currentName.startsWith("FUN_") && !currentName.startsWith("thunk_FUN_");

            // Calculate current function's completeness for comparison
            int currentCompleteness = 0;
            if (isCurrentlyDocumented) {
                currentCompleteness = calculateLocalCompleteness(func);
            }

            // Phase 1: Try strict hash match
            String strictHash = computeStrictHash(func);
            if (strictHash != null && hashIndex.has(strictHash)) {
                JsonObject hashEntry = hashIndex.getAsJsonObject(strictHash);
                JsonObject canonical = hashEntry.getAsJsonObject("canonical");

                if (canonical != null) {
                    String sourceName = canonical.get("name").getAsString();
                    String sourceProgram = canonical.get("program").getAsString();
                    int sourceCompleteness = canonical.has("completeness_score") ?
                        (int) canonical.get("completeness_score").getAsDouble() : 0;

                    // Skip if source is undocumented (FUN_*)
                    if (sourceName.startsWith("FUN_")) {
                        // Continue to other phases
                    }
                    // Names already match - return special result to track this
                    else if (sourceName.equals(currentName)) {
                        MatchResult result = new MatchResult();
                        result.targetAddress = funcAddress;
                        result.targetCurrentName = currentName;
                        result.sourceName = sourceName;
                        result.sourceProgram = sourceProgram;
                        result.confidence = CONFIDENCE_ALREADY_CORRECT;
                        result.matchType = "already_correct";
                        result.evidence = "hash match, names identical";
                        return result;
                    }
                    // HASH MATCH: Always sync names for identical functions
                    // If hash matches and source is documented, update the target name
                    else {
                        MatchResult result = new MatchResult();
                        result.targetAddress = funcAddress;
                        result.targetCurrentName = currentName;
                        result.sourceName = sourceName;
                        result.sourceProgram = sourceProgram;
                        result.confidence = SCORE_HASH_MATCH;
                        result.matchType = isCurrentlyDocumented ? "hash (sync)" : "hash";
                        result.evidence = "strict_hash=" + strictHash.substring(0, 16) + "...";
                        result.sourceCompleteness = sourceCompleteness;
                        result.targetCompleteness = currentCompleteness;
                        return result;
                    }
                }
            }

            // Phase 2: Try callee-based matching (need 3+ named callees)
            Set<String> calleeNames = getNamedCallees(func);
            if (calleeIndex != null && calleeNames.size() >= MIN_CALLEES_FOR_SIGNAL) {
                String calleeKey = createCalleeKey(calleeNames);
                if (calleeIndex.has(calleeKey)) {
                    JsonObject calleeEntry = calleeIndex.getAsJsonObject(calleeKey);
                    JsonArray candidates = calleeEntry.getAsJsonArray("instances");

                    // Find best candidate from different program
                    JsonObject bestCandidate = findBestCandidate(candidates, targetProgramName, func);
                    if (bestCandidate != null) {
                        int confidence = SCORE_CALLEE_MATCH;

                        // Bonus for size similarity
                        int sourceSize = bestCandidate.get("size").getAsInt();
                        int targetSize = (int) func.getBody().getNumAddresses();
                        if (Math.abs(sourceSize - targetSize) < sourceSize * 0.1) {
                            confidence += SCORE_SIZE_SIMILAR;
                        }

                        // Bonus for signature match
                        String sourceSignature = bestCandidate.has("signature_hash") ?
                            bestCandidate.get("signature_hash").getAsString() : null;
                        String targetSignature = computeSignatureHash(func);
                        if (sourceSignature != null && sourceSignature.equals(targetSignature)) {
                            confidence += SCORE_SIGNATURE_MATCH;
                        }

                        MatchResult result = new MatchResult();
                        result.targetAddress = funcAddress;
                        result.targetCurrentName = func.getName();
                        result.sourceName = bestCandidate.get("name").getAsString();
                        result.sourceProgram = bestCandidate.get("program").getAsString();
                        result.confidence = confidence;
                        result.matchType = "callee+" + (confidence > SCORE_CALLEE_MATCH ? "sig+size" : "");
                        result.evidence = "callees=" + calleeNames.size() + " " + calleeNames;
                        return result;
                    }
                }
            }

            // Phase 3: Try signature + string matching
            String signatureHash = computeSignatureHash(func);
            Set<String> stringRefs = getStringReferences(func);

            if (signatureIndex != null && signatureHash != null && signatureIndex.has(signatureHash)) {
                JsonObject sigEntry = signatureIndex.getAsJsonObject(signatureHash);
                JsonArray candidates = sigEntry.getAsJsonArray("instances");

                // Filter by string overlap
                for (int i = 0; i < candidates.size(); i++) {
                    JsonObject candidate = candidates.get(i).getAsJsonObject();
                    String candidateProgram = candidate.get("program").getAsString();

                    if (candidateProgram.equals(targetProgramName)) continue;

                    JsonArray candidateStrings = candidate.has("string_refs") ?
                        candidate.getAsJsonArray("string_refs") : null;

                    if (candidateStrings != null && candidateStrings.size() >= MIN_STRINGS_FOR_SIGNAL) {
                        Set<String> candidateStringSet = new HashSet<>();
                        for (int j = 0; j < candidateStrings.size(); j++) {
                            candidateStringSet.add(candidateStrings.get(j).getAsString());
                        }

                        // Calculate string overlap
                        Set<String> intersection = new HashSet<>(stringRefs);
                        intersection.retainAll(candidateStringSet);

                        if (intersection.size() >= MIN_STRINGS_FOR_SIGNAL) {
                            int confidence = SCORE_SIGNATURE_MATCH + SCORE_STRING_MATCH;

                            // Bonus for size similarity
                            int sourceSize = candidate.get("size").getAsInt();
                            int targetSize = (int) func.getBody().getNumAddresses();
                            if (Math.abs(sourceSize - targetSize) < sourceSize * 0.1) {
                                confidence += SCORE_SIZE_SIMILAR;
                            }

                            MatchResult result = new MatchResult();
                            result.targetAddress = funcAddress;
                            result.targetCurrentName = func.getName();
                            result.sourceName = candidate.get("name").getAsString();
                            result.sourceProgram = candidate.get("program").getAsString();
                            result.confidence = confidence;
                            result.matchType = "signature+strings";
                            result.evidence = "strings=" + intersection.size() + " " + intersection;
                            return result;
                        }
                    }
                }
            }

            return null;

        } catch (Exception e) {
            // Silent fail for individual functions
            return null;
        }
    }

    private JsonObject findBestCandidate(JsonArray candidates, String targetProgramName, Function targetFunc) {
        JsonObject best = null;
        int bestScore = 0;

        for (int i = 0; i < candidates.size(); i++) {
            JsonObject candidate = candidates.get(i).getAsJsonObject();
            String candidateProgram = candidate.get("program").getAsString();
            String candidateName = candidate.get("name").getAsString();

            // Skip same program and undocumented functions
            if (candidateProgram.equals(targetProgramName)) continue;
            if (candidateName.startsWith("FUN_")) continue;

            // Score based on completeness
            int score = 0;
            if (candidate.has("completeness_score")) {
                score = (int) candidate.get("completeness_score").getAsDouble();
            }

            if (score > bestScore) {
                bestScore = score;
                best = candidate;
            }
        }

        return best;
    }

    private void applyMatch(Function func, MatchResult match) {
        try {
            // Rename function
            func.setName(match.sourceName, SourceType.USER_DEFINED);

            // Add plate comment noting the propagation
            String existingComment = func.getComment();
            String propagationNote = String.format(
                "[Propagated from %s via %s (confidence: %d)]",
                match.sourceProgram, match.matchType, match.confidence);

            if (existingComment != null && !existingComment.isEmpty()) {
                func.setComment(propagationNote + "\n\n" + existingComment);
            } else {
                func.setComment(propagationNote);
            }

            println(String.format("  %s -> %s (%s, conf=%d)",
                match.targetCurrentName, match.sourceName, match.matchType, match.confidence));

        } catch (Exception e) {
            printerr("Failed to apply match for " + func.getName() + ": " + e.getMessage());
        }
    }

    // ============ Hash computation methods (same as BuildHashIndex_V2) ============

    private String computeStrictHash(Function func) {
        try {
            StringBuilder sb = new StringBuilder();
            Listing listing = currentProgram.getListing();
            AddressSetView body = func.getBody();

            InstructionIterator instIter = listing.getInstructions(body, true);
            while (instIter.hasNext()) {
                Instruction inst = instIter.next();
                String mnemonic = inst.getMnemonicString();
                sb.append(mnemonic);

                for (int i = 0; i < inst.getNumOperands(); i++) {
                    int opType = inst.getOperandType(i);
                    Object[] opObjects = inst.getOpObjects(i);

                    if ((opType & OperandType.REGISTER) != 0) {
                        sb.append("_REG");
                        for (Object obj : opObjects) {
                            if (obj instanceof ghidra.program.model.lang.Register) {
                                sb.append("_").append(((ghidra.program.model.lang.Register) obj).getName());
                            }
                        }
                    } else if ((opType & OperandType.ADDRESS) != 0 ||
                               (opType & OperandType.DYNAMIC) != 0) {
                        Address refAddr = inst.getAddress(i);
                        if (refAddr != null && body.contains(refAddr)) {
                            long offset = refAddr.subtract(func.getEntryPoint());
                            sb.append("_LOCAL_").append(offset);
                        } else {
                            sb.append("_EXT");
                        }
                    } else if ((opType & OperandType.SCALAR) != 0) {
                        for (Object obj : opObjects) {
                            if (obj instanceof ghidra.program.model.scalar.Scalar) {
                                long val = ((ghidra.program.model.scalar.Scalar) obj).getValue();
                                if (val < 0x10000) {
                                    sb.append("_IMM_").append(val);
                                } else {
                                    sb.append("_IMM_LARGE");
                                }
                            }
                        }
                    }
                }
                sb.append(";");
            }

            return md5(sb.toString());
        } catch (Exception e) {
            return null;
        }
    }

    private String computeSignatureHash(Function func) {
        try {
            StringBuilder sb = new StringBuilder();
            Listing listing = currentProgram.getListing();
            AddressSetView body = func.getBody();

            InstructionIterator instIter = listing.getInstructions(body, true);
            while (instIter.hasNext()) {
                Instruction inst = instIter.next();
                sb.append(inst.getMnemonicString());
                sb.append("_").append(inst.getNumOperands());
                sb.append(";");
            }

            return md5(sb.toString());
        } catch (Exception e) {
            return null;
        }
    }

    private Set<String> getNamedCallees(Function func) {
        Set<String> callees = new TreeSet<>();
        try {
            Listing listing = currentProgram.getListing();
            AddressSetView body = func.getBody();

            InstructionIterator instIter = listing.getInstructions(body, true);
            while (instIter.hasNext()) {
                Instruction inst = instIter.next();
                if (inst.getMnemonicString().equals("CALL")) {
                    Reference[] refs = inst.getReferencesFrom();
                    for (Reference ref : refs) {
                        if (ref.getReferenceType().isCall()) {
                            Function callee = getFunctionAt(ref.getToAddress());
                            if (callee != null) {
                                String name = callee.getName();
                                // Only include user-defined names, not FUN_*
                                if (!name.startsWith("FUN_") && !name.startsWith("thunk_FUN_")) {
                                    callees.add(name);
                                }
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            // Silent fail
        }
        return callees;
    }

    private String createCalleeKey(Set<String> callees) {
        List<String> sorted = new ArrayList<>(callees);
        Collections.sort(sorted);
        return md5(String.join(",", sorted));
    }

    private Set<String> getStringReferences(Function func) {
        Set<String> strings = new HashSet<>();
        try {
            AddressSetView body = func.getBody();
            ReferenceManager refManager = currentProgram.getReferenceManager();

            AddressIterator addrIter = body.getAddresses(true);
            while (addrIter.hasNext()) {
                Address addr = addrIter.next();
                Reference[] refs = refManager.getReferencesFrom(addr);
                for (Reference ref : refs) {
                    if (ref.getReferenceType().isData()) {
                        Data data = getDataAt(ref.getToAddress());
                        if (data != null && data.hasStringValue()) {
                            String str = data.getDefaultValueRepresentation();
                            if (str != null && str.length() > 3) {
                                strings.add(str);
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            // Silent fail
        }
        return strings;
    }

    private int getInstructionCount(Function func) {
        int count = 0;
        try {
            Listing listing = currentProgram.getListing();
            InstructionIterator instIter = listing.getInstructions(func.getBody(), true);
            while (instIter.hasNext()) {
                instIter.next();
                count++;
            }
        } catch (Exception e) {
            // Silent fail
        }
        return count;
    }

    private String md5(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] digest = md.digest(input.getBytes());
            return String.format("%032x", new BigInteger(1, digest));
        } catch (Exception e) {
            return null;
        }
    }

    // Result class
    private static class MatchResult {
        String targetAddress;
        String targetCurrentName;
        String sourceName;
        String sourceProgram;
        int confidence;
        String matchType;
        String evidence;
        int sourceCompleteness;
        int targetCompleteness;
    }

    // Calculate completeness score for a local function (mirrors BuildHashIndex_V2 logic)
    private int calculateLocalCompleteness(Function func) {
        int score = 0;
        String name = func.getName();
        boolean isDocumented = !name.startsWith("FUN_") && !name.startsWith("thunk_FUN_");

        if (isDocumented) score += 30;

        String plateComment = func.getComment();
        if (plateComment != null && !plateComment.isEmpty()) score += 30;

        DataType returnType = func.getReturnType();
        if (returnType != null && !returnType.getName().equals("undefined")) {
            score += 15;
        }

        Parameter[] params = func.getParameters();
        int namedParams = 0;
        for (Parameter p : params) {
            if (!p.getName().startsWith("param_")) namedParams++;
        }
        if (namedParams > 0) score += 15;

        Variable[] locals = func.getLocalVariables();
        int namedLocals = 0;
        for (Variable v : locals) {
            if (!v.getName().startsWith("local_") && !v.getName().startsWith("unaff_")) {
                namedLocals++;
            }
        }
        if (namedLocals > 0) score += 10;

        return score;
    }
}
