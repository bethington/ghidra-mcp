// BSim Identify Dump
//
// Queries EVERY function in the current program against a BSim reference index at
// deliberately LOW thresholds and writes one JSON line per queried function --
// including zero-match functions and every candidate above the floor -- to a JSONL
// file. This script deliberately makes NO decisions: it is the measurement half of
// the BSim identification lane. All thresholds, the tie/abstain rule and every write
// live in `fun-doc/bsim_identify.py`, which consumes this dump.
//
// Dump low and decide later, on purpose. The floors are calibration outputs
// (Phase 0, 2026-08-03) and WILL be re-tuned per reference corpus; re-running an
// 8-minute Ghidra query to change a number that a scorer could have applied offline
// is how a calibration loop stops being run at all. It also means the raw evidence
// for any verdict survives on disk, which is what made Phase 0's negative controls
// cheap.
//
// Keep this script in its OWN directory. Ghidra compiles each script directory as a
// single OSGi bundle, and `~/ghidra_scripts` currently contains ~10 scripts with
// API-drift compile errors -- any one of them blocks every script in that folder.
//
// Usage (headless postScript): Args: [0]=BSim URL, [1]=output JSONL path,
//   [2]=max matches per function (default 10), [3]=similarity floor (default 0.3),
//   [4]=significance floor (default 0.0), [5]=chunk size (default 500).
// Output: JSONL file; console prints a one-line JSON summary.
//
//   analyzeHeadless <proj> <name> -process <binary> -noanalysis \
//     -scriptPath <repo>\scripts\bsim \
//     -postScript Analyze_BSimIdentifyDump.java \
//        file:/C:/path/to/refindex out.jsonl 10 0.3 0.0 500
//
// @author Ben Ethington
// @category Diablo 2.Analysis
// @description Dump low-threshold BSim matches for every function; decisions happen in Python
// @menupath Diablo 2.Analysis.BSim Identify Dump

import java.io.PrintWriter;
import java.net.URL;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.features.bsim.query.BSimClientFactory;
import ghidra.features.bsim.query.FunctionDatabase;
import ghidra.features.bsim.query.GenSignatures;
import ghidra.features.bsim.query.description.DescriptionManager;
import ghidra.features.bsim.query.description.ExecutableRecord;
import ghidra.features.bsim.query.description.FunctionDescription;
import ghidra.features.bsim.query.protocol.QueryNearest;
import ghidra.features.bsim.query.protocol.ResponseNearest;
import ghidra.features.bsim.query.protocol.SimilarityNote;
import ghidra.features.bsim.query.protocol.SimilarityResult;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;

public class Analyze_BSimIdentifyDump extends GhidraScript {

    @Override
    protected void run() throws Exception {
        if (currentProgram == null) {
            println("{\"status\": \"error\", \"error\": \"No program is open\"}");
            return;
        }

        String[] args = getScriptArgs();
        if (args == null || args.length < 2) {
            println("{\"status\": \"error\", \"error\": \"Args: bsimUrl outputPath [maxMatches] [simThresh] [signifThresh] [chunkSize]\"}");
            return;
        }
        String bsimUrl = args[0].trim();
        String outputPath = args[1].trim();
        int maxMatches = args.length > 2 && !args[2].isEmpty() ? Integer.parseInt(args[2].trim()) : 10;
        double simThresh = args.length > 3 && !args[3].isEmpty() ? Double.parseDouble(args[3].trim()) : 0.3;
        double signifThresh = args.length > 4 && !args[4].isEmpty() ? Double.parseDouble(args[4].trim()) : 0.0;
        int chunkSize = args.length > 5 && !args[5].isEmpty() ? Integer.parseInt(args[5].trim()) : 500;

        FunctionManager fman = currentProgram.getFunctionManager();
        List<Function> all = new ArrayList<>();
        FunctionIterator fiter = fman.getFunctions(true);
        while (fiter.hasNext()) {
            Function f = fiter.next();
            if (f.isThunk()) {
                continue; // thunks carry no body of their own; signatures would alias the target
            }
            all.add(f);
        }

        int queried = 0;
        int withMatches = 0;
        int totalMatches = 0;
        int skippedNoSig = 0;

        FunctionDatabase database = null;
        try (PrintWriter out = new PrintWriter(outputPath, "UTF-8")) {
            URL url = BSimClientFactory.deriveBSimURL(bsimUrl);
            database = BSimClientFactory.buildClient(url, false);
            if (!database.initialize()) {
                String errMsg = database.getLastError() != null
                    ? database.getLastError().message : "Unknown error";
                println("{\"status\": \"error\", \"error\": \"Connection failed: " + escapeJson(errMsg) + "\"}");
                return;
            }

            for (int start = 0; start < all.size(); start += chunkSize) {
                int end = Math.min(start + chunkSize, all.size());
                List<Function> chunk = all.subList(start, end);

                GenSignatures gensig = new GenSignatures(false);
                try {
                    gensig.setVectorFactory(database.getLSHVectorFactory());
                    gensig.openProgram(currentProgram, null, null, null, null, null);
                    gensig.scanFunctions(chunk.iterator(), chunk.size(), monitor);

                    DescriptionManager manager = gensig.getDescriptionManager();
                    int signed = manager.numFunctions();
                    skippedNoSig += chunk.size() - signed;
                    if (signed == 0) {
                        continue;
                    }

                    QueryNearest query = new QueryNearest();
                    query.manage = manager;
                    query.max = maxMatches;
                    query.thresh = simThresh;
                    query.signifthresh = signifThresh;

                    ResponseNearest response = query.execute(database);
                    if (response == null) {
                        String errMsg = database.getLastError() != null
                            ? database.getLastError().message : "Unknown query error";
                        println("{\"status\": \"error\", \"error\": \"Query failed at chunk " + start
                            + ": " + escapeJson(errMsg) + "\"}");
                        return;
                    }

                    // Index results by address so unmatched functions still get a line
                    java.util.Map<Long, SimilarityResult> byAddr = new java.util.HashMap<>();
                    if (response.result != null) {
                        for (SimilarityResult sim : response.result) {
                            byAddr.put(sim.getBase().getAddress(), sim);
                        }
                    }

                    for (Function f : chunk) {
                        long addr = f.getEntryPoint().getOffset();
                        StringBuilder sb = new StringBuilder();
                        sb.append("{\"query_function\":\"").append(escapeJson(f.getName()))
                          .append("\",\"query_address\":\"0x").append(Long.toHexString(addr))
                          .append("\",\"body_size\":").append(f.getBody().getNumAddresses())
                          .append(",\"matches\":[");
                        SimilarityResult sim = byAddr.get(addr);
                        int n = 0;
                        if (sim != null) {
                            Iterator<SimilarityNote> noteIter = sim.iterator();
                            while (noteIter.hasNext()) {
                                SimilarityNote note = noteIter.next();
                                FunctionDescription matchDesc = note.getFunctionDescription();
                                ExecutableRecord matchExe = matchDesc.getExecutableRecord();
                                if (n > 0) {
                                    sb.append(',');
                                }
                                sb.append("{\"exe\":\"").append(escapeJson(matchExe.getNameExec()))
                                  .append("\",\"name\":\"").append(escapeJson(matchDesc.getFunctionName()))
                                  .append("\",\"addr\":\"0x").append(Long.toHexString(matchDesc.getAddress()))
                                  .append("\",\"sim\":").append(note.getSimilarity())
                                  .append(",\"signif\":").append(note.getSignificance())
                                  .append('}');
                                n++;
                            }
                        }
                        sb.append("]}");
                        out.println(sb);
                        queried++;
                        if (n > 0) {
                            withMatches++;
                            totalMatches += n;
                        }
                    }
                    out.flush();
                }
                finally {
                    gensig.dispose();
                }
                monitor.checkCancelled();
            }
        }
        finally {
            if (database != null) {
                try {
                    database.close();
                }
                catch (Exception ignored) {
                    // nothing useful to do on close failure
                }
            }
        }

        println("{\"status\":\"success\",\"program\":\"" + escapeJson(currentProgram.getName())
            + "\",\"queried\":" + queried + ",\"with_matches\":" + withMatches
            + ",\"total_matches\":" + totalMatches + ",\"skipped_no_signature\":" + skippedNoSig
            + ",\"output\":\"" + escapeJson(outputPath) + "\"}");
    }

    private String escapeJson(String s) {
        if (s == null) {
            return "";
        }
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }
}
