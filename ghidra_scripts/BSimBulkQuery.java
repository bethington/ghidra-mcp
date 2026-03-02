// Bulk query all undocumented functions (FUN_*) against a BSim database.
// Finds functions that still have default names and queries each against BSim
// to find matches from other ingested binaries. Returns a JSON summary.
//
// Script args: [0] = BSim URL (default: postgresql://10.0.10.30:5432/bsim)
//              [1] = max matches per function (default: 5)
//              [2] = similarity threshold 0.0-1.0 (default: 0.7)
//              [3] = confidence/significance threshold (default: 10.0)
//              [4] = max functions to query, 0=all (default: 0)
//
// Usage from MCP: run_script("BSimBulkQuery", args=["postgresql://10.0.10.30:5432/bsim"])
// Usage from MCP: run_script("BSimBulkQuery", args=["postgresql://10.0.10.30:5432/bsim", "5", "0.7", "10.0", "100"])
//@category BSim
//@keybinding
//@menupath
//@toolbar

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

public class BSimBulkQuery extends GhidraScript {

    private static final String DEFAULT_BSIM_URL = "postgresql://10.0.10.30:5432/bsim";
    private static final int DEFAULT_MAX_MATCHES = 5;
    private static final double DEFAULT_SIMILARITY = 0.7;
    private static final double DEFAULT_CONFIDENCE = 10.0;
    private static final int DEFAULT_MAX_FUNCTIONS = 0; // 0 = all

    @Override
    protected void run() throws Exception {
        if (currentProgram == null) {
            println("{\"status\": \"error\", \"error\": \"No program is open\"}");
            return;
        }

        // Parse arguments
        String[] args = getScriptArgs();
        String bsimUrl = DEFAULT_BSIM_URL;
        int maxMatches = DEFAULT_MAX_MATCHES;
        double similarityThresh = DEFAULT_SIMILARITY;
        double confidenceThresh = DEFAULT_CONFIDENCE;
        int maxFunctions = DEFAULT_MAX_FUNCTIONS;

        if (args != null && args.length > 0 && args[0] != null && !args[0].isEmpty()) {
            bsimUrl = args[0].trim();
        } else if (!isRunningHeadless()) {
            bsimUrl = askString("BSim Bulk Query",
                "Enter BSim database URL:", DEFAULT_BSIM_URL);
        }
        if (args != null && args.length > 1 && args[1] != null && !args[1].isEmpty()) {
            maxMatches = Integer.parseInt(args[1].trim());
        }
        if (args != null && args.length > 2 && args[2] != null && !args[2].isEmpty()) {
            similarityThresh = Double.parseDouble(args[2].trim());
        }
        if (args != null && args.length > 3 && args[3] != null && !args[3].isEmpty()) {
            confidenceThresh = Double.parseDouble(args[3].trim());
        }
        if (args != null && args.length > 4 && args[4] != null && !args[4].isEmpty()) {
            maxFunctions = Integer.parseInt(args[4].trim());
        }

        // Collect all undocumented functions (FUN_* prefix = default auto-analysis names)
        FunctionManager fman = currentProgram.getFunctionManager();
        List<Function> undocumented = new ArrayList<>();
        FunctionIterator fiter = fman.getFunctions(true);
        while (fiter.hasNext()) {
            Function f = fiter.next();
            String name = f.getName();
            if (name.startsWith("FUN_") || name.startsWith("fun_")) {
                undocumented.add(f);
                if (maxFunctions > 0 && undocumented.size() >= maxFunctions) {
                    break;
                }
            }
        }

        int totalFunctions = fman.getFunctionCount();

        println("{");
        println("  \"operation\": \"bsim_bulk_query\",");
        println("  \"program\": \"" + escapeJson(currentProgram.getName()) + "\",");
        println("  \"url\": \"" + escapeJson(bsimUrl) + "\",");
        println("  \"total_functions\": " + totalFunctions + ",");
        println("  \"undocumented_functions\": " + undocumented.size() + ",");
        println("  \"similarity_threshold\": " + similarityThresh + ",");
        println("  \"confidence_threshold\": " + confidenceThresh + ",");
        println("  \"max_matches_per_function\": " + maxMatches + ",");

        if (undocumented.isEmpty()) {
            println("  \"functions_with_matches\": 0,");
            println("  \"results\": [],");
            println("  \"status\": \"success\",");
            println("  \"message\": \"No undocumented (FUN_*) functions found\"");
            println("}");
            return;
        }

        FunctionDatabase database = null;
        GenSignatures gensig = null;
        try {
            URL url = BSimClientFactory.deriveBSimURL(bsimUrl);
            database = BSimClientFactory.buildClient(url, false);

            if (!database.initialize()) {
                String errMsg = database.getLastError() != null
                    ? database.getLastError().message : "Unknown error";
                println("  \"status\": \"error\",");
                println("  \"error\": \"Connection failed: " + escapeJson(errMsg) + "\"");
                println("}");
                return;
            }

            // Generate signatures for ALL undocumented functions at once (batch)
            gensig = new GenSignatures(false);
            gensig.setVectorFactory(database.getLSHVectorFactory());
            gensig.openProgram(currentProgram, null, null, null, null, null);

            // Scan all undocumented functions in one pass for efficiency
            gensig.scanFunctions(undocumented.iterator(), undocumented.size(), monitor);

            DescriptionManager manager = gensig.getDescriptionManager();
            int signedCount = manager.numFunctions();

            println("  \"signed_functions\": " + signedCount + ",");

            if (signedCount == 0) {
                println("  \"functions_with_matches\": 0,");
                println("  \"results\": [],");
                println("  \"status\": \"success\",");
                println("  \"message\": \"No functions produced valid signatures\"");
                println("}");
                return;
            }

            // Query BSim for nearest matches
            QueryNearest query = new QueryNearest();
            query.manage = manager;
            query.max = maxMatches;
            query.thresh = similarityThresh;
            query.signifthresh = confidenceThresh;

            ResponseNearest response = query.execute(database);
            if (response == null) {
                String errMsg = database.getLastError() != null
                    ? database.getLastError().message : "Unknown query error";
                println("  \"status\": \"error\",");
                println("  \"error\": \"Query failed: " + escapeJson(errMsg) + "\"");
                println("}");
                return;
            }

            // Process results
            println("  \"results\": [");

            int functionsWithMatches = 0;
            int totalMatchesFound = 0;
            boolean firstResult = true;

            if (response.result != null) {
                Iterator<SimilarityResult> resultIter = response.result.iterator();
                while (resultIter.hasNext()) {
                    SimilarityResult sim = resultIter.next();
                    FunctionDescription baseDesc = sim.getBase();

                    // Collect all notes for this function
                    List<SimilarityNote> notes = new ArrayList<>();
                    Iterator<SimilarityNote> noteIter = sim.iterator();
                    while (noteIter.hasNext()) {
                        notes.add(noteIter.next());
                    }

                    if (notes.isEmpty()) {
                        continue;
                    }

                    functionsWithMatches++;

                    if (!firstResult) {
                        println(",");
                    }
                    firstResult = false;

                    String baseFuncName = baseDesc.getFunctionName();
                    long baseFuncAddr = baseDesc.getAddress();

                    println("    {");
                    println("      \"query_function\": \"" + escapeJson(baseFuncName) + "\",");
                    println("      \"query_address\": \"0x" + Long.toHexString(baseFuncAddr) + "\",");
                    println("      \"match_count\": " + notes.size() + ",");
                    println("      \"best_similarity\": " + (notes.isEmpty() ? 0.0 : notes.get(0).getSimilarity()) + ",");
                    println("      \"matches\": [");

                    for (int i = 0; i < notes.size(); i++) {
                        SimilarityNote note = notes.get(i);
                        FunctionDescription matchDesc = note.getFunctionDescription();
                        ExecutableRecord matchExe = matchDesc.getExecutableRecord();

                        println("        {");
                        println("          \"executable\": \"" + escapeJson(matchExe.getNameExec()) + "\",");
                        println("          \"executable_md5\": \"" + escapeJson(matchExe.getMd5()) + "\",");
                        println("          \"architecture\": \"" + escapeJson(matchExe.getArchitecture()) + "\",");
                        println("          \"function_name\": \"" + escapeJson(matchDesc.getFunctionName()) + "\",");
                        println("          \"function_address\": \"0x" + Long.toHexString(matchDesc.getAddress()) + "\",");
                        println("          \"similarity\": " + note.getSimilarity() + ",");
                        println("          \"significance\": " + note.getSignificance());

                        String noteComma = (i < notes.size() - 1) ? "," : "";
                        println("        }" + noteComma);
                        totalMatchesFound++;
                    }

                    println("      ]");
                    print("    }");
                }
            }

            if (!firstResult) {
                println("");
            }
            println("  ],");
            println("  \"functions_with_matches\": " + functionsWithMatches + ",");
            println("  \"total_matches_found\": " + totalMatchesFound + ",");
            println("  \"functions_without_matches\": " + (signedCount - functionsWithMatches) + ",");
            println("  \"status\": \"success\"");
            println("}");

        } catch (Exception e) {
            println("  \"status\": \"error\",");
            println("  \"error\": \"" + escapeJson(e.getClass().getSimpleName() + ": " + e.getMessage()) + "\"");
            println("}");
        } finally {
            if (gensig != null) {
                gensig.dispose();
            }
            if (database != null) {
                try {
                    database.close();
                } catch (Exception ignored) {
                }
            }
        }
    }

    private String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }
}
