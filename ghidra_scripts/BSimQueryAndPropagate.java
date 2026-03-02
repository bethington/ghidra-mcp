// Query BSim database for matches to a specific function, returning results as JSON.
// Designed for use in the RE loop PROPAGATE phase to find cross-version matches.
//
// Script args: [0] = function address (hex, e.g. "0x10001000")
//              [1] = BSim URL (default: postgresql://10.0.10.30:5432/bsim)
//              [2] = max matches per function (default: 10)
//              [3] = similarity threshold 0.0-1.0 (default: 0.7)
//              [4] = confidence/significance threshold (default: 0.0)
//
// Usage from MCP: run_script("BSimQueryAndPropagate", args=["0x10001000"])
// Usage from MCP: run_script("BSimQueryAndPropagate", args=["0x10001000", "postgresql://10.0.10.30:5432/bsim", "10", "0.7", "0.0"])
//@category BSim
//@keybinding
//@menupath
//@toolbar

import java.net.URL;
import java.util.Iterator;

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
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

public class BSimQueryAndPropagate extends GhidraScript {

    private static final String DEFAULT_BSIM_URL = "postgresql://10.0.10.30:5432/bsim";
    private static final int DEFAULT_MAX_MATCHES = 10;
    private static final double DEFAULT_SIMILARITY = 0.7;
    private static final double DEFAULT_CONFIDENCE = 0.0;

    @Override
    protected void run() throws Exception {
        if (currentProgram == null) {
            println("{\"status\": \"error\", \"error\": \"No program is open\"}");
            return;
        }

        // Parse arguments
        String[] args = getScriptArgs();
        String addressStr = null;
        String bsimUrl = DEFAULT_BSIM_URL;
        int maxMatches = DEFAULT_MAX_MATCHES;
        double similarityThresh = DEFAULT_SIMILARITY;
        double confidenceThresh = DEFAULT_CONFIDENCE;

        if (args != null && args.length > 0 && args[0] != null && !args[0].isEmpty()) {
            addressStr = args[0].trim();
        }
        if (args != null && args.length > 1 && args[1] != null && !args[1].isEmpty()) {
            bsimUrl = args[1].trim();
        }
        if (args != null && args.length > 2 && args[2] != null && !args[2].isEmpty()) {
            maxMatches = Integer.parseInt(args[2].trim());
        }
        if (args != null && args.length > 3 && args[3] != null && !args[3].isEmpty()) {
            similarityThresh = Double.parseDouble(args[3].trim());
        }
        if (args != null && args.length > 4 && args[4] != null && !args[4].isEmpty()) {
            confidenceThresh = Double.parseDouble(args[4].trim());
        }

        // If no address from args, try interactive or current address
        if (addressStr == null || addressStr.isEmpty()) {
            if (!isRunningHeadless()) {
                addressStr = askString("BSim Query",
                    "Enter function address (hex):", currentAddress.toString());
            } else {
                // Use current address in headless mode
                addressStr = currentAddress != null ? currentAddress.toString() : null;
            }
        }

        if (addressStr == null || addressStr.isEmpty()) {
            println("{\"status\": \"error\", \"error\": \"No function address specified\"}");
            return;
        }

        // Resolve the function at the given address
        Address addr = currentProgram.getAddressFactory().getDefaultAddressSpace()
            .getAddress(addressStr);
        Function func = currentProgram.getFunctionManager().getFunctionAt(addr);
        if (func == null) {
            func = getFunctionContaining(addr);
        }
        if (func == null) {
            println("{\"status\": \"error\", \"error\": \"No function at address " +
                escapeJson(addressStr) + "\"}");
            return;
        }

        String funcName = func.getName();
        String funcAddr = func.getEntryPoint().toString();

        println("{");
        println("  \"operation\": \"bsim_query_function\",");
        println("  \"program\": \"" + escapeJson(currentProgram.getName()) + "\",");
        println("  \"function_name\": \"" + escapeJson(funcName) + "\",");
        println("  \"function_address\": \"" + escapeJson(funcAddr) + "\",");
        println("  \"url\": \"" + escapeJson(bsimUrl) + "\",");
        println("  \"max_matches\": " + maxMatches + ",");
        println("  \"similarity_threshold\": " + similarityThresh + ",");
        println("  \"confidence_threshold\": " + confidenceThresh + ",");

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

            // Generate signature for the target function
            gensig = new GenSignatures(false);
            gensig.setVectorFactory(database.getLSHVectorFactory());
            gensig.openProgram(currentProgram, null, null, null, null, null);
            gensig.scanFunction(func);

            DescriptionManager manager = gensig.getDescriptionManager();

            if (manager.numFunctions() == 0) {
                println("  \"status\": \"error\",");
                println("  \"error\": \"Failed to generate signature for function (may be a thunk or stub)\"");
                println("}");
                return;
            }

            // Build and execute the nearest-match query
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
            println("  \"total_functions_queried\": " + response.totalfunc + ",");
            println("  \"total_matches\": " + response.totalmatch + ",");
            println("  \"unique_matches\": " + response.uniquematch + ",");
            println("  \"matches\": [");

            int matchIndex = 0;
            if (response.result != null) {
                Iterator<SimilarityResult> resultIter = response.result.iterator();
                while (resultIter.hasNext()) {
                    SimilarityResult sim = resultIter.next();
                    FunctionDescription baseDesc = sim.getBase();

                    Iterator<SimilarityNote> noteIter = sim.iterator();
                    while (noteIter.hasNext()) {
                        SimilarityNote note = noteIter.next();
                        FunctionDescription matchDesc = note.getFunctionDescription();
                        ExecutableRecord matchExe = matchDesc.getExecutableRecord();

                        if (matchIndex > 0) {
                            println(",");
                        }
                        println("    {");
                        println("      \"executable\": \"" + escapeJson(matchExe.getNameExec()) + "\",");
                        println("      \"executable_md5\": \"" + escapeJson(matchExe.getMd5()) + "\",");
                        println("      \"architecture\": \"" + escapeJson(matchExe.getArchitecture()) + "\",");
                        println("      \"function_name\": \"" + escapeJson(matchDesc.getFunctionName()) + "\",");
                        println("      \"function_address\": \"0x" + Long.toHexString(matchDesc.getAddress()) + "\",");
                        println("      \"similarity\": " + note.getSimilarity() + ",");
                        println("      \"significance\": " + note.getSignificance());
                        print("    }");
                        matchIndex++;
                    }
                }
            }

            if (matchIndex > 0) {
                println("");
            }
            println("  ],");
            println("  \"match_count\": " + matchIndex + ",");
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
