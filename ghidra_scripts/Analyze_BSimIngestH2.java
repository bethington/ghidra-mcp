// BSim Ingest H2
//
// Generates BSim feature vectors (LSH signatures) for every function in the current program and inserts them into an H2 database. One-time per binary.
//
// Usage: Args: [0]=H2 database path (default: C:/tmp/bsim_diablo2). Run after BSimCreateH2Database.
// Output: Populates the H2 BSim database with function signatures.
//
// @author Ben Ethington
// @category Diablo 2.Analysis
// @description Ingest all functions into an H2 file-based BSim database
// @menupath Diablo 2.Analysis.BSim Ingest H2

import java.io.File;
import java.net.URL;
import java.util.Iterator;

import generic.lsh.vector.LSHVectorFactory;
import ghidra.app.script.GhidraScript;
import ghidra.features.bsim.query.BSimClientFactory;
import ghidra.features.bsim.query.BSimServerInfo;
import ghidra.features.bsim.query.FunctionDatabase;
import ghidra.features.bsim.query.FunctionDatabase.ErrorCategory;
import ghidra.features.bsim.query.GenSignatures;
import ghidra.features.bsim.query.description.DatabaseInformation;
import ghidra.features.bsim.query.description.DescriptionManager;
import ghidra.features.bsim.query.file.BSimH2FileDBConnectionManager;
import ghidra.features.bsim.query.file.BSimH2FileDBConnectionManager.BSimH2FileDataSource;
import ghidra.features.bsim.query.protocol.InsertRequest;
import ghidra.features.bsim.query.protocol.QueryExeCount;
import ghidra.features.bsim.query.protocol.ResponseExe;
import ghidra.features.bsim.query.protocol.ResponseInsert;
import ghidra.framework.model.DomainFile;
import ghidra.framework.protocol.ghidra.GhidraURL;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;

public class Analyze_BSimIngestH2 extends GhidraScript {

    private static final String DEFAULT_DB_PATH = "C:/tmp/bsim_diablo2";

    @Override
    protected void run() throws Exception {
        if (currentProgram == null) {
            println("{\"status\": \"error\", \"error\": \"No program is open\"}");
            return;
        }

        String dbPath = DEFAULT_DB_PATH;

        String[] args = getScriptArgs();
        if (args != null && args.length > 0 && args[0] != null && !args[0].isEmpty()) {
            dbPath = args[0].trim();
        } else if (!isRunningHeadless()) {
            dbPath = askString("BSim H2 Ingest",
                "Enter H2 BSim database path (without .mv.db):", DEFAULT_DB_PATH);
        }

        String programName = currentProgram.getName();
        String md5 = currentProgram.getExecutableMD5();

        println("{");
        println("  \"operation\": \"bsim_ingest_h2\",");
        println("  \"program\": \"" + escapeJson(programName) + "\",");
        println("  \"md5\": \"" + escapeJson(md5 != null ? md5 : "") + "\",");
        println("  \"db_path\": \"" + escapeJson(dbPath) + "\",");

        if (md5 == null || md5.length() < 10) {
            println("  \"status\": \"error\",");
            println("  \"error\": \"Program has no valid MD5 hash. Ensure it has been analyzed.\"");
            println("}");
            return;
        }

        // Check that the database file exists
        File testFile = new File(dbPath + BSimServerInfo.H2_FILE_EXTENSION);
        if (!testFile.exists()) {
            println("  \"status\": \"error\",");
            println("  \"error\": \"H2 database file not found: " + escapeJson(testFile.getAbsolutePath()) + ". Run BSimCreateH2Database first.\"");
            println("}");
            return;
        }

        BSimServerInfo serverInfo = new BSimServerInfo(dbPath);
        BSimH2FileDataSource existingBDS =
            BSimH2FileDBConnectionManager.getDataSourceIfExists(serverInfo);

        GenSignatures gensig = null;
        try (FunctionDatabase h2Database = BSimClientFactory.buildClient(serverInfo, false)) {

            h2Database.initialize();
            DatabaseInformation dbInfo = h2Database.getInfo();
            LSHVectorFactory vectorFactory = h2Database.getLSHVectorFactory();

            // Initialize signature generator
            gensig = new GenSignatures(dbInfo.trackcallgraph);
            gensig.setVectorFactory(vectorFactory);
            gensig.addExecutableCategories(dbInfo.execats);
            gensig.addFunctionTags(dbInfo.functionTags);
            gensig.addDateColumnName(dbInfo.dateColumnName);

            // Resolve the program's repository path for BSim tracking
            DomainFile dFile = currentProgram.getDomainFile();
            URL fileURL = dFile.getSharedProjectURL(null);
            if (fileURL == null) {
                fileURL = dFile.getLocalProjectURL(null);
            }

            String repo = null;
            String path = null;
            if (fileURL != null) {
                path = GhidraURL.getProjectPathname(fileURL);
                int lastSlash = path.lastIndexOf('/');
                path = lastSlash == 0 ? "/" : path.substring(0, lastSlash);
                URL normalizedProjectURL = GhidraURL.getProjectURL(fileURL);
                repo = normalizedProjectURL.toExternalForm();
            } else {
                repo = "ghidra://localhost/" + state.getProject().getName();
                path = GenSignatures.getPathFromDomainFile(currentProgram);
            }

            println("  \"repo\": \"" + escapeJson(repo) + "\",");
            println("  \"path\": \"" + escapeJson(path) + "\",");

            // Open program in GenSignatures and scan all functions
            gensig.openProgram(currentProgram, null, null, null, repo, path);

            FunctionManager fman = currentProgram.getFunctionManager();
            int funcCount = fman.getFunctionCount();
            Iterator<Function> iter = fman.getFunctions(true);

            println("  \"total_functions\": " + funcCount + ",");

            gensig.scanFunctions(iter, funcCount, monitor);

            DescriptionManager manager = gensig.getDescriptionManager();
            int signedFunctions = manager.numFunctions();

            println("  \"signed_functions\": " + signedFunctions + ",");

            if (signedFunctions == 0) {
                println("  \"status\": \"skipped\",");
                println("  \"error\": \"No functions with bodies found to ingest\"");
                println("}");
                return;
            }

            // De-duplicate callgraph entries to avoid SQL constraint violations
            manager.listAllFunctions().forEachRemaining(fd -> fd.sortCallgraph());

            // Insert into BSim database
            InsertRequest insertReq = new InsertRequest();
            insertReq.manage = manager;
            ResponseInsert insertResponse = insertReq.execute(h2Database);

            if (insertResponse == null) {
                FunctionDatabase.BSimError lastError = h2Database.getLastError();
                if (lastError != null &&
                    (lastError.category == ErrorCategory.Format ||
                     lastError.category == ErrorCategory.Nonfatal)) {
                    println("  \"status\": \"skipped\",");
                    println("  \"error\": \"" + escapeJson(lastError.message) + "\"");
                    println("}");
                    return;
                }
                String errMsg = lastError != null ? lastError.message : "Unknown insert error";
                println("  \"status\": \"error\",");
                println("  \"error\": \"" + escapeJson(errMsg) + "\"");
                println("}");
                return;
            }

            // Get updated executable count
            QueryExeCount exeCount = new QueryExeCount();
            ResponseExe countResponse = exeCount.execute(h2Database);
            int totalExes = countResponse != null ? countResponse.recordCount : -1;

            println("  \"inserted_executables\": " + insertResponse.numexe + ",");
            println("  \"inserted_functions\": " + insertResponse.numfunc + ",");
            println("  \"database_name\": \"" + escapeJson(dbInfo.databasename) + "\",");
            println("  \"total_executables_in_db\": " + totalExes + ",");
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
            if (existingBDS == null) {
                BSimH2FileDataSource bds =
                    BSimH2FileDBConnectionManager.getDataSourceIfExists(serverInfo);
                if (bds != null) {
                    bds.dispose();
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
