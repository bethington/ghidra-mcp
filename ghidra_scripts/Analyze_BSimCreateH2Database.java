// BSim Create H2 Database
//
// Creates a new H2 file-based BSim database for local similarity analysis. Works headlessly from MCP without any GUI prompts or dialogs.
//
// Usage: Args: [0]=database file path (no .mv.db extension), [1]=template name (default: medium_32), [2]=display name.
// Output: Creates H2 database file at the specified path.
//
// @author Ben Ethington
// @category Diablo 2.Analysis
// @description Create an H2 file-based BSim database without GUI dialogs
// @menupath Diablo 2.Analysis.BSim Create H2 Database

import java.io.File;
import java.io.IOException;

import ghidra.app.script.GhidraScript;
import ghidra.features.bsim.query.BSimClientFactory;
import ghidra.features.bsim.query.BSimServerInfo;
import ghidra.features.bsim.query.FunctionDatabase;
import ghidra.features.bsim.query.description.DatabaseInformation;
import ghidra.features.bsim.query.file.BSimH2FileDBConnectionManager;
import ghidra.features.bsim.query.file.BSimH2FileDBConnectionManager.BSimH2FileDataSource;
import ghidra.features.bsim.query.protocol.CreateDatabase;
import ghidra.features.bsim.query.protocol.InstallCategoryRequest;
import ghidra.features.bsim.query.protocol.ResponseInfo;

public class Analyze_BSimCreateH2Database extends GhidraScript {

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();

        // Parse args
        String dbPath = "C:/tmp/bsim_diablo2";
        String template = "medium_32";
        String dbName = "Diablo2_BSim";

        if (args != null && args.length > 0 && !args[0].isEmpty()) {
            dbPath = args[0].trim();
        }
        if (args != null && args.length > 1 && !args[1].isEmpty()) {
            template = args[1].trim();
        }
        if (args != null && args.length > 2 && !args[2].isEmpty()) {
            dbName = args[2].trim();
        } else {
            // Derive name from path
            File f = new File(dbPath);
            dbName = f.getName();
        }

        println("{");
        println("  \"operation\": \"create_h2_bsim_database\",");
        println("  \"path\": \"" + escapeJson(dbPath) + "\",");
        println("  \"template\": \"" + escapeJson(template) + "\",");
        println("  \"name\": \"" + escapeJson(dbName) + "\",");

        // Check if file already exists
        File testFile = new File(dbPath + BSimServerInfo.H2_FILE_EXTENSION);
        if (testFile.exists()) {
            println("  \"status\": \"already_exists\",");
            println("  \"message\": \"Database file already exists at " + escapeJson(testFile.getAbsolutePath()) + "\"");
            println("}");
            return;
        }

        BSimServerInfo serverInfo = new BSimServerInfo(dbPath);
        BSimH2FileDataSource existingBDS =
            BSimH2FileDBConnectionManager.getDataSourceIfExists(serverInfo);

        try (FunctionDatabase h2Database = BSimClientFactory.buildClient(serverInfo, false)) {
            CreateDatabase command = new CreateDatabase();
            command.info = new DatabaseInformation();
            command.info.databasename = dbName;
            command.config_template = template;
            command.info.trackcallgraph = true;

            ResponseInfo response = command.execute(h2Database);
            if (response == null) {
                String errMsg = h2Database.getLastError() != null
                    ? h2Database.getLastError().message : "Unknown error";
                println("  \"status\": \"error\",");
                println("  \"error\": \"" + escapeJson(errMsg) + "\"");
                println("}");
                return;
            }

            // Add a "version" category so we can tag executables by game version
            InstallCategoryRequest catReq = new InstallCategoryRequest();
            catReq.type_name = "Version";
            catReq.execute(h2Database);

            println("  \"status\": \"success\",");
            println("  \"h2_file\": \"" + escapeJson(testFile.getAbsolutePath()) + "\"");
            println("}");

        } finally {
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
