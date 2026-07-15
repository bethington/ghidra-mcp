// Test connectivity to a BSim PostgreSQL database and report database info as JSON.
// Script args: [0] = BSim URL (required in headless/MCP mode)
//
// Usage from MCP: run_script("BSimTestConnection", args=["postgresql://127.0.0.1:5432/bsim"])
// Usage from Ghidra Script Manager: will prompt for URL if no args provided
//@category BSim
//@keybinding
//@menupath
//@toolbar

import java.net.URL;

import ghidra.app.script.GhidraScript;
import ghidra.features.bsim.query.BSimClientFactory;
import ghidra.features.bsim.query.FunctionDatabase;
import ghidra.features.bsim.query.description.DatabaseInformation;
import ghidra.features.bsim.query.protocol.QueryExeCount;
import ghidra.features.bsim.query.protocol.QueryInfo;
import ghidra.features.bsim.query.protocol.ResponseExe;
import ghidra.features.bsim.query.protocol.ResponseInfo;

public class BSimTestConnection extends GhidraScript {

    @Override
    protected void run() throws Exception {
        String bsimUrl = null;

        // Check script args first (headless/MCP mode)
        String[] args = getScriptArgs();
        if (args != null && args.length > 0 && args[0] != null && !args[0].isEmpty()) {
            bsimUrl = args[0].trim();
        } else if (!isRunningHeadless()) {
            // Interactive mode: prompt the user
            bsimUrl = askString("BSim Connection Test",
                "Enter BSim database URL:", "").trim();
        }

        if (bsimUrl == null || bsimUrl.isEmpty()) {
            println("{\"status\": \"error\", \"error\": \"BSim URL is required; no default destination is configured\"}");
            return;
        }

        println("{");
        println("  \"operation\": \"bsim_test_connection\",");
        println("  \"url\": \"" + escapeJson(bsimUrl) + "\",");

        FunctionDatabase database = null;
        try {
            URL url = BSimClientFactory.deriveBSimURL(bsimUrl);
            database = BSimClientFactory.buildClient(url, false);

            if (!database.initialize()) {
                String errMsg = database.getLastError() != null
                    ? database.getLastError().message : "Unknown error";
                println("  \"status\": \"error\",");
                println("  \"error\": \"" + escapeJson(errMsg) + "\"");
                println("}");
                return;
            }

            // Connection succeeded - get database info
            DatabaseInformation dbInfo = database.getInfo();
            println("  \"status\": \"connected\",");
            println("  \"database_name\": \"" + escapeJson(dbInfo.databasename) + "\",");
            println("  \"owner\": \"" + escapeJson(dbInfo.owner != null ? dbInfo.owner : "") + "\",");
            println("  \"description\": \"" + escapeJson(dbInfo.description != null ? dbInfo.description : "") + "\",");
            println("  \"version\": \"" + dbInfo.major + "." + dbInfo.minor + "\",");
            println("  \"layout_version\": " + dbInfo.layout_version + ",");
            println("  \"settings\": " + dbInfo.settings + ",");
            println("  \"track_callgraph\": " + dbInfo.trackcallgraph + ",");
            println("  \"readonly\": " + dbInfo.readonly + ",");

            // Get executable count
            QueryExeCount exeCount = new QueryExeCount();
            ResponseExe countResponse = exeCount.execute(database);
            if (countResponse != null) {
                println("  \"executable_count\": " + countResponse.recordCount + ",");
            } else {
                println("  \"executable_count\": -1,");
            }

            // List executable categories if any
            if (dbInfo.execats != null && !dbInfo.execats.isEmpty()) {
                println("  \"executable_categories\": [");
                for (int i = 0; i < dbInfo.execats.size(); i++) {
                    String comma = (i < dbInfo.execats.size() - 1) ? "," : "";
                    println("    \"" + escapeJson(dbInfo.execats.get(i)) + "\"" + comma);
                }
                println("  ],");
            } else {
                println("  \"executable_categories\": [],");
            }

            // List function tags if any
            if (dbInfo.functionTags != null && !dbInfo.functionTags.isEmpty()) {
                println("  \"function_tags\": [");
                for (int i = 0; i < dbInfo.functionTags.size(); i++) {
                    String comma = (i < dbInfo.functionTags.size() - 1) ? "," : "";
                    println("    \"" + escapeJson(dbInfo.functionTags.get(i)) + "\"" + comma);
                }
                println("  ],");
            } else {
                println("  \"function_tags\": [],");
            }

            String dateCol = dbInfo.dateColumnName != null ? dbInfo.dateColumnName : "";
            println("  \"date_column\": \"" + escapeJson(dateCol) + "\"");
            println("}");

        } catch (Exception e) {
            println("  \"status\": \"error\",");
            println("  \"error\": \"" + escapeJson(e.getClass().getSimpleName() + ": " + e.getMessage()) + "\"");
            println("}");
        } finally {
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
