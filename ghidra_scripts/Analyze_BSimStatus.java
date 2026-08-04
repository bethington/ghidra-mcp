// BSim Status
//
// Simple status check for an H2 BSim database. Reports database info, executable count, and function count.
//
// Usage: Args: [0]=H2 database path (default: C:/tmp/bsim_diablo2).
// Output: Console output with database statistics.
//
// @author Ben Ethington
// @category Diablo 2.Analysis
// @description Check BSim H2 database status and contents
// @menupath Diablo 2.Analysis.BSim Status

import java.io.File;
import java.util.Iterator;
import ghidra.app.script.GhidraScript;
import ghidra.features.bsim.query.BSimClientFactory;
import ghidra.features.bsim.query.BSimServerInfo;
import ghidra.features.bsim.query.FunctionDatabase;
import ghidra.features.bsim.query.description.DatabaseInformation;
import ghidra.features.bsim.query.description.ExecutableRecord;
import ghidra.features.bsim.query.file.BSimH2FileDBConnectionManager;
import ghidra.features.bsim.query.file.BSimH2FileDBConnectionManager.BSimH2FileDataSource;
import ghidra.features.bsim.query.protocol.QueryExeCount;
import ghidra.features.bsim.query.protocol.QueryExeInfo;
import ghidra.features.bsim.query.protocol.ResponseExe;

public class Analyze_BSimStatus extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String dbPath = "C:/tmp/bsim_diablo2";
        String[] args = getScriptArgs();
        if (args != null && args.length > 0 && !args[0].isEmpty()) dbPath = args[0].trim();

        BSimServerInfo si = new BSimServerInfo(dbPath);
        BSimH2FileDataSource existing = BSimH2FileDBConnectionManager.getDataSourceIfExists(si);
        try (FunctionDatabase db = BSimClientFactory.buildClient(si, false)) {
            db.initialize();
            DatabaseInformation info = db.getInfo();
            QueryExeCount qc = new QueryExeCount();
            ResponseExe cr = qc.execute(db);
            println("Database: " + info.databasename);
            println("Total executables: " + (cr != null ? cr.recordCount : -1));

            QueryExeInfo qi = new QueryExeInfo();
            qi.limit = 200;
            qi.includeFakes = false;
            ResponseExe er = qi.execute(db);
            if (er != null && er.manage != null) {
                Iterator<ExecutableRecord> it = er.manage.getExecutableRecordSet().iterator();
                int totalFuncs = 0;
                while (it.hasNext()) {
                    ExecutableRecord r = it.next();
                    println("  " + r.getNameExec() + " | " + r.getPath() + " | md5=" + r.getMd5());
                }
            }
        } finally {
            if (existing == null) {
                BSimH2FileDataSource bds = BSimH2FileDBConnectionManager.getDataSourceIfExists(si);
                if (bds != null) bds.dispose();
            }
        }
    }
}
