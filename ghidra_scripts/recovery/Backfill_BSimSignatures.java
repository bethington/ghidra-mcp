// Backfill_BSimSignatures.java
// Generates Ghidra BSim LSH signatures for every function in the current
// program and POSTs them to the cross-version doc archive to populate
// re_kb.functions.bsim_signature. This unlocks Phase 1.5 / Q2 tier 2 (BSim LSH
// similarity) for the matching cascade — without bsim_signature populated,
// tier 2 always misses.
//
// Both destinations are read from the environment and have no default:
//
//   GHIDRA_MCP_BSIM_URL      postgresql://<host>:5432/bsim   (required)
//   GHIDRA_MCP_ARCHIVE_URL   http://<host>:8422              (required to post)
//
// The LSH weighting configuration is pulled from the BSim database itself
// (matching what the existing Analyze_BSimIngestProgram.java uses) so vectors
// are comparable across all binaries that get ingested.
//
// Usage:
//   1. Run from any CodeBrowser's Script Manager, with ghidra_scripts/recovery
//      registered as a script directory.
//   2. Make sure the program you want signatures for is the active one
//      in CodeBrowser.
//   3. First run with PERFORM_POSTS = false. Script generates vectors and
//      logs counts without touching the archive.
//   4. Set PERFORM_POSTS = true and re-run. Each function's vector is
//      posted as a partial doc_archive upsert (only the bsim_signature
//      field; field-level merge resolution leaves everything else alone).
//   5. Repeat for each of the 30 binaries.
//
//@author benam
//@category Recovery
//@menupath Tools.Recovery.Backfill BSim Signatures

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Iterator;

import generic.lsh.vector.LSHVector;
import generic.lsh.vector.LSHVectorFactory;
import ghidra.app.script.GhidraScript;
import ghidra.features.bsim.query.BSimClientFactory;
import ghidra.features.bsim.query.FunctionDatabase;
import ghidra.features.bsim.query.GenSignatures;
import ghidra.features.bsim.query.description.DatabaseInformation;
import ghidra.features.bsim.query.description.DescriptionManager;
import ghidra.features.bsim.query.description.FunctionDescription;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;

public class Backfill_BSimSignatures extends GhidraScript {

    // === Configuration ===
    // Both destinations come from the environment and have no default. The
    // archive is opt-in by design (see DocumentationHashService, which reads
    // GHIDRA_MCP_ARCHIVE_URL the same way): a script that ships with a working
    // address posts somebody's binaries to somebody else's host the first time
    // it is run, and a guard test enforces that no such address is committed.
    private static final String  ARCHIVE_URL    = envOr("GHIDRA_MCP_ARCHIVE_URL", "");
    private static final String  BSIM_URL       = envOr("GHIDRA_MCP_BSIM_URL", "");
    private static final boolean PERFORM_POSTS  = false;  // <-- flip to true to write
    private static final int     BATCH_FLUSH_EVERY = 100;  // log progress every N

    private static String envOr(String name, String fallback) {
        String value = System.getenv(name);
        return (value == null || value.trim().isEmpty()) ? fallback : value.trim();
    }

    @Override
    public void run() throws Exception {
        Program program = currentProgram;
        if (program == null) {
            println("ERROR: open a program in CodeBrowser first");
            return;
        }

        if (BSIM_URL.isEmpty()) {
            println("ERROR: set GHIDRA_MCP_BSIM_URL (e.g. postgresql://host:5432/bsim)");
            return;
        }
        if (PERFORM_POSTS && ARCHIVE_URL.isEmpty()) {
            println("ERROR: PERFORM_POSTS is on but GHIDRA_MCP_ARCHIVE_URL is unset");
            return;
        }

        DomainFile df = program.getDomainFile();
        if (df == null) {
            println("ERROR: program has no DomainFile (orphan?)");
            return;
        }

        // (binary_name, version) match the Java extractVersion() heuristic in
        // DocumentationHashService.java for symmetry with archive_ingest_program.
        String binaryName = program.getName();
        String version = extractVersion(df.getPathname());
        println("Program: " + program.getName());
        println("DomainFile: " + df.getPathname());
        println("binary_name=" + binaryName + "  version=" + version);

        // --- Initialize BSim signature generator ---
        FunctionDatabase database = null;
        GenSignatures gensig = null;
        try {
            URL url = BSimClientFactory.deriveBSimURL(BSIM_URL);
            database = BSimClientFactory.buildClient(url, false);
            if (!database.initialize()) {
                println("ERROR: cannot initialize BSim client at " + BSIM_URL
                    + ": " + database.getLastError());
                return;
            }
            DatabaseInformation dbInfo = database.getInfo();
            LSHVectorFactory vectorFactory = database.getLSHVectorFactory();

            gensig = new GenSignatures(dbInfo.trackcallgraph);
            gensig.setVectorFactory(vectorFactory);
            gensig.addExecutableCategories(dbInfo.execats);
            gensig.addFunctionTags(dbInfo.functionTags);
            gensig.addDateColumnName(dbInfo.dateColumnName);
            gensig.openProgram(program, null, null, null, null, null);

            FunctionIterator iter = program.getFunctionManager().getFunctions(true);
            int funcCount = program.getFunctionManager().getFunctionCount();
            println("Scanning " + funcCount + " functions for signatures...");
            gensig.scanFunctions(iter, funcCount, monitor);

            DescriptionManager manager = gensig.getDescriptionManager();
            int signedFunctions = manager.numFunctions();
            println("Got " + signedFunctions + " signed functions");

            // --- Walk descriptions, POST per function ---
            int posted = 0;
            int skipped = 0;
            int errors = 0;
            int total = 0;
            Iterator<FunctionDescription> fdIt = manager.listAllFunctions();
            while (fdIt.hasNext()) {
                if (monitor.isCancelled()) break;
                FunctionDescription fd = fdIt.next();
                total++;
                LSHVector vec = fd.getSignatureRecord() != null
                    ? fd.getSignatureRecord().getLSHVector() : null;
                if (vec == null) {
                    skipped++;
                    continue;
                }

                // The Function we matched on (entry point + name)
                Function fn = program.getFunctionManager().getFunctionAt(
                    program.getAddressFactory().getDefaultAddressSpace()
                        .getAddress(fd.getAddress()));
                if (fn == null) {
                    skipped++;
                    continue;
                }
                String addr = "0x" + fn.getEntryPoint().toString();
                String sigText = vec.saveSQL();

                if (!PERFORM_POSTS) {
                    posted++;
                } else {
                    try {
                        postPartialSignature(binaryName, version, addr, sigText);
                        posted++;
                    } catch (Exception e) {
                        errors++;
                        if (errors <= 5) {
                            println("  POST error @" + addr + ": " + e.getMessage());
                        }
                    }
                }

                if (total % BATCH_FLUSH_EVERY == 0) {
                    println(String.format("  ... %d / %d  (posted=%d skipped=%d err=%d)",
                        total, signedFunctions, posted, skipped, errors));
                }
            }

            println("\n=== Summary ===");
            println("mode:       " + (PERFORM_POSTS ? "EXECUTED" : "DRY RUN"));
            println("scanned:    " + total);
            println("vectors:    " + posted);
            println("no-vector:  " + skipped);
            println("errors:     " + errors);
            if (!PERFORM_POSTS) {
                println("\nDRY RUN — set PERFORM_POSTS=true at top of script and re-run to write.");
            }
        } finally {
            if (gensig != null) gensig.dispose();
            if (database != null) database.close();
        }
    }

    private static String extractVersion(String pathname) {
        if (pathname == null) return "unknown";
        String[] parts = pathname.split("/");
        if (parts.length >= 3 && !parts[2].isEmpty()) return parts[2];
        return "unknown";
    }

    /**
     * POST a minimal upsert to the archive containing only the matching
     * keys + bsim_signature. The archive's field-level merge resolution
     * leaves all other fields (name, plate, locals, etc.) untouched.
     */
    private static void postPartialSignature(
            String binaryName, String version, String address, String sigText)
            throws Exception {
        String json = "{"
            + "\"binary_name\":\"" + escape(binaryName) + "\","
            + "\"version\":\"" + escape(version) + "\","
            + "\"address\":\"" + escape(address) + "\","
            + "\"source_run_id\":\"bsim-backfill\","
            + "\"source_tool\":\"bsim_backfill\","
            + "\"bsim_signature\":\"" + escape(sigText) + "\""
            + "}";
        URL url = new URL(ARCHIVE_URL + "/v1/doc_archive/upsert");
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setDoOutput(true);
        conn.setConnectTimeout(5000);
        conn.setReadTimeout(20000);
        try (OutputStream os = conn.getOutputStream()) {
            os.write(json.getBytes(StandardCharsets.UTF_8));
        }
        int code = conn.getResponseCode();
        if (code < 200 || code >= 300) {
            try (BufferedReader r = new BufferedReader(
                    new InputStreamReader(conn.getErrorStream(), StandardCharsets.UTF_8))) {
                StringBuilder body = new StringBuilder();
                String line;
                while ((line = r.readLine()) != null) body.append(line);
                throw new RuntimeException("HTTP " + code + ": " + body);
            }
        }
        // Drain success body to release connection
        try (BufferedReader r = new BufferedReader(
                new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
            while (r.readLine() != null) {}
        }
    }

    private static String escape(String s) {
        if (s == null) return "";
        StringBuilder sb = new StringBuilder(s.length() + 16);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"':  sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
                    else sb.append(c);
            }
        }
        return sb.toString();
    }
}
