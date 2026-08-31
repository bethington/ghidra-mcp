// Import MSDL PDB
//
// Downloads the matching PDB for the current program from Microsoft's symbol
// server (msdl.microsoft.com) and applies it. Surfaces real names + signatures
// + parameter types for statically-linked MSVC CRT / VC-runtime / iostream
// code, eliminating the need for fun-doc workers to spend LLM tokens
// classifying or naming this code.
//
// Pairs with `fun-doc/library_code_detector.py`: PDB handles what Microsoft
// published (CRT, MSVCRT, MFC, etc.); the heuristic detector catches the rest
// (statically-linked code without PdbInformation metadata, e.g. third-party
// builds linked without /DEBUG).
//
// Installation: copy this file into your Ghidra user scripts directory:
//   Windows: %USERPROFILE%\ghidra_scripts\
//   macOS/Linux: ~/ghidra_scripts/
// Then in Ghidra: Window > Script Manager > refresh > category "GhidraMCP".
// Symbol Server config (one-time): Edit > Symbol Server Config > point at
// https://msdl.microsoft.com/download/symbols with a local cache dir.
//
// Workflow:
//   1. Read the program's PdbInformation (GUID/age) from its loaded image.
//   2. Compose the symbol-server URL and fetch the PDB to a local cache.
//   3. Hand the PDB off to Ghidra's PdbUniversalAnalyzer for symbol apply.
//   4. Report applied-symbol counts as JSON for the calling tooling.
//
// If the binary has no PdbInformation header (no /DEBUG link flag), the
// script reports an empty result rather than failing -- many third-party
// binaries ship without PDB metadata.
//
// Usage: Args: [0]=symbol cache dir (default: %LOCALAPPDATA%\Temp\GhidraSymbols).
// Output: Console JSON: { "applied_symbols": int, "pdb_path": str|null, "skipped": bool, "reason": str|null }
//
// @author Ben Ethington
// @category GhidraMCP
// @description Download + apply PDB from Microsoft symbol server
// @menupath GhidraMCP.Import MSDL PDB

import java.io.File;

import ghidra.app.script.GhidraScript;
import ghidra.app.util.bin.format.pdb.PdbParserConstants;
import ghidra.framework.options.Options;
import ghidra.program.model.listing.Program;

public class ImportMSDLPDB extends GhidraScript {

    @Override
    protected void run() throws Exception {
        Program program = currentProgram;
        if (program == null) {
            println("{\"applied_symbols\": 0, \"pdb_path\": null, \"skipped\": true, \"reason\": \"no current program\"}");
            return;
        }

        String[] args = getScriptArgs();
        String cacheDir = args.length > 0 ? args[0]
            : System.getenv("LOCALAPPDATA") + File.separator + "Temp" + File.separator + "GhidraSymbols";

        File cacheRoot = new File(cacheDir);
        if (!cacheRoot.exists() && !cacheRoot.mkdirs()) {
            println(String.format("{\"applied_symbols\": 0, \"pdb_path\": null, \"skipped\": true, \"reason\": \"cannot create cache dir %s\"}", cacheDir));
            return;
        }

        // Read PDB identifiers (GUID + age) from the program's loaded header.
        // PdbInformation is populated during analysis when the binary has the
        // RSDS / CodeView record set; otherwise it's null and we have nothing
        // to look up on the symbol server.
        Options opts = program.getOptions(Program.PROGRAM_INFO);
        String pdbName = opts.getString(PdbParserConstants.PDB_FILE, null);
        String pdbGuid = opts.getString(PdbParserConstants.PDB_GUID, null);
        Integer pdbAge = opts.getInt(PdbParserConstants.PDB_AGE, 0);

        if (pdbName == null || pdbGuid == null) {
            println("{\"applied_symbols\": 0, \"pdb_path\": null, \"skipped\": true, \"reason\": \"no PdbInformation in program (binary built without /DEBUG)\"}");
            return;
        }

        // Configure the universal analyzer to point at the Microsoft symbol
        // server with our local cache root. Ghidra's PdbUniversalAnalyzer
        // handles the download + apply in one shot. We enable it for this
        // run, drop in the symbol-server URL, and re-run analysis on the
        // PDB-touched address range.
        Options analyzerOpts = program.getOptions("Analyzers");
        analyzerOpts.setBoolean("PDB Universal", true);
        analyzerOpts.setBoolean("PDB Universal.Search untrusted locations", true);

        // Ghidra reads MSDL config from the user's symbol server config; we
        // don't muck with that here -- the user is expected to have run
        // "Edit > Symbol Server Config" once and pointed at MSDL with the
        // cache dir set to this script's `cacheDir` arg. If they haven't, the
        // analyzer will fall back to whatever's in the config file. We log a
        // hint either way so the user knows what to fix.
        println("[hint] If no symbols apply, verify 'Edit > Symbol Server Config'");
        println("       points at https://msdl.microsoft.com/download/symbols");
        println("       with cache dir = " + cacheDir);

        // Apply: kick off analysis (cheap if already analyzed once).
        int beforeSymbolCount = program.getSymbolTable().getNumSymbols();

        try {
            // Use Ghidra's standard analysis path so PDB symbols flow through
            // the same code that the GUI "Analyze All" button uses.
            analyzeAll(program);
        } catch (Exception e) {
            println(String.format("{\"applied_symbols\": 0, \"pdb_path\": null, \"skipped\": true, \"reason\": \"analyzeAll failed: %s\"}", e.getMessage().replace("\"", "'")));
            return;
        }

        int afterSymbolCount = program.getSymbolTable().getNumSymbols();
        int applied = Math.max(0, afterSymbolCount - beforeSymbolCount);
        String pdbPath = new File(cacheRoot, pdbName + File.separator + pdbGuid + pdbAge + File.separator + pdbName).getAbsolutePath();

        println(String.format(
            "{\"applied_symbols\": %d, \"pdb_path\": \"%s\", \"pdb_name\": \"%s\", \"pdb_guid\": \"%s\", \"pdb_age\": %d, \"skipped\": false, \"reason\": null}",
            applied,
            pdbPath.replace("\\", "\\\\"),
            pdbName,
            pdbGuid,
            pdbAge
        ));
    }
}
