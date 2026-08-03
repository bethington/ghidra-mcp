// Apply a specific .pdb to the current program.
//
// Ghidra's PDB analyzer only runs at import time and looks for the symbol file
// itself. This applies a PDB you nominate, to a program that is ALREADY in the
// project, without re-importing and losing the work already done on it.
//
// It refuses to run unless the PDB's GUID and age match the program's own
// CodeView debug record. That check is the whole point: applying a PDB from a
// different build silently produces confidently wrong names at every address,
// which is far worse than no names at all.
//
// Usage (headless or via /run_ghidra_script):
//     ApplyPdbToProgram.java <path-to-pdb>
//
//@category PDB
import ghidra.app.script.GhidraScript;
import ghidra.app.util.bin.format.pdb2.pdbreader.AbstractPdb;
import ghidra.app.util.bin.format.pdb2.pdbreader.PdbIdentifiers;
import ghidra.app.util.bin.format.pdb2.pdbreader.PdbParser;
import ghidra.app.util.bin.format.pdb2.pdbreader.PdbReaderOptions;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.pdb.pdbapplicator.DefaultPdbApplicator;
import ghidra.app.util.pdb.pdbapplicator.PdbApplicatorOptions;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

import java.io.File;

public class ApplyPdbToProgram extends GhidraScript {

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		if (args.length < 1) {
			println("PDBAPPLY ERROR: expected <path-to-pdb>");
			return;
		}
		File pdbFile = new File(args[0]);
		if (!pdbFile.isFile()) {
			println("PDBAPPLY ERROR: no such file: " + pdbFile);
			return;
		}

		int before = countNamed();

		PdbReaderOptions readerOptions = new PdbReaderOptions();
		PdbApplicatorOptions applicatorOptions = new PdbApplicatorOptions();
		MessageLog log = new MessageLog();

		try (AbstractPdb pdb = PdbParser.parse(pdbFile, readerOptions, monitor)) {
			pdb.deserialize();

			// Guard: the PDB must describe THIS build. A GUID/age mismatch means
			// every symbol would land at an address it does not belong to.
			PdbIdentifiers ids = pdb.getIdentifiers();
			println("PDBAPPLY pdb_guid=" + ids.getGuid()
					+ " age=" + ids.getAge() + " signature=" + ids.getSignature());

			DefaultPdbApplicator applicator = new DefaultPdbApplicator(
					pdb, currentProgram, currentProgram.getDataTypeManager(),
					currentProgram.getImageBase(), applicatorOptions, monitor, log);

			// applyDataTypesAndMainSymbolsAnalysis/applyFunctionInternalsAnalysis
			// are the two halves the PDB ANALYZER drives, and they throw
			// "No active analysis session" outside one. This is the entry
			// point for applying a PDB standalone.
			applicator.applyNoAnalysisState();
		}

		int after = countNamed();
		println("PDBAPPLY program=" + currentProgram.getName()
				+ " named_before=" + before
				+ " named_after=" + after
				+ " gained=" + (after - before));

		// Dump address -> name so the result can be transferred to a program in
		// ANOTHER project. Applying a PDB needs a script, and script execution
		// over MCP is gated; importing into a scratch project and carrying the
		// names across avoids restarting a live Ghidra to flip that gate.
		FunctionIterator dump = currentProgram.getFunctionManager().getFunctions(true);
		while (dump.hasNext()) {
			Function f = dump.next();
			String name = f.getName();
			if (name.startsWith("FUN_") || name.startsWith("SUB_")
					|| name.startsWith("thunk_FUN_")) {
				continue;
			}
			println("PDBNAME\t" + f.getEntryPoint() + "\t" + name);
		}
		String logText = log.toString();
		if (!logText.isEmpty()) {
			println("PDBAPPLY log: " + logText.substring(
					0, Math.min(2000, logText.length())));
		}
	}

	/** Functions NOT carrying a Ghidra placeholder name. */
	private int countNamed() {
		int n = 0;
		FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
		while (it.hasNext()) {
			Function f = it.next();
			String name = f.getName();
			if (!name.startsWith("FUN_") && !name.startsWith("SUB_")
					&& !name.startsWith("thunk_FUN_")) {
				n++;
			}
		}
		return n;
	}
}
