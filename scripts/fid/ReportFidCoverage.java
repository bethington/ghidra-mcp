// Report Function ID coverage split by authored code vs library code.
//
// The benchmark binary is the only place this can be measured honestly: we
// wrote every game function in it, so anything FID does NOT claim is a
// quantified miss, and anything of OURS that FID claims is a false positive.
// Reading those two numbers on a controlled binary is what justifies trusting
// the same tooling on the D2 binaries, where ground truth does not exist.
//
// Prints one summary line plus the unidentified library functions, so a shell
// can scrape it and a human can eyeball what is still missing.
//
//@category FunctionID
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.Function;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.TreeSet;

public class ReportFidCoverage extends GhidraScript {

	private static final String FID_CATEGORY = "Function ID Analyzer";

	/** Everything hand-authored in fun-doc/benchmark/src/*.c. */
	private static final Set<String> AUTHORED = new HashSet<>(Arrays.asList(
		"calc_crc16", "compute_gcd", "compute_str_len",
		"get_stat_list_flags", "get_stat_list_layer",
		"get_stat_list_owner_guid", "get_stat_list_prev_link",
		"stat_list_add", "advance_parser_state",
		"dllmain", "DllMain", "build_sibling_path", "require_export", "main"));

	@Override
	protected void run() throws Exception {
		int authored = 0, authoredClaimed = 0, lib = 0, libClaimed = 0;
		Set<String> missed = new TreeSet<>();
		Set<String> falsePositives = new TreeSet<>();

		for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
			String name = f.getName();
			boolean claimed = hasFidBookmark(f.getEntryPoint());
			// Strip any stdcall decoration before matching our source names.
			String bare = name.startsWith("_") ? name.substring(1) : name;
			int at = bare.indexOf('@');
			if (at > 0) {
				bare = bare.substring(0, at);
			}

			if (AUTHORED.contains(bare)) {
				authored++;
				if (claimed) {
					authoredClaimed++;
					falsePositives.add(name);
				}
			}
			else {
				lib++;
				if (claimed) {
					libClaimed++;
				}
				else {
					missed.add(name);
				}
			}
		}

		int pct = lib == 0 ? 0 : (100 * libClaimed) / lib;
		println("FIDCOVERAGE program=" + currentProgram.getName()
				+ " authored=" + authored
				+ " authored_falsely_claimed=" + authoredClaimed
				+ " library=" + lib
				+ " library_identified=" + libClaimed
				+ " library_missed=" + missed.size()
				+ " coverage_pct=" + pct);

		if (!falsePositives.isEmpty()) {
			println("FALSE POSITIVES (FID claimed our own code): " + falsePositives);
		}
		int shown = 0;
		for (String m : missed) {
			println("  MISSED " + m);
			if (++shown >= 40) {
				println("  ... and " + (missed.size() - shown) + " more");
				break;
			}
		}
	}

	private boolean hasFidBookmark(Address addr) {
		for (Bookmark b : currentProgram.getBookmarkManager().getBookmarks(addr)) {
			if (FID_CATEGORY.equals(b.getCategory())) {
				return true;
			}
		}
		return false;
	}
}
