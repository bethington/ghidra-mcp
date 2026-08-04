// Dump every Function ID Analyzer match in the current program as TSV.
//
// CountFidMatches answers "how many?", which is enough to A/B a database.
// This answers "which ones, and what would they be called?", which is what you
// need before re-running the FID analyzer over a program that has ALREADY been
// documented: the analyzer's bookmark is harmless, but a name it applies over
// hand-written or LLM-written documentation is not. Run this on a throwaway
// fresh import, diff the names against the live program, and you know exactly
// what a re-analysis would touch before you let it touch anything.
//
// Output is one machine-greppable line per match:
//
//     FIDMATCH<TAB>address<TAB>single|multiple<TAB>fid_name<TAB>current_name
//
//@category FunctionID
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.Function;

import java.util.Iterator;

public class DumpFidMatches extends GhidraScript {

	private static final String FID_CATEGORY = "Function ID Analyzer";

	@Override
	protected void run() throws Exception {
		BookmarkManager manager = currentProgram.getBookmarkManager();
		int total = 0;

		println("FIDDUMP program=" + currentProgram.getName()
				+ " base=" + currentProgram.getImageBase()
				+ " functions=" + currentProgram.getFunctionManager().getFunctionCount());

		Iterator<Bookmark> it = manager.getBookmarksIterator("Analysis");
		while (it.hasNext()) {
			Bookmark bookmark = it.next();
			if (!FID_CATEGORY.equals(bookmark.getCategory())) {
				continue;
			}
			total++;
			Address address = bookmark.getAddress();
			String comment = bookmark.getComment() == null ? "" : bookmark.getComment();
			String kind = comment.contains("Multiple") ? "multiple" : "single";

			// "Library Function - Single Match,  ___crtExitProcess"
			// "Library Function - Multiple Matches, Different  __time32"
			// The name is whatever follows the last comma, and the analyzer
			// emits two spaces after it. A multi-match bookmark can carry
			// several names, so keep the whole tail rather than guessing.
			String name = comment;
			int comma = comment.lastIndexOf(',');
			if (comma >= 0 && comma + 1 < comment.length()) {
				name = comment.substring(comma + 1).trim();
			}

			Function function = getFunctionContaining(address);
			String current = function == null ? "<no-function>" : function.getName();

			println("FIDMATCH\t" + address + "\t" + kind + "\t" + name + "\t" + current);
		}

		println("FIDDUMP total=" + total);
	}
}
