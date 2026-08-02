// Count Function ID Analyzer matches in the current program.
//
// Used to measure what a newly built FidDb actually buys: run the same binary
// through analyzeHeadless twice -- once with only the stock databases attached,
// once with the new one chained in via AttachFidDatabase -- and diff the
// counts. Prints one machine-greppable line so a shell can scrape it.
//
//@category FunctionID
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkManager;

import java.util.Iterator;

public class CountFidMatches extends GhidraScript {

	private static final String FID_CATEGORY = "Function ID Analyzer";

	@Override
	protected void run() throws Exception {
		BookmarkManager manager = currentProgram.getBookmarkManager();
		int total = 0;
		int single = 0;
		int multiple = 0;

		Iterator<Bookmark> it = manager.getBookmarksIterator("Analysis");
		while (it.hasNext()) {
			Bookmark bookmark = it.next();
			if (!FID_CATEGORY.equals(bookmark.getCategory())) {
				continue;
			}
			total++;
			String comment = bookmark.getComment() == null ? "" : bookmark.getComment();
			// "Library Function - Multiple Matches, Different  _printf" is a
			// weaker claim than "Single Match" and is worth counting apart.
			if (comment.contains("Multiple")) {
				multiple++;
			}
			else {
				single++;
			}
		}

		int functions = currentProgram.getFunctionManager().getFunctionCount();
		println("FIDCOUNT program=" + currentProgram.getName()
				+ " functions=" + functions
				+ " fid_total=" + total
				+ " fid_single=" + single
				+ " fid_multiple=" + multiple);
	}
}
