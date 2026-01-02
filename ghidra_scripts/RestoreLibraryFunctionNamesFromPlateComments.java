// Restores library function names (e.g., __exit, __fassign) from Ghidra-generated
// "Library Function - Single Match" plate comments.
//
// This is useful when those functions were later renamed (e.g., by user/AI) and you
// want to revert them back to the library identity name that Ghidra matched.
//
// @category Analysis
// @menupath Tools.Restore Library Function Names (from Plate Comments)

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

public class RestoreLibraryFunctionNamesFromPlateComments extends GhidraScript {

    // Example plate comment snippet:
    // "*************************************************************************************************\n" +
    // "* Library Function - Single Match                                                              *\n" +
    // "*  __exit                                                                                       *\n" +
    // "*                                                                                               *\n" +
    // "* Library: Visual Studio 2003 Release                                                          *\n" +
    // "*************************************************************************************************"

    private static final Pattern LIB_HEADER = Pattern.compile("(?m)^\\*\\s*Library Function\\s*-\\s*Single Match\\s*$");

    // Capture a plausible C/CRT symbol name that appears on a line like:
    // *  __exit
    // We intentionally require leading underscores to match the user's goal.
    private static final Pattern LIB_NAME_LINE = Pattern.compile("(?m)^\\*\\s{1,}(__[A-Za-z0-9_]+)\\s*$");

    @Override
    protected void run() throws Exception {
        boolean dryRun = askYesNo("Restore Library Names", "Dry-run only? (Yes = report only, No = apply renames)");
        boolean overwriteUserNames = askYesNo("Restore Library Names",
                "Overwrite user-renamed functions too?\n\nYes = rename even if current name is custom\nNo = only rename FUN_* / default-ish names");

        int scanned = 0;
        int eligible = 0;
        int renamed = 0;
        int skipped = 0;
        int failed = 0;

        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        while (it.hasNext() && !monitor.isCancelled()) {
            Function f = it.next();
            scanned++;

            String plate = f.getComment();
            if (plate == null || plate.isEmpty()) {
                continue;
            }

            if (!LIB_HEADER.matcher(plate).find()) {
                continue;
            }

            Matcher m = LIB_NAME_LINE.matcher(plate);
            if (!m.find()) {
                continue;
            }

            String desiredName = m.group(1);
            String currentName = f.getName();

            // If not overwriting, only touch default-ish names.
            if (!overwriteUserNames) {
                if (!(currentName.startsWith("FUN_") || currentName.startsWith("thunk_") || currentName.startsWith("sub_"))) {
                    skipped++;
                    continue;
                }
            }

            if (desiredName.equals(currentName)) {
                continue;
            }

            eligible++;

            if (dryRun) {
                println(String.format("Would rename %s @ %s -> %s", currentName, f.getEntryPoint(), desiredName));
                continue;
            }

            try {
                // Treat as analysis-derived name.
                f.setName(desiredName, SourceType.ANALYSIS);
                println(String.format("Renamed %s @ %s -> %s", currentName, f.getEntryPoint(), desiredName));
                renamed++;
            } catch (DuplicateNameException | InvalidInputException e) {
                printerr(String.format("FAILED rename %s @ %s -> %s : %s", currentName, f.getEntryPoint(), desiredName,
                        e.getMessage()));
                failed++;
            }
        }

        println("\n=== Restore Library Names Summary ===");
        println("Scanned:   " + scanned);
        println("Eligible:  " + eligible);
        println("Renamed:   " + renamed);
        println("Skipped:   " + skipped);
        println("Failed:    " + failed);
        println("Dry-run:   " + dryRun);
        println("Overwrite: " + overwriteUserNames);
    }
}
