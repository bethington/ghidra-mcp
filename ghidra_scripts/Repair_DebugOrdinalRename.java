// Debug Ordinal Rename
//
// Shows detailed information about the ordinal symbol rename process including all external libraries, locations, and rename attempts. Useful for troubleshooting ordinal linkage issues.
//
// Usage: Run from Script Manager on any program with ordinal imports.
// Output: Console debug output of ordinal rename operations.
//
// @author Ben Ethington
// @category Diablo 2.Repair
// @description Debug ordinal rename operations with detailed output
// @menupath Diablo 2.Repair.Debug Ordinal Rename

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.CancelledException;
import java.util.*;

public class Repair_DebugOrdinalRename extends GhidraScript {

    private void debugOrdinalRename() {
        println("=== DEBUG ORDINAL RENAME ===");

        ExternalManager extManager = currentProgram.getExternalManager();
        println("External Manager: " + extManager);

        List<ExternalLocation> libs = new ArrayList<>();
        Iterator<ExternalLocation> allExternalLocations = extManager.getExternalLocations(null);
        // Get external library names
        Collection<String> libNames = extManager.getExternalLibraryNames();
        println("Found " + libNames.size() + " external libraries:");

        for (String libName : libNames) {
            println("  Library: " + libName);

            if (libName.contains("D2COMMON")) {
                println("  --> Processing D2COMMON library");

                Iterator<ExternalLocation> locationIter = extManager.getExternalLocations(libName);
                List<ExternalLocation> locations = new ArrayList<>();
                while (locationIter.hasNext()) {
                    locations.add(locationIter.next());
                }
                println("  --> Total locations: " + locations.size());

                int ordinalCount = 0;
                for (ExternalLocation location : locations) {
                    String label = location.getLabel();
                    if (label != null && label.contains("Ordinal_")) {
                        ordinalCount++;
                        if (label.equals("Ordinal_10078") || label.equals("Ordinal_11020")) {
                            ghidra.program.model.address.Address address = location.getAddress();
                            println("  --> Found TARGET: " + label + " @ " + address);

                            String newName;
                            if (label.equals("Ordinal_10078")) {
                                newName = "FindNearestValidRoomWrapper";
                            } else {
                                newName = "GetUnitPropertyValue";
                            }

                            println("      Attempting rename: " + label + " -> " + newName);

                            try {
                                location.setName(newName, SourceType.USER_DEFINED);
                                String verifyLabel = location.getLabel();
                                println("      Method 1 result: '" + verifyLabel + "'");
                            } catch (Exception e) {
                                println("      Method 1 failed: " + e.getMessage());

                                try {
                                    println("      Trying Method 2: Recreation...");
                                    ghidra.program.model.address.Address oldAddr = location.getAddress();

                                    extManager.removeExternalLocation(location);
                                    ExternalLocation newLoc = extManager.addExtFunction(
                                        libName, newName, oldAddr, SourceType.USER_DEFINED);
                                    println("      Method 2 success: Created " + newName);
                                } catch (Exception e2) {
                                    println("      Method 2 also failed: " + e2.getMessage());
                                }
                            }
                        }
                    }
                }
                println("  --> Total ordinals found: " + ordinalCount);
            }
        }

        println("=== DEBUG COMPLETED ===");
    }

    @Override
    public void run() throws Exception {
        debugOrdinalRename();
    }
}
