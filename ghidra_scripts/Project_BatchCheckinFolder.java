// Batch Checkin Folder
//
// Checks in all checked-out files within a specified project folder to the shared Ghidra server with a standard commit message.
//
// Usage: Args: [0]=folder path (e.g., /Vanilla/1.13c).
// Output: Checks in all modified files to the version control server.
//
// @author Ben Ethington
// @category Diablo 2.Project
// @description Batch check in all files in a project folder
// @menupath Diablo 2.Project.Batch Checkin Folder

import ghidra.app.script.GhidraScript;
import ghidra.framework.model.*;
import ghidra.framework.data.CheckinHandler;

public class Project_BatchCheckinFolder extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            println("ERROR: Need args: folder_path");
            return;
        }

        String folderPath = args[0];
        String comment = "1.13c documentation: 2590 functions named via hash propagation + manual RE";

        var projectData = state.getProject().getProjectData();
        var folder = projectData.getFolder(folderPath);

        if (folder == null) {
            println("ERROR: Folder not found: " + folderPath);
            return;
        }

        println("Folder: " + folderPath);
        int checkedIn = 0;
        int skipped = 0;
        int errors = 0;

        CheckinHandler handler = new CheckinHandler() {
            @Override
            public boolean keepCheckedOut() { return false; }
            @Override
            public String getComment() { return comment; }
            @Override
            public boolean createKeepFile() { return false; }
        };

        var files = folder.getFiles();
        for (var file : files) {
            if (monitor.isCancelled()) break;
            String name = file.getName();

            if (!file.isCheckedOut()) {
                skipped++;
                continue;
            }

            try {
                file.checkin(handler, monitor);
                println("  CHECKIN OK: " + name);
                checkedIn++;
            } catch (Exception e) {
                String msg = e.getMessage();
                if (msg != null && msg.contains("not been modified")) {
                    // Undo checkout for unmodified files
                    try {
                        file.undoCheckout(false);
                        println("  UNDO CHECKOUT: " + name + " (not modified)");
                    } catch (Exception e2) {
                        println("  SKIP: " + name + " (not modified, undo failed)");
                    }
                    skipped++;
                } else {
                    println("  ERROR: " + name + " - " + msg);
                    errors++;
                }
            }
        }

        println("=== RESULTS ===");
        println("Checked in: " + checkedIn);
        println("Skipped/undone: " + skipped);
        println("Errors: " + errors);
    }
}
