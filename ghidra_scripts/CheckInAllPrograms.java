//Check in all checked-out programs in the project with a dated commit message
//@category Project
//@menupath Tools.Check In All Programs
//@author Ben Ethington

import ghidra.app.script.GhidraScript;
import ghidra.framework.model.*;
import ghidra.framework.Application;
import ghidra.util.task.TaskMonitor;
import java.text.SimpleDateFormat;
import java.util.Date;

public class CheckInAllPrograms extends GhidraScript {

    private int checkedInCount = 0;
    private int skippedCount = 0;
    private int errorCount = 0;
    private String commitMessage;
    private boolean keepCheckedOut;

    @Override
    protected void run() throws Exception {
        Project project = state.getProject();
        if (project == null) {
            printerr("No project is open!");
            return;
        }

        // Generate date string in YYYYMMDD format
        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyyMMdd");
        String dateString = dateFormat.format(new Date());
        
        ProjectData projectData = project.getProjectData();
        DomainFolder rootFolder = projectData.getRootFolder();

        println("===========================================");
        println("  Ghidra Check-In Utility");
        println("  Date: " + dateString);
        println("===========================================");
        println("");

        // Ask if user wants to keep files checked out after check-in
        keepCheckedOut = askYesNo("Keep Checked Out?", 
            "Do you want to KEEP files checked out after check-in?\n\n" +
            "YES = Check in changes but keep exclusive access (for continued editing)\n" +
            "NO = Check in and release files (others can edit)");

        // Ask for custom commit message or use default
        String defaultMessage = "Updated " + dateString;
        commitMessage = askString("Commit Message", 
            "Enter commit message (or leave default):", 
            defaultMessage);

        if (commitMessage == null || commitMessage.trim().isEmpty()) {
            commitMessage = defaultMessage;
        }

        println("Commit message: " + commitMessage);
        println("Keep checked out: " + (keepCheckedOut ? "Yes" : "No"));
        println("");

        // Confirm before proceeding
        boolean proceed = askYesNo("Confirm Check-In", 
            "This will check in ALL checked-out programs in the project.\n\n" +
            "Commit message: " + commitMessage + "\n" +
            "Keep checked out: " + (keepCheckedOut ? "Yes" : "No") + "\n\n" +
            "Continue?");

        if (!proceed) {
            println("Check-in cancelled by user.");
            return;
        }

        println("Starting check-in process...");
        println("");

        // Process all folders recursively
        processFolder(rootFolder, "");

        println("");
        println("===========================================");
        println("  Check-In Complete!");
        println("  Checked in: " + checkedInCount);
        println("  Skipped (not checked out): " + skippedCount);
        println("  Errors: " + errorCount);
        println("===========================================");
    }

    private void processFolder(DomainFolder folder, String indent) throws Exception {
        // Process all files in this folder
        for (DomainFile file : folder.getFiles()) {
            if (monitor.isCancelled()) {
                println("Check-in cancelled!");
                return;
            }

            if (!"Program".equals(file.getContentType())) {
                continue; // Skip non-program files
            }

            processFile(file, indent);
        }

        // Recursively process subfolders
        for (DomainFolder subfolder : folder.getFolders()) {
            if (monitor.isCancelled()) {
                return;
            }
            processFolder(subfolder, indent);
        }
    }

    private void processFile(DomainFile file, String indent) {
        String filePath = file.getPathname();
        
        try {
            // Only process files that are checked out
            if (!file.isCheckedOut()) {
                skippedCount++;
                return; // Silently skip - don't clutter output
            }

            // Check if there are changes to check in
            if (!file.canCheckin()) {
                println("[SKIP] " + filePath + " - No changes to check in");
                skippedCount++;
                return;
            }

            // Perform the check-in
            file.checkin(new ghidra.framework.data.CheckinHandler() {
                @Override
                public boolean keepCheckedOut() {
                    return keepCheckedOut;
                }
                @Override
                public String getComment() {
                    return commitMessage;
                }
                @Override
                public boolean createKeepFile() {
                    return false;
                }
            }, monitor);

            if (keepCheckedOut) {
                println("[OK] " + filePath + " - Checked in (kept checked out)");
            } else {
                println("[OK] " + filePath + " - Checked in and released");
            }
            checkedInCount++;

        } catch (Exception e) {
            println("[FAIL] " + filePath + " - Error: " + e.getMessage());
            errorCount++;
        }
    }
}
