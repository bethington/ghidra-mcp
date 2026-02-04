//Upgrade all programs in the current project to the latest Ghidra version format
//@category Project
//@menupath Tools.Upgrade All Programs
//@author Ben Ethington

import ghidra.app.script.GhidraScript;
import ghidra.framework.model.*;
import ghidra.framework.Application;
import ghidra.util.task.TaskMonitor;

public class UpgradeAllPrograms extends GhidraScript {

    private int upgradedCount = 0;
    private int skippedCount = 0;
    private int errorCount = 0;
    private String ghidraVersion;

    @Override
    protected void run() throws Exception {
        Project project = state.getProject();
        if (project == null) {
            printerr("No project is open!");
            return;
        }

        ghidraVersion = Application.getApplicationVersion();
        ProjectData projectData = project.getProjectData();
        DomainFolder rootFolder = projectData.getRootFolder();

        println("===========================================");
        println("  Ghidra Project Upgrade Utility");
        println("  Target Version: " + ghidraVersion);
        println("===========================================");
        println("");

        // Ask user for confirmation
        boolean proceed = askYesNo("Upgrade All Programs", 
            "This will upgrade ALL programs in the project to Ghidra " + 
            ghidraVersion + ".\n\n" +
            "This operation cannot be undone!\n\n" +
            "Make sure you have a backup before proceeding.\n\n" +
            "Continue?");

        if (!proceed) {
            println("Upgrade cancelled by user.");
            return;
        }

        println("Starting upgrade process...");
        println("");

        // Process all folders recursively
        processFolder(rootFolder, "");

        println("");
        println("===========================================");
        println("  Upgrade Complete!");
        println("  Upgraded: " + upgradedCount);
        println("  Skipped (already current): " + skippedCount);
        println("  Errors: " + errorCount);
        println("===========================================");
    }

    private void processFolder(DomainFolder folder, String indent) throws Exception {
        println(indent + "[Folder] " + folder.getName() + "/");

        // Process all files in this folder
        for (DomainFile file : folder.getFiles()) {
            if (monitor.isCancelled()) {
                println("Upgrade cancelled!");
                return;
            }

            if (!"Program".equals(file.getContentType())) {
                continue; // Skip non-program files
            }

            processFile(file, indent + "  ");
        }

        // Recursively process subfolders
        for (DomainFolder subfolder : folder.getFolders()) {
            if (monitor.isCancelled()) {
                return;
            }
            processFolder(subfolder, indent + "  ");
        }
    }

    private void processFile(DomainFile file, String indent) {
        String fileName = file.getName();
        
        try {
            // Check out the file exclusively for upgrade if versioned
            if (file.isVersioned() && !file.isCheckedOut()) {
                if (!file.checkout(true, monitor)) { // exclusive checkout
                    println(indent + "[WARN] " + fileName + " - Could not checkout (may be locked)");
                    errorCount++;
                    return;
                }
            }

            // Open the program (this triggers the upgrade)
            DomainObject domainObj = file.getDomainObject(this, true, false, monitor);
            
            if (domainObj == null) {
                println(indent + "[FAIL] " + fileName + " - Failed to open");
                errorCount++;
                return;
            }

            try {
                // Check if it was actually upgraded (modified)
                if (domainObj.isChanged()) {
                    // Save the upgraded program
                    domainObj.save("Upgraded to Ghidra " + ghidraVersion, monitor);
                    println(indent + "[OK] " + fileName + " - Upgraded and saved");
                    upgradedCount++;
                } else {
                    println(indent + "[SKIP] " + fileName + " - Already current version");
                    skippedCount++;
                }
            } finally {
                // Always release the domain object
                domainObj.release(this);
            }

            // Note: Files left checked out - user can check in manually via Project window
            // Right-click -> Check In to commit changes to repository

        } catch (Exception e) {
            println(indent + "[FAIL] " + fileName + " - Error: " + e.getMessage());
            errorCount++;
        }
    }
}
