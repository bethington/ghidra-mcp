// Upgrade All
//
// Upgrades every Program in the current project to the running Ghidra's database
// and SLEIGH language version, checking versioned files in afterwards.
//
// PREFER THE HEADLESS TOOL for anything corpus-sized:
//
//     python scripts/upgrade_project_language.py            # dry run
//     python scripts/upgrade_project_language.py --apply
//
// It reports per-file outcomes, is resumable folder by folder, and does not tie
// up the GUI. This script exists for the case the headless tool cannot cover: a
// file already checked out by THIS project instance, which a separate headless
// project can never take an exclusive checkout on.
//
// WHY AN UPGRADE IS NEEDED AT ALL
// Ghidra records the language version a Program was built against. When the
// installed Ghidra ships a newer revision (e.g. x86:LE:32:default 4.6 -> 4.7),
// the old Program still opens READ-ONLY but refuses a read-write open until it
// is upgraded -- and an upgrade requires an EXCLUSIVE checkout. On a shared
// project that presents as "everything opens read-only and my edits vanish".
//
// A minor language change needs no translator and no re-disassembly, so
// documentation is preserved. This script refuses major changes rather than
// guessing at them.
//
// @author Ben Ethington
// @category Diablo 2.Project
// @description Upgrade all programs to the current Ghidra language/DB version
// @menupath Diablo 2.Project.Upgrade All

import ghidra.app.script.GhidraScript;
import ghidra.framework.Application;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.DomainObject;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectData;

public class Project_UpgradeAll extends GhidraScript {

    private int upgradedCount = 0;
    private int skippedCount = 0;
    private int blockedCount = 0;
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

        boolean proceed = askYesNo("Upgrade All Programs",
            "Upgrade ALL programs in this project to Ghidra " + ghidraVersion + ".\n\n" +
            "Versioned files are checked out exclusively, upgraded, and CHECKED IN.\n" +
            "This cannot be undone. Make sure you have a backup.\n\n" +
            "Continue?");

        if (!proceed) {
            println("Upgrade cancelled by user.");
            return;
        }

        processFolder(rootFolder, "");

        println("");
        println("===========================================");
        println("  Upgrade Complete");
        println("  Upgraded and checked in: " + upgradedCount);
        println("  Already current:         " + skippedCount);
        println("  Blocked (in use/locked): " + blockedCount);
        println("  Errors:                  " + errorCount);
        println("===========================================");
        if (errorCount > 0 || blockedCount > 0) {
            printerr("Some files were not upgraded -- see the log lines above. They will "
                + "keep opening read-only until they are.");
        }
    }

    private void processFolder(DomainFolder folder, String indent) throws Exception {
        println(indent + "[Folder] " + folder.getName() + "/");

        for (DomainFile file : folder.getFiles()) {
            if (monitor.isCancelled()) {
                println("Upgrade cancelled!");
                return;
            }
            if (!"Program".equals(file.getContentType())) {
                continue;
            }
            processFile(file, indent + "  ");
        }

        for (DomainFolder subfolder : folder.getFolders()) {
            if (monitor.isCancelled()) {
                return;
            }
            processFolder(subfolder, indent + "  ");
        }
    }

    private void processFile(DomainFile file, String indent) {
        String fileName = file.getName();

        // Only undo a checkout WE took. Undoing a pre-existing one would discard
        // whatever work it was holding.
        boolean weCheckedOut = false;

        try {
            if (file.isVersioned() && !file.isCheckedOut()) {
                if (!file.canCheckout()) {
                    println(indent + "[BLOCK] " + fileName + " - read-only repository");
                    blockedCount++;
                    return;
                }
                // Exclusive: a non-exclusive checkout cannot perform an upgrade.
                if (!file.checkout(true, monitor)) {
                    println(indent + "[BLOCK] " + fileName + " - no exclusive checkout available");
                    blockedCount++;
                    return;
                }
                weCheckedOut = true;
            }
            else if (file.isVersioned() && !file.isCheckedOutExclusive()) {
                println(indent + "[BLOCK] " + fileName + " - checked out NON-exclusively; "
                    + "an upgrade needs an exclusive checkout");
                blockedCount++;
                return;
            }

            // okToUpgrade = true is the entire point: this is what the MCP
            // server's own open path cannot do (it passes false).
            DomainObject domainObj = file.getDomainObject(this, true, false, monitor);
            if (domainObj == null) {
                println(indent + "[FAIL] " + fileName + " - failed to open");
                errorCount++;
                return;
            }

            boolean changed;
            try {
                changed = domainObj.isChanged();
                if (changed) {
                    domainObj.save("Upgraded to Ghidra " + ghidraVersion, monitor);
                }
            } finally {
                domainObj.release(this);
            }

            if (!changed) {
                println(indent + "[SKIP] " + fileName + " - already current");
                skippedCount++;
                if (weCheckedOut && !file.modifiedSinceCheckout()) {
                    file.undoCheckout(false);
                }
                return;
            }

            // save() only writes the LOCAL checkout. On a shared project the work
            // does not exist for anyone -- including the next headless pass --
            // until it is checked in. Leaving 579 files checked out with an
            // uncommitted upgrade is worse than not having run at all.
            if (file.isVersioned()) {
                file.checkin(new ghidra.framework.data.CheckinHandler() {
                    @Override
                    public String getComment() {
                        return "Upgraded to Ghidra " + ghidraVersion;
                    }

                    @Override
                    public boolean keepCheckedOut() {
                        return false;
                    }

                    @Override
                    public boolean createKeepFile() {
                        return false;
                    }
                }, monitor);
                println(indent + "[OK] " + fileName + " - upgraded and checked in");
            } else {
                println(indent + "[OK] " + fileName + " - upgraded (private file, no check-in)");
            }
            upgradedCount++;

        } catch (Exception e) {
            // Loud, never silent: a swallowed failure here reads as a clean run
            // over a program that will keep opening read-only.
            printerr(indent + "[FAIL] " + fileName + " - " + e.getClass().getSimpleName()
                + ": " + e.getMessage());
            errorCount++;
        }
    }
}
