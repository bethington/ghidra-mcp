// Rename Folder
//
// Renames a project folder after releasing all cached programs from it. Prevents stale program references from blocking the rename operation.
//
// Usage: Args: [0]='oldPath|newName' (e.g., /Releases/latest|v2.1).
// Output: Renames the specified project folder.
//
// @author Ben Ethington
// @category GhidraMCP.Project
// @description Rename a project folder with cache cleanup
// @menupath GhidraMCP.Project.Rename Folder

import ghidra.app.script.GhidraScript;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.PluginTool;

public class Project_RenameFolder extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length == 0 || !args[0].contains("|")) {
            println("Usage: args = 'oldPath|newName'");
            return;
        }

        String[] parts = args[0].split("\\|");
        String oldPath = parts[0].trim();
        String newName = parts[1].trim();

        ProjectData projectData = state.getProject().getProjectData();
        DomainFolder folder = projectData.getFolder(oldPath);
        if (folder == null) {
            println("ERROR: Folder not found: " + oldPath);
            return;
        }

        // Release all cached programs from this folder
        println("Releasing cached programs from " + oldPath + "...");
        DomainFile[] files = folder.getFiles();
        for (DomainFile df : files) {
            // Close any open consumers
            java.util.List<?> consumers = df.getConsumers();
            if (consumers != null) {
                println("  File " + df.getName() + " has " + consumers.size() + " consumer(s)");
                for (Object consumer : consumers) {
                    try {
                        DomainObject obj = df.getDomainObject(consumer, false, false, monitor);
                        if (obj != null) {
                            obj.release(consumer);
                            println("    Released consumer: " + consumer.getClass().getSimpleName());
                        }
                    } catch (Exception e) {
                        // ignore
                    }
                }
            }
        }

        // Try rename
        String oldName = folder.getName();
        println("Renaming: " + oldPath + " -> " + newName);
        try {
            folder.setName(newName);
            println("SUCCESS: Renamed '" + oldName + "' to '" + newName + "'");
        } catch (Exception e) {
            println("ERROR: " + e.getMessage());
            println("Try closing all programs from this folder in Ghidra first.");
        }
    }
}
