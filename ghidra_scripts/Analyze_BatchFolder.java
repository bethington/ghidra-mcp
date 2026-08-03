// Batch Folder
//
// Runs Ghidra auto-analysis on every program in a specified project folder. Skips known non-game binaries (binkw32, SmackW32, etc.).
//
// Usage: Args: [0]=folder path (e.g., /Mods/PD2-S12).
// Output: Auto-analysis applied to all programs in the folder.
//
// @author Ben Ethington
// @category Diablo 2.Analysis
// @description Batch analyze all programs in a project folder
// @menupath Diablo 2.Analysis.Batch Folder

import ghidra.app.script.GhidraScript;
import ghidra.framework.model.*;
import ghidra.program.model.listing.Program;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;

public class Analyze_BatchFolder extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length == 0) {
            println("Usage: args = folderPath");
            return;
        }
        String folderPath = args[0].trim();
        
        ProjectData projectData = state.getProject().getProjectData();
        DomainFolder folder = projectData.getFolder(folderPath);
        if (folder == null) {
            println("ERROR: Folder not found: " + folderPath);
            return;
        }
        
        String[] skip = {"binkw32.dll", "SmackW32.dll", "ijl11.dll", "glide3x.dll", "libcrypto-1_1.dll"};
        
        DomainFile[] files = folder.getFiles();
        int analyzed = 0;
        int skipped = 0;
        int errors = 0;
        
        println("Found " + files.length + " files in " + folderPath);
        
        for (DomainFile df : files) {
            String name = df.getName();
            
            // Skip 3rd party
            boolean shouldSkip = false;
            for (String s : skip) {
                if (name.equalsIgnoreCase(s)) {
                    shouldSkip = true;
                    break;
                }
            }
            if (shouldSkip) {
                println("SKIP: " + name + " (3rd party)");
                skipped++;
                continue;
            }
            
            try {
                println("ANALYZING: " + name + "...");
                Program program = (Program) df.getDomainObject(this, true, true, monitor);
                
                int beforeCount = program.getFunctionManager().getFunctionCount();
                
                AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
                mgr.reAnalyzeAll(null);
                mgr.startAnalysis(monitor);
                
                int afterCount = program.getFunctionManager().getFunctionCount();
                
                program.save("Auto-analysis complete", monitor);
                program.release(this);
                
                println("  DONE: " + name + " (" + beforeCount + " -> " + afterCount + " functions)");
                analyzed++;
            } catch (Exception e) {
                println("  ERROR: " + name + " - " + e.getMessage());
                errors++;
            }
        }
        
        println("\n=== RESULTS ===");
        println("Analyzed: " + analyzed);
        println("Skipped: " + skipped);
        println("Errors: " + errors);
    }
}
