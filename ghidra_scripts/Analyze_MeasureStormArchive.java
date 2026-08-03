// Measure Storm Archive
//
// Searches Storm.dll and Fog.dll for archive/MPQ-related functions and reports their sizes and coverage. Useful for tracking reverse engineering progress on the archive subsystem.
//
// Usage: Run from Script Manager. Hardcoded paths for 1.13c Storm/Fog.
// Output: Console report of archive-related function sizes and counts.
//
// @author Ben Ethington
// @category Diablo 2.Analysis
// @description Measure Storm/Fog archive function coverage
// @menupath Diablo 2.Analysis.Measure Storm Archive

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.framework.model.*;
import java.util.*;

public class Analyze_MeasureStormArchive extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] paths = {
            "/Vanilla/1.13c/Storm.dll",
            "/Vanilla/1.13c/Fog.dll"
        };
        String[] keywords = {"Archive", "Mpq", "mpq", "SFile", "ReadArchive", "HashTable", "BlockTable"};
        
        Project project = state.getProject();
        ProjectData projectData = project.getProjectData();
        
        for (String path : paths) {
            DomainFile df = projectData.getFile(path);
            if (df == null) continue;
            DomainObject obj = df.getDomainObject(this, true, false, monitor);
            if (!(obj instanceof Program)) { if (obj != null) obj.release(this); continue; }
            Program prog = (Program) obj;
            try {
                FunctionManager fm = prog.getFunctionManager();
                long totalSize = 0;
                int count = 0;
                println("=== " + prog.getName() + " (" + path + ") ===");
                FunctionIterator iter = fm.getFunctions(true);
                while (iter.hasNext()) {
                    Function f = iter.next();
                    String name = f.getName();
                    boolean match = false;
                    for (String kw : keywords) {
                        if (name.contains(kw)) { match = true; break; }
                    }
                    if (match) {
                        long sz = f.getBody().getNumAddresses();
                        totalSize += sz;
                        count++;
                        println("  " + sz + " bytes | " + f.getEntryPoint() + " | " + name);
                    }
                }
                println("TOTAL: " + count + " functions, " + totalSize + " bytes");
            } finally {
                prog.release(this);
            }
        }
    }
}
