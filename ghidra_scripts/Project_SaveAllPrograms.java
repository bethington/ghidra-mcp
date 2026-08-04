// Save All Programs
//
// Saves a list of hardcoded programs from the project. Opens each by path, saves if modified, and releases. Useful for batch-saving after multi-binary editing sessions.
//
// Usage: Run from Script Manager. Edit source to change target paths.
// Output: Saves all modified programs in the list.
//
// @author Ben Ethington
// @category Diablo 2.Project
// @description Save multiple programs by project path
// @menupath Diablo 2.Project.Save All Programs

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.framework.model.*;

public class Project_SaveAllPrograms extends GhidraScript {
    @Override
    public void run() throws Exception {
        Project project = state.getProject();
        ProjectData pd = project.getProjectData();
        String[] paths = {
            "/Vanilla/1.13c/D2Gfx.dll",
            "/Vanilla/1.13c/D2Client.dll",
            "/Mods/PD2/ProjectDiablo.dll",
        };
        for (String path : paths) {
            DomainFile df = pd.getFile(path);
            if (df == null) { println("Not found: " + path); continue; }
            if (!df.canSave()) { println("Cannot save (read-only?): " + path); continue; }
            try {
                Program prog = (Program) df.getDomainObject(this, false, false, monitor);
                if (prog.isChanged()) {
                    prog.save(path, monitor);
                    println("Saved: " + path);
                } else {
                    println("No changes: " + path);
                }
                prog.release(this);
            } catch (Exception e) {
                println("Error saving " + path + ": " + e.getMessage());
            }
        }
        println("Done.");
    }
}
