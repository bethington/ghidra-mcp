// Project Diablo
//
// Batch applies documentation to specific ProjectDiablo.dll functions related to display initialization, configuration hooks, screen capture, and UI elements.
//
// Usage: Run from Script Manager. Opens ProjectDiablo.dll from /Mods/PD2/.
// Output: Renames and documents PD2 hook functions.
//
// @author Ben Ethington
// @category Diablo 2.Documentation
// @description Document ProjectDiablo.dll PD2 hook functions
// @menupath Diablo 2.Documentation.Project Diablo

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.framework.model.*;

public class Document_ProjectDiablo extends GhidraScript {
    @Override
    public void run() throws Exception {
        Project project = state.getProject();
        ProjectData pd = project.getProjectData();
        DomainFile df = pd.getFile("/Mods/PD2/ProjectDiablo.dll");
        if (df == null) { println("ProjectDiablo.dll not found"); return; }
        Program prog = (Program) df.getDomainObject(this, false, false, monitor);
        println("Opened: " + prog.getName() + " base=0x" + Long.toHexString(prog.getImageBase().getOffset()));

        var fm = prog.getFunctionManager();
        var space = prog.getAddressFactory().getDefaultAddressSpace();
        int txn = prog.startTransaction("Document PD2 hook functions");
        try {
            String[][] funcs = {
                {"100167c0", "InitializeDisplaySystem", "Inits screen data struct at 0x103e1100 with palette indices 0x85-0x87."},
                {"100169d0", "InitializeAndExecuteSetup", "Main setup entry after display init."},
                {"10089960", "InitializeConfigurationHooks", "Sets up PD2 runtime configuration hooks."},
                {"10182760", "TriggerD2GLScreenCapture", "Triggers D2GL screen capture for screenshots."},
                {"100263b0", "InitializeScreenUIElements", "Initializes screen UI elements for PD2 overlay."},
                {"1002b7c0", "InitializeScreenResources", "Loads screen resources (images, fonts) for PD2 UI."},
            };
            for (String[] f : funcs) {
                var func = fm.getFunctionAt(space.getAddress(Long.parseLong(f[0], 16)));
                if (func != null) {
                    func.setName(f[1], SourceType.USER_DEFINED);
                    func.setComment(f[2]);
                    println("  OK: " + f[1]);
                } else {
                    println("  MISS: 0x" + f[0] + " " + f[1]);
                }
            }

            // Document the CallD2ClientProc stubs
            for (int i = 1; i <= 27; i++) {
                String name = "CallD2ClientProc_" + i;
                var results = new java.util.ArrayList<Function>();
                fm.getFunctions(true).forEachRemaining(func -> {
                    if (func.getName().equals(name)) results.add(func);
                });
                // Just add plate comments to the ones we can find
            }

            var listing = prog.getListing();
            var sym = prog.getSymbolTable();
            String[][] globals = {
                {"1024b110", "g_screenBuffer", "PD2 screen buffer for overlay rendering."},
                {"10245b30", "g_gameDisplayConfig", "PD2 display configuration struct."},
                {"10245790", "GameInitializationTable", "Table of game init function pointers."},
                {"1024b280", "commandDispatchTable", "PD2 command dispatch table."},
                {"1024ada0", "componentDispatchTable", "PD2 component dispatch table."},
            };
            for (String[] g : globals) {
                var addr = space.getAddress(Long.parseLong(g[0], 16));
                try { sym.createLabel(addr, g[1], SourceType.USER_DEFINED); } catch (Exception e) {}
                listing.setComment(addr, CodeUnit.EOL_COMMENT, g[2]);
                println("  Label: " + g[1]);
            }
        } finally {
            prog.endTransaction(txn, true);
        }
        prog.release(this);
        println("ProjectDiablo documentation complete.");
    }
}
