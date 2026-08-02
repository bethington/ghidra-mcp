// Recover_OrphanedProgramSaveAs.java
// Rescues a Program instance held in GhidraMCPPlugin's FrontEndProgramProvider cache
// whose underlying DomainFile location was severed (DomainFile.save throws
// "Location does not exist for a save operation!").
//
// Usage:
//   1. Run from any CodeBrowser's Script Manager (Window -> Script Manager).
//   2. First run with PERFORM_SAVE = false. The script lists every program in the
//      provider cache and the live CodeBrowsers, marks orphan candidates, and exits
//      without writing.
//   3. Inspect the printout. Confirm Instance B (the documented one) is identified.
//      If TARGET_NAME / EXPECTED_FUNCTIONS / EXPECTED_SYMBOLS need adjusting,
//      edit them and re-run.
//   4. Set PERFORM_SAVE = true and re-run. The script saves Instance B as a new
//      DomainFile under RESCUE_FOLDER with name RESCUE_NAME (auto-suffixed if
//      collision).
//   5. In the project window, checkout original Bnclient.dll, then propagate
//      function names / signatures / comments / data types / globals from the
//      rescued file back to the original. Checkin both.
//
//@author benam
//@category Recovery
//@menupath Tools.Recovery.Recover Orphaned Program (Save As)

import ghidra.app.script.GhidraScript;
import ghidra.framework.main.AppInfo;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.SymbolTable;

import java.lang.reflect.Field;
import java.util.*;

public class Recover_OrphanedProgramSaveAs extends GhidraScript {

    // === Configuration ===
    // Edit these before running. Defaults match Bnclient.dll Instance B as of
    // 2026-05-02 (functions=800, symbols=3819, data_types=501).
    private static final String  TARGET_NAME        = "Bnclient.dll";
    private static final long    EXPECTED_FUNCTIONS = 800L;
    private static final int     EXPECTED_SYMBOLS   = 3941;
    private static final String  RESCUE_FOLDER      = "/Mods/PD2-S12";
    private static final String  RESCUE_NAME        = "Bnclient_recovered";
    private static final boolean PERFORM_SAVE       = true;  // <-- flip to true when ready

    @Override
    public void run() throws Exception {
        Project project = state.getProject();
        if (project == null) {
            println("ERROR: no active project");
            return;
        }

        // Find the GhidraMCPPlugin in the FrontEnd tool
        PluginTool frontEndTool = AppInfo.getFrontEndTool();
        if (frontEndTool == null) {
            println("ERROR: FrontEnd tool not found via AppInfo.getFrontEndTool()");
            return;
        }

        Plugin mcpPlugin = null;
        for (Plugin p : frontEndTool.getManagedPlugins()) {
            if (p.getClass().getName().equals("com.xebyte.GhidraMCPPlugin")) {
                mcpPlugin = p;
                break;
            }
        }
        if (mcpPlugin == null) {
            println("ERROR: com.xebyte.GhidraMCPPlugin not loaded in FrontEnd tool. Open Project > Configure > Utility and enable it, then retry.");
            return;
        }
        println("Found plugin: " + mcpPlugin.getClass().getName() + " in " + frontEndTool.getName());

        // Reflect: GhidraMCPPlugin.programProvider (FrontEndProgramProvider)
        Field providerField = mcpPlugin.getClass().getDeclaredField("programProvider");
        providerField.setAccessible(true);
        Object provider = providerField.get(mcpPlugin);
        if (provider == null) {
            println("ERROR: programProvider field is null");
            return;
        }
        println("Provider class: " + provider.getClass().getName());

        // Reflect: FrontEndProgramProvider.openPrograms (ConcurrentHashMap<String, Program>)
        Field cacheField = provider.getClass().getDeclaredField("openPrograms");
        cacheField.setAccessible(true);
        @SuppressWarnings("unchecked")
        Map<String, Program> cache = (Map<String, Program>) cacheField.get(provider);

        // Also collect CodeBrowser-held programs so we can flag which provider entries
        // are orphans (in cache but not in any CodeBrowser).
        Set<Program> liveInCodeBrowser = Collections.newSetFromMap(new IdentityHashMap<>());
        ToolManager tm = project.getToolManager();
        for (PluginTool t : tm.getRunningTools()) {
            ghidra.app.services.ProgramManager pm = t.getService(ghidra.app.services.ProgramManager.class);
            if (pm == null) continue;
            for (Program p : pm.getAllOpenPrograms()) {
                liveInCodeBrowser.add(p);
            }
        }

        println("\n=== FrontEndProgramProvider cache (" + cache.size() + " entries) ===");
        Program orphanCandidate = null;
        Program nameMatchHighestSym = null;
        for (Map.Entry<String, Program> e : cache.entrySet()) {
            Program prog = e.getValue();
            if (prog == null) {
                println("  [null] cacheKey=" + e.getKey());
                continue;
            }
            FunctionManager fm = prog.getFunctionManager();
            SymbolTable st = prog.getSymbolTable();
            DomainFile df = prog.getDomainFile();
            boolean inCb = liveInCodeBrowser.contains(prog);
            long fnCount = fm.getFunctionCount();
            int symCount = st.getNumSymbols();
            int dtCount = prog.getDataTypeManager().getDataTypeCount(true);

            String marker;
            if (TARGET_NAME.equalsIgnoreCase(prog.getName())
                    && fnCount == EXPECTED_FUNCTIONS
                    && symCount == EXPECTED_SYMBOLS) {
                marker = " <-- INSTANCE B MATCH";
                if (orphanCandidate == null) {
                    orphanCandidate = prog;
                }
            } else if (!inCb) {
                marker = " (orphan: not in any CodeBrowser)";
            } else {
                marker = "";
            }

            // Track the Bnclient.dll with most symbols as a fallback
            if (TARGET_NAME.equalsIgnoreCase(prog.getName())) {
                if (nameMatchHighestSym == null
                        || symCount > nameMatchHighestSym.getSymbolTable().getNumSymbols()) {
                    nameMatchHighestSym = prog;
                }
            }

            println(String.format(
                "  cacheKey=%s%n" +
                "    name=%s  fns=%d  syms=%d  dts=%d  inCB=%s%n" +
                "    df=%s  canSave=%s%s",
                e.getKey(),
                prog.getName(), fnCount, symCount, dtCount, inCb,
                (df != null ? df.getPathname() : "NULL"),
                (df != null && df.canSave()),
                marker));
        }

        println("\n=== CodeBrowser open programs (" + liveInCodeBrowser.size() + ") ===");
        for (Program p : liveInCodeBrowser) {
            DomainFile df = p.getDomainFile();
            println(String.format("  %s  fns=%d  syms=%d  df=%s",
                p.getName(),
                p.getFunctionManager().getFunctionCount(),
                p.getSymbolTable().getNumSymbols(),
                df != null ? df.getPathname() : "NULL"));
        }

        // === Decide and act ===
        Program target = orphanCandidate;
        if (target == null) {
            println("\nNo cache entry matched the EXPECTED_FUNCTIONS/EXPECTED_SYMBOLS signature.");
            if (nameMatchHighestSym != null) {
                int sc = nameMatchHighestSym.getSymbolTable().getNumSymbols();
                long fc = nameMatchHighestSym.getFunctionManager().getFunctionCount();
                println("Best fallback: " + nameMatchHighestSym.getName()
                    + " (fns=" + fc + ", syms=" + sc + ")");
                println("Re-run with EXPECTED_FUNCTIONS=" + fc + " and EXPECTED_SYMBOLS=" + sc
                    + " if this is the intended target.");
            }
            return;
        }

        println("\n=== Selected for rescue ===");
        println("name=" + target.getName());
        println("functions=" + target.getFunctionManager().getFunctionCount());
        println("symbols=" + target.getSymbolTable().getNumSymbols());
        println("data types=" + target.getDataTypeManager().getDataTypeCount(true));
        DomainFile origDf = target.getDomainFile();
        println("origDomainFile=" + (origDf != null ? origDf.getPathname() : "NULL")
            + "  canSave=" + (origDf != null && origDf.canSave()));

        if (!PERFORM_SAVE) {
            println("\nDRY RUN — set PERFORM_SAVE=true at the top of the script and re-run to actually save.");
            return;
        }

        // Resolve target folder
        DomainFolder folder = project.getProjectData().getFolder(RESCUE_FOLDER);
        if (folder == null) {
            println("ERROR: target folder not found: " + RESCUE_FOLDER);
            return;
        }

        // Avoid name collision
        String name = RESCUE_NAME;
        int suffix = 1;
        while (folder.getFile(name) != null) {
            name = RESCUE_NAME + "_" + suffix++;
        }

        println("\nSaving to: " + folder.getPathname() + "/" + name);
        DomainFile newDf = folder.createFile(name, target, monitor);
        println("\n=== SUCCESS ===");
        println("Created: " + newDf.getPathname());
        println("isCheckedOut=" + newDf.isCheckedOut()
            + " modifiedSinceCheckout=" + newDf.modifiedSinceCheckout());
        println("\nNext steps:");
        println("  1. In Project Manager, find " + newDf.getPathname());
        println("  2. Right-click -> Add to Version Control (or Checkin) to push to shared server.");
        println("  3. Checkout the original /Mods/PD2-S12/Bnclient.dll for write.");
        println("  4. Run a propagation script (e.g. Propagate_CrossVersionHash) to copy");
        println("     names / signatures / comments / data types / globals from " + name);
        println("     back to Bnclient.dll. Then checkin Bnclient.dll.");
        println("  5. Optional: delete " + newDf.getPathname() + " when done.");
    }
}
