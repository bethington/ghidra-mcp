// Recover_AllOrphans.java
// Companion to Recover_OrphanedProgramSaveAs.java. Walks every entry in
// GhidraMCPPlugin's FrontEndProgramProvider cache and saves each one as a
// new DomainFile named "<original>_recovered" in the same folder. Skips:
//   - programs currently open in any CodeBrowser (no rescue needed —
//     they aren't orphaned)
//   - programs that already have a "<original>_recovered*" sibling file in
//     the same folder (already rescued in a prior run)
//
// Always uses save-as via DomainFolder.createFile(), even when canSave=true,
// so the original DomainFile is never touched. You can checkin / merge
// the recovered files separately on your own schedule.
//
// Usage:
//   1. First run with DRY_RUN = true (the default). The script prints what
//      it WOULD do for every cache entry without writing anything.
//   2. Inspect the printout. If the plan looks right, set DRY_RUN = false
//      and re-run.
//   3. After success, in Project Manager, right-click each "*_recovered"
//      file -> Add to Version Control to push to the shared server.
//
//@author benam
//@category Recovery
//@menupath Tools.Recovery.Recover All Orphaned Programs

import ghidra.app.script.GhidraScript;
import ghidra.framework.main.AppInfo;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;

import java.lang.reflect.Field;
import java.util.*;

public class Recover_AllOrphans extends GhidraScript {

    // === Configuration ===
    private static final boolean DRY_RUN          = false;            // <-- flip to false to actually save
    private static final String  RECOVERED_SUFFIX = "_recovered";    // appended to original name
    // Stem-only names to skip (in addition to already-recovered detection).
    // Useful if you want to exclude specific programs from the bulk run.
    private static final Set<String> SKIP_NAMES = new HashSet<>(Arrays.asList(
        // "ProjectDiablo.dll"   // example
    ));

    @Override
    public void run() throws Exception {
        Project project = state.getProject();
        if (project == null) {
            println("ERROR: no active project");
            return;
        }

        // 1. Find the GhidraMCPPlugin in the FrontEnd tool
        PluginTool frontEndTool = AppInfo.getFrontEndTool();
        if (frontEndTool == null) {
            println("ERROR: FrontEnd tool not found");
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
            println("ERROR: com.xebyte.GhidraMCPPlugin not loaded in FrontEnd tool");
            return;
        }

        // 2. Reflect the FrontEndProgramProvider.openPrograms cache
        Field providerField = mcpPlugin.getClass().getDeclaredField("programProvider");
        providerField.setAccessible(true);
        Object provider = providerField.get(mcpPlugin);
        Field cacheField = provider.getClass().getDeclaredField("openPrograms");
        cacheField.setAccessible(true);
        @SuppressWarnings("unchecked")
        Map<String, Program> cache = (Map<String, Program>) cacheField.get(provider);

        // 3. Collect CodeBrowser-held programs so we can skip them
        Set<Program> liveInCodeBrowser = Collections.newSetFromMap(new IdentityHashMap<>());
        for (PluginTool t : project.getToolManager().getRunningTools()) {
            ghidra.app.services.ProgramManager pm = t.getService(ghidra.app.services.ProgramManager.class);
            if (pm == null) continue;
            for (Program p : pm.getAllOpenPrograms()) {
                liveInCodeBrowser.add(p);
            }
        }

        println(String.format("Mode: %s   Cache entries: %d   CodeBrowser-live: %d",
            DRY_RUN ? "DRY RUN (no writes)" : "EXECUTE", cache.size(), liveInCodeBrowser.size()));

        // 4. For each cache entry, plan and (optionally) execute
        int savedCount = 0;
        int skippedLive = 0;
        int skippedAlreadyRescued = 0;
        int skippedExplicit = 0;
        int skippedDuplicateAlias = 0;
        int errors = 0;
        List<String> savedList = new ArrayList<>();
        List<String> errorList = new ArrayList<>();

        // Dedupe: same Program may be cached under multiple keys (e.g. an alias key
        // is added after a save-as renames the DomainFile). Process each unique
        // Program object at most once.
        Set<Program> processed = Collections.newSetFromMap(new IdentityHashMap<>());

        for (Map.Entry<String, Program> entry : cache.entrySet()) {
            String cacheKey = entry.getKey();
            Program prog = entry.getValue();
            if (prog == null) {
                println(String.format("  [null entry] cacheKey=%s -- skip", cacheKey));
                continue;
            }

            if (!processed.add(prog)) {
                println(String.format("[%s] cacheKey=%s  -- SKIP (duplicate alias for already-processed Program)",
                    prog.getName(), cacheKey));
                skippedDuplicateAlias++;
                continue;
            }

            String origName = prog.getName();
            // Strip a single trailing extension (.dll / .exe / etc.) so the rescue file
            // is named "Bnclient_recovered" instead of "Bnclient.dll_recovered".
            String stem = origName;
            int dot = stem.lastIndexOf('.');
            if (dot > 0 && dot > stem.lastIndexOf('/')) {
                stem = stem.substring(0, dot);
            }
            long fns = prog.getFunctionManager().getFunctionCount();
            int syms = prog.getSymbolTable().getNumSymbols();
            int dts = prog.getDataTypeManager().getDataTypeCount(true);
            DomainFile origDf = prog.getDomainFile();
            boolean inCb = liveInCodeBrowser.contains(prog);

            String header = String.format("[%s] fns=%d syms=%d dts=%d  cacheKey=%s",
                origName, fns, syms, dts, cacheKey);

            if (SKIP_NAMES.contains(origName)) {
                println(header + "  -- SKIP (in SKIP_NAMES)");
                skippedExplicit++;
                continue;
            }

            if (inCb) {
                println(header + "  -- SKIP (live in CodeBrowser; not orphaned)");
                skippedLive++;
                continue;
            }

            // Resolve the parent folder for save-as. Prefer the orig DomainFile's parent;
            // fall back to the folder of the cache key path.
            DomainFolder parentFolder = null;
            if (origDf != null) {
                parentFolder = origDf.getParent();
            }
            if (parentFolder == null && cacheKey.startsWith("/")) {
                int slash = cacheKey.lastIndexOf('/');
                if (slash > 0) {
                    parentFolder = project.getProjectData().getFolder(cacheKey.substring(0, slash));
                } else if (slash == 0) {
                    parentFolder = project.getProjectData().getRootFolder();
                }
            }
            if (parentFolder == null) {
                println(header + "  -- ERROR: cannot resolve parent folder");
                errorList.add(origName + " (no parent folder)");
                errors++;
                continue;
            }

            // Detect prior rescue: any file in this folder named "<stem>_recovered*"
            String baseRescueName = stem + RECOVERED_SUFFIX;
            DomainFile existing = parentFolder.getFile(baseRescueName);
            boolean alreadyRescued = (existing != null);
            if (!alreadyRescued) {
                // Check suffixed variants too
                for (DomainFile sibling : parentFolder.getFiles()) {
                    String sn = sibling.getName();
                    if (sn.equals(baseRescueName) || sn.startsWith(baseRescueName + "_")) {
                        alreadyRescued = true;
                        existing = sibling;
                        break;
                    }
                }
            }
            if (alreadyRescued) {
                println(String.format("%s  -- SKIP (already rescued: %s)",
                    header, existing.getPathname()));
                skippedAlreadyRescued++;
                continue;
            }

            // Resolve unique target name
            String targetName = baseRescueName;
            int suffix = 1;
            while (parentFolder.getFile(targetName) != null) {
                targetName = baseRescueName + "_" + suffix++;
            }
            String targetPath = parentFolder.getPathname() + "/" + targetName;
            String savePlan = String.format(
                "  origDf=%s  canSave=%s -> save-as %s",
                (origDf != null ? origDf.getPathname() : "NULL"),
                (origDf != null && origDf.canSave()),
                targetPath);

            if (DRY_RUN) {
                println(header + "  -- WOULD SAVE");
                println(savePlan);
                continue;
            }

            // Execute the save-as
            println(header + "  -- SAVING");
            println(savePlan);
            try {
                DomainFile newDf = parentFolder.createFile(targetName, prog, monitor);
                println("    SUCCESS: " + newDf.getPathname());
                savedCount++;
                savedList.add(newDf.getPathname() + "  (fns=" + fns + " syms=" + syms + " dts=" + dts + ")");
            } catch (Throwable t) {
                println("    ERROR: " + t.getClass().getSimpleName() + ": " + t.getMessage());
                errorList.add(origName + ": " + t.getMessage());
                errors++;
            }
        }

        // 5. Summary
        println("\n=== Summary ===");
        println("mode:                  " + (DRY_RUN ? "DRY RUN" : "EXECUTED"));
        println("saved:                 " + savedCount);
        println("skipped (in CB):       " + skippedLive);
        println("skipped (already done):" + skippedAlreadyRescued);
        println("skipped (duplicate):   " + skippedDuplicateAlias);
        println("skipped (explicit):    " + skippedExplicit);
        println("errors:                " + errors);
        if (!savedList.isEmpty()) {
            println("\nSaved files:");
            for (String s : savedList) println("  " + s);
        }
        if (!errorList.isEmpty()) {
            println("\nErrors:");
            for (String e : errorList) println("  " + e);
        }
        if (DRY_RUN) {
            println("\n>>> DRY RUN ONLY — set DRY_RUN=false at top of script and re-run to actually save. <<<");
        } else {
            println("\nNext: in Project Manager, right-click each '*_recovered' file -> Add to Version Control to push to shared server.");
        }
    }
}
