package com.xebyte.core;

import ghidra.app.services.CodeViewerService;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;

import javax.swing.SwingUtilities;
import java.util.ArrayList;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Set;

/**
 * The analyst's windows: the running CodeBrowsers, their program managers and code viewers.
 * A provider that has a GUI hands one out from {@link ProgramProvider#workbench()}; headless
 * has none, which is how GUI-only operations know they cannot run. Keeping every
 * {@link PluginTool} touch here is what lets the services above it work without one.
 *
 * <p>The tool is only a seed: the FrontEnd tool carries neither a ProgramManager nor a
 * CodeViewer, so both are looked up across the project's running tools.
 */
public final class Workbench {

    private final PluginTool tool;
    private final ProgramProvider provider;

    public Workbench(PluginTool tool, ProgramProvider provider) {
        this.tool = tool;
        this.provider = provider;
    }

    /** Names of the running tool windows, and whether any of them is a CodeBrowser. */
    public List<String> runningToolNames() {
        List<String> names = new ArrayList<>();
        ghidra.framework.model.Project project = tool.getProject();
        if (project != null && project.getToolManager() != null) {
            for (PluginTool running : project.getToolManager().getRunningTools()) {
                names.add(running.getName());
            }
        }
        return names;
    }

    public boolean codeBrowserActive() {
        ghidra.framework.model.Project project = tool.getProject();
        if (project == null || project.getToolManager() == null) {
            return false;
        }
        for (PluginTool running : project.getToolManager().getRunningTools()) {
            if (running.getService(ProgramManager.class) != null) {
                return true;
            }
        }
        return false;
    }

    /**
     * Show the program in a CodeBrowser, reusing a running one. The CodeBrowser takes its own
     * consumer; the provider's cached reference stays and is what close and eviction release.
     * Returns "shown", or why not.
     */
    public String showProgram(Program program) {
        ProgramManager pm = orCreateProgramManager(tool);
        if (pm == null) {
            return "no CodeBrowser could be found or launched";
        }
        try {
            SwingUtilities.invokeAndWait(() -> {
                pm.openProgram(program);
                pm.setCurrentProgram(program);
            });
            return "shown";
        } catch (Exception e) {
            return "failed: " + (e.getMessage() != null ? e.getMessage() : e.toString());
        }
    }

    /**
     * Close the program open for a project file in the running CodeBrowser. Never spawns one:
     * with none running there is nothing open to close.
     */
    public void closeProgramForFile(String filePath) {
        ProgramManager pm = existingProgramManager(tool);
        if (pm == null) {
            return;
        }
        for (Program prog : provider.getAllOpenPrograms()) {
            if (prog.getDomainFile() != null
                    && prog.getDomainFile().getPathname().equalsIgnoreCase(filePath)) {
                // ignoreChanges=true: this only runs to clear the way for
                // delete_file's delete() call right after, so there is
                // nothing worth saving. false would risk Ghidra's own
                // interactive "Save changes?" dialog, which blocks the Swing
                // event thread -- and with it every other MCP request -- until
                // a human dismisses it.
                pm.closeProgram(prog, true);
                return;
            }
        }
    }

    /** The state a script runs with: this tool, its project, the program and a location in it. */
    public ghidra.app.script.GhidraState scriptState(Program program, ProgramLocation location) {
        return new ghidra.app.script.GhidraState(tool, tool.getProject(), program, location, null, null);
    }

    // ========================================================================
    // Script Execution
    public List<ProgramManager> allProgramManagers() {
        List<ProgramManager> managers = new ArrayList<>();
        Set<PluginTool> seen = Collections.newSetFromMap(new IdentityHashMap<>());

        PluginTool activeTool = tool;
        if (activeTool != null) {
            seen.add(activeTool);
            ProgramManager pm = activeTool.getService(ProgramManager.class);
            if (pm != null) {
                managers.add(pm);
            }

            try {
                ghidra.framework.model.Project project = activeTool.getProject();
                if (project != null) {
                    ghidra.framework.model.ToolManager tm = project.getToolManager();
                    if (tm != null) {
                        for (PluginTool runningTool : tm.getRunningTools()) {
                            if (!seen.add(runningTool)) {
                                continue;
                            }
                            ProgramManager runningPm = runningTool.getService(ProgramManager.class);
                            if (runningPm != null) {
                                managers.add(runningPm);
                            }
                        }
                    }
                }
            } catch (Exception e) {
                Msg.warn(this, "Error scanning for ProgramManager services: " + e.getMessage());
            }
        }

        ProgramManager providerPm = provider.findProgramManager();
        if (providerPm != null && !managers.contains(providerPm)) {
            managers.add(providerPm);
        }
        return managers;
    }

    /**
     * Find an existing ProgramManager without spawning a new CodeBrowser.
     * Returns null when no CodeBrowser is currently running and exposing
     * ProgramManager. Use this from close paths and other operations that
     * have nothing useful to do in a freshly-spawned empty tool.
     */
    private ProgramManager existingProgramManager(PluginTool tool) {
        ProgramManager pm = tool.getService(ProgramManager.class);
        if (pm != null) return pm;

        pm = provider.findProgramManager();
        if (pm != null) return pm;

        ghidra.framework.model.Project project = tool.getProject();
        if (project == null) return null;
        ghidra.framework.model.ToolManager tm = project.getToolManager();
        if (tm == null) return null;
        try {
            for (PluginTool running : tm.getRunningTools()) {
                if (running == tool) continue;
                ProgramManager rpm = running.getService(ProgramManager.class);
                if (rpm != null) return rpm;
            }
        } catch (Exception e) {
            Msg.warn(this, "Error scanning running tools for ProgramManager: " + e.getMessage());
        }
        return null;
    }

    /**
     * Find an existing ProgramManager or launch a new CodeBrowser to get one.
     *
     * <p>Resolution order matters for window hygiene: GhidraMCPPlugin lives in
     * the FrontEnd tool, which has no ProgramManager of its own, so the answer
     * always comes from a running CodeBrowser. Without scanning running tools
     * first, every /open_program and /import_file call would fall through to
     * ws.runTool and accumulate a fresh CodeBrowser per call. The scan reuses
     * any existing CodeBrowser so additional programs open as tabs in it.
     */
    private ProgramManager orCreateProgramManager(PluginTool tool) {
        ProgramManager pm = existingProgramManager(tool);
        if (pm != null) return pm;

        // No CodeBrowser is up — spawn one. This should be rare in practice;
        // it covers genuinely-headless-style sessions where no GUI tool is up.
        ghidra.framework.model.Project project = tool.getProject();
        try {
            if (project != null) {
                ghidra.framework.model.ToolManager tm = project.getToolManager();
                if (tm != null) {
                    ghidra.framework.model.ToolTemplate template =
                        project.getLocalToolChest().getToolTemplate("CodeBrowser");
                    if (template != null) {
                        ghidra.framework.model.Workspace ws = tm.getActiveWorkspace();
                        PluginTool newTool = ws.runTool(template);
                        if (newTool != null) {
                            pm = newTool.getService(ProgramManager.class);
                            if (pm != null) return pm;
                        }
                    }
                }
            }
        } catch (Exception e) {
            Msg.warn(this, "Failed to launch CodeBrowser: " + e.getMessage());
        }

        return null;
    }

    /**
     * CodeViewerService from this tool or any running CodeBrowser — FrontEnd
     * alone has none.
     */
    public CodeViewerService codeViewer() {
        CodeViewerService service = tool.getService(CodeViewerService.class);
        if (service != null) {
            return service;
        }
        try {
            ghidra.framework.model.Project project = tool.getProject();
            if (project == null) {
                return null;
            }
            ghidra.framework.model.ToolManager tm = project.getToolManager();
            if (tm == null) {
                return null;
            }
            for (PluginTool runningTool : tm.getRunningTools()) {
                service = runningTool.getService(CodeViewerService.class);
                if (service != null) {
                    return service;
                }
            }
        } catch (Exception e) {
            // ToolManager may not be available in all contexts
        }
        return null;
    }

}
