package com.xebyte.core;

import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;

/**
 * ProgramProvider that searches across all registered PluginTools.
 *
 * Used by ServerManager to aggregate programs from multiple CodeBrowser
 * windows within the same Ghidra JVM. Thread-safe.
 */
public class MultiToolProgramProvider implements ProgramProvider {

    private final Map<String, PluginTool> tools;
    private final AtomicReference<String> activeToolId;

    public MultiToolProgramProvider(Map<String, PluginTool> tools,
                                    AtomicReference<String> activeToolId) {
        this.tools = tools;
        this.activeToolId = activeToolId;
    }

    @Override
    public Program getCurrentProgram() {
        // Try active tool first
        PluginTool active = getActiveTool();
        if (active != null) {
            ProgramManager pm = active.getService(ProgramManager.class);
            if (pm != null) {
                Program p = pm.getCurrentProgram();
                if (p != null) return p;
            }
        }
        // Fall back to any tool with an open program
        for (PluginTool tool : tools.values()) {
            ProgramManager pm = tool.getService(ProgramManager.class);
            if (pm != null) {
                Program p = pm.getCurrentProgram();
                if (p != null) return p;
            }
        }
        return null;
    }

    @Override
    public Program getProgram(String name) {
        if (name == null || name.trim().isEmpty()) {
            return getCurrentProgram();
        }
        String searchName = name.trim();

        // Exact name match (case-insensitive) across all tools
        for (PluginTool tool : tools.values()) {
            ProgramManager pm = tool.getService(ProgramManager.class);
            if (pm == null) continue;
            for (Program prog : pm.getAllOpenPrograms()) {
                if (prog.getName().equalsIgnoreCase(searchName)) {
                    return prog;
                }
            }
        }

        // Partial match on path
        for (PluginTool tool : tools.values()) {
            ProgramManager pm = tool.getService(ProgramManager.class);
            if (pm == null) continue;
            for (Program prog : pm.getAllOpenPrograms()) {
                String path = prog.getDomainFile().getPathname();
                if (path.toLowerCase().contains(searchName.toLowerCase())) {
                    return prog;
                }
            }
        }

        // Match without extension
        for (PluginTool tool : tools.values()) {
            ProgramManager pm = tool.getService(ProgramManager.class);
            if (pm == null) continue;
            for (Program prog : pm.getAllOpenPrograms()) {
                String pname = prog.getName();
                String nameNoExt = pname.contains(".") ?
                    pname.substring(0, pname.lastIndexOf('.')) : pname;
                if (nameNoExt.equalsIgnoreCase(searchName)) {
                    return prog;
                }
            }
        }

        return null;
    }

    @Override
    public Program[] getAllOpenPrograms() {
        // Use identity set to deduplicate programs shared between tools
        Set<Program> seen = Collections.newSetFromMap(new IdentityHashMap<>());
        for (PluginTool tool : tools.values()) {
            ProgramManager pm = tool.getService(ProgramManager.class);
            if (pm != null) {
                Collections.addAll(seen, pm.getAllOpenPrograms());
            }
        }
        return seen.toArray(new Program[0]);
    }

    @Override
    public void setCurrentProgram(Program program) {
        // Find which tool owns this program and set it there
        for (PluginTool tool : tools.values()) {
            ProgramManager pm = tool.getService(ProgramManager.class);
            if (pm == null) continue;
            for (Program prog : pm.getAllOpenPrograms()) {
                if (prog == program) {
                    pm.setCurrentProgram(program);
                    return;
                }
            }
        }
    }

    /**
     * Find a ProgramManager from any registered tool (active tool preferred).
     * Returns null only if no tool has a ProgramManager (e.g., only FrontEndTool registered).
     */
    public ProgramManager findProgramManager() {
        PluginTool active = getActiveTool();
        if (active != null) {
            ProgramManager pm = active.getService(ProgramManager.class);
            if (pm != null) return pm;
        }
        for (PluginTool tool : tools.values()) {
            ProgramManager pm = tool.getService(ProgramManager.class);
            if (pm != null) return pm;
        }
        return null;
    }

    /**
     * Get the currently active PluginTool (the one whose window was last focused).
     */
    public PluginTool getActiveTool() {
        String id = activeToolId.get();
        if (id != null) {
            PluginTool t = tools.get(id);
            if (t != null) return t;
        }
        // Fall back to any registered tool
        var iter = tools.values().iterator();
        return iter.hasNext() ? iter.next() : null;
    }
}
