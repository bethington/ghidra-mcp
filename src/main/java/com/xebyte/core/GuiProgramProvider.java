/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.xebyte.core;

import ghidra.app.services.ProgramManager;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectData;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

/**
 * GUI mode implementation of ProgramProvider.
 *
 * Wraps Ghidra's ProgramManager service for program access in GUI mode.
 */
public class GuiProgramProvider implements ProgramProvider {

    private final PluginTool tool;

    /**
     * Create a GuiProgramProvider for the given tool.
     *
     * @param tool The Ghidra PluginTool providing services
     */
    public GuiProgramProvider(PluginTool tool) {
        this.tool = tool;
    }

    @Override
    public Program getCurrentProgram() {
        ProgramManager pm = tool.getService(ProgramManager.class);
        return pm != null ? pm.getCurrentProgram() : null;
    }

    @Override
    public Program getProgram(String name) {
        if (name == null || name.trim().isEmpty()) {
            return getCurrentProgram();
        }

        ProgramManager pm = tool.getService(ProgramManager.class);
        if (pm == null) {
            return null;
        }

        Program[] programs = pm.getAllOpenPrograms();
        String searchName = name.trim();

        // Try exact name match first (case-insensitive)
        for (Program prog : programs) {
            if (prog.getName().equalsIgnoreCase(searchName)) {
                return prog;
            }
        }

        // Try partial match (name contains search term)
        for (Program prog : programs) {
            if (prog.getName().toLowerCase().contains(searchName.toLowerCase())) {
                return prog;
            }
        }

        return null;
    }

    @Override
    public Program[] getAllOpenPrograms() {
        ProgramManager pm = tool.getService(ProgramManager.class);
        return pm != null ? pm.getAllOpenPrograms() : new Program[0];
    }

    @Override
    public void setCurrentProgram(Program program) {
        ProgramManager pm = tool.getService(ProgramManager.class);
        if (pm != null && program != null) {
            pm.setCurrentProgram(program);
        }
    }

    @Override
    public Project getProject() {
        return tool.getProject();
    }

    @Override
    public Program openFromProject(String path) {
        Project project = tool.getProject();
        if (project == null) {
            return null;
        }

        ProjectData projectData = project.getProjectData();
        DomainFile domainFile = projectData.getFile(path);
        if (domainFile == null) {
            return null;
        }

        try {
            Program program = (Program) domainFile.getDomainObject(
                tool, false, false, TaskMonitor.DUMMY);
            if (program != null) {
                ProgramManager pm = tool.getService(ProgramManager.class);
                if (pm != null) {
                    pm.openProgram(program);
                    pm.setCurrentProgram(program);
                }
            }
            return program;
        } catch (Exception e) {
            Msg.error(this, "Failed to open program: " + path + " - " + e.getMessage());
            return null;
        }
    }

    /**
     * Get the underlying PluginTool.
     *
     * @return The PluginTool
     */
    public PluginTool getTool() {
        return tool;
    }
}
