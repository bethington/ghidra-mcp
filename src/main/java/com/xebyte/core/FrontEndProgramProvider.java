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
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;

import java.util.ArrayList;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Set;

/**
 * The GUI's programs: whatever the running CodeBrowsers have open, then
 * {@link ProjectProgramProvider}'s on-demand cache over the FrontEnd's project.
 *
 * <p>Everything except the CodeBrowser layer is shared with the headless server.
 * {@code getDomainObject} hands back the same Program instance a CodeBrowser already
 * has, so a program the user is looking at and one this provider opened are one object.
 */
public class FrontEndProgramProvider extends ProjectProgramProvider {

    private final PluginTool tool;
    private final Workbench workbench;
    // Current program when no CodeBrowser has one: the first program opened on demand,
    // or the one /switch_program selected. CodeBrowser focus always wins over it.
    private volatile Program currentProgram;

    /**
     * @param tool     the FrontEnd tool
     * @param consumer the DomainObject consumer our references are held under (the plugin)
     */
    public FrontEndProgramProvider(PluginTool tool, Object consumer) {
        super(consumer, false);
        this.tool = tool;
        this.workbench = new Workbench(tool, this);
    }

    @Override
    protected Project project() {
        return tool.getProject();
    }

    @Override
    protected List<Program> liveSessionPrograms() {
        List<Program> all = new ArrayList<>();
        Set<Program> seen = Collections.newSetFromMap(new IdentityHashMap<>());
        for (ProgramManager pm : findAllCodeBrowserProgramManagers()) {
            for (Program p : pm.getAllOpenPrograms()) {
                // Identity, not name: two versions of one DLL are two programs.
                if (seen.add(p)) {
                    all.add(p);
                }
            }
        }
        return all;
    }

    @Override
    protected void onOpened(Program program) {
        if (currentProgram == null) {
            currentProgram = program;
        }
    }

    @Override
    protected void onReleased(Program program) {
        if (program == currentProgram) {
            currentProgram = null;
        }
    }

    @Override
    public Program getCurrentProgram() {
        for (ProgramManager pm : findAllCodeBrowserProgramManagers()) {
            Program p = pm.getCurrentProgram();
            if (p != null) {
                return p;
            }
        }
        return currentProgram;
    }

    @Override
    public void setCurrentProgram(Program program) {
        this.currentProgram = program;
        if (program == null) {
            return;
        }
        // Focus the CodeBrowser that actually has it open.
        for (ProgramManager pm : findAllCodeBrowserProgramManagers()) {
            for (Program p : pm.getAllOpenPrograms()) {
                if (p == program) {
                    pm.setCurrentProgram(program);
                    return;
                }
            }
        }
    }

    /** ProgramManagers of every running CodeBrowser; the FrontEnd tool has none of its own. */
    private List<ProgramManager> findAllCodeBrowserProgramManagers() {
        List<ProgramManager> managers = new ArrayList<>();
        Project project = tool.getProject();
        if (project == null) {
            return managers;
        }
        try {
            ghidra.framework.model.ToolManager tm = project.getToolManager();
            if (tm == null) {
                return managers;
            }
            for (PluginTool running : tm.getRunningTools()) {
                ProgramManager pm = running.getService(ProgramManager.class);
                if (pm != null) {
                    managers.add(pm);
                }
            }
        } catch (Exception e) {
            // ToolManager may not be available in all contexts
        }
        return managers;
    }

    @Override
    public ProgramManager findProgramManager() {
        List<ProgramManager> managers = findAllCodeBrowserProgramManagers();
        return managers.isEmpty() ? null : managers.get(0);
    }

    /**
     * Close every open instance of the program at this project path: in each
     * CodeBrowser, and our own cached handle.
     */
    @Override
    public boolean closeProgramByPath(String path) {
        if (path == null || path.isBlank()) {
            return false;
        }
        String wanted = path.trim();
        boolean closed = false;
        for (ProgramManager pm : findAllCodeBrowserProgramManagers()) {
            for (Program prog : pm.getAllOpenPrograms()) {
                DomainFile df = prog.getDomainFile();
                if (df != null && df.getPathname().equalsIgnoreCase(wanted)) {
                    // ignoreChanges=true: this makes way for a delete, so there is nothing
                    // to save for. false would let Ghidra raise its own "Save changes?"
                    // dialog, which blocks the Swing thread -- and every MCP request
                    // queued behind it -- until a human clicks something.
                    pm.closeProgram(prog, true);
                    closed = true;
                }
            }
        }
        return super.closeProgramByPath(wanted) || closed;
    }

    @Override
    public Workbench workbench() {
        return workbench;
    }
}
