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

import ghidra.app.services.CodeViewerService;
import ghidra.app.services.GoToService;
import ghidra.app.services.ProgramManager;
import ghidra.framework.model.Project;
import ghidra.framework.model.ToolManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;

import java.util.ArrayList;
import java.util.List;

/**
 * Bridge to running CodeBrowser tools from the FrontEnd plugin.
 *
 * The FrontEnd (Project Manager) tool doesn't have CodeBrowser-specific services
 * like CodeViewerService, GoToService, or the OSGi BundleHost needed for script
 * compilation. This bridge finds running CodeBrowser instances via the ToolManager
 * and delegates operations that require CodeBrowser capabilities.
 *
 * Usage:
 * <pre>
 *   CodeBrowserBridge bridge = new CodeBrowserBridge(frontEndTool);
 *   if (bridge.hasCodeBrowser()) {
 *       ProgramLocation loc = bridge.getCurrentLocation();
 *       bridge.goTo(program, address);
 *       bridge.openProgramInCodeBrowser(program);
 *   }
 * </pre>
 */
public class CodeBrowserBridge {

    private final PluginTool hostTool;

    /**
     * Create a bridge from the given host tool (typically the FrontEnd).
     *
     * @param hostTool The plugin's host tool (FrontEnd or CodeBrowser)
     */
    public CodeBrowserBridge(PluginTool hostTool) {
        this.hostTool = hostTool;
    }

    // ========================================================================
    // CodeBrowser Discovery
    // ========================================================================

    /**
     * Check if any CodeBrowser tool is currently running.
     */
    public boolean hasCodeBrowser() {
        return findCodeBrowser() != null;
    }

    /**
     * Find the first running CodeBrowser tool.
     * A CodeBrowser is identified by having a ProgramManager service.
     *
     * @return The CodeBrowser PluginTool, or null if none running
     */
    public PluginTool findCodeBrowser() {
        // If the host tool IS a CodeBrowser, return it
        if (hostTool.getService(ProgramManager.class) != null
                && hostTool.getService(CodeViewerService.class) != null) {
            return hostTool;
        }

        // Search running tools
        for (PluginTool runningTool : getRunningTools()) {
            if (runningTool != hostTool
                    && runningTool.getService(ProgramManager.class) != null
                    && runningTool.getService(CodeViewerService.class) != null) {
                return runningTool;
            }
        }
        return null;
    }

    /**
     * Find all running CodeBrowser tools.
     */
    public List<PluginTool> findAllCodeBrowsers() {
        List<PluginTool> browsers = new ArrayList<>();
        for (PluginTool runningTool : getRunningTools()) {
            if (runningTool.getService(CodeViewerService.class) != null) {
                browsers.add(runningTool);
            }
        }
        return browsers;
    }

    // ========================================================================
    // CodeViewerService Delegation
    // ========================================================================

    /**
     * Get the CodeViewerService from any running CodeBrowser.
     *
     * @return CodeViewerService, or null if no CodeBrowser is running
     */
    public CodeViewerService getCodeViewerService() {
        // Fast path: check host tool first
        CodeViewerService service = hostTool.getService(CodeViewerService.class);
        if (service != null) return service;

        // Search CodeBrowsers
        for (PluginTool runningTool : getRunningTools()) {
            service = runningTool.getService(CodeViewerService.class);
            if (service != null) return service;
        }
        return null;
    }

    /**
     * Get the current cursor location from any running CodeBrowser.
     *
     * @return Current ProgramLocation, or null if unavailable
     */
    public ProgramLocation getCurrentLocation() {
        CodeViewerService service = getCodeViewerService();
        return (service != null) ? service.getCurrentLocation() : null;
    }

    // ========================================================================
    // GoToService Delegation
    // ========================================================================

    /**
     * Get the GoToService from any running CodeBrowser.
     *
     * @return GoToService, or null if no CodeBrowser is running
     */
    public GoToService getGoToService() {
        GoToService service = hostTool.getService(GoToService.class);
        if (service != null) return service;

        for (PluginTool runningTool : getRunningTools()) {
            service = runningTool.getService(GoToService.class);
            if (service != null) return service;
        }
        return null;
    }

    // ========================================================================
    // ProgramManager Delegation
    // ========================================================================

    /**
     * Get the ProgramManager from any running CodeBrowser.
     * Useful for opening programs in CodeBrowser context.
     *
     * @return ProgramManager, or null if no CodeBrowser is running
     */
    public ProgramManager getProgramManager() {
        // Don't return FrontEnd's ProgramManager (it doesn't have one)
        // Only return from actual CodeBrowser tools
        for (PluginTool runningTool : getRunningTools()) {
            if (runningTool.getService(CodeViewerService.class) != null) {
                ProgramManager pm = runningTool.getService(ProgramManager.class);
                if (pm != null) return pm;
            }
        }
        return null;
    }

    /**
     * Get all ProgramManagers from running CodeBrowsers.
     */
    public List<ProgramManager> getAllProgramManagers() {
        List<ProgramManager> managers = new ArrayList<>();
        for (PluginTool runningTool : getRunningTools()) {
            ProgramManager pm = runningTool.getService(ProgramManager.class);
            if (pm != null) {
                managers.add(pm);
            }
        }
        return managers;
    }

    // ========================================================================
    // Script Execution Support
    // ========================================================================

    /**
     * Get the CodeBrowser PluginTool suitable for script execution.
     * Scripts need a CodeBrowser context for OSGi bundle compilation
     * and access to the full Ghidra API surface.
     *
     * @return CodeBrowser PluginTool for script execution, or null
     */
    public PluginTool getToolForScriptExecution() {
        return findCodeBrowser();
    }

    /**
     * Check if script execution is available (requires CodeBrowser with OSGi).
     */
    public boolean canExecuteScripts() {
        return findCodeBrowser() != null;
    }

    // ========================================================================
    // Analysis Support
    // ========================================================================

    /**
     * Check if a program is open in any CodeBrowser.
     * This is important because analysis works best when the program
     * is open in a CodeBrowser (proper analysis manager context).
     *
     * @param program The program to check
     * @return true if the program is open in at least one CodeBrowser
     */
    public boolean isProgramInCodeBrowser(Program program) {
        if (program == null) return false;
        for (ProgramManager pm : getAllProgramManagers()) {
            Program current = pm.getCurrentProgram();
            if (current != null && current.getDomainFile().equals(program.getDomainFile())) {
                return true;
            }
            // Check all open programs in this CodeBrowser
            for (Program open : pm.getAllOpenPrograms()) {
                if (open.getDomainFile().equals(program.getDomainFile())) {
                    return true;
                }
            }
        }
        return false;
    }

    // ========================================================================
    // Generic Service Lookup
    // ========================================================================

    /**
     * Find a service from any running tool (host first, then CodeBrowsers).
     * Generic version of the service-specific methods above.
     *
     * @param serviceClass The service interface class
     * @return Service instance, or null if not available in any tool
     */
    public <T> T findService(Class<T> serviceClass) {
        T service = hostTool.getService(serviceClass);
        if (service != null) return service;

        for (PluginTool runningTool : getRunningTools()) {
            service = runningTool.getService(serviceClass);
            if (service != null) return service;
        }
        return null;
    }

    // ========================================================================
    // Status / Diagnostics
    // ========================================================================

    /**
     * Get a diagnostic summary of available capabilities.
     */
    public String getCapabilitySummary() {
        StringBuilder sb = new StringBuilder();
        sb.append("Host tool: ").append(hostTool.getName()).append("\n");

        List<PluginTool> browsers = findAllCodeBrowsers();
        sb.append("CodeBrowsers running: ").append(browsers.size()).append("\n");

        for (PluginTool cb : browsers) {
            ProgramManager pm = cb.getService(ProgramManager.class);
            Program current = (pm != null) ? pm.getCurrentProgram() : null;
            sb.append("  - ").append(cb.getName());
            if (current != null) {
                sb.append(" [").append(current.getName()).append("]");
            }
            sb.append("\n");
        }

        sb.append("Capabilities:\n");
        sb.append("  CodeViewer: ").append(getCodeViewerService() != null ? "YES" : "NO").append("\n");
        sb.append("  GoTo: ").append(getGoToService() != null ? "YES" : "NO").append("\n");
        sb.append("  Scripts: ").append(canExecuteScripts() ? "YES" : "NO").append("\n");
        sb.append("  ProgramManager: ").append(getProgramManager() != null ? "YES" : "NO").append("\n");

        return sb.toString();
    }

    // ========================================================================
    // Internal Helpers
    // ========================================================================

    private PluginTool[] getRunningTools() {
        Project project = hostTool.getProject();
        if (project == null) return new PluginTool[0];

        try {
            ToolManager tm = project.getToolManager();
            if (tm == null) return new PluginTool[0];
            return tm.getRunningTools();
        } catch (Exception e) {
            return new PluginTool[0];
        }
    }
}
