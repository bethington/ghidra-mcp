package com.xebyte.core;

import ghidra.app.services.GoToService;
import ghidra.app.services.ProgramManager;
import ghidra.framework.model.Project;
import ghidra.framework.model.ToolManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

import javax.swing.SwingUtilities;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * The tools that only mean something with a Ghidra window: what tools are running, and
 * moving a CodeBrowser to an address. Registered by the GUI plugin alone, so the headless
 * schema never advertises them.
 *
 * <p>Opening a program in a CodeBrowser is not here. {@code /open_program} does that, and
 * releases its reference to the program properly; the retired
 * {@code /tool/launch_codebrowser} took one under the plugin as consumer and never gave
 * it back.
 */
public class GuiToolService {

    private final PluginTool tool;

    public GuiToolService(PluginTool tool) {
        this.tool = tool;
    }

    private ToolManager toolManager() {
        Project project = tool.getProject();
        return project != null ? project.getToolManager() : null;
    }

    /** The first running tool with a program manager: the CodeBrowser. */
    private PluginTool codeBrowser(ToolManager tm) {
        for (PluginTool running : tm.getRunningTools()) {
            if (running.getService(ProgramManager.class) != null) {
                return running;
            }
        }
        return null;
    }

    @McpTool(path = "/tool/running_tools",
            description = "The Ghidra tool windows that are running, with each one's current program and "
                + "open programs when it has a program manager (a CodeBrowser does).",
            category = "utility", access = ToolAccess.READ_ONLY)
    public Response runningTools() {
        if (tool.getProject() == null) {
            return Response.err("No project open");
        }
        ToolManager tm = toolManager();
        if (tm == null) {
            return Response.err("ToolManager not available");
        }
        try {
            List<Map<String, Object>> tools = new ArrayList<>();
            for (PluginTool running : tm.getRunningTools()) {
                Map<String, Object> row = new LinkedHashMap<>();
                row.put("name", running.getName());
                row.put("instance", running.getInstanceName());
                ProgramManager pm = running.getService(ProgramManager.class);
                row.put("has_program_manager", pm != null);
                if (pm != null) {
                    Program current = pm.getCurrentProgram();
                    if (current != null) {
                        row.put("current_program", current.getName());
                    }
                    List<String> open = new ArrayList<>();
                    for (Program p : pm.getAllOpenPrograms()) {
                        open.add(p.getName());
                    }
                    row.put("open_programs", open);
                }
                tools.add(row);
            }
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("tools", tools);
            out.put("count", tools.size());
            return Response.ok(out);
        } catch (Exception e) {
            return Response.err("Failed to list tools: " + messageOf(e));
        }
    }

    @McpTool(path = "/tool/goto_address", dryRun = false, method = "POST",
            description = "Move the running CodeBrowser's listing and decompiler to an address, in the "
                + "program it has current. Reports the function containing the address, if any.",
            category = "utility", access = ToolAccess.WRITE)
    public Response gotoAddress(
            @Param(value = "address", source = ParamSource.BODY,
                   description = "Address to navigate to, as 0x<hex> or <space>:<hex>. It moves a "
                               + "CodeBrowser window, so it needs a running CodeBrowser with a "
                               + "program open.") String address) {
        if (address == null || address.trim().isEmpty()) {
            return Response.err("address parameter is required");
        }
        try {
            if (tool.getProject() == null) {
                return Response.err("No project open");
            }
            ToolManager tm = toolManager();
            if (tm == null) {
                return Response.err("ToolManager not available");
            }
            PluginTool browser = codeBrowser(tm);
            if (browser == null) {
                return Response.err("No CodeBrowser running");
            }
            GoToService goTo = browser.getService(GoToService.class);
            if (goTo == null) {
                return Response.err("GoToService not available in CodeBrowser");
            }
            Program program = browser.getService(ProgramManager.class).getCurrentProgram();
            if (program == null) {
                return Response.err("No program open in CodeBrowser");
            }
            Address target = ServiceUtils.parseAddress(program, address);
            if (target == null) {
                return Response.err(ServiceUtils.getLastParseError());
            }

            AtomicBoolean moved = new AtomicBoolean(false);
            SwingUtilities.invokeAndWait(() -> moved.set(goTo.goTo(target)));
            if (!moved.get()) {
                return Response.err("GoToService could not navigate to " + address);
            }
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("success", true);
            out.put("address", target.toString());
            Function containing = program.getFunctionManager().getFunctionContaining(target);
            if (containing != null) {
                out.put("function", containing.getName());
            }
            return Response.ok(out);
        } catch (Exception e) {
            return Response.err("Failed to navigate: " + messageOf(e));
        }
    }

    private static String messageOf(Exception e) {
        return e.getMessage() != null ? e.getMessage() : e.toString();
    }
}
