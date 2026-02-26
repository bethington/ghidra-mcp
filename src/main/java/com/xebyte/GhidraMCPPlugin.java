package com.xebyte;

import com.xebyte.core.ServerManager;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.framework.main.ApplicationLevelPlugin;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.Msg;

import java.io.IOException;

@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = ghidra.app.DeveloperPluginPackage.NAME,
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "GhidraMCP - MCP server plugin",
    description = "GhidraMCP - Exposes program data via Unix domain socket HTTP server " +
                  "for MCP bridge and AI tool integration. " +
                  "Loads in both Project Window and CodeBrowser. " +
                  "See https://github.com/bethington/ghidra-mcp for documentation."
)
public class GhidraMCPPlugin extends Plugin implements ApplicationLevelPlugin {

    public GhidraMCPPlugin(PluginTool tool) {
        super(tool);
        try {
            ServerManager.getInstance().registerTool(tool);
            Msg.info(this, "GhidraMCP plugin registered with ServerManager");
        } catch (IOException e) {
            Msg.error(this, "Failed to start GhidraMCP server: " + e.getMessage(), e);
            Msg.showError(this, null, "GhidraMCP Server Error",
                "Failed to start MCP server.\n\n" +
                "Error: " + e.getMessage());
        }
    }

    @Override
    public void dispose() {
        ServerManager.getInstance().deregisterTool(tool);
        Msg.info(this, "GhidraMCP plugin deregistered from ServerManager");
        super.dispose();
    }
}
