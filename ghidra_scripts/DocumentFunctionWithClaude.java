// Document current function by calling Claude AI with comprehensive plate comment prompt
// This script analyzes the current function and uses Claude to generate a detailed
// function header comment following the standard plate comment format.
//
// @author Ben Ethington
// @category Documentation
// @keybinding ctrl shift P
// @menupath Tools.Document Function with Claude
// @toolbar

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Reference;

import java.io.*;
import java.util.ArrayList;
import java.util.List;

public class DocumentFunctionWithClaude extends GhidraScript {
    
    private static final String PLATE_COMMENT_PROMPT = 
        "First, call get_current_function() function to retrieve the function at the current cursor position in Ghidra.\n\n" +
        "Then, create a comprehensive function header comment using set_plate_comment following the exact format template from Format Template. " +
        "The plate comment must use plain text format WITHOUT any decorative borders - Ghidra adds all formatting automatically. " +
        "The format includes: a one-line function summary, an Algorithm section with numbered steps describing each major operation in the function, " +
        "a Parameters section listing each parameter with its type and purpose, a Returns section documenting return values and conditions, " +
        "a Special Cases section for edge cases and magic numbers, and optionally a Structure Layout section with an ASCII table showing field offsets " +
        "sizes and descriptions when the function accesses structured data. Number algorithm steps starting from 1 and include all validation checks, " +
        "function calls, and error handling. Reference specific ordinals, addresses, and magic numbers by their values. For structure layouts, use the " +
        "table format with columns for Offset, Size, Field Name, Type, and Description, and calculate the total structure size from stride patterns or " +
        "highest offset. Create struct definitions for repeated access patterns using create_struct, and use analyze_data_region to analyze pointer " +
        "targets and understand data layouts. Replace all undefined types with proper types: undefined1 becomes byte, undefined2 becomes word, " +
        "undefined4 becomes uint or pointer, and undefined8 becomes qword.\n\n" +
        "Format Template:\n\n" +
        "**IMPORTANT**: Do NOT include any decorative borders or `/* */` markers - Ghidra adds these automatically!\n\n" +
        "```\n" +
        "[ONE-LINE FUNCTION SUMMARY]\n\n" +
        "Algorithm:\n" +
        "1. [First major step in algorithm]\n" +
        "2. [Second major step in algorithm]\n" +
        "3. [Third major step in algorithm]\n" +
        "4. [Continue numbering all algorithm steps]\n" +
        "5. [Each step should be one clear action]\n" +
        "6. [Include validation, error handling, and special cases]\n" +
        "7. [Reference specific functions/data when relevant]\n" +
        "8. [Document magic numbers and sentinel values]\n\n" +
        "Parameters:\n" +
        "  param_name: [Type and purpose description]\n" +
        "  secondParam: [Type and purpose description]\n" +
        "  pointerParam: [What the pointer references and expected state]\n" +
        "  registerParam: [If passed via register, note which register]\n\n" +
        "Returns:\n" +
        "  [Return type]: [What the return value means and possible values]\n" +
        "  [Document all return paths - success, failure, special cases]\n\n" +
        "Special Cases:\n" +
        "  - [Document edge cases, boundary conditions]\n" +
        "  - [Note special handling for specific values]\n" +
        "  - [Explain error conditions and their handling]\n" +
        "  - [Reference validation checks and their reasons]\n\n" +
        "[OPTIONAL SECTION: Structure Layout]\n" +
        "[If function accesses structured data, document the structure here]\n" +
        "  Offset  | Size | Field Name       | Type    | Description\n" +
        "  --------|------|------------------|---------|------------------------------------------\n" +
        "  +0x00   | 4    | dwType           | DWORD   | [Field purpose]\n" +
        "  +0x04   | 4    | dwUnitId         | DWORD   | [Field purpose]\n" +
        "  +0x08   | 4    | dwMode           | DWORD   | [Field purpose]\n" +
        "  ...\n" +
        "  Total Size: [Calculate from highest offset + size]\n" +
        "```\n\n" +
        "## Formatting Rules\n\n" +
        "- **No decorative borders**: Do NOT include lines of asterisks\n" +
        "- **No comment markers**: Do NOT include `/*` or `*/`\n" +
        "- **No line prefixes**: Do NOT prefix lines with ` * ` or similar markers\n" +
        "- **Clean text only**: Just provide the actual documentation content\n" +
        "- **Indentation**: Use 2 spaces for indenting parameters, list items, and table rows\n\n";

    @Override
    public void run() throws Exception {
        // Get current function to verify cursor is inside a function
        Function currentFunction = getFunctionContaining(currentAddress);
        if (currentFunction == null) {
            popup("No function at current address. Please place cursor inside a function.");
            return;
        }

        println("Analyzing function: " + currentFunction.getName() + " @ " + currentFunction.getEntryPoint());
        println("Claude will retrieve full function details via get_current_function() MCP tool");

        // Build the complete prompt
        String fullPrompt = PLATE_COMMENT_PROMPT +
            "Please analyze the current function retrieved via get_current_function() and generate a comprehensive plate comment following the format template. " +
            "Use the MCP tool set_plate_comment to apply the comment to the function's address. " +
            "Remember: provide ONLY plain text without decorative borders - Ghidra adds formatting automatically.";

        println("\n=== Calling Claude AI ===");
        println("Prompt length: " + fullPrompt.length() + " characters");
        println("Claude will query Ghidra for current function details via MCP");

        // Find Claude CLI and MCP config
        String userHome = System.getProperty("user.home");
        String mcpConfig = findMcpConfig(userHome);
        
        if (mcpConfig == null) {
            popup("Could not find mcp-config.json. Please ensure it exists in:\n" +
                  "- " + userHome + "\\source\\mcp\\ghidra-mcp\\\n" +
                  "- Current directory");
            return;
        }

        // Execute Claude CLI with direct stdin
        // Use full path to claude.cmd since Java ProcessBuilder doesn't use PATH
        String claudePath = System.getenv("APPDATA") + "\\npm\\claude.cmd";
        ProcessBuilder pb = new ProcessBuilder(
            claudePath, "-p", 
            "--mcp-config", mcpConfig,
            "--dangerously-skip-permissions"
        );
        pb.redirectErrorStream(true);
        
        println("Executing: " + String.join(" ", pb.command()));
        
        Process process = pb.start();
        
        // Write prompt directly to stdin
        try (OutputStreamWriter writer = new OutputStreamWriter(process.getOutputStream())) {
            writer.write(fullPrompt);
            writer.flush();
        }
        
        // Read output
        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        StringBuilder output = new StringBuilder();
        String line;
        
        println("\n=== Claude Output ===");
        while ((line = reader.readLine()) != null) {
            println(line);
            output.append(line).append("\n");
        }
        
        int exitCode = process.waitFor();
        
        if (exitCode == 0) {
            println("\n=== SUCCESS ===");
            println("Function documentation completed!");
            println("Check the function's plate comment in the decompiler view.");
        } else {
            popup("Claude CLI failed with exit code: " + exitCode + "\n\nSee console for details.");
        }
    }

    private String findMcpConfig(String userHome) {
        // Check common locations
        String[] possiblePaths = {
            userHome + "\\source\\mcp\\ghidra-mcp\\mcp-config.json",
            System.getProperty("user.dir") + "\\mcp-config.json",
            "..\\mcp-config.json"
        };
        
        for (String path : possiblePaths) {
            File f = new File(path);
            if (f.exists()) {
                return f.getAbsolutePath();
            }
        }
        
        return null;
    }
}
