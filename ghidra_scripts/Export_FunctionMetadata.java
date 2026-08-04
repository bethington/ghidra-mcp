// Function Metadata
//
// Exports all functions to JSON with complete metadata including addresses, parameters, return types, disassembly snippets, and jumpback addresses for creating hooking frameworks.
//
// Usage: Run from Script Manager on any program.
// Output: JSON files (game.json and game_minify.json) with function metadata.
//
// @author Ben Ethington
// @category Diablo 2.Export
// @description Export function metadata with hooking information
// @menupath Diablo 2.Export.Function Metadata

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.util.exception.CancelledException;
import java.io.*;
import java.nio.file.*;

public class Export_FunctionMetadata extends GhidraScript {

    private String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    @Override
    public void run() throws Exception {
        StringBuilder sb = new StringBuilder();
        sb.append("[\n");
        int o = 0;
        boolean first = true;

        try {
            FunctionIterator funcIter = currentProgram.getFunctionManager().getFunctions(true);
            while (funcIter.hasNext()) {
                monitor.checkCanceled();
                Function func = funcIter.next();

                if (func.getEntryPoint().toString().equals("00681a48")) break;
                o++;

                String asm = "";
                String jumpback = "";

                for (Instruction inst : currentProgram.getListing().getInstructions(func.getBody(), true)) {
                    if (inst.getAddress().compareTo(func.getEntryPoint().add(5)) >= 0) {
                        jumpback = "0x" + inst.getAddress();
                        break;
                    }
                    asm += inst.toString() + "\\n";
                }

                if (!first) sb.append(",\n");
                first = false;

                sb.append("  {\n");
                sb.append("    \"name\": \"").append(escapeJson(func.getName())).append("\",\n");
                sb.append("    \"address\": \"0x").append(func.getEntryPoint()).append("\",\n");
                sb.append("    \"paramcount\": ").append(func.getParameterCount()).append(",\n");
                sb.append("    \"returntype\": \"").append(escapeJson(func.getReturn().getDataType().toString())).append("\",\n");
                sb.append("    \"ASM\": \"").append(asm).append("\",\n");
                sb.append("    \"jumpback\": \"").append(escapeJson(jumpback)).append("\",\n");
                sb.append("    \"params\": [\n");

                Parameter[] params = func.getParameters();
                for (int i = 0; i < params.length; i++) {
                    Parameter p = params[i];
                    String typeName = p.getDataType().toString();
                    int size = p.getDataType().getLength();
                    String loc;
                    if (p.isRegisterVariable()) {
                        loc = p.getRegister().toString();
                    } else if (p.isStackVariable()) {
                        loc = String.format("Stack[0x%02X]", p.getStackOffset());
                    } else {
                        loc = p.getVariableStorage().toString();
                    }
                    if (i > 0) sb.append(",\n");
                    sb.append("      {\n");
                    sb.append("        \"name\": \"").append(escapeJson(p.getName())).append("\",\n");
                    sb.append("        \"type\": \"").append(escapeJson(typeName)).append("\",\n");
                    sb.append("        \"location\": \"").append(escapeJson(loc)).append("\",\n");
                    sb.append("        \"idx\": ").append(i).append(",\n");
                    sb.append("        \"size\": ").append(size).append("\n");
                    sb.append("      }");
                }

                sb.append("\n    ]\n  }");
            }
        } catch (CancelledException e) {
            // cancelled
        }

        sb.append("\n]\n");

        String outputPath = System.getProperty("user.home") + "/game.json";
        Files.writeString(Path.of(outputPath), sb.toString());

        // Write minified version
        String minified = sb.toString()
            .replaceAll("\\s*\\n\\s*", "")
            .replaceAll(",\\s+", ",")
            .replaceAll(":\\s+", ":")
            .replaceAll("\\{\\s+", "{")
            .replaceAll("\\[\\s+", "[")
            .replaceAll("\\s+\\}", "}")
            .replaceAll("\\s+\\]", "]");

        String minPath = System.getProperty("user.home") + "/game_minify.json";
        Files.writeString(Path.of(minPath), minified);

        println("Exported " + o + " functions");
        println("Output: " + outputPath);
        println("Minified: " + minPath);
    }
}
