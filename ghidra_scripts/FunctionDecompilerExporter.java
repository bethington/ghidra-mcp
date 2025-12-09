//Function Decompiler Exporter
//
//This script exports all functions to JSON format with their function prototypes
//and decompiled C code. Outputs both formatted and minified JSON versions.
//Useful for external analysis, documentation, or code review.
//
//@author Ben Ethington
//@category Diablo 2
//@description Exports all functions with prototypes and decompiled code to JSON
//@keybinding
//@menupath Diablo II.Function Decompiler Exporter

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Parameter;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class FunctionDecompilerExporter extends GhidraScript {

    @Override
    public void run() throws Exception {
        // Initialize the decompiler
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        decompiler.setSimplificationStyle("decompile");

        try {
            JsonArray functionsArray = new JsonArray();
            int functionCount = 0;

            // Get all functions
            FunctionIterator functionIterator = currentProgram.getFunctionManager().getFunctions(true);

            println("Starting function export...");

            for (Function function : functionIterator) {
                monitor.checkCancelled();

                JsonObject functionObj = new JsonObject();

                // Basic function information
                functionObj.addProperty("name", function.getName());
                functionObj.addProperty("address", "0x" + function.getEntryPoint().toString());
                functionObj.addProperty("prototype", function.getPrototypeString(false, false));

                // Get decompiled code
                String decompiledCode = "";
                try {
                    DecompileResults results = decompiler.decompileFunction(function, 30, monitor);

                    if (results != null && results.decompileCompleted()) {
                        decompiledCode = results.getDecompiledFunction().getC();
                    } else {
                        decompiledCode = "// Decompilation failed or timed out";
                        if (results != null && results.getErrorMessage() != null) {
                            decompiledCode += "\n// Error: " + results.getErrorMessage();
                        }
                    }
                } catch (Exception e) {
                    decompiledCode = "// Exception during decompilation: " + e.getMessage();
                }

                functionObj.addProperty("decompiled", decompiledCode);

                // Add parameter details
                JsonArray paramsArray = new JsonArray();
                Parameter[] parameters = function.getParameters();
                for (int i = 0; i < parameters.length; i++) {
                    Parameter param = parameters[i];
                    JsonObject paramObj = new JsonObject();
                    paramObj.addProperty("name", param.getName());
                    paramObj.addProperty("type", param.getDataType().toString());
                    paramObj.addProperty("size", param.getDataType().getLength());
                    paramObj.addProperty("idx", i);

                    if (param.isRegisterVariable()) {
                        paramObj.addProperty("location", param.getRegister().toString());
                    } else if (param.isStackVariable()) {
                        paramObj.addProperty("location", String.format("Stack[0x%02X]", param.getStackOffset()));
                    } else {
                        paramObj.addProperty("location", "unknown");
                    }

                    paramsArray.add(paramObj);
                }
                functionObj.add("params", paramsArray);

                // Return type
                if (function.getReturn() != null) {
                    functionObj.addProperty("returntype", function.getReturn().getDataType().toString());
                } else {
                    functionObj.addProperty("returntype", "void");
                }

                functionObj.addProperty("paramcount", parameters.length);

                functionsArray.add(functionObj);
                functionCount++;

                if (functionCount % 100 == 0) {
                    println("Processed " + functionCount + " functions...");
                }
            }

            // Get binary name for output files
            String binaryName = currentProgram.getName();
            // Remove file extension if present
            if (binaryName.contains(".")) {
                binaryName = binaryName.substring(0, binaryName.lastIndexOf('.'));
            }

            // Write formatted JSON
            Gson gsonPretty = new GsonBuilder().setPrettyPrinting().create();
            String prettyJson = gsonPretty.toJson(functionsArray);

            File outputFile = new File(binaryName + "_funcs.json");
            try (FileWriter writer = new FileWriter(outputFile)) {
                writer.write(prettyJson);
            }
            println("Wrote formatted JSON to: " + outputFile.getAbsolutePath());

            // Write minified JSON
            Gson gsonCompact = new Gson();
            String compactJson = gsonCompact.toJson(functionsArray);

            File minifiedFile = new File(binaryName + "_funcs_min.json");
            try (FileWriter writer = new FileWriter(minifiedFile)) {
                writer.write(compactJson);
            }
            println("Wrote minified JSON to: " + minifiedFile.getAbsolutePath());

            println("Exported " + functionCount + " functions with decompiled code");

        } catch (CancelledException e) {
            println("Export cancelled by user");
        } finally {
            decompiler.dispose();
        }
    }
}
