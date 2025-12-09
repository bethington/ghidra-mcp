//Export enhanced function data for ALL programs in the current Ghidra project
//@category D2VersionChanger
//@menupath Tools.Export All Enhanced
//@description Iterates through all programs in the project and exports enhanced function data for each. Output: data/enhanced/{GameType}/{Version}/{dll}.json

import ghidra.app.script.GhidraScript;
import ghidra.framework.model.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;
import ghidra.util.exception.*;
import java.io.*;
import java.util.*;

/**
 * Batch export script that processes all programs in the current Ghidra project.
 * 
 * For each program found in the project, this script:
 * 1. Opens the program
 * 2. Runs the enhanced export (callees, callers, strings, instructions)
 * 3. Saves to data/enhanced/{GameType}/{Version}/{programName}.json
 * 4. Closes the program to free memory
 * 
 * Expected project structure:
 *   /LoD/1.07/D2Client.dll
 *   /LoD/1.08/D2Client.dll
 *   /Classic/1.00/D2Client.dll
 *   etc.
 * 
 * The game type and version are derived from the folder path.
 */
public class ExportAllEnhanced extends GhidraScript {

    private int totalProcessed = 0;
    private int totalFailed = 0;
    private List<String> failedPrograms = new ArrayList<>();

    @Override
    public void run() throws Exception {
        println("=".repeat(70));
        println("BATCH ENHANCED FUNCTION EXPORT");
        println("=".repeat(70));
        
        // Get the project
        Project project = state.getProject();
        if (project == null) {
            printerr("No project is open!");
            return;
        }
        
        ProjectData projectData = project.getProjectData();
        println("Project: " + projectData.getProjectLocator().getName());
        
        // Get root folder
        DomainFolder rootFolder = projectData.getRootFolder();
        
        // Count total files first
        int totalFiles = countProgramFiles(rootFolder);
        println("Total program files found: " + totalFiles);
        println("");
        
        // Ask user for confirmation
        if (!askYesNo("Confirm Batch Export", 
                "This will export enhanced data for " + totalFiles + " programs.\n" +
                "This may take a while. Continue?")) {
            println("Export cancelled by user.");
            return;
        }
        
        // Process all folders recursively
        processFolder(rootFolder, "");
        
        // Summary
        println("");
        println("=".repeat(70));
        println("BATCH EXPORT COMPLETE");
        println("=".repeat(70));
        println("Successfully processed: " + totalProcessed);
        println("Failed: " + totalFailed);
        
        if (!failedPrograms.isEmpty()) {
            println("");
            println("Failed programs:");
            for (String prog : failedPrograms) {
                println("  - " + prog);
            }
        }
    }
    
    private int countProgramFiles(DomainFolder folder) throws Exception {
        int count = 0;
        
        // Count files in this folder
        for (DomainFile file : folder.getFiles()) {
            String contentType = file.getContentType();
            if (contentType.equals("Program")) {
                count++;
            }
        }
        
        // Recurse into subfolders
        for (DomainFolder subfolder : folder.getFolders()) {
            count += countProgramFiles(subfolder);
        }
        
        return count;
    }
    
    private void processFolder(DomainFolder folder, String path) throws Exception {
        String currentPath = path.isEmpty() ? folder.getName() : path + "/" + folder.getName();
        
        // Skip root folder name in path
        if (folder.getParent() == null) {
            currentPath = "";
        }
        
        // Process files in this folder
        for (DomainFile file : folder.getFiles()) {
            if (monitor.isCancelled()) {
                println("Export cancelled by user.");
                return;
            }
            
            String contentType = file.getContentType();
            if (!contentType.equals("Program")) {
                continue;
            }
            
            String filePath = currentPath.isEmpty() ? file.getName() : currentPath + "/" + file.getName();
            processProgram(file, filePath);
        }
        
        // Recurse into subfolders
        for (DomainFolder subfolder : folder.getFolders()) {
            if (monitor.isCancelled()) {
                return;
            }
            processFolder(subfolder, currentPath);
        }
    }
    
    private void processProgram(DomainFile file, String projectPath) {
        Program program = null;
        
        try {
            println("");
            println("-".repeat(50));
            println("Processing: " + projectPath);
            
            // Open the program (read-only is fine for export)
            program = (Program) file.getDomainObject(this, false, false, monitor);
            
            if (program == null) {
                throw new Exception("Failed to open program");
            }
            
            // Parse version from project path: LoD/1.07/D2Client.dll
            String[] pathParts = projectPath.split("/");
            String gameType = "Unknown";
            String version = "Unknown";
            String programName = file.getName();
            
            if (pathParts.length >= 3) {
                // Path format: GameType/Version/filename
                gameType = pathParts[0];
                version = pathParts[1];
            } else if (pathParts.length == 2) {
                // Path format: Version/filename (assume LoD)
                gameType = "LoD";
                version = pathParts[0];
            }
            
            println("  Game Type: " + gameType);
            println("  Version: " + version);
            
            // Create output directory
            File outputDir = new File("F:/D2VersionChanger/data/enhanced/" + gameType + "/" + version);
            outputDir.mkdirs();
            File outputFile = new File(outputDir, programName + ".json");
            
            // Export the program
            exportProgram(program, gameType, version, outputFile);
            
            println("  Exported to: " + outputFile.getAbsolutePath());
            totalProcessed++;
            
        } catch (Exception e) {
            printerr("  ERROR: " + e.getMessage());
            failedPrograms.add(projectPath + " - " + e.getMessage());
            totalFailed++;
        } finally {
            // Always release the program to free memory
            if (program != null) {
                program.release(this);
            }
        }
    }
    
    private void exportProgram(Program program, String gameType, String version, File outputFile) throws Exception {
        FunctionManager funcManager = program.getFunctionManager();
        ReferenceManager refManager = program.getReferenceManager();
        SymbolTable symbolTable = program.getSymbolTable();
        long imageBase = program.getImageBase().getOffset();
        String programName = program.getName();
        
        // Collect function data
        List<String> functionEntries = new ArrayList<>();
        int namedFuncs = 0;
        int processedFuncs = 0;
        
        FunctionIterator funcIter = funcManager.getFunctions(true);
        while (funcIter.hasNext()) {
            if (monitor.isCancelled()) {
                throw new Exception("Cancelled by user");
            }
            
            Function func = funcIter.next();
            processedFuncs++;
            
            // Progress update
            if (processedFuncs % 500 == 0) {
                monitor.setMessage(programName + ": " + processedFuncs + " functions");
            }
            
            String entry = exportFunction(func, program, refManager, symbolTable, imageBase);
            functionEntries.add(entry);
            
            if (hasCustomName(func)) {
                namedFuncs++;
            }
        }
        
        // Write JSON
        try (PrintWriter writer = new PrintWriter(new FileWriter(outputFile))) {
            writer.println("{");
            writer.println("  \"program_name\": \"" + escapeJson(programName) + "\",");
            writer.println("  \"game_type\": \"" + escapeJson(gameType) + "\",");
            writer.println("  \"version\": \"" + escapeJson(version) + "\",");
            writer.println("  \"image_base\": \"" + String.format("0x%08X", imageBase) + "\",");
            writer.println("  \"total_functions\": " + processedFuncs + ",");
            writer.println("  \"named_functions\": " + namedFuncs + ",");
            writer.println("  \"export_version\": \"2.0\",");
            writer.println("  \"functions\": [");
            
            for (int i = 0; i < functionEntries.size(); i++) {
                writer.print(functionEntries.get(i));
                if (i < functionEntries.size() - 1) {
                    writer.println(",");
                } else {
                    writer.println();
                }
            }
            
            writer.println("  ]");
            writer.println("}");
        }
        
        println("  Functions: " + processedFuncs + " (" + namedFuncs + " named)");
    }
    
    private String exportFunction(Function func, Program program, 
                                  ReferenceManager refManager, 
                                  SymbolTable symbolTable,
                                  long imageBase) {
        StringBuilder sb = new StringBuilder();
        sb.append("    {\n");
        
        long address = func.getEntryPoint().getOffset();
        long rva = address - imageBase;
        String name = func.getName();
        boolean hasCustom = hasCustomName(func);
        
        // Basic info
        sb.append("      \"address\": \"").append(String.format("0x%X", address)).append("\",\n");
        sb.append("      \"rva\": \"").append(String.format("0x%X", rva)).append("\",\n");
        sb.append("      \"name\": \"").append(escapeJson(name)).append("\",\n");
        sb.append("      \"has_custom_name\": ").append(hasCustom).append(",\n");
        
        // Signature
        String sig = func.getSignature().getPrototypeString();
        sb.append("      \"signature\": \"").append(escapeJson(sig)).append("\",\n");
        
        // Calling convention
        String callingConv = func.getCallingConventionName();
        sb.append("      \"calling_convention\": \"").append(escapeJson(callingConv != null ? callingConv : "")).append("\",\n");
        
        // Return type
        String returnType = func.getReturnType().getName();
        sb.append("      \"return_type\": \"").append(escapeJson(returnType)).append("\",\n");
        
        // Size
        long size = func.getBody().getNumAddresses();
        sb.append("      \"size\": ").append(size).append(",\n");
        
        // Instruction count and first instructions
        List<String> instructions = new ArrayList<>();
        int instrCount = 0;
        Listing listing = program.getListing();
        InstructionIterator instrIter = listing.getInstructions(func.getBody(), true);
        while (instrIter.hasNext() && instructions.size() < 15) {
            Instruction instr = instrIter.next();
            instrCount++;
            if (instructions.size() < 15) {
                long instrRva = instr.getAddress().getOffset() - imageBase;
                String mnemonic = instr.getMnemonicString();
                String operands = formatOperands(instr);
                instructions.add(String.format("0x%X|%s|%s", instrRva, mnemonic, operands));
            }
        }
        // Count remaining instructions
        while (instrIter.hasNext()) {
            instrIter.next();
            instrCount++;
        }
        
        sb.append("      \"instruction_count\": ").append(instrCount).append(",\n");
        
        // Local variables and parameters
        int localCount = func.getLocalVariables().length;
        int paramCount = func.getParameterCount();
        sb.append("      \"local_var_count\": ").append(localCount).append(",\n");
        sb.append("      \"param_count\": ").append(paramCount).append(",\n");
        
        // Instructions array
        sb.append("      \"instructions\": [");
        for (int i = 0; i < instructions.size(); i++) {
            sb.append("\"").append(escapeJson(instructions.get(i))).append("\"");
            if (i < instructions.size() - 1) sb.append(", ");
        }
        sb.append("],\n");
        
        // Callees (functions this function calls)
        List<String> callees = new ArrayList<>();
        Set<String> seenCallees = new HashSet<>();
        for (Function callee : func.getCalledFunctions(monitor)) {
            if (callees.size() >= 50) break;
            String calleeName = callee.getName();
            if (!seenCallees.contains(calleeName)) {
                seenCallees.add(calleeName);
                long calleeAddr = callee.getEntryPoint().getOffset();
                callees.add(String.format("{\"name\":\"%s\",\"address\":\"0x%X\"}", 
                    escapeJson(calleeName), calleeAddr));
            }
        }
        sb.append("      \"callees\": [").append(String.join(",", callees)).append("],\n");
        
        // Callers (functions that call this function)
        List<String> callers = new ArrayList<>();
        Set<String> seenCallers = new HashSet<>();
        for (Function caller : func.getCallingFunctions(monitor)) {
            if (callers.size() >= 50) break;
            String callerName = caller.getName();
            if (!seenCallers.contains(callerName)) {
                seenCallers.add(callerName);
                long callerAddr = caller.getEntryPoint().getOffset();
                callers.add(String.format("{\"name\":\"%s\",\"address\":\"0x%X\"}", 
                    escapeJson(callerName), callerAddr));
            }
        }
        sb.append("      \"callers\": [").append(String.join(",", callers)).append("],\n");
        
        // String references
        List<String> strings = new ArrayList<>();
        Reference[] refs = refManager.getReferencesFrom(func.getEntryPoint());
        Set<String> seenStrings = new HashSet<>();
        
        // Get all references from the function body
        AddressSetView body = func.getBody();
        for (ghidra.program.model.address.Address addr : body.getAddresses(true)) {
            if (strings.size() >= 20) break;
            Reference[] fromRefs = refManager.getReferencesFrom(addr);
            for (Reference ref : fromRefs) {
                if (strings.size() >= 20) break;
                ghidra.program.model.address.Address toAddr = ref.getToAddress();
                Data data = listing.getDataAt(toAddr);
                if (data != null && data.hasStringValue()) {
                    String strValue = data.getDefaultValueRepresentation();
                    if (strValue != null && !seenStrings.contains(strValue) && strValue.length() > 2) {
                        seenStrings.add(strValue);
                        // Clean up the string representation
                        if (strValue.startsWith("\"") && strValue.endsWith("\"")) {
                            strValue = strValue.substring(1, strValue.length() - 1);
                        }
                        strings.add(escapeJson(strValue));
                    }
                }
            }
        }
        
        sb.append("      \"strings\": [");
        for (int i = 0; i < strings.size(); i++) {
            sb.append("\"").append(strings.get(i)).append("\"");
            if (i < strings.size() - 1) sb.append(", ");
        }
        sb.append("],\n");
        
        // Parameters
        sb.append("      \"parameters\": [");
        Parameter[] params = func.getParameters();
        for (int i = 0; i < params.length; i++) {
            Parameter p = params[i];
            sb.append(String.format("{\"name\":\"%s\",\"type\":\"%s\",\"storage\":\"%s\"}",
                escapeJson(p.getName()),
                escapeJson(p.getDataType().getName()),
                escapeJson(p.getVariableStorage().toString())));
            if (i < params.length - 1) sb.append(",");
        }
        sb.append("]\n");
        
        sb.append("    }");
        return sb.toString();
    }
    
    private boolean hasCustomName(Function func) {
        String name = func.getName();
        // FUN_ and thunk_FUN_ are auto-generated
        if (name.startsWith("FUN_") || name.startsWith("thunk_FUN_")) {
            return false;
        }
        // Check if it's in the default namespace with default naming
        Symbol symbol = func.getSymbol();
        if (symbol != null && symbol.getSource() == ghidra.program.model.symbol.SourceType.DEFAULT) {
            return false;
        }
        return true;
    }
    
    private String formatOperands(Instruction instr) {
        int numOperands = instr.getNumOperands();
        if (numOperands == 0) return "";
        
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < numOperands; i++) {
            if (i > 0) sb.append(", ");
            String rep = instr.getDefaultOperandRepresentation(i);
            sb.append(rep);
        }
        return sb.toString();
    }
    
    private String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }
}
