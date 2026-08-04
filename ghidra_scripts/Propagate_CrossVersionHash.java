// Cross Version Hash
//
// Computes opcode hashes for FUN_* functions in a target program and matches them against documented functions in a source program. Renames matched functions automatically.
//
// Usage: Args: [0]='source_path|target_path' (e.g., /Vanilla/1.13d/D2Game.dll|/Vanilla/1.13c/D2Game.dll).
// Output: Renames matched FUN_* functions in the target program.
//
// @author Ben Ethington
// @category Diablo 2.Propagation
// @description Propagate names via cross-version hash matching
// @menupath Diablo 2.Propagation.Cross Version Hash

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.framework.model.*;
import java.security.MessageDigest;
import java.util.*;

public class Propagate_CrossVersionHash extends GhidraScript {

    private String computeOpcodeHash(Program prog, Function func) throws Exception {
        var body = func.getBody();
        var instrIter = prog.getListing().getInstructions(body, true);
        var sb = new StringBuilder();
        int count = 0;
        while (instrIter.hasNext()) {
            var instr = instrIter.next();
            sb.append(instr.getMnemonicString());
            sb.append(instr.getNumOperands());
            count++;
        }
        if (count < 2) return null;
        
        var md = MessageDigest.getInstance("SHA-256");
        md.update(sb.toString().getBytes("UTF-8"));
        byte[] digest = md.digest();
        var hex = new StringBuilder();
        for (byte b : digest) {
            hex.append(String.format("%02x", b));
        }
        return hex.toString();
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1 || !args[0].contains("|")) {
            println("ERROR: Need args: source_path|target_path");
            return;
        }
        
        String[] paths = args[0].split("\\|");
        String sourcePath = paths[0];
        String targetPath = paths[1];
        
        println("Source: " + sourcePath);
        println("Target: " + targetPath);
        
        // Get project and find programs
        var project = state.getProject();
        if (project == null) {
            // FrontEnd mode - use currentProgram's domain file to navigate
            println("Running in FrontEnd mode, using DomainFile API");
        }
        
        var projectData = state.getProject().getProjectData();
        var rootFolder = projectData.getRootFolder();
        
        // Find source and target domain files
        DomainFile sourceFile = null;
        DomainFile targetFile = null;
        
        // Parse folder path and filename
        String srcFolder = sourcePath.substring(0, sourcePath.lastIndexOf('/'));
        String srcName = sourcePath.substring(sourcePath.lastIndexOf('/') + 1);
        String tgtFolder = targetPath.substring(0, targetPath.lastIndexOf('/'));
        String tgtName = targetPath.substring(targetPath.lastIndexOf('/') + 1);
        
        var srcFolderObj = projectData.getFolder(srcFolder);
        var tgtFolderObj = projectData.getFolder(tgtFolder);
        
        if (srcFolderObj == null) { println("ERROR: Source folder not found: " + srcFolder); return; }
        if (tgtFolderObj == null) { println("ERROR: Target folder not found: " + tgtFolder); return; }
        
        sourceFile = srcFolderObj.getFile(srcName);
        targetFile = tgtFolderObj.getFile(tgtName);
        
        if (sourceFile == null) { println("ERROR: Source file not found: " + sourcePath); return; }
        if (targetFile == null) { println("ERROR: Target file not found: " + targetPath); return; }
        
        println("Found source: " + sourceFile.getPathname());
        println("Found target: " + targetFile.getPathname());
        
        // Open programs
        Program sourceProg = (Program) sourceFile.getDomainObject(this, true, false, monitor);
        Program targetProg = (Program) targetFile.getDomainObject(this, true, false, monitor);
        
        try {
            // Step 1: Build hash->name map from documented source functions
            println("Building source hash index...");
            var sourceMap = new HashMap<String, String>(); // hash -> name
            var sourceFM = sourceProg.getFunctionManager();
            var sourceIter = sourceFM.getFunctions(true);
            int srcTotal = 0;
            int srcHashed = 0;
            
            while (sourceIter.hasNext()) {
                if (monitor.isCancelled()) return;
                var func = sourceIter.next();
                if (func.getName().startsWith("FUN_")) continue; // Skip undocumented
                srcTotal++;
                
                String hash = computeOpcodeHash(sourceProg, func);
                if (hash != null) {
                    sourceMap.put(hash, func.getName());
                    srcHashed++;
                }
            }
            println("Source: " + srcTotal + " documented, " + srcHashed + " hashed, " + sourceMap.size() + " unique");
            
            // Step 2: Hash undocumented target functions and match
            println("Matching target FUN_* functions...");
            var targetFM = targetProg.getFunctionManager();
            var targetIter = targetFM.getFunctions(true);
            int tgtUndoc = 0;
            int tgtHashed = 0;
            int matched = 0;
            int renamed = 0;
            
            int txId = targetProg.startTransaction("CrossVersionHashPropagate");
            try {
                while (targetIter.hasNext()) {
                    if (monitor.isCancelled()) break;
                    var func = targetIter.next();
                    if (!func.getName().startsWith("FUN_")) continue;
                    tgtUndoc++;
                    
                    String hash = computeOpcodeHash(targetProg, func);
                    if (hash == null) continue;
                    tgtHashed++;
                    
                    String sourceName = sourceMap.get(hash);
                    if (sourceName != null) {
                        matched++;
                        try {
                            func.setName(sourceName, SourceType.IMPORTED);
                            renamed++;
                        } catch (Exception e) {
                            // Name conflict - try with suffix
                            try {
                                func.setName(sourceName + "_v13c", SourceType.IMPORTED);
                                renamed++;
                            } catch (Exception e2) {
                                // Skip
                            }
                        }
                    }
                }
                targetProg.endTransaction(txId, true);
            } catch (Exception e) {
                targetProg.endTransaction(txId, false);
                throw e;
            }
            
            // Save
            targetProg.save("CrossVersionHashPropagate from " + sourcePath, monitor);
            
            println("=== RESULTS ===");
            println("Target undocumented: " + tgtUndoc);
            println("Target hashable: " + tgtHashed);
            println("Hash matches: " + matched);
            println("Renamed: " + renamed);
            println("Remaining FUN_*: " + (tgtUndoc - renamed));
            
        } finally {
            sourceProg.release(this);
            targetProg.release(this);
        }
    }
}
