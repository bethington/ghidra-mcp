// [STEP 2] Batch propagate documentation from hash index for ALL binaries in project folder
// @category Documentation
// @author GhidraMCP
// @description Automatically propagates documentation (function names, signatures, plate comments, data types) to all versions of all binaries in the current project folder based on the function hash index. Skips canonical (source) versions.

import ghidra.app.script.GhidraScript;
import ghidra.framework.model.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.data.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;

import java.io.File;
import java.nio.file.Files;
import java.util.*;
import java.security.MessageDigest;
import javax.swing.JOptionPane;

public class BatchPropagateToAllVersions_ProjectFolder extends GhidraScript {

    private static final String INDEX_FILE = System.getProperty("user.home") + "/ghidra_function_hash_index_v2.json";
    
    private Map<String, Map<String, Object>> functionsIndex;
    private Map<String, Map<String, Object>> dataTypesIndex;

    @Override
    public void run() throws Exception {
        println("========================================");
        println("Batch Propagate from Index - Project Folder");
        println("========================================");
        
        // Ask user for processing scope
        String[] options = {"Current Program Only", "All Binaries in Project", "Cancel"};
        int choice = JOptionPane.showOptionDialog(
            null,
            "Choose propagation scope:",
            "Batch Propagate Documentation",
            JOptionPane.YES_NO_CANCEL_OPTION,
            JOptionPane.QUESTION_MESSAGE,
            null,
            options,
            options[1] // Default to "All Binaries"
        );
        
        if (choice == 2 || choice == JOptionPane.CLOSED_OPTION) {
            println("\nCancelled by user.");
            return;
        }
        
        boolean currentProgramOnly = (choice == 0);
        
        if (currentProgramOnly) {
            if (currentProgram == null) {
                println("\nError: No program is currently open.");
                return;
            }
            println("\nProcessing mode: Current program only (" + currentProgram.getName() + ")");
        } else {
            println("\nProcessing mode: All binaries in project");
        }
        
        // Load the index
        println("\n1. Loading function hash index V2...");
        Map<String, Object> index = loadIndex();

        // V2 index uses "functions_by_hash" instead of "functions"
        @SuppressWarnings("unchecked")
        Map<String, Map<String, Object>> funcs = (Map<String, Map<String, Object>>) index.get("functions_by_hash");
        if (funcs == null) {
            // Fallback to V1 key for backward compatibility
            funcs = (Map<String, Map<String, Object>>) index.get("functions");
        }
        functionsIndex = funcs != null ? funcs : new LinkedHashMap<>();

        @SuppressWarnings("unchecked")
        Map<String, Map<String, Object>> datatypes = (Map<String, Map<String, Object>>) index.get("data_types");
        dataTypesIndex = datatypes != null ? datatypes : new LinkedHashMap<>();

        println("  Functions indexed: " + functionsIndex.size());
        println("  Data types indexed: " + dataTypesIndex.size());
        
        if (functionsIndex.isEmpty()) {
            println("\n  Error: No functions in index. Run BuildHashIndex_V2.java first.");
            return;
        }
        
        // Get unique program names from index
        println("\n2. Identifying unique binaries from index...");
        Set<String> programNames = new HashSet<>();
        
        if (currentProgramOnly) {
            // Only process current program's name
            programNames.add(currentProgram.getName());
            println("  Processing only: " + currentProgram.getName());
        } else {
            // Get all unique program names from index
            for (Map<String, Object> hashEntry : functionsIndex.values()) {
                @SuppressWarnings("unchecked")
                Map<String, Object> canonical = (Map<String, Object>) hashEntry.get("canonical");
                if (canonical != null) {
                    String programPath = (String) canonical.get("program_path");
                    if (programPath != null) {
                        // Extract program name from path (e.g., "/LoD/1.13d/D2Client.dll" -> "D2Client.dll")
                        String programName = new File(programPath).getName();
                        programNames.add(programName);
                    }
                }
                
                @SuppressWarnings("unchecked")
                List<Map<String, Object>> instances = (List<Map<String, Object>>) hashEntry.get("instances");
                if (instances != null) {
                    for (Map<String, Object> instance : instances) {
                        String programPath = (String) instance.get("program_path");
                        if (programPath != null) {
                            String programName = new File(programPath).getName();
                            programNames.add(programName);
                        }
                    }
                }
            }
            
            println("  Found " + programNames.size() + " unique binaries:");
            for (String name : programNames) {
                println("    - " + name);
            }
        }
        
        // Get the current project and folder
        Project project = state.getProject();
        if (project == null) {
            println("\n  Error: No project is open.");
            return;
        }
        
        DomainFolder rootFolder = project.getProjectData().getRootFolder();
        
        // Process each unique binary name
        println("\n3. Processing each binary...");
        int totalBinaries = programNames.size();
        int currentBinary = 0;
        int totalProgramsProcessed = 0;
        int totalFunctionsUpdated = 0;
        int totalDataTypesCreated = 0;
        
        for (String programName : programNames) {
            currentBinary++;
            println("\n[" + currentBinary + "/" + totalBinaries + "] Processing: " + programName);
            
            // Find all matching programs
            List<DomainFile> matchingPrograms = new ArrayList<>();
            findMatchingPrograms(rootFolder, programName, matchingPrograms);
            
            println("  Found " + matchingPrograms.size() + " versions");
            
            if (matchingPrograms.isEmpty()) {
                println("  Warning: No matching programs found in project");
                continue;
            }
            
            // Collect canonical paths to skip
            Set<String> canonicalPaths = collectCanonicalPaths(programName);
            println("  Canonical sources to skip: " + canonicalPaths.size());
            
            // Process each version
            int programNum = 0;
            for (DomainFile domainFile : matchingPrograms) {
                if (monitor.isCancelled()) {
                    println("\n  Cancelled by user");
                    return;
                }
                
                programNum++;
                String programPath = domainFile.getPathname();
                
                // Skip canonical sources
                if (canonicalPaths.contains(programPath)) {
                    println("  [" + programNum + "/" + matchingPrograms.size() + "] " + programPath + " - SKIPPED (canonical source)");
                    continue;
                }
                
                // Skip currently open program (it's the source in current program only mode)
                if (currentProgram != null && currentProgram.getDomainFile().equals(domainFile)) {
                    println("  [" + programNum + "/" + matchingPrograms.size() + "] " + programPath + " - SKIPPED (currently open" + (currentProgramOnly ? " - source program" : "") + ")");
                    continue;
                }
                
                println("  [" + programNum + "/" + matchingPrograms.size() + "] " + programPath + " - PROCESSING...");
                
                try {
                    int[] stats = processProgram(domainFile);
                    int functionsUpdated = stats[0];
                    int dataTypesCreated = stats[1];
                    
                    println("    Functions updated: " + functionsUpdated + ", Data types created: " + dataTypesCreated);
                    
                    totalProgramsProcessed++;
                    totalFunctionsUpdated += functionsUpdated;
                    totalDataTypesCreated += dataTypesCreated;
                    
                } catch (Exception e) {
                    println("    ERROR: " + e.getMessage());
                }
            }
        }
        
        println("\n========================================");
        println("Batch Propagation Complete");
        println("========================================");
        println("Total binaries processed: " + currentBinary);
        println("Total programs updated: " + totalProgramsProcessed);
        println("Total functions updated: " + totalFunctionsUpdated);
        println("Total data types created: " + totalDataTypesCreated);
    }

    /**
     * Collect all canonical paths for a given program name.
     */
    private Set<String> collectCanonicalPaths(String programName) {
        Set<String> paths = new HashSet<>();
        
        for (Map<String, Object> hashEntry : functionsIndex.values()) {
            @SuppressWarnings("unchecked")
            Map<String, Object> canonical = (Map<String, Object>) hashEntry.get("canonical");
            if (canonical == null) continue;
            
            String programPath = (String) canonical.get("program_path");
            if (programPath == null) continue;
            
            String canonicalName = new File(programPath).getName();
            if (canonicalName.equals(programName)) {
                paths.add(programPath);
            }
        }
        
        return paths;
    }

    /**
     * Recursively find all programs matching the target name.
     */
    private void findMatchingPrograms(DomainFolder folder, String targetName, List<DomainFile> results) {
        // Check files in this folder
        for (DomainFile file : folder.getFiles()) {
            if (file.getName().equals(targetName)) {
                results.add(file);
            }
        }
        
        // Recurse into subfolders
        for (DomainFolder subfolder : folder.getFolders()) {
            findMatchingPrograms(subfolder, targetName, results);
        }
    }

    /**
     * Process a single program - open, propagate, save, close.
     * Returns [functionsUpdated, dataTypesCreated]
     */
    private int[] processProgram(DomainFile domainFile) throws Exception {
        int functionsUpdated = 0;
        int dataTypesCreated = 0;
        
        // Open the program
        Program program = (Program) domainFile.getDomainObject(this, true, false, monitor);
        
        try {
            String programPath = domainFile.getPathname();
            DataTypeManager dtm = program.getDataTypeManager();
            Map<String, DataType> createdDataTypes = new HashMap<>();
            
            // Start transaction
            int txId = program.startTransaction("Batch Propagate from Index");
            
            try {
                FunctionManager funcMgr = program.getFunctionManager();
                FunctionIterator funcIter = funcMgr.getFunctions(true);
                
                while (funcIter.hasNext() && !monitor.isCancelled()) {
                    Function func = funcIter.next();
                    
                    // Skip thunks only (process external/exported functions)
                    if (func.isThunk()) {
                        continue;
                    }
                    
                    // Compute hash
                    String hash = computeFunctionHash(func, program);
                    if (hash == null) continue;
                    
                    // Look up in index
                    Map<String, Object> hashEntry = functionsIndex.get(hash);
                    if (hashEntry == null) continue;
                    
                    @SuppressWarnings("unchecked")
                    Map<String, Object> canonical = (Map<String, Object>) hashEntry.get("canonical");
                    if (canonical == null) continue;
                    
                    // Find the best documented entry (canonical may be from old index without plate_comment/signature)
                    canonical = findBestDocumentedEntry(hashEntry, canonical);
                    
                    // Skip if canonical is this same program
                    String canonicalPath = (String) canonical.get("program_path");
                    if (programPath.equals(canonicalPath)) continue;
                    
                    // Skip if canonical is undocumented
                    // V2 uses "is_documented", V1 uses "has_custom_name"
                    Boolean isDocumented = (Boolean) canonical.get("is_documented");
                    if (isDocumented == null) {
                        isDocumented = (Boolean) canonical.get("has_custom_name");
                    }
                    if (isDocumented == null || !isDocumented) continue;
                    
                    // Apply documentation
                    if (applyDocumentation(func, canonical, dtm, createdDataTypes)) {
                        functionsUpdated++;
                    }
                }
                
                dataTypesCreated = createdDataTypes.size();
                
                // Commit transaction
                program.endTransaction(txId, true);
                
            } catch (Exception e) {
                program.endTransaction(txId, false);
                throw e;
            }
            
            // Save the program
            domainFile.save(monitor);
            
        } finally {
            // Release/close the program
            program.release(this);
        }
        
        return new int[] { functionsUpdated, dataTypesCreated };
    }

    /**
     * Apply documentation to a function.
     */
    private boolean applyDocumentation(Function target, Map<String, Object> canonical,
                                        DataTypeManager dtm, Map<String, DataType> createdDataTypes) {
        boolean changed = false;
        Program program = target.getProgram();
        
        try {
            // 1. Rename function
            String name = (String) canonical.get("name");
            if (name != null && !name.startsWith("FUN_")) {
                target.setName(name, SourceType.USER_DEFINED);
                changed = true;
            }
            
            // 2. Apply plate comment
            String plateComment = (String) canonical.get("plate_comment");
            if (plateComment != null && !plateComment.isEmpty()) {
                target.setComment(plateComment);
                changed = true;
            }
            
            // 3. Apply repeatable comment
            String repeatableComment = (String) canonical.get("repeatable_comment");
            if (repeatableComment != null && !repeatableComment.isEmpty()) {
                Listing listing = program.getListing();
                CodeUnit cu = listing.getCodeUnitAt(target.getEntryPoint());
                if (cu != null) {
                    @SuppressWarnings("removal")
                    int commentType = CodeUnit.REPEATABLE_COMMENT;
                    cu.setComment(commentType, repeatableComment);
                    changed = true;
                }
            }
            
            // 4. Apply function tags
            @SuppressWarnings("unchecked")
            List<String> tags = (List<String>) canonical.get("tags");
            if (tags != null && !tags.isEmpty()) {
                FunctionManager funcMgr = program.getFunctionManager();
                for (String tagName : tags) {
                    FunctionTag tag = funcMgr.getFunctionTagManager().getFunctionTag(tagName);
                    if (tag == null) {
                        tag = funcMgr.getFunctionTagManager().createFunctionTag(tagName, "");
                    }
                    if (tag != null) {
                        target.addTag(tagName);
                    }
                }
                changed = true;
            }
            
            // 5. Apply signature
            @SuppressWarnings("unchecked")
            Map<String, Object> signature = (Map<String, Object>) canonical.get("signature");
            if (signature != null) {
                if (applySignature(target, signature, dtm, createdDataTypes)) {
                    changed = true;
                }
            }
            
            // 6. Apply inline/EOL comments throughout function body
            @SuppressWarnings("unchecked")
            Map<String, Object> inlineComments = (Map<String, Object>) canonical.get("inline_comments");
            if (inlineComments != null && !inlineComments.isEmpty()) {
                if (applyInlineComments(target, inlineComments, program)) {
                    changed = true;
                }
            }
            
            // 7. Apply global variable references
            @SuppressWarnings("unchecked")
            List<Map<String, Object>> globalRefs = (List<Map<String, Object>>) canonical.get("global_references");
            if (globalRefs != null && !globalRefs.isEmpty()) {
                if (applyGlobalReferences(target, globalRefs, program)) {
                    changed = true;
                }
            }
            
            // 8. Apply callee function names (rename called functions)
            @SuppressWarnings("unchecked")
            List<Map<String, Object>> callees = (List<Map<String, Object>>) canonical.get("callees");
            if (callees != null && !callees.isEmpty()) {
                if (applyCalleeFunctionNames(target, callees, program)) {
                    changed = true;
                }
            }
            
        } catch (Exception e) {
            // Continue with other functions
        }
        
        return changed;
    }

    /**
     * Find the best documented entry from hashEntry (canonical or instances).
     * Some old index entries may have canonical without plate_comment/signature.
     */
    private Map<String, Object> findBestDocumentedEntry(Map<String, Object> hashEntry, Map<String, Object> canonical) {
        boolean canonicalHasPlate = canonical.containsKey("plate_comment") && canonical.get("plate_comment") != null;
        boolean canonicalHasSignature = canonical.containsKey("signature") && canonical.get("signature") != null;
        
        // If canonical is complete, use it
        if (canonicalHasPlate && canonicalHasSignature) {
            return canonical;
        }
        
        // Search instances for a better documented entry
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> instances = (List<Map<String, Object>>) hashEntry.get("instances");
        if (instances == null) {
            return canonical;
        }
        
        Map<String, Object> best = canonical;
        int bestScore = (canonicalHasPlate ? 1 : 0) + (canonicalHasSignature ? 1 : 0);
        
        for (Map<String, Object> inst : instances) {
            boolean hasPlate = inst.containsKey("plate_comment") && inst.get("plate_comment") != null;
            boolean hasSignature = inst.containsKey("signature") && inst.get("signature") != null;
            int score = (hasPlate ? 1 : 0) + (hasSignature ? 1 : 0);
            
            if (score > bestScore) {
                best = inst;
                bestScore = score;
            }
        }
        
        return best;
    }

    /**
     * Apply function signature.
     */
    private boolean applySignature(Function target, Map<String, Object> signature,
                                    DataTypeManager dtm, Map<String, DataType> createdDataTypes) {
        boolean changed = false;
        
        try {
            // Calling convention
            String callingConv = (String) signature.get("calling_convention");
            if (callingConv != null && !callingConv.equals("unknown")) {
                try {
                    target.setCallingConvention(callingConv);
                    changed = true;
                } catch (Exception e) { }
            }
            
            // Return type
            @SuppressWarnings("unchecked")
            Map<String, Object> returnTypeInfo = (Map<String, Object>) signature.get("return_type");
            if (returnTypeInfo != null) {
                DataType returnType = resolveOrCreateDataType(returnTypeInfo, dtm, createdDataTypes);
                if (returnType != null) {
                    target.setReturnType(returnType, SourceType.USER_DEFINED);
                    changed = true;
                }
            }
            
            // Parameters
            @SuppressWarnings("unchecked")
            List<Map<String, Object>> params = (List<Map<String, Object>>) signature.get("parameters");
            if (params != null) {
                Parameter[] existingParams = target.getParameters();
                for (Map<String, Object> paramInfo : params) {
                    int ordinal = ((Number) paramInfo.get("ordinal")).intValue();
                    String paramName = (String) paramInfo.get("name");
                    
                    if (ordinal < existingParams.length) {
                        Parameter p = existingParams[ordinal];
                        
                        if (paramName != null && !paramName.startsWith("param_")) {
                            p.setName(paramName, SourceType.USER_DEFINED);
                            changed = true;
                        }
                        
                        @SuppressWarnings("unchecked")
                        Map<String, Object> typeInfo = (Map<String, Object>) paramInfo.get("type");
                        if (typeInfo != null) {
                            DataType paramType = resolveOrCreateDataType(typeInfo, dtm, createdDataTypes);
                            if (paramType != null) {
                                p.setDataType(paramType, SourceType.USER_DEFINED);
                                changed = true;
                            }
                        }
                    }
                }
            }
            
            // Local variables
            @SuppressWarnings("unchecked")
            List<Map<String, Object>> locals = (List<Map<String, Object>>) signature.get("local_variables");
            if (locals != null && !locals.isEmpty()) {
                for (Map<String, Object> localInfo : locals) {
                    String localName = (String) localInfo.get("name");
                    String storage = (String) localInfo.get("storage");
                    
                    if (localName == null || storage == null) continue;
                    
                    try {
                        // Find existing local variable by storage location
                        Variable[] existingLocals = target.getLocalVariables();
                        Variable matchedVar = null;
                        
                        for (Variable v : existingLocals) {
                            if (v.getVariableStorage().toString().equals(storage)) {
                                matchedVar = v;
                                break;
                            }
                        }
                        
                        if (matchedVar != null) {
                            // Update name
                            matchedVar.setName(localName, SourceType.USER_DEFINED);
                            
                            // Update type
                            @SuppressWarnings("unchecked")
                            Map<String, Object> typeInfo = (Map<String, Object>) localInfo.get("type");
                            if (typeInfo != null) {
                                DataType localType = resolveOrCreateDataType(typeInfo, dtm, createdDataTypes);
                                if (localType != null) {
                                    matchedVar.setDataType(localType, SourceType.USER_DEFINED);
                                }
                            }
                            
                            // Update comment
                            String comment = (String) localInfo.get("comment");
                            if (comment != null && !comment.isEmpty()) {
                                matchedVar.setComment(comment);
                            }
                            
                            changed = true;
                        }
                    } catch (Exception e) {
                        // Continue with other locals
                    }
                }
            }
            
        } catch (Exception e) { }
        
        return changed;
    }

    /**
     * Apply inline/EOL comments throughout the function body.
     */
    private boolean applyInlineComments(Function target, Map<String, Object> comments, Program program) {
        boolean changed = false;
        
        try {
            Listing listing = program.getListing();
            Address entryPoint = target.getEntryPoint();
            AddressSetView body = target.getBody();
            
            // Iterate through comment entries
            for (Map.Entry<String, Object> entry : comments.entrySet()) {
                String offsetStr = entry.getKey();
                @SuppressWarnings("unchecked")
                Map<String, String> commentTypes = (Map<String, String>) entry.getValue();
                
                // Parse offset (e.g., "0x10" -> 16)
                long offset = Long.parseLong(offsetStr.substring(2), 16);
                Address addr = entryPoint.add(offset);
                
                // Skip if address is outside function body
                if (!body.contains(addr)) continue;
                
                CodeUnit cu = listing.getCodeUnitAt(addr);
                if (cu != null) {
                    // Apply EOL comment
                    String eolComment = commentTypes.get("eol");
                    if (eolComment != null) {
                        @SuppressWarnings("removal")
                        int eolType = CodeUnit.EOL_COMMENT;
                        cu.setComment(eolType, eolComment);
                        changed = true;
                    }
                    
                    // Apply Pre comment
                    String preComment = commentTypes.get("pre");
                    if (preComment != null) {
                        @SuppressWarnings("removal")
                        int preType = CodeUnit.PRE_COMMENT;
                        cu.setComment(preType, preComment);
                        changed = true;
                    }
                    
                    // Apply Post comment
                    String postComment = commentTypes.get("post");
                    if (postComment != null) {
                        @SuppressWarnings("removal")
                        int postType = CodeUnit.POST_COMMENT;
                        cu.setComment(postType, postComment);
                        changed = true;
                    }
                }
            }
        } catch (Exception e) {
            // Continue
        }
        
        return changed;
    }

    /**
     * Apply global variable names from references using instruction offset matching.
     */
    private boolean applyGlobalReferences(Function target, List<Map<String, Object>> globalRefs, Program program) {
        boolean changed = false;
        
        try {
            SymbolTable symbolTable = program.getSymbolTable();
            Listing listing = program.getListing();
            Address entryPoint = target.getEntryPoint();
            AddressSetView body = target.getBody();
            
            for (Map<String, Object> globalRef : globalRefs) {
                Number offsetNum = (Number) globalRef.get("offset");
                Number operandNum = (Number) globalRef.get("operand");
                String name = (String) globalRef.get("name");
                
                if (offsetNum == null || operandNum == null || name == null) continue;
                
                try {
                    long offset = offsetNum.longValue();
                    int operandIdx = operandNum.intValue();
                    
                    // Calculate instruction address at this offset
                    Address instrAddr = entryPoint.add(offset);
                    if (!body.contains(instrAddr)) continue;
                    
                    // Get instruction at this offset
                    Instruction instr = listing.getInstructionAt(instrAddr);
                    if (instr == null) continue;
                    
                    // Get the memory reference from the specified operand
                    if (operandIdx >= instr.getNumOperands()) continue;
                    
                    Object[] opObjects = instr.getOpObjects(operandIdx);
                    for (Object obj : opObjects) {
                        if (obj instanceof Address) {
                            Address refAddr = (Address) obj;
                            
                            // Skip if it's within the function
                            if (body.contains(refAddr)) continue;
                            
                            // Check current symbol name
                            Symbol primarySymbol = symbolTable.getPrimarySymbol(refAddr);
                            if (primarySymbol != null && primarySymbol.getName().equals(name)) {
                                continue; // Already correct
                            }
                            
                            // Create or rename symbol
                            if (primarySymbol == null || primarySymbol.isDynamic()) {
                                // Create new symbol
                                symbolTable.createLabel(refAddr, name, SourceType.USER_DEFINED);
                                changed = true;
                            } else if (!primarySymbol.isExternal()) {
                                // Rename existing non-external symbol
                                primarySymbol.setName(name, SourceType.USER_DEFINED);
                                changed = true;
                            }
                            
                            break; // Only process first address in operand
                        }
                    }
                    
                } catch (Exception e) {
                    // Continue with other globals
                }
            }
        } catch (Exception e) {
            // Continue
        }
        
        return changed;
    }

    /**
     * Apply callee function names (rename functions that are called by the target function).
     */
    private boolean applyCalleeFunctionNames(Function target, List<Map<String, Object>> callees, Program program) {
        boolean changed = false;
        
        try {
            FunctionManager funcMgr = program.getFunctionManager();
            Listing listing = program.getListing();
            Address entryPoint = target.getEntryPoint();
            AddressSetView body = target.getBody();
            
            for (Map<String, Object> calleeInfo : callees) {
                Number offsetNum = (Number) calleeInfo.get("offset");
                String calleeName = (String) calleeInfo.get("name");
                String calleeAddr = (String) calleeInfo.get("address");
                
                if (offsetNum == null || calleeName == null) continue;
                
                // Skip truly generic names (FUN_, thunk_), but allow Ordinal_ names
                // since they're better than FUN_ and may be the best documentation available
                if (calleeName.startsWith("FUN_") || 
                    calleeName.startsWith("thunk_") ||
                    calleeName.equals("entry")) {
                    continue;
                }
                
                try {
                    long offset = offsetNum.longValue();
                    
                    // Calculate instruction address at this offset
                    Address instrAddr = entryPoint.add(offset);
                    if (!body.contains(instrAddr)) continue;
                    
                    // Get instruction at this offset
                    Instruction instr = listing.getInstructionAt(instrAddr);
                    if (instr == null) continue;
                    
                    // Check if this is a call instruction
                    if (!instr.getMnemonicString().toUpperCase().startsWith("CALL")) {
                        continue;
                    }
                    
                    // Get the call target address
                    Address[] flows = instr.getFlows();
                    if (flows == null || flows.length == 0) continue;
                    
                    for (Address targetAddr : flows) {
                        Function calledFunc = funcMgr.getFunctionAt(targetAddr);
                        if (calledFunc == null) continue;
                        
                        // Skip thunks
                        if (calledFunc.isThunk()) continue;
                        
                        // Check if function needs renaming
                        String currentName = calledFunc.getName();
                        if (currentName.equals(calleeName)) {
                            continue; // Already has correct name
                        }
                        
                        // Only rename if current name is generic (FUN_, thunk_, Ordinal_)
                        // Ordinal_ names will be replaced by better Ordinal_ names or real names
                        if (currentName.startsWith("FUN_") || 
                            currentName.startsWith("thunk_") ||
                            currentName.startsWith("Ordinal_")) {
                            
                            try {
                                calledFunc.setName(calleeName, SourceType.USER_DEFINED);
                                changed = true;
                            } catch (Exception e) {
                                // Name conflict or other error - continue
                            }
                        }
                        
                        break; // Only process first matching call target
                    }
                    
                } catch (Exception e) {
                    // Continue with other callees
                }
            }
        } catch (Exception e) {
            // Continue
        }
        
        return changed;
    }

    /**
     * Resolve or create a data type.
     */
    private DataType resolveOrCreateDataType(Map<String, Object> typeInfo,
                                              DataTypeManager dtm, Map<String, DataType> cache) {
        if (typeInfo == null) return null;
        
        String name = (String) typeInfo.get("name");
        String path = (String) typeInfo.get("path");
        String kind = (String) typeInfo.get("kind");
        
        if (name == null || "undefined".equals(name)) return null;
        
        // Check cache
        if (path != null && cache.containsKey(path)) {
            return cache.get(path);
        }
        
        // Try to find existing
        if (path != null) {
            DataType existing = dtm.getDataType(path);
            if (existing != null) {
                cache.put(path, existing);
                return existing;
            }
        }
        
        // Search by name
        Iterator<DataType> iter = dtm.getAllDataTypes();
        while (iter.hasNext()) {
            DataType dt = iter.next();
            if (dt.getName().equals(name)) {
                if (path != null) cache.put(path, dt);
                return dt;
            }
        }
        
        // Handle pointer
        if ("pointer".equals(kind)) {
            @SuppressWarnings("unchecked")
            Map<String, Object> pointedTo = (Map<String, Object>) typeInfo.get("pointed_to");
            DataType baseType = resolveOrCreateDataType(pointedTo, dtm, cache);
            if (baseType != null) {
                DataType ptr = dtm.getPointer(baseType);
                if (path != null) cache.put(path, ptr);
                return ptr;
            }
        }
        
        // Handle array
        if ("array".equals(kind)) {
            @SuppressWarnings("unchecked")
            Map<String, Object> elemType = (Map<String, Object>) typeInfo.get("element_type");
            int count = ((Number) typeInfo.getOrDefault("element_count", 1)).intValue();
            DataType baseType = resolveOrCreateDataType(elemType, dtm, cache);
            if (baseType != null) {
                ArrayDataType arr = new ArrayDataType(baseType, count, baseType.getLength());
                if (path != null) cache.put(path, arr);
                return arr;
            }
        }
        
        // Handle struct/union/enum from index
        if (("struct".equals(kind) || "union".equals(kind) || "enum".equals(kind)) && path != null) {
            if (dataTypesIndex.containsKey(path)) {
                DataType created = createDataTypeFromIndex(path, dtm, cache);
                if (created != null) {
                    cache.put(path, created);
                    return created;
                }
            }
        }
        
        // Try primitive
        return findPrimitiveType(name);
    }

    /**
     * Create a data type from the index.
     */
    private DataType createDataTypeFromIndex(String path, DataTypeManager dtm, Map<String, DataType> cache) {
        Map<String, Object> dtDef = dataTypesIndex.get(path);
        if (dtDef == null) return null;
        
        String kind = (String) dtDef.get("kind");
        String name = (String) dtDef.get("name");
        String category = (String) dtDef.get("category");
        
        if (name == null) return null;
        
        try {
            CategoryPath catPath = new CategoryPath(category != null ? category : "/");
            
            if ("struct".equals(kind)) {
                int size = ((Number) dtDef.getOrDefault("size", 0)).intValue();
                StructureDataType struct = new StructureDataType(catPath, name, size, dtm);
                
                @SuppressWarnings("unchecked")
                List<Map<String, Object>> fields = (List<Map<String, Object>>) dtDef.get("fields");
                if (fields != null) {
                    for (Map<String, Object> field : fields) {
                        int offset = ((Number) field.get("offset")).intValue();
                        String fieldName = (String) field.get("name");
                        int fieldSize = ((Number) field.getOrDefault("size", 4)).intValue();
                        String comment = (String) field.get("comment");
                        
                        @SuppressWarnings("unchecked")
                        Map<String, Object> fieldTypeInfo = (Map<String, Object>) field.get("type");
                        DataType fieldType = resolveOrCreateDataType(fieldTypeInfo, dtm, cache);
                        if (fieldType == null) fieldType = Undefined.getUndefinedDataType(fieldSize);
                        
                        try {
                            if (offset < struct.getLength()) {
                                struct.replaceAtOffset(offset, fieldType, fieldSize, fieldName, comment);
                            }
                        } catch (Exception e) { }
                    }
                }
                
                return dtm.addDataType(struct, DataTypeConflictHandler.REPLACE_HANDLER);
                
            } else if ("enum".equals(kind)) {
                int size = ((Number) dtDef.getOrDefault("size", 4)).intValue();
                EnumDataType enumDt = new EnumDataType(catPath, name, size, dtm);
                
                @SuppressWarnings("unchecked")
                Map<String, Object> values = (Map<String, Object>) dtDef.get("values");
                if (values != null) {
                    for (Map.Entry<String, Object> entry : values.entrySet()) {
                        enumDt.add(entry.getKey(), ((Number) entry.getValue()).longValue());
                    }
                }
                
                return dtm.addDataType(enumDt, DataTypeConflictHandler.REPLACE_HANDLER);
                
            } else if ("union".equals(kind)) {
                UnionDataType union = new UnionDataType(catPath, name, dtm);
                
                String desc = (String) dtDef.get("description");
                if (desc != null && !desc.isEmpty()) {
                    union.setDescription(desc);
                }
                
                @SuppressWarnings("unchecked")
                List<Map<String, Object>> fields = (List<Map<String, Object>>) dtDef.get("fields");
                if (fields != null) {
                    for (Map<String, Object> field : fields) {
                        String fieldName = (String) field.get("name");
                        int fieldSize = ((Number) field.getOrDefault("size", 4)).intValue();
                        String comment = (String) field.get("comment");
                        
                        @SuppressWarnings("unchecked")
                        Map<String, Object> fieldTypeInfo = (Map<String, Object>) field.get("type");
                        DataType fieldType = resolveOrCreateDataType(fieldTypeInfo, dtm, cache);
                        if (fieldType == null) fieldType = Undefined.getUndefinedDataType(fieldSize);
                        
                        union.add(fieldType, fieldName, comment);
                    }
                }
                
                return dtm.addDataType(union, DataTypeConflictHandler.REPLACE_HANDLER);
            }
            
        } catch (Exception e) { }
        
        return null;
    }

    /**
     * Find a primitive type by name.
     */
    private DataType findPrimitiveType(String name) {
        switch (name) {
            case "int": return IntegerDataType.dataType;
            case "uint": return UnsignedIntegerDataType.dataType;
            case "char": return CharDataType.dataType;
            case "short": return ShortDataType.dataType;
            case "long": return LongDataType.dataType;
            case "float": return FloatDataType.dataType;
            case "double": return DoubleDataType.dataType;
            case "void": return VoidDataType.dataType;
            case "bool": return BooleanDataType.dataType;
            case "byte": return ByteDataType.dataType;
            case "word": return WordDataType.dataType;
            case "dword": return DWordDataType.dataType;
            case "qword": return QWordDataType.dataType;
            case "undefined": return Undefined.getUndefinedDataType(1);
            case "undefined1": return Undefined1DataType.dataType;
            case "undefined2": return Undefined2DataType.dataType;
            case "undefined4": return Undefined4DataType.dataType;
        }
        return null;
    }

    /**
     * Compute normalized function hash.
     */
    private String computeFunctionHash(Function func, Program program) {
        try {
            StringBuilder normalized = new StringBuilder();
            Listing listing = program.getListing();
            AddressSetView body = func.getBody();
            
            InstructionIterator instructions = listing.getInstructions(body, true);
            while (instructions.hasNext()) {
                Instruction instr = instructions.next();
                
                normalized.append(instr.getMnemonicString());
                normalized.append(" ");
                
                int numOperands = instr.getNumOperands();
                for (int i = 0; i < numOperands; i++) {
                    Object[] opObjects = instr.getOpObjects(i);
                    for (Object obj : opObjects) {
                        if (obj instanceof Address) {
                            Address addr = (Address) obj;
                            if (body.contains(addr)) {
                                long offset = addr.subtract(func.getEntryPoint());
                                normalized.append("REL:").append(offset);
                            } else if (program.getFunctionManager().getFunctionAt(addr) != null) {
                                normalized.append("CALL_EXT");
                            } else {
                                normalized.append("DATA_EXT");
                            }
                        } else if (obj instanceof ghidra.program.model.scalar.Scalar) {
                            long value = ((ghidra.program.model.scalar.Scalar) obj).getValue();
                            if (Math.abs(value) < 0x10000) {
                                normalized.append("IMM:").append(value);
                            } else {
                                normalized.append("IMM_LARGE");
                            }
                        } else if (obj instanceof Register) {
                            normalized.append("REG:").append(((Register) obj).getName());
                        }
                    }
                    normalized.append(",");
                }
                normalized.append(";");
            }
            
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(normalized.toString().getBytes());
            
            StringBuilder hexString = new StringBuilder();
            for (byte b : hashBytes) {
                hexString.append(String.format("%02x", b));
            }
            return hexString.toString();
            
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Load index from file.
     */
    private Map<String, Object> loadIndex() {
        File file = new File(INDEX_FILE);
        if (!file.exists()) return new LinkedHashMap<>();
        
        try {
            String content = new String(Files.readAllBytes(file.toPath()));
            return parseJson(content);
        } catch (Exception e) {
            println("  Warning: Could not load index: " + e.getMessage());
            return new LinkedHashMap<>();
        }
    }

    /**
     * Parse JSON using Gson.
     */
    private Map<String, Object> parseJson(String json) {
        try {
            Class<?> gsonClass = Class.forName("com.google.gson.Gson");
            Object gson = gsonClass.getConstructor().newInstance();
            java.lang.reflect.Method fromJson = gsonClass.getMethod("fromJson", String.class, Class.class);
            @SuppressWarnings("unchecked")
            Map<String, Object> result = (Map<String, Object>) fromJson.invoke(gson, json, Map.class);
            return result != null ? result : new LinkedHashMap<>();
        } catch (Exception e) {
            return new LinkedHashMap<>();
        }
    }
}
