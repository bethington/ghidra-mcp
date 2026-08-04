// Resolve Ordinal Imports All
//
// Batch version that processes all binaries in the current folder or entire project. For each program, resolves ordinal imports using sibling DLLs, copies signatures, and renames thunks.
//
// Usage: Run from Script Manager. Prompts for scope: folder or entire project.
// Output: Resolves ordinal imports across all processed binaries.
//
// @author Ben Ethington
// @category Diablo 2.Propagation
// @description Resolve ordinal imports for all binaries in project
// @menupath Diablo 2.Propagation.Resolve Ordinal Imports All

import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.data.*;
import ghidra.framework.model.*;
import ghidra.util.task.TaskMonitor;
import java.util.*;

/**
 * Batch version of ResolveOrdinalImports that processes ALL binaries
 * in the current project folder or the entire project.
 * 
 * This script:
 * 1. Prompts the user to select scope: Current Folder or Entire Project
 * 2. Iterates through all programs in the selected scope
 * 3. For each program, resolves ordinal imports using sibling DLLs
 * 4. Copies function signatures and updates addresses
 * 5. Cleans up comments and renames thunks
 * 
 * When processing the entire project, each folder is treated as a separate
 * version/build, so imports are resolved using DLLs from the same folder.
 */
public class Propagate_ResolveOrdinalImportsAll extends GhidraScript {

    // Processing scope options
    private static final String SCOPE_CURRENT_FOLDER = "Current Folder Only";
    private static final String SCOPE_ENTIRE_PROJECT = "Entire Project (All Folders)";
    
    // Track statistics
    private int totalProgramsProcessed = 0;
    private int totalImportsResolved = 0;
    private int totalThunksRenamed = 0;
    private int totalSkipped = 0;
    private int totalFoldersProcessed = 0;

    @Override
    public void run() throws Exception {
        // Get the current program's location in the project
        DomainFile currentFile = currentProgram.getDomainFile();
        DomainFolder currentFolder = currentFile.getParent();
        
        // Prompt user for processing scope
        String[] scopeOptions = { SCOPE_CURRENT_FOLDER, SCOPE_ENTIRE_PROJECT };
        String selectedScope = askChoice("Processing Scope", 
            "Select which binaries to process:", 
            Arrays.asList(scopeOptions), 
            SCOPE_CURRENT_FOLDER);
        
        if (selectedScope == null) {
            println("Operation cancelled by user.");
            return;
        }
        
        boolean processEntireProject = selectedScope.equals(SCOPE_ENTIRE_PROJECT);
        
        println("=".repeat(60));
        println("BATCH ORDINAL IMPORT RESOLUTION");
        println("=".repeat(60));
        println("Mode: " + selectedScope);
        
        if (processEntireProject) {
            // Get the project root folder
            DomainFolder rootFolder = getProjectRoot(currentFolder);
            println("Project root: " + rootFolder.getPathname());
            println("");
            
            // Process all folders recursively
            processAllFolders(rootFolder);
        } else {
            println("Current folder: " + currentFolder.getPathname());
            
            // Get all files in the project folder
            DomainFile[] allFiles = currentFolder.getFiles();
            println("Found " + allFiles.length + " files in folder");
            println("");
            
            // Process each program file in current folder
            for (DomainFile file : allFiles) {
                if (monitor.isCancelled()) {
                    println("\n*** CANCELLED BY USER ***");
                    break;
                }
                
                // Skip non-program files
                if (!file.getContentType().equals("Program")) {
                    continue;
                }
                
                processProgram(file, currentFolder);
            }
            totalFoldersProcessed = 1;
        }
        
        // Print final summary
        println("\n" + "=".repeat(60));
        println("BATCH PROCESSING COMPLETE");
        println("=".repeat(60));
        println("Folders processed:  " + totalFoldersProcessed);
        println("Programs processed: " + totalProgramsProcessed);
        println("Imports resolved:   " + totalImportsResolved);
        println("Thunks renamed:     " + totalThunksRenamed);
        println("Skipped:            " + totalSkipped);
        println("=".repeat(60));
    }
    
    /**
     * Get the project root folder.
     */
    private DomainFolder getProjectRoot(DomainFolder folder) {
        DomainFolder parent = folder.getParent();
        if (parent == null) {
            return folder;
        }
        return getProjectRoot(parent);
    }
    
    /**
     * Recursively process all folders in the project.
     */
    private void processAllFolders(DomainFolder folder) throws Exception {
        if (monitor.isCancelled()) return;
        
        // Get files in this folder
        DomainFile[] files = folder.getFiles();
        
        // Count program files in this folder
        int programCount = 0;
        for (DomainFile file : files) {
            if (file.getContentType().equals("Program")) {
                programCount++;
            }
        }
        
        // Only process folders that contain programs
        if (programCount > 0) {
            println("\n" + "=".repeat(50));
            println("FOLDER: " + folder.getPathname());
            println("=".repeat(50));
            println("Found " + programCount + " program(s)");
            
            for (DomainFile file : files) {
                if (monitor.isCancelled()) {
                    println("\n*** CANCELLED BY USER ***");
                    return;
                }
                
                if (!file.getContentType().equals("Program")) {
                    continue;
                }
                
                // Process using the current folder as the library source
                processProgram(file, folder);
            }
            
            totalFoldersProcessed++;
        }
        
        // Recurse into subfolders
        DomainFolder[] subfolders = folder.getFolders();
        for (DomainFolder subfolder : subfolders) {
            if (monitor.isCancelled()) return;
            processAllFolders(subfolder);
        }
    }
    
    /**
     * Process a single program file.
     */
    private void processProgram(DomainFile programFile, DomainFolder projectFolder) {
        String programName = programFile.getName();
        
        println("\n" + "-".repeat(50));
        println("Processing: " + programName);
        println("-".repeat(50));
        
        Program program = null;
        Object consumer = this;
        boolean needsSave = false;
        
        try {
            // Open the program with write access
            program = (Program) programFile.getDomainObject(consumer, true, false, monitor);
            
            if (program == null) {
                println("  ERROR: Could not open " + programName);
                return;
            }
            
            // Start a transaction for modifications
            int txId = program.startTransaction("Resolve Ordinal Imports");
            
            try {
                // Process this program
                int[] results = processImports(program, projectFolder);
                int renamed = results[0];
                int thunks = results[1];
                int skipped = results[2];
                
                totalImportsResolved += renamed;
                totalThunksRenamed += thunks;
                totalSkipped += skipped;
                totalProgramsProcessed++;
                
                needsSave = (renamed > 0 || thunks > 0);
                
                println("  Summary: " + renamed + " imports, " + thunks + " thunks, " + skipped + " skipped");
                
                program.endTransaction(txId, needsSave);
                
            } catch (Exception e) {
                program.endTransaction(txId, false);
                println("  ERROR: " + e.getMessage());
                e.printStackTrace();
            }
            
            // Save if changes were made
            if (needsSave) {
                program.save(programName, monitor);
                println("  Saved changes to " + programName);
            }
            
        } catch (Exception e) {
            println("  ERROR opening " + programName + ": " + e.getMessage());
        } finally {
            if (program != null) {
                program.release(consumer);
            }
        }
    }
    
    /**
     * Process imports for a single program.
     * Returns [renamed, thunks, skipped]
     */
    private int[] processImports(Program program, DomainFolder projectFolder) throws Exception {
        int totalRenamed = 0;
        int totalSkipped = 0;
        int thunksRenamed = 0;
        
        ExternalManager extMgr = program.getExternalManager();
        String[] libNames = extMgr.getExternalLibraryNames();
        
        // Process each library
        for (String libName : libNames) {
            if (monitor.isCancelled()) break;
            
            // Skip standard Windows DLLs
            String libUpper = libName.toUpperCase();
            if (isWindowsDll(libUpper)) {
                continue;
            }
            
            // Count imports from this library
            int importCount = 0;
            ExternalLocationIterator countIter = extMgr.getExternalLocations(libName);
            while (countIter.hasNext()) {
                countIter.next();
                importCount++;
            }
            
            if (importCount == 0) continue;
            
            // Try to find this DLL in the project folder
            DomainFile libFile = findLibraryInProject(projectFolder, libName);
            
            if (libFile == null) {
                println("    WARNING: " + libName + " not found in project");
                totalSkipped += importCount;
                continue;
            }
            
            // Set the external library path
            String libPath = libFile.getPathname();
            String currentPath = extMgr.getExternalLibraryPath(libName);
            if (currentPath == null || !currentPath.equals(libPath)) {
                extMgr.setExternalPath(libName, libPath, true);
            }
            
            // Open the library
            Program libProgram = null;
            Object consumer = this;
            
            try {
                libProgram = (Program) libFile.getDomainObject(consumer, false, false, monitor);
                
                if (libProgram == null) {
                    totalSkipped += importCount;
                    continue;
                }
                
                // Build ordinal -> address mapping from PE export directory
                Map<Integer, Address> ordinalToAddr = getOrdinalAddressMap(libProgram);
                
                // Build name -> function mapping
                Map<String, Function> nameToFunc = new HashMap<>();
                FunctionManager libFuncMgr = libProgram.getFunctionManager();
                FunctionIterator allFuncs = libFuncMgr.getFunctions(true);
                while (allFuncs.hasNext()) {
                    Function f = allFuncs.next();
                    nameToFunc.put(f.getName(), f);
                }
                
                SymbolTable libSymTable = libProgram.getSymbolTable();
                
                // Process external locations
                ExternalLocationIterator iter = extMgr.getExternalLocations(libName);
                while (iter.hasNext()) {
                    if (monitor.isCancelled()) break;
                    
                    ExternalLocation loc = iter.next();
                    String label = loc.getLabel();
                    
                    if (label == null) {
                        totalSkipped++;
                        continue;
                    }
                    
                    Function srcFunc = null;
                    String newName = null;
                    
                    if (label.startsWith("Ordinal_")) {
                        // Ordinal import
                        try {
                            int ordinal = Integer.parseInt(label.substring(8));
                            Address funcAddr = ordinalToAddr.get(ordinal);
                            
                            if (funcAddr == null) {
                                totalSkipped++;
                                continue;
                            }
                            
                            srcFunc = libFuncMgr.getFunctionAt(funcAddr);
                            if (srcFunc != null) {
                                newName = srcFunc.getName();
                            } else {
                                Symbol sym = libSymTable.getPrimarySymbol(funcAddr);
                                if (sym != null) {
                                    newName = sym.getName();
                                }
                            }
                            
                            if (newName == null || newName.startsWith("Ordinal_") || newName.startsWith("FUN_")) {
                                totalSkipped++;
                                continue;
                            }
                            
                            // Update name and address
                            loc.setLocation(newName, funcAddr, SourceType.USER_DEFINED);
                            
                            // Update references
                            updateReferencesToExternal(program, loc, newName);
                            
                            // Apply signature
                            if (srcFunc != null) {
                                applySignatureToExternal(program, loc, srcFunc, newName);
                            }
                            
                            totalRenamed++;
                            
                        } catch (NumberFormatException e) {
                            totalSkipped++;
                        }
                    } else {
                        // Already named - update address and signature
                        srcFunc = nameToFunc.get(label);
                        
                        if (srcFunc != null) {
                            Address srcAddr = srcFunc.getEntryPoint();
                            
                            try {
                                loc.setLocation(label, srcAddr, SourceType.USER_DEFINED);
                            } catch (Exception e) {
                                // Ignore
                            }
                            
                            updateReferencesToExternal(program, loc, label);
                            applySignatureToExternal(program, loc, srcFunc, label);
                            totalRenamed++;
                        } else {
                            totalSkipped++;
                        }
                    }
                }
                
            } finally {
                if (libProgram != null) {
                    libProgram.release(consumer);
                }
            }
        }
        
        // Process thunk functions
        FunctionManager funcMgr = program.getFunctionManager();
        FunctionIterator funcIter = funcMgr.getFunctions(true);
        
        while (funcIter.hasNext() && !monitor.isCancelled()) {
            Function func = funcIter.next();
            
            if (!func.isThunk()) continue;
            
            String funcName = func.getName();
            if (!funcName.startsWith("Ordinal_") && !funcName.contains("::Ordinal_")) {
                continue;
            }
            
            Function thunkedFunc = func.getThunkedFunction(true);
            if (thunkedFunc == null) continue;
            
            String thunkedName = thunkedFunc.getName();
            if (thunkedName.startsWith("Ordinal_") || thunkedName.startsWith("FUN_")) {
                continue;
            }
            
            try {
                func.setName(thunkedName, SourceType.USER_DEFINED);
                func.setReturnType(thunkedFunc.getReturnType(), SourceType.USER_DEFINED);
                
                String callingConv = thunkedFunc.getCallingConventionName();
                if (callingConv != null && !callingConv.equals("unknown")) {
                    try {
                        func.setCallingConvention(callingConv);
                    } catch (Exception e) {}
                }
                
                Parameter[] params = thunkedFunc.getParameters();
                if (params.length > 0) {
                    ArrayList<ParameterImpl> newParams = new ArrayList<>();
                    for (Parameter p : params) {
                        newParams.add(new ParameterImpl(p.getName(), p.getDataType(), program));
                    }
                    func.replaceParameters(newParams,
                        FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
                        true, SourceType.USER_DEFINED);
                }
                
                thunksRenamed++;
            } catch (Exception e) {}
        }
        
        return new int[] { totalRenamed, thunksRenamed, totalSkipped };
    }
    
    /**
     * Check if a DLL name is a Windows system DLL.
     */
    private boolean isWindowsDll(String libUpper) {
        return libUpper.equals("KERNEL32.DLL") || libUpper.equals("USER32.DLL") ||
               libUpper.equals("ADVAPI32.DLL") || libUpper.equals("GDI32.DLL") ||
               libUpper.equals("NTDLL.DLL") || libUpper.equals("MSVCRT.DLL") ||
               libUpper.equals("WS2_32.DLL") || libUpper.equals("WINMM.DLL") ||
               libUpper.equals("SHELL32.DLL") || libUpper.equals("OLE32.DLL") ||
               libUpper.equals("OLEAUT32.DLL") || libUpper.equals("COMCTL32.DLL") ||
               libUpper.equals("WSOCK32.DLL") || libUpper.equals("COMDLG32.DLL") ||
               libUpper.equals("VERSION.DLL") || libUpper.equals("SHLWAPI.DLL") ||
               libUpper.equals("DDRAW.DLL") || libUpper.equals("DSOUND.DLL") ||
               libUpper.equals("DINPUT.DLL") || libUpper.equals("OPENGL32.DLL") ||
               libUpper.equals("GLU32.DLL") || libUpper.equals("D3D9.DLL") ||
               libUpper.equals("D3DX9_43.DLL");
    }
    
    /**
     * Find a library DLL in the project folder (case-insensitive).
     */
    private DomainFile findLibraryInProject(DomainFolder folder, String libName) {
        DomainFile file = folder.getFile(libName);
        if (file != null) return file;
        
        String libLower = libName.toLowerCase();
        String baseName = libLower.endsWith(".dll") ? libLower.substring(0, libLower.length() - 4) : libLower;
        
        try {
            DomainFile[] files = folder.getFiles();
            for (DomainFile f : files) {
                String fname = f.getName().toLowerCase();
                if (fname.equals(libLower) || fname.equals(baseName) || 
                    fname.equals(baseName + ".dll")) {
                    return f;
                }
            }
        } catch (Exception e) {}
        
        return null;
    }
    
    /**
     * Build ordinal -> address mapping from PE export directory.
     */
    private Map<Integer, Address> getOrdinalAddressMap(Program libProgram) {
        Map<Integer, Address> exports = new HashMap<>();
        
        try {
            Memory memory = libProgram.getMemory();
            Address dosHeader = libProgram.getImageBase();
            
            int peOffset = memory.getInt(dosHeader.add(0x3C));
            Address peHeader = dosHeader.add(peOffset);
            Address optionalHeader = peHeader.add(24);
            
            short magic = memory.getShort(optionalHeader);
            int exportDirOffset = (magic == 0x20b) ? 112 : 96;
            
            Address exportDirEntry = optionalHeader.add(exportDirOffset);
            int exportDirRVA = memory.getInt(exportDirEntry);
            int exportDirSize = memory.getInt(exportDirEntry.add(4));
            
            if (exportDirRVA == 0) return exports;
            
            Address exportDir = dosHeader.add(exportDirRVA);
            
            int ordinalBase = memory.getInt(exportDir.add(0x10));
            int numberOfFunctions = memory.getInt(exportDir.add(0x14));
            int addressOfFunctions = memory.getInt(exportDir.add(0x1C));
            
            Address eatAddr = dosHeader.add(addressOfFunctions);
            
            for (int i = 0; i < numberOfFunctions && !monitor.isCancelled(); i++) {
                int funcRVA = memory.getInt(eatAddr.add(i * 4));
                
                if (funcRVA == 0) continue;
                if (funcRVA >= exportDirRVA && funcRVA < exportDirRVA + exportDirSize) continue;
                
                int ordinal = ordinalBase + i;
                Address funcAddr = dosHeader.add(funcRVA);
                exports.put(ordinal, funcAddr);
            }
            
        } catch (Exception e) {}
        
        return exports;
    }
    
    /**
     * Apply function signature from source to external location.
     */
    private void applySignatureToExternal(Program program, ExternalLocation loc, Function srcFunc, String label) {
        try {
            Function extFunc = loc.getFunction();
            
            if (extFunc == null) {
                try {
                    extFunc = loc.createFunction();
                } catch (Exception e) {
                    return;
                }
            }
            
            if (extFunc != null) {
                extFunc.setReturnType(srcFunc.getReturnType(), SourceType.USER_DEFINED);
                
                String callingConv = srcFunc.getCallingConventionName();
                if (callingConv != null && !callingConv.equals("unknown")) {
                    try {
                        extFunc.setCallingConvention(callingConv);
                    } catch (Exception e) {}
                }
                
                Parameter[] srcParams = srcFunc.getParameters();
                if (srcParams.length > 0) {
                    ArrayList<ParameterImpl> newParams = new ArrayList<>();
                    for (Parameter p : srcParams) {
                        newParams.add(new ParameterImpl(p.getName(), p.getDataType(), program));
                    }
                    extFunc.replaceParameters(newParams,
                        FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
                        true, SourceType.USER_DEFINED);
                }
            } else {
                try {
                    FunctionDefinitionDataType funcDef = new FunctionDefinitionDataType(srcFunc, false);
                    loc.setDataType(funcDef);
                } catch (Exception e) {}
            }
        } catch (Exception e) {}
    }
    
    /**
     * Update references to an external location.
     */
    private void updateReferencesToExternal(Program program, ExternalLocation loc, String newName) {
        try {
            Address extSpaceAddr = loc.getExternalSpaceAddress();
            if (extSpaceAddr == null) return;
            
            ReferenceManager refMgr = program.getReferenceManager();
            SymbolTable symTable = program.getSymbolTable();
            Listing listing = program.getListing();
            
            ReferenceIterator refIter = refMgr.getReferencesTo(extSpaceAddr);
            
            while (refIter.hasNext()) {
                Reference ref = refIter.next();
                Address ptrAddr = ref.getFromAddress();
                
                // Remove comments at pointer location
                listing.setComment(ptrAddr, CodeUnit.PRE_COMMENT, null);
                listing.setComment(ptrAddr, CodeUnit.PLATE_COMMENT, null);
                listing.setComment(ptrAddr, CodeUnit.EOL_COMMENT, null);
                listing.setComment(ptrAddr, CodeUnit.POST_COMMENT, null);
                listing.setComment(ptrAddr, CodeUnit.REPEATABLE_COMMENT, null);
                
                // Rename pointer symbols
                Symbol[] ptrSymbols = symTable.getSymbols(ptrAddr);
                for (Symbol sym : ptrSymbols) {
                    String symName = sym.getName();
                    if (symName.startsWith("PTR_") || symName.startsWith("Ordinal_")) {
                        try {
                            String updatedName = "PTR_" + newName + "_" + ptrAddr.toString().replace(":", "");
                            sym.setName(updatedName, SourceType.USER_DEFINED);
                        } catch (Exception e) {}
                    }
                }
                
                // Process call sites
                ReferenceIterator callRefs = refMgr.getReferencesTo(ptrAddr);
                while (callRefs.hasNext()) {
                    Reference callRef = callRefs.next();
                    Address callAddr = callRef.getFromAddress();
                    
                    listing.setComment(callAddr, CodeUnit.PRE_COMMENT, null);
                    listing.setComment(callAddr, CodeUnit.PLATE_COMMENT, null);
                    listing.setComment(callAddr, CodeUnit.EOL_COMMENT, null);
                    listing.setComment(callAddr, CodeUnit.POST_COMMENT, null);
                    listing.setComment(callAddr, CodeUnit.REPEATABLE_COMMENT, null);
                    
                    Symbol[] callSymbols = symTable.getSymbols(callAddr);
                    for (Symbol sym : callSymbols) {
                        String symName = sym.getName();
                        if (sym.getSource() == SourceType.USER_DEFINED &&
                            !symName.equals(newName) && 
                            !symName.startsWith("FUN_") && 
                            !symName.startsWith("LAB_")) {
                            try {
                                sym.setName(newName, SourceType.USER_DEFINED);
                            } catch (Exception e) {}
                        }
                    }
                }
            }
            
            // Check for thunk functions
            Symbol extSym = loc.getSymbol();
            if (extSym != null) {
                Reference[] thunkRefs = extSym.getReferences();
                for (Reference ref : thunkRefs) {
                    Address fromAddr = ref.getFromAddress();
                    Function func = program.getFunctionManager().getFunctionAt(fromAddr);
                    if (func != null && func.isThunk()) {
                        String funcName = func.getName();
                        if (!funcName.equals(newName)) {
                            try {
                                func.setName(newName, SourceType.USER_DEFINED);
                            } catch (Exception e) {}
                        }
                    }
                }
            }
            
        } catch (Exception e) {}
    }
}
