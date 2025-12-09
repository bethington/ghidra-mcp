//Resolve ordinal imports by looking up exports in the actual DLL from the same project folder.
//@author D2VersionChanger
//@category D2VersionChanger
//@keybinding
//@menupath Tools.D2.Resolve Ordinal Imports
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.data.*;
import ghidra.framework.model.*;
import ghidra.util.task.TaskMonitor;
import ghidra.app.cmd.comments.SetCommentCmd;
import java.util.*;

/**
 * Resolves ordinal imports by finding the exporting DLL in the same project folder
 * and looking up the actual function names and signatures from its symbols.
 * 
 * For example, if D2Common.dll imports FOG.DLL::Ordinal_10042, this script will:
 * 1. Find Fog.dll in the same project folder as D2Common.dll
 * 2. Find the function at the entry point for ordinal 10042
 * 3. If that function has a proper name and signature, apply both
 * 4. Rename the import from Ordinal_10042 to the actual name with correct signature
 * 
 * This leverages the RE work done on the exporting DLLs.
 */
public class ResolveOrdinalImports extends GhidraScript {

    @Override
    public void run() throws Exception {
        // Get the current program's location in the project
        DomainFile currentFile = currentProgram.getDomainFile();
        DomainFolder currentFolder = currentFile.getParent();
        
        println("Current program: " + currentFile.getName());
        println("Project folder: " + currentFolder.getPathname());
        
        // Get all external libraries this program imports from
        ExternalManager extMgr = currentProgram.getExternalManager();
        String[] libNames = extMgr.getExternalLibraryNames();
        
        println("\nExternal libraries imported:");
        for (String lib : libNames) {
            println("  " + lib);
        }
        
        int totalRenamed = 0;
        int totalSkipped = 0;
        
        // Process each library
        for (String libName : libNames) {
            // Skip standard Windows DLLs
            String libUpper = libName.toUpperCase();
            if (libUpper.equals("KERNEL32.DLL") || libUpper.equals("USER32.DLL") ||
                libUpper.equals("ADVAPI32.DLL") || libUpper.equals("GDI32.DLL") ||
                libUpper.equals("NTDLL.DLL") || libUpper.equals("MSVCRT.DLL") ||
                libUpper.equals("WS2_32.DLL") || libUpper.equals("WINMM.DLL") ||
                libUpper.equals("SHELL32.DLL") || libUpper.equals("OLE32.DLL") ||
                libUpper.equals("OLEAUT32.DLL") || libUpper.equals("COMCTL32.DLL")) {
                continue;
            }
            
            // Count all imports from this library
            int importCount = 0;
            ExternalLocationIterator iter = extMgr.getExternalLocations(libName);
            while (iter.hasNext()) {
                iter.next();
                importCount++;
            }
            
            if (importCount == 0) {
                continue;
            }
            
            println("\n" + libName + ": " + importCount + " external references to process");
            
            // Try to find this DLL in the same project folder
            DomainFile libFile = findLibraryInProject(currentFolder, libName);
            
            if (libFile == null) {
                println("  WARNING: Could not find " + libName + " in project folder");
                totalSkipped += importCount;
                continue;
            }
            
            println("  Found: " + libFile.getPathname());
            
            // Set the external library path to point to the found DLL in the project
            // This enables navigation from external references to the actual DLL
            String libPath = libFile.getPathname();
            String currentPath = extMgr.getExternalLibraryPath(libName);
            if (currentPath == null || !currentPath.equals(libPath)) {
                extMgr.setExternalPath(libName, libPath, true);
                println("  Set library path: " + libPath);
            }
            
            // Open the library and process exports with signatures
            Program libProgram = null;
            Object consumer = this;
            
            try {
                libProgram = (Program) libFile.getDomainObject(consumer, false, false, monitor);
                
                if (libProgram == null) {
                    println("  Could not open " + libFile.getName());
                    totalSkipped += importCount;
                    continue;
                }
                
                // Build ordinal -> address mapping from PE export directory
                Map<Integer, Address> ordinalToAddr = getOrdinalAddressMap(libProgram);
                
                // Also build name -> function mapping for direct lookups
                Map<String, Function> nameToFunc = new HashMap<>();
                FunctionManager libFuncMgr = libProgram.getFunctionManager();
                FunctionIterator allFuncs = libFuncMgr.getFunctions(true);
                while (allFuncs.hasNext()) {
                    Function f = allFuncs.next();
                    nameToFunc.put(f.getName(), f);
                }
                
                println("  Loaded " + ordinalToAddr.size() + " exports, " + nameToFunc.size() + " functions");
                
                SymbolTable libSymTable = libProgram.getSymbolTable();
                
                // Process ALL external locations
                iter = extMgr.getExternalLocations(libName);
                while (iter.hasNext()) {
                    ExternalLocation loc = iter.next();
                    String label = loc.getLabel();
                    
                    if (label == null) {
                        totalSkipped++;
                        continue;
                    }
                    
                    Function srcFunc = null;
                    String newName = null;
                    
                    if (label.startsWith("Ordinal_")) {
                        // Ordinal import - look up by ordinal number
                        try {
                            int ordinal = Integer.parseInt(label.substring(8));
                            Address funcAddr = ordinalToAddr.get(ordinal);
                            
                            if (funcAddr == null) {
                                println("    " + label + ": ordinal not in export table");
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
                                println("    " + label + ": no useful name at " + funcAddr);
                                totalSkipped++;
                                continue;
                            }
                            
                            // Update both name and address together using setLocation
                            // This properly updates the external location to point to the function
                            loc.setLocation(newName, funcAddr, SourceType.USER_DEFINED);
                            
                            println("    " + label + " -> " + newName + " @ " + funcAddr);
                            
                            // Update references to this external (call sites, pointer labels)
                            updateReferencesToExternal(loc, newName);
                            
                            // Apply signature if we have a function
                            if (srcFunc != null) {
                                applySignatureToExternal(loc, srcFunc, newName);
                                totalRenamed++;
                            } else {
                                totalRenamed++;  // Still count the rename
                            }
                            
                        } catch (NumberFormatException e) {
                            totalSkipped++;
                            continue;
                        }
                    } else {
                        // Already named - look up the function by name for signature AND address
                        srcFunc = nameToFunc.get(label);
                        
                        // Apply signature and update address if we have a source function
                        if (srcFunc != null) {
                            Address srcAddr = srcFunc.getEntryPoint();
                            
                            // Update the address to point to correct location in source DLL
                            try {
                                loc.setLocation(label, srcAddr, SourceType.USER_DEFINED);
                                println("    " + label + " @ " + srcAddr);
                            } catch (Exception e) {
                                println("    " + label + ": setLocation failed: " + e.getMessage());
                            }
                            
                            // Update references to this external (call sites, pointer labels)
                            updateReferencesToExternal(loc, label);
                            
                            applySignatureToExternal(loc, srcFunc, label);
                            totalRenamed++;
                        } else {
                            // println("    " + label + ": no source function found (skipping sig)");
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
        
        // Now process thunk functions that reference external ordinals
        println("\n--- Processing Thunk Functions ---");
        int thunksRenamed = 0;
        
        FunctionManager funcMgr = currentProgram.getFunctionManager();
        FunctionIterator funcIter = funcMgr.getFunctions(true);
        
        while (funcIter.hasNext() && !monitor.isCancelled()) {
            Function func = funcIter.next();
            
            // Only process thunk functions
            if (!func.isThunk()) {
                continue;
            }
            
            String funcName = func.getName();
            
            // Check if the thunk has an ordinal name
            if (!funcName.startsWith("Ordinal_") && !funcName.contains("::Ordinal_")) {
                continue;
            }
            
            // Get the thunked function (the external it jumps to)
            Function thunkedFunc = func.getThunkedFunction(true);
            if (thunkedFunc == null) {
                continue;
            }
            
            // Check if the thunked function has a proper name now
            String thunkedName = thunkedFunc.getName();
            if (thunkedName.startsWith("Ordinal_") || thunkedName.startsWith("FUN_")) {
                // The external still has ordinal name, skip
                continue;
            }
            
            // Rename the thunk to match the resolved external function
            try {
                func.setName(thunkedName, SourceType.USER_DEFINED);
                println("  Thunk " + funcName + " -> " + thunkedName);
                thunksRenamed++;
                
                // Also copy the signature from the thunked function
                func.setReturnType(thunkedFunc.getReturnType(), SourceType.USER_DEFINED);
                
                String callingConv = thunkedFunc.getCallingConventionName();
                if (callingConv != null && !callingConv.equals("unknown")) {
                    try {
                        func.setCallingConvention(callingConv);
                    } catch (Exception e) {
                        // Ignore
                    }
                }
                
                Parameter[] params = thunkedFunc.getParameters();
                if (params.length > 0) {
                    ArrayList<ParameterImpl> newParams = new ArrayList<>();
                    for (Parameter p : params) {
                        ParameterImpl newParam = new ParameterImpl(
                            p.getName(),
                            p.getDataType(),
                            currentProgram
                        );
                        newParams.add(newParam);
                    }
                    func.replaceParameters(newParams,
                        FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
                        true, SourceType.USER_DEFINED);
                }
                
            } catch (Exception e) {
                println("  Thunk " + funcName + ": rename failed - " + e.getMessage());
            }
        }
        
        println("\n========================================");
        println("Done! Updated " + totalRenamed + " imports, " + thunksRenamed + " thunks, skipped " + totalSkipped);
        println("========================================");
    }
    
    /**
     * Find a library DLL in the same project folder (case-insensitive).
     */
    private DomainFile findLibraryInProject(DomainFolder folder, String libName) {
        // Try exact match first
        DomainFile file = folder.getFile(libName);
        if (file != null) {
            return file;
        }
        
        // Try case-insensitive match
        String libLower = libName.toLowerCase();
        // Remove .dll extension for matching
        String baseName = libLower.endsWith(".dll") ? libLower.substring(0, libLower.length() - 4) : libLower;
        
        try {
            DomainFile[] files = folder.getFiles();
            for (DomainFile f : files) {
                String fname = f.getName().toLowerCase();
                // Match with or without .dll extension
                if (fname.equals(libLower) || fname.equals(baseName) || 
                    fname.equals(baseName + ".dll")) {
                    return f;
                }
            }
        } catch (Exception e) {
            println("Error listing folder: " + e.getMessage());
        }
        
        return null;
    }
    
    /**
     * Build ordinal -> address mapping from PE export directory.
     * 
     * This reads the PE export directory to get ordinal-to-RVA mappings.
     */
    private Map<Integer, Address> getOrdinalAddressMap(Program libProgram) {
        Map<Integer, Address> exports = new HashMap<>();
        
        try {
            Memory memory = libProgram.getMemory();
            
            // Get the image base
            Address dosHeader = libProgram.getImageBase();
            
            // Read DOS header to find PE header
            int peOffset = memory.getInt(dosHeader.add(0x3C));  // e_lfanew
            Address peHeader = dosHeader.add(peOffset);
            
            // PE signature is at peHeader, optional header starts at +24
            Address optionalHeader = peHeader.add(24);
            
            // Check PE32 vs PE32+ by reading magic
            short magic = memory.getShort(optionalHeader);
            int exportDirOffset = (magic == 0x20b) ? 112 : 96;  // PE32+ : PE32
            
            // Read export directory RVA and size
            Address exportDirEntry = optionalHeader.add(exportDirOffset);
            int exportDirRVA = memory.getInt(exportDirEntry);
            int exportDirSize = memory.getInt(exportDirEntry.add(4));
            
            if (exportDirRVA == 0) {
                println("  No export directory found");
                return exports;
            }
            
            // Calculate export directory address
            Address exportDir = dosHeader.add(exportDirRVA);
            
            // Read export directory structure
            int ordinalBase = memory.getInt(exportDir.add(0x10));
            int numberOfFunctions = memory.getInt(exportDir.add(0x14));
            int addressOfFunctions = memory.getInt(exportDir.add(0x1C));
            
            println("  Export directory: ordinalBase=" + ordinalBase + 
                    ", numberOfFunctions=" + numberOfFunctions);
            
            // Read the export address table
            Address eatAddr = dosHeader.add(addressOfFunctions);
            
            for (int i = 0; i < numberOfFunctions && !monitor.isCancelled(); i++) {
                int funcRVA = memory.getInt(eatAddr.add(i * 4));
                
                if (funcRVA == 0) {
                    continue;  // Empty slot
                }
                
                // Check if it's a forwarder (RVA points within export directory)
                if (funcRVA >= exportDirRVA && funcRVA < exportDirRVA + exportDirSize) {
                    continue;  // Skip forwarders
                }
                
                int ordinal = ordinalBase + i;
                Address funcAddr = dosHeader.add(funcRVA);
                
                exports.put(ordinal, funcAddr);
            }
            
        } catch (Exception e) {
            println("  Error reading export directory: " + e.getMessage());
            e.printStackTrace();
        }
        
        return exports;
    }
    
    /**
     * Apply function signature from source to external location.
     */
    private void applySignatureToExternal(ExternalLocation loc, Function srcFunc, String label) {
        try {
            // Get or create the external function
            Function extFunc = loc.getFunction();
            
            if (extFunc == null) {
                try {
                    extFunc = loc.createFunction();
                } catch (Exception e) {
                    println("    " + label + ": could not create ext function: " + e.getMessage());
                }
            }
            
            if (extFunc != null) {
                // Copy return type
                DataType returnType = srcFunc.getReturnType();
                extFunc.setReturnType(returnType, SourceType.USER_DEFINED);
                
                // Copy calling convention first (before parameters)
                String callingConv = srcFunc.getCallingConventionName();
                if (callingConv != null && !callingConv.equals("unknown")) {
                    try {
                        extFunc.setCallingConvention(callingConv);
                    } catch (Exception e) {
                        // Calling convention might not be available
                    }
                }
                
                // Copy parameters
                Parameter[] srcParams = srcFunc.getParameters();
                if (srcParams.length > 0) {
                    ArrayList<ParameterImpl> newParams = new ArrayList<>();
                    for (Parameter p : srcParams) {
                        ParameterImpl newParam = new ParameterImpl(
                            p.getName(),
                            p.getDataType(),
                            currentProgram
                        );
                        newParams.add(newParam);
                    }
                    
                    extFunc.replaceParameters(newParams,
                        FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
                        true, SourceType.USER_DEFINED);
                }
                
                println("    " + label + " sig updated: " + srcFunc.getSignature().getPrototypeString());
            } else {
                // Try setting data type directly
                try {
                    FunctionDefinitionDataType funcDef = new FunctionDefinitionDataType(srcFunc, false);
                    loc.setDataType(funcDef);
                    println("    " + label + " sig via datatype: " + funcDef.getPrototypeString());
                } catch (Exception e) {
                    println("    " + label + ": could not apply signature");
                }
            }
        } catch (Exception e) {
            println("    " + label + " sig failed: " + e.getMessage());
        }
    }
    
    /**
     * Update references to an external location.
     * 
     * This handles:
     * 1. Pointer symbols (PTR_OldName_addr) - renames them to match the external
     * 2. Call site labels (OldName at call addresses) - renames or removes them
     * 3. Comments at those locations - removes obsolete comments
     */
    private void updateReferencesToExternal(ExternalLocation loc, String newName) {
        try {
            // Get the external space address (the fake address in EXTERNAL space)
            Address extSpaceAddr = loc.getExternalSpaceAddress();
            
            if (extSpaceAddr == null) {
                println("      No external space address");
                return;
            }
            
            ReferenceManager refMgr = currentProgram.getReferenceManager();
            SymbolTable symTable = currentProgram.getSymbolTable();
            Listing listing = currentProgram.getListing();
            
            int refsUpdated = 0;
            
            // First, find all references TO the external space address
            // These are typically the import pointers in .idata
            ReferenceIterator refIter = refMgr.getReferencesTo(extSpaceAddr);
            
            while (refIter.hasNext()) {
                Reference ref = refIter.next();
                Address ptrAddr = ref.getFromAddress();  // This is the pointer location (e.g., in .idata)
                
                // Remove comments at the pointer location
                listing.setComment(ptrAddr, CodeUnit.PRE_COMMENT, null);
                listing.setComment(ptrAddr, CodeUnit.PLATE_COMMENT, null);
                listing.setComment(ptrAddr, CodeUnit.EOL_COMMENT, null);
                listing.setComment(ptrAddr, CodeUnit.POST_COMMENT, null);
                listing.setComment(ptrAddr, CodeUnit.REPEATABLE_COMMENT, null);
                
                // Rename symbols at the pointer location
                Symbol[] ptrSymbols = symTable.getSymbols(ptrAddr);
                for (Symbol sym : ptrSymbols) {
                    String symName = sym.getName();
                    if (symName.startsWith("PTR_") || symName.startsWith("Ordinal_")) {
                        try {
                            String updatedName = "PTR_" + newName + "_" + ptrAddr.toString().replace(":", "");
                            sym.setName(updatedName, SourceType.USER_DEFINED);
                            refsUpdated++;
                        } catch (Exception e) {
                            // Rename failed
                        }
                    }
                }
                
                // Now find all references TO this pointer (the actual CALL sites)
                ReferenceIterator callRefs = refMgr.getReferencesTo(ptrAddr);
                while (callRefs.hasNext()) {
                    Reference callRef = callRefs.next();
                    Address callAddr = callRef.getFromAddress();
                    
                    // Remove comments at the call site
                    listing.setComment(callAddr, CodeUnit.PRE_COMMENT, null);
                    listing.setComment(callAddr, CodeUnit.PLATE_COMMENT, null);
                    listing.setComment(callAddr, CodeUnit.EOL_COMMENT, null);
                    listing.setComment(callAddr, CodeUnit.POST_COMMENT, null);
                    listing.setComment(callAddr, CodeUnit.REPEATABLE_COMMENT, null);
                    refsUpdated++;
                    
                    // Rename any user-defined labels at the call site
                    Symbol[] callSymbols = symTable.getSymbols(callAddr);
                    for (Symbol sym : callSymbols) {
                        String symName = sym.getName();
                        if (sym.getSource() == SourceType.USER_DEFINED &&
                            !symName.equals(newName) && 
                            !symName.startsWith("FUN_") && 
                            !symName.startsWith("LAB_")) {
                            try {
                                sym.setName(newName, SourceType.USER_DEFINED);
                            } catch (Exception e) {
                                // Rename failed
                            }
                        }
                    }
                }
            }
            
            // Also check for thunk functions
            Symbol extSym = loc.getSymbol();
            if (extSym != null) {
                Reference[] thunkRefs = extSym.getReferences();
                for (Reference ref : thunkRefs) {
                    Address fromAddr = ref.getFromAddress();
                    Function func = currentProgram.getFunctionManager().getFunctionAt(fromAddr);
                    if (func != null && func.isThunk()) {
                        String funcName = func.getName();
                        if (!funcName.equals(newName)) {
                            try {
                                func.setName(newName, SourceType.USER_DEFINED);
                                refsUpdated++;
                            } catch (Exception e) {
                                // Function rename failed
                            }
                        }
                    }
                }
            }
            
            if (refsUpdated > 0) {
                println("      Updated " + refsUpdated + " references/comments");
            }
            
        } catch (Exception e) {
            println("      Error updating references: " + e.getMessage());
        }
    }
}
