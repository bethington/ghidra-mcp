// Function Index
//
// Exports all functions with multi-method matching indexes (EXP/STR/API/MNE/CFG/PRO) for cross-version function identification. Supports single program or batch mode.
//
// Usage: Run from Script Manager via Ctrl+Shift+E.
// Output: JSON at data/function_index/{GameType}/{Version}/{dll}.json.
//
// @author Ben Ethington
// @category Diablo 2.Export
// @description Export comprehensive function index for cross-version matching
// @menupath Diablo 2.Export.Function Index

import ghidra.app.script.GhidraScript;
import ghidra.framework.model.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.data.*;
import ghidra.program.model.block.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.scalar.*;
import java.io.*;
import java.util.*;
import java.security.*;

/**
 * Exports comprehensive function data with multiple matching indexes.
 *
 * Supports two modes:
 * - Single program: Export current program only
 * - Batch mode: Export all programs in the project
 *
 * For each function, exports:
 * - Basic info (address, size, name if human-assigned)
 * - EXP index: Export ordinal (for exported functions)
 * - STR index: Hash of referenced unique strings
 * - NOP index: Normalized OPcode hash (address-independent, like MCP)
 * - CAL index: Hash of sorted callee function names
 * - API index: Hash of imported API call sequence
 * - APS index: Hash of sorted API calls (order-independent)
 * - CON index: Hash of sorted constants (magic numbers)
 * - MNE index: Hash of instruction mnemonic sequence + size
 * - CFG index: Hash of basic block count + edge structure
 * - PRO index: Hash of prologue bytes + size
 *
 * Index Selection Priority:
 * 1. STR (99% reliable) - if has unique string references
 * 2. NOP (98% reliable) - normalized opcode hash for unchanged functions
 * 3. CAL (95% reliable) - sorted callee names are stable
 * 4. API (90% reliable) - if calls 2+ imported APIs
 * 5. CON (85% reliable) - sorted magic numbers
 * 6. MNE (80% reliable) - default workhorse
 * 7. CFG (70% reliable) - for medium+ functions
 * 8. PRO (60% reliable) - fallback for tiny functions
 * 9. EXP (50% - NOT reliable) - ordinals change between versions
 *
 * Output path derived from program location:
 *   /F:/D2VersionChanger/VersionChanger/LoD/1.07/D2Client.dll
 *   -> F:/D2VersionChanger/data/function_index/LoD/1.07/D2Client.dll.json
 */
public class Export_FunctionIndex extends GhidraScript {

    // Batch mode statistics
    private int totalProcessed = 0;
    private int totalFailed = 0;
    private int totalFunctions = 0;
    private List<String> failedPrograms = new ArrayList<>();

    // Per-program state (reset for each program in batch mode)
    private Program activeProgram;
    private Map<String, Integer> stringRefCounts;
    private Map<Address, String> importMap;
    private Map<Address, Integer> exportOrdinalMap;

    @Override
    public void run() throws Exception {
        println("=".repeat(70));
        println("FUNCTION INDEX EXPORT");
        println("=".repeat(70));

        // Ask user which mode to use
        String singleOption = "Current Program Only";
        String batchOption = "All Programs in Project";

        String choice = askChoice("Export Mode",
            "Choose export mode:",
            Arrays.asList(singleOption, batchOption),
            singleOption);

        if (choice.equals(singleOption)) {
            // Single program mode
            runSingleMode();
        } else {
            // Batch mode
            runBatchMode();
        }
    }

    //==========================================================================
    // SINGLE PROGRAM MODE
    //==========================================================================

    private void runSingleMode() throws Exception {
        activeProgram = currentProgram;

        String programName = activeProgram.getName();
        String programPath = activeProgram.getExecutablePath();

        println("Mode: Single Program");
        println("Program: " + programName);
        println("Path: " + programPath);

        // Skip PD2 (expansion mod - not currently supported)
        if (programPath.contains("PD2") || programPath.toUpperCase().contains("\\PD2\\")) {
            println("ERROR: PD2 programs are currently not supported. Skipping.");
            println("=".repeat(70));
            return;
        }

        // Parse version from path: /F:/D2VersionChanger/VersionChanger/LoD/1.07/file.dll
        String[] pathParts = programPath.replace("\\", "/").split("/");
        String gameType = "Unknown";
        String version = "Unknown";
        String fileName = programName;

        // Find VersionChanger in path to extract game type and version
        for (int i = 0; i < pathParts.length - 2; i++) {
            if (pathParts[i].equals("VersionChanger")) {
                if (i + 2 < pathParts.length) {
                    gameType = pathParts[i + 1];
                    version = pathParts[i + 2];

                    // If gameType is a version number, detect game type from version
                    if (gameType.matches("\\d+\\.\\d+.*")) {
                        version = gameType;
                        gameType = detectGameType(version);
                    }
                }
                break;
            }
        }

        println("Game Type: " + gameType);
        println("Version: " + version);

        // Output path
        File outputDir = new File("F:/D2VersionChanger/data/function_index/" + gameType + "/" + version);
        outputDir.mkdirs();
        File outputFile = new File(outputDir, fileName + ".json");

        println("Output: " + outputFile.getAbsolutePath());
        println("=".repeat(70));

        // Initialize per-program state
        stringRefCounts = new HashMap<>();
        importMap = new HashMap<>();
        exportOrdinalMap = new HashMap<>();

        // Phase 1: Build import map, export ordinal map, and count string references
        println("\nPhase 1: Analyzing imports, exports, and string references...");
        buildImportMap();
        buildExportOrdinalMap();
        countStringReferences();

        // Phase 2: Process all functions
        println("\nPhase 2: Processing functions...");
        List<FunctionData> functions = processFunctions();

        // Phase 3: Write output
        println("\nPhase 3: Writing output...");
        writeOutput(outputFile, gameType, version, functions);

        // Summary
        println("\n" + "=".repeat(70));
        println("EXPORT COMPLETE");
        println("=".repeat(70));
        println("Total functions: " + functions.size());

        int named = 0, withStrings = 0, withApis = 0, exported = 0, withTags = 0;
        int withParams = 0, withConstants = 0, withGlobals = 0;
        int totalStrings = 0, totalParams = 0, totalConstants = 0, totalGlobals = 0;
        int typeExport = 0, typeOrdinal = 0, typeThunk = 0, typeEntry = 0, typeInternal = 0, typeExternal = 0;
        for (FunctionData f : functions) {
            if (f.hasHumanName) named++;
            if (f.stringRefs.size() > 0) { withStrings++; totalStrings += f.stringRefs.size(); }
            if (f.apiCalls.size() > 0) withApis++;
            if (f.exportOrdinal >= 0) exported++;
            if (f.tags.size() > 0) withTags++;
            if (f.parameters.size() > 0) { withParams++; totalParams += f.parameters.size(); }
            if (f.constants.size() > 0) { withConstants++; totalConstants += f.constants.size(); }
            if (f.globals.size() > 0) { withGlobals++; totalGlobals += f.globals.size(); }
            // Count by function type
            if ("export".equals(f.functionType)) typeExport++;
            else if ("ordinal".equals(f.functionType)) typeOrdinal++;
            else if ("thunk".equals(f.functionType)) typeThunk++;
            else if ("entry".equals(f.functionType)) typeEntry++;
            else if ("internal".equals(f.functionType)) typeInternal++;
            else if ("external".equals(f.functionType)) typeExternal++;
        }

        println("  Named (human): " + named);
        println("  With strings: " + withStrings + " (" + totalStrings + " total refs)");
        println("  With parameters: " + withParams + " (" + totalParams + " total params)");
        println("  With constants: " + withConstants + " (" + totalConstants + " total constants)");
        println("  With globals: " + withGlobals + " (" + totalGlobals + " total globals)");
        println("  With API calls: " + withApis);
        println("  Exported: " + exported);
        println("  With tags: " + withTags);
        println("  By type:");
        println("    - export: " + typeExport);
        println("    - ordinal: " + typeOrdinal);
        println("    - thunk: " + typeThunk);
        println("    - entry: " + typeEntry);
        println("    - internal: " + typeInternal);
        if (typeExternal > 0) println("    - external: " + typeExternal);
        println("Output: " + outputFile.getAbsolutePath());
    }

    //==========================================================================
    // BATCH MODE (ALL PROGRAMS)
    //==========================================================================

    private void runBatchMode() throws Exception {
        println("Mode: Batch (All Programs)");

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
                "This will export function index data for " + totalFiles + " programs.\n" +
                "This may take a while. Continue?")) {
            println("Export cancelled by user.");
            return;
        }

        long startTime = System.currentTimeMillis();

        // Process all folders recursively
        processFolder(rootFolder, "");

        long elapsed = (System.currentTimeMillis() - startTime) / 1000;

        // Summary
        println("");
        println("=".repeat(70));
        println("BATCH EXPORT COMPLETE");
        println("=".repeat(70));
        println("Successfully processed: " + totalProcessed + " programs");
        println("Total functions exported: " + totalFunctions);
        println("Failed: " + totalFailed);
        println("Elapsed time: " + elapsed + " seconds");

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

        for (DomainFile file : folder.getFiles()) {
            String contentType = file.getContentType();
            if (contentType.equals("Program")) {
                count++;
            }
        }

        for (DomainFolder subfolder : folder.getFolders()) {
            count += countProgramFiles(subfolder);
        }

        return count;
    }

    private void processFolder(DomainFolder folder, String path) throws Exception {
        String currentPath = path.isEmpty() ? folder.getName() : path + "/" + folder.getName();

        if (folder.getParent() == null) {
            currentPath = "";
        }

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

            // Skip PD2 (expansion) - only process Classic and LoD
            if (filePath.contains("PD2") || currentPath.contains("PD2")) {
                println("Skipping PD2 program: " + filePath);
                continue;
            }

            processBatchProgram(file, filePath);
        }

        for (DomainFolder subfolder : folder.getFolders()) {
            if (monitor.isCancelled()) {
                return;
            }

            if (subfolder.getName().equals("PD2")) {
                println("Skipping PD2 folder");
                continue;
            }

            processFolder(subfolder, currentPath);
        }
    }

    private void processBatchProgram(DomainFile file, String projectPath) {
        activeProgram = null;

        try {
            println("");
            println("-".repeat(50));
            println("Processing: " + projectPath);

            // Open the program (read-only)
            activeProgram = (Program) file.getDomainObject(this, false, false, monitor);

            if (activeProgram == null) {
                throw new Exception("Failed to open program");
            }

            // Parse version from project path
            String[] pathParts = projectPath.split("/");
            String gameType = "Unknown";
            String version = "Unknown";
            String programName = file.getName();

            if (pathParts.length >= 3) {
                gameType = pathParts[0];
                version = pathParts[1];
            } else if (pathParts.length == 2) {
                version = pathParts[0];
                gameType = detectGameType(version);
            }

            println("  Game Type: " + gameType);
            println("  Version: " + version);

            // Create output directory
            File outputDir = new File("F:/D2VersionChanger/data/function_index/" + gameType + "/" + version);
            outputDir.mkdirs();
            File outputFile = new File(outputDir, programName + ".json");

            // Reset per-program state
            stringRefCounts = new HashMap<>();
            importMap = new HashMap<>();
            exportOrdinalMap = new HashMap<>();

            // Phase 1
            monitor.setMessage("Analyzing " + programName + ": imports...");
            buildImportMap();

            monitor.setMessage("Analyzing " + programName + ": exports...");
            buildExportOrdinalMap();

            monitor.setMessage("Analyzing " + programName + ": strings...");
            countStringReferences();

            // Phase 2
            monitor.setMessage("Processing " + programName + ": functions...");
            List<FunctionData> functions = processFunctions();

            // Phase 3
            monitor.setMessage("Writing " + programName + ": output...");
            writeOutput(outputFile, gameType, version, functions);

            // Stats
            int named = 0;
            for (FunctionData f : functions) {
                if (f.hasHumanName) named++;
            }

            println("  Functions: " + functions.size() + " (" + named + " named)");
            println("  Output: " + outputFile.getName());

            totalProcessed++;
            totalFunctions += functions.size();

        } catch (Exception e) {
            printerr("  ERROR: " + e.getMessage());
            failedPrograms.add(projectPath + " - " + e.getMessage());
            totalFailed++;
        } finally {
            if (activeProgram != null) {
                activeProgram.release(this);
                activeProgram = null;
            }
        }
    }

    //==========================================================================
    // SHARED HELPER METHODS
    //==========================================================================

    private String detectGameType(String version) {
        if (version == null || version.equals("Unknown")) {
            return "Unknown";
        }

        try {
            String[] versionParts = version.split("\\.");
            if (versionParts.length < 2) {
                return "Unknown";
            }

            int major = Integer.parseInt(versionParts[0]);
            int minor = Integer.parseInt(versionParts[1].replaceAll("[a-zA-Z]", ""));

            if (major == 1) {
                if (minor < 7) {
                    return "Classic";
                } else {
                    return "LoD";
                }
            }
        } catch (Exception e) {
            // Fall through
        }

        return "Unknown";
    }

    private void buildImportMap() throws Exception {
        SymbolTable symTable = activeProgram.getSymbolTable();
        ReferenceManager refMgr = activeProgram.getReferenceManager();

        SymbolIterator extSymbols = symTable.getExternalSymbols();
        while (extSymbols.hasNext()) {
            Symbol sym = extSymbols.next();
            if (sym.getSymbolType() == SymbolType.FUNCTION) {
                ReferenceIterator refIter = refMgr.getReferencesTo(sym.getAddress());
                while (refIter.hasNext()) {
                    Reference ref = refIter.next();
                    importMap.put(ref.getFromAddress(), sym.getName());
                }
            }
        }

        for (Symbol sym : symTable.getAllSymbols(true)) {
            if (sym.isExternalEntryPoint() || sym.getName().startsWith("_imp_")) {
                importMap.put(sym.getAddress(), sym.getName().replace("_imp_", ""));
            }
        }

        println("  Found " + importMap.size() + " import references");
    }

    private void buildExportOrdinalMap() throws Exception {
        SymbolTable symTable = activeProgram.getSymbolTable();
        FunctionManager funcMgr = activeProgram.getFunctionManager();

        int foundCount = 0;

        // Method 1: Look for Ordinal_XXXX named symbols
        SymbolIterator symIter = symTable.getAllSymbols(true);
        while (symIter.hasNext()) {
            Symbol sym = symIter.next();
            String name = sym.getName();

            if (name.startsWith("Ordinal_")) {
                try {
                    int ordinal = Integer.parseInt(name.substring(8));
                    Address addr = sym.getAddress();
                    Function func = funcMgr.getFunctionAt(addr);
                    if (func != null && !exportOrdinalMap.containsKey(addr)) {
                        exportOrdinalMap.put(addr, ordinal);
                        foundCount++;
                    }
                } catch (NumberFormatException e) {
                    // Skip
                }
            }
        }

        // Method 2: Parse plate comments for ordinal info
        FunctionIterator funcIter = funcMgr.getFunctions(true);
        while (funcIter.hasNext()) {
            Function func = funcIter.next();
            Address addr = func.getEntryPoint();

            if (exportOrdinalMap.containsKey(addr)) {
                continue;
            }

            Symbol[] symbols = symTable.getSymbols(addr);
            boolean isExported = false;
            for (Symbol sym : symbols) {
                if (sym.isExternalEntryPoint()) {
                    isExported = true;
                    break;
                }
            }

            if (!isExported) {
                continue;
            }

            // Get plate comment from function
            String plateComment = func.getComment();

            if (plateComment != null) {
                java.util.regex.Pattern pattern = java.util.regex.Pattern.compile(
                    "0x[0-9a-fA-F]+\\s+(\\d+)");
                java.util.regex.Matcher matcher = pattern.matcher(plateComment);
                if (matcher.find()) {
                    try {
                        int ordinal = Integer.parseInt(matcher.group(1));
                        if (ordinal > 0 && ordinal < 100000) {
                            exportOrdinalMap.put(addr, ordinal);
                            foundCount++;
                        }
                    } catch (NumberFormatException e) {
                        // Skip
                    }
                }
            }
        }

        // Method 3: Check all symbols at exported addresses for ordinal aliases
        symIter = symTable.getAllSymbols(true);
        while (symIter.hasNext()) {
            Symbol sym = symIter.next();
            if (sym.isExternalEntryPoint()) {
                Address addr = sym.getAddress();
                if (!exportOrdinalMap.containsKey(addr)) {
                    Symbol[] allSyms = symTable.getSymbols(addr);
                    for (Symbol s : allSyms) {
                        String name = s.getName();
                        if (name.startsWith("Ordinal_")) {
                            try {
                                int ordinal = Integer.parseInt(name.substring(8));
                                exportOrdinalMap.put(addr, ordinal);
                                foundCount++;
                                break;
                            } catch (NumberFormatException e) {
                                // Skip
                            }
                        }
                    }
                }
            }
        }

        println("  Found " + exportOrdinalMap.size() + " export ordinals");
    }

    private void countStringReferences() throws Exception {
        Listing listing = activeProgram.getListing();
        DataIterator dataIter = listing.getDefinedData(true);

        Set<String> allStrings = new HashSet<>();
        while (dataIter.hasNext()) {
            Data data = dataIter.next();
            if (data.hasStringValue()) {
                String str = data.getDefaultValueRepresentation();
                if (str != null && str.length() >= 4) {
                    allStrings.add(str);
                }
            }
        }

        for (String str : allStrings) {
            stringRefCounts.put(str, 0);
        }

        FunctionManager funcMgr = activeProgram.getFunctionManager();
        FunctionIterator funcIter = funcMgr.getFunctions(true);
        while (funcIter.hasNext()) {
            Function func = funcIter.next();
            Set<String> funcStrings = getStringReferences(func);
            for (String str : funcStrings) {
                stringRefCounts.merge(str, 1, Integer::sum);
            }
        }

        int uniqueCount = 0;
        for (int count : stringRefCounts.values()) {
            if (count == 1) uniqueCount++;
        }

        println("  Found " + allStrings.size() + " strings, " + uniqueCount + " unique to single function");
    }

    private Set<String> getStringReferences(Function func) {
        Set<String> strings = new HashSet<>();

        AddressSetView body = func.getBody();
        ReferenceManager refMgr = activeProgram.getReferenceManager();
        Listing listing = activeProgram.getListing();
        long imageBase = activeProgram.getImageBase().getOffset();

        AddressIterator addrIter = body.getAddresses(true);
        while (addrIter.hasNext()) {
            Address addr = addrIter.next();
            Reference[] refs = refMgr.getReferencesFrom(addr);
            for (Reference ref : refs) {
                Address toAddr = ref.getToAddress();
                Data data = listing.getDataAt(toAddr);
                if (data != null && data.hasStringValue()) {
                    Object value = data.getValue();
                    if (value instanceof String) {
                        String str = (String) value;
                        if (str.length() >= 4) {
                            long refRva = toAddr.getOffset() - imageBase;
                            Symbol sym = activeProgram.getSymbolTable().getPrimarySymbol(toAddr);
                            String symName = (sym != null) ? sym.getName() : "";
                            strings.add(String.format("0x%X|%s|%s", refRva, symName, str));
                        }
                    }
                }
            }
        }

        return strings;
    }

    private List<String> getApiCalls(Function func) {
        List<String> apis = new ArrayList<>();

        AddressSetView body = func.getBody();
        ReferenceManager refMgr = activeProgram.getReferenceManager();

        AddressIterator addrIter = body.getAddresses(true);
        while (addrIter.hasNext()) {
            Address addr = addrIter.next();
            Reference[] refs = refMgr.getReferencesFrom(addr);
            for (Reference ref : refs) {
                if (ref.getReferenceType().isCall()) {
                    Address toAddr = ref.getToAddress();
                    String importName = importMap.get(toAddr);
                    if (importName != null) {
                        apis.add(importName);
                    } else {
                        Function calledFunc = activeProgram.getFunctionManager().getFunctionAt(toAddr);
                        if (calledFunc != null && calledFunc.isThunk()) {
                            Function thunkedFunc = calledFunc.getThunkedFunction(false);
                            if (thunkedFunc != null && thunkedFunc.isExternal()) {
                                apis.add(thunkedFunc.getName());
                            }
                        }
                    }
                }
            }
        }

        return apis;
    }

    private String getMnemonicSequence(Function func) {
        StringBuilder mnemonics = new StringBuilder();

        Listing listing = activeProgram.getListing();
        AddressSetView body = func.getBody();

        InstructionIterator instrIter = listing.getInstructions(body, true);
        while (instrIter.hasNext()) {
            Instruction instr = instrIter.next();
            mnemonics.append(instr.getMnemonicString());
            mnemonics.append(";");
        }

        return mnemonics.toString();
    }

    private byte[] getPrologueBytes(Function func, int maxBytes) {
        Address entry = func.getEntryPoint();
        Memory memory = activeProgram.getMemory();

        int bytesToRead = Math.min(maxBytes, (int)func.getBody().getNumAddresses());
        byte[] bytes = new byte[bytesToRead];

        try {
            memory.getBytes(entry, bytes);
        } catch (Exception e) {
            return new byte[0];
        }

        return bytes;
    }

    private int getBasicBlockCount(Function func) {
        try {
            BasicBlockModel bbModel = new BasicBlockModel(activeProgram);
            CodeBlockIterator blocks = bbModel.getCodeBlocksContaining(func.getBody(), monitor);
            int count = 0;
            while (blocks.hasNext()) {
                blocks.next();
                count++;
            }
            return count;
        } catch (Exception e) {
            return 0;
        }
    }

    /**
     * Compute a Normalized OPcode hash that ignores absolute addresses.
     * This mimics the MCP get_function_hash normalization:
     * - Internal jump/call targets → relative offset from function start
     * - External calls → "CALL_EXT"
     * - External data refs → "DATA_EXT"
     * - Large immediates (>0x10000) → "IMM_LARGE"
     * - Small immediates → kept as-is (likely constants)
     * - Registers → kept as-is
     */
    private String computeNormalizedOpcodeHash(Function func) {
        StringBuilder normalized = new StringBuilder();
        long funcStart = func.getEntryPoint().getOffset();
        long imageBase = activeProgram.getImageBase().getOffset();

        try {
            Listing listing = activeProgram.getListing();
            AddressSetView body = func.getBody();
            InstructionIterator instrIter = listing.getInstructions(body, true);

            int instrCount = 0;
            while (instrIter.hasNext() && instrCount < 1000) {
                Instruction instr = instrIter.next();
                instrCount++;

                String mnemonic = instr.getMnemonicString();
                normalized.append(mnemonic);

                // Process operands
                for (int op = 0; op < instr.getNumOperands(); op++) {
                    int opType = instr.getOperandType(op);
                    Object[] opObjs = instr.getOpObjects(op);

                    for (Object obj : opObjs) {
                        if (obj instanceof Scalar) {
                            long val = ((Scalar) obj).getValue();

                            // Check if this is an internal address (jump/call target)
                            if (isInternalAddress(body, val)) {
                                // Normalize to relative offset from function start
                                long relOffset = val - funcStart;
                                normalized.append("_REL_").append(relOffset);
                            } else if (val > 0x10000 && val < 0xFFFFFFFFL) {
                                // Large immediate - likely an address
                                // Check if it's an external reference
                                Address potentialAddr = activeProgram.getAddressFactory().getDefaultAddressSpace().getAddress(val);
                                Function calledFunc = activeProgram.getFunctionManager().getFunctionAt(potentialAddr);

                                if (calledFunc != null && calledFunc.isExternal()) {
                                    normalized.append("_CALL_EXT");
                                } else if (importMap.containsKey(potentialAddr)) {
                                    normalized.append("_CALL_EXT");
                                } else if (isDataReference(potentialAddr)) {
                                    normalized.append("_DATA_EXT");
                                } else {
                                    normalized.append("_IMM_LARGE");
                                }
                            } else {
                                // Small immediate - keep as constant
                                normalized.append("_IMM_").append(val);
                            }
                        } else if (obj instanceof ghidra.program.model.lang.Register) {
                            // Keep register names
                            normalized.append("_REG_").append(((ghidra.program.model.lang.Register) obj).getName());
                        } else if (obj instanceof Address) {
                            Address addr = (Address) obj;
                            if (body.contains(addr)) {
                                // Internal address
                                long relOffset = addr.getOffset() - funcStart;
                                normalized.append("_REL_").append(relOffset);
                            } else {
                                // External address
                                Function calledFunc = activeProgram.getFunctionManager().getFunctionAt(addr);
                                if (calledFunc != null && (calledFunc.isExternal() || calledFunc.isThunk())) {
                                    normalized.append("_CALL_EXT");
                                } else if (importMap.containsKey(addr)) {
                                    normalized.append("_CALL_EXT");
                                } else {
                                    normalized.append("_ADDR_EXT");
                                }
                            }
                        }
                    }
                }
                normalized.append("|");
            }

            // Hash the normalized sequence
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return hashToHex(md.digest(normalized.toString().getBytes("UTF-8")), 32);

        } catch (Exception e) {
            return null;
        }
    }

    private boolean isInternalAddress(AddressSetView body, long addr) {
        try {
            Address potentialAddr = activeProgram.getAddressFactory().getDefaultAddressSpace().getAddress(addr);
            return body.contains(potentialAddr);
        } catch (Exception e) {
            return false;
        }
    }

    private boolean isDataReference(Address addr) {
        try {
            Data data = activeProgram.getListing().getDataAt(addr);
            return data != null;
        } catch (Exception e) {
            return false;
        }
    }

    private void extractEnhancedInstructionData(Function func, FunctionData data, long imageBase) {
        final int MAX_INSTRUCTIONS = 15;
        final int MAX_CONSTANTS = 30;
        final int MAX_GLOBALS = 20;

        try {
            Listing listing = activeProgram.getListing();
            AddressSetView body = func.getBody();
            InstructionIterator instrIter = listing.getInstructions(body, true);

            while (instrIter.hasNext()) {
                Instruction instr = instrIter.next();
                data.instructionCount++;
                long instrAddr = instr.getAddress().getOffset();
                String mnemonic = instr.getMnemonicString();

                // Detect backward jumps (loops)
                if (mnemonic.startsWith("J") || mnemonic.equals("LOOP")) {
                    Reference[] refs = instr.getReferencesFrom();
                    for (Reference ref : refs) {
                        if (ref.getReferenceType().isJump()) {
                            long targetAddr = ref.getToAddress().getOffset();
                            if (targetAddr < instrAddr && body.contains(ref.getToAddress())) {
                                data.loopCount++;
                            }
                        }
                    }
                }

                // Extract constants from operands
                for (int op = 0; op < instr.getNumOperands(); op++) {
                    Object[] opObjs = instr.getOpObjects(op);
                    for (Object obj : opObjs) {
                        if (obj instanceof Scalar) {
                            long val = ((Scalar) obj).getValue();
                            if (val > 0xFF && val < 0x10000000L && data.constants.size() < MAX_CONSTANTS) {
                                long instrRva = instrAddr - imageBase;
                                // Format: address||value (no name for inline constants)
                                data.constants.add(String.format("0x%X||0x%X", instrRva, val));
                            }
                        }
                    }
                }

                // Track global/data references (exclude strings and stack refs)
                Reference[] refs = instr.getReferencesFrom();
                for (Reference ref : refs) {
                    if (ref.getReferenceType().isData() && data.globals.size() < MAX_GLOBALS) {
                        Address toAddr = ref.getToAddress();

                        // Skip stack-space addresses (not real globals)
                        // Check address space and filter out non-memory addresses
                        if (toAddr.getAddressSpace().isStackSpace() ||
                            toAddr.getAddressSpace().isRegisterSpace() ||
                            !toAddr.getAddressSpace().isMemorySpace()) {
                            continue;
                        }
                        // Also filter by raw address - stack refs have pattern 0xFFFFFFFF902A...
                        // or negative addresses (high bit set in 32-bit context)
                        long addrOffset = toAddr.getOffset();
                        if (addrOffset < 0 || addrOffset > 0xFFFFFFFFL) {
                            continue;
                        }

                        if (!body.contains(toAddr)) {
                            Data globalData = listing.getDataAt(toAddr);

                            // Skip string data - already captured in string references
                            if (globalData != null && globalData.hasStringValue()) {
                                continue;
                            }

                            long refRva = toAddr.getOffset() - imageBase;
                            Symbol sym = activeProgram.getSymbolTable().getPrimarySymbol(toAddr);
                            String symName = (sym != null) ? sym.getName() : "";

                            // Get the value at this address
                            String valueStr = "";
                            if (globalData != null) {
                                Object value = globalData.getValue();
                                if (value != null) {
                                    valueStr = value.toString();
                                }
                            }
                            data.globals.add(String.format("0x%X|%s|%s", refRva, symName, valueStr));
                        }
                    }
                }

                // Capture first N instructions with full details
                if (data.instructions.size() < MAX_INSTRUCTIONS) {
                    long instrRva = instrAddr - imageBase;
                    String operands = formatInstructionOperands(instr);
                    data.instructions.add(String.format("0x%X|%s|%s", instrRva, mnemonic, operands));
                }
            }
        } catch (Exception e) {
            // Ignore instruction parsing errors
        }
    }

    private String formatInstructionOperands(Instruction instr) {
        StringBuilder sb = new StringBuilder();
        int numOperands = instr.getNumOperands();
        for (int i = 0; i < numOperands; i++) {
            if (i > 0) sb.append(", ");
            String opStr = instr.getDefaultOperandRepresentation(i);
            sb.append(opStr);
        }
        return sb.toString();
    }

    private List<FunctionData> processFunctions() throws Exception {
        List<FunctionData> functions = new ArrayList<>();

        FunctionManager funcMgr = activeProgram.getFunctionManager();
        SymbolTable symTable = activeProgram.getSymbolTable();
        long imageBase = activeProgram.getImageBase().getOffset();

        FunctionIterator funcIter = funcMgr.getFunctions(true);
        int total = funcMgr.getFunctionCount();
        int processed = 0;

        while (funcIter.hasNext()) {
            if (monitor.isCancelled()) {
                throw new Exception("Cancelled by user");
            }

            Function func = funcIter.next();
            processed++;

            if (processed % 500 == 0) {
                monitor.setMessage("Processing functions: " + processed + "/" + total);
                println("  Processed " + processed + "/" + total + " functions...");
            }

            FunctionData data = new FunctionData();

            // Basic info
            data.address = func.getEntryPoint().getOffset();
            data.rva = data.address - imageBase;
            data.size = (int) func.getBody().getNumAddresses();
            data.name = func.getName();

            // Check if name is human-assigned
            data.hasHumanName = !data.name.startsWith("FUN_") &&
                               !data.name.startsWith("thunk_FUN_") &&
                               !data.name.startsWith("LAB_") &&
                               !data.name.equals("entry");

            // Export ordinal
            Address funcAddr = func.getEntryPoint();
            Integer mapOrdinal = exportOrdinalMap.get(funcAddr);
            if (mapOrdinal != null) {
                data.exportOrdinal = mapOrdinal;
                data.exportName = data.name;
            } else {
                data.exportOrdinal = -1;
                Symbol[] symbols = symTable.getSymbols(funcAddr);
                for (Symbol sym : symbols) {
                    if (sym.isExternalEntryPoint()) {
                        String symName = sym.getName();
                        if (symName.startsWith("Ordinal_")) {
                            try {
                                data.exportOrdinal = Integer.parseInt(symName.substring(8));
                                data.exportName = symName;
                            } catch (NumberFormatException e) {
                                // Skip
                            }
                        }
                        break;
                    }
                }
            }

            // Determine function type and original name
            data.originalName = String.format("FUN_%08x", funcAddr.getOffset());

            if (func.isThunk()) {
                data.functionType = "thunk";
                data.originalName = "thunk_" + data.originalName;
            } else if (func.isExternal()) {
                data.functionType = "external";
            } else if (data.exportOrdinal >= 0) {
                // Has an export ordinal
                if (data.exportName != null && data.exportName.startsWith("Ordinal_")) {
                    data.functionType = "ordinal";
                    data.originalName = data.exportName;
                } else {
                    data.functionType = "export";
                    // Keep originalName as FUN_xxx but we have the real export name
                }
            } else {
                // Check if it's an entry point
                boolean isEntry = false;
                Symbol[] symbols = symTable.getSymbols(funcAddr);
                for (Symbol sym : symbols) {
                    if (sym.isExternalEntryPoint() || sym.getName().equals("entry")) {
                        isEntry = true;
                        break;
                    }
                }
                if (isEntry) {
                    data.functionType = "entry";
                } else {
                    data.functionType = "internal";
                }
            }

            // String references (only unique ones for index)
            Set<String> allStrings = getStringReferences(func);
            for (String str : allStrings) {
                Integer count = stringRefCounts.get(str);
                if (count != null && count == 1) {
                    data.uniqueStrings.add(str);
                }
            }
            data.stringRefs = allStrings;

            // API calls
            data.apiCalls = getApiCalls(func);

            // Mnemonic sequence
            data.mnemonicSeq = getMnemonicSequence(func);

            // Prologue bytes
            data.prologueBytes = getPrologueBytes(func, 16);

            // Basic block count
            data.basicBlockCount = getBasicBlockCount(func);

            // NOP (Normalized OPcode) index - computed before other indexes
            data.nopIndex = computeNormalizedOpcodeHash(func);

            // Signature and metadata
            data.signature = func.getSignature().getPrototypeString();
            data.callingConvention = func.getCallingConventionName();
            data.comment = func.getComment();

            // Return type
            try {
                data.returnType = func.getReturnType().getDisplayName();
            } catch (Exception e) {
                data.returnType = "void";
            }

            // Parameters
            for (Parameter p : func.getParameters()) {
                ParamData pd = new ParamData();
                pd.name = p.getName();
                pd.type = p.getDataType().getName();
                pd.storage = p.getVariableStorage().toString();
                data.parameters.add(pd);
            }

            // Local variable count
            try {
                Variable[] locals = func.getLocalVariables();
                data.localVarCount = locals.length;
            } catch (Exception e) {
                // Ignore
            }

            // Stack frame size
            try {
                StackFrame frame = func.getStackFrame();
                if (frame != null) {
                    data.stackFrameSize = frame.getFrameSize();
                }
            } catch (Exception e) {
                // Ignore
            }

            // Function tags
            try {
                Set<ghidra.program.model.listing.FunctionTag> funcTags = func.getTags();
                for (ghidra.program.model.listing.FunctionTag tag : funcTags) {
                    data.tags.add(tag.getName());
                }
            } catch (Exception e) {
                // Ignore - tags not available
            }

            // Enhanced instruction analysis
            extractEnhancedInstructionData(func, data, imageBase);

            // Callees
            try {
                Set<Function> calledFuncs = func.getCalledFunctions(monitor);
                for (Function callee : calledFuncs) {
                    if (data.callees.size() >= 50) break;
                    String calleeName = callee.getName();
                    long calleeAddr = callee.getEntryPoint().getOffset();
                    data.callees.add(String.format("%s|0x%X", calleeName, calleeAddr));
                }
            } catch (Exception e) {
                // Ignore
            }

            // Callers
            try {
                Set<Function> callingFuncs = func.getCallingFunctions(monitor);
                for (Function caller : callingFuncs) {
                    if (data.callers.size() >= 50) break;
                    String callerName = caller.getName();
                    long callerAddr = caller.getEntryPoint().getOffset();
                    data.callers.add(String.format("%s|0x%X", callerName, callerAddr));
                }
            } catch (Exception e) {
                // Ignore
            }

            // Compute indexes
            computeIndexes(data);

            functions.add(data);
        }

        return functions;
    }

    private void computeIndexes(FunctionData data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");

        // EXP index
        if (data.exportOrdinal >= 0) {
            data.expIndex = String.valueOf(data.exportOrdinal);
        }

        // STR index
        if (!data.uniqueStrings.isEmpty()) {
            List<String> sorted = new ArrayList<>(data.uniqueStrings);
            Collections.sort(sorted);
            String combined = String.join("|", sorted);
            data.strIndex = hashToHex(md.digest(combined.getBytes("UTF-8")), 16);
        }

        // API index
        if (data.apiCalls.size() >= 1) {
            String combined = String.join("|", data.apiCalls);
            data.apiIndex = hashToHex(md.digest(combined.getBytes("UTF-8")), 16);
        }

        // MNE index
        if (!data.mnemonicSeq.isEmpty()) {
            String combined = data.mnemonicSeq + "|" + data.size;
            data.mneIndex = hashToHex(md.digest(combined.getBytes("UTF-8")), 16);
        }

        // NOP index (computed separately - stored in data.nopIndex already)

        // CFG index - Enhanced with more discriminators to reduce collisions
        // Includes: block count, loop count, instruction count, callee count,
        // param count, return type category, and branch pattern
        if (data.basicBlockCount >= 1) {
            // Extract branch pattern from instructions (J*, CALL, RET sequence)
            StringBuilder branchPattern = new StringBuilder();
            for (String instr : data.instructions) {
                String[] parts = instr.split("\\|");
                if (parts.length >= 2) {
                    String mnemonic = parts[1];
                    if (mnemonic.startsWith("J") || mnemonic.equals("CALL") ||
                        mnemonic.equals("RET") || mnemonic.equals("RETN") ||
                        mnemonic.equals("LOOP")) {
                        if (branchPattern.length() > 0) branchPattern.append("|");
                        branchPattern.append(mnemonic);
                    }
                }
            }

            // Categorize return type
            String retCategory;
            if (data.returnType.contains("*") || data.returnType.toLowerCase().contains("pointer")) {
                retCategory = "ptr";
            } else if (data.returnType.equals("void") || data.returnType.equals("undefined")) {
                retCategory = "void";
            } else if (data.returnType.matches("(?i)int|uint|long|ulong|dword|DWORD|short|ushort|byte|char")) {
                retCategory = "int";
            } else {
                retCategory = "other";
            }

            // Build comprehensive CFG signature
            String combined = data.basicBlockCount + "|" +
                             data.loopCount + "|" +
                             data.instructionCount + "|" +
                             data.callees.size() + "|" +
                             data.parameters.size() + "|" +
                             retCategory + "|" +
                             branchPattern.toString();
            data.cfgIndex = hashToHex(md.digest(combined.getBytes("UTF-8")), 16);
        }

        // PRO index
        if (data.prologueBytes.length > 0) {
            md.update(data.prologueBytes);
            md.update(String.valueOf(data.size).getBytes("UTF-8"));
            data.proIndex = hashToHex(md.digest(), 16);
        }

        // CAL index - sorted human-named callee functions (stable across versions)
        List<String> namedCallees = new ArrayList<>();
        for (String callee : data.callees) {
            String calleeName = callee.split("\\|")[0];
            // Only include human-assigned names, not FUN_ or thunk_FUN_
            if (!calleeName.startsWith("FUN_") && !calleeName.startsWith("thunk_FUN_") &&
                !calleeName.isEmpty()) {
                namedCallees.add(calleeName);
            }
        }
        if (namedCallees.size() >= 2) {
            Collections.sort(namedCallees);
            String combined = String.join("|", namedCallees);
            data.calIndex = hashToHex(md.digest(combined.getBytes("UTF-8")), 16);
        }

        // CON index - sorted significant constants (magic numbers stable across versions)
        // Constants are stored as "address||value" - extract just the values for hashing
        List<Long> sigConstants = new ArrayList<>();
        for (String constStr : data.constants) {
            String[] parts = constStr.split("\\|\\|");
            if (parts.length >= 2) {
                try {
                    long c = Long.parseLong(parts[1].replace("0x", ""), 16);
                    // Filter: > 255 (not small immediates) and < 0x10000000 (not addresses)
                    if (c > 255 && c < 0x10000000L) {
                        sigConstants.add(c);
                    }
                } catch (NumberFormatException e) {
                    // Skip malformed constants
                }
            }
        }
        if (sigConstants.size() >= 2) {
            Collections.sort(sigConstants);
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < sigConstants.size(); i++) {
                if (i > 0) sb.append("|");
                sb.append(sigConstants.get(i));
            }
            data.conIndex = hashToHex(md.digest(sb.toString().getBytes("UTF-8")), 16);
        }

        // APS index - sorted API calls (order-independent, better for minor reorderings)
        if (data.apiCalls.size() >= 2) {
            List<String> sortedApis = new ArrayList<>(data.apiCalls);
            Collections.sort(sortedApis);
            String combined = String.join("|", sortedApis);
            data.apsIndex = hashToHex(md.digest(combined.getBytes("UTF-8")), 16);
        }

        // Select best index
        // Priority: STR > NOP > CAL > API > CON > MNE > CFG > PRO > EXP > ADDR
        // NOTE: EXP demoted to last because ordinals change between D2 versions
        // STR: Unique strings (99% reliable but rare)
        // NOP: Normalized opcode hash (98% reliable for unchanged functions)
        // CAL: Sorted callee names (95% reliable - function names are stable)
        // API: API call sequence (90% reliable - order can change)
        // CON: Sorted constants (85% reliable - magic numbers are stable)
        // MNE: Mnemonic sequence (80% reliable - compiler variations)
        // CFG: Block count + size (70% reliable)
        // PRO: Prologue bytes (60% reliable)
        // EXP: Export ordinal (50% - NOT reliable for cross-version matching)
        if (data.strIndex != null) {
            data.bestIndex = "STR:" + data.strIndex;
            data.bestMethod = "STR";
        } else if (data.nopIndex != null) {
            data.bestIndex = "NOP:" + data.nopIndex;
            data.bestMethod = "NOP";
        } else if (data.calIndex != null) {
            data.bestIndex = "CAL:" + data.calIndex;
            data.bestMethod = "CAL";
        } else if (data.apiIndex != null) {
            data.bestIndex = "API:" + data.apiIndex;
            data.bestMethod = "API";
        } else if (data.conIndex != null) {
            data.bestIndex = "CON:" + data.conIndex;
            data.bestMethod = "CON";
        } else if (data.mneIndex != null) {
            data.bestIndex = "MNE:" + data.mneIndex;
            data.bestMethod = "MNE";
        } else if (data.cfgIndex != null) {
            data.bestIndex = "CFG:" + data.cfgIndex;
            data.bestMethod = "CFG";
        } else if (data.proIndex != null) {
            data.bestIndex = "PRO:" + data.proIndex;
            data.bestMethod = "PRO";
        } else if (data.expIndex != null) {
            // EXP last (before ADDR) - ordinals NOT reliable across versions
            data.bestIndex = "EXP:" + data.expIndex;
            data.bestMethod = "EXP";
        } else {
            data.bestIndex = "ADDR:" + String.format("%08X", data.rva);
            data.bestMethod = "ADDR";
        }

        // Display name
        if (data.hasHumanName) {
            data.displayName = data.name;
        } else {
            data.displayName = data.bestMethod + "_" +
                (data.bestIndex.length() > 20 ?
                    data.bestIndex.substring(data.bestIndex.indexOf(':') + 1, Math.min(data.bestIndex.length(), 20)) :
                    data.bestIndex.substring(data.bestIndex.indexOf(':') + 1));
        }
    }

    private String hashToHex(byte[] hash, int length) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < Math.min(hash.length, length); i++) {
            sb.append(String.format("%02x", hash[i]));
        }
        return sb.toString();
    }

    private void writeOutput(File outputFile, String gameType, String version,
                            List<FunctionData> functions) throws Exception {
        long imageBase = activeProgram.getImageBase().getOffset();

        try (PrintWriter writer = new PrintWriter(new OutputStreamWriter(
                new FileOutputStream(outputFile), "UTF-8"))) {

            writer.println("{");
            writer.println("  \"program_name\": \"" + escapeJson(activeProgram.getName()) + "\",");
            writer.println("  \"game_type\": \"" + escapeJson(gameType) + "\",");
            writer.println("  \"version\": \"" + escapeJson(version) + "\",");
            writer.println("  \"image_base\": \"" + String.format("0x%08X", imageBase) + "\",");
            writer.println("  \"total_functions\": " + functions.size() + ",");
            writer.println("  \"export_timestamp\": \"" + new java.util.Date().toString() + "\",");
            writer.println("  \"functions\": [");

            for (int i = 0; i < functions.size(); i++) {
                FunctionData f = functions.get(i);

                writer.println("    {");

                // === IDENTITY ===
                writer.println("      \"address\": \"" + String.format("0x%08X", f.address) + "\",");
                writer.println("      \"rva\": \"" + String.format("0x%X", f.rva) + "\",");
                writer.println("      \"size\": " + f.size + ",");
                writer.println("      \"name\": \"" + escapeJson(f.name) + "\",");
                writer.println("      \"display_name\": \"" + escapeJson(f.displayName) + "\",");
                writer.println("      \"original_name\": \"" + escapeJson(f.originalName) + "\",");
                writer.println("      \"has_human_name\": " + f.hasHumanName + ",");
                writer.println("      \"function_type\": \"" + escapeJson(f.functionType) + "\",");

                // === SIGNATURE & TYPE INFO ===
                writer.println("      \"signature\": \"" + escapeJson(f.signature) + "\",");
                writer.println("      \"calling_convention\": \"" + escapeJson(f.callingConvention) + "\",");
                writer.println("      \"return_type\": \"" + escapeJson(f.returnType) + "\",");

                // === INDEXES (for cross-version matching) ===
                writer.println("      \"index\": \"" + escapeJson(f.bestIndex) + "\",");
                writer.println("      \"index_method\": \"" + f.bestMethod + "\",");
                writer.println("      \"indexes\": {");
                writer.println("        \"EXP\": " + (f.expIndex != null ? "\"" + escapeJson(f.expIndex) + "\"" : "null") + ",");
                writer.println("        \"STR\": " + (f.strIndex != null ? "\"" + escapeJson(f.strIndex) + "\"" : "null") + ",");
                writer.println("        \"NOP\": " + (f.nopIndex != null ? "\"" + escapeJson(f.nopIndex) + "\"" : "null") + ",");
                writer.println("        \"CAL\": " + (f.calIndex != null ? "\"" + escapeJson(f.calIndex) + "\"" : "null") + ",");
                writer.println("        \"API\": " + (f.apiIndex != null ? "\"" + escapeJson(f.apiIndex) + "\"" : "null") + ",");
                writer.println("        \"APS\": " + (f.apsIndex != null ? "\"" + escapeJson(f.apsIndex) + "\"" : "null") + ",");
                writer.println("        \"CON\": " + (f.conIndex != null ? "\"" + escapeJson(f.conIndex) + "\"" : "null") + ",");
                writer.println("        \"MNE\": " + (f.mneIndex != null ? "\"" + escapeJson(f.mneIndex) + "\"" : "null") + ",");
                writer.println("        \"CFG\": " + (f.cfgIndex != null ? "\"" + escapeJson(f.cfgIndex) + "\"" : "null") + ",");
                writer.println("        \"PRO\": " + (f.proIndex != null ? "\"" + escapeJson(f.proIndex) + "\"" : "null") + "");
                writer.println("      },");

                // === STRUCTURE METRICS ===
                writer.println("      \"instruction_count\": " + f.instructionCount + ",");
                writer.println("      \"basic_block_count\": " + f.basicBlockCount + ",");
                writer.println("      \"loop_count\": " + f.loopCount + ",");
                writer.println("      \"stack_frame_size\": " + f.stackFrameSize + ",");
                writer.println("      \"local_var_count\": " + f.localVarCount + ",");

                // === PARAMETERS (count + list) ===
                writer.println("      \"param_count\": " + f.parameters.size() + ",");
                writer.print("      \"parameters\": [");
                for (int j = 0; j < f.parameters.size(); j++) {
                    ParamData p = f.parameters.get(j);
                    if (j > 0) writer.print(", ");
                    writer.print("{\"name\": \"" + escapeJson(p.name) + "\", ");
                    writer.print("\"type\": \"" + escapeJson(p.type) + "\", ");
                    writer.print("\"storage\": \"" + escapeJson(p.storage) + "\"}");
                }
                writer.println("],");

                // === CALL GRAPH (counts + lists) ===
                writer.println("      \"callee_count\": " + f.callees.size() + ",");
                writer.print("      \"callees\": [");
                for (int j = 0; j < Math.min(f.callees.size(), 20); j++) {
                    if (j > 0) writer.print(", ");
                    writer.print("\"" + escapeJson(f.callees.get(j)) + "\"");
                }
                if (f.callees.size() > 20) {
                    writer.print(", \"...+" + (f.callees.size() - 20) + " more\"");
                }
                writer.println("],");

                writer.println("      \"caller_count\": " + f.callers.size() + ",");
                writer.print("      \"callers\": [");
                for (int j = 0; j < Math.min(f.callers.size(), 20); j++) {
                    if (j > 0) writer.print(", ");
                    writer.print("\"" + escapeJson(f.callers.get(j)) + "\"");
                }
                if (f.callers.size() > 20) {
                    writer.print(", \"...+" + (f.callers.size() - 20) + " more\"");
                }
                writer.println("],");

                // === STRING REFERENCES (count + list) ===
                writer.println("      \"string_count\": " + f.stringRefs.size() + ",");
                writer.print("      \"strings\": [");
                int strIdx = 0;
                for (String str : f.stringRefs) {
                    if (strIdx > 0) writer.print(", ");
                    writer.print("\"" + escapeJson(str) + "\"");
                    strIdx++;
                }
                writer.println("],");

                // === CONSTANTS (count + list) ===
                writer.println("      \"constant_count\": " + f.constants.size() + ",");
                writer.print("      \"constants\": [");
                int constIdx = 0;
                for (String c : f.constants) {
                    if (constIdx > 0) writer.print(", ");
                    writer.print("\"" + escapeJson(c) + "\"");
                    constIdx++;
                }
                writer.println("],");

                // === GLOBALS (count + list) ===
                writer.println("      \"global_count\": " + f.globals.size() + ",");
                writer.print("      \"globals\": [");
                int globIdx = 0;
                for (String g : f.globals) {
                    if (globIdx > 0) writer.print(", ");
                    writer.print("\"" + escapeJson(g) + "\"");
                    globIdx++;
                }
                writer.println("],");

                // === API CALLS (count + list) ===
                writer.println("      \"api_count\": " + f.apiCalls.size() + ",");
                writer.print("      \"api_calls\": [");
                for (int j = 0; j < Math.min(f.apiCalls.size(), 10); j++) {
                    if (j > 0) writer.print(", ");
                    writer.print("\"" + escapeJson(f.apiCalls.get(j)) + "\"");
                }
                if (f.apiCalls.size() > 10) {
                    writer.print(", \"...+" + (f.apiCalls.size() - 10) + " more\"");
                }
                writer.println("],");

                // === INSTRUCTIONS (first N for prologue comparison) ===
                writer.print("      \"instructions\": [");
                for (int j = 0; j < f.instructions.size(); j++) {
                    if (j > 0) writer.print(", ");
                    writer.print("\"" + escapeJson(f.instructions.get(j)) + "\"");
                }
                writer.println("],");

                // === METADATA ===
                writer.println("      \"comment\": \"" + escapeJson(f.comment != null ? f.comment : "") + "\",");
                writer.print("      \"tags\": [");
                for (int j = 0; j < f.tags.size(); j++) {
                    if (j > 0) writer.print(", ");
                    writer.print("\"" + escapeJson(f.tags.get(j)) + "\"");
                }
                writer.println("]");

                writer.print("    }");
                if (i < functions.size() - 1) {
                    writer.println(",");
                } else {
                    writer.println();
                }
            }

            writer.println("  ]");
            writer.println("}");
        }
    }

    private String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    // Data classes
    class FunctionData {
        long address;
        long rva;
        int size;
        String name;
        String displayName;
        boolean hasHumanName;

        // Function classification
        String functionType;    // "export", "ordinal", "thunk", "entry", "internal"
        String originalName;    // Original auto-generated name (FUN_XXXX or Ordinal_XXXX)

        int exportOrdinal = -1;
        String exportName;

        Set<String> stringRefs = new HashSet<>();
        Set<String> uniqueStrings = new HashSet<>();
        List<String> apiCalls = new ArrayList<>();
        String mnemonicSeq;
        byte[] prologueBytes;
        int basicBlockCount;

        String signature;
        String callingConvention;
        String comment;
        String returnType = "void";
        List<ParamData> parameters = new ArrayList<>();

        int instructionCount = 0;
        int localVarCount = 0;
        int stackFrameSize = 0;
        int loopCount = 0;
        List<String> instructions = new ArrayList<>();
        List<String> callees = new ArrayList<>();
        List<String> callers = new ArrayList<>();
        Set<String> constants = new LinkedHashSet<>();
        Set<String> globals = new LinkedHashSet<>();

        String expIndex;
        String strIndex;
        String apiIndex;
        String mneIndex;
        String cfgIndex;
        String proIndex;

        // New indexes for improved matching
        String calIndex;    // Sorted callee names hash (stable across versions)
        String conIndex;    // Sorted constants hash (magic numbers stable)
        String apsIndex;    // Sorted API calls hash (order-independent)
        String nopIndex;    // Normalized OPcode hash (address-independent, like MCP)

        String bestIndex;
        String bestMethod;

        // Function tags
        List<String> tags = new ArrayList<>();
    }

    class ParamData {
        String name;
        String type;
        String storage;
    }
}
