// BSim Step 1 Add Program
//
// Primary ingestion script that handles both program import and signature generation in a single pass. Supports folder structure parsing for version detection and batch processing of multiple programs.
//
// Usage: Run from Script Manager. Supports single program, all programs, or version-filtered processing.
// Output: Populates BSim database with executable records and function signatures.
//
// @author Ben Ethington
// @category Diablo 2.Analysis
// @description Add programs to BSim database with full ingestion
// @menupath Diablo 2.Analysis.BSim Step 1 Add Program

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.util.exception.CancelledException;
import ghidra.framework.model.*;
import ghidra.program.database.ProgramDB;
import ghidra.base.project.GhidraProject;
import java.util.*;
import java.sql.*;
import java.util.regex.*;

public class Analyze_BSimStep1_AddProgram extends GhidraScript {

    // Resolved credentials (loaded from db.env)
    private String dbUrl;
    private String dbUser;
    private String dbPass;

    private void loadDbConfig() throws Exception {
        String host = "";  // no default: set BSIM_DB_HOST in db.env (see db.env.example)
        String port = "5432";
        String dbName = "bsim";
        dbUser = "";  // no default: set BSIM_DB_USER in db.env
        dbPass = "";

        String scriptDir = getSourceFile().getParentFile().getAbsolutePath();
        java.io.File envFile = new java.io.File(scriptDir, "db.env");

        if (envFile.exists()) {
            println("Loading database config from db.env");
            try (java.io.BufferedReader reader = new java.io.BufferedReader(new java.io.FileReader(envFile))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    line = line.trim();
                    if (line.isEmpty() || line.startsWith("#")) continue;
                    int eq = line.indexOf('=');
                    if (eq <= 0) continue;
                    String key = line.substring(0, eq).trim();
                    String value = line.substring(eq + 1).trim();
                    switch (key) {
                        case "BSIM_DB_HOST": host = value; break;
                        case "BSIM_DB_PORT": port = value; break;
                        case "BSIM_DB_NAME": dbName = value; break;
                        case "BSIM_DB_USER": dbUser = value; break;
                        case "BSIM_DB_PASSWORD": dbPass = value; break;
                    }
                }
            }
        } else {
            throw new Exception("ERROR: db.env not found at " + envFile.getAbsolutePath() +
                ". Create this file with BSIM_DB_HOST, BSIM_DB_PORT, BSIM_DB_NAME, BSIM_DB_USER, BSIM_DB_PASSWORD.");
        }

        dbUrl = "jdbc:postgresql://" + host + ":" + port + "/" + dbName;
        println("Database: " + dbUrl + " (user: " + dbUser + ")");
    }

    // Version code mapping: version string -> numeric code
    // Format: major*1000 + minor*10 + patch_letter_offset
    // These values match game_versions.id in the database (FK: exetable.game_version -> game_versions.id)
    private static final java.util.Map<String, Integer> VERSION_CODES = new java.util.HashMap<String, Integer>() {{
        put("1.00",  1000); put("1.01",  1010); put("1.02",  1020); put("1.03",  1030);
        put("1.04",  1040); put("1.04b", 1041); put("1.04c", 1042);
        put("1.05",  1050); put("1.05b", 1051);
        put("1.06",  1060); put("1.06b", 1061);
        put("1.07",  1070); put("1.08",  1080);
        put("1.09",  1090); put("1.09b", 1091); put("1.09d", 1093);
        put("1.10",  1100); put("1.10s", 1101);
        put("1.11",  1110); put("1.11b", 1111);
        put("1.12",  1120); put("1.12a", 1121);
        put("1.13",  1130); put("1.13c", 1132); put("1.13d", 1133);
        put("1.14",  1140); put("1.14a", 1141); put("1.14b", 1142); put("1.14c", 1143); put("1.14d", 1144);
    }};

    // Known valid Diablo 2 versions (for validation display)
    private static final String[] VALID_GAME_VERSIONS = VERSION_CODES.keySet().toArray(new String[0]);

    // Valid version families (ONLY official Diablo 2 releases)
    // All versions use "vanilla" family in the unified folder structure
    private static final String[] VALID_VERSION_FAMILIES = {"vanilla"};

    // Processing mode
    private static final String MODE_SINGLE = "Single Program (current)";
    private static final String MODE_ALL = "All Programs in Project";
    private static final String MODE_VERSION = "Programs by Version Filter";

    // Processing modes for handling existing executables
    private enum ProcessingMode {
        UPDATE_ALL,     // Process all binaries, updating existing ones
        ADD_MISSING,    // Only process binaries not yet in database
        ASK_INDIVIDUAL, // Prompt individually for each binary
        CANCELLED       // User cancelled operation
    }

    private ProcessingMode processingMode = ProcessingMode.ASK_INDIVIDUAL;
    
    // Current version info for the program being processed (used by helper methods)
    private UnifiedVersionInfo currentVersionInfo = null;

    // Helper class for unified version parsing
    private static class UnifiedVersionInfo {
        String gameVersion = null;
        String familyType = "vanilla";
        boolean isException = false;
        String detectionMethod = "unknown";

        UnifiedVersionInfo(String executableName, String projectPath) {
            // Try folder structure parsing first (preferred method)
            if (parseFromFolderStructure(projectPath)) {
                detectionMethod = "folder_structure";
                return;
            }

            // Fallback to filename parsing
            parseUnifiedName(executableName);
            if (gameVersion != null) {
                detectionMethod = "filename";
            } else {
                detectionMethod = "fallback";
                familyType = "vanilla";
                gameVersion = "Unknown";
            }
        }

        // Legacy constructor for backward compatibility
        UnifiedVersionInfo(String executableName) {
            this(executableName, null);
        }

        private void parseUnifiedName(String executableName) {
            if (executableName == null || executableName.isEmpty()) return;

            // Extract version from unified naming convention
            // Standard binaries: 1.03_D2Game.dll -> version: 1.03, family: vanilla
            Pattern standardPattern = Pattern.compile("^(1\\.[0-9]+[a-zA-Z]?)_([A-Za-z0-9_]+)\\.(dll|exe)$", Pattern.CASE_INSENSITIVE);
            Matcher standardMatcher = standardPattern.matcher(executableName);

            if (standardMatcher.matches()) {
                gameVersion = standardMatcher.group(1).toLowerCase();  // Normalize to lowercase
                familyType = "vanilla";
                isException = false;
                return;
            }

            // Legacy exception binaries: Classic_1.03_Game.exe or LoD_1.03_Game.exe -> version: 1.03, family: vanilla
            Pattern exceptionPattern = Pattern.compile("^(Classic|LoD|vanilla)_(1\\.[0-9]+[a-zA-Z]?)_(Game|Diablo_II)\\.(exe|dll)$", Pattern.CASE_INSENSITIVE);
            Matcher exceptionMatcher = exceptionPattern.matcher(executableName);

            if (exceptionMatcher.matches()) {
                familyType = "vanilla";
                gameVersion = exceptionMatcher.group(2).toLowerCase();  // Normalize to lowercase
                isException = true;
                return;
            }

            // Fallback: try to extract version from filename
            Pattern versionPattern = Pattern.compile("(1\\.[0-9]+[a-zA-Z]?)", Pattern.CASE_INSENSITIVE);
            Matcher versionMatcher = versionPattern.matcher(executableName);
            if (versionMatcher.find()) {
                gameVersion = versionMatcher.group(1).toLowerCase();  // Normalize to lowercase
                familyType = "vanilla";
            }
        }

        /**
         * Parse version and family information from folder structure
         * Expected structure: /vanilla/1.01/, /vanilla/1.07/, or just /1.04b/
         */
        private boolean parseFromFolderStructure(String projectPath) {
            if (projectPath == null || projectPath.isEmpty()) {
                return false;
            }

            // Normalize path separators and remove leading/trailing slashes
            String normalizedPath = projectPath.replace("\\", "/").replaceAll("^/+|/+$", "");

            // Split path into components
            String[] pathComponents = normalizedPath.split("/");

            // PASS 1: Look for vanilla/Mod followed by version folder
            for (int i = 0; i < pathComponents.length; i++) {
                String component = pathComponents[i];

                // Check for family indicators (vanilla, and mods)
                if (component.equals("vanilla") || isModFolder(component)) {
                    familyType = component.equals("vanilla") ? "vanilla" : component;

                    // Look for version in next component
                    if (i + 1 < pathComponents.length) {
                        String nextComponent = pathComponents[i + 1];

                        // Check if next component looks like a version (1.xx format)
                        Pattern versionPattern = Pattern.compile("^(1\\.[0-9]+[a-z]?)$", Pattern.CASE_INSENSITIVE);
                        Matcher versionMatcher = versionPattern.matcher(nextComponent);

                        if (versionMatcher.matches()) {
                            gameVersion = nextComponent.toLowerCase();  // Normalize to lowercase

                            // Handle mods and standard versions
                            if (isModFolder(component)) {
                                String baseVersion = getModBaseVersion(component);
                                familyType = component;
                                isException = true;
                                // Track as mod with base version (e.g., "1.13c-PD2")
                                gameVersion = baseVersion + "-" + component;
                            } else {
                                // vanilla with proper version
                                isException = false;
                            }

                            return true;
                        }
                    }

                    // Special case: Mod folder without version subfolder
                    if (isModFolder(component)) {
                        String baseVersion = getModBaseVersion(component);
                        familyType = component;
                        gameVersion = baseVersion + "-" + component;
                        isException = true;
                        return true;
                    }
                }

                // Legacy support: also accept Classic/LoD folders, map to vanilla
                if (component.equals("Classic") || component.equals("LoD")) {
                    familyType = "vanilla";

                    if (i + 1 < pathComponents.length) {
                        String nextComponent = pathComponents[i + 1];
                        Pattern versionPattern = Pattern.compile("^(1\\.[0-9]+[a-z]?)$", Pattern.CASE_INSENSITIVE);
                        Matcher versionMatcher = versionPattern.matcher(nextComponent);

                        if (versionMatcher.matches()) {
                            gameVersion = nextComponent.toLowerCase();
                            isException = false;
                            return true;
                        }
                    }
                }
            }

            // PASS 2: Look for version folder directly (without vanilla prefix)
            // This handles project structures like /1.04b/D2Game.dll
            for (int i = 0; i < pathComponents.length; i++) {
                String component = pathComponents[i];
                
                // Check if this component looks like a version (1.xx format)
                Pattern versionPattern = Pattern.compile("^(1\\.[0-9]+[a-z]?)$", Pattern.CASE_INSENSITIVE);
                Matcher versionMatcher = versionPattern.matcher(component);
                
                if (versionMatcher.matches()) {
                    gameVersion = component.toLowerCase();  // Normalize to lowercase
                    familyType = "vanilla";
                    isException = false;
                    return true;
                }
            }

            return false;
        }

        /**
         * Check if a folder component represents a mod
         */
        private boolean isModFolder(String component) {
            // Known Diablo 2 mods - add more as needed
            String[] knownMods = {"PD2", "PoD", "MedianXL", "Eastern Sun", "Requiem"};
            for (String mod : knownMods) {
                if (component.equals(mod)) {
                    return true;
                }
            }
            return false;
        }

        /**
         * Get the base Diablo 2 version that a mod is built upon
         */
        private String getModBaseVersion(String modName) {
            // Map mods to their base versions
            switch (modName) {
                case "PD2":
                    return "1.13c";  // Project Diablo 2 is based on 1.13c
                case "PoD":
                    return "1.13c";  // Path of Diablo typically based on 1.13c
                case "MedianXL":
                    return "1.13c";  // Median XL latest versions
                case "Eastern Sun":
                    return "1.13c";  // Eastern Sun mod
                case "Requiem":
                    return "1.13c";  // Requiem mod
                default:
                    return "1.13c";  // Default to 1.13c for unknown mods
            }
        }

        private boolean isClassicVersion(String version) {
            // Versions 1.00-1.06b are Classic era
            String[] classicVersions = {"1.00", "1.01", "1.02", "1.03", "1.04", "1.04b", "1.04c", "1.05", "1.05b", "1.06", "1.06b"};
            for (String classicVer : classicVersions) {
                if (version.equals(classicVer)) {
                    return true;
                }
            }
            return false;
        }

        /**
         * Check if this program should be skipped (not an official D2 version)
         * Only versions 1.00-1.14d are processed
         * All mods (PD2, PoD, MedianXL, etc.) are ignored
         */
        public boolean shouldSkip() {
            // Skip if family type is a mod folder
            if (familyType != null && isModFolder(familyType)) {
                return true;
            }
            
            // Skip if version is unknown or not in our valid list
            if (gameVersion == null || gameVersion.equals("Unknown")) {
                return true;
            }
            
            // Extract base version (strip mod suffix like "1.13c-PD2")
            String baseVersion = gameVersion.contains("-") ? gameVersion.split("-")[0] : gameVersion;
            
            // Only allow versions in VERSION_CODES (1.00 through 1.14d)
            return !VERSION_CODES.containsKey(baseVersion);
        }

        /**
         * Get the reason why this program would be skipped
         */
        public String getSkipReason() {
            if (familyType != null && isModFolder(familyType)) {
                return "Mod folder (" + familyType + ") - only official D2 versions processed";
            }
            if (gameVersion == null || gameVersion.equals("Unknown")) {
                return "Unknown version - cannot determine version from path or filename";
            }
            String baseVersion = gameVersion.contains("-") ? gameVersion.split("-")[0] : gameVersion;
            if (!VERSION_CODES.containsKey(baseVersion)) {
                return "Unsupported version (" + baseVersion + ") - only 1.00-1.14d supported";
            }
            return "Unknown reason";
        }

        public boolean isValidUnifiedFormat() {
            return gameVersion != null && !gameVersion.equals("Unknown") && isKnownVersion(gameVersion);
        }

        /**
         * Check if a version string is a known valid Diablo 2 version
         */
        private boolean isKnownVersion(String version) {
            if (version == null) return false;
            // Handle mod versions like "1.13c-PD2" by extracting base version
            String baseVersion = version.contains("-") ? version.split("-")[0] : version;
            for (String validVersion : VALID_GAME_VERSIONS) {
                if (baseVersion.equals(validVersion)) {
                    return true;
                }
            }
            return false;
        }

        /**
         * Get the validated game version code (returns null if invalid)
         */
        public Integer getVersionCode() {
            if (gameVersion == null || gameVersion.equals("Unknown")) return null;
            // Handle mod versions - extract base version
            String baseVersion = gameVersion.contains("-") ? gameVersion.split("-")[0] : gameVersion;
            return VERSION_CODES.get(baseVersion);
        }

        /**
         * Get the validated game version string (returns null if invalid)
         */
        public String getValidatedGameVersion() {
            if (gameVersion == null || gameVersion.equals("Unknown")) return null;
            // Handle mod versions - extract base version
            String baseVersion = gameVersion.contains("-") ? gameVersion.split("-")[0] : gameVersion;
            if (VERSION_CODES.containsKey(baseVersion)) {
                return baseVersion;  // Return just the base version for DB constraint
            }
            return null;
        }

        /**
         * Get the validated version family (returns null if invalid)
         * All official versions use "vanilla" family
         */
        public String getValidatedVersionFamily() {
            return "vanilla";
        }

        public String getDisplayInfo() {
            if (!isValidUnifiedFormat()) {
                return String.format("Invalid/Unknown format (detection: %s)", detectionMethod);
            }

            String baseInfo;
            if (isException) {
                baseInfo = String.format("%s %s", familyType, gameVersion);
            } else {
                baseInfo = String.format("Unified %s", gameVersion);
            }

            // Add detection method for transparency
            return String.format("%s (detected via %s)", baseInfo, detectionMethod);
        }
    }

    @Override
    public void run() throws Exception {

        println("=== BSim Database Population Script ===");

        // Load database credentials from db.env
        loadDbConfig();
        println("Supports folder structure: /vanilla/1.01/, /vanilla/1.07/, /PD2/");
        println("Mod support: PD2 → 1.13c-PD2, PoD → 1.13c-PoD, MedianXL → 1.13c-MedianXL");
        println("Fallback filename parsing: 1.03_D2Game.dll");

        // Ask user which mode to use
        String[] modes = { MODE_SINGLE, MODE_ALL, MODE_VERSION };
        String selectedMode = askChoice("Select Processing Mode",
            "How would you like to populate the BSim database?", Arrays.asList(modes), MODE_SINGLE);

        if (selectedMode == null) {
            println("Operation cancelled by user");
            return;
        }

        println("Selected mode: " + selectedMode);

        try {
            if (MODE_SINGLE.equals(selectedMode)) {
                processSingleProgram();
            } else if (MODE_ALL.equals(selectedMode)) {
                processAllPrograms();
            } else if (MODE_VERSION.equals(selectedMode)) {
                processVersionFiltered();
            }

            println("BSim database population completed!");

        } catch (Exception e) {
            printerr("Error during BSim population: " + e.getMessage());
            e.printStackTrace();
            throw e;
        }
    }

    /**
     * Process only the currently open program
     */
    private void processSingleProgram() throws Exception {
        if (currentProgram == null) {
            popup("No program is currently open. Please open a program first.");
            return;
        }

        String programName = currentProgram.getName();

        // Get the project path
        String programPath = "";
        DomainFile domainFile = currentProgram.getDomainFile();
        if (domainFile != null) {
            programPath = domainFile.getPathname();
        } else {
            programPath = currentProgram.getExecutablePath();
        }

        // Parse unified version information
        UnifiedVersionInfo versionInfo = new UnifiedVersionInfo(programName, programPath);
        currentVersionInfo = versionInfo;  // Store for helper methods

        // Check if this program should be skipped (mod or unsupported version)
        if (versionInfo.shouldSkip()) {
            popup("Program Skipped\n\n" +
                "This program cannot be processed:\n\n" +
                versionInfo.getSkipReason() + "\n\n" +
                "Only official Diablo 2 versions are supported:\n" +
                "• Versions 1.00 through 1.14d");
            println("Skipped: " + versionInfo.getSkipReason());
            return;
        }

        println("Program: " + programName);
        println("Project Path: " + programPath);
        println("Version Info: " + versionInfo.getDisplayInfo());
        println("  - Family: " + versionInfo.familyType);
        println("  - Version: " + versionInfo.gameVersion);
        println("  - Compiler: " + getCompilerForVersion(versionInfo));
        println("  - Detection: " + versionInfo.detectionMethod);
        println("Functions: " + currentProgram.getFunctionManager().getFunctionCount());

        if (!versionInfo.isValidUnifiedFormat()) {
            boolean proceed = askYesNo("Version Detection Failed",
                "Could not detect version information from folder structure or filename.\n" +
                "Expected folder structure: /vanilla/1.01/, /vanilla/1.07/, /PD2/\n" +
                "Or filename formats: 1.03_D2Game.dll\n\n" +
                "Detection attempted via: " + versionInfo.detectionMethod + "\n" +
                "Program path: " + programPath + "\n\n" +
                "Proceed with unknown version info?");

            if (!proceed) {
                println("Operation cancelled - invalid naming format");
                return;
            }
        }

        boolean proceed = askYesNo("Confirm BSim Addition",
            String.format("Add program '%s' to BSim database?\n\nVersion Info: %s",
                programName, versionInfo.getDisplayInfo()));

        if (!proceed) {
            println("Operation cancelled by user");
            return;
        }

        addProgramToBSim(currentProgram, programName, programPath, versionInfo);
        println("Successfully added " + programName + " to BSim database!");
    }

    /**
     * Process all programs in the Ghidra project
     */
    private void processAllPrograms() throws Exception {
        Project project = state.getProject();
        if (project == null) {
            popup("No project is open. Please open a Ghidra project first.");
            return;
        }

        ProjectData projectData = project.getProjectData();
        DomainFolder rootFolder = projectData.getRootFolder();

        // Collect all program files
        List<DomainFile> allProgramFiles = new ArrayList<>();
        collectProgramFiles(rootFolder, allProgramFiles);

        if (allProgramFiles.isEmpty()) {
            popup("No programs found in the project.");
            return;
        }

        // Filter to only official D2 versions (exclude mods and unsupported versions)
        List<DomainFile> programFiles = new ArrayList<>();
        List<String> skippedMods = new ArrayList<>();
        
        for (DomainFile file : allProgramFiles) {
            UnifiedVersionInfo versionInfo = new UnifiedVersionInfo(file.getName(), file.getPathname());
            if (versionInfo.shouldSkip()) {
                skippedMods.add(file.getName() + " (" + versionInfo.getSkipReason() + ")");
            } else {
                programFiles.add(file);
            }
        }

        // Report what's being skipped
        if (!skippedMods.isEmpty()) {
            println("Skipping " + skippedMods.size() + " non-official binaries (mods/unsupported):");
            for (String skipped : skippedMods) {
                println("  ⏭ " + skipped);
            }
            println("");
        }

        if (programFiles.isEmpty()) {
            popup("No official Diablo 2 programs found in the project.\n\n" +
                  "Only versions 1.00-1.14d are supported.");
            return;
        }

        // Validate unified naming convention for remaining files
        int validCount = 0;
        int invalidCount = 0;
        for (DomainFile file : programFiles) {
            UnifiedVersionInfo versionInfo = new UnifiedVersionInfo(file.getName(), file.getPathname());
            if (versionInfo.isValidUnifiedFormat()) {
                validCount++;
            } else {
                invalidCount++;
            }
        }

        println("Found " + programFiles.size() + " official D2 programs to process");
        println("  (Excluded " + skippedMods.size() + " mod/unsupported binaries)");
        println("  Valid unified format: " + validCount);
        println("  Invalid/unknown format: " + invalidCount);

        if (invalidCount > 0) {
            boolean proceed = askYesNo("Invalid Formats Detected",
                String.format("%d files don't follow unified naming convention.\n" +
                "These will be processed with limited version info.\n\n" +
                "Continue?", invalidCount));

            if (!proceed) {
                println("Operation cancelled due to naming format issues");
                return;
            }
        }

        boolean proceed = askYesNo("Process Official D2 Programs",
            String.format("Add %d official D2 programs to BSim database?\n\n" +
                "• Versions 1.00-1.14d: included\n" +
                "• Mods/Other: %d excluded\n\n" +
                "This may take a while.", programFiles.size(), skippedMods.size()));

        if (!proceed) {
            println("Operation cancelled by user");
            return;
        }

        // Ask user for processing mode
        processingMode = askProcessingMode();
        if (processingMode == ProcessingMode.CANCELLED) {
            println("Operation cancelled by user");
            return;
        }

        int successCount = 0;
        int errorCount = 0;
        int skippedCount = 0;
        
        // Store results for summary
        List<String> successfulFiles = new ArrayList<>();
        List<String> skippedFiles = new ArrayList<>();
        List<String> errorFiles = new ArrayList<>();

        for (int i = 0; i < programFiles.size(); i++) {
            DomainFile file = programFiles.get(i);
            monitor.setMessage(String.format("Processing %d/%d: %s", i + 1, programFiles.size(), file.getName()));
            monitor.setProgress(i);

            if (monitor.isCancelled()) {
                println("Operation cancelled by user");
                break;
            }

            try {
                processProjectFile(file);
                successCount++;
                successfulFiles.add(file.getName());
                println("  ✓ Successfully added: " + file.getName());
            } catch (Exception e) {
                String msg = e.getMessage();
                if (msg != null && msg.startsWith("SKIP_EXISTING")) {
                    println("  ⏭ Skipped " + file.getName() + " (already in database)");
                    skippedCount++;
                    skippedFiles.add(file.getName() + " (already in database)");
                } else if (msg != null && msg.startsWith("SKIP_NONOFFICIAL")) {
                    String reason = msg.replace("SKIP_NONOFFICIAL: ", "");
                    println("  ⏭ Skipped " + file.getName() + " (" + reason + ")");
                    skippedCount++;
                    skippedFiles.add(file.getName() + " (" + reason + ")");
                } else {
                    printerr("  ✗ Error processing " + file.getName() + ": " + msg);
                    errorCount++;
                    errorFiles.add(file.getName() + ": " + msg);
                }
            }
        }

        // Print detailed summary
        println("");
        println("═══════════════════════════════════════════════════════════════");
        println("                    PROCESSING SUMMARY");
        println("═══════════════════════════════════════════════════════════════");
        println(String.format("Total processed: %d files", programFiles.size()));
        println(String.format("  ✓ Successful: %d", successCount));
        println(String.format("  ⏭ Skipped:    %d", skippedCount));
        println(String.format("  ✗ Errors:     %d", errorCount));
        if (!errorFiles.isEmpty()) {
            println("");
            println("Errors encountered:");
            for (String err : errorFiles) {
                println("  ! " + err);
            }
        }
        println("═══════════════════════════════════════════════════════════════");
    }

    /**
     * Process programs matching a version filter
     */
    private void processVersionFiltered() throws Exception {
        Project project = state.getProject();
        if (project == null) {
            popup("No project is open. Please open a Ghidra project first.");
            return;
        }

        // Ask for version filter
        String versionFilter = askString("Version Filter",
            "Enter filter in one of these formats:\n\n" +
            "• 'vanilla/1.09' - Binaries for version 1.09 only\n" +
            "• '1.09' - Binaries for version 1.09\n" +
            "• 'vanilla' - All vanilla versions", "vanilla/1.09");

        if (versionFilter == null || versionFilter.trim().isEmpty()) {
            println("Operation cancelled - no filter provided");
            return;
        }

        // Parse the filter - check for family/version format
        String familyFilter = null;
        String versionFilterPart = null;
        
        if (versionFilter.contains("/")) {
            // Format: "vanilla/1.09"
            String[] parts = versionFilter.split("/", 2);
            familyFilter = parts[0].trim();
            versionFilterPart = parts[1].trim();
            println("Filter: Family='" + familyFilter + "', Version='" + versionFilterPart + "'");
        } else if (versionFilter.equalsIgnoreCase("vanilla") ||
                   versionFilter.equalsIgnoreCase("D2R")) {
            // Family-only filter
            familyFilter = versionFilter;
            println("Filter: Family='" + familyFilter + "' (all versions)");
        } else {
            // Version-only filter
            versionFilterPart = versionFilter;
            println("Filter: Version='" + versionFilterPart + "' (all families)");
        }

        ProjectData projectData = project.getProjectData();
        DomainFolder rootFolder = projectData.getRootFolder();

        // Collect matching program files
        List<DomainFile> programFiles = new ArrayList<>();
        collectProgramFiles(rootFolder, programFiles);

        // Filter by version and/or family using EXACT matching
        // Also exclude mods and unsupported versions
        final String finalFamilyFilter = familyFilter;
        final String finalVersionFilter = versionFilterPart;
        
        List<DomainFile> matchingFiles = new ArrayList<>();
        int skippedModCount = 0;
        
        for (DomainFile file : programFiles) {
            String fileName = file.getName();
            String filePath = file.getPathname();
            UnifiedVersionInfo versionInfo = new UnifiedVersionInfo(fileName, filePath);

            // Skip mods and unsupported versions first
            if (versionInfo.shouldSkip()) {
                skippedModCount++;
                continue;
            }

            boolean familyMatches = true;
            boolean versionMatches = true;
            
            // Check family filter (if specified)
            if (finalFamilyFilter != null) {
                familyMatches = versionInfo.familyType.equalsIgnoreCase(finalFamilyFilter);
            }
            
            // Check version filter (if specified) - EXACT match only
            if (finalVersionFilter != null) {
                versionMatches = false;
                // Check parsed version info (exact match)
                if (versionInfo.gameVersion != null && versionInfo.gameVersion.equals(finalVersionFilter)) {
                    versionMatches = true;
                }
                // Also check folder path for exact version folder (e.g., "/1.09/" not "/1.09b/")
                else if (filePath.contains("/" + finalVersionFilter + "/")) {
                    versionMatches = true;
                }
            }
            
            if (familyMatches && versionMatches) {
                matchingFiles.add(file);
            }
        }

        if (skippedModCount > 0) {
            println("(Excluded " + skippedModCount + " mod/unsupported binaries from search)");
        }

        if (matchingFiles.isEmpty()) {
            popup("No official D2 programs matching filter '" + versionFilter + "' found.\n\n" +
                  "Only versions 1.00-1.14d are supported.");
            return;
        }

        println("Found " + matchingFiles.size() + " programs matching '" + versionFilter + "'");

        // Show matching files with version info
        println("Matching programs:");
        for (DomainFile file : matchingFiles) {
            UnifiedVersionInfo versionInfo = new UnifiedVersionInfo(file.getName(), file.getPathname());
            println("  - " + file.getName() + " (" + versionInfo.getDisplayInfo() + ")");
        }

        boolean proceed = askYesNo("Process Filtered Programs",
            String.format("Add %d programs matching '%s' to BSim database?", matchingFiles.size(), versionFilter));

        if (!proceed) {
            println("Operation cancelled by user");
            return;
        }

        processingMode = askProcessingMode();
        if (processingMode == ProcessingMode.CANCELLED) {
            println("Operation cancelled by user");
            return;
        }

        int successCount = 0;
        int errorCount = 0;
        int skippedCount = 0;
        
        // Store results for summary
        List<String> successfulFiles = new ArrayList<>();
        List<String> skippedFiles = new ArrayList<>();
        List<String> errorFiles = new ArrayList<>();

        for (int i = 0; i < matchingFiles.size(); i++) {
            DomainFile file = matchingFiles.get(i);
            monitor.setMessage(String.format("Processing %d/%d: %s", i + 1, matchingFiles.size(), file.getName()));
            monitor.setProgress(i);

            if (monitor.isCancelled()) {
                println("Operation cancelled by user");
                break;
            }

            try {
                processProjectFile(file);
                successCount++;
                successfulFiles.add(file.getName());
                println("  ✓ Successfully added: " + file.getName());
            } catch (Exception e) {
                String msg = e.getMessage();
                if (msg != null && msg.startsWith("SKIP_EXISTING")) {
                    println("  ⏭ Skipped " + file.getName() + " (already in database)");
                    skippedCount++;
                    skippedFiles.add(file.getName() + " (already in database)");
                } else if (msg != null && msg.startsWith("SKIP_NONOFFICIAL")) {
                    String reason = msg.replace("SKIP_NONOFFICIAL: ", "");
                    println("  ⏭ Skipped " + file.getName() + " (" + reason + ")");
                    skippedCount++;
                    skippedFiles.add(file.getName() + " (" + reason + ")");
                } else {
                    printerr("  ✗ Error processing " + file.getName() + ": " + msg);
                    errorCount++;
                    errorFiles.add(file.getName() + ": " + msg);
                }
            }
        }

        // Print detailed summary
        println("");
        println("═══════════════════════════════════════════════════════════════");
        println("                    PROCESSING SUMMARY");
        println("═══════════════════════════════════════════════════════════════");
        println(String.format("Total processed: %d files", matchingFiles.size()));
        println(String.format("  ✓ Successful: %d", successCount));
        println(String.format("  ⏭ Skipped:    %d", skippedCount));
        println(String.format("  ✗ Errors:     %d", errorCount));
        println("");
        
        if (!successfulFiles.isEmpty()) {
            println("Successfully added to database:");
            for (String name : successfulFiles) {
                println("  + " + name);
            }
            println("");
        }
        
        if (!skippedFiles.isEmpty()) {
            println("Skipped (already exist):");
            for (String name : skippedFiles) {
                println("  - " + name);
            }
            println("");
        }
        
        if (!errorFiles.isEmpty()) {
            println("Errors encountered:");
            for (String err : errorFiles) {
                println("  ! " + err);
            }
            println("");
        }
        
        println("═══════════════════════════════════════════════════════════════");
    }

    /**
     * Recursively collect all program files from a folder
     */
    private void collectProgramFiles(DomainFolder folder, List<DomainFile> files) throws Exception {
        for (DomainFile file : folder.getFiles()) {
            if (file.getContentType().equals("Program")) {
                files.add(file);
            }
        }

        for (DomainFolder subfolder : folder.getFolders()) {
            collectProgramFiles(subfolder, files);
        }
    }

    /**
     * Process a single project file
     */
    private void processProjectFile(DomainFile file) throws Exception {
        String programPath = file.getPathname();
        String programName = file.getName();
        
        // Check if this program should be skipped BEFORE opening it
        UnifiedVersionInfo preCheckInfo = new UnifiedVersionInfo(programName, programPath);
        if (preCheckInfo.shouldSkip()) {
            throw new Exception("SKIP_NONOFFICIAL: " + preCheckInfo.getSkipReason());
        }
        
        println("Processing: " + programPath);

        // Open the program
        Program program = (Program) file.getDomainObject(this, true, false, monitor);

        try {
            UnifiedVersionInfo versionInfo = new UnifiedVersionInfo(programName, programPath);
            currentVersionInfo = versionInfo;  // Store for helper methods

            addProgramToBSim(program, programName, programPath, versionInfo);
            println("  Added " + programName + " (" + versionInfo.getDisplayInfo() + ") to BSim database");

        } finally {
            program.release(this);
        }
    }

    /**
     * Ask user for processing mode when handling existing executables
     */
    private ProcessingMode askProcessingMode() {
        String message = "How should existing executables be handled?\n\n" +
            "Choose your processing mode:\n\n" +
            "• Update All: Process all binaries, updating existing ones\n" +
            "• Add Missing: Only process binaries not yet in database (recommended)\n" +
            "• Ask Individual: Prompt individually for each binary\n" +
            "• Cancel: Exit the operation";

        java.util.List<String> choices = java.util.Arrays.asList(
            "Update All",
            "Add Missing (Recommended)",
            "Ask Individual",
            "Cancel"
        );

        String choice;
        try {
            choice = askChoice("Processing Mode", message, choices, "Add Missing (Recommended)");
        } catch (CancelledException e) {
            println("Operation cancelled by user");
            return ProcessingMode.CANCELLED;
        }

        if ("Update All".equals(choice)) {
            println("Selected: Update All mode");
            return ProcessingMode.UPDATE_ALL;
        } else if ("Add Missing (Recommended)".equals(choice)) {
            println("Selected: Add Missing mode");
            return ProcessingMode.ADD_MISSING;
        } else if ("Ask Individual".equals(choice)) {
            println("Selected: Ask Individual mode");
            return ProcessingMode.ASK_INDIVIDUAL;
        } else {
            println("Operation cancelled");
            return ProcessingMode.CANCELLED;
        }
    }

    /**
     * Add a program to the BSim database with unified version support
     */
    private void addProgramToBSim(Program program, String programName, String programPath, UnifiedVersionInfo versionInfo) throws Exception {

        println("Connecting to BSim database...");

        try (Connection conn = DriverManager.getConnection(dbUrl, dbUser, dbPass)) {

            println("Connected to BSim database successfully");

            // Ensure this specific game version exists in the table (on-demand, not all versions)
            Integer versionCode = versionInfo.getVersionCode();
            String versionString = versionInfo.getValidatedGameVersion();
            if (versionCode != null && versionString != null) {
                ensureGameVersionExists(conn, versionCode, versionString);
            }

            // Use individual transactions for better error isolation
            conn.setAutoCommit(true);

            // Step 1: Get or create executable (separate transaction)
            int executableId;
            try {
                conn.setAutoCommit(false);
                executableId = getOrCreateExecutableUnified(conn, program, programName, programPath, versionInfo);
                // Only commit if we haven't already committed in the fallback path
                if (!conn.getAutoCommit()) {
                    conn.commit();
                }
                println("Executable ID: " + executableId);
                
                // Verify the executable actually exists in the database after commit
                conn.setAutoCommit(true);  // Reset for verification query
                if (!verifyExecutableExists(conn, executableId)) {
                    throw new SQLException("Executable ID " + executableId + " was not properly committed to database");
                }

                // Step 1b: Store API imports and exports (once per executable)
                storeApiImports(conn, executableId, program);
                storeApiExports(conn, executableId, program);
                
                // Step 1c: Record this version association in binary_versions junction table
                // This allows tracking when the same binary appears in multiple game versions
                storeBinaryVersionAssociation(conn, executableId, versionInfo);
            } catch (Exception e) {
                try {
                    if (!conn.getAutoCommit()) {
                        conn.rollback();
                    }
                } catch (SQLException rollbackEx) {
                    println("Warning: Rollback failed: " + rollbackEx.getMessage());
                }
                printerr("Error creating executable entry: " + e.getMessage());
                throw e;
            }

            // Step 2: Process functions (separate transaction for each batch)
            try {
                conn.setAutoCommit(true); // Use autocommit for function processing
                processFunctions(conn, executableId, programName, program);
            } catch (Exception e) {
                printerr("Error processing functions: " + e.getMessage());
                throw e;
            }

            // Step 3: Update materialized views (separate transaction, non-critical)
            try {
                conn.setAutoCommit(false);
                refreshMaterializedViews(conn);
                conn.commit();
            } catch (Exception e) {
                conn.rollback();
                println("Warning: Could not refresh materialized views: " + e.getMessage());
                // Don't fail the entire process for view refresh issues
            }

            println("Database operations completed successfully");

        } catch (SQLException e) {
            printerr("Database error: " + e.getMessage());
            throw e;
        }
    }

    /**
     * Get or create executable record with unified version support
     * Uses plain executable names (no version prefix) with integer version codes
     */
    private int getOrCreateExecutableUnified(Connection conn, Program program, String programName, String programPath, UnifiedVersionInfo versionInfo) throws SQLException {

        // Extract plain executable name (no version prefix)
        String execName = extractExecutableName(programName);
        
        // Get version code (integer) and validated version string
        Integer versionCode = versionInfo.getVersionCode();
        String validatedGameVersion = versionInfo.getValidatedGameVersion();
        String validatedVersionFamily = versionInfo.getValidatedVersionFamily();

        // Ensure the version exists in game_versions table (create if needed)
        if (versionCode != null && validatedGameVersion != null && validatedVersionFamily != null) {
            ensureVersionExists(conn, versionCode, validatedGameVersion, validatedVersionFamily);
        }

        // Check if executable already exists (by name + version combination)
        String selectSql = "SELECT id FROM exetable WHERE name_exec = ? AND game_version = ?";
        try (PreparedStatement stmt = conn.prepareStatement(selectSql)) {
            stmt.setString(1, execName);
            if (versionCode != null) {
                stmt.setInt(2, versionCode);
            } else {
                stmt.setNull(2, java.sql.Types.INTEGER);
            }
            ResultSet rs = stmt.executeQuery();

            if (rs.next()) {
                int existingId = rs.getInt("id");
                println("Executable already exists in database with ID: " + existingId);
                println("  name_exec: " + execName + ", game_version: " + versionCode);

                // Handle based on processing mode
                switch (processingMode) {
                    case UPDATE_ALL:
                        println("  Auto-updating existing executable...");
                        return existingId;

                    case ADD_MISSING:
                        // Verify function counts match before skipping
                        int dbFunctionCount = getDatabaseFunctionCount(conn, existingId);
                        int ghidraFunctionCount = program.getFunctionManager().getFunctionCount();
                        
                        if (dbFunctionCount < ghidraFunctionCount) {
                            // Functions are missing - need to process
                            println("  ⚠ Function count mismatch: DB has " + dbFunctionCount + ", Ghidra has " + ghidraFunctionCount);
                            println("  Processing missing functions...");
                            return existingId;  // Return ID so functions get processed
                        } else {
                            println("  ✓ Function counts match (DB: " + dbFunctionCount + ", Ghidra: " + ghidraFunctionCount + ")");
                            println("  Skipping existing executable (Add Missing mode)");
                            throw new RuntimeException("SKIP_EXISTING");
                        }

                    case ASK_INDIVIDUAL:
                        boolean update = askYesNo("Executable Exists",
                            "Executable already exists in database. Update function data?");
                        if (!update) {
                            throw new RuntimeException("SKIP_EXISTING");
                        }
                        println("  Updating existing executable...");
                        return existingId;

                    default:
                        throw new RuntimeException("SKIP_EXISTING");
                }
            }
        }

        if (versionCode == null) {
            printerr("WARNING: Could not validate game version from: " + versionInfo.gameVersion);
            printerr("  Known versions: 1.00-1.14d");
        }

        // Generate hashes from actual program
        String md5Hash = generateMD5(program);
        String sha256Hash = generateSHA256(program);

        // Create new executable record with SHA256 and integer version code
        // Use ON CONFLICT (md5) for idempotent insert (standard BSim behavior - md5 is unique)
        // NOTE: Do NOT update game_version on conflict - keep the first seen version as canonical
        // The binary_versions junction table tracks all versions that contain this binary
        String insertSql = "INSERT INTO exetable (name_exec, md5, sha256, architecture, name_compiler, ingest_date, repository, path, game_version, version_family) " +
            "VALUES (?, ?, ?, get_or_create_arch_id(?), get_or_create_compiler_id(?), NOW(), get_or_create_repository_id(?), get_or_create_path_id(?), ?, ?) " +
            "ON CONFLICT (md5) DO UPDATE SET name_exec = EXCLUDED.name_exec, sha256 = EXCLUDED.sha256, ingest_date = NOW() " +
            "RETURNING id";

        try (PreparedStatement stmt = conn.prepareStatement(insertSql)) {
            stmt.setString(1, execName);
            stmt.setString(2, md5Hash);
            stmt.setString(3, sha256Hash);
            stmt.setString(4, getArchitectureString());
            stmt.setString(5, getCompilerString());
            stmt.setString(6, getRepositoryString());
            stmt.setString(7, getPathString());
            // Set game_version as integer version code
            if (versionCode != null) {
                stmt.setInt(8, versionCode);
            } else {
                stmt.setNull(8, java.sql.Types.INTEGER);
            }
            // Set version_family
            if (validatedVersionFamily != null) {
                stmt.setString(9, validatedVersionFamily);
            } else {
                stmt.setNull(9, java.sql.Types.VARCHAR);
            }

            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                int newId = rs.getInt("id");
                println("Created new executable record with ID: " + newId);
                println("  name_exec: " + execName);
                println("  md5: " + md5Hash);
                println("  sha256: " + sha256Hash.substring(0, 16) + "...");
                println("  game_version: " + (versionCode != null ? versionCode + " (" + validatedGameVersion + ")" : "NULL"));
                println("  version_family: " + (validatedVersionFamily != null ? validatedVersionFamily : "NULL"));

                return newId;
            }
        } catch (SQLException e) {
            // In PostgreSQL, after an error the transaction is in "aborted" state
            // We need to rollback before we can do anything else
            println("  Note: Insert failed, rolling back to try basic insert");
            println("  Original error: " + e.getMessage());
            
            try {
                conn.rollback();  // Clear the aborted transaction state
            } catch (SQLException rollbackError) {
                println("  Warning: Rollback failed: " + rollbackError.getMessage());
            }

            // Fall back to basic insert
            println("  Attempting basic insert with integer version code");

            // NOTE: Do NOT update game_version on conflict - keep the first seen version as canonical
            String basicInsertSql = "INSERT INTO exetable (name_exec, md5, sha256, architecture, name_compiler, ingest_date, repository, path, game_version, version_family) " +
                "VALUES (?, ?, ?, get_or_create_arch_id(?), get_or_create_compiler_id(?), NOW(), get_or_create_repository_id(?), get_or_create_path_id(?), ?, ?) " +
                "ON CONFLICT (md5) DO UPDATE SET name_exec = EXCLUDED.name_exec, sha256 = EXCLUDED.sha256, ingest_date = NOW() " +
                "RETURNING id";
            try (PreparedStatement stmt = conn.prepareStatement(basicInsertSql)) {
                stmt.setString(1, execName);
                stmt.setString(2, md5Hash);
                stmt.setString(3, sha256Hash);
                stmt.setString(4, getArchitectureString());
                stmt.setString(5, getCompilerString());
                stmt.setString(6, getRepositoryString());
                stmt.setString(7, getPathString());
                // Set game_version as integer version code
                if (versionCode != null) {
                    stmt.setInt(8, versionCode);
                } else {
                    stmt.setNull(8, java.sql.Types.INTEGER);
                }
                // Set version_family
                if (validatedVersionFamily != null) {
                    stmt.setString(9, validatedVersionFamily);
                } else {
                    stmt.setNull(9, java.sql.Types.VARCHAR);
                }

                println("  Attempting basic insert with name: " + execName);
                ResultSet rs = stmt.executeQuery();
                if (rs.next()) {
                    int newId = rs.getInt("id");
                    println("Created new executable record with ID: " + newId);
                    // Commit immediately since we rolled back earlier
                    conn.commit();
                    conn.setAutoCommit(true);  // Signal to caller that we've committed
                    return newId;
                }
            } catch (SQLException basicInsertError) {
                printerr("Error in basic insert for '" + execName + "': " + basicInsertError.getMessage());

                // Check if it's a constraint violation and try to work around it
                if (basicInsertError.getMessage().contains("proper_executable_naming")) {
                    println("  Constraint violation detected. Trying with normalized filename...");
                    String normalizedName = normalizeExecutableName(execName);
                    return tryInsertWithNormalizedName(conn, normalizedName);
                }
                throw basicInsertError;
            }
        }

        throw new SQLException("Failed to create executable record");
    }

    /**
     * Normalize executable name to work around naming constraints
     */
    private String normalizeExecutableName(String originalName) {
        // Remove problematic characters and apply basic normalization
        String normalized = originalName.replaceAll("[^a-zA-Z0-9._-]", "_");

        // If it's just a basic DLL/EXE name without version, try to make it comply
        if (!normalized.matches(".*\\d+\\.\\d+.*")) {
            // Add a default version if none present
            if (normalized.endsWith(".dll")) {
                normalized = "Unknown_" + normalized;
            } else if (normalized.endsWith(".exe")) {
                normalized = "Unknown_" + normalized;
            }
        }

        return normalized;
    }

    /**
     * Try insert with normalized name as last resort
     */
    private int tryInsertWithNormalizedName(Connection conn, String normalizedName) throws SQLException {
        // Rollback any aborted transaction first
        try {
            conn.rollback();
        } catch (SQLException e) {
            println("  Warning: Rollback failed before normalized insert: " + e.getMessage());
        }
        
        // Generate hashes from actual program
        String md5Hash = generateMD5(currentProgram);
        String sha256Hash = generateSHA256(currentProgram);
        
        String basicInsertSql = "INSERT INTO exetable (name_exec, md5, sha256, architecture, name_compiler, ingest_date, repository, path, game_version, version_family) " +
            "VALUES (?, ?, ?, get_or_create_arch_id(?), get_or_create_compiler_id(?), NOW(), get_or_create_repository_id(?), get_or_create_path_id(?), NULL, NULL) " +
            "ON CONFLICT (md5) DO UPDATE SET name_exec = EXCLUDED.name_exec, sha256 = EXCLUDED.sha256, ingest_date = NOW() " +
            "RETURNING id";

        try (PreparedStatement stmt = conn.prepareStatement(basicInsertSql)) {
            stmt.setString(1, normalizedName);
            stmt.setString(2, md5Hash);
            stmt.setString(3, sha256Hash);
            stmt.setString(4, getArchitectureString());
            stmt.setString(5, getCompilerString());
            stmt.setString(6, getRepositoryString());
            stmt.setString(7, getPathString());
            // Normalized names lose version info, so we set NULL for both

            println("  Attempting insert with normalized name: " + normalizedName);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                int newId = rs.getInt("id");
                println("Created executable record with normalized name, ID: " + newId);
                conn.commit();
                conn.setAutoCommit(true);  // Signal to caller that we've committed
                return newId;
            }
        }

        throw new SQLException("Failed to create executable record even with normalized name");
    }

    /**
     * Verify that an executable ID actually exists in the database
     */
    private boolean verifyExecutableExists(Connection conn, int executableId) {
        String sql = "SELECT id FROM exetable WHERE id = ?";
        try (PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setInt(1, executableId);
            ResultSet rs = stmt.executeQuery();
            boolean exists = rs.next();
            rs.close();
            if (exists) {
                println("  Verified executable ID " + executableId + " exists in database");
            } else {
                printerr("  ERROR: Executable ID " + executableId + " NOT FOUND in database!");
            }
            return exists;
        } catch (SQLException e) {
            printerr("  Error verifying executable: " + e.getMessage());
            return false;
        }
    }

    /**
     * Get the count of functions in the database for a given executable
     * Used to verify that all functions have been imported
     */
    private int getDatabaseFunctionCount(Connection conn, int executableId) {
        String sql = "SELECT COUNT(*) as func_count FROM desctable WHERE id_exe = ?";
        try (PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setInt(1, executableId);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                return rs.getInt("func_count");
            }
            return 0;
        } catch (SQLException e) {
            printerr("  Error getting function count: " + e.getMessage());
            return 0;  // Return 0 to trigger re-processing on error
        }
    }

    /**
     * Process all functions in the program and add to database
     */
    private void processFunctions(Connection conn, int executableId, String programName, Program program) throws Exception {

        println("Processing functions...");
        monitor.setMessage("Processing functions for BSim");

        FunctionManager funcManager = program.getFunctionManager();
        FunctionIterator functions = funcManager.getFunctions(true);

        int functionCount = 0;
        int addedCount = 0;
        int skippedCount = 0;

        // Use INSERT ... ON CONFLICT for idempotent operations
        // Store plate comment in the 'val' field (standard BSim metadata field)
        // Note: Requires unique constraint on (id_exe, addr) - if not present, falls back to check-then-insert
        String upsertSql = "INSERT INTO desctable (name_func, id_exe, id_signature, flags, addr, val) " +
            "VALUES (?, ?, ?, ?, ?, ?) " +
            "ON CONFLICT (id_exe, addr) DO UPDATE SET name_func = EXCLUDED.name_func, id_signature = EXCLUDED.id_signature, val = EXCLUDED.val " +
            "RETURNING id";
        
        // Fallback for databases without the unique constraint
        String checkSql = "SELECT id FROM desctable WHERE id_exe = ? AND addr = ?";
        String insertSql = "INSERT INTO desctable (name_func, id_exe, id_signature, flags, addr, val) VALUES (?, ?, ?, ?, ?, ?) RETURNING id";
        
        boolean useUpsert = true;  // Try upsert first
        PreparedStatement workingStmt = null;

        try {
            // Test if upsert works (constraint exists)
            workingStmt = conn.prepareStatement(upsertSql);
        } catch (SQLException e) {
            println("  Note: Using check-then-insert pattern (unique constraint not available)");
            useUpsert = false;
        }

        try (PreparedStatement checkStmt = conn.prepareStatement(checkSql);
             PreparedStatement insertStmt = useUpsert ? conn.prepareStatement(upsertSql) : conn.prepareStatement(insertSql)) {

            while (functions.hasNext() && !monitor.isCancelled()) {
                Function function = functions.next();
                functionCount++;

                if (functionCount % 100 == 0) {
                    monitor.setMessage(String.format("Processing function %d: %s",
                        functionCount, function.getName()));
                }

                try {
                    int functionId = -1;
                    boolean isNew = false;
                    
                    // Get plate comment for the val field
                    String plateComment = getPlateComment(program, function);
                    
                    if (useUpsert) {
                        // Use upsert - always insert/update in one atomic operation
                        insertStmt.setString(1, function.getName());
                        insertStmt.setInt(2, executableId);
                        insertStmt.setLong(3, generateSignatureId(function));
                        insertStmt.setInt(4, 0);
                        insertStmt.setLong(5, function.getEntryPoint().getOffset());
                        insertStmt.setString(6, plateComment);  // Store plate comment in val field

                        ResultSet insertRs = insertStmt.executeQuery();
                        if (insertRs.next()) {
                            functionId = insertRs.getInt("id");
                            isNew = true;  // Upsert always processes
                        }
                        insertRs.close();
                    } else {
                        // Check-then-insert pattern (less safe but works without constraint)
                        checkStmt.setInt(1, executableId);
                        checkStmt.setLong(2, function.getEntryPoint().getOffset());
                        ResultSet rs = checkStmt.executeQuery();

                        if (rs.next()) {
                            functionId = rs.getInt("id");
                            skippedCount++;
                            rs.close();
                            continue;  // Already exists
                        }
                        rs.close();

                        // Insert new function
                        insertStmt.setString(1, function.getName());
                        insertStmt.setInt(2, executableId);
                        insertStmt.setLong(3, generateSignatureId(function));
                        insertStmt.setInt(4, 0);
                        insertStmt.setLong(5, function.getEntryPoint().getOffset());
                        insertStmt.setString(6, plateComment);  // Store plate comment in val field

                        ResultSet insertRs = insertStmt.executeQuery();
                        if (insertRs.next()) {
                            functionId = insertRs.getInt("id");
                            isNew = true;
                        }
                        insertRs.close();
                    }
                    
                    if (functionId > 0 && isNew) {
                        addedCount++;

                        // Apply comprehensive function tagging and analysis
                        applyFunctionTags(program, function);

                        // Store detailed function analysis metrics with known function ID
                        storeFunctionAnalysisWithId(conn, function, functionId, executableId, program);

                        // Store function tags with known function ID
                        storeFunctionTagsWithId(conn, function, functionId, executableId);

                        // EFFICIENCY ENHANCEMENT: Populate additional tables during initial processing
                        // This reduces the need for later scripts to re-process the same functions

                        // Store function signatures (basic prototype info)
                        storeFunctionSignatureWithId(conn, function, functionId, executableId, program);

                        // Store enhanced BSim signatures (structural analysis for similarity matching)
                        // This was previously Step2 - now done inline for efficiency
                        storeEnhancedSignatureWithId(conn, function, functionId, executableId, program);

                        // Store function parameters (individual param metadata)
                        storeFunctionParametersWithId(conn, function, functionId);

                        // Note: Function calls require second pass after all functions are loaded
                        // storeFunctionCallsWithId(conn, function, functionId, executableId, program);

                        // Store data references (global data access patterns)
                        storeDataReferencesWithId(conn, function, functionId, program);

                        // Store API usage (imports/exports)
                        storeApiUsageWithId(conn, function, functionId, executableId, program);

                        // Store string references
                        storeStringReferencesWithId(conn, function, functionId, executableId, program);

                        // Store call graph metrics (computed leaf/entry point status)
                        storeCallGraphMetricsWithId(conn, function, functionId, program);
                    }

                } catch (SQLException e) {
                    if (!e.getMessage().contains("duplicate key")) {
                        printerr("Error processing function " + function.getName() + ": " + e.getMessage());
                    } else {
                        skippedCount++;
                    }
                }
            }
        }

        if (monitor.isCancelled()) {
            println("Operation cancelled by user");
            return;
        }

        println(String.format("Processed %d functions, added %d new, skipped %d existing",
            functionCount, addedCount, skippedCount));
        println("Applied comprehensive function tagging for " + addedCount + " new functions");
    }

    /**
     * Refresh materialized views for cross-version analysis (authentic BSim schema)
     */
    private void refreshMaterializedViews(Connection conn) throws SQLException {
        println("Checking for materialized views to refresh...");

        try (Statement stmt = conn.createStatement()) {
            // Check if any materialized views exist in the authentic schema
            ResultSet rs = stmt.executeQuery("SELECT matviewname FROM pg_matviews WHERE schemaname = 'public'");
            if (rs.next()) {
                // Refresh any materialized views that exist
                do {
                    String viewName = rs.getString("matviewname");
                    try {
                        stmt.execute("REFRESH MATERIALIZED VIEW " + viewName);
                        println("Refreshed materialized view: " + viewName);
                    } catch (SQLException e) {
                        println("Note: Could not refresh materialized view " + viewName + ": " + e.getMessage());
                    }
                } while (rs.next());
            } else {
                println("No materialized views found to refresh");
            }
        } catch (SQLException e) {
            println("Note: Could not check for materialized views: " + e.getMessage());
        }
    }

    /**
     * Generate MD5 hash for executable (from actual program bytes when available)
     */
    private String generateMD5(Program program) {
        try {
            // Try to get actual executable MD5 from Ghidra
            String execMD5 = program.getExecutableMD5();
            if (execMD5 != null && !execMD5.isEmpty()) {
                return execMD5.toLowerCase();
            }
            // Fallback: generate from program name + executable path
            String input = program.getName() + "_" + program.getExecutablePath();
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("MD5");
            byte[] hash = md.digest(input.getBytes());
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (Exception e) {
            return "unknown_md5";
        }
    }

    /**
     * Generate SHA256 hash for executable (from actual program bytes when available)
     */
    private String generateSHA256(Program program) {
        try {
            // Try to get actual executable SHA256 from Ghidra
            String execSHA256 = program.getExecutableSHA256();
            if (execSHA256 != null && !execSHA256.isEmpty()) {
                return execSHA256.toLowerCase();
            }
            // Fallback: generate from program name + executable path
            String input = program.getName() + "_" + program.getExecutablePath();
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(input.getBytes());
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (Exception e) {
            return "unknown_sha256";
        }
    }

    /**
     * Get architecture as string for authentic BSim schema (for lookup table)
     */
    private String getArchitectureString() {
        String arch = currentProgram.getLanguage().getProcessor().toString().toLowerCase();
        if (arch.contains("x86") && arch.contains("64")) {
            return "x86_64";  // Use standard lookup table value
        } else if (arch.contains("x86")) {
            return "x86";
        } else {
            return "unknown";
        }
    }

    /**
     * Get compiler as string for authentic BSim schema (for lookup table)
     * Determines compiler based on game version - Diablo 2 used specific compilers per era
     */
    private String getCompilerString() {
        return getCompilerForVersion(currentVersionInfo);
    }

    /**
     * Determine the compiler used for a specific Diablo 2 version
     * 
     * Compiler history:
     * - 1.00 - 1.09d: Visual C++ 6.0 (MSVC 6.0, released 1998)
     * - 1.10 - 1.13d: Visual C++ 6.0 (same compiler maintained for compatibility)
     * - 1.14 - 1.14d: Visual Studio 2015 (modern recompile for Windows 10 compatibility)
     */
    private String getCompilerForVersion(UnifiedVersionInfo versionInfo) {
        if (versionInfo == null || versionInfo.gameVersion == null) {
            return "unknown";
        }
        
        Integer versionCode = versionInfo.getVersionCode();
        if (versionCode == null) {
            return "unknown";
        }
        
        // 1.14+ = Visual Studio 2015 (Windows 10 recompile)
        if (versionCode >= 1140) {
            return "visualstudio:2015";
        }
        
        // 1.00 - 1.13d = Visual C++ 6.0
        // This covers the entire vanilla era before the 2016 update
        return "visualstudio:vc6";
    }

    /**
     * Get repository as string for authentic BSim schema (for lookup table)
     */
    private String getRepositoryString() {
        // For local Ghidra analysis, use "local" repository
        return "local";
    }

    /**
     * Get path as string for authentic BSim schema (for lookup table)
     * Returns Ghidra project folder path like "/vanilla/1.09d" or "/vanilla/1.07"
     */
    private String getPathString() {
        return getPathForVersion(currentVersionInfo);
    }

    /**
     * Construct Ghidra project folder path from version info
     * Format: /vanilla/{GameVersion}
     * Examples: /vanilla/1.00, /vanilla/1.07, /vanilla/1.09d
     */
    private String getPathForVersion(UnifiedVersionInfo versionInfo) {
        if (versionInfo == null) {
            return "/unknown";
        }
        
        String family = "vanilla";
        String version = versionInfo.gameVersion;
        
        // Normalize version
        if (version == null || version.equals("Unknown")) {
            version = "unknown";
        }
        
        // Handle mod versions (e.g., "1.13c-PD2" -> use base version)
        if (version.contains("-")) {
            version = version.split("-")[0];
        }
        
        return "/" + family + "/" + version;
    }

    /**
     * Get plate comment for a function (used for desctable.val field)
     */
    private String getPlateComment(Program program, Function function) {
        try {
            CodeUnit cu = program.getListing().getCodeUnitAt(function.getEntryPoint());
            if (cu != null) {
                String comment = cu.getComment(ghidra.program.model.listing.CommentType.PLATE);
                if (comment != null && !comment.trim().isEmpty()) {
                    return comment.trim();
                }
            }
        } catch (Exception e) {
            // Ignore - plate comment is optional
        }
        return null;  // NULL in database if no plate comment
    }

    /**
     * Generate signature ID for function
     */
    private long generateSignatureId(Function function) {
        String signature = function.getName() + "_" + function.getBody().getNumAddresses();
        return Math.abs(signature.hashCode());
    }

    /**
     * Comprehensive Function Analysis and Tagging System
     * Applies multiple categories of tags for reverse engineering, modding, and analysis
     */
    private void applyFunctionTags(Program program, Function function) {
        try {
            // Get function information
            String functionName = function.getName();
            Address entryPoint = function.getEntryPoint();

            // Start Ghidra transaction for function tag modifications
            int transactionID = program.startTransaction("Apply Function Tags");
            try {
                // Clear existing auto-generated tags to avoid duplicates
                clearAutoTags(function);

                // Apply all tagging categories
                applyLibraryFunctionTags(function, functionName);
                applyFunctionTypeTags(program, function);
                applyCallingPatternTags(program, function);
                applyGameLogicTags(program, function, functionName);
                applyUtilityFunctionTags(program, function);
                applyModRelevantTags(program, function);
                applyComplexityTags(program, function);
                applyArchitecturalTags(program, function);

            } finally {
                // End Ghidra transaction
                program.endTransaction(transactionID, true);
            }

        } catch (Exception e) {
            // Don't fail the entire process if tagging fails
            println("Warning: Could not tag function " + function.getName() + ": " + e.getMessage());
        }
    }

    /**
     * Store detailed function analysis metrics in the database
     */
    private void storeFunctionAnalysis(Connection conn, Function function, int executableId, Program program) {
        try {
            // Calculate comprehensive function metrics
            FunctionAnalysisMetrics metrics = calculateFunctionMetrics(program, function);

            // Store function analysis data
            String insertAnalysisSql = """
                INSERT INTO function_analysis
                (function_id, executable_id, function_name, entry_address, instruction_count,
                 basic_block_count, cyclomatic_complexity, calls_made, calls_received,
                 has_loops, has_recursion, max_depth, stack_frame_size, calling_convention,
                 is_leaf_function, is_library_function, is_thunk, confidence_score)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (function_id, executable_id) DO UPDATE SET
                instruction_count = EXCLUDED.instruction_count,
                cyclomatic_complexity = EXCLUDED.cyclomatic_complexity,
                analyzed_at = CURRENT_TIMESTAMP
            """;

            try (PreparedStatement stmt = conn.prepareStatement(insertAnalysisSql)) {
                stmt.setInt(1, getFunctionId(conn, function, executableId));
                stmt.setInt(2, executableId);
                stmt.setString(3, function.getName());
                stmt.setLong(4, function.getEntryPoint().getOffset());
                stmt.setInt(5, metrics.instructionCount);
                stmt.setInt(6, metrics.basicBlockCount);
                stmt.setInt(7, metrics.cyclomaticComplexity);
                stmt.setInt(8, metrics.callsMade);
                stmt.setInt(9, metrics.callsReceived);
                stmt.setBoolean(10, metrics.hasLoops);
                stmt.setBoolean(11, metrics.hasRecursion);
                stmt.setInt(12, metrics.maxDepth);
                stmt.setInt(13, metrics.stackFrameSize);
                stmt.setString(14, function.getCallingConventionName());
                stmt.setBoolean(15, metrics.isLeafFunction);
                stmt.setBoolean(16, metrics.isLibraryFunction);
                stmt.setBoolean(17, function.isThunk());
                stmt.setFloat(18, metrics.confidenceScore);

                stmt.executeUpdate();
            }

            // Store function tags in database
            storeFunctionTags(conn, function, executableId);

        } catch (SQLException e) {
            // Log but don't fail the entire process
            println("Warning: Could not store analysis for function " + function.getName() + ": " + e.getMessage());
        }
    }

    /**
     * Store function tags in the database
     */
    private void storeFunctionTags(Connection conn, Function function, int executableId) throws SQLException {
        int functionId = getFunctionId(conn, function, executableId);

        // Clear existing auto-generated tags
        String deleteSql = "DELETE FROM function_tags WHERE function_id = ? AND executable_id = ? AND auto_generated = true";
        try (PreparedStatement deleteStmt = conn.prepareStatement(deleteSql)) {
            deleteStmt.setInt(1, functionId);
            deleteStmt.setInt(2, executableId);
            deleteStmt.executeUpdate();
        }

        // Insert new tags
        String insertSql = """
            INSERT INTO function_tags (function_id, executable_id, tag_category, tag_value, confidence, auto_generated)
            VALUES (?, ?, ?, ?, ?, true)
            ON CONFLICT (function_id, executable_id, tag_category, tag_value) DO NOTHING
        """;

        try (PreparedStatement insertStmt = conn.prepareStatement(insertSql)) {
            // Get all tags from Ghidra and convert to strings
            Set<ghidra.program.model.listing.FunctionTag> functionTags = function.getTags();

            for (ghidra.program.model.listing.FunctionTag tagObj : functionTags) {
                String tag = tagObj.getName();
                if (tag.contains("_")) {
                    String[] parts = tag.split("_", 2);
                    String category = parts[0];
                    String value = parts.length > 1 ? parts[1] : tag;

                    insertStmt.setInt(1, functionId);
                    insertStmt.setInt(2, executableId);
                    insertStmt.setString(3, category);
                    insertStmt.setString(4, value);
                    insertStmt.setFloat(5, 1.0f); // Default confidence
                    insertStmt.executeUpdate();
                }
            }
        }
    }

    /**
     * Get function ID from the database
     */
    private int getFunctionId(Connection conn, Function function, int executableId) throws SQLException {
        String sql = "SELECT id FROM desctable WHERE name_func = ? AND id_exe = ? AND addr = ?";
        try (PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, function.getName());
            stmt.setInt(2, executableId);
            stmt.setLong(3, function.getEntryPoint().getOffset());

            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                return rs.getInt("id");
            }
        }
        throw new SQLException("Function not found in database: " + function.getName());
    }

    /**
     * Store function analysis with known function ID (more efficient)
     */
    private void storeFunctionAnalysisWithId(Connection conn, Function function, int functionId, int executableId, Program program) {
        try {
            // Calculate comprehensive function metrics
            FunctionAnalysisMetrics metrics = calculateFunctionMetrics(program, function);

            // Store function analysis data
            String insertAnalysisSql = """
                INSERT INTO function_analysis
                (function_id, executable_id, function_name, entry_address, instruction_count,
                 basic_block_count, cyclomatic_complexity, calls_made, calls_received,
                 has_loops, has_recursion, max_depth, stack_frame_size, calling_convention,
                 is_leaf_function, is_library_function, is_thunk, confidence_score)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (function_id, executable_id) DO UPDATE SET
                instruction_count = EXCLUDED.instruction_count,
                cyclomatic_complexity = EXCLUDED.cyclomatic_complexity,
                analyzed_at = CURRENT_TIMESTAMP
            """;

            try (PreparedStatement stmt = conn.prepareStatement(insertAnalysisSql)) {
                stmt.setInt(1, functionId);
                stmt.setInt(2, executableId);
                stmt.setString(3, function.getName());
                stmt.setLong(4, function.getEntryPoint().getOffset());
                stmt.setInt(5, metrics.instructionCount);
                stmt.setInt(6, metrics.basicBlockCount);
                stmt.setInt(7, metrics.cyclomaticComplexity);
                stmt.setInt(8, metrics.callsMade);
                stmt.setInt(9, metrics.callsReceived);
                stmt.setBoolean(10, metrics.hasLoops);
                stmt.setBoolean(11, metrics.hasRecursion);
                stmt.setInt(12, metrics.maxDepth);
                stmt.setInt(13, metrics.stackFrameSize);
                stmt.setString(14, metrics.callingConvention);
                stmt.setBoolean(15, metrics.isLeafFunction);
                stmt.setBoolean(16, metrics.isLibraryFunction);
                stmt.setBoolean(17, metrics.isThunk);
                stmt.setFloat(18, metrics.confidenceScore);

                stmt.executeUpdate();
            }

        } catch (SQLException e) {
            // Log but don't fail the entire process
            println("Warning: Could not store analysis for function " + function.getName() + ": " + e.getMessage());
        }
    }

    /**
     * Store function tags with known function ID (more efficient)
     */
    private void storeFunctionTagsWithId(Connection conn, Function function, int functionId, int executableId) {
        try {
            // Clear existing auto-generated tags
            String deleteSql = "DELETE FROM function_tags WHERE function_id = ? AND executable_id = ? AND auto_generated = true";
            try (PreparedStatement deleteStmt = conn.prepareStatement(deleteSql)) {
                deleteStmt.setInt(1, functionId);
                deleteStmt.setInt(2, executableId);
                deleteStmt.executeUpdate();
            }

            // Insert new tags from Ghidra function tags
            String insertSql = """
                INSERT INTO function_tags (function_id, executable_id, tag_category, tag_value, confidence, auto_generated)
                VALUES (?, ?, ?, ?, ?, true)
                ON CONFLICT (function_id, executable_id, tag_category, tag_value) DO NOTHING
            """;

            try (PreparedStatement insertStmt = conn.prepareStatement(insertSql)) {
                // Get all tags from Ghidra and convert to strings
                Set<ghidra.program.model.listing.FunctionTag> functionTags = function.getTags();

                for (ghidra.program.model.listing.FunctionTag tagObj : functionTags) {
                    String tag = tagObj.getName();
                    if (tag.contains("_")) {
                        String[] parts = tag.split("_", 2);
                        String category = parts[0];
                        String value = parts.length > 1 ? parts[1] : tag;

                        insertStmt.setInt(1, functionId);
                        insertStmt.setInt(2, executableId);
                        insertStmt.setString(3, category);
                        insertStmt.setString(4, value);
                        insertStmt.setFloat(5, 0.8f); // Default confidence
                        insertStmt.executeUpdate();
                    }
                }
            }

        } catch (SQLException e) {
            println("Warning: Could not tag function " + function.getName() + ": " + e.getMessage());
        }
    }

    /**
     * Calculate comprehensive function metrics
     */
    private FunctionAnalysisMetrics calculateFunctionMetrics(Program program, Function function) {
        FunctionAnalysisMetrics metrics = new FunctionAnalysisMetrics();

        try {
            AddressSetView body = function.getBody();

            // Count instructions and track jump targets for basic block detection
            Set<Address> jumpTargets = new HashSet<>();
            Set<Address> jumpSources = new HashSet<>();
            InstructionIterator instructions = program.getListing().getInstructions(body, true);
            
            while (instructions.hasNext()) {
                Instruction instr = instructions.next();
                metrics.instructionCount++;
                
                // Track jump/branch targets for basic block and loop detection
                if (instr.getFlowType().isJump() || instr.getFlowType().isConditional()) {
                    Address[] flows = instr.getFlows();
                    for (Address flow : flows) {
                        if (body.contains(flow)) {
                            jumpTargets.add(flow);
                            // Check for backward jump (potential loop)
                            if (flow.getOffset() < instr.getAddress().getOffset()) {
                                metrics.hasLoops = true;
                            }
                        }
                    }
                    jumpSources.add(instr.getAddress());
                }
            }
            
            // Calculate basic block count
            // Basic blocks start at: function entry, jump targets, instruction after jumps
            metrics.basicBlockCount = calculateBasicBlockCount(program, function, jumpTargets, jumpSources);

            // Analyze function calls
            Set<Function> calledFunctions = function.getCalledFunctions(null);
            Set<Function> callingFunctions = function.getCallingFunctions(null);
            metrics.callsMade = calledFunctions.size();
            metrics.callsReceived = callingFunctions.size();

            // Check for recursion (function calls itself directly or indirectly)
            metrics.hasRecursion = checkForRecursion(function, calledFunctions);

            // Calculate max call depth (how deep the call chain goes from this function)
            metrics.maxDepth = calculateMaxCallDepth(function, new HashSet<>(), 0, 5); // Limit depth to 5 levels

            // Get stack frame size from Ghidra's analysis
            metrics.stackFrameSize = getStackFrameSize(function);

            // Determine function characteristics
            metrics.isLeafFunction = calledFunctions.isEmpty();
            metrics.isLibraryFunction = isLibraryFunction(function.getName());
            metrics.callingConvention = function.getCallingConventionName();
            metrics.isThunk = function.isThunk();

            // Basic complexity estimation
            metrics.cyclomaticComplexity = estimateCyclomaticComplexity(program, function);
            metrics.confidenceScore = calculateConfidenceScore(metrics);

        } catch (Exception e) {
            // Set defaults on error
            metrics.confidenceScore = 0.5f;
        }

        return metrics;
    }

    /**
     * Calculate the number of basic blocks in a function
     */
    private int calculateBasicBlockCount(Program program, Function function, 
                                         Set<Address> jumpTargets, Set<Address> jumpSources) {
        try {
            AddressSetView body = function.getBody();
            
            // Each address range in the function body is at minimum one basic block
            int blockCount = body.getNumAddressRanges();
            
            // Add blocks for jump targets within the function (these start new blocks)
            // Subtract 1 because function entry is already counted
            blockCount += Math.max(0, jumpTargets.size() - 1);
            
            // Ensure at least 1 basic block
            return Math.max(1, blockCount);
        } catch (Exception e) {
            return 1;
        }
    }

    /**
     * Check if function has recursion (calls itself directly or through immediate callees)
     */
    private boolean checkForRecursion(Function function, Set<Function> calledFunctions) {
        // Direct recursion: function calls itself
        for (Function called : calledFunctions) {
            if (called.getEntryPoint().equals(function.getEntryPoint())) {
                return true;
            }
        }
        
        // Check for indirect recursion (A calls B, B calls A) - one level deep
        for (Function called : calledFunctions) {
            try {
                Set<Function> secondLevelCalls = called.getCalledFunctions(null);
                for (Function secondLevel : secondLevelCalls) {
                    if (secondLevel.getEntryPoint().equals(function.getEntryPoint())) {
                        return true;
                    }
                }
            } catch (Exception e) {
                // Ignore errors in recursion detection
            }
        }
        
        return false;
    }

    /**
     * Calculate maximum call depth from this function
     * Limited to prevent infinite loops and excessive computation
     */
    private int calculateMaxCallDepth(Function function, Set<Address> visited, int currentDepth, int maxAllowedDepth) {
        if (currentDepth >= maxAllowedDepth) {
            return currentDepth;
        }
        
        Address funcAddr = function.getEntryPoint();
        if (visited.contains(funcAddr)) {
            return currentDepth; // Prevent infinite recursion
        }
        
        visited.add(funcAddr);
        
        try {
            Set<Function> calledFunctions = function.getCalledFunctions(null);
            
            if (calledFunctions.isEmpty()) {
                return currentDepth; // Leaf function
            }
            
            int maxDepth = currentDepth;
            for (Function called : calledFunctions) {
                // Skip external/library functions
                if (called.isExternal() || called.isThunk()) {
                    continue;
                }
                
                int depth = calculateMaxCallDepth(called, new HashSet<>(visited), currentDepth + 1, maxAllowedDepth);
                maxDepth = Math.max(maxDepth, depth);
            }
            
            return maxDepth;
        } catch (Exception e) {
            return currentDepth;
        }
    }

    /**
     * Get the stack frame size for a function
     */
    private int getStackFrameSize(Function function) {
        try {
            // Get the function's stack frame
            ghidra.program.model.listing.StackFrame stackFrame = function.getStackFrame();
            if (stackFrame != null) {
                // Get the size of local variables (negative offset from frame pointer)
                int localSize = Math.abs(stackFrame.getLocalSize());
                // Get the size of parameters (positive offset)
                int paramSize = stackFrame.getParameterSize();
                
                // Total frame size
                return localSize + paramSize;
            }
        } catch (Exception e) {
            // Error getting stack frame
        }
        return 0;
    }

    /**
     * Estimate cyclomatic complexity (simplified)
     */
    private int estimateCyclomaticComplexity(Program program, Function function) {
        try {
            AddressSetView body = function.getBody();
            int branches = 0;

            InstructionIterator instructions = program.getListing().getInstructions(body, true);
            while (instructions.hasNext()) {
                Instruction instr = instructions.next();

                // Check if instruction has conditional or jump flow
                if (instr.getFlowType().isConditional() || instr.getFlowType().isJump()) {
                    branches++;
                }
            }

            return Math.max(1, branches); // Minimum complexity is 1
        } catch (Exception e) {
            return 1; // Default complexity
        }
    }

    /**
     * Calculate confidence score based on available metrics
     * Higher scores indicate more reliable/complete analysis
     */
    private float calculateConfidenceScore(FunctionAnalysisMetrics metrics) {
        float score = 0.3f; // Base score

        // Instruction count indicates meaningful code
        if (metrics.instructionCount > 5) score += 0.15f;
        if (metrics.instructionCount > 20) score += 0.1f;
        
        // Multiple basic blocks indicate structured code
        if (metrics.basicBlockCount > 1) score += 0.1f;
        
        // Cyclomatic complexity indicates decision points analyzed
        if (metrics.cyclomaticComplexity > 1) score += 0.1f;
        
        // Non-library functions are more interesting for analysis
        if (!metrics.isLibraryFunction) score += 0.15f;
        
        // Stack frame detected indicates proper function analysis
        if (metrics.stackFrameSize > 0) score += 0.1f;
        
        // Calling convention identified
        if (metrics.callingConvention != null && !metrics.callingConvention.equals("UNKNOWN")) {
            score += 0.1f;
        }

        return Math.min(1.0f, score);
    }

    /**
     * Check if function appears to be a library function
     */
    private boolean isLibraryFunction(String functionName) {
        return functionName.startsWith("_") ||
               functionName.contains("@") ||
               isCRuntimeFunction(functionName) ||
               isDiablo2Library(functionName);
    }

    /**
     * Helper class to store function analysis metrics
     */
    private static class FunctionAnalysisMetrics {
        int instructionCount = 0;
        int basicBlockCount = 0;
        int cyclomaticComplexity = 1;
        int callsMade = 0;
        int callsReceived = 0;
        boolean hasLoops = false;
        boolean hasRecursion = false;
        int maxDepth = 0;
        int stackFrameSize = 0;
        boolean isLeafFunction = false;
        boolean isLibraryFunction = false;
        float confidenceScore = 0.5f;
        String callingConvention = "UNKNOWN";
        boolean isThunk = false;
    }

    /**
     * Clear existing auto-generated tags to prevent duplicates
     */
    private void clearAutoTags(Function function) {
        String[] autoTagPrefixes = {
            "LIBRARY_", "FUNCTION_", "GAME_LOGIC_", "UTILITY_", "MOD_",
            "COMPLEXITY_", "ARCH_", "PATTERN_"
        };

        for (String prefix : autoTagPrefixes) {
            function.removeTag(prefix);
        }
    }

    /**
     * Detect and tag library functions (Windows API, game engine libraries, etc.)
     */
    private void applyLibraryFunctionTags(Function function, String functionName) {

        // Windows API Detection
        if (isWindowsApiFunction(functionName)) {
            function.addTag("LIBRARY_WINDOWS_API");

            // Specific API categories
            if (functionName.matches(".*(?i)(createfile|readfile|writefile|getfileattributes).*")) {
                function.addTag("LIBRARY_FILE_IO");
            } else if (functionName.matches(".*(?i)(createprocess|exitprocess|createthread).*")) {
                function.addTag("LIBRARY_PROCESS_THREAD");
            } else if (functionName.matches(".*(?i)(virtualalloc|heapalloc|malloc).*")) {
                function.addTag("LIBRARY_MEMORY");
            } else if (functionName.matches(".*(?i)(socket|send|recv|connect).*")) {
                function.addTag("LIBRARY_NETWORK");
            }
        }

        // DirectX and Graphics Libraries
        if (functionName.matches(".*(?i)(d3d|directdraw|direct3d|opengl|glide).*")) {
            function.addTag("LIBRARY_GRAPHICS");
        }

        // Audio Libraries
        if (functionName.matches(".*(?i)(directsound|dsound|winmm|audio).*")) {
            function.addTag("LIBRARY_AUDIO");
        }

        // C Runtime Library
        if (isCRuntimeFunction(functionName)) {
            function.addTag("LIBRARY_CRT");
        }

        // Diablo 2 specific libraries
        if (isDiablo2Library(functionName)) {
            function.addTag("LIBRARY_DIABLO2_ENGINE");
        }
    }

    /**
     * Tag functions by their type (thunk, ordinal, pointer, entry, etc.)
     */
    private void applyFunctionTypeTags(Program program, Function function) {
        String functionName = function.getName();

        // Thunk functions (jump trampolines)
        if (function.isThunk()) {
            function.addTag("FUNCTION_THUNK");
        }

        // Functions exported by ordinal
        if (functionName.matches(".*ordinal_\\d+.*") || functionName.matches(".*Ordinal\\d+.*")) {
            function.addTag("FUNCTION_ORDINAL");
        }

        // Function pointers and callbacks
        if (functionName.contains("_ptr") || functionName.contains("Callback") ||
            functionName.contains("Handler") || functionName.contains("Proc")) {
            function.addTag("FUNCTION_POINTER");
        }

        // Entry points
        if (functionName.equals("entry") || functionName.equals("_start") ||
            functionName.equals("DllMain") || functionName.equals("WinMain")) {
            function.addTag("FUNCTION_ENTRY");
        }

        // External functions (imports)
        if (function.isExternal()) {
            function.addTag("FUNCTION_EXTERNAL");
        }
    }

    /**
     * Analyze calling patterns and tag accordingly
     */
    private void applyCallingPatternTags(Program program, Function function) {
        try {
            // Get function calls
            Set<Function> calledFunctions = function.getCalledFunctions(null);
            Set<Function> callingFunctions = function.getCallingFunctions(null);

            // Leaf functions (don't call other functions)
            if (calledFunctions.isEmpty()) {
                function.addTag("FUNCTION_LEAF");
            }

            // Functions that only call library/system functions
            if (!calledFunctions.isEmpty() && onlyCallsLibraryFunctions(calledFunctions)) {
                function.addTag("FUNCTION_ISOLATED");
            }

            // Highly connected functions (called by many other functions)
            if (callingFunctions.size() > 10) {
                function.addTag("FUNCTION_HEAVILY_USED");
            }

            // Functions that are never called (potential dead code)
            if (callingFunctions.isEmpty() && !function.isExternal() &&
                !function.getName().equals("entry")) {
                function.addTag("FUNCTION_UNUSED");
            }

        } catch (Exception e) {
            // Ignore calling pattern analysis errors
        }
    }

    /**
     * Identify and tag game logic functions (high-value reverse engineering targets)
     */
    private void applyGameLogicTags(Program program, Function function, String functionName) {

        // Player and Character Logic
        if (functionName.matches(".*(?i)(player|char|character|stats?).*")) {
            function.addTag("GAME_LOGIC_PLAYER");
        }

        // Combat and Damage Systems
        if (functionName.matches(".*(?i)(damage|combat|attack|hit|crit|defense).*")) {
            function.addTag("GAME_LOGIC_COMBAT");
        }

        // Item and Inventory Systems
        if (functionName.matches(".*(?i)(item|inventory|equip|drop|pick|loot).*")) {
            function.addTag("GAME_LOGIC_ITEMS");
        }

        // Skills and Spells
        if (functionName.matches(".*(?i)(skill|spell|magic|cast|mana).*")) {
            function.addTag("GAME_LOGIC_SKILLS");
        }

        // AI and Monster Logic
        if (functionName.matches(".*(?i)(monster|ai|enemy|mob|npc).*")) {
            function.addTag("GAME_LOGIC_AI");
        }

        // Network and Multiplayer
        if (functionName.matches(".*(?i)(network|multiplayer|sync|packet|client|server).*")) {
            function.addTag("GAME_LOGIC_NETWORK");
        }

        // World and Level Generation
        if (functionName.matches(".*(?i)(level|world|map|generate|seed|terrain).*")) {
            function.addTag("GAME_LOGIC_WORLD");
        }

        // Quest and Story Logic
        if (functionName.matches(".*(?i)(quest|story|dialog|npc|trigger).*")) {
            function.addTag("GAME_LOGIC_QUEST");
        }
    }

    /**
     * Identify utility functions
     */
    private void applyUtilityFunctionTags(Program program, Function function) {
        String functionName = function.getName();

        // String manipulation functions
        if (functionName.matches(".*(?i)(string|str|text|format|parse|convert).*")) {
            function.addTag("UTILITY_STRING");
        }

        // Mathematical functions
        if (functionName.matches(".*(?i)(math|calc|sin|cos|sqrt|pow|random|rand).*")) {
            function.addTag("UTILITY_MATH");
        }

        // Memory management
        if (functionName.matches(".*(?i)(alloc|free|memory|mem|pool|buffer).*")) {
            function.addTag("UTILITY_MEMORY");
        }

        // File operations
        if (functionName.matches(".*(?i)(file|read|write|save|load|config).*")) {
            function.addTag("UTILITY_FILE");
        }

        // Data conversion
        if (functionName.matches(".*(?i)(convert|transform|encode|decode|serialize).*")) {
            function.addTag("UTILITY_CONVERSION");
        }

        // Logging and debugging
        if (functionName.matches(".*(?i)(log|debug|print|trace|dump).*")) {
            function.addTag("UTILITY_DEBUG");
        }
    }

    /**
     * Tag functions relevant for modders
     */
    private void applyModRelevantTags(Program program, Function function) {
        String functionName = function.getName();

        // Data-driven functions (load from files, configurable)
        if (functionName.matches(".*(?i)(load|config|data|table|init|setup).*")) {
            function.addTag("MOD_DATA_DRIVEN");
        }

        // UI and interface functions
        if (functionName.matches(".*(?i)(ui|menu|interface|button|dialog|window).*")) {
            function.addTag("MOD_UI");
        }

        // Rendering and visual functions
        if (functionName.matches(".*(?i)(render|draw|sprite|texture|color|effect).*")) {
            function.addTag("MOD_VISUAL");
        }

        // Audio and sound functions
        if (functionName.matches(".*(?i)(sound|audio|music|sfx|play).*")) {
            function.addTag("MOD_AUDIO");
        }

        // Functions commonly hooked by mods
        if (isCommonlyHookedFunction(functionName)) {
            function.addTag("MOD_HOOKABLE");
        }
    }

    /**
     * Tag based on function complexity for analysis prioritization
     */
    private void applyComplexityTags(Program program, Function function) {
        try {
            // Get basic complexity metrics
            AddressSetView body = function.getBody();
            int instructionCount = 0;
            int basicBlockCount = 0;

            // Count instructions
            InstructionIterator instructions = program.getListing().getInstructions(body, true);
            while (instructions.hasNext()) {
                instructions.next();
                instructionCount++;
            }

            // Estimate complexity
            if (instructionCount < 10) {
                function.addTag("COMPLEXITY_TRIVIAL");
            } else if (instructionCount < 50) {
                function.addTag("COMPLEXITY_SIMPLE");
            } else if (instructionCount < 200) {
                function.addTag("COMPLEXITY_MODERATE");
            } else if (instructionCount < 500) {
                function.addTag("COMPLEXITY_COMPLEX");
            } else {
                function.addTag("COMPLEXITY_VERY_COMPLEX");
            }

        } catch (Exception e) {
            function.addTag("COMPLEXITY_UNKNOWN");
        }
    }

    /**
     * Architecture and calling convention specific tags
     */
    private void applyArchitecturalTags(Program program, Function function) {

        // Calling convention
        String callingConvention = function.getCallingConventionName();
        if (callingConvention != null) {
            function.addTag("ARCH_CALLING_" + callingConvention.toUpperCase());
        }

        // Stack frame analysis
        if (function.hasNoReturn()) {
            function.addTag("ARCH_NO_RETURN");
        }

        if (function.hasVarArgs()) {
            function.addTag("ARCH_VARARGS");
        }
    }

    // Helper methods for function classification

    private boolean isWindowsApiFunction(String functionName) {
        return functionName.startsWith("_") &&
               (functionName.contains("@") ||  // stdcall convention
                functionName.toLowerCase().matches(".*(get|set|create|open|close|read|write|alloc|free).*"));
    }

    private boolean isCRuntimeFunction(String functionName) {
        String[] crtPatterns = {
            "malloc", "free", "calloc", "realloc", "printf", "scanf", "strlen",
            "strcmp", "strcpy", "memcpy", "memset", "exit", "abort"
        };

        String lowerName = functionName.toLowerCase();
        for (String pattern : crtPatterns) {
            if (lowerName.contains(pattern)) {
                return true;
            }
        }
        return false;
    }

    private boolean isDiablo2Library(String functionName) {
        String[] d2Patterns = {
            "storm", "fog", "d2client", "d2common", "d2game", "d2gfx",
            "d2win", "d2lang", "d2net", "d2sound", "d2cmp"
        };

        String lowerName = functionName.toLowerCase();
        for (String pattern : d2Patterns) {
            if (lowerName.contains(pattern)) {
                return true;
            }
        }
        return false;
    }

    private boolean onlyCallsLibraryFunctions(Set<Function> calledFunctions) {
        for (Function called : calledFunctions) {
            if (!called.isExternal() && !called.getName().startsWith("_")) {
                return false;
            }
        }
        return true;
    }

    private boolean isCommonlyHookedFunction(String functionName) {
        String[] commonHooks = {
            "D2CLIENT_", "D2COMMON_", "D2GAME_", "GetUnitStat", "SetUnitStat",
            "GameDraw", "GameInput", "PlayerMove", "ItemClick", "SkillCast",
            "DamageCalc", "GameLoop", "PacketSend", "PacketReceive"
        };

        for (String hook : commonHooks) {
            if (functionName.contains(hook)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Extract plain executable name (no version prefix)
     * Version is stored separately in game_version field
     */
    private String extractExecutableName(String programName) {
        // Extract just the filename without any path
        String fileName = programName;
        if (fileName.contains("/")) {
            fileName = fileName.substring(fileName.lastIndexOf("/") + 1);
        }
        if (fileName.contains("\\")) {
            fileName = fileName.substring(fileName.lastIndexOf("\\") + 1);
        }

        // Preserve original filename as-is for data integrity
        // Note: Original filenames maintained to match actual file system names

        // Strip any version prefix that might be in the filename
        // Pattern: 1.XX_FileName.ext or 1.XXx_FileName.ext
        java.util.regex.Pattern versionPrefixPattern = 
            java.util.regex.Pattern.compile("^1\\.[0-9]+[a-z]?_(.+)$");
        java.util.regex.Matcher matcher = versionPrefixPattern.matcher(fileName);
        if (matcher.matches()) {
            fileName = matcher.group(1);
        }

        // Also handle Classic_1.XX_, LoD_1.XX_, and vanilla_1.XX_ prefixes (legacy support)
        java.util.regex.Pattern familyPrefixPattern = 
            java.util.regex.Pattern.compile("^(Classic|LoD|vanilla)_1\\.[0-9]+[a-z]?_(.+)$");
        java.util.regex.Matcher familyMatcher = familyPrefixPattern.matcher(fileName);
        if (familyMatcher.matches()) {
            fileName = familyMatcher.group(2);
        }

        return fileName;
    }

    /**
     * Ensures a game version exists in the game_versions table, creating it if necessary
     */
    private void ensureVersionExists(Connection conn, int versionCode, String versionString, String versionFamily) {
        try {
            // Check if version already exists
            String checkSql = "SELECT 1 FROM game_versions WHERE id = ?";
            try (PreparedStatement checkStmt = conn.prepareStatement(checkSql)) {
                checkStmt.setInt(1, versionCode);
                ResultSet rs = checkStmt.executeQuery();

                if (rs.next()) {
                    // Version already exists
                    return;
                }
            }

            // Create the version record with descriptive text
            String insertSql = "INSERT INTO game_versions (id, version_string, version_family, description) " +
                              "VALUES (?, ?, ?, ?) " +
                              "ON CONFLICT (id) DO NOTHING";

            try (PreparedStatement insertStmt = conn.prepareStatement(insertSql)) {
                insertStmt.setInt(1, versionCode);
                insertStmt.setString(2, versionString);
                insertStmt.setString(3, versionFamily);
                insertStmt.setString(4, getVersionDescription(versionString, versionFamily));

                int rowsInserted = insertStmt.executeUpdate();
                if (rowsInserted > 0) {
                    println("Created new game version: " + versionString + " (" + versionFamily + ")");
                }
            }

        } catch (SQLException e) {
            println("Warning: Could not ensure version " + versionString + " exists: " + e.getMessage());
            // Non-fatal error - continue processing
        }
    }

    /**
     * @deprecated Use extractExecutableName instead
     */
    @Deprecated
    private String generateUnifiedExecutableName(String programName, UnifiedVersionInfo versionInfo) {
        return extractExecutableName(programName);
    }

    /**
     * Ensure a specific game version exists in the game_versions table.
     * Only inserts the version being processed, not all versions upfront.
     */
    private void ensureGameVersionExists(Connection conn, int versionCode, String versionString) throws SQLException {
        String checkSql = "SELECT id FROM game_versions WHERE id = ?";
        String insertSql = "INSERT INTO game_versions (id, version_string, version_family, description) " +
                          "VALUES (?, ?, ?, ?) ON CONFLICT (id) DO NOTHING";
        
        try (PreparedStatement checkStmt = conn.prepareStatement(checkSql)) {
            checkStmt.setInt(1, versionCode);
            try (ResultSet rs = checkStmt.executeQuery()) {
                if (!rs.next()) {
                    // Version doesn't exist, insert it
                    String family = "vanilla";
                    String description = getVersionDescription(versionString, family);
                    
                    try (PreparedStatement insertStmt = conn.prepareStatement(insertSql)) {
                        insertStmt.setInt(1, versionCode);
                        insertStmt.setString(2, versionString);
                        insertStmt.setString(3, family);
                        insertStmt.setString(4, description);
                        insertStmt.executeUpdate();
                        println("  Created game_version entry: " + versionString + " (" + versionCode + ", " + family + ")");
                    }
                }
            }
        }
    }

    /**
     * Check if a version code represents a Classic-era version (1.00-1.06b)
     */
    private boolean isClassicVersionCode(int versionCode) {
        // Classic: 1.00 (1000) through 1.06b (1061)
        return versionCode >= 1000 && versionCode <= 1061;
    }

    /**
     * Generate a descriptive text for a game version.
     * Provides historical context about each Diablo 2 release.
     */
    private String getVersionDescription(String versionString, String family) {
        switch (versionString) {
            // Classic era (1.00 - 1.06b)
            case "1.00":
                return "Diablo II original release (June 29, 2000). Initial retail version.";
            case "1.01":
                return "First patch. Minor bug fixes and stability improvements.";
            case "1.02":
                return "Early patch. Bug fixes and balance adjustments.";
            case "1.03":
                return "Pre-LoD patch. Bug fixes and game balance changes.";
            case "1.04":
                return "Major Classic patch. Significant bug fixes and improvements.";
            case "1.04b":
                return "Classic hotfix. Critical bug fixes for 1.04.";
            case "1.04c":
                return "Classic stability patch. Additional fixes for 1.04 series.";
            case "1.05":
                return "Classic update. Balance changes and bug fixes.";
            case "1.05b":
                return "Classic hotfix. Fixes for 1.05 issues.";
            case "1.06":
                return "Final pre-LoD patch. Prepared game for expansion.";
            case "1.06b":
                return "Last Classic-only patch. Final fixes before LoD era.";
            
            // Lord of Destruction era (1.07+)
            case "1.07":
                return "Lord of Destruction initial release (June 29, 2001). Added Act V, new classes, items.";
            case "1.08":
                return "Early LoD patch. Balance adjustments and bug fixes.";
            case "1.09":
                return "Major LoD update. Synergies introduced, skill rebalancing.";
            case "1.09b":
                return "LoD hotfix. Bug fixes for 1.09.";
            case "1.09d":
                return "LoD stability patch. Additional fixes for 1.09 series.";
            case "1.10":
                return "Major content patch (October 2003). Uber Tristram, new runewords, ladder system.";
            case "1.10s":
                return "1.10 beta/stress test version. Pre-release testing build.";
            case "1.11":
                return "Content update. Pandemonium Event, new uber bosses.";
            case "1.11b":
                return "Hotfix for 1.11. Bug fixes and stability improvements.";
            case "1.12":
                return "CD-check removal patch. No longer requires disc in drive.";
            case "1.12a":
                return "Minor update to 1.12. Bug fixes.";
            case "1.13":
                return "Major patch. Respec feature introduced, skill changes.";
            case "1.13c":
                return "Popular modding base (March 2010). Stable version used by many mods.";
            case "1.13d":
                return "Final 1.13 update. Bug fixes and minor improvements.";
            case "1.14":
                return "Windows 10 compatibility update (March 2016). Modern OS support.";
            case "1.14a":
                return "First 1.14 hotfix. Compatibility improvements.";
            case "1.14b":
                return "Second 1.14 hotfix. Additional fixes.";
            case "1.14c":
                return "Third 1.14 hotfix. Stability improvements.";
            case "1.14d":
                return "Final official patch (June 2016). Last Blizzard-supported version.";
            
            default:
                return family + " version " + versionString + " - Diablo II patch.";
        }
    }

    /**
     * Store API imports (DLL dependencies) for an executable.
     * Called once per executable, not per function.
     */
    private void storeApiImports(Connection conn, int executableId, Program program) {
        String sql = "INSERT INTO api_imports " +
            "(executable_id, dll_name, function_name, ordinal_number, is_delayed) " +
            "VALUES (?, ?, ?, ?, ?) " +
            "ON CONFLICT (executable_id, dll_name, function_name) DO NOTHING";

        try {
            ghidra.program.model.listing.FunctionManager funcMgr = program.getFunctionManager();
            ghidra.program.model.symbol.ExternalManager extMgr = program.getExternalManager();
            
            int importCount = 0;
            
            try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
                // Iterate through external libraries
                for (String libraryName : extMgr.getExternalLibraryNames()) {
                    // Get all external locations from this library
                    ghidra.program.model.symbol.ExternalLocationIterator extLocs = 
                        extMgr.getExternalLocations(libraryName);
                    
                    while (extLocs.hasNext()) {
                        ghidra.program.model.symbol.ExternalLocation extLoc = extLocs.next();
                        String funcName = extLoc.getLabel();
                        
                        if (funcName != null && !funcName.isEmpty()) {
                            pstmt.setInt(1, executableId);
                            pstmt.setString(2, libraryName);
                            pstmt.setString(3, funcName);
                            
                            // Extract ordinal number from various sources
                            Integer ordinal = extractImportOrdinal(extLoc, funcName);
                            
                            if (ordinal != null) {
                                pstmt.setInt(4, ordinal);
                            } else {
                                pstmt.setNull(4, java.sql.Types.INTEGER);
                            }
                            pstmt.setBoolean(5, false);  // TODO: detect delayed imports
                            pstmt.addBatch();
                            importCount++;
                            
                            if (importCount % 100 == 0) {
                                pstmt.executeBatch();
                            }
                        }
                    }
                }
                pstmt.executeBatch();
            }
            
            if (importCount > 0) {
                println("Stored " + importCount + " API imports");
            }
        } catch (SQLException e) {
            if (!e.getMessage().contains("duplicate key")) {
                println("Note: Could not store API imports: " + e.getMessage());
            }
        } catch (Exception e) {
            println("Note: Error extracting API imports: " + e.getMessage());
        }
    }

    /**
     * Extract ordinal number from an import.
     * Checks multiple sources: original imported name, function name pattern.
     */
    private Integer extractImportOrdinal(ghidra.program.model.symbol.ExternalLocation extLoc, String funcName) {
        // Try original imported name first (most reliable for ordinal-only imports)
        String origName = extLoc.getOriginalImportedName();
        if (origName != null) {
            // Check for "Ordinal_123" pattern
            if (origName.startsWith("Ordinal_")) {
                try {
                    return Integer.parseInt(origName.substring(8));
                } catch (NumberFormatException e) {
                    // Not a valid ordinal
                }
            }
            // Check for pure numeric (rare but possible)
            try {
                return Integer.parseInt(origName);
            } catch (NumberFormatException e) {
                // Not numeric
            }
        }
        
        // Check function name for ordinal pattern
        if (funcName != null && funcName.startsWith("Ordinal_")) {
            try {
                return Integer.parseInt(funcName.substring(8));
            } catch (NumberFormatException e) {
                // Not a valid ordinal
            }
        }
        
        // Check for "#123" pattern sometimes used
        if (funcName != null && funcName.startsWith("#")) {
            try {
                return Integer.parseInt(funcName.substring(1));
            } catch (NumberFormatException e) {
                // Not a valid ordinal
            }
        }
        
        return null;
    }

    /**
     * Store API exports for an executable.
     * Called once per executable, not per function.
     */
    private void storeApiExports(Connection conn, int executableId, Program program) {
        String sql = "INSERT INTO api_exports " +
            "(executable_id, function_name, ordinal_number, rva_address, is_forwarded) " +
            "VALUES (?, ?, ?, ?, ?) " +
            "ON CONFLICT (executable_id, function_name) DO NOTHING";

        try {
            ghidra.program.model.symbol.SymbolTable symTable = program.getSymbolTable();
            ghidra.program.model.address.AddressIterator entryPoints = 
                symTable.getExternalEntryPointIterator();
            
            // Try to get ordinal info from PE headers if available
            Map<String, Integer> exportOrdinals = extractExportOrdinals(program);
            
            int exportCount = 0;
            
            try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
                while (entryPoints.hasNext()) {
                    ghidra.program.model.address.Address entryPoint = entryPoints.next();
                    ghidra.program.model.symbol.Symbol[] symbols = symTable.getSymbols(entryPoint);
                    
                    for (ghidra.program.model.symbol.Symbol sym : symbols) {
                        String exportName = sym.getName();
                        if (exportName != null && !exportName.isEmpty()) {
                            pstmt.setInt(1, executableId);
                            pstmt.setString(2, exportName);
                            
                            // Get ordinal from extracted map, or try to parse from name
                            Integer ordinal = exportOrdinals.get(exportName);
                            if (ordinal == null && exportName.startsWith("Ordinal_")) {
                                try {
                                    ordinal = Integer.parseInt(exportName.substring(8));
                                } catch (NumberFormatException e) {
                                    // Not a valid ordinal
                                }
                            }
                            
                            if (ordinal != null) {
                                pstmt.setInt(3, ordinal);
                            } else {
                                pstmt.setNull(3, java.sql.Types.INTEGER);
                            }
                            
                            pstmt.setLong(4, entryPoint.getOffset());
                            pstmt.setBoolean(5, false);  // TODO: detect forwarded exports
                            pstmt.addBatch();
                            exportCount++;
                            
                            if (exportCount % 100 == 0) {
                                pstmt.executeBatch();
                            }
                        }
                    }
                }
                pstmt.executeBatch();
            }
            
            if (exportCount > 0) {
                println("Stored " + exportCount + " API exports");
            }
        } catch (SQLException e) {
            if (!e.getMessage().contains("duplicate key")) {
                println("Note: Could not store API exports: " + e.getMessage());
            }
        } catch (Exception e) {
            println("Note: Error extracting API exports: " + e.getMessage());
        }
    }

    /**
     * Store binary-version association in the junction table.
     * This allows tracking when the same binary (by MD5) appears in multiple game versions.
     * Example: Storm.dll might be identical in 1.04b, 1.04c, and 1.05
     */
    private void storeBinaryVersionAssociation(Connection conn, int executableId, UnifiedVersionInfo versionInfo) {
        Integer versionCode = versionInfo.getVersionCode();
        String versionFamily = versionInfo.getValidatedVersionFamily();
        
        if (versionCode == null) {
            println("  Skipping binary_versions entry - no version code");
            return;
        }
        
        String insertSql = """
            INSERT INTO binary_versions (executable_id, game_version, version_family)
            VALUES (?, ?, ?)
            ON CONFLICT (executable_id, game_version) DO NOTHING
            """;
        
        try (PreparedStatement stmt = conn.prepareStatement(insertSql)) {
            stmt.setInt(1, executableId);
            stmt.setInt(2, versionCode);
            stmt.setString(3, versionFamily);
            
            int rows = stmt.executeUpdate();
            if (rows > 0) {
                println("  Recorded version association: binary " + executableId + " → version " + versionCode);
            } else {
                println("  Version association already exists for binary " + executableId + " → version " + versionCode);
            }
        } catch (SQLException e) {
            println("  Note: Could not store binary version association: " + e.getMessage());
        }
    }

    /**
     * Extract export ordinal numbers from PE export directory.
     * Returns a map of export name -> ordinal number.
     */
    private Map<String, Integer> extractExportOrdinals(Program program) {
        Map<String, Integer> ordinals = new HashMap<>();
        
        try {
            // Get the data type manager to find export structures
            ghidra.program.model.listing.Listing listing = program.getListing();
            ghidra.program.model.mem.Memory memory = program.getMemory();
            
            // Look for export directory in .edata section or search by data type
            ghidra.program.model.mem.MemoryBlock edataBlock = memory.getBlock(".edata");
            if (edataBlock == null) {
                // Try to find export info through symbols with ordinal in name
                ghidra.program.model.symbol.SymbolIterator symbols = 
                    program.getSymbolTable().getAllSymbols(true);
                int ordinalCounter = 1;
                while (symbols.hasNext()) {
                    ghidra.program.model.symbol.Symbol sym = symbols.next();
                    if (sym.isExternalEntryPoint()) {
                        String name = sym.getName();
                        // Check if this is an ordinal-only export
                        if (name.startsWith("Ordinal_")) {
                            try {
                                int ord = Integer.parseInt(name.substring(8));
                                ordinals.put(name, ord);
                            } catch (NumberFormatException e) {
                                // Skip
                            }
                        } else {
                            // For named exports, we can't determine ordinal without PE parsing
                            // Ghidra may have stored it in the symbol's ordinal property
                            // This is a simplified approach - ordinal assignment based on order
                        }
                    }
                }
            }
        } catch (Exception e) {
            // Failed to extract ordinals - will use NULL values
        }
        
        return ordinals;
    }

    /**
     * Store function signature during Step1 for efficiency
     */
    private void storeFunctionSignatureWithId(Connection conn, Function function, int functionId,
                                            int executableId, Program program) {
        try {
            // Generate basic signature information that can be extracted immediately
            String parameterTypes = getFunctionParameterTypes(function);
            String returnType = getFunctionReturnType(function);
            int parameterCount = function.getParameterCount();

            String insertSql = """
                INSERT INTO function_signatures
                (function_id, signature_text, parameter_count, return_type, calling_convention)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT (function_id) DO NOTHING
                """;

            try (PreparedStatement stmt = conn.prepareStatement(insertSql)) {
                stmt.setInt(1, functionId);
                stmt.setString(2, returnType + " " + function.getName() + "(" + parameterTypes + ")");
                stmt.setInt(3, parameterCount);
                stmt.setString(4, returnType);
                stmt.setString(5, function.getCallingConventionName());
                stmt.executeUpdate();
            }

        } catch (SQLException e) {
            // Don't fail entire process for signature storage
            println("Note: Could not store signature for " + function.getName() + ": " + e.getMessage());
        }
    }

    /**
     * Store function calls during Step1 for efficiency
     */
    private void storeFunctionCallsWithId(Connection conn, Function function, int functionId,
                                        int executableId, Program program) {
        // Get functions called by this function
        Set<Function> calledFunctions = function.getCalledFunctions(null);

        if (calledFunctions.isEmpty()) return;

        // Function calls enhancement disabled - schema mismatch
        // Script expects: (caller_function_id, caller_executable_id, callee_name)
        // Deployed schema has: (caller_function_id, callee_function_id, call_type)
        // Would require function ID lookup for callee functions
        // println("Skipping function calls enhancement - schema mismatch");
    }

    /**
     * Store API usage during Step1 for efficiency
     */
    private void storeApiUsageWithId(Connection conn, Function function, int functionId,
                                   int executableId, Program program) {
        try {
            // Check if function uses any imported APIs
            Set<Function> calledFunctions = function.getCalledFunctions(null);

            String insertSql = """
                INSERT INTO function_api_usage (function_id, executable_id, api_name, usage_type, usage_count)
                VALUES (?, ?, ?, 'call', 1)
                ON CONFLICT (function_id, executable_id, api_name)
                DO UPDATE SET usage_count = function_api_usage.usage_count + 1
                """;

            try (PreparedStatement stmt = conn.prepareStatement(insertSql)) {
                int apiCount = 0;
                for (Function calledFunc : calledFunctions) {
                    // Only store external/imported functions as API usage
                    if (calledFunc.isExternal() || calledFunc.getName().startsWith("_")) {
                        stmt.setInt(1, functionId);
                        stmt.setInt(2, executableId);
                        stmt.setString(3, calledFunc.getName());
                        stmt.addBatch();
                        apiCount++;
                    }
                }

                if (apiCount > 0) {
                    stmt.executeBatch();
                }
            }

        } catch (SQLException e) {
            println("Note: Could not store API usage for " + function.getName() + ": " + e.getMessage());
        }
    }

    /**
     * Store string references.
     * Uses the proper two-table schema:
     * - string_references: catalog of unique strings per executable
     * - function_string_refs: junction table linking functions to strings
     */
    private void storeStringReferencesWithId(Connection conn, Function function, int functionId,
                                            int executableId, Program program) {
        // SQL for string catalog (one entry per unique string address per executable)
        String insertStringSql = """
            INSERT INTO string_references 
            (executable_id, string_address, string_content, string_length, encoding_type)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT (executable_id, string_address) DO NOTHING
            """;

        // SQL to get string reference ID after insert
        String getStringIdSql = """
            SELECT id FROM string_references 
            WHERE executable_id = ? AND string_address = ?
            """;

        // SQL to link function to string
        String linkFunctionSql = """
            INSERT INTO function_string_refs 
            (function_id, string_ref_id, usage_type, reference_count)
            VALUES (?, ?, ?, ?)
            ON CONFLICT (function_id, string_ref_id) DO UPDATE SET
            reference_count = function_string_refs.reference_count + EXCLUDED.reference_count
            """;

        try {
            ghidra.program.model.address.AddressSetView body = function.getBody();
            ghidra.program.model.listing.Listing listing = program.getListing();
            ghidra.program.model.symbol.ReferenceManager refManager = program.getReferenceManager();

            // Collect string references with counts
            java.util.Map<Long, Object[]> stringRefs = new java.util.HashMap<>();

            ghidra.program.model.listing.InstructionIterator instructions = listing.getInstructions(body, true);
            while (instructions.hasNext()) {
                ghidra.program.model.listing.Instruction instr = instructions.next();

                ghidra.program.model.symbol.Reference[] refs = refManager.getReferencesFrom(instr.getAddress());
                for (ghidra.program.model.symbol.Reference ref : refs) {
                    if (ref.isMemoryReference()) {
                        ghidra.program.model.address.Address toAddr = ref.getToAddress();
                        ghidra.program.model.listing.Data data = listing.getDataAt(toAddr);

                        if (data != null && data.hasStringValue()) {
                            String strValue = data.getDefaultValueRepresentation();
                            if (strValue != null && strValue.length() > 1 && strValue.length() < 2000) {
                                long stringAddr = toAddr.getOffset();
                                Object[] existing = stringRefs.get(stringAddr);
                                if (existing == null) {
                                    // [content, length, encoding, refCount]
                                    String encoding = strValue.startsWith("u\"") ? "unicode" : "ascii";
                                    stringRefs.put(stringAddr, new Object[]{strValue, strValue.length(), encoding, 1});
                                } else {
                                    existing[3] = (Integer)existing[3] + 1;  // increment count
                                }
                            }
                        }
                    }
                }
            }

            if (stringRefs.isEmpty()) {
                return;
            }

            // Insert strings and link to function
            try (PreparedStatement insertStmt = conn.prepareStatement(insertStringSql);
                 PreparedStatement getIdStmt = conn.prepareStatement(getStringIdSql);
                 PreparedStatement linkStmt = conn.prepareStatement(linkFunctionSql)) {

                for (java.util.Map.Entry<Long, Object[]> entry : stringRefs.entrySet()) {
                    long stringAddr = entry.getKey();
                    Object[] data = entry.getValue();
                    String content = (String) data[0];
                    int length = (Integer) data[1];
                    String encoding = (String) data[2];
                    int refCount = (Integer) data[3];

                    // Insert into string catalog
                    insertStmt.setInt(1, executableId);
                    insertStmt.setLong(2, stringAddr);
                    insertStmt.setString(3, content);
                    insertStmt.setInt(4, length);
                    insertStmt.setString(5, encoding);
                    insertStmt.executeUpdate();

                    // Get the string reference ID
                    getIdStmt.setInt(1, executableId);
                    getIdStmt.setLong(2, stringAddr);
                    ResultSet rs = getIdStmt.executeQuery();
                    if (rs.next()) {
                        long stringRefId = rs.getLong("id");

                        // Link function to string
                        linkStmt.setInt(1, functionId);
                        linkStmt.setLong(2, stringRefId);
                        linkStmt.setString(3, "reference");
                        linkStmt.setInt(4, refCount);
                        linkStmt.executeUpdate();
                    }
                }
            }

        } catch (SQLException e) {
            if (!e.getMessage().contains("duplicate key")) {
                // Silent failure for non-critical table
            }
        } catch (Exception e) {
            // Don't fail for non-SQL errors
        }
    }

    /**
     * Extract function parameter types as string
     */
    private String getFunctionParameterTypes(Function function) {
        try {
            Parameter[] params = function.getParameters();
            if (params.length == 0) return "void";

            StringBuilder types = new StringBuilder();
            for (int i = 0; i < params.length; i++) {
                if (i > 0) types.append(", ");
                types.append(params[i].getDataType().getName());
            }
            return types.toString();
        } catch (Exception e) {
            return "unknown";
        }
    }

    /**
     * Extract function return type as string
     */
    private String getFunctionReturnType(Function function) {
        try {
            if (function.getReturnType() != null) {
                return function.getReturnType().getName();
            }
            return "void";
        } catch (Exception e) {
            return "unknown";
        }
    }

    /**
     * Store function parameters in the function_parameters table.
     * Captures ordinal, name, type, and storage location for each parameter.
     */
    private void storeFunctionParametersWithId(Connection conn, Function function, int functionId) {
        String sql = "INSERT INTO function_parameters " +
            "(function_id, ordinal, param_name, param_type, storage_location) " +
            "VALUES (?, ?, ?, ?, ?) " +
            "ON CONFLICT (function_id, ordinal) DO UPDATE SET " +
            "param_name = EXCLUDED.param_name, param_type = EXCLUDED.param_type, " +
            "storage_location = EXCLUDED.storage_location";

        try {
            Parameter[] params = function.getParameters();
            if (params == null || params.length == 0) {
                return;
            }

            try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
                for (int i = 0; i < params.length; i++) {
                    Parameter param = params[i];
                    pstmt.setInt(1, functionId);
                    pstmt.setInt(2, i);  // ordinal
                    pstmt.setString(3, param.getName());
                    pstmt.setString(4, param.getDataType() != null ? param.getDataType().getName() : "unknown");
                    pstmt.setString(5, param.getVariableStorage() != null ? 
                        param.getVariableStorage().toString() : "unknown");
                    pstmt.addBatch();
                }
                pstmt.executeBatch();
            }
        } catch (SQLException e) {
            if (!e.getMessage().contains("duplicate key")) {
                // Silent failure for non-critical table
            }
        } catch (Exception e) {
            // Don't fail for parameter extraction issues
        }
    }

    /**
     * Store data references (references to global data, not code) in data_references table.
     * Captures what global variables/data a function accesses.
     */
    private void storeDataReferencesWithId(Connection conn, Function function, int functionId, Program program) {
        String sql = "INSERT INTO data_references " +
            "(function_id, data_address, reference_type, access_type, reference_count) " +
            "VALUES (?, ?, ?, ?, ?) " +
            "ON CONFLICT (function_id, data_address, reference_type) DO UPDATE SET " +
            "reference_count = data_references.reference_count + EXCLUDED.reference_count";

        try {
            ghidra.program.model.address.AddressSetView body = function.getBody();
            ghidra.program.model.symbol.ReferenceManager refMgr = program.getReferenceManager();
            ghidra.program.model.listing.Listing listing = program.getListing();

            // Track data references with counts
            java.util.Map<String, int[]> dataRefs = new java.util.HashMap<>();

            for (ghidra.program.model.address.Address addr : body.getAddresses(true)) {
                ghidra.program.model.symbol.Reference[] refs = refMgr.getReferencesFrom(addr);
                for (ghidra.program.model.symbol.Reference ref : refs) {
                    ghidra.program.model.address.Address toAddr = ref.getToAddress();
                    
                    // Only interested in data references, not code
                    ghidra.program.model.listing.Data data = listing.getDataAt(toAddr);
                    if (data != null) {
                        String key = toAddr.getOffset() + "|" + ref.getReferenceType().getName();
                        int[] counts = dataRefs.computeIfAbsent(key, k -> new int[]{0});
                        counts[0]++;
                    }
                }
            }

            if (dataRefs.isEmpty()) {
                return;
            }

            try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
                for (java.util.Map.Entry<String, int[]> entry : dataRefs.entrySet()) {
                    String[] parts = entry.getKey().split("\\|");
                    long dataAddr = Long.parseLong(parts[0]);
                    String refType = parts[1];

                    pstmt.setInt(1, functionId);
                    pstmt.setLong(2, dataAddr);
                    pstmt.setString(3, refType);
                    pstmt.setString(4, refType.contains("READ") ? "read" : 
                                      (refType.contains("WRITE") ? "write" : "access"));
                    pstmt.setInt(5, entry.getValue()[0]);
                    pstmt.addBatch();
                }
                pstmt.executeBatch();
            }
        } catch (SQLException e) {
            if (!e.getMessage().contains("duplicate key")) {
                // Silent failure for non-critical table
            }
        } catch (Exception e) {
            // Don't fail for reference extraction issues
        }
    }

    /**
     * Store call graph metrics (incoming/outgoing calls, leaf/entry detection).
     * Computes structural information about function's position in call graph.
     */
    private void storeCallGraphMetricsWithId(Connection conn, Function function, int functionId, Program program) {
        String sql = "INSERT INTO call_graph_metrics " +
            "(function_id, incoming_calls, outgoing_calls, unique_callers, unique_callees, is_leaf, is_entry_point) " +
            "VALUES (?, ?, ?, ?, ?, ?, ?) " +
            "ON CONFLICT (function_id) DO UPDATE SET " +
            "incoming_calls = EXCLUDED.incoming_calls, outgoing_calls = EXCLUDED.outgoing_calls, " +
            "unique_callers = EXCLUDED.unique_callers, unique_callees = EXCLUDED.unique_callees, " +
            "is_leaf = EXCLUDED.is_leaf, is_entry_point = EXCLUDED.is_entry_point, " +
            "computed_at = NOW()";

        try {
            // Get calling functions (who calls this function)
            java.util.Set<ghidra.program.model.address.Address> callers = 
                new java.util.HashSet<>();
            ghidra.program.model.symbol.ReferenceIterator incomingRefs = 
                program.getReferenceManager().getReferencesTo(function.getEntryPoint());
            int incomingCount = 0;
            while (incomingRefs.hasNext()) {
                ghidra.program.model.symbol.Reference ref = incomingRefs.next();
                if (ref.getReferenceType().isCall()) {
                    incomingCount++;
                    callers.add(ref.getFromAddress());
                }
            }

            // Get called functions (functions this one calls)
            java.util.Set<ghidra.program.model.address.Address> callees = 
                new java.util.HashSet<>();
            int outgoingCount = 0;
            ghidra.program.model.address.AddressSetView body = function.getBody();
            for (ghidra.program.model.address.Address addr : body.getAddresses(true)) {
                // getReferencesFrom returns Reference[] (array), not iterator
                ghidra.program.model.symbol.Reference[] refs = 
                    program.getReferenceManager().getReferencesFrom(addr);
                for (ghidra.program.model.symbol.Reference ref : refs) {
                    if (ref.getReferenceType().isCall()) {
                        outgoingCount++;
                        callees.add(ref.getToAddress());
                    }
                }
            }

            // Determine leaf and entry point status
            boolean isLeaf = callees.isEmpty();
            boolean isEntryPoint = function.isExternal() || 
                program.getSymbolTable().getExternalEntryPointIterator()
                    .hasNext() && incomingCount == 0;

            try (PreparedStatement pstmt = conn.prepareStatement(sql)) {
                pstmt.setInt(1, functionId);
                pstmt.setInt(2, incomingCount);
                pstmt.setInt(3, outgoingCount);
                pstmt.setInt(4, callers.size());
                pstmt.setInt(5, callees.size());
                pstmt.setBoolean(6, isLeaf);
                pstmt.setBoolean(7, isEntryPoint);
                pstmt.executeUpdate();
            }
        } catch (SQLException e) {
            if (!e.getMessage().contains("duplicate key")) {
                // Silent failure for non-critical table
            }
        } catch (Exception e) {
            // Don't fail for metric computation issues
        }
    }

    // ========================================================================
    // ENHANCED SIGNATURE GENERATION (merged from Step2)
    // Generates structural signatures for BSim similarity matching inline
    // during function processing - no need for separate Step2 script
    // ========================================================================

    /**
     * Store enhanced BSim signature for similarity matching.
     * This performs structural analysis of the function (instruction count, basic blocks,
     * call patterns) and creates a signature hash for cross-version matching.
     * 
     * Previously required running Step2_GenerateBSimSignatures as a separate pass.
     * Now done inline during Step1 for efficiency - each function gets its signature
     * immediately after being added to the database.
     */
    private void storeEnhancedSignatureWithId(Connection conn, Function function, int functionId,
                                              int executableId, Program program) {
        try {
            // Compute structural signature metrics
            int instructionCount = 0;
            int basicBlockCount = function.getBody().getNumAddressRanges();
            int callCount = 0;

            // Count instructions and calls by iterating through function body
            InstructionIterator instructions = program.getListing().getInstructions(function.getBody(), true);
            while (instructions.hasNext()) {
                Instruction instruction = instructions.next();
                instructionCount++;
                if (instruction.getFlowType().isCall()) {
                    callCount++;
                }
            }

            // Generate feature vector for LSH-style matching
            String featureVector = String.format("inst:%d,bb:%d,calls:%d",
                instructionCount, basicBlockCount, callCount);

            // Calculate quality score (higher = more reliable for matching)
            double quality = 0.5; // Base quality
            if (instructionCount > 10) quality += 0.2;
            if (basicBlockCount > 1) quality += 0.2;
            if (callCount > 0) quality += 0.1;
            quality = Math.min(quality, 1.0);

            // Generate signature hash from structural properties
            String hashData = function.getName() + "_" + instructionCount + "_" +
                             basicBlockCount + "_" + callCount;
            String signatureHash = Integer.toHexString(hashData.hashCode());

            // Create JSON signature data
            String signatureData = String.format(
                "{\"instructionCount\":%d,\"basicBlockCount\":%d,\"callCount\":%d,\"quality\":%.2f,\"featureVector\":\"%s\"}",
                instructionCount, basicBlockCount, callCount, quality, featureVector);

            // Insert into enhanced_signatures table
            String insertSql = """
                INSERT INTO enhanced_signatures 
                    (function_id, executable_id, signature_hash, signature_data, lsh_vector, confidence_score)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT (function_id) DO NOTHING
                """;

            try (PreparedStatement stmt = conn.prepareStatement(insertSql)) {
                stmt.setInt(1, functionId);
                stmt.setInt(2, executableId);
                stmt.setString(3, signatureHash);
                stmt.setString(4, signatureData);
                stmt.setString(5, featureVector);
                stmt.setDouble(6, quality);
                stmt.executeUpdate();
            }

        } catch (SQLException e) {
            // Don't fail entire process for signature storage
            // This is non-critical - can be regenerated if needed
        }
    }
}