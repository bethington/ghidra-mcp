// BSim Step 4 Similarity Matrix
//
// Creates a comprehensive similarity matrix for cross-version function matching using structure-based, context-aware, and API-based analysis of function signatures.
//
// Usage: Run after Step1. Enhanced by Step3 data. Processes all versions in unified format.
// Output: Function similarity matrix with confidence scores and cross-version mappings.
//
// @author Ben Ethington
// @category Diablo 2.Analysis
// @description Generate cross-version function similarity matrix
// @menupath Diablo 2.Analysis.BSim Step 4 Similarity Matrix

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.util.exception.CancelledException;
import ghidra.framework.model.*;
import java.sql.*;
import java.util.*;
import java.util.regex.*;

public class Analyze_BSimStep4_SimilarityMatrix extends GhidraScript {

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

    private static final String[] VALID_GAME_VERSIONS = VERSION_CODES.keySet().toArray(new String[0]);
    private static final String[] VALID_VERSION_FAMILIES = {"vanilla"};

    // Unified version info helper - ported from Step1 for full folder structure parsing
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

            // Standard binaries: 1.03_D2Game.dll -> version: 1.03, family: vanilla
            Pattern standardPattern = Pattern.compile("^(1\\.[0-9]+[a-zA-Z]?)_([A-Za-z0-9_]+)\\.(dll|exe)$", Pattern.CASE_INSENSITIVE);
            Matcher standardMatcher = standardPattern.matcher(executableName);

            if (standardMatcher.matches()) {
                gameVersion = standardMatcher.group(1).toLowerCase();
                familyType = "vanilla";
                isException = false;
                return;
            }

            // Legacy exception binaries: Classic_1.03_Game.exe or LoD_1.03_Game.exe -> version: 1.03, family: vanilla
            Pattern exceptionPattern = Pattern.compile("^(Classic|LoD|vanilla)_(1\\.[0-9]+[a-zA-Z]?)_(Game|Diablo_II)\\.(exe|dll)$", Pattern.CASE_INSENSITIVE);
            Matcher exceptionMatcher = exceptionPattern.matcher(executableName);

            if (exceptionMatcher.matches()) {
                familyType = "vanilla";
                gameVersion = exceptionMatcher.group(2).toLowerCase();
                isException = true;
                return;
            }

            // Fallback: try to extract version from filename
            Pattern versionPattern = Pattern.compile("(1\\.[0-9]+[a-zA-Z]?)", Pattern.CASE_INSENSITIVE);
            Matcher versionMatcher = versionPattern.matcher(executableName);
            if (versionMatcher.find()) {
                gameVersion = versionMatcher.group(1).toLowerCase();
                familyType = "vanilla";
            }
        }

        /**
         * Parse version and family information from folder structure.
         * Expected structure: /vanilla/1.04b/D2Game.dll or /1.04b/D2Game.dll
         */
        private boolean parseFromFolderStructure(String projectPath) {
            if (projectPath == null || projectPath.isEmpty()) {
                return false;
            }

            String normalizedPath = projectPath.replace("\\", "/").replaceAll("^/+|/+$", "");
            String[] pathComponents = normalizedPath.split("/");

            // PASS 1: Look for vanilla (or legacy Classic/LoD) followed by version folder
            for (int i = 0; i < pathComponents.length; i++) {
                String component = pathComponents[i];

                if (component.equals("vanilla") || component.equals("Classic") || component.equals("LoD")) {
                    familyType = "vanilla";

                    if (i + 1 < pathComponents.length) {
                        String nextComponent = pathComponents[i + 1];
                        Pattern versionPattern = Pattern.compile("^(1\\.[0-9]+[a-z]?)$", Pattern.CASE_INSENSITIVE);
                        Matcher versionMatcher = versionPattern.matcher(nextComponent);

                        if (versionMatcher.matches()) {
                            gameVersion = nextComponent.toLowerCase();
                            return true;
                        }
                    }
                }
            }

            // PASS 2: Look for version folder directly (e.g., /1.04b/D2Game.dll)
            for (int i = 0; i < pathComponents.length; i++) {
                String component = pathComponents[i];
                Pattern versionPattern = Pattern.compile("^(1\\.[0-9]+[a-z]?)$", Pattern.CASE_INSENSITIVE);
                Matcher versionMatcher = versionPattern.matcher(component);

                if (versionMatcher.matches()) {
                    gameVersion = component.toLowerCase();
                    familyType = "vanilla";
                    isException = false;
                    return true;
                }
            }

            return false;
        }

        public boolean shouldSkip() {
            if (gameVersion == null || gameVersion.equals("Unknown")) {
                return true;
            }
            String baseVersion = gameVersion.contains("-") ? gameVersion.split("-")[0] : gameVersion;
            return !VERSION_CODES.containsKey(baseVersion);
        }

        public Integer getVersionCode() {
            if (gameVersion == null || gameVersion.equals("Unknown")) return null;
            String baseVersion = gameVersion.contains("-") ? gameVersion.split("-")[0] : gameVersion;
            return VERSION_CODES.get(baseVersion);
        }

        public String getValidatedGameVersion() {
            if (gameVersion == null || gameVersion.equals("Unknown")) return null;
            String baseVersion = gameVersion.contains("-") ? gameVersion.split("-")[0] : gameVersion;
            if (VERSION_CODES.containsKey(baseVersion)) {
                return baseVersion;
            }
            return null;
        }

        public String getValidatedVersionFamily() {
            return "vanilla";
        }

        public String getDisplayInfo() {
            if (gameVersion == null || gameVersion.equals("Unknown")) {
                return String.format("Invalid/Unknown format (detection: %s)", detectionMethod);
            }
            return String.format("vanilla %s (detected via %s)", gameVersion, detectionMethod);
        }

        public boolean isValid() {
            return gameVersion != null && !gameVersion.equals("Unknown") && VERSION_CODES.containsKey(gameVersion);
        }
    }

    // Similarity thresholds
    private static final double MIN_SIMILARITY = 0.7;
    private static final double MIN_CONFIDENCE = 15.0; // Lowered from 25.0 as confidence calc only goes to ~55

    // Mode selection constants
    private static final String MODE_SINGLE = "Single Program (current)";
    private static final String MODE_ALL = "All Programs in Project";
    private static final String MODE_VERSION = "Programs by Version Filter";

    @Override
    public void run() throws Exception {
        println("=== Function Similarity Matrix Generation ===");

        // Load database credentials from db.env
        loadDbConfig();

        // Ask user for processing mode
        String[] modes = { MODE_SINGLE, MODE_ALL, MODE_VERSION };
        String selectedMode = askChoice("Select Processing Mode",
            "How would you like to generate similarity matrix?",
            Arrays.asList(modes), MODE_SINGLE);

        if (selectedMode.equals(MODE_SINGLE)) {
            processSingleProgram();
        } else if (selectedMode.equals(MODE_ALL)) {
            processAllPrograms();
        } else if (selectedMode.equals(MODE_VERSION)) {
            processVersionFiltered();
        }
    }

    private void processSingleProgram() throws Exception {
        if (currentProgram == null) {
            popup("No program is currently open. Please open a program first.");
            return;
        }

        String programName = currentProgram.getName();
        String programPath = "";
        DomainFile domainFile = currentProgram.getDomainFile();
        if (domainFile != null) {
            programPath = domainFile.getPathname();
        }
        println("Program: " + programName);

        FunctionManager funcManager = currentProgram.getFunctionManager();
        int functionCount = funcManager.getFunctionCount();
        println("Functions in current program: " + functionCount);

        boolean proceed = askYesNo("Generate Similarity Matrix",
            String.format("Generate similarity matrix for %d functions?\n\nThis will:\n" +
            "- Compare functions against all other versions\n" +
            "- Calculate structural similarity scores\n" +
            "- Build cross-version relationships\n" +
            "- Replace name-based matching\n\nProceed?", functionCount));

        if (!proceed) {
            println("Operation cancelled by user");
            return;
        }

        try {
            generateSimilarityMatrix(currentProgram, programName, programPath);
            println("Successfully generated similarity matrix!");

        } catch (Exception e) {
            printerr("Error generating similarity matrix: " + e.getMessage());
            e.printStackTrace();
            throw e;
        }
    }

    private void processAllPrograms() throws Exception {
        Project project = state.getProject();
        if (project == null) {
            popup("No project is currently open.");
            return;
        }

        ProjectData projectData = project.getProjectData();
        DomainFolder rootFolder = projectData.getRootFolder();

        List<DomainFile> programFiles = new ArrayList<>();
        collectProgramFiles(rootFolder, programFiles);

        if (programFiles.isEmpty()) {
            popup("No program files found in the project.");
            return;
        }

        boolean proceed = askYesNo("Process All Programs",
            String.format("Found %d programs in project.\n\nGenerate similarity matrix for all programs?",
                programFiles.size()));

        if (!proceed) {
            println("Operation cancelled by user");
            return;
        }

        println("Processing " + programFiles.size() + " programs...");
        int successCount = 0;
        int errorCount = 0;

        for (DomainFile file : programFiles) {
            if (monitor.isCancelled()) break;

            try {
                processProjectFile(file);
                successCount++;
            } catch (Exception e) {
                printerr("Error processing " + file.getName() + ": " + e.getMessage());
                errorCount++;
            }
        }

        println(String.format("\n=== Batch Processing Complete ===\nSuccess: %d\nErrors: %d",
            successCount, errorCount));
    }

    private void processVersionFiltered() throws Exception {
        String versionFilter = askString("Version Filter",
            "Enter version pattern to match (e.g., '1.14' or 'D2R'):");

        if (versionFilter == null || versionFilter.trim().isEmpty()) {
            println("No version filter specified, operation cancelled.");
            return;
        }

        Project project = state.getProject();
        if (project == null) {
            popup("No project is currently open.");
            return;
        }

        ProjectData projectData = project.getProjectData();
        DomainFolder rootFolder = projectData.getRootFolder();

        List<DomainFile> allFiles = new ArrayList<>();
        collectProgramFiles(rootFolder, allFiles);

        // Filter by version
        List<DomainFile> matchingFiles = new ArrayList<>();
        for (DomainFile file : allFiles) {
            String path = file.getPathname();
            if (path.contains(versionFilter) || file.getName().contains(versionFilter)) {
                matchingFiles.add(file);
            }
        }

        if (matchingFiles.isEmpty()) {
            popup("No programs matching version '" + versionFilter + "' found.");
            return;
        }

        boolean proceed = askYesNo("Process Filtered Programs",
            String.format("Found %d programs matching '%s'.\n\nGenerate similarity matrix for these programs?",
                matchingFiles.size(), versionFilter));

        if (!proceed) {
            println("Operation cancelled by user");
            return;
        }

        println("Processing " + matchingFiles.size() + " matching programs...");
        int successCount = 0;
        int errorCount = 0;

        for (DomainFile file : matchingFiles) {
            if (monitor.isCancelled()) break;

            try {
                processProjectFile(file);
                successCount++;
            } catch (Exception e) {
                printerr("Error processing " + file.getName() + ": " + e.getMessage());
                errorCount++;
            }
        }

        println(String.format("\n=== Version Filtered Processing Complete ===\nVersion: %s\nSuccess: %d\nErrors: %d",
            versionFilter, successCount, errorCount));
    }

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

    private void processProjectFile(DomainFile file) throws Exception {
        println("\nProcessing: " + file.getPathname());
        monitor.setMessage("Processing: " + file.getName());

        Program program = (Program) file.getDomainObject(this, false, false, monitor);
        try {
            generateSimilarityMatrix(program, file.getName(), file.getPathname());
            println("  Similarity matrix generated successfully");
        } finally {
            program.release(this);
        }
    }

    private void generateSimilarityMatrix(Program program, String programName) throws Exception {
        // Delegate to path-aware version with null path (single-program mode)
        generateSimilarityMatrix(program, programName, null);
    }

    private void generateSimilarityMatrix(Program program, String programName, String programPath) throws Exception {
        println("Connecting to BSim database...");

        UnifiedVersionInfo versionInfo = new UnifiedVersionInfo(programName, programPath);
        println("Processing: " + programName + " (" + versionInfo.getDisplayInfo() + ")");

        try (Connection conn = DriverManager.getConnection(dbUrl, dbUser, dbPass)) {
            println("Connected to BSim database successfully");

            // Optimize connection for bulk operations
            conn.setAutoCommit(true); // Will be set to false in batch operations

            // Get current executable info
            int currentExeId = getExecutableId(conn, programName, versionInfo);
            if (currentExeId == -1) {
                String unifiedName = generateUnifiedExecutableName(programName, versionInfo);
                throw new RuntimeException(String.format("Current executable not found in database.\n" +
                    "  Tried: '%s', unified: '%s', version: %s\n" +
                    "  Run AddProgramToBSimDatabase.java first.",
                    programName, unifiedName, versionInfo.getDisplayInfo()));
            }

            // Get all other executables for comparison
            List<ExecutableInfo> otherExecutables = getOtherExecutables(conn, currentExeId);
            println("Found " + otherExecutables.size() + " other executables for comparison");

            // Process similarity for current program's functions
            processFunctionSimilarities(conn, program, currentExeId, otherExecutables, versionInfo);

        } catch (SQLException e) {
            printerr("Database error: " + e.getMessage());
            throw e;
        }
    }

    private int getExecutableId(Connection conn, String programName, UnifiedVersionInfo versionInfo) throws SQLException {
        // First try with the original name (for backward compatibility)
        String originalSql = "SELECT id FROM exetable WHERE name_exec = ?";
        try (PreparedStatement stmt = conn.prepareStatement(originalSql)) {
            stmt.setString(1, programName);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                return rs.getInt("id");
            }
        }

        // Try with unified name format (generated by Step1)
        String unifiedName = generateUnifiedExecutableName(programName, versionInfo);
        String unifiedSql = "SELECT id FROM exetable WHERE name_exec = ?";
        try (PreparedStatement stmt = conn.prepareStatement(unifiedSql)) {
            stmt.setString(1, unifiedName);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                println("Found executable using unified name: " + unifiedName);
                return rs.getInt("id");
            }
        }

        // Try partial matching for executables stored with different naming patterns
        // Order by function count to prefer more complete entries
        String partialSql = """
            SELECT e.id, e.name_exec, COUNT(d.id) as function_count
            FROM exetable e
            LEFT JOIN desctable d ON d.id_exe = e.id
            WHERE e.name_exec ILIKE ?
            GROUP BY e.id, e.name_exec
            ORDER BY function_count DESC, e.name_exec
            """;
        try (PreparedStatement stmt = conn.prepareStatement(partialSql)) {
            // Extract just the base filename
            String baseFileName = programName;
            if (baseFileName.contains("/")) {
                baseFileName = baseFileName.substring(baseFileName.lastIndexOf("/") + 1);
            }
            if (baseFileName.contains("\\")) {
                baseFileName = baseFileName.substring(baseFileName.lastIndexOf("\\") + 1);
            }

            stmt.setString(1, "%" + baseFileName);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                int id = rs.getInt("id");
                String foundName = rs.getString("name_exec");
                int functionCount = rs.getInt("function_count");
                println("Found executable using partial match: " + foundName + " (" + functionCount + " functions) for " + baseFileName);
                return id;
            }
        }

        return -1;
    }

    /**
     * Generate unified executable name (matching Step1 logic)
     */
    private String generateUnifiedExecutableName(String programName, UnifiedVersionInfo versionInfo) {
        String fileName = programName;
        if (fileName.contains("/")) {
            fileName = fileName.substring(fileName.lastIndexOf("/") + 1);
        }
        if (fileName.contains("\\")) {
            fileName = fileName.substring(fileName.lastIndexOf("\\") + 1);
        }
        fileName = fileName.replace(" ", "_");

        // Handle null/missing version info
        String gameVersion = versionInfo.gameVersion != null ? versionInfo.gameVersion : "Unknown";
        String familyType = versionInfo.familyType != null ? versionInfo.familyType : "vanilla";

        if (fileName.equals("Game.exe") || fileName.equals("Diablo_II.exe")) {
            return String.format("%s_%s_Diablo_II.exe", familyType, gameVersion);
        }
        return String.format("%s_%s", gameVersion, fileName);
    }

    private List<ExecutableInfo> getOtherExecutables(Connection conn, int currentExeId) throws SQLException {
        List<ExecutableInfo> executables = new ArrayList<>();

        String sql = """
            SELECT DISTINCT e.id, e.name_exec,
                   'vanilla' as game_type
            FROM exetable e
            JOIN desctable d ON e.id = d.id_exe
            JOIN enhanced_signatures es ON d.id = es.function_id
            WHERE e.id != ?
            ORDER BY e.name_exec
            """;

        try (PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setInt(1, currentExeId);
            ResultSet rs = stmt.executeQuery();

            while (rs.next()) {
                ExecutableInfo info = new ExecutableInfo();
                info.id = rs.getInt("id");
                info.name = rs.getString("name_exec");
                info.gameType = rs.getString("game_type");
                executables.add(info);
            }
        }

        return executables;
    }

    private void processFunctionSimilarities(Connection conn, Program program, int currentExeId,
                                           List<ExecutableInfo> otherExecutables, UnifiedVersionInfo currentVersionInfo) throws Exception {

        println("Processing function similarities...");
        monitor.setMessage("Generating similarity matrix");

        FunctionManager funcManager = program.getFunctionManager();
        FunctionIterator functions = funcManager.getFunctions(true);

        // Cache function IDs to avoid repeated database lookups
        Map<String, Long> functionIdCache = new HashMap<>();

        int processedCount = 0;
        int similarityCount = 0;

        // Prepare batch insert statement for better performance
        String insertSimilaritySql = """
            INSERT INTO function_similarity_matrix
            (source_function_id, target_function_id, similarity_score, confidence_score, match_type)
            VALUES (?, ?, ?, ?, 'structural_analysis')
            ON CONFLICT (source_function_id, target_function_id) DO UPDATE SET
                similarity_score = EXCLUDED.similarity_score,
                confidence_score = EXCLUDED.confidence_score,
                updated_at = now()
            """;

        // Prepare statement for single-match cross-version system
        String insertEquivalenceSql = """
            INSERT INTO function_equivalence (primary_function_id, primary_version, binary_name, canonical_name)
            VALUES (?, ?, ?, ?)
            ON CONFLICT (primary_function_id) DO NOTHING
            """;

        String insertBestMatchSql = """
            INSERT INTO function_version_matches (equivalence_id, target_function_id, target_version, similarity_score, match_method)
            VALUES (?, ?, ?, ?, 'similarity_analysis')
            ON CONFLICT (equivalence_id, target_version) DO UPDATE SET
                target_function_id = EXCLUDED.target_function_id,
                similarity_score = EXCLUDED.similarity_score,
                analyzed_at = NOW()
            WHERE EXCLUDED.similarity_score > function_version_matches.similarity_score
            """;

        // Set connection for better performance
        conn.setAutoCommit(false); // Enable batch processing

        try (PreparedStatement similarityStmt = conn.prepareStatement(insertSimilaritySql)) {
            int batchCount = 0;

            while (functions.hasNext() && !monitor.isCancelled()) {
                Function currentFunction = functions.next();
                processedCount++;

                if (processedCount % 50 == 0) {
                    monitor.setMessage(String.format("Processing function %d: %s",
                        processedCount, currentFunction.getName()));
                    println(String.format("Processed %d functions, found %d similarities...",
                        processedCount, similarityCount));
                }

                try {
                    // Get current function's ID from database (with caching)
                    String cacheKey = currentExeId + ":" + currentFunction.getName();
                    long currentFuncId = functionIdCache.computeIfAbsent(cacheKey,
                        k -> {
                            try {
                                return getFunctionId(conn, currentFunction.getName(), currentExeId);
                            } catch (SQLException e) {
                                return -1L;
                            }
                        });
                    if (currentFuncId == -1) continue;

                    // Get enhanced signature for current function from database
                    FunctionSignature currentSig = getFunctionSignatureFromDatabase(conn, currentFuncId);
                    if (currentSig == null) {
                        // Fallback to live analysis if no database signature
                        currentSig = generateFunctionSignature(currentFunction);
                        if (currentSig == null) continue;
                    }

                    // Compare against functions in other executables
                    for (ExecutableInfo otherExe : otherExecutables) {
                        List<FunctionCandidate> candidates = getSimilarFunctionCandidates(
                            conn, currentFunction, otherExe.id);

                        for (FunctionCandidate candidate : candidates) {
                            double similarity = calculateSimilarity(currentSig, candidate.signature);
                            double confidence = calculateConfidence(currentSig, candidate.signature);

                            if (similarity >= MIN_SIMILARITY && confidence >= MIN_CONFIDENCE) {
                                // Add to batch instead of immediate execution
                                similarityStmt.setLong(1, currentFuncId);
                                similarityStmt.setLong(2, candidate.functionId);
                                similarityStmt.setDouble(3, similarity);
                                similarityStmt.setDouble(4, confidence);

                                similarityStmt.addBatch();
                                batchCount++;
                                similarityCount++;

                                // Execute batch every 500 similarities for better performance
                                if (batchCount >= 500) {
                                    similarityStmt.executeBatch();
                                    conn.commit();
                                    batchCount = 0;
                                }
                            }
                        }
                    }

                } catch (Exception e) {
                    printerr("Error processing function " + currentFunction.getName() + ": " + e.getMessage());
                }
            }

            // Execute any remaining batch items
            if (batchCount > 0) {
                similarityStmt.executeBatch();
                conn.commit();
            }
        }

        // Restore autoCommit
        conn.setAutoCommit(true);

        if (monitor.isCancelled()) {
            println("Operation cancelled by user");
            return;
        }

        println(String.format("Generated %d similarity relationships for %d functions",
            similarityCount, processedCount));

        // Now populate the single-match cross-version system
        populateSingleMatchCrossVersionSystem(conn, currentExeId, currentVersionInfo, program.getName());
    }

    /**
     * Populate the single-match cross-version system using similarity matrix data
     */
    private void populateSingleMatchCrossVersionSystem(Connection conn, int currentExeId,
            UnifiedVersionInfo currentVersionInfo, String programName) throws SQLException {

        if (currentVersionInfo == null || currentVersionInfo.gameVersion == null) {
            println("Skipping cross-version system - no version information");
            return;
        }

        println("Populating single-match cross-version system for version " + currentVersionInfo.gameVersion);

        // Step 1: Create equivalence records for functions in current version (as primary)
        String createEquivalenceSql = """
            INSERT INTO function_equivalence (primary_function_id, primary_version, binary_name, canonical_name)
            SELECT d.id, ?, ?, d.name_func
            FROM desctable d
            WHERE d.id_exe = ?
            ON CONFLICT (primary_function_id) DO NOTHING
            """;

        int equivalenceCount = 0;
        try (PreparedStatement stmt = conn.prepareStatement(createEquivalenceSql)) {
            stmt.setString(1, currentVersionInfo.gameVersion);
            stmt.setString(2, extractBinaryName(programName));
            stmt.setInt(3, currentExeId);
            equivalenceCount = stmt.executeUpdate();
        }

        println(String.format("Created %d function equivalence records for primary version %s",
            equivalenceCount, currentVersionInfo.gameVersion));

        // Step 2: For each function in primary version, find single best match per target version
        String findBestMatchesSql = """
            WITH best_matches AS (
                SELECT
                    fe.id as equivalence_id,
                    fsm.target_function_id,
                    target_exe.game_version as target_version,
                    fsm.similarity_score,
                    ROW_NUMBER() OVER (PARTITION BY fe.id, target_exe.game_version ORDER BY fsm.similarity_score DESC) as rank
                FROM function_equivalence fe
                JOIN function_similarity_matrix fsm ON fe.primary_function_id = fsm.source_function_id
                JOIN desctable target_func ON fsm.target_function_id = target_func.id
                JOIN exetable target_exe ON target_func.id_exe = target_exe.id
                WHERE fe.primary_version = ?
                AND fe.binary_name = ?
                AND target_exe.game_version != fe.primary_version
                AND fsm.similarity_score >= 0.7  -- Only high-confidence matches
            )
            INSERT INTO function_version_matches (equivalence_id, target_function_id, target_version, similarity_score, match_method)
            SELECT equivalence_id, target_function_id, target_version, similarity_score, 'step4_similarity'
            FROM best_matches
            WHERE rank = 1
            ON CONFLICT (equivalence_id, target_version) DO UPDATE SET
                target_function_id = EXCLUDED.target_function_id,
                similarity_score = EXCLUDED.similarity_score,
                analyzed_at = NOW()
            WHERE EXCLUDED.similarity_score > function_version_matches.similarity_score
            """;

        int matchCount = 0;
        try (PreparedStatement stmt = conn.prepareStatement(findBestMatchesSql)) {
            stmt.setString(1, currentVersionInfo.gameVersion);
            stmt.setString(2, extractBinaryName(programName));
            matchCount = stmt.executeUpdate();
        }

        println(String.format("Found %d single best matches across other versions", matchCount));
    }

    /**
     * Extract binary name from the program being analyzed.
     * Uses the actual program name rather than a hardcoded value.
     */
    private String extractBinaryName(String programName) {
        if (programName != null && !programName.isEmpty()) {
            return programName;
        }
        return "Unknown";
    }

    private long getFunctionId(Connection conn, String functionName, int executableId) throws SQLException {
        String sql = "SELECT id FROM desctable WHERE name_func = ? AND id_exe = ?";
        try (PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, functionName);
            stmt.setInt(2, executableId);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                return rs.getLong("id");
            }
        }
        return -1;
    }

    private FunctionSignature getFunctionSignatureFromDatabase(Connection conn, long functionId) throws SQLException {
        String sql = """
            SELECT signature_data, signature_hash, lsh_vector
            FROM enhanced_signatures
            WHERE function_id = ?
            """;

        try (PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setLong(1, functionId);
            ResultSet rs = stmt.executeQuery();

            if (rs.next()) {
                return createSignatureFromDatabase(rs);
            }
        }
        return null;
    }

    private FunctionSignature generateFunctionSignature(Function function) {
        try {
            FunctionSignature sig = new FunctionSignature();

            // Basic metrics - fixed type conversion
            sig.instructionCount = (int)function.getBody().getNumAddresses();
            sig.parameterCount = function.getParameterCount();

            // Instruction pattern analysis
            sig.mnemonicPattern = extractMnemonicPattern(function);
            sig.operandPattern = extractOperandPattern(function);
            sig.controlFlowPattern = extractControlFlowPattern(function);

            // Function complexity
            sig.branchCount = countBranches(function);
            sig.callCount = countCalls(function);

            return sig;

        } catch (Exception e) {
            return null;
        }
    }

    private String extractMnemonicPattern(Function function) {
        Map<String, Integer> mnemonicCounts = new HashMap<>();
        AddressSetView body = function.getBody();
        InstructionIterator instructions = currentProgram.getListing().getInstructions(body, true);

        while (instructions.hasNext()) {
            Instruction instr = instructions.next();
            String mnemonic = instr.getMnemonicString();
            mnemonicCounts.merge(mnemonic, 1, Integer::sum);
        }

        // Create normalized pattern (top 5 most common mnemonics)
        return mnemonicCounts.entrySet().stream()
            .sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
            .limit(5)
            .map(e -> e.getKey() + ":" + e.getValue())
            .reduce("", (a, b) -> a.isEmpty() ? b : a + "," + b);
    }

    private String extractOperandPattern(Function function) {
        Map<String, Integer> operandTypes = new HashMap<>();
        AddressSetView body = function.getBody();
        InstructionIterator instructions = currentProgram.getListing().getInstructions(body, true);

        while (instructions.hasNext()) {
            Instruction instr = instructions.next();
            for (int i = 0; i < instr.getNumOperands(); i++) {
                int opType = instr.getOperandType(i);
                String opTypeStr = Integer.toString(opType); // Simplified operand type handling
                operandTypes.merge(opTypeStr, 1, Integer::sum);
            }
        }

        return operandTypes.entrySet().stream()
            .sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
            .limit(3)
            .map(e -> e.getKey() + ":" + e.getValue())
            .reduce("", (a, b) -> a.isEmpty() ? b : a + "," + b);
    }

    private String extractControlFlowPattern(Function function) {
        Map<String, Integer> flowTypes = new HashMap<>();
        AddressSetView body = function.getBody();
        InstructionIterator instructions = currentProgram.getListing().getInstructions(body, true);

        while (instructions.hasNext()) {
            Instruction instr = instructions.next();
            // Use flow type methods directly without variable
            if (instr.getFlowType().hasFallthrough() || instr.getFlowType().isJump() || instr.getFlowType().isCall()) {
                flowTypes.merge(instr.getFlowType().toString(), 1, Integer::sum);
            }
        }

        return flowTypes.entrySet().stream()
            .sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
            .map(e -> e.getKey() + ":" + e.getValue())
            .reduce("", (a, b) -> a.isEmpty() ? b : a + "," + b);
    }

    private int countBranches(Function function) {
        int branchCount = 0;
        AddressSetView body = function.getBody();
        InstructionIterator instructions = currentProgram.getListing().getInstructions(body, true);

        while (instructions.hasNext()) {
            Instruction instr = instructions.next();
            if (instr.getFlowType().isJump() || instr.getFlowType().isConditional()) {
                branchCount++;
            }
        }
        return branchCount;
    }

    private int countCalls(Function function) {
        return function.getCalledFunctions(monitor).size();
    }

    private List<FunctionCandidate> getSimilarFunctionCandidates(Connection conn, Function sourceFunc, int targetExeId) throws SQLException {
        List<FunctionCandidate> candidates = new ArrayList<>();

        // Get functions from target executable with their actual enhanced signatures
        String sql = """
            SELECT d.id, d.name_func, d.addr,
                   es.signature_data, es.signature_hash, es.lsh_vector
            FROM desctable d
            JOIN enhanced_signatures es ON d.id = es.function_id
            WHERE d.id_exe = ?
            AND es.signature_data IS NOT NULL
            ORDER BY d.addr
            LIMIT 200
            """;

        try (PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setInt(1, targetExeId);

            ResultSet rs = stmt.executeQuery();
            while (rs.next()) {
                FunctionCandidate candidate = new FunctionCandidate();
                candidate.functionId = rs.getLong("id");
                candidate.name = rs.getString("name_func");
                candidate.address = rs.getLong("addr");

                // Create signature from enhanced_signatures data
                candidate.signature = createSignatureFromDatabase(rs);

                candidates.add(candidate);
            }
        }

        return candidates;
    }

    private FunctionSignature createSignatureFromDatabase(ResultSet rs) throws SQLException {
        FunctionSignature sig = new FunctionSignature();

        // Use signature_data JSON to extract fields if available
        String signatureData = rs.getString("signature_data");
        String signatureHash = rs.getString("signature_hash");
        String lshVector = rs.getString("lsh_vector");

        if (signatureData != null && !signatureData.isEmpty()) {
            // Parse signature_data JSON to extract metrics (simplified parsing)
            try {
                if (signatureData.contains("instructionCount")) {
                    String instCount = signatureData.replaceAll(".*\"instructionCount\":(\\d+).*", "$1");
                    sig.instructionCount = Integer.parseInt(instCount);
                } else {
                    sig.instructionCount = signatureHash != null ? signatureHash.length() : 10;
                }
                sig.mnemonicPattern = signatureHash != null ? signatureHash.substring(0, Math.min(signatureHash.length(), 20)) : "";
            } catch (Exception e) {
                // Fallback values if parsing fails
                sig.instructionCount = 10;
                sig.mnemonicPattern = signatureHash != null ? signatureHash.substring(0, Math.min(signatureHash.length(), 10)) : "";
            }
        } else {
            // Use hash-based defaults
            sig.instructionCount = signatureHash != null ? signatureHash.length() : 10;
            sig.mnemonicPattern = signatureHash != null ? signatureHash.substring(0, Math.min(signatureHash.length(), 10)) : "";
        }

        sig.branchCount = 0; // Default since not available
        sig.callCount = 0; // Default since not available
        sig.parameterCount = 0; // Will enhance later if needed
        return sig;
    }

    private FunctionSignature createPlaceholderSignature(String functionName) {
        // Create a basic signature based on function name patterns
        FunctionSignature sig = new FunctionSignature();
        sig.instructionCount = functionName.length() * 10; // Rough estimate
        sig.mnemonicPattern = functionName.substring(0, Math.min(functionName.length(), 10));
        sig.parameterCount = 0;
        sig.branchCount = 0;
        sig.callCount = 0;
        return sig;
    }

    private double calculateSimilarity(FunctionSignature sig1, FunctionSignature sig2) {
        double similarity = 0.0;
        int factors = 0;

        // Instruction count similarity
        if (sig1.instructionCount > 0 && sig2.instructionCount > 0) {
            int minCount = Math.min(sig1.instructionCount, sig2.instructionCount);
            int maxCount = Math.max(sig1.instructionCount, sig2.instructionCount);
            similarity += (double) minCount / maxCount;
            factors++;
        }

        // Mnemonic pattern similarity
        if (sig1.mnemonicPattern != null && sig2.mnemonicPattern != null) {
            similarity += calculateStringSimilarity(sig1.mnemonicPattern, sig2.mnemonicPattern);
            factors++;
        }

        // Parameter count similarity
        if (sig1.parameterCount >= 0 && sig2.parameterCount >= 0) {
            if (sig1.parameterCount == sig2.parameterCount) {
                similarity += 1.0;
            } else if (Math.abs(sig1.parameterCount - sig2.parameterCount) <= 1) {
                similarity += 0.5;
            }
            factors++;
        }

        return factors > 0 ? similarity / factors : 0.0;
    }

    private double calculateStringSimilarity(String s1, String s2) {
        if (s1.equals(s2)) return 1.0;

        int maxLength = Math.max(s1.length(), s2.length());
        if (maxLength == 0) return 1.0;

        int commonChars = 0;
        for (int i = 0; i < Math.min(s1.length(), s2.length()); i++) {
            if (s1.charAt(i) == s2.charAt(i)) {
                commonChars++;
            }
        }

        return (double) commonChars / maxLength;
    }

    private double calculateConfidence(FunctionSignature sig1, FunctionSignature sig2) {
        // Confidence based on how many factors we could compare
        double confidence = 0.0;

        if (sig1.instructionCount > 10 && sig2.instructionCount > 10) confidence += 20.0;
        if (sig1.mnemonicPattern != null && sig1.mnemonicPattern.length() > 5) confidence += 15.0;
        if (sig1.branchCount > 0) confidence += 10.0;
        if (sig1.callCount > 0) confidence += 10.0;

        return Math.min(confidence, 100.0);
    }

    // Helper classes
    private static class ExecutableInfo {
        int id;
        String name;
        String gameType;
    }

    private static class FunctionSignature {
        int instructionCount;
        int parameterCount;
        String mnemonicPattern;
        String operandPattern;
        String controlFlowPattern;
        int branchCount;
        int callCount;
    }

    private static class FunctionCandidate {
        long functionId;
        String name;
        long address;
        FunctionSignature signature;
    }
}
