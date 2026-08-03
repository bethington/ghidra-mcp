// BSim Step 5 Complete Workflow
//
// Orchestrates the entire BSim workflow from ingestion through similarity analysis. Detects completed steps and runs missing ones, with batch processing and quality assurance.
//
// Usage: Run from Script Manager. Automatically determines which steps need execution.
// Output: Complete BSim analysis results with quality metrics and reports.
//
// @author Ben Ethington
// @category Diablo 2.Analysis
// @description Run the complete automated BSim analysis pipeline
// @menupath Diablo 2.Analysis.BSim Step 5 Complete Workflow

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.util.exception.CancelledException;
import ghidra.framework.model.*;
import java.sql.*;
import java.util.*;

public class Analyze_BSimStep5_CompleteWorkflow extends GhidraScript {

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
    private static final double MIN_SIMILARITY = 0.75;
    private static final double MIN_CONFIDENCE = 30.0;
    private static final int MAX_COMPARISONS = 2000; // Limit for performance

    // Scope selection constants
    private static final String SCOPE_SINGLE = "Single Program (current)";
    private static final String SCOPE_ALL = "All Programs in Project";
    private static final String SCOPE_VERSION = "Programs by Version Filter";

    // Current working program (set before processing each program)
    private Program workingProgram;

    @Override
    public void run() throws Exception {
        println("=== BSim Similarity-Based Cross-Version Matching ===");

        // Load database credentials from db.env
        loadDbConfig();

        // First ask for scope
        String[] scopes = { SCOPE_SINGLE, SCOPE_ALL, SCOPE_VERSION };
        String selectedScope = askChoice("Select Processing Scope",
            "Which programs would you like to process?",
            Arrays.asList(scopes), SCOPE_SINGLE);

        if (selectedScope.equals(SCOPE_SINGLE)) {
            processSingleProgram();
        } else if (selectedScope.equals(SCOPE_ALL)) {
            processAllPrograms();
        } else if (selectedScope.equals(SCOPE_VERSION)) {
            processVersionFiltered();
        }
    }

    private void processSingleProgram() throws Exception {
        if (currentProgram == null) {
            popup("No program is currently open. Please open a program first.");
            return;
        }

        String programName = currentProgram.getName();
        println("Program: " + programName);

        // Ask user for workflow mode
        String[] modes = {
            "Generate Enhanced Signatures Only",
            "Generate + Find Similar Functions",
            "Query Existing Similarities",
            "Full Workflow (Recommended)"
        };

        String selectedMode = askChoice("Select Workflow Mode",
            "What would you like to do?",
            Arrays.asList(modes), modes[3]);

        if (selectedMode.equals(modes[0])) {
            generateSignatures(currentProgram);
        } else if (selectedMode.equals(modes[1])) {
            generateSignatures(currentProgram);
            findSimilarFunctions(currentProgram);
        } else if (selectedMode.equals(modes[2])) {
            queryExistingSimilarities(currentProgram);
        } else if (selectedMode.equals(modes[3])) {
            runFullWorkflow(currentProgram);
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
            String.format("Found %d programs in project.\n\nRun full workflow for all programs?",
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
            String.format("Found %d programs matching '%s'.\n\nRun full workflow for these programs?",
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
            runFullWorkflow(program);
            println("  Workflow completed successfully");
        } finally {
            program.release(this);
        }
    }

    private void runFullWorkflow(Program program) throws Exception {
        println("\n=== Running Full BSim Similarity Workflow ===");

        // Set the working program for helper methods
        this.workingProgram = program;

        try {
            // Step 1: Generate signatures
            println("\n--- Step 1: Generating Enhanced Signatures ---");
            generateSignatures(program);

            // Step 2: Find similar functions
            println("\n--- Step 2: Finding Similar Functions ---");
            findSimilarFunctions(program);

            // Step 3: Update database relationships
            println("\n--- Step 3: Updating Database ---");
            updateCrossVersionRelationships(program);

            println("\n✅ Full BSim workflow completed successfully!");

        } catch (Exception e) {
            printerr("Error in BSim workflow: " + e.getMessage());
            e.printStackTrace();
            throw e;
        }
    }

    private void generateSignatures(Program program) throws Exception {
        println("Generating enhanced function signatures...");

        try (Connection conn = DriverManager.getConnection(dbUrl, dbUser, dbPass)) {
            int executableId = getExecutableId(conn, program.getName());
            if (executableId == -1) {
                throw new RuntimeException("Executable not found. Please run AddProgramToBSimDatabase.java first.");
            }

            generateProgramSignatures(conn, program, executableId);

        } catch (SQLException e) {
            printerr("Database error: " + e.getMessage());
            throw e;
        }
    }

    private void generateProgramSignatures(Connection conn, Program program, int executableId) throws Exception {
        println("Processing functions for signature generation...");

        FunctionManager funcManager = program.getFunctionManager();
        FunctionIterator functions = funcManager.getFunctions(true);

        int totalFunctions = funcManager.getFunctionCount();
        int processedCount = 0;
        int signatureCount = 0;

        // Ensure the table exists with correct schema
        ensureEnhancedSignaturesTable(conn);

        String insertSql = """
            INSERT INTO enhanced_signatures
            (function_id, executable_id, signature_data, signature_hash, lsh_vector, confidence_score)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT (function_id) DO UPDATE SET
                signature_data = EXCLUDED.signature_data,
                signature_hash = EXCLUDED.signature_hash,
                lsh_vector = EXCLUDED.lsh_vector,
                confidence_score = EXCLUDED.confidence_score,
                created_at = NOW()
            """;

        String getFunctionIdSql = "SELECT id FROM desctable WHERE name_func = ? AND id_exe = ?";

        try (PreparedStatement insertStmt = conn.prepareStatement(insertSql);
             PreparedStatement funcIdStmt = conn.prepareStatement(getFunctionIdSql)) {

            while (functions.hasNext() && !monitor.isCancelled()) {
                Function function = functions.next();
                processedCount++;

                if (processedCount % 100 == 0) {
                    monitor.setMessage(String.format("Processing function %d of %d: %s",
                        processedCount, totalFunctions, function.getName()));
                    println(String.format("Processed %d/%d functions...", processedCount, totalFunctions));
                }

                try {
                    // Get function ID
                    funcIdStmt.setString(1, function.getName());
                    funcIdStmt.setInt(2, executableId);
                    ResultSet rs = funcIdStmt.executeQuery();

                    if (!rs.next()) {
                        rs.close();
                        continue;
                    }

                    long functionId = rs.getLong("id");
                    rs.close();

                    // Generate signature
                    FunctionSignature signature = createEnhancedSignature(function);
                    if (signature != null) {
                        // Build JSON signature data
                        String signatureData = String.format("""
                            {"instructionCount":%d,"parameterCount":%d,"branchCount":%d,"callCount":%d,
                             "mnemonicPattern":"%s","controlFlowPattern":"%s","featureCount":%d}
                            """,
                            signature.instructionCount, signature.parameterCount, signature.branchCount,
                            signature.callCount, signature.mnemonicPattern.replace("\"", "\\\""),
                            signature.controlFlowPattern.replace("\"", "\\\""), signature.featureCount);

                        insertStmt.setLong(1, functionId);
                        insertStmt.setInt(2, executableId);
                        insertStmt.setString(3, signatureData);
                        insertStmt.setString(4, signature.mnemonicPattern); // Use as hash
                        insertStmt.setString(5, bytesToHex(signature.vectorData));
                        insertStmt.setDouble(6, signature.quality);

                        insertStmt.executeUpdate();
                        signatureCount++;
                    }

                } catch (Exception e) {
                    printerr("Error processing function " + function.getName() + ": " + e.getMessage());
                }
            }
        }

        println(String.format("Generated %d enhanced signatures for %d functions",
            signatureCount, processedCount));
    }

    private FunctionSignature createEnhancedSignature(Function function) {
        try {
            FunctionSignature sig = new FunctionSignature();

            // Basic metrics
            AddressSetView body = function.getBody();
            sig.instructionCount = (int)body.getNumAddresses();
            sig.parameterCount = function.getParameterCount();

            // Extract features
            List<Integer> features = extractFunctionFeatures(function);
            sig.vectorData = createSignatureVector(features);
            sig.featureCount = features.size();

            // Pattern analysis
            sig.mnemonicPattern = extractMnemonicPattern(function);
            sig.controlFlowPattern = extractControlFlowPattern(function);

            // Complexity metrics
            sig.branchCount = countBranches(function);
            sig.callCount = function.getCalledFunctions(monitor).size();

            // Quality assessment
            sig.quality = calculateSignatureQuality(sig);

            return sig;

        } catch (Exception e) {
            return null;
        }
    }

    private List<Integer> extractFunctionFeatures(Function function) {
        List<Integer> features = new ArrayList<>();

        try {
            AddressSetView body = function.getBody();
            InstructionIterator instructions = workingProgram.getListing().getInstructions(body, true);

            while (instructions.hasNext()) {
                Instruction instr = instructions.next();

                // Instruction features
                features.add(instr.getMnemonicString().hashCode());
                features.add(instr.getFlowType().hashCode());

                // Operand features
                for (int i = 0; i < instr.getNumOperands(); i++) {
                    features.add(instr.getOperandType(i));
                }
            }

            // Structural features
            features.add((int)function.getBody().getNumAddresses());
            features.add(function.getParameterCount());

        } catch (Exception e) {
            // Return partial features
        }

        return features;
    }

    private byte[] createSignatureVector(List<Integer> features) {
        if (features.isEmpty()) {
            return new byte[32];
        }

        byte[] vector = new byte[32]; // 256 bits

        for (int i = 0; i < 256; i++) {
            int hash = 0;
            for (Integer feature : features) {
                hash ^= (feature >>> (i % 32)) & 1;
            }

            if ((hash & 1) == 1) {
                vector[i / 8] |= (1 << (i % 8));
            }
        }

        return vector;
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
    }

    private String extractMnemonicPattern(Function function) {
        Map<String, Integer> mnemonics = new HashMap<>();
        AddressSetView body = function.getBody();
        InstructionIterator instructions = workingProgram.getListing().getInstructions(body, true);

        while (instructions.hasNext()) {
            Instruction instr = instructions.next();
            mnemonics.merge(instr.getMnemonicString(), 1, Integer::sum);
        }

        return mnemonics.entrySet().stream()
            .sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
            .limit(5)
            .map(e -> e.getKey() + ":" + e.getValue())
            .reduce("", (a, b) -> a.isEmpty() ? b : a + "," + b);
    }

    private String extractControlFlowPattern(Function function) {
        Map<String, Integer> flows = new HashMap<>();
        AddressSetView body = function.getBody();
        InstructionIterator instructions = workingProgram.getListing().getInstructions(body, true);

        while (instructions.hasNext()) {
            Instruction instr = instructions.next();
            // Use flow type methods directly without variable
            if (instr.getFlowType().hasFallthrough() || instr.getFlowType().isJump() || instr.getFlowType().isCall()) {
                flows.merge(instr.getFlowType().toString(), 1, Integer::sum);
            }
        }

        return flows.entrySet().stream()
            .sorted(Map.Entry.<String, Integer>comparingByValue().reversed())
            .map(e -> e.getKey() + ":" + e.getValue())
            .reduce("", (a, b) -> a.isEmpty() ? b : a + "," + b);
    }

    private int countBranches(Function function) {
        int count = 0;
        AddressSetView body = function.getBody();
        InstructionIterator instructions = workingProgram.getListing().getInstructions(body, true);

        while (instructions.hasNext()) {
            Instruction instr = instructions.next();
            if (instr.getFlowType().isJump() || instr.getFlowType().isConditional()) {
                count++;
            }
        }
        return count;
    }

    private double calculateSignatureQuality(FunctionSignature sig) {
        double quality = 0.0;

        if (sig.instructionCount > 10) quality += 0.3;
        if (sig.featureCount > 20) quality += 0.2;
        if (sig.branchCount > 0) quality += 0.2;
        if (sig.callCount > 0) quality += 0.2;
        if (sig.mnemonicPattern != null && sig.mnemonicPattern.length() > 10) quality += 0.1;

        return Math.min(quality, 1.0);
    }

    private void findSimilarFunctions(Program program) throws Exception {
        println("Finding similar functions across versions...");

        try (Connection conn = DriverManager.getConnection(dbUrl, dbUser, dbPass)) {
            int executableId = getExecutableId(conn, program.getName());
            findAndStoreSimilarities(conn, executableId);

        } catch (SQLException e) {
            printerr("Error finding similarities: " + e.getMessage());
            throw e;
        }
    }

    private void findAndStoreSimilarities(Connection conn, int currentExeId) throws SQLException {
        println("Comparing against other executables...");

        String compareSql = """
            SELECT
                d1.id as source_id, d1.name_func as source_name,
                d2.id as target_id, d2.name_func as target_name,
                e2.name_exec as target_exe,
                es1.lsh_vector as source_vector,
                es2.lsh_vector as target_vector,
                es1.signature_data as source_data,
                es2.signature_data as target_data,
                (SELECT COUNT(*) FROM desctable dx WHERE dx.id_exe = d1.id_exe) as source_instr,
                (SELECT COUNT(*) FROM desctable dx WHERE dx.id_exe = d2.id_exe) as target_instr
            FROM enhanced_signatures es1
            JOIN desctable d1 ON es1.function_id = d1.id
            JOIN enhanced_signatures es2 ON es2.function_id != es1.function_id
            JOIN desctable d2 ON es2.function_id = d2.id
            JOIN exetable e2 ON d2.id_exe = e2.id
            WHERE d1.id_exe = ?
            AND d2.id_exe != ?
            AND es1.confidence_score > 0.5
            AND es2.confidence_score > 0.5
            LIMIT ?
            """;

        String insertSimilaritySql = """
            INSERT INTO function_similarity_matrix
            (source_function_id, target_function_id, similarity_score, confidence_score, match_type)
            VALUES (?, ?, ?, ?, 'enhanced_signature')
            ON CONFLICT (source_function_id, target_function_id) DO UPDATE SET
                similarity_score = EXCLUDED.similarity_score,
                confidence_score = EXCLUDED.confidence_score,
                computed_at = NOW()
            """;

        int similarityCount = 0;

        try (PreparedStatement compareStmt = conn.prepareStatement(compareSql);
             PreparedStatement insertStmt = conn.prepareStatement(insertSimilaritySql)) {

            compareStmt.setInt(1, currentExeId);
            compareStmt.setInt(2, currentExeId);
            compareStmt.setInt(3, MAX_COMPARISONS);

            ResultSet rs = compareStmt.executeQuery();

            while (rs.next() && !monitor.isCancelled()) {
                try {
                    byte[] sourceVector = rs.getBytes("source_vector");
                    byte[] targetVector = rs.getBytes("target_vector");

                    double similarity = calculateVectorSimilarity(sourceVector, targetVector);
                    double confidence = calculateConfidence(
                        rs.getInt("source_instr"),
                        rs.getInt("target_instr"),
                        similarity
                    );

                    if (similarity >= MIN_SIMILARITY && confidence >= MIN_CONFIDENCE) {
                        insertStmt.setLong(1, rs.getLong("source_id"));
                        insertStmt.setLong(2, rs.getLong("target_id"));
                        insertStmt.setDouble(3, similarity);
                        insertStmt.setDouble(4, confidence);

                        insertStmt.executeUpdate();
                        similarityCount++;

                        if (similarityCount % 100 == 0) {
                            println("Found " + similarityCount + " similarity matches...");
                        }
                    }

                } catch (SQLException e) {
                    // Continue with next comparison
                }
            }
        }

        println(String.format("Found %d similarity relationships", similarityCount));
    }

    private double calculateVectorSimilarity(byte[] vector1, byte[] vector2) {
        if (vector1 == null || vector2 == null || vector1.length != vector2.length) {
            return 0.0;
        }

        int matches = 0;
        int totalBits = vector1.length * 8;

        for (int i = 0; i < vector1.length; i++) {
            byte v1 = vector1[i];
            byte v2 = vector2[i];

            // Count matching bits
            for (int bit = 0; bit < 8; bit++) {
                int b1 = (v1 >> bit) & 1;
                int b2 = (v2 >> bit) & 1;
                if (b1 == b2) {
                    matches++;
                }
            }
        }

        return (double) matches / totalBits;
    }

    private double calculateConfidence(int instrCount1, int instrCount2, double similarity) {
        // Size similarity factor
        int minCount = Math.min(instrCount1, instrCount2);
        int maxCount = Math.max(instrCount1, instrCount2);
        double sizeSimilarity = (double) minCount / maxCount;

        // Confidence based on instruction count and similarity
        double confidence = similarity * 50.0;
        if (minCount > 20) confidence += 20.0;
        if (sizeSimilarity > 0.8) confidence += 15.0;
        if (similarity > 0.9) confidence += 15.0;

        return Math.min(confidence, 100.0);
    }

    private void updateCrossVersionRelationships(Program program) throws SQLException {
        println("Refreshing cross-version relationships...");

        try (Connection conn = DriverManager.getConnection(dbUrl, dbUser, dbPass)) {
            // Try calling the refresh function for single-match cross-version system
            try (Statement stmt = conn.createStatement()) {
                stmt.execute("SELECT refresh_cross_version_matrix()");
                println("Cross-version relationships updated successfully");
            } catch (SQLException e) {
                println("Note: refresh_cross_version_matrix() not available: " + e.getMessage());

                // Fallback: directly refresh any materialized views that exist
                try (Statement stmt2 = conn.createStatement()) {
                    ResultSet rs = stmt2.executeQuery("""
                        SELECT matviewname FROM pg_matviews
                        WHERE schemaname = 'public'
                        AND matviewname LIKE '%cross_version%'
                        """);

                    while (rs.next()) {
                        String viewName = rs.getString("matviewname");
                        try (Statement refreshStmt = conn.createStatement()) {
                            refreshStmt.execute("REFRESH MATERIALIZED VIEW " + viewName);
                            println("Refreshed materialized view: " + viewName);
                        } catch (SQLException refreshError) {
                            println("Note: Could not refresh " + viewName + ": " + refreshError.getMessage());
                        }
                    }
                } catch (SQLException e2) {
                    println("Note: Could not query for materialized views: " + e2.getMessage());
                }
            }
        }
    }

    private void queryExistingSimilarities(Program program) throws Exception {
        println("Querying existing similarities from database...");

        try (Connection conn = DriverManager.getConnection(dbUrl, dbUser, dbPass)) {
            String querySql = """
                SELECT
                    s.name_func as source_function,
                    t.name_func as target_function,
                    se.name_exec as source_executable,
                    te.name_exec as target_executable,
                    fsm.similarity_score,
                    fsm.confidence_score
                FROM function_similarity_matrix fsm
                JOIN desctable s ON fsm.source_function_id = s.id
                JOIN desctable t ON fsm.target_function_id = t.id
                JOIN exetable se ON s.id_exe = se.id
                JOIN exetable te ON t.id_exe = te.id
                WHERE fsm.similarity_score >= ?
                ORDER BY fsm.similarity_score DESC
                LIMIT 50
                """;

            try (PreparedStatement stmt = conn.prepareStatement(querySql)) {
                stmt.setDouble(1, MIN_SIMILARITY);
                ResultSet rs = stmt.executeQuery();

                println("\n=== Top Function Similarities ===");
                int count = 0;
                while (rs.next() && count < 20) {
                    printf("%.3f: %s (%s) -> %s (%s)\n",
                        rs.getDouble("similarity_score"),
                        rs.getString("source_function"),
                        rs.getString("source_executable"),
                        rs.getString("target_function"),
                        rs.getString("target_executable"));
                    count++;
                }
            }
        }
    }

    private int getExecutableId(Connection conn, String programName) throws SQLException {
        String sql = "SELECT id FROM exetable WHERE name_exec = ?";
        try (PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, programName);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                return rs.getInt("id");
            }
        }
        return -1;
    }

    private void ensureEnhancedSignaturesTable(Connection conn) throws SQLException {
        // Create table if it doesn't exist (using bytea for our custom signatures, not lshvector)
        String createTableSql = """
            CREATE TABLE IF NOT EXISTS enhanced_signatures (
                id SERIAL PRIMARY KEY,
                function_id BIGINT NOT NULL UNIQUE,
                signature_vector BYTEA,
                feature_count INTEGER,
                signature_quality DOUBLE PRECISION,
                instruction_count INTEGER,
                parameter_count INTEGER,
                branch_count INTEGER,
                call_count INTEGER,
                mnemonic_pattern TEXT,
                control_flow_pattern TEXT,
                created_at TIMESTAMP DEFAULT NOW()
            )
            """;
        
        try (Statement stmt = conn.createStatement()) {
            stmt.execute(createTableSql);
        }

        // Schema uses lsh_vector - no changes needed
        println("Using existing enhanced_signatures table with lsh_vector column");
    }

    // Helper class for function signatures
    private static class FunctionSignature {
        byte[] vectorData;
        int featureCount;
        double quality;
        int instructionCount;
        int parameterCount;
        int branchCount;
        int callCount;
        String mnemonicPattern;
        String controlFlowPattern;
    }
}
