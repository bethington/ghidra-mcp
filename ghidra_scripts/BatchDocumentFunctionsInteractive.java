// Batch Document Functions with Claude Code (Interactive Version)
// Interactive version with configuration prompts before processing.
//
// Completeness Tests:
// 1. Plate Comment: Has summary, Algorithm, Parameters (if needed), Returns sections
// 2. Function Signature: Custom name, PascalCase verb-first, return type, Hungarian params
// 3. Local Variables: No SSA names (iVar1), Hungarian notation, resolved types
// 4. Global References: No DAT_* or s_* labels
//
// @author Ben Ethington
// @category Documentation
// @keybinding ctrl shift I
// @menupath Tools.Batch Document Functions (Interactive)

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.program.model.pcode.*;

import java.io.*;
import java.util.*;
import java.util.regex.*;

public class BatchDocumentFunctionsInteractive extends GhidraScript {

    // User-configurable options (set via prompts)
    private int maxFunctions = 0;
    private int minScore = 0;
    private int maxScore = 99;
    private boolean dryRun = false;
    private boolean generateTodoFile = true;
    private boolean invokeClaudeDirectly = false;
    private int delayBetweenFunctionsMs = 2000;
    private String outputDirectory = "";

    // Scoring weights (total = 100)
    private static final int WEIGHT_CUSTOM_NAME = 15;
    private static final int WEIGHT_VERB_PATTERN = 10;
    private static final int WEIGHT_RETURN_TYPE = 10;
    private static final int WEIGHT_PARAM_TYPES = 10;
    private static final int WEIGHT_PARAM_NAMES = 5;
    private static final int WEIGHT_PLATE_COMMENT = 20;
    private static final int WEIGHT_LOCAL_NAMES = 10;
    private static final int WEIGHT_LOCAL_TYPES = 10;
    private static final int WEIGHT_NO_DAT_GLOBALS = 5;
    private static final int WEIGHT_NO_STRING_LABELS = 5;

    // Patterns
    private static final Pattern FUN_PATTERN = Pattern.compile("^FUN_[0-9a-fA-F]+$");
    private static final Pattern THUNK_FUN_PATTERN = Pattern.compile("^thunk_FUN_[0-9a-fA-F]+$");
    private static final Pattern VERB_FIRST_PATTERN = Pattern.compile("^(Get|Set|Is|Has|Can|Init|Process|Update|Validate|Create|Free|Handle|Find|Load|Save|Draw|Render|Parse|Build|Calculate|Compute|Check|Add|Remove|Delete|Clear|Reset|Enable|Disable|Start|Stop|Open|Close|Read|Write|Alloc|Dealloc|Register|Unregister|Setup|Cleanup|Execute|Run|Call|Invoke|Apply|Convert|Transform|Format|Compare|Sort|Search|Filter|Map|Reduce|Merge|Split|Join|Copy|Move|Swap|Lock|Unlock|Acquire|Release|Push|Pop|Enqueue|Dequeue|Insert|Append|Prepend)[A-Z].*");
    private static final Pattern SSA_VAR_PATTERN = Pattern.compile("^[a-z]+Var[0-9]+$");
    private static final Pattern UNDEFINED_TYPE_PATTERN = Pattern.compile("^undefined[0-9]*$");
    private static final Pattern HUNGARIAN_PATTERN = Pattern.compile("^(p{1,2}|g_p{0,2}|dw|n|w|b|f|fl|d|ld|ll|qw|sz|wsz|lpsz|lpwsz|csz|a[bdwn]|pp)[A-Z].*|^(this|param_[0-9]+)$");
    private static final Pattern DAT_PATTERN = Pattern.compile("DAT_[0-9a-fA-F]+");
    private static final Pattern STRING_LABEL_PATTERN = Pattern.compile("^s_[A-Za-z0-9_]+_[0-9a-fA-F]+$");

    private DecompInterface decompiler;
    private int totalFunctions = 0;
    private int processedFunctions = 0;
    private int skippedFunctions = 0;
    private int needsWorkFunctions = 0;
    private List<FunctionScore> functionScores = new ArrayList<>();

    private static class FunctionScore {
        String name;
        String address;
        int score;
        List<String> issues;

        FunctionScore(String name, String address, int score, List<String> issues) {
            this.name = name;
            this.address = address;
            this.score = score;
            this.issues = issues;
        }
    }

    @Override
    public void run() throws Exception {
        println("=== Batch Document Functions with Claude Code ===");
        println("Interactive Configuration Mode");
        println("");

        // Prompt for configuration
        if (!configureOptions()) {
            println("Configuration cancelled.");
            return;
        }

        println("");
        println("=== Configuration Summary ===");
        println("  Max Functions: " + (maxFunctions == 0 ? "Unlimited" : maxFunctions));
        println("  Score Range: " + minScore + " - " + maxScore);
        println("  Dry Run: " + dryRun);
        println("  Generate Todo File: " + generateTodoFile);
        println("  Invoke Claude Directly: " + invokeClaudeDirectly);
        println("  Output Directory: " + (outputDirectory.isEmpty() ? "Current" : outputDirectory));
        println("");

        if (!askYesNo("Confirm", "Proceed with these settings?")) {
            println("Cancelled by user.");
            return;
        }

        // Initialize decompiler
        decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);

        FunctionManager funcManager = currentProgram.getFunctionManager();

        // Count functions
        FunctionIterator countIter = funcManager.getFunctions(true);
        while (countIter.hasNext()) {
            countIter.next();
            totalFunctions++;
        }
        println("Total functions to analyze: " + totalFunctions);
        println("");

        // Process functions
        FunctionIterator funcIter = funcManager.getFunctions(true);
        while (funcIter.hasNext()) {
            if (monitor.isCancelled()) {
                println("Cancelled by user.");
                break;
            }

            Function func = funcIter.next();
            processedFunctions++;

            if (processedFunctions % 100 == 0) {
                monitor.setMessage("Analyzing " + processedFunctions + "/" + totalFunctions);
                println("Progress: " + processedFunctions + "/" + totalFunctions +
                       " (Needs work: " + needsWorkFunctions + ", Skipped: " + skippedFunctions + ")");
            }

            List<String> issues = new ArrayList<>();
            int score = analyzeFunction(func, issues);

            String addrHex = func.getEntryPoint().toString().replace("0x", "");
            functionScores.add(new FunctionScore(func.getName(), addrHex, score, issues));

            if (score >= minScore && score <= maxScore) {
                needsWorkFunctions++;
            } else {
                skippedFunctions++;
            }

            if (maxFunctions > 0 && needsWorkFunctions >= maxFunctions) {
                println("Reached max functions limit (" + maxFunctions + ")");
                break;
            }
        }

        decompiler.dispose();

        println("");
        println("=== Analysis Complete ===");
        println("Total analyzed: " + processedFunctions);
        println("Needs work: " + needsWorkFunctions);
        println("Skipped (complete): " + skippedFunctions);

        if (generateTodoFile) {
            generateTodoFile();
        }

        if (invokeClaudeDirectly && !dryRun) {
            if (askYesNo("Invoke Claude", "Ready to invoke Claude Code for " + needsWorkFunctions + " functions?")) {
                invokeClaudeForFunctions();
            }
        }

        printScoreDistribution();
        generateDetailedReport();
    }

    private boolean configureOptions() throws Exception {
        // Mode selection
        String modeAnalyze = "Analyze Only (generate todo file for functions-process.ps1)";
        String modeClaude = "Analyze and Invoke Claude (process directly)";
        String modeQuick = "Quick Analysis (dry run, no output files)";

        String mode = askChoice("Select Operation Mode",
            "What would you like to do?",
            Arrays.asList(modeAnalyze, modeClaude, modeQuick),
            modeAnalyze);

        if (mode.equals(modeAnalyze)) {
            generateTodoFile = true;
            invokeClaudeDirectly = false;
            dryRun = false;
        } else if (mode.equals(modeClaude)) {
            generateTodoFile = true;
            invokeClaudeDirectly = true;
            dryRun = false;
        } else {
            generateTodoFile = false;
            invokeClaudeDirectly = false;
            dryRun = true;
        }

        // Score range
        String scoreRange = askString("Score Range",
            "Enter score range to process (format: min-max, e.g., 0-99 for all undocumented):",
            "0-99");

        try {
            String[] parts = scoreRange.split("-");
            minScore = Integer.parseInt(parts[0].trim());
            maxScore = Integer.parseInt(parts[1].trim());
        } catch (Exception e) {
            println("Invalid score range, using defaults (0-99)");
            minScore = 0;
            maxScore = 99;
        }

        // Max functions
        String maxStr = askString("Max Functions",
            "Maximum functions to process (0 = unlimited):",
            "0");

        try {
            maxFunctions = Integer.parseInt(maxStr.trim());
        } catch (Exception e) {
            maxFunctions = 0;
        }

        // Output directory
        if (generateTodoFile) {
            outputDirectory = askString("Output Directory",
                "Output directory for todo file (leave empty for current directory):",
                "");
        }

        return true;
    }

    private int analyzeFunction(Function func, List<String> issues) {
        int score = 0;
        String funcName = func.getName();

        // 1. Custom name check
        if (!FUN_PATTERN.matcher(funcName).matches() &&
            !THUNK_FUN_PATTERN.matcher(funcName).matches()) {
            score += WEIGHT_CUSTOM_NAME;
        } else {
            issues.add("No custom name");
        }

        // 2. Verb-first pattern check
        if (VERB_FIRST_PATTERN.matcher(funcName).matches()) {
            score += WEIGHT_VERB_PATTERN;
        } else if (!FUN_PATTERN.matcher(funcName).matches()) {
            issues.add("Not verb-first");
        }

        // 3. Return type check
        String returnType = func.getReturnType().getDisplayName();
        if (!UNDEFINED_TYPE_PATTERN.matcher(returnType).matches() &&
            !returnType.equals("undefined")) {
            score += WEIGHT_RETURN_TYPE;
        } else {
            issues.add("Undefined return");
        }

        // 4. Parameter checks
        Parameter[] params = func.getParameters();
        boolean allParamTypesResolved = true;
        boolean allParamNamesHungarian = true;

        for (Parameter param : params) {
            String paramType = param.getDataType().getDisplayName();
            String paramName = param.getName();

            if (UNDEFINED_TYPE_PATTERN.matcher(paramType).matches() ||
                paramType.contains("undefined")) {
                allParamTypesResolved = false;
            }

            if (!HUNGARIAN_PATTERN.matcher(paramName).matches()) {
                allParamNamesHungarian = false;
            }
        }

        if (params.length == 0 || allParamTypesResolved) {
            score += WEIGHT_PARAM_TYPES;
        } else {
            issues.add("Undefined param types");
        }

        if (params.length == 0 || allParamNamesHungarian) {
            score += WEIGHT_PARAM_NAMES;
        } else {
            issues.add("Params not Hungarian");
        }

        // 5. Plate comment check
        String plateComment = func.getComment();
        if (plateComment != null && !plateComment.isEmpty()) {
            boolean hasAlgorithm = plateComment.contains("Algorithm:");
            boolean hasReturns = plateComment.contains("Returns:") || plateComment.contains("Return:");
            boolean hasParams = plateComment.contains("Parameters:") || plateComment.contains("Params:") || params.length == 0;

            if (hasAlgorithm && hasReturns && hasParams) {
                score += WEIGHT_PLATE_COMMENT;
            } else {
                if (!hasAlgorithm) issues.add("No Algorithm section");
                if (!hasReturns) issues.add("No Returns section");
                if (!hasParams && params.length > 0) issues.add("No Params section");
            }
        } else {
            issues.add("No plate comment");
        }

        // 6. Local variable checks (via decompilation)
        try {
            DecompileResults results = decompiler.decompileFunction(func, 30, monitor);
            if (results != null && results.decompileCompleted()) {
                HighFunction highFunc = results.getHighFunction();
                if (highFunc != null) {
                    boolean hasSSANames = false;
                    boolean hasUndefinedTypes = false;

                    Iterator<HighSymbol> symIter = highFunc.getLocalSymbolMap().getSymbols();
                    while (symIter.hasNext()) {
                        HighSymbol sym = symIter.next();
                        String varName = sym.getName();
                        String varType = sym.getDataType().getDisplayName();

                        if (SSA_VAR_PATTERN.matcher(varName).matches()) {
                            hasSSANames = true;
                        }

                        if (UNDEFINED_TYPE_PATTERN.matcher(varType).matches() ||
                            varType.contains("undefined")) {
                            hasUndefinedTypes = true;
                        }
                    }

                    if (!hasSSANames) {
                        score += WEIGHT_LOCAL_NAMES;
                    } else {
                        issues.add("SSA var names");
                    }

                    if (!hasUndefinedTypes) {
                        score += WEIGHT_LOCAL_TYPES;
                    } else {
                        issues.add("Undefined locals");
                    }

                    // 7. DAT_* globals check
                    String decompiledCode = results.getDecompiledFunction().getC();
                    if (decompiledCode != null) {
                        if (!DAT_PATTERN.matcher(decompiledCode).find()) {
                            score += WEIGHT_NO_DAT_GLOBALS;
                        } else {
                            issues.add("DAT_* globals");
                        }

                        // 8. s_* string labels check
                        if (!STRING_LABEL_PATTERN.matcher(decompiledCode).find()) {
                            score += WEIGHT_NO_STRING_LABELS;
                        } else {
                            issues.add("s_* labels");
                        }
                    }
                }
            }
        } catch (Exception e) {
            issues.add("Decompile failed");
        }

        return score;
    }

    private void generateTodoFile() throws Exception {
        String baseDir = outputDirectory.isEmpty() ? "." : outputDirectory;
        File todoFile = new File(baseDir, "FunctionsTodo.txt");

        println("\nGenerating todo file: " + todoFile.getAbsolutePath());

        functionScores.sort((a, b) -> Integer.compare(a.score, b.score));

        try (PrintWriter writer = new PrintWriter(new FileWriter(todoFile))) {
            writer.println("# Function Documentation Todo List");
            writer.println("# Generated: " + new java.util.Date());
            writer.println("# Program: " + currentProgram.getName());
            writer.println("# Total: " + totalFunctions + " | Needs Work: " + needsWorkFunctions);
            writer.println("# Score Range: " + minScore + "-" + maxScore);
            writer.println("#");
            writer.println("# Format: [Status] FunctionName @ Address");
            writer.println("");

            int written = 0;
            for (FunctionScore fs : functionScores) {
                if (fs.score >= minScore && fs.score <= maxScore) {
                    writer.println("[ ] " + fs.name + " @ " + fs.address);
                    written++;

                    if (maxFunctions > 0 && written >= maxFunctions) {
                        break;
                    }
                }
            }
        }

        println("Written " + needsWorkFunctions + " functions to todo file");
    }

    private void generateDetailedReport() throws Exception {
        String baseDir = outputDirectory.isEmpty() ? "." : outputDirectory;
        File reportFile = new File(baseDir, "FunctionsReport.txt");

        println("\nGenerating detailed report: " + reportFile.getAbsolutePath());

        try (PrintWriter writer = new PrintWriter(new FileWriter(reportFile))) {
            writer.println("=== Function Documentation Analysis Report ===");
            writer.println("Generated: " + new java.util.Date());
            writer.println("Program: " + currentProgram.getName());
            writer.println("");
            writer.println("=== Summary ===");
            writer.println("Total Functions: " + totalFunctions);
            writer.println("Analyzed: " + processedFunctions);
            writer.println("Needs Work (score " + minScore + "-" + maxScore + "): " + needsWorkFunctions);
            writer.println("Complete (score > " + maxScore + "): " + skippedFunctions);
            writer.println("");
            writer.println("=== Scoring Weights ===");
            writer.println("Custom Name: " + WEIGHT_CUSTOM_NAME);
            writer.println("Verb-First Pattern: " + WEIGHT_VERB_PATTERN);
            writer.println("Return Type: " + WEIGHT_RETURN_TYPE);
            writer.println("Parameter Types: " + WEIGHT_PARAM_TYPES);
            writer.println("Parameter Names: " + WEIGHT_PARAM_NAMES);
            writer.println("Plate Comment: " + WEIGHT_PLATE_COMMENT);
            writer.println("Local Names: " + WEIGHT_LOCAL_NAMES);
            writer.println("Local Types: " + WEIGHT_LOCAL_TYPES);
            writer.println("No DAT_* Globals: " + WEIGHT_NO_DAT_GLOBALS);
            writer.println("No s_* Labels: " + WEIGHT_NO_STRING_LABELS);
            writer.println("");
            writer.println("=== Functions by Score ===");
            writer.println("");

            functionScores.sort((a, b) -> Integer.compare(a.score, b.score));

            for (FunctionScore fs : functionScores) {
                writer.println(String.format("%-50s @ %-10s Score: %3d", fs.name, fs.address, fs.score));
                if (!fs.issues.isEmpty()) {
                    writer.println("  Issues: " + String.join(", ", fs.issues));
                }
            }
        }
    }

    private void invokeClaudeForFunctions() throws Exception {
        println("\n=== Invoking Claude Code ===");

        String userHome = System.getProperty("user.home");
        String mcpConfig = findMcpConfig(userHome);
        String promptFile = findPromptFile(userHome);

        if (mcpConfig == null || promptFile == null) {
            popup("Could not find required configuration files:\n" +
                  "- mcp-config.json\n" +
                  "- FUNCTION_DOC_WORKFLOW_V4.md");
            return;
        }

        String claudePath = System.getenv("APPDATA") + "\\npm\\claude.cmd";

        int processed = 0;
        int successful = 0;

        for (FunctionScore fs : functionScores) {
            if (monitor.isCancelled()) break;
            if (fs.score < minScore || fs.score > maxScore) continue;

            processed++;
            println("[" + processed + "/" + needsWorkFunctions + "] " + fs.name);

            try {
                ProcessBuilder pb = new ProcessBuilder(
                    claudePath,
                    "--system-prompt-file", promptFile,
                    "--mcp-config", mcpConfig,
                    "--dangerously-skip-permissions",
                    "-p"
                );
                pb.redirectErrorStream(true);

                Process process = pb.start();

                try (OutputStreamWriter writer = new OutputStreamWriter(process.getOutputStream())) {
                    writer.write("Document " + fs.name + " at 0x" + fs.address);
                    writer.flush();
                }

                BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                StringBuilder output = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\n");
                }

                if (process.waitFor() == 0 && output.toString().contains("DONE:")) {
                    println("  SUCCESS");
                    successful++;
                }
            } catch (Exception e) {
                println("  ERROR: " + e.getMessage());
            }

            Thread.sleep(delayBetweenFunctionsMs);
        }

        println("\nCompleted: " + successful + "/" + processed);
    }

    private void printScoreDistribution() {
        println("\n=== Score Distribution ===");

        int[] buckets = new int[11];
        for (FunctionScore fs : functionScores) {
            buckets[Math.min(fs.score / 10, 10)]++;
        }

        for (int i = 0; i <= 10; i++) {
            String range = i == 10 ? "100" : String.format("%d-%d", i * 10, i * 10 + 9);
            println(String.format("  %6s: %5d", range, buckets[i]));
        }
    }

    private String findMcpConfig(String userHome) {
        String[] paths = {
            userHome + "\\source\\mcp\\ghidra-mcp\\mcp-config.json",
            "mcp-config.json"
        };
        for (String p : paths) {
            if (new File(p).exists()) return p;
        }
        return null;
    }

    private String findPromptFile(String userHome) {
        String[] paths = {
            userHome + "\\source\\mcp\\ghidra-mcp\\docs\\prompts\\FUNCTION_DOC_WORKFLOW_V4.md",
            "docs\\prompts\\FUNCTION_DOC_WORKFLOW_V4.md"
        };
        for (String p : paths) {
            if (new File(p).exists()) return p;
        }
        return null;
    }
}