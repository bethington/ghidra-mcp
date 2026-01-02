// Batch Document Functions with Claude Code
// Iterates through all functions, validates completeness, and invokes Claude for undocumented ones.
//
// Completeness Tests:
// 1. Plate Comment: Has summary, Algorithm, Parameters (if needed), Returns sections
// 2. Function Signature: Custom name, PascalCase verb-first, return type, Hungarian params
// 3. Local Variables: No SSA names (iVar1), Hungarian notation, resolved types
// 4. Global References: No DAT_* or s_* labels
//
// @author Ben Ethington
// @category Documentation
// @keybinding ctrl shift B
// @menupath Tools.Batch Document Functions

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.program.model.pcode.*;

import java.io.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.regex.*;

import javax.swing.*;
import javax.swing.event.*;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.Frame;
import java.awt.Insets;
import java.awt.event.*;

public class BatchDocumentFunctions extends GhidraScript {

    // Configuration
    private static final int MAX_FUNCTIONS = 0;           // 0 = unlimited
    private static final int DEFAULT_THRESHOLD = 80;      // Default minimum completeness threshold
    private static final boolean DRY_RUN = false;         // If true, only generate list without invoking Claude
    private static final boolean GENERATE_TODO_FILE = true; // Generate FunctionsTodo.txt for PowerShell script
    private static final boolean INVOKE_CLAUDE_DIRECTLY = false; // Invoke Claude from Java (slower)
    private static final int DELAY_BETWEEN_FUNCTIONS_MS = 2000;   // Delay between Claude calls

    // Runtime configuration (set by dialog)
    private int minThreshold = 0;                         // Functions BELOW this need work
    private int maxScore = 99;                            // Maximum score to include (skip 100%)

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

    // Inner class to hold function scoring data
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

    /**
     * Shows a dialog to pick the minimum completeness threshold.
     * Functions scoring below this threshold will be included in the todo list.
     *
     * @return The selected threshold (0-100), or null if cancelled
     */
    private Integer showThresholdPickerDialog() {
        final int[] result = {-1};

        try {
            SwingUtilities.invokeAndWait(() -> {
                JDialog dialog = new JDialog((Frame) null, "Select Minimum Completeness Threshold", true);
                dialog.setDefaultCloseOperation(JDialog.DISPOSE_ON_CLOSE);
                dialog.setLayout(new BorderLayout(10, 10));
                dialog.setSize(450, 280);
                dialog.setLocationRelativeTo(null);

                // Main panel with padding
                JPanel mainPanel = new JPanel();
                mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.Y_AXIS));
                mainPanel.setBorder(BorderFactory.createEmptyBorder(15, 20, 15, 20));

                // Instructions
                JLabel instructionLabel = new JLabel("<html><body style='width: 380px'>" +
                    "Functions with completeness scores <b>BELOW</b> this threshold will be " +
                    "included in the todo list for reprocessing.</body></html>");
                instructionLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
                mainPanel.add(instructionLabel);
                mainPanel.add(Box.createVerticalStrut(15));

                // Slider panel
                JPanel sliderPanel = new JPanel(new BorderLayout(10, 0));
                sliderPanel.setAlignmentX(Component.LEFT_ALIGNMENT);

                JLabel sliderLabel = new JLabel("Minimum Score:");
                sliderPanel.add(sliderLabel, BorderLayout.WEST);

                JSlider slider = new JSlider(0, 100, DEFAULT_THRESHOLD);
                slider.setMajorTickSpacing(10);
                slider.setMinorTickSpacing(5);
                slider.setPaintTicks(true);
                slider.setPaintLabels(true);
                sliderPanel.add(slider, BorderLayout.CENTER);

                JLabel valueLabel = new JLabel(DEFAULT_THRESHOLD + "%");
                valueLabel.setFont(valueLabel.getFont().deriveFont(Font.BOLD, 16f));
                valueLabel.setPreferredSize(new Dimension(50, 30));
                sliderPanel.add(valueLabel, BorderLayout.EAST);

                slider.addChangeListener(e -> valueLabel.setText(slider.getValue() + "%"));

                mainPanel.add(sliderPanel);
                mainPanel.add(Box.createVerticalStrut(15));

                // Preset buttons panel
                JPanel presetPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
                presetPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
                presetPanel.add(new JLabel("Quick presets:"));

                int[] presets = {50, 70, 80, 90, 100};
                for (int preset : presets) {
                    JButton btn = new JButton(preset + "%");
                    btn.setMargin(new Insets(2, 8, 2, 8));
                    btn.addActionListener(e -> slider.setValue(preset));
                    presetPanel.add(btn);
                }
                mainPanel.add(presetPanel);
                mainPanel.add(Box.createVerticalStrut(20));

                // Button panel
                JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 20, 0));
                buttonPanel.setAlignmentX(Component.LEFT_ALIGNMENT);

                JButton okButton = new JButton("Generate Todo List");
                okButton.addActionListener(e -> {
                    result[0] = slider.getValue();
                    dialog.dispose();
                });

                JButton cancelButton = new JButton("Cancel");
                cancelButton.addActionListener(e -> {
                    result[0] = -1;
                    dialog.dispose();
                });

                buttonPanel.add(okButton);
                buttonPanel.add(cancelButton);
                mainPanel.add(buttonPanel);

                dialog.add(mainPanel, BorderLayout.CENTER);
                dialog.setVisible(true);
            });
        } catch (Exception e) {
            printerr("Error showing dialog: " + e.getMessage());
            return null;
        }

        return result[0] >= 0 ? result[0] : null;
    }

    @Override
    public void run() throws Exception {
        println("=== Batch Document Functions with Claude Code ===");

        // Show threshold picker dialog
        Integer threshold = showThresholdPickerDialog();
        if (threshold == null) {
            println("Cancelled by user.");
            return;
        }

        // Set runtime configuration based on dialog
        // Functions scoring BELOW the threshold need work
        minThreshold = 0;           // Include all functions from score 0
        maxScore = threshold - 1;   // Up to (threshold - 1), so threshold and above are "complete"

        println("Configuration:");
        println("  Minimum Completeness Threshold: " + threshold + "%");
        println("  Functions below " + threshold + "% will be included in todo list");
        println("  Max Functions: " + (MAX_FUNCTIONS == 0 ? "Unlimited" : MAX_FUNCTIONS));
        println("  Dry Run: " + DRY_RUN);
        println("  Generate Todo File: " + GENERATE_TODO_FILE);
        println("  Invoke Claude Directly: " + INVOKE_CLAUDE_DIRECTLY);
        println("");

        // Initialize decompiler for variable analysis
        decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);

        FunctionManager funcManager = currentProgram.getFunctionManager();

        // Count total functions
        FunctionIterator countIter = funcManager.getFunctions(true);
        while (countIter.hasNext()) {
            countIter.next();
            totalFunctions++;
        }
        println("Total functions to analyze: " + totalFunctions);
        println("");

        // Process all functions
        FunctionIterator funcIter = funcManager.getFunctions(true);
        while (funcIter.hasNext()) {
            if (monitor.isCancelled()) {
                println("Cancelled by user.");
                break;
            }

            Function func = funcIter.next();
            processedFunctions++;

            // Progress update
            if (processedFunctions % 100 == 0) {
                monitor.setMessage("Analyzing " + processedFunctions + "/" + totalFunctions);
                println("Progress: " + processedFunctions + "/" + totalFunctions +
                       " (Needs work: " + needsWorkFunctions + ", Skipped: " + skippedFunctions + ")");
            }

            // Analyze function completeness
            List<String> issues = new ArrayList<>();
            int score = analyzeFunction(func, issues);

            // Store for reporting
            String addrHex = func.getEntryPoint().toString().replace("0x", "");
            functionScores.add(new FunctionScore(func.getName(), addrHex, score, issues));

            // Check if function needs work (below threshold)
            if (score >= minThreshold && score <= maxScore) {
                needsWorkFunctions++;
            } else {
                skippedFunctions++;
            }

            // Check max functions limit
            if (MAX_FUNCTIONS > 0 && needsWorkFunctions >= MAX_FUNCTIONS) {
                println("Reached MAX_FUNCTIONS limit (" + MAX_FUNCTIONS + ")");
                break;
            }
        }

        decompiler.dispose();

        // Generate output
        println("");
        println("=== Analysis Complete ===");
        println("Total analyzed: " + processedFunctions);
        println("Needs work: " + needsWorkFunctions);
        println("Skipped (complete): " + skippedFunctions);

        if (GENERATE_TODO_FILE) {
            generateTodoFile();
        }

        if (INVOKE_CLAUDE_DIRECTLY && !DRY_RUN) {
            invokeClaudeForFunctions();
        }

        // Print summary statistics
        printScoreDistribution();
    }

    /**
     * Analyze a function and return completeness score (0-100)
     */
    private int analyzeFunction(Function func, List<String> issues) {
        int score = 0;
        String funcName = func.getName();

        // 1. Check custom name (not FUN_*)
        if (!FUN_PATTERN.matcher(funcName).matches() &&
            !THUNK_FUN_PATTERN.matcher(funcName).matches()) {
            score += WEIGHT_CUSTOM_NAME;
        } else {
            issues.add("No custom name (FUN_*)");
        }

        // 2. Check verb-first PascalCase pattern
        if (VERB_FIRST_PATTERN.matcher(funcName).matches()) {
            score += WEIGHT_VERB_PATTERN;
        } else if (!FUN_PATTERN.matcher(funcName).matches()) {
            issues.add("Name doesn't follow verb-first pattern");
        }

        // 3. Check return type
        String returnType = func.getReturnType().getDisplayName();
        if (!UNDEFINED_TYPE_PATTERN.matcher(returnType).matches() &&
            !returnType.equals("undefined")) {
            score += WEIGHT_RETURN_TYPE;
        } else {
            issues.add("Undefined return type");
        }

        // 4. Check parameter types
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
            issues.add("Undefined parameter types");
        }

        if (params.length == 0 || allParamNamesHungarian) {
            score += WEIGHT_PARAM_NAMES;
        } else {
            issues.add("Parameters not following Hungarian notation");
        }

        // 5. Check plate comment
        String plateComment = func.getComment();
        if (plateComment != null && !plateComment.isEmpty()) {
            boolean hasAlgorithm = plateComment.contains("Algorithm:");
            boolean hasReturns = plateComment.contains("Returns:") || plateComment.contains("Return:");
            boolean hasParams = plateComment.contains("Parameters:") || plateComment.contains("Params:") || params.length == 0;

            if (hasAlgorithm && hasReturns && hasParams) {
                score += WEIGHT_PLATE_COMMENT;
            } else {
                if (!hasAlgorithm) issues.add("Plate comment missing Algorithm section");
                if (!hasReturns) issues.add("Plate comment missing Returns section");
                if (!hasParams && params.length > 0) issues.add("Plate comment missing Parameters section");
            }
        } else {
            issues.add("No plate comment");
        }

        // 6. Check local variables (requires decompilation)
        try {
            DecompileResults results = decompiler.decompileFunction(func, 30, monitor);
            if (results != null && results.decompileCompleted()) {
                HighFunction highFunc = results.getHighFunction();
                if (highFunc != null) {
                    boolean hasSSANames = false;
                    boolean hasUndefinedTypes = false;
                    boolean allHungarian = true;

                    Iterator<HighSymbol> symIter = highFunc.getLocalSymbolMap().getSymbols();
                    while (symIter.hasNext()) {
                        HighSymbol sym = symIter.next();
                        String varName = sym.getName();
                        String varType = sym.getDataType().getDisplayName();

                        // Check for SSA names (iVar1, uVar2, etc.)
                        if (SSA_VAR_PATTERN.matcher(varName).matches()) {
                            hasSSANames = true;
                        }

                        // Check for undefined types
                        if (UNDEFINED_TYPE_PATTERN.matcher(varType).matches() ||
                            varType.contains("undefined")) {
                            hasUndefinedTypes = true;
                        }

                        // Check Hungarian notation (skip compiler-generated names)
                        if (!varName.startsWith("in_") && !varName.startsWith("extraout_") &&
                            !varName.startsWith("unaff_") && !varName.startsWith("local_") &&
                            !varName.startsWith("param_") && !varName.startsWith("stack") &&
                            !HUNGARIAN_PATTERN.matcher(varName).matches()) {
                            // Only flag if it looks like a user-defined name
                            if (!SSA_VAR_PATTERN.matcher(varName).matches()) {
                                allHungarian = false;
                            }
                        }
                    }

                    if (!hasSSANames && allHungarian) {
                        score += WEIGHT_LOCAL_NAMES;
                    } else {
                        if (hasSSANames) issues.add("Has SSA variable names (iVar1, uVar2, etc.)");
                        if (!allHungarian) issues.add("Local variables not following Hungarian notation");
                    }

                    if (!hasUndefinedTypes) {
                        score += WEIGHT_LOCAL_TYPES;
                    } else {
                        issues.add("Has undefined local variable types");
                    }

                    // 7. Check for DAT_* globals in decompiled code
                    String decompiledCode = results.getDecompiledFunction().getC();
                    if (decompiledCode != null) {
                        Matcher datMatcher = DAT_PATTERN.matcher(decompiledCode);
                        if (!datMatcher.find()) {
                            score += WEIGHT_NO_DAT_GLOBALS;
                        } else {
                            issues.add("References DAT_* globals");
                        }

                        // 8. Check for s_* string labels
                        Matcher strMatcher = STRING_LABEL_PATTERN.matcher(decompiledCode);
                        if (!strMatcher.find()) {
                            score += WEIGHT_NO_STRING_LABELS;
                        } else {
                            issues.add("References s_* string labels");
                        }
                    }
                }
            }
        } catch (Exception e) {
            // Decompilation failed, assume worst case for these checks
            issues.add("Decompilation failed");
        }

        return score;
    }

    /**
     * Generate FunctionsTodo.txt for use with functions-process.ps1
     */
    private void generateTodoFile() throws Exception {
        File todoFile = new File(getScriptArgs().length > 0 ? getScriptArgs()[0] : "FunctionsTodo.txt");

        println("\nGenerating todo file: " + todoFile.getAbsolutePath());

        // Sort by score ascending (lowest score = most work needed = highest priority)
        functionScores.sort((a, b) -> Integer.compare(a.score, b.score));

        try (PrintWriter writer = new PrintWriter(new FileWriter(todoFile))) {
            writer.println("# Function Documentation Todo List");
            writer.println("# Generated: " + new java.util.Date());
            writer.println("# Program: " + currentProgram.getName());
            writer.println("# Total Functions: " + totalFunctions);
            writer.println("# Functions Needing Work: " + needsWorkFunctions);
            writer.println("# Minimum Threshold: " + (maxScore + 1) + "%");
            writer.println("# Score Range: " + minThreshold + " - " + maxScore);
            writer.println("#");
            writer.println("# Format: [Status] FunctionName @ Address (Score: X) - Issues");
            writer.println("# Status: [ ] = Pending, [X] = Complete, [!] = Failed");
            writer.println("#");
            writer.println("");

            int written = 0;
            for (FunctionScore fs : functionScores) {
                if (fs.score >= minThreshold && fs.score <= maxScore) {
                    String issuesSummary = fs.issues.isEmpty() ? "" : " - " + String.join(", ", fs.issues);
                    writer.println("[ ] " + fs.name + " @ " + fs.address + " (Score: " + fs.score + ")" + issuesSummary);
                    written++;

                    if (MAX_FUNCTIONS > 0 && written >= MAX_FUNCTIONS) {
                        break;
                    }
                }
            }
        }

        println("Todo file written with " + needsWorkFunctions + " functions");
    }

    /**
     * Invoke Claude Code for each function that needs work
     */
    private void invokeClaudeForFunctions() throws Exception {
        println("\n=== Invoking Claude Code for " + needsWorkFunctions + " functions ===");

        String userHome = System.getProperty("user.home");
        String mcpConfig = findMcpConfig(userHome);
        String promptFile = findPromptFile(userHome);

        if (mcpConfig == null) {
            println("ERROR: Could not find mcp-config.json");
            return;
        }

        if (promptFile == null) {
            println("ERROR: Could not find FUNCTION_DOC_WORKFLOW_V4.md prompt file");
            return;
        }

        println("MCP Config: " + mcpConfig);
        println("Prompt File: " + promptFile);

        String claudePath = System.getenv("APPDATA") + "\\npm\\claude.cmd";

        int processed = 0;
        int successful = 0;
        int failed = 0;

        for (FunctionScore fs : functionScores) {
            if (monitor.isCancelled()) {
                println("Cancelled by user.");
                break;
            }

            if (fs.score < minThreshold || fs.score > maxScore) {
                continue;
            }

            processed++;
            println("\n[" + processed + "/" + needsWorkFunctions + "] Processing: " + fs.name + " @ " + fs.address + " (Score: " + fs.score + ")");

            // Build user message
            String userMessage = "Use the attached workflow document to document " + fs.name + " at 0x" + fs.address + ".";

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

                // Write prompt to stdin
                try (OutputStreamWriter writer = new OutputStreamWriter(process.getOutputStream())) {
                    writer.write(userMessage);
                    writer.flush();
                }

                // Read output
                BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                StringBuilder output = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\n");
                }

                int exitCode = process.waitFor();

                if (exitCode == 0) {
                    // Check for DONE in output
                    if (output.toString().contains("DONE:")) {
                        println("  SUCCESS: Function documented");
                        successful++;
                    } else if (output.toString().contains("SKIP:")) {
                        println("  SKIPPED: " + extractSkipReason(output.toString()));
                        successful++;
                    } else {
                        println("  WARNING: Claude completed but no DONE marker found");
                        successful++;
                    }
                } else {
                    println("  FAILED: Exit code " + exitCode);
                    failed++;
                }

            } catch (Exception e) {
                println("  ERROR: " + e.getMessage());
                failed++;
            }

            // Delay between functions
            if (processed < needsWorkFunctions && DELAY_BETWEEN_FUNCTIONS_MS > 0) {
                Thread.sleep(DELAY_BETWEEN_FUNCTIONS_MS);
            }

            // Check max functions limit
            if (MAX_FUNCTIONS > 0 && processed >= MAX_FUNCTIONS) {
                println("Reached MAX_FUNCTIONS limit (" + MAX_FUNCTIONS + ")");
                break;
            }
        }

        println("\n=== Claude Processing Complete ===");
        println("Processed: " + processed);
        println("Successful: " + successful);
        println("Failed: " + failed);
    }

    private String extractSkipReason(String output) {
        int idx = output.indexOf("SKIP:");
        if (idx >= 0) {
            int endIdx = output.indexOf("\n", idx);
            if (endIdx > idx) {
                return output.substring(idx + 5, endIdx).trim();
            }
        }
        return "Unknown reason";
    }

    private void printScoreDistribution() {
        println("\n=== Score Distribution ===");

        int[] buckets = new int[11]; // 0-9, 10-19, ..., 90-99, 100
        for (FunctionScore fs : functionScores) {
            int bucket = Math.min(fs.score / 10, 10);
            buckets[bucket]++;
        }

        for (int i = 0; i <= 10; i++) {
            String range = i == 10 ? "100" : String.format("%d-%d", i * 10, i * 10 + 9);
            int count = buckets[i];
            String bar = repeat("#", Math.min(count / 10, 50));
            println(String.format("  %6s: %5d %s", range, count, bar));
        }

        // Print top issues
        println("\n=== Most Common Issues ===");
        Map<String, Integer> issueCounts = new HashMap<>();
        for (FunctionScore fs : functionScores) {
            for (String issue : fs.issues) {
                issueCounts.merge(issue, 1, Integer::sum);
            }
        }

        issueCounts.entrySet().stream()
            .sorted((a, b) -> b.getValue().compareTo(a.getValue()))
            .limit(10)
            .forEach(e -> println(String.format("  %5d: %s", e.getValue(), e.getKey())));
    }

    private String repeat(String s, int count) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < count; i++) {
            sb.append(s);
        }
        return sb.toString();
    }

    private String findMcpConfig(String userHome) {
        String[] possiblePaths = {
            userHome + "\\source\\mcp\\ghidra-mcp\\mcp-config.json",
            System.getProperty("user.dir") + "\\mcp-config.json",
            "..\\mcp-config.json"
        };

        for (String path : possiblePaths) {
            File f = new File(path);
            if (f.exists()) {
                return f.getAbsolutePath();
            }
        }
        return null;
    }

    private String findPromptFile(String userHome) {
        String[] possiblePaths = {
            userHome + "\\source\\mcp\\ghidra-mcp\\docs\\prompts\\FUNCTION_DOC_WORKFLOW_V4.md",
            userHome + "\\source\\mcp\\ghidra-mcp\\docs\\prompts\\FUNCTION_DOC_WORKFLOW_V4_COMPACT.md",
            System.getProperty("user.dir") + "\\docs\\prompts\\FUNCTION_DOC_WORKFLOW_V4.md"
        };

        for (String path : possiblePaths) {
            File f = new File(path);
            if (f.exists()) {
                return f.getAbsolutePath();
            }
        }
        return null;
    }
}
