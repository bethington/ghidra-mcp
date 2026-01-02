// Batch Document Functions - All Binaries in Project Folder
// Analyzes ALL programs in the current project folder (e.g., all D2 DLLs for a version)
// and generates a single consolidated todo list ordered by binary dependency hierarchy.
//
// Binary processing order follows docs/prompts/BINARY_DOCUMENTATION_ORDER.md:
//   Storm.dll -> Fog.dll -> D2Lang.dll -> D2CMP.dll -> D2Common.dll -> ...
//
// Output:
//   - FunctionsTodo.txt - Single ordered todo list (binaries processed in dependency order)
//   - FunctionsReport_AllBinaries.txt - Detailed analysis report
//
// @author Ben Ethington
// @category Documentation
// @keybinding ctrl shift A
// @menupath Tools.Batch Document All Binaries

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.program.model.pcode.*;
import ghidra.framework.model.*;

import java.io.*;
import java.util.*;
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

public class BatchDocumentFunctionsAllBinaries extends GhidraScript {

    // Binary processing order based on BINARY_DOCUMENTATION_ORDER.md
    // Lower index = higher priority (process first due to fewer dependencies)
    private static final String[] BINARY_ORDER = {
        "Storm.dll",           // 1 - Foundation
        "Fog.dll",             // 2 - Foundation
        "D2Lang.dll",          // 3 - Core Services
        "D2CMP.dll",           // 4 - Core Services
        "D2Common.dll",        // 5 - Game Foundation (CRITICAL)
        "D2Sound.dll",         // 6 - Subsystems
        "D2Win.dll",           // 7 - Subsystems
        "D2Gfx.dll",           // 8 - Subsystems
        "D2Gdi.dll",           // 9 - Subsystems
        "D2Net.dll",           // 10 - Subsystems
        "D2Multi.dll",         // 11 - High-Level
        "Bnclient.dll",        // 12 - Battle.net
        "D2MCPClient.dll",     // 13 - Battle.net
        "D2Game.dll",          // 14 - High-Level (Server)
        "D2Client.dll",        // 15 - High-Level (Client)
        "D2DDraw.dll",         // 16 - Render Backend
        "D2Direct3D.dll",      // 17 - Render Backend
        "D2Glide.dll",         // 18 - Render Backend
        "D2Launch.dll",        // 24 - Entry Point
        "Game.exe",            // 25 - Entry Point
        "BH.dll",              // 26 - Battle.net Helper
        "PD2_EXT.dll",         // 27 - PD2 Extensions
        "SGD2FreeRes.dll",     // 28 - PD2 Extensions
        "SGD2FreeDisplayFix.dll" // 29 - PD2 Extensions
    };

    // Configuration
    private static final int DEFAULT_THRESHOLD = 80;      // Default minimum completeness threshold
    private static final String OUTPUT_DIR = System.getProperty("user.home") +
        java.io.File.separator + "source" + java.io.File.separator + "mcp" +
        java.io.File.separator + "ghidra-mcp";

    // Runtime configuration (set by dialog)
    private int minThreshold = 0;                         // Functions BELOW this need work
    private int maxScore = 99;                            // Maximum score to include (skip 100%)

    // Scoring penalties (subtractive from 100) - matches GhidraMCPPlugin.java
    private static final int PENALTY_FUN_NAME = 30;           // FUN_* or thunk_FUN_*
    private static final int PENALTY_NO_SIGNATURE = 20;       // No function signature
    private static final int PENALTY_NO_CALLING_CONV = 10;    // No calling convention
    private static final int PENALTY_NO_PLATE_COMMENT = 20;   // No plate comment
    private static final int PENALTY_PLATE_ISSUE = 5;         // Missing section in plate comment
    private static final int PENALTY_UNDEFINED_VAR = 5;       // Per undefined variable
    private static final int PENALTY_HUNGARIAN_VIOLATION = 3; // Per Hungarian naming violation
    private static final int PENALTY_TYPE_QUALITY = 15;       // Per type quality issue (void*, state-based)
    private static final int PENALTY_DAT_GLOBAL = 3;          // Per DAT_* global reference
    private static final int PENALTY_UNDOC_ORDINAL = 2;       // Per undocumented ordinal
    private static final int PENALTY_LOW_COMMENT_DENSITY = 5; // Low inline comment density
    private static final int PENALTY_STRING_LABEL = 2;        // Per s_* string label

    // Patterns
    private static final Pattern FUN_PATTERN = Pattern.compile("^FUN_[0-9a-fA-F]+$");
    private static final Pattern THUNK_FUN_PATTERN = Pattern.compile("^thunk_FUN_[0-9a-fA-F]+$");
    private static final Pattern VERB_FIRST_PATTERN = Pattern.compile("^(Get|Set|Is|Has|Can|Init|Process|Update|Validate|Create|Free|Handle|Find|Load|Save|Draw|Render|Parse|Build|Calculate|Compute|Check|Add|Remove|Delete|Clear|Reset|Enable|Disable|Start|Stop|Open|Close|Read|Write|Alloc|Dealloc|Register|Unregister|Setup|Cleanup|Execute|Run|Call|Invoke|Apply|Convert|Transform|Format|Compare|Sort|Search|Filter|Map|Reduce|Merge|Split|Join|Copy|Move|Swap|Lock|Unlock|Acquire|Release|Push|Pop|Enqueue|Dequeue|Insert|Append|Prepend)[A-Z].*");
    private static final Pattern SSA_VAR_PATTERN = Pattern.compile("^[a-z]+Var[0-9]+$");
    private static final Pattern UNDEFINED_TYPE_PATTERN = Pattern.compile("^undefined[0-9]*$");
    private static final Pattern HUNGARIAN_PATTERN = Pattern.compile("^(p{1,2}|g_p{0,2}|dw|n|w|b|f|fl|d|ld|ll|qw|sz|wsz|lpsz|lpwsz|csz|a[bdwn]|pp)[A-Z].*|^(this|param_[0-9]+)$");
    private static final Pattern DAT_PATTERN = Pattern.compile("DAT_[0-9a-fA-F]+");
    private static final Pattern STRING_LABEL_PATTERN = Pattern.compile("^s_[A-Za-z0-9_]+_[0-9a-fA-F]+$");

    // Statistics
    private int totalPrograms = 0;
    private int totalFunctions = 0;
    private int totalNeedsWork = 0;
    private int totalComplete = 0;
    private Map<String, List<FunctionScore>> programScores = new LinkedHashMap<>();
    private Map<String, int[]> programStats = new LinkedHashMap<>(); // [total, needsWork, complete]

    private static class FunctionScore {
        String programName;
        String funcName;
        String address;
        int score;
        List<String> issues;

        FunctionScore(String programName, String funcName, String address, int score, List<String> issues) {
            this.programName = programName;
            this.funcName = funcName;
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
    protected void run() throws Exception {
        if (currentProgram == null) {
            printerr("No program is open!");
            return;
        }

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

        // Get the project folder containing this program
        DomainFile currentFile = currentProgram.getDomainFile();
        DomainFolder parentFolder = currentFile.getParent();

        println("=".repeat(70));
        println("BATCH DOCUMENT FUNCTIONS - ALL BINARIES");
        println("=".repeat(70));
        println("Current program: " + currentProgram.getName());
        println("Project folder: " + parentFolder.getPathname());
        println("Output directory: " + OUTPUT_DIR);
        println("Minimum Completeness Threshold: " + threshold + "%");
        println("Functions below " + threshold + "% will be included in todo list");
        println("");

        // Get all programs in the folder
        List<DomainFile> programFiles = new ArrayList<>();
        for (DomainFile file : parentFolder.getFiles()) {
            if (file.getContentType().equals("Program")) {
                programFiles.add(file);
            }
        }

        println("Found " + programFiles.size() + " programs in folder:");
        for (DomainFile pf : programFiles) {
            println("  - " + pf.getName());
        }
        println("");

        if (programFiles.isEmpty()) {
            printerr("No programs found in folder!");
            return;
        }

        // Sort programs by BINARY_ORDER (programs not in list go last)
        programFiles.sort((a, b) -> {
            int indexA = getBinaryOrderIndex(a.getName());
            int indexB = getBinaryOrderIndex(b.getName());
            return Integer.compare(indexA, indexB);
        });

        println("\nProcessing order (by dependency hierarchy):");
        for (int i = 0; i < programFiles.size(); i++) {
            DomainFile pf = programFiles.get(i);
            int orderIndex = getBinaryOrderIndex(pf.getName());
            String orderStr = orderIndex < BINARY_ORDER.length ? String.valueOf(orderIndex + 1) : "N/A";
            println("  " + (i + 1) + ". " + pf.getName() + " (priority: " + orderStr + ")");
        }
        println("");

        // Process each program in dependency order
        for (DomainFile file : programFiles) {
            if (monitor.isCancelled()) {
                println("\nCancelled by user");
                break;
            }
            processProgram(file);
        }

        // Generate output files
        generateCombinedTodoFile();
        generateDetailedReport();

        // Print summary
        printSummary();
    }

    private void processProgram(DomainFile file) {
        String programName = file.getName();
        println("-".repeat(50));
        println("Processing: " + programName);

        Program program = null;
        DecompInterface decompiler = null;
        List<FunctionScore> scores = new ArrayList<>();

        try {
            // Open the program (read-only)
            program = (Program) file.getDomainObject(this, false, false, monitor);

            // Initialize decompiler
            decompiler = new DecompInterface();
            decompiler.openProgram(program);

            FunctionManager funcManager = program.getFunctionManager();

            int funcCount = 0;
            int needsWork = 0;
            int complete = 0;

            FunctionIterator funcIter = funcManager.getFunctions(true);
            while (funcIter.hasNext() && !monitor.isCancelled()) {
                Function func = funcIter.next();
                funcCount++;

                List<String> issues = new ArrayList<>();
                int score = analyzeFunction(func, program, decompiler, issues);

                String addrHex = func.getEntryPoint().toString().replace("0x", "");
                FunctionScore fs = new FunctionScore(programName, func.getName(), addrHex, score, issues);
                scores.add(fs);

                if (score >= minThreshold && score <= maxScore) {
                    needsWork++;
                } else {
                    complete++;
                }
            }

            programScores.put(programName, scores);
            programStats.put(programName, new int[]{funcCount, needsWork, complete});

            totalPrograms++;
            totalFunctions += funcCount;
            totalNeedsWork += needsWork;
            totalComplete += complete;

            println("  Functions: " + funcCount + " | Needs work: " + needsWork + " | Complete: " + complete);

        } catch (Exception e) {
            printerr("  Error processing " + programName + ": " + e.getMessage());
        } finally {
            if (decompiler != null) {
                decompiler.dispose();
            }
            if (program != null) {
                program.release(this);
            }
        }
    }

    private int analyzeFunction(Function func, Program program, DecompInterface decompiler, List<String> issues) {
        // Start at 100, subtract penalties - matches GhidraMCPPlugin.java approach
        int score = 100;
        String funcName = func.getName();

        // 1. Custom name check (-30 for FUN_* or thunk_FUN_*)
        if (FUN_PATTERN.matcher(funcName).matches() ||
            THUNK_FUN_PATTERN.matcher(funcName).matches()) {
            score -= PENALTY_FUN_NAME;
            issues.add("-30: FUN_* name");
        }

        // 2. Signature/prototype check (-20 for no signature)
        if (func.getSignature() == null) {
            score -= PENALTY_NO_SIGNATURE;
            issues.add("-20: No signature");
        }

        // 3. Calling convention check (-10 for unknown)
        String callingConv = func.getCallingConventionName();
        if (callingConv == null || callingConv.equals("unknown")) {
            score -= PENALTY_NO_CALLING_CONV;
            issues.add("-10: No calling convention");
        }

        // 4. Plate comment check (-20 for missing, -5 per missing section)
        String plateComment = func.getComment();
        Parameter[] params = func.getParameters();
        if (plateComment == null || plateComment.isEmpty()) {
            score -= PENALTY_NO_PLATE_COMMENT;
            issues.add("-20: No plate comment");
        } else {
            boolean hasAlgorithm = plateComment.contains("Algorithm:");
            boolean hasReturns = plateComment.contains("Returns:") || plateComment.contains("Return:");
            boolean hasParams = plateComment.contains("Parameters:") || plateComment.contains("Params:") || params.length == 0;

            if (!hasAlgorithm) {
                score -= PENALTY_PLATE_ISSUE;
                issues.add("-5: No Algorithm section");
            }
            if (!hasReturns) {
                score -= PENALTY_PLATE_ISSUE;
                issues.add("-5: No Returns section");
            }
            if (!hasParams && params.length > 0) {
                score -= PENALTY_PLATE_ISSUE;
                issues.add("-5: No Params section");
            }
        }

        // 5. Parameter type and naming checks
        int undefinedParamCount = 0;
        int hungarianViolationCount = 0;
        for (Parameter param : params) {
            String paramType = param.getDataType().getDisplayName();
            String paramName = param.getName();

            // Check for undefined types (-5 each)
            if (UNDEFINED_TYPE_PATTERN.matcher(paramType).matches() ||
                paramType.contains("undefined")) {
                undefinedParamCount++;
            }

            // Check for Hungarian notation violations (-3 each)
            if (!HUNGARIAN_PATTERN.matcher(paramName).matches() &&
                !paramName.startsWith("param_")) {
                hungarianViolationCount++;
            }
        }

        if (undefinedParamCount > 0) {
            int penalty = undefinedParamCount * PENALTY_UNDEFINED_VAR;
            score -= penalty;
            issues.add("-" + penalty + ": " + undefinedParamCount + " undefined param types");
        }

        if (hungarianViolationCount > 0) {
            int penalty = hungarianViolationCount * PENALTY_HUNGARIAN_VIOLATION;
            score -= penalty;
            issues.add("-" + penalty + ": " + hungarianViolationCount + " Hungarian violations");
        }

        // 6. Local variable checks (via decompilation)
        try {
            DecompileResults results = decompiler.decompileFunction(func, 30, monitor);
            if (results != null && results.decompileCompleted()) {
                HighFunction highFunc = results.getHighFunction();
                if (highFunc != null) {
                    int undefinedLocalCount = 0;
                    int ssaVarCount = 0;

                    Iterator<HighSymbol> symIter = highFunc.getLocalSymbolMap().getSymbols();
                    while (symIter.hasNext()) {
                        HighSymbol sym = symIter.next();
                        String varName = sym.getName();
                        String varType = sym.getDataType().getDisplayName();

                        // Count SSA var names (iVar1, uVar2, etc.) - these indicate unrenamed locals
                        if (SSA_VAR_PATTERN.matcher(varName).matches()) {
                            ssaVarCount++;
                        }

                        // Count undefined types
                        if (UNDEFINED_TYPE_PATTERN.matcher(varType).matches() ||
                            varType.contains("undefined")) {
                            undefinedLocalCount++;
                        }
                    }

                    if (undefinedLocalCount > 0) {
                        int penalty = undefinedLocalCount * PENALTY_UNDEFINED_VAR;
                        score -= penalty;
                        issues.add("-" + penalty + ": " + undefinedLocalCount + " undefined locals");
                    }

                    // SSA names indicate unrenamed variables (penalize like Hungarian violations)
                    if (ssaVarCount > 0) {
                        int penalty = ssaVarCount * PENALTY_HUNGARIAN_VIOLATION;
                        score -= penalty;
                        issues.add("-" + penalty + ": " + ssaVarCount + " SSA var names");
                    }

                    // 7. DAT_* globals check (-3 per occurrence)
                    String decompiledCode = results.getDecompiledFunction().getC();
                    if (decompiledCode != null) {
                        java.util.regex.Matcher datMatcher = DAT_PATTERN.matcher(decompiledCode);
                        int datCount = 0;
                        Set<String> datRefs = new HashSet<>();
                        while (datMatcher.find()) {
                            datRefs.add(datMatcher.group());
                        }
                        datCount = datRefs.size();

                        if (datCount > 0) {
                            int penalty = datCount * PENALTY_DAT_GLOBAL;
                            score -= penalty;
                            issues.add("-" + penalty + ": " + datCount + " DAT_* globals");
                        }

                        // 8. s_* string labels check (-2 per occurrence)
                        java.util.regex.Matcher strMatcher = STRING_LABEL_PATTERN.matcher(decompiledCode);
                        int strCount = 0;
                        Set<String> strRefs = new HashSet<>();
                        while (strMatcher.find()) {
                            strRefs.add(strMatcher.group());
                        }
                        strCount = strRefs.size();

                        if (strCount > 0) {
                            int penalty = strCount * PENALTY_STRING_LABEL;
                            score -= penalty;
                            issues.add("-" + penalty + ": " + strCount + " s_* labels");
                        }

                        // 9. Inline comment density check
                        // Count inline comments vs code lines
                        if (plateComment != null && !plateComment.isEmpty()) {
                            int codeLines = 0;
                            int inlineComments = 0;
                            boolean inFunctionBody = false;
                            int braceDepth = 0;

                            for (String line : decompiledCode.split("\n")) {
                                String trimmed = line.trim();

                                // Track function body
                                for (char c : trimmed.toCharArray()) {
                                    if (c == '{') { braceDepth++; inFunctionBody = true; }
                                    else if (c == '}') braceDepth--;
                                }

                                if (inFunctionBody && !trimmed.isEmpty() &&
                                    !trimmed.startsWith("/*") && !trimmed.startsWith("*") && !trimmed.startsWith("//")) {
                                    codeLines++;
                                }

                                if (inFunctionBody && (trimmed.contains("/*") || trimmed.contains("//"))) {
                                    if (!trimmed.contains("WARNING:")) {
                                        inlineComments++;
                                    }
                                }
                            }

                            double density = codeLines > 0 ? (double) inlineComments / codeLines * 10 : 0;
                            if (density < 1.0) {
                                score -= PENALTY_LOW_COMMENT_DENSITY;
                                issues.add("-5: Low comment density");
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            issues.add("Decompile failed");
        }

        return Math.max(0, score);
    }

    /**
     * Get the index of a binary in the BINARY_ORDER array.
     * Returns Integer.MAX_VALUE if not found (sorts to end).
     */
    private int getBinaryOrderIndex(String binaryName) {
        for (int i = 0; i < BINARY_ORDER.length; i++) {
            if (BINARY_ORDER[i].equalsIgnoreCase(binaryName)) {
                return i;
            }
        }
        return Integer.MAX_VALUE;
    }

    private void generateCombinedTodoFile() throws Exception {
        File todoFile = new File(OUTPUT_DIR, "FunctionsTodo.txt");
        println("\nGenerating todo file: " + todoFile.getAbsolutePath());

        // Get ordered list of programs (same order as processing)
        List<String> orderedPrograms = new ArrayList<>(programScores.keySet());
        orderedPrograms.sort((a, b) -> {
            int indexA = getBinaryOrderIndex(a);
            int indexB = getBinaryOrderIndex(b);
            return Integer.compare(indexA, indexB);
        });

        try (PrintWriter writer = new PrintWriter(new FileWriter(todoFile))) {
            writer.println("# Function Documentation Todo List - All Binaries");
            writer.println("# Generated: " + new java.util.Date());
            writer.println("# Project Folder: " + currentProgram.getDomainFile().getParent().getPathname());
            writer.println("# Programs: " + totalPrograms);
            writer.println("# Total Functions: " + totalFunctions);
            writer.println("# Functions Needing Work: " + totalNeedsWork);
            writer.println("# Complete Functions: " + totalComplete);
            writer.println("# Minimum Threshold: " + (maxScore + 1) + "%");
            writer.println("# Score Range: " + minThreshold + "-" + maxScore);
            writer.println("#");
            writer.println("# Binaries are ordered by dependency hierarchy (process in order).");
            writer.println("# Within each binary, functions are sorted by score (lowest first).");
            writer.println("#");
            writer.println("# Format: [Status] ProgramName::FunctionName @ Address (Score: N) [Issues]");
            writer.println("# Issues show what needs to be fixed with penalty amounts.");
            writer.println("");

            int totalWritten = 0;

            // Process each binary in dependency order
            for (String programName : orderedPrograms) {
                List<FunctionScore> scores = programScores.get(programName);
                if (scores == null) continue;

                // Collect and sort functions needing work for this binary
                List<FunctionScore> needsWork = new ArrayList<>();
                for (FunctionScore fs : scores) {
                    if (fs.score >= minThreshold && fs.score <= maxScore) {
                        needsWork.add(fs);
                    }
                }
                needsWork.sort((a, b) -> Integer.compare(a.score, b.score));

                if (needsWork.isEmpty()) continue;

                // Write section header for this binary
                int orderIndex = getBinaryOrderIndex(programName);
                String priority = orderIndex < BINARY_ORDER.length ?
                    "Priority " + (orderIndex + 1) : "Unranked";

                writer.println("");
                writer.println("# " + "=".repeat(60));
                writer.println("# " + programName + " (" + priority + ")");
                writer.println("# Functions needing work: " + needsWork.size());
                writer.println("# " + "=".repeat(60));
                writer.println("");

                for (FunctionScore fs : needsWork) {
                    StringBuilder line = new StringBuilder();
                    line.append("[ ] ").append(fs.programName).append("::").append(fs.funcName);
                    line.append(" @ ").append(fs.address);
                    line.append(" (Score: ").append(fs.score).append(")");

                    // Append issues list for Claude Code to know what to fix
                    if (!fs.issues.isEmpty()) {
                        line.append(" [").append(String.join("; ", fs.issues)).append("]");
                    }

                    writer.println(line.toString());
                    totalWritten++;
                }
            }

            writer.println("");
            writer.println("# End of todo list - " + totalWritten + " functions total");
        }

        println("  Written " + totalNeedsWork + " functions across " + totalPrograms + " binaries");
    }

    private void generateDetailedReport() throws Exception {
        File reportFile = new File(OUTPUT_DIR, "FunctionsReport_AllBinaries.txt");
        println("\nGenerating detailed report: " + reportFile.getAbsolutePath());

        try (PrintWriter writer = new PrintWriter(new FileWriter(reportFile))) {
            writer.println("=".repeat(70));
            writer.println("FUNCTION DOCUMENTATION ANALYSIS REPORT - ALL BINARIES");
            writer.println("=".repeat(70));
            writer.println("Generated: " + new java.util.Date());
            writer.println("Project Folder: " + currentProgram.getDomainFile().getParent().getPathname());
            writer.println("");

            writer.println("=== OVERALL SUMMARY ===");
            writer.println("Total Programs: " + totalPrograms);
            writer.println("Total Functions: " + totalFunctions);
            writer.println("Functions Needing Work: " + totalNeedsWork);
            writer.println("Complete Functions: " + totalComplete);
            writer.println("Completion Rate: " + String.format("%.1f%%",
                totalFunctions > 0 ? (100.0 * totalComplete / totalFunctions) : 0));
            writer.println("");

            writer.println("=== PER-PROGRAM SUMMARY ===");
            writer.println(String.format("%-25s %8s %10s %10s %10s",
                "Program", "Total", "NeedsWork", "Complete", "Rate"));
            writer.println("-".repeat(70));

            for (Map.Entry<String, int[]> entry : programStats.entrySet()) {
                String name = entry.getKey();
                int[] stats = entry.getValue();
                double rate = stats[0] > 0 ? (100.0 * stats[2] / stats[0]) : 0;
                writer.println(String.format("%-25s %8d %10d %10d %9.1f%%",
                    name, stats[0], stats[1], stats[2], rate));
            }
            writer.println("");

            writer.println("=== SCORE DISTRIBUTION ===");
            int[] globalBuckets = new int[11];
            for (List<FunctionScore> scores : programScores.values()) {
                for (FunctionScore fs : scores) {
                    globalBuckets[Math.min(fs.score / 10, 10)]++;
                }
            }

            for (int i = 0; i <= 10; i++) {
                String range = i == 10 ? "100" : String.format("%d-%d", i * 10, i * 10 + 9);
                writer.println(String.format("  %6s: %5d", range, globalBuckets[i]));
            }
            writer.println("");

            writer.println("=== MOST COMMON ISSUES ===");
            Map<String, Integer> issueCounts = new HashMap<>();
            for (List<FunctionScore> scores : programScores.values()) {
                for (FunctionScore fs : scores) {
                    for (String issue : fs.issues) {
                        issueCounts.merge(issue, 1, Integer::sum);
                    }
                }
            }

            issueCounts.entrySet().stream()
                .sorted((a, b) -> b.getValue().compareTo(a.getValue()))
                .limit(15)
                .forEach(e -> writer.println(String.format("  %5d: %s", e.getValue(), e.getKey())));
            writer.println("");

            writer.println("=== LOWEST SCORING FUNCTIONS (TOP 50) ===");
            List<FunctionScore> allScores = new ArrayList<>();
            for (List<FunctionScore> scores : programScores.values()) {
                allScores.addAll(scores);
            }
            allScores.sort((a, b) -> Integer.compare(a.score, b.score));

            int count = 0;
            for (FunctionScore fs : allScores) {
                if (count >= 50) break;
                if (fs.score >= minThreshold && fs.score <= maxScore) {
                    writer.println(String.format("  %3d: %-20s :: %-35s @ %s",
                        fs.score, fs.programName, fs.funcName, fs.address));
                    if (!fs.issues.isEmpty()) {
                        writer.println("       Issues: " + String.join(", ", fs.issues));
                    }
                    count++;
                }
            }
        }
    }

    private void printSummary() {
        println("");
        println("=".repeat(70));
        println("SUMMARY");
        println("=".repeat(70));
        println("Programs processed: " + totalPrograms);
        println("Total functions: " + totalFunctions);
        println("Functions needing work: " + totalNeedsWork);
        println("Complete functions: " + totalComplete);
        println("Completion rate: " + String.format("%.1f%%",
            totalFunctions > 0 ? (100.0 * totalComplete / totalFunctions) : 0));
        println("");
        println("Output files:");
        println("  - FunctionsTodo.txt (ordered by binary dependency)");
        println("  - FunctionsReport_AllBinaries.txt (detailed report)");
        println("");
        println("Processing order (per BINARY_DOCUMENTATION_ORDER.md):");
        println("  Storm.dll -> Fog.dll -> D2Lang.dll -> D2CMP.dll -> D2Common.dll -> ...");
        println("");
        println("Use with functions-process.ps1:");
        println("  .\\functions-process.ps1 -todoFile FunctionsTodo.txt -w 4");
    }
}
