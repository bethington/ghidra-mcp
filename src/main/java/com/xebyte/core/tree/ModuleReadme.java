package com.xebyte.core.tree;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * A compartment's {@code modules/<slug>/README.md}: why the sweep grouped these functions
 * (method, confidence, evidence such as {@code peripheral_pages}) and which files hold them.
 *
 * <p>One renderer for every writer. The reconciler and the narrower used to write their own
 * shorter README, so the first edit that touched a compartment dropped its method,
 * confidence and evidence and stamped it "narrowed by /decompile_tree_configure". The
 * grouping is the sweep's decision and survives a rewrite ({@link #parse} reads it back);
 * only the member count and the file table are recomputed.
 */
public final class ModuleReadme {

    private ModuleReadme() {
    }

    /** One row of the file table. */
    public record FileRow(String path, String first, String last, int functions) {
    }

    /**
     * Why the compartment exists. {@code method} is null for a README a previous version
     * already stripped; that cannot be recovered short of a resweep.
     */
    public record Grouping(String method, double confidence, Map<String, String> evidence, String note) {

        Grouping withNote(String newNote) {
            return new Grouping(method, confidence, evidence, newNote);
        }

        static Grouping unknown() {
            return new Grouping(null, 0.0, Map.of(), null);
        }
    }

    public static String render(String slug, Grouping g, int functions, List<FileRow> files) {
        StringBuilder sb = new StringBuilder();
        sb.append("# Module ").append(slug).append("\n\n");
        if (g.method() != null) {
            sb.append("method: ").append(g.method()).append('\n');
            sb.append("confidence: ")
                    .append(String.format(Locale.ROOT, "%.2f", g.confidence())).append('\n');
        }
        sb.append("functions: ").append(functions).append('\n');
        sb.append("files: ").append(files.size()).append('\n');
        if (g.note() != null) {
            sb.append("note: ").append(g.note()).append('\n');
        }
        if (g.method() != null) {
            // What the grouping asserts, in the reader's terms. Without this an
            // address-band compartment reads as a defect rather than as the expected
            // outcome for code that carries no signal.
            sb.append('\n').append(TreeGuidance.interpretation(g.method(), g.confidence()))
                    .append('\n');
        }
        sb.append("\n## Files\n\n");
        sb.append("| file | first | last | functions |\n");
        sb.append("| --- | --- | --- | ---: |\n");
        for (FileRow f : files) {
            sb.append("| ").append(f.path())
                    .append(" | ").append(f.first())
                    .append(" | ").append(f.last())
                    .append(" | ").append(f.functions())
                    .append(" |\n");
        }
        if (!g.evidence().isEmpty()) {
            sb.append("\n## Evidence\n\n");
            for (Map.Entry<String, String> e : g.evidence().entrySet()) {
                sb.append("- ").append(e.getKey()).append(": ").append(e.getValue()).append('\n');
            }
        }
        return sb.toString();
    }

    /** The grouping an existing README records; {@link Grouping#unknown()} for none. */
    public static Grouping parse(String readme) {
        if (readme == null) {
            return Grouping.unknown();
        }
        String method = null;
        double confidence = 0.0;
        String note = null;
        Map<String, String> evidence = new LinkedHashMap<>();
        boolean inEvidence = false;
        for (String line : readme.split("\n")) {
            if (line.startsWith("## ")) {
                inEvidence = line.equals("## Evidence");
                continue;
            }
            if (inEvidence) {
                if (line.startsWith("- ")) {
                    int colon = line.indexOf(": ");
                    if (colon > 2) {
                        evidence.put(line.substring(2, colon), line.substring(colon + 2));
                    }
                }
            } else if (line.startsWith("method: ")) {
                method = line.substring("method: ".length());
            } else if (line.startsWith("confidence: ")) {
                try {
                    confidence = Double.parseDouble(line.substring("confidence: ".length()));
                } catch (NumberFormatException e) {
                    confidence = 0.0;
                }
            } else if (line.startsWith("note: ")) {
                note = line.substring("note: ".length());
            }
        }
        return new Grouping(method, confidence, evidence, note);
    }
}
