package com.xebyte.core.tree;

import com.xebyte.core.AddressKeys;
import com.xebyte.core.FunctionFacts;
import ghidra.app.decompiler.DecompInterface;
import ghidra.program.model.listing.Function;
import ghidra.util.task.TaskMonitor;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * One function's block in a tree file, rendered from
 * {@link com.xebyte.core.FunctionFacts} — the same map {@code /get_functions} returns — so the
 * tree and the bundle show the same fields with the same content.
 *
 * <p>Every header line is {@code // key: value}, one fact per line, so each greps on its
 * own ({@code grep '// callers:.*Foo'}, {@code grep '// refs:.*0x40020000'}). List fields
 * repeat their key once per item. The header ends at {@link #HEADER_END}; everything after
 * it is the decompiler's C, which can itself contain {@code //} comment lines.
 *
 * <p>{@link #parse} reads a block back into the facts map's keys and shapes; the parity test
 * holds the two directions together.
 */
public final class FunctionBlock {

    /** Last header line. The body starts on the next line. */
    public static final String HEADER_END = "// ----";

    private FunctionBlock() {
    }

    /** Where the block sits in the tree; not a fact about the function. */
    public record Placement(String partitionSlug, String method, double confidence,
            boolean evidenceBacked, java.time.Instant dts, String uri) {
    }

    /**
     * What a block holds in the tree: every {@code /get_functions} field except
     * {@code call_context} (a decompile per caller, and each caller's own block is in the tree)
     * and {@code disassembly} (opt-in on both surfaces).
     */
    public static final FunctionFacts.Options TREE_FIELDS =
            new FunctionFacts.Options(null, false, 0, 3, false);

    /** A rendered block, and whether the decompiler produced code for it. */
    public record Built(String text, boolean failed) {
    }

    /**
     * Decompile {@code func} with the tree's pooled decompiler and render its block. The
     * facts come from the same builder {@code /get_functions} uses, configured the same way
     * ({@link FunctionFacts#configureDecompiler} on {@code decomp}).
     */
    public static Built build(Function func, DecompInterface decomp, int timeoutSeconds,
            TaskMonitor monitor, String partitionSlug, String method, double confidence,
            boolean evidenceBacked, String programName) {
        Map<String, Object> facts = FunctionFacts.build(func.getProgram(), func, TREE_FIELDS, f -> {
            try {
                return decomp.decompileFunction(f, timeoutSeconds, monitor);
            } catch (Exception e) {
                return null;
            }
        });
        boolean failed = Boolean.TRUE.equals(facts.get("decompile_failed"))
                || facts.get("decompiled_code") == null;
        String body = failed
                ? SweepJob.renderFailedBody(String.valueOf(facts.getOrDefault("decompile_error", "no output")))
                : String.valueOf(facts.get("decompiled_code"));
        String addressHex = AddressKeys.of(func);
        Placement where = new Placement(partitionSlug, method, confidence, evidenceBacked,
                Instant.now(),
                SweepJob.functionResourceUri(programName, addressHex));
        return new Built(render(facts, body, where), failed);
    }

    /**
     * Header plus body. {@code body} is the C, or the failure marker when there is none. The
     * {@code // fp:} line is {@link #fingerprint} of the rest, computed here so it always
     * describes the block it sits in.
     */
    public static String render(Map<String, Object> facts, String body, Placement where) {
        return withFingerprint(renderWithFp(facts, body, where, ""));
    }

    /**
     * A short hash of the block as written, without the lines that change on every render
     * ({@code dts}) and without the {@code fp} line itself. A full reconcile
     * rebuilds a block whose text no longer matches its {@code fp}: one edited by hand, cut
     * short, or patched without its fingerprint, which the program's inputs alone cannot
     * reveal.
     */
    public static String fingerprint(String block) {
        StringBuilder sb = new StringBuilder(block.length());
        for (String line : block.split("\n", -1)) {
            if (line.startsWith("// dts: ") || line.startsWith("// fp: ")) {
                continue;
            }
            sb.append(line).append('\n');
        }
        return SweepJob.shortContentHash(sb.toString().strip());
    }

    /** {@code block} with its {@code fp} line set to {@link #fingerprint} of the rest. */
    public static String withFingerprint(String block) {
        String fp = fingerprint(block);
        StringBuilder sb = new StringBuilder(block.length() + 16);
        boolean done = false;
        for (String line : block.split("\n", -1)) {
            if (!done && line.startsWith("// fp: ")) {
                line = "// fp: " + fp;
                done = true;
            }
            sb.append(line).append('\n');
        }
        sb.setLength(sb.length() - 1);
        return sb.toString();
    }

    /**
     * Whether {@code block}'s text still matches its {@code fp} line. A block that still
     * carries a {@code // mod:} stamp was written by an earlier build (the modification number
     * starts over on every open, so the stamp was dropped) and is rebuilt, so an old tree
     * ends up as a fresh sweep writes it.
     */
    public static boolean intact(String block) {
        for (String line : block.split("\n", -1)) {
            if (line.equals(HEADER_END)) {
                break;
            }
            if (line.startsWith("// mod: ")) {
                return false;
            }
            if (line.startsWith("// fp: ")) {
                return line.substring("// fp: ".length()).strip().equals(fingerprint(block));
            }
        }
        return false;
    }

    private static String renderWithFp(Map<String, Object> facts, String body, Placement where, String fp) {
        StringBuilder sb = new StringBuilder();
        line(sb, "fn", str(facts.get("name")) + " @ " + str(facts.get("entry_point"))
                + " size=" + str(facts.get("size")));
        line(sb, "signature", facts.get("signature"));
        line(sb, "classification", facts.get("classification"));
        if (facts.containsKey("return_type")) {
            line(sb, "return_type", str(facts.get("return_type"))
                    + (Boolean.FALSE.equals(facts.get("return_type_resolved")) ? " (unresolved)" : ""));
        }
        line(sb, "body", str(facts.get("body_start")) + ".." + str(facts.get("body_end")));
        line(sb, "tags", joinOrNone(list(facts.get("tags"))));
        if (facts.get("plate_comment") != null) {
            line(sb, "plate", oneLine(facts.get("plate_comment")));
        }
        for (Object issue : list(facts.get("plate_comment_issues"))) {
            line(sb, "plate_issue", issue);
        }
        line(sb, "calls", neighbours(facts, "callees", "callee_count"));
        line(sb, "callers", neighbours(facts, "callers", "caller_count"));
        if (!list(facts.get("refs")).isEmpty()) {
            line(sb, "refs", String.join(" ", strings(list(facts.get("refs")))));
        }
        for (Object o : list(facts.get("parameters"))) {
            Map<?, ?> p = (Map<?, ?>) o;
            line(sb, "param", "#" + str(p.get("ordinal")) + " " + str(p.get("type")) + " "
                    + str(p.get("name")) + " @" + str(p.get("storage"))
                    + (p.get("comment") != null ? " — " + oneLine(p.get("comment")) : ""));
        }
        for (Object o : list(facts.get("locals"))) {
            Map<?, ?> l = (Map<?, ?>) o;
            line(sb, "local", str(l.get("type")) + " " + str(l.get("name"))
                    + (l.get("storage") != null ? " @" + str(l.get("storage")) : "")
                    + (Boolean.TRUE.equals(l.get("is_phantom")) ? " [phantom]" : "")
                    + (Boolean.FALSE.equals(l.get("in_decompiled_code")) ? " [not in code]" : ""));
        }
        for (Object o : list(facts.get("labels"))) {
            Map<?, ?> l = (Map<?, ?>) o;
            line(sb, "label", offset(l.get("relative_offset")) + " " + str(l.get("name"))
                    + " (" + str(l.get("source")) + ")");
        }
        for (Object o : list(facts.get("comments"))) {
            Map<?, ?> c = (Map<?, ?>) o;
            line(sb, "comment", offset(c.get("relative_offset")) + " " + str(c.get("kind")) + " "
                    + oneLine(c.get("text")));
        }
        for (Object o : list(facts.get("xrefs"))) {
            Map<?, ?> x = (Map<?, ?>) o;
            line(sb, "xref", str(x.get("from")) + " " + str(x.get("type"))
                    + (x.get("from_function") != null ? " " + str(x.get("from_function")) : ""));
        }
        for (Object target : list(facts.get("jump_targets"))) {
            line(sb, "jump", target);
        }
        for (Object o : list(facts.get("call_context"))) {
            Map<?, ?> c = (Map<?, ?>) o;
            line(sb, "context", str(c.get("caller")) + " @ " + str(c.get("site_address")) + ": "
                    + oneLine(c.get("text")));
        }
        for (Object o : list(facts.get("disassembly"))) {
            Map<?, ?> d = (Map<?, ?>) o;
            line(sb, "disasm", str(d.get("address")) + " " + str(d.get("mnemonic"))
                    + (d.get("operands") != null && !str(d.get("operands")).isEmpty()
                            ? " " + str(d.get("operands")) : ""));
        }
        if (Boolean.TRUE.equals(facts.get("decompile_failed"))) {
            line(sb, "decompile_error", oneLine(facts.get("decompile_error")));
        }
        line(sb, "part", where.partitionSlug() + " " + where.method()
                + " conf=" + String.format(Locale.ROOT, "%.2f", where.confidence())
                + " evidence_backed=" + where.evidenceBacked());
        sb.append("// fp: ").append(fp).append('\n');
        line(sb, "dts", where.dts());
        line(sb, "uri", where.uri());
        line(sb, "see", "modules/" + where.partitionSlug() + "/README.md");
        sb.append(HEADER_END).append('\n');
        sb.append(body);
        if (!body.endsWith("\n")) {
            sb.append('\n');
        }
        return sb.toString();
    }

    /**
     * Callers or callees exactly as the facts carry them (sorted, capped), as
     * {@code name@address} so a grep for the name hits and the address disambiguates;
     * {@code +N more} when the facts were capped.
     */
    static String neighbours(Map<String, Object> facts, String key, String countKey) {
        List<Object> items = list(facts.get(key));
        if (items.isEmpty()) {
            return "(none)";
        }
        List<String> names = new ArrayList<>();
        for (Object o : items) {
            Map<?, ?> m = (Map<?, ?>) o;
            names.add(str(m.get("name")) + "@" + str(m.get("address")));
        }
        String joined = String.join(", ", names);
        Object count = facts.get(countKey);
        if (count instanceof Number n && n.intValue() > items.size()) {
            joined += " +" + (n.intValue() - items.size()) + " more";
        }
        return joined;
    }

    private static final FunctionFacts.Options NEIGHBOURS =
            new FunctionFacts.Options(java.util.Set.of("callers", "callees"), false, 0, 3, false);

    /**
     * The {@code // calls:} and {@code // callers:} values for {@code func} now, by the same
     * rule as a full block (no decompile needed). For patching neighbours' headers after a
     * rename or a new call.
     */
    public static String[] neighbourValues(Function func) {
        Map<String, Object> facts = FunctionFacts.build(func.getProgram(), func, NEIGHBOURS, f -> null);
        return new String[] {
            neighbours(facts, "callees", "callee_count"),
            neighbours(facts, "callers", "caller_count")
        };
    }

    /** Where the header ends: the index of the first body line, or -1 for an older block. */
    public static int bodyStart(String[] lines) {
        for (int i = 0; i < lines.length; i++) {
            if (lines[i].equals(HEADER_END)) {
                return i + 1;
            }
        }
        return -1;
    }

    /** The C under the header (everything after {@link #HEADER_END}). */
    public static String body(String block) {
        int at = block.indexOf("\n" + HEADER_END + "\n");
        return at < 0 ? block : block.substring(at + HEADER_END.length() + 2);
    }

    /**
     * Read a block's header back into facts keys. Scalars come back as strings; list fields
     * as lists of strings in the order written. The parity test compares these with the
     * facts the block was rendered from.
     */
    public static Map<String, Object> parse(String block) {
        Map<String, Object> out = new LinkedHashMap<>();
        for (String raw : block.split("\n")) {
            if (raw.equals(HEADER_END)) {
                break;
            }
            if (!raw.startsWith("// ")) {
                continue;
            }
            int colon = raw.indexOf(": ", 3);
            if (colon < 0) {
                continue;
            }
            String key = raw.substring(3, colon);
            String value = raw.substring(colon + 2);
            switch (key) {
                case "param", "local", "label", "comment", "xref", "jump", "context", "disasm",
                        "plate_issue" -> {
                    @SuppressWarnings("unchecked")
                    List<String> items = (List<String>) out.computeIfAbsent(key, k -> new ArrayList<String>());
                    items.add(value);
                }
                default -> out.put(key, value);
            }
        }
        out.put("body", body(block));
        return out;
    }

    // ------------------------------------------------------------------ helpers

    private static void line(StringBuilder sb, String key, Object value) {
        if (value == null) {
            return;
        }
        sb.append("// ").append(key).append(": ").append(oneLine(value)).append('\n');
    }

    /** One header line per fact: newlines inside a value are written as {@code \n}. */
    static String oneLine(Object value) {
        return value == null ? "" : String.valueOf(value).replace("\r", "").replace("\n", "\\n");
    }

    /** A body-relative offset as {@code +0x14}. */
    static String offset(Object value) {
        return value instanceof Number n ? "+0x" + Long.toHexString(n.longValue()) : str(value);
    }

    private static String joinOrNone(List<Object> items) {
        return items.isEmpty() ? "(none)" : String.join(", ", strings(items));
    }

    private static List<String> strings(List<Object> items) {
        List<String> out = new ArrayList<>(items.size());
        for (Object o : items) {
            out.add(String.valueOf(o));
        }
        return out;
    }

    @SuppressWarnings("unchecked")
    static List<Object> list(Object value) {
        return value instanceof List<?> l ? (List<Object>) l : List.of();
    }

    private static String str(Object value) {
        return value == null ? "" : String.valueOf(value);
    }
}
