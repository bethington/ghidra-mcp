package com.xebyte.core.tree;

import com.xebyte.core.AddressKeys;
import com.xebyte.core.FunctionFacts;
import com.xebyte.core.ServiceUtils;
import com.xebyte.core.partition.PartitionContext;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Reading and editing single function blocks: finding one in a file, comparing two, patching
 * a header's neighbour lines, reading its compartment line, and building one with the
 * tree's decompiler. Laying blocks out into files is {@link CompartmentPacker}'s job.
 *
 * <p>Block boundaries reuse {@link TreeFiles#splitFunctionChunks}: a block starts only at a
 * line beginning with {@code // fn: }, so a string literal containing that text cannot open
 * a false block.
 *
 * @since 7.2.0
 */
public final class BlockSplicer {

    private static final Pattern PART_LINE = Pattern.compile(
            "^// part: (\\S+) (\\S+) conf=([0-9.]+) evidence_backed=(true|false)\\s*$");
    private static final String FAILED_MARKER_PREFIX = "// DECOMPILATION FAILED: ";

    private BlockSplicer() {
    }

    // -------------------------------------------------------------------------
    // Pure helpers (offline-tested)
    // -------------------------------------------------------------------------

    /**
     * Locate the chunk whose header address matches {@code addressHex}.
     * Returns null when no line-start {@code // fn: … @ <addr>} matches —
     * callers must fail that address rather than guess an offset.
     */
    public static String findBlock(String fileBody, String addressHex) {
        String want = AddressKeys.normalize(addressHex);
        if (want.isEmpty() || fileBody == null) {
            return null;
        }
        for (String chunk : TreeFiles.splitFunctionChunks(fileBody)) {
            String addr = TreeFiles.addressFromChunk(chunk);
            if (addr != null && want.equals(AddressKeys.normalize(addr))) {
                return chunk;
            }
        }
        return null;
    }

    /**
     * Whether two renderings of a block say the same thing: equal but for the lines that
     * change on every render ({@code // dts:}).
     *
     * <p>This used to compare {@code // fp:}, a hash of the decompiled C alone. Since the
     * header carries facts the C never prints (callers' names on {@code // xref:} lines,
     * tags, refs, labels), a change to those alone was computed, judged unchanged and
     * dropped: a function renamed a second time kept its old name in every callee's
     * {@code // xref:} lines.
     */
    public static boolean sameBlock(String a, String b) {
        return withoutRenderStamps(a).equals(withoutRenderStamps(b));
    }

    private static String withoutRenderStamps(String block) {
        StringBuilder sb = new StringBuilder(block.length());
        for (String line : block.split("\n", -1)) {
            if (line.startsWith("// dts: ")) {
                continue;
            }
            sb.append(line).append('\n');
        }
        return sb.toString().strip();
    }

    /**
     * Replace only the {@code // calls:} / {@code // callers:} lines. Inserts
     * them after {@code // fn:} when an older seven-line header lacks them —
     * never touches the body or fp/dts/uri/see.
     */
    public static String patchNeighbourhoodLines(
            String block, String callsValue, String callersValue) {
        if (block == null) {
            return "";
        }
        String callsLine = "// calls: " + (callsValue != null ? callsValue : "(none)");
        String callersLine = "// callers: " + (callersValue != null ? callersValue : "(none)");
        String[] lines = block.split("\n", -1);
        boolean hadTrailing = block.endsWith("\n");
        // Drop the artificial empty element split(-1) adds for a trailing newline.
        int n = lines.length;
        if (hadTrailing && n > 0 && lines[n - 1].isEmpty()) {
            n--;
        }

        boolean hasCalls = false;
        boolean hasCallers = false;
        for (int i = 0; i < n; i++) {
            if (lines[i].startsWith("// calls:")) {
                lines[i] = callsLine;
                hasCalls = true;
            } else if (lines[i].startsWith("// callers:")) {
                lines[i] = callersLine;
                hasCallers = true;
            }
        }

        StringBuilder sb = new StringBuilder();
        if (hasCalls && hasCallers) {
            for (int i = 0; i < n; i++) {
                if (i > 0) {
                    sb.append('\n');
                }
                sb.append(lines[i]);
            }
        } else {
            // Older trees: insert after the fn: line so Grep still finds neighbourhood.
            for (int i = 0; i < n; i++) {
                if (i > 0) {
                    sb.append('\n');
                }
                sb.append(lines[i]);
                if (lines[i].startsWith("// fn: ")) {
                    if (!hasCalls) {
                        sb.append('\n').append(callsLine);
                    }
                    if (!hasCallers) {
                        sb.append('\n').append(callersLine);
                    }
                }
            }
        }
        if (hadTrailing || block.isEmpty()) {
            sb.append('\n');
        }
        return sb.toString();
    }

    /**
     * Extract the current {@code // calls:} / {@code // callers:} values
     * (text after the prefix), or null when absent.
     */
    public static String[] neighbourhoodValuesFromBlock(String block) {
        String calls = null;
        String callers = null;
        if (block == null) {
            return new String[]{null, null};
        }
        for (String line : block.split("\n", -1)) {
            if (line.equals(FunctionBlock.HEADER_END)) {
                break;
            }
            if (line.startsWith("// calls:")) {
                calls = line.substring("// calls:".length()).trim();
            } else if (line.startsWith("// callers:")) {
                callers = line.substring("// callers:".length()).trim();
            }
        }
        return new String[]{calls, callers};
    }

    /** Everything after the leading {@code // } comment block — body identity for patches. */
    public static String bodyAfterLeadingComments(String block) {
        if (block == null) {
            return "";
        }
        String[] lines = block.split("\n", -1);
        // The header ends at its terminator; the decompiler's own // lines below it are body.
        // Blocks written before the terminator existed end at the first non-comment line.
        int idx = FunctionBlock.bodyStart(lines);
        if (idx < 0) {
            idx = 0;
            while (idx < lines.length && lines[idx].startsWith("// ")) {
                idx++;
            }
        }
        StringBuilder sb = new StringBuilder();
        for (; idx < lines.length; idx++) {
            if (sb.length() > 0) {
                sb.append('\n');
            }
            sb.append(lines[idx]);
        }
        return sb.toString();
    }

    public static PartitionMeta partitionMetaFromBlock(String block) {
        if (block == null) {
            return null;
        }
        for (String line : block.split("\n", -1)) {
            Matcher m = PART_LINE.matcher(line);
            if (m.matches()) {
                double conf;
                try {
                    conf = Double.parseDouble(m.group(3));
                } catch (NumberFormatException e) {
                    conf = 0.0;
                }
                return new PartitionMeta(
                        m.group(1), m.group(2), conf, Boolean.parseBoolean(m.group(4)));
            }
        }
        return null;
    }

    // -------------------------------------------------------------------------
    // Orchestration (Program + disk)
    // -------------------------------------------------------------------------

    /** Live callers ∪ callees of every address in {@code seeds}. */
    static Set<String> neighbourAddresses(
            PartitionContext ctx, Program program, Set<String> seeds) {
        Set<String> out = new LinkedHashSet<>();
        PartitionContext.CallGraph cg = ctx.callGraph();
        List<Function> fns = ctx.functions();
        for (String hex : seeds) {
            Function func = AddressKeys.function(program, hex);
            if (func == null) {
                continue;
            }
            Integer idx = ctx.indexOf(func.getEntryPoint());
            if (idx == null) {
                continue;
            }
            addNeighbourHexes(out, fns, cg.callees().get(idx));
            addNeighbourHexes(out, fns, cg.callers().get(idx));
        }
        return out;
    }

    private static void addNeighbourHexes(
            Set<String> out, List<Function> fns, Set<Integer> indices) {
        if (indices == null) {
            return;
        }
        for (int i : indices) {
            if (i >= 0 && i < fns.size()) {
                out.add(AddressKeys.of(fns.get(i)));
            }
        }
    }

    /** One function's block, decompiled with the tree's pooled decompiler. */
    static FunctionBlock.Built decompileBlock(
            DecompInterface decomp,
            Function func,
            PartitionMeta part,
            int timeoutSeconds,
            String programName) {
        return FunctionBlock.build(func, decomp, timeoutSeconds, TaskMonitor.DUMMY, part.slug(),
                part.method(), part.confidence(), part.evidenceBacked(), programName);
    }

    // -------------------------------------------------------------------------
    // Result types
    // -------------------------------------------------------------------------

    public record PartitionMeta(
            String slug, String method, double confidence, boolean evidenceBacked) {}

}
