package com.xebyte.core.tree;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Reading a tree back: splitting a compartment file into function blocks, the
 * address in a block's {@code // fn:} line, and {@code index/by-address.tsv} rows. Writing
 * goes through {@link CompartmentPacker} and {@link DerivedFiles}.
 */
public final class TreeFiles {

    /** First header line: {@code // fn: Name @ <addr> size=N} */
    private static final Pattern FN_HEADER = Pattern.compile(
            "^// fn: .* @ ((?:[A-Za-z0-9_.]+:)?[0-9A-Fa-f]+) size=");

    private TreeFiles() {
    }

    /** Split a partition {@code .c} into per-function chunks (header + body). */
    public static List<String> splitFunctionChunks(String fileBody) {
        List<String> chunks = new ArrayList<>();
        if (fileBody == null || fileBody.isEmpty()) {
            return chunks;
        }
        String[] lines = fileBody.split("\n", -1);
        StringBuilder cur = null;
        for (int i = 0; i < lines.length; i++) {
            String line = lines[i];
            boolean startsFn = line.startsWith("// fn: ");
            if (startsFn) {
                if (cur != null) {
                    chunks.add(trimTrailingBlank(cur.toString()));
                }
                cur = new StringBuilder();
            }
            if (cur == null) {
                // Preamble / stray text before the first header — keep with next
                // chunk by starting one, or drop if the file is malformed.
                if (!line.isEmpty()) {
                    cur = new StringBuilder();
                } else {
                    continue;
                }
            }
            cur.append(line);
            if (i < lines.length - 1 || fileBody.endsWith("\n")) {
                cur.append('\n');
            }
        }
        if (cur != null && !cur.isEmpty()) {
            chunks.add(trimTrailingBlank(cur.toString()));
        }
        return chunks;
    }

    public static String addressFromChunk(String chunk) {
        if (chunk == null) {
            return null;
        }
        int nl = chunk.indexOf('\n');
        String first = nl < 0 ? chunk : chunk.substring(0, nl);
        Matcher m = FN_HEADER.matcher(first);
        if (!m.find()) {
            return null;
        }
        return m.group(1);
    }

    private static String trimTrailingBlank(String s) {
        // Leave a single trailing newline; strip extra blank lines the splitter
        // may have absorbed so rewrite can re-insert a consistent separator.
        while (s.endsWith("\n\n")) {
            s = s.substring(0, s.length() - 1);
        }
        return s;
    }

    /** Load {@code index/by-address.tsv}; empty ifp on 5-column trees = unknown. */
    public static List<IndexEntry> readIndex(Path indexPath) throws IOException {
        List<String> lines = Files.readAllLines(indexPath, StandardCharsets.UTF_8);
        List<IndexEntry> out = new ArrayList<>();
        for (String line : lines) {
            if (line.isBlank() || line.startsWith("address\t")) {
                continue;
            }
            String[] cols = line.split("\t", -1);
            if (cols.length < 4) {
                continue;
            }
            out.add(new IndexEntry(
                    cols[0],
                    cols[1],
                    cols[2],
                    // The index is a file on disk anyone can edit; a path that is not a
                    // compartment file reads as no file, so the block is rebuilt instead of
                    // read from wherever the row points.
                    TreeLayout.isModuleFile(cols[3]) ? cols[3] : "",
                    cols.length > 4 && Boolean.parseBoolean(cols[4]),
                    cols.length > 5 ? cols[5] : ""));
        }
        return out;
    }

    /**
     * One row of {@code index/by-address.tsv}. Shared by narrow and reconcile —
     * a second row type would let the two writers drift on column meaning.
     */
    public record IndexEntry(
            String addressHex,
            String name,
            String slug,
            String file,
            boolean evidenceBacked,
            String ifp) {

        public IndexEntry withFile(String newFile) {
            return new IndexEntry(addressHex, name, slug, newFile, evidenceBacked, ifp);
        }

        public IndexEntry withName(String newName) {
            return new IndexEntry(addressHex, newName, slug, file, evidenceBacked, ifp);
        }

        public IndexEntry withIfp(String newIfp) {
            return new IndexEntry(addressHex, name, slug, file, evidenceBacked, newIfp);
        }
    }
}
