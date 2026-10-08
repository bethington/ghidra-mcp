package com.xebyte.core.tree;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Lays a compartment's blocks, in address order, out into its {@code .c} files: the one rule
 * for how a tree is split into files, used by the sweep (as it decompiles) and by the
 * reconciler (re-packing a compartment after blocks changed, came or went).
 *
 * <p>The reconciler used to keep its own layout logic, inserting into the file whose range
 * covered the address, splitting a file that grew past the budget, renaming one whose first
 * function changed. That is a second answer to the sweep's question, and the two drifted:
 * after edits a reconciled compartment was split differently from the sweep of the same
 * program. Packing every time from the blocks means one answer.
 *
 * <p>The rule: bytes, not function count, decide a split (median C is ~386 B, max 23 KB, so a
 * fixed count swings between ~8 KB and ~460 KB files), with {@link #MAX_FUNCTIONS_PER_FILE} as
 * a backstop. A file closes BEFORE the block that would overflow it, so the budget is a hard
 * Read ceiling; an empty file takes any block, so an oversized function gets a file of its own
 * and is never split. A file is named for its first function.
 */
public final class CompartmentPacker {

    public static final int MAX_FUNCTIONS_PER_FILE = 200;

    /** A finished file: its tree-relative path, its text, and the keys of its blocks in order. */
    public record PackedFile(String path, String body, List<String> keys) {
    }

    private final String slug;
    private final int maxFileBytes;
    private final int pointerSize;

    private final StringBuilder body = new StringBuilder();
    private final List<String> keys = new ArrayList<>();
    private int bytes;
    private String path;

    public CompartmentPacker(String slug, int maxFileBytes, int pointerSize) {
        this.slug = slug;
        this.maxFileBytes = maxFileBytes;
        this.pointerSize = Math.max(1, pointerSize);
    }

    /**
     * Add the next block. Returns the file this closed to make room, or null. The block itself
     * lands in {@link #currentPath()}.
     */
    public PackedFile add(String key, String blockText) {
        String text = normalized(blockText);
        int size = text.getBytes(StandardCharsets.UTF_8).length;
        PackedFile closed = null;
        if (!keys.isEmpty() && (bytes + size > maxFileBytes || keys.size() >= MAX_FUNCTIONS_PER_FILE)) {
            closed = finish();
        }
        if (path == null) {
            path = TreeLayout.moduleFunctionFile(slug,
                    TreeLayout.compartmentFileName(key, pointerSize));
        }
        body.append(text);
        bytes += size;
        keys.add(key);
        return closed;
    }

    /** The file the last block went into. */
    public String currentPath() {
        return path;
    }

    /** Close the open file; null when nothing is open. */
    public PackedFile finish() {
        if (keys.isEmpty()) {
            return null;
        }
        PackedFile out = new PackedFile(path, body.toString(), List.copyOf(keys));
        body.setLength(0);
        keys.clear();
        bytes = 0;
        path = null;
        return out;
    }

    /** Pack {@code blocks} (key → text, in address order) in one go. */
    public static List<PackedFile> pack(String slug, int maxFileBytes, int pointerSize,
            List<java.util.Map.Entry<String, String>> blocks) {
        CompartmentPacker packer = new CompartmentPacker(slug, maxFileBytes, pointerSize);
        List<PackedFile> out = new ArrayList<>();
        for (java.util.Map.Entry<String, String> b : blocks) {
            PackedFile closed = packer.add(b.getKey(), b.getValue());
            if (closed != null) {
                out.add(closed);
            }
        }
        PackedFile last = packer.finish();
        if (last != null) {
            out.add(last);
        }
        return out;
    }

    /**
     * A block as it sits in a file: no trailing blank lines of its own, one newline, then the
     * blank line that separates it from the next. A block read back from a file therefore packs
     * to the same bytes as the freshly rendered one.
     */
    static String normalized(String blockText) {
        String t = blockText == null ? "" : blockText;
        int end = t.length();
        while (end > 0 && (t.charAt(end - 1) == '\n' || t.charAt(end - 1) == '\r')) {
            end--;
        }
        return t.substring(0, end) + "\n\n";
    }
}
