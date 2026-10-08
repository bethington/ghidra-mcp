package com.xebyte.core.tree;

import com.xebyte.core.AddressKeys;
import java.util.Locale;

/**
 * Pure path and filename generation for a tree.
 *
 * <p>No Ghidra imports — take pointer size in bytes so offline tests can pin
 * lexical-order == address-order without a Program. Filenames are deliberately
 * not rename-stable: a stale path after a rename gives a loud ENOENT instead
 * of silently serving the wrong function.
 */
public final class TreeLayout {

    public static final int MAX_SANITISED_NAME_LENGTH = 96;

    private TreeLayout() {
    }

    /**
     * {@code <zero-padded-address>.c} — one Read-budget file inside a compartment,
     * named by its first function. No function name in the path: the file holds
     * several functions, so naming it after one would be a lie. Zero-padding
     * makes lexical sort match address order.
     *
     * @param address           first function entry as an unsigned offset
     * @param pointerSizeBytes  program pointer size ({@code 4} or {@code 8});
     *                          hex width is {@code pointerSizeBytes * 2}
     */
    public static String compartmentFileName(long address, int pointerSizeBytes) {
        return paddedAddressHex(address, pointerSizeBytes) + ".c";
    }

    /**
     * The file name for a first function's tree key ({@link AddressKeys}): the padded
     * offset, prefixed with the space outside the default one ({@code ovl1_00001000.c}) so
     * two functions at one offset in different spaces never share a file.
     */
    public static String compartmentFileName(String key, int pointerSizeBytes) {
        String space = AddressKeys.space(key);
        String name = compartmentFileName(AddressKeys.offset(key), pointerSizeBytes);
        return space.isEmpty() ? name : sanitiseName(space) + "_" + name;
    }

    /**
     * Legacy one-function form ({@code <addr>_<name>.c}). Prefer
     * {@link #compartmentFileName} for decompilation trees — grouping is deliberate.
     */
    public static String functionFileName(long address, String functionName, int pointerSizeBytes) {
        return paddedAddressHex(address, pointerSizeBytes) + "_" + sanitiseName(functionName) + ".c";
    }

    /** Zero-pad to pointer width; truncate on overflow so paths stay fixed-width. */
    public static String paddedAddressHex(long address, int pointerSizeBytes) {
        int hexWidth = Math.max(1, pointerSizeBytes) * 2;
        String hex = String.format(Locale.ROOT, "%0" + hexWidth + "x", address);
        if (hex.length() > hexWidth) {
            hex = hex.substring(hex.length() - hexWidth);
        }
        return hex;
    }

    /**
     * Keep {@code [A-Za-z0-9_.-]}; collapse any other run to a single {@code _};
     * truncate to {@link #MAX_SANITISED_NAME_LENGTH}.
     */
    public static String sanitiseName(String name) {
        if (name == null || name.isEmpty()) {
            return "unnamed";
        }
        StringBuilder out = new StringBuilder(name.length());
        boolean lastWasSep = false;
        for (int i = 0; i < name.length(); i++) {
            char c = name.charAt(i);
            if (isSafe(c)) {
                out.append(c);
                lastWasSep = false;
            } else if (!lastWasSep) {
                out.append('_');
                lastWasSep = true;
            }
        }
        String result = out.toString();
        // Trim leading/trailing underscores produced by leading operators etc.
        while (result.startsWith("_")) {
            result = result.substring(1);
        }
        while (result.endsWith("_")) {
            result = result.substring(0, result.length() - 1);
        }
        if (result.isEmpty()) {
            result = "unnamed";
        }
        if (result.length() > MAX_SANITISED_NAME_LENGTH) {
            result = result.substring(0, MAX_SANITISED_NAME_LENGTH);
        }
        return result;
    }

    private static boolean isSafe(char c) {
        return (c >= 'A' && c <= 'Z')
                || (c >= 'a' && c <= 'z')
                || (c >= '0' && c <= '9')
                || c == '_' || c == '.' || c == '-';
    }

    public static String treeJson() {
        return "tree.json";
    }

    public static String statusMd() {
        return "STATUS.md";
    }

    public static String readmeMd() {
        return "README.md";
    }

    public static String modulesIndexMd() {
        return "modules/index.md";
    }

    /** The contract an agent reads first; generated, never shipped in the repo. */
    public static String agentsMd() {
        return "AGENTS.md";
    }

    public static String moduleReadme(String slug) {
        return "modules/" + requireSlug(slug) + "/README.md";
    }

    public static String moduleFunctionFile(String slug, String fileName) {
        return "modules/" + requireSlug(slug) + "/" + requireFileName(fileName);
    }

    public static String byAddressTsv() {
        return "index/by-address.tsv";
    }

    public static String partitionsJson() {
        return "index/partitions.json";
    }

    public static String callgraphTsv() {
        return "callgraph.tsv";
    }

    /** Written by builds before the refs line carried the pool word; a sweep deletes it. */
    public static String legacyAddressesTsv() {
        return "index/addresses.tsv";
    }

    private static final java.util.Set<String> FIXED_FILES = java.util.Set.of(
            treeJson(), statusMd(), readmeMd(), agentsMd(), callgraphTsv(),
            modulesIndexMd(), byAddressTsv(), partitionsJson(), legacyAddressesTsv());

    /**
     * True when {@code relative} (separated by {@code /}) is a path the tree writes, or the
     * {@code .tmp} sibling an interrupted atomic write leaves. A root can hold the caller's own
     * files too, and deleting a tree must not take them with it, so this is the rule for what
     * a delete may remove.
     */
    public static boolean isTreeFile(String relative) {
        String rel = relative.endsWith(".tmp")
                ? relative.substring(0, relative.length() - ".tmp".length())
                : relative;
        if (FIXED_FILES.contains(rel)) {
            return true;
        }
        if (isModuleFile(rel)) {
            return true;
        }
        String[] parts = rel.split("/", -1);
        return parts.length == 3 && parts[0].equals("modules") && isValidSlug(parts[1])
                && parts[2].equals("README.md");
    }

    /**
     * A module slug becomes a directory name, so it is held to the character set function
     * file names already use: no separator, no {@code ..}, nothing a filesystem treats
     * specially ({@code :} on Windows). Generated slugs ({@code c05}, {@code b003}) always
     * pass; this is the gate for pinned ones.
     */
    public static boolean isValidSlug(String slug) {
        if (slug == null || slug.isEmpty() || slug.equals(".") || slug.equals("..")) {
            return false;
        }
        return slug.chars().allMatch(c -> isSafe((char) c));
    }

    /** {@code modules/<slug>/<name>.c}: a compartment file, the only kind the index names. */
    public static boolean isModuleFile(String relative) {
        String[] parts = relative.split("/", -1);
        return parts.length == 3 && parts[0].equals("modules") && isValidSlug(parts[1])
                && parts[2].endsWith(".c") && parts[2].length() > ".c".length()
                && parts[2].chars().allMatch(c -> isSafe((char) c));
    }

    private static String requireSlug(String slug) {
        if (!isValidSlug(slug)) {
            throw new IllegalArgumentException(
                    "module slug must be a plain name of letters, digits, '_', '.' and '-': " + slug);
        }
        return slug;
    }

    private static String requireFileName(String fileName) {
        if (fileName == null || fileName.isBlank()) {
            throw new IllegalArgumentException("file name must not be blank");
        }
        if (fileName.indexOf('/') >= 0 || fileName.indexOf('\\') >= 0) {
            throw new IllegalArgumentException("file name must not contain separators: " + fileName);
        }
        return fileName;
    }
}
