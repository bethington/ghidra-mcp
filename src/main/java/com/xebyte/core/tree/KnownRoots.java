package com.xebyte.core.tree;

import ghidra.framework.Application;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * The explicit roots trees were created at, so a status scan after a restart finds them.
 *
 * <p>Trees at the default root are found by listing its parent; a tree at a root the caller
 * chose ({@code ~/.cache/ghidra-decomp/lenovosgx}) was invisible to {@code
 * decompile_tree_status} after a restart until someone remembered its path and passed it
 * to {@code create} again. Kept in Ghidra's user settings directory, which outlives the temp
 * directory the default roots sit in and is per instance for the headless services (each has
 * its own settings directory). One absolute path per line.
 */
public final class KnownRoots {

    private static final String FILE_NAME = "ghidra-mcp-tree-roots.txt";

    private final Path file;

    public KnownRoots(Path file) {
        this.file = file;
    }

    /** The instance's default store: the Ghidra user settings directory, else the default parent. */
    static KnownRoots forThisInstance() {
        Path dir = null;
        try {
            if (Application.isInitialized()) {
                dir = Application.getUserSettingsDirectory().toPath();
            }
        } catch (Exception e) {
            dir = null;
        }
        return new KnownRoots((dir != null ? dir : TreeRegistry.defaultParent()).resolve(FILE_NAME));
    }

    /** Remember {@code root}. Best effort: a store that cannot be written loses discoverability, not data. */
    public synchronized void add(Path root) {
        Set<String> roots = read();
        if (roots.add(normal(root))) {
            write(roots);
        }
    }

    public synchronized void remove(Path root) {
        Set<String> roots = read();
        if (roots.remove(normal(root))) {
            write(roots);
        }
    }

    /** The remembered roots that still hold a tree; the rest are forgotten. */
    public synchronized List<Path> list() {
        Set<String> roots = read();
        List<Path> live = new ArrayList<>();
        Set<String> kept = new LinkedHashSet<>();
        for (String r : roots) {
            Path p = Path.of(r);
            if (Files.isRegularFile(p.resolve(TreeLayout.treeJson()))) {
                live.add(p);
                kept.add(r);
            }
        }
        if (kept.size() != roots.size()) {
            write(kept);
        }
        return live;
    }

    private Set<String> read() {
        Set<String> out = new LinkedHashSet<>();
        try {
            if (Files.isRegularFile(file)) {
                for (String line : Files.readAllLines(file, StandardCharsets.UTF_8)) {
                    if (!line.isBlank()) {
                        out.add(line.strip());
                    }
                }
            }
        } catch (IOException e) {
            // unreadable: treat as empty
        }
        return out;
    }

    private void write(Set<String> roots) {
        try {
            Files.createDirectories(file.getParent());
            Files.write(file, roots, StandardCharsets.UTF_8);
        } catch (IOException e) {
            // see add()
        }
    }

    private static String normal(Path p) {
        return p.toAbsolutePath().normalize().toString();
    }
}
