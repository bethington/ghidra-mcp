package com.xebyte.offline;

import com.xebyte.core.tree.TreeLayout;
import com.xebyte.core.tree.KnownRoots;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.List;

import static org.junit.Assert.*;

/**
 * Found live: after a server restart, decompile_tree_status listed nothing for a tree at
 * a custom root, because the scan looked only under the default root.
 */
public class KnownRootsTest {

    private Path dir;
    private KnownRoots roots;

    @Before
    public void setUp() throws IOException {
        dir = Files.createTempDirectory("known-roots");
        roots = new KnownRoots(dir.resolve("settings").resolve("roots.txt"));
    }

    @After
    public void tearDown() throws IOException {
        try (var walk = Files.walk(dir)) {
            walk.sorted(Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
        }
    }

    private Path tree(String name) throws IOException {
        Path root = dir.resolve(name);
        Files.createDirectories(root);
        Files.writeString(root.resolve(TreeLayout.treeJson()), "{}");
        return root;
    }

    @Test
    public void aRememberedRootIsListedOnceAndAcrossInstances() throws IOException {
        Path lenovo = tree("lenovosgx");
        roots.add(lenovo);
        roots.add(lenovo);
        assertEquals(List.of(lenovo.toAbsolutePath().normalize()),
            new KnownRoots(dir.resolve("settings").resolve("roots.txt")).list());
    }

    @Test
    public void aRootWhoseTreeIsGoneIsForgotten() throws IOException {
        Path kept = tree("kept");
        Path gone = tree("gone");
        roots.add(kept);
        roots.add(gone);
        Files.delete(gone.resolve(TreeLayout.treeJson()));

        assertEquals(List.of(kept.toAbsolutePath().normalize()), roots.list());
        assertEquals("pruned on disk too", 1,
            Files.readAllLines(dir.resolve("settings").resolve("roots.txt")).size());
    }

    @Test
    public void aDeletedDecompTreesRootIsRemoved() throws IOException {
        Path a = tree("a");
        roots.add(a);
        roots.remove(a);
        assertTrue(roots.list().isEmpty());
    }
}
