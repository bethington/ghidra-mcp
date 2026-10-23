package com.xebyte.offline;

import com.xebyte.core.tree.TreeConfig;
import com.xebyte.core.tree.TreeKey;
import com.xebyte.core.tree.TreeRegistry;
import com.xebyte.core.tree.TreeRoot;
import com.xebyte.core.SafePaths;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Offline tests for {@link TreeRoot} — containment, same-basename
 * directory divergence, recreate-and-retry, and cancel-safe atomic writes.
 */
public class TreeRootTest {

    private Path tempBase;

    @Before
    public void setUp() throws IOException {
        tempBase = Files.createTempDirectory("tree-root-test");
    }

    @After
    public void tearDown() throws IOException {
        if (tempBase != null && Files.exists(tempBase)) {
            try (Stream<Path> walk = Files.walk(tempBase)) {
                walk.sorted(Comparator.reverseOrder()).forEach(p -> {
                    try {
                        Files.deleteIfExists(p);
                    } catch (IOException ignored) {
                        // best-effort
                    }
                });
            }
        }
    }

    @Test
    public void sameBasenameDifferentDomainPathsProduceDifferentDirectories() {
        Path parent = TreeRegistry.defaultParent();
        TreeKey vanilla = TreeKey.of("/Vanilla/1.13d/D2Common.dll", parent.toString());
        TreeKey mod = TreeKey.of("/Mods/PD2-S12/D2Common.dll", parent.toString());

        String dirA = vanilla.directoryName("D2Common.dll");
        String dirB = mod.directoryName("D2Common.dll");

        assertTrue(dirA.startsWith("D2Common.dll-"));
        assertTrue(dirB.startsWith("D2Common.dll-"));
        assertNotEquals(
                "domain path must separate same-basename trees",
                dirA, dirB);
        assertNotEquals(vanilla.id(), mod.id());
        assertEquals(8, vanilla.shortHash().length());
        assertTrue(dirA.endsWith(vanilla.shortHash()));
        assertTrue(dirB.endsWith(mod.shortHash()));
    }

    @Test
    public void isWithinRejectsSiblingPrefixCollision() throws IOException {
        Path exports = tempBase.resolve("exports");
        Path evil = tempBase.resolve("exports-evil");
        Files.createDirectories(exports);
        Files.createDirectories(evil);

        assertTrue(SafePaths.isWithin(exports.toFile(), exports.resolve("out.c").toFile()));
        assertFalse(
                "sibling exports-evil must not count as inside exports",
                SafePaths.isWithin(exports.toFile(), evil.resolve("out.c").toFile()));
    }

    @Test
    public void writeRejectsPathEscape() throws IOException {
        Path rootDir = tempBase.resolve("decompTree");
        Files.createDirectories(rootDir);
        TreeRoot root = TreeRoot.ofResolved(rootDir);
        root.ensureExists();
        try {
            root.writeFile(Path.of("..", "escape.c"), "nope");
            fail("expected SecurityException for escaped write");
        } catch (SecurityException expected) {
            assertTrue(expected.getMessage().contains("escapes"));
        }
    }

    @Test
    public void recreateAndRetryWhenRootDeletedMidFlight() throws IOException {
        Path rootDir = tempBase.resolve("vanishing");
        TreeRoot root = TreeRoot.ofResolved(rootDir);
        root.ensureExists();
        root.writeFile(Path.of("STATUS.md"), "dirty\n");
        assertEquals(0, root.rootRecreated());

        // Measured failure mode: the temp tree is deleted under a running process.
        deleteRecursively(rootDir);
        assertFalse(Files.exists(rootDir));

        root.writeFile(Path.of("STATUS.md"), "recovered\n");
        assertTrue(Files.isRegularFile(rootDir.resolve("STATUS.md")));
        assertEquals(1, root.rootRecreated());
        assertEquals("recovered\n", Files.readString(rootDir.resolve("STATUS.md")));
    }

    @Test
    public void successfulWriteLeavesNoTmpBehind() throws IOException {
        Path rootDir = tempBase.resolve("atomic");
        TreeRoot root = TreeRoot.ofResolved(rootDir);
        root.ensureExists();
        root.writeFile(Path.of("modules", "c01", "00001000_Foo.c"), "int Foo(void) { return 0; }\n");

        Path written = rootDir.resolve("modules/c01/00001000_Foo.c");
        assertTrue(Files.isRegularFile(written));
        try (Stream<Path> walk = Files.walk(rootDir)) {
            long tmpCount = walk
                    .filter(p -> p.getFileName().toString().endsWith(".tmp"))
                    .count();
            assertEquals("cancel-safe write must not leave .tmp files", 0, tmpCount);
        }
    }

    @Test
    public void explicitRootRejectsRelativePath() {
        try {
            TreeRoot.explicit("relative/tree");
            fail("relative root must be rejected");
        } catch (IllegalArgumentException expected) {
            assertTrue(expected.getMessage().contains("absolute"));
        }
    }

    @Test
    public void defaultsConfigRoundTripThroughExplicitRoot() throws IOException {
        Path rootDir = tempBase.resolve("explicit-co");
        Files.createDirectories(rootDir);
        TreeRoot root = TreeRoot.explicit(rootDir.toAbsolutePath().toString());
        assertEquals(rootDir.toAbsolutePath().normalize(), root.path());
        TreeConfig cfg = TreeConfig.defaults().withRootPath(root.path().toString());
        assertEquals(root.path().toString(), cfg.rootPath());
    }

    @Test
    public void deleteTreeRemovesWhatTheManifestSaysAndKeepsEverythingElse() throws IOException {
        Path rootDir = tempBase.resolve("shared-root");
        TreeRoot root = TreeRoot.ofResolved(rootDir);
        for (String rel : new String[] {"tree.json", "STATUS.md", "AGENTS.md", "index/by-address.tsv",
                "modules/index.md", "modules/crt/README.md", "modules/crt/00401000_main.c",
                "modules/gone/00402000_f.c"}) {
            root.writeFile(Path.of(rel), "x");
        }
        // Interrupted atomic write sibling of a recorded path — delete removes it too.
        write(rootDir.resolve("modules/crt/00401000_main.c.tmp"));
        for (String rel : new String[] {"notes.md", "modules/crt/notes.txt", "src/main.c"}) {
            write(rootDir.resolve(rel));
        }
        Path outside = tempBase.resolve("outside.c");
        write(outside);
        Files.createSymbolicLink(rootDir.resolve("modules/crt/00404000_h.c"), outside);

        TreeRoot.DeleteResult result = root.deleteTree();

        // 8 recorded + 1 .tmp + 1 manifest
        assertEquals(10, result.filesRemoved());
        assertEquals(java.util.Set.of("notes.md", "modules/crt/notes.txt", "src/main.c",
                "modules/crt/00404000_h.c"), new java.util.HashSet<>(result.kept()));
        assertTrue(Files.exists(rootDir.resolve("notes.md")));
        assertTrue(Files.exists(rootDir.resolve("src/main.c")));
        assertTrue(Files.exists(rootDir.resolve("modules/crt/notes.txt")));
        assertTrue(Files.exists(outside));
        assertFalse(Files.exists(rootDir.resolve("tree.json")));
        assertFalse(Files.exists(rootDir.resolve("index")));
        assertFalse(Files.exists(rootDir.resolve("modules/gone")));
    }

    @Test
    public void deleteTreeRemovesTheRootWhenOnlyTheTreeWasInIt() throws IOException {
        Path rootDir = tempBase.resolve("own-root");
        TreeRoot root = TreeRoot.ofResolved(rootDir);
        root.writeFile(Path.of("tree.json"), "x");
        root.writeFile(Path.of("modules/crt/00401000_main.c"), "x");

        TreeRoot.DeleteResult result = root.deleteTree();

        // 2 recorded + manifest
        assertEquals(3, result.filesRemoved());
        assertTrue(result.kept().isEmpty());
        assertFalse(Files.exists(rootDir));
    }

    @Test
    public void deleteLeavesUserLookalikesTheTreeNeverWrote() throws IOException {
        Path rootDir = tempBase.resolve("lookalike-root");
        TreeRoot root = TreeRoot.ofResolved(rootDir);
        root.writeFile(Path.of("tree.json"), "{}");
        root.writeFile(Path.of("modules/crt/00401000_main.c"), "int main;");
        // Same names the tree uses, planted by the caller — not in the manifest.
        write(rootDir.resolve("README.md"));
        write(rootDir.resolve("modules/crt/README.md"));
        write(rootDir.resolve("modules/crt/00402000_other.c"));

        TreeRoot.DeleteResult result = root.deleteTree();

        assertTrue(Files.exists(rootDir.resolve("README.md")));
        assertTrue(Files.exists(rootDir.resolve("modules/crt/README.md")));
        assertTrue(Files.exists(rootDir.resolve("modules/crt/00402000_other.c")));
        assertFalse(Files.exists(rootDir.resolve("tree.json")));
        assertFalse(Files.exists(rootDir.resolve("modules/crt/00401000_main.c")));
        assertEquals(java.util.Set.of("README.md", "modules/crt/README.md",
                "modules/crt/00402000_other.c"), new java.util.HashSet<>(result.kept()));
    }

    @Test
    public void manifestSurvivesATreeRootReload() throws IOException {
        Path rootDir = tempBase.resolve("manifest-reload");
        TreeRoot first = TreeRoot.ofResolved(rootDir);
        first.writeFile(Path.of("STATUS.md"), "a\n");
        first.writeFile(Path.of("modules/c00/00401000.c"), "int f;");

        TreeRoot second = TreeRoot.ofResolved(rootDir);
        assertTrue(second.deleteFile("STATUS.md"));
        assertFalse(Files.exists(rootDir.resolve("STATUS.md")));
        assertTrue(Files.exists(rootDir.resolve("modules/c00/00401000.c")));

        String manifest = Files.readString(rootDir.resolve("index/manifest.txt"));
        assertFalse(manifest.contains("STATUS.md"));
        assertTrue(manifest.contains("modules/c00/00401000.c"));
    }

    @Test
    public void deleteFileRemovesThePathFromTheManifest() throws IOException {
        Path rootDir = tempBase.resolve("manifest-delete");
        TreeRoot root = TreeRoot.ofResolved(rootDir);
        root.writeFile(Path.of("modules/c00/00401000.c"), "int f;");
        root.writeFile(Path.of("STATUS.md"), "clean\n");
        assertTrue(root.deleteFile("modules/c00/00401000.c"));

        String manifest = Files.readString(rootDir.resolve("index/manifest.txt"));
        assertFalse(manifest.contains("modules/c00/00401000.c"));
        assertTrue(manifest.contains("STATUS.md"));
        assertFalse(root.deleteFile("modules/c00/00401000.c"));
    }

    private static void write(Path file) throws IOException {
        Files.createDirectories(file.getParent());
        Files.writeString(file, "x");
    }

    private static void deleteRecursively(Path dir) throws IOException {
        if (!Files.exists(dir)) {
            return;
        }
        try (Stream<Path> walk = Files.walk(dir)) {
            walk.sorted(Comparator.reverseOrder()).forEach(p -> {
                try {
                    Files.deleteIfExists(p);
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            });
        }
    }

    @Test
    public void aLinkPlantedAtTheTempFileCannotCarryAWriteOutsideTheRoot() throws IOException {
        Path rootDir = tempBase.resolve("tmp-link-root");
        Path outside = tempBase.resolve("victim.txt");
        Files.writeString(outside, "keep");
        Files.createDirectories(rootDir.resolve("modules/c00"));
        Files.createSymbolicLink(rootDir.resolve("modules/c00/00401000_main.c.tmp"), outside);

        TreeRoot.ofResolved(rootDir).writeFile(Path.of("modules/c00/00401000_main.c"), "int f;");

        assertEquals("keep", Files.readString(outside));
        assertEquals("int f;", Files.readString(rootDir.resolve("modules/c00/00401000_main.c")));
        assertFalse(Files.exists(rootDir.resolve("modules/c00/00401000_main.c.tmp"),
                java.nio.file.LinkOption.NOFOLLOW_LINKS));
    }

    @Test
    public void deletesNeverReachThroughALinkedDirectory() throws IOException {
        Path rootDir = tempBase.resolve("linked-root");
        Path source = tempBase.resolve("someones-source");
        write(source.resolve("main.c"));
        write(source.resolve("c00/00401000_main.c"));
        TreeRoot root = TreeRoot.ofResolved(rootDir);
        root.writeFile(Path.of("tree.json"), "x");
        Files.createDirectories(rootDir.resolve("modules"));
        Files.createSymbolicLink(rootDir.resolve("modules/c00"), source);

        assertFalse(root.deleteFile("modules/c00/main.c"));
        assertFalse(root.deleteFile("modules/c00/../../someones-source/main.c"));

        // The whole tree's delete: the link is kept, what it points at is untouched.
        // tree.json + manifest removed; modules/c00 link kept.
        TreeRoot.DeleteResult result = root.deleteTree();
        assertEquals(2, result.filesRemoved());
        assertEquals(List.of("modules/c00"), result.kept());
        assertTrue(Files.exists(source.resolve("main.c")));
        assertTrue(Files.exists(source.resolve("c00/00401000_main.c")));

        // A linked directory ABOVE the module: modules itself points elsewhere.
        Path rootB = tempBase.resolve("linked-modules-root");
        Files.createDirectories(rootB);
        Files.createSymbolicLink(rootB.resolve("modules"), source);
        assertFalse(TreeRoot.ofResolved(rootB).deleteFile("modules/c00/00401000_main.c"));
        assertTrue(Files.exists(source.resolve("c00/00401000_main.c")));
    }

    @Test
    public void deleteFileRemovesOnlyManifestListedPaths() throws IOException {
        Path rootDir = tempBase.resolve("delete-file-root");
        TreeRoot root = TreeRoot.ofResolved(rootDir);
        root.writeFile(Path.of("modules/c00/00401000_main.c"), "x");
        write(rootDir.resolve("modules/c00/notes.txt"));

        assertFalse(root.deleteFile("modules/c00/notes.txt"));
        assertTrue(root.deleteFile("modules/c00/00401000_main.c"));
        assertTrue(Files.exists(rootDir.resolve("modules/c00/notes.txt")));
    }
}
