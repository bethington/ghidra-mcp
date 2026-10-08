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
    public void deleteTreeRemovesWhatTheTreeWroteAndKeepsEverythingElse() throws IOException {
        Path rootDir = tempBase.resolve("shared-root");
        for (String rel : new String[] {"tree.json", "STATUS.md", "AGENTS.md", "index/by-address.tsv",
                "modules/index.md", "modules/crt/README.md", "modules/crt/00401000_main.c",
                "modules/gone/00402000_f.c", "modules/crt/00403000_g.c.tmp"}) {
            write(rootDir.resolve(rel));
        }
        for (String rel : new String[] {"notes.md", "modules/crt/notes.txt", "src/main.c"}) {
            write(rootDir.resolve(rel));
        }
        Path outside = tempBase.resolve("outside.c");
        write(outside);
        Files.createSymbolicLink(rootDir.resolve("modules/crt/00404000_h.c"), outside);

        TreeRoot.DeleteResult result = TreeRoot.ofResolved(rootDir).deleteTree();

        assertEquals(9, result.filesRemoved());
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
        write(rootDir.resolve("tree.json"));
        write(rootDir.resolve("modules/crt/00401000_main.c"));

        TreeRoot.DeleteResult result = TreeRoot.ofResolved(rootDir).deleteTree();

        assertEquals(2, result.filesRemoved());
        assertTrue(result.kept().isEmpty());
        assertFalse(Files.exists(rootDir));
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
        write(rootDir.resolve("tree.json"));
        Files.createDirectories(rootDir.resolve("modules"));
        Files.createSymbolicLink(rootDir.resolve("modules/c00"), source);
        TreeRoot root = TreeRoot.ofResolved(rootDir);

        assertFalse(root.deleteFile("modules/c00/main.c"));
        assertFalse(root.deleteFile("modules/c00/../../someones-source/main.c"));

        // The whole tree's delete: the link is kept, what it points at is untouched.
        TreeRoot.DeleteResult result = root.deleteTree();
        assertEquals(1, result.filesRemoved());
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
    public void deleteFileRemovesOnlyTreeFiles() throws IOException {
        Path rootDir = tempBase.resolve("delete-file-root");
        write(rootDir.resolve("modules/c00/00401000_main.c"));
        write(rootDir.resolve("modules/c00/notes.txt"));
        TreeRoot root = TreeRoot.ofResolved(rootDir);

        assertFalse(root.deleteFile("modules/c00/notes.txt"));
        assertTrue(root.deleteFile("modules/c00/00401000_main.c"));
        assertTrue(Files.exists(rootDir.resolve("modules/c00/notes.txt")));
    }
}
