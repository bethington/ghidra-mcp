package com.xebyte.offline;

import com.xebyte.core.tree.DecompTree;
import com.xebyte.core.tree.TreeConfig;
import com.xebyte.core.tree.TreeKey;
import com.xebyte.core.tree.TreeRegistry;
import com.xebyte.core.tree.TreeRoot;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

/**
 * Offline tests for {@link TreeRegistry} — singleton shape, resolve
 * ambiguity, and the single-thread enqueue hook.
 */
public class TreeRegistryTest {

    private Path tempA;
    private Path tempB;

    @Before
    public void setUp() throws IOException {
        TreeRegistry.getInstance().clearForTests();
        tempA = Files.createTempDirectory("tree-reg-a");
        tempB = Files.createTempDirectory("tree-reg-b");
    }

    @After
    public void tearDown() throws IOException {
        TreeRegistry.getInstance().clearForTests();
        deleteRecursively(tempA);
        deleteRecursively(tempB);
    }

    @Test
    public void getInstanceIsStableSingleton() {
        assertSame(TreeRegistry.getInstance(), TreeRegistry.getInstance());
    }

    @Test
    public void resolveAmbiguityNamesBothCandidates() throws IOException {
        TreeRegistry registry = TreeRegistry.getInstance();

        TreeConfig cfgA = TreeConfig.defaults()
                .withRootPath(tempA.toAbsolutePath().toString());
        TreeConfig cfgB = TreeConfig.defaults()
                .withRootPath(tempB.toAbsolutePath().toString());

        DecompTree a = registry.create("/Vanilla/1.13d/D2Common.dll", "D2Common.dll", cfgA);
        DecompTree b = registry.create("/Mods/PD2-S12/D2Common.dll", "D2Common.dll", cfgB);

        assertNotNull(a);
        assertNotNull(b);
        assertFalse(a.id().equals(b.id()));

        TreeRegistry.ResolveResult result = registry.resolve("D2Common.dll");
        assertFalse(result.isOk());
        assertNotNull(result.error());
        assertTrue(
                "ambiguity error must name first candidate id: " + result.error(),
                result.error().contains(a.id()));
        assertTrue(
                "ambiguity error must name second candidate id: " + result.error(),
                result.error().contains(b.id()));
        assertTrue(result.error().contains("/Vanilla/1.13d/D2Common.dll"));
        assertTrue(result.error().contains("/Mods/PD2-S12/D2Common.dll"));
    }

    /**
     * One tree, one identity — regardless of how its root was expressed.
     *
     * <p>Regression: creating with no root and then re-creating from a config that
     * had been persisted with the resolved absolute root minted a SECOND id for the
     * same directory (tree_7de33ad7 and tree_adeb2a7d), each with its own resource URI.
     * A client subscribed to the first would never hear about the tree again.
     */
    @Test
    public void createIsIdempotentHoweverTheDefaultRootIsExpressed() throws IOException {
        TreeRegistry registry = TreeRegistry.getInstance();
        String domain = "/Mods/PD2-S12/D2Common.dll";

        DecompTree first = registry.create(domain, "D2Common.dll", null);
        DecompTree again = registry.create(domain, "D2Common.dll", null);
        assertEquals("repeat create must return the same identity", first.id(), again.id());

        // Now the shape that actually broke: the persisted config carries the
        // resolved absolute root, which used to take the explicit branch.
        TreeConfig persisted =
                TreeConfig.defaults().withRootPath(first.root().path().toString());
        DecompTree adopted = registry.create(domain, "D2Common.dll", persisted);
        assertEquals("explicit default root must key like the default branch",
                first.id(), adopted.id());
        assertEquals("one tree must never hold two registrations", 1, registry.all().size());
    }

    @Test
    public void resolveByIdAndDomainPathIsUnique() throws IOException {
        TreeRegistry registry = TreeRegistry.getInstance();
        DecompTree created = registry.create(
                "/Vanilla/1.13d/D2Common.dll",
                "D2Common.dll",
                TreeConfig.defaults().withRootPath(tempA.toAbsolutePath().toString()));

        TreeRegistry.ResolveResult byId = registry.resolve(created.id());
        assertTrue(byId.isOk());
        assertSame(created, byId.decompTree());

        TreeRegistry.ResolveResult byPath = registry.resolve("/Vanilla/1.13d/D2Common.dll");
        assertTrue(byPath.isOk());
        assertSame(created, byPath.decompTree());
    }

    @Test
    public void createIsIdempotentForSameKey() throws IOException {
        TreeRegistry registry = TreeRegistry.getInstance();
        TreeConfig cfg = TreeConfig.defaults()
                .withRootPath(tempA.toAbsolutePath().toString());
        DecompTree first = registry.create("/proj/app.exe", "app.exe", cfg);
        DecompTree second = registry.create("/proj/app.exe", "app.exe", cfg);
        assertSame(first, second);
        assertEquals(1, registry.all().size());
    }

    @Test
    public void defaultRootsDivergeForSameBasename() throws IOException {
        TreeRegistry registry = TreeRegistry.getInstance();
        DecompTree a = registry.create(
                "/Vanilla/1.13d/D2Common.dll", "D2Common.dll", TreeConfig.defaults());
        DecompTree b = registry.create(
                "/Mods/PD2-S12/D2Common.dll", "D2Common.dll", TreeConfig.defaults());

        assertNotEqualsPaths(a.root().path(), b.root().path());
        assertTrue(a.root().path().getFileName().toString().startsWith("D2Common.dll-"));
        assertTrue(b.root().path().getFileName().toString().startsWith("D2Common.dll-"));

        // Clean default trees created under tmpdir.
        registry.delete(a.id(), true);
        registry.delete(b.id(), true);
    }

    @Test
    public void enqueueRunsOnNamedDaemonThread() throws Exception {
        CountDownLatch done = new CountDownLatch(1);
        AtomicReference<Thread> seen = new AtomicReference<>();
        TreeRegistry.getInstance().enqueue(() -> {
            seen.set(Thread.currentThread());
            done.countDown();
        });
        assertTrue(done.await(5, TimeUnit.SECONDS));
        Thread t = seen.get();
        assertNotNull(t);
        assertEquals("GhidraMCP-DecompTree-Sweep", t.getName());
        assertTrue(t.isDaemon());
        assertEquals(Thread.MIN_PRIORITY, t.getPriority());
    }

    @Test
    public void deleteRemovesRegistration() throws IOException {
        TreeRegistry registry = TreeRegistry.getInstance();
        DecompTree c = registry.create(
                "/x/y.exe",
                "y.exe",
                TreeConfig.defaults().withRootPath(tempA.toAbsolutePath().toString()));
        assertNotNull(registry.delete(c.id(), false));
        assertTrue(registry.byId(c.id()) == null);
        assertFalse(registry.resolve(c.id()).isOk());
    }

    @Test
    public void registerAndKeyDerivation() {
        TreeKey key = TreeKey.of("/a/b.dll", tempA.toAbsolutePath().toString());
        assertTrue(key.id().startsWith("tree_"));
        assertEquals(13, key.id().length()); // tree_ + 8 hex
        TreeRoot root = TreeRoot.ofResolved(tempA);
        DecompTree decompTree = new DecompTree(key, "b.dll", TreeConfig.defaults(), root);
        TreeRegistry.getInstance().register(decompTree);
        assertSame(decompTree, TreeRegistry.getInstance().byId(key.id()));
    }

    private static void assertNotEqualsPaths(Path a, Path b) {
        assertFalse(a.toAbsolutePath().normalize().equals(b.toAbsolutePath().normalize()));
    }

    private static void deleteRecursively(Path dir) throws IOException {
        if (dir == null || !Files.exists(dir)) {
            return;
        }
        try (Stream<Path> walk = Files.walk(dir)) {
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
