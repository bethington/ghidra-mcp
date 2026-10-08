package com.xebyte.core.tree;

import com.xebyte.core.SecurityConfig;
import com.xebyte.core.SafePaths;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.DirectoryStream;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Resolved tree root plus safe, recreate-tolerant writing.
 *
 * <p>Default roots live under {@code java.io.tmpdir/ghidra-mcp-tree/},
 * deliberately <em>not</em> {@code Application.getUserTempDirectory()} —
 * Ghidra caches a handle to a directory that can be deleted out from under a
 * running process (measured), after which imports fail with a misleading
 * "No such file or directory". Every write therefore
 * {@link Files#createDirectories} first; if the root has vanished since it was
 * established, {@link #rootRecreated()} increments so silent healing is
 * visible. A {@link NoSuchFileException} mid-write recreates once and retries.
 */
public final class TreeRoot {

    private final Path root;
    private int rootRecreated;
    /** True after the first successful ensure/write — distinguishes create from recreate. */
    private boolean established;

    private TreeRoot(Path root) {
        this.root = root.toAbsolutePath().normalize();
    }

    /**
     * Explicit caller-supplied root. Routed through
     * {@link SecurityConfig#resolveWithinFileRoot(String)}; when
     * {@code GHIDRA_MCP_FILE_ROOT} is unset that returns the path unconstrained,
     * so we also require the input to be absolute (relative roots silently
     * binding to cwd are never what an agent meant).
     *
     * @throws IllegalArgumentException when the path is rejected
     */
    public static TreeRoot explicit(String path) {
        Objects.requireNonNull(path, "path");
        String trimmed = path.trim();
        if (trimmed.isEmpty()) {
            throw new IllegalArgumentException("tree root must not be blank");
        }
        Path input = Path.of(trimmed);
        if (!input.isAbsolute()) {
            // Unconditional, not merely a stand-in for an unset allow-list: a
            // relative root binds to the server process's cwd, which is never
            // where the caller meant and is not visible to them.
            throw new IllegalArgumentException(
                    "tree root must be an absolute path: " + trimmed);
        }
        Path resolved = SecurityConfig.getInstance().resolveWithinFileRoot(trimmed);
        if (resolved == null) {
            throw new IllegalArgumentException(
                    "tree root escapes GHIDRA_MCP_FILE_ROOT: " + trimmed);
        }
        return new TreeRoot(resolved);
    }

    /**
     * Default root: {@code ${java.io.tmpdir}/ghidra-mcp-tree/<dirName>}.
     */
    public static TreeRoot defaultRoot(String dirName) {
        Objects.requireNonNull(dirName, "dirName");
        if (dirName.isBlank() || dirName.contains("/") || dirName.contains("\\")
                || dirName.contains("..")) {
            throw new IllegalArgumentException("invalid tree directory name: " + dirName);
        }
        Path root = Path.of(System.getProperty("java.io.tmpdir"), "ghidra-mcp-tree", dirName);
        return new TreeRoot(root);
    }

    /** Already-resolved absolute root (tests and registry default-path wiring). */
    public static TreeRoot ofResolved(Path root) {
        return new TreeRoot(root);
    }

    public Path path() {
        return root;
    }

    /** Times this root was recreated after vanishing mid-write. */
    public synchronized int rootRecreated() {
        return rootRecreated;
    }

    public void writeFile(Path relative, String content) throws IOException {
        writeFile(relative, content.getBytes(StandardCharsets.UTF_8));
    }

    public void writeFile(Path relative, byte[] content) throws IOException {
        Objects.requireNonNull(relative, "relative");
        Objects.requireNonNull(content, "content");
        if (relative.isAbsolute()) {
            throw new IllegalArgumentException("relative path must not be absolute: " + relative);
        }
        try {
            writeFileOnce(relative, content);
        } catch (NoSuchFileException first) {
            // TOCTOU: directory vanished between createDirectories and write.
            recreateRoot();
            try {
                writeFileOnce(relative, content);
            } catch (NoSuchFileException second) {
                throw new IOException(
                        "tree root vanished and recreate failed: " + root, second);
            }
        }
    }

    private void writeFileOnce(Path relative, byte[] content) throws IOException {
        Path target = root.resolve(relative).normalize();
        if (!SafePaths.isWithin(root.toFile(), target.toFile())) {
            throw new SecurityException(
                    "tree write escapes root: " + relative + " (root=" + root + ")");
        }
        ensureParentForWrite(target);
        // Re-check after createDirectories: a symlink race could have moved us.
        if (!SafePaths.isWithin(root.toFile(), target.toFile())) {
            throw new SecurityException(
                    "tree write escapes root after createDirectories: " + relative);
        }
        Path tmp = target.resolveSibling(target.getFileName().toString() + ".tmp");
        try {
            // The containment check covered target, not tmp: a link planted at tmp would carry
            // a plain write outside the root. Removing it and creating exclusively cannot follow one.
            Files.deleteIfExists(tmp);
            Files.write(tmp, content, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
            try {
                Files.move(tmp, target,
                        StandardCopyOption.REPLACE_EXISTING,
                        StandardCopyOption.ATOMIC_MOVE);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING);
            }
        } catch (IOException e) {
            try {
                Files.deleteIfExists(tmp);
            } catch (IOException ignored) {
                // Best-effort cleanup; the original failure is what matters.
            }
            throw e;
        }
    }

    private void ensureParentForWrite(Path target) throws IOException {
        synchronized (this) {
            if (established && !Files.isDirectory(root)) {
                rootRecreated++;
            }
        }
        Path parent = target.getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        } else {
            Files.createDirectories(root);
        }
        synchronized (this) {
            established = true;
        }
    }

    private synchronized void recreateRoot() throws IOException {
        Files.createDirectories(root);
        rootRecreated++;
        established = true;
    }

    /** Ensure the root directory exists (e.g. before first status write). */
    public void ensureExists() throws IOException {
        Files.createDirectories(root);
        synchronized (this) {
            established = true;
        }
    }

    /**
     * Delete the files the tree wrote ({@link TreeLayout#isTreeFile}), then every directory
     * that leaves empty, the root included. Anything else under the root stays, with the
     * directories holding it: a root may be a directory the caller also keeps their own
     * files in, and {@code delete_files} is not a request to delete those.
     * Used by {@code /decompile_tree_delete?delete_files=true}.
     */
    public DeleteResult deleteTree() throws IOException {
        return deleteTreeFiles(root, root);
    }

    /** What {@link #deleteTree} removed and what it left in place. */
    public record DeleteResult(int filesRemoved, List<String> kept) {}

    /**
     * Delete one file the tree wrote ({@link TreeLayout#isTreeFile}), if it is a regular file
     * really under the root. A path that is not the tree's, a link, or one that reaches the
     * root through a linked directory is left alone. The one way the tree deletes a file.
     *
     * @return true when the file was deleted
     */
    public boolean deleteFile(String relative) throws IOException {
        if (!TreeLayout.isTreeFile(relative)) {
            return false;
        }
        Path file = root.resolve(relative).normalize();
        if (!Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)
                || !SafePaths.isWithin(root.toFile(), file.getParent().toFile())) {
            return false;
        }
        return Files.deleteIfExists(file);
    }

    /** {@link #deleteTree}'s rule applied to {@code start}, a directory under {@code root}. */
    static DeleteResult deleteTreeFiles(Path root, Path start) throws IOException {
        // NOFOLLOW sees a linked start; the canonical check sees a linked directory above it.
        if (!Files.isDirectory(start, LinkOption.NOFOLLOW_LINKS)
                || !SafePaths.isWithin(root.toFile(), start.toFile())) {
            return new DeleteResult(0, List.of());
        }
        int[] removed = {0};
        List<String> kept = new ArrayList<>();
        Files.walkFileTree(start, new SimpleFileVisitor<>() {
            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attrs)
                    throws IOException {
                String rel = root.relativize(file).toString().replace('\\', '/');
                // The tree writes regular files only; a link is the caller's, whatever its name.
                if (attrs.isRegularFile() && TreeLayout.isTreeFile(rel)) {
                    Files.delete(file);
                    removed[0]++;
                } else {
                    kept.add(rel);
                }
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult postVisitDirectory(Path dir, IOException exc)
                    throws IOException {
                if (exc != null) {
                    throw exc;
                }
                try (DirectoryStream<Path> entries = Files.newDirectoryStream(dir)) {
                    if (!entries.iterator().hasNext()) {
                        Files.delete(dir);
                    }
                }
                return FileVisitResult.CONTINUE;
            }
        });
        return new DeleteResult(removed[0], List.copyOf(kept));
    }
}
