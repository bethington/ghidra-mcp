package com.xebyte.offline;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Locates this project's own files for the handful of offline tests that
 * assert on source text, and reads them in a form those assertions can rely
 * on.
 *
 * <p>It exists because two independent outside contributors (PRs #447 and
 * #448) both reported {@code HardeningWiringTest} and
 * {@code RunGhidraScriptProgramPropagationTest} failing on a clean checkout
 * and shipped their work without a green suite. Both failures had the same
 * cause, and neither was a real regression:
 *
 * <h2>1. Line endings (the reproducer)</h2>
 *
 * Those tests matched string literals that contained {@code "\n"} against
 * source read verbatim off disk. Java sources here are stored LF, but a clone
 * made with Git for Windows' installer default ({@code core.autocrlf=true})
 * materialises them CRLF, so an {@code indexOf} on an LF literal cannot match
 * and the test fails with a message ("Could not locate 3-arg
 * runGhidraScript") that reads like a real code regression. 93 of this repo's
 * 197 Java files are additionally stored CRLF <em>in the index</em>, so the
 * on-disk line ending of a given source file is not something a test may
 * assume either way. Every read here is therefore normalised to LF.
 *
 * <h2>2. Working directory</h2>
 *
 * The same tests resolved {@code Paths.get("src", "main", ...)} against the
 * JVM's current directory. Maven Surefire and the Gradle {@code Test} task
 * both default their fork's working directory to the project directory, so
 * this did not cause the reported failures — but an IDE run configuration, a
 * custom {@code <workingDirectory>}, or a Gradle {@code workingDir} override
 * does not have to, and the resulting failure looks identical to a code
 * regression. The project root is located from a stable anchor instead.
 *
 * <p>Root resolution tries, in order: an explicitly configured
 * {@code -Dproject.basedir} (the build files pass it); the directory this
 * class was compiled into, walked upward; and finally {@code user.dir},
 * walked upward. Each candidate must actually look like this project
 * ({@code pom.xml} plus {@code src/main/java/com/xebyte}) or it is skipped,
 * so a stale or wrong property cannot break the lookup.
 *
 * <p>The classpath-resource alternative was rejected: serving main sources as
 * test resources means asserting against a <em>copy</em>, and a copy that
 * silently goes stale turns a wiring regression test into a test of its own
 * fixture.
 */
public final class ProjectSource {

    private ProjectSource() {}

    /** Package directory holding all main sources, relative to the root. */
    private static final Path MAIN_PKG =
            Paths.get("src", "main", "java", "com", "xebyte");

    private static volatile Path cachedRoot;

    /**
     * The project root — the directory holding {@code pom.xml}.
     *
     * @throws IllegalStateException if it cannot be located, with the
     *         candidates that were tried.
     */
    public static Path root() {
        Path r = cachedRoot;
        if (r == null) {
            synchronized (ProjectSource.class) {
                r = cachedRoot;
                if (r == null) {
                    r = locateRoot();
                    cachedRoot = r;
                }
            }
        }
        return r;
    }

    /** Resolve a path relative to the project root. */
    public static Path path(String first, String... more) {
        Path p = root().resolve(first);
        for (String s : more) p = p.resolve(s);
        return p;
    }

    /**
     * Read a main source file under {@code src/main/java/com/xebyte}, with
     * line endings normalised to LF.
     *
     * @param parts path segments below the {@code com.xebyte} package, e.g.
     *              {@code read("core", "UdsHttpServer.java")}
     */
    public static String readMainSource(String... parts) throws IOException {
        Path p = root().resolve(MAIN_PKG);
        for (String s : parts) p = p.resolve(s);
        return read(p);
    }

    /** The {@code src/main/java/com/xebyte} directory. */
    public static Path mainSourceRoot() {
        return root().resolve(MAIN_PKG);
    }

    /**
     * Read any project file by its root-relative path (e.g.
     * {@code "tests/endpoints.json"}), with line endings normalised to LF.
     */
    public static String readProjectFile(String relativePath) throws IOException {
        return read(root().resolve(relativePath));
    }

    /** Read a file as UTF-8 with line endings normalised to LF. */
    public static String read(Path p) throws IOException {
        if (!Files.isRegularFile(p)) {
            throw new IOException("Expected project file " + p + " (project root resolved to "
                    + root() + "). If that root is wrong, pass -Dproject.basedir=<repo root>.");
        }
        return normalizeNewlines(new String(Files.readAllBytes(p), StandardCharsets.UTF_8));
    }

    /**
     * Collapse CRLF and lone CR to LF so source assertions can be written
     * against a single line-ending convention regardless of how the checkout
     * was made.
     */
    public static String normalizeNewlines(String s) {
        if (s.indexOf('\r') < 0) return s;
        return s.replace("\r\n", "\n").replace('\r', '\n');
    }

    // ------------------------------------------------------------------
    // root location
    // ------------------------------------------------------------------

    private static Path locateRoot() {
        StringBuilder tried = new StringBuilder();

        // 1. Explicit configuration from the build (pom.xml / build.gradle).
        Path fromProperty = fromSystemProperty(tried);
        if (fromProperty != null) return fromProperty;

        // 2. Where this test class was compiled to — target/test-classes under
        //    Maven, build/classes/java/test under Gradle. Both live inside the
        //    project, and neither depends on the working directory.
        Path fromCode = walkUp(codeSourceDir(), tried);
        if (fromCode != null) return fromCode;

        // 3. Last resort: the working directory, which is what the old
        //    Paths.get("src", ...) calls relied on outright.
        Path fromCwd = walkUp(Paths.get("").toAbsolutePath(), tried);
        if (fromCwd != null) return fromCwd;

        throw new IllegalStateException(
                "Could not locate the ghidra-mcp project root (a directory containing "
                        + "pom.xml and " + MAIN_PKG + "). Tried: " + tried
                        + ". Pass -Dproject.basedir=<repo root> to point the offline "
                        + "source-reading tests at it explicitly.");
    }

    private static Path fromSystemProperty(StringBuilder tried) {
        for (String key : new String[] {"project.basedir", "basedir"}) {
            String v = System.getProperty(key);
            if (v == null || v.trim().isEmpty()) continue;
            Path candidate = Paths.get(v.trim()).toAbsolutePath().normalize();
            tried.append("[-D").append(key).append('=').append(candidate).append("] ");
            if (looksLikeProjectRoot(candidate)) return candidate;
        }
        return null;
    }

    /** Directory this class was loaded from, or null if it cannot be determined. */
    private static Path codeSourceDir() {
        try {
            java.security.CodeSource cs =
                    ProjectSource.class.getProtectionDomain().getCodeSource();
            if (cs == null || cs.getLocation() == null) return null;
            URI uri = cs.getLocation().toURI();
            if (!"file".equalsIgnoreCase(uri.getScheme())) return null;
            Path p = Paths.get(uri);
            return Files.isDirectory(p) ? p : p.getParent();
        } catch (Exception e) {
            return null;
        }
    }

    /** Walk upward from {@code start} looking for a directory that is this project. */
    private static Path walkUp(Path start, StringBuilder tried) {
        if (start == null) return null;
        Path p = start.toAbsolutePath().normalize();
        tried.append("[walk-up from ").append(p).append("] ");
        while (p != null) {
            if (looksLikeProjectRoot(p)) return p;
            p = p.getParent();
        }
        return null;
    }

    /**
     * A candidate is this project only if it has both the Maven descriptor and
     * the main package — {@code pom.xml} alone would also match an unrelated
     * parent project a contributor happened to nest the checkout inside.
     */
    private static boolean looksLikeProjectRoot(Path candidate) {
        return Files.isRegularFile(candidate.resolve("pom.xml"))
                && Files.isDirectory(candidate.resolve(MAIN_PKG));
    }

    /** Convenience for callers that would otherwise wrap every read. */
    public static String readMainSourceUnchecked(String... parts) {
        try {
            return readMainSource(parts);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
