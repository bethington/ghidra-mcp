package com.xebyte.offline;

import junit.framework.TestCase;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Guards the guard: {@link ProjectSource} is what stops the offline
 * source-reading tests from failing on somebody else's machine, so its two
 * properties are pinned here, plus a meta-check that no test drifts back to
 * the working-directory-relative form.
 *
 * <p>Context: {@code HardeningWiringTest} and
 * {@code RunGhidraScriptProgramPropagationTest} both failed on a clean
 * checkout for two separate outside contributors (#447, #448). Neither was a
 * real regression — the tests matched literals containing {@code "\n"} against
 * source that a default Git-for-Windows clone materialises with CRLF.
 */
public class ProjectSourceTest extends TestCase {

    // ------------------------------------------------------------------
    // Line endings
    // ------------------------------------------------------------------

    public void testNormalizeCollapsesCrlfAndLoneCr() {
        assertEquals("a\nb\nc", ProjectSource.normalizeNewlines("a\r\nb\rc"));
        assertEquals("no newlines", ProjectSource.normalizeNewlines("no newlines"));
        assertEquals("already\nlf", ProjectSource.normalizeNewlines("already\nlf"));
        // Idempotent, so double-normalising a string is harmless.
        String once = ProjectSource.normalizeNewlines("x\r\ny");
        assertEquals(once, ProjectSource.normalizeNewlines(once));
    }

    /**
     * The reproducer in miniature: a source file written to disk with CRLF —
     * exactly what {@code core.autocrlf=true} produces — must read back
     * matchable against an LF literal.
     */
    public void testReadNormalizesACrlfFileOnDisk() throws IOException {
        Path tmp = Files.createTempFile("project-source-crlf", ".java");
        try {
            String crlf = "public Response runGhidraScript(\r\n"
                    + "            @Param(value = \"script_path\") String p) {\r\n}\r\n";
            Files.write(tmp, crlf.getBytes(StandardCharsets.UTF_8));

            String raw = new String(Files.readAllBytes(tmp), StandardCharsets.UTF_8);
            assertTrue("fixture must actually be CRLF on disk", raw.contains("\r\n"));
            assertEquals("an LF literal cannot match CRLF source — this is the bug",
                    -1, raw.indexOf("public Response runGhidraScript(\n"));

            String read = ProjectSource.read(tmp);
            assertEquals("ProjectSource.read must strip CR entirely", -1, read.indexOf('\r'));
            assertTrue("and the LF literal must then match",
                    read.contains("public Response runGhidraScript(\n"));
        } finally {
            Files.deleteIfExists(tmp);
        }
    }

    public void testMainSourceReadsAreNormalized() throws IOException {
        String src = ProjectSource.readMainSource("core", "ProgramScriptService.java");
        assertTrue("expected a non-trivial source file", src.length() > 1000);
        assertEquals("main sources must reach assertions LF-only", -1, src.indexOf('\r'));
    }

    // ------------------------------------------------------------------
    // Root anchoring
    // ------------------------------------------------------------------

    /**
     * The root must be found from a stable anchor, not the working directory.
     * Asserting it is an ancestor of the directory this test class was
     * compiled into is what proves the anchor is the build output
     * ({@code target/test-classes} or {@code build/classes/java/test}) rather
     * than {@code user.dir}, which a run configuration is free to change.
     */
    public void testRootIsAnchoredOnTheBuildOutputNotTheWorkingDirectory() {
        Path root = ProjectSource.root();
        assertTrue("root must be absolute", root.isAbsolute());
        assertTrue("root must hold pom.xml", Files.isRegularFile(root.resolve("pom.xml")));
        assertTrue("root must hold the main package",
                Files.isDirectory(ProjectSource.mainSourceRoot()));

        Path here = classesDir();
        assertNotNull("could not locate this test's own class directory", here);
        assertTrue("the project root must be an ancestor of the compiled test classes ("
                        + here + "), which is what makes it independent of user.dir",
                here.toAbsolutePath().normalize().startsWith(root));
    }

    public void testReadOfAMissingFileNamesTheResolvedRoot() {
        try {
            ProjectSource.readProjectFile("no/such/file/anywhere.txt");
            fail("expected an IOException");
        } catch (IOException e) {
            assertTrue("the error must name the resolved root so a wrong root is "
                            + "diagnosable — got: " + e.getMessage(),
                    e.getMessage().contains(ProjectSource.root().toString()));
            assertTrue("and must name the override — got: " + e.getMessage(),
                    e.getMessage().contains("project.basedir"));
        }
    }

    private static Path classesDir() {
        try {
            java.security.CodeSource cs =
                    ProjectSourceTest.class.getProtectionDomain().getCodeSource();
            if (cs == null || cs.getLocation() == null) return null;
            Path p = java.nio.file.Paths.get(cs.getLocation().toURI());
            return Files.isDirectory(p) ? p : p.getParent();
        } catch (Exception e) {
            return null;
        }
    }

    // ------------------------------------------------------------------
    // Meta-check
    // ------------------------------------------------------------------

    /**
     * No test may resolve a project file against the working directory. That
     * idiom is what made two tests look broken to outside contributors, and it
     * fails in a way ("Could not locate ...") that reads like a code
     * regression rather than an environment difference.
     */
    public void testNoTestResolvesProjectFilesAgainstTheWorkingDirectory() throws IOException {
        // Paths.get("src"...) / Paths.get("tests/...") / new File("src/...")
        // — anything anchoring a repo-relative path on the JVM's cwd.
        Pattern cwdRelative = Pattern.compile(
                "(?:Paths\\.get|new\\s+File)\\s*\\(\\s*\"(?:src|tests|docs|python|tools)[/\"]");

        Path testRoot = ProjectSource.path("src", "test", "java");
        List<String> offenders = new ArrayList<>();
        try (java.util.stream.Stream<Path> paths = Files.walk(testRoot)) {
            for (Path p : (Iterable<Path>) paths
                    .filter(f -> f.toString().endsWith(".java"))
                    .filter(f -> !f.getFileName().toString().equals("ProjectSource.java"))
                    .filter(f -> !f.getFileName().toString().equals("ProjectSourceTest.java"))
                    ::iterator) {
                if (cwdRelative.matcher(ProjectSource.read(p)).find()) {
                    offenders.add(ProjectSource.root().relativize(p).toString());
                }
            }
        }

        if (!offenders.isEmpty()) {
            java.util.Collections.sort(offenders);
            fail("These tests resolve repo paths against the working directory, which "
                    + "breaks under any runner that does not set it to the project dir "
                    + "(IDE run configurations, a custom surefire <workingDirectory>, a "
                    + "Gradle workingDir override). Read through ProjectSource instead — "
                    + "it anchors on the project root and normalises line endings:\n  - "
                    + String.join("\n  - ", offenders));
        }
    }
}
