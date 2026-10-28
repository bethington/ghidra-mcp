package com.xebyte.core;

import com.xebyte.offline.ProjectSource;
import org.junit.Test;

import javax.tools.Diagnostic;
import javax.tools.DiagnosticCollector;
import javax.tools.JavaCompiler;
import javax.tools.JavaFileObject;
import javax.tools.StandardJavaFileManager;
import javax.tools.ToolProvider;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.junit.Assume.assumeTrue;

/**
 * Compiles every Java script under {@code ghidra_scripts/} against the Ghidra installation
 * named by {@code GHIDRA_INSTALL_DIR}.
 *
 * <p>Ghidra compiles a script only when a user runs it, so nothing in the build ever looked at
 * these files. Measured against Ghidra 12.1.4: 9 of 85 shipped scripts did not compile -- API
 * drift ({@code DataTypeManager.getAllDataTypes()} returns an {@code Iterator},
 * {@code ExternalManager.getExternalLibraryNames()} a {@code String[]},
 * {@code DomainFile.getConsumers()} a {@code List<?>},
 * {@code HighFunctionDBUtil.commitParamsToDatabase} gained a {@code ReturnCommitOption} and
 * lost its {@code commitReturnToDatabase} sibling) plus plain Java errors such as
 * {@code Address <= Address} that could never have compiled anywhere. Each one surfaced only
 * as a compile error in the Script Manager when someone tried to use it.
 *
 * <p>The classpath is every jar under {@code $GHIDRA_INSTALL_DIR/Ghidra}, a superset of what
 * the Script Manager puts on a script's classpath, so this test can pass a script Ghidra would
 * still reject only for a module that is installed but not enabled -- never the reverse.
 * Python scripts are out of scope.
 */
public class GhidraScriptsCompileGhidraTest {

    private static String ghidraInstallDir() {
        String dir = System.getenv("GHIDRA_INSTALL_DIR");
        assumeTrue("GHIDRA_INSTALL_DIR is required for real Ghidra tests",
            dir != null && !dir.isBlank());
        return dir;
    }

    @Test
    public void everyJavaScriptCompilesAgainstTheInstalledGhidra() throws Exception {
        String installDir = ghidraInstallDir();

        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        assertNotNull("No system Java compiler -- this test must run on a JDK, not a JRE",
            compiler);

        List<File> classpath = listFiles(Paths.get(installDir, "Ghidra"), ".jar");
        assertFalse("No jars under " + installDir + "/Ghidra -- GHIDRA_INSTALL_DIR does not"
            + " point at a Ghidra installation", classpath.isEmpty());

        Path scriptsDir = ProjectSource.path("ghidra_scripts");
        assertTrue("ghidra_scripts/ not found at " + scriptsDir, Files.isDirectory(scriptsDir));
        List<File> scripts = listFiles(scriptsDir, ".java");
        assertFalse("ghidra_scripts/ contains no Java scripts -- did the directory move?",
            scripts.isEmpty());

        Path outDir = Files.createTempDirectory("ghidra-scripts-compile");
        DiagnosticCollector<JavaFileObject> diagnostics = new DiagnosticCollector<>();
        boolean ok;
        try (StandardJavaFileManager fileManager =
                 compiler.getStandardFileManager(diagnostics, Locale.ROOT, StandardCharsets.UTF_8)) {
            List<String> options = List.of(
                "-classpath", classpath.stream().map(File::getPath)
                    .collect(Collectors.joining(File.pathSeparator)),
                "-d", outDir.toString(),
                "-proc:none",
                "-nowarn",
                "-Xlint:none",
                "-encoding", "UTF-8");
            ok = compiler.getTask(null, fileManager, diagnostics, options, null,
                fileManager.getJavaFileObjectsFromFiles(scripts)).call();
        }
        finally {
            deleteRecursively(outDir);
        }

        // First error per file, keyed by path relative to the repo for a stable, readable list.
        Map<String, String> firstErrorByFile = new TreeMap<>();
        Map<String, Integer> errorCountByFile = new TreeMap<>();
        List<String> unattributed = new ArrayList<>();
        for (Diagnostic<? extends JavaFileObject> d : diagnostics.getDiagnostics()) {
            if (d.getKind() != Diagnostic.Kind.ERROR) {
                continue;
            }
            String message = d.getMessage(Locale.ROOT).lines().findFirst().orElse("");
            if (d.getSource() == null) {
                unattributed.add(message);
                continue;
            }
            String file = relativize(scriptsDir.getParent(), d.getSource().toUri());
            errorCountByFile.merge(file, 1, Integer::sum);
            firstErrorByFile.putIfAbsent(file, file + ":" + d.getLineNumber() + ": " + message);
        }

        if (!ok || !firstErrorByFile.isEmpty() || !unattributed.isEmpty()) {
            StringBuilder report = new StringBuilder();
            report.append(firstErrorByFile.size()).append(" of ").append(scripts.size())
                .append(" ghidra_scripts/ Java file(s) do not compile against ")
                .append(installDir).append(" (first error per file):");
            for (Map.Entry<String, String> e : firstErrorByFile.entrySet()) {
                report.append("\n  ").append(e.getValue());
                int more = errorCountByFile.get(e.getKey()) - 1;
                if (more > 0) {
                    report.append("  (+").append(more).append(" more)");
                }
            }
            for (String message : unattributed) {
                report.append("\n  [no source] ").append(message);
            }
            report.append("\nGhidra compiles a script only when it is run, so these fail in the"
                + " Script Manager for whoever uses them next. Fix the script against this"
                + " Ghidra's API (javap the jar under GHIDRA_INSTALL_DIR/Ghidra) -- do not"
                + " exclude it from this test.");
            fail(report.toString());
        }
    }

    private static List<File> listFiles(Path root, String suffix) throws IOException {
        try (Stream<Path> walk = Files.walk(root)) {
            return walk.filter(Files::isRegularFile)
                .filter(p -> p.getFileName().toString().endsWith(suffix))
                .sorted()
                .map(Path::toFile)
                .collect(Collectors.toList());
        }
    }

    private static String relativize(Path base, java.net.URI source) {
        Path p = Paths.get(source);
        try {
            return base.toAbsolutePath().normalize().relativize(p.toAbsolutePath().normalize())
                .toString().replace('\\', '/');
        }
        catch (IllegalArgumentException e) {
            return p.toString();
        }
    }

    private static void deleteRecursively(Path dir) throws IOException {
        if (!Files.exists(dir)) {
            return;
        }
        try (Stream<Path> walk = Files.walk(dir)) {
            for (Path p : walk.sorted(Comparator.reverseOrder()).collect(Collectors.toList())) {
                Files.deleteIfExists(p);
            }
        }
    }
}
