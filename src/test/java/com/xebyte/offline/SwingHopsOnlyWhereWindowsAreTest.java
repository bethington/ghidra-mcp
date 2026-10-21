package com.xebyte.offline;

import org.junit.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static org.junit.Assert.assertEquals;

/**
 * Tool bodies run on the request thread. Only code that drives windows may hop to the
 * Swing thread: work sent there runs outside the server lock, and a long one freezes the
 * GUI. {@code batchAnalyzeCompleteness} queued a decompile per function on it with
 * {@code invokeLater}, long after {@code runOnUi} was gone; this keeps the next one out.
 */
public class SwingHopsOnlyWhereWindowsAreTest {

    /** Classes that drive windows, prompts or tool state, and the doc that names the call. */
    private static final Set<String> ALLOWED = Set.of(
            "GuiToolService.java", "DebuggerService.java", "PromptPolicyService.java",
            "Workbench.java", "ThreadingStrategy.java");

    private static final Pattern HOP = Pattern.compile(
            "SwingUtilities\\.invoke(Later|AndWait)|\\bSwing\\.run(Now|Later)");

    @Test
    public void onlyWindowDrivingClassesHopToTheSwingThread() throws IOException {
        Path core = ProjectSource.mainSourceRoot().resolve("core");
        List<String> offenders;
        try (Stream<Path> files = Files.walk(core)) {
            offenders = files.filter(p -> p.toString().endsWith(".java"))
                    .filter(p -> !ALLOWED.contains(p.getFileName().toString()))
                    .filter(p -> {
                        try {
                            return HOP.matcher(ProjectSource.read(p)).find();
                        } catch (IOException e) {
                            throw new java.io.UncheckedIOException(e);
                        }
                    })
                    .map(p -> core.relativize(p).toString())
                    .sorted()
                    .toList();
        }
        assertEquals("services run on the request thread; move the work there", List.of(), offenders);
    }
}
