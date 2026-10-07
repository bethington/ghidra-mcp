package com.xebyte.offline;

import com.xebyte.core.settings.Scope;
import com.xebyte.core.settings.SettingKey;
import com.xebyte.core.settings.SettingsRegistry;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Locale;
import java.util.stream.Collectors;

import static org.junit.Assert.assertEquals;

/**
 * The tool guide's settings table is generated from the registry, so a key added, retyped or
 * re-scoped there cannot leave the guide describing the old one. Regenerate with
 * {@code mvn test -Dtest=SettingsKeyTableTest -Dregenerate=true}.
 *
 * <p>The table has no environment-variable column on purpose: the guide is read by agents,
 * and a guardrail's override is the operator's (the README's security section names them).
 */
public class SettingsKeyTableTest {

    private static final Path GUIDE = Path.of(System.getProperty("project.basedir", "."))
        .resolve("docs/prompts/TOOL_USAGE_GUIDE.md");
    private static final String START = "<!-- settings-keys:start -->";
    private static final String END = "<!-- settings-keys:end -->";

    static String table() {
        StringBuilder sb = new StringBuilder();
        sb.append("| Key | Kind | Type | Default | Scopes | Meaning |\n");
        sb.append("| --- | --- | --- | --- | --- | --- |\n");
        for (SettingKey k : SettingsRegistry.DEFAULT.keys()) {
            String def = k.kind() == SettingKey.Kind.SECRET ? "hidden"
                : k.defaultRaw().isEmpty() ? "none" : "`" + k.defaultRaw() + "`";
            sb.append("| `").append(k.key()).append("` | ")
                .append(k.kind().name().toLowerCase(Locale.ROOT)).append(" | ")
                .append(k.type().name().toLowerCase(Locale.ROOT)).append(" | ")
                .append(def).append(" | ")
                .append(k.scopes().stream().map(Scope::wireName).collect(Collectors.joining(", "))).append(" | ")
                .append(k.description()).append(" |\n");
        }
        return sb.toString();
    }

    @Test
    public void theGuidesKeyTableMatchesTheRegistry() throws Exception {
        String raw = Files.readString(GUIDE, StandardCharsets.UTF_8);
        String nl = raw.contains("\r\n") ? "\r\n" : "\n";
        String text = raw.replace("\r\n", "\n");
        int start = text.indexOf(START) + START.length();
        int end = text.indexOf(END);
        String expected = "\n" + table();
        String actual = text.substring(start, end);
        if (Boolean.getBoolean("regenerate") && !expected.equals(actual)) {
            String updated = text.substring(0, start) + expected + text.substring(end);
            Files.writeString(GUIDE, updated.replace("\n", nl), StandardCharsets.UTF_8);
            return;
        }
        assertEquals("docs/prompts/TOOL_USAGE_GUIDE.md settings table is stale; regenerate with "
            + "-Dtest=SettingsKeyTableTest -Dregenerate=true", expected, actual);
    }
}
