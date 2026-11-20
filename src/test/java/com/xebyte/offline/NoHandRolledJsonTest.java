package com.xebyte.offline;

import org.junit.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.Assert.assertEquals;

/**
 * JSON must be produced and parsed with Gson via {@code JsonHelper} / {@code Response},
 * never by string concatenation or hand-rolled escaping. This walks
 * {@code src/main/java} the same way {@link WritesTakeTheWriteLockTest} does.
 *
 * <p>What it flags (no allow-list):
 * <ul>
 *   <li>{@code escapeJson} / {@code escapeJsonString} / {@code serializeListToJson} /
 *       {@code serializeMapToJson} — the deleted hand serializers</li>
 *   <li>source substring quote-brace-backslash-quote — the usual start of a
 *       hand-built JSON object string literal such as return "{\"error\": ...}</li>
 *   <li>{@code append("\\":")} — the StringBuilder key separator from the old
 *       map/list serializers</li>
 * </ul>
 *
 * <p>Prose in {@code @Param} descriptions that illustrates a JSON shape (e.g. a
 * {@code "NAME": 0} example) is not construction: those lines contain a bare
 * {@code \":} sequence but not the three patterns above, so they stay.
 */
public class NoHandRolledJsonTest {

    private static final List<String> FORBIDDEN_IDENTIFIERS = List.of(
            "escapeJson",
            "escapeJsonString",
            "serializeListToJson",
            "serializeMapToJson"
    );

    /** The old serializeMapToJson key separator, as it appears in Java source. */
    private static final String APPEND_JSON_KEY = ".append(\"\\\":\")";

    @Test
    public void noHandRolledJsonInMainSources() throws IOException {
        List<String> found = new ArrayList<>();
        try (Stream<Path> files = Files.walk(ProjectSource.mainSourceRoot())) {
            for (Path p : files.filter(f -> f.toString().endsWith(".java")).toList()) {
                String src = ProjectSource.read(p);
                String[] lines = src.split("\n", -1);
                for (int i = 0; i < lines.length; i++) {
                    String line = lines[i];
                    int lineNo = i + 1;
                    for (String id : FORBIDDEN_IDENTIFIERS) {
                        if (containsIdentifier(line, id)) {
                            found.add(p.getFileName() + ":" + lineNo + " " + id);
                        }
                    }
                    if (containsQuoteBraceEscQuote(line)) {
                        found.add(p.getFileName() + ":" + lineNo + " hand-built-{\" ");
                    }
                    if (line.contains(APPEND_JSON_KEY)) {
                        found.add(p.getFileName() + ":" + lineNo + " append-json-key");
                    }
                }
            }
        }
        assertEquals("use JsonHelper.toJson / Response / JsonHelper.parseJson instead",
                List.of(), found);
    }

    /** True when {@code id} appears as a Java identifier, not as a substring of a longer word. */
    static boolean containsIdentifier(String line, String id) {
        int at = -1;
        while ((at = line.indexOf(id, at + 1)) >= 0) {
            char before = at == 0 ? '\0' : line.charAt(at - 1);
            char after = at + id.length() >= line.length() ? '\0' : line.charAt(at + id.length());
            if (!Character.isJavaIdentifierPart(before) && !Character.isJavaIdentifierPart(after)) {
                return true;
            }
        }
        return false;
    }

    /** Source contains the four characters quote, brace, backslash, quote. */
    static boolean containsQuoteBraceEscQuote(String line) {
        for (int i = 0; i + 3 < line.length(); i++) {
            if (line.charAt(i) == '"'
                    && line.charAt(i + 1) == '{'
                    && line.charAt(i + 2) == '\\'
                    && line.charAt(i + 3) == '"') {
                return true;
            }
        }
        return false;
    }
}
