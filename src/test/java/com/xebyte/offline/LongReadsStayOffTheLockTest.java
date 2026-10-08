package com.xebyte.offline;

import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Long script runs must not go through {@code executeRead}/{@code executeWrite}: under the
 * server-wide lock a script can hold every other request for up to its 30-minute timeout,
 * and a script that calls back into the server over HTTP would deadlock against itself.
 *
 * <p>Pinned by source inspection, in the style of {@link WritesTakeTheWriteLockTest}, on
 * {@code runGhidraScript} and on the method that runs the script for it.
 */
public class LongReadsStayOffTheLockTest {

    @Test
    public void runningAScriptDoesNotTakeTheServerLock() throws Exception {
        String src = ProjectSource.readMainSource("core", "ProgramScriptService.java");
        for (String signature : new String[] {
                "public Response runGhidraScript(String scriptPath, String scriptArgs, "
                        + "String programName, int timeoutSeconds)",
                "private ScriptRunOutcome executeGhidraScriptBody("}) {
            String body = methodBody(src, signature);
            assertFalse(signature + " must not call executeRead", body.contains("executeRead("));
            assertFalse(signature + " must not call executeWrite", body.contains("executeWrite("));
        }
    }

    private static String methodBody(String src, String signature) {
        int method = src.indexOf(signature);
        assertTrue(signature + " not found", method >= 0);
        int open = src.indexOf('{', method);
        int depth = 0;
        for (int i = open; i < src.length(); i++) {
            char c = src.charAt(i);
            if (c == '{') {
                depth++;
            } else if (c == '}' && --depth == 0) {
                return src.substring(open, i + 1);
            }
        }
        throw new AssertionError(signature + " has no closing brace");
    }
}
