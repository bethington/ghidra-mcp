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
 * A program write goes through {@code threadingStrategy.executeWrite}. On the headless server
 * that is what takes the global write lock; a transaction opened inside
 * {@code executeRead} skips it, so the write is not serialized with any other. Found
 * 2026-10-07 in 21 tools (comments, labels, bookmarks, memory blocks, image base, variable
 * renames and types, prototypes, documentation merge). This catches the direct form, a
 * transaction opened in the lambda itself (13 of those 21); a write reached through a helper
 * method, or opened on the request thread with no lambda at all, still needs a reviewer.
 */
public class WritesTakeTheWriteLockTest {

    private static final List<String> OPENERS = List.of("executeRead(");

    @Test
    public void noTransactionIsOpenedInsideExecuteRead() throws IOException {
        List<String> found = new ArrayList<>();
        try (Stream<Path> files = Files.walk(ProjectSource.mainSourceRoot())) {
            for (Path p : files.filter(f -> f.toString().endsWith(".java")).toList()) {
                String src = ProjectSource.read(p);
                for (String opener : OPENERS) {
                    int at = -1;
                    while ((at = src.indexOf(opener, at + 1)) >= 0) {
                        String arg = balanced(src, at + opener.length() - 1);
                        if (arg.contains("WriteTx.begin(") || arg.contains(".startTransaction(")) {
                            int line = (int) src.substring(0, at).chars().filter(c -> c == '\n').count() + 1;
                            found.add(p.getFileName() + ":" + line + " " + opener);
                        }
                    }
                }
            }
        }
        assertEquals("open the transaction with threadingStrategy.executeWrite instead", List.of(), found);
    }

    /** The text inside the parentheses that open at {@code open}. */
    private static String balanced(String src, int open) {
        int depth = 0;
        for (int i = open; i < src.length(); i++) {
            char c = src.charAt(i);
            if (c == '(') {
                depth++;
            } else if (c == ')' && --depth == 0) {
                return src.substring(open + 1, i);
            }
        }
        return src.substring(open + 1);
    }
}
