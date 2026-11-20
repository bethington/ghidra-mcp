package com.xebyte.offline;

import com.xebyte.core.ProjectPaths;
import com.xebyte.core.Refusal;
import org.junit.Test;

import static org.junit.Assert.*;

/** Offline coverage for {@link ProjectPaths#normalize}, {@link ProjectPaths#parentOf},
 *  {@link ProjectPaths#nameOf}. File/folder/scope need a real project — see
 *  {@code ProjectPathsGhidraTest}. */
public class ProjectPathsTest {

    @Test
    public void normalizeAddsLeadingSlashAndCollapsesSlashes() {
        assertEquals("/a/b", ProjectPaths.normalize("a/b"));
        assertEquals("/a/b", ProjectPaths.normalize("/a/b"));
        assertEquals("/a/b", ProjectPaths.normalize("//a//b/"));
        assertEquals("/a/b", ProjectPaths.normalize("  /a/b/  "));
        assertEquals("/", ProjectPaths.normalize("/"));
        assertEquals("/", ProjectPaths.normalize("///"));
    }

    @Test
    public void normalizeKeepsBackslashAsPartOfAName() {
        // Domain paths use '/' only; '\\' is a literal character in one segment.
        assertEquals("/a\\b", ProjectPaths.normalize("a\\b"));
        assertEquals("/a\\b", ProjectPaths.normalize("/a\\b"));
    }

    @Test
    public void normalizeRejectsDotAndDotDotSegments() {
        assertRefusal("..", "..");
        assertRefusal("/a/../b", "/a/../b");
        assertRefusal(".", ".");
        assertRefusal("/a/./b", "/a/./b");
        assertRefusal("a/../b", "a/../b");
    }

    @Test
    public void normalizeRejectsBlank() {
        try {
            ProjectPaths.normalize("  ");
            fail("expected Refusal");
        } catch (Refusal r) {
            assertEquals("path is required", r.getMessage());
        }
        try {
            ProjectPaths.normalize(null);
            fail("expected Refusal");
        } catch (Refusal r) {
            assertEquals("path is required", r.getMessage());
        }
    }

    @Test
    public void parentOfAndNameOfOnNormalizedPaths() {
        assertEquals("/a", ProjectPaths.parentOf("/a/b"));
        assertEquals("b", ProjectPaths.nameOf("/a/b"));
        assertEquals("/", ProjectPaths.parentOf("/a"));
        assertEquals("a", ProjectPaths.nameOf("/a"));
        assertEquals("/", ProjectPaths.parentOf("/"));
        assertEquals("", ProjectPaths.nameOf("/"));
    }

    private static void assertRefusal(String input, String namedInMessage) {
        try {
            ProjectPaths.normalize(input);
            fail("expected Refusal for " + input);
        } catch (Refusal r) {
            assertTrue(r.getMessage(), r.getMessage().contains(namedInMessage));
            assertTrue(r.getMessage(), r.getMessage().startsWith("Invalid project path:"));
        }
    }
}
