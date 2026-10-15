package com.xebyte.offline;

import com.xebyte.core.tree.TreeLayout;
import org.junit.Test;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Offline tests for {@link TreeLayout} filename padding and sanitisation.
 */
public class TreeLayoutTest {

    @Test
    public void compartmentFileNamePaddingGivesLexicalOrderEqualToAddressOrder() {
        int pointerSize = 4;
        long[] addresses = {0x10L, 0x100L, 0x1000L, 0xffffL, 0x10000L, 0x6fdd1234L};
        List<String> names = new ArrayList<>();
        for (long addr : addresses) {
            names.add(TreeLayout.compartmentFileName(addr, pointerSize));
        }
        List<String> sorted = new ArrayList<>(names);
        Collections.sort(sorted);
        assertEquals(
                "zero-padded hex must make lexical order match address order",
                names, sorted);
        assertEquals("00000010.c", names.get(0));
        assertEquals("6fdd1234.c", names.get(5));
        // No function name — the file holds several functions.
        assertFalse(names.get(0).contains("_"));
    }

    @Test
    public void compartmentFileNameFor64BitPointers() {
        assertEquals(
                "0000000180001000.c",
                TreeLayout.compartmentFileName(0x180001000L, 8));
    }

    @Test
    public void filenamePaddingGivesLexicalOrderEqualToAddressOrder() {
        int pointerSize = 4; // 8 hex chars
        long[] addresses = {0x10L, 0x100L, 0x1000L, 0xffffL, 0x10000L, 0x6fdd1234L};
        List<String> names = new ArrayList<>();
        for (long addr : addresses) {
            names.add(TreeLayout.functionFileName(addr, "Fn", pointerSize));
        }
        List<String> sorted = new ArrayList<>(names);
        Collections.sort(sorted);
        assertEquals(
                "zero-padded hex must make lexical order match address order",
                names, sorted);

        assertEquals("00000010_Fn.c", names.get(0));
        assertEquals("00000100_Fn.c", names.get(1));
        assertEquals("6fdd1234_Fn.c", names.get(5));
    }

    @Test
    public void filenamePaddingFor64BitPointers() {
        String name = TreeLayout.functionFileName(0x180001000L, "ParseHeader", 8);
        assertEquals("0000000180001000_ParseHeader.c", name);
    }

    @Test
    public void sanitisesCppOperatorAndTemplateNames() {
        assertEquals("operator", TreeLayout.sanitiseName("operator<<"));
        assertEquals(
                "std_vector_int_push_back",
                TreeLayout.sanitiseName("std::vector<int>::push_back"));
        assertEquals(
                "MyClass_operator",
                TreeLayout.sanitiseName("MyClass::operator=="));
    }

    @Test
    public void sanitiseKeepsSafeCharsetAndCollapsesRuns() {
        // Underscore is itself safe, so runs of '_' are preserved.
        assertEquals("foo__bar.baz-1", TreeLayout.sanitiseName("foo__bar.baz-1"));
        // Multiple unsafe chars collapse to a single underscore.
        assertEquals("a_b", TreeLayout.sanitiseName("a<<<>>>b"));
    }

    @Test
    public void sanitiseTruncatesTo96() {
        String longName = "a".repeat(200);
        String sanitised = TreeLayout.sanitiseName(longName);
        assertEquals(96, sanitised.length());
    }

    @Test
    public void layoutPathsAreStableRelativeNames() {
        assertEquals("tree.json", TreeLayout.treeJson());
        assertEquals("STATUS.md", TreeLayout.statusMd());
        assertEquals("README.md", TreeLayout.readmeMd());
        assertEquals("modules/index.md", TreeLayout.modulesIndexMd());
        assertEquals("modules/c05/README.md", TreeLayout.moduleReadme("c05"));
        assertEquals(
                "modules/c05/00001000.c",
                TreeLayout.moduleFunctionFile("c05", "00001000.c"));
        assertEquals("index/by-address.tsv", TreeLayout.byAddressTsv());
        assertEquals("callgraph.tsv", TreeLayout.callgraphTsv());
    }

    @Test
    public void functionFileNameUsesSanitisedName() {
        String file = TreeLayout.functionFileName(0x1000L, "operator<<", 4);
        assertEquals("00001000_operator.c", file);
        assertFalse(file.contains("<"));
        assertTrue(file.endsWith(".c"));
    }

    @Test
    public void treeFilesAreExactlyWhatTheTreeWrites() {
        for (String rel : List.of("tree.json", "STATUS.md", "README.md", "AGENTS.md",
                "callgraph.tsv", "index/by-address.tsv", "index/partitions.json",
                "index/addresses.tsv", "modules/index.md", "modules/crt/README.md",
                "modules/crt/00401000_main.c", "modules/crt/00401000_main.c.tmp",
                "STATUS.md.tmp")) {
            assertTrue(rel, TreeLayout.isTreeFile(rel));
        }
        for (String rel : List.of("notes.md", "src/main.c", "modules/crt/notes.txt",
                "modules/crt/sub/00401000_main.c", "modules/README.md", "modules//x.c",
                "modules/crt/.c", "index/other.tsv", "x.tmp", "modules/crt/x.h")) {
            assertFalse(rel, TreeLayout.isTreeFile(rel));
        }
    }

    @Test
    public void slugsAndModuleFilesAreHeldToTheFileNameCharacterSet() {
        for (String ok : List.of("c05", "b003", "crt", "my-mod.v2")) {
            assertTrue(ok, TreeLayout.isValidSlug(ok));
        }
        for (String bad : List.of("", ".", "..", "a/b", "a\\b", "c:x", "a b", "x\u0000")) {
            assertFalse(bad, TreeLayout.isValidSlug(bad));
        }
        assertTrue(TreeLayout.isModuleFile("modules/c05/00401000_main.c"));
        for (String bad : List.of("modules/../00401000.c", "modules/c05/../x.c", "../modules/c05/x.c",
                "modules/c:x/a.c", "modules/c05/a b.c", "modules/c05/README.md", "/modules/c05/x.c")) {
            assertFalse(bad, TreeLayout.isModuleFile(bad));
        }
    }
}
