package com.xebyte.offline;

import com.xebyte.core.tree.TreeFiles;
import org.junit.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Offline tests for configure-time tree narrowing: a partially-excluded
 * partition file is rewritten, not deleted.
 */
public class TreeFilesTest {

    private static final String PARTITION_BODY = ""
            + "// fn: Foo @ 00100000 size=16\n"
            + "// part: c05 address-band conf=0.50 evidence_backed=false\n"
            + "// fp:aaaaaaaaaaaa\n"
            + "// dts:2026-01-01T00:00:00Z\n"
            + "// mod:1\n"
            + "// uri: ghidra://function/x/00100000\n"
            + "// see: modules/c05/README.md\n"
            + "void Foo(void) {}\n"
            + "\n"
            + "// fn: Bar @ 00100100 size=16\n"
            + "// part: c05 address-band conf=0.50 evidence_backed=false\n"
            + "// fp:bbbbbbbbbbbb\n"
            + "// dts:2026-01-01T00:00:00Z\n"
            + "// mod:1\n"
            + "// uri: ghidra://function/x/00100100\n"
            + "// see: modules/c05/README.md\n"
            + "void Bar(void) {}\n"
            + "\n"
            + "// fn: Baz @ 00100200 size=16\n"
            + "// part: c05 address-band conf=0.50 evidence_backed=false\n"
            + "// fp:cccccccccccc\n"
            + "// dts:2026-01-01T00:00:00Z\n"
            + "// mod:1\n"
            + "// uri: ghidra://function/x/00100200\n"
            + "// see: modules/c05/README.md\n"
            + "void Baz(void) {}\n"
            + "\n";

    @Test
    public void splitChunksRoundTripAddresses() {
        List<String> chunks = TreeFiles.splitFunctionChunks(PARTITION_BODY);
        assertEquals(3, chunks.size());
        assertEquals("00100000", TreeFiles.addressFromChunk(chunks.get(0)));
        assertEquals("00100100", TreeFiles.addressFromChunk(chunks.get(1)));
        assertEquals("00100200", TreeFiles.addressFromChunk(chunks.get(2)));
    }

    @Test
    public void anIndexRowPointingOutsideTheModulesReadsAsNoFile() throws Exception {
        Path dir = Files.createTempDirectory("tree-index");
        try {
            Path index = dir.resolve("by-address.tsv");
            Files.writeString(index, "address\tname\tslug\tfile\n"
                    + "00401000\tmain\tc00\tmodules/c00/00401000_main.c\n"
                    + "00402000\tf\tc00\t../../etc/passwd\n"
                    + "00403000\tg\tc00\tmodules/c00/../../x.c\n"
                    + "00404000\th\tc00\t/abs/modules/c00/x.c\n");
            List<TreeFiles.IndexEntry> rows = TreeFiles.readIndex(index);
            assertEquals(List.of("modules/c00/00401000_main.c", "", "", ""),
                    rows.stream().map(TreeFiles.IndexEntry::file).toList());
        } finally {
            try (java.util.stream.Stream<Path> walk = Files.walk(dir)) {
                for (Path p : walk.sorted(java.util.Comparator.reverseOrder()).toList()) {
                    Files.deleteIfExists(p);
                }
            }
        }
    }
}
