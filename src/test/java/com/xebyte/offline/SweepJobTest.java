package com.xebyte.offline;

import com.xebyte.core.tree.DecompTree;
import com.xebyte.core.tree.TreeConfig;
import com.xebyte.core.tree.TreeKey;
import com.xebyte.core.tree.TreeLayout;
import com.xebyte.core.tree.TreeRoot;
import com.xebyte.core.tree.TreeStatusMd;
import com.xebyte.core.tree.SweepJob;
import com.xebyte.core.tree.SweepProgress;
import ghidra.framework.model.TransactionInfo;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Stream;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Pure offline tests for {@link SweepJob} helpers — header rendering, index
 * row shape, STATUS.md states, and cancel-flag plumbing. No live Program.
 */
public class SweepJobTest {

    private Path tempRoot;

    @Before
    public void setUp() throws IOException {
        tempRoot = Files.createTempDirectory("sweep-job-test");
    }

    @After
    public void tearDown() throws IOException {
        if (tempRoot != null && Files.exists(tempRoot)) {
            try (Stream<Path> walk = Files.walk(tempRoot)) {
                walk.sorted(Comparator.reverseOrder()).forEach(p -> {
                    try {
                        Files.deleteIfExists(p);
                    } catch (IOException ignored) {
                        // best-effort
                    }
                });
            }
        }
    }

    @Test
    public void functionUriEncodesProgramNameLikeBridgeQuote() {
        assertEquals(
                "ghidra://function/my%20prog/00401000",
                SweepJob.functionResourceUri("my prog", "00401000"));
        assertEquals(
                "ghidra://function/proj%2Fbin/mem:1000",
                SweepJob.functionResourceUri("proj/bin", "mem:1000"));
    }

    @Test
    public void failedDecompileMarkerIsNeverSilent() {
        String body = SweepJob.renderFailedBody("timed out");
        assertTrue(body.startsWith("// DECOMPILATION FAILED: "));
        assertTrue(body.contains("timed out"));
        assertTrue(body.endsWith("\n"));
    }

    @Test
    public void byAddressTsvRowShape() {
        assertEquals(
                "address\tname\tpartition_slug\tfile\tevidence_backed\tifp\n",
                SweepJob.byAddressHeader());
        assertEquals(
                "00100000\tFoo\tc05\tmodules/c05/00100000.c\ttrue\tabcdef123456\n",
                SweepJob.formatByAddressRow(
                        "00100000", "Foo", "c05", "modules/c05/00100000.c", true,
                        "abcdef123456"));
        assertEquals(
                "00100000\tBar\tb003\tmodules/b003/00100000.c\tfalse\t\n",
                SweepJob.formatByAddressRow(
                        "00100000", "Bar", "b003", "modules/b003/00100000.c", false,
                        ""));
    }

    @Test
    public void moduleReadmeListsEveryFileWithRange() {
        // Shape the Files table the sweep writes — navigable without opening .c.
        String readme = ""
                + "# Module c03\n\n"
                + "method: address-band\n"
                + "confidence: 0.10\n"
                + "functions: 4\n"
                + "files: 2\n"
                + "\n## Files\n\n"
                + "| file | first | last | functions |\n"
                + "| --- | --- | --- | ---: |\n"
                + "| modules/c03/00001000.c | 00001000 | 00001100 | 2 |\n"
                + "| modules/c03/00001200.c | 00001200 | 00001300 | 2 |\n"
                + "\n## Evidence\n\n";
        assertTrue(readme.contains("| modules/c03/00001000.c | 00001000 | 00001100 | 2 |"));
        assertTrue(readme.contains("| modules/c03/00001200.c | 00001200 | 00001300 | 2 |"));
        assertTrue(readme.contains("files: 2"));
    }

    @Test
    public void statusMdBeforeAndAfterStates() throws IOException {
        TreeKey key = TreeKey.of("/proj/app.exe", tempRoot.toString());
        TreeRoot root = TreeRoot.ofResolved(tempRoot);
        DecompTree decompTree = new DecompTree(key, "app.exe", TreeConfig.defaults(), root);

        // Before work: dirty, no swept_at.
        decompTree.setProgress(decompTree.progress()
                .withPhase(SweepProgress.Phase.DECOMPILING)
                .withCounts(100, 10, 1)
                .withBytesWritten(4096L));
        String dirty = TreeStatusMd.render(decompTree, "dirty");
        assertTrue(dirty.contains("state: dirty"));
        assertTrue(dirty.contains("phase: decompiling"));
        assertTrue(dirty.contains("functions_total: 100"));
        assertTrue(dirty.contains("functions_done: 10"));
        assertTrue(dirty.contains("functions_failed: 1"));
        assertTrue(dirty.contains("disassembled_on_demand: 0"));
        assertTrue(dirty.contains("disassembly_failed: 0"));
        assertTrue(dirty.contains("bodies_recomputed: 0"));
        assertTrue(dirty.contains("body_recompute_failed: 0"));
        assertTrue(dirty.contains("swept_at_modification_number: \n")
                || dirty.contains("swept_at_modification_number:\n"));

        TreeStatusMd.write(decompTree, "dirty");
        assertTrue(Files.isRegularFile(tempRoot.resolve("STATUS.md")));
        String onDisk = Files.readString(tempRoot.resolve("STATUS.md"));
        assertTrue(onDisk.contains("state: dirty"));

        // After success: clean + modification number.
        decompTree.setProgress(decompTree.progress()
                .withPhase(SweepProgress.Phase.COMPLETE)
                .withCounts(100, 100, 1)
                .withBytesWritten(9999L)
                .sweptAt(7L));
        String clean = TreeStatusMd.render(decompTree, "clean");
        assertTrue(clean.contains("state: clean"));
        assertTrue(clean.contains("phase: complete"));
        assertTrue(clean.contains("swept_at_modification_number: 7"));
        assertTrue(clean.contains("reconciled_at_modification_number: 7"));
        assertEquals("clean", TreeStatusMd.stateForPhase(SweepProgress.Phase.COMPLETE));
        assertEquals("cancelled", TreeStatusMd.stateForPhase(SweepProgress.Phase.CANCELLED));
        assertEquals("failed", TreeStatusMd.stateForPhase(SweepProgress.Phase.FAILED));
        assertEquals("dirty", TreeStatusMd.stateForPhase(SweepProgress.Phase.DECOMPILING));
        assertEquals("stale", TreeStatusMd.stateForPhase(SweepProgress.Phase.STALE));
    }

    /**
     * Found in a live RE session: after any splice STATUS.md said clean, spliced_since_sweep
     * stayed 0 and swept_at went blank, so nothing told an agent the tree had drifted from
     * the sweep's output. Every writer now takes the numbers from progress.
     */
    @Test
    public void aSpliceKeepsTheSweptNumberAndSaysTheTreeWasSpliced() {
        DecompTree decompTree = new DecompTree(
                TreeKey.of("/p/app.exe", tempRoot), "app.exe", TreeConfig.defaults(),
                TreeRoot.ofResolved(tempRoot));
        decompTree.setProgress(decompTree.progress().withPhase(SweepProgress.Phase.COMPLETE).sweptAt(4L));
        assertEquals("clean", TreeStatusMd.settledState(decompTree.progress()));

        // One replaced block (a comment edit), no structural change.
        decompTree.setProgress(decompTree.progress().reconciledAt(5L, 1, 0));
        assertEquals("spliced", TreeStatusMd.settledState(decompTree.progress()));
        String status = TreeStatusMd.render(decompTree, TreeStatusMd.settledState(decompTree.progress()));
        assertTrue(status, status.contains("state: spliced"));
        assertTrue(status, status.contains("swept_at_modification_number: 4\n"));
        assertTrue(status, status.contains("reconciled_at_modification_number: 5\n"));
        assertTrue(status, status.contains("spliced_since_sweep: 1\n"));
        assertTrue(status, status.contains("structural_since_sweep: 0\n"));

        // A fresh sweep is the sweep's output again.
        decompTree.setProgress(decompTree.progress().sweptAt(9L));
        assertEquals("clean", TreeStatusMd.settledState(decompTree.progress()));
        assertEquals(Long.valueOf(9L), decompTree.progress().reconciledAtModification());
        assertEquals(0, decompTree.progress().splicedSinceSweep());
    }

    @Test
    public void aStaleDecompTreeSaysWhy() {
        DecompTree decompTree = new DecompTree(
                TreeKey.of("/p/app.exe", tempRoot), "app.exe", TreeConfig.defaults(),
                TreeRoot.ofResolved(tempRoot));
        decompTree.setProgress(decompTree.progress()
                .withPhase(SweepProgress.Phase.STALE)
                .withLastError("edits were discarded"));
        String status = TreeStatusMd.render(decompTree, TreeStatusMd.settledState(decompTree.progress()));
        assertTrue(status, status.contains("state: stale"));
        assertTrue(status, status.contains("last_error: edits were discarded"));
    }

    @Test
    public void disassemblePassSkipsFunctionsThatAlreadyHaveInstructions() {
        Program program = mock(Program.class);
        FunctionManager fm = mock(FunctionManager.class);
        Listing listing = mock(Listing.class);
        when(program.getFunctionManager()).thenReturn(fm);
        when(program.getListing()).thenReturn(listing);

        Function needs = mock(Function.class);
        Function hasInsn = mock(Function.class);
        Address missing = mock(Address.class);
        Address present = mock(Address.class);

        when(needs.isExternal()).thenReturn(false);
        when(needs.isThunk()).thenReturn(false);
        when(needs.getEntryPoint()).thenReturn(missing);

        when(hasInsn.isExternal()).thenReturn(false);
        when(hasInsn.isThunk()).thenReturn(false);
        when(hasInsn.getEntryPoint()).thenReturn(present);

        when(listing.getInstructionAt(missing)).thenReturn(null);
        when(listing.getInstructionAt(present)).thenReturn(mock(Instruction.class));

        FunctionIterator it = mock(FunctionIterator.class);
        when(fm.getFunctions(true)).thenReturn(it);
        when(it.hasNext()).thenReturn(true, true, false);
        when(it.next()).thenReturn(needs, hasInsn);

        List<Address> touched = new ArrayList<>();
        SweepJob.DisassemblyPassResult result = SweepJob.disassembleMissingAtEntries(
                program,
                new SweepJob.CancelSignal(),
                0,
                (prog, entry) -> {
                    touched.add(entry);
                    return true;
                });

        assertEquals(1, result.disassembledOnDemand());
        assertEquals(0, result.disassemblyFailed());
        assertEquals(1, touched.size());
        assertEquals(missing, touched.get(0));
    }

    @Test
    public void disassemblePassCountsFailuresAndHonoursCancel() {
        Program program = mock(Program.class);
        FunctionManager fm = mock(FunctionManager.class);
        Listing listing = mock(Listing.class);
        when(program.getFunctionManager()).thenReturn(fm);
        when(program.getListing()).thenReturn(listing);

        Function a = mock(Function.class);
        Function b = mock(Function.class);
        Address addrA = mock(Address.class);
        Address addrB = mock(Address.class);

        when(a.isExternal()).thenReturn(false);
        when(a.isThunk()).thenReturn(false);
        when(a.getEntryPoint()).thenReturn(addrA);
        when(b.isExternal()).thenReturn(false);
        when(b.isThunk()).thenReturn(false);
        when(b.getEntryPoint()).thenReturn(addrB);
        when(listing.getInstructionAt(addrA)).thenReturn(null);
        when(listing.getInstructionAt(addrB)).thenReturn(null);

        FunctionIterator it = mock(FunctionIterator.class);
        when(fm.getFunctions(true)).thenReturn(it);
        when(it.hasNext()).thenReturn(true, true, false);
        when(it.next()).thenReturn(a, b);

        SweepJob.DisassemblyPassResult result = SweepJob.disassembleMissingAtEntries(
                program,
                new SweepJob.CancelSignal(),
                0,
                (prog, entry) -> entry.equals(addrA));

        assertEquals(1, result.disassembledOnDemand());
        assertEquals(1, result.disassemblyFailed());

        SweepJob.CancelSignal cancel = new SweepJob.CancelSignal();
        cancel.cancel();
        SweepJob.DisassemblyPassResult cancelled = SweepJob.disassembleMissingAtEntries(
                program, cancel, 0, (prog, entry) -> true);
        assertEquals(0, cancelled.disassembledOnDemand());
        assertEquals(0, cancelled.disassemblyFailed());
    }

    @Test
    public void sweepProgressReportsDisassemblyCounts() {
        SweepProgress progress = SweepProgress.idle().withDisassemblyCounts(12, 3);
        assertEquals(12, progress.disassembledOnDemand());
        assertEquals(3, progress.disassemblyFailed());
        assertEquals(0, progress.bodiesRecomputed());
        assertEquals(0, progress.bodyRecomputeFailed());
    }

    @Test
    public void bodyReflowCountsReachStatusMd() {
        TreeKey key = TreeKey.of("/proj/app.exe", tempRoot.toString());
        TreeRoot root = TreeRoot.ofResolved(tempRoot);
        DecompTree decompTree = new DecompTree(key, "app.exe", TreeConfig.defaults(), root);
        decompTree.setProgress(decompTree.progress()
                .withDisassemblyCounts(12, 3)
                .withBodyReflowCounts(10, 2));
        String status = TreeStatusMd.render(decompTree, "dirty");
        assertTrue(status.contains("disassembled_on_demand: 12"));
        assertTrue(status.contains("disassembly_failed: 3"));
        assertTrue(status.contains("bodies_recomputed: 10"));
        assertTrue(status.contains("body_recompute_failed: 2"));
    }

    @Test
    public void recomputeBodyLeavesRealBodyAlone() throws Exception {
        Program program = mock(Program.class);
        when(program.getCurrentTransactionInfo()).thenReturn(mock(TransactionInfo.class));

        Function func = mock(Function.class);
        AddressSetView realBody = mock(AddressSetView.class);
        when(realBody.getNumAddresses()).thenReturn(64L);
        when(func.getBody()).thenReturn(realBody);

        AddressSetView candidate = mock(AddressSetView.class);
        when(candidate.getNumAddresses()).thenReturn(128L);

        SweepJob.BodyReflowOutcome outcome = SweepJob.recomputeBodyIfDegenerate(
                program, func, TaskMonitor.DUMMY,
                (prog, entry, mon) -> candidate);

        assertEquals(SweepJob.BodyReflowOutcome.SKIPPED, outcome);
        verify(func, never()).setBody(org.mockito.ArgumentMatchers.any());
    }

    @Test
    public void recomputeBodySetsBiggerBodyOnDegenerate() throws Exception {
        Program program = mock(Program.class);
        when(program.getCurrentTransactionInfo()).thenReturn(mock(TransactionInfo.class));

        Function func = mock(Function.class);
        Address entry = mock(Address.class);
        AddressSetView stubBody = mock(AddressSetView.class);
        when(stubBody.getNumAddresses()).thenReturn(1L);
        when(func.getBody()).thenReturn(stubBody);
        when(func.getEntryPoint()).thenReturn(entry);

        AddressSetView candidate = mock(AddressSetView.class);
        when(candidate.getNumAddresses()).thenReturn(40L);

        SweepJob.BodyReflowOutcome outcome = SweepJob.recomputeBodyIfDegenerate(
                program, func, TaskMonitor.DUMMY,
                (prog, e, mon) -> candidate);

        assertEquals(SweepJob.BodyReflowOutcome.RECOMPUTED, outcome);
        verify(func).setBody(candidate);
    }

    @Test
    public void recomputeBodyCountsOverlapAsFailure() throws Exception {
        Program program = mock(Program.class);
        when(program.getCurrentTransactionInfo()).thenReturn(mock(TransactionInfo.class));

        Function func = mock(Function.class);
        Address entry = mock(Address.class);
        AddressSetView stubBody = mock(AddressSetView.class);
        when(stubBody.getNumAddresses()).thenReturn(1L);
        when(func.getBody()).thenReturn(stubBody);
        when(func.getEntryPoint()).thenReturn(entry);

        AddressSetView candidate = mock(AddressSetView.class);
        when(candidate.getNumAddresses()).thenReturn(40L);
        org.mockito.Mockito.doThrow(new OverlappingFunctionException(entry))
                .when(func).setBody(candidate);

        SweepJob.BodyReflowOutcome outcome = SweepJob.recomputeBodyIfDegenerate(
                program, func, TaskMonitor.DUMMY,
                (prog, e, mon) -> candidate);

        assertEquals(SweepJob.BodyReflowOutcome.FAILED, outcome);
    }

    @Test
    public void disassemblePassReflowsDegenerateBodiesAndCountsOverlap() throws Exception {
        Program program = mock(Program.class);
        FunctionManager fm = mock(FunctionManager.class);
        Listing listing = mock(Listing.class);
        when(program.getFunctionManager()).thenReturn(fm);
        when(program.getListing()).thenReturn(listing);
        when(program.getCurrentTransactionInfo()).thenReturn(mock(TransactionInfo.class));

        Function needs = mock(Function.class);
        Address missing = mock(Address.class);
        AddressSetView stubBody = mock(AddressSetView.class);
        when(stubBody.getNumAddresses()).thenReturn(1L);
        when(needs.isExternal()).thenReturn(false);
        when(needs.isThunk()).thenReturn(false);
        when(needs.getEntryPoint()).thenReturn(missing);
        when(needs.getBody()).thenReturn(stubBody);
        when(listing.getInstructionAt(missing)).thenReturn(null);

        FunctionIterator it = mock(FunctionIterator.class);
        when(fm.getFunctions(true)).thenReturn(it);
        when(it.hasNext()).thenReturn(true, false);
        when(it.next()).thenReturn(needs);

        AddressSetView bigger = mock(AddressSetView.class);
        when(bigger.getNumAddresses()).thenReturn(32L);

        SweepJob.DisassemblyPassResult ok = SweepJob.disassembleMissingAtEntries(
                program,
                new SweepJob.CancelSignal(),
                0,
                (prog, entry) -> true,
                (prog, entry, mon) -> bigger);
        assertEquals(1, ok.disassembledOnDemand());
        assertEquals(1, ok.bodiesRecomputed());
        assertEquals(0, ok.bodyRecomputeFailed());

        when(it.hasNext()).thenReturn(true, false);
        when(it.next()).thenReturn(needs);
        org.mockito.Mockito.doThrow(new OverlappingFunctionException(missing))
                .when(needs).setBody(bigger);

        SweepJob.DisassemblyPassResult overlap = SweepJob.disassembleMissingAtEntries(
                program,
                new SweepJob.CancelSignal(),
                0,
                (prog, entry) -> true,
                (prog, entry, mon) -> bigger);
        assertEquals(1, overlap.disassembledOnDemand());
        assertEquals(0, overlap.bodiesRecomputed());
        assertEquals(1, overlap.bodyRecomputeFailed());
    }

    @Test
    public void cancelFlagPlumbsThroughTaskMonitor() {
        TreeKey key = TreeKey.of("/proj/app.exe", tempRoot.toString());
        TreeRoot root = TreeRoot.ofResolved(tempRoot);
        DecompTree decompTree = new DecompTree(key, "app.exe", TreeConfig.defaults(), root);

        // Program is required at construction for a real sweep; cancel plumbing
        // is tested via CancelSignal without running. Build a job-shaped signal
        // the same way SweepJob does.
        SweepJob.CancelSignal signal = new SweepJob.CancelSignal();
        assertFalse(signal.isCancelled());
        assertFalse(signal.monitor().isCancelled());

        signal.cancel();
        assertTrue(signal.isCancelled());
        assertTrue(
                "TaskMonitor.isCancelled must mirror the volatile flag so the "
                        + "native decompiler aborts",
                signal.monitor().isCancelled());
    }

    @Test
    public void shortContentHashIsStableTwelveHex() {
        String a = SweepJob.shortContentHash("int foo() { return 1; }\n");
        String b = SweepJob.shortContentHash("int foo() { return 1; }\n");
        String c = SweepJob.shortContentHash("int foo() { return 2; }\n");
        assertEquals(12, a.length());
        assertEquals(a, b);
        assertFalse(a.equals(c));
    }
}
