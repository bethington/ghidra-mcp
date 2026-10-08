package com.xebyte.offline;

import com.xebyte.core.ProgramProvider;
import com.xebyte.core.ProjectProgramProvider;
import com.xebyte.core.ProjectVersionControl;
import com.xebyte.core.Response;
import ghidra.framework.client.RepositoryAdapter;
import ghidra.framework.data.CheckinHandler;
import ghidra.framework.data.DomainFileProxy;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectData;
import ghidra.framework.store.ItemCheckoutStatus;
import ghidra.framework.store.Version;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import org.junit.Test;
import org.mockito.ArgumentCaptor;

import java.util.List;
import java.util.Map;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

/**
 * Version control over the open project's files, for both servers.
 *
 * <p>This logic was written three times: as GUI plugin helpers, in headless's
 * {@code GhidraServerManager} (which ignored {@code exclusive}, {@code keep} and
 * {@code keepCheckedOut}), and in {@code ProjectProgramProvider}. None of the copies had a
 * test. These pin the one that remains.
 */
public class ProjectVersionControlTest {

    private static final class Fixture {
        final ProgramProvider provider = mock(ProgramProvider.class);
        final Project project = mock(Project.class);
        final ProjectData data = mock(ProjectData.class);
        final RepositoryAdapter repository = mock(RepositoryAdapter.class);
        final ProjectVersionControl vc = new ProjectVersionControl(provider);

        Fixture() {
            when(provider.getProject()).thenReturn(project);
            when(project.getProjectData()).thenReturn(data);
            when(data.getRepository()).thenReturn(repository);
            when(repository.getName()).thenReturn("firmware-shared");
            when(provider.getAllOpenPrograms()).thenReturn(new Program[0]);
        }

        DomainFile file(String path, boolean versioned, boolean checkedOut) {
            DomainFile f = mock(DomainFile.class);
            when(f.getPathname()).thenReturn(path);
            when(f.getName()).thenReturn(path.substring(path.lastIndexOf('/') + 1));
            when(f.isVersioned()).thenReturn(versioned);
            when(f.isCheckedOut()).thenReturn(checkedOut);
            when(f.getContentType()).thenReturn("Program");
            when(data.getFile(path)).thenReturn(f);
            return f;
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> ok(Response r) {
        assertTrue("expected Ok: " + r, r instanceof Response.Ok);
        return (Map<String, Object>) ((Response.Ok) r).data();
    }

    private static String err(Response r) {
        assertTrue("expected Err: " + r, r instanceof Response.Err);
        return ((Response.Err) r).message();
    }

    // ------------------------------------------------------------------ lookup

    @Test
    public void everyOperationNeedsAPathAProjectAndAFile() {
        Fixture f = new Fixture();
        assertEquals("path is required", err(f.vc.checkout("  ", true)));
        assertEquals("File not found in project: /nope", err(f.vc.checkout("nope", true)));
        when(f.provider.getProject()).thenReturn(null);
        assertEquals("No project open. Call /open_project first.", err(f.vc.checkout("/a", true)));
    }

    @Test
    public void aPathWithoutALeadingSlashIsTheSameFile() throws Exception {
        Fixture f = new Fixture();
        DomainFile a = f.file("/fw/a", true, false);
        when(a.checkout(anyBoolean(), any(TaskMonitor.class))).thenReturn(true);
        assertEquals("checked_out", ok(f.vc.checkout("fw/a", true)).get("status"));
    }

    // ---------------------------------------------------------------- checkout

    @Test
    public void checkoutHonoursExclusiveInBothDirections() throws Exception {
        Fixture f = new Fixture();
        DomainFile a = f.file("/fw/a", true, false);
        when(a.checkout(anyBoolean(), any(TaskMonitor.class))).thenReturn(true);

        Map<String, Object> exclusive = ok(f.vc.checkout("/fw/a", true));
        Map<String, Object> shared = ok(f.vc.checkout("/fw/a", false));

        verify(a).checkout(eq(true), any(TaskMonitor.class));
        verify(a).checkout(eq(false), any(TaskMonitor.class));
        assertEquals(true, exclusive.get("exclusive"));
        assertEquals(false, shared.get("exclusive"));
        assertEquals(true, exclusive.get("success"));
        assertEquals("firmware-shared", exclusive.get("repository"));
    }

    @Test
    public void aCheckoutTheServerRefusesIsReportedAsFailed() throws Exception {
        Fixture f = new Fixture();
        DomainFile a = f.file("/fw/a", true, false);
        when(a.checkout(anyBoolean(), any(TaskMonitor.class))).thenReturn(false);
        Map<String, Object> out = ok(f.vc.checkout("/fw/a", true));
        assertEquals("checkout_failed", out.get("status"));
        assertEquals(false, out.get("success"));
    }

    /**
     * Found live: a second checkout failed with Ghidra's "Cannot checkout, private file
     * exists" while the file was checked out all along.
     */
    @Test
    public void checkingOutAFileAlreadyCheckedOutSaysSoAndSucceeds() throws Exception {
        Fixture f = new Fixture();
        DomainFile a = f.file("/fw/a", true, true);
        when(a.isCheckedOutExclusive()).thenReturn(true);

        Map<String, Object> out = ok(f.vc.checkout("/fw/a", false));

        assertEquals("already_checked_out", out.get("status"));
        assertEquals(true, out.get("success"));
        assertEquals("the existing checkout's mode, not the request's", true, out.get("exclusive"));
        verify(a, never()).checkout(anyBoolean(), any());
    }

    @Test
    public void aHijackedFileIsNamedAsTheReasonACheckoutCannotHappen() throws Exception {
        Fixture f = new Fixture();
        DomainFile a = f.file("/fw/a", true, false);
        when(a.isHijacked()).thenReturn(true);
        assertTrue(err(f.vc.checkout("/fw/a", true)).contains("hijacked"));
        verify(a, never()).checkout(anyBoolean(), any());
    }

    /** A program opened before its checkout: an in-memory copy that saves nowhere. */
    private static Program preCheckoutCopy(String path, boolean edited) {
        DomainFileProxy proxy = mock(DomainFileProxy.class);
        when(proxy.getPathname()).thenReturn(path);
        Program p = mock(Program.class);
        when(p.getDomainFile()).thenReturn(proxy);
        when(p.canSave()).thenReturn(false);
        when(p.isChanged()).thenReturn(edited);
        return p;
    }

    @Test
    public void anEditedCopyOpenedBeforeTheCheckoutIsLeftAloneAndTheCallerTold() throws Exception {
        Fixture f = new Fixture();
        DomainFile a = f.file("/fw/a", true, false);
        when(a.checkout(anyBoolean(), any(TaskMonitor.class))).thenReturn(true);
        Program copy = preCheckoutCopy("/fw/a", true);
        when(f.provider.getAllOpenPrograms()).thenReturn(new Program[] {copy});

        Map<String, Object> out = ok(f.vc.checkout("/fw/a", false));

        assertEquals("checked_out", out.get("status"));
        assertEquals(true, out.get("reopen_required"));
        assertTrue(String.valueOf(out.get("open_copy")).contains("save=false"));
        verify(f.provider, never()).closeProgramByPath(any());
    }

    @Test
    public void anUneditedCopyOpenedBeforeTheCheckoutIsReopenedOnIt() throws Exception {
        ProjectProgramProvider provider = mock(ProjectProgramProvider.class);
        Project project = mock(Project.class);
        ProjectData data = mock(ProjectData.class);
        when(provider.getProject()).thenReturn(project);
        when(project.getProjectData()).thenReturn(data);
        DomainFile a = mock(DomainFile.class);
        when(a.getPathname()).thenReturn("/fw/a");
        when(a.isVersioned()).thenReturn(true);
        when(a.checkout(anyBoolean(), any(TaskMonitor.class))).thenReturn(true);
        when(data.getFile("/fw/a")).thenReturn(a);
        Program copy = preCheckoutCopy("/fw/a", false);
        when(provider.getAllOpenPrograms()).thenReturn(new Program[] {copy});

        Map<String, Object> out = ok(new ProjectVersionControl(provider).checkout("/fw/a", false));

        assertEquals(true, out.get("reopened"));
        assertFalse(out.containsKey("reopen_required"));
        org.mockito.InOrder order = inOrder(provider);
        order.verify(provider).closeProgramByPath("/fw/a");
        order.verify(provider).openDomainFile(any(DomainFile.class));
    }

    @Test
    public void aWritableOpenProgramIsNotTouchedByACheckout() throws Exception {
        Fixture f = new Fixture();
        DomainFile a = f.file("/fw/a", true, false);
        when(a.checkout(anyBoolean(), any(TaskMonitor.class))).thenReturn(true);
        Program writable = mock(Program.class);
        when(writable.getDomainFile()).thenReturn(a);
        when(writable.canSave()).thenReturn(true);
        when(f.provider.getAllOpenPrograms()).thenReturn(new Program[] {writable});

        Map<String, Object> out = ok(f.vc.checkout("/fw/a", false));

        assertFalse(out.containsKey("reopened"));
        assertFalse(out.containsKey("reopen_required"));
        verify(f.provider, never()).closeProgramByPath(any());
    }

    @Test
    public void aFileNotUnderVersionControlCannotBeCheckedOut() {
        Fixture f = new Fixture();
        f.file("/fw/a", false, false);
        assertEquals("File is not under version control: /fw/a", err(f.vc.checkout("/fw/a", true)));
    }

    // ----------------------------------------------------------------- checkin

    @Test
    public void checkinRefusesAFileThatIsNotCheckedOut() throws Exception {
        Fixture f = new Fixture();
        DomainFile a = f.file("/fw/a", true, false);
        assertEquals("File is not checked out: /fw/a", err(f.vc.checkin("/fw/a", "c", false, false)));
        verify(a, never()).checkin(any(), any());
    }

    @Test
    public void checkinRefusesAFileNotUnderVersionControl() {
        Fixture f = new Fixture();
        f.file("/fw/a", false, false);
        assertTrue(err(f.vc.checkin("/fw/a", "c", false, false)).startsWith("File is not under version control"));
    }

    @Test
    public void checkinReportsTheVersionItProducedAndPassesTheCommentThrough() throws Exception {
        Fixture f = new Fixture();
        DomainFile a = f.file("/fw/a", true, true);
        when(a.getVersion()).thenReturn(4, 5);

        Map<String, Object> out = ok(f.vc.checkin("/fw/a", "fix, retry: now", true, false));

        assertEquals(4, out.get("version_before"));
        assertEquals(5, out.get("version"));
        assertEquals(true, out.get("version_bumped"));
        assertEquals("fix, retry: now", out.get("comment"));
        assertEquals(true, out.get("keep_checked_out"));
        ArgumentCaptor<CheckinHandler> handler = ArgumentCaptor.forClass(CheckinHandler.class);
        verify(a).checkin(handler.capture(), any(TaskMonitor.class));
        assertEquals("fix, retry: now", handler.getValue().getComment());
        assertTrue(handler.getValue().keepCheckedOut());
        assertFalse(handler.getValue().createKeepFile());
    }

    @Test
    public void checkinClosesTheOpenInstanceBeforeCheckingIn() throws Exception {
        // A file checked in while open must stay checked out, so the open instance goes first.
        Fixture f = new Fixture();
        DomainFile a = f.file("/fw/a", true, true);
        Program open = mock(Program.class);
        when(open.getDomainFile()).thenReturn(a);
        when(open.isChanged()).thenReturn(false);
        when(f.provider.getAllOpenPrograms()).thenReturn(new Program[] {open});

        f.vc.checkin("/fw/a", "c", false, false);

        org.mockito.InOrder order = inOrder(f.provider, a);
        order.verify(f.provider).closeProgramByPath("/fw/a");
        order.verify(a).checkin(any(), any(TaskMonitor.class));
    }

    /**
     * Found live: checkin_program(dry_run=true) saved, closed and checked in for real (the
     * scanner's rollback cannot undo a check-in), then failed ending its transaction on the
     * closed program. The dry run is now the tool's own, and touches nothing.
     */
    @Test
    public void aDryRunReportsWhatWouldHappenAndTouchesNothing() throws Exception {
        Fixture f = new Fixture();
        DomainFile a = f.file("/fw/a", true, true);
        when(a.getVersion()).thenReturn(1);
        Program open = mock(Program.class);
        when(open.getDomainFile()).thenReturn(a);
        when(open.isChanged()).thenReturn(true);
        when(f.provider.getAllOpenPrograms()).thenReturn(new Program[] {open});

        Map<String, Object> out = ok(f.vc.checkin("/fw/a", "c", false, true));

        assertEquals("would_check_in", out.get("status"));
        assertEquals(java.util.List.of("/fw/a"), out.get("would_save"));
        assertEquals(true, out.get("would_close"));
        assertEquals(1, out.get("version"));
        verify(a, never()).checkin(any(), any());
        verify(f.provider, never()).closeProgramByPath(any());
        verify(open, never()).save(any(), any());
    }

    @Test
    public void checkinWithNoPathUsesTheSoleOpenProgram() throws Exception {
        Fixture f = new Fixture();
        DomainFile a = f.file("/fw/a", true, true);
        Program open = mock(Program.class);
        when(open.getDomainFile()).thenReturn(a);
        when(f.provider.getCurrentProgram()).thenReturn(open);

        assertEquals("checked_in", ok(f.vc.checkin("", "c", false, false)).get("status"));
        verify(a).checkin(any(), any(TaskMonitor.class));
    }

    @Test
    public void checkinWithNoPathAndNothingOpenSaysSo() {
        Fixture f = new Fixture();
        assertEquals("No sole open program; supply 'path'.", err(f.vc.checkin(null, "c", false, false)));
    }

    // ---------------------------------------------------------- undo and add

    @Test
    public void undoCheckoutPassesKeepThroughAndRefusesWhatIsNotCheckedOut() throws Exception {
        Fixture f = new Fixture();
        DomainFile a = f.file("/fw/a", true, true);
        DomainFile idle = f.file("/fw/idle", true, false);

        assertEquals(true, ok(f.vc.undoCheckout("/fw/a", true)).get("kept_copy"));
        verify(a).undoCheckout(true);
        assertEquals("File is not checked out: /fw/idle", err(f.vc.undoCheckout("/fw/idle", false)));
        verify(idle, never()).undoCheckout(anyBoolean());
    }

    @Test
    public void addToVersionControlDefaultsTheCommentAndHonoursKeepCheckedOut() throws Exception {
        Fixture f = new Fixture();
        DomainFile a = f.file("/fw/a", false, false);

        Map<String, Object> out = ok(f.vc.addToVersionControl("/fw/a", "", true));

        verify(a).addToVersionControl(eq("Added via GhidraMCP"), eq(true), any(TaskMonitor.class));
        assertEquals("Added via GhidraMCP", out.get("comment"));
        assertEquals(true, out.get("keep_checked_out"));
    }

    /**
     * Found live: adding an open file with keep_checked_out=false left it checked out,
     * because Ghidra keeps an open file's checkout whatever it is told. Same as checkin.
     */
    @Test
    public void addSavesAndClosesTheOpenInstanceFirst() throws Exception {
        Fixture f = new Fixture();
        DomainFile a = f.file("/fw/a", false, false);
        Program open = mock(Program.class);
        when(open.getDomainFile()).thenReturn(a);
        when(f.provider.getAllOpenPrograms()).thenReturn(new Program[] {open});
        when(f.provider.closeProgramByPath("/fw/a")).thenReturn(true);

        Map<String, Object> out = ok(f.vc.addToVersionControl("/fw/a", "c", false));

        assertEquals(true, out.get("closed"));
        org.mockito.InOrder order = inOrder(f.provider, a);
        order.verify(f.provider).closeProgramByPath("/fw/a");
        order.verify(a).addToVersionControl(eq("c"), eq(false), any(TaskMonitor.class));
    }

    @Test
    public void aFileAlreadyVersionedCannotBeAdded() {
        Fixture f = new Fixture();
        f.file("/fw/a", true, false);
        assertEquals("File already under version control: /fw/a", err(f.vc.addToVersionControl("/fw/a", "c", false)));
    }

    // ----------------------------------------------------------------- history

    @Test
    public void versionHistoryIsSnakeCaseWithAReadableTime() throws Exception {
        Fixture f = new Fixture();
        DomainFile a = f.file("/fw/a", true, false);
        when(a.getVersionHistory()).thenReturn(new Version[] {new Version(1, 1_000_000_000_000L, "alice", "first, fix")});

        Map<String, Object> out = ok(f.vc.versionHistory("/fw/a"));

        assertEquals(1, out.get("count"));
        @SuppressWarnings("unchecked")
        Map<String, Object> v = ((List<Map<String, Object>>) out.get("versions")).get(0);
        assertEquals(1, v.get("version"));
        assertEquals("alice", v.get("user"));
        assertEquals("first, fix", v.get("comment"));
        assertEquals("2001-09-09T01:46:40Z", v.get("created"));
        assertEquals(1_000_000_000_000L, v.get("create_time_ms"));
    }

    // --------------------------------------------------------------- checkouts

    @Test
    public void checkoutsWalkFoldersAndMergeServerHolders() throws Exception {
        Fixture f = new Fixture();
        DomainFile mine = f.file("/fw/mine", true, true);
        when(mine.modifiedSinceCheckout()).thenReturn(true);
        DomainFile theirs = f.file("/fw/sub/theirs", true, false);
        DomainFile idle = f.file("/fw/idle", true, false);

        DomainFolder root = mock(DomainFolder.class);
        DomainFolder fw = mock(DomainFolder.class);
        DomainFolder sub = mock(DomainFolder.class);
        when(f.data.getRootFolder()).thenReturn(root);
        when(root.getFiles()).thenReturn(new DomainFile[0]);
        when(root.getFolders()).thenReturn(new DomainFolder[] {fw});
        when(fw.getFiles()).thenReturn(new DomainFile[] {mine, idle});
        when(fw.getFolders()).thenReturn(new DomainFolder[] {sub});
        when(sub.getFiles()).thenReturn(new DomainFile[] {theirs});
        when(sub.getFolders()).thenReturn(new DomainFolder[0]);

        ItemCheckoutStatus holder = mock(ItemCheckoutStatus.class);
        when(holder.getCheckoutId()).thenReturn(7L);
        when(holder.getUser()).thenReturn("bob");
        when(holder.getProjectName()).thenReturn("bobs-copy");
        when(holder.getCheckoutVersion()).thenReturn(3);
        when(f.repository.getCheckouts("/fw/sub", "theirs")).thenReturn(new ItemCheckoutStatus[] {holder});

        Map<String, Object> out = ok(f.vc.checkouts("/"));

        assertEquals(2, out.get("count"));
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> rows = (List<Map<String, Object>>) out.get("checkouts");
        Map<String, Object> first = rows.get(0);
        assertEquals("/fw/mine", first.get("path"));
        assertEquals("a checkout holding work is visible", true, first.get("modified_since_checkout"));
        assertFalse(first.containsKey("server_checkouts"));
        Map<String, Object> second = rows.get(1);
        assertEquals("/fw/sub/theirs", second.get("path"));
        @SuppressWarnings("unchecked")
        Map<String, Object> holderRow = ((List<Map<String, Object>>) second.get("server_checkouts")).get(0);
        assertEquals(7L, holderRow.get("checkout_id"));
        assertEquals("bob", holderRow.get("user"));
    }

    @Test
    public void checkoutsOfASingleFileReportJustThatFile() throws Exception {
        Fixture f = new Fixture();
        f.file("/fw/mine", true, true);
        f.file("/fw/other", true, true);
        assertEquals(1, ok(f.vc.checkouts("/fw/mine")).get("count"));
    }

    @Test
    public void checkoutsUnderAMissingFolderIsAnError() {
        Fixture f = new Fixture();
        assertEquals("Folder not found: /nope", err(f.vc.checkouts("/nope")));
    }

    // --------------------------------------------------------------- terminate

    @Test
    public void terminateOneCheckoutByIdGoesToTheRepository() throws Exception {
        Fixture f = new Fixture();
        f.file("/fw/a", true, false);

        Map<String, Object> out = ok(f.vc.terminateCheckout("/fw/a", 42L));

        verify(f.repository).terminateCheckout("/fw", "a", 42L, false);
        assertEquals("checkout_terminated", out.get("status"));
        assertEquals(42L, out.get("checkout_id"));
    }

    @Test
    public void terminateWithoutAnIdReleasesTheLocalCheckoutFirst() throws Exception {
        Fixture f = new Fixture();
        DomainFile a = f.file("/fw/a", true, true);
        Map<String, Object> out = ok(f.vc.terminateCheckout("/fw/a", null));
        verify(a).undoCheckout(false, true);
        assertEquals("undo_checkout_force", out.get("method"));
        verify(f.repository, never()).terminateCheckout(anyString(), anyString(), anyLong(), anyBoolean());
    }

    @Test
    public void terminateWithoutAnIdFallsBackToEveryServerCheckout() throws Exception {
        Fixture f = new Fixture();
        f.file("/fw/a", true, false);
        ItemCheckoutStatus one = mock(ItemCheckoutStatus.class);
        ItemCheckoutStatus two = mock(ItemCheckoutStatus.class);
        when(one.getCheckoutId()).thenReturn(1L);
        when(two.getCheckoutId()).thenReturn(2L);
        when(f.repository.getCheckouts("/fw", "a")).thenReturn(new ItemCheckoutStatus[] {one, two});
        doThrow(new java.io.IOException("gone")).when(f.repository).terminateCheckout("/fw", "a", 2L, false);

        Map<String, Object> out = ok(f.vc.terminateCheckout("/fw/a", null));

        assertEquals(1, out.get("terminated_count"));
        assertEquals("partial progress is reported, not hidden", 2, out.get("total_checkouts"));
    }

    @Test
    public void terminateNeedsARepository() {
        Fixture f = new Fixture();
        f.file("/fw/a", true, false);
        when(f.data.getRepository()).thenReturn(null);
        assertEquals("Cannot terminate checkout: project has no repository connection",
            err(f.vc.terminateCheckout("/fw/a", 1L)));
        assertEquals("Cannot terminate checkouts: project has no repository connection",
            err(f.vc.terminateAllCheckouts("/")));
    }

    @Test
    public void terminateAllCountsWhatLanded() throws Exception {
        Fixture f = new Fixture();
        DomainFile a = f.file("/fw/a", true, false);
        DomainFile plain = f.file("/fw/plain", false, false);
        DomainFolder root = mock(DomainFolder.class);
        when(f.data.getRootFolder()).thenReturn(root);
        when(root.getFiles()).thenReturn(new DomainFile[] {a, plain});
        when(root.getFolders()).thenReturn(new DomainFolder[0]);
        ItemCheckoutStatus held = mock(ItemCheckoutStatus.class);
        when(held.getCheckoutId()).thenReturn(9L);
        when(f.repository.getCheckouts("/fw", "a")).thenReturn(new ItemCheckoutStatus[] {held});

        Map<String, Object> out = ok(f.vc.terminateAllCheckouts(""));

        assertEquals(1, out.get("files_with_checkouts"));
        assertEquals(1, out.get("checkouts_terminated"));
        assertEquals("/", out.get("folder"));
        verify(f.repository, never()).getCheckouts(eq("/fw"), eq("plain"));
    }

    // ------------------------------------------------------------ state shape

    @Test
    public void fileStateHidesCheckoutDetailForAFileThatIsNotCheckedOut() {
        Fixture f = new Fixture();
        Map<String, Object> idle = ProjectVersionControl.fileState(f.file("/fw/a", true, false));
        assertFalse(idle.containsKey("modified_since_checkout"));
        assertEquals("Program", idle.get("content_type"));

        DomainFile held = f.file("/fw/b", true, true);
        Map<String, Object> checkedOut = ProjectVersionControl.fileState(held);
        assertTrue(checkedOut.containsKey("modified_since_checkout"));
        assertTrue(checkedOut.containsKey("is_hijacked"));
    }
}
