package com.xebyte.core;

import ghidra.framework.client.RepositoryAdapter;
import ghidra.framework.data.CheckinHandler;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectData;
import ghidra.framework.store.ItemCheckoutStatus;
import ghidra.framework.store.Version;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TaskMonitor;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Version control over the open project's files: check out, check in, undo, add, history,
 * and who holds what.
 *
 * <p>Both servers do this on the open project's {@link DomainFile}s. It was written twice:
 * as {@code GhidraMCPPlugin} helpers for the GUI, and again in {@code GhidraServerManager}
 * for headless, with the two copies differing only in hard-coded defaults (headless
 * ignored {@code exclusive}, {@code keep} and {@code keepCheckedOut}) -- and a third time
 * as {@code ProjectProgramProvider.checkinProgram}. This is the one copy.
 *
 * <p>Every operation that names a file goes through {@link #file}, so the
 * project-folder scope applies to all of them. It applied to none of the routes it
 * replaces.
 *
 * <p>Responses are snake_case throughout, and every state report is re-read from the
 * project after the operation rather than taken off the instance that was acted on,
 * whose version-control state is cached.
 */
public final class ProjectVersionControl {

    private static final String NO_PROJECT = "No project open. Call /open_project first.";

    private final ProgramProvider provider;
    private final TaskMonitor monitor = new ConsoleTaskMonitor();

    public ProjectVersionControl(ProgramProvider provider) {
        this.provider = provider;
    }

    // ------------------------------------------------------------------ lookup

    private record FileOrError(DomainFile file, String error) {
        boolean hasError() { return file == null; }
    }

    private Project project() {
        return provider.getProject();
    }

    /** The project file at {@code path}, if it exists and is inside this server's scope. */
    private FileOrError file(String path) {
        if (path == null || path.isBlank()) {
            return new FileOrError(null, "path is required");
        }
        Project project = project();
        if (project == null) {
            return new FileOrError(null, NO_PROJECT);
        }
        String normalized = path.trim().startsWith("/") ? path.trim() : "/" + path.trim();
        if (!SecurityConfig.getInstance().isPathInProjectScope(normalized)) {
            return new FileOrError(null,
                "Path is outside this server's project-folder scope: " + normalized);
        }
        DomainFile file = project.getProjectData().getFile(normalized);
        if (file == null) {
            return new FileOrError(null, "File not found in project: " + normalized);
        }
        return new FileOrError(file, null);
    }

    /** The repository the open project is bound to, or null when it is local-only. */
    private RepositoryAdapter repository() {
        Project project = project();
        return project != null ? project.getProjectData().getRepository() : null;
    }

    private static String parentOf(String path) {
        int slash = path.lastIndexOf('/');
        return slash > 0 ? path.substring(0, slash) : "/";
    }

    private static String nameOf(String path) {
        return path.substring(path.lastIndexOf('/') + 1);
    }

    private static String messageOf(Exception e) {
        return e.getMessage() != null ? e.getMessage() : e.toString();
    }

    // ------------------------------------------------------------------- state

    /**
     * A file's version-control state. {@code modified_since_checkout} decides whether a
     * checkout holds uncommitted work and is therefore unsafe to release: on a shared
     * project that work exists only in the local project directory, with no server copy.
     */
    public static Map<String, Object> fileState(DomainFile f) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("name", f.getName());
        m.put("path", f.getPathname());
        m.put("content_type", f.getContentType());
        m.put("version", f.getVersion());
        m.put("latest_version", f.getLatestVersion());
        m.put("is_versioned", f.isVersioned());
        m.put("is_checked_out", f.isCheckedOut());
        m.put("is_checked_out_exclusive", f.isCheckedOutExclusive());
        m.put("is_read_only", f.isReadOnly());
        if (f.isCheckedOut()) {
            m.put("modified_since_checkout", f.modifiedSinceCheckout());
            m.put("is_hijacked", f.isHijacked());
            try {
                ItemCheckoutStatus status = f.getCheckoutStatus();
                if (status != null) {
                    m.put("checkout_user", status.getUser());
                    m.put("checkout_id", status.getCheckoutId());
                    m.put("checkout_version", status.getCheckoutVersion());
                }
            } catch (Exception e) {
                m.put("checkout_error", messageOf(e));
            }
        }
        return m;
    }

    /**
     * The state after an operation, re-read from the project. A checkin with
     * keep_checked_out=false answering {@code is_checked_out: true} is not necessarily
     * stale: measured against a live server, the checkout genuinely survived it.
     */
    private Response report(String status, boolean success, DomainFile file, Map<String, Object> extras) {
        DomainFile current = refreshed(file);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("success", success);
        out.put("status", status);
        out.put("path", file.getPathname());
        RepositoryAdapter repo = repository();
        if (repo != null) {
            out.put("repository", repo.getName());
        }
        out.put("is_versioned", current.isVersioned());
        out.put("is_checked_out", current.isCheckedOut());
        out.put("can_checkin", current.canCheckin());
        out.put("modified_since_checkout", current.modifiedSinceCheckout());
        out.putAll(extras);
        return Response.ok(out);
    }

    /** Re-resolve the file so post-operation state is fresh; the original if it cannot be. */
    private DomainFile refreshed(DomainFile file) {
        try {
            ProjectData data = file.getParent().getProjectData();
            data.refresh(true);
            DomainFile again = data.getFile(file.getPathname());
            return again != null ? again : file;
        } catch (Exception e) {
            return file;
        }
    }

    // -------------------------------------------------------------- operations

    public Response checkout(String path, boolean exclusive) {
        FileOrError f = file(path);
        if (f.hasError()) return Response.err(f.error());
        DomainFile file = f.file();
        if (!file.isVersioned()) {
            return Response.err("File is not under version control: " + file.getPathname());
        }
        // Ghidra answers a second checkout with "Cannot checkout, private file exists", which
        // reads as a failure while the file is in fact checked out.
        if (file.isCheckedOut()) {
            Map<String, Object> extras = new LinkedHashMap<>();
            extras.put("exclusive", file.isCheckedOutExclusive());
            extras.putAll(rebindOpenCopies(file));
            return report("already_checked_out", true, file, extras);
        }
        if (file.isHijacked()) {
            return Response.err(file.getPathname() + " has a private local file at its path (a "
                + "hijacked file), so it cannot be checked out. Move or delete the local file first.");
        }
        try {
            boolean ok = file.checkout(exclusive, monitor);
            Map<String, Object> extras = new LinkedHashMap<>();
            extras.put("exclusive", exclusive);
            if (ok) {
                extras.putAll(rebindOpenCopies(file));
            }
            return report(ok ? "checked_out" : "checkout_failed", ok, file, extras);
        } catch (Exception e) {
            return Response.err("Checkout failed: " + messageOf(e));
        }
    }

    /**
     * Point open copies of {@code file} at its checkout. A program opened before the checkout
     * is an in-memory copy of the versioned file and stays one: it saves nowhere, so each save
     * fails with "Location does not exist for a save operation!". An unedited copy is closed
     * and reopened on the checkout. An edited one is left alone, because its edits cannot move
     * into the checkout, and the caller is told so rather than having them dropped.
     */
    private Map<String, Object> rebindOpenCopies(DomainFile file) {
        Map<String, Object> out = new LinkedHashMap<>();
        String path = file.getPathname();
        for (Program p : provider.getAllOpenPrograms()) {
            if (p.getDomainFile() == null || !p.getDomainFile().getPathname().equals(path)
                    || ProgramSaves.unsaveableReason(p) == null) {
                continue;
            }
            if (p.isChanged()) {
                out.put("reopen_required", true);
                out.put("open_copy", "The open copy of " + path + " has edits made before the "
                    + "checkout. They cannot be saved into it. Close it with save=false, open it "
                    + "again, and redo them.");
                return out;
            }
            if (!(provider instanceof ProjectProgramProvider projectProvider)) {
                out.put("reopen_required", true);
                out.put("open_copy", "Close and reopen " + path + " to edit the checkout.");
                return out;
            }
            provider.closeProgramByPath(path);
            try {
                projectProvider.openDomainFile(refreshed(file));
                out.put("reopened", true);
            } catch (Exception e) {
                out.put("reopen_required", true);
                out.put("open_copy", "Closed the copy opened before the checkout, but reopening "
                    + path + " failed: " + messageOf(e));
            }
            return out;
        }
        return out;
    }

    /**
     * Check a file in as a new version.
     *
     * <p>Pending edits on any open instance are saved to the local project first, and every
     * open instance is then closed, because checking in a file that is still open forces
     * {@code keepCheckedOut=true} whatever the handler says ("File currently open - must
     * keep checked-out"). The repository client's own {@code RepositoryAdapter} has no
     * checkin at all (#119), so this has to go through the project's {@link DomainFile}.
     *
     * @param path null or blank checks in the sole open program's file
     */
    public Response checkin(String path, String comment, boolean keepCheckedOut, boolean dryRun) {
        if (project() == null) return Response.err(NO_PROJECT);
        String cmt = comment == null ? "" : comment;

        String target = path;
        if (target == null || target.isBlank()) {
            Program current = provider.getCurrentProgram();
            if (current == null || current.getDomainFile() == null) {
                return Response.err("No sole open program; supply 'path'.");
            }
            target = current.getDomainFile().getPathname();
        }
        FileOrError f = file(target);
        if (f.hasError()) return Response.err(f.error());
        DomainFile file = f.file();
        String filePath = file.getPathname();

        if (!file.isVersioned()) {
            return Response.err("File is not under version control: " + filePath
                + " (add it first, or check out a versioned file)");
        }
        if (!file.isCheckedOut()) {
            return Response.err("File is not checked out: " + filePath);
        }

        if (dryRun) {
            List<String> wouldSave = new ArrayList<>();
            boolean open = false;
            for (Program p : provider.getAllOpenPrograms()) {
                if (p.getDomainFile() != null && p.getDomainFile().getPathname().equals(filePath)) {
                    open = true;
                    if (p.isChanged()) {
                        wouldSave.add(filePath);
                    }
                }
            }
            Map<String, Object> extras = new LinkedHashMap<>();
            extras.put("dry_run", true);
            extras.put("version", file.getVersion());
            extras.put("would_save", wouldSave);
            extras.put("would_close", open);
            extras.put("modified_since_checkout", file.modifiedSinceCheckout() || !wouldSave.isEmpty());
            extras.put("keep_checked_out", keepCheckedOut);
            extras.put("comment", cmt);
            return report("would_check_in", true, file, extras);
        }

        for (Program p : provider.getAllOpenPrograms()) {
            if (p.getDomainFile() != null && p.getDomainFile().getPathname().equals(filePath)
                    && !ProgramSaves.saveIfChanged(p, monitor)) {
                return Response.err("Save before checkin failed for " + filePath
                    + "; nothing was checked in (see the Ghidra log)");
            }
        }
        provider.closeProgramByPath(filePath);

        try {
            int before = file.getVersion();
            file.checkin(new CheckinHandler() {
                @Override public boolean keepCheckedOut() { return keepCheckedOut; }
                @Override public String getComment() { return cmt; }
                @Override public boolean createKeepFile() { return false; }
            }, monitor);
            int after = file.getVersion();
            Msg.info(this, "Checked in " + filePath + " (v" + before + " -> v" + after + ")");
            Map<String, Object> extras = new LinkedHashMap<>();
            extras.put("version_before", before);
            extras.put("version", after);
            extras.put("version_bumped", after > before);
            extras.put("comment", cmt);
            extras.put("keep_checked_out", keepCheckedOut);
            return report("checked_in", true, file, extras);
        } catch (Exception e) {
            Msg.error(this, "Checkin failed for " + filePath, e);
            return Response.err("Checkin failed (" + e.getClass().getSimpleName() + "): " + messageOf(e));
        }
    }

    /** Release a checkout. {@code keep} leaves the local copy behind as a private file. */
    public Response undoCheckout(String path, boolean keep) {
        FileOrError f = file(path);
        if (f.hasError()) return Response.err(f.error());
        if (!f.file().isCheckedOut()) {
            return Response.err("File is not checked out: " + f.file().getPathname());
        }
        try {
            f.file().undoCheckout(keep);
            return report("checkout_undone", true, f.file(), Map.of("kept_copy", keep));
        } catch (Exception e) {
            return Response.err("Undo checkout failed: " + messageOf(e));
        }
    }

    public Response addToVersionControl(String path, String comment, boolean keepCheckedOut) {
        FileOrError f = file(path);
        if (f.hasError()) return Response.err(f.error());
        if (f.file().isVersioned()) {
            return Response.err("File already under version control: " + f.file().getPathname());
        }
        String cmt = comment == null || comment.isBlank() ? "Added via GhidraMCP" : comment;
        // An open file is added checked out whatever keep_checked_out says, as with checkin.
        String filePath = f.file().getPathname();
        for (Program p : provider.getAllOpenPrograms()) {
            if (p.getDomainFile() != null && p.getDomainFile().getPathname().equals(filePath)
                    && !ProgramSaves.saveIfChanged(p, monitor)) {
                return Response.err("Save before adding failed for " + filePath
                    + "; nothing was added (see the Ghidra log)");
            }
        }
        boolean closed = provider.closeProgramByPath(filePath);
        try {
            f.file().addToVersionControl(cmt, keepCheckedOut, monitor);
            Map<String, Object> extras = new LinkedHashMap<>();
            extras.put("comment", cmt);
            extras.put("keep_checked_out", keepCheckedOut);
            extras.put("closed", closed);
            return report("added", true, f.file(), extras);
        } catch (Exception e) {
            return Response.err("Add to version control failed: " + messageOf(e));
        }
    }

    public Response versionHistory(String path) {
        FileOrError f = file(path);
        if (f.hasError()) return Response.err(f.error());
        if (!f.file().isVersioned()) {
            return Response.err("File is not under version control: " + f.file().getPathname());
        }
        try {
            List<Map<String, Object>> versions = new ArrayList<>();
            for (Version v : f.file().getVersionHistory()) {
                Map<String, Object> row = new LinkedHashMap<>();
                row.put("version", v.getVersion());
                row.put("user", v.getUser());
                row.put("comment", v.getComment() != null ? v.getComment() : "");
                row.put("created", Instant.ofEpochMilli(v.getCreateTime()).toString());
                row.put("create_time_ms", v.getCreateTime());
                versions.add(row);
            }
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("path", f.file().getPathname());
            out.put("versions", versions);
            out.put("count", versions.size());
            return Response.ok(out);
        } catch (Exception e) {
            return Response.err("Failed to get version history: " + messageOf(e));
        }
    }

    /**
     * What is checked out, locally or on the server, under a file or folder. Files outside
     * this server's project-folder scope are left out rather than reported.
     */
    public Response checkouts(String path) {
        Project project = project();
        if (project == null) return Response.err(NO_PROJECT);
        String at = path == null || path.isBlank() ? "/" : path.trim();
        ProjectData data = project.getProjectData();

        List<Map<String, Object>> rows = new ArrayList<>();
        DomainFile single = "/".equals(at) ? null : data.getFile(at);
        if (single != null) {
            FileOrError f = file(at);
            if (f.hasError()) return Response.err(f.error());
            collect(f.file(), repository(), rows);
        } else {
            DomainFolder folder = "/".equals(at) ? data.getRootFolder() : data.getFolder(at);
            if (folder == null) return Response.err("Folder not found: " + at);
            collect(folder, repository(), rows);
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("checkouts", rows);
        out.put("count", rows.size());
        return Response.ok(out);
    }

    private static void collect(DomainFolder folder, RepositoryAdapter repo, List<Map<String, Object>> rows) {
        for (DomainFile f : folder.getFiles()) {
            collect(f, repo, rows);
        }
        for (DomainFolder sub : folder.getFolders()) {
            collect(sub, repo, rows);
        }
    }

    private static void collect(DomainFile f, RepositoryAdapter repo, List<Map<String, Object>> rows) {
        if (!SecurityConfig.getInstance().isPathInProjectScope(f.getPathname())) {
            return;
        }
        ItemCheckoutStatus[] server = null;
        if (repo != null && f.isVersioned()) {
            try {
                server = repo.getCheckouts(parentOf(f.getPathname()), f.getName());
            } catch (Exception e) {
                // A file that disappears mid-walk, or a server that rejects the query,
                // is left out of the report rather than failing it.
            }
        }
        boolean onServer = server != null && server.length > 0;
        if (!f.isCheckedOut() && !onServer) {
            return;
        }
        Map<String, Object> row = fileState(f);
        if (onServer) {
            List<Map<String, Object>> holders = new ArrayList<>();
            for (ItemCheckoutStatus cs : server) {
                Map<String, Object> h = new LinkedHashMap<>();
                h.put("checkout_id", cs.getCheckoutId());
                h.put("user", cs.getUser());
                h.put("project_name", cs.getProjectName());
                h.put("checkout_version", cs.getCheckoutVersion());
                holders.add(h);
            }
            row.put("server_checkouts", holders);
        }
        rows.add(row);
    }

    /**
     * Force-release checkouts on one file: a single one by id, or, without an id, this
     * project's own checkout first and then every server checkout of the file.
     */
    public Response terminateCheckout(String path, Long checkoutId) {
        FileOrError f = file(path);
        if (f.hasError()) return Response.err(f.error());
        DomainFile file = f.file();
        String filePath = file.getPathname();
        RepositoryAdapter repo = repository();

        if (checkoutId != null) {
            if (repo == null) {
                return Response.err("Cannot terminate checkout: project has no repository connection");
            }
            try {
                repo.terminateCheckout(parentOf(filePath), nameOf(filePath), checkoutId, false);
                Map<String, Object> out = new LinkedHashMap<>();
                out.put("status", "checkout_terminated");
                out.put("path", filePath);
                out.put("checkout_id", checkoutId);
                return Response.ok(out);
            } catch (Exception e) {
                return Response.err("Terminate checkout failed: " + messageOf(e));
            }
        }

        if (file.isCheckedOut()) {
            try {
                file.undoCheckout(false, true);
                return Response.ok(Map.of("status", "terminated", "path", filePath,
                    "method", "undo_checkout_force"));
            } catch (Exception e) {
                // fall through to the server-side route
            }
        }
        if (repo == null) {
            return Response.err("Cannot terminate checkout: project has no repository connection");
        }
        try {
            ItemCheckoutStatus[] held = repo.getCheckouts(parentOf(filePath), nameOf(filePath));
            if (held == null || held.length == 0) {
                return Response.err("No active checkouts found for: " + filePath);
            }
            int terminated = terminateAll(repo, filePath, held);
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("status", "terminated");
            out.put("path", filePath);
            out.put("terminated_count", terminated);
            out.put("total_checkouts", held.length);
            return Response.ok(out);
        } catch (Exception e) {
            return Response.err("Terminate checkout failed: " + messageOf(e));
        }
    }

    /** Force-release every server checkout under a folder, recursively, reporting partial progress. */
    public Response terminateAllCheckouts(String folderPath) {
        Project project = project();
        if (project == null) return Response.err(NO_PROJECT);
        RepositoryAdapter repo = repository();
        if (repo == null) {
            return Response.err("Cannot terminate checkouts: project has no repository connection");
        }
        String at = folderPath == null || folderPath.isBlank() ? "/" : folderPath.trim();
        ProjectData data = project.getProjectData();
        DomainFolder folder = "/".equals(at) ? data.getRootFolder() : data.getFolder(at);
        if (folder == null) return Response.err("Folder not found: " + at);

        List<Map<String, Object>> details = new ArrayList<>();
        int[] totals = {0};
        terminateUnder(folder, repo, details, totals);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("status", "terminated");
        out.put("folder", at);
        out.put("files_with_checkouts", details.size());
        out.put("checkouts_terminated", totals[0]);
        out.put("details", details);
        return Response.ok(out);
    }

    private static void terminateUnder(DomainFolder folder, RepositoryAdapter repo,
            List<Map<String, Object>> details, int[] totals) {
        for (DomainFile f : folder.getFiles()) {
            if (!f.isVersioned() || !SecurityConfig.getInstance().isPathInProjectScope(f.getPathname())) {
                continue;
            }
            try {
                ItemCheckoutStatus[] held = repo.getCheckouts(parentOf(f.getPathname()), f.getName());
                if (held == null || held.length == 0) {
                    continue;
                }
                int terminated = terminateAll(repo, f.getPathname(), held);
                Map<String, Object> row = new LinkedHashMap<>();
                row.put("path", f.getPathname());
                row.put("terminated", terminated);
                row.put("total", held.length);
                details.add(row);
                totals[0] += terminated;
            } catch (Exception e) {
                // a file that disappears or rejects the query mid-walk is skipped
            }
        }
        for (DomainFolder sub : folder.getFolders()) {
            terminateUnder(sub, repo, details, totals);
        }
    }

    private static int terminateAll(RepositoryAdapter repo, String filePath, ItemCheckoutStatus[] held) {
        int terminated = 0;
        for (ItemCheckoutStatus cs : held) {
            try {
                repo.terminateCheckout(parentOf(filePath), nameOf(filePath), cs.getCheckoutId(), false);
                terminated++;
            } catch (Exception e) {
                // keep going: report how many landed
            }
        }
        return terminated;
    }
}
