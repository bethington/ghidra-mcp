package com.xebyte.core;

import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectData;

/**
 * One resolver for Ghidra project (domain) paths: normalize, parent/name, file and folder
 * lookup with {@code project.folder_scope}.
 *
 * <p>Domain paths use {@code '/'} only — a backslash is a literal character in a folder or
 * file name, never a separator. Every caller-supplied path that reaches
 * {@code ProjectData.getFile}/{@code getFolder} goes through here so slash policy, {@code ..}
 * rejection and folder scope cannot drift between tools.
 */
public final class ProjectPaths {

    private ProjectPaths() {}

    /**
     * Trim, ensure one leading {@code '/'}, collapse repeated slashes, strip a trailing slash
     * (except root). Rejects blank input and any {@code '.'} or {@code '..'} segment.
     */
    public static String normalize(String path) {
        if (path == null || path.isBlank()) {
            throw new Refusal("path is required");
        }
        String trimmed = path.trim();
        String withSlash = trimmed.startsWith("/") ? trimmed : "/" + trimmed;
        StringBuilder out = new StringBuilder();
        for (String part : withSlash.split("/", -1)) {
            if (part.isEmpty()) {
                continue;
            }
            if (".".equals(part) || "..".equals(part)) {
                // Name the caller-supplied path so refusals are diagnosable.
                throw new Refusal("Invalid project path: " + trimmed);
            }
            out.append('/').append(part);
        }
        return out.length() == 0 ? "/" : out.toString();
    }

    /** Parent folder of a normalized path; {@code "/"} for a top-level name or root. */
    public static String parentOf(String path) {
        int slash = path.lastIndexOf('/');
        return slash > 0 ? path.substring(0, slash) : "/";
    }

    /** Final segment of a normalized path; empty for root. */
    public static String nameOf(String path) {
        return path.substring(path.lastIndexOf('/') + 1);
    }

    /**
     * The project file at {@code path}, after normalize and folder-scope check.
     *
     * @throws Refusal when the path is invalid, out of scope, or no file exists there
     */
    public static DomainFile file(Project project, String path) {
        DomainFile file = findFile(project, path);
        if (file == null) {
            throw new Refusal("No file at " + normalize(path));
        }
        return file;
    }

    /** As {@link #file}, but null when no file exists there (invalid or out-of-scope paths still refuse). */
    public static DomainFile findFile(Project project, String path) {
        requireProject(project);
        String normalized = normalize(path);
        requireInScope(normalized);
        return project.getProjectData().getFile(normalized);
    }

    /**
     * A file for the operator's own tools (the settings CLI): normalized like every other
     * path, but not held to {@code project.folder_scope}, which bounds what agents reach.
     */
    public static DomainFile operatorFile(Project project, String path) {
        requireProject(project);
        String normalized = normalize(path);
        DomainFile file = project.getProjectData().getFile(normalized);
        if (file == null) {
            throw new Refusal("No file at " + normalized);
        }
        return file;
    }

    /**
     * A folder to list: in scope, or an ancestor of the scope so a caller can walk down to it.
     * Pair with {@link #visible}: from an ancestor only the branch toward the scope shows.
     */
    public static DomainFolder listable(Project project, String path) {
        requireProject(project);
        String normalized = normalize(path == null || path.isBlank() ? "/" : path);
        if (!visible(normalized)) {
            requireInScope(normalized);
        }
        DomainFolder folder = "/".equals(normalized)
            ? project.getProjectData().getRootFolder()
            : project.getProjectData().getFolder(normalized);
        if (folder == null) {
            throw new Refusal("No folder at " + normalized);
        }
        return folder;
    }

    /** True when {@code normalized} is inside the scope or a folder on the way to it. */
    public static boolean visible(String normalized) {
        String scope = SecurityConfig.getInstance().getProjectFolderScope();
        if (scope == null || SecurityConfig.pathWithinScope(normalized, scope)) {
            return true;
        }
        return "/".equals(normalized) || scope.startsWith(normalized + "/");
    }

    private static void requireProject(Project project) {
        if (project == null) {
            throw new Refusal("No project open. Call /open_project first.");
        }
    }

    /**
     * The project folder at {@code path}, after normalize and folder-scope check.
     * Blank/{@code null} means root. When {@code createMissing} is true, intermediate
     * folders are created (segments already validated by {@link #normalize}).
     *
     * @throws Refusal when the path is invalid, out of scope, missing (and not creating),
     *         or creation fails
     */
    public static DomainFolder folder(Project project, String path, boolean createMissing) {
        requireProject(project);
        String normalized = normalize(path == null || path.isBlank() ? "/" : path);
        requireInScope(normalized);
        ProjectData data = project.getProjectData();
        if ("/".equals(normalized)) {
            return data.getRootFolder();
        }
        DomainFolder existing = data.getFolder(normalized);
        if (existing != null) {
            return existing;
        }
        if (!createMissing) {
            throw new Refusal("No folder at " + normalized);
        }
        try {
            DomainFolder cur = data.getRootFolder();
            for (String part : normalized.substring(1).split("/")) {
                DomainFolder next = cur.getFolder(part);
                if (next == null) {
                    next = cur.createFolder(part);
                }
                cur = next;
            }
            return cur;
        } catch (Exception e) {
            throw new Refusal("Could not create folder " + normalized + ": "
                + ServiceUtils.failureMessage(e));
        }
    }

    /** Same refusal text {@link ProjectVersionControl} used for out-of-scope paths. */
    static void requireInScope(String normalizedPath) {
        if (!SecurityConfig.getInstance().isPathInProjectScope(normalizedPath)) {
            throw new Refusal(
                "Path is outside this server's project-folder scope: " + normalizedPath);
        }
    }
}
