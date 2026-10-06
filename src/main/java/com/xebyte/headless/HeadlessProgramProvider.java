/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.xebyte.headless;

import com.xebyte.core.ProjectProgramProvider;
import ghidra.base.project.GhidraProject;
import ghidra.framework.client.RepositoryAdapter;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectData;
import ghidra.framework.model.ProjectLocator;
import ghidra.framework.model.ProjectManager;
import ghidra.framework.project.DefaultProjectManager;
import ghidra.framework.store.LockException;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Headless mode implementation of ProgramProvider.
 *
 * Manages programs directly without relying on GUI services like ProgramManager.
 * Programs can be loaded from files or Ghidra project folders.
 */
public class HeadlessProgramProvider extends ProjectProgramProvider {

    private Project project;
    private GhidraProject ghidraProject;  // For headless project management

    /**
     * Create a new HeadlessProgramProvider.
     */
    public HeadlessProgramProvider() {
        // okToUpgrade: headless may upgrade a program's stored format on open. The GUI
        // may not -- an upgrade needs an exclusive checkout it must not take silently.
        super(null, true);
    }

    @Override
    protected Project project() {
        return project;
    }

    /**
     * Create a HeadlessProgramProvider with an existing Ghidra project.
     *
     * @param project The Ghidra project to use
     */
    public HeadlessProgramProvider(Project project) {
        this();
        this.project = project;
    }

    @Override
    public Program getCurrentProgram() {
        // Headless has no GUI focus. Exactly one open program is unambiguous;
        // zero or many leaves nothing honest to return — inventing sticky
        // "current" state is what made a 17-program survey return one binary's
        // numbers seventeen times (headless never reassigned after the first load,
        // and /switch_program is not even registered headless).
        Program[] open = getAllOpenPrograms();
        return (open != null && open.length == 1) ? open[0] : null;
    }

    @Override
    public void setCurrentProgram(Program program) {
        // Explicit no-op: headless has no current-program concept. GUI providers
        // implement this against ProgramManager / CodeBrowser focus; pretending
        // here would reintroduce sticky omit-program state with no way to steer it.
    }

    /**
     * Get the current project.
     *
     * <p>Also satisfies {@link ProgramProvider#getProject()}, which is how the
     * shared {@code @McpTool} project endpoints in {@code com.xebyte.core}
     * reach ProjectData without a PluginTool. Keep it public and keep the
     * signature — dropping it would silently make {@code /move_file},
     * {@code /move_folder} and friends GUI-only again.
     *
     * @return The current project, or null if none set
     */
    @Override
    public Project getProject() {
        return project;
    }

    /**
     * Result of {@link #openProject(String, GhidraServerManager)}. Structured so a
     * malformed {@code ghidra://} URL surfaces as an error instead of a boolean
     * false that looked like "file not found".
     */
    public static final class OpenProjectResult {
        public final boolean success;
        public final String error;
        public final String projectName;
        public final boolean shared;
        public final String repository;
        public final String localProjectDir;

        private OpenProjectResult(boolean success, String error, String projectName,
                                  boolean shared, String repository, String localProjectDir) {
            this.success = success;
            this.error = error;
            this.projectName = projectName;
            this.shared = shared;
            this.repository = repository;
            this.localProjectDir = localProjectDir;
        }

        public static OpenProjectResult ok(String projectName, boolean shared,
                                           String repository, String localProjectDir) {
            return new OpenProjectResult(true, null, projectName, shared, repository, localProjectDir);
        }

        public static OpenProjectResult fail(String error) {
            return new OpenProjectResult(false, error, null, false, null, null);
        }
    }

    /**
     * Open a local {@code .gpr} or a shared Ghidra Server repository URL.
     *
     * <p>When {@code projectPath} is a {@code ghidra://} URL, opens (or creates)
     * a persistent shared project bound to that repository. A plain filesystem
     * path keeps the pre-existing local {@code .gpr} behaviour exactly.
     *
     * @param projectPath {@code .gpr}/directory path, or {@code ghidra://host[:port]/repo}
     * @param serverManager required for URL opens (connected adapter + credentials)
     */
    public OpenProjectResult openProject(String projectPath, GhidraServerManager serverManager) {
        if (projectPath == null || projectPath.isBlank()) {
            return OpenProjectResult.fail("Project path required");
        }
        // Any ghidra: string must parse as a server URL or fail — never fall
        // through to the local .gpr branch (that would mkdir a project named
        // after the URL string).
        if (SharedProjectLocator.isGhidraUrl(projectPath)) {
            return openSharedProject(projectPath.trim(), serverManager);
        }
        return openLocalProject(projectPath.trim());
    }

    /**
     * Open a Ghidra project from a .gpr file path (local-only).
     *
     * @param projectPath Path to the .gpr file (e.g., "/projects/MyProject.gpr")
     * @return true if project was opened successfully
     */
    public boolean openProject(String projectPath) {
        return openProject(projectPath, null).success;
    }

    private OpenProjectResult openLocalProject(String projectPath) {
        try {
            File projectFile = new File(projectPath);

            // Handle both .gpr file path and directory path
            File projectDir;
            String projectName;

            if (projectPath.endsWith(".gpr")) {
                projectDir = projectFile.getParentFile();
                projectName = projectFile.getName().replace(".gpr", "");
            } else {
                // Assume it's a directory containing the project
                projectDir = projectFile;
                // Look for .gpr file in the directory
                File[] gprFiles = projectDir.listFiles((dir, name) -> name.endsWith(".gpr"));
                if (gprFiles == null || gprFiles.length == 0) {
                    Msg.error(this, "No .gpr file found in: " + projectPath);
                    return OpenProjectResult.fail("No .gpr file found in: " + projectPath);
                }
                projectName = gprFiles[0].getName().replace(".gpr", "");
            }

            if (!projectDir.exists()) {
                Msg.error(this, "Project directory not found: " + projectDir.getAbsolutePath());
                return OpenProjectResult.fail(
                        "Project directory not found: " + projectDir.getAbsolutePath());
            }

            // Close existing project if any
            if (project != null) {
                closeProject();
            }

            // Go through the low-level ProjectManager so we can pass
            // resetOwner=true. GhidraProject.openProject(..., restore=true) only
            // toggles restoreDefault and hard-codes resetOwner=false, leaving
            // project.prp pinned to whichever username originally created the
            // project. That breaks .tar.gz round-trips between hosts (or between
            // a container running as root and a standalone Ghidra GUI). With
            // resetOwner=true, project.prp is rewritten to the current user on
            // every open.
            ProjectLocator locator = new ProjectLocator(projectDir.getAbsolutePath(), projectName);
            ProjectManager pm = new HeadlessProjectManager();
            ghidraProject = null;
            project = pm.openProject(locator, /*restoreDefault*/ true, /*resetOwner*/ true);

            if (project != null) {
                Msg.info(this, "Opened project: " + projectName + " from " + projectDir.getAbsolutePath());
                return OpenProjectResult.ok(projectName, false, null, projectDir.getAbsolutePath());
            }
            Msg.error(this, "Failed to open project: " + projectPath);
            return OpenProjectResult.fail("Failed to open project: " + projectPath);
        } catch (LockException e) {
            // Two JVMs cannot share one project dir — fail loud, don't corrupt.
            Msg.error(this, "Project locked (another Ghidra instance holds it): " + projectPath, e);
            return OpenProjectResult.fail(
                    "Project locked by another Ghidra instance: " + e.getMessage());
        } catch (Exception e) {
            Msg.error(this, "Error opening project: " + projectPath, e);
            return OpenProjectResult.fail(
                    "Error opening project: " + e.getMessage());
        }
    }

    /**
     * Open-or-create a shared project bound to a Ghidra Server repository.
     *
     * <p>Same door as local open: the agent writes, so we need a real local
     * {@code .rep} for working copies — not a transient URL view.
     */
    private OpenProjectResult openSharedProject(String ghidraUrl, GhidraServerManager serverManager) {
        if (serverManager == null) {
            return OpenProjectResult.fail(
                    "Opening a ghidra:// URL requires the headless server manager "
                            + "(credentials via GHIDRA_SERVER_USER/PASSWORD, then /server/connect)");
        }

        final SharedProjectLocator.Parsed parsed;
        try {
            parsed = SharedProjectLocator.parseServerUrl(ghidraUrl);
        } catch (IllegalArgumentException e) {
            return OpenProjectResult.fail(e.getMessage());
        }

        final Path projectParent;
        try {
            projectParent = SharedProjectLocator.resolveProjectDir(parsed);
            Files.createDirectories(projectParent);
        } catch (IllegalArgumentException e) {
            return OpenProjectResult.fail(e.getMessage());
        } catch (Exception e) {
            return OpenProjectResult.fail(
                    "Cannot create shared project directory: " + e.getMessage());
        }

        final RepositoryAdapter repo;
        try {
            serverManager.ensureConnectedTo(parsed.host(), parsed.port());
            repo = serverManager.openRepository(parsed.repo());
            if (repo == null) {
                return OpenProjectResult.fail("Repository not found: " + parsed.repo());
            }
        } catch (Exception e) {
            return OpenProjectResult.fail(
                    "Server connection failed for " + parsed.host() + ":" + parsed.port()
                            + ": " + e.getMessage());
        }

        if (project != null) {
            closeProject();
        }

        // Parent is keyed by host_port_repo; project name stays the repo name
        // so DomainFile paths match what analyzeHeadless imported.
        ProjectLocator locator =
                new ProjectLocator(projectParent.toAbsolutePath().toString(), parsed.repo());
        ProjectManager pm = new HeadlessProjectManager();
        ghidraProject = null;

        try {
            if (locator.exists() || pm.projectExists(locator)) {
                project = pm.openProject(locator, /*restoreDefault*/ true, /*resetOwner*/ true);
                Msg.info(this, "Opened shared project '" + parsed.repo()
                        + "' from " + projectParent);
            } else {
                // false = durable project (GUI "New Shared Project"), not transient.
                project = pm.createProject(locator, repo, false);
                Msg.info(this, "Created shared project '" + parsed.repo()
                        + "' at " + projectParent);
            }
        } catch (LockException e) {
            return OpenProjectResult.fail(
                    "Shared project directory locked by another Ghidra instance at "
                            + projectParent + ": " + e.getMessage()
                            + " (each JVM needs its own GHIDRA_MCP_SHARED_PROJECT_DIR)");
        } catch (Exception e) {
            Msg.error(this, "Failed to open/create shared project for " + ghidraUrl, e);
            return OpenProjectResult.fail(
                    "Failed to open/create shared project: " + e.getMessage());
        }

        if (project == null) {
            return OpenProjectResult.fail("ProjectManager returned null for " + ghidraUrl);
        }
        return OpenProjectResult.ok(
                parsed.repo(), true, parsed.repo(), projectParent.toAbsolutePath().toString());
    }

    /**
     * Close the current project.
     */
    public void closeProject() {
        if (ghidraProject != null) {
            try {
                // Close all programs from this project first
                releaseAll();
                ghidraProject.close();
                Msg.info(this, "Closed project");
            } catch (Exception e) {
                Msg.warn(this, "Error closing project: " + e.getMessage());
            }
            ghidraProject = null;
            project = null;
        } else if (project != null) {
            try {
                releaseAll();
                project.close();
                Msg.info(this, "Closed project");
            } catch (Exception e) {
                Msg.warn(this, "Error closing project: " + e.getMessage());
            }
            project = null;
        }
    }

    /**
     * Check if a project is currently open.
     *
     * @return true if a project is open
     */
    public boolean hasProject() {
        return project != null;
    }

    /**
     * Get the name of the current project.
     *
     * @return Project name or null if no project is open
     */
    public String getProjectName() {
        return project != null ? project.getName() : null;
    }

    /**
     * Creates a new Ghidra project.
     *
     * @param parentDir The parent directory for the new project
     * @param name The name of the new project
     * @return true if the project was created successfully
     */
    public boolean createProject(String parentDir, String name) {
        try {
            File dir = new File(parentDir);
            if (!dir.exists()) {
                Msg.error(this, "Parent directory not found: " + parentDir);
                return false;
            }
            if (project != null) {
                closeProject();
            }
            ghidraProject = GhidraProject.createProject(parentDir, name, false);
            project = ghidraProject.getProject();
            Msg.info(this, "Created project: " + name + " in " + parentDir);
            return project != null;
        } catch (Exception e) {
            Msg.error(this, "Error creating project: " + e.getMessage(), e);
            return false;
        }
    }

    /**
     * Deletes a Ghidra project by path.
     *
     * @param projectPath Path to the .gpr file or project directory
     * @return true if the project was deleted successfully
     */
    public boolean deleteProject(String projectPath) {
        try {
            File projectFile = new File(projectPath);
            File projectDir;
            String projectName;
            if (projectPath.endsWith(".gpr")) {
                projectDir = projectFile.getParentFile();
                projectName = projectFile.getName().replace(".gpr", "");
            } else {
                projectDir = projectFile.getParentFile() != null ? projectFile.getParentFile() : projectFile;
                projectName = projectFile.getName();
            }
            // Close if this is the currently open project
            if (project != null && projectName.equals(project.getName())) {
                closeProject();
            }
            ghidra.framework.model.ProjectLocator locator =
                new ghidra.framework.model.ProjectLocator(projectDir.getAbsolutePath(), projectName);
            // Delete project files (marker file + project directory)
            java.io.File markerFile = locator.getMarkerFile();
            java.io.File projectDirFile = locator.getProjectDir();
            if (markerFile.exists()) markerFile.delete();
            deleteRecursive(projectDirFile);
            Msg.info(this, "Deleted project: " + projectName);
            return true;
        } catch (Exception e) {
            Msg.error(this, "Error deleting project: " + e.getMessage(), e);
            return false;
        }
    }

    /**
     * Scan a directory for .gpr files and return a list of ProjectInfo objects.
     *
     * @param searchDir The directory to search, or null/empty for the user home directory
     * @return List of ProjectInfo objects representing found projects
     */
    public List<ProjectInfo> listProjects(String searchDir) {
        List<ProjectInfo> result = new ArrayList<>();
        try {
            File dir = searchDir != null && !searchDir.isEmpty() ? new File(searchDir) : new File(System.getProperty("user.home"));
            if (!dir.exists() || !dir.isDirectory()) {
                return result;
            }
            scanForProjects(dir, result, 0, 3);
        } catch (Exception e) {
            Msg.error(this, "Error listing projects: " + e.getMessage(), e);
        }
        return result;
    }

    private void scanForProjects(File dir, List<ProjectInfo> result, int depth, int maxDepth) {
        if (depth > maxDepth) return;
        File[] files = dir.listFiles();
        if (files == null) return;
        for (File f : files) {
            if (f.isFile() && f.getName().endsWith(".gpr")) {
                String name = f.getName().replace(".gpr", "");
                boolean active = project != null && name.equals(project.getName());
                result.add(new ProjectInfo(name, f.getAbsolutePath(), active));
            } else if (f.isDirectory() && depth < maxDepth) {
                scanForProjects(f, result, depth + 1, maxDepth);
            }
        }
    }

    /**
     * Information about a Ghidra project found on disk.
     */
    public static class ProjectInfo {
        public final String name;
        public final String path;
        public final boolean active;

        public ProjectInfo(String name, String path, boolean active) {
            this.name = name;
            this.path = path;
            this.active = active;
        }
    }

    private void deleteRecursive(java.io.File f) {
        if (f == null || !f.exists()) return;
        if (f.isDirectory()) {
            java.io.File[] children = f.listFiles();
            if (children != null) for (java.io.File child : children) deleteRecursive(child);
        }
        f.delete();
    }

    /**
     * Concrete handle on {@link DefaultProjectManager} \u2014 its constructor is
     * protected so we cannot instantiate it directly. Mirrors the inner class
     * used by Ghidra's own headless analyzer.
     */
    private static final class HeadlessProjectManager extends DefaultProjectManager {
        HeadlessProjectManager() {
            super();
        }
    }
}
