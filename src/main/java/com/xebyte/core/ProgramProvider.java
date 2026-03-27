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
package com.xebyte.core;

import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectData;
import ghidra.program.model.listing.Program;

import java.util.ArrayList;
import java.util.List;

/**
 * Interface for providing access to Ghidra programs.
 *
 * This abstraction allows the MCP core to work in both GUI mode
 * (via ProgramManager) and headless mode (via direct program management).
 */
public interface ProgramProvider {

    /**
     * Get the currently active program.
     *
     * @return The current program, or null if no program is open
     */
    Program getCurrentProgram();

    /**
     * Get a program by its name.
     *
     * @param name The program name to look up
     * @return The matching program, or null if not found
     */
    Program getProgram(String name);

    /**
     * Get all currently open programs.
     *
     * @return Array of all open programs (may be empty, never null)
     */
    Program[] getAllOpenPrograms();

    /**
     * Set the current program.
     *
     * @param program The program to make current
     */
    void setCurrentProgram(Program program);

    /**
     * Check if any program is currently open.
     *
     * @return true if at least one program is open
     */
    default boolean hasOpenProgram() {
        return getCurrentProgram() != null;
    }

    /**
     * Get a program by name, falling back to current program if name is null or empty.
     *
     * @param name The program name (may be null)
     * @return The resolved program
     */
    default Program resolveProgram(String name) {
        if (name == null || name.isEmpty()) {
            return getCurrentProgram();
        }
        Program program = getProgram(name);
        return program != null ? program : getCurrentProgram();
    }

    // ========================================================================
    // Project-level operations
    // ========================================================================

    /**
     * Get the underlying Ghidra project, if available.
     *
     * @return The current project, or null if no project is available
     */
    default Project getProject() {
        return null;
    }

    /**
     * List files in a project folder.
     * Default implementation uses {@link #getProject()} and shared folder navigation.
     *
     * @param folderPath The folder path to list, or null/empty for root
     * @return Listing of folders and files, or null if no project or folder not found
     */
    default ProjectFileListing listProjectFiles(String folderPath) {
        return buildFileListing(getProject(), folderPath);
    }

    /**
     * Open a program from the current project by path or name.
     *
     * @param path The project path or name of the program to open
     * @return The opened program, or null if not found or no project available
     */
    default Program openFromProject(String path) {
        return null;
    }

    // ========================================================================
    // Project data classes
    // ========================================================================

    /**
     * A single file entry in a project listing.
     */
    class ProjectFileEntry {
        public final String name;
        public final String path;
        public final String contentType;
        public final int version;
        public final boolean readOnly;
        public final boolean versioned;

        public ProjectFileEntry(String name, String path, String contentType,
                                int version, boolean readOnly, boolean versioned) {
            this.name = name;
            this.path = path;
            this.contentType = contentType;
            this.version = version;
            this.readOnly = readOnly;
            this.versioned = versioned;
        }
    }

    /**
     * Result of listing a project folder, including subfolders and files.
     */
    class ProjectFileListing {
        public final String projectName;
        public final String currentFolder;
        public final List<String> folders;
        public final List<ProjectFileEntry> files;

        public ProjectFileListing(String projectName, String currentFolder,
                                  List<String> folders, List<ProjectFileEntry> files) {
            this.projectName = projectName;
            this.currentFolder = currentFolder;
            this.folders = folders;
            this.files = files;
        }
    }

    /**
     * Shared helper to build a file listing from a Ghidra project.
     * Navigates to the specified folder and enumerates its contents.
     *
     * @param project The Ghidra project
     * @param folderPath Folder path to list, or null/empty for root
     * @return Listing, or null if project is null or folder not found
     */
    static ProjectFileListing buildFileListing(Project project, String folderPath) {
        if (project == null) {
            return null;
        }

        ProjectData projectData = project.getProjectData();
        DomainFolder rootFolder = projectData.getRootFolder();

        DomainFolder targetFolder = rootFolder;
        if (folderPath != null && !folderPath.trim().isEmpty() && !folderPath.equals("/")) {
            String cleanPath = folderPath.startsWith("/") ? folderPath.substring(1) : folderPath;
            String[] pathParts = cleanPath.split("/");
            for (String part : pathParts) {
                if (part.isEmpty()) continue;
                DomainFolder nextFolder = targetFolder.getFolder(part);
                if (nextFolder == null) {
                    return null; // folder not found
                }
                targetFolder = nextFolder;
            }
        }

        List<String> folderNames = new ArrayList<>();
        for (DomainFolder subfolder : targetFolder.getFolders()) {
            folderNames.add(subfolder.getName());
        }

        List<ProjectFileEntry> files = new ArrayList<>();
        for (DomainFile file : targetFolder.getFiles()) {
            files.add(new ProjectFileEntry(
                file.getName(), file.getPathname(), file.getContentType(),
                file.getVersion(), file.isReadOnly(), file.isVersioned()
            ));
        }

        return new ProjectFileListing(
            project.getName(), targetFolder.getPathname(), folderNames, files
        );
    }
}
