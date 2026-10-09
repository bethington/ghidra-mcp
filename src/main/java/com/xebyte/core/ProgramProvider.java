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

import ghidra.program.model.listing.Program;

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
     * Release this provider's handle on a program it holds.
     *
     * @param program The program to close
     * @param save    save unsaved changes first; false discards them
     * @return true if the provider held the program and released it
     */
    default boolean closeProgram(Program program, boolean save) {
        return false;
    }

    /**
     * Check if any program is currently open.
     *
     * @return true if at least one program is open
     */
    default boolean hasOpenProgram() {
        return getCurrentProgram() != null;
    }

    /**
     * Get the project this provider is serving programs from.
     *
     * <p>GUI providers reach the project through their PluginTool, so the
     * default is null and callers fall back to the tool. Headless providers
     * own a Project directly and should override this — without it, project
     * -level tools (move/create/delete) would be GUI-only, which is exactly
     * the regression that converting {@code /move_file} to an {@code @McpTool}
     * would otherwise have introduced.
     *
     * @return The active project, or null if this provider has no direct handle
     */
    default ghidra.framework.model.Project getProject() {
        return null;
    }

    /**
     * The analyst's windows (running CodeBrowsers and their program managers), when there
     * are any. Headless has none and returns null, which is how GUI-only operations detect
     * that they cannot run.
     *
     * @return The workbench, or null when running headless
     */
    default Workbench workbench() {
        return null;
    }

    /**
     * A ProgramManager from an open CodeBrowser, when one is running.
     *
     * <p>Distinct from walking the tool's own services: the FrontEnd tool has
     * no ProgramManager, so a provider that can see CodeBrowsers answers here
     * and spares the caller a second discovery pass.
     *
     * @return A ProgramManager, or null when none is reachable
     */
    default ghidra.app.services.ProgramManager findProgramManager() {
        return null;
    }

    /**
     * Close whatever is open for this project path, in whichever window holds it.
     *
     * <p>By project path rather than name on purpose — the caller is about to
     * move or delete that DomainFile, and a name match would also close its
     * namesakes.
     *
     * @param path The DomainFile path to close
     * @return true if something was closed
     */
    default boolean closeProgramByPath(String path) {
        return false;
    }

    /**
     * Drop any handle this provider is holding for {@code nameOrPath}.
     *
     * <p>For providers that cache programs they opened themselves. A cached
     * handle outlives the window that showed it, so closing in the GUI is not
     * enough to release the file.
     *
     * @param nameOrPath Program name or project path
     * @param save       save unsaved changes first; false discards them -- a close
     *                   that was asked to discard must not have its edits saved on
     *                   the way out by a cached handle
     * @return true if a cached handle was released
     */
    default boolean releaseCachedProgram(String nameOrPath, boolean save) {
        return false;
    }

    /**
     * Resolve a program by name, or the current program when {@code name} is
     * null or empty.
     *
     * <p>A non-blank name that misses must return null — falling back to the
     * current program made a typo (or a closed program) silently operate on
     * the wrong binary. Callers that need a hard error on miss should use
     * {@link ServiceUtils#getProgramOrError}.
     *
     * @param name The program name (may be null)
     * @return The resolved program, or null when a non-blank name misses
     */
    default Program resolveProgram(String name) {
        if (name == null || name.isEmpty()) {
            return getCurrentProgram();
        }
        return getProgram(name);
    }
}
