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
}
