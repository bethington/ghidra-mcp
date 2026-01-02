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

import java.util.concurrent.Callable;
import java.util.function.Supplier;

/**
 * Interface for executing code with proper threading and transaction handling.
 *
 * In GUI mode, this wraps SwingUtilities.invokeAndWait() for EDT safety.
 * In headless mode, this executes directly with synchronized blocks.
 */
public interface ThreadingStrategy {

    /**
     * Execute a read-only operation (no transaction needed).
     *
     * @param <T> The return type
     * @param action The action to execute
     * @return The result of the action
     * @throws Exception if the action fails
     */
    <T> T executeRead(Callable<T> action) throws Exception;

    /**
     * Execute a read-only operation, converting checked exceptions to runtime.
     *
     * @param <T> The return type
     * @param action The action to execute
     * @return The result of the action
     */
    default <T> T executeReadUnchecked(Supplier<T> action) {
        try {
            return executeRead(() -> action.get());
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Execute a write operation within a transaction.
     *
     * @param <T> The return type
     * @param program The program to modify
     * @param txName Transaction name for undo/redo
     * @param action The action to execute
     * @return The result of the action
     * @throws Exception if the action fails (transaction will be rolled back)
     */
    <T> T executeWrite(Program program, String txName, Callable<T> action) throws Exception;

    /**
     * Execute a write operation within a transaction, no return value.
     *
     * @param program The program to modify
     * @param txName Transaction name for undo/redo
     * @param action The action to execute
     * @throws Exception if the action fails (transaction will be rolled back)
     */
    default void executeWrite(Program program, String txName, Runnable action) throws Exception {
        executeWrite(program, txName, () -> {
            action.run();
            return null;
        });
    }

    /**
     * Execute a write operation, converting checked exceptions to runtime.
     *
     * @param <T> The return type
     * @param program The program to modify
     * @param txName Transaction name
     * @param action The action to execute
     * @return The result of the action
     */
    default <T> T executeWriteUnchecked(Program program, String txName, Supplier<T> action) {
        try {
            return executeWrite(program, txName, () -> action.get());
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Execute a write operation with no return value, converting exceptions.
     *
     * @param program The program to modify
     * @param txName Transaction name
     * @param action The action to execute
     */
    default void executeWriteUnchecked(Program program, String txName, Runnable action) {
        try {
            executeWrite(program, txName, action);
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Check if we're running in headless mode.
     *
     * @return true if running headless (no GUI)
     */
    boolean isHeadless();
}
