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
import ghidra.util.Msg;

import javax.swing.SwingUtilities;
import java.lang.reflect.InvocationTargetException;
import java.util.concurrent.Callable;
import java.util.concurrent.atomic.AtomicReference;

/**
 * GUI mode implementation of ThreadingStrategy.
 *
 * Uses SwingUtilities.invokeAndWait() to execute operations on the
 * Event Dispatch Thread (EDT) as required by Ghidra GUI mode.
 */
public class SwingThreadingStrategy implements ThreadingStrategy {

    @Override
    public <T> T executeRead(Callable<T> action) throws Exception {
        if (SwingUtilities.isEventDispatchThread()) {
            // Already on EDT, execute directly
            return action.call();
        }

        // Execute on EDT
        AtomicReference<T> result = new AtomicReference<>();
        AtomicReference<Exception> error = new AtomicReference<>();

        SwingUtilities.invokeAndWait(() -> {
            try {
                result.set(action.call());
            } catch (Exception e) {
                error.set(e);
            }
        });

        if (error.get() != null) {
            throw error.get();
        }
        return result.get();
    }

    @Override
    public <T> T executeWrite(Program program, String txName, Callable<T> action) throws Exception {
        if (program == null) {
            throw new IllegalArgumentException("Program cannot be null for write operations");
        }

        AtomicReference<T> result = new AtomicReference<>();
        AtomicReference<Exception> error = new AtomicReference<>();

        Runnable writeTask = () -> {
            int tx = program.startTransaction(txName);
            boolean success = false;
            try {
                result.set(action.call());
                success = true;
            } catch (Exception e) {
                error.set(e);
                Msg.error(this, "Error during transaction '" + txName + "'", e);
            } finally {
                program.endTransaction(tx, success);
            }

            // Force event processing to ensure changes propagate
            if (success) {
                program.flushEvents();
            }
        };

        if (SwingUtilities.isEventDispatchThread()) {
            // Already on EDT
            writeTask.run();
        } else {
            // Execute on EDT
            SwingUtilities.invokeAndWait(writeTask);
        }

        if (error.get() != null) {
            throw error.get();
        }
        return result.get();
    }

    @Override
    public boolean isHeadless() {
        return false;
    }
}
