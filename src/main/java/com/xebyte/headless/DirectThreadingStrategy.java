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

import com.xebyte.core.ThreadingStrategy;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import java.util.concurrent.Callable;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Headless mode implementation of ThreadingStrategy.
 *
 * Executes operations directly without requiring the Swing EDT.
 * Uses a ReentrantLock for thread safety when multiple requests
 * access the same program concurrently.
 */
public class DirectThreadingStrategy implements ThreadingStrategy {

    private final ReentrantLock globalLock = new ReentrantLock();

    @Override
    public <T> T executeRead(Callable<T> action) throws Exception {
        // Read operations can run without locking in most cases,
        // but we still use locking for safety with concurrent access
        globalLock.lock();
        try {
            return action.call();
        } finally {
            globalLock.unlock();
        }
    }

    @Override
    public <T> T executeWrite(Program program, String txName, Callable<T> action) throws Exception {
        if (program == null) {
            throw new IllegalArgumentException("Program cannot be null for write operations");
        }

        globalLock.lock();
        int tx = -1;
        boolean success = false;

        try {
            tx = program.startTransaction(txName);
            T result = action.call();
            success = true;
            return result;
        } catch (Exception e) {
            Msg.error(this, "Error during transaction '" + txName + "'", e);
            throw e;
        } finally {
            if (tx != -1) {
                program.endTransaction(tx, success);
            }

            // Force event processing in headless mode
            if (success) {
                try {
                    program.flushEvents();
                } catch (Exception e) {
                    Msg.warn(this, "Error flushing events: " + e.getMessage());
                }
            }

            globalLock.unlock();
        }
    }

    @Override
    public boolean isHeadless() {
        return true;
    }
}
