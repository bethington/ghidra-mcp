package com.xebyte.offline;

import com.xebyte.core.ProgramProvider;
import ghidra.program.model.listing.Program;

/**
 * Test stub for {@link ProgramProvider} that returns nothing.
 *
 * Used in offline tests that need to construct service instances so they can
 * be scanned by {@link com.xebyte.core.AnnotationScanner}, without touching
 * a real Ghidra program. The scanner only reflects on method signatures; it
 * never invokes them, so these accessors are never actually called during
 * offline tests.
 */
public class StubProgramProvider implements ProgramProvider {

    @Override
    public Program getCurrentProgram() {
        return null;
    }

    @Override
    public Program getProgram(String name) {
        return null;
    }

    @Override
    public Program[] getAllOpenPrograms() {
        return new Program[0];
    }

    @Override
    public void setCurrentProgram(Program program) {
        // no-op
    }
}
