package com.xebyte.offline;

import com.xebyte.core.ProjectProgramProvider;
import ghidra.program.model.listing.Program;
import org.junit.Test;

import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import static org.junit.Assert.*;
import static org.mockito.Mockito.mock;

/**
 * Unit tests for the LRU victim-selection that bounds ProjectProgramProvider's on-demand
 * program cache (the unbounded cache previously held a consumer reference per documented
 * program and OOM-crashed Ghidra on long multi-binary runs). pickLruVictim is pure, so the
 * eviction decision is verified offline without a live Ghidra.
 */
public class ProjectProgramProviderEvictionTest {

    private static Program prog() {
        return mock(Program.class);
    }

    @Test
    public void picksLeastRecentlyAccessed() {
        Program a = prog(), b = prog(), c = prog();
        Map<String, Program> programs = new LinkedHashMap<>();
        programs.put("a", a);
        programs.put("b", b);
        programs.put("c", c);
        Map<String, Long> access = new LinkedHashMap<>();
        access.put("a", 300L);
        access.put("b", 100L); // oldest
        access.put("c", 200L);

        assertEquals("b", ProjectProgramProvider.pickLruVictim(programs, access, new HashSet<>()));
    }

    @Test
    public void neverPicksProtectedProgram() {
        Program a = prog(), b = prog();
        Map<String, Program> programs = new LinkedHashMap<>();
        programs.put("a", a);
        programs.put("b", b);
        Map<String, Long> access = new LinkedHashMap<>();
        access.put("a", 100L); // oldest, but protected
        access.put("b", 200L);
        Set<Program> protectedProgs = new HashSet<>();
        protectedProgs.add(a);

        assertEquals("b", ProjectProgramProvider.pickLruVictim(programs, access, protectedProgs));
    }

    @Test
    public void returnsNullWhenAllProtected() {
        Program a = prog(), b = prog();
        Map<String, Program> programs = new LinkedHashMap<>();
        programs.put("a", a);
        programs.put("b", b);
        Map<String, Long> access = new LinkedHashMap<>();
        access.put("a", 100L);
        access.put("b", 200L);
        Set<Program> protectedProgs = new HashSet<>();
        protectedProgs.add(a);
        protectedProgs.add(b);

        assertNull(ProjectProgramProvider.pickLruVictim(programs, access, protectedProgs));
    }

    @Test
    public void missingAccessTimeIsTreatedAsOldest() {
        // A program with no recorded access (never touched) is the most evictable.
        Program a = prog(), b = prog();
        Map<String, Program> programs = new LinkedHashMap<>();
        programs.put("a", a);
        programs.put("b", b);
        Map<String, Long> access = new LinkedHashMap<>();
        access.put("a", 500L);
        // "b" has no access entry -> defaults to 0 -> oldest

        assertEquals("b", ProjectProgramProvider.pickLruVictim(programs, access, new HashSet<>()));
    }

    @Test
    public void emptyCacheReturnsNull() {
        assertNull(ProjectProgramProvider.pickLruVictim(
                new LinkedHashMap<>(), new LinkedHashMap<>(), new HashSet<>()));
    }
}
