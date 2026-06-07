package com.xebyte.offline;

import com.xebyte.core.FunctionService;
import org.junit.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.Assert.*;

/**
 * Unit tests for FunctionService.buildVariableNameHint — the guidance appended to a
 * "variable not found" error from set_local_variable_type. Pure string logic, no Ghidra
 * runtime, so it runs in the offline tier.
 */
public class FunctionServiceVariableHintTest {

    @Test
    public void nonDefaultName_returnsNoHint() {
        // A real/renamed name (not <prefix>Var<digits>) gets no decompiler-default hint.
        assertEquals("", FunctionService.buildVariableNameHint(
                "nTileCount", Arrays.asList("nTileCount", "local_ESI_256")));
    }

    @Test
    public void nullName_returnsNoHint() {
        assertEquals("", FunctionService.buildVariableNameHint(null, Arrays.asList("uVar1")));
    }

    @Test
    public void ssaRenumberDrift_whenSamePrefixDefaultRemains_recommendsSetVariables() {
        // uVar2 missing but uVar5/uVar7 still present → previous retype renumbered SSA temps.
        String hint = FunctionService.buildVariableNameHint(
                "uVar2", Arrays.asList("uVar5", "uVar7", "iVar3"));
        assertTrue("should flag SSA-renumber drift: " + hint, hint.contains("SSA-renumber drift"));
        assertTrue("should recommend set_variables: " + hint, hint.contains("set_variables"));
    }

    @Test
    public void renamedAwayOrRegisterResident_whenNoDefaultNamesRemain_tellsToReDecompile() {
        // The reported case: puVar3/uVar1 etc. missing, only register-named/renamed vars left.
        List<String> available = Arrays.asList(
                "local_ESI_256", "local_EAX_19", "nTileCount",
                "local_MM2_Wb_112", "local_MM6_265");
        String hint = FunctionService.buildVariableNameHint("puVar3", available);
        assertTrue("should name the requested var: " + hint, hint.contains("puVar3"));
        assertTrue("should explain renamed/register-resident: " + hint,
                hint.contains("renamed") || hint.contains("register-resident"));
        assertTrue("should tell caller to re-decompile: " + hint, hint.contains("re-decompile"));
        assertTrue("should offer set_variables: " + hint, hint.contains("set_variables"));
        // Must NOT misfire the SSA-drift branch when no default names remain.
        assertFalse("should not claim SSA-renumber drift: " + hint, hint.contains("SSA-renumber drift"));
    }

    @Test
    public void uVar1WithEmptyAvailable_givesRenamedAwayHint() {
        String hint = FunctionService.buildVariableNameHint("uVar1", Collections.emptyList());
        assertTrue(hint.contains("re-decompile"));
    }

    @Test
    public void uVar1WithNullAvailable_doesNotThrow() {
        String hint = FunctionService.buildVariableNameHint("uVar1", null);
        assertNotNull(hint);
        assertTrue(hint.contains("re-decompile"));
    }
}
