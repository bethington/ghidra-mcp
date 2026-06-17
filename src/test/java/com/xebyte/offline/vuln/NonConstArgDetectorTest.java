package com.xebyte.offline.vuln;

import com.xebyte.core.vuln.*;
import com.xebyte.core.vuln.detectors.FormatStringDetector;
import com.xebyte.core.vuln.detectors.CommandInjectionDetector;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import org.junit.Test;
import java.util.List;
import java.util.Map;
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class NonConstArgDetectorTest {

    private SinkCallSite site(String entryId, String vulnClass, String roleKey,
                              int argIdx, Varnode argVn) {
        CatalogEntry e = new CatalogEntry(entryId, "sink", vulnClass,
            Map.of(roleKey, argIdx), false, List.of(), List.of(), List.of());
        Varnode tgt = mock(Varnode.class);
        PcodeOp call = mock(PcodeOp.class);
        when(call.getOpcode()).thenReturn(PcodeOp.CALL);
        when(call.getNumInputs()).thenReturn(argIdx + 2);
        when(call.getInput(0)).thenReturn(tgt);
        when(call.getInput(argIdx + 1)).thenReturn(argVn);
        Address addr = mock(Address.class);
        when(addr.toString()).thenReturn("00401000");
        Function callee = mock(Function.class);
        when(callee.getName()).thenReturn(entryId);
        return new SinkCallSite(call, e, callee, addr);
    }

    private Varnode constArg() {
        Varnode v = mock(Varnode.class);
        when(v.isConstant()).thenReturn(true);
        when(v.getDef()).thenReturn(null);
        return v;
    }

    private Varnode paramArg() {
        Varnode v = mock(Varnode.class);
        when(v.isConstant()).thenReturn(false);
        when(v.getDef()).thenReturn(null);
        return v;
    }

    private Varnode loadFromConstAddr() {
        // LOAD(const_space_id, const_addr) → non-constant result; def chain has
        // no input and no CALL → confidence should be "medium".
        Varnode space = mock(Varnode.class);
        when(space.isConstant()).thenReturn(true); when(space.getDef()).thenReturn(null);
        Varnode addr = mock(Varnode.class);
        when(addr.isConstant()).thenReturn(true); when(addr.getDef()).thenReturn(null);
        PcodeOp load = mock(PcodeOp.class);
        when(load.getOpcode()).thenReturn(PcodeOp.LOAD);
        when(load.getNumInputs()).thenReturn(2);
        when(load.getInput(0)).thenReturn(space);
        when(load.getInput(1)).thenReturn(addr);
        Varnode v = mock(Varnode.class);
        when(v.isConstant()).thenReturn(false);
        when(v.getDef()).thenReturn(load);
        return v;
    }

    private HighFunction hf(String fnName) {
        HighFunction hf = mock(HighFunction.class);
        Function f = mock(Function.class);
        when(f.getName()).thenReturn(fnName);
        when(hf.getFunction()).thenReturn(f);
        return hf;
    }

    @Test
    public void formatString_constantFmt_emitsNothing() {
        var d = new FormatStringDetector();
        var s = site("printf", "format", "fmt_arg", 0, constArg());
        assertTrue(d.scan(hf("F"), List.of(s)).isEmpty());
    }

    @Test
    public void formatString_paramFmt_emitsHighConfidence() {
        var d = new FormatStringDetector();
        var s = site("printf", "format", "fmt_arg", 0, paramArg());
        List<Finding> out = d.scan(hf("F"), List.of(s));
        assertEquals(1, out.size());
        assertEquals("format_string", out.get(0).detectorId());
        assertEquals("high", out.get(0).confidence());
        assertEquals("printf", out.get(0).sink());
    }

    @Test
    public void formatString_loadFromGlobal_emitsMediumConfidence() {
        var d = new FormatStringDetector();
        var s = site("printf", "format", "fmt_arg", 0, loadFromConstAddr());
        List<Finding> out = d.scan(hf("F"), List.of(s));
        assertEquals(1, out.size());
        assertEquals("medium", out.get(0).confidence());
    }

    @Test
    public void commandInjection_paramCmd_emitsFinding() {
        var d = new CommandInjectionDetector();
        var s = site("system", "exec", "cmd_arg", 0, paramArg());
        List<Finding> out = d.scan(hf("F"), List.of(s));
        assertEquals(1, out.size());
        assertEquals("command_injection", out.get(0).detectorId());
        assertEquals("exec", out.get(0).vulnClass());
        assertEquals("high", out.get(0).confidence());
    }

    @Test
    public void detector_ignoresSitesOutsideItsClass() {
        var d = new FormatStringDetector();
        var s = site("memcpy", "copy", "size_arg", 2, paramArg());
        assertTrue(d.scan(hf("F"), List.of(s)).isEmpty());
    }
}
