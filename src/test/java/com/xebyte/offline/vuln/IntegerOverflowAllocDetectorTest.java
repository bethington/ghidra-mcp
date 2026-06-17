package com.xebyte.offline.vuln;

import com.xebyte.core.vuln.*;
import com.xebyte.core.vuln.detectors.IntegerOverflowAllocDetector;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.*;
import org.junit.Test;
import java.util.*;
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class IntegerOverflowAllocDetectorTest {

    private HighFunction hfNoCompares() {
        HighFunction hf = mock(HighFunction.class);
        Function f = mock(Function.class); when(f.getName()).thenReturn("F");
        when(hf.getFunction()).thenReturn(f);
        when(hf.getPcodeOps()).thenAnswer(inv -> Collections.<PcodeOpAST>emptyIterator());
        return hf;
    }

    private Varnode constVn(long k) {
        Varnode v = mock(Varnode.class);
        when(v.isConstant()).thenReturn(true); when(v.getOffset()).thenReturn(k);
        when(v.getDef()).thenReturn(null); return v;
    }
    private Varnode paramVn() {
        Varnode v = mock(Varnode.class);
        when(v.isConstant()).thenReturn(false); when(v.getDef()).thenReturn(null); return v;
    }
    private Varnode definedBy(PcodeOp op) {
        Varnode v = mock(Varnode.class);
        when(v.isConstant()).thenReturn(false); when(v.getDef()).thenReturn(op); return v;
    }
    private PcodeOp op(int oc, Varnode... in) {
        PcodeOp p = mock(PcodeOp.class);
        when(p.getOpcode()).thenReturn(oc); when(p.getNumInputs()).thenReturn(in.length);
        for (int i=0;i<in.length;i++) when(p.getInput(i)).thenReturn(in[i]); return p;
    }

    private SinkCallSite allocSite(Varnode size) {
        CatalogEntry e = new CatalogEntry("malloc","sink","alloc",
            Map.of("size_arg",0), false, List.of(), List.of(), List.of());
        PcodeOp call = mock(PcodeOp.class);
        when(call.getOpcode()).thenReturn(PcodeOp.CALL);
        when(call.getNumInputs()).thenReturn(2);
        when(call.getInput(0)).thenReturn(mock(Varnode.class));
        when(call.getInput(1)).thenReturn(size);
        Address a = mock(Address.class); when(a.toString()).thenReturn("00401000");
        Function callee = mock(Function.class); when(callee.getName()).thenReturn("malloc");
        return new SinkCallSite(call, e, callee, a);
    }

    @Test
    public void mult_paramTimesConst_intoMalloc_noCheck_flags() {
        PcodeOp mul = op(PcodeOp.INT_MULT, paramVn(), constVn(16));
        var s = allocSite(definedBy(mul));
        var out = new IntegerOverflowAllocDetector().scan(hfNoCompares(), List.of(s));
        assertEquals(1, out.size());
        assertEquals("integer_overflow_alloc", out.get(0).detectorId());
        assertEquals("alloc", out.get(0).vulnClass());
        assertEquals("medium", out.get(0).confidence());
    }

    @Test
    public void mult_constTimesConst_safe() {
        PcodeOp mul = op(PcodeOp.INT_MULT, constVn(8), constVn(16));
        var s = allocSite(definedBy(mul));
        assertTrue(new IntegerOverflowAllocDetector().scan(hfNoCompares(), List.of(s)).isEmpty());
    }

    @Test
    public void plainParamSize_noArith_doesNotFlag() {
        var s = allocSite(paramVn());
        assertTrue("no MULT/ADD → not an overflow pattern",
            new IntegerOverflowAllocDetector().scan(hfNoCompares(), List.of(s)).isEmpty());
    }

    @Test
    public void add_paramPlusConst_intoMalloc_flags() {
        PcodeOp add = op(PcodeOp.INT_ADD, paramVn(), constVn(8));
        var s = allocSite(definedBy(add));
        var out = new IntegerOverflowAllocDetector().scan(hfNoCompares(), List.of(s));
        assertEquals(1, out.size());
    }

    @Test
    public void constSize_doesNotFlag() {
        var s = allocSite(constVn(128));
        assertTrue(new IntegerOverflowAllocDetector().scan(hfNoCompares(), List.of(s)).isEmpty());
    }
}
