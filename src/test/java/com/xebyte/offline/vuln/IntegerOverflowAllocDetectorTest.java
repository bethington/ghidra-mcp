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

    @Test
    public void mult_paramTimesConst_withCompare_suppressesFinding() {
        // size = param*16; an INT_LESS reading `size` exists in hf → hasDominatingCompare → skip.
        PcodeOp mul = op(PcodeOp.INT_MULT, paramVn(), constVn(16));
        Varnode size = definedBy(mul);
        Varnode bound = constVn(0x1000);
        ghidra.program.model.pcode.PcodeOpAST cmp = mock(ghidra.program.model.pcode.PcodeOpAST.class);
        when(cmp.getOpcode()).thenReturn(PcodeOp.INT_LESS);
        when(cmp.getNumInputs()).thenReturn(2);
        when(cmp.getInput(0)).thenReturn(size);
        when(cmp.getInput(1)).thenReturn(bound);

        HighFunction hf = mock(HighFunction.class);
        Function f = mock(Function.class); when(f.getName()).thenReturn("F");
        when(hf.getFunction()).thenReturn(f);
        when(hf.getPcodeOps()).thenAnswer(inv -> java.util.List.of(cmp).iterator());

        var s = allocSite(size);
        assertTrue("compare on size should suppress the finding",
            new IntegerOverflowAllocDetector().scan(hf, List.of(s)).isEmpty());
    }

    @Test
    public void mult_throughCopy_intoMalloc_flags() {
        // size = COPY(INT_MULT(param, 16)) — definingOps must walk past COPY to find MULT.
        PcodeOp mul = op(PcodeOp.INT_MULT, paramVn(), constVn(16));
        Varnode prod = definedBy(mul);
        PcodeOp copy = op(PcodeOp.COPY, prod);
        var s = allocSite(definedBy(copy));
        var out = new IntegerOverflowAllocDetector().scan(hfNoCompares(), List.of(s));
        assertEquals(1, out.size());
    }
}
