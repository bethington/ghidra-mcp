package com.xebyte.offline.vuln;

import com.xebyte.core.vuln.*;
import com.xebyte.core.vuln.detectors.UnboundedCopyDetector;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.*;
import org.junit.Test;
import java.util.*;
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class UnboundedCopyDetectorTest {

    private HighFunction hfNoCompares(String name) {
        HighFunction hf = mock(HighFunction.class);
        Function f = mock(Function.class);
        when(f.getName()).thenReturn(name);
        when(hf.getFunction()).thenReturn(f);
        // hasDominatingCompare scans hf.getPcodeOps(); empty iterator → no compares.
        when(hf.getPcodeOps())
            .thenAnswer(inv -> Collections.<PcodeOpAST>emptyIterator());
        return hf;
    }

    private Varnode boundedDst(int size) {
        // PcodeQuery.destBufferSize prefers HighSymbol.getDataType().getLength().
        Varnode v = mock(Varnode.class);
        HighVariable hv = mock(HighVariable.class);
        HighSymbol sym = mock(HighSymbol.class);
        DataType dt = mock(DataType.class);
        when(dt.getLength()).thenReturn(size);
        when(sym.getDataType()).thenReturn(dt);
        when(hv.getSymbol()).thenReturn(sym);
        when(v.getHigh()).thenReturn(hv);
        return v;
    }

    private Varnode constVn(long k) {
        Varnode v = mock(Varnode.class);
        when(v.isConstant()).thenReturn(true);
        when(v.getOffset()).thenReturn(k);
        when(v.getDef()).thenReturn(null);
        return v;
    }

    private Varnode paramVn() {
        Varnode v = mock(Varnode.class);
        when(v.isConstant()).thenReturn(false);
        when(v.getDef()).thenReturn(null);
        return v;
    }

    private SinkCallSite copySite(Integer sizeArg, Varnode dst, Varnode src, Varnode size) {
        Map<String, Integer> roles = new LinkedHashMap<>();
        roles.put("dst_arg", 0);
        if (sizeArg != null) roles.put("size_arg", sizeArg);
        CatalogEntry e = new CatalogEntry(sizeArg == null ? "strcpy" : "memcpy",
            "sink", "copy", roles, false, List.of(), List.of(), List.of());
        PcodeOp call = mock(PcodeOp.class);
        when(call.getOpcode()).thenReturn(PcodeOp.CALL);
        int n = sizeArg == null ? 3 : 4;
        when(call.getNumInputs()).thenReturn(n);
        when(call.getInput(0)).thenReturn(mock(Varnode.class));
        when(call.getInput(1)).thenReturn(dst);
        when(call.getInput(2)).thenReturn(src);
        if (sizeArg != null) when(call.getInput(3)).thenReturn(size);
        Address a = mock(Address.class); when(a.toString()).thenReturn("00401000");
        Function callee = mock(Function.class); when(callee.getName()).thenReturn(e.id());
        return new SinkCallSite(call, e, callee, a);
    }

    @Test
    public void strcpy_intoBoundedLocal_fromNonConst_flags() {
        var d = new UnboundedCopyDetector();
        var s = copySite(null, boundedDst(64), paramVn(), null);
        var out = d.scan(hfNoCompares("F"), List.of(s));
        assertEquals(1, out.size());
        assertEquals("unbounded_copy", out.get(0).detectorId());
        assertEquals("high", out.get(0).confidence());
    }

    @Test
    public void memcpy_constSizeWithinDest_safe() {
        var d = new UnboundedCopyDetector();
        var s = copySite(2, boundedDst(64), paramVn(), constVn(32));
        assertTrue(d.scan(hfNoCompares("F"), List.of(s)).isEmpty());
    }

    @Test
    public void memcpy_constSizeExceedsDest_flagsHigh() {
        var d = new UnboundedCopyDetector();
        var s = copySite(2, boundedDst(64), paramVn(), constVn(128));
        var out = d.scan(hfNoCompares("F"), List.of(s));
        assertEquals(1, out.size());
        assertEquals("high", out.get(0).confidence());
        assertTrue(out.get(0).why().contains("128"));
    }

    @Test
    public void memcpy_paramSizeNoCompare_intoBoundedDest_flagsMedium() {
        var d = new UnboundedCopyDetector();
        var s = copySite(2, boundedDst(64), paramVn(), paramVn());
        var out = d.scan(hfNoCompares("F"), List.of(s));
        assertEquals(1, out.size());
        assertEquals("medium", out.get(0).confidence());
    }

    @Test
    public void memcpy_unknownDestSize_doesNotFlag() {
        var d = new UnboundedCopyDetector();
        Varnode dst = mock(Varnode.class); when(dst.getHigh()).thenReturn(null);
        var s = copySite(2, dst, paramVn(), paramVn());
        assertTrue("unknown dest size → can't claim overflow",
            d.scan(hfNoCompares("F"), List.of(s)).isEmpty());
    }
}
