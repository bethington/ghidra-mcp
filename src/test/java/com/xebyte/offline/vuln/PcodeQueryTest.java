package com.xebyte.offline.vuln;

import com.xebyte.core.vuln.PcodeQuery;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import org.junit.Test;
import java.util.Set;
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class PcodeQueryTest {

    private Varnode constVn(long v) {
        Varnode vn = mock(Varnode.class);
        when(vn.isConstant()).thenReturn(true);
        when(vn.getOffset()).thenReturn(v);
        when(vn.getDef()).thenReturn(null);
        return vn;
    }

    private Varnode definedBy(PcodeOp op) {
        Varnode vn = mock(Varnode.class);
        when(vn.isConstant()).thenReturn(false);
        when(vn.getDef()).thenReturn(op);
        return vn;
    }

    private PcodeOp op(int opcode, Varnode... inputs) {
        PcodeOp p = mock(PcodeOp.class);
        when(p.getOpcode()).thenReturn(opcode);
        when(p.getNumInputs()).thenReturn(inputs.length);
        for (int i = 0; i < inputs.length; i++) when(p.getInput(i)).thenReturn(inputs[i]);
        return p;
    }

    @Test
    public void argVarnode_returnsCallInputAtIndexPlusOne() {
        Varnode tgt = mock(Varnode.class);
        Varnode a0 = mock(Varnode.class);
        Varnode a1 = mock(Varnode.class);
        PcodeOp call = op(PcodeOp.CALL, tgt, a0, a1);
        assertSame(a0, PcodeQuery.argVarnode(call, 0));
        assertSame(a1, PcodeQuery.argVarnode(call, 1));
        assertNull(PcodeQuery.argVarnode(call, 2));
    }

    @Test
    public void reachesConstantOnly_trueForConstThroughCopyCast() {
        Varnode k = constVn(0x1000);
        PcodeOp copy = op(PcodeOp.COPY, k);
        Varnode v1 = definedBy(copy);
        PcodeOp cast = op(PcodeOp.CAST, v1);
        Varnode v2 = definedBy(cast);
        assertTrue(PcodeQuery.reachesConstantOnly(v2, 16));
    }

    @Test
    public void reachesConstantOnly_falseWhenDefChainHitsCallOrInput() {
        Varnode param = mock(Varnode.class);
        when(param.isConstant()).thenReturn(false);
        when(param.getDef()).thenReturn(null);
        assertFalse(PcodeQuery.reachesConstantOnly(param, 16));

        PcodeOp call = op(PcodeOp.CALL, mock(Varnode.class));
        Varnode ret = definedBy(call);
        assertFalse(PcodeQuery.reachesConstantOnly(ret, 16));
    }

    @Test
    public void definingOps_collectsTransitiveProducers() {
        Varnode k = constVn(4);
        PcodeOp mul = op(PcodeOp.INT_MULT, k, k);
        Varnode prod = definedBy(mul);
        PcodeOp add = op(PcodeOp.INT_ADD, prod, constVn(8));
        Varnode sum = definedBy(add);
        Set<PcodeOp> ops = PcodeQuery.definingOps(sum, 16);
        assertTrue(ops.contains(add));
        assertTrue(ops.contains(mul));
    }

    @Test
    public void definingOps_respectsMaxStepsAndCycles() {
        PcodeOp copy = mock(PcodeOp.class);
        Varnode v = mock(Varnode.class);
        when(v.isConstant()).thenReturn(false);
        when(v.getDef()).thenReturn(copy);
        when(copy.getOpcode()).thenReturn(PcodeOp.COPY);
        when(copy.getNumInputs()).thenReturn(1);
        when(copy.getInput(0)).thenReturn(v);
        Set<PcodeOp> ops = PcodeQuery.definingOps(v, 8);
        assertTrue(ops.size() <= 8);
    }

    @Test
    public void defChainHasInput_trueForParamLike() {
        Varnode param = mock(Varnode.class);
        when(param.isConstant()).thenReturn(false);
        when(param.getDef()).thenReturn(null);
        assertTrue(PcodeQuery.defChainHasInput(param, 16));
        assertFalse(PcodeQuery.defChainHasInput(constVn(0), 16));
    }

    @Test
    public void defChainHasCall_trueWhenCallInChain() {
        PcodeOp call = op(PcodeOp.CALL, mock(Varnode.class));
        Varnode ret = definedBy(call);
        PcodeOp copy = op(PcodeOp.COPY, ret);
        Varnode v = definedBy(copy);
        assertTrue(PcodeQuery.defChainHasCall(v, 16));
        assertFalse(PcodeQuery.defChainHasCall(constVn(0), 16));
    }

    @Test
    public void reachesConstantOnly_transparentThroughIndirect() {
        // const → COPY → INDIRECT(prev, iop) — must still prove constant.
        Varnode k = constVn(0x40a010);
        PcodeOp copy = op(PcodeOp.COPY, k);
        Varnode prev = definedBy(copy);
        Varnode iop = constVn(0); // iop-ref is in const space
        PcodeOp ind = op(PcodeOp.INDIRECT, prev, iop);
        Varnode v = definedBy(ind);
        assertTrue(PcodeQuery.reachesConstantOnly(v, 16));
    }

    @Test
    public void reachesConstantOnly_intSubOfConstants_isConstant() {
        // sizeof(buf)-1 pattern: INT_SUB(const, const)
        PcodeOp sub = op(PcodeOp.INT_SUB, constVn(64), constVn(1));
        assertTrue(PcodeQuery.reachesConstantOnly(definedBy(sub), 16));
    }

    @Test
    public void destBufferSize_prefersDeclaredSymbolTypeOverPointerElement() {
        // char buf[64] → HighSymbol DataType length 64; HighVariable type char* → element 1.
        ghidra.program.model.pcode.HighSymbol sym = mock(ghidra.program.model.pcode.HighSymbol.class);
        ghidra.program.model.data.DataType arr = mock(ghidra.program.model.data.DataType.class);
        when(arr.getLength()).thenReturn(64);
        when(sym.getDataType()).thenReturn(arr);
        ghidra.program.model.pcode.HighVariable hv = mock(ghidra.program.model.pcode.HighVariable.class);
        when(hv.getSymbol()).thenReturn(sym);
        Varnode dst = mock(Varnode.class);
        when(dst.getHigh()).thenReturn(hv);
        assertEquals(64, PcodeQuery.destBufferSize(dst, null));
    }

    @Test
    public void destBufferSize_pointerToPrimitive_returnsUnknown() {
        // char* with no symbol → unwrap → char (len 1) → must return -1, not 1.
        ghidra.program.model.data.DataType ch = mock(ghidra.program.model.data.DataType.class);
        when(ch.getLength()).thenReturn(1);
        ghidra.program.model.data.Pointer ptr = mock(ghidra.program.model.data.Pointer.class);
        when(ptr.getDataType()).thenReturn(ch);
        ghidra.program.model.pcode.HighVariable hv = mock(ghidra.program.model.pcode.HighVariable.class);
        when(hv.getSymbol()).thenReturn(null);
        when(hv.getDataType()).thenReturn(ptr);
        Varnode dst = mock(Varnode.class);
        when(dst.getHigh()).thenReturn(hv);
        // hf=null → ptrSize defaults to 8 → 1 ≤ 8 → unknown
        assertEquals(-1, PcodeQuery.destBufferSize(dst, null));
    }
}
