package com.xebyte.offline.vuln;

import com.xebyte.core.vuln.*;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import org.junit.Test;
import java.util.*;
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class TaintTracerTest {

    private SinkCatalog catalog() { return SinkCatalog.load(null); }

    @Test
    public void close_disposesOwnedDecompiler_butNotShared() {
        Program p = mock(Program.class);
        DecompInterface shared = mock(DecompInterface.class);
        TaintTracer t = new TaintTracer(p, catalog(), shared);
        t.close();
        verify(shared, never()).dispose();
        // Owned-ctor path: openProgram throws on a mock Program → ctor must
        // still construct (decomp may be null) and close() must not NPE.
        TaintTracer owned = new TaintTracer(p, catalog());
        owned.close(); // no exception
    }

    @Test
    public void taintedBufferRoots_collectsSourceOutArgAndReturn() {
        // hf has two CALLs: recv(sock, BUF, len) → out_arg=1; getenv() → return=true.
        HighFunction hf = mock(HighFunction.class);
        Function fn = mock(Function.class); when(hf.getFunction()).thenReturn(fn);

        Function recvFn = mock(Function.class);
        when(recvFn.isThunk()).thenReturn(false);
        when(recvFn.getName()).thenReturn("recv");
        when(recvFn.getTags()).thenReturn(Set.of());
        Function getenvFn = mock(Function.class);
        when(getenvFn.isThunk()).thenReturn(false);
        when(getenvFn.getName()).thenReturn("getenv");
        when(getenvFn.getTags()).thenReturn(Set.of());

        Varnode buf = mock(Varnode.class);
        Varnode envRet = mock(Varnode.class);

        PcodeOpAST callRecv = mock(PcodeOpAST.class);
        when(callRecv.getOpcode()).thenReturn(PcodeOp.CALL);
        when(callRecv.getNumInputs()).thenReturn(4);
        Varnode tgtR = mock(Varnode.class); when(tgtR.isAddress()).thenReturn(true);
        Address aR = mock(Address.class); when(tgtR.getAddress()).thenReturn(aR);
        when(callRecv.getInput(0)).thenReturn(tgtR);
        when(callRecv.getInput(1)).thenReturn(mock(Varnode.class)); // sock
        when(callRecv.getInput(2)).thenReturn(buf);                 // out_arg=1 → input(2)
        when(callRecv.getInput(3)).thenReturn(mock(Varnode.class));

        PcodeOpAST callGetenv = mock(PcodeOpAST.class);
        when(callGetenv.getOpcode()).thenReturn(PcodeOp.CALL);
        when(callGetenv.getNumInputs()).thenReturn(2);
        Varnode tgtG = mock(Varnode.class); when(tgtG.isAddress()).thenReturn(true);
        Address aG = mock(Address.class); when(tgtG.getAddress()).thenReturn(aG);
        when(callGetenv.getInput(0)).thenReturn(tgtG);
        when(callGetenv.getInput(1)).thenReturn(mock(Varnode.class));
        when(callGetenv.getOutput()).thenReturn(envRet);

        when(hf.getPcodeOps()).thenAnswer(inv -> List.of(callRecv, callGetenv).iterator());

        Program p = mock(Program.class);
        ghidra.program.model.listing.FunctionManager fm =
            mock(ghidra.program.model.listing.FunctionManager.class);
        when(p.getFunctionManager()).thenReturn(fm);
        when(fm.getFunctionAt(aR)).thenReturn(recvFn);
        when(fm.getFunctionAt(aG)).thenReturn(getenvFn);

        TaintTracer t = new TaintTracer(p, catalog(), mock(DecompInterface.class));
        Set<Varnode> roots = t.taintedBufferRoots(hf);
        assertTrue(roots.contains(buf));
        assertTrue(roots.contains(envRet));
        // cached: second call same instance
        assertSame(roots, t.taintedBufferRoots(hf));
        t.close();
    }

    // ---- algorithm-test harness ----

    private Varnode konst(long k) {
        Varnode v = mock(Varnode.class);
        when(v.isConstant()).thenReturn(true);
        when(v.getOffset()).thenReturn(k);
        return v;
    }
    private Varnode vn(PcodeOp def) {
        Varnode v = mock(Varnode.class);
        when(v.isConstant()).thenReturn(false);
        when(v.getDef()).thenReturn(def);
        return v;
    }
    private Varnode paramVn(int slot) {
        Varnode v = mock(Varnode.class);
        when(v.isConstant()).thenReturn(false);
        when(v.getDef()).thenReturn(null);
        HighVariable hv = mock(HighVariable.class);
        HighSymbol sym = mock(HighSymbol.class);
        when(sym.isParameter()).thenReturn(true);
        when(sym.getCategoryIndex()).thenReturn(slot);
        when(hv.getSymbol()).thenReturn(sym);
        when(v.getHigh()).thenReturn(hv);
        return v;
    }
    private PcodeOpAST callOp(Address site, Varnode tgt, Varnode out, Varnode... args) {
        PcodeOpAST op = mock(PcodeOpAST.class);
        when(op.getOpcode()).thenReturn(PcodeOp.CALL);
        when(op.getNumInputs()).thenReturn(1 + args.length);
        when(op.getInput(0)).thenReturn(tgt);
        for (int i = 0; i < args.length; i++) when(op.getInput(i+1)).thenReturn(args[i]);
        when(op.getOutput()).thenReturn(out);
        SequenceNumber sn = mock(SequenceNumber.class);
        when(sn.getTarget()).thenReturn(site);
        when(op.getSeqnum()).thenReturn(sn);
        return op;
    }
    private Varnode addrTgt(Address a) {
        Varnode t = mock(Varnode.class);
        when(t.isAddress()).thenReturn(true);
        when(t.getAddress()).thenReturn(a);
        return t;
    }
    private HighFunction hfOf(Function fn, PcodeOpAST... ops) {
        HighFunction hf = mock(HighFunction.class);
        when(hf.getFunction()).thenReturn(fn);
        when(hf.getPcodeOps()).thenAnswer(inv -> Arrays.asList(ops).iterator());
        return hf;
    }
    private Function fn(String name, Address entry) {
        Function f = mock(Function.class);
        when(f.getName()).thenReturn(name);
        when(f.getEntryPoint()).thenReturn(entry);
        when(f.isThunk()).thenReturn(false);
        when(f.getTags()).thenReturn(Set.of());
        return f;
    }
    private DecompInterface decompOf(Map<Function, HighFunction> map) {
        DecompInterface d = mock(DecompInterface.class);
        when(d.decompileFunction(any(), anyInt(), any())).thenAnswer(inv -> {
            Function f = inv.getArgument(0);
            HighFunction hf = map.get(f);
            DecompileResults r = mock(DecompileResults.class);
            when(r.decompileCompleted()).thenReturn(hf != null);
            when(r.getHighFunction()).thenReturn(hf);
            return r;
        });
        return d;
    }

    // ---- algorithm tests ----

    @Test
    public void trace_paramChain_reachesSourceCall() {
        // Sink(n=param0) ← Mid calls Sink(len) where len = output of recv(...).
        // Backward: n → param0 → caller Mid's arg0 = recvRet → CALL recv → source.
        Program p = mock(Program.class);
        FunctionManager fm = mock(FunctionManager.class);
        when(p.getFunctionManager()).thenReturn(fm);
        ReferenceManager rm = mock(ReferenceManager.class);
        when(p.getReferenceManager()).thenReturn(rm);

        Address aSink = mock(Address.class), aMid = mock(Address.class),
                aRecv = mock(Address.class), aMemcpy = mock(Address.class),
                callSite = mock(Address.class), recvSite = mock(Address.class);
        Function sinkFn = fn("Sink", aSink), midFn = fn("Mid", aMid),
                 recvFn = fn("recv", aRecv), memcpyFn = fn("memcpy", aMemcpy);
        when(fm.getFunctionAt(aRecv)).thenReturn(recvFn);
        when(fm.getFunctionAt(aMemcpy)).thenReturn(memcpyFn);
        when(fm.getFunctionAt(aSink)).thenReturn(sinkFn);

        // Sink: memcpy(dst, src, n) where n = param0
        Varnode n = paramVn(0);
        PcodeOpAST sinkCall = callOp(mock(Address.class), addrTgt(aMemcpy), null,
            mock(Varnode.class), mock(Varnode.class), n);
        HighFunction hfSink = hfOf(sinkFn, sinkCall);

        // Mid: len = recv(...); Sink(len);
        Varnode recvRet = mock(Varnode.class);
        PcodeOpAST callRecv = callOp(recvSite, addrTgt(aRecv), recvRet,
            mock(Varnode.class), mock(Varnode.class), mock(Varnode.class));
        when(recvRet.isConstant()).thenReturn(false);
        when(recvRet.getDef()).thenReturn(callRecv);
        PcodeOpAST callSink = callOp(callSite, addrTgt(aSink), null, recvRet);
        HighFunction hfMid = hfOf(midFn, callRecv, callSink);

        // Caller wiring: Sink has one caller Mid at callSite
        Reference ref = mock(Reference.class);
        RefType rt = mock(RefType.class);
        when(rt.isCall()).thenReturn(true);
        when(ref.getReferenceType()).thenReturn(rt);
        when(ref.getFromAddress()).thenReturn(callSite);
        ReferenceIterator rit = mock(ReferenceIterator.class);
        when(rit.hasNext()).thenReturn(true, false);
        when(rit.next()).thenReturn(ref);
        when(rm.getReferencesTo(aSink)).thenReturn(rit);
        when(fm.getFunctionContaining(callSite)).thenReturn(midFn);
        // Mid's hf must let trace find callSink at callSite:
        when(hfMid.getPcodeOps(callSite)).thenAnswer(inv -> List.of(callSink).iterator());

        TaintTracer t = new TaintTracer(p, catalog(),
            decompOf(Map.of(sinkFn, hfSink, midFn, hfMid)));
        TaintResult r = t.trace(hfSink, sinkCall, 2, 5, 64);
        assertNotNull("should reach recv as a source", r.source());
        assertEquals("recv", r.source().id());
        assertEquals("source", r.terminalReason());
        t.close();
    }

    @Test
    public void trace_loadFromTaintedBuffer_reachesSource() {
        // Single function: recv(sock, buf, len); n = LOAD(buf + 8); memcpy(dst,src,n).
        Program p = mock(Program.class);
        FunctionManager fm = mock(FunctionManager.class);
        when(p.getFunctionManager()).thenReturn(fm);
        when(p.getReferenceManager()).thenReturn(mock(ReferenceManager.class));
        Address aRecv = mock(Address.class), aMemcpy = mock(Address.class);
        Function fnF = fn("F", mock(Address.class));
        Function recvFn = fn("recv", aRecv), memcpyFn = fn("memcpy", aMemcpy);
        when(fm.getFunctionAt(aRecv)).thenReturn(recvFn);
        when(fm.getFunctionAt(aMemcpy)).thenReturn(memcpyFn);

        Varnode buf = mock(Varnode.class);
        when(buf.isConstant()).thenReturn(false); when(buf.getDef()).thenReturn(null);
        PcodeOpAST callRecv = callOp(mock(Address.class), addrTgt(aRecv), null,
            mock(Varnode.class), buf, mock(Varnode.class)); // out_arg=1 → buf
        // addr = PTRADD(buf, 8, 1)  — konst() pre-built so when() doesn't nest
        Varnode k8 = konst(8), k1 = konst(1), k0 = konst(0);
        PcodeOp ptradd = mock(PcodeOp.class);
        when(ptradd.getOpcode()).thenReturn(PcodeOp.PTRADD);
        when(ptradd.getNumInputs()).thenReturn(3);
        when(ptradd.getInput(0)).thenReturn(buf);
        when(ptradd.getInput(1)).thenReturn(k8);
        when(ptradd.getInput(2)).thenReturn(k1);
        Varnode addr = vn(ptradd);
        // n = LOAD(space, addr)
        PcodeOp load = mock(PcodeOp.class);
        when(load.getOpcode()).thenReturn(PcodeOp.LOAD);
        when(load.getNumInputs()).thenReturn(2);
        when(load.getInput(0)).thenReturn(k0);
        when(load.getInput(1)).thenReturn(addr);
        Varnode n = vn(load);
        PcodeOpAST sinkCall = callOp(mock(Address.class), addrTgt(aMemcpy), null,
            mock(Varnode.class), mock(Varnode.class), n);
        HighFunction hf = hfOf(fnF, callRecv, sinkCall);

        TaintTracer t = new TaintTracer(p, catalog(), decompOf(Map.of(fnF, hf)));
        TaintResult r = t.trace(hf, sinkCall, 2, 5, 64);
        assertNotNull(r.source());
        assertEquals("recv", r.source().id());
        assertEquals("tainted_load", r.terminalReason());
        t.close();
    }

    @Test
    public void trace_noSource_terminatesWithReason() {
        // memcpy(dst, src, const) — n is constant → terminal "constant", source null.
        Program p = mock(Program.class);
        when(p.getFunctionManager()).thenReturn(mock(FunctionManager.class));
        when(p.getReferenceManager()).thenReturn(mock(ReferenceManager.class));
        Function fnF = fn("F", mock(Address.class));
        PcodeOpAST sinkCall = callOp(mock(Address.class),
            addrTgt(mock(Address.class)), null,
            mock(Varnode.class), mock(Varnode.class), konst(32));
        HighFunction hf = hfOf(fnF, sinkCall);
        TaintTracer t = new TaintTracer(p, catalog(), decompOf(Map.of(fnF, hf)));
        TaintResult r = t.trace(hf, sinkCall, 2, 5, 64);
        assertNull(r.source());
        assertEquals("constant", r.terminalReason());
        t.close();
    }

    @Test
    public void trace_callDepthCap_stopsAtBoundary() {
        // Sink(param0) ← Mid calls Sink(midParam0) ← Top calls Mid(...).
        // maxCallDepth=1: hop Sink→Mid (depth 1); Mid's param0 hits the cap
        // before crossing to Top → terminal "call_depth", callDepthReached=1.
        Program p = mock(Program.class);
        FunctionManager fm = mock(FunctionManager.class);
        when(p.getFunctionManager()).thenReturn(fm);
        ReferenceManager rm = mock(ReferenceManager.class);
        when(p.getReferenceManager()).thenReturn(rm);

        Address aSink = mock(Address.class), aMid = mock(Address.class),
                callSite = mock(Address.class);
        Function sinkFn = fn("Sink", aSink), midFn = fn("Mid", aMid);
        when(fm.getFunctionAt(aSink)).thenReturn(sinkFn);

        // Sink: memcpy(dst, src, n) where n = param0
        Varnode n = paramVn(0);
        PcodeOpAST sinkCall = callOp(mock(Address.class),
            addrTgt(mock(Address.class)), null,
            mock(Varnode.class), mock(Varnode.class), n);
        HighFunction hfSink = hfOf(sinkFn, sinkCall);

        // Mid: Sink(midParam0) — arg0 is Mid's own param0, so the next hop
        // would need another caller crossing (which the cap forbids).
        Varnode midParam0 = paramVn(0);
        PcodeOpAST callSink = callOp(callSite, addrTgt(aSink), null, midParam0);
        HighFunction hfMid = hfOf(midFn, callSink);
        when(hfMid.getPcodeOps(callSite)).thenAnswer(inv -> List.of(callSink).iterator());

        // Sink's sole caller is Mid at callSite.
        Reference ref = mock(Reference.class);
        RefType rt = mock(RefType.class);
        when(rt.isCall()).thenReturn(true);
        when(ref.getReferenceType()).thenReturn(rt);
        when(ref.getFromAddress()).thenReturn(callSite);
        ReferenceIterator rit = mock(ReferenceIterator.class);
        when(rit.hasNext()).thenReturn(true, false);
        when(rit.next()).thenReturn(ref);
        when(rm.getReferencesTo(aSink)).thenReturn(rit);
        when(fm.getFunctionContaining(callSite)).thenReturn(midFn);

        TaintTracer t = new TaintTracer(p, catalog(),
            decompOf(Map.of(sinkFn, hfSink, midFn, hfMid)));
        TaintResult r = t.trace(hfSink, sinkCall, 2, /*maxCallDepth*/ 1, 64);
        assertNull(r.source());
        assertEquals("call_depth", r.terminalReason());
        assertEquals(1, r.callDepthReached());
        t.close();
    }

    @Test
    public void trace_callReturn_recursesIntoCalleeReturn() {
        // Sink: n = Helper(); memcpy(dst, src, n).
        // Helper: return recv(...). Backward: n → CALL Helper (not a source)
        // → enqueueReturns → Helper's RETURN.input(1) = recvRet → CALL recv → source.
        Program p = mock(Program.class);
        FunctionManager fm = mock(FunctionManager.class);
        when(p.getFunctionManager()).thenReturn(fm);
        when(p.getReferenceManager()).thenReturn(mock(ReferenceManager.class));

        Address aHelper = mock(Address.class), aRecv = mock(Address.class);
        Function sinkFn = fn("Sink", mock(Address.class));
        Function helperFn = fn("Helper", aHelper);
        Function recvFn = fn("recv", aRecv);
        when(fm.getFunctionAt(aHelper)).thenReturn(helperFn);
        when(fm.getFunctionAt(aRecv)).thenReturn(recvFn);

        // Helper body: recvRet = recv(...); RETURN(space, recvRet);
        PcodeOpAST callRecv = callOp(mock(Address.class), addrTgt(aRecv), null,
            mock(Varnode.class), mock(Varnode.class), mock(Varnode.class));
        Varnode recvRet = vn(callRecv);
        PcodeOpAST retOp = mock(PcodeOpAST.class);
        when(retOp.getOpcode()).thenReturn(PcodeOp.RETURN);
        when(retOp.getNumInputs()).thenReturn(2);
        when(retOp.getInput(1)).thenReturn(recvRet);
        HighFunction hfHelper = hfOf(helperFn, callRecv, retOp);

        // Sink body: n = Helper(); memcpy(_, _, n);
        PcodeOpAST callHelper = callOp(mock(Address.class), addrTgt(aHelper), null);
        Varnode n = vn(callHelper);
        PcodeOpAST sinkCall = callOp(mock(Address.class),
            addrTgt(mock(Address.class)), null,
            mock(Varnode.class), mock(Varnode.class), n);
        HighFunction hfSink = hfOf(sinkFn, callHelper, sinkCall);

        TaintTracer t = new TaintTracer(p, catalog(),
            decompOf(Map.of(sinkFn, hfSink, helperFn, hfHelper)));
        TaintResult r = t.trace(hfSink, sinkCall, 2, 5, 64);
        assertNotNull("should reach recv via callee RETURN", r.source());
        assertEquals("recv", r.source().id());
        assertEquals("source", r.terminalReason());
        t.close();
    }

    @Test
    public void trace_recursionGuard_preventsLoop() {
        // F.param0 → caller F (self-recursive). onPath guard must terminate.
        Program p = mock(Program.class);
        FunctionManager fm = mock(FunctionManager.class);
        when(p.getFunctionManager()).thenReturn(fm);
        ReferenceManager rm = mock(ReferenceManager.class);
        when(p.getReferenceManager()).thenReturn(rm);
        Address aF = mock(Address.class), site = mock(Address.class);
        Function fnF = fn("F", aF);
        when(fm.getFunctionAt(aF)).thenReturn(fnF);
        when(fm.getFunctionContaining(site)).thenReturn(fnF);
        Reference ref = mock(Reference.class);
        RefType rt = mock(RefType.class);
        when(rt.isCall()).thenReturn(true);
        when(ref.getReferenceType()).thenReturn(rt);
        when(ref.getFromAddress()).thenReturn(site);
        ReferenceIterator rit = mock(ReferenceIterator.class);
        when(rit.hasNext()).thenReturn(true, false);
        when(rit.next()).thenReturn(ref);
        when(rm.getReferencesTo(aF)).thenReturn(rit);

        Varnode n = paramVn(0);
        PcodeOpAST sinkCall = callOp(mock(Address.class), addrTgt(mock(Address.class)),
            null, mock(Varnode.class), mock(Varnode.class), n);
        // Self-call at `site` passing param0 again
        PcodeOpAST selfCall = callOp(site, addrTgt(aF), null, n);
        HighFunction hf = hfOf(fnF, selfCall, sinkCall);
        when(hf.getPcodeOps(site)).thenAnswer(inv -> List.of(selfCall).iterator());

        TaintTracer t = new TaintTracer(p, catalog(), decompOf(Map.of(fnF, hf)));
        TaintResult r = t.trace(hf, sinkCall, 2, 5, 64);
        // Load-bearing: the on-path guard prevents an infinite loop and no
        // source is reached. The terminal reason is "no_path" rather than
        // "recursion" because enqueueCallers() silently skips the on-path
        // caller (F is already in onPath at frame creation), leaving the
        // worklist empty without ever taking the call_return / recursion
        // branch — so aggTerminal stays at its initial value.
        assertNull(r.source());
        assertEquals("no_path", r.terminalReason());
        t.close();
    }

    @Test
    public void trace_loopCarriedPhi_terminates() {
        // n = MULTIEQUAL(init, INT_ADD(n, 1)) — loop accumulator into memcpy size.
        // `init` is a non-const local input so the phi forks: each frame that
        // reaches φ enqueues a new frame at `body`, which walks back to φ and
        // forks again → unbounded worklist without a per-function varnode
        // seen-set. INTRA_STEP_CAP bounds each frame but not the frame count.
        Program p = mock(Program.class);
        when(p.getFunctionManager()).thenReturn(mock(FunctionManager.class));
        when(p.getReferenceManager()).thenReturn(mock(ReferenceManager.class));
        Function fnF = fn("F", mock(Address.class));

        // init: non-const, no def, no HighVariable → "input" terminal when reached.
        Varnode init = mock(Varnode.class);
        when(init.isConstant()).thenReturn(false);
        when(init.getDef()).thenReturn(null);
        when(init.getHigh()).thenReturn(null);
        // body = INT_ADD(n, 1) where n is the phi output → cycle.
        PcodeOp phi = mock(PcodeOp.class);
        Varnode n = vn(phi);
        Varnode one = konst(1);
        PcodeOp add = mock(PcodeOp.class);
        when(add.getOpcode()).thenReturn(PcodeOp.INT_ADD);
        when(add.getNumInputs()).thenReturn(2);
        when(add.getInput(0)).thenReturn(n);
        when(add.getInput(1)).thenReturn(one);
        Varnode body = vn(add);
        when(phi.getOpcode()).thenReturn(PcodeOp.MULTIEQUAL);
        when(phi.getNumInputs()).thenReturn(2);
        when(phi.getInput(0)).thenReturn(init);
        when(phi.getInput(1)).thenReturn(body);

        PcodeOpAST sinkCall = callOp(mock(Address.class), addrTgt(mock(Address.class)),
            null, mock(Varnode.class), mock(Varnode.class), n);
        HighFunction hf = hfOf(fnF, sinkCall);

        TaintTracer t = new TaintTracer(p, catalog(), decompOf(Map.of(fnF, hf)));
        long start = System.nanoTime();
        TaintResult r = t.trace(hf, sinkCall, 2, 5, 64);
        long ms = (System.nanoTime() - start) / 1_000_000;
        assertNull(r.source());
        assertTrue("must terminate quickly (was " + ms + "ms)", ms < 5000);
        t.close();
    }
}
