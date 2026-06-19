package com.xebyte.offline.vuln;

import com.xebyte.core.vuln.*;
import ghidra.app.decompiler.DecompInterface;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.*;
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
}
