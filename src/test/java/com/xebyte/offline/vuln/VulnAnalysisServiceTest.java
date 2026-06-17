package com.xebyte.offline.vuln;

import com.xebyte.core.FunctionService;
import com.xebyte.core.ProgramProvider;
import com.xebyte.core.Response;
import com.xebyte.core.vuln.VulnAnalysisService;
import com.xebyte.offline.NoopThreadingStrategy;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import org.junit.Test;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class VulnAnalysisServiceTest {

    private VulnAnalysisService svc(Program p) {
        ProgramProvider pp = mock(ProgramProvider.class);
        when(pp.getCurrentProgram()).thenReturn(p);
        FunctionService fs = mock(FunctionService.class);
        return new VulnAnalysisService(pp, new NoopThreadingStrategy(), fs);
    }

    @Test
    @SuppressWarnings("unchecked")
    public void listVulnDetectors_returnsAllFour() {
        Response r = svc(mock(Program.class)).listVulnDetectors("");
        assertTrue(r instanceof Response.Ok);
        Map<String, Object> body = (Map<String, Object>) ((Response.Ok) r).data();
        List<?> ds = (List<?>) body.get("detectors");
        assertEquals(4, ds.size());
        Set<String> ids = new HashSet<>();
        for (Object d : ds) ids.add((String) ((Map<?, ?>) d).get("id"));
        assertTrue(ids.containsAll(Set.of("format_string", "command_injection",
            "unbounded_copy", "integer_overflow_alloc")));
        assertNotNull(body.get("catalog"));
    }

    @Test
    @SuppressWarnings("unchecked")
    public void detectVulnPatterns_noFunctions_returnsEmptyWithCounts() {
        Program p = mock(Program.class);
        FunctionManager fm = mock(FunctionManager.class);
        when(p.getFunctionManager()).thenReturn(fm);
        FunctionIterator empty = mock(FunctionIterator.class);
        when(empty.hasNext()).thenReturn(false);
        when(fm.getFunctions(true)).thenReturn(empty);

        Response r = svc(p).detectVulnPatterns("", "", "", false, 0);
        assertTrue(r instanceof Response.Ok);
        Map<String, Object> body = (Map<String, Object>) ((Response.Ok) r).data();
        assertEquals(0, ((List<?>) body.get("findings")).size());
        assertEquals(0, ((Number) body.get("scanned_functions")).intValue());
        assertEquals(0, ((Number) body.get("decompile_failures")).intValue());
        List<?> ran = (List<?>) body.get("detectors_run");
        assertEquals(4, ran.size());
    }

    @Test
    @SuppressWarnings("unchecked")
    public void detectVulnPatterns_classesFilter_limitsDetectorsRun() {
        Program p = mock(Program.class);
        FunctionManager fm = mock(FunctionManager.class);
        when(p.getFunctionManager()).thenReturn(fm);
        FunctionIterator empty = mock(FunctionIterator.class);
        when(empty.hasNext()).thenReturn(false);
        when(fm.getFunctions(true)).thenReturn(empty);

        Response r = svc(p).detectVulnPatterns("", "format_string,unbounded_copy", "", false, 0);
        Map<String, Object> body = (Map<String, Object>) ((Response.Ok) r).data();
        List<?> ran = (List<?>) body.get("detectors_run");
        assertEquals(2, ran.size());
        assertTrue(ran.contains("format_string"));
        assertTrue(ran.contains("unbounded_copy"));
    }

    @Test
    @SuppressWarnings("unchecked")
    public void detectVulnPatterns_unknownDetectorId_returnsError() {
        Program p = mock(Program.class);
        FunctionManager fm = mock(FunctionManager.class);
        when(p.getFunctionManager()).thenReturn(fm);
        Response r = svc(p).detectVulnPatterns("", "fmt_string", "", false, 0);
        assertFalse("unknown detector id should NOT return Ok", r instanceof Response.Ok);
        assertTrue("expected Response.Err for unknown detector id", r instanceof Response.Err);
        String msg = ((Response.Err) r).message();
        assertTrue(msg.contains("fmt_string"));
    }

    @Test
    @SuppressWarnings("unchecked")
    public void enumerateAttackSurface_groupsCallersBySourceClass() {
        Program p = mock(Program.class);
        FunctionManager fm = mock(FunctionManager.class);
        when(p.getFunctionManager()).thenReturn(fm);
        ghidra.program.model.symbol.ReferenceManager rm =
            mock(ghidra.program.model.symbol.ReferenceManager.class);
        when(p.getReferenceManager()).thenReturn(rm);
        // addressToJson(program) calls getAddressFactory().getAddressSpaces() — stub minimally
        ghidra.program.model.address.AddressFactory af =
            mock(ghidra.program.model.address.AddressFactory.class);
        when(af.getAddressSpaces()).thenReturn(new ghidra.program.model.address.AddressSpace[0]);
        when(p.getAddressFactory()).thenReturn(af);

        // Source: function tagged SOURCE_NETWORK (catalog 'recv' → class "network")
        Function recv = mock(Function.class);
        ghidra.program.model.listing.FunctionTag tag = mock(ghidra.program.model.listing.FunctionTag.class);
        when(tag.getName()).thenReturn("SOURCE_NETWORK");
        when(recv.getTags()).thenReturn(java.util.Set.of(tag));
        when(recv.isThunk()).thenReturn(false);
        when(recv.getName()).thenReturn("MyRecv");
        ghidra.program.model.address.Address recvEntry = mock(ghidra.program.model.address.Address.class);
        ghidra.program.model.address.AddressSpace ramSpace = mock(ghidra.program.model.address.AddressSpace.class);
        when(ramSpace.isOverlaySpace()).thenReturn(false);
        when(recvEntry.getAddressSpace()).thenReturn(ramSpace);
        when(recvEntry.toString(false)).thenReturn("00100000");
        when(recv.getEntryPoint()).thenReturn(recvEntry);

        // One caller: HandlePacket
        Function caller = mock(Function.class);
        when(caller.isThunk()).thenReturn(false);
        when(caller.getName()).thenReturn("HandlePacket");
        when(caller.getTags()).thenReturn(java.util.Set.of());
        ghidra.program.model.address.Address callerEntry = mock(ghidra.program.model.address.Address.class);
        when(callerEntry.getAddressSpace()).thenReturn(ramSpace);
        when(callerEntry.toString(false)).thenReturn("00200000");
        when(caller.getEntryPoint()).thenReturn(callerEntry);

        // FunctionManager.getFunctions(true) → just recv (caller discovered via refs)
        FunctionIterator fit = mock(FunctionIterator.class);
        when(fit.hasNext()).thenReturn(true, false);
        when(fit.next()).thenReturn(recv);
        when(fm.getFunctions(true)).thenReturn(fit);

        // ReferenceManager: one CALL ref from caller → recv
        ghidra.program.model.symbol.Reference ref = mock(ghidra.program.model.symbol.Reference.class);
        ghidra.program.model.symbol.RefType rt = mock(ghidra.program.model.symbol.RefType.class);
        when(rt.isCall()).thenReturn(true);
        when(ref.getReferenceType()).thenReturn(rt);
        ghidra.program.model.address.Address fromAddr = mock(ghidra.program.model.address.Address.class);
        when(ref.getFromAddress()).thenReturn(fromAddr);
        when(fm.getFunctionContaining(fromAddr)).thenReturn(caller);
        ghidra.program.model.symbol.ReferenceIterator rit =
            mock(ghidra.program.model.symbol.ReferenceIterator.class);
        when(rit.hasNext()).thenReturn(true, false);
        when(rit.next()).thenReturn(ref);
        when(rm.getReferencesTo(recvEntry)).thenReturn(rit);
        // Caller has no further callers
        ghidra.program.model.symbol.ReferenceIterator emptyRit =
            mock(ghidra.program.model.symbol.ReferenceIterator.class);
        when(emptyRit.hasNext()).thenReturn(false);
        when(rm.getReferencesTo(callerEntry)).thenReturn(emptyRit);

        Response r = svc(p).enumerateAttackSurface(2, "");
        Map<String,Object> body = (Map<String,Object>) ((Response.Ok) r).data();
        Map<String,Object> groups = (Map<String,Object>) body.get("by_source_class");
        assertTrue(groups.containsKey("network"));
        List<?> netFns = (List<?>) groups.get("network");
        assertTrue(netFns.stream().anyMatch(m -> "HandlePacket".equals(((Map<?,?>)m).get("name"))));
        assertEquals(1, ((Number) body.get("source_count")).intValue());
    }
}
