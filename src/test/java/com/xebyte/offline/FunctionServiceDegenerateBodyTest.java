package com.xebyte.offline;

import com.xebyte.core.FunctionService;
import com.xebyte.core.ProgramProvider;
import com.xebyte.core.Response;
import com.xebyte.core.ThreadingStrategy;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.DefaultAddressFactory;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import org.junit.Test;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.*;

/**
 * /disassemble_function must not answer a degenerate function body with a
 * single instruction and no way to tell.
 *
 * <p>Ghidra's boundary analysis records {@code body_end == body_start} on a
 * measured fraction of real binaries (8 of 24 launcher functions in Game.exe,
 * 2026-08-11). The listing loop bounded itself by that stored body, so it
 * emitted exactly one instruction and returned the ordinary
 * {@code {instructions, count}} envelope -- a truncated listing shaped exactly
 * like a complete one. These tests pin both halves of the fix: the listing is
 * re-bounded, AND the response says why it disagrees with the stored extent.
 *
 * <p>Everything here is mocked so it runs in the offline tier with no Ghidra
 * install. {@code FunctionServiceDegenerateBodyGhidraTest} covers the same
 * ground against a real {@code ProgramDB} built by {@code ProgramBuilder}.
 */
public class FunctionServiceDegenerateBodyTest {

    // ------------------------------------------------------------------
    // Fixture
    // ------------------------------------------------------------------

    /**
     * A mocked Program just deep enough for disassembleFunction: a real
     * address factory (so compareTo/previous carry true semantics), a listing
     * that serves instructions in address order, a function manager that
     * iterates entry points in address order, and one memory block.
     */
    private static final class Fixture {
        final AddressSpace ram = new GenericAddressSpace("ram", 32, AddressSpace.TYPE_RAM, 0);
        // A SECOND space, ordered after "ram" by space id. Address.compareTo()
        // compares space id before offset, so anything here sorts after every
        // "ram" address regardless of its offset.
        final AddressSpace other = new GenericAddressSpace("code", 32, AddressSpace.TYPE_RAM, 1);
        final AddressFactory factory =
                new DefaultAddressFactory(new AddressSpace[]{ram, other}, ram);

        final Listing listing = mock(Listing.class);
        final FunctionManager functionManager = mock(FunctionManager.class);
        final Memory memory = mock(Memory.class);
        final Program program = mock(Program.class);

        final List<Instruction> instructions = new ArrayList<>();
        final List<Function> functions = new ArrayList<>();
        MemoryBlock block; // null means "address is not in any block"

        Fixture() {
            when(program.getAddressFactory()).thenReturn(factory);
            when(program.getListing()).thenReturn(listing);
            when(program.getFunctionManager()).thenReturn(functionManager);
            when(program.getMemory()).thenReturn(memory);
            when(listing.getComment(anyInt(), any(Address.class))).thenReturn(null);

            // Fresh iterator per call, filtered and ordered like Ghidra's.
            when(listing.getInstructions(any(Address.class), anyBoolean()))
                    .thenAnswer(inv -> {
                        Address from = inv.getArgument(0);
                        List<Instruction> hits = new ArrayList<>();
                        for (Instruction i : sortedInstructions()) {
                            if (i.getAddress().compareTo(from) >= 0) hits.add(i);
                        }
                        return instructionIterator(hits);
                    });
            when(listing.getInstructionAt(any(Address.class))).thenAnswer(inv -> {
                Address at = inv.getArgument(0);
                for (Instruction i : instructions) {
                    if (i.getAddress().equals(at)) return i;
                }
                return null;
            });
            when(functionManager.getFunctions(any(Address.class), anyBoolean()))
                    .thenAnswer(inv -> {
                        Address from = inv.getArgument(0);
                        List<Function> hits = new ArrayList<>();
                        for (Function f : sortedFunctions()) {
                            if (f.getEntryPoint().compareTo(from) >= 0) hits.add(f);
                        }
                        return functionIterator(hits);
                    });
            when(functionManager.getFunctionAt(any(Address.class))).thenAnswer(inv -> {
                Address at = inv.getArgument(0);
                for (Function f : functions) {
                    if (f.getEntryPoint().equals(at)) return f;
                }
                return null;
            });
            when(functionManager.getFunctionContaining(any(Address.class))).thenReturn(null);
            when(memory.getBlock(any(Address.class))).thenAnswer(inv -> block);
        }

        Address addr(long offset) {
            return ram.getAddress(offset);
        }

        Address otherSpaceAddr(long offset) {
            return other.getAddress(offset);
        }

        /** Register one instruction at {@code offset} rendering as {@code text}. */
        Fixture instruction(long offset, String text, int length) {
            Instruction i = mock(Instruction.class);
            when(i.getAddress()).thenReturn(addr(offset));
            when(i.getMaxAddress()).thenReturn(addr(offset + length - 1));
            when(i.getLength()).thenReturn(length);
            doReturn(text).when(i).toString();
            instructions.add(i);
            return this;
        }

        /** Register a function whose stored body is {@code [bodyStart, bodyEnd]}. */
        Fixture function(long entry, long bodyStart, long bodyEnd) {
            return function(addr(entry), new AddressSet(addr(bodyStart), addr(bodyEnd)));
        }

        /** Register a function with an EMPTY stored body. */
        Fixture functionWithEmptyBody(long entry) {
            return function(addr(entry), new AddressSet());
        }

        Fixture function(Address entry, AddressSet body) {
            Function f = mock(Function.class);
            when(f.getEntryPoint()).thenReturn(entry);
            when(f.getBody()).thenReturn(body);
            functions.add(f);
            return this;
        }

        Fixture block(long start, long end) {
            MemoryBlock b = mock(MemoryBlock.class);
            when(b.getStart()).thenReturn(addr(start));
            when(b.getEnd()).thenReturn(addr(end));
            this.block = b;
            return this;
        }

        Fixture noBlock() {
            this.block = null;
            return this;
        }

        private List<Instruction> sortedInstructions() {
            List<Instruction> copy = new ArrayList<>(instructions);
            copy.sort(Comparator.comparing(Instruction::getAddress));
            return copy;
        }

        private List<Function> sortedFunctions() {
            List<Function> copy = new ArrayList<>(functions);
            copy.sort(Comparator.comparing(Function::getEntryPoint));
            return copy;
        }

        FunctionService service() {
            ProgramProvider provider = mock(ProgramProvider.class);
            when(provider.getCurrentProgram()).thenReturn(program);
            ThreadingStrategy ts = new NoopThreadingStrategy();
            return new FunctionService(provider, ts);
        }
    }

    private static InstructionIterator instructionIterator(List<Instruction> items) {
        Iterator<Instruction> it = items.iterator();
        return new InstructionIterator() {
            @Override public boolean hasNext() { return it.hasNext(); }
            @Override public Instruction next() { return it.next(); }
            @Override public Iterator<Instruction> iterator() { return this; }
        };
    }

    private static FunctionIterator functionIterator(List<Function> items) {
        Iterator<Function> it = items.iterator();
        return new FunctionIterator() {
            @Override public boolean hasNext() { return it.hasNext(); }
            @Override public Function next() { return it.next(); }
            @Override public Iterator<Function> iterator() { return this; }
        };
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> okBody(Response r) {
        assertTrue("expected Response.Ok, got: " + r.toJson(), r instanceof Response.Ok);
        return (Map<String, Object>) ((Response.Ok) r).data();
    }

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> listing(Map<String, Object> body) {
        return (List<Map<String, Object>>) body.get("instructions");
    }

    private static List<String> texts(Map<String, Object> body) {
        List<String> out = new ArrayList<>();
        for (Map<String, Object> e : listing(body)) out.add((String) e.get("instruction"));
        return out;
    }

    // ------------------------------------------------------------------
    // The non-degenerate path must be byte-for-byte what it always was
    // ------------------------------------------------------------------

    @Test
    public void healthyBody_responseShapeIsUnchanged() {
        Fixture f = new Fixture()
                .block(0x400000L, 0x401fffL)
                .instruction(0x401000L, "PUSH EBP", 1)
                .instruction(0x401001L, "MOV EBP,ESP", 2)
                .instruction(0x401003L, "RET", 1)
                // Next function's code: must NOT appear.
                .instruction(0x401010L, "XOR EAX,EAX", 2);
        f.function(0x401000L, 0x401000L, 0x401003L);
        f.function(0x401010L, 0x401010L, 0x401011L);

        Map<String, Object> body = okBody(f.service().disassembleFunction("0x401000", ""));

        assertEquals(List.of("PUSH EBP", "MOV EBP,ESP", "RET"), texts(body));
        assertEquals(3, body.get("count"));
        // Exactly the pre-existing ServiceUtils.listed() envelope, nothing else.
        assertEquals("healthy bodies must not gain fields",
                List.of("instructions", "count"), new ArrayList<>(body.keySet()));
    }

    @Test
    public void genuineOneByteFunction_isNotReportedDegenerate() {
        // An empty __cdecl compiles to a bare RET. Its body is ONE address and
        // that is CORRECT -- the body reaches the end of its own instruction.
        // Flagging it would attach a degeneracy warning to a listing that was
        // already right.
        Fixture f = new Fixture()
                .block(0x400000L, 0x401fffL)
                .instruction(0x401000L, "RET", 1)
                .instruction(0x401001L, "INT3", 1)
                .instruction(0x401010L, "XOR EAX,EAX", 2);
        f.function(0x401000L, 0x401000L, 0x401000L);
        f.function(0x401010L, 0x401010L, 0x401011L);

        Map<String, Object> body = okBody(f.service().disassembleFunction("0x401000", ""));

        assertEquals(List.of("RET"), texts(body));
        assertEquals(List.of("instructions", "count"), new ArrayList<>(body.keySet()));
    }

    // ------------------------------------------------------------------
    // Degenerate bodies
    // ------------------------------------------------------------------

    @Test
    public void degenerateBody_isBoundedByTheNextFunction() {
        // The measured shape: body_end == body_start on a 5-byte first
        // instruction. Ghidra's own bound would have stopped after the MOV.
        Fixture f = new Fixture()
                .block(0x400000L, 0x401fffL)
                .instruction(0x401000L, "MOV EAX,[0x0040cf30]", 5)
                .instruction(0x401005L, "ADD EAX,0x4", 3)
                .instruction(0x401008L, "RET", 1)
                .instruction(0x401010L, "XOR EAX,EAX", 2);
        f.function(0x401000L, 0x401000L, 0x401000L);   // degenerate
        f.function(0x401010L, 0x401010L, 0x401011L);   // next function

        Map<String, Object> body = okBody(f.service().disassembleFunction("0x401000", ""));

        assertEquals(List.of("MOV EAX,[0x0040cf30]", "ADD EAX,0x4", "RET"), texts(body));
        assertEquals(3, body.get("count"));
        assertEquals(Boolean.TRUE, body.get("body_degenerate"));
        assertEquals("next_function", body.get("bounded_by"));
        assertTrue(String.valueOf(body.get("warning")).contains("degenerate"));
        assertTrue("warning must name the bound it used",
                String.valueOf(body.get("warning")).contains("next_function"));
    }

    @Test
    public void degenerateBody_trailingAlignmentFillIsTrimmed() {
        // MSVC pads to the next 16-byte boundary with INT3; other linkers use
        // NOP, including the multi-byte encodings Ghidra renders with operands.
        Fixture f = new Fixture()
                .block(0x400000L, 0x401fffL)
                .instruction(0x401000L, "MOV EAX,0x1", 5)
                .instruction(0x401005L, "RET", 1)
                .instruction(0x401006L, "INT3", 1)
                .instruction(0x401007L, "INT3", 1)
                .instruction(0x401008L, "NOP", 1)
                .instruction(0x401009L, "NOP dword ptr [EAX + EAX*0x1]", 7);
        f.function(0x401000L, 0x401000L, 0x401000L);
        f.function(0x401010L, 0x401010L, 0x401011L);

        Map<String, Object> body = okBody(f.service().disassembleFunction("0x401000", ""));

        assertEquals(List.of("MOV EAX,0x1", "RET"), texts(body));
        assertEquals(2, body.get("count"));
        assertEquals("next_function", body.get("bounded_by"));
    }

    @Test
    public void degenerateBody_interiorPaddingShapedInstructionsSurvive() {
        // Only the TAIL is trimmed. A NOP in the middle of a function is real
        // code -- it is reached by flow -- and removing it would silently
        // change the listing's meaning.
        Fixture f = new Fixture()
                .block(0x400000L, 0x401fffL)
                .instruction(0x401000L, "MOV EAX,0x1", 5)
                .instruction(0x401005L, "NOP", 1)
                .instruction(0x401006L, "RET", 1)
                .instruction(0x401007L, "INT3", 1);
        f.function(0x401000L, 0x401000L, 0x401000L);
        f.function(0x401010L, 0x401010L, 0x401011L);

        Map<String, Object> body = okBody(f.service().disassembleFunction("0x401000", ""));

        assertEquals(List.of("MOV EAX,0x1", "NOP", "RET"), texts(body));
    }

    @Test
    public void degenerateBody_entryInstructionIsNeverTrimmedAway() {
        // Everything visible looks like padding. Returning count 0 would be
        // strictly worse than the one-instruction answer we set out to fix.
        Fixture f = new Fixture()
                .block(0x400000L, 0x401fffL)
                .instruction(0x401000L, "NOP dword ptr [EAX + EAX*0x1]", 7)
                .instruction(0x401007L, "INT3", 1);
        f.function(0x401000L, 0x401000L, 0x401000L);
        f.function(0x401010L, 0x401010L, 0x401011L);

        Map<String, Object> body = okBody(f.service().disassembleFunction("0x401000", ""));

        assertEquals(1, body.get("count"));
        assertEquals(List.of("NOP dword ptr [EAX + EAX*0x1]"), texts(body));
    }

    @Test
    public void degenerateBody_lastFunctionInBlock_fallsBackToTheBlockEnd() {
        Fixture f = new Fixture()
                .block(0x400000L, 0x401007L)   // block ends right after the RET
                .instruction(0x401000L, "MOV EAX,[0x0040cf30]", 5)
                .instruction(0x401005L, "ADD EAX,0x4", 3)
                // Different block entirely: must NOT be swept in.
                .instruction(0x402000L, "PUSH EBP", 1);
        f.function(0x401000L, 0x401000L, 0x401000L);   // the only function

        Map<String, Object> body = okBody(f.service().disassembleFunction("0x401000", ""));

        assertEquals(List.of("MOV EAX,[0x0040cf30]", "ADD EAX,0x4"), texts(body));
        assertEquals("memory_block", body.get("bounded_by"));
        assertEquals(Boolean.TRUE, body.get("body_degenerate"));
        assertTrue(String.valueOf(body.get("warning")).contains("memory_block"));
    }

    @Test
    public void degenerateBody_nextFunctionBeyondTheBlockClampsToTheBlockEnd() {
        // The function iterator walks the WHOLE program, so the "next
        // function" for the last function in a block lives in a later block.
        // Bounding by it alone would sweep in the gap and the other block's
        // leading code. The tighter of the two bounds must win, and the
        // reported bounded_by must say which one that was.
        Fixture f = new Fixture()
                .block(0x400000L, 0x401007L)
                .instruction(0x401000L, "MOV EAX,[0x0040cf30]", 5)
                .instruction(0x401005L, "ADD EAX,0x4", 3)
                .instruction(0x402000L, "PUSH EBP", 1);
        f.function(0x401000L, 0x401000L, 0x401000L);
        f.function(0x402000L, 0x402000L, 0x402000L);   // next function, other block

        Map<String, Object> body = okBody(f.service().disassembleFunction("0x401000", ""));

        assertEquals(List.of("MOV EAX,[0x0040cf30]", "ADD EAX,0x4"), texts(body));
        assertEquals("memory_block", body.get("bounded_by"));
    }

    @Test
    public void degenerateBody_nextFunctionInAnotherAddressSpaceIsIgnored() {
        // Address.compareTo() orders by address SPACE first, so a function in
        // another space sorts after ours no matter what its offset is, and
        // using its entry as a bound would be meaningless -- previous() on it
        // yields an address in a space our listing never visits. The block end
        // is the only real bound here.
        Fixture f = new Fixture()
                .block(0x400000L, 0x401005L)
                .instruction(0x401000L, "MOV EAX,[0x0040cf30]", 5)
                .instruction(0x401005L, "RET", 1)
                .instruction(0x401006L, "INT3", 1);
        f.function(0x401000L, 0x401000L, 0x401000L);
        f.function(f.otherSpaceAddr(0x10L),
                new AddressSet(f.otherSpaceAddr(0x10L), f.otherSpaceAddr(0x10L)));

        Map<String, Object> body = okBody(f.service().disassembleFunction("0x401000", ""));

        assertEquals(List.of("MOV EAX,[0x0040cf30]", "RET"), texts(body));
        assertEquals("memory_block", body.get("bounded_by"));
    }

    @Test
    public void degenerateBody_withNoUsableBound_saysSoRatherThanInventingOne() {
        Fixture f = new Fixture()
                .noBlock()
                .instruction(0x401000L, "MOV EAX,[0x0040cf30]", 5)
                .instruction(0x401005L, "RET", 1);
        f.function(0x401000L, 0x401000L, 0x401000L);   // no next function, no block

        Map<String, Object> body = okBody(f.service().disassembleFunction("0x401000", ""));

        assertEquals(1, body.get("count"));
        assertEquals("function_body", body.get("bounded_by"));
        // Still flagged: the caller must not trust the extent even when we
        // could not do better than Ghidra did.
        assertEquals(Boolean.TRUE, body.get("body_degenerate"));
    }

    @Test
    public void emptyBody_listsInsteadOfThrowing() {
        // Before the fix an empty body made getMaxAddress() null and the
        // listing loop NPE'd into "Error disassembling function: null".
        Fixture f = new Fixture()
                .block(0x400000L, 0x401fffL)
                .instruction(0x401000L, "MOV EAX,0x1", 5)
                .instruction(0x401005L, "RET", 1);
        f.functionWithEmptyBody(0x401000L);
        f.function(0x401010L, 0x401010L, 0x401011L);

        Response r = f.service().disassembleFunction("0x401000", "");
        Map<String, Object> body = okBody(r);

        assertEquals(List.of("MOV EAX,0x1", "RET"), texts(body));
        assertEquals(Boolean.TRUE, body.get("body_degenerate"));
        assertEquals("next_function", body.get("bounded_by"));
    }

    @Test
    public void degenerateBody_stopsExactlyBeforeTheNextEntryPoint() {
        // Off-by-one guard on limit.previous(): the instruction sitting AT the
        // next function's entry belongs to that function, never to this one.
        Fixture f = new Fixture()
                .block(0x400000L, 0x401fffL)
                .instruction(0x401000L, "MOV EAX,0x1", 5)
                .instruction(0x401005L, "RET", 1)
                .instruction(0x401006L, "PUSH EBP", 1);
        f.function(0x401000L, 0x401000L, 0x401000L);
        f.function(0x401006L, 0x401006L, 0x401006L);   // starts immediately after

        Map<String, Object> body = okBody(f.service().disassembleFunction("0x401000", ""));

        assertEquals(List.of("MOV EAX,0x1", "RET"), texts(body));
        assertEquals("next_function", body.get("bounded_by"));
    }

    // ------------------------------------------------------------------
    // Helpers, tested directly
    // ------------------------------------------------------------------

    @Test
    public void alignmentFillMatchesWholeMnemonicsOnly() {
        assertTrue(FunctionService.isAlignmentFill("NOP"));
        assertTrue(FunctionService.isAlignmentFill("NOP dword ptr [EAX + EAX*0x1]"));
        assertTrue(FunctionService.isAlignmentFill("INT3"));
        assertFalse(FunctionService.isAlignmentFill("RET"));
        assertFalse(FunctionService.isAlignmentFill("INT 0x21"));
        assertFalse("a bare startsWith would eat this", FunctionService.isAlignmentFill("NOPE"));
        assertFalse(FunctionService.isAlignmentFill(null));
        // `??` is how the Ghidra LISTING renders undefined bytes -- Data, not
        // Instruction. getInstructions() never yields it, so matching on it
        // would advertise coverage that does not exist.
        assertFalse(FunctionService.isAlignmentFill("??"));
    }
}
