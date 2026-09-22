package com.xebyte.core;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.FunctionTag;
import ghidra.program.model.listing.Program;
import org.junit.Test;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Callable;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Regression coverage for the 2026-09-21 incident: {@code /delete_function} on any
 * function that carried a {@link FunctionTag} threw
 * {@code java.util.ConcurrentModificationException} from inside Ghidra's own
 * {@code FunctionManagerDB.doRemoveFunction}, which iterates the function's live tag
 * set while removing tags from it (stack: {@code HashMap$KeyIterator.next} &lt;-
 * {@code FunctionManagerDB.doRemoveFunction} &lt;- {@code FunctionSymbol.delete} &lt;-
 * {@code FunctionManagerDB.removeFunction} &lt;-
 * {@code FunctionService.deleteFunctionAtAddress}). The fix detaches every tag from the
 * function itself, via the same {@code func.removeTag(name)} call
 * {@code /remove_function_tag} already uses, before calling
 * {@code FunctionManager.removeFunction}, so Ghidra's internal loop has nothing left to
 * iterate.
 *
 * <p>This test cannot drive real Ghidra database internals, but it reproduces the exact
 * failure mechanism with a plain {@link java.util.LinkedHashSet}: the mocked
 * {@code FunctionManager.removeFunction} stands in for
 * {@code FunctionManagerDB.doRemoveFunction} and iterates the function's own (mocked)
 * tag set while removing from that same set outside the iterator -- the textbook
 * fail-fast trigger, and the same live-view mutation Ghidra's real implementation
 * performs. If {@code deleteFunctionAtAddress} still had tags attached when this runs,
 * the test throws a genuine {@code ConcurrentModificationException}, exactly as it does
 * against a live Ghidra program.
 */
public class FunctionServiceDeleteFunctionTest {

    private static final class InlineThreadingStrategy implements ThreadingStrategy {
        @Override
        public <T> T executeRead(Callable<T> action) throws Exception {
            return action.call();
        }

        @Override
        public <T> T executeWrite(Program program, String txName, Callable<T> action)
                throws Exception {
            return action.call();
        }

        @Override
        public boolean isHeadless() {
            return true;
        }
    }

    /** Wires a mocked Program/FunctionManager/Function so deleteFunctionAtAddress runs for real. */
    private static final class Fixture {
        final Program program = mock(Program.class);
        final FunctionManager functionManager = mock(FunctionManager.class);
        final Function func = mock(Function.class);
        final Address addr = mock(Address.class);
        final AddressFactory addressFactory = mock(AddressFactory.class);
        final ProgramProvider provider = mock(ProgramProvider.class);
        final Set<FunctionTag> liveTags = new LinkedHashSet<>();

        Fixture(String addressStr, String... tagNames) {
            AddressSpace space = mock(AddressSpace.class);
            when(space.isOverlaySpace()).thenReturn(false);
            when(space.getType()).thenReturn(AddressSpace.TYPE_RAM);
            when(addr.toString(false)).thenReturn(addressStr.replace("0x", ""));
            when(addr.getAddressSpace()).thenReturn(space);

            when(addressFactory.getAddress(addressStr)).thenReturn(addr);
            when(addressFactory.getAddressSpaces()).thenReturn(new AddressSpace[0]);
            when(program.getAddressFactory()).thenReturn(addressFactory);
            when(program.getFunctionManager()).thenReturn(functionManager);

            AddressSetView body = mock(AddressSetView.class);
            when(body.getNumAddresses()).thenReturn(42L);
            when(func.getName()).thenReturn("FUN_" + addressStr.replace("0x", ""));
            when(func.getBody()).thenReturn(body);

            for (String name : tagNames) {
                FunctionTag tag = mock(FunctionTag.class);
                when(tag.getName()).thenReturn(name);
                liveTags.add(tag);
            }
            when(func.getTags()).thenAnswer(inv -> liveTags);
            doAnswer(inv -> {
                String name = inv.getArgument(0);
                liveTags.removeIf(t -> t.getName().equals(name));
                return null;
            }).when(func).removeTag(anyString());

            when(functionManager.getFunctionAt(addr)).thenReturn(func);

            // Stands in for FunctionManagerDB.doRemoveFunction: iterates the function's
            // own live tag set while removing from that same set outside the iterator.
            // Throws a real ConcurrentModificationException if any tag is still
            // attached when this runs -- the exact bug this test guards against.
            doAnswer(inv -> {
                for (FunctionTag t : func.getTags()) {
                    liveTags.remove(t);
                }
                return null;
            }).when(functionManager).removeFunction(addr);

            when(provider.getCurrentProgram()).thenReturn(program);
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    public void deletingATaggedFunctionDetachesItsTagsFirstAndDoesNotThrowCME() {
        Fixture fx = new Fixture("0x401000", "HOT", "REVIEWED");

        FunctionService service = new FunctionService(fx.provider, new InlineThreadingStrategy());
        Response response = service.deleteFunctionAtAddress("0x401000", "");

        assertTrue("expected success, got: " + response.toJson(), response instanceof Response.Ok);
        Map<String, Object> body = (Map<String, Object>) ((Response.Ok) response).data();
        assertEquals(Boolean.TRUE, body.get("success"));
        assertEquals("FUN_401000", body.get("deleted_function"));
        assertEquals(List.of("HOT", "REVIEWED"), body.get("detached_tags"));
        assertTrue("tag set must be fully detached", fx.liveTags.isEmpty());

        verify(fx.func).removeTag("HOT");
        verify(fx.func).removeTag("REVIEWED");
        verify(fx.functionManager).removeFunction(fx.addr);
    }

    @Test
    @SuppressWarnings("unchecked")
    public void deletingAnUntaggedFunctionStillWorks() {
        Fixture fx = new Fixture("0x402000");

        FunctionService service = new FunctionService(fx.provider, new InlineThreadingStrategy());
        Response response = service.deleteFunctionAtAddress("0x402000", "");

        assertTrue("expected success, got: " + response.toJson(), response instanceof Response.Ok);
        Map<String, Object> body = (Map<String, Object>) ((Response.Ok) response).data();
        assertEquals(Boolean.TRUE, body.get("success"));
        assertEquals(List.of(), body.get("detached_tags"));
        verify(fx.func, never()).removeTag(anyString());
        verify(fx.functionManager).removeFunction(fx.addr);
    }
}
