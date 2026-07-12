package com.xebyte.core;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import org.junit.Test;
import org.mockito.InOrder;

import java.util.Map;
import java.util.concurrent.Callable;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

public class FunctionServiceNoReturnTest {

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

    private static final class FunctionDouble {
        final Function function;
        private Function target;
        private boolean localNoReturn;
        private boolean ignoreLocalSet;
        private RuntimeException detachedSetFailure;

        FunctionDouble(String name, boolean localNoReturn) {
            this.function = mock(Function.class);
            this.localNoReturn = localNoReturn;

            when(function.getName()).thenReturn(name);
            when(function.isThunk()).thenAnswer(invocation -> target != null);
            when(function.getThunkedFunction(anyBoolean())).thenAnswer(invocation -> target);
            when(function.hasNoReturn()).thenAnswer(invocation -> this.localNoReturn);

            doAnswer(invocation -> {
                target = invocation.getArgument(0);
                return null;
            }).when(function).setThunkedFunction(nullable(Function.class));

            doAnswer(invocation -> {
                boolean value = invocation.getArgument(0);
                if (target != null) {
                    target.setNoReturn(value);
                } else {
                    if (detachedSetFailure != null) {
                        throw detachedSetFailure;
                    }
                    if (!ignoreLocalSet) {
                        this.localNoReturn = value;
                    }
                }
                return null;
            }).when(function).setNoReturn(anyBoolean());
        }

        FunctionDouble linkTo(FunctionDouble target) {
            this.target = target.function;
            return this;
        }

        FunctionDouble failWhenSetWhileDetached(RuntimeException failure) {
            this.detachedSetFailure = failure;
            return this;
        }

        FunctionDouble ignoreLocalSet() {
            this.ignoreLocalSet = true;
            return this;
        }
    }

    @Test
    public void clearStaleThunkFlagUpdatesLocalAndTerminalStateInOrder() {
        FunctionDouble terminal = new FunctionDouble("target", true);
        FunctionDouble thunk = new FunctionDouble("thunk", true).linkTo(terminal);

        FunctionService.NoReturnUpdateResult result =
            FunctionService.setNoReturnState(thunk.function, false);

        assertFalse(thunk.function.hasNoReturn());
        assertFalse(terminal.function.hasNoReturn());
        assertSame(terminal.function, thunk.function.getThunkedFunction(false));
        assertFalse(result.functionNoReturn());
        assertFalse(result.terminalNoReturn());

        InOrder order = inOrder(thunk.function, terminal.function);
        order.verify(thunk.function).setThunkedFunction(isNull());
        order.verify(thunk.function).setNoReturn(false);
        order.verify(thunk.function).setThunkedFunction(terminal.function);
        order.verify(terminal.function).setNoReturn(false);
    }

    @Test
    public void setNoReturnOnThunkUpdatesLocalAndTerminalState() {
        FunctionDouble terminal = new FunctionDouble("target", false);
        FunctionDouble thunk = new FunctionDouble("thunk", false).linkTo(terminal);

        FunctionService.NoReturnUpdateResult result =
            FunctionService.setNoReturnState(thunk.function, true);

        assertTrue(thunk.function.hasNoReturn());
        assertTrue(terminal.function.hasNoReturn());
        assertTrue(result.functionNoReturn());
        assertTrue(result.terminalNoReturn());
    }

    @Test
    public void exceptionDuringDetachedUpdateRestoresOriginalThunkLink() {
        FunctionDouble terminal = new FunctionDouble("target", true);
        FunctionDouble thunk = new FunctionDouble("thunk", true)
            .linkTo(terminal)
            .failWhenSetWhileDetached(new IllegalStateException("local write failed"));

        IllegalStateException error = assertThrows(IllegalStateException.class,
            () -> FunctionService.setNoReturnState(thunk.function, false));

        assertEquals("local write failed", error.getMessage());
        assertSame(terminal.function, thunk.function.getThunkedFunction(false));
        verify(thunk.function).setThunkedFunction(isNull());
        verify(thunk.function).setThunkedFunction(terminal.function);
        verify(terminal.function, never()).setNoReturn(anyBoolean());
    }

    @Test
    public void nonThunkUsesDirectUpdateWithoutDetaching() {
        FunctionDouble function = new FunctionDouble("plain", false);

        FunctionService.NoReturnUpdateResult result =
            FunctionService.setNoReturnState(function.function, true);

        assertTrue(result.functionNoReturn());
        assertTrue(result.terminalNoReturn());
        verify(function.function).setNoReturn(true);
        verify(function.function, never()).setThunkedFunction(nullable(Function.class));
    }

    @Test
    public void consistentThunkSkipsDetachButStillUpdatesTerminal() {
        FunctionDouble terminal = new FunctionDouble("target", true);
        FunctionDouble thunk = new FunctionDouble("thunk", false).linkTo(terminal);

        FunctionService.setNoReturnState(thunk.function, false);

        assertFalse(thunk.function.hasNoReturn());
        assertFalse(terminal.function.hasNoReturn());
        verify(thunk.function, never()).setThunkedFunction(nullable(Function.class));
        verify(thunk.function, never()).setNoReturn(anyBoolean());
        verify(terminal.function).setNoReturn(false);
    }

    @Test
    public void multiHopChainSynchronizesEveryLocalFlagAndPreservesLinks() {
        FunctionDouble terminal = new FunctionDouble("target", true);
        FunctionDouble middle = new FunctionDouble("middle", true).linkTo(terminal);
        FunctionDouble entry = new FunctionDouble("entry", true).linkTo(middle);

        FunctionService.setNoReturnState(entry.function, false);

        assertFalse(entry.function.hasNoReturn());
        assertFalse(middle.function.hasNoReturn());
        assertFalse(terminal.function.hasNoReturn());
        assertSame(middle.function, entry.function.getThunkedFunction(false));
        assertSame(terminal.function, middle.function.getThunkedFunction(false));
    }

    @Test
    public void verificationMismatchFailsTheOperation() {
        FunctionDouble function = new FunctionDouble("unchanged", false).ignoreLocalSet();

        IllegalStateException error = assertThrows(IllegalStateException.class,
            () -> FunctionService.setNoReturnState(function.function, true));

        assertTrue(error.getMessage().contains("unchanged"));
        assertTrue(error.getMessage().contains("expected true"));
        assertTrue(error.getMessage().contains("actual false"));
        assertFalse(function.function.hasNoReturn());
    }

    @Test
    @SuppressWarnings("unchecked")
    public void endpointReportsVerifiedSelectedAndTerminalStates() {
        Address address = mock(Address.class);
        AddressFactory addressFactory = mock(AddressFactory.class);
        FunctionManager functionManager = mock(FunctionManager.class);
        Program program = mock(Program.class);
        ProgramProvider provider = mock(ProgramProvider.class);

        FunctionDouble terminal = new FunctionDouble("target", true);
        FunctionDouble thunk = new FunctionDouble("thunk", true).linkTo(terminal);

        when(addressFactory.getAddress("0x1000")).thenReturn(address);
        when(program.getAddressFactory()).thenReturn(addressFactory);
        when(program.getFunctionManager()).thenReturn(functionManager);
        when(functionManager.getFunctionAt(address)).thenReturn(thunk.function);
        when(provider.getCurrentProgram()).thenReturn(program);

        FunctionService service = new FunctionService(provider, new InlineThreadingStrategy());
        Response response = service.setFunctionNoReturn("0x1000", false, "");

        assertTrue(response instanceof Response.Ok);
        Map<String, Object> body = (Map<String, Object>) ((Response.Ok) response).data();
        assertEquals("success", body.get("status"));
        assertEquals(Boolean.FALSE, body.get("function_no_return"));
        assertEquals(Boolean.FALSE, body.get("terminal_no_return"));
        assertTrue(((String) body.get("message")).contains("to returning"));
    }
}
