package com.xebyte.core;

import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import org.junit.Before;
import org.junit.Test;

import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

public class FunctionServiceRenameTest {
    private final Program program = mock(Program.class);
    private final Function target = mock(Function.class);
    private final Function existing = mock(Function.class);
    private FunctionService service;

    @Before
    public void setUp() {
        Address address = mock(Address.class);
        AddressSpace space = mock(AddressSpace.class);
        AddressFactory factory = mock(AddressFactory.class);
        FunctionManager manager = mock(FunctionManager.class);
        BookmarkManager bookmarks = mock(BookmarkManager.class);
        ProgramProvider provider = mock(ProgramProvider.class);
        when(address.getAddressSpace()).thenReturn(space);
        when(space.getType()).thenReturn(AddressSpace.TYPE_RAM);
        when(factory.getAddress("0x10060dc0")).thenReturn(address);
        when(factory.getAddressSpaces()).thenReturn(new AddressSpace[0]);
        when(program.getAddressFactory()).thenReturn(factory);
        when(program.getFunctionManager()).thenReturn(manager);
        when(program.getBookmarkManager()).thenReturn(bookmarks);
        when(bookmarks.getBookmarks(address)).thenReturn(new Bookmark[0]);
        when(manager.getFunctionAt(address)).thenReturn(target);
        when(manager.getFunctions(true)).thenAnswer(inv -> {
            FunctionIterator functions = mock(FunctionIterator.class);
            when(functions.iterator()).thenReturn(List.of(target, existing).iterator());
            return functions;
        });
        when(target.getName()).thenReturn("FUN_10060dc0");
        when(target.getEntryPoint()).thenReturn(address);
        when(existing.getName()).thenReturn("GetTransform");
        when(provider.getCurrentProgram()).thenReturn(program);
        service = new FunctionService(provider, new ThreadingStrategy() {
            public <T> T executeRead(Callable<T> action) throws Exception {
                return action.call();
            }
            public <T> T executeWrite(Program p, String name, Callable<T> action) throws Exception {
                return action.call();
            }
            public boolean isHeadless() { return true; }
        });
    }

    @Test
    public void descriptiveSupersetNameIsAllowedInEnforceMode() throws Exception {
        assertAdvisoryRename("GetNamedMatrixAlignmentTransformFlags");
    }

    @Test
    public void trailingSpecifierIsAllowedInEnforceMode() throws Exception {
        assertAdvisoryRename("GetTransformFlags");
    }

    @Test
    public void shorterRelatedNameIsAllowedInEnforceMode() throws Exception {
        when(existing.getName()).thenReturn("GetTransformFlags");
        assertAdvisoryRename("GetTransform");
    }

    private void assertAdvisoryRename(String name) throws Exception {
        Response response = service.renameFunctionByAddress(target, name, program, "enforce");
        assertTrue(response.toJson(), response instanceof Response.Ok);
        Map<?, ?> data = (Map<?, ?>) ((Response.Ok) response).data();
        assertEquals(response.toJson(), "success", data.get("status"));
        assertTrue(response.toJson(), data.get("warnings").toString().contains("Advisory name similarity"));
        verify(target).setName(name, SourceType.USER_DEFINED);
    }

    @Test
    public void namingQualityStillRejectsWithoutWriting() throws Exception {
        Response response = service.renameFunctionByAddress(target, "Get", program, "enforce");
        Map<?, ?> data = (Map<?, ?>) ((Response.Ok) response).data();
        assertEquals("rejected", data.get("status"));
        assertEquals("name_quality", data.get("error"));
        verify(target, never()).setName(anyString(), any(SourceType.class));
    }
}
