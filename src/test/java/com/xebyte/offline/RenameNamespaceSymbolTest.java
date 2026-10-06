package com.xebyte.offline;

import com.xebyte.core.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import org.junit.Test;

import java.util.List;
import java.util.concurrent.Callable;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class RenameNamespaceSymbolTest {
    private final Program program = mock(Program.class);
    private final SymbolTable table = mock(SymbolTable.class);
    private final Namespace global = mock(Namespace.class);

    private SymbolLabelService service(List<Symbol> symbols) {
        when(program.getSymbolTable()).thenReturn(table);
        when(program.getGlobalNamespace()).thenReturn(global);
        when(global.isGlobal()).thenReturn(true);
        when(table.getAllSymbols(true)).thenAnswer(inv -> {
            var inner = symbols.iterator();
            SymbolIterator iterator = mock(SymbolIterator.class);
            when(iterator.iterator()).thenReturn(iterator);
            when(iterator.hasNext()).thenAnswer(call -> inner.hasNext());
            when(iterator.next()).thenAnswer(call -> inner.next());
            return iterator;
        });
        ProgramProvider provider = mock(ProgramProvider.class);
        when(provider.getCurrentProgram()).thenReturn(program);
        return new SymbolLabelService(provider, new ThreadingStrategy() {
            public <T> T executeRead(Callable<T> action) throws Exception { return action.call(); }
            public <T> T executeWrite(Program p, String name, Callable<T> action) throws Exception {
                return action.call();
            }
            public boolean isHeadless() { return true; }
        });
    }

    private Namespace namespace(String name, String qualified, Namespace parent, SymbolType type) {
        Namespace ns = mock(Namespace.class);
        Symbol symbol = mock(Symbol.class);
        when(ns.getSymbol()).thenReturn(symbol);
        when(ns.getParentNamespace()).thenReturn(parent);
        when(symbol.getSymbolType()).thenReturn(type);
        when(symbol.getName()).thenReturn(name);
        when(symbol.getName(true)).thenReturn(qualified);
        return ns;
    }

    private Symbol member(Namespace parent) {
        Symbol symbol = mock(Symbol.class);
        when(symbol.getSymbolType()).thenReturn(SymbolType.FUNCTION);
        when(symbol.getParentNamespace()).thenReturn(parent);
        return symbol;
    }

    @Test
    public void findsAddresslessClassThroughMembers() throws Exception {
        Namespace cls = namespace("AutoClass2", "AutoClass2", global, SymbolType.CLASS);
        Response response = service(List.of(member(cls), member(cls)))
                .renameSymbol("AutoClass2", "VariantValue", "class", "", "");
        assertTrue(response.toJson(), response instanceof Response.Ok);
        verify(cls.getSymbol()).setName("VariantValue", SourceType.USER_DEFINED);
    }

    @Test
    public void findsEmptyGlobalClassDirectly() throws Exception {
        Namespace cls = namespace("AutoClass2", "AutoClass2", global, SymbolType.CLASS);
        SymbolLabelService service = service(List.of());
        when(table.getNamespace("AutoClass2", global)).thenReturn(cls);
        assertTrue(service.renameSymbol("AutoClass2", "VariantValue", "class", "", "") instanceof Response.Ok);
        verify(cls.getSymbol()).setName("VariantValue", SourceType.USER_DEFINED);
    }

    @Test
    public void findsNamespaceThroughNestedMemberAncestors() throws Exception {
        Namespace outer = namespace("ddd", "ddd", global, SymbolType.NAMESPACE);
        Namespace inner = namespace("AutoClass2", "ddd::AutoClass2", outer, SymbolType.CLASS);
        assertTrue(service(List.of(member(inner)))
                .renameSymbol("ddd", "values", "namespace", "", "") instanceof Response.Ok);
        verify(outer.getSymbol()).setName("values", SourceType.USER_DEFINED);
    }

    @Test
    public void rejectsAmbiguousBareNamesWithoutRenaming() throws Exception {
        Namespace one = namespace("AutoClass2", "one::AutoClass2", global, SymbolType.CLASS);
        Namespace two = namespace("AutoClass2", "two::AutoClass2", global, SymbolType.CLASS);
        Response response = service(List.of(member(one), member(two)))
                .renameSymbol("AutoClass2", "VariantValue", "class", "", "");
        assertTrue(response.toJson().contains("Ambiguous namespace"));
        verify(one.getSymbol(), never()).setName(anyString(), any());
        verify(two.getSymbol(), never()).setName(anyString(), any());
    }

    @Test
    public void qualifiedNameDisambiguatesAddresslessClasses() throws Exception {
        Namespace one = namespace("AutoClass2", "one::AutoClass2", global, SymbolType.CLASS);
        Namespace two = namespace("AutoClass2", "two::AutoClass2", global, SymbolType.CLASS);
        assertTrue(service(List.of(member(one), member(two)))
                .renameSymbol("two::AutoClass2", "VariantValue", "class", "", "") instanceof Response.Ok);
        verify(two.getSymbol()).setName("VariantValue", SourceType.USER_DEFINED);
        verify(one.getSymbol(), never()).setName(anyString(), any());
    }
}
