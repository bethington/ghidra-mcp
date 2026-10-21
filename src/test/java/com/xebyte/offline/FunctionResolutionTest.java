package com.xebyte.offline;

import com.xebyte.core.ServiceUtils;
import com.xebyte.core.ServiceUtils.FunctionOrError;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.DefaultAddressFactory;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import org.junit.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

/**
 * One rule for what a function reference means, for every endpoint.
 *
 * <p>There were two resolvers. One had a case-insensitive fallback and the other did not,
 * so a name typed in the wrong case worked in some tools and not others. Neither noticed
 * a name two functions share (it took the first hit), a function named like a hex number
 * ("add", "dead") resolved to whatever sat at that address, and a miss said one of seven
 * different things. These pin the single policy.
 */
public class FunctionResolutionTest {

    private static final class Fixture {
        final AddressSpace ram = new GenericAddressSpace("ram", 32, AddressSpace.TYPE_RAM, 0);
        final AddressFactory factory = new DefaultAddressFactory(new AddressSpace[] {ram}, ram);
        final Program program = mock(Program.class);
        final FunctionManager functionManager = mock(FunctionManager.class);
        final SymbolTable symbolTable = mock(SymbolTable.class);
        final List<Function> functions = new ArrayList<>();
        final List<Symbol> symbols = new ArrayList<>();

        Fixture() {
            when(program.getAddressFactory()).thenReturn(factory);
            when(program.getFunctionManager()).thenReturn(functionManager);
            when(program.getSymbolTable()).thenReturn(symbolTable);
            when(functionManager.getFunctionAt(any(Address.class))).thenAnswer(inv -> {
                Address at = inv.getArgument(0);
                return functions.stream().filter(f -> f.getEntryPoint().equals(at)).findFirst().orElse(null);
            });
            // A function "contains" an address when it starts within 0x10 before it.
            when(functionManager.getFunctionContaining(any(Address.class))).thenAnswer(inv -> {
                Address at = inv.getArgument(0);
                return functions.stream().filter(f -> {
                    long d = at.getOffset() - f.getEntryPoint().getOffset();
                    return d >= 0 && d < 0x10;
                }).findFirst().orElse(null);
            });
            when(functionManager.getFunctions(anyBoolean())).thenAnswer(inv -> iterator(functions));
            when(symbolTable.getSymbols(anyString())).thenAnswer(inv -> {
                String name = inv.getArgument(0);
                return symbolIterator(symbols.stream().filter(s -> s.getName().equals(name)).toList());
            });
        }

        Function function(String name, long entry) {
            return function(name, entry, false, null);
        }

        Function function(String name, long entry, boolean thunk, String namespace) {
            Function f = mock(Function.class);
            Address at = ram.getAddress(entry);
            when(f.getName()).thenReturn(name);
            when(f.getEntryPoint()).thenReturn(at);
            when(f.isThunk()).thenReturn(thunk);
            Namespace ns = mock(Namespace.class);
            when(ns.isGlobal()).thenReturn(namespace == null);
            when(ns.getName(true)).thenReturn(namespace);
            when(f.getParentNamespace()).thenReturn(ns);
            functions.add(f);
            Symbol sym = mock(Symbol.class);
            when(sym.getName()).thenReturn(name);
            when(sym.getAddress()).thenReturn(at);
            when(sym.getSymbolType()).thenReturn(SymbolType.FUNCTION);
            symbols.add(sym);
            return f;
        }

        FunctionOrError resolve(String ref) {
            return ServiceUtils.getFunctionOrError(program, ref);
        }
    }

    private static FunctionIterator iterator(List<Function> list) {
        FunctionIterator it = mock(FunctionIterator.class);
        java.util.Iterator<Function> inner = list.iterator();
        when(it.iterator()).thenReturn(it);
        when(it.hasNext()).thenAnswer(inv -> inner.hasNext());
        when(it.next()).thenAnswer(inv -> inner.next());
        return it;
    }

    private static SymbolIterator symbolIterator(List<Symbol> list) {
        SymbolIterator it = mock(SymbolIterator.class);
        java.util.Iterator<Symbol> inner = list.iterator();
        when(it.hasNext()).thenAnswer(inv -> inner.hasNext());
        when(it.next()).thenAnswer(inv -> inner.next());
        return it;
    }

    @Test
    public void anExactNameResolves() {
        Fixture f = new Fixture();
        Function foo = f.function("syna_helper", 0x1000);
        assertSame(foo, f.resolve("syna_helper").function());
    }

    @Test
    public void aNameTypedInTheWrongCaseResolvesWhenNothingMatchesExactly() {
        Fixture f = new Fixture();
        Function foo = f.function("DrawFrame", 0x1000);
        assertSame(foo, f.resolve("drawframe").function());
    }

    @Test
    public void anExactMatchBeatsACaseInsensitiveOne() {
        Fixture f = new Fixture();
        f.function("Init", 0x1000);
        Function lower = f.function("init", 0x2000);
        assertSame(lower, f.resolve("init").function());
    }

    @Test
    public void aBareTokenThatNamesAFunctionIsThatFunctionNotTheAddress() {
        // "add" is valid hex. Address-first sent it to whatever contains 0xadd.
        Fixture f = new Fixture();
        f.function("other", 0xadd);
        Function add = f.function("add", 0x4000);
        assertSame(add, f.resolve("add").function());
    }

    @Test
    public void an0xPrefixedValueIsAlwaysAnAddress() {
        Fixture f = new Fixture();
        Function other = f.function("other", 0xadd);
        f.function("add", 0x4000);
        assertSame(other, f.resolve("0xadd").function());
    }

    @Test
    public void anAddressResolvesToTheFunctionAtOrContainingIt() {
        Fixture f = new Fixture();
        Function foo = f.function("foo", 0x1000);
        assertSame(foo, f.resolve("0x1000").function());
        assertSame("interior address", foo, f.resolve("0x1008").function());
        assertSame("bare hex", foo, f.resolve("1000").function());
    }

    @Test
    public void aNameTwoFunctionsShareIsAnErrorListingBoth() {
        Fixture f = new Fixture();
        f.function("Init", 0x1000, false, "CGame");
        f.function("Init", 0x2000, false, "CUi");
        FunctionOrError r = f.resolve("Init");
        assertTrue(r.hasError());
        assertTrue(r.message(), r.message().contains("ambiguous"));
        assertTrue(r.message(), r.message().contains("00001000") && r.message().contains("00002000"));
        assertTrue("says which namespace each is in: " + r.message(),
            r.message().contains("CGame") && r.message().contains("CUi"));
        assertTrue(r.message(), r.message().contains("Pass the address"));
    }

    @Test
    public void aRealFunctionBeatsItsThunk() {
        Fixture f = new Fixture();
        f.function("send", 0x1000, true, null);
        Function real = f.function("send", 0x2000, false, null);
        assertSame(real, f.resolve("send").function());
    }

    @Test
    public void twoThunksOfTheSameNameStillAmbiguous() {
        Fixture f = new Fixture();
        f.function("send", 0x1000, true, null);
        f.function("send", 0x2000, true, null);
        assertTrue(f.resolve("send").message().contains("ambiguous"));
    }

    @Test
    public void aMissSaysWhatWasTried() {
        Fixture f = new Fixture();
        f.function("foo", 0x1000);
        assertEquals("Function not found: 'nope' (not a function name, and not an address)",
            f.resolve("nope").message());
        assertTrue(f.resolve("0x9000").message(),
            f.resolve("0x9000").message().startsWith("Function not found: '0x9000'"));
        assertTrue(f.resolve("0x9000").message().contains("no function at or containing that address"));
    }

    @Test
    public void aBlankReferenceIsRefused() {
        Fixture f = new Fixture();
        assertEquals("Function name or address is required", f.resolve("  ").message());
        assertEquals("Function name or address is required", f.resolve(null).message());
    }

    @Test
    public void errorIsAResponseThatCarriesTheMessage() {
        Fixture f = new Fixture();
        assertEquals("{\"error\":\"Function not found: 'x' (not a function name, and not an address)\"}"
                .replace(" ", ""), f.resolve("x").error().toJson().replace(" ", ""));
    }

    // ---- resolveFunctionAddress: the same rule, for callers that need an Address

    @Test
    public void functionAddressOfANameIsItsEntryPoint() {
        Fixture f = new Fixture();
        Function foo = f.function("foo", 0x1000);
        assertEquals(foo.getEntryPoint(), ServiceUtils.resolveFunctionAddress(f.program, "foo"));
    }

    @Test
    public void functionAddressKeepsAnInteriorAddressInterior() {
        Fixture f = new Fixture();
        f.function("foo", 0x1000);
        assertEquals(f.ram.getAddress(0x1008), ServiceUtils.resolveFunctionAddress(f.program, "0x1008"));
    }

    @Test
    public void functionAddressOfAnAmbiguousNameFailsWithTheReasonForTheCallerToReport() {
        Fixture f = new Fixture();
        f.function("Init", 0x1000);
        f.function("Init", 0x2000);
        assertNull(ServiceUtils.resolveFunctionAddress(f.program, "Init"));
        assertTrue(ServiceUtils.getLastParseError(), ServiceUtils.getLastParseError().contains("ambiguous"));
    }

    @Test
    public void functionAddressOfAMissNamesTheFunctionNotTheAddressSpaces() {
        // It used to say "Address 'nope' could not be resolved in the default address space".
        Fixture f = new Fixture();
        assertNull(ServiceUtils.resolveFunctionAddress(f.program, "nope"));
        assertEquals("Function not found: 'nope' (not a function name, and not an address)",
            ServiceUtils.getLastParseError());
    }

    // ---- findGlobalSymbol: the lookup rename_symbol runs twice

    private static Symbol symbol(String name, SymbolType type) {
        Symbol sym = mock(Symbol.class);
        when(sym.getName()).thenReturn(name);
        when(sym.getSymbolType()).thenReturn(type);
        return sym;
    }

    @Test
    public void aGlobalNamespaceSymbolIsTheGlobal() {
        Fixture f = new Fixture();
        Namespace global = mock(Namespace.class);
        when(f.program.getGlobalNamespace()).thenReturn(global);
        Symbol inGlobal = symbol("g_x", SymbolType.LABEL);
        when(f.symbolTable.getSymbols("g_x", global)).thenReturn(new ArrayList<>(List.of(inGlobal)));
        assertSame(inGlobal, ServiceUtils.findGlobalSymbol(f.program, "g_x"));
    }

    @Test
    public void otherwiseTheFirstNonFunctionSymbolAnywhereWins() {
        Fixture f = new Fixture();
        Namespace global = mock(Namespace.class);
        when(f.program.getGlobalNamespace()).thenReturn(global);
        when(f.symbolTable.getSymbols("g_x", global)).thenReturn(new ArrayList<>());
        Symbol fn = symbol("g_x", SymbolType.FUNCTION);
        Symbol label = symbol("g_x", SymbolType.LABEL);
        when(f.symbolTable.getSymbols("g_x")).thenAnswer(inv -> symbolIterator(List.of(fn, label)));
        assertSame("a function symbol is not a global variable", label,
            ServiceUtils.findGlobalSymbol(f.program, "g_x"));
    }

    @Test
    public void noGlobalIsNull() {
        Fixture f = new Fixture();
        Namespace global = mock(Namespace.class);
        when(f.program.getGlobalNamespace()).thenReturn(global);
        when(f.symbolTable.getSymbols("g_x", global)).thenReturn(new ArrayList<>());
        when(f.symbolTable.getSymbols("g_x")).thenAnswer(inv -> symbolIterator(List.of()));
        assertNull(ServiceUtils.findGlobalSymbol(f.program, "g_x"));
    }
}
