package com.xebyte.offline;

import com.xebyte.core.partition.PartitionContext;
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
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.ReferenceManager;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Shared mock Program / {@link PartitionContext} builder for partitioner offline tests.
 *
 * <p>Eligible functions are wired through the real {@link PartitionContext} constructor
 * (FunctionManager + {@code getInstructionAt}). The literal index that partitioners
 * read is installed via reflection: building it through Listing/Data would require
 * {@code StringDataType}, whose static init needs Ghidra's full runtime and fails
 * under {@code env -u GHIDRA_INSTALL_DIR} (the offline CI gate).
 */
final class PartitionFixtures {

    private PartitionFixtures() {
    }

    static Builder builder() {
        return new Builder();
    }

    static final class Builder {
        private final AddressSpace ram = new GenericAddressSpace("ram", 32, AddressSpace.TYPE_RAM, 0);
        private final AddressFactory factory =
                new DefaultAddressFactory(new AddressSpace[]{ram}, ram);
        private final List<FnSpec> specs = new ArrayList<>();

        Builder function(String name, long entry) {
            specs.add(new FnSpec(name, entry));
            return this;
        }

        /** Raw string(s) referenced by the last function (feeds qualified-name + locality). */
        Builder withStrings(String... texts) {
            for (String t : texts) {
                last().rawStrings.add(t);
            }
            return this;
        }

        /** High-constant page keys ({@code value >>> 24}) for the last function. */
        Builder withPages(long... pageKeys) {
            for (long p : pageKeys) {
                last().pages.add(p);
            }
            return this;
        }

        /**
         * Median referenced-string address for the last function; {@code -1} means none.
         * When omitted, defaults to {@code -1} unless {@link #withStrings} was used, in
         * which case a synthetic increasing address is assigned at {@link #context()} time.
         */
        Builder withMedianStringAddr(long addr) {
            last().medianStringAddr = addr;
            last().medianSet = true;
            return this;
        }

        PartitionContext context() {
            PartitionContext ctx = new PartitionContext(program());
            installLiterals(ctx, buildLiteralIndex());
            return ctx;
        }

        Program program() {
            Listing listing = mock(Listing.class);
            FunctionManager fm = mock(FunctionManager.class);
            ReferenceManager rm = mock(ReferenceManager.class);
            Program program = mock(Program.class);
            when(program.getListing()).thenReturn(listing);
            when(program.getFunctionManager()).thenReturn(fm);
            when(program.getReferenceManager()).thenReturn(rm);
            when(program.getAddressFactory()).thenReturn(factory);

            Map<Address, Instruction> insnAt = new HashMap<>();
            List<Function> functions = new ArrayList<>();

            for (FnSpec spec : specs) {
                Address entry = addr(spec.entry);
                AddressSet body = new AddressSet(entry, addr(spec.entry + 0x0f));
                Function f = mock(Function.class);
                when(f.getName()).thenReturn(spec.name);
                when(f.getEntryPoint()).thenReturn(entry);
                when(f.getBody()).thenReturn(body);
                when(f.isExternal()).thenReturn(false);
                when(f.isThunk()).thenReturn(false);
                functions.add(f);

                Instruction insn = mock(Instruction.class);
                when(insn.getAddress()).thenReturn(entry);
                insnAt.put(entry, insn);
            }

            when(listing.getInstructionAt(any(Address.class))).thenAnswer(inv ->
                    insnAt.get(inv.getArgument(0)));
            when(fm.getFunctions(true)).thenAnswer(inv -> functionIterator(functions));
            return program;
        }

        private PartitionContext.LiteralIndex buildLiteralIndex() {
            int n = specs.size();
            long[] medians = new long[n];
            List<Set<String>> tokens = new ArrayList<>(n);
            List<Set<Long>> pages = new ArrayList<>(n);
            List<List<String>> raw = new ArrayList<>(n);
            long autoString = 0x60000000L;
            for (int i = 0; i < n; i++) {
                FnSpec s = specs.get(i);
                long med = s.medianSet ? s.medianStringAddr
                        : (s.rawStrings.isEmpty() ? -1L : (autoString + i * 100L));
                medians[i] = med;
                Set<String> tok = new HashSet<>();
                for (String str : s.rawStrings) {
                    for (String w : str.split("[^A-Za-z0-9_]+")) {
                        if (w.length() >= 4 && w.length() <= 24 && !w.matches("\\d+")) {
                            tok.add(w.toLowerCase());
                        }
                    }
                }
                tokens.add(tok);
                pages.add(new TreeSet<>(s.pages));
                raw.add(List.copyOf(s.rawStrings));
            }
            return new PartitionContext.LiteralIndex(medians, tokens, pages, raw);
        }

        private FnSpec last() {
            if (specs.isEmpty()) {
                throw new IllegalStateException("add a function first");
            }
            return specs.get(specs.size() - 1);
        }

        private Address addr(long offset) {
            return ram.getAddress(offset);
        }
    }

    static void installLiterals(PartitionContext ctx, PartitionContext.LiteralIndex li) {
        try {
            Field f = PartitionContext.class.getDeclaredField("literals");
            f.setAccessible(true);
            f.set(ctx, li);
        } catch (ReflectiveOperationException e) {
            throw new AssertionError("failed to install LiteralIndex on PartitionContext", e);
        }
    }

    private static final class FnSpec {
        final String name;
        final long entry;
        final List<String> rawStrings = new ArrayList<>();
        final Set<Long> pages = new TreeSet<>();
        long medianStringAddr = -1;
        boolean medianSet;

        FnSpec(String name, long entry) {
            this.name = name;
            this.entry = entry;
        }
    }

    private static FunctionIterator functionIterator(List<Function> items) {
        Iterator<Function> it = items.iterator();
        return new FunctionIterator() {
            @Override public boolean hasNext() { return it.hasNext(); }
            @Override public Function next() { return it.next(); }
            @Override public Iterator<Function> iterator() { return this; }
        };
    }
}
