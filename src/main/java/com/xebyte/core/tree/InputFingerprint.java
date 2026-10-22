package com.xebyte.core.tree;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.TreeSet;

/**
 * Cheap input fingerprint ({@code ifp}) over program-DB facts — never decompilation.
 *
 * <p>{@code fp} in the block header hashes the decompiled body, so verifying it
 * costs a decompile (a full tree check ≈ a sweep). The reconciler needs to answer
 * "did this function's <em>inputs</em> change?" without paying that. {@code ifp}
 * hashes name, prototype, locals, body extents, comment text, referenced symbol names
 * and data types, and the layout of every type the function uses — everything an agent
 * write typically moves, and what a different revision of the program can differ in —
 * and lives as a column in
 * {@code index/by-address.tsv}, not in the 9-line agent-read header.
 *
 * <p><b>Never call {@code DecompInterface} from here.</b>
 *
 * @since 7.2.0
 */
public final class InputFingerprint {

    private static final int[] COMMENT_KINDS = {
            CodeUnit.PLATE_COMMENT,
            CodeUnit.PRE_COMMENT,
            CodeUnit.EOL_COMMENT,
            CodeUnit.POST_COMMENT,
            CodeUnit.REPEATABLE_COMMENT,
    };

    private InputFingerprint() {
    }

    /**
     * 12-hex SHA-256 prefix over DB-cheap facts for {@code func}.
     * Stable across repeated reads; moves when name/signature/comments/refs change.
     */
    public static String of(Function func) {
        if (func == null) {
            return shortHash("", 6);
        }
        Program program = func.getProgram();
        StringBuilder sb = new StringBuilder(256);
        sb.append("name=").append(nullToEmpty(func.getName())).append('\n');
        sb.append("proto=").append(prototypeOf(func)).append('\n');
        appendExtents(sb, func);
        appendComments(sb, program, func);
        Map<String, DataType> types = new TreeMap<>();
        appendLocals(sb, func, types);
        appendReferencedSymbols(sb, program, func, types);
        appendTypeLayouts(sb, types);
        appendBlockOnlyFacts(sb, program, func);
        return shortHash(sb.toString(), 6);
    }

    /** SHA-256 of UTF-8 {@code content}, hex of the first {@code byteCount} digest bytes. */
    public static String shortHash(String content, int byteCount) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(content.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest, 0, byteCount);
        } catch (NoSuchAlgorithmException e) {
            return "0".repeat(byteCount * 2);
        }
    }

    private static String prototypeOf(Function func) {
        try {
            String p = func.getPrototypeString(false, false);
            if (p != null && !p.isBlank()) {
                return p;
            }
        } catch (Exception ignored) {
            // fall through
        }
        try {
            if (func.getSignature() != null) {
                return func.getSignature().toString();
            }
        } catch (Exception ignored) {
            // fall through
        }
        return "";
    }

    private static void appendExtents(StringBuilder sb, Function func) {
        try {
            AddressSetView body = func.getBody();
            if (body == null || body.isEmpty()) {
                sb.append("extent=\n");
                return;
            }
            Address min = body.getMinAddress();
            Address max = body.getMaxAddress();
            sb.append("extent=")
                    .append(min != null ? min.toString(false) : "")
                    .append('-')
                    .append(max != null ? max.toString(false) : "")
                    .append(" size=")
                    .append(body.getNumAddresses())
                    .append('\n');
        } catch (Exception e) {
            sb.append("extent=\n");
        }
    }

    private static void appendComments(StringBuilder sb, Program program, Function func) {
        // Plate via Function API — same source batch_set_comments writes.
        sb.append("plate=").append(nullToEmpty(func.getComment())).append('\n');
        if (program == null) {
            return;
        }
        Listing listing = program.getListing();
        AddressSetView body = func.getBody();
        if (listing == null || body == null) {
            return;
        }
        // Sorted address walk so comment order cannot flip the hash.
        List<Address> addrs = new ArrayList<>();
        Iterator<Address> it = body.getAddresses(true);
        while (it.hasNext()) {
            addrs.add(it.next());
        }
        for (Address addr : addrs) {
            for (int kind : COMMENT_KINDS) {
                // Plate at entry already recorded; skip duplicate CodeUnit plate.
                if (kind == CodeUnit.PLATE_COMMENT && addr.equals(func.getEntryPoint())) {
                    continue;
                }
                String text;
                try {
                    text = listing.getComment(kind, addr);
                } catch (Exception e) {
                    continue;
                }
                if (text == null || text.isEmpty()) {
                    continue;
                }
                sb.append("c").append(kind).append('@')
                        .append(addr.toString(false)).append('=')
                        .append(text).append('\n');
            }
        }
    }

    private static void appendLocals(StringBuilder sb, Function func, Map<String, DataType> types) {
        TreeSet<String> locals = new TreeSet<>();
        try {
            collect(types, func.getReturnType());
            for (Variable v : nonNull(func.getParameters())) {
                collect(types, v.getDataType());
            }
            for (Variable v : nonNull(func.getLocalVariables())) {
                locals.add(v.getName() + ":" + typeName(v.getDataType()) + "@" + v.getVariableStorage());
                collect(types, v.getDataType());
            }
        } catch (Exception e) {
            // An unreadable variable hashes as absent, stably.
        }
        sb.append("locals=").append(locals).append('\n');
    }

    private static void appendReferencedSymbols(StringBuilder sb, Program program, Function func,
            Map<String, DataType> types) {
        if (program == null) {
            sb.append("refs=\n");
            return;
        }
        TreeSet<String> names = new TreeSet<>();
        TreeSet<String> data = new TreeSet<>();
        try {
            AddressSetView body = func.getBody();
            Listing listing = program.getListing();
            if (body == null || listing == null) {
                sb.append("refs=\n");
                return;
            }
            SymbolTable symbols = program.getSymbolTable();
            // Instruction walk — same shape as PartitionContext's literal index;
            // ReferenceManager has no AddressSet→ReferenceIterator overload.
            InstructionIterator ii = listing.getInstructions(body, true);
            while (ii.hasNext()) {
                Instruction ins = ii.next();
                for (Reference ref : ins.getReferencesFrom()) {
                    if (ref == null || ref.getToAddress() == null) {
                        continue;
                    }
                    Symbol sym = symbols.getPrimarySymbol(ref.getToAddress());
                    if (sym != null && sym.getName() != null && !sym.getName().isBlank()) {
                        names.add(sym.getName());
                    }
                    // A global typed or retyped changes every read of it, under the same name.
                    Data d = listing.getDataContaining(ref.getToAddress());
                    if (d != null && d.isDefined()) {
                        data.add(d.getAddress().toString(false) + ":" + typeName(d.getDataType()));
                        collect(types, d.getDataType());
                    }
                }
            }
        } catch (Exception e) {
            // Missing listing/refs must not abort a sweep — empty refs still hashes stably.
        }
        sb.append("refs=");
        boolean first = true;
        for (String n : names) {
            if (!first) {
                sb.append(',');
            }
            sb.append(n);
            first = false;
        }
        sb.append('\n');
        sb.append("data=").append(data).append('\n');
    }

    /**
     * The members of every struct, union and enum the function's variables and data reach
     * (through pointers, typedefs and arrays): a renamed field changes each
     * {@code p->field} in the body, with no change to the function itself.
     */
    private static void appendTypeLayouts(StringBuilder sb, Map<String, DataType> types) {
        for (Map.Entry<String, DataType> e : types.entrySet()) {
            sb.append("type ").append(e.getKey()).append('=');
            try {
                if (e.getValue() instanceof Composite c) {
                    sb.append(c.getLength());
                    for (DataTypeComponent m : c.getDefinedComponents()) {
                        sb.append(' ').append(m.getOffset()).append(':').append(m.getFieldName())
                                .append(':').append(typeName(m.getDataType()));
                    }
                } else if (e.getValue() instanceof Enum en) {
                    for (String n : en.getNames()) {
                        sb.append(' ').append(n).append('=').append(en.getValue(n));
                    }
                }
            } catch (Exception ex) {
                // A type that cannot be read hashes as its name alone, stably.
            }
            sb.append('\n');
        }
    }

    /** Record the struct, union or enum under {@code dt}, if any. */
    private static void collect(Map<String, DataType> types, DataType dt) {
        for (int depth = 0; dt != null && depth < 8; depth++) {
            if (dt instanceof Pointer ptr) {
                dt = ptr.getDataType();
            } else if (dt instanceof TypeDef td) {
                dt = td.getDataType();
            } else if (dt instanceof Array arr) {
                dt = arr.getDataType();
            } else {
                if (dt instanceof Composite || dt instanceof Enum) {
                    types.putIfAbsent(dt.getPathName(), dt);
                }
                return;
            }
        }
    }

    private static String typeName(DataType dt) {
        return dt == null ? "" : dt.getPathName();
    }

    private static Variable[] nonNull(Variable[] vars) {
        return vars == null ? new Variable[0] : vars;
    }

    /**
     * Facts a block shows that the decompiled C does not: tags, labels in the body, and who
     * references the entry (the block's callers and xrefs). Without them a full reconcile
     * would keep a block whose header no longer matches the program.
     */
    private static void appendBlockOnlyFacts(StringBuilder sb, Program program, Function func) {
        try {
            sb.append("tags=").append(func.getTags().stream().map(t -> t.getName()).sorted().toList())
                    .append('\n');
            if (program == null) {
                return;
            }
            TreeSet<String> labels = new TreeSet<>();
            for (Symbol s : program.getSymbolTable().getSymbols(func.getBody(), SymbolType.LABEL, true)) {
                labels.add(s.getAddress().toString(false) + "=" + s.getName());
            }
            sb.append("labels=").append(labels).append('\n');
            TreeSet<String> incoming = new TreeSet<>();
            for (Reference ref : program.getReferenceManager().getReferencesTo(func.getEntryPoint())) {
                Function from = program.getFunctionManager().getFunctionContaining(ref.getFromAddress());
                incoming.add(ref.getFromAddress().toString(false) + " " + ref.getReferenceType()
                        + (from != null ? " " + from.getName() : ""));
            }
            sb.append("incoming=").append(incoming).append('\n');
        } catch (Exception e) {
            // A fact that cannot be read hashes as absent, stably.
        }
    }

    private static String nullToEmpty(String s) {
        return s == null ? "" : s;
    }
}
