package com.xebyte.core.tree;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
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
import java.util.TreeSet;

/**
 * Cheap input fingerprint ({@code ifp}) over program-DB facts — never decompilation.
 *
 * <p>{@code fp} in the block header hashes the decompiled body, so verifying it
 * costs a decompile (a full tree check ≈ a sweep). The reconciler needs to answer
 * "did this function's <em>inputs</em> change?" without paying that. {@code ifp}
 * hashes name, prototype, body extents, comment text, and referenced symbol names
 * — everything an agent write typically moves — and lives as a column in
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
            return shortHash("");
        }
        Program program = func.getProgram();
        StringBuilder sb = new StringBuilder(256);
        sb.append("name=").append(nullToEmpty(func.getName())).append('\n');
        sb.append("proto=").append(prototypeOf(func)).append('\n');
        appendExtents(sb, func);
        appendComments(sb, program, func);
        appendReferencedSymbols(sb, program, func);
        appendBlockOnlyFacts(sb, program, func);
        return shortHash(sb.toString());
    }

    /** Same width as {@link SweepJob#shortContentHash} so columns line up visually. */
    public static String shortHash(String content) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(content.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest, 0, 6);
        } catch (NoSuchAlgorithmException e) {
            return "000000000000";
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

    private static void appendReferencedSymbols(StringBuilder sb, Program program, Function func) {
        if (program == null) {
            sb.append("refs=\n");
            return;
        }
        TreeSet<String> names = new TreeSet<>();
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
