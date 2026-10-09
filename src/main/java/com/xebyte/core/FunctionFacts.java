package com.xebyte.core;

import ghidra.app.decompiler.ClangCommentToken;
import ghidra.app.decompiler.ClangLine;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Everything known about one function, as one map: the single source for
 * {@code /get_functions}, the decompilation checkout's function blocks and the
 * {@code ghidra://function} resource. Each surface renders this map; none computes a field
 * of its own, so they cannot disagree about what a function is.
 *
 * <p>The decompiler is passed in: the bundle builds a fresh one per request, a checkout
 * sweep reuses one across thousands of functions. Both configure it with
 * {@link #configureDecompiler}.
 */
public final class FunctionFacts {

    private FunctionFacts() {
    }

    /** Decompiles one function, or returns null / an incomplete result when it cannot. */
    @FunctionalInterface
    public interface Decompiler {
        DecompileResults decompile(Function function);
    }

    /** Which fields (null = all) and how much call context and disassembly to include. */
    public record Options(Set<String> fields, boolean includeCallContext, int callContextLimit,
            int callContextLines, boolean includeDisasm) {
    }

    /** Hard caps: a bundle is a read for an agent, not a bulk export. */
    private static final int MAX_CALLERS = 50;
    private static final int MAX_CALLEES = 50;
    private static final int MAX_XREFS = 100;
    private static final int MAX_DISASM = 200;
    private static final int MAX_DECOMPILED_CHARS = 120_000;

    /** Subset keys accepted by {@code fields=}; omitted/empty means all. */
    public static final Set<String> FIELDS = Set.of(
            "signature", "classification", "return_type", "entry_point",
            "body_start", "body_end", "decompiled_code",
            "plate_comment", "comments", "labels", "tags", "parameters", "locals",
            "callers", "call_context", "callees", "xrefs", "disassembly",
            "jump_targets", "refs");

    /**
     * The bundle's own decompiler settings: show EOL comments, in {@code //} style.
     *
     * <p>An agent writes EOL comments through {@code set_comment}/{@code batch_set_comments}
     * and then reads the function back — and none of them appeared in the code, because the
     * decompiler's EOL option is off by default and this program's saved options keep it off.
     * They were only visible as an address in {@code comments[]}, which is exactly not where
     * a reader is looking.
     *
     * <p>Scoped to this endpoint rather than {@code createConfiguredDecompiler}: the shared
     * path feeds {@code analyze_function_completeness}, whose comment counter special-cases
     * Ghidra's {@code WARNING:} banners in its {@code /*} branch but not its {@code //} one,
     * and an external port pipeline's {@code _strip_comments}, which strips only {@code /* … *}{@code /}.
     * Under {@code //} both would silently change behaviour, and both are scoring inputs.
     *
     * <p>Ghidra renders a comment on its own line above the statement, never trailing it, so
     * this reads as {@code // note} then the code — {@code x = 1; // note} is not something
     * the decompiler will produce.
     */
    public static void configureDecompiler(ghidra.app.decompiler.DecompileOptions opts) {
        opts.setEOLCommentIncluded(true);
        opts.setCommentStyle(ghidra.app.decompiler.DecompileOptions.CommentStyleEnum.CPPStyle);
    }

    /**
     * Intra-function control flow: where the jumps inside this function go.
     *
     * <p>Folded in from the former {@code /get_function_jump_targets}. It reads
     * instructions out of the function body and never decompiles -- measured at
     * 0.6 ms warm against the full bundle's 228 ms -- so it costs nothing to
     * carry by default, and {@code fields=} excludes it for callers who do not
     * want it.
     *
     * <p>Conditional jumps contribute their fall-through as well: a branch has
     * two successors, and reporting only the taken edge would describe a control
     * flow graph that does not exist.
     */
    private static List<String> collectJumpTargets(Program program, Function func) {
        java.util.Set<ghidra.program.model.address.Address> targets = new java.util.HashSet<>();
        ghidra.program.model.listing.InstructionIterator instructions =
                program.getListing().getInstructions(func.getBody(), true);
        while (instructions.hasNext()) {
            ghidra.program.model.listing.Instruction instr = instructions.next();
            if (!instr.getFlowType().isJump()) {
                continue;
            }
            for (ghidra.program.model.symbol.Reference ref : instr.getReferencesFrom()) {
                ghidra.program.model.address.Address to = ref.getToAddress();
                if (to != null && program.getMemory().contains(to)) {
                    targets.add(to);
                }
            }
            if (instr.getFlowType().isConditional()) {
                ghidra.program.model.address.Address fallThrough = instr.getFallThrough();
                if (fallThrough != null) {
                    targets.add(fallThrough);
                }
            }
        }
        List<ghidra.program.model.address.Address> sorted = new ArrayList<>(targets);
        java.util.Collections.sort(sorted);
        List<String> out = new ArrayList<>(sorted.size());
        for (ghidra.program.model.address.Address a : sorted) {
            out.add(AddressKeys.of(a, program));
        }
        return out;
    }

    private static boolean wantsField(Set<String> fields, String name) {
        return fields == null || fields.contains(name);
    }

    public static Map<String, Object> build(Program program, Function func, Options options,
            Decompiler decompiler) {
        Set<String> fields = options.fields();
        boolean includeCallContext = options.includeCallContext();
        int callContextLimit = options.callContextLimit();
        int callContextLines = options.callContextLines();
        boolean includeDisasm = options.includeDisasm();
        Address entry = func.getEntryPoint();
        Map<String, Object> out = new LinkedHashMap<>();
        Map<String, Object> truncation = new LinkedHashMap<>();

        out.put("name", func.getName());
        out.put("size", func.getBody().getNumAddresses());
        out.putAll(ServiceUtils.addressToJson(entry, program));

        boolean wantsAll = fields == null;
        // refs takes the addresses the decompiled code loads and stores, so it decompiles too.
        boolean needsTargetDecompile = wantsAll || wantsField(fields, "decompiled_code")
            || wantsField(fields, "refs");
        boolean needsCallContext = wantsField(fields, "call_context")
            && includeCallContext && callContextLimit > 0;

        if (wantsField(fields, "signature")) {
            out.put("signature", func.getSignature().toString());
        }
        if (wantsField(fields, "classification")) {
            out.put("classification", AnalysisService.classifyFunction(func, program));
        }
        if (wantsField(fields, "return_type")) {
            String returnType = func.getReturnType().getName();
            out.put("return_type", returnType);
            if (returnType.startsWith("undefined")) {
                out.put("return_type_resolved", false);
                out.put("return_type_warning", "Return type is '" + returnType
                    + "' -- verify the return register at RET. Do not trust a decompiler 'void'.");
            } else {
                out.put("return_type_resolved", true);
            }
        }
        if (wantsField(fields, "entry_point")) {
            out.put("entry_point", AddressKeys.of(entry, program));
        }
        if (wantsField(fields, "body_start")) {
            out.put("body_start", AddressKeys.of(func.getBody().getMinAddress(), program));
        }
        if (wantsField(fields, "body_end")) {
            out.put("body_end", AddressKeys.of(func.getBody().getMaxAddress(), program));
        }

        DecompileResults decomp = null;
        boolean decompiled = false;
        if (needsTargetDecompile) {
            decomp = decompiler.decompile(func);
            decompiled = decomp != null && decomp.decompileCompleted()
                && decomp.getDecompiledFunction() != null;
            if (wantsField(fields, "decompiled_code")) {
                if (decompiled) {
                    String code = decomp.getDecompiledFunction().getC();
                    if (code != null) {
                        if (code.length() > MAX_DECOMPILED_CHARS) {
                            out.put("decompiled_code", code.substring(0, MAX_DECOMPILED_CHARS));
                            truncation.put("decompiled_code", true);
                            out.put("decompiled_code_note", "Truncated at " + MAX_DECOMPILED_CHARS
                                + " chars; call get_functions with fields=decompiled_code for more.");
                        } else {
                            out.put("decompiled_code", code);
                        }
                    }
                } else {
                    out.put("decompiled_code", null);
                    out.put("decompile_failed", true);
                    out.put("decompile_error", decompileError(decomp));
                }
            }
        }

        if (wantsField(fields, "plate_comment")) {
            out.put("plate_comment", func.getComment());
            List<String> plateIssues = NamingConventions.validatePlateCommentStructure(func.getComment());
            if (!plateIssues.isEmpty()) {
                out.put("plate_comment_issues", plateIssues);
            }
        }
        if (wantsField(fields, "comments")) {
            out.put("comments", collectComments(program, func));
        }
        if (wantsField(fields, "labels")) {
            out.put("labels", collectLabels(program, func));
        }
        if (wantsField(fields, "tags")) {
            out.put("tags", func.getTags().stream().map(t -> t.getName()).sorted().toList());
        }
        if (wantsField(fields, "refs")) {
            out.put("refs", refAddresses(addressRefs(program, func,
                decompiled ? decomp.getHighFunction() : null), program));
        }
        if (wantsField(fields, "jump_targets")) {
            out.put("jump_targets", collectJumpTargets(program, func));
        }
        if (wantsField(fields, "parameters")) {
            out.put("parameters", collectParameters(func));
        }
        if (wantsField(fields, "locals")) {
            out.put("locals", collectLocals(func, decompiled ? decomp.getHighFunction() : null));
        }

        List<Function> callers = null;
        if (wantsField(fields, "callers") || needsCallContext) {
            callers = callersOf(program, func);
        }
        if (wantsField(fields, "callers") && callers != null) {
            out.put("caller_count", callers.size());
            out.put("callers", summarizeFunctions(program, callers, MAX_CALLERS));
            if (callers.size() > MAX_CALLERS) truncation.put("callers", true);
        }

        if (needsCallContext && callers != null && !callers.isEmpty()) {
            List<Map<String, Object>> context =
                collectCallContext(program, entry, callers, callContextLimit, callContextLines, decompiler);
            out.put("call_context", context);
            if (callers.size() > callContextLimit) truncation.put("call_context", true);
        }

        if (wantsField(fields, "callees")) {
            List<Function> callees = calleesOf(func);
            out.put("callee_count", callees.size());
            out.put("callees", summarizeFunctions(program, callees, MAX_CALLEES));
            if (callees.size() > MAX_CALLEES) truncation.put("callees", true);
        }

        if (wantsField(fields, "xrefs")) {
            out.put("xrefs", collectXrefs(program, entry, truncation));
        }

        if (wantsField(fields, "disassembly") && includeDisasm) {
            out.put("disassembly", collectDisassembly(program, func, truncation));
        }

        Map<String, Object> revision = new LinkedHashMap<>();
        revision.putAll(ProgramRevision.toMap(program));
        revision.put("decompiled", decompiled);
        out.put("revision", revision);

        if (!truncation.isEmpty()) {
            out.put("truncation", truncation);
        }
        return out;
    }

    /** All five comment kinds at every address in the body, with body-relative offsets. */
    private static List<Map<String, Object>> collectComments(Program program, Function func) {
        Listing listing = program.getListing();
        Address entry = func.getEntryPoint();
        List<Map<String, Object>> comments = new ArrayList<>();
        int[] kinds = {CodeUnit.PLATE_COMMENT, CodeUnit.PRE_COMMENT, CodeUnit.EOL_COMMENT,
                       CodeUnit.POST_COMMENT, CodeUnit.REPEATABLE_COMMENT};
        String[] kindNames = {"plate", "pre", "eol", "post", "repeatable"};
        Iterator<Address> addresses = func.getBody().getAddresses(true);
        while (addresses.hasNext()) {
            Address addr = addresses.next();
            for (int i = 0; i < kinds.length; i++) {
                String text = listing.getComment(kinds[i], addr);
                if (text == null || text.isEmpty()) continue;
                Map<String, Object> item = new LinkedHashMap<>();
                item.putAll(ServiceUtils.addressToJson(addr, program));
                item.put("relative_offset", addr.subtract(entry));
                item.put("kind", kindNames[i]);
                item.put("text", text);
                comments.add(item);
            }
        }
        return comments;
    }

    private static List<Map<String, Object>> collectLabels(Program program, Function func) {
        List<Map<String, Object>> labels = new ArrayList<>();
        SymbolTable symbolTable = program.getSymbolTable();
        Address entry = func.getEntryPoint();
        SymbolIterator symbols = symbolTable.getSymbolIterator();
        while (symbols.hasNext()) {
            Symbol symbol = symbols.next();
            if (symbol.getSymbolType() != SymbolType.LABEL) continue;
            if (!func.getBody().contains(symbol.getAddress())) continue;
            Map<String, Object> item = new LinkedHashMap<>();
            item.putAll(ServiceUtils.addressToJson(symbol.getAddress(), program));
            item.put("relative_offset", symbol.getAddress().subtract(entry));
            item.put("name", symbol.getName());
            item.put("source", symbol.getSource().toString());
            labels.add(item);
        }
        return labels;
    }

    private static List<Map<String, Object>> collectParameters(Function func) {
        List<Map<String, Object>> params = new ArrayList<>();
        int ordinal = 0;
        for (Variable param : func.getParameters()) {
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("ordinal", ordinal++);
            item.put("name", param.getName());
            item.put("type", param.getDataType().getName());
            item.put("storage", param.getVariableStorage().toString());
            if (param.getComment() != null && !param.getComment().isEmpty()) {
                item.put("comment", param.getComment());
            }
            params.add(item);
        }
        return params;
    }

    /**
     * Locals from the decompiler's view when available — that is the set whose names the
     * agent actually sees in {@code decompiled_code} — falling back to the listing's
     * low-level variables when decompilation failed.
     */
    /**
     * Where a decompiler variable actually lives, or null when that is not a thing a
     * reader can act on.
     *
     * <p>Goes through {@link VariableStorage#toString()} — the same rendering
     * {@code /get_function_variables} and this bundle's own parameters use — so a register
     * comes back as {@code RDI:8} rather than {@code register:00001200:8}. The raw varnode
     * address this used to print is an offset into the register address space: it names no
     * register, and for a parameter the register IS the calling convention, which is the
     * one thing worth reading here.
     *
     * <p>p-code temporaries ({@code unique:}/hash storage) return null: an SSA temp has no
     * storage a reader could rename, retype or find in the frame, so the field is omitted
     * rather than filled with an address that means nothing outside the decompiler.
     */
    private static String describeStorage(HighSymbol symbol) {
        VariableStorage storage = symbol.getStorage();
        if (storage == null || !storage.isValid()) return null;
        if (storage.isUniqueStorage() || storage.isHashStorage()) return null;
        String text = storage.toString();
        return text == null || text.isEmpty() ? null : text;
    }

    private static List<Map<String, Object>> collectLocals(Function func, HighFunction high) {
        List<Map<String, Object>> locals = new ArrayList<>();
        if (high != null) {
            Iterator<HighSymbol> symbols = high.getLocalSymbolMap().getSymbols();
            while (symbols.hasNext()) {
                HighSymbol symbol = symbols.next();
                Map<String, Object> item = new LinkedHashMap<>();
                String name = symbol.getName();
                item.put("name", name);
                item.put("type", symbol.getDataType().getName());
                String storage = describeStorage(symbol);
                if (storage != null) {
                    item.put("storage", storage);
                }
                // Decompiler-invented names: not real storage the user can rename usefully.
                item.put("is_phantom", name.startsWith("extraout_") || name.startsWith("in_")
                    || name.startsWith("unaff_"));
                item.put("in_decompiled_code", true);
                locals.add(item);
            }
            return locals;
        }
        for (Variable local : func.getLocalVariables()) {
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("name", local.getName());
            item.put("type", local.getDataType().getName());
            item.put("storage", local.getVariableStorage().toString());
            item.put("is_phantom", false);
            item.put("in_decompiled_code", false);
            locals.add(item);
        }
        return locals;
    }

    /**
     * Callers as the union of address references and Ghidra's own calling-function set —
     * the thorough form {@code /get_function_callers} uses. {@code getCallingFunctions}
     * alone misses callers reachable only through data/indirect references.
     */
    /** Every function referencing {@code func}'s entry, or calling it; sorted by name. */
    public static List<Function> callersOf(Program program, Function func) {
        Set<Function> callers = new LinkedHashSet<>();
        FunctionManager functionManager = program.getFunctionManager();
        ReferenceManager refManager = program.getReferenceManager();
        ReferenceIterator refs = refManager.getReferencesTo(func.getEntryPoint());
        while (refs.hasNext()) {
            Reference ref = refs.next();
            Function containing = functionManager.getFunctionContaining(ref.getFromAddress());
            if (containing != null) callers.add(containing);
        }
        try {
            callers.addAll(func.getCallingFunctions(null));
        } catch (Exception ignored) {
            // Ghidra could not compute them; the address references above still stand.
        }
        List<Function> sorted = new ArrayList<>(callers);
        sorted.sort((a, b) -> a.getName().compareTo(b.getName()));
        return sorted;
    }

    /** Every function {@code func} calls; sorted by name. */
    public static List<Function> calleesOf(Function func) {
        Set<Function> callees;
        try {
            callees = new LinkedHashSet<>(func.getCalledFunctions(null));
        } catch (Exception e) {
            return List.of();
        }
        List<Function> sorted = new ArrayList<>(callees);
        sorted.sort((a, b) -> a.getName().compareTo(b.getName()));
        return sorted;
    }

    private static List<Map<String, Object>> summarizeFunctions(Program program,
            List<Function> functions, int cap) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (Function f : functions) {
            if (out.size() >= cap) break;
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("name", f.getName());
            item.putAll(ServiceUtils.addressToJson(f.getEntryPoint(), program));
            // Qualified outside the default space, so an overlay caller cannot read as the
            // default-space function at the same offset.
            item.put("address", AddressKeys.of(f.getEntryPoint(), program));
            out.add(item);
        }
        return out;
    }

    /**
     * The caller's own source lines around each call site — "who calls me, and how".
     *
     * <p>Deduped by caller function before decompiling: a caller that calls the target six
     * times must be decompiled once, not six times. Measured ~43 ms per unique caller.
     */
    private static List<Map<String, Object>> collectCallContext(Program program, Address target,
            List<Function> callers, int limit, int contextLines, Decompiler decompiler) {
        List<Map<String, Object>> out = new ArrayList<>();
        FunctionManager functionManager = program.getFunctionManager();

        // Call sites grouped by the caller that contains them.
        Map<Function, List<Address>> sitesByCaller = new LinkedHashMap<>();
        ReferenceIterator refs = program.getReferenceManager().getReferencesTo(target);
        while (refs.hasNext()) {
            Reference ref = refs.next();
            if (!ref.getReferenceType().isCall()) continue;
            Function containing = functionManager.getFunctionContaining(ref.getFromAddress());
            if (containing == null) continue;
            sitesByCaller.computeIfAbsent(containing, k -> new ArrayList<>()).add(ref.getFromAddress());
        }

        int decompiled = 0;
        for (Map.Entry<Function, List<Address>> entry : sitesByCaller.entrySet()) {
            if (decompiled >= limit) break;
            Function caller = entry.getKey();
            decompiled++;
            DecompileResults results = decompiler.decompile(caller);
            List<ClangLine> lines = (results != null && results.decompileCompleted()
                && results.getCCodeMarkup() != null)
                ? DecompilerUtils.toLines(results.getCCodeMarkup())
                : List.of();
            for (Address site : entry.getValue()) {
                Map<String, Object> item = new LinkedHashMap<>();
                item.put("caller", caller.getName());
                item.put("caller_address", AddressKeys.of(caller.getEntryPoint(), program));
                item.put("site_address", AddressKeys.of(site, program));
                int at = indexOfLineContaining(lines, site);
                if (at >= 0) {
                    item.put("line_number", lines.get(at).getLineNumber());
                    // Window is centred on the call, biased upward when it cannot be split
                    // evenly: the guard that decides whether the call happens reads better
                    // than one more line after it.
                    int before = contextLines / 2;
                    int from = Math.max(0, at - before);
                    int to = Math.min(lines.size(), from + contextLines);
                    from = Math.max(0, to - contextLines);
                    StringBuilder text = new StringBuilder();
                    for (int i = from; i < to; i++) {
                        if (i > from) text.append('\n');
                        // ClangLine.toString() gives "<n>: <tokens>" with the indentation
                        // dropped — the indent is a separate field. Put it back: whether the
                        // neighbouring line is inside the branch above it or after it is most
                        // of what makes a window worth more than the call line alone.
                        ClangLine line = lines.get(i);
                        text.append(line.getLineNumber()).append(": ")
                            .append(line.getIndentString());
                        for (ClangToken token : line.getAllTokens()) {
                            text.append(token.getText());
                        }
                        stripTrailingInPlace(text);
                    }
                    item.put("text", text.toString());
                    if (contextLines > 1) {
                        item.put("first_line_number", lines.get(from).getLineNumber());
                        item.put("last_line_number", lines.get(to - 1).getLineNumber());
                    }
                } else {
                    item.put("text", null);
                }
                out.add(item);
            }
        }
        return out;
    }

    private static int indexOfLineContaining(List<ClangLine> lines, Address site) {
        for (int i = 0; i < lines.size(); i++) {
            for (ClangToken token : lines.get(i).getAllTokens()) {
                // Comment tokens carry the address they are attached to, so a rendered EOL
                // comment at the call site would match before the call itself and centre the
                // window on the note instead of the code it annotates.
                if (token instanceof ClangCommentToken) continue;
                Address min = token.getMinAddress();
                if (min != null && min.equals(site)) return i;
            }
        }
        return -1;
    }

    /** Drop trailing whitespace from what has been appended so far. */
    private static void stripTrailingInPlace(StringBuilder text) {
        int end = text.length();
        while (end > 0 && Character.isWhitespace(text.charAt(end - 1))
                && text.charAt(end - 1) != '\n') {
            end--;
        }
        text.setLength(end);
    }

    /**
     * References to the entry point, carrying the reference TYPE — which
     * {@code analyze_function_complete} drops, leaving a caller unable to tell a call from
     * a data reference.
     */
    private static List<Map<String, Object>> collectXrefs(Program program, Address entry,
            Map<String, Object> truncation) {
        List<Map<String, Object>> out = new ArrayList<>();
        ReferenceIterator refs = program.getReferenceManager().getReferencesTo(entry);
        int total = 0;
        while (refs.hasNext()) {
            Reference ref = refs.next();
            total++;
            if (out.size() >= MAX_XREFS) continue;
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("from", AddressKeys.of(ref.getFromAddress(), program));
            item.put("type", ref.getReferenceType().getName());
            Function containing = program.getFunctionManager()
                .getFunctionContaining(ref.getFromAddress());
            if (containing != null) item.put("from_function", containing.getName());
            out.add(item);
        }
        if (total > out.size()) truncation.put("xrefs", true);
        return out;
    }

    private static List<Map<String, Object>> collectDisassembly(Program program, Function func,
            Map<String, Object> truncation) {
        List<Map<String, Object>> out = new ArrayList<>();
        InstructionIterator instructions = program.getListing().getInstructions(func.getBody(), true);
        int total = 0;
        while (instructions.hasNext()) {
            Instruction instruction = instructions.next();
            total++;
            if (out.size() >= MAX_DISASM) continue;
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("address", AddressKeys.of(instruction.getAddress(), program));
            item.put("mnemonic", instruction.getMnemonicString());
            List<String> operands = new ArrayList<>();
            for (int i = 0; i < instruction.getNumOperands(); i++) {
                operands.add(instruction.getDefaultOperandRepresentation(i));
            }
            item.put("operands", String.join(", ", operands));
            out.add(item);
        }
        if (total > out.size()) truncation.put("disassembly", true);
        return out;
    }

    /** Whether a {@code fields=} subset pays for target decompilation. */
    public static boolean requiresTargetDecompile(Set<String> fields) {
        return fields == null || fields.contains("decompiled_code");
    }

    /** Why a decompile produced no code, in the decompiler's own words when it gave any. */
    public static String decompileError(DecompileResults results) {
        if (results == null) {
            return "decompiler unavailable";
        }
        String message = results.getErrorMessage();
        if (message != null && !message.isBlank()) {
            return message.trim();
        }
        return results.isTimedOut() ? "timed out" : results.isCancelled() ? "cancelled" : "no output";
    }

    /**
     * One address a function uses, and how it reaches it.
     *
     * <ul>
     *   <li>{@code data}: a data reference from the function's body.
     *   <li>{@code pointer}: the value of a pointer-sized word the function references;
     *       {@code via} is the word. The literal-pool case: {@code iVar2 = DAT_08016e58;}
     *       prints the pool word, and only its value, {@code 0x40020000}, says which
     *       peripheral the function drives.
     *   <li>{@code load} / {@code store}: a memory location the decompiled code reads or
     *       writes, folded to one address. The only place a register reached as base + offset exists as one
     *       number: the C prints {@code *(uint *)(&GPIOB_CFGR + 0xc)}, and no reference
     *       points at {@code 0x40003c0c}.
     * </ul>
     */
    public record AddressRef(Address address, String kind, Address via) {
    }

    /**
     * Every address {@code func} uses, in the order found, without duplicates. {@code high}
     * is the decompiled function, or null when there is none; then the load and store
     * addresses are missing.
     */
    public static List<AddressRef> addressRefs(Program program, Function func, HighFunction high) {
        LinkedHashSet<AddressRef> found = new LinkedHashSet<>();
        ReferenceManager refs = program.getReferenceManager();
        ghidra.program.model.mem.Memory memory = program.getMemory();
        int pointerSize = program.getDefaultPointerSize();
        for (Address from : refs.getReferenceSourceIterator(func.getBody(), true)) {
            for (Reference ref : refs.getReferencesFrom(from)) {
                Address to = ref.getToAddress();
                if (!ref.getReferenceType().isData() || to == null || !to.isMemoryAddress()) {
                    continue;
                }
                found.add(new AddressRef(to, "data", null));
                Address value = pointerValue(program, memory, to, pointerSize);
                if (value != null) {
                    found.add(new AddressRef(value, "pointer", to));
                }
            }
        }
        if (high != null) {
            Iterator<PcodeOpAST> ops = high.getPcodeOps();
            while (ops.hasNext()) {
                PcodeOpAST op = ops.next();
                int opcode = op.getOpcode();
                if (opcode == PcodeOp.LOAD || opcode == PcodeOp.STORE) {
                    // An access through a pointer the decompiler could not turn into a
                    // location, but whose value is still a constant sum.
                    Address target = constantTarget(program, op);
                    if (target != null) {
                        found.add(new AddressRef(target, opcode == PcodeOp.LOAD ? "load" : "store", null));
                    }
                    continue;
                }
                // Fully folded: the access became the memory location itself, e.g.
                // (ram, 0x40003c0c, 4) COPY (const, 0x1, 4).
                Address written = memoryLocation(op.getOutput());
                if (written != null) {
                    found.add(new AddressRef(written, "store", null));
                }
                for (Varnode in : op.getInputs()) {
                    Address read = memoryLocation(in);
                    if (read != null) {
                        found.add(new AddressRef(read, "load", null));
                    }
                }
            }
        }
        return new ArrayList<>(found);
    }

    /**
     * The distinct addresses of {@code refs}, sorted, as {@link AddressKeys#display}.
     * An address the function reaches through a literal-pool word carries it after a
     * {@code <}: {@code 0x40020000<0x08016e58} reads "0x40020000, loaded from 0x08016e58". Both
     * halves grep, and the second answers which pool word to retype. Not capped: the list is
     * the one place a register's own address appears.
     */
    static List<String> refAddresses(List<AddressRef> refs, Program program) {
        java.util.TreeMap<Address, java.util.TreeSet<Address>> via = new java.util.TreeMap<>();
        for (AddressRef r : refs) {
            java.util.TreeSet<Address> words = via.computeIfAbsent(r.address(), a -> new java.util.TreeSet<>());
            if (r.via() != null) {
                words.add(r.via());
            }
        }
        List<String> out = new ArrayList<>(via.size());
        via.forEach((a, words) -> {
            StringBuilder sb = new StringBuilder(AddressKeys.display(a, program));
            words.forEach(w -> sb.append('<').append(AddressKeys.display(w, program)));
            out.add(sb.toString());
        });
        return out;
    }

    /** {@code v}'s address when it is a location in memory, not a register, stack slot or temporary. */
    private static Address memoryLocation(Varnode v) {
        if (v == null || !v.isAddress()) {
            return null;
        }
        Address a = v.getAddress();
        return a.getAddressSpace().isMemorySpace() && !a.getAddressSpace().isStackSpace() ? a : null;
    }

    /** The address a LOAD or STORE goes to, when the pointer folds to a constant. */
    private static Address constantTarget(Program program, PcodeOp op) {
        Long offset = constantValue(op.getInput(1), 4);
        if (offset == null || offset == 0) {
            return null;
        }
        AddressSpace space = program.getAddressFactory()
            .getAddressSpace((int) op.getInput(0).getOffset());
        if (space == null || !space.isMemorySpace()) {
            return null;
        }
        try {
            return space.getTruncatedAddress(offset, true);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * The value of {@code v} when it is a constant, or a sum the decompiler left unfolded:
     * {@code PTRSUB(0, 0x40003c00)} for a global, {@code INT_ADD}/{@code PTRSUB} of base and
     * offset, {@code PTRADD} of base, index and element size, through copies and casts.
     */
    private static Long constantValue(Varnode v, int depth) {
        if (v == null) {
            return null;
        }
        if (v.isConstant()) {
            return v.getOffset();
        }
        PcodeOp def = v.getDef();
        if (def == null || depth == 0) {
            return null;
        }
        switch (def.getOpcode()) {
            case PcodeOp.COPY, PcodeOp.CAST, PcodeOp.INT_ZEXT -> {
                return constantValue(def.getInput(0), depth - 1);
            }
            case PcodeOp.INT_ADD, PcodeOp.PTRSUB -> {
                Long a = constantValue(def.getInput(0), depth - 1);
                Long b = constantValue(def.getInput(1), depth - 1);
                return a != null && b != null ? a + b : null;
            }
            case PcodeOp.PTRADD -> {
                Long base = constantValue(def.getInput(0), depth - 1);
                Long index = constantValue(def.getInput(1), depth - 1);
                Long size = constantValue(def.getInput(2), depth - 1);
                return base != null && index != null && size != null ? base + index * size : null;
            }
            default -> {
                return null;
            }
        }
    }

    /** The address a pointer-sized word holds, when it is one: mapped, or labelled. */
    private static Address pointerValue(Program program, ghidra.program.model.mem.Memory memory,
            Address word, int pointerSize) {
        try {
            if (!memory.contains(word) || (pointerSize != 4 && pointerSize != 8)) {
                return null;
            }
            ghidra.program.model.mem.MemBuffer buf =
                new ghidra.program.model.mem.DumbMemBufferImpl(memory, word);
            long raw = pointerSize == 4 ? Integer.toUnsignedLong(buf.getInt(0)) : buf.getLong(0);
            Address value = word.getAddressSpace().getAddress(raw);
            if (memory.contains(value) || program.getSymbolTable().getPrimarySymbol(value) != null) {
                return value;
            }
        } catch (Exception e) {
            // uninitialized or unreadable: not a pointer we can report
        }
        return null;
    }
}
