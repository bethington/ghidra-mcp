package com.xebyte.core;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.Msg;

import java.util.*;

/**
 * Shared static utility methods used by all service classes.
 * Methods are thread-safe. {@code parseAddress} maintains per-thread error state via a
 * {@link ThreadLocal}; see {@link #getLastParseError()}.
 */
public final class ServiceUtils {

    private ServiceUtils() {} // Prevent instantiation

    // ========================================================================
    // JSON Encoding/Decoding
    // ========================================================================

    /**
     * Escape a string for safe inclusion in JSON values.
     * Handles quotes, backslashes, and control characters.
     * @deprecated Use {@link JsonHelper#toJson(Object)} instead — Gson handles escaping automatically.
     */
    @Deprecated
    public static String escapeJson(String str) {
        if (str == null) return "";
        return str.replace("\\", "\\\\")
                  .replace("\"", "\\\"")
                  .replace("\n", "\\n")
                  .replace("\r", "\\r")
                  .replace("\t", "\\t");
    }

    /**
     * Serialize a List of objects to a JSON array string.
     * @deprecated Use {@link JsonHelper#toJson(Object)} instead.
     */
    @Deprecated
    public static String serializeListToJson(List<?> list) {
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < list.size(); i++) {
            if (i > 0) sb.append(",");
            Object item = list.get(i);
            if (item instanceof String) {
                sb.append("\"").append(escapeJson((String) item)).append("\"");
            } else if (item instanceof Number) {
                sb.append(item);
            } else if (item instanceof Map) {
                sb.append(serializeMapToJson((Map<?, ?>) item));
            } else if (item instanceof List) {
                sb.append(serializeListToJson((List<?>) item));
            } else {
                sb.append("\"").append(escapeJson(item.toString())).append("\"");
            }
        }
        sb.append("]");
        return sb.toString();
    }

    /**
     * Serialize a Map to a JSON object string.
     * @deprecated Use {@link JsonHelper#toJson(Object)} instead.
     */
    @Deprecated
    public static String serializeMapToJson(Map<?, ?> map) {
        StringBuilder sb = new StringBuilder("{");
        boolean first = true;
        for (Map.Entry<?, ?> entry : map.entrySet()) {
            if (!first) sb.append(",");
            first = false;
            sb.append("\"").append(escapeJson(entry.getKey().toString())).append("\":");
            Object value = entry.getValue();
            if (value instanceof String) {
                sb.append("\"").append(escapeJson((String) value)).append("\"");
            } else if (value instanceof Number) {
                sb.append(value);
            } else if (value instanceof Map) {
                sb.append(serializeMapToJson((Map<?, ?>) value));
            } else if (value instanceof List) {
                sb.append(serializeListToJson((List<?>) value));
            } else if (value instanceof Boolean) {
                sb.append(value);
            } else if (value == null) {
                sb.append("null");
            } else {
                sb.append("\"").append(escapeJson(value.toString())).append("\"");
            }
        }
        sb.append("}");
        return sb.toString();
    }

    // ========================================================================
    // Numeric/Boolean Parsing
    // ========================================================================

    // ========================================================================
    // Collection Utilities
    // ========================================================================

    /**
     * Build the standard list-shaped response envelope.
     *
     * <p>Per {@code docs/project-management/MCP_RESPONSE_CONTRACT.md}, every
     * collection-returning tool emits a named plural key plus paging metadata:
     *
     * <pre>{@code {"segments": [...], "count": 7, "offset": 0, "limit": 100, "total": 7}}</pre>
     *
     * <p>{@code total} is the point of the envelope. A bare array cannot tell a
     * caller whether it received everything or the first page of 5,739, and
     * {@code len(items)} cannot either.
     *
     * @param key   plural name for the collection ("segments", "functions")
     * @param all   the full result set, before paging
     * @param offset first item to return
     * @param limit  maximum items to return; {@code <= 0} means "no limit"
     */
    public static Response paged(String key, List<?> all, int offset, int limit) {
        int start = Math.max(0, offset);
        int end = (limit > 0) ? Math.min(all.size(), start + limit) : all.size();
        List<?> page = (start >= all.size()) ? List.of() : all.subList(start, end);

        Map<String, Object> out = new LinkedHashMap<>();
        out.put(key, page);
        out.put("count", page.size());
        out.put("offset", start);
        if (limit > 0) {
            out.put("limit", limit);
        }
        out.put("total", all.size());
        return Response.ok(out);
    }

    /**
     * Paged envelope for {@code /list_program_items}: one {@code items} array
     * regardless of kind, so agents learn one shape instead of eight.
     */
    public static Response pagedProgramItems(String kind, List<?> all, int offset, int limit) {
        int start = Math.max(0, offset);
        int end = (limit > 0) ? Math.min(all.size(), start + limit) : all.size();
        List<?> page = (start >= all.size()) ? List.of() : all.subList(start, end);

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("kind", kind);
        out.put("items", page);
        out.put("count", page.size());
        out.put("offset", start);
        if (limit > 0) {
            out.put("limit", limit);
        }
        out.put("total", all.size());
        return Response.ok(out);
    }

    /**
     * List envelope for tools that do not paginate.
     *
     * <pre>{@code {"entry_points": [...], "count": 12}}</pre>
     */
    public static Response listed(String key, List<?> all) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put(key, all);
        out.put("count", all.size());
        return Response.ok(out);
    }

    /**
     * Safely downcast a List&lt;Object&gt; to List&lt;Map&lt;String,String&gt;&gt;.
     */
    @SuppressWarnings("unchecked")
    public static List<Map<String, String>> convertToMapList(Object obj) {
        if (obj == null) {
            return null;
        }

        if (obj instanceof List) {
            List<Object> objList = (List<Object>) obj;
            List<Map<String, String>> result = new ArrayList<>();

            for (Object item : objList) {
                if (item instanceof Map) {
                    result.add((Map<String, String>) item);
                }
            }

            return result;
        }

        if (obj instanceof String json) {
            String trimmed = json.trim();
            if (trimmed.isEmpty()) {
                return null;
            }

            Object parsed = JsonHelper.parseJson(trimmed);
            List<Map<String, String>> parsedList = JsonHelper.toMapStringList(parsed);
            if (parsedList != null) {
                return parsedList;
            }

            // Some providers stringify arrays directly; parseJson() only handles objects.
            if (trimmed.startsWith("[")) {
                try {
                    parsedList = JsonHelper.toMapStringList(
                        com.google.gson.JsonParser.parseString(trimmed));
                } catch (Exception ignored) {
                    // Fall through and return null below.
                }
            }

            return parsedList;
        }

        return null;
    }

    // ========================================================================
    // String Utilities
    // ========================================================================

    /**
     * Check if a string meets quality criteria: 4+ chars, 80%+ printable ASCII.
     */
    public static boolean isQualityString(String str) {
        if (str == null || str.length() < 4) {
            return false;
        }

        int printableCount = 0;
        for (int i = 0; i < str.length(); i++) {
            char c = str.charAt(i);
            if ((c >= 32 && c < 127) || c == '\n' || c == '\r' || c == '\t') {
                printableCount++;
            }
        }

        double printableRatio = (double) printableCount / str.length();
        return printableRatio >= 0.80;
    }

    /**
     * Check if a Data item represents string data based on its type name.
     */
    public static boolean isStringData(Data data) {
        if (data == null) return false;

        DataType dt = data.getDataType();
        String typeName = dt.getName().toLowerCase();
        return typeName.contains("string") || typeName.contains("char") || typeName.equals("unicode");
    }

    // ========================================================================
    // Function Utilities
    // ========================================================================

    // ========================================================================
    // Number Conversion
    // ========================================================================

    /**
     * Convert a number to different representations (decimal, hex, binary, octal).
     * Supports hex (0x), binary (0b), octal (0), and decimal input formats.
     *
     * @param text The number string to convert
     * @param size The byte size for masking (1, 2, 4, or 8)
     * @return Formatted string with all representations, or an error message
     */
    /**
     * @throws IllegalArgumentException if {@code text} is null/empty or not parseable as a number
     *     in any supported base -- callers should catch and route to {@code Response.err(...)}.
     */
    public static Map<String, Object> convertNumberData(String text, int size) {
        if (text == null || text.isEmpty()) {
            throw new IllegalArgumentException("No number provided");
        }

        try {
            long value;
            String inputType;

            // Determine input format and parse
            if (text.startsWith("0x") || text.startsWith("0X")) {
                value = Long.parseUnsignedLong(text.substring(2), 16);
                inputType = "hexadecimal";
            } else if (text.startsWith("0b") || text.startsWith("0B")) {
                value = Long.parseUnsignedLong(text.substring(2), 2);
                inputType = "binary";
            } else if (text.startsWith("0") && text.length() > 1 && text.matches("0[0-7]+")) {
                value = Long.parseUnsignedLong(text, 8);
                inputType = "octal";
            } else {
                value = Long.parseUnsignedLong(text);
                inputType = "decimal";
            }

            // Handle different sizes with proper masking
            long mask = (size == 8) ? -1L : (1L << (size * 8)) - 1L;
            long maskedValue = value & mask;

            Map<String, Object> out = new LinkedHashMap<>();
            out.put("input", text);
            out.put("input_type", inputType);
            out.put("size", size);
            out.put("decimal_unsigned", Long.toUnsignedString(maskedValue));

            // Signed representation for appropriate sizes
            if (size <= 8) {
                long signedValue = maskedValue;
                if (size < 8) {
                    // Sign extend for smaller sizes
                    long signBit = 1L << (size * 8 - 1);
                    if ((maskedValue & signBit) != 0) {
                        signedValue = maskedValue | (~mask);
                    }
                }
                out.put("decimal_signed", Long.toString(signedValue));
            }

            out.put("hexadecimal", "0x" + Long.toHexString(maskedValue).toUpperCase());
            out.put("binary", "0b" + Long.toBinaryString(maskedValue));
            out.put("octal", "0" + Long.toOctalString(maskedValue));

            // Add size-specific hex representation
            String hexFormat = String.format("%%0%dX", size * 2);
            out.put("hex_padded", "0x" + String.format(hexFormat, maskedValue));

            return out;
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Invalid number format: " + text, e);
        }
    }

    /**
     * Check if a function name is auto-generated (not user-assigned).
     * Covers FUN_, Ordinal_, and thunk variants of both.
     */
    public static boolean isAutoGeneratedName(String name) {
        return name.startsWith("FUN_") || name.startsWith("Ordinal_") ||
               name.startsWith("thunk_FUN_") || name.startsWith("thunk_Ordinal_");
    }

    /**
     * Get a function at the given address, falling back to the function containing the address.
     */
    public static Function getFunctionForAddress(Program program, Address addr) {
        Function func = program.getFunctionManager().getFunctionAt(addr);
        if (func == null) {
            func = program.getFunctionManager().getFunctionContaining(addr);
        }
        return func;
    }

    /** A function reference resolved, or the reason it was not (and the message to say so). */
    public record FunctionOrError(Function function, String message) {
        public boolean hasError() { return function == null; }

        /** The failure as a response. Only meaningful when {@link #hasError()}. */
        public Response error() { return Response.err(message); }
    }

    /** How many candidate functions an ambiguity message lists. */
    private static final int MAX_LISTED_CANDIDATES = 8;

    /**
     * Whether a reference is unmistakably an address: a {@code 0x} prefix or a
     * {@code space:offset} form. Anything else, bare hex included, may also be a name.
     */
    private static boolean looksLikeExplicitAddress(String ref) {
        return ref.startsWith("0x") || ref.startsWith("0X") || ref.indexOf(':') >= 0;
    }

    /**
     * The one function a reference names: an address, or a function name.
     *
     * <p>This is the only place that decides what a function reference means; every endpoint
     * that takes one goes through it, so the same text resolves the same way everywhere
     * and fails with the same message. Before it there were two resolvers, and a name typed
     * in the wrong case worked in some tools and not others.
     *
     * <p>Order:
     * <ol>
     *   <li>A bare token (no {@code 0x}, no {@code :}) that exactly names a function is that
     *       function. A function called {@code add} or {@code dead} must not resolve to
     *       whatever lives at {@code 0xadd}.</li>
     *   <li>An address: the function at it, else the function containing it.</li>
     *   <li>A case-insensitive name, only when nothing matched exactly.</li>
     * </ol>
     * A name several functions share (two namespaces, a thunk and its target) is an error
     * listing their addresses, never the first hit: a non-thunk beats a thunk, and if that
     * still leaves more than one, the caller must pass the address. That matches what
     * {@code ProjectProgramProvider.match} does for programs.
     */
    public static FunctionOrError getFunctionOrError(Program program, String ref) {
        if (ref == null || ref.isBlank()) {
            return functionError("Function name or address is required");
        }
        String s = ref.trim();
        boolean explicit = looksLikeExplicitAddress(s);

        if (!explicit) {
            List<Function> exact = functionsNamed(program, s);
            if (!exact.isEmpty()) {
                return pickFunction(exact, s);
            }
        }

        Address addr = parseAddress(program, s);
        if (addr != null) {
            Function func = getFunctionForAddress(program, addr);
            if (func != null) {
                return new FunctionOrError(func, null);
            }
        }
        String parseError = getLastParseError();
        lastParseError.remove();

        if (explicit) {
            List<Function> exact = functionsNamed(program, s);
            if (!exact.isEmpty()) {
                return pickFunction(exact, s);
            }
        }
        List<Function> anyCase = functionsNamedIgnoreCase(program, s);
        if (!anyCase.isEmpty()) {
            return pickFunction(anyCase, s);
        }

        String why;
        if (addr != null) {
            why = "no function at or containing that address, and no function has that name";
        } else if (explicit && parseError != null && !parseError.isEmpty()) {
            why = parseError;
        } else {
            why = "not a function name, and not an address";
        }
        return functionError("Function not found: '" + s + "' (" + why + ")");
    }

    /**
     * The entry point of the function a reference names, for call sites that need an
     * {@code Address} rather than a {@link Function}. On failure returns null and leaves
     * the reason in {@link #getLastParseError()}, which every caller already reports.
     *
     * <p>An address argument behaves exactly as {@link #parseAddress}, including an
     * interior address, which stays interior so a following {@code getFunctionAt} still
     * rejects it. A name resolves as in {@link #getFunctionOrError}.
     *
     * <p>That asymmetry is why a dozen tools advertised "function address" and meant it
     * literally, even though the resolver behind them took either form.
     */
    public static Address resolveFunctionAddress(Program program, String ref) {
        String s = ref == null ? "" : ref.trim();
        if (!s.isEmpty() && !looksLikeExplicitAddress(s)) {
            List<Function> exact = functionsNamed(program, s);
            if (!exact.isEmpty()) {
                FunctionOrError picked = pickFunction(exact, s);
                if (picked.hasError()) {
                    lastParseError.set(picked.message());
                    return null;
                }
                return picked.function().getEntryPoint();
            }
        }
        Address parsed = parseAddress(program, s);
        if (parsed != null) {
            return parsed;
        }
        FunctionOrError byName = getFunctionOrError(program, s);
        if (!byName.hasError()) {
            return byName.function().getEntryPoint();
        }
        lastParseError.set(byName.message());
        return null;
    }

    /** The function a reference names, or null; for callers with nothing to say about a miss. */
    public static Function resolveFunction(Program program, String functionRef) {
        return getFunctionOrError(program, functionRef).function();
    }

    /**
     * The symbol a global name refers to, or null: a symbol in the global namespace, else
     * the first non-function symbol under that name in any namespace. The lookup
     * {@code rename_symbol} runs twice (its naming-rule check, then the rename itself),
     * which used to be two copies that had to agree.
     */
    public static Symbol findGlobalSymbol(Program program, String name) {
        SymbolTable symbolTable = program.getSymbolTable();
        List<Symbol> inGlobalNamespace = symbolTable.getSymbols(name, program.getGlobalNamespace());
        if (!inGlobalNamespace.isEmpty()) {
            return inGlobalNamespace.get(0);
        }
        SymbolIterator anywhere = symbolTable.getSymbols(name);
        while (anywhere.hasNext()) {
            Symbol symbol = anywhere.next();
            if (symbol.getSymbolType() != SymbolType.FUNCTION) {
                return symbol;
            }
        }
        return null;
    }

    private static FunctionOrError functionError(String message) {
        return new FunctionOrError(null, message);
    }

    /** Functions whose name is exactly {@code name}, by entry point. */
    private static List<Function> functionsNamed(Program program, String name) {
        FunctionManager funcManager = program.getFunctionManager();
        Map<Address, Function> found = new LinkedHashMap<>();
        SymbolIterator symbols = program.getSymbolTable().getSymbols(name);
        while (symbols.hasNext()) {
            Symbol symbol = symbols.next();
            if (symbol.getSymbolType() == SymbolType.FUNCTION) {
                Function func = funcManager.getFunctionAt(symbol.getAddress());
                if (func != null) {
                    found.putIfAbsent(func.getEntryPoint(), func);
                }
            }
        }
        return new ArrayList<>(found.values());
    }

    /** Functions whose name matches ignoring case: a linear scan, so a last resort. */
    private static List<Function> functionsNamedIgnoreCase(Program program, String name) {
        List<Function> found = new ArrayList<>();
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            if (func.getName().equalsIgnoreCase(name)) {
                found.add(func);
            }
        }
        return found;
    }

    private static FunctionOrError pickFunction(List<Function> candidates, String ref) {
        if (candidates.size() == 1) {
            return new FunctionOrError(candidates.get(0), null);
        }
        List<Function> real = candidates.stream().filter(f -> !f.isThunk()).toList();
        if (real.size() == 1) {
            return new FunctionOrError(real.get(0), null);
        }
        List<String> listed = new ArrayList<>();
        for (Function f : candidates) {
            if (listed.size() == MAX_LISTED_CANDIDATES) {
                break;
            }
            listed.add(f.getEntryPoint() + (f.isThunk() ? " (thunk)" : "")
                + (f.getParentNamespace() != null && !f.getParentNamespace().isGlobal()
                    ? " in " + f.getParentNamespace().getName(true) : ""));
        }
        return functionError("Function name '" + ref + "' is ambiguous: it matches "
            + candidates.size() + " functions (" + String.join(", ", listed)
            + (candidates.size() > listed.size() ? ", ..." : "")
            + "). Pass the address of the one you mean.");
    }

    // ========================================================================
    // Decompiler
    // ========================================================================

    /**
     * Create a {@link DecompInterface} configured to match the Ghidra GUI /
     * analysis decompiler. Applies the program's saved {@link DecompileOptions}
     * via {@link DecompileOptions#grabFromProgram(Program)} — most importantly
     * the "Respect Read-Only Flags" option — so that PIC/GOT- and
     * relocation-indirected accesses fold to their named globals instead of
     * rendering as opaque {@code DAT_} constants.
     *
     * <p>A bare {@code new DecompInterface()} leaves "Respect Read-Only Flags"
     * at the C++ decompiler-core default (OFF), which makes a read-only GOT slot
     * stay an opaque {@code DAT_} rather than being propagated and folded to the
     * symbol it points at. {@code grabFromProgram} restores the GUI-faithful
     * behavior while still respecting any per-program override.
     *
     * <p>{@code setOptions} is applied <em>before</em> {@code openProgram}, per
     * Ghidra's decompiler contract. The returned interface is already opened on
     * {@code program}; the caller owns its lifecycle and must call
     * {@link DecompInterface#dispose()} when finished.
     */
    public static DecompInterface createConfiguredDecompiler(Program program) {
        return createConfiguredDecompiler(program, null);
    }

    /**
     * As above, but with a hook to adjust the options before they are applied.
     *
     * <p>Exists so one endpoint can deviate without moving the default for the ten call
     * sites that share {@code decompileFunctionNoRetry}: {@code analyze_function_completeness}
     * counts comment lines in this text, so a change here is a change to a scoring input.
     */
    public static DecompInterface createConfiguredDecompiler(Program program,
            java.util.function.Consumer<DecompileOptions> tune) {
        DecompInterface decomp = new DecompInterface();
        DecompileOptions opts = new DecompileOptions();
        opts.grabFromProgram(program);              // GUI-faithful; respects per-program setting
        if (tune != null) tune.accept(opts);
        decomp.setOptions(opts);
        decomp.setSimplificationStyle("decompile"); // default style; explicit for consistency
        decomp.openProgram(program);                // openProgram AFTER setOptions
        return decomp;
    }

    // ========================================================================
    // Program Resolution
    // ========================================================================

    /**
     * Type-safe result from program resolution.
     * Replaces the Object[] {Program, String} pattern used across all services.
     */
    public record ProgramOrError(Program program, Response error) {
        public boolean hasError() { return program == null; }
    }

    /**
     * Which program this HTTP request actually resolved, if any.
     *
     * <p>HTTP threads are pooled. An uncleared value lets request N+1 inherit
     * request N's program name and report data as belonging to a binary it never
     * touched — the multi-program survey confusion wearing an authoritative label.
     * {@link AnnotationScanner} clears on entry and in {@code finally}; background
     * jobs (SweepJob, DirtyQueue) do not use this path.
     */
    private static final ThreadLocal<Program> resolvedProgram = new ThreadLocal<>();

    /** Record the resolved program for response labeling. Call only on success. */
    static void recordResolvedProgram(Program program) {
        if (program != null) {
            resolvedProgram.set(program);
        }
    }

    /** Clear before/after each annotation-driven request (entry + finally). */
    public static void clearResolvedProgramName() {
        resolvedProgram.remove();
    }

    /** Peek the name recorded for this thread, or null if none. */
    public static String peekResolvedProgramName() {
        Program program = resolvedProgram.get();
        return program != null ? program.getName() : null;
    }

    /** The program this request resolved, or null if none. */
    static Program peekResolvedProgram() {
        return resolvedProgram.get();
    }

    /**
     * Format the open-program list for error messages (leading space when non-empty).
     */
    private static String formatAvailablePrograms(ProgramProvider provider) {
        Program[] all = provider.getAllOpenPrograms();
        if (all == null || all.length == 0) {
            return "";
        }
        StringBuilder sb = new StringBuilder(" Available programs: ");
        for (int i = 0; i < all.length; i++) {
            if (i > 0) sb.append(", ");
            sb.append(all[i].getName());
        }
        return sb.toString();
    }

    /**
     * Resolve the target program by name, or the sole open program when name is omitted.
     *
     * <p>When {@code programName} is omitted (null/blank):
     * <ul>
     *   <li>exactly one program open → that program (no verbosity tax on the common case)</li>
     *   <li>more than one open → error naming every open program; with more than one
     *       candidate, guessing is never acceptable. Measured failure mode: a
     *       17-program survey that omitted {@code program} returned the same binary's
     *       numbers 17 times because headless never reassigned {@code currentProgram}
     *       after the first load.</li>
     *   <li>zero open → {@code "No program loaded."}</li>
     * </ul>
     * An explicit name that misses keeps the existing not-found error.
     *
     * <p>{@code /switch_program} does NOT create an exemption for later calls —
     * having switched N calls ago is exactly the stale implicit state this closes.
     * Endpoints whose contract IS the active program use
     * {@link #getActiveProgramOrError} instead.
     */
    public static ProgramOrError getProgramOrError(ProgramProvider provider, String programName) {
        if (programName != null && !programName.isEmpty()) {
            Program program;
            try {
                program = provider.getProgram(programName);
            } catch (AmbiguousProgramException e) {
                return new ProgramOrError(null, Response.err(e.getMessage()));
            }
            if (program == null) {
                return new ProgramOrError(null, Response.err(
                        "Program not found: " + programName + formatAvailablePrograms(provider)));
            }
            recordResolvedProgram(program);
            return new ProgramOrError(program, null);
        }

        // Omitted: refuse to guess when more than one program is open.
        Program[] all = provider.getAllOpenPrograms();
        if (all != null && all.length > 1) {
            StringBuilder names = new StringBuilder();
            for (int i = 0; i < all.length; i++) {
                if (i > 0) names.append(", ");
                names.append(all[i].getName());
            }
            return new ProgramOrError(null, Response.err(
                    "Multiple programs open; 'program' is required. Open programs: " + names));
        }

        Program program = provider.getCurrentProgram();
        if (program == null) {
            return new ProgramOrError(null, Response.err(
                    "No program loaded." + formatAvailablePrograms(provider)));
        }
        recordResolvedProgram(program);
        return new ProgramOrError(program, null);
    }

    /**
     * Resolve the active (current) program without the multi-program omit rule.
     *
     * <p>Use ONLY for endpoints whose contract IS the active program:
     * {@code /get_ui_cursor} (program facet), {@code /list_open_programs},
     * {@code /switch_program}. A distinct helper (not a boolean on
     * {@link #getProgramOrError}) keeps the exemption a greppable list rather
     * than a flag someone can flip by accident.
     *
     * <p>{@code /switch_program} does NOT create an exemption for later calls —
     * having switched N calls ago is exactly the stale implicit state
     * {@link #getProgramOrError} closes. That is deliberate.
     */
    public static ProgramOrError getActiveProgramOrError(ProgramProvider provider) {
        Program program = provider.getCurrentProgram();
        if (program == null) {
            // Distinguish "nothing is open" from "several are open and none is
            // active". Headless no longer has a current-program concept, so this
            // returns null the moment a second program opens — and answering
            // "No program loaded." while listing two loaded programs is a message
            // that contradicts its own evidence.
            Program[] all = provider.getAllOpenPrograms();
            String message = (all != null && all.length > 1)
                    ? "Multiple programs open and none is active; 'program' is required."
                            + formatAvailablePrograms(provider)
                    : "No program loaded." + formatAvailablePrograms(provider);
            return new ProgramOrError(null, Response.err(message));
        }
        recordResolvedProgram(program);
        return new ProgramOrError(program, null);
    }

    // ========================================================================
    // Address Resolution
    // ========================================================================

    /** Holds the error message from the most recent failed parseAddress call on this thread. */
    private static final ThreadLocal<String> lastParseError = new ThreadLocal<>();

    /**
     * Get the error message from the most recent failed parseAddress() call on the current thread.
     * Returns null if the last call succeeded or if parseAddress has not been called.
     * Must be checked immediately after a null return from parseAddress, before any other call.
     */
    public static String getLastParseError() {
        return lastParseError.get();
    }

    /**
     * Parse an address string using the program's AddressFactory.
     * Accepts both plain hex (e.g., "0x1000") and segment:offset (e.g., "mem:1000", "code:ff00",
     * "EXTERNAL:00000012").
     *
     * Returns null on failure and sets the thread-local error message (read via getLastParseError()).
     *
     * THREADING: Must be called on the HTTP worker thread, BEFORE entering any
     * threadingStrategy.executeRead/executeWrite lambda. SwingThreadingStrategy transfers
     * execution to the EDT inside execute*; a ThreadLocal set there is invisible to the caller.
     */
    public static Address parseAddress(Program program, String addressStr) {
        lastParseError.remove();
        if (addressStr == null || addressStr.isBlank()) {
            lastParseError.set("Address parameter is required.");
            return null;
        }
        addressStr = addressStr.strip();

        // Detect array-shaped input. Workers occasionally send a JSON array
        // of addresses for the `address` parameter when they meant to use the
        // batch-comments inner lists (decompiler_comments / disassembly_comments).
        // The default error message ("could not be resolved... try <space>:<hex>")
        // misled at least one worker into prepending "ram:" to the array, then
        // retrying with the same wrong shape. Detect and fail fast with a
        // structured hint instead.
        if (addressStr.startsWith("[")) {
            lastParseError.set("Address must be a single string, not an array. "
                    + "Got: " + (addressStr.length() > 80 ? addressStr.substring(0, 80) + "..." : addressStr) + ". "
                    + "If you're calling batch_set_comments, the top-level `address` is the "
                    + "function entry only; per-line addresses go inside the `decompiler_comments` "
                    + "and `disassembly_comments` arrays as objects like {\"address\": \"0x...\", \"comment\": \"...\"}. "
                    + "If you're addressing a single location, pass one hex string like \"0x6ff6a4a0\".");
            return null;
        }

        // Detect a delimited multi-address string, e.g. "10020295;100202af;..." — another
        // shape workers send when they meant to use the batch-comments inner lists. The plain
        // "could not be resolved... try <space>:<hex>" message used to suggest prepending the
        // space name to the WHOLE string, and the retry ("ram:..;ram:..") then produced a
        // second, self-contradictory "Unknown address space 'ram'. Available: ram" error.
        // Fail fast with the same structured hint as the array case instead. (addressStr is
        // already stripped, so any remaining whitespace is internal — i.e. list-shaped.)
        boolean looksLikeList = addressStr.indexOf(';') >= 0
                || addressStr.indexOf(',') >= 0
                || addressStr.chars().anyMatch(Character::isWhitespace);
        if (looksLikeList) {
            lastParseError.set("Address must be a single location, not a list. "
                    + "Got: " + (addressStr.length() > 80 ? addressStr.substring(0, 80) + "..." : addressStr) + ". "
                    + "If you're calling batch_set_comments, the top-level `address` is the "
                    + "function entry only; per-line addresses go inside the `decompiler_comments` "
                    + "and `disassembly_comments` arrays as objects like {\"address\": \"0x...\", \"comment\": \"...\"}. "
                    + "If you're addressing a single location, pass one hex string like \"0x6ff6a4a0\".");
            return null;
        }

        // Detect if this is a segment:offset form for better error messages
        boolean hasColon = addressStr.contains(":");

        // Build a resolution candidate. AddressFactory rejects a "0x" prefix on the
        // OFFSET, so strip it from the part after the last colon. The SPACE NAME is
        // left untouched — overlay space names (e.g. "cli.Initial") are case-sensitive
        // and Ghidra accepts both ':' and '::' separators.
        String candidate = addressStr;
        if (hasColon) {
            int lastColon = addressStr.lastIndexOf(':');
            String prefix = addressStr.substring(0, lastColon + 1); // includes ':' or trailing of '::'
            String offset = addressStr.substring(lastColon + 1);
            if (offset.startsWith("0x") || offset.startsWith("0X")) {
                offset = offset.substring(2);
            }
            candidate = prefix + offset;
        }

        // 1) Exact-case attempt (handles overlays and correctly-cased physical spaces).
        try {
            Address addr = program.getAddressFactory().getAddress(candidate);
            if (addr != null) return addr;
        } catch (Exception ignored) {}

        // 2) Case-insensitive space-name fallback. Preserves the forgiving behavior for
        //    physical input like "MEM:0x1000" without blindly lowercasing (which would
        //    break case-sensitive overlay names).
        if (hasColon) {
            int firstColon = candidate.indexOf(':');
            String spaceName = candidate.substring(0, firstColon);
            String offset = candidate.substring(candidate.lastIndexOf(':') + 1);
            AddressSpace match = findSpaceIgnoreCase(program, spaceName);
            if (match != null && !match.getName().equals(spaceName)) {
                try {
                    Address addr = program.getAddressFactory().getAddress(match.getName() + ":" + offset);
                    if (addr != null) return addr;
                } catch (Exception ignored) {}
            }
        }

        // Build a rich error message listing available spaces (including overlays)
        String available = buildAvailableSpacesHint(program);
        if (hasColon) {
            String spaceName = candidate.substring(0, candidate.indexOf(':'));
            String offsetPart = candidate.substring(candidate.lastIndexOf(':') + 1);
            if (isKnownSpace(program, spaceName)) {
                lastParseError.set("Could not resolve offset '" + offsetPart
                    + "' in address space '" + spaceName + "'. Check that it is valid hex "
                    + "within that space's range. Available spaces: " + available + ".");
            } else {
                lastParseError.set("Unknown address space '" + spaceName + "' in '" + addressStr
                    + "'. Available spaces: " + available + ".");
            }
        } else {
            lastParseError.set("Address '" + addressStr
                + "' could not be resolved in the default address space. "
                + "Available spaces: " + available
                + ". Try <space>:<hex> (e.g., " + buildSpaceSuggestion(program, addressStr) + ").");
        }
        return null;
    }

    /**
     * Return enriched address fields as a Map for JSON responses.
     * Always includes "address" (plain hex, no space prefix).
     * Includes "address_full" and "address_space" when the address is in an overlay
     * space (so it round-trips correctly) OR when the program has >1 physical space.
     * If program is null and the address is non-overlay, emits only "address".
     */
    public static Map<String, Object> addressToJson(Address address, Program program) {
        String plainHex = address.toString(false);
        boolean isOverlay = address.getAddressSpace().isOverlaySpace();
        boolean isExternal = address.getAddressSpace().getType() == AddressSpace.TYPE_EXTERNAL;
        // Overlay and external addresses must ALWAYS carry the qualifier: their bare hex
        // can re-resolve to the wrong logical space. For non-overlay, non-external addresses
        // keep the existing rule (qualify only when there is real physical ambiguity).
        if (!isOverlay && !isExternal && (program == null || getPhysicalSpaceCount(program) <= 1)) {
            return JsonHelper.mapOf("address", plainHex);
        }
        String spaceName = address.getAddressSpace().getName();
        return JsonHelper.mapOf(
            "address",       plainHex,
            "address_full",  address.toString(),
            "address_space", spaceName
        );
    }

    /**
     * Count the number of real (physical) address spaces in the program.
     * Excludes Ghidra internal pseudo-spaces (EXTERNAL, STACK, HASH, OTHER, REGISTER)
     * and overlay spaces (which map onto existing physical spaces and must not be double-counted).
     * Only spaces of TYPE_RAM or TYPE_CODE are counted.
     */
    public static int getPhysicalSpaceCount(Program program) {
        int count = 0;
        for (AddressSpace space : program.getAddressFactory().getAddressSpaces()) {
            if (space.isOverlaySpace()) continue;
            int type = space.getType();
            if (type == AddressSpace.TYPE_RAM || type == AddressSpace.TYPE_CODE) {
                count++;
            }
        }
        return count;
    }

    /**
     * Count the program's overlay address spaces (regardless of base type).
     * Overlay addresses must be qualified with their space name; this is
     * orthogonal to {@link #getPhysicalSpaceCount} (which measures physical
     * ambiguity for plain hex addresses).
     */
    public static int getOverlaySpaceCount(Program program) {
        int count = 0;
        for (AddressSpace space : program.getAddressFactory().getAddressSpaces()) {
            if (space.isOverlaySpace()) count++;
        }
        return count;
    }

    /**
     * True if {@code spaceName} (case-insensitive) names a known address space in the
     * program — a physical RAM/CODE space OR an overlay space (overlays carry their own
     * types, e.g. TYPE_OTHER for ".shstrtab"). Used to distinguish a genuinely unknown
     * space from a known space with a bad offset when building parse errors.
     */
    private static boolean isKnownSpace(Program program, String spaceName) {
        return findSpaceIgnoreCase(program, spaceName) != null;
    }

    /**
     * Find the address space whose name matches {@code spaceName} case-insensitively.
     * Considers overlay spaces (any type) and physical RAM/CODE spaces. Returns null
     * if none match. Used by parseAddress's case-insensitive fallback.
     */
    private static AddressSpace findSpaceIgnoreCase(Program program, String spaceName) {
        if (spaceName == null || spaceName.isEmpty()) return null;
        for (AddressSpace space : program.getAddressFactory().getAddressSpaces()) {
            boolean eligible = space.isOverlaySpace()
                    || space.getType() == AddressSpace.TYPE_RAM
                    || space.getType() == AddressSpace.TYPE_CODE
                    || space.getType() == AddressSpace.TYPE_EXTERNAL;
            if (eligible && space.getName().equalsIgnoreCase(spaceName)) {
                return space;
            }
        }
        return null;
    }

    private static String buildAvailableSpacesHint(Program program) {
        StringBuilder physical = new StringBuilder();
        StringBuilder external = new StringBuilder();
        StringBuilder overlays = new StringBuilder();
        for (AddressSpace space : program.getAddressFactory().getAddressSpaces()) {
            if (space.isOverlaySpace()) {
                if (overlays.length() > 0) overlays.append(", ");
                overlays.append(space.getName());
                continue;
            }
            int type = space.getType();
            if (type == AddressSpace.TYPE_RAM || type == AddressSpace.TYPE_CODE) {
                if (physical.length() > 0) physical.append(", ");
                physical.append(space.getName());
            } else if (type == AddressSpace.TYPE_EXTERNAL) {
                if (external.length() > 0) external.append(", ");
                external.append(space.getName());
            }
        }
        if (physical.length() == 0 && external.length() == 0 && overlays.length() == 0) return "(none)";
        StringBuilder out = new StringBuilder(physical.length() > 0 ? physical.toString() : "");
        if (external.length() > 0) {
            if (out.length() > 0) out.append(", ");
            out.append("[external] ").append(external);
        }
        if (overlays.length() > 0) {
            if (out.length() > 0) out.append(", ");
            out.append("[overlays] ").append(overlays);
        }
        return out.toString();
    }

    private static String buildSpaceSuggestion(Program program, String rawOffset) {
        // Strip leading 0x if present
        String hex = rawOffset.toLowerCase().startsWith("0x") ? rawOffset.substring(2) : rawOffset;
        // rawOffset isn't guaranteed to be a hex address -- a caller that passes a
        // decompiler-visible label (e.g. Ghidra's own "DAT_<addr>" auto-name for an
        // unresolved data reference) lands here too, since that's exactly the
        // "couldn't resolve this as an address" path. Blindly echoing it back
        // produces a nonsensical suggestion like "ram:DAT_41544144" -- still not
        // valid hex, so retrying it would just fail the same way. Confirmed live
        // 2026-07-26. Fall back to a generic placeholder when the input isn't
        // actually hex, so the suggested example is always something that would
        // really work.
        if (!hex.matches("[0-9a-fA-F]+")) {
            hex = "1000";
        }
        StringBuilder sb = new StringBuilder();
        for (AddressSpace space : program.getAddressFactory().getAddressSpaces()) {
            if (space.isOverlaySpace()) continue;
            int type = space.getType();
            if (type == AddressSpace.TYPE_RAM || type == AddressSpace.TYPE_CODE) {
                if (sb.length() > 0) sb.append(", ");
                sb.append(space.getName()).append(":").append(hex);
            } else if (type == AddressSpace.TYPE_EXTERNAL) {
                if (sb.length() > 0) sb.append(", ");
                sb.append(space.getName()).append(":").append(hex);
            }
        }
        return sb.length() > 0 ? sb.toString() : "<space>:" + hex;
    }

    // ========================================================================
    // Data Type Resolution
    // ========================================================================

    /**
     * Maps common C type names to Ghidra built-in DataType instances.
     */
    public static DataType resolveWellKnownType(String typeName) {
        switch (typeName.toLowerCase()) {
            case "int":        return IntegerDataType.dataType;
            case "uint":       return UnsignedIntegerDataType.dataType;
            case "short":      return ShortDataType.dataType;
            case "ushort":     return UnsignedShortDataType.dataType;
            case "long":       return LongDataType.dataType;
            case "ulong":      return UnsignedLongDataType.dataType;
            case "longlong":
            case "long long":  return LongLongDataType.dataType;
            case "char":       return CharDataType.dataType;
            case "uchar":      return UnsignedCharDataType.dataType;
            case "float":      return FloatDataType.dataType;
            case "double":     return DoubleDataType.dataType;
            case "bool":
            case "boolean":    return BooleanDataType.dataType;
            case "void":       return VoidDataType.dataType;
            case "byte":       return ByteDataType.dataType;
            case "sbyte":      return SignedByteDataType.dataType;
            case "word":       return WordDataType.dataType;
            case "dword":      return DWordDataType.dataType;
            case "qword":      return QWordDataType.dataType;
            case "int8_t":
            case "int8":       return SignedByteDataType.dataType;
            case "uint8_t":
            case "uint8":      return ByteDataType.dataType;
            case "int16_t":
            case "int16":      return ShortDataType.dataType;
            case "uint16_t":
            case "uint16":     return UnsignedShortDataType.dataType;
            case "int32_t":
            case "int32":      return IntegerDataType.dataType;
            case "uint32_t":
            case "uint32":     return UnsignedIntegerDataType.dataType;
            case "int64_t":
            case "int64":      return LongLongDataType.dataType;
            case "uint64_t":
            case "uint64":     return UnsignedLongLongDataType.dataType;
            case "size_t":     return UnsignedIntegerDataType.dataType;
            case "unsigned int": return UnsignedIntegerDataType.dataType;
            case "unsigned short": return UnsignedShortDataType.dataType;
            case "unsigned long": return UnsignedLongDataType.dataType;
            case "unsigned char": return UnsignedCharDataType.dataType;
            case "signed char": return SignedByteDataType.dataType;
            default:           return null;
        }
    }

    /**
     * Resolves a data type by name, handling common types, pointer types, and array types.
     * @param dtm The data type manager
     * @param typeName The type name to resolve
     * @return The resolved DataType, or null if not found
     */
    public static DataType resolveDataType(DataTypeManager dtm, String typeName) {
        try {
            return resolveDataTypeInternal(dtm, typeName);
        } catch (IllegalArgumentException e) {
            // Ghidra's CategoryPath(String) constructor throws this for a
            // malformed path (empty segment from an internal "//", missing
            // leading "/", trailing "/") when typeName itself is used to
            // probe a category path, e.g. via dtm.getDataType("/" + typeName)
            // below. Confirmed live 2026-07-26: this leaked through every
            // caller's generic outer catch as a raw, unhelpful "Error
            // processing request: Paths must have non-empty elements" --
            // every one of this method's 18 call sites already treats a
            // null return as "type not found" with its own clear message,
            // so folding a malformed name into that same path is strictly
            // more useful than exposing Ghidra's internal path-validation
            // wording as if it were a generic request-processing failure.
            Msg.error(ServiceUtils.class,
                    "Invalid type name (malformed path segment): " + typeName + " -- " + e.getMessage());
            return null;
        }
    }

    private static DataType resolveDataTypeInternal(DataTypeManager dtm, String typeName) {
        // ZERO: Map common C type names to Ghidra built-in DataType instances
        DataType wellKnown = resolveWellKnownType(typeName);
        if (wellKnown != null) {
            Msg.info(ServiceUtils.class, "Resolved well-known type: " + typeName + " -> " + wellKnown.getName());
            return wellKnown;
        }

        // FIRST: Try Ghidra builtin types in root category
        DataType builtinType = dtm.getDataType("/" + typeName);
        if (builtinType != null) {
            Msg.info(ServiceUtils.class, "Found builtin data type: " + builtinType.getPathName());
            return builtinType;
        }

        // SECOND: Try lowercase version of builtin types
        DataType builtinTypeLower = dtm.getDataType("/" + typeName.toLowerCase());
        if (builtinTypeLower != null) {
            Msg.info(ServiceUtils.class, "Found builtin data type (lowercase): " + builtinTypeLower.getPathName());
            return builtinTypeLower;
        }

        // THIRD: Search all categories as fallback
        DataType dataType = findDataTypeByNameInAllCategories(dtm, typeName);
        if (dataType != null) {
            Msg.info(ServiceUtils.class, "Found data type in categories: " + dataType.getPathName());
            return dataType;
        }

        // Check for array syntax: "type[count]"
        if (typeName.contains("[") && typeName.endsWith("]")) {
            int bracketPos = typeName.indexOf('[');
            String baseTypeName = typeName.substring(0, bracketPos);
            String countStr = typeName.substring(bracketPos + 1, typeName.length() - 1);

            try {
                int count = Integer.parseInt(countStr);
                DataType baseType = resolveDataTypeInternal(dtm, baseTypeName);

                if (baseType != null && count > 0) {
                    ArrayDataType arrayType = new ArrayDataType(baseType, count, baseType.getLength());
                    Msg.info(ServiceUtils.class, "Auto-created array type: " + typeName +
                            " (base: " + baseType.getName() + ", count: " + count +
                            ", total size: " + arrayType.getLength() + " bytes)");
                    return arrayType;
                } else if (baseType == null) {
                    Msg.error(ServiceUtils.class, "Cannot create array: base type '" + baseTypeName + "' not found");
                    return null;
                }
            } catch (NumberFormatException e) {
                Msg.error(ServiceUtils.class, "Invalid array count in type: " + typeName);
                return null;
            }
        }

        // Check for C-style pointer types (type*)
        if (typeName.endsWith("*")) {
            String baseTypeName = typeName.substring(0, typeName.length() - 1).trim();

            if (baseTypeName.equals("void") || baseTypeName.isEmpty()) {
                Msg.info(ServiceUtils.class, "Creating void* pointer type");
                return new PointerDataType(dtm.getDataType("/void"));
            }

            DataType baseType = resolveDataTypeInternal(dtm, baseTypeName);
            if (baseType != null) {
                Msg.info(ServiceUtils.class, "Creating pointer type: " + typeName +
                        " (base: " + baseType.getName() + ")");
                return new PointerDataType(baseType);
            }

            Msg.warn(ServiceUtils.class, "Base type not found for " + typeName + ", defaulting to void*");
            return new PointerDataType(dtm.getDataType("/void"));
        }

        // Check for Windows-style pointer types (PXXX)
        if (typeName.startsWith("P") && typeName.length() > 1) {
            String baseTypeName = typeName.substring(1);

            if (baseTypeName.equals("VOID")) {
                return new PointerDataType(dtm.getDataType("/void"));
            }

            DataType baseType = findDataTypeByNameInAllCategories(dtm, baseTypeName);
            if (baseType != null) {
                return new PointerDataType(baseType);
            }

            Msg.warn(ServiceUtils.class, "Base type not found for " + typeName + ", defaulting to void*");
            return new PointerDataType(dtm.getDataType("/void"));
        }

        // Handle common built-in types via DTM path lookup
        switch (typeName.toLowerCase()) {
            case "int":
            case "long":
                return dtm.getDataType("/int");
            case "uint":
            case "unsigned int":
            case "unsigned long":
            case "dword":
                return dtm.getDataType("/uint");
            case "short":
                return dtm.getDataType("/short");
            case "ushort":
            case "unsigned short":
            case "word":
                return dtm.getDataType("/ushort");
            case "char":
            case "byte":
                return dtm.getDataType("/char");
            case "uchar":
            case "unsigned char":
                return dtm.getDataType("/uchar");
            case "longlong":
            case "__int64":
                return dtm.getDataType("/longlong");
            case "ulonglong":
            case "unsigned __int64":
                return dtm.getDataType("/ulonglong");
            case "bool":
            case "boolean":
                return dtm.getDataType("/bool");
            case "float":
                return dtm.getDataType("/dword");
            case "double":
                return dtm.getDataType("/double");
            case "void":
                return dtm.getDataType("/void");
            default:
                DataType directType = dtm.getDataType("/" + typeName);
                if (directType != null) {
                    return directType;
                }
                Msg.error(ServiceUtils.class, "Unknown type: " + typeName);
                return null;
        }
    }

    /**
     * Find a data type by name in all categories/folders of the data type manager.
     */
    public static DataType findDataTypeByNameInAllCategories(DataTypeManager dtm, String typeName) {
        DataType result = searchByNameInAllCategories(dtm, typeName);
        if (result != null) {
            return result;
        }
        return searchByNameInAllCategories(dtm, typeName.toLowerCase());
    }

    /**
     * Search for a data type by name across all categories.
     */
    public static DataType searchByNameInAllCategories(DataTypeManager dtm, String name) {
        Iterator<DataType> allTypes = dtm.getAllDataTypes();
        while (allTypes.hasNext()) {
            DataType dt = allTypes.next();
            if (dt.getName().equals(name)) {
                return dt;
            }
            if (dt.getName().equalsIgnoreCase(name)) {
                return dt;
            }
        }
        return null;
    }
}
