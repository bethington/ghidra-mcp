package com.xebyte.core;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.GlobalNamespace;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;

import java.util.*;
import java.util.Comparator;
import java.util.regex.Pattern;

/**
 * Service for listing and enumeration endpoints.
 * All methods are read-only and do not require transactions.
 */
@McpToolGroup(value = "listing", description = "Enumerate functions, strings, segments, imports, exports, namespaces, classes, data items")
public class ListingService {

    private final ProgramProvider programProvider;

    public ListingService(ProgramProvider programProvider) {
        this.programProvider = programProvider;
    }

    // ========================================================================
    // Listing endpoints
    // ========================================================================

    /** Kinds accepted by {@link #listProgramItems}; unknown values are rejected. */
    private static final Set<String> PROGRAM_ITEM_KINDS = Set.of(
            "classes", "methods", "namespaces", "imports", "exports",
            "segments", "data_items", "external_locations");

    @McpTool(path = "/list_program_items",
        description = "List one kind of program inventory with pagination. "
            + "Replaces list_classes, list_methods, list_namespaces, list_imports, "
            + "list_exports, list_segments, list_data_items and list_external_locations — "
            + "one envelope ({kind, items, count, total, limit, offset}), item shape varies "
            + "by kind: classes|methods|namespaces → string names; imports|exports → "
            + "{address, name}; segments → {name, start, end, size, readable, writable, "
            + "executable, initialized}; data_items → {address, block, label, size, type}; "
            + "external_locations → {name, library, address, original_imported_name?}. "
            + "Unknown kind is an error listing the valid values.",
        category = "listing", access = ToolAccess.READ_ONLY)
    public Response listProgramItems(
            @Param(value = "kind", description = "classes | methods | namespaces | imports | "
                        + "exports | segments | data_items | external_locations") String kind,
            @Param(value = "offset", defaultValue = "0",
                   description = "Number of entries to skip before this page starts; 0 begins at the "
                               + "first entry. Page by adding `limit` each call until offset reaches the "
                               + "`total` the response reports.") int offset,
            @Param(value = "limit", defaultValue = "100",
                   description = "Maximum entries returned in this page (default 100). Pass 0 or a "
                               + "negative value for no limit; `total` in the response always reports the "
                               + "full unpaged count.") int limit,
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        if (kind == null || kind.isBlank()) {
            return Response.err("kind parameter is required");
        }
        String normalized = kind.trim().toLowerCase();
        if (!PROGRAM_ITEM_KINDS.contains(normalized)) {
            return Response.err("Unknown kind: " + kind + ". Valid kinds: "
                    + String.join(", ", PROGRAM_ITEM_KINDS));
        }

        List<?> all = switch (normalized) {
            case "classes" -> collectClassNames(program);
            case "methods" -> collectMethodNames(program);
            case "namespaces" -> collectNamespaceNames(program);
            case "imports" -> collectImports(program);
            case "exports" -> collectExports(program);
            case "segments" -> collectSegments(program);
            case "data_items" -> collectDataItems(program);
            case "external_locations" -> collectExternalLocations(program);
            default -> List.of();
        };
        return ServiceUtils.pagedProgramItems(normalized, all, offset, limit);
    }

    private List<String> collectMethodNames(Program program) {
        List<String> names = new ArrayList<>();
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            names.add(f.getName());
        }
        return names;
    }

    private List<String> collectClassNames(Program program) {
        Set<String> classNames = new HashSet<>();
        for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
            Namespace ns = symbol.getParentNamespace();
            if (ns != null && !ns.isGlobal()) {
                classNames.add(ns.getName());
            }
        }
        List<String> sorted = new ArrayList<>(classNames);
        Collections.sort(sorted);
        return sorted;
    }

    private List<Map<String, Object>> collectSegments(Program program) {
        List<Map<String, Object>> segments = new ArrayList<>();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("name", block.getName());
            entry.put("start", block.getStart().toString(false));
            entry.put("end", block.getEnd().toString(false));
            entry.put("size", block.getSize());
            entry.put("readable", block.isRead());
            entry.put("writable", block.isWrite());
            entry.put("executable", block.isExecute());
            entry.put("initialized", block.isInitialized());
            segments.add(entry);
        }
        return segments;
    }

    private List<Map<String, Object>> collectImports(Program program) {
        ExternalManager extMgr = program.getExternalManager();
        List<Map<String, Object>> all = new ArrayList<>();
        for (Symbol symbol : program.getSymbolTable().getExternalSymbols()) {
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("name", symbol.getName());
            entry.put("address", symbol.getAddress().toString());
            ExternalLocation extLoc = extMgr.getExternalLocation(symbol);
            if (extLoc != null) {
                String original = extLoc.getOriginalImportedName();
                if (original != null && !original.isEmpty() && !original.equals(symbol.getName())) {
                    entry.put("original_imported_name", original);
                }
            }
            all.add(entry);
        }
        return all;
    }

    private List<Map<String, Object>> collectExports(Program program) {
        SymbolTable table = program.getSymbolTable();
        SymbolIterator it = table.getAllSymbols(true);

        List<Map<String, Object>> exports = new ArrayList<>();
        while (it.hasNext()) {
            Symbol s = it.next();
            if (s.isExternalEntryPoint()) {
                Map<String, Object> entry = new LinkedHashMap<>();
                entry.put("name", s.getName());
                entry.put("address", s.getAddress().toString(false));
                exports.add(entry);
            }
        }
        return exports;
    }

    private List<String> collectNamespaceNames(Program program) {
        Set<String> namespaces = new HashSet<>();
        for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
            Namespace ns = symbol.getParentNamespace();
            if (ns != null && !(ns instanceof GlobalNamespace)) {
                namespaces.add(ns.getName());
            }
        }
        List<String> sorted = new ArrayList<>(namespaces);
        Collections.sort(sorted);
        return sorted;
    }

    private List<Map<String, Object>> collectDataItems(Program program) {
        List<Map<String, Object>> items = new ArrayList<>();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            DataIterator it = program.getListing().getDefinedData(block.getStart(), true);
            while (it.hasNext()) {
                Data data = it.next();
                if (block.contains(data.getAddress())) {
                    DataType dt = data.getDataType();
                    Map<String, Object> entry = new LinkedHashMap<>();
                    entry.put("label", data.getLabel() != null
                            ? data.getLabel()
                            : "DAT_" + data.getAddress().toString(false));
                    entry.put("address", data.getAddress().toString(false));
                    entry.put("type", (dt != null) ? dt.getName() : "undefined");
                    entry.put("size", data.getLength());
                    entry.put("block", block.getName());
                    items.add(entry);
                }
            }
        }
        return items;
    }

    /** Package-visible for offline tests that exercise null external addresses. */
    List<Map<String, Object>> collectExternalLocations(Program program) {
        ExternalManager extMgr = program.getExternalManager();
        List<Map<String, Object>> results = new ArrayList<>();
        String[] extLibNames = extMgr.getExternalLibraryNames();
        for (String libName : extLibNames) {
            ExternalLocationIterator iter = extMgr.getExternalLocations(libName);
            while (iter.hasNext()) {
                ExternalLocation extLoc = iter.next();
                Map<String, Object> entry = new LinkedHashMap<>();
                entry.put("name", extLoc.getLabel());
                entry.put("library", libName);
                Address address = extLoc.getAddress();
                if (address != null) {
                    entry.putAll(ServiceUtils.addressToJson(address, program));
                    entry.putIfAbsent("address_full", address.toString());
                    entry.putIfAbsent("address_space", address.getAddressSpace().getName());
                } else {
                    entry.put("address", null);
                }
                String original = extLoc.getOriginalImportedName();
                if (original != null && !original.isEmpty() && !original.equals(extLoc.getLabel())) {
                    entry.put("original_imported_name", original);
                }
                results.add(entry);
            }
        }
        return results;
    }

    @McpTool(path = "/list_data_items_by_xrefs", description = "List data items sorted by xref count (descending). By default returns only defined data items. `filter` and `type_filter` (each: all/defined/undefined) compose orthogonally to also include unnamed/untyped addresses — `filter=all,type_filter=all` returns the full data surface (named + DAT_*-style autogen + raw undefined-with-xrefs). `min_xrefs` (default 1) suppresses zero-xref noise on undefined items.", category = "listing", access = ToolAccess.READ_ONLY)
    public Response listDataItemsByXrefs(
            @Param(value = "offset", defaultValue = "0",
                   description = "Number of entries to skip before this page starts; 0 begins at the "
                               + "first entry. Page by adding `limit` each call until offset reaches the "
                               + "`total` the response reports.") int offset,
            @Param(value = "limit", defaultValue = "100",
                   description = "Maximum entries returned in this page (default 100). Pass 0 or a "
                               + "negative value for no limit; `total` in the response always reports the "
                               + "full unpaged count.") int limit,
            @Param(value = "format", defaultValue = "text",
                   description = "Deprecated, no-op: every response is JSON regardless of this value (kept only for backward-compatible calls that still pass it).") String format,
            @Param(value = "filter", defaultValue = "defined",
                   description = "Symbol-naming axis: `all`, `defined` (default — only named symbols, preserves legacy behavior), `undefined` (only DAT_*-style and raw unnamed addresses).") String filter,
            @Param(value = "type_filter", defaultValue = "all",
                   description = "Type-assignment axis: `all` (default), `defined` (only items with a real type), `undefined` (only items with `undefined*` types or no type).") String typeFilter,
            @Param(value = "min_xrefs", defaultValue = "1",
                   description = "When undefined items are included, only return addresses with at least this many xrefs. Default 1 suppresses padding/alignment noise; set to 0 for the firehose.") int minXrefs,
            @Param(value = "include_all_sections", defaultValue = "false",
                   description = "By default only data sections are scanned. Pass true to include every memory section.") boolean includeAllSections,
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        String fSym = (filter == null || filter.isEmpty()) ? "defined" : filter.toLowerCase();
        String fType = (typeFilter == null || typeFilter.isEmpty()) ? "all" : typeFilter.toLowerCase();
        int xrefMin = Math.max(0, minXrefs);

        List<DataItemInfo> dataItems = new ArrayList<>();
        ReferenceManager refMgr = program.getReferenceManager();
        Listing listing = program.getListing();
        FunctionManager functionManager = program.getFunctionManager();
        SymbolTable symTable = program.getSymbolTable();
        Set<Address> emittedAddrs = new HashSet<>();

        // Pass 1: defined data items (existing behavior, with axis filters).
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            if (!includeAllSections && !isDataBlock(block)) continue;
            DataIterator it = listing.getDefinedData(block.getStart(), true);
            while (it.hasNext()) {
                Data data = it.next();
                if (!block.contains(data.getAddress())) continue;
                Address addr = data.getAddress();

                Symbol primary = symTable.getPrimarySymbol(addr);
                String name = (primary != null) ? primary.getName() : null;
                boolean isNamed = (name != null
                        && !NamingConventions.isAutoGeneratedGlobalName(name)
                        && !ServiceUtils.isAutoGeneratedName(name));
                if ("defined".equals(fSym) && !isNamed) continue;
                if ("undefined".equals(fSym) && isNamed) continue;

                DataType dt = data.getDataType();
                String typeName = (dt != null) ? dt.getName() : "undefined";
                boolean isTyped = !typeName.startsWith("undefined");
                if ("defined".equals(fType) && !isTyped) continue;
                if ("undefined".equals(fType) && isTyped) continue;

                int xrefCount = refMgr.getReferenceCountTo(addr);
                if (!isNamed && xrefCount < xrefMin) continue;

                String label = (name != null) ? name : "DAT_" + addr.toString(false);
                dataItems.add(new DataItemInfo(addr.toString(false), label, typeName,
                        data.getLength(), xrefCount));
                emittedAddrs.add(addr);
            }
        }

        // Pass 2: raw undefined addresses with xrefs (when both axes allow undefined).
        boolean wantUnnamed = "all".equals(fSym) || "undefined".equals(fSym);
        boolean wantUntyped = "all".equals(fType) || "undefined".equals(fType);
        if (wantUnnamed && wantUntyped) {
            for (MemoryBlock block : program.getMemory().getBlocks()) {
                if (!includeAllSections && !isDataBlock(block)) continue;
                AddressIterator refs = refMgr.getReferenceDestinationIterator(
                        new AddressSet(block.getStart(), block.getEnd()), true);
                while (refs.hasNext()) {
                    Address addr = refs.next();
                    if (emittedAddrs.contains(addr)) continue;
                    if (symTable.getPrimarySymbol(addr) != null) continue;
                    if (listing.getInstructionAt(addr) != null) continue;
                    if (functionManager.getFunctionContaining(addr) != null) continue;
                    int xrefCount = refMgr.getReferenceCountTo(addr);
                    if (xrefCount < xrefMin) continue;
                    dataItems.add(new DataItemInfo(addr.toString(false),
                            "DAT_" + addr.toString(false), "undefined", 1, xrefCount));
                    emittedAddrs.add(addr);
                }
            }
        }

        dataItems.sort((a, b) -> Integer.compare(b.xrefCount, a.xrefCount));

        return formatDataItems(dataItems, offset, limit);
    }

    /** Backward-compat overload preserving the pre-5.7.x signature (no
     *  filter axes, no min_xrefs). Defaults exactly match the legacy
     *  behavior — defined data only, no axis filtering. */
    public Response listDataItemsByXrefs(int offset, int limit, String format,
                                         String programName) {
        return listDataItemsByXrefs(offset, limit, format,
                "defined", "all", 1, false, programName);
    }

    @McpTool(path = "/find_functions",
        description = "Find functions: every filter is optional, so with none it lists the whole "
            + "program a page at a time. Filter by name (substring or regex=true), xref count, "
            + "calling convention, whether the name is user-given, thunk or external, or by tag "
            + "(tag=a,b keeps functions carrying ANY of them); each result lists its tags; sort by "
            + "address, name or xref_count. Replaces list_functions, list_functions_enhanced, "
            + "search_functions and search_functions_enhanced, which returned four different "
            + "shapes for the same question.",
        category = "listing", access = ToolAccess.READ_ONLY)
    public Response findFunctions(
            @Param(value = "name_pattern", defaultValue = "",
                   aliases = {"pattern", "query", "name"},
                   description = "Substring to match, or a regex when regex=true. Omit to match "
                               + "every function.") String namePattern,
            @Param(value = "regex", defaultValue = "false",
                   description = "Treat name_pattern as a regular expression.") boolean regex,
            @Param(value = "min_xrefs", defaultValue = "",
                   description = "Only functions with at least this many references to them.") Integer minXrefs,
            @Param(value = "max_xrefs", defaultValue = "",
                   description = "Only functions with at most this many references to them.") Integer maxXrefs,
            @Param(value = "calling_convention", defaultValue = "",
                   description = "Only functions with this calling convention (e.g. __stdcall).") String callingConvention,
            @Param(value = "has_custom_name", defaultValue = "",
                   description = "true = only functions somebody has named; false = only "
                               + "auto-generated names (FUN_*, thunk_*).") Boolean hasCustomName,
            @Param(value = "is_thunk", defaultValue = "",
                   description = "true = only thunks, false = exclude them, omit for both.") Boolean isThunkFilter,
            @Param(value = "is_external", defaultValue = "",
                   description = "true = only external functions, false = exclude them.") Boolean isExternalFilter,
            @Param(value = "tag", defaultValue = "",
                   description = "Only functions carrying any of these tags: one name or a "
                               + "comma-separated list. A name that is not a defined tag is an "
                               + "error (list_function_tags shows the definitions).") String tagFilter,
            @Param(value = "sort_by", defaultValue = "address",
                   description = "address | name | xref_count.") String sortBy,
            @Param(value = "offset", defaultValue = "0",
                   description = "Number of entries to skip before this page starts; 0 begins at the "
                               + "first entry. Page by adding `limit` each call until offset reaches the "
                               + "`total` the response reports.") int offset,
            @Param(value = "limit", defaultValue = "100",
                   description = "Page size. 0 means no limit, which on a large binary is a "
                               + "megabytes-long response — the old list_functions had no "
                               + "pagination at all and returned 1.7MB on a stripped `ls`.") int limit,
            @Param(value = "program", defaultValue = "",
                   description = "Target program name (omit to use the active program — always "
                               + "specify when multiple programs are open)") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        Pattern pattern = null;
        if (regex && namePattern != null && !namePattern.isEmpty()) {
            try {
                pattern = Pattern.compile(namePattern);
            } catch (Exception e) {
                return Response.err("Invalid regex pattern: " + e.getMessage());
            }
        }

        Set<String> wantedTags = new java.util.LinkedHashSet<>();
        if (tagFilter != null) {
            for (String part : tagFilter.split(",")) {
                if (!part.trim().isEmpty()) wantedTags.add(part.trim());
            }
        }
        var tagManager = program.getFunctionManager().getFunctionTagManager();
        for (String wanted : wantedTags) {
            if (tagManager.getFunctionTag(wanted) == null) {
                return Response.err("Tag not found: " + wanted);
            }
        }

        // Classification walks a function's instructions, so it is the one expensive test here.
        // Only pay it during the scan when a caller actually filters on it; otherwise it is
        // deferred to the returned page, turning 25,779 instruction walks into `limit` of them.
        boolean classifyWhileScanning = isThunkFilter != null;

        List<Map<String, Object>> matches = new ArrayList<>();
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            String name = func.getName();
            if (namePattern != null && !namePattern.isEmpty()) {
                boolean hit = regex ? pattern.matcher(name).find() : name.contains(namePattern);
                if (!hit) continue;
            }
            if (hasCustomName != null && hasCustomName == ServiceUtils.isAutoGeneratedName(name)) {
                continue;
            }
            if (callingConvention != null && !callingConvention.isEmpty()
                    && !callingConvention.equalsIgnoreCase(func.getCallingConventionName())) {
                continue;
            }
            if (!wantedTags.isEmpty()
                    && func.getTags().stream().noneMatch(t -> wantedTags.contains(t.getName()))) {
                continue;
            }
            int xrefCount = func.getSymbol().getReferenceCount();
            if (minXrefs != null && xrefCount < minXrefs) continue;
            if (maxXrefs != null && xrefCount > maxXrefs) continue;

            boolean external = func.isExternal();
            if (isExternalFilter != null && external != isExternalFilter) continue;
            if (classifyWhileScanning) {
                boolean thunk = "thunk".equals(AnalysisService.classifyFunction(func, program));
                if (thunk != isThunkFilter) continue;
            }

            Map<String, Object> row = new LinkedHashMap<>();
            row.put("name", name);
            row.putAll(ServiceUtils.addressToJson(func.getEntryPoint(), program));
            row.put("xref_count", xrefCount);
            row.put("is_external", external);
            if (classifyWhileScanning) {
                row.put("is_thunk", isThunkFilter);
            }
            matches.add(row);
        }

        if ("name".equals(sortBy)) {
            matches.sort(Comparator.comparing(m -> (String) m.get("name")));
        } else if ("xref_count".equals(sortBy)) {
            matches.sort((a, b) -> Integer.compare((Integer) b.get("xref_count"), (Integer) a.get("xref_count")));
        } else {
            matches.sort(Comparator.comparing(m -> (String) m.get("address")));
        }

        Response paged = ServiceUtils.paged("functions", matches, offset, limit);
        // Per-result work that only the returned page pays for: tags, and thunk
        // classification when nothing filtered on it.
        if (paged instanceof Response.Ok ok
                && ok.data() instanceof Map<?, ?> map
                && map.get("functions") instanceof List<?> rows) {
            for (Object o : rows) {
                if (!(o instanceof Map)) continue;
                @SuppressWarnings("unchecked")
                Map<String, Object> row = (Map<String, Object>) o;
                Function func = ServiceUtils.resolveFunction(program, String.valueOf(row.get("address")));
                row.put("tags", func == null ? List.of()
                    : func.getTags().stream().map(t -> t.getName()).sorted().toList());
                if (!classifyWhileScanning) {
                    row.put("is_thunk", func != null
                        && "thunk".equals(AnalysisService.classifyFunction(func, program)));
                }
            }
        }
        return paged;
    }

    @McpTool(path = "/list_calling_conventions", description = "List available calling conventions", category = "listing", access = ToolAccess.READ_ONLY)
    public Response listCallingConventions(
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        try {
            ghidra.program.model.lang.CompilerSpec compilerSpec = program.getCompilerSpec();
            ghidra.program.model.lang.PrototypeModel[] available = compilerSpec.getCallingConventions();

            List<String> names = new ArrayList<>();
            for (ghidra.program.model.lang.PrototypeModel model : available) {
                names.add(model.getName());
            }
            return ServiceUtils.listed("calling_conventions", names);
        } catch (Exception e) {
            return Response.err("Error listing calling conventions: " + e.getMessage());
        }
    }

    @McpTool(path = "/list_strings", description = "List defined strings with optional filter", category = "listing", access = ToolAccess.READ_ONLY)
    public Response listDefinedStrings(
            @Param(value = "offset", defaultValue = "0",
                   description = "Number of entries to skip before this page starts; 0 begins at the "
                               + "first entry. Page by adding `limit` each call until offset reaches the "
                               + "`total` the response reports.") int offset,
            @Param(value = "limit", defaultValue = "100",
                   description = "Maximum entries returned in this page (default 100). Pass 0 or a "
                               + "negative value for no limit; `total` in the response always reports the "
                               + "full unpaged count.") int limit,
            @Param(value = "filter", description = "Substring filter", defaultValue = "") String filter,
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        List<Map<String, Object>> strings = new ArrayList<>();
        DataIterator dataIt = program.getListing().getDefinedData(true);

        while (dataIt.hasNext()) {
            Data data = dataIt.next();

            if (data != null && ServiceUtils.isStringData(data)) {
                String value = data.getValue() != null ? data.getValue().toString() : "";

                if (!ServiceUtils.isQualityString(value)) {
                    continue;
                }

                if (filter == null || value.toLowerCase().contains(filter.toLowerCase())) {
                    Map<String, Object> entry = new LinkedHashMap<>();
                    entry.put("address", data.getAddress().toString(false));
                    entry.put("value", value);
                    entry.put("length", value.length());
                    strings.add(entry);
                }
            }
        }
        // An empty result is a normal outcome, not an error: quality filtering
        // (>=4 chars, 80% printable) legitimately rejects everything in some
        // programs. Callers read count==0 rather than parsing a prose message.
        return ServiceUtils.paged("strings", strings, offset, limit);
    }

    @McpTool(path = "/get_function_count", description = "Get total function count", category = "listing", access = ToolAccess.READ_ONLY)
    public Response getFunctionCount(
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        int count = program.getFunctionManager().getFunctionCount();
        return Response.ok(JsonHelper.mapOf(
                "function_count", count,
                "program", program.getName()
        ));
    }

    @McpTool(path = "/search_strings", description = "Search strings by regex pattern.", category = "listing", access = ToolAccess.READ_ONLY)
    public Response searchStrings(
            @Param(value = "search_term", description = "Regex search pattern") String query,
            @Param(value = "min_length", defaultValue = "4",
                   description = "Ignore strings shorter than this many CHARACTERS of decoded text "
                               + "(not bytes on disk). Default 4 drops one- to three-character fragments.") int minLength,
            @Param(value = "encoding", defaultValue = "",
                   description = "Label echoed back in each match's `encoding` field. It does NOT filter: "
                               + "every defined string is searched whatever you pass here, and matches that "
                               + "carry no value report the literal string `ascii`.") String encoding,
            @Param(value = "offset", defaultValue = "0",
                   description = "Number of matches to skip before this page starts; 0 begins at the first "
                               + "match. Applied after the regex and min_length filters.") int offset,
            @Param(value = "limit", defaultValue = "100",
                   description = "Maximum matches returned in this page (default 100). `total` in the "
                               + "response reports how many matched before paging. Unlike the paged list "
                               + "endpoints, 0 here returns an EMPTY page rather than everything.") int limit,
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        if (query == null || query.isEmpty()) return Response.err("search_term parameter is required");

        Pattern pat;
        try {
            pat = Pattern.compile(query, Pattern.CASE_INSENSITIVE);
        } catch (Exception e) {
            return Response.err("Invalid regex: " + e.getMessage());
        }

        List<Map<String, Object>> results = new ArrayList<>();
        DataIterator dataIt = program.getListing().getDefinedData(true);
        while (dataIt.hasNext()) {
            Data data = dataIt.next();
            if (data == null || !ServiceUtils.isStringData(data)) continue;
            String value = data.getValue() != null ? data.getValue().toString() : "";
            if (value.length() < minLength) continue;
            if (!pat.matcher(value).find()) continue;
            String enc = (encoding != null && !encoding.isEmpty()) ? encoding : "ascii";
            Map<String, Object> item = new LinkedHashMap<>();
            item.putAll(ServiceUtils.addressToJson(data.getAddress(), program));
            item.put("value", value);
            item.put("encoding", enc);
            results.add(item);
        }

        int total = results.size();
        int from = Math.min(offset, total);
        int to = Math.min(from + limit, total);

        return Response.ok(JsonHelper.mapOf(
                "matches", results.subList(from, to),
                "total", total,
                "offset", offset,
                "limit", limit
        ));
    }

    @McpTool(path = "/list_globals", description = "List global DATA symbols. By default returns every global in the program (named + unnamed-but-xrefed undefined addresses). `filter` and `type_filter` (each: all/defined/undefined) compose orthogonally to scope the result — e.g., `filter=named, type_filter=undefined` returns the cleanup backlog (placeholders awaiting real types). `min_xrefs` (default 1) suppresses zero-xref noise when including undefined items. Code labels (branch targets, error handlers) are still excluded — they're not data globals. Each line ends with `xrefs=N` for prioritization.", category = "listing", access = ToolAccess.READ_ONLY)
    public Response listGlobals(
            @Param(value = "offset", defaultValue = "0",
                   description = "Number of entries to skip before this page starts; 0 begins at the "
                               + "first entry. Page by adding `limit` each call until offset reaches the "
                               + "`total` the response reports.") int offset,
            @Param(value = "limit", defaultValue = "100",
                   description = "Maximum entries returned in this page (default 100). Pass 0 or a "
                               + "negative value for no limit; `total` in the response always reports the "
                               + "full unpaged count.") int limit,
            @Param(value = "filter", defaultValue = "all",
                   description = "Symbol-naming axis: `all` (default), `defined` (only named symbols), `undefined` (only unnamed addresses, e.g. DAT_*-style and raw undefined data with xrefs).") String filter,
            @Param(value = "type_filter", defaultValue = "all",
                   description = "Type-assignment axis: `all` (default), `defined` (only items with a real type), `undefined` (only items with no defined type or `undefined*` types).") String typeFilter,
            @Param(value = "min_xrefs", defaultValue = "1",
                   description = "When undefined items are included, only return addresses with at least this many xrefs. Default 1 suppresses padding/alignment noise; set to 0 for the firehose.") int minXrefs,
            @Param(value = "include_all_sections", defaultValue = "false",
                   description = "By default only data sections (.data/.rdata/.bss and similar) are scanned. Pass true to include every memory section (rare — picks up .text gaps which are usually padding).") boolean includeAllSections,
            @Param(value = "name_substring", defaultValue = "",
                   description = "Optional substring match against the symbol's display line (case-insensitive). Empty = no substring filter.") String nameSubstring,
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        // Normalize filter axes (case-insensitive, default `all`).
        String fSym = (filter == null || filter.isEmpty()) ? "all" : filter.toLowerCase();
        String fType = (typeFilter == null || typeFilter.isEmpty()) ? "all" : typeFilter.toLowerCase();
        int xrefMin = Math.max(0, minXrefs);
        String subFilter = (nameSubstring == null) ? "" : nameSubstring.toLowerCase();

        SymbolTable symbolTable = program.getSymbolTable();
        Listing listing = program.getListing();
        FunctionManager functionManager = program.getFunctionManager();
        ReferenceManager refMgr = program.getReferenceManager();

        // Track addresses we've already emitted so the "include undefined
        // by walking memory blocks" pass doesn't duplicate symbols already
        // surfaced by the symbol-iterator pass.
        Set<Address> emittedAddrs = new HashSet<>();
        List<String> globals = new ArrayList<>();

        // Pass 1: iterate the global namespace, emit symbols that match
        // the filter axes (skipping code labels and functions as before).
        Namespace globalNamespace = program.getGlobalNamespace();
        SymbolIterator symbols = symbolTable.getSymbols(globalNamespace);
        while (symbols.hasNext()) {
            Symbol symbol = symbols.next();
            if (symbol.getSymbolType() == SymbolType.FUNCTION) {
                continue;
            }
            Address symAddr = symbol.getAddress();
            if (symAddr == null) continue;

            Data definedData = listing.getDefinedDataAt(symAddr);
            if (!isGlobalDataSymbol(program, symbol, includeAllSections)) continue;

            // Axis: is this symbol "named" (real user-given name) or "undefined"
            // (DAT_*, PTR_DAT_*, FUN_*, LAB_*, UNK_*, undefined-style auto names)?
            boolean isNamed = !NamingConventions.isAutoGeneratedGlobalName(symbol.getName())
                    && !ServiceUtils.isAutoGeneratedName(symbol.getName());
            if ("defined".equals(fSym) && !isNamed) continue;
            if ("undefined".equals(fSym) && isNamed) continue;

            // Axis: type assignment.
            boolean isTyped = (definedData != null
                    && definedData.getDataType() != null
                    && !definedData.getDataType().getName().startsWith("undefined"));
            if ("defined".equals(fType) && !isTyped) continue;
            if ("undefined".equals(fType) && isTyped) continue;

            int xrefCount = refMgr.getReferenceCountTo(symAddr);
            // Apply min_xrefs only when surfacing undefined items — the
            // user explicitly asked for the noise floor on undefined-data
            // discovery, not on already-named symbols.
            if (!isNamed && xrefCount < xrefMin) continue;

            String line = formatGlobalSymbol(symbol) + " xrefs=" + xrefCount;
            if (!subFilter.isEmpty() && !line.toLowerCase().contains(subFilter)) continue;
            globals.add(line);
            emittedAddrs.add(symAddr);
        }

        // Pass 2: when the filter axes allow undefined items, also walk
        // the data sections and surface raw undefined addresses with
        // ≥ min_xrefs that have no symbol at all (and weren't already
        // emitted by Pass 1). These are the high-value discovery
        // candidates.
        boolean wantUnnamed = "all".equals(fSym) || "undefined".equals(fSym);
        boolean wantUntyped = "all".equals(fType) || "undefined".equals(fType);
        if (wantUnnamed && wantUntyped) {
            for (MemoryBlock block : program.getMemory().getBlocks()) {
                if (!includeAllSections && !isDataBlock(block)) continue;
                if (!block.isInitialized() && !block.isMapped()) {
                    // .bss-style uninitialized blocks ARE valid data sections;
                    // keep them. Other unmapped/special blocks are skipped.
                    if (!"bss".equalsIgnoreCase(block.getName())) continue;
                }
                Address start = block.getStart();
                Address end = block.getEnd();
                AddressIterator refs = refMgr.getReferenceDestinationIterator(
                        new AddressSet(start, end), true);
                while (refs.hasNext()) {
                    Address addr = refs.next();
                    if (emittedAddrs.contains(addr)) continue;
                    // Skip if there's a symbol — already covered by Pass 1.
                    if (symbolTable.getPrimarySymbol(addr) != null) continue;
                    // Skip code addresses.
                    if (listing.getInstructionAt(addr) != null) continue;
                    if (functionManager.getFunctionContaining(addr) != null) continue;
                    int xrefCount = refMgr.getReferenceCountTo(addr);
                    if (xrefCount < xrefMin) continue;
                    Data d = listing.getDefinedDataAt(addr);
                    String typeName = (d != null && d.getDataType() != null)
                            ? d.getDataType().getName() : "undefined";
                    int len = (d != null) ? d.getLength() : 1;
                    String line = "DAT_" + addr.toString(false)
                            + " @ " + addr.toString(false)
                            + " [Label] (" + typeName + ")"
                            + " xrefs=" + xrefCount;
                    if (!subFilter.isEmpty() && !line.toLowerCase().contains(subFilter)) continue;
                    globals.add(line);
                    emittedAddrs.add(addr);
                }
            }
        }

        // TODO(response-contract): entries are still preformatted strings; they are
        // built in two branches above and want structuring into records
        // ({address, name, type, xrefs}) in a follow-up. The envelope is
        // contract-correct today.
        return ServiceUtils.paged("globals", globals, offset, limit);
    }

    @McpTool(path = "/list_shadowed_globals",
            description = "List named global DATA symbols that have NO type of their own because a larger data unit starting at an earlier address covers them. These are invisible to /list_globals — it resolves the CONTAINING unit, so it reports the covering neighbour's type at the shadowed address and the global looks perfectly typed. Each record carries the container that swallowed it. Use this to find documentation that a neighbouring type application destroyed, or a symbol sitting inside an array where it does not belong.",
            category = "listing", access = ToolAccess.READ_ONLY)
    public Response listShadowedGlobals(
            @Param(value = "offset", defaultValue = "0",
                   description = "Number of entries to skip before this page starts; 0 begins at the "
                               + "first entry. Page by adding `limit` each call until offset reaches the "
                               + "`total` the response reports.") int offset,
            @Param(value = "limit", defaultValue = "500",
                   description = "Maximum entries returned in this page (default 500). Pass 0 or a "
                               + "negative value for no limit; `total` in the response always reports the "
                               + "full unpaged count.") int limit,
            @Param(value = "include_all_sections", defaultValue = "false",
                   description = "By default only data sections are scanned, matching list_globals.") boolean includeAllSections,
            @Param(value = "program", description = "Target program name (omit to use the active program)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        SymbolTable symbolTable = program.getSymbolTable();
        Listing listing = program.getListing();
        FunctionManager functionManager = program.getFunctionManager();
        ReferenceManager refMgr = program.getReferenceManager();

        List<Map<String, Object>> out = new ArrayList<>();
        // Same population and the same gates as listGlobals Pass 1, on purpose:
        // this count is rendered next to that one, and two views of "the globals
        // in this binary" that disagree on their denominator is the bug class
        // this whole endpoint exists to expose.
        SymbolIterator symbols = symbolTable.getSymbols(program.getGlobalNamespace());
        while (symbols.hasNext()) {
            Symbol symbol = symbols.next();
            // SAME gate as listGlobals — see isGlobalDataSymbol for why this is
            // shared rather than copied. The shadowed set is a strict subset of
            // that listing, and an integration test pins the subset relation.
            if (!isGlobalDataSymbol(program, symbol, includeAllSections)) continue;
            Address symAddr = symbol.getAddress();

            // Shadowed means: nothing starts here, but something covers it.
            if (listing.getDefinedDataAt(symAddr) != null) continue;

            // Auto-generated labels are not documentation, so their loss is not
            // a finding — same rule the eviction guard uses to decide what may
            // be cleared.
            if (NamingConventions.isAutoGeneratedGlobalName(symbol.getName())
                    || ServiceUtils.isAutoGeneratedName(symbol.getName())) {
                continue;
            }

            Data container = listing.getDataContaining(symAddr);
            if (container == null || container.getMinAddress().equals(symAddr)) continue;

            Symbol containerSym = symbolTable.getPrimarySymbol(container.getMinAddress());
            out.add(JsonHelper.mapOf(
                    "address", symAddr.toString(),
                    "name", symbol.getName(),
                    "xrefs", refMgr.getReferenceCountTo(symAddr),
                    "container", JsonHelper.mapOf(
                            "address", container.getMinAddress().toString(),
                            "name", containerSym != null ? containerSym.getName() : "",
                            "type", container.getDataType() != null
                                    ? container.getDataType().getName() : "",
                            "length", container.getLength())
            ));
        }
        out.sort((a, b) -> String.valueOf(a.get("address")).compareTo(String.valueOf(b.get("address"))));
        return ServiceUtils.paged("shadowed", out, offset, limit);
    }

    /** Backward-compat overload preserving the pre-5.7.x signature
     *  (single substring filter only). The legacy `filter` param is now
     *  the substring matcher; new callers should use the full overload
     *  to access the defined/undefined axis filters. */
    public Response listGlobals(int offset, int limit, String filter,
                                String programName) {
        return listGlobals(offset, limit,
                /* filter (axis) */ "all",
                /* type_filter */ "all",
                /* min_xrefs */ 1,
                /* include_all_sections */ false,
                /* name_substring (legacy filter param) */ filter,
                programName);
    }

    /** Whether {@code block} is a data section (.data/.rdata/.bss/etc.) — an
     *  initialized non-executable block, or the conventional .bss name. */
    private static boolean isDataBlock(MemoryBlock block) {
        if (block.isExecute()) return false;
        String name = (block.getName() == null) ? "" : block.getName().toLowerCase();
        if (name.contains(".text") || name.contains("code")) return false;
        // Data-style block: data, rdata, bss, idata (import directory),
        // .CRT, .tls, etc. Default-allow all non-executable blocks.
        return true;
    }

    /** Convenience wrapper for callers that already have an Address. */
    private static boolean isInDataSection(Program program, Address addr) {
        MemoryBlock block = program.getMemory().getBlock(addr);
        return block != null && isDataBlock(block);
    }

    @McpTool(path = "/get_entry_points", description = "Get program entry points", category = "listing", access = ToolAccess.READ_ONLY)
    public Response getEntryPoints(
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        List<Map<String, Object>> entryPoints = new ArrayList<>();
        SymbolTable symbolTable = program.getSymbolTable();

        SymbolIterator allSymbols = symbolTable.getAllSymbols(true);
        while (allSymbols.hasNext()) {
            Symbol symbol = allSymbols.next();
            if (symbol.isExternalEntryPoint()) {
                entryPoints.add(formatEntryPoint(symbol, "external_entry"));
            }
        }

        String[] commonEntryNames = {"main", "_main", "start", "_start", "WinMain", "_WinMain",
                                   "DllMain", "_DllMain", "entry", "_entry"};

        for (String entryName : commonEntryNames) {
            SymbolIterator symbols = symbolTable.getSymbols(entryName);
            while (symbols.hasNext()) {
                Symbol symbol = symbols.next();
                if (symbol.getSymbolType() == SymbolType.FUNCTION || symbol.getSymbolType() == SymbolType.LABEL) {
                    if (!containsAddress(entryPoints, symbol.getAddress())) {
                        entryPoints.add(formatEntryPoint(symbol, "common_entry_name"));
                    }
                }
            }
        }

        Address programEntry = program.getImageBase();
        if (programEntry != null) {
            Symbol entrySymbol = symbolTable.getPrimarySymbol(programEntry);
            Map<String, Object> entryInfo;
            if (entrySymbol != null) {
                entryInfo = formatEntryPoint(entrySymbol, "program_entry");
            } else {
                entryInfo = new LinkedHashMap<>();
                entryInfo.put("name", "entry");
                entryInfo.put("address", programEntry.toString(false));
                entryInfo.put("symbol_type", "FUNCTION");
                entryInfo.put("kind", "program_entry");
            }
            if (!containsAddress(entryPoints, programEntry)) {
                entryPoints.add(entryInfo);
            }
        }

        if (entryPoints.isEmpty()) {
            String[] commonHexAddresses = {"0x401000", "0x400000", "0x1000", "0x10000"};
            for (String hexAddr : commonHexAddresses) {
                try {
                    Address addr = ServiceUtils.parseAddress(program, hexAddr);
                    if (addr != null && program.getMemory().contains(addr)) {
                        Function func = program.getFunctionManager().getFunctionAt(addr);
                        if (func != null) {
                            Map<String, Object> potential = new LinkedHashMap<>();
                            potential.put("name", func.getName());
                            potential.put("address", addr.toString(false));
                            potential.put("symbol_type", "FUNCTION");
                            potential.put("kind", "potential_entry");
                            entryPoints.add(potential);
                        }
                    }
                } catch (Exception e) {
                    // Ignore invalid addresses
                }
            }
        }

        return ServiceUtils.listed("entry_points", entryPoints);
    }

    // ========================================================================
    // Inner classes and helpers
    // ========================================================================

    static class DataItemInfo {
        final String address;
        final String label;
        final String typeName;
        final int length;
        final int xrefCount;

        DataItemInfo(String address, String label, String typeName, int length, int xrefCount) {
            this.address = address;
            this.label = label;
            this.typeName = typeName;
            this.length = length;
            this.xrefCount = xrefCount;
        }
    }

    /**
     * Every tool returns JSON (see MCP_RESPONSE_CONTRACT.md); the sibling
     * {@code formatDataItemsAsText} this replaces produced an opaque
     * newline-joined string, and even the "json" branch was a bare array
     * with no {@code count}/{@code offset}/{@code limit}/{@code total} --
     * both were contract violations. {@code format} is accepted for
     * backward compatibility but no longer changes the response shape.
     */
    private Response formatDataItems(List<DataItemInfo> dataItems, int offset, int limit) {
        List<Map<String, Object>> items = new ArrayList<>();
        for (DataItemInfo item : dataItems) {
            String sizeStr = (item.length == 1) ? "1 byte" : item.length + " bytes";
            items.add(JsonHelper.mapOf(
                    "address", item.address,
                    "name", item.label,
                    "type", item.typeName,
                    "size", sizeStr,
                    "xref_count", item.xrefCount
            ));
        }
        return ServiceUtils.paged("data_items", items, offset, limit);
    }

    /**
     * Is this symbol a global DATA symbol — the population `/list_globals` and
     * `/list_shadowed_globals` both operate over?
     *
     * ONE definition, shared by both, because they are two views of the same
     * set and their counts render side by side on the dashboard. Hand-copying
     * these gates into the second scanner (as the first cut of
     * `listShadowedGlobals` did) recreates the exact failure mode this project
     * keeps paying for: two code paths answering one question and drifting
     * apart, with the divergence surfacing as two numbers that disagree in the
     * same panel.
     *
     * Rejects functions, code addresses (branch targets, error handlers — a
     * label on an instruction is not a data global), and anything outside a
     * data section unless the caller asks for every section.
     */
    private boolean isGlobalDataSymbol(Program program, Symbol symbol, boolean includeAllSections) {
        if (symbol == null || symbol.getSymbolType() == SymbolType.FUNCTION) return false;
        Address addr = symbol.getAddress();
        if (addr == null) return false;
        Listing listing = program.getListing();
        if (listing.getDefinedDataAt(addr) == null) {
            // No data starts here, so it must not be code.
            if (listing.getInstructionAt(addr) != null) return false;
            if (program.getFunctionManager().getFunctionContaining(addr) != null) return false;
        }
        return includeAllSections || isInDataSection(program, addr);
    }

    /**
     * One line per global: {@code name @ addr [SymbolType] (type)}.
     *
     * The type is the type AT this address — {@code getDefinedDataAt} — not
     * {@code symbol.getObject()}. For a label sitting INSIDE a larger data
     * unit, Ghidra's {@code getObject()} hands back the CONTAINING Data, so the
     * old line reported the covering neighbour's type at an address that has no
     * type at all. Every consumer reads this field as "the type of this
     * global", so a global swallowed by its neighbour rendered as perfectly
     * typed in all of them: the dashboard's types bar, the globals inventory,
     * `plate_scaffold`, and the assess pass. Measured 2026-08-03 across a
     * multi-DLL production corpus — 540 shadowed globals, 539 of them invisible everywhere
     * for this one reason.
     *
     * It also contradicted this very method's own caller: `listGlobals` derives
     * its `type_filter` axis from {@code getDefinedDataAt}, so `type_filter=
     * undefined` correctly SELECTED these globals while the line it printed
     * said they were typed. Selection and display now agree.
     *
     * `undefined` (not empty) matches what the unnamed-data pass emits for the
     * same condition, so both halves of the listing spell "no type here" the
     * same way.
     */
    private String formatGlobalSymbol(Symbol symbol) {
        StringBuilder info = new StringBuilder();
        info.append(symbol.getName());
        info.append(" @ ").append(symbol.getAddress());
        info.append(" [").append(symbol.getSymbolType()).append("]");

        Data data = symbol.getProgram().getListing().getDefinedDataAt(symbol.getAddress());
        DataType dt = (data != null) ? data.getDataType() : null;
        info.append(" (").append(dt != null ? dt.getName() : "undefined").append(")");

        return info.toString();
    }

    private Map<String, Object> formatEntryPoint(Symbol symbol, String kind) {
        Map<String, Object> entry = new LinkedHashMap<>();
        entry.put("name", symbol.getName());
        entry.put("address", symbol.getAddress().toString(false));
        entry.put("symbol_type", symbol.getSymbolType().toString());
        entry.put("kind", kind);

        if (symbol.getSymbolType() == SymbolType.FUNCTION) {
            Function func = (Function) symbol.getObject();
            if (func != null) {
                entry.put("param_count", func.getParameterCount());
            }
        }

        return entry;
    }

    private boolean containsAddress(List<Map<String, Object>> entryPoints, Address address) {
        String addrStr = address.toString(false);
        for (Map<String, Object> entry : entryPoints) {
            if (addrStr.equals(entry.get("address"))) {
                return true;
            }
        }
        return false;
    }

    // ========================================================================
    // External Location Listing
    // ========================================================================

    @McpTool(path = "/get_external_location", description = "Get external location details by address or DLL name", category = "listing", access = ToolAccess.READ_ONLY)
    public Response getExternalLocationDetails(
            @Param(value = "address", paramType = "address",
                   description = "Address of the external location, as 0x<hex> (default space) or "
                               + "<space>:<hex> (e.g. mem:1000). This is the selector: matching is done "
                               + "on the address alone, so a dll_name with no address finds nothing.") String address,
            @Param(value = "dll_name", defaultValue = "",
                   description = "External library name (as list_program_items(kind=imports) or "
                               + "kind=external_locations reports it) to scope the search to. Omit to scan every library. It narrows the "
                               + "search only — it cannot select an entry by itself.") String dllName,
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        ExternalManager extMgr = program.getExternalManager();
        Address addr = null;
        if (address != null && !address.isBlank()) {
            addr = ServiceUtils.parseAddress(program, address);
            if (addr == null) return Response.err(ServiceUtils.getLastParseError());
        }

        if (dllName != null && !dllName.isEmpty()) {
            ExternalLocationIterator iter = extMgr.getExternalLocations(dllName);
            while (iter.hasNext()) {
                ExternalLocation extLoc = iter.next();
                if (matchesExternalLocation(extLoc, addr, null)) {
                    return Response.ok(externalLocationToMap(extLoc, dllName));
                }
            }
            return Response.err("External location not found in DLL");
        } else {
            String[] libNames = extMgr.getExternalLibraryNames();
            for (String libName : libNames) {
                ExternalLocationIterator iter = extMgr.getExternalLocations(libName);
                while (iter.hasNext()) {
                    ExternalLocation extLoc = iter.next();
                    if (matchesExternalLocation(extLoc, addr, address)) {
                        return Response.ok(externalLocationToMap(extLoc, libName));
                    }
                }
            }
            return Response.ok(JsonHelper.mapOf("address", address));
        }
    }

    public Response getExternalLocationDetails(String address, String dllName) {
        return getExternalLocationDetails(address, dllName, null);
    }

    private static Map<String, Object> externalLocationToMap(ExternalLocation extLoc, String libName) {
        Map<String, Object> entry = new LinkedHashMap<>();
        Address address = extLoc.getAddress();
        if (address != null) {
            entry.putAll(ServiceUtils.addressToJson(address, null));
            entry.putIfAbsent("address_full", address.toString());
            entry.putIfAbsent("address_space", address.getAddressSpace().getName());
        } else {
            entry.put("address", null);
        }
        entry.put("dll_name", libName);
        entry.put("label", extLoc.getLabel());
        String original = extLoc.getOriginalImportedName();
        if (original != null && !original.isEmpty() && !original.equals(extLoc.getLabel())) {
            entry.put("original_imported_name", original);
        }
        return entry;
    }

    private static boolean matchesExternalLocation(ExternalLocation extLoc, Address addr, String rawAddress) {
        Address extAddr = extLoc.getAddress();
        if (addr != null) {
            return extAddr != null && extAddr.equals(addr);
        }
        if (rawAddress == null || rawAddress.isBlank()) {
            return false;
        }
        return extAddr != null && extAddr.toString().equalsIgnoreCase(rawAddress.strip());
    }

    // ======================================================================
    // Equate endpoints (the only writers in this service)
    //
    // Equate names are printed verbatim by the decompiler, which is how a magic
    // constant gets a readable name (value 404 -> "sizeof(tagIecTaskNode)").
    // dry_run is deliberately NOT declared as a parameter: the framework wraps
    // every POST endpoint in a transaction and rolls it back when the request
    // carries dry_run=true (see AnnotationScanner), so declaring it here would
    // only move it into the body and bypass that wrapper.
    // ======================================================================

    @McpTool(path = "/list_equates",
            description = "List equate definitions (name/value/reference count) with optional filters, optionally "
                    + "expanded into their (address, operand_index) references. Equate names are printed verbatim "
                    + "by the decompiler.",
            category = "listing")
    public Response listEquates(
            @Param(value = "value", defaultValue = "",
                    description = "Only equates with this value: decimal, 0x-hex, or a character literal like '\\x03'") String valueText,
            @Param(value = "name_contains", defaultValue = "",
                    description = "Only equates whose name contains this substring (case-insensitive)") String nameContains,
            @Param(value = "address", paramType = "address", defaultValue = "",
                    description = "Only equates referenced at this address") String addressText,
            @Param(value = "include_references", defaultValue = "false",
                    description = "Expand each equate into its (address, operand_index) references") boolean includeReferences,
            @Param(value = "offset", defaultValue = "0") int offset,
            @Param(value = "limit", defaultValue = "200") int limit,
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        boolean valueGiven = valueText != null && !valueText.isBlank();
        Long want = parseEquateValue(valueText);
        if (valueGiven && want == null) return Response.err("Invalid `value`: " + valueText);

        Address filterAddr = null;
        if (addressText != null && !addressText.isBlank()) {
            filterAddr = ServiceUtils.parseAddress(program, addressText);
            if (filterAddr == null) return Response.err("Invalid `address`: " + ServiceUtils.getLastParseError());
        }

        List<Map<String, Object>> items = new ArrayList<>();
        EquateTable table = program.getEquateTable();
        for (Iterator<Equate> it = table.getEquates(); it.hasNext(); ) {
            Equate eq = it.next();
            if (want != null && eq.getValue() != want.longValue()) continue;
            if (nameContains != null && !nameContains.isBlank()
                    && !eq.getName().toLowerCase().contains(nameContains.toLowerCase().strip())) continue;

            List<Map<String, Object>> refs = new ArrayList<>();
            if (includeReferences || filterAddr != null) {
                for (EquateReference ref : eq.getReferences()) {
                    if (filterAddr != null && !filterAddr.equals(ref.getAddress())) continue;
                    refs.add(equateReferenceToMap(ref));
                }
                if (filterAddr != null && refs.isEmpty()) continue;
            }

            Map<String, Object> item = new LinkedHashMap<>();
            item.put("name", eq.getName());
            item.put("value", eq.getValue());
            item.put("display_value", eq.getDisplayValue());
            item.put("reference_count", eq.getReferenceCount());
            item.put("enum_based", eq.isEnumBased());
            if (includeReferences || filterAddr != null) item.put("references", refs);
            items.add(item);
        }

        int from = Math.max(0, Math.min(offset, items.size()));
        int to = Math.min(items.size(), from + Math.max(0, limit));
        return Response.ok(JsonHelper.mapOf(
                "equates", new ArrayList<>(items.subList(from, to)),
                "total", items.size(),
                "offset", offset,
                "limit", limit,
                "program", program.getName()));
    }

    @McpTool(path = "/apply_equate", method = "POST",
            description = "Create an equate (if it does not exist yet) and attach it to scalar operand(s). Use it to "
                    + "give magic constants a readable name: value 404 -> \"sizeof(tagIecTaskNode)\", value 3 -> "
                    + "\"TASKSTAT_SUSPEND\". Select one instruction with `address` (plus `operand_index`; -1 = every "
                    + "operand of that instruction) or a whole function with `function_address`; `value` filters which "
                    + "scalars match, and may be omitted when a single operand is selected. Pass dry_run=true to see "
                    + "the targets without writing (the framework rolls the transaction back).",
            category = "listing")
    public Response applyEquate(
            @Param(value = "name", source = ParamSource.BODY,
                    description = "Equate name — arbitrary text, printed verbatim by the decompiler") String name,
            @Param(value = "value", source = ParamSource.BODY, defaultValue = "",
                    description = "Scalar value to match: decimal, 0x-hex, or a character literal like '\\x03'") String valueText,
            @Param(value = "address", paramType = "address", source = ParamSource.BODY, defaultValue = "",
                    description = "Instruction address (single-operand mode)") String addressText,
            @Param(value = "operand_index", source = ParamSource.BODY, defaultValue = "-1",
                    description = "Operand index at `address`; -1 = every operand carrying a matching scalar") int operandIndex,
            @Param(value = "function_address", paramType = "address", source = ParamSource.BODY, defaultValue = "",
                    description = "Scan every instruction of the function containing this address") String functionAddressText,
            @Param(value = "max_hits", source = ParamSource.BODY, defaultValue = "1000",
                    description = "Safety cap on how many operands may be modified by one call") int maxHits,
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();
        if (name == null || name.isBlank()) return Response.err("`name` is required");

        boolean valueGiven = valueText != null && !valueText.isBlank();
        Long want = parseEquateValue(valueText);
        if (valueGiven && want == null) return Response.err("Invalid `value`: " + valueText);

        boolean byFunction = functionAddressText != null && !functionAddressText.isBlank();
        boolean byAddress = addressText != null && !addressText.isBlank();
        if (!byFunction && !byAddress) return Response.err("`address` or `function_address` is required");

        List<OperandHit> hits = new ArrayList<>();
        String scope;
        if (byFunction) {
            Address funcAddr = ServiceUtils.parseAddress(program, functionAddressText);
            if (funcAddr == null) {
                return Response.err("Invalid `function_address`: " + ServiceUtils.getLastParseError());
            }
            Function func = ServiceUtils.getFunctionForAddress(program, funcAddr);
            if (func == null) return Response.err("No function contains address " + functionAddressText);
            scope = "function " + func.getName();
            InstructionIterator it = program.getListing().getInstructions(func.getBody(), true);
            while (it.hasNext()) collectScalarOperands(it.next(), want, -1, hits);
        } else {
            Address addr = ServiceUtils.parseAddress(program, addressText);
            if (addr == null) return Response.err("Invalid `address`: " + ServiceUtils.getLastParseError());
            Instruction ins = program.getListing().getInstructionAt(addr);
            if (ins == null) return Response.err("No instruction at " + addressText);
            scope = "instruction " + ins.getAddress();
            collectScalarOperands(ins, want, operandIndex, hits);
        }
        if (hits.isEmpty()) {
            return Response.err("No scalar operand matched" + (valueGiven ? " value " + valueText : "")
                    + " in " + scope);
        }
        if (hits.size() > maxHits) {
            return Response.err("Refusing to modify " + hits.size() + " operands (max_hits=" + maxHits + ")");
        }
        long hitValue = hits.get(0).value();
        for (OperandHit hit : hits) {
            if (hit.value() != hitValue) {
                return Response.err("Matched operands have different values (" + hitValue + " and " + hit.value()
                        + "); pass `value` to disambiguate");
            }
        }
        long equateValue = (want != null) ? want.longValue() : hitValue;
        List<Map<String, Object>> targets = hitsToMaps(hits);

        EquateTable table = program.getEquateTable();
        Equate existing = table.getEquate(name);
        if (existing != null && existing.getValue() != equateValue) {
            return Response.err("Equate '" + name + "' already exists with value " + existing.getValue()
                    + " (requested " + equateValue + ")");
        }
        if (existing != null && existing.isEnumBased()) {
            return Response.err("Equate '" + name + "' is owned by an enum and cannot be re-pointed; "
                    + "use a different name");
        }

        int tx = program.startTransaction("apply_equate " + name);
        boolean commit = false;
        boolean created = false;
        int applied = 0;
        try {
            Equate equate = existing;
            if (equate == null) {
                equate = table.createEquate(name, equateValue);
                created = true;
            }
            for (OperandHit hit : hits) {
                equate.addReference(hit.address(), hit.operandIndex());
                applied++;
            }
            commit = true;
        } catch (Exception e) {
            Msg.error(this, "apply_equate failed: " + e.getMessage(), e);
            return Response.err("Failed to apply equate: " + e);
        } finally {
            program.endTransaction(tx, commit);
        }
        return Response.ok(JsonHelper.mapOf(
                "equate", name,
                "value", equateValue,
                "created", created,
                "applied", applied,
                "scope", scope,
                "targets", targets,
                "program", program.getName()));
    }

    @McpTool(path = "/remove_equate", method = "POST",
            description = "Detach an equate from operand(s) and optionally delete the definition itself. Operand "
                    + "selection is the same as /apply_equate (`address` or `function_address`, plus optional `name` "
                    + "and `value` filters); with neither selector every reference of `name` is removed. "
                    + "Pass dry_run=true to preview (the framework rolls the transaction back).",
            category = "listing")
    public Response removeEquate(
            @Param(value = "name", source = ParamSource.BODY, defaultValue = "",
                    description = "Only touch equates with exactly this name") String name,
            @Param(value = "value", source = ParamSource.BODY, defaultValue = "",
                    description = "Only touch equates with this value (decimal, 0x-hex, or a character literal)") String valueText,
            @Param(value = "address", paramType = "address", source = ParamSource.BODY, defaultValue = "",
                    description = "Instruction address; omit together with function_address to clear all references of `name`") String addressText,
            @Param(value = "operand_index", source = ParamSource.BODY, defaultValue = "-1",
                    description = "Operand index at `address`; -1 = every operand") int operandIndex,
            @Param(value = "function_address", paramType = "address", source = ParamSource.BODY, defaultValue = "",
                    description = "Scan every instruction of the function containing this address") String functionAddressText,
            @Param(value = "delete_definition", source = ParamSource.BODY, defaultValue = "false",
                    description = "After detaching, also delete the equate definition (it is shared by every reference)") boolean deleteDefinition,
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        boolean hasName = name != null && !name.isBlank();
        boolean valueGiven = valueText != null && !valueText.isBlank();
        Long want = parseEquateValue(valueText);
        if (valueGiven && want == null) return Response.err("Invalid `value`: " + valueText);
        if (!hasName && !valueGiven) return Response.err("`name` or `value` is required");

        boolean byFunction = functionAddressText != null && !functionAddressText.isBlank();
        boolean byAddress = addressText != null && !addressText.isBlank();

        EquateTable table = program.getEquateTable();
        if (!byFunction && !byAddress) {
            Equate single = table.getEquate(name);
            if (single == null) return Response.err("No equate named '" + name + "'");
        } else if (byFunction) {
            Address funcAddr = ServiceUtils.parseAddress(program, functionAddressText);
            if (funcAddr == null) {
                return Response.err("Invalid `function_address`: " + ServiceUtils.getLastParseError());
            }
            if (ServiceUtils.getFunctionForAddress(program, funcAddr) == null) {
                return Response.err("No function contains address " + functionAddressText);
            }
        } else {
            Address addr = ServiceUtils.parseAddress(program, addressText);
            if (addr == null) return Response.err("Invalid `address`: " + ServiceUtils.getLastParseError());
            if (program.getListing().getInstructionAt(addr) == null) {
                return Response.err("No instruction at " + addressText);
            }
        }

        List<Map<String, Object>> removed = new ArrayList<>();
        int tx = program.startTransaction("remove_equate");
        boolean commit = false;
        try {
            if (byFunction || byAddress) {
                List<Instruction> instructions = new ArrayList<>();
                if (byFunction) {
                    Address funcAddr = ServiceUtils.parseAddress(program, functionAddressText);
                    Function func = ServiceUtils.getFunctionForAddress(program, funcAddr);
                    InstructionIterator it = program.getListing().getInstructions(func.getBody(), true);
                    while (it.hasNext()) instructions.add(it.next());
                } else {
                    Address addr = ServiceUtils.parseAddress(program, addressText);
                    instructions.add(program.getListing().getInstructionAt(addr));
                }
                for (Instruction ins : instructions) {
                    int operandCount = ins.getNumOperands();
                    for (int i = 0; i < operandCount; i++) {
                        if (operandIndex >= 0 && i != operandIndex) continue;
                        for (Equate eq : table.getEquates(ins.getAddress(), i)) {
                            if (hasName && !eq.getName().equals(name)) continue;
                            if (want != null && eq.getValue() != want.longValue()) continue;
                            eq.removeReference(ins.getAddress(), i);
                            removed.add(equateRefToMap(eq.getName(), eq.getValue(),
                                    ins.getAddress().toString(), i));
                        }
                    }
                }
            } else {
                Equate single = table.getEquate(name);
                for (EquateReference ref : single.getReferences()) {
                    single.removeReference(ref.getAddress(), ref.getOpIndex());
                    removed.add(equateRefToMap(single.getName(), single.getValue(),
                            ref.getAddress().toString(), ref.getOpIndex()));
                }
            }
            if (deleteDefinition && hasName) table.removeEquate(name);
            commit = true;
        } catch (Exception e) {
            Msg.error(this, "remove_equate failed: " + e.getMessage(), e);
            return Response.err("Failed to remove equate: " + e);
        } finally {
            program.endTransaction(tx, commit);
        }
        return Response.ok(JsonHelper.mapOf(
                "removed_count", removed.size(),
                "removed", removed,
                "definition_deleted", deleteDefinition && hasName,
                "program", program.getName()));
    }

    @McpTool(path = "/rename_equate", method = "POST",
            description = "Rename an equate definition; every operand reference is preserved (the GUI cannot do this "
                    + "once an equate has been applied). Pass dry_run=true to preview (the framework rolls the "
                    + "transaction back).",
            category = "listing")
    public Response renameEquate(
            @Param(value = "old_name", source = ParamSource.BODY,
                    description = "Existing equate name") String oldName,
            @Param(value = "new_name", source = ParamSource.BODY,
                    description = "New name (arbitrary text, printed verbatim by the decompiler)") String newName,
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();
        if (oldName == null || oldName.isBlank()) return Response.err("`old_name` is required");
        if (newName == null || newName.isBlank()) return Response.err("`new_name` is required");

        EquateTable table = program.getEquateTable();
        Equate equate = table.getEquate(oldName);
        if (equate == null) return Response.err("No equate named '" + oldName + "'");
        if (equate.isEnumBased()) {
            return Response.err("Equate '" + oldName + "' is owned by an enum; rename the enum member instead");
        }
        Equate clash = table.getEquate(newName);
        if (clash != null && clash != equate) return Response.err("Equate '" + newName + "' already exists");
        int references = equate.getReferenceCount();

        int tx = program.startTransaction("rename_equate");
        boolean commit = false;
        try {
            equate.renameEquate(newName);
            commit = true;
        } catch (Exception e) {
            Msg.error(this, "rename_equate failed: " + e.getMessage(), e);
            return Response.err("Failed to rename equate: " + e);
        } finally {
            program.endTransaction(tx, commit);
        }
        return Response.ok(JsonHelper.mapOf(
                "old_name", oldName,
                "new_name", newName,
                "references_preserved", references,
                "program", program.getName()));
    }

    /** One scalar operand that an equate is attached to. */
    private record OperandHit(Address address, int operandIndex, long value) {}

    private static Map<String, Object> equateReferenceToMap(EquateReference ref) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("address", ref.getAddress().toString());
        map.put("operand_index", (int) ref.getOpIndex());
        return map;
    }

    private static Map<String, Object> equateRefToMap(String name, long value, String address, int operandIndex) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("name", name);
        map.put("value", value);
        map.put("address", address);
        map.put("operand_index", operandIndex);
        return map;
    }

    private static Map<String, Object> operandHitToMap(OperandHit hit) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("address", hit.address().toString());
        map.put("operand_index", hit.operandIndex());
        map.put("value", hit.value());
        return map;
    }

    private static List<Map<String, Object>> hitsToMaps(List<OperandHit> hits) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (OperandHit hit : hits) out.add(operandHitToMap(hit));
        return out;
    }

    /**
     * Parses an equate value: decimal, 0x-hex, or a single character / escape literal
     * (e.g. {@code 'A'}, {@code '\x03'}, {@code '\0'}). Returns null when unparsable.
     */
    private static Long parseEquateValue(String text) {
        if (text == null) return null;
        String trimmed = text.strip();
        if (trimmed.isEmpty()) return null;
        if (trimmed.length() >= 3 && trimmed.charAt(0) == '\''
                && trimmed.charAt(trimmed.length() - 1) == '\'') {
            String body = trimmed.substring(1, trimmed.length() - 1);
            if (body.startsWith("\\") && body.length() >= 2) {
                char escape = body.charAt(1);
                if ((escape == 'x' || escape == 'X') && body.length() > 2) {
                    try {
                        return Long.parseLong(body.substring(2), 16);
                    } catch (NumberFormatException e) {
                        return null;
                    }
                }
                switch (escape) {
                    case '0': return 0L;
                    case 'n': return 10L;
                    case 't': return 9L;
                    case 'r': return 13L;
                    case 'a': return 7L;
                    case 'b': return 8L;
                    case 'f': return 12L;
                    case 'v': return 11L;
                    case '\\': return 92L;
                    case '\'': return 39L;
                    default: return (long) escape;
                }
            }
            return body.isEmpty() ? null : (long) body.charAt(0);
        }
        try {
            if (trimmed.startsWith("-0x") || trimmed.startsWith("-0X")) {
                return -Long.parseLong(trimmed.substring(3), 16);
            }
            if (trimmed.startsWith("0x") || trimmed.startsWith("0X")) {
                return Long.parseLong(trimmed.substring(2), 16);
            }
            return Long.parseLong(trimmed);
        } catch (NumberFormatException e) {
            return null;
        }
    }

    /** Collects the scalar operands of one instruction, filtered by value and/or operand index. */
    private static void collectScalarOperands(Instruction ins, Long want, int onlyOperand,
                                              List<OperandHit> out) {
        int operandCount = ins.getNumOperands();
        for (int i = 0; i < operandCount; i++) {
            if (onlyOperand >= 0 && i != onlyOperand) continue;
            for (Object opObject : ins.getOpObjects(i)) {
                if (!(opObject instanceof Scalar)) continue;
                long value = ((Scalar) opObject).getUnsignedValue();
                if (want != null && value != want.longValue()) continue;
                out.add(new OperandHit(ins.getAddress(), i, value));
            }
        }
    }


    // ======================================================================
    // Utility endpoints (not program-scoped)
    // ======================================================================

    @McpTool(path = "/convert_number", description = "Convert number between hex/decimal/binary formats", category = "listing", access = ToolAccess.READ_ONLY)
    public Response convertNumber(
            @Param(value = "text", description = "Number to convert") String text,
            @Param(value = "size", defaultValue = "4", description = "Size in bytes") int size) {
        try {
            return Response.ok(ServiceUtils.convertNumberData(text, size));
        } catch (IllegalArgumentException e) {
            return Response.err(e.getMessage());
        }
    }
}
