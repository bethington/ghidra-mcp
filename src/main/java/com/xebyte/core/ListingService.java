package com.xebyte.core;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.GlobalNamespace;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;

import java.util.*;
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

    @McpTool(path = "/list_methods", description = "List all function names with pagination", category = "listing")
    public Response getAllFunctionNames(
            @Param(value = "offset", defaultValue = "0") int offset,
            @Param(value = "limit", defaultValue = "100") int limit,
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        List<String> names = new ArrayList<>();
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            names.add(f.getName());
        }
        return Response.text(ServiceUtils.paginateList(names, offset, limit));
    }

    @McpTool(path = "/list_classes", description = "List class and namespace names with pagination", category = "listing")
    public Response getAllClassNames(
            @Param(value = "offset", defaultValue = "0") int offset,
            @Param(value = "limit", defaultValue = "100") int limit,
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        Set<String> classNames = new HashSet<>();
        for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
            Namespace ns = symbol.getParentNamespace();
            if (ns != null && !ns.isGlobal()) {
                classNames.add(ns.getName());
            }
        }
        List<String> sorted = new ArrayList<>(classNames);
        Collections.sort(sorted);
        return Response.text(ServiceUtils.paginateList(sorted, offset, limit));
    }

    @McpTool(path = "/list_segments", description = "List memory blocks/segments", category = "listing")
    public Response listSegments(
            @Param(value = "offset", defaultValue = "0") int offset,
            @Param(value = "limit", defaultValue = "100") int limit,
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        List<String> lines = new ArrayList<>();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            lines.add(String.format("%s: %s - %s", block.getName(), block.getStart(), block.getEnd()));
        }
        return Response.text(ServiceUtils.paginateList(lines, offset, limit));
    }

    @McpTool(path = "/list_imports", description = "List external/imported symbols", category = "listing")
    public Response listImports(
            @Param(value = "offset", defaultValue = "0") int offset,
            @Param(value = "limit", defaultValue = "100") int limit,
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

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
        int end = Math.min(offset + limit, all.size());
        return Response.ok(offset < all.size() ? all.subList(offset, end) : List.of());
    }

    @McpTool(path = "/list_exports", description = "List exported entry points", category = "listing")
    public Response listExports(
            @Param(value = "offset", defaultValue = "0") int offset,
            @Param(value = "limit", defaultValue = "100") int limit,
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        SymbolTable table = program.getSymbolTable();
        SymbolIterator it = table.getAllSymbols(true);

        List<String> lines = new ArrayList<>();
        while (it.hasNext()) {
            Symbol s = it.next();
            if (s.isExternalEntryPoint()) {
                lines.add(s.getName() + " -> " + s.getAddress());
            }
        }
        return Response.text(ServiceUtils.paginateList(lines, offset, limit));
    }

    @McpTool(path = "/list_namespaces", description = "List namespace hierarchy", category = "listing")
    public Response listNamespaces(
            @Param(value = "offset", defaultValue = "0") int offset,
            @Param(value = "limit", defaultValue = "100") int limit,
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        Set<String> namespaces = new HashSet<>();
        for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
            Namespace ns = symbol.getParentNamespace();
            if (ns != null && !(ns instanceof GlobalNamespace)) {
                namespaces.add(ns.getName());
            }
        }
        List<String> sorted = new ArrayList<>(namespaces);
        Collections.sort(sorted);
        return Response.text(ServiceUtils.paginateList(sorted, offset, limit));
    }

    @McpTool(path = "/list_data_items", description = "List defined data items", category = "listing")
    public Response listDefinedData(
            @Param(value = "offset", defaultValue = "0") int offset,
            @Param(value = "limit", defaultValue = "100") int limit,
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        List<String> lines = new ArrayList<>();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            DataIterator it = program.getListing().getDefinedData(block.getStart(), true);
            while (it.hasNext()) {
                Data data = it.next();
                if (block.contains(data.getAddress())) {
                    StringBuilder info = new StringBuilder();
                    String label = data.getLabel() != null ? data.getLabel() : "DAT_" + data.getAddress().toString(false);
                    info.append(label);
                    info.append(" @ ").append(data.getAddress().toString(false));

                    DataType dt = data.getDataType();
                    String typeName = (dt != null) ? dt.getName() : "undefined";
                    info.append(" [").append(typeName).append("]");

                    int length = data.getLength();
                    String sizeStr = (length == 1) ? "1 byte" : length + " bytes";
                    info.append(" (").append(sizeStr).append(")");

                    lines.add(info.toString());
                }
            }
        }
        return Response.text(ServiceUtils.paginateList(lines, offset, limit));
    }

    @McpTool(path = "/list_data_items_by_xrefs", description = "List data items sorted by xref count (descending). By default returns only defined data items. `filter` and `type_filter` (each: all/defined/undefined) compose orthogonally to also include unnamed/untyped addresses — `filter=all,type_filter=all` returns the full data surface (named + DAT_*-style autogen + raw undefined-with-xrefs). `min_xrefs` (default 1) suppresses zero-xref noise on undefined items.", category = "listing")
    public Response listDataItemsByXrefs(
            @Param(value = "offset", defaultValue = "0") int offset,
            @Param(value = "limit", defaultValue = "100") int limit,
            @Param(value = "format", defaultValue = "text", description = "Output format (text or json)") String format,
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

        if ("json".equalsIgnoreCase(format)) {
            return formatDataItemsAsJson(dataItems, offset, limit);
        } else {
            return formatDataItemsAsText(dataItems, offset, limit);
        }
    }

    /** Backward-compat overload preserving the pre-5.7.x signature (no
     *  filter axes, no min_xrefs). Defaults exactly match the legacy
     *  behavior — defined data only, no axis filtering. */
    public Response listDataItemsByXrefs(int offset, int limit, String format,
                                         String programName) {
        return listDataItemsByXrefs(offset, limit, format,
                "defined", "all", 1, false, programName);
    }

    @McpTool(path = "/search_functions", description = "Search functions by name pattern. Omit name_pattern to list all functions.", category = "listing")
    public Response searchFunctionsByName(
            @Param(value = "name_pattern", description = "Substring to match against function names (omit or leave empty to return all functions)", defaultValue = "") String searchTerm,
            @Param(value = "offset", defaultValue = "0") int offset,
            @Param(value = "limit", defaultValue = "100") int limit,
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        if (searchTerm == null || searchTerm.isEmpty()) return Response.err("Search term is required");

        List<String> matches = new ArrayList<>();
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            String name = func.getName();
            if (name.toLowerCase().contains(searchTerm.toLowerCase())) {
                matches.add(String.format("%s @ %s", name, func.getEntryPoint()));
            }
        }

        Collections.sort(matches);

        if (matches.isEmpty()) {
            return Response.text("No functions matching '" + searchTerm + "'");
        }
        return Response.text(ServiceUtils.paginateList(matches, offset, limit));
    }

    @McpTool(path = "/list_functions", description = "List all functions (no pagination)", category = "listing")
    public Response listFunctions(
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        StringBuilder result = new StringBuilder();
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            result.append(String.format("%s at %s\n",
                func.getName(),
                func.getEntryPoint()));
        }

        return Response.text(result.toString());
    }

    @McpTool(path = "/list_functions_enhanced", description = "List functions with thunk/external flags as JSON", category = "listing")
    public Response listFunctionsEnhanced(
            @Param(value = "offset", defaultValue = "0") int offset,
            @Param(value = "limit", defaultValue = "10000") int limit,
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        List<Map<String, Object>> functions = new ArrayList<>();
        int count = 0;
        int skipped = 0;

        for (Function func : program.getFunctionManager().getFunctions(true)) {
            if (skipped < offset) {
                skipped++;
                continue;
            }
            if (count >= limit) break;

            Map<String, Object> funcItem = new LinkedHashMap<>();
            funcItem.putAll(ServiceUtils.addressToJson(func.getEntryPoint(), program));
            funcItem.put("name", func.getName());
            funcItem.put("isThunk", "thunk".equals(AnalysisService.classifyFunction(func, program)));
            funcItem.put("isExternal", func.isExternal());
            functions.add(funcItem);
            count++;
        }

        return Response.ok(JsonHelper.mapOf(
                "functions", functions,
                "count", count,
                "offset", offset,
                "limit", limit
        ));
    }

    @McpTool(path = "/list_calling_conventions", description = "List available calling conventions", category = "listing")
    public Response listCallingConventions(
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        try {
            ghidra.program.model.lang.CompilerSpec compilerSpec = program.getCompilerSpec();
            ghidra.program.model.lang.PrototypeModel[] available = compilerSpec.getCallingConventions();

            StringBuilder result = new StringBuilder();
            result.append("Available Calling Conventions (").append(available.length).append("):\n\n");

            for (ghidra.program.model.lang.PrototypeModel model : available) {
                result.append("- ").append(model.getName()).append("\n");
            }

            return Response.text(result.toString());
        } catch (Exception e) {
            return Response.err("Error listing calling conventions: " + e.getMessage());
        }
    }

    @McpTool(path = "/list_strings", description = "List defined strings with optional filter", category = "listing")
    public Response listDefinedStrings(
            @Param(value = "offset", defaultValue = "0") int offset,
            @Param(value = "limit", defaultValue = "100") int limit,
            @Param(value = "filter", description = "Substring filter", defaultValue = "") String filter,
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        List<String> lines = new ArrayList<>();
        DataIterator dataIt = program.getListing().getDefinedData(true);

        while (dataIt.hasNext()) {
            Data data = dataIt.next();

            if (data != null && ServiceUtils.isStringData(data)) {
                String value = data.getValue() != null ? data.getValue().toString() : "";

                if (!ServiceUtils.isQualityString(value)) {
                    continue;
                }

                if (filter == null || value.toLowerCase().contains(filter.toLowerCase())) {
                    String escapedValue = ServiceUtils.escapeString(value);
                    lines.add(String.format("%s: \"%s\"", data.getAddress(), escapedValue));
                }
            }
        }

        if (lines.isEmpty()) {
            return Response.text("No quality strings found (minimum 4 characters, 80% printable)");
        }

        return Response.text(ServiceUtils.paginateList(lines, offset, limit));
    }

    @McpTool(path = "/get_function_count", description = "Get total function count", category = "listing")
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

    @McpTool(path = "/search_strings", description = "Search strings by regex pattern.", category = "listing")
    public Response searchStrings(
            @Param(value = "search_term", description = "Regex search pattern") String query,
            @Param(value = "min_length", defaultValue = "4") int minLength,
            @Param(value = "encoding", description = "String encoding filter (omit for all encodings)", defaultValue = "") String encoding,
            @Param(value = "offset", defaultValue = "0") int offset,
            @Param(value = "limit", defaultValue = "100") int limit,
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

    @McpTool(path = "/list_globals", description = "List global DATA symbols. By default returns every global in the program (named + unnamed-but-xrefed undefined addresses). `filter` and `type_filter` (each: all/defined/undefined) compose orthogonally to scope the result — e.g., `filter=named, type_filter=undefined` returns the cleanup backlog (placeholders awaiting real types). `min_xrefs` (default 1) suppresses zero-xref noise when including undefined items. Code labels (branch targets, error handlers) are still excluded — they're not data globals. Each line ends with `xrefs=N` for prioritization.", category = "listing")
    public Response listGlobals(
            @Param(value = "offset", defaultValue = "0") int offset,
            @Param(value = "limit", defaultValue = "100") int limit,
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

            // Reject code-address symbols (branch targets, error handlers).
            Data definedData = listing.getDefinedDataAt(symAddr);
            if (definedData == null) {
                if (listing.getInstructionAt(symAddr) != null) continue;
                if (functionManager.getFunctionContaining(symAddr) != null) continue;
            }

            // Section gate.
            if (!includeAllSections && !isInDataSection(program, symAddr)) {
                continue;
            }

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

        return Response.text(ServiceUtils.paginateList(globals, offset, limit));
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

    @McpTool(path = "/get_entry_points", description = "Get program entry points", category = "listing")
    public Response getEntryPoints(
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        List<String> entryPoints = new ArrayList<>();
        SymbolTable symbolTable = program.getSymbolTable();

        SymbolIterator allSymbols = symbolTable.getAllSymbols(true);
        while (allSymbols.hasNext()) {
            Symbol symbol = allSymbols.next();
            if (symbol.isExternalEntryPoint()) {
                String entryInfo = formatEntryPoint(symbol) + " [external entry]";
                entryPoints.add(entryInfo);
            }
        }

        String[] commonEntryNames = {"main", "_main", "start", "_start", "WinMain", "_WinMain",
                                   "DllMain", "_DllMain", "entry", "_entry"};

        for (String entryName : commonEntryNames) {
            SymbolIterator symbols = symbolTable.getSymbols(entryName);
            while (symbols.hasNext()) {
                Symbol symbol = symbols.next();
                if (symbol.getSymbolType() == SymbolType.FUNCTION || symbol.getSymbolType() == SymbolType.LABEL) {
                    String entryInfo = formatEntryPoint(symbol) + " [common entry name]";
                    if (!containsAddress(entryPoints, symbol.getAddress())) {
                        entryPoints.add(entryInfo);
                    }
                }
            }
        }

        Address programEntry = program.getImageBase();
        if (programEntry != null) {
            Symbol entrySymbol = symbolTable.getPrimarySymbol(programEntry);
            String entryInfo;
            if (entrySymbol != null) {
                entryInfo = formatEntryPoint(entrySymbol) + " [program entry]";
            } else {
                entryInfo = "entry @ " + programEntry + " [program entry] [FUNCTION]";
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
                            entryPoints.add("entry @ " + addr + " (" + func.getName() + ") [potential entry] [FUNCTION]");
                        }
                    }
                } catch (Exception e) {
                    // Ignore invalid addresses
                }
            }
        }

        if (entryPoints.isEmpty()) {
            return Response.text("No entry points found in program");
        }

        return Response.text(String.join("\n", entryPoints));
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

    private Response formatDataItemsAsText(List<DataItemInfo> dataItems, int offset, int limit) {
        List<String> lines = new ArrayList<>();

        int start = Math.min(offset, dataItems.size());
        int end = Math.min(start + limit, dataItems.size());

        for (int i = start; i < end; i++) {
            DataItemInfo item = dataItems.get(i);

            StringBuilder line = new StringBuilder();
            line.append(item.label);
            line.append(" @ ").append(item.address);
            line.append(" [").append(item.typeName).append("]");

            String sizeStr = (item.length == 1) ? "1 byte" : item.length + " bytes";
            line.append(" (").append(sizeStr).append(")");
            line.append(" - ").append(item.xrefCount).append(" xrefs");

            lines.add(line.toString());
        }

        return Response.text(String.join("\n", lines));
    }

    private Response formatDataItemsAsJson(List<DataItemInfo> dataItems, int offset, int limit) {
        int start = Math.min(offset, dataItems.size());
        int end = Math.min(start + limit, dataItems.size());

        List<Map<String, Object>> items = new ArrayList<>();
        for (int i = start; i < end; i++) {
            DataItemInfo item = dataItems.get(i);
            String sizeStr = (item.length == 1) ? "1 byte" : item.length + " bytes";
            items.add(JsonHelper.mapOf(
                    "address", item.address,
                    "name", item.label,
                    "type", item.typeName,
                    "size", sizeStr,
                    "xref_count", item.xrefCount
            ));
        }

        return Response.ok(items);
    }

    private String formatGlobalSymbol(Symbol symbol) {
        StringBuilder info = new StringBuilder();
        info.append(symbol.getName());
        info.append(" @ ").append(symbol.getAddress());
        info.append(" [").append(symbol.getSymbolType()).append("]");

        if (symbol.getObject() instanceof Data) {
            Data data = (Data) symbol.getObject();
            DataType dt = data.getDataType();
            if (dt != null) {
                info.append(" (").append(dt.getName()).append(")");
            }
        }

        return info.toString();
    }

    private String formatEntryPoint(Symbol symbol) {
        StringBuilder info = new StringBuilder();
        info.append(symbol.getName());
        info.append(" @ ").append(symbol.getAddress());
        info.append(" [").append(symbol.getSymbolType()).append("]");

        if (symbol.getSymbolType() == SymbolType.FUNCTION) {
            Function func = (Function) symbol.getObject();
            if (func != null) {
                info.append(" (").append(func.getParameterCount()).append(" params)");
            }
        }

        return info.toString();
    }

    private boolean containsAddress(List<String> entryPoints, Address address) {
        String addrStr = address.toString();
        for (String entry : entryPoints) {
            if (entry.contains("@ " + addrStr)) {
                return true;
            }
        }
        return false;
    }

    // ========================================================================
    // External Location Listing
    // ========================================================================

    @McpTool(path = "/list_external_locations", description = "List external symbol locations", category = "listing")
    public Response listExternalLocations(
            @Param(value = "offset", defaultValue = "0") int offset,
            @Param(value = "limit", defaultValue = "100") int limit,
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        ExternalManager extMgr = program.getExternalManager();

        try {
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
            int end = Math.min(offset + limit, results.size());
            return Response.ok(offset < results.size() ? results.subList(offset, end) : List.of());
        } catch (Exception e) {
            Msg.error(this, "Error listing external locations: " + e.getMessage());
            return Response.err(e.getMessage());
        }
    }

    public Response listExternalLocations(int offset, int limit) {
        return listExternalLocations(offset, limit, null);
    }

    @McpTool(path = "/get_external_location", description = "Get external location details by address or DLL name", category = "listing")
    public Response getExternalLocationDetails(
            @Param(value = "address") String address,
            @Param(value = "dll_name") String dllName,
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
    // Utility endpoints (not program-scoped)
    // ======================================================================

    @McpTool(path = "/convert_number", description = "Convert number between hex/decimal/binary formats", category = "listing")
    public Response convertNumber(
            @Param(value = "text", description = "Number to convert") String text,
            @Param(value = "size", defaultValue = "4", description = "Size in bytes") int size) {
        return Response.text(ServiceUtils.convertNumber(text, size));
    }
}
