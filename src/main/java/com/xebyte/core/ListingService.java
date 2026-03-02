package com.xebyte.core;

import ghidra.program.model.address.Address;
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
public class ListingService {

    private final ProgramProvider programProvider;

    public ListingService(ProgramProvider programProvider) {
        this.programProvider = programProvider;
    }

    // ========================================================================
    // Listing endpoints
    // ========================================================================

    public Response getAllFunctionNames(int offset, int limit, String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        List<String> names = new ArrayList<>();
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            names.add(f.getName());
        }
        return Response.text(ServiceUtils.paginateList(names, offset, limit));
    }

    public Response getAllClassNames(int offset, int limit, String programName) {
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

    public Response listSegments(int offset, int limit, String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        List<String> lines = new ArrayList<>();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            lines.add(String.format("%s: %s - %s", block.getName(), block.getStart(), block.getEnd()));
        }
        return Response.text(ServiceUtils.paginateList(lines, offset, limit));
    }

    public Response listImports(int offset, int limit, String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        List<String> lines = new ArrayList<>();
        for (Symbol symbol : program.getSymbolTable().getExternalSymbols()) {
            lines.add(symbol.getName() + " -> " + symbol.getAddress());
        }
        return Response.text(ServiceUtils.paginateList(lines, offset, limit));
    }

    public Response listExports(int offset, int limit, String programName) {
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

    public Response listNamespaces(int offset, int limit, String programName) {
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

    public Response listDefinedData(int offset, int limit, String programName) {
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
                    String label = data.getLabel() != null ? data.getLabel() : "DAT_" + data.getAddress().toString().replace(":", "");
                    info.append(label);
                    info.append(" @ ").append(data.getAddress().toString().replace(":", ""));

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

    public Response listDataItemsByXrefs(int offset, int limit, String format, String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        List<DataItemInfo> dataItems = new ArrayList<>();
        ReferenceManager refMgr = program.getReferenceManager();

        for (MemoryBlock block : program.getMemory().getBlocks()) {
            DataIterator it = program.getListing().getDefinedData(block.getStart(), true);
            while (it.hasNext()) {
                Data data = it.next();
                if (block.contains(data.getAddress())) {
                    Address addr = data.getAddress();
                    int xrefCount = refMgr.getReferenceCountTo(addr);

                    String label = data.getLabel() != null ? data.getLabel() :
                                   "DAT_" + addr.toString().replace(":", "");

                    DataType dt = data.getDataType();
                    String typeName = (dt != null) ? dt.getName() : "undefined";
                    int length = data.getLength();

                    dataItems.add(new DataItemInfo(addr.toString().replace(":", ""), label, typeName, length, xrefCount));
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

    public Response searchFunctionsByName(String searchTerm, int offset, int limit, String programName) {
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

    public Response listFunctions(String programName) {
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

    public Response listFunctionsEnhanced(int offset, int limit, String programName) {
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

            functions.add(JsonHelper.mapOf(
                    "name", func.getName(),
                    "address", func.getEntryPoint().toString(),
                    "isThunk", func.isThunk(),
                    "isExternal", func.isExternal()
            ));
            count++;
        }

        return Response.ok(JsonHelper.mapOf(
                "functions", functions,
                "count", count,
                "offset", offset,
                "limit", limit
        ));
    }

    public Response listCallingConventions(String programName) {
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

    public Response listDefinedStrings(int offset, int limit, String filter, String programName) {
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

    public Response getFunctionCount(String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        int count = program.getFunctionManager().getFunctionCount();
        return Response.ok(JsonHelper.mapOf(
                "function_count", count,
                "program", program.getName()
        ));
    }

    public Response searchStrings(String query, int minLength, String encoding, int offset, int limit, String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        if (query == null || query.isEmpty()) return Response.err("query parameter is required");

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
            results.add(JsonHelper.mapOf(
                    "address", data.getAddress().toString(),
                    "value", value,
                    "encoding", enc
            ));
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

    public Response listGlobals(int offset, int limit, String filter, String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        List<String> globals = new ArrayList<>();
        SymbolTable symbolTable = program.getSymbolTable();

        Namespace globalNamespace = program.getGlobalNamespace();
        SymbolIterator symbols = symbolTable.getSymbols(globalNamespace);

        while (symbols.hasNext()) {
            Symbol symbol = symbols.next();
            if (symbol.getSymbolType() == SymbolType.FUNCTION) {
                continue;
            }

            String symbolInfo = formatGlobalSymbol(symbol);
            if (filter == null || filter.isEmpty() ||
                symbolInfo.toLowerCase().contains(filter.toLowerCase())) {
                globals.add(symbolInfo);
            }
        }

        return Response.text(ServiceUtils.paginateList(globals, offset, limit));
    }

    public Response getEntryPoints(String programName) {
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
                    Address addr = program.getAddressFactory().getAddress(hexAddr);
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

    public Response listExternalLocations(int offset, int limit, String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        ExternalManager extMgr = program.getExternalManager();
        List<String> lines = new ArrayList<>();

        try {
            String[] extLibNames = extMgr.getExternalLibraryNames();
            for (String libName : extLibNames) {
                ExternalLocationIterator iter = extMgr.getExternalLocations(libName);
                while (iter.hasNext()) {
                    ExternalLocation extLoc = iter.next();
                    String locName = extLoc.getLabel();
                    String address = extLoc.getAddress().toString().replace(":", "");
                    String info = String.format("%s (%s) - %s @ %s",
                        locName, libName, extLoc.getLabel(), address);
                    lines.add(info);
                }
            }
        } catch (Exception e) {
            Msg.error(this, "Error listing external locations: " + e.getMessage());
            return Response.err(e.getMessage());
        }

        return Response.text(ServiceUtils.paginateList(lines, offset, limit));
    }

    public Response listExternalLocations(int offset, int limit) {
        return listExternalLocations(offset, limit, null);
    }

    public Response getExternalLocationDetails(String address, String dllName, String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        try {
            Address addr = program.getAddressFactory().getAddress(address);
            ExternalManager extMgr = program.getExternalManager();

            if (dllName != null && !dllName.isEmpty()) {
                ExternalLocationIterator iter = extMgr.getExternalLocations(dllName);
                while (iter.hasNext()) {
                    ExternalLocation extLoc = iter.next();
                    if (extLoc.getAddress().equals(addr)) {
                        return Response.ok(JsonHelper.mapOf(
                                "address", addr.toString(),
                                "dll_name", dllName,
                                "label", extLoc.getLabel()
                        ));
                    }
                }
                return Response.err("External location not found in DLL");
            } else {
                String[] libNames = extMgr.getExternalLibraryNames();
                for (String libName : libNames) {
                    ExternalLocationIterator iter = extMgr.getExternalLocations(libName);
                    while (iter.hasNext()) {
                        ExternalLocation extLoc = iter.next();
                        if (extLoc.getAddress().equals(addr)) {
                            return Response.ok(JsonHelper.mapOf(
                                    "address", addr.toString(),
                                    "dll_name", libName,
                                    "label", extLoc.getLabel()
                            ));
                        }
                    }
                }
                return Response.ok(JsonHelper.mapOf("address", address));
            }
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    public Response getExternalLocationDetails(String address, String dllName) {
        return getExternalLocationDetails(address, dllName, null);
    }
}
