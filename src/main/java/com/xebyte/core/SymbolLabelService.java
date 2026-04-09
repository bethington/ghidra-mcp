package com.xebyte.core;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;

import javax.swing.SwingUtilities;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Service for symbol and label operations: create, rename, delete, batch operations.
 */
@McpToolGroup(value = "symbol", description = "Create/rename/delete labels, rename data, globals, external locations")
public class SymbolLabelService {

    private final ProgramProvider programProvider;
    private final ThreadingStrategy threadingStrategy;

    public SymbolLabelService(ProgramProvider programProvider, ThreadingStrategy threadingStrategy) {
        this.programProvider = programProvider;
        this.threadingStrategy = threadingStrategy;
    }

    // -----------------------------------------------------------------------
    // Label Methods
    // -----------------------------------------------------------------------

    public Response getFunctionLabels(String functionName, int offset, int limit) {
        return getFunctionLabels(functionName, offset, limit, null);
    }

    @McpTool(path = "/get_function_labels", description = "Get labels within a function body. Requires the function name — if you only have an address, call get_function_by_address first to retrieve the name.", category = "symbol")
    public Response getFunctionLabels(
            @Param(value = "name", description = "Function name (not an address — use get_function_by_address to resolve an address to a name first)") String functionName,
            @Param(value = "offset", defaultValue = "0") int offset,
            @Param(value = "limit", defaultValue = "20") int limit,
            @Param(value = "program", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        StringBuilder sb = new StringBuilder();
        SymbolTable symbolTable = program.getSymbolTable();
        FunctionManager functionManager = program.getFunctionManager();

        Function function = null;
        for (Function f : functionManager.getFunctions(true)) {
            if (f.getName().equals(functionName)) {
                function = f;
                break;
            }
        }

        if (function == null) {
            return Response.text("Function not found: " + functionName);
        }

        AddressSetView functionBody = function.getBody();
        SymbolIterator symbols = symbolTable.getSymbolIterator();
        int count = 0;
        int skipped = 0;

        while (symbols.hasNext() && count < limit) {
            Symbol symbol = symbols.next();

            if (symbol.getSymbolType() == SymbolType.LABEL &&
                functionBody.contains(symbol.getAddress())) {

                if (skipped < offset) {
                    skipped++;
                    continue;
                }

                if (sb.length() > 0) {
                    sb.append("\n");
                }
                sb.append("Address: ").append(symbol.getAddress().toString())
                  .append(", Name: ").append(symbol.getName())
                  .append(", Source: ").append(symbol.getSource().toString());
                count++;
            }
        }

        if (sb.length() == 0) {
            return Response.text("No labels found in function: " + functionName);
        }

        return Response.text(sb.toString());
    }

    public Response renameLabel(String addressStr, String oldName, String newName) {
        return renameLabel(addressStr, oldName, newName, null);
    }

    @McpTool(path = "/rename_label", method = "POST", description = "Rename a label at address. On programs with multiple address spaces (e.g., embedded targets), prefix addresses with the space name (mem:1000) to avoid ambiguous resolution.", category = "symbol")
    public Response renameLabel(
            @Param(value = "address", paramType = "address", source = ParamSource.BODY,
                   description = "Address in the program. Accepts 0x<hex> (default space) or <space>:<hex> "
                               + "(e.g., mem:1000, code:ff00). Note: some programs — particularly "
                               + "embedded/microcontroller targets — are not address-space-agnostic; "
                               + "use get_address_spaces to discover spaces before assuming a plain hex "
                               + "address is unambiguous.") String addressStr,
            @Param(value = "old_name", source = ParamSource.BODY) String oldName,
            @Param(value = "new_name", source = ParamSource.BODY) String newName,
            @Param(value = "program", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        try {
            Address address = ServiceUtils.parseAddress(program, addressStr);
            if (address == null) {
                return Response.err(ServiceUtils.getLastParseError());
            }

            SymbolTable symbolTable = program.getSymbolTable();
            Symbol[] symbols = symbolTable.getSymbols(address);

            Symbol targetSymbol = null;
            for (Symbol symbol : symbols) {
                if (symbol.getName().equals(oldName) && symbol.getSymbolType() == SymbolType.LABEL) {
                    targetSymbol = symbol;
                    break;
                }
            }

            if (targetSymbol == null) {
                return Response.err("Label not found: " + oldName + " at address " + addressStr);
            }

            for (Symbol symbol : symbols) {
                if (symbol.getName().equals(newName) && symbol.getSymbolType() == SymbolType.LABEL) {
                    return Response.err("Label with name '" + newName + "' already exists at address " + addressStr);
                }
            }

            int transactionId = program.startTransaction("Rename Label");
            try {
                targetSymbol.setName(newName, SourceType.USER_DEFINED);
                List<String> labelWarnings = NamingConventions.validateLabelName(newName);
                if (labelWarnings.isEmpty()) {
                    return Response.ok(JsonHelper.mapOf("status", "success", "message",
                            "Renamed label from '" + oldName + "' to '" + newName + "' at address " + addressStr));
                } else {
                    return Response.ok(JsonHelper.mapOf("status", "success", "message",
                            "Renamed label from '" + oldName + "' to '" + newName + "' at address " + addressStr,
                            "warnings", labelWarnings));
                }
            } catch (Exception e) {
                return Response.err("Error renaming label: " + e.getMessage());
            } finally {
                program.endTransaction(transactionId, true);
            }

        } catch (Exception e) {
            return Response.err("Error processing request: " + e.getMessage());
        }
    }

    public Response createLabel(String addressStr, String labelName) {
        return createLabel(addressStr, labelName, null);
    }

    @McpTool(path = "/create_label", method = "POST", description = "Create a label at address. On programs with multiple address spaces (e.g., embedded targets), prefix addresses with the space name (mem:1000) to avoid ambiguous resolution.", category = "symbol")
    public Response createLabel(
            @Param(value = "address", paramType = "address", source = ParamSource.BODY,
                   description = "Address in the program. Accepts 0x<hex> (default space) or <space>:<hex> "
                               + "(e.g., mem:1000, code:ff00). Note: some programs — particularly "
                               + "embedded/microcontroller targets — are not address-space-agnostic; "
                               + "use get_address_spaces to discover spaces before assuming a plain hex "
                               + "address is unambiguous.") String addressStr,
            @Param(value = "name", source = ParamSource.BODY) String labelName,
            @Param(value = "program", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        if (addressStr == null || addressStr.isEmpty()) {
            return Response.err("Address is required");
        }
        if (labelName == null || labelName.isEmpty()) {
            return Response.err("Label name is required");
        }

        try {
            Address address = ServiceUtils.parseAddress(program, addressStr);
            if (address == null) {
                return Response.err(ServiceUtils.getLastParseError());
            }

            SymbolTable symbolTable = program.getSymbolTable();

            Symbol[] existingSymbols = symbolTable.getSymbols(address);
            for (Symbol symbol : existingSymbols) {
                if (symbol.getName().equals(labelName) && symbol.getSymbolType() == SymbolType.LABEL) {
                    return Response.err("Label '" + labelName + "' already exists at address " + addressStr);
                }
            }

            SymbolIterator existingLabels = symbolTable.getSymbolIterator(labelName, true);
            if (existingLabels.hasNext()) {
                Symbol existingSymbol = existingLabels.next();
                if (existingSymbol.getSymbolType() == SymbolType.LABEL) {
                    Msg.warn(this, "Label name '" + labelName + "' already exists at address " +
                            existingSymbol.getAddress() + ". Creating duplicate at " + addressStr);
                }
            }

            int transactionId = program.startTransaction("Create Label");
            try {
                Symbol newSymbol = symbolTable.createLabel(address, labelName, SourceType.USER_DEFINED);
                if (newSymbol != null) {
                    List<String> labelWarnings = NamingConventions.validateLabelName(labelName);
                    if (labelWarnings.isEmpty()) {
                        return Response.ok(JsonHelper.mapOf("status", "success", "message",
                                "Created label '" + labelName + "' at address " + addressStr));
                    } else {
                        return Response.ok(JsonHelper.mapOf("status", "success", "message",
                                "Created label '" + labelName + "' at address " + addressStr,
                                "warnings", labelWarnings));
                    }
                } else {
                    return Response.err("Failed to create label '" + labelName + "' at address " + addressStr);
                }
            } catch (Exception e) {
                return Response.err("Error creating label: " + e.getMessage());
            } finally {
                program.endTransaction(transactionId, true);
            }

        } catch (Exception e) {
            return Response.err("Error processing request: " + e.getMessage());
        }
    }

    public Response batchCreateLabels(List<Map<String, String>> labels) {
        return batchCreateLabels(labels, null);
    }

    @McpTool(path = "/batch_create_labels", method = "POST", description = "Create multiple labels at once", category = "symbol")
    public Response batchCreateLabels(
            @Param(value = "labels", source = ParamSource.BODY) List<Map<String, String>> labels,
            @Param(value = "program", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        if (labels == null || labels.isEmpty()) {
            return Response.err("No labels provided");
        }

        final AtomicInteger successCount = new AtomicInteger(0);
        final AtomicInteger skipCount = new AtomicInteger(0);
        final AtomicInteger errorCount = new AtomicInteger(0);
        final List<String> errors = new ArrayList<>();

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Batch Create Labels");
                try {
                    SymbolTable symbolTable = program.getSymbolTable();

                    for (Map<String, String> labelEntry : labels) {
                        String addressStr = labelEntry.get("address");
                        String labelName = labelEntry.get("name");

                        if (addressStr == null || addressStr.isEmpty()) {
                            errors.add("Missing address in label entry");
                            errorCount.incrementAndGet();
                            continue;
                        }
                        if (labelName == null || labelName.isEmpty()) {
                            errors.add("Missing name for address " + addressStr);
                            errorCount.incrementAndGet();
                            continue;
                        }

                        try {
                            Address address = ServiceUtils.parseAddress(program, addressStr);
                            if (address == null) {
                                errors.add(ServiceUtils.getLastParseError());
                                errorCount.incrementAndGet();
                                continue;
                            }

                            Symbol[] existingSymbols = symbolTable.getSymbols(address);
                            boolean labelExists = false;
                            for (Symbol symbol : existingSymbols) {
                                if (symbol.getName().equals(labelName) && symbol.getSymbolType() == SymbolType.LABEL) {
                                    labelExists = true;
                                    break;
                                }
                            }

                            if (labelExists) {
                                skipCount.incrementAndGet();
                                continue;
                            }

                            Symbol newSymbol = symbolTable.createLabel(address, labelName, SourceType.USER_DEFINED);
                            if (newSymbol != null) {
                                successCount.incrementAndGet();
                                // Validate label naming convention
                                List<String> lw = NamingConventions.validateLabelName(labelName);
                                if (!lw.isEmpty()) errors.addAll(lw);  // Surface as errors for visibility
                            } else {
                                errors.add("Failed to create label '" + labelName + "' at " + addressStr);
                                errorCount.incrementAndGet();
                            }

                        } catch (Exception e) {
                            errors.add("Error at " + addressStr + ": " + e.getMessage());
                            errorCount.incrementAndGet();
                            Msg.error(this, "Error creating label at " + addressStr, e);
                        }
                    }

                } catch (Exception e) {
                    errors.add("Transaction error: " + e.getMessage());
                    Msg.error(this, "Error in batch create labels transaction", e);
                } finally {
                    program.endTransaction(tx, successCount.get() > 0);
                }
            });
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }

        Map<String, Object> result = JsonHelper.mapOf(
                "success", true,
                "labels_created", successCount.get(),
                "labels_skipped", skipCount.get(),
                "labels_failed", errorCount.get()
        );
        if (!errors.isEmpty()) {
            result.put("errors", errors);
        }
        return Response.ok(result);
    }

    public Response renameOrLabel(String addressStr, String newName) {
        return renameOrLabel(addressStr, newName, null);
    }

    @McpTool(path = "/rename_or_label", method = "POST", description = "Rename or create label at address. On programs with multiple address spaces (e.g., embedded targets), prefix addresses with the space name (mem:1000) to avoid ambiguous resolution.", category = "symbol")
    public Response renameOrLabel(
            @Param(value = "address", paramType = "address", source = ParamSource.BODY,
                   description = "Address in the program. Accepts 0x<hex> (default space) or <space>:<hex> "
                               + "(e.g., mem:1000, code:ff00). Note: some programs — particularly "
                               + "embedded/microcontroller targets — are not address-space-agnostic; "
                               + "use get_address_spaces to discover spaces before assuming a plain hex "
                               + "address is unambiguous.") String addressStr,
            @Param(value = "name", source = ParamSource.BODY) String newName,
            @Param(value = "program", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        if (addressStr == null || addressStr.isEmpty()) {
            return Response.err("Address is required");
        }
        if (newName == null || newName.isEmpty()) {
            return Response.err("Name is required");
        }

        try {
            Address address = ServiceUtils.parseAddress(program, addressStr);
            if (address == null) {
                return Response.err(ServiceUtils.getLastParseError());
            }

            Listing listing = program.getListing();
            Data data = listing.getDefinedDataAt(address);

            List<String> conventions;
            if (data != null) {
                // This is defined data (global variable) — validate g_ prefix
                conventions = NamingConventions.validateGlobalName(newName);
                Response result = renameDataAtAddress(addressStr, newName, programName);
                if (!conventions.isEmpty() && result instanceof Response.Ok okResp) {
                    @SuppressWarnings("unchecked")
                    java.util.Map<String, Object> okData = okResp.data() instanceof java.util.Map
                            ? (java.util.Map<String, Object>) okResp.data() : new java.util.LinkedHashMap<>();
                    okData.put("warnings", conventions);
                    return Response.ok(okData);
                }
                return result;
            } else {
                // This is a label (code address) — validate snake_case
                conventions = NamingConventions.validateLabelName(newName);
                Response result = createLabel(addressStr, newName, programName);
                if (!conventions.isEmpty() && result instanceof Response.Ok okResp) {
                    @SuppressWarnings("unchecked")
                    java.util.Map<String, Object> okData = okResp.data() instanceof java.util.Map
                            ? (java.util.Map<String, Object>) okResp.data() : new java.util.LinkedHashMap<>();
                    okData.put("warnings", conventions);
                    return Response.ok(okData);
                }
                return result;
            }

        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    public Response deleteLabel(String addressStr, String labelName) {
        return deleteLabel(addressStr, labelName, null);
    }

    @McpTool(path = "/delete_label", method = "POST", description = "Delete a label at address. On programs with multiple address spaces (e.g., embedded targets), prefix addresses with the space name (mem:1000) to avoid ambiguous resolution.", category = "symbol")
    public Response deleteLabel(
            @Param(value = "address", paramType = "address", source = ParamSource.BODY,
                   description = "Address in the program. Accepts 0x<hex> (default space) or <space>:<hex> "
                               + "(e.g., mem:1000, code:ff00). Note: some programs — particularly "
                               + "embedded/microcontroller targets — are not address-space-agnostic; "
                               + "use get_address_spaces to discover spaces before assuming a plain hex "
                               + "address is unambiguous.") String addressStr,
            @Param(value = "name", source = ParamSource.BODY) String labelName,
            @Param(value = "program", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        if (addressStr == null || addressStr.isEmpty()) {
            return Response.err("Address is required");
        }

        try {
            Address address = ServiceUtils.parseAddress(program, addressStr);
            if (address == null) {
                return Response.err(ServiceUtils.getLastParseError());
            }

            SymbolTable symbolTable = program.getSymbolTable();
            Symbol[] symbols = symbolTable.getSymbols(address);

            if (symbols == null || symbols.length == 0) {
                return Response.ok(JsonHelper.mapOf("success", false, "message",
                        "No symbols found at address " + addressStr));
            }

            final AtomicInteger deletedCount = new AtomicInteger(0);
            final List<String> deletedNames = new ArrayList<>();
            final List<String> errors = new ArrayList<>();

            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Delete Label");
                try {
                    for (Symbol symbol : symbols) {
                        if (symbol.getSymbolType() != SymbolType.LABEL) {
                            continue;
                        }
                        if (labelName != null && !labelName.isEmpty()) {
                            if (!symbol.getName().equals(labelName)) {
                                continue;
                            }
                        }

                        String name = symbol.getName();
                        boolean deleted = symbol.delete();
                        if (deleted) {
                            deletedCount.incrementAndGet();
                            deletedNames.add(name);
                        } else {
                            errors.add("Failed to delete label: " + name);
                        }
                    }
                } catch (Exception e) {
                    errors.add("Error during deletion: " + e.getMessage());
                } finally {
                    program.endTransaction(tx, deletedCount.get() > 0);
                }
            });

            Map<String, Object> result = JsonHelper.mapOf(
                    "success", deletedCount.get() > 0,
                    "deleted_count", deletedCount.get(),
                    "deleted_names", deletedNames
            );
            if (!errors.isEmpty()) {
                result.put("errors", errors);
            }
            return Response.ok(result);

        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    public Response batchDeleteLabels(List<Map<String, String>> labels) {
        return batchDeleteLabels(labels, null);
    }

    @McpTool(path = "/batch_delete_labels", method = "POST", description = "Delete multiple labels at once", category = "symbol")
    public Response batchDeleteLabels(
            @Param(value = "labels", source = ParamSource.BODY) List<Map<String, String>> labels,
            @Param(value = "program", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        if (labels == null || labels.isEmpty()) {
            return Response.err("No labels provided");
        }

        final AtomicInteger deletedCount = new AtomicInteger(0);
        final AtomicInteger skippedCount = new AtomicInteger(0);
        final AtomicInteger errorCount = new AtomicInteger(0);
        final List<String> errors = new ArrayList<>();

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Batch Delete Labels");
                try {
                    SymbolTable symbolTable = program.getSymbolTable();

                    for (Map<String, String> labelEntry : labels) {
                        String addressStr = labelEntry.get("address");
                        String labelNameEntry = labelEntry.get("name");

                        if (addressStr == null || addressStr.isEmpty()) {
                            errors.add("Missing address in label entry");
                            errorCount.incrementAndGet();
                            continue;
                        }

                        try {
                            Address address = ServiceUtils.parseAddress(program, addressStr);
                            if (address == null) {
                                errors.add(ServiceUtils.getLastParseError());
                                errorCount.incrementAndGet();
                                continue;
                            }

                            Symbol[] symbols = symbolTable.getSymbols(address);
                            if (symbols == null || symbols.length == 0) {
                                skippedCount.incrementAndGet();
                                continue;
                            }

                            for (Symbol symbol : symbols) {
                                if (symbol.getSymbolType() != SymbolType.LABEL) {
                                    continue;
                                }
                                if (labelNameEntry != null && !labelNameEntry.isEmpty()) {
                                    if (!symbol.getName().equals(labelNameEntry)) {
                                        continue;
                                    }
                                }

                                boolean deleted = symbol.delete();
                                if (deleted) {
                                    deletedCount.incrementAndGet();
                                } else {
                                    errors.add("Failed to delete at " + addressStr);
                                    errorCount.incrementAndGet();
                                }
                            }
                        } catch (Exception e) {
                            errors.add("Error at " + addressStr + ": " + e.getMessage());
                            errorCount.incrementAndGet();
                        }
                    }
                } catch (Exception e) {
                    errors.add("Transaction error: " + e.getMessage());
                } finally {
                    program.endTransaction(tx, deletedCount.get() > 0);
                }
            });
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }

        Map<String, Object> result = JsonHelper.mapOf(
                "success", true,
                "labels_deleted", deletedCount.get(),
                "labels_skipped", skippedCount.get(),
                "errors_count", errorCount.get()
        );
        if (!errors.isEmpty()) {
            result.put("errors", errors.subList(0, Math.min(errors.size(), 10)));
        }
        return Response.ok(result);
    }

    // -----------------------------------------------------------------------
    // Data Rename Methods
    // -----------------------------------------------------------------------

    public Response renameDataAtAddress(String addressStr, String newName) {
        return renameDataAtAddress(addressStr, newName, null);
    }

    @McpTool(path = "/rename_data", method = "POST", description = "Rename data at address. On programs with multiple address spaces (e.g., embedded targets), prefix addresses with the space name (mem:1000) to avoid ambiguous resolution.", category = "symbol")
    public Response renameDataAtAddress(
            @Param(value = "address", paramType = "address", source = ParamSource.BODY,
                   description = "Address in the program. Accepts 0x<hex> (default space) or <space>:<hex> "
                               + "(e.g., mem:1000, code:ff00). Note: some programs — particularly "
                               + "embedded/microcontroller targets — are not address-space-agnostic; "
                               + "use get_address_spaces to discover spaces before assuming a plain hex "
                               + "address is unambiguous.") String addressStr,
            @Param(value = "newName", source = ParamSource.BODY) String newName,
            @Param(value = "program", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        // Resolve address before entering SwingUtilities lambda
        Address addr = ServiceUtils.parseAddress(program, addressStr);
        if (addr == null) return Response.err(ServiceUtils.getLastParseError());

        final AtomicBoolean success = new AtomicBoolean(false);
        final AtomicReference<String> errorMsg = new AtomicReference<>();
        final AtomicReference<String> successMsg = new AtomicReference<>();

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Rename data");
                try {
                    Listing listing = program.getListing();
                    Data data = listing.getDefinedDataAt(addr);

                    if (data != null) {
                        SymbolTable symTable = program.getSymbolTable();
                        Symbol symbol = symTable.getPrimarySymbol(addr);
                        if (symbol != null) {
                            symbol.setName(newName, SourceType.USER_DEFINED);
                            successMsg.set("Renamed defined data at " + addressStr + " to '" + newName + "'");
                            success.set(true);
                        } else {
                            symTable.createLabel(addr, newName, SourceType.USER_DEFINED);
                            successMsg.set("Created label '" + newName + "' at " + addressStr);
                            success.set(true);
                        }
                    } else {
                        errorMsg.set("No defined data at address " + addressStr + ". Use create_label for undefined addresses.");
                    }
                } catch (Exception e) {
                    errorMsg.set(e.getMessage());
                    Msg.error(this, "Rename data error", e);
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (Exception e) {
            return Response.err("Failed to execute rename on Swing thread: " + e.getMessage());
        }

        if (success.get()) {
            return Response.ok(JsonHelper.mapOf("status", "success", "message", successMsg.get()));
        }
        return Response.err(errorMsg.get() != null ? errorMsg.get() : "Unknown failure");
    }

    public Response renameGlobalVariable(String oldName, String newName) {
        return renameGlobalVariable(oldName, newName, null);
    }

    @McpTool(path = "/rename_global_variable", method = "POST", description = "Rename a global variable", category = "symbol")
    public Response renameGlobalVariable(
            @Param(value = "old_name", source = ParamSource.BODY) String oldName,
            @Param(value = "new_name", source = ParamSource.BODY) String newName,
            @Param(value = "program", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        if (oldName == null || oldName.isEmpty()) {
            return Response.err("Old variable name is required");
        }
        if (newName == null || newName.isEmpty()) {
            return Response.err("New variable name is required");
        }

        int txId = program.startTransaction("Rename Global Variable");
        boolean success = false;
        try {
            SymbolTable symbolTable = program.getSymbolTable();

            Namespace globalNamespace = program.getGlobalNamespace();
            List<Symbol> symbols = symbolTable.getSymbols(oldName, globalNamespace);

            if (symbols.isEmpty()) {
                SymbolIterator allSymbols = symbolTable.getSymbols(oldName);
                while (allSymbols.hasNext()) {
                    Symbol symbol = allSymbols.next();
                    if (symbol.getSymbolType() != SymbolType.FUNCTION) {
                        symbols.add(symbol);
                        break;
                    }
                }
            }

            if (symbols.isEmpty()) {
                return Response.err("Global variable '" + oldName + "' not found");
            }

            Symbol symbol = symbols.get(0);
            Address symbolAddr = symbol.getAddress();
            symbol.setName(newName, SourceType.USER_DEFINED);

            success = true;
            List<String> globalWarnings = NamingConventions.validateGlobalName(newName);
            if (globalWarnings.isEmpty()) {
                return Response.ok(JsonHelper.mapOf("status", "success", "message",
                        "Renamed global variable '" + oldName + "' to '" + newName + "' at " + symbolAddr));
            } else {
                return Response.ok(JsonHelper.mapOf("status", "success", "message",
                        "Renamed global variable '" + oldName + "' to '" + newName + "' at " + symbolAddr,
                        "warnings", globalWarnings));
            }

        } catch (Exception e) {
            Msg.error(this, "Error renaming global variable: " + e.getMessage());
            return Response.err(e.getMessage());
        } finally {
            program.endTransaction(txId, success);
        }
    }

    // -----------------------------------------------------------------------
    // External Location Methods
    // -----------------------------------------------------------------------

    public Response renameExternalLocation(String address, String newName) {
        return renameExternalLocation(address, newName, null);
    }

    @McpTool(path = "/rename_external_location", method = "POST", description = "Rename external location. On programs with multiple address spaces (e.g., embedded targets), prefix addresses with the space name (mem:1000) to avoid ambiguous resolution.", category = "symbol")
    public Response renameExternalLocation(
            @Param(value = "address", paramType = "address", source = ParamSource.BODY,
                   description = "Address in the program. Accepts 0x<hex> (default space) or <space>:<hex> "
                               + "(e.g., mem:1000, code:ff00). Note: some programs — particularly "
                               + "embedded/microcontroller targets — are not address-space-agnostic; "
                               + "use get_address_spaces to discover spaces before assuming a plain hex "
                               + "address is unambiguous.") String address,
            @Param(value = "new_name", source = ParamSource.BODY) String newName,
            @Param(value = "program", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        try {
            Address addr = ServiceUtils.parseAddress(program, address);
            if (addr == null) return Response.err(ServiceUtils.getLastParseError());
            ExternalManager extMgr = program.getExternalManager();

            String[] libNames = extMgr.getExternalLibraryNames();
            for (String libName : libNames) {
                ExternalLocationIterator iter = extMgr.getExternalLocations(libName);
                while (iter.hasNext()) {
                    ExternalLocation extLoc = iter.next();
                    if (extLoc.getAddress().equals(addr)) {
                        final String finalLibName = libName;
                        final ExternalLocation finalExtLoc = extLoc;
                        final String oldName = extLoc.getLabel();

                        AtomicBoolean success = new AtomicBoolean(false);
                        AtomicReference<String> errorMsg = new AtomicReference<>();

                        try {
                            SwingUtilities.invokeAndWait(() -> {
                                int tx = program.startTransaction("Rename external location");
                                try {
                                    Namespace extLibNamespace = extMgr.getExternalLibrary(finalLibName);
                                    finalExtLoc.setName(extLibNamespace, newName, SourceType.USER_DEFINED);
                                    success.set(true);
                                    Msg.info(this, "Renamed external location: " + oldName + " -> " + newName);
                                } catch (Exception e) {
                                    errorMsg.set(e.getMessage());
                                    Msg.error(this, "Error renaming external location: " + e.getMessage());
                                } finally {
                                    program.endTransaction(tx, success.get());
                                }
                            });
                        } catch (Exception e) {
                            errorMsg.set(e.getMessage());
                        }

                        if (success.get()) {
                            return Response.ok(JsonHelper.mapOf(
                                    "success", true,
                                    "old_name", oldName,
                                    "new_name", newName,
                                    "dll", finalLibName
                            ));
                        } else {
                            return Response.err(errorMsg.get() != null ? errorMsg.get() : "Unknown error");
                        }
                    }
                }
            }

            return Response.err("External location not found at address " + address);
        } catch (Exception e) {
            Msg.error(this, "Exception in renameExternalLocation: " + e.getMessage());
            return Response.err(e.getMessage());
        }
    }

    // -----------------------------------------------------------------------
    // Address Inspection Methods
    // -----------------------------------------------------------------------

    public Response canRenameAtAddress(String addressStr) {
        return canRenameAtAddress(addressStr, null);
    }

    @McpTool(path = "/can_rename_at_address", description = "Check if address supports rename. On programs with multiple address spaces (e.g., embedded targets), prefix addresses with the space name (mem:1000) to avoid ambiguous resolution.", category = "symbol")
    public Response canRenameAtAddress(
            @Param(value = "address", paramType = "address",
                   description = "Address in the program. Accepts 0x<hex> (default space) or <space>:<hex> "
                               + "(e.g., mem:1000, code:ff00). Note: some programs — particularly "
                               + "embedded/microcontroller targets — are not address-space-agnostic; "
                               + "use get_address_spaces to discover spaces before assuming a plain hex "
                               + "address is unambiguous.") String addressStr,
            @Param(value = "program", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        // Resolve address before entering SwingUtilities lambda
        Address addr = ServiceUtils.parseAddress(program, addressStr);
        if (addr == null) return Response.err(ServiceUtils.getLastParseError());

        final AtomicReference<Map<String, Object>> resultData = new AtomicReference<>();
        final AtomicReference<String> errorMsg = new AtomicReference<>();

        try {
            SwingUtilities.invokeAndWait(() -> {
                try {
                    Function func = program.getFunctionManager().getFunctionAt(addr);
                    if (func != null) {
                        resultData.set(JsonHelper.mapOf(
                                "can_rename", true,
                                "type", "function",
                                "suggested_operation", "rename_function",
                                "current_name", func.getName()
                        ));
                        return;
                    }

                    Data data = program.getListing().getDefinedDataAt(addr);
                    if (data != null) {
                        Map<String, Object> map = JsonHelper.mapOf(
                                "can_rename", true,
                                "type", "defined_data",
                                "suggested_operation", "rename_data"
                        );
                        Symbol symbol = program.getSymbolTable().getPrimarySymbol(addr);
                        if (symbol != null) {
                            map.put("current_name", symbol.getName());
                        }
                        resultData.set(map);
                        return;
                    }

                    resultData.set(JsonHelper.mapOf(
                            "can_rename", true,
                            "type", "undefined",
                            "suggested_operation", "create_label"
                    ));
                } catch (Exception e) {
                    errorMsg.set(e.getMessage());
                }
            });

            if (errorMsg.get() != null) {
                return Response.err(errorMsg.get());
            }
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }

        return Response.ok(resultData.get());
    }
}
