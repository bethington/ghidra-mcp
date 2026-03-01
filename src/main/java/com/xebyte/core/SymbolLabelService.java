package com.xebyte.core;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;

import javax.swing.SwingUtilities;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Service for symbol and label operations: create, rename, delete, batch operations.
 * Extracted from GhidraMCPPlugin as part of v4.0.0 refactor.
 */
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

    /**
     * List all labels within a function's address range.
     */
    public Response getFunctionLabels(String functionName, int offset, int limit) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) {
            return Response.err("No program loaded");
        }

        StringBuilder sb = new StringBuilder();
        SymbolTable symbolTable = program.getSymbolTable();
        FunctionManager functionManager = program.getFunctionManager();

        // Find the function by name
        Function function = null;
        for (Function f : functionManager.getFunctions(true)) {
            if (f.getName().equals(functionName)) {
                function = f;
                break;
            }
        }

        if (function == null) {
            return Response.err("Function not found: " + functionName);
        }

        AddressSetView functionBody = function.getBody();
        SymbolIterator symbols = symbolTable.getSymbolIterator();
        int count = 0;
        int skipped = 0;

        while (symbols.hasNext() && count < limit) {
            Symbol symbol = symbols.next();

            // Check if symbol is within the function's address range
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

    /**
     * Rename a label at the specified address.
     */
    public Response renameLabel(String addressStr, String oldName, String newName) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) {
            return Response.err("No program loaded");
        }

        try {
            Address address = program.getAddressFactory().getAddress(addressStr);
            if (address == null) {
                return Response.err("Invalid address: " + addressStr);
            }

            SymbolTable symbolTable = program.getSymbolTable();
            Symbol[] symbols = symbolTable.getSymbols(address);

            // Find the specific symbol with the old name
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

            // Check if new name already exists at this address
            for (Symbol symbol : symbols) {
                if (symbol.getName().equals(newName) && symbol.getSymbolType() == SymbolType.LABEL) {
                    return Response.err("Label with name '" + newName + "' already exists at address " + addressStr);
                }
            }

            // Perform the rename
            int transactionId = program.startTransaction("Rename Label");
            try {
                targetSymbol.setName(newName, SourceType.USER_DEFINED);
                return Response.text("Successfully renamed label from '" + oldName + "' to '" + newName + "' at address " + addressStr);
            } catch (Exception e) {
                return Response.err("Error renaming label: " + e.getMessage());
            } finally {
                program.endTransaction(transactionId, true);
            }

        } catch (Exception e) {
            return Response.err("Error processing request: " + e.getMessage());
        }
    }

    /**
     * Create a new label at the specified address.
     */
    public Response createLabel(String addressStr, String labelName) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) {
            return Response.err("No program loaded");
        }

        if (addressStr == null || addressStr.isEmpty()) {
            return Response.err("Address is required");
        }

        if (labelName == null || labelName.isEmpty()) {
            return Response.err("Label name is required");
        }

        try {
            Address address = program.getAddressFactory().getAddress(addressStr);
            if (address == null) {
                return Response.err("Invalid address: " + addressStr);
            }

            SymbolTable symbolTable = program.getSymbolTable();

            // Check if a label with this name already exists at this address
            Symbol[] existingSymbols = symbolTable.getSymbols(address);
            for (Symbol symbol : existingSymbols) {
                if (symbol.getName().equals(labelName) && symbol.getSymbolType() == SymbolType.LABEL) {
                    return Response.err("Label '" + labelName + "' already exists at address " + addressStr);
                }
            }

            // Check if the label name is already used elsewhere (optional warning)
            SymbolIterator existingLabels = symbolTable.getSymbolIterator(labelName, true);
            if (existingLabels.hasNext()) {
                Symbol existingSymbol = existingLabels.next();
                if (existingSymbol.getSymbolType() == SymbolType.LABEL) {
                    Msg.warn(this, "Label name '" + labelName + "' already exists at address " +
                            existingSymbol.getAddress() + ". Creating duplicate at " + addressStr);
                }
            }

            // Create the label
            int transactionId = program.startTransaction("Create Label");
            try {
                Symbol newSymbol = symbolTable.createLabel(address, labelName, SourceType.USER_DEFINED);
                if (newSymbol != null) {
                    return Response.text("Successfully created label '" + labelName + "' at address " + addressStr);
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

    /**
     * Batch create multiple labels in a single transaction.
     */
    public Response batchCreateLabels(List<Map<String, String>> labels) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) {
            return Response.err("No program loaded");
        }

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
                            Address address = program.getAddressFactory().getAddress(addressStr);
                            if (address == null) {
                                errors.add("Invalid address: " + addressStr);
                                errorCount.incrementAndGet();
                                continue;
                            }

                            // Check if label already exists
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

                            // Create the label
                            Symbol newSymbol = symbolTable.createLabel(address, labelName, SourceType.USER_DEFINED);
                            if (newSymbol != null) {
                                successCount.incrementAndGet();
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

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("success", true);
            result.put("labels_created", successCount.get());
            result.put("labels_skipped", skipCount.get());
            result.put("labels_failed", errorCount.get());
            if (!errors.isEmpty()) {
                result.put("errors", errors);
            }
            return Response.ok(result);

        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    /**
     * Intelligently rename data or create label based on whether data is defined.
     */
    public Response renameOrLabel(String addressStr, String newName) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) {
            return Response.err("No program loaded");
        }

        if (addressStr == null || addressStr.isEmpty()) {
            return Response.err("Address is required");
        }

        if (newName == null || newName.isEmpty()) {
            return Response.err("Name is required");
        }

        try {
            Address address = program.getAddressFactory().getAddress(addressStr);
            if (address == null) {
                return Response.err("Invalid address: " + addressStr);
            }

            Listing listing = program.getListing();
            Data data = listing.getDefinedDataAt(address);

            if (data != null) {
                // Defined data exists - use rename_data logic
                return renameDataAtAddress(addressStr, newName);
            } else {
                // No defined data - use create_label logic
                return createLabel(addressStr, newName);
            }

        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    /**
     * Delete a label at the specified address.
     */
    public Response deleteLabel(String addressStr, String labelName) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) {
            return Response.err("No program loaded");
        }

        if (addressStr == null || addressStr.isEmpty()) {
            return Response.err("Address is required");
        }

        try {
            Address address = program.getAddressFactory().getAddress(addressStr);
            if (address == null) {
                return Response.err("Invalid address: " + addressStr);
            }

            SymbolTable symbolTable = program.getSymbolTable();
            Symbol[] symbols = symbolTable.getSymbols(address);

            if (symbols == null || symbols.length == 0) {
                Map<String, Object> result = new LinkedHashMap<>();
                result.put("success", false);
                result.put("message", "No symbols found at address " + addressStr);
                return Response.ok(result);
            }

            final AtomicInteger deletedCount = new AtomicInteger(0);
            final List<String> deletedNames = new ArrayList<>();
            final List<String> errors = new ArrayList<>();

            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Delete Label");
                try {
                    for (Symbol symbol : symbols) {
                        // Only delete LABEL type symbols
                        if (symbol.getSymbolType() != SymbolType.LABEL) {
                            continue;
                        }

                        // If a specific name was given, only delete that one
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

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("success", deletedCount.get() > 0);
            result.put("deleted_count", deletedCount.get());
            result.put("deleted_names", deletedNames);
            if (!errors.isEmpty()) {
                result.put("errors", errors);
            }
            return Response.ok(result);

        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    /**
     * Batch delete multiple labels in a single transaction.
     */
    public Response batchDeleteLabels(List<Map<String, String>> labels) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) {
            return Response.err("No program loaded");
        }

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
                        String labelNameEntry = labelEntry.get("name");  // Optional

                        if (addressStr == null || addressStr.isEmpty()) {
                            errors.add("Missing address in label entry");
                            errorCount.incrementAndGet();
                            continue;
                        }

                        try {
                            Address address = program.getAddressFactory().getAddress(addressStr);
                            if (address == null) {
                                errors.add("Invalid address: " + addressStr);
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

                                // If a specific name was given, only delete that one
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

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("success", true);
            result.put("labels_deleted", deletedCount.get());
            result.put("labels_skipped", skippedCount.get());
            result.put("errors_count", errorCount.get());
            if (!errors.isEmpty()) {
                result.put("errors", errors.subList(0, Math.min(errors.size(), 10)));
            }
            return Response.ok(result);

        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    // -----------------------------------------------------------------------
    // Data Rename Methods
    // -----------------------------------------------------------------------

    /**
     * Rename defined data symbols at an address.
     */
    public Response renameDataAtAddress(String addressStr, String newName) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) {
            return Response.err("No program loaded");
        }

        final AtomicReference<Response> responseRef = new AtomicReference<>(Response.err("Unknown failure"));

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Rename data");
                boolean success = false;
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    if (addr == null) {
                        responseRef.set(Response.err("Invalid address: " + addressStr));
                        return;
                    }

                    Listing listing = program.getListing();
                    Data data = listing.getDefinedDataAt(addr);

                    if (data != null) {
                        // Data is defined - rename its symbol
                        SymbolTable symTable = program.getSymbolTable();
                        Symbol symbol = symTable.getPrimarySymbol(addr);
                        if (symbol != null) {
                            symbol.setName(newName, SourceType.USER_DEFINED);
                            responseRef.set(Response.text("Success: Renamed defined data at " + addressStr +
                                    " to '" + newName + "'"));
                            success = true;
                        } else {
                            symTable.createLabel(addr, newName, SourceType.USER_DEFINED);
                            responseRef.set(Response.text("Success: Created label '" + newName +
                                    "' at " + addressStr));
                            success = true;
                        }
                    } else {
                        // No defined data at this address
                        responseRef.set(Response.err("No defined data at address " + addressStr +
                                ". Use create_label for undefined addresses."));
                    }
                }
                catch (Exception e) {
                    responseRef.set(Response.err(e.getMessage()));
                    Msg.error(this, "Rename data error", e);
                }
                finally {
                    program.endTransaction(tx, success);
                }
            });
        }
        catch (InterruptedException | InvocationTargetException e) {
            responseRef.set(Response.err("Failed to execute rename on Swing thread: " + e.getMessage()));
            Msg.error(this, "Failed to execute rename data on Swing thread", e);
        }

        return responseRef.get();
    }

    /**
     * Rename a global variable/symbol.
     */
    public Response renameGlobalVariable(String oldName, String newName) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) {
            return Response.err("No program loaded");
        }

        if (oldName == null || oldName.isEmpty()) {
            return Response.err("Old variable name is required");
        }

        if (newName == null || newName.isEmpty()) {
            return Response.err("New variable name is required");
        }

        int txId = program.startTransaction("Rename Global Variable");
        try {
            SymbolTable symbolTable = program.getSymbolTable();

            // Find the symbol by name in global namespace
            Namespace globalNamespace = program.getGlobalNamespace();
            List<Symbol> symbols = symbolTable.getSymbols(oldName, globalNamespace);

            if (symbols.isEmpty()) {
                // Try finding in any namespace
                SymbolIterator allSymbols = symbolTable.getSymbols(oldName);
                while (allSymbols.hasNext()) {
                    Symbol symbol = allSymbols.next();
                    if (symbol.getSymbolType() != SymbolType.FUNCTION) {
                        symbols.add(symbol);
                        break; // Take the first non-function match
                    }
                }
            }

            if (symbols.isEmpty()) {
                program.endTransaction(txId, false);
                return Response.err("Global variable '" + oldName + "' not found");
            }

            // Rename the first matching symbol
            Symbol symbol = symbols.get(0);
            Address symbolAddr = symbol.getAddress();
            symbol.setName(newName, SourceType.USER_DEFINED);

            program.endTransaction(txId, true);
            return Response.text("Success: Renamed global variable '" + oldName + "' to '" + newName +
                   "' at " + symbolAddr);

        } catch (Exception e) {
            program.endTransaction(txId, false);
            Msg.error(this, "Error renaming global variable: " + e.getMessage());
            return Response.err(e.getMessage());
        }
    }

    // -----------------------------------------------------------------------
    // External Location Methods
    // -----------------------------------------------------------------------

    /**
     * Rename an external location (e.g., change Ordinal_123 to a real function name).
     * Uses SwingUtilities.invokeAndWait + transaction for thread safety.
     */
    public Response renameExternalLocation(String address, String newName) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) return Response.err("No program loaded");

        try {
            Address addr = program.getAddressFactory().getAddress(address);
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
                                    // Get the external library namespace for this external location
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
                        } catch (InterruptedException e) {
                            errorMsg.set("Interrupted: " + e.getMessage());
                        } catch (InvocationTargetException e) {
                            errorMsg.set(e.getCause() != null ? e.getCause().getMessage() : e.getMessage());
                        }

                        if (success.get()) {
                            Map<String, Object> result = new LinkedHashMap<>();
                            result.put("success", true);
                            result.put("old_name", oldName);
                            result.put("new_name", newName);
                            result.put("dll", finalLibName);
                            return Response.ok(result);
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

    /**
     * Determine if address has data/code and suggest the appropriate rename operation.
     * Read-only detection using SwingUtilities.invokeAndWait for thread safety.
     */
    public Response canRenameAtAddress(String addressStr) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) {
            return Response.err("No program loaded");
        }

        final AtomicReference<Response> responseRef = new AtomicReference<>();
        final AtomicReference<String> errorMsg = new AtomicReference<>(null);

        try {
            SwingUtilities.invokeAndWait(() -> {
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    if (addr == null) {
                        Map<String, Object> result = new LinkedHashMap<>();
                        result.put("can_rename", false);
                        result.put("error", "Invalid address");
                        responseRef.set(Response.ok(result));
                        return;
                    }

                    Map<String, Object> result = new LinkedHashMap<>();
                    result.put("can_rename", true);

                    // Check if it's a function
                    Function func = program.getFunctionManager().getFunctionAt(addr);
                    if (func != null) {
                        result.put("type", "function");
                        result.put("suggested_operation", "rename_function");
                        result.put("current_name", func.getName());
                        responseRef.set(Response.ok(result));
                        return;
                    }

                    // Check if it's defined data
                    Data data = program.getListing().getDefinedDataAt(addr);
                    if (data != null) {
                        result.put("type", "defined_data");
                        result.put("suggested_operation", "rename_data");
                        Symbol symbol = program.getSymbolTable().getPrimarySymbol(addr);
                        if (symbol != null) {
                            result.put("current_name", symbol.getName());
                        }
                        responseRef.set(Response.ok(result));
                        return;
                    }

                    // Check if it's undefined (can create label)
                    result.put("type", "undefined");
                    result.put("suggested_operation", "create_label");
                    responseRef.set(Response.ok(result));
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

        return responseRef.get();
    }
}
