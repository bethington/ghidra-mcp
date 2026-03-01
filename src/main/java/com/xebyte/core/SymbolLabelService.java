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

    // ========================================================================
    // Program resolution helper
    // ========================================================================

    private Object[] getProgramOrError(String programName) {
        Program program = null;
        if (programName != null && !programName.isEmpty()) {
            program = programProvider.resolveProgram(programName);
        } else {
            program = programProvider.getCurrentProgram();
        }
        if (program == null) {
            String available = "";
            Program[] all = programProvider.getAllOpenPrograms();
            if (all != null && all.length > 0) {
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < all.length; i++) {
                    if (i > 0) sb.append(", ");
                    sb.append(all[i].getName());
                }
                available = " Available programs: " + sb;
            }
            String error = programName != null && !programName.isEmpty()
                    ? ServiceUtils.programNotFoundError(programName) + available
                    : "No program loaded." + available;
            return new Object[]{null, error};
        }
        return new Object[]{program, null};
    }

    // -----------------------------------------------------------------------
    // Label Methods
    // -----------------------------------------------------------------------

    /**
     * List all labels within a function's address range.
     */
    public String getFunctionLabels(String functionName, int offset, int limit) {
        return getFunctionLabels(functionName, offset, limit, null);
    }

    public String getFunctionLabels(String functionName, int offset, int limit, String programName) {
        Object[] programResult = getProgramOrError(programName);
        Program program = (Program) programResult[0];
        if (program == null) {
            return (String) programResult[1];
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
            return "Function not found: " + functionName;
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
            return "No labels found in function: " + functionName;
        }

        return sb.toString();
    }

    /**
     * Rename a label at the specified address.
     */
    public String renameLabel(String addressStr, String oldName, String newName) {
        return renameLabel(addressStr, oldName, newName, null);
    }

    public String renameLabel(String addressStr, String oldName, String newName, String programName) {
        Object[] programResult = getProgramOrError(programName);
        Program program = (Program) programResult[0];
        if (program == null) {
            return (String) programResult[1];
        }

        try {
            Address address = program.getAddressFactory().getAddress(addressStr);
            if (address == null) {
                return "Invalid address: " + addressStr;
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
                return "Label not found: " + oldName + " at address " + addressStr;
            }

            // Check if new name already exists at this address
            for (Symbol symbol : symbols) {
                if (symbol.getName().equals(newName) && symbol.getSymbolType() == SymbolType.LABEL) {
                    return "Label with name '" + newName + "' already exists at address " + addressStr;
                }
            }

            // Perform the rename
            int transactionId = program.startTransaction("Rename Label");
            try {
                targetSymbol.setName(newName, SourceType.USER_DEFINED);
                return "Successfully renamed label from '" + oldName + "' to '" + newName + "' at address " + addressStr;
            } catch (Exception e) {
                return "Error renaming label: " + e.getMessage();
            } finally {
                program.endTransaction(transactionId, true);
            }

        } catch (Exception e) {
            return "Error processing request: " + e.getMessage();
        }
    }

    /**
     * Create a new label at the specified address.
     */
    public String createLabel(String addressStr, String labelName) {
        return createLabel(addressStr, labelName, null);
    }

    public String createLabel(String addressStr, String labelName, String programName) {
        Object[] programResult = getProgramOrError(programName);
        Program program = (Program) programResult[0];
        if (program == null) {
            return (String) programResult[1];
        }

        if (addressStr == null || addressStr.isEmpty()) {
            return "Address is required";
        }

        if (labelName == null || labelName.isEmpty()) {
            return "Label name is required";
        }

        try {
            Address address = program.getAddressFactory().getAddress(addressStr);
            if (address == null) {
                return "Invalid address: " + addressStr;
            }

            SymbolTable symbolTable = program.getSymbolTable();

            // Check if a label with this name already exists at this address
            Symbol[] existingSymbols = symbolTable.getSymbols(address);
            for (Symbol symbol : existingSymbols) {
                if (symbol.getName().equals(labelName) && symbol.getSymbolType() == SymbolType.LABEL) {
                    return "Label '" + labelName + "' already exists at address " + addressStr;
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
                    return "Successfully created label '" + labelName + "' at address " + addressStr;
                } else {
                    return "Failed to create label '" + labelName + "' at address " + addressStr;
                }
            } catch (Exception e) {
                return "Error creating label: " + e.getMessage();
            } finally {
                program.endTransaction(transactionId, true);
            }

        } catch (Exception e) {
            return "Error processing request: " + e.getMessage();
        }
    }

    /**
     * Batch create multiple labels in a single transaction.
     */
    public String batchCreateLabels(List<Map<String, String>> labels) {
        return batchCreateLabels(labels, null);
    }

    public String batchCreateLabels(List<Map<String, String>> labels, String programName) {
        Object[] programResult = getProgramOrError(programName);
        Program program = (Program) programResult[0];
        if (program == null) {
            return (String) programResult[1];
        }

        if (labels == null || labels.isEmpty()) {
            return "{\"error\": \"No labels provided\"}";
        }

        final StringBuilder result = new StringBuilder();
        result.append("{");
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

            result.append("\"success\": true, ");
            result.append("\"labels_created\": ").append(successCount.get()).append(", ");
            result.append("\"labels_skipped\": ").append(skipCount.get()).append(", ");
            result.append("\"labels_failed\": ").append(errorCount.get());

            if (!errors.isEmpty()) {
                result.append(", \"errors\": [");
                for (int i = 0; i < errors.size(); i++) {
                    if (i > 0) result.append(", ");
                    result.append("\"").append(errors.get(i).replace("\"", "\\\"")).append("\"");
                }
                result.append("]");
            }

        } catch (Exception e) {
            result.append("\"error\": \"").append(e.getMessage().replace("\"", "\\\"")).append("\"");
        }

        result.append("}");
        return result.toString();
    }

    /**
     * Intelligently rename data or create label based on whether data is defined.
     */
    public String renameOrLabel(String addressStr, String newName) {
        return renameOrLabel(addressStr, newName, null);
    }

    public String renameOrLabel(String addressStr, String newName, String programName) {
        Object[] programResult = getProgramOrError(programName);
        Program program = (Program) programResult[0];
        if (program == null) {
            return (String) programResult[1];
        }

        if (addressStr == null || addressStr.isEmpty()) {
            return "Error: Address is required";
        }

        if (newName == null || newName.isEmpty()) {
            return "Error: Name is required";
        }

        try {
            Address address = program.getAddressFactory().getAddress(addressStr);
            if (address == null) {
                return "Error: Invalid address: " + addressStr;
            }

            Listing listing = program.getListing();
            Data data = listing.getDefinedDataAt(address);

            if (data != null) {
                // Defined data exists - use rename_data logic
                return renameDataAtAddress(addressStr, newName, programName);
            } else {
                // No defined data - use create_label logic
                return createLabel(addressStr, newName, programName);
            }

        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    /**
     * Delete a label at the specified address.
     */
    public String deleteLabel(String addressStr, String labelName) {
        return deleteLabel(addressStr, labelName, null);
    }

    public String deleteLabel(String addressStr, String labelName, String programName) {
        Object[] programResult = getProgramOrError(programName);
        Program program = (Program) programResult[0];
        if (program == null) {
            return (String) programResult[1];
        }

        if (addressStr == null || addressStr.isEmpty()) {
            return "{\"error\": \"Address is required\"}";
        }

        try {
            Address address = program.getAddressFactory().getAddress(addressStr);
            if (address == null) {
                return "{\"error\": \"Invalid address: " + addressStr + "\"}";
            }

            SymbolTable symbolTable = program.getSymbolTable();
            Symbol[] symbols = symbolTable.getSymbols(address);

            if (symbols == null || symbols.length == 0) {
                return "{\"success\": false, \"message\": \"No symbols found at address " + addressStr + "\"}";
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

            StringBuilder resultBuilder = new StringBuilder();
            resultBuilder.append("{\"success\": ").append(deletedCount.get() > 0);
            resultBuilder.append(", \"deleted_count\": ").append(deletedCount.get());
            resultBuilder.append(", \"deleted_names\": [");
            for (int i = 0; i < deletedNames.size(); i++) {
                if (i > 0) resultBuilder.append(", ");
                resultBuilder.append("\"").append(deletedNames.get(i).replace("\"", "\\\"")).append("\"");
            }
            resultBuilder.append("]");
            if (!errors.isEmpty()) {
                resultBuilder.append(", \"errors\": [");
                for (int i = 0; i < errors.size(); i++) {
                    if (i > 0) resultBuilder.append(", ");
                    resultBuilder.append("\"").append(errors.get(i).replace("\"", "\\\"")).append("\"");
                }
                resultBuilder.append("]");
            }
            resultBuilder.append("}");
            return resultBuilder.toString();

        } catch (Exception e) {
            return "{\"error\": \"" + e.getMessage().replace("\"", "\\\"") + "\"}";
        }
    }

    /**
     * Batch delete multiple labels in a single transaction.
     */
    public String batchDeleteLabels(List<Map<String, String>> labels) {
        return batchDeleteLabels(labels, null);
    }

    public String batchDeleteLabels(List<Map<String, String>> labels, String programName) {
        Object[] programResult = getProgramOrError(programName);
        Program program = (Program) programResult[0];
        if (program == null) {
            return (String) programResult[1];
        }

        if (labels == null || labels.isEmpty()) {
            return "{\"error\": \"No labels provided\"}";
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

            StringBuilder result = new StringBuilder();
            result.append("{\"success\": true");
            result.append(", \"labels_deleted\": ").append(deletedCount.get());
            result.append(", \"labels_skipped\": ").append(skippedCount.get());
            result.append(", \"errors_count\": ").append(errorCount.get());
            if (!errors.isEmpty()) {
                result.append(", \"errors\": [");
                for (int i = 0; i < Math.min(errors.size(), 10); i++) {  // Limit to first 10 errors
                    if (i > 0) result.append(", ");
                    result.append("\"").append(errors.get(i).replace("\"", "\\\"")).append("\"");
                }
                result.append("]");
            }
            result.append("}");
            return result.toString();

        } catch (Exception e) {
            return "{\"error\": \"" + e.getMessage().replace("\"", "\\\"") + "\"}";
        }
    }

    // -----------------------------------------------------------------------
    // Data Rename Methods
    // -----------------------------------------------------------------------

    /**
     * Rename defined data symbols at an address.
     */
    public String renameDataAtAddress(String addressStr, String newName) {
        return renameDataAtAddress(addressStr, newName, null);
    }

    public String renameDataAtAddress(String addressStr, String newName, String programName) {
        Object[] programResult = getProgramOrError(programName);
        Program program = (Program) programResult[0];
        if (program == null) {
            return (String) programResult[1];
        }

        final StringBuilder resultMsg = new StringBuilder();

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Rename data");
                boolean success = false;
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    if (addr == null) {
                        resultMsg.append("Error: Invalid address: ").append(addressStr);
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
                            resultMsg.append("Success: Renamed defined data at ").append(addressStr)
                                    .append(" to '").append(newName).append("'");
                            success = true;
                        } else {
                            symTable.createLabel(addr, newName, SourceType.USER_DEFINED);
                            resultMsg.append("Success: Created label '").append(newName)
                                    .append("' at ").append(addressStr);
                            success = true;
                        }
                    } else {
                        // No defined data at this address
                        resultMsg.append("Error: No defined data at address ").append(addressStr)
                                .append(". Use create_label for undefined addresses.");
                    }
                }
                catch (Exception e) {
                    resultMsg.append("Error: ").append(e.getMessage());
                    Msg.error(this, "Rename data error", e);
                }
                finally {
                    program.endTransaction(tx, success);
                }
            });
        }
        catch (InterruptedException | InvocationTargetException e) {
            resultMsg.append("Error: Failed to execute rename on Swing thread: ").append(e.getMessage());
            Msg.error(this, "Failed to execute rename data on Swing thread", e);
        }

        return resultMsg.length() > 0 ? resultMsg.toString() : "Error: Unknown failure";
    }

    /**
     * Rename a global variable/symbol.
     */
    public String renameGlobalVariable(String oldName, String newName) {
        return renameGlobalVariable(oldName, newName, null);
    }

    public String renameGlobalVariable(String oldName, String newName, String programName) {
        Object[] programResult = getProgramOrError(programName);
        Program program = (Program) programResult[0];
        if (program == null) {
            return (String) programResult[1];
        }

        if (oldName == null || oldName.isEmpty()) {
            return "Error: Old variable name is required";
        }

        if (newName == null || newName.isEmpty()) {
            return "Error: New variable name is required";
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
                return "Error: Global variable '" + oldName + "' not found";
            }

            // Rename the first matching symbol
            Symbol symbol = symbols.get(0);
            Address symbolAddr = symbol.getAddress();
            symbol.setName(newName, SourceType.USER_DEFINED);

            program.endTransaction(txId, true);
            return "Success: Renamed global variable '" + oldName + "' to '" + newName +
                   "' at " + symbolAddr;

        } catch (Exception e) {
            program.endTransaction(txId, false);
            Msg.error(this, "Error renaming global variable: " + e.getMessage());
            return "Error: " + e.getMessage();
        }
    }

    // -----------------------------------------------------------------------
    // External Location Methods
    // -----------------------------------------------------------------------

    /**
     * Rename an external location (e.g., change Ordinal_123 to a real function name).
     * Uses SwingUtilities.invokeAndWait + transaction for thread safety.
     */
    public String renameExternalLocation(String address, String newName) {
        return renameExternalLocation(address, newName, null);
    }

    public String renameExternalLocation(String address, String newName, String programName) {
        Object[] programResult = getProgramOrError(programName);
        Program program = (Program) programResult[0];
        if (program == null) {
            return (String) programResult[1];
        }

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
                            return "{\"success\": true, \"old_name\": \"" + ServiceUtils.escapeJson(oldName) +
                                   "\", \"new_name\": \"" + ServiceUtils.escapeJson(newName) +
                                   "\", \"dll\": \"" + finalLibName + "\"}";
                        } else {
                            return "{\"error\": \"" + (errorMsg.get() != null ? errorMsg.get().replace("\"", "\\\"") : "Unknown error") + "\"}";
                        }
                    }
                }
            }

            return "{\"error\": \"External location not found at address " + address + "\"}";
        } catch (Exception e) {
            Msg.error(this, "Exception in renameExternalLocation: " + e.getMessage());
            return "{\"error\": \"" + e.getMessage().replace("\"", "\\\"") + "\"}";
        }
    }

    // -----------------------------------------------------------------------
    // Address Inspection Methods
    // -----------------------------------------------------------------------

    /**
     * Determine if address has data/code and suggest the appropriate rename operation.
     * Read-only detection using SwingUtilities.invokeAndWait for thread safety.
     */
    public String canRenameAtAddress(String addressStr) {
        return canRenameAtAddress(addressStr, null);
    }

    public String canRenameAtAddress(String addressStr, String programName) {
        Object[] programResult = getProgramOrError(programName);
        Program program = (Program) programResult[0];
        if (program == null) {
            return (String) programResult[1];
        }

        final StringBuilder result = new StringBuilder();
        final AtomicReference<String> errorMsg = new AtomicReference<>(null);

        try {
            SwingUtilities.invokeAndWait(() -> {
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    if (addr == null) {
                        result.append("{\"can_rename\": false, \"error\": \"Invalid address\"}");
                        return;
                    }

                    result.append("{\"can_rename\": true");

                    // Check if it's a function
                    Function func = program.getFunctionManager().getFunctionAt(addr);
                    if (func != null) {
                        result.append(", \"type\": \"function\"");
                        result.append(", \"suggested_operation\": \"rename_function\"");
                        result.append(", \"current_name\": \"").append(func.getName()).append("\"");
                        result.append("}");
                        return;
                    }

                    // Check if it's defined data
                    Data data = program.getListing().getDefinedDataAt(addr);
                    if (data != null) {
                        result.append(", \"type\": \"defined_data\"");
                        result.append(", \"suggested_operation\": \"rename_data\"");
                        Symbol symbol = program.getSymbolTable().getPrimarySymbol(addr);
                        if (symbol != null) {
                            result.append(", \"current_name\": \"").append(symbol.getName()).append("\"");
                        }
                        result.append("}");
                        return;
                    }

                    // Check if it's undefined (can create label)
                    result.append(", \"type\": \"undefined\"");
                    result.append(", \"suggested_operation\": \"create_label\"");
                    result.append("}");
                } catch (Exception e) {
                    errorMsg.set(e.getMessage());
                }
            });

            if (errorMsg.get() != null) {
                return "{\"error\": \"" + errorMsg.get().replace("\"", "\\\"") + "\"}";
            }
        } catch (Exception e) {
            return "{\"error\": \"" + e.getMessage().replace("\"", "\\\"") + "\"}";
        }

        return result.toString();
    }
}
