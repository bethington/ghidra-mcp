package com.xebyte.core;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.util.Msg;

import javax.swing.SwingUtilities;
import java.lang.reflect.InvocationTargetException;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Service for comment operations: set/get/clear decompiler, disassembly, and plate comments.
 * Extracted from GhidraMCPPlugin as part of v4.0.0 refactor.
 */
public class CommentService {

    private final ProgramProvider programProvider;
    private final ThreadingStrategy threadingStrategy;

    public CommentService(ProgramProvider programProvider, ThreadingStrategy threadingStrategy) {
        this.programProvider = programProvider;
        this.threadingStrategy = threadingStrategy;
    }

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
    // Comment Methods
    // -----------------------------------------------------------------------

    /**
     * Set a comment using the specified comment type (PRE_COMMENT or EOL_COMMENT).
     */
    @SuppressWarnings("deprecation")
    public String setCommentAtAddress(String addressStr, String comment, int commentType, String transactionName) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) {
            return "Error: No program loaded";
        }

        if (addressStr == null || addressStr.isEmpty()) {
            return "Error: Address is required";
        }

        if (comment == null) {
            return "Error: Comment text is required";
        }

        final StringBuilder resultMsg = new StringBuilder();
        final AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction(transactionName);
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    if (addr == null) {
                        resultMsg.append("Error: Invalid address: ").append(addressStr);
                        return;
                    }

                    program.getListing().setComment(addr, commentType, comment);
                    success.set(true);
                    resultMsg.append("Success: Set comment at ").append(addressStr);
                } catch (Exception e) {
                    resultMsg.append("Error: ").append(e.getMessage());
                    Msg.error(this, "Error setting " + transactionName.toLowerCase(), e);
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (InterruptedException | InvocationTargetException e) {
            resultMsg.append("Error: Failed to execute on Swing thread: ").append(e.getMessage());
            Msg.error(this, "Failed to execute " + transactionName.toLowerCase() + " on Swing thread", e);
        }

        return resultMsg.length() > 0 ? resultMsg.toString() : "Error: Unknown failure";
    }

    /**
     * Set a comment for a given address in the function pseudocode (PRE_COMMENT).
     */
    @SuppressWarnings("deprecation")
    public String setDecompilerComment(String addressStr, String comment) {
        return setCommentAtAddress(addressStr, comment, CodeUnit.PRE_COMMENT, "Set decompiler comment");
    }

    /**
     * Set a comment for a given address in the function disassembly (EOL_COMMENT).
     */
    @SuppressWarnings("deprecation")
    public String setDisassemblyComment(String addressStr, String comment) {
        return setCommentAtAddress(addressStr, comment, CodeUnit.EOL_COMMENT, "Set disassembly comment");
    }

    /**
     * Get the plate (header) comment for a function.
     */
    public String getPlateComment(String address, String programName) {
        Object[] programResult = getProgramOrError(programName);
        Program program = (Program) programResult[0];
        if (program == null) return (String) programResult[1];

        if (address == null || address.isEmpty()) {
            return "{\"error\": \"address parameter is required\"}";
        }

        Address addr = program.getAddressFactory().getAddress(address);
        if (addr == null) {
            return "{\"error\": \"Invalid address: " + address + "\"}";
        }

        Function func = program.getFunctionManager().getFunctionAt(addr);
        if (func == null) {
            func = program.getFunctionManager().getFunctionContaining(addr);
        }
        if (func == null) {
            return "{\"error\": \"No function at address: " + address + "\"}";
        }

        String comment = func.getComment();
        StringBuilder json = new StringBuilder("{");
        json.append("\"address\": \"").append(func.getEntryPoint().toString()).append("\", ");
        json.append("\"function_name\": \"").append(ServiceUtils.escapeJson(func.getName())).append("\", ");
        json.append("\"comment\": ").append(comment != null ? "\"" + ServiceUtils.escapeJson(comment) + "\"" : "null");
        json.append("}");
        return json.toString();
    }

    /**
     * Set function plate (header) comment.
     */
    @SuppressWarnings("deprecation")
    public String setPlateComment(String functionAddress, String comment) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) {
            return "Error: No program loaded";
        }

        if (functionAddress == null || functionAddress.isEmpty()) {
            return "Error: Function address is required";
        }

        if (comment == null) {
            return "Error: Comment is required";
        }

        final StringBuilder resultMsg = new StringBuilder();
        final AtomicBoolean success = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Set Plate Comment");
                try {
                    Address addr = program.getAddressFactory().getAddress(functionAddress);
                    if (addr == null) {
                        resultMsg.append("Error: Invalid address: ").append(functionAddress);
                        return;
                    }

                    Function func = program.getFunctionManager().getFunctionAt(addr);
                    if (func == null) {
                        resultMsg.append("Error: No function at address: ").append(functionAddress);
                        return;
                    }

                    func.setComment(comment);
                    success.set(true);
                    resultMsg.append("Success: Set plate comment for function at ").append(functionAddress);
                } catch (Exception e) {
                    resultMsg.append("Error: ").append(e.getMessage());
                    Msg.error(this, "Error setting plate comment", e);
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });

            // Force event processing to ensure changes propagate to decompiler cache
            if (success.get()) {
                program.flushEvents();
                try {
                    Thread.sleep(500);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
        } catch (Exception e) {
            resultMsg.append("Error: Failed to execute on Swing thread: ").append(e.getMessage());
        }

        return resultMsg.length() > 0 ? resultMsg.toString() : "Error: Unknown failure";
    }

    /**
     * Batch set multiple comments (decompiler, disassembly, and plate) in a single operation.
     */
    @SuppressWarnings("deprecation")
    public String batchSetComments(String functionAddress, List<Map<String, String>> decompilerComments,
                                   List<Map<String, String>> disassemblyComments, String plateComment) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) {
            return "{\"error\": \"No program loaded\"}";
        }

        final StringBuilder result = new StringBuilder();
        result.append("{");
        final AtomicBoolean success = new AtomicBoolean(false);
        final AtomicReference<Integer> decompilerCount = new AtomicReference<>(0);
        final AtomicReference<Integer> disassemblyCount = new AtomicReference<>(0);
        final AtomicReference<Boolean> plateSet = new AtomicReference<>(false);
        final AtomicReference<Integer> overwrittenCount = new AtomicReference<>(0);

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Batch Set Comments");
                try {
                    // Set or clear plate comment (v3.0.1: null=skip, ""=clear, non-empty=set)
                    if (plateComment != null && !plateComment.equals("null") && functionAddress != null) {
                        Address funcAddr = program.getAddressFactory().getAddress(functionAddress);
                        if (funcAddr != null) {
                            Function func = program.getFunctionManager().getFunctionAt(funcAddr);
                            if (func != null) {
                                String existingPlate = func.getComment();
                                if (existingPlate != null && !existingPlate.isEmpty()) {
                                    overwrittenCount.getAndSet(overwrittenCount.get() + 1);
                                }
                                if (plateComment.isEmpty()) {
                                    func.setComment(null);  // Clear plate comment
                                } else {
                                    func.setComment(plateComment);
                                }
                                plateSet.set(true);
                            }
                        }
                    }

                    // Set decompiler comments (PRE_COMMENT)
                    Listing listing = program.getListing();
                    if (decompilerComments != null) {
                        for (Map<String, String> commentEntry : decompilerComments) {
                            String addr = commentEntry.get("address");
                            String cmt = commentEntry.get("comment");
                            if (addr != null && cmt != null) {
                                Address address = program.getAddressFactory().getAddress(addr);
                                if (address != null) {
                                    String existing = listing.getComment(CodeUnit.PRE_COMMENT, address);
                                    if (existing != null && !existing.isEmpty()) {
                                        overwrittenCount.getAndSet(overwrittenCount.get() + 1);
                                    }
                                    listing.setComment(address, CodeUnit.PRE_COMMENT,
                                            cmt.isEmpty() ? null : cmt);
                                    decompilerCount.getAndSet(decompilerCount.get() + 1);
                                }
                            }
                        }
                    }

                    // Set disassembly comments (EOL_COMMENT)
                    if (disassemblyComments != null) {
                        for (Map<String, String> commentEntry : disassemblyComments) {
                            String addr = commentEntry.get("address");
                            String cmt = commentEntry.get("comment");
                            if (addr != null && cmt != null) {
                                Address address = program.getAddressFactory().getAddress(addr);
                                if (address != null) {
                                    String existing = listing.getComment(CodeUnit.EOL_COMMENT, address);
                                    if (existing != null && !existing.isEmpty()) {
                                        overwrittenCount.getAndSet(overwrittenCount.get() + 1);
                                    }
                                    listing.setComment(address, CodeUnit.EOL_COMMENT,
                                            cmt.isEmpty() ? null : cmt);
                                    disassemblyCount.getAndSet(disassemblyCount.get() + 1);
                                }
                            }
                        }
                    }

                    success.set(true);
                } catch (Exception e) {
                    result.append("\"error\": \"").append(e.getMessage().replace("\"", "\\\"")).append("\"");
                    Msg.error(this, "Error in batch set comments", e);
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });

            // Force event processing to ensure changes propagate to decompiler cache
            if (success.get()) {
                program.flushEvents();
                try {
                    Thread.sleep(500);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }

            if (success.get()) {
                result.append("\"success\": true, ");
                result.append("\"decompiler_comments_set\": ").append(decompilerCount.get()).append(", ");
                result.append("\"disassembly_comments_set\": ").append(disassemblyCount.get()).append(", ");
                result.append("\"plate_comment_set\": ").append(plateSet.get()).append(", ");
                result.append("\"plate_comment_cleared\": ").append(plateSet.get() && plateComment != null && plateComment.isEmpty()).append(", ");
                result.append("\"comments_overwritten\": ").append(overwrittenCount.get());
            }
        } catch (Exception e) {
            result.append("\"error\": \"").append(e.getMessage().replace("\"", "\\\"")).append("\"");
        }

        result.append("}");
        return result.toString();
    }

    /**
     * Clear all comments (plate, PRE, EOL) within a function's address range.
     */
    @SuppressWarnings("deprecation")
    public String clearFunctionComments(String functionAddress, boolean clearPlate, boolean clearPre, boolean clearEol) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) {
            return "{\"error\": \"No program loaded\"}";
        }

        if (functionAddress == null || functionAddress.isEmpty()) {
            return "{\"error\": \"function_address parameter is required\"}";
        }

        final StringBuilder result = new StringBuilder();
        result.append("{");
        final AtomicBoolean success = new AtomicBoolean(false);
        final AtomicReference<Integer> preCleared = new AtomicReference<>(0);
        final AtomicReference<Integer> eolCleared = new AtomicReference<>(0);
        final AtomicReference<Boolean> plateCleared = new AtomicReference<>(false);

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Clear Function Comments");
                try {
                    Address addr = program.getAddressFactory().getAddress(functionAddress);
                    if (addr == null) {
                        result.append("\"error\": \"Invalid address: ").append(functionAddress).append("\"");
                        return;
                    }

                    Function func = program.getFunctionManager().getFunctionAt(addr);
                    if (func == null) {
                        result.append("\"error\": \"No function at address: ").append(functionAddress).append("\"");
                        return;
                    }

                    // Clear plate comment
                    if (clearPlate && func.getComment() != null) {
                        func.setComment(null);
                        plateCleared.set(true);
                    }

                    // Clear inline comments within the function body
                    Listing listing = program.getListing();
                    AddressSetView body = func.getBody();
                    InstructionIterator instrIter = listing.getInstructions(body, true);

                    while (instrIter.hasNext()) {
                        Instruction instr = instrIter.next();
                        Address instrAddr = instr.getAddress();

                        if (clearPre) {
                            String existing = listing.getComment(CodeUnit.PRE_COMMENT, instrAddr);
                            if (existing != null) {
                                listing.setComment(instrAddr, CodeUnit.PRE_COMMENT, null);
                                preCleared.getAndSet(preCleared.get() + 1);
                            }
                        }

                        if (clearEol) {
                            String existing = listing.getComment(CodeUnit.EOL_COMMENT, instrAddr);
                            if (existing != null) {
                                listing.setComment(instrAddr, CodeUnit.EOL_COMMENT, null);
                                eolCleared.getAndSet(eolCleared.get() + 1);
                            }
                        }
                    }

                    success.set(true);
                } catch (Exception e) {
                    result.append("\"error\": \"").append(e.getMessage().replace("\"", "\\\"")).append("\"");
                    Msg.error(this, "Error clearing function comments", e);
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });

            if (success.get()) {
                result.append("\"success\": true, ");
                result.append("\"plate_comment_cleared\": ").append(plateCleared.get()).append(", ");
                result.append("\"pre_comments_cleared\": ").append(preCleared.get()).append(", ");
                result.append("\"eol_comments_cleared\": ").append(eolCleared.get());
            }
        } catch (Exception e) {
            result.append("\"error\": \"").append(e.getMessage().replace("\"", "\\\"")).append("\"");
        }

        result.append("}");
        return result.toString();
    }
}
