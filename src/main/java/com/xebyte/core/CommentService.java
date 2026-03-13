package com.xebyte.core;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.util.Msg;

import javax.swing.SwingUtilities;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Service for comment operations: set/get/clear decompiler, disassembly, and plate comments.
 */
@McpToolGroup(value = "comment", description = "Set/get plate, decompiler, disassembly, repeatable comments")
public class CommentService {

    private final ProgramProvider programProvider;
    private final ThreadingStrategy threadingStrategy;

    public CommentService(ProgramProvider programProvider, ThreadingStrategy threadingStrategy) {
        this.programProvider = programProvider;
        this.threadingStrategy = threadingStrategy;
    }

    // -----------------------------------------------------------------------
    // Comment Methods
    // -----------------------------------------------------------------------

    /**
     * Set a comment using the specified comment type (PRE_COMMENT or EOL_COMMENT).
     */
    public Response setCommentAtAddress(String addressStr, String comment, int commentType, String transactionName, String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        if (addressStr == null || addressStr.isEmpty()) {
            return Response.err("Address is required");
        }
        if (comment == null) {
            return Response.err("Comment text is required");
        }

        final AtomicBoolean success = new AtomicBoolean(false);
        final AtomicReference<String> errorMsg = new AtomicReference<>();

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction(transactionName);
                try {
                    Address addr = program.getAddressFactory().getAddress(addressStr);
                    if (addr == null) {
                        errorMsg.set("Invalid address: " + addressStr);
                        return;
                    }
                    program.getListing().setComment(addr, commentType, comment);
                    success.set(true);
                } catch (Exception e) {
                    errorMsg.set(e.getMessage());
                    Msg.error(this, "Error setting " + transactionName.toLowerCase(), e);
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (Exception e) {
            return Response.err("Failed to execute on Swing thread: " + e.getMessage());
        }

        if (success.get()) {
            return Response.ok(JsonHelper.mapOf("status", "success", "message", "Set comment at " + addressStr));
        }
        return Response.err(errorMsg.get() != null ? errorMsg.get() : "Unknown failure");
    }

    public Response setCommentAtAddress(String addressStr, String comment, int commentType, String transactionName) {
        return setCommentAtAddress(addressStr, comment, commentType, transactionName, null);
    }

    @McpTool(path = "/set_decompiler_comment", method = "POST", description = "Set decompiler PRE_COMMENT at address", category = "comment")
    public Response setDecompilerComment(
            @Param(value = "address", source = ParamSource.BODY) String addressStr,
            @Param(value = "comment", source = ParamSource.BODY) String comment,
            @Param(value = "program", source = ParamSource.BODY, description = "Target program name") String programName) {
        return setCommentAtAddress(addressStr, comment, CodeUnit.PRE_COMMENT, "Set decompiler comment", programName);
    }

    public Response setDecompilerComment(String addressStr, String comment) {
        return setDecompilerComment(addressStr, comment, null);
    }

    @McpTool(path = "/set_disassembly_comment", method = "POST", description = "Set disassembly EOL_COMMENT at address", category = "comment")
    public Response setDisassemblyComment(
            @Param(value = "address", source = ParamSource.BODY) String addressStr,
            @Param(value = "comment", source = ParamSource.BODY) String comment,
            @Param(value = "program", source = ParamSource.BODY, description = "Target program name") String programName) {
        return setCommentAtAddress(addressStr, comment, CodeUnit.EOL_COMMENT, "Set disassembly comment", programName);
    }

    public Response setDisassemblyComment(String addressStr, String comment) {
        return setDisassemblyComment(addressStr, comment, null);
    }

    /**
     * Get the plate (header) comment for a function.
     */
    @McpTool(path = "/get_plate_comment", description = "Get function header/plate comment", category = "comment")
    public Response getPlateComment(
            @Param(value = "address", description = "Function address") String address,
            @Param(value = "program", description = "Target program name") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        if (address == null || address.isEmpty()) {
            return Response.err("address parameter is required");
        }

        Address addr = program.getAddressFactory().getAddress(address);
        if (addr == null) {
            return Response.err("Invalid address: " + address);
        }

        Function func = program.getFunctionManager().getFunctionAt(addr);
        if (func == null) {
            func = program.getFunctionManager().getFunctionContaining(addr);
        }
        if (func == null) {
            return Response.err("No function at address: " + address);
        }

        return Response.ok(JsonHelper.mapOf(
                "address", func.getEntryPoint().toString(),
                "function_name", func.getName(),
                "comment", func.getComment()
        ));
    }

    /**
     * Set function plate (header) comment.
     */
    @McpTool(path = "/set_plate_comment", method = "POST", description = "Set function header/plate comment", category = "comment")
    public Response setPlateComment(
            @Param(value = "function_address", source = ParamSource.BODY) String functionAddress,
            @Param(value = "comment", source = ParamSource.BODY) String comment,
            @Param(value = "program", source = ParamSource.BODY, description = "Target program name") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        if (functionAddress == null || functionAddress.isEmpty()) {
            return Response.err("Function address is required");
        }
        if (comment == null) {
            return Response.err("Comment is required");
        }

        final AtomicBoolean success = new AtomicBoolean(false);
        final AtomicReference<String> errorMsg = new AtomicReference<>();

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Set Plate Comment");
                try {
                    Address addr = program.getAddressFactory().getAddress(functionAddress);
                    if (addr == null) {
                        errorMsg.set("Invalid address: " + functionAddress);
                        return;
                    }

                    Function func = program.getFunctionManager().getFunctionAt(addr);
                    if (func == null) {
                        errorMsg.set("No function at address: " + functionAddress);
                        return;
                    }

                    func.setComment(comment);
                    success.set(true);
                } catch (Exception e) {
                    errorMsg.set(e.getMessage());
                    Msg.error(this, "Error setting plate comment", e);
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });

            // Force event processing to ensure changes propagate to decompiler cache
            if (success.get()) {
                program.flushEvents();
                try { Thread.sleep(500); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
            }
        } catch (Exception e) {
            return Response.err("Failed to execute on Swing thread: " + e.getMessage());
        }

        if (success.get()) {
            return Response.ok(JsonHelper.mapOf("status", "success", "message",
                    "Set plate comment for function at " + functionAddress));
        }
        return Response.err(errorMsg.get() != null ? errorMsg.get() : "Unknown failure");
    }

    public Response setPlateComment(String functionAddress, String comment) {
        return setPlateComment(functionAddress, comment, null);
    }

    /**
     * Batch set multiple comments (decompiler, disassembly, and plate) in a single operation.
     */
    @McpTool(path = "/batch_set_comments", method = "POST", description = "Set multiple comments in one operation", category = "comment")
    public Response batchSetComments(
            @Param(value = "function_address", source = ParamSource.BODY) String functionAddress,
            @Param(value = "decompiler_comments", source = ParamSource.BODY) List<Map<String, String>> decompilerComments,
            @Param(value = "disassembly_comments", source = ParamSource.BODY) List<Map<String, String>> disassemblyComments,
            @Param(value = "plate_comment", source = ParamSource.BODY, defaultValue = "") String plateComment,
            @Param(value = "program", source = ParamSource.BODY, description = "Target program name") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        final AtomicBoolean success = new AtomicBoolean(false);
        final AtomicReference<String> errorMsg = new AtomicReference<>();
        final AtomicInteger decompilerCount = new AtomicInteger(0);
        final AtomicInteger disassemblyCount = new AtomicInteger(0);
        final AtomicBoolean plateSet = new AtomicBoolean(false);
        final AtomicInteger overwrittenCount = new AtomicInteger(0);

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
                                    overwrittenCount.incrementAndGet();
                                }
                                func.setComment(plateComment.isEmpty() ? null : plateComment);
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
                                        overwrittenCount.incrementAndGet();
                                    }
                                    listing.setComment(address, CodeUnit.PRE_COMMENT, cmt.isEmpty() ? null : cmt);
                                    decompilerCount.incrementAndGet();
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
                                        overwrittenCount.incrementAndGet();
                                    }
                                    listing.setComment(address, CodeUnit.EOL_COMMENT, cmt.isEmpty() ? null : cmt);
                                    disassemblyCount.incrementAndGet();
                                }
                            }
                        }
                    }

                    success.set(true);
                } catch (Exception e) {
                    errorMsg.set(e.getMessage());
                    Msg.error(this, "Error in batch set comments", e);
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });

            // Force event processing to ensure changes propagate to decompiler cache
            if (success.get()) {
                program.flushEvents();
                try { Thread.sleep(500); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
            }
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }

        if (!success.get()) {
            return Response.err(errorMsg.get() != null ? errorMsg.get() : "Unknown failure");
        }

        return Response.ok(JsonHelper.mapOf(
                "success", true,
                "decompiler_comments_set", decompilerCount.get(),
                "disassembly_comments_set", disassemblyCount.get(),
                "plate_comment_set", plateSet.get(),
                "plate_comment_cleared", plateSet.get() && plateComment != null && plateComment.isEmpty(),
                "comments_overwritten", overwrittenCount.get()
        ));
    }

    public Response batchSetComments(String functionAddress, List<Map<String, String>> decompilerComments,
                                     List<Map<String, String>> disassemblyComments, String plateComment) {
        return batchSetComments(functionAddress, decompilerComments, disassemblyComments, plateComment, null);
    }

    /**
     * Clear all comments (plate, PRE, EOL) within a function's address range.
     */
    @McpTool(path = "/clear_function_comments", method = "POST", description = "Clear all comments within a function", category = "comment")
    public Response clearFunctionComments(
            @Param(value = "function_address", source = ParamSource.BODY) String functionAddress,
            @Param(value = "clear_plate", source = ParamSource.BODY, defaultValue = "true") boolean clearPlate,
            @Param(value = "clear_pre", source = ParamSource.BODY, defaultValue = "true") boolean clearPre,
            @Param(value = "clear_eol", source = ParamSource.BODY, defaultValue = "true") boolean clearEol,
            @Param(value = "program", source = ParamSource.BODY, description = "Target program name") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        if (functionAddress == null || functionAddress.isEmpty()) {
            return Response.err("function_address parameter is required");
        }

        final AtomicBoolean success = new AtomicBoolean(false);
        final AtomicReference<String> errorMsg = new AtomicReference<>();
        final AtomicInteger preCleared = new AtomicInteger(0);
        final AtomicInteger eolCleared = new AtomicInteger(0);
        final AtomicBoolean plateCleared = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Clear Function Comments");
                try {
                    Address addr = program.getAddressFactory().getAddress(functionAddress);
                    if (addr == null) {
                        errorMsg.set("Invalid address: " + functionAddress);
                        return;
                    }

                    Function func = program.getFunctionManager().getFunctionAt(addr);
                    if (func == null) {
                        errorMsg.set("No function at address: " + functionAddress);
                        return;
                    }

                    if (clearPlate && func.getComment() != null) {
                        func.setComment(null);
                        plateCleared.set(true);
                    }

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
                                preCleared.incrementAndGet();
                            }
                        }

                        if (clearEol) {
                            String existing = listing.getComment(CodeUnit.EOL_COMMENT, instrAddr);
                            if (existing != null) {
                                listing.setComment(instrAddr, CodeUnit.EOL_COMMENT, null);
                                eolCleared.incrementAndGet();
                            }
                        }
                    }

                    success.set(true);
                } catch (Exception e) {
                    errorMsg.set(e.getMessage());
                    Msg.error(this, "Error clearing function comments", e);
                } finally {
                    program.endTransaction(tx, success.get());
                }
            });
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }

        if (!success.get()) {
            return Response.err(errorMsg.get() != null ? errorMsg.get() : "Unknown failure");
        }

        return Response.ok(JsonHelper.mapOf(
                "success", true,
                "plate_comment_cleared", plateCleared.get(),
                "pre_comments_cleared", preCleared.get(),
                "eol_comments_cleared", eolCleared.get()
        ));
    }

    public Response clearFunctionComments(String functionAddress, boolean clearPlate, boolean clearPre, boolean clearEol) {
        return clearFunctionComments(functionAddress, clearPlate, clearPre, clearEol, null);
    }
}
