package com.xebyte.core;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.util.Msg;

import javax.swing.SwingUtilities;
import java.util.LinkedHashMap;
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

        // Resolve address before entering SwingUtilities lambda
        Address addr = ServiceUtils.parseAddress(program, addressStr);
        if (addr == null) return Response.err(ServiceUtils.getLastParseError());

        final AtomicBoolean success = new AtomicBoolean(false);
        final AtomicReference<String> errorMsg = new AtomicReference<>();

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction(transactionName);
                try {
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

    @McpTool(path = "/set_decompiler_comment", method = "POST", description = "Set decompiler PRE_COMMENT at address. On programs with multiple address spaces (e.g., embedded targets), prefix addresses with the space name (mem:1000) to avoid ambiguous resolution.", category = "comment")
    public Response setDecompilerComment(
            @Param(value = "address", paramType = "address", source = ParamSource.BODY,
                   description = "Address in the program. Accepts 0x<hex> (default space) or <space>:<hex> "
                               + "(e.g., mem:1000, code:ff00). Note: some programs — particularly "
                               + "embedded/microcontroller targets — are not address-space-agnostic; "
                               + "use get_address_spaces to discover spaces before assuming a plain hex "
                               + "address is unambiguous.") String addressStr,
            @Param(value = "comment", source = ParamSource.BODY) String comment,
            @Param(value = "program", description = "Target program name", defaultValue = "") String programName) {
        return setCommentAtAddress(addressStr, comment, CodeUnit.PRE_COMMENT, "Set decompiler comment", programName);
    }

    public Response setDecompilerComment(String addressStr, String comment) {
        return setDecompilerComment(addressStr, comment, null);
    }

    @McpTool(path = "/set_disassembly_comment", method = "POST", description = "Set disassembly EOL_COMMENT at address. On programs with multiple address spaces (e.g., embedded targets), prefix addresses with the space name (mem:1000) to avoid ambiguous resolution.", category = "comment")
    public Response setDisassemblyComment(
            @Param(value = "address", paramType = "address", source = ParamSource.BODY,
                   description = "Address in the program. Accepts 0x<hex> (default space) or <space>:<hex> "
                               + "(e.g., mem:1000, code:ff00). Note: some programs — particularly "
                               + "embedded/microcontroller targets — are not address-space-agnostic; "
                               + "use get_address_spaces to discover spaces before assuming a plain hex "
                               + "address is unambiguous.") String addressStr,
            @Param(value = "comment", source = ParamSource.BODY) String comment,
            @Param(value = "program", description = "Target program name", defaultValue = "") String programName) {
        return setCommentAtAddress(addressStr, comment, CodeUnit.EOL_COMMENT, "Set disassembly comment", programName);
    }

    public Response setDisassemblyComment(String addressStr, String comment) {
        return setDisassemblyComment(addressStr, comment, null);
    }

    /**
     * Get the plate (header) comment for a function.
     */
    @McpTool(path = "/get_plate_comment", description = "Get function header/plate comment. On programs with multiple address spaces (e.g., embedded targets), prefix addresses with the space name (mem:1000) to avoid ambiguous resolution.", category = "comment")
    public Response getPlateComment(
            @Param(value = "address", paramType = "address",
                   description = "Address in the program. Accepts 0x<hex> (default space) or <space>:<hex> "
                               + "(e.g., mem:1000, code:ff00). Note: some programs — particularly "
                               + "embedded/microcontroller targets — are not address-space-agnostic; "
                               + "use get_address_spaces to discover spaces before assuming a plain hex "
                               + "address is unambiguous.") String address,
            @Param(value = "program", description = "Target program name (omit to use the active program — always specify when multiple programs are open)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        if (address == null || address.isEmpty()) {
            return Response.err("address parameter is required");
        }

        Address addr = ServiceUtils.parseAddress(program, address);
        if (addr == null) {
            return Response.err(ServiceUtils.getLastParseError());
        }

        Function func = program.getFunctionManager().getFunctionAt(addr);
        if (func == null) {
            func = program.getFunctionManager().getFunctionContaining(addr);
        }
        if (func == null) {
            return Response.err("No function at address: " + address);
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.putAll(ServiceUtils.addressToJson(func.getEntryPoint(), program));
        result.put("function_name", func.getName());
        result.put("comment", func.getComment());
        return Response.ok(result);
    }

    private static String firstNonEmpty(String... ss) {
        for (String s : ss) {
            if (s != null && !s.trim().isEmpty()) return s;
        }
        return null;
    }

    /**
     * Get listing comments at ANY address (plate/pre/eol/post/repeatable), including data
     * addresses. Unlike get_plate_comment, this does not require a function at the address --
     * so it can read the plate/EOL comment attached to a global/data symbol.
     */
    @McpTool(path = "/get_comment", description = "Get listing comments (plate/pre/eol/post/repeatable) at ANY address, including data addresses (unlike get_plate_comment which requires a function). Returns each comment kind plus a convenience `comment` (first non-empty) and `has_comment` flag.", category = "comment")
    public Response getComment(
            @Param(value = "address", paramType = "address",
                   description = "Address in the program. Accepts 0x<hex> (default space) or <space>:<hex>. "
                               + "Works for data addresses, not just functions.") String addressStr,
            @Param(value = "program", description = "Target program name (omit to use the active program)", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        if (addressStr == null || addressStr.isEmpty()) {
            return Response.err("address parameter is required");
        }
        Address addr = ServiceUtils.parseAddress(program, addressStr);
        if (addr == null) {
            return Response.err(ServiceUtils.getLastParseError());
        }

        Listing listing = program.getListing();
        String plate = listing.getComment(CodeUnit.PLATE_COMMENT, addr);
        String pre = listing.getComment(CodeUnit.PRE_COMMENT, addr);
        String eol = listing.getComment(CodeUnit.EOL_COMMENT, addr);
        String post = listing.getComment(CodeUnit.POST_COMMENT, addr);
        String repeatable = listing.getComment(CodeUnit.REPEATABLE_COMMENT, addr);

        String best = firstNonEmpty(plate, pre, eol, post, repeatable);
        Map<String, Object> result = new LinkedHashMap<>();
        result.putAll(ServiceUtils.addressToJson(addr, program));
        result.put("plate", plate);
        result.put("pre", pre);
        result.put("eol", eol);
        result.put("post", post);
        result.put("repeatable", repeatable);
        result.put("comment", best);
        result.put("has_comment", best != null && !best.trim().isEmpty());
        return Response.ok(result);
    }

    /**
     * Symmetric writer for get_comment: set a listing comment of a given kind at ANY address,
     * including data globals. Unlike set_plate_comment (function-only), this can set a PLATE
     * comment on a data global via Listing.setComment.
     */
    @McpTool(path = "/set_comment", method = "POST", description = "Set a listing comment of a given kind (plate/pre/eol/post/repeatable) at ANY address, including data addresses. Symmetric writer for get_comment; unlike set_plate_comment this can set a PLATE comment on a data global.", category = "comment")
    public Response setComment(
            @Param(value = "address", paramType = "address", source = ParamSource.BODY,
                   description = "Address in the program (data or code). 0x<hex> or <space>:<hex>.") String addressStr,
            @Param(value = "comment", source = ParamSource.BODY) String comment,
            @Param(value = "type", source = ParamSource.BODY, defaultValue = "plate",
                   description = "Comment kind: plate | pre | eol | post | repeatable (default plate)") String type,
            @Param(value = "program", description = "Target program name (omit to use the active program)", defaultValue = "") String programName) {
        String t = (type == null || type.trim().isEmpty()) ? "plate" : type.trim().toLowerCase();
        int ct;
        switch (t) {
            case "plate":                 ct = CodeUnit.PLATE_COMMENT;      break;
            case "pre": case "decompiler": ct = CodeUnit.PRE_COMMENT;        break;
            case "eol": case "disassembly": ct = CodeUnit.EOL_COMMENT;       break;
            case "post":                  ct = CodeUnit.POST_COMMENT;       break;
            case "repeatable":            ct = CodeUnit.REPEATABLE_COMMENT; break;
            default:
                return Response.err("Unknown comment type: " + type + " (use plate|pre|eol|post|repeatable)");
        }
        return setCommentAtAddress(addressStr, comment, ct, "Set " + t + " comment", programName);
    }

    /**
     * Set function plate (header) comment.
     */
    @McpTool(path = "/set_plate_comment", method = "POST", description = "Set function header/plate comment. On programs with multiple address spaces (e.g., embedded targets), prefix addresses with the space name (mem:1000) to avoid ambiguous resolution.", category = "comment")
    public Response setPlateComment(
            @Param(value = "address", paramType = "address", source = ParamSource.BODY,
                   description = "Address in the program. Accepts 0x<hex> (default space) or <space>:<hex> "
                               + "(e.g., mem:1000, code:ff00). Note: some programs — particularly "
                               + "embedded/microcontroller targets — are not address-space-agnostic; "
                               + "use get_address_spaces to discover spaces before assuming a plain hex "
                               + "address is unambiguous.") String functionAddress,
            @Param(value = "comment", source = ParamSource.BODY) String comment,
            @Param(value = "program", description = "Target program name", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        if (functionAddress == null || functionAddress.isEmpty()) {
            return Response.err("Function address is required");
        }
        if (comment == null) {
            return Response.err("Comment is required");
        }

        // Resolve address before entering SwingUtilities lambda
        Address resolvedAddr = ServiceUtils.parseAddress(program, functionAddress);
        if (resolvedAddr == null) return Response.err(ServiceUtils.getLastParseError());

        final AtomicBoolean success = new AtomicBoolean(false);
        final AtomicReference<String> errorMsg = new AtomicReference<>();

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Set Plate Comment");
                try {
                    Function func = program.getFunctionManager().getFunctionAt(resolvedAddr);
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
            List<String> plateWarnings = NamingConventions.validatePlateCommentStructure(comment);
            if (plateWarnings.isEmpty()) {
                return Response.ok(JsonHelper.mapOf("status", "success", "message",
                        "Set plate comment for function at " + functionAddress));
            } else {
                return Response.ok(JsonHelper.mapOf("status", "success", "message",
                        "Set plate comment for function at " + functionAddress,
                        "warnings", plateWarnings));
            }
        }
        return Response.err(errorMsg.get() != null ? errorMsg.get() : "Unknown failure");
    }

    public Response setPlateComment(String functionAddress, String comment) {
        return setPlateComment(functionAddress, comment, null);
    }

    /**
     * Batch set multiple comments (decompiler, disassembly, and plate) in a single operation.
     */
    @McpTool(path = "/batch_set_comments", method = "POST", description = "Set multiple comments in one operation. On programs with multiple address spaces (e.g., embedded targets), prefix addresses with the space name (mem:1000) to avoid ambiguous resolution.", category = "comment")
    public Response batchSetComments(
            @Param(value = "address", paramType = "address", source = ParamSource.BODY,
                   description = "Address in the program. Accepts 0x<hex> (default space) or <space>:<hex> "
                               + "(e.g., mem:1000, code:ff00). Note: some programs — particularly "
                               + "embedded/microcontroller targets — are not address-space-agnostic; "
                               + "use get_address_spaces to discover spaces before assuming a plain hex "
                               + "address is unambiguous.") String functionAddress,
            @Param(value = "decompiler_comments", source = ParamSource.BODY, defaultValue = "[]") List<Map<String, String>> decompilerComments,
            @Param(value = "disassembly_comments", source = ParamSource.BODY, defaultValue = "[]") List<Map<String, String>> disassemblyComments,
            @Param(value = "plate_comment", source = ParamSource.BODY, defaultValue = "null",
                   description = "Plate comment text. Omit to leave existing plate untouched. Pass empty string to explicitly clear.") String plateComment,
            @Param(value = "program", description = "Target program name", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        // Resolve function address before entering SwingUtilities lambda
        final Address funcAddr;
        if (functionAddress != null && !functionAddress.isEmpty()) {
            funcAddr = ServiceUtils.parseAddress(program, functionAddress);
            if (funcAddr == null) return Response.err(ServiceUtils.getLastParseError());
        } else {
            funcAddr = null;
        }

        // Pre-flight plate-quality gate (option B enforcement). When the
        // target address is a data global (defined data, no function),
        // applying a sub-quality plate via batch_set_comments would have
        // been an escape hatch around set_global's upfront validator. Run
        // the same check that set_global runs so a single-tool plate write
        // can't ship a 1-word summary into a global. Function-target plate
        // comments retain the existing (warning-only) flow because
        // function plates have their own structural rules in
        // validatePlateCommentStructure called below.
        if (funcAddr != null
                && plateComment != null
                && !plateComment.equals("null")
                && !plateComment.isEmpty()) {
            Function preFunc = program.getFunctionManager().getFunctionAt(funcAddr);
            if (preFunc == null) {
                Data preData = program.getListing().getDefinedDataAt(funcAddr);
                if (preData != null) {
                    String[] plateIssue = NamingConventions.checkGlobalPlateComment(plateComment);
                    if (plateIssue != null) {
                        return Response.ok(JsonHelper.mapOf(
                                "status", "rejected",
                                "error", plateIssue[0],
                                "address", functionAddress,
                                "first_line", plateIssue[1],
                                "message", "Plate-comment first line must be a >=4-word summary describing what the global represents.",
                                "suggestion", "Replace with a one-liner like 'Bitmap of currently-active quests for the player' or 'Pointer to the head of the linked unit list.'"
                        ));
                    }
                }
            }
        }

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
                    // - Function target → use Function.setComment (existing behavior).
                    // - Data-global target → use Listing.setComment(addr, PLATE_COMMENT, …).
                    //   Without this, plate writes on data addresses silently no-op'd
                    //   (returning success with `plate_comment_set: false`), which is
                    //   exactly what made the globals worker think it had set a plate
                    //   when nothing actually landed.
                    if (plateComment != null && !plateComment.equals("null") && funcAddr != null) {
                        Function func = program.getFunctionManager().getFunctionAt(funcAddr);
                        if (func != null) {
                            String existingPlate = func.getComment();
                            if (existingPlate != null && !existingPlate.isEmpty()) {
                                overwrittenCount.incrementAndGet();
                            }
                            func.setComment(plateComment.isEmpty() ? null : plateComment);
                            plateSet.set(true);
                        } else {
                            // Data-global path. Previously gated on
                            // `getDefinedDataAt(funcAddr) != null` which
                            // silently skipped the plate write when the
                            // address had no defined data yet (the most
                            // common pre-documentation state — symbol
                            // exists but type hasn't been applied). The
                            // caller would see `plate_comment_set: false`
                            // hidden inside an overall success response.
                            // Listing.setComment works on any in-memory
                            // address regardless of defined-data status,
                            // so the gate was never necessary.
                            Listing dataListing = program.getListing();
                            String existingPlate = dataListing.getComment(
                                    CodeUnit.PLATE_COMMENT, funcAddr);
                            if (existingPlate != null && !existingPlate.isEmpty()) {
                                overwrittenCount.incrementAndGet();
                            }
                            dataListing.setComment(
                                    funcAddr,
                                    CodeUnit.PLATE_COMMENT,
                                    plateComment.isEmpty() ? null : plateComment);
                            plateSet.set(true);
                        }
                    }

                    // Set decompiler comments (PRE_COMMENT)
                    Listing listing = program.getListing();
                    if (decompilerComments != null) {
                        for (Map<String, String> commentEntry : decompilerComments) {
                            String addrStr = commentEntry.get("address");
                            String cmt = commentEntry.get("comment");
                            if (addrStr != null && cmt != null) {
                                Address address = ServiceUtils.parseAddress(program, addrStr);
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
                            String addrStr = commentEntry.get("address");
                            String cmt = commentEntry.get("comment");
                            if (addrStr != null && cmt != null) {
                                Address address = ServiceUtils.parseAddress(program, addrStr);
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

        // Validate plate comment structure (apply + warn)
        List<String> plateWarnings = (plateSet.get() && plateComment != null && !plateComment.isEmpty())
                ? NamingConventions.validatePlateCommentStructure(plateComment)
                : List.of();

        Map<String, Object> resultMap = new LinkedHashMap<>();
        resultMap.put("success", true);
        resultMap.put("decompiler_comments_set", decompilerCount.get());
        resultMap.put("disassembly_comments_set", disassemblyCount.get());
        resultMap.put("plate_comment_set", plateSet.get());
        resultMap.put("plate_comment_cleared", plateSet.get() && plateComment != null && plateComment.isEmpty());
        resultMap.put("comments_overwritten", overwrittenCount.get());
        if (!plateWarnings.isEmpty()) {
            resultMap.put("warnings", plateWarnings);
        }
        return Response.ok(resultMap);
    }

    public Response batchSetComments(String functionAddress, List<Map<String, String>> decompilerComments,
                                     List<Map<String, String>> disassemblyComments, String plateComment) {
        return batchSetComments(functionAddress, decompilerComments, disassemblyComments, plateComment, null);
    }

    /**
     * Clear all comments (plate, PRE, EOL) within a function's address range.
     */
    @McpTool(path = "/clear_function_comments", method = "POST", description = "Clear all comments within a function. On programs with multiple address spaces (e.g., embedded targets), prefix addresses with the space name (mem:1000) to avoid ambiguous resolution.", category = "comment")
    public Response clearFunctionComments(
            @Param(value = "address", paramType = "address", source = ParamSource.BODY,
                   description = "Address in the program. Accepts 0x<hex> (default space) or <space>:<hex> "
                               + "(e.g., mem:1000, code:ff00). Note: some programs — particularly "
                               + "embedded/microcontroller targets — are not address-space-agnostic; "
                               + "use get_address_spaces to discover spaces before assuming a plain hex "
                               + "address is unambiguous.") String functionAddress,
            @Param(value = "clear_plate", source = ParamSource.BODY, defaultValue = "true") boolean clearPlate,
            @Param(value = "clear_pre", source = ParamSource.BODY, defaultValue = "true") boolean clearPre,
            @Param(value = "clear_eol", source = ParamSource.BODY, defaultValue = "true") boolean clearEol,
            @Param(value = "program", description = "Target program name", defaultValue = "") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        if (functionAddress == null || functionAddress.isEmpty()) {
            return Response.err("function_address parameter is required");
        }

        // Resolve address before entering SwingUtilities lambda
        Address resolvedAddr = ServiceUtils.parseAddress(program, functionAddress);
        if (resolvedAddr == null) return Response.err(ServiceUtils.getLastParseError());

        final AtomicBoolean success = new AtomicBoolean(false);
        final AtomicReference<String> errorMsg = new AtomicReference<>();
        final AtomicInteger preCleared = new AtomicInteger(0);
        final AtomicInteger eolCleared = new AtomicInteger(0);
        final AtomicBoolean plateCleared = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Clear Function Comments");
                try {
                    Function func = program.getFunctionManager().getFunctionAt(resolvedAddr);
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
