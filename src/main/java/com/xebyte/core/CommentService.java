package com.xebyte.core;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.util.Msg;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Service for comment operations: set/get/clear decompiler, disassembly, and plate comments.
 */
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

    @SuppressWarnings("deprecation")
    public Response setCommentAtAddress(String addressStr, String comment, int commentType, String transactionName) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) return Response.err("No program loaded");
        if (addressStr == null || addressStr.isEmpty()) return Response.err("Address is required");
        if (comment == null) return Response.err("Comment text is required");

        try {
            return threadingStrategy.executeWrite(program, transactionName, () -> {
                Address addr = program.getAddressFactory().getAddress(addressStr);
                if (addr == null) return Response.err("Invalid address: " + addressStr);
                program.getListing().setComment(addr, commentType, comment);
                return Response.text("Success: Set comment at " + addressStr);
            });
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    @SuppressWarnings("deprecation")
    @McpTool(value = "/set_decompiler_comment", description = "Set a comment for a given address in the function pseudocode", method = McpTool.Method.POST)

    public Response setDecompilerComment(

            @Param(value = "address") String addressStr,

            @Param(value = "comment") String comment) {
        return setCommentAtAddress(addressStr, comment, CodeUnit.PRE_COMMENT, "Set decompiler comment");
    }

    @SuppressWarnings("deprecation")
    @McpTool(value = "/set_disassembly_comment", description = "Set a comment for a given address in the function disassembly", method = McpTool.Method.POST)

    public Response setDisassemblyComment(

            @Param(value = "address") String addressStr,

            @Param(value = "comment") String comment) {
        return setCommentAtAddress(addressStr, comment, CodeUnit.EOL_COMMENT, "Set disassembly comment");
    }

    @McpTool(value = "/get_plate_comment", description = "Get function plate (header) comment")


    public Response getPlateComment(


            @Param(value = "address") FunctionRef funcRef,


            @Param(value = "program", required = false) String programName) {
        Program program = programProvider.resolveProgram(programName);
        if (program == null) return Response.err("No program loaded");
        if (funcRef == null) return Response.err("Function name or address is required");

        Function func = funcRef.resolve(program);
        if (func == null) return Response.err("No function found: " + funcRef.value());

        String plateComment = func.getComment();
        var result = new LinkedHashMap<String, Object>();
        result.put("address", func.getEntryPoint().toString());
        result.put("function_name", func.getName());
        result.put("comment", plateComment);
        return Response.ok(result);
    }

    @SuppressWarnings("deprecation")
    @McpTool(value = "/set_plate_comment", description = "Set function plate (header) comment (v1.5.0)", method = McpTool.Method.POST)

    public Response setPlateComment(

            @Param(value = "function_address") FunctionRef funcRef,

            @Param(value = "comment") String comment) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) return Response.err("No program loaded");
        if (funcRef == null) return Response.err("Function name or address is required");
        if (comment == null) return Response.err("Comment is required");

        try {
            Response result = threadingStrategy.executeWrite(program, "Set Plate Comment", () -> {
                Function func = funcRef.resolve(program);
                if (func == null) return Response.err("No function found: " + funcRef.value());
                func.setComment(comment);
                return Response.text("Success: Set plate comment for function " + func.getName());
            });
            if (result instanceof Response.Text) {
                program.flushEvents();
                try { Thread.sleep(500); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
            }
            return result;
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    @SuppressWarnings("deprecation")
    @McpTool(value = "/batch_set_comments", description = "Set multiple comments in a single operation (v1.5.0)", method = McpTool.Method.POST)

    public Response batchSetComments(

            @Param(value = "function_address") FunctionRef funcRef,

            @Param(value = "decompilerComments", type = "object") List<Map<String, String>> decompilerComments,

            @Param(value = "disassemblyComments", type = "object") List<Map<String, String>> disassemblyComments,

            @Param(value = "plateComment") String plateComment) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) return Response.err("No program loaded");

        try {
            final int[] counts = new int[4]; // [decompiler, disassembly, plateSet, overwritten]
            threadingStrategy.executeWrite(program, "Batch Set Comments", () -> {
                Listing listing = program.getListing();

                // Set or clear plate comment
                if (plateComment != null && !plateComment.equals("null") && funcRef != null) {
                    Function func = funcRef.resolve(program);
                    if (func != null) {
                        String existingPlate = func.getComment();
                        if (existingPlate != null && !existingPlate.isEmpty()) counts[3]++;
                        func.setComment(plateComment.isEmpty() ? null : plateComment);
                        counts[2] = 1;
                    }
                }

                // Set decompiler comments (PRE_COMMENT)
                if (decompilerComments != null) {
                    for (Map<String, String> commentEntry : decompilerComments) {
                        String addr = commentEntry.get("address");
                        String cmt = commentEntry.get("comment");
                        if (addr != null && cmt != null) {
                            Address address = program.getAddressFactory().getAddress(addr);
                            if (address != null) {
                                String existing = listing.getComment(CodeUnit.PRE_COMMENT, address);
                                if (existing != null && !existing.isEmpty()) counts[3]++;
                                listing.setComment(address, CodeUnit.PRE_COMMENT, cmt.isEmpty() ? null : cmt);
                                counts[0]++;
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
                                if (existing != null && !existing.isEmpty()) counts[3]++;
                                listing.setComment(address, CodeUnit.EOL_COMMENT, cmt.isEmpty() ? null : cmt);
                                counts[1]++;
                            }
                        }
                    }
                }
                return null;
            });

            program.flushEvents();
            try { Thread.sleep(500); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }

            return Response.ok(Map.of(
                "success", true,
                "decompiler_comments_set", counts[0],
                "disassembly_comments_set", counts[1],
                "plate_comment_set", counts[2] == 1,
                "plate_comment_cleared", counts[2] == 1 && plateComment != null && plateComment.isEmpty(),
                "comments_overwritten", counts[3]
            ));
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }

    @SuppressWarnings("deprecation")
    @McpTool(value = "/clear_function_comments", description = "Clear all comments (plate, PRE, EOL) within a function's address range (v3.0.1)", method = McpTool.Method.POST)

    public Response clearFunctionComments(

            @Param(value = "function_address") FunctionRef funcRef,

            @Param(value = "clearPlate", type = "boolean") boolean clearPlate,

            @Param(value = "clearPre", type = "boolean") boolean clearPre,

            @Param(value = "clearEol", type = "boolean") boolean clearEol) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) return Response.err("No program loaded");
        if (funcRef == null) return Response.err("Function name or address is required");

        try {
            final int[] counts = new int[3]; // [preCleared, eolCleared, plateCleared]
            threadingStrategy.executeWrite(program, "Clear Function Comments", () -> {
                Function func = funcRef.resolve(program);
                if (func == null) throw new IllegalArgumentException("No function found: " + funcRef.value());

                if (clearPlate && func.getComment() != null) {
                    func.setComment(null);
                    counts[2] = 1;
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
                            counts[0]++;
                        }
                    }
                    if (clearEol) {
                        String existing = listing.getComment(CodeUnit.EOL_COMMENT, instrAddr);
                        if (existing != null) {
                            listing.setComment(instrAddr, CodeUnit.EOL_COMMENT, null);
                            counts[1]++;
                        }
                    }
                }
                return null;
            });

            return Response.ok(Map.of(
                "success", true,
                "plate_comment_cleared", counts[2] == 1,
                "pre_comments_cleared", counts[0],
                "eol_comments_cleared", counts[1]
            ));
        } catch (Exception e) {
            return Response.err(e.getMessage());
        }
    }
}
