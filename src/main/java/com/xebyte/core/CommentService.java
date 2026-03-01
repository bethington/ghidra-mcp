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
    public Response setDecompilerComment(String addressStr, String comment) {
        return setCommentAtAddress(addressStr, comment, CodeUnit.PRE_COMMENT, "Set decompiler comment");
    }

    @SuppressWarnings("deprecation")
    public Response setDisassemblyComment(String addressStr, String comment) {
        return setCommentAtAddress(addressStr, comment, CodeUnit.EOL_COMMENT, "Set disassembly comment");
    }

    public Response getPlateComment(String address, String programName) {
        Program program = programProvider.resolveProgram(programName);
        if (program == null) return Response.err("No program loaded");
        if (address == null || address.isEmpty()) return Response.err("address parameter is required");

        Address addr = program.getAddressFactory().getAddress(address);
        if (addr == null) return Response.err("Invalid address: " + address);

        Function func = program.getFunctionManager().getFunctionAt(addr);
        if (func == null) func = program.getFunctionManager().getFunctionContaining(addr);
        if (func == null) return Response.err("No function at address: " + address);

        String plateComment = func.getComment();
        var result = new LinkedHashMap<String, Object>();
        result.put("address", func.getEntryPoint().toString());
        result.put("function_name", func.getName());
        result.put("comment", plateComment);
        return Response.ok(result);
    }

    @SuppressWarnings("deprecation")
    public Response setPlateComment(String functionAddress, String comment) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) return Response.err("No program loaded");
        if (functionAddress == null || functionAddress.isEmpty()) return Response.err("Function address is required");
        if (comment == null) return Response.err("Comment is required");

        try {
            Response result = threadingStrategy.executeWrite(program, "Set Plate Comment", () -> {
                Address addr = program.getAddressFactory().getAddress(functionAddress);
                if (addr == null) return Response.err("Invalid address: " + functionAddress);
                Function func = program.getFunctionManager().getFunctionAt(addr);
                if (func == null) return Response.err("No function at address: " + functionAddress);
                func.setComment(comment);
                return Response.text("Success: Set plate comment for function at " + functionAddress);
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
    public Response batchSetComments(String functionAddress, List<Map<String, String>> decompilerComments,
                                     List<Map<String, String>> disassemblyComments, String plateComment) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) return Response.err("No program loaded");

        try {
            final int[] counts = new int[4]; // [decompiler, disassembly, plateSet, overwritten]
            threadingStrategy.executeWrite(program, "Batch Set Comments", () -> {
                Listing listing = program.getListing();

                // Set or clear plate comment
                if (plateComment != null && !plateComment.equals("null") && functionAddress != null) {
                    Address funcAddr = program.getAddressFactory().getAddress(functionAddress);
                    if (funcAddr != null) {
                        Function func = program.getFunctionManager().getFunctionAt(funcAddr);
                        if (func != null) {
                            String existingPlate = func.getComment();
                            if (existingPlate != null && !existingPlate.isEmpty()) counts[3]++;
                            func.setComment(plateComment.isEmpty() ? null : plateComment);
                            counts[2] = 1;
                        }
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
    public Response clearFunctionComments(String functionAddress, boolean clearPlate, boolean clearPre, boolean clearEol) {
        Program program = programProvider.getCurrentProgram();
        if (program == null) return Response.err("No program loaded");
        if (functionAddress == null || functionAddress.isEmpty()) return Response.err("function_address parameter is required");

        try {
            final int[] counts = new int[3]; // [preCleared, eolCleared, plateCleared]
            threadingStrategy.executeWrite(program, "Clear Function Comments", () -> {
                Address addr = program.getAddressFactory().getAddress(functionAddress);
                if (addr == null) throw new IllegalArgumentException("Invalid address: " + functionAddress);
                Function func = program.getFunctionManager().getFunctionAt(addr);
                if (func == null) throw new IllegalArgumentException("No function at address: " + functionAddress);

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
