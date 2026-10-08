package com.xebyte.core;

import ghidra.program.model.listing.Program;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Cheap change token for out-of-band edits the bridge cannot see.
 *
 * <p>The token is {@link ProgramRevision#token}: the program file's saved time, an id for
 * this open, and the modification number. The number alone advances on real DB changes and
 * never on a read, but starts over each time the program is opened, so after a restart it
 * could land on the value a client had cached and a stale resource would read as current.
 * Compare the whole token. It over-invalidates rather than serving stale text: re-setting an
 * identical comment moves it.
 *
 * @since 7.1.0
 */
public class ChangeTokenService {

    private final ProgramProvider programProvider;

    public ChangeTokenService(ProgramProvider programProvider) {
        this.programProvider = programProvider;
    }

    @McpTool(path = "/get_change_token",
        description = "Return the program's change token: '<saved time>:<open epoch>:<modification "
            + "number>'. It moves on every DB change (rename, comment, struct edit, undo/redo, GUI "
            + "writes, scripts), on a save, and on a reopen or server restart, and never on a read. "
            + "Compare the whole token; the modification number alone starts over on every open. "
            + "Used by the bridge to invalidate cached function resources after out-of-band edits.",
        category = "program", access = ToolAccess.READ_ONLY)
    public Response getChangeToken(
            @Param(value = "program", defaultValue = "",
                   description = "Target program name (omit for the active program).") String programName) {
        ServiceUtils.ProgramOrError pe = ServiceUtils.getProgramOrError(programProvider, programName);
        if (pe.hasError()) return pe.error();
        Program program = pe.program();

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("program", program.getName());
        out.putAll(ProgramRevision.toMap(program));
        return Response.ok(out);
    }
}
