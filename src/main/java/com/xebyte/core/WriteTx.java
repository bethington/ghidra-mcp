package com.xebyte.core;

import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

/**
 * A write transaction that refuses to roll back somebody else's work.
 *
 * <p>Ghidra transactions nest by <em>counting entries on one transaction</em>, not by
 * creating independent ones. Ending an inner entry with {@code commit=false} therefore
 * marks the <em>whole</em> transaction aborted, and everything the outer owner did is
 * discarded with it. Measured during this project's own experiments: a probe script that
 * rolled back its own nested transaction silently threw away a rename, two comments and a
 * struct that the enclosing script transaction had already made.
 *
 * <p>That is easy to hit here. Endpoints nest by design — {@code apply_documentation}
 * calls into rename and comment paths that each open their own transaction — and every
 * script runs inside a transaction the script manager opened, so anything reached from
 * {@code /run_ghidra_script} or {@code /run_script_inline} is nested by construction.
 *
 * <p>So: {@link #begin} starts a transaction only when none is open, and otherwise
 * <em>joins</em> the ambient one, where {@link #end} is a no-op. A failed inner write then
 * leaves its partial changes for the ambient owner to commit or undo as one unit, instead
 * of destroying that owner's work. This is the same trade Ghidra's own
 * {@code DomainObject.withTransaction} makes — it ends its entry with {@code commit=true}
 * unconditionally and lets the exception decide what the outermost owner does.
 *
 * <p>Nesting is decided at {@link #begin} time and cannot be decided later: once our own
 * entry is open, {@code getCurrentTransactionInfo()} is non-null whether or not anyone else
 * was there first.
 *
 * @since 7.1.0
 */
public final class WriteTx {

    /** Returned by {@link #id()} when this scope joined an ambient transaction. */
    public static final int JOINED = -1;

    private final Program program;
    private final int id;
    private boolean ended;

    private WriteTx(Program program, int id) {
        this.program = program;
        this.id = id;
    }

    /** Open a transaction on {@code program}, or join the one already open. */
    public static WriteTx begin(Program program, String description) {
        if (program == null) {
            return new WriteTx(null, JOINED);
        }
        if (program.getCurrentTransactionInfo() != null) {
            Msg.debug(WriteTx.class, "Joining an open transaction for '" + description
                + "'; a failure here cannot roll back without discarding the outer work");
            return new WriteTx(program, JOINED);
        }
        return new WriteTx(program, program.startTransaction(description));
    }

    /** True when this scope joined an ambient transaction and owns nothing. */
    public boolean joined() {
        return id == JOINED;
    }

    public int id() {
        return id;
    }

    /**
     * Commit or roll back, if we own the transaction. Safe to call more than once;
     * a no-op for a joined scope, whose owner ends the transaction itself.
     */
    public void end(boolean commit) {
        if (ended || id == JOINED || program == null) {
            return;
        }
        ended = true;
        program.endTransaction(id, commit);
    }
}
