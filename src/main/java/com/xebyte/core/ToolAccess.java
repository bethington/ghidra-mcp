package com.xebyte.core;

/**
 * What a tool does to the program, project or host — the source for MCP's
 * {@code readOnlyHint} / {@code destructiveHint} tool annotations.
 *
 * <p>Clients act on these. Claude Code, for one, derives a tool's read-only-ness
 * <em>solely</em> from {@code annotations.readOnlyHint} (absent ⇒ false) and,
 * while planning, forces a permission prompt for every MCP tool that is not
 * read-only — a prompt no allow-rule can suppress, because the plan-mode gate is
 * evaluated before allow-rules and returns early. It also gates whether calls
 * may run concurrently on the same flag. So an unannotated read is a tool that
 * cannot be used unattended and cannot be parallelised.
 *
 * <p>{@link #UNSPECIFIED} is the default and emits no hints at all, leaving the
 * client's own defaults in play. That is deliberate: a wrong {@code READ_ONLY}
 * lets a mutating tool run unattended, so a tool nobody has classified must
 * stay in the cautious column rather than be guessed at from its HTTP method.
 * {@code AnnotationScannerTest} fails on any tool left {@code UNSPECIFIED}.
 *
 * @since 7.0.0
 */
public enum ToolAccess {

    /** Not classified: no annotations are emitted. New tools must not stay here. */
    UNSPECIFIED,

    /**
     * Only queries state. Nothing about the program, project, host filesystem or
     * any external service changes as a result of the call.
     */
    READ_ONLY,

    /**
     * Changes state additively — creates, renames, retypes, comments, saves.
     * Emits {@code readOnlyHint=false, destructiveHint=false}.
     */
    WRITE,

    /**
     * Removes or overwrites existing state: deletes, clears, closes, restores
     * over the top of something. Emits {@code destructiveHint=true}, which
     * clients use to require firmer confirmation.
     */
    DESTRUCTIVE;

    /** Whether MCP's {@code readOnlyHint} should be true. */
    public boolean isReadOnly() {
        return this == READ_ONLY;
    }

    /** Whether MCP's {@code destructiveHint} should be true. */
    public boolean isDestructive() {
        return this == DESTRUCTIVE;
    }
}
