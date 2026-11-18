package com.xebyte.core;

/**
 * The native decompiler could not be started for a program.
 *
 * <p>{@code DecompInterface.openProgram} reports this by returning {@code false} and
 * leaving the reason in {@code getLastMessage()} -- typically a missing or
 * unexecutable {@code decompile} binary (a source install, an unsupported
 * platform, natives stripped from the distribution). Ignoring that return value
 * left the interface half-open, so the first decompile came back as a
 * <em>cancelled</em> result and every caller reported "cancelled", which names
 * nothing the user can fix (#654).
 *
 * <p>Thrown by {@link ServiceUtils#createConfiguredDecompiler}, the one place
 * a {@code DecompInterface} is created, so every decompile path sees the real
 * reason. It is unchecked on purpose: an endpoint that does not catch it still
 * turns it into an error response through {@code AnnotationScanner}, carrying
 * this message.
 */
public final class DecompilerInitException extends IllegalStateException {

    private static final long serialVersionUID = 1L;

    /** What Ghidra said, or {@code null} when it said nothing. */
    private final String reason;

    public DecompilerInitException(String programName, String reason) {
        super(describe(programName, reason));
        this.reason = reason == null || reason.isBlank() ? null : reason.trim();
    }

    /** Ghidra's own explanation ({@code getLastMessage()}), or {@code null}. */
    public String reason() {
        return reason;
    }

    static String describe(String programName, String reason) {
        StringBuilder sb = new StringBuilder("Decompiler failed to initialise");
        if (programName != null && !programName.isBlank()) {
            sb.append(" for ").append(programName);
        }
        if (reason != null && !reason.isBlank()) {
            sb.append(": ").append(reason.trim());
        } else {
            sb.append(": Ghidra gave no reason; check that the native decompiler is installed "
                + "and executable for this platform");
        }
        return sb.toString();
    }
}
