package com.xebyte.core;

import java.util.List;

/**
 * A program name matched more than one program, and resolving it would mean guessing.
 *
 * <p>The multi-version corpus is the everyday case: {@code D2Common.dll} exists in every
 * version folder. Both servers used to pick one -- the GUI the first file its recursive
 * walk found, headless the first loaded name containing the string -- and every write
 * that followed went to whichever that was. A full project path always resolves.
 */
public final class AmbiguousProgramException extends RuntimeException {

    private final List<String> candidates;

    public AmbiguousProgramException(String requested, List<String> candidates) {
        super("'" + requested + "' is ambiguous: it matches " + candidates.size()
            + " programs (" + String.join(", ", candidates.subList(0, Math.min(8, candidates.size())))
            + (candidates.size() > 8 ? ", ..." : "")
            + "). Pass the full project path of the one you mean.");
        this.candidates = List.copyOf(candidates);
    }

    public List<String> candidates() {
        return candidates;
    }
}
