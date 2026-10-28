package com.xebyte.core;

import ghidra.framework.model.DomainFile;
import ghidra.program.model.listing.Program;

import java.security.SecureRandom;
import java.util.Collections;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.WeakHashMap;

/**
 * Which state of a program a reader saw, comparable across opens and restarts.
 *
 * <p>{@link Program#getModificationNumber()} sees every change, saved or not, but starts
 * over each time a program is opened, so a value from before a close or a server restart
 * says nothing about the program now. Two more parts make it comparable:
 * <ul>
 *   <li>the <b>epoch</b>: a random id for this open of the program, so counters from
 *       different opens never compare equal;
 *   <li>the <b>saved state</b>: the program file's last-modified time, and its version when
 *       it is versioned. It survives restarts but cannot see unsaved edits. The time is the
 *       local file's, so it is comparable on one machine; the version across machines.
 * </ul>
 * {@link #token} joins all three; any reopen, save or edit changes it.
 */
public final class ProgramRevision {

    private static final Map<Program, String> EPOCHS =
            Collections.synchronizedMap(new WeakHashMap<>());
    private static final SecureRandom RANDOM = new SecureRandom();

    private ProgramRevision() {
    }

    /** This open's id; the same for as long as this Program instance lives. */
    public static String epoch(Program program) {
        return EPOCHS.computeIfAbsent(program, p -> {
            byte[] b = new byte[4];
            RANDOM.nextBytes(b);
            return HexFormat.of().formatHex(b);
        });
    }

    /** Last-modified time of the program's file, in ms; 0 when it has none. */
    public static long savedTime(Program program) {
        DomainFile df = program.getDomainFile();
        return df != null ? df.getLastModifiedTime() : 0L;
    }

    /** The file's version when it is under version control, else null. */
    public static Integer fileVersion(Program program) {
        DomainFile df = program.getDomainFile();
        return df != null && df.isVersioned() ? df.getVersion() : null;
    }

    /** {@code <saved time>:<epoch>:<modification number>}. */
    public static String token(Program program) {
        return savedTime(program) + ":" + epoch(program) + ":" + program.getModificationNumber();
    }

    /** The token and its parts, for a response. */
    public static Map<String, Object> toMap(Program program) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("token", token(program));
        out.put("epoch", epoch(program));
        out.put("modification_number", program.getModificationNumber());
        out.put("saved_time", savedTime(program));
        Integer version = fileVersion(program);
        if (version != null) {
            out.put("file_version", version);
        }
        out.put("unsaved_changes", program.isChanged());
        return out;
    }
}
