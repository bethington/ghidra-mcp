package com.xebyte.headless;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

/**
 * Decides what happens to each checkout the headless server took for itself once the
 * program goes idle. An edited program is checked in, so other clients of the Ghidra
 * Server can see it. An untouched one has its checkout undone, so a read-only session
 * leaves no new version behind and blocks nobody's exclusive checkout. A read-only copy, opened
 * because someone else holds the checkout, is closed when idle so that the next open sees
 * their check-in and can take the checkout itself.
 *
 * <p>Deliberately free of Ghidra types, so the decision table runs in the offline tier.
 *
 * <p><b>Every doubt resolves towards a check-in.</b> Undoing a checkout destroys whatever it
 * held and an extra version costs only a little space, so "changed" is sticky and is set by
 * the program's modification number rather than by watching write endpoints: a script makes
 * its edits in its own transactions, and tracking only the endpoints would have undone those.
 *
 * <p>Lock order: callers of {@link #sweep} and {@link #flush} hold the threading strategy's
 * global lock first. A writer holding that lock may open a program and land in
 * {@link #opened}, so taking this monitor first could deadlock against it.
 */
public final class CheckoutLeases {

    public static final String IDLE_ENV = "GHIDRA_MCP_AUTO_CHECKIN_IDLE_SECONDS";

    /** {@link Ops#modificationStamp} for a program that is not open. */
    public static final long NOT_OPEN = -1;

    /** What leases need from the project; the implementation holds the Ghidra types. */
    public interface Ops {
        /** The open program's modification number, or {@link #NOT_OPEN}. */
        long modificationStamp(String path);

        boolean isCheckedOut(String path);

        /** Whether the local working copy differs from the version it was checked out at. */
        boolean modifiedOnDisk(String path);

        /** Check in and release. True only if the file is no longer checked out. */
        boolean checkin(String path, String comment);

        /** Discard the open copy and undo the checkout. True only if it is gone. */
        boolean release(String path);

        /** Close a read-only copy, which holds nothing that could be saved. */
        void closeCopy(String path);
    }

    private static final class Lease {
        long stamp;
        long lastActivity;
        boolean changed;
        boolean readOnlyCopy;
    }

    private final Ops ops;
    private final long idleMillis;
    private final Consumer<String> log;
    private final Map<String, Lease> leases = new LinkedHashMap<>();

    public CheckoutLeases(Ops ops, long idleSeconds, Consumer<String> log) {
        this.ops = ops;
        this.idleMillis = idleSeconds * 1000;
        this.log = log;
    }

    /**
     * Parse {@link #IDLE_ENV}. Unset or blank means off (0). Garbage is refused rather than
     * read as off: a server that silently never checks in looks fine until the work is needed.
     */
    public static long parseIdleSeconds(String value) {
        if (value == null || value.isBlank()) {
            return 0;
        }
        long seconds;
        try {
            seconds = Long.parseLong(value.trim());
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException(IDLE_ENV + " must be a number of seconds: " + value);
        }
        if (seconds < 0) {
            throw new IllegalArgumentException(IDLE_ENV + " must not be negative: " + value);
        }
        return seconds;
    }

    /**
     * A program was opened on a checkout. A cached program comes back through here too, with
     * edits no sweep has seen yet, so a stamp this lease does not recognise counts as a change
     * and is never simply taken as the new baseline.
     */
    public synchronized void opened(String path, long stamp, long now) {
        Lease lease = leases.get(path);
        if (lease == null) {
            lease = new Lease();
            lease.stamp = stamp;
            leases.put(path, lease);
        } else {
            lease.changed |= stamp != lease.stamp || ops.modifiedOnDisk(path);
            lease.stamp = stamp;
        }
        lease.lastActivity = now;
    }

    /** A program was opened read-only because someone else holds its checkout. */
    public synchronized void openedReadOnly(String path, long now) {
        Lease lease = new Lease();
        lease.readOnlyCopy = true;
        lease.lastActivity = now;
        leases.put(path, lease);
    }

    /** A checkout that survived a restart: settle it like any other, keeping what it holds. */
    public synchronized void adopt(String path, long now) {
        if (leases.containsKey(path)) {
            return;
        }
        Lease lease = new Lease();
        lease.stamp = NOT_OPEN;
        lease.lastActivity = now;
        lease.changed = ops.modifiedOnDisk(path);
        leases.put(path, lease);
    }

    /** Settle every lease idle for the full period. */
    public synchronized void sweep(long now) {
        settle(now, false);
    }

    /** Settle every lease now, idle or not: the server is stopping. */
    public synchronized void flush(long now) {
        settle(now, true);
    }

    public synchronized List<String> leasedPaths() {
        return new ArrayList<>(leases.keySet());
    }

    private void settle(long now, boolean force) {
        for (String path : new ArrayList<>(leases.keySet())) {
            Lease lease = leases.get(path);
            try {
                if (lease.readOnlyCopy) {
                    if (force || now - lease.lastActivity >= idleMillis) {
                        ops.closeCopy(path);
                        leases.remove(path);
                    }
                    continue;
                }
                if (!ops.isCheckedOut(path)) {
                    // Someone checked it in or undid it by hand: nothing left to settle.
                    leases.remove(path);
                    continue;
                }
                long stamp = ops.modificationStamp(path);
                if (stamp != NOT_OPEN && stamp != lease.stamp) {
                    lease.changed |= lease.stamp != NOT_OPEN;
                    lease.stamp = stamp;
                    lease.lastActivity = now;
                }
                if (!force && now - lease.lastActivity < idleMillis) {
                    continue;
                }
                if (!lease.changed) {
                    lease.changed = ops.modifiedOnDisk(path);
                }
                boolean settled = lease.changed
                        ? ops.checkin(path, "Auto check-in by ghidra-mcp after idle")
                        : ops.release(path);
                if (settled) {
                    log.accept((lease.changed ? "Auto checked in " : "Released unchanged checkout of ")
                            + path);
                    leases.remove(path);
                } else {
                    log.accept("Could not settle checkout of " + path + "; will retry");
                }
            } catch (Exception e) {
                log.accept("Could not settle checkout of " + path + "; will retry: " + e);
            }
        }
    }
}
