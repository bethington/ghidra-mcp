package com.xebyte.offline;

import com.xebyte.headless.CheckoutLeases;
import org.junit.Test;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

/**
 * The rule these pin: an undo destroys work and a check-in only adds a version, so anything
 * that might hold an edit is checked in.
 */
public class CheckoutLeasesTest {

    private static final String P = "/Vanilla/1.13c/D2Common.dll";
    private static final long IDLE_SECONDS = 60;
    private static final long IDLE = IDLE_SECONDS * 1000;

    private static final class FakeOps implements CheckoutLeases.Ops {
        final Map<String, Long> stamps = new HashMap<>();
        final Set<String> checkedOut = new HashSet<>();
        final Set<String> dirtyOnDisk = new HashSet<>();
        final List<String> checkins = new ArrayList<>();
        final List<String> releases = new ArrayList<>();
        final List<String> closedCopies = new ArrayList<>();
        boolean failSettle;

        @Override public long modificationStamp(String path) {
            return stamps.getOrDefault(path, CheckoutLeases.NOT_OPEN);
        }
        @Override public boolean isCheckedOut(String path) { return checkedOut.contains(path); }
        @Override public boolean modifiedOnDisk(String path) { return dirtyOnDisk.contains(path); }
        @Override public boolean checkin(String path, String comment) {
            checkins.add(path);
            if (failSettle) return false;
            checkedOut.remove(path);
            return true;
        }
        @Override public void closeCopy(String path) { closedCopies.add(path); }
        @Override public boolean release(String path) {
            releases.add(path);
            if (failSettle) return false;
            checkedOut.remove(path);
            return true;
        }
    }

    private final FakeOps ops = new FakeOps();
    private final List<String> logged = new ArrayList<>();
    private final CheckoutLeases leases = new CheckoutLeases(ops, IDLE_SECONDS, logged::add);

    private void open(long stamp, long now) {
        ops.checkedOut.add(P);
        ops.stamps.put(P, stamp);
        leases.opened(P, stamp, now);
    }

    @Test
    public void untouchedProgramIsReleasedNotCheckedIn() {
        open(10, 0);
        leases.sweep(IDLE);
        assertEquals(List.of(P), ops.releases);
        assertTrue(ops.checkins.isEmpty());
        assertTrue(leases.leasedPaths().isEmpty());
    }

    @Test
    public void editedProgramIsCheckedInNotReleased() {
        open(10, 0);
        ops.stamps.put(P, 11L);
        leases.sweep(1);
        leases.sweep(1 + IDLE);
        assertEquals(List.of(P), ops.checkins);
        assertTrue(ops.releases.isEmpty());
    }

    @Test
    public void nothingSettlesBeforeTheIdlePeriod() {
        open(10, 0);
        leases.sweep(IDLE - 1);
        assertTrue(ops.checkins.isEmpty());
        assertTrue(ops.releases.isEmpty());
    }

    @Test
    public void eachEditRestartsTheIdlePeriod() {
        open(10, 0);
        ops.stamps.put(P, 11L);
        leases.sweep(IDLE - 1);
        leases.sweep(IDLE + 1);
        assertTrue("edited at IDLE-1, so not idle yet", ops.checkins.isEmpty());
        leases.sweep(2 * IDLE - 1);
        assertEquals(List.of(P), ops.checkins);
    }

    @Test
    public void flushCatchesAnEditNoSweepSaw() {
        open(10, 0);
        ops.stamps.put(P, 11L);
        leases.flush(5);
        assertEquals(List.of(P), ops.checkins);
    }

    /** A cached program returning through opened() must not launder an unseen edit. */
    @Test
    public void cachedReopenDoesNotHideAnUnseenEdit() {
        open(10, 0);
        ops.stamps.put(P, 11L);
        leases.opened(P, 11, 5);
        leases.sweep(5 + IDLE);
        assertEquals(List.of(P), ops.checkins);
        assertTrue(ops.releases.isEmpty());
    }

    @Test
    public void cachedReopenWithNoEditStaysUnchanged() {
        open(10, 0);
        leases.opened(P, 10, 5);
        leases.sweep(5 + IDLE);
        assertEquals(List.of(P), ops.releases);
    }

    @Test
    public void evictedProgramWithSavedEditsIsCheckedIn() {
        open(10, 0);
        ops.stamps.remove(P);
        ops.dirtyOnDisk.add(P);
        leases.sweep(IDLE);
        assertEquals(List.of(P), ops.checkins);
    }

    @Test
    public void reopeningAfterEvictionKeepsTheEdit() {
        open(10, 0);
        ops.stamps.remove(P);
        ops.dirtyOnDisk.add(P);
        leases.opened(P, 10, 5);
        ops.stamps.put(P, 10L);
        leases.sweep(5 + IDLE);
        assertEquals(List.of(P), ops.checkins);
    }

    @Test
    public void adoptedCheckoutHoldingWorkIsCheckedIn() {
        ops.checkedOut.add(P);
        ops.dirtyOnDisk.add(P);
        leases.adopt(P, 0);
        leases.sweep(IDLE);
        assertEquals(List.of(P), ops.checkins);
    }

    @Test
    public void adoptedCleanCheckoutIsReleased() {
        ops.checkedOut.add(P);
        leases.adopt(P, 0);
        leases.sweep(IDLE);
        assertEquals(List.of(P), ops.releases);
    }

    /** Adopted leases have no baseline, so the first stamp seen is not itself an edit. */
    @Test
    public void adoptedCleanCheckoutOpenedLaterIsNotCountedAsEdited() {
        ops.checkedOut.add(P);
        leases.adopt(P, 0);
        ops.stamps.put(P, 7L);
        leases.sweep(1);
        leases.sweep(1 + IDLE);
        assertEquals(List.of(P), ops.releases);
    }

    @Test
    public void failedSettleKeepsTheLeaseSaysSoAndRetries() {
        open(10, 0);
        ops.stamps.put(P, 11L);
        ops.failSettle = true;
        leases.flush(1);
        assertEquals(List.of(P), leases.leasedPaths());
        assertTrue(logged.stream().anyMatch(m -> m.contains("Could not settle")));

        ops.failSettle = false;
        leases.sweep(1 + IDLE);
        assertEquals(2, ops.checkins.size());
        assertTrue(leases.leasedPaths().isEmpty());
    }

    @Test
    public void aFailedRetryNeverFallsBackToUndo() {
        open(10, 0);
        ops.stamps.put(P, 11L);
        ops.failSettle = true;
        leases.flush(1);
        leases.flush(2);
        assertTrue(ops.releases.isEmpty());
    }

    @Test
    public void handCheckedInFileIsDroppedWithoutSettling() {
        open(10, 0);
        ops.checkedOut.remove(P);
        leases.flush(IDLE);
        assertTrue(ops.checkins.isEmpty());
        assertTrue(ops.releases.isEmpty());
        assertFalse(leases.leasedPaths().contains(P));
    }

    @Test
    public void flushIgnoresTheIdlePeriod() {
        open(10, 0);
        leases.flush(1);
        assertEquals(List.of(P), ops.releases);
    }

    @Test
    public void idleReadOnlyCopyIsClosedSoTheNextOpenSeesCheckIns() {
        leases.openedReadOnly(P, 0);
        leases.sweep(IDLE - 1);
        assertTrue(ops.closedCopies.isEmpty());
        leases.sweep(IDLE);
        assertEquals(List.of(P), ops.closedCopies);
        assertTrue(leases.leasedPaths().isEmpty());
    }

    /** It is not checked out by definition, which must not read as "settled by hand". */
    @Test
    public void readOnlyCopyIsNeverCheckedInOrUndone() {
        leases.openedReadOnly(P, 0);
        leases.flush(1);
        assertEquals(List.of(P), ops.closedCopies);
        assertTrue(ops.checkins.isEmpty());
        assertTrue(ops.releases.isEmpty());
    }

    @Test
    public void idleSettingParses() {
        assertEquals(0, CheckoutLeases.parseIdleSeconds(null));
        assertEquals(0, CheckoutLeases.parseIdleSeconds("  "));
        assertEquals(300, CheckoutLeases.parseIdleSeconds(" 300 "));
        assertThrows(IllegalArgumentException.class, () -> CheckoutLeases.parseIdleSeconds("5m"));
        assertThrows(IllegalArgumentException.class, () -> CheckoutLeases.parseIdleSeconds("-1"));
    }
}
