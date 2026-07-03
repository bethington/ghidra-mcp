package com.xebyte.offline;

import com.xebyte.headless.GhidraServerManager;
import ghidra.framework.remote.User;
import junit.framework.TestCase;

/**
 * Offline tests for {@link GhidraServerManager} pure helpers.
 *
 * <p>{@code User} is a plain Serializable value class
 * ({@code User(String, int)}, {@code getName()}, {@code getPermissionType()})
 * with no Ghidra-init transitive chain, so it is safe to instantiate in the
 * Maven offline suite.
 */
public class GhidraServerManagerTest extends TestCase {

    public void testMergeUserPermission_replacesExistingEntryAndPreservesOthers() {
        User[] existing = {
            new User("alice", User.ADMIN),
            new User("bob",   User.READ_ONLY),
            new User("carol", User.WRITE),
        };
        User[] merged = GhidraServerManager.mergeUserPermission(existing, "bob", User.WRITE);

        assertEquals("ACL size must not shrink", 3, merged.length);
        assertEquals("alice", merged[0].getName());
        assertEquals(User.ADMIN, merged[0].getPermissionType());
        assertEquals("bob", merged[1].getName());
        assertEquals("bob's level updated", User.WRITE, merged[1].getPermissionType());
        assertEquals("carol", merged[2].getName());
        assertEquals(User.WRITE, merged[2].getPermissionType());
        // Input not mutated
        assertEquals(User.READ_ONLY, existing[1].getPermissionType());
    }

    public void testMergeUserPermission_appendsNewUser() {
        User[] existing = {
            new User("alice", User.ADMIN),
        };
        User[] merged = GhidraServerManager.mergeUserPermission(existing, "dave", User.READ_ONLY);

        assertEquals(2, merged.length);
        assertEquals("alice", merged[0].getName());
        assertEquals(User.ADMIN, merged[0].getPermissionType());
        assertEquals("dave", merged[1].getName());
        assertEquals(User.READ_ONLY, merged[1].getPermissionType());
    }

    public void testMergeUserPermission_handlesNullOrEmptyExisting() {
        User[] fromNull = GhidraServerManager.mergeUserPermission(null, "alice", User.ADMIN);
        assertEquals(1, fromNull.length);
        assertEquals("alice", fromNull[0].getName());

        User[] fromEmpty = GhidraServerManager.mergeUserPermission(new User[0], "alice", User.ADMIN);
        assertEquals(1, fromEmpty.length);
        assertEquals("alice", fromEmpty[0].getName());
    }
}
