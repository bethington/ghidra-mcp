package com.xebyte.core;

import com.xebyte.core.settings.ServerSettings;

/**
 * Registers Ghidra Server credentials from server-scope settings before any project opens.
 */
public final class ServerCredentials {

    private ServerCredentials() {}

    /**
     * When a password is configured, register the authenticator (user defaults to the OS user).
     *
     * @return whether credentials were registered
     */
    public static boolean registerFromSettings() {
        String password = ServerSettings.string("ghidra_server.password");
        if (password.isEmpty()) {
            return false;
        }
        String user = ServerSettings.string("ghidra_server.user");
        if (user.isEmpty()) {
            user = System.getProperty("user.name");
        }
        GhidraMCPAuthenticator.register(user, password.toCharArray());
        System.out.println("[GhidraMCP] Auto-registered server authenticator for user: " + user);
        return true;
    }
}
