package com.xebyte.offline;

import com.xebyte.core.GhidraMCPAuthenticator;
import ghidra.framework.client.ClientUtil;
import org.junit.Test;

import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * A Ghidra Server started without -u never lets the client choose a name, so the configured
 * ghidra_server.user is silently replaced by the OS user and the login fails as "Authentication
 * failed" (ghidra-mcp-xkc). The failure must say so instead of sending the operator after the
 * password.
 */
public class AuthenticatorUserNameTest {

    private static final String CONFIGURED = "svc-account-not-the-os-user";

    @Test
    public void aServerThatDoesNotAskForANameIsExplained() {
        GhidraMCPAuthenticator auth = new GhidraMCPAuthenticator(CONFIGURED, "pw".toCharArray());
        auth.processPasswordCallbacks("t", "Ghidra Server", "repo-host", false,
            new NameCallback("User ID:", ClientUtil.getUserName()), new PasswordCallback("Password:", false),
            null, null, null);
        String explained = GhidraMCPAuthenticator.explain("Authentication failed");
        assertTrue(explained, explained.startsWith("Authentication failed The Ghidra Server at repo-host"));
        assertTrue(explained, explained.contains("'" + ClientUtil.getUserName() + "', not ghidra_server.user '"
            + CONFIGURED + "'"));
        assertEquals("explaining twice adds nothing", explained, GhidraMCPAuthenticator.explain(explained));
    }

    @Test
    public void aServerThatAsksForANameGetsTheConfiguredOne() {
        GhidraMCPAuthenticator auth = new GhidraMCPAuthenticator(CONFIGURED, "pw".toCharArray());
        NameCallback name = new NameCallback("User ID:", ClientUtil.getUserName());
        auth.processPasswordCallbacks("t", "Ghidra Server", "repo-host", true, name,
            new PasswordCallback("Password:", false), null, null, null);
        assertEquals(CONFIGURED, name.getName());
        assertEquals("Authentication failed", GhidraMCPAuthenticator.explain("Authentication failed"));
    }
}
