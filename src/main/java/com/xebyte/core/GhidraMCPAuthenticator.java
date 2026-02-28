/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.xebyte.core;

import java.net.Authenticator;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import ghidra.framework.client.ClientAuthenticator;
import ghidra.framework.remote.AnonymousCallback;
import ghidra.framework.remote.SSHSignatureCallback;
import ghidra.util.Msg;

/**
 * Programmatic authenticator for Ghidra server connections.
 * Implements ClientAuthenticator to provide credentials without GUI interaction.
 * Shared between the GUI plugin (FrontEnd) and headless server.
 *
 * Register via: ClientUtil.setClientAuthenticator(new GhidraMCPAuthenticator(user, password));
 */
public class GhidraMCPAuthenticator implements ClientAuthenticator {
    private volatile String username;
    private volatile char[] password;

    public GhidraMCPAuthenticator(String username, char[] password) {
        this.username = username;
        this.password = password;
    }

    /**
     * Update credentials at runtime (e.g., from /server/authenticate endpoint).
     */
    public void updateCredentials(String username, char[] password) {
        this.username = username;
        this.password = password;
    }

    public String getUsername() {
        return username;
    }

    @Override
    public boolean isSSHKeyAvailable() {
        return false;
    }

    @Override
    public boolean processSSHSignatureCallbacks(String serverName, NameCallback nameCb,
            SSHSignatureCallback sshCb) {
        return false;
    }

    @Override
    public boolean processPasswordCallbacks(String title, String serverType, String serverName,
            boolean nameEditable, NameCallback nameCb, PasswordCallback passCb,
            javax.security.auth.callback.ChoiceCallback choiceCb, AnonymousCallback anonymousCb,
            String loginError) {
        try {
            if (nameCb != null) {
                nameCb.setName(username);
            }
            if (passCb != null) {
                passCb.setPassword(password);
            }
            if (choiceCb != null) {
                choiceCb.setSelectedIndex(choiceCb.getDefaultChoice());
            }
            if (anonymousCb != null) {
                anonymousCb.setAnonymousAccessRequested(false);
            }
            Msg.info(this, "GhidraMCP authenticator provided credentials for user: " + username);
            return true;
        } catch (Exception e) {
            Msg.error(this, "Password callback failed: " + e.getMessage());
            return false;
        }
    }

    @Override
    public boolean promptForReconnect(java.awt.Component parent, String message) {
        Msg.info(this, "Reconnect requested: " + message);
        return true;
    }

    @Override
    public char[] getNewPassword(java.awt.Component parent, String serverInfo, String user) {
        return null;
    }

    @Override
    public Authenticator getAuthenticator() {
        return null;
    }

    @Override
    public char[] getKeyStorePassword(String keystorePath, boolean passwordError) {
        return null;
    }
}
