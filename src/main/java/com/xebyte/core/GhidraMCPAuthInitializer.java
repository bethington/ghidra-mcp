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

import ghidra.framework.ModuleInitializer;
import ghidra.framework.client.ClientUtil;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Registers the GhidraMCP server authenticator at application startup,
 * before any project is opened. This bypasses the GUI password dialog.
 *
 * This class implements ModuleInitializer (an ExtensionPoint), which Ghidra's
 * ClassSearcher discovers and executes during Application.initializeApplication().
 * This runs well before plugins load and before any project/server connection.
 *
 * Credential resolution order:
 *   1. GHIDRA_SERVER_PASSWORD environment variable
 *   2. .ghidra-cred file in user home directory (single line: password)
 *   3. .ghidra-cred file next to Ghidra installation
 *
 * Username resolution:
 *   1. GHIDRA_SERVER_USER environment variable
 *   2. System username (user.name property)
 */
public class GhidraMCPAuthInitializer implements ModuleInitializer {

    private static volatile boolean registered = false;
    private static GhidraMCPAuthenticator authenticator;

    @Override
    public void run() {
        if (registered) {
            return;
        }

        // Resolve password: env var > ~/.ghidra-cred > install-dir/.ghidra-cred
        String password = System.getenv("GHIDRA_SERVER_PASSWORD");
        if (password == null || password.isEmpty()) {
            password = readCredFile(Paths.get(System.getProperty("user.home"), ".ghidra-cred"));
        }
        if (password == null || password.isEmpty()) {
            password = readCredFile(Paths.get(System.getProperty("user.dir"), ".ghidra-cred"));
        }
        if (password == null || password.isEmpty()) {
            return;
        }

        String user = System.getenv("GHIDRA_SERVER_USER");
        if (user == null || user.isEmpty()) {
            user = System.getProperty("user.name");
        }

        authenticator = new GhidraMCPAuthenticator(user, password.toCharArray());
        ClientUtil.setClientAuthenticator(authenticator);
        registered = true;
        System.out.println("[GhidraMCP] Auto-registered server authenticator for user: " + user);
    }

    private static String readCredFile(Path path) {
        try {
            if (Files.exists(path) && Files.isRegularFile(path)) {
                String content = Files.readString(path).trim();
                if (!content.isEmpty()) {
                    System.out.println("[GhidraMCP] Read credentials from: " + path);
                    return content;
                }
            }
        } catch (IOException e) {
            // Silently ignore - file not readable
        }
        return null;
    }

    @Override
    public String getName() {
        return "GhidraMCP Auth";
    }

    public static boolean isRegistered() {
        return registered;
    }

    public static GhidraMCPAuthenticator getAuthenticator() {
        return authenticator;
    }
}
