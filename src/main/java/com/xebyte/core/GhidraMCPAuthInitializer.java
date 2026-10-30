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

/**
 * Registers the GhidraMCP server authenticator at application startup,
 * before any project is opened. This bypasses the GUI password dialog.
 *
 * This class implements ModuleInitializer (an ExtensionPoint), which Ghidra's
 * ClassSearcher discovers and executes during Application.initializeApplication().
 * This runs well before plugins load and before any project/server connection.
 *
 * Credentials come from server-scope settings ({@code ghidra_server.user} /
 * {@code ghidra_server.password}) in the process environment and standard
 * {@code .env} files ({@code user.dir}, then {@code user.home}).
 */
public class GhidraMCPAuthInitializer implements ModuleInitializer {

    @Override
    public void run() {
        ServerCredentials.registerFromSettings();
    }

    @Override
    public String getName() {
        return "GhidraMCP Auth";
    }
}
