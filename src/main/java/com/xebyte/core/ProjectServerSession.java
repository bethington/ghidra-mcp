package com.xebyte.core;

import ghidra.framework.client.RepositoryAdapter;
import ghidra.framework.client.RepositoryServerAdapter;
import ghidra.framework.model.Project;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The server connection of the open project. The GUI's session: it never connects, since
 * a shared project is already bound to its server, and reports what that project holds.
 * A local-only project has no server.
 */
public final class ProjectServerSession implements ServerSession {

    private final ProgramProvider provider;

    public ProjectServerSession(ProgramProvider provider) {
        this.provider = provider;
    }

    private RepositoryAdapter repository() {
        Project project = provider.getProject();
        return project != null ? project.getProjectData().getRepository() : null;
    }

    @Override
    public RepositoryServerAdapter server() {
        RepositoryAdapter repo = repository();
        RepositoryServerAdapter server = repo != null ? repo.getServer() : null;
        return server != null && server.isConnected() ? server : null;
    }

    @Override
    public Response connect() {
        Project project = provider.getProject();
        if (project == null) {
            return Response.err("No project open in Ghidra");
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("status", "connected");
        out.put("project", project.getName());
        out.put("shared", repository() != null);
        out.put("message", "The open project is the connection. There is nothing to establish; "
            + "open a shared project to reach a Ghidra Server.");
        return Response.ok(out);
    }

    @Override
    public Response disconnect() {
        return Response.ok(Map.of("status", "ok",
            "message", "The open project holds the connection. There is nothing to disconnect."));
    }

    @Override
    public void useCredentials(String username, char[] password) {
        GhidraMCPAuthenticator.register(username, password);
    }

    @Override
    public Map<String, Object> status() {
        RepositoryAdapter repo = repository();
        Map<String, Object> out = new LinkedHashMap<>();
        boolean connected = false;
        if (repo != null) {
            try {
                connected = repo.isConnected();
                out.put("server_info", String.valueOf(repo.getServerInfo()));
            } catch (Exception e) {
                out.put("last_error", e.getMessage());
            }
            out.put("repository", repo.getName());
        }
        out.put("connected", connected);
        out.put("shared_project", repo != null);
        return out;
    }
}
