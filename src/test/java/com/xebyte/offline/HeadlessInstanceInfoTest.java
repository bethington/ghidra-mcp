package com.xebyte.offline;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.sun.net.httpserver.HttpServer;
import com.xebyte.headless.GhidraMCPHeadlessServer;
import com.xebyte.headless.HeadlessProgramProvider;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectLocator;
import ghidra.program.model.listing.Program;
import org.junit.Before;
import org.junit.Test;

import java.net.InetSocketAddress;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

/** Pins the identity contract required by eager bridge connections to headless servers. */
public class HeadlessInstanceInfoTest {
    private GhidraMCPHeadlessServer server;
    private HeadlessProgramProvider provider;

    @Before
    public void setUp() throws Exception {
        server = new GhidraMCPHeadlessServer();
        provider = mock(HeadlessProgramProvider.class);
        when(provider.getAllOpenPrograms()).thenReturn(new Program[0]);
        HttpServer http = mock(HttpServer.class);
        when(http.getAddress()).thenReturn(new InetSocketAddress("127.0.0.1", 19089));
        setField("programProvider", provider);
        setField("server", http);
    }

    private void setField(String name, Object value) throws Exception {
        var field = GhidraMCPHeadlessServer.class.getDeclaredField(name);
        field.setAccessible(true);
        field.set(server, value);
    }

    private JsonObject info() throws Exception {
        var method = GhidraMCPHeadlessServer.class.getDeclaredMethod("buildInstanceInfoJson");
        method.setAccessible(true);
        return JsonParser.parseString((String) method.invoke(server)).getAsJsonObject();
    }

    @Test
    public void emptyServerHasProcessIdentityAndActualBoundPort() throws Exception {
        JsonObject info = info();
        assertEquals(ProcessHandle.current().pid(), info.get("pid").getAsLong());
        assertEquals("unknown", info.get("project").getAsString());
        assertEquals("", info.get("project_path").getAsString());
        assertEquals(19089, info.get("tcp_port").getAsInt());
        assertEquals(0, info.getAsJsonArray("programs").size());
    }

    @Test
    public void identityTracksProjectOpenAndClose() throws Exception {
        Project project = mock(Project.class);
        ProjectLocator locator = mock(ProjectLocator.class);
        when(locator.toString()).thenReturn("/projects/alpha");
        when(project.getName()).thenReturn("alpha");
        when(project.getProjectLocator()).thenReturn(locator);
        when(provider.getProject()).thenReturn(project);
        assertEquals("alpha", info().get("project").getAsString());
        assertEquals(locator.toString(), info().get("project_path").getAsString());
        when(provider.getProject()).thenReturn(null);
        assertEquals("", info().get("project_path").getAsString());
    }

    @Test
    public void reportsOpenProgramsWithoutRequiringSavedDomainFiles() throws Exception {
        Program program = mock(Program.class);
        when(program.getName()).thenReturn("sample.exe");
        when(provider.getAllOpenPrograms()).thenReturn(new Program[] { program });
        JsonObject entry = info().getAsJsonArray("programs").get(0).getAsJsonObject();
        assertEquals("sample.exe", entry.get("name").getAsString());
        assertTrue(entry.get("open").getAsBoolean());
    }

    @Test
    public void instanceMetadataIsNotAuthExempt() throws Exception {
        var method = GhidraMCPHeadlessServer.class.getDeclaredMethod("isAuthExempt", String.class);
        method.setAccessible(true);
        assertEquals(false, method.invoke(null, "/mcp/instance_info"));
    }
}
