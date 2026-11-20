package com.xebyte.core;

import com.xebyte.headless.HeadlessManagementService;
import com.xebyte.headless.HeadlessProgramProvider;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.Map;
import java.util.stream.Stream;

import static org.junit.Assert.*;
import static org.junit.Assume.assumeTrue;

/**
 * #656: {@code /create_project} must hand back a path that reopens the project.
 *
 * <p>It returned {@code parentDir/name} -- Ghidra's locator form, which is not on disk
 * (Ghidra writes {@code name.gpr} and {@code name.rep}) -- and {@code /open_project}
 * read a non-{@code .gpr} path as a directory to scan, so the documented
 * create -> open sequence failed with "No .gpr file found". This drives the real
 * service and the real Ghidra project code in a temp directory.
 */
public class HeadlessCreateProjectGhidraTest {

    private Path tmp;
    private HeadlessProgramProvider provider;
    private HeadlessManagementService service;

    @BeforeClass
    public static void initializeGhidra() {
        String installDir = System.getenv("GHIDRA_INSTALL_DIR");
        assumeTrue("GHIDRA_INSTALL_DIR is required for real Ghidra tests",
            installDir != null && !installDir.isBlank());
        assumeTrue("a configured GHIDRA_MCP_FILE_ROOT would deny the temp directory",
            SecurityConfig.getInstance().getFileRoot() == null);
        if (!Application.isInitialized()) {
            ApplicationConfiguration configuration = new ApplicationConfiguration();
            configuration.setInitializeLogging(false);
            try {
                Application.initializeApplication(new GhidraApplicationLayout(new File(installDir)),
                    configuration);
            } catch (Exception e) {
                throw new AssertionError("Ghidra failed to initialize from " + installDir, e);
            }
        }
        // ProjectLocator forms a ghidra: URL; the servers register this at startup.
        ghidra.framework.protocol.ghidra.Handler.registerHandler();
    }

    @Before
    public void setUp() throws Exception {
        tmp = Files.createTempDirectory("create-project");
        provider = new HeadlessProgramProvider();
        service = new HeadlessManagementService(provider, null);
    }

    @After
    public void tearDown() throws Exception {
        if (provider != null) {
            provider.closeProject();
        }
        try (Stream<Path> walk = Files.walk(tmp)) {
            walk.sorted(Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> ok(Response r) {
        assertTrue("expected success, got " + r.toJson(), r instanceof Response.Ok);
        return (Map<String, Object>) ((Response.Ok) r).data();
    }

    private static String err(Response r) {
        assertTrue("expected an error, got " + r.toJson(), r instanceof Response.Err);
        return ((Response.Err) r).message();
    }

    private String create(String name) {
        Map<String, Object> body = ok(service.createProject(tmp.toString(), name));
        return (String) body.get("path");
    }

    @Test
    public void createReturnsTheGprPathAndItReopensTheProject() {
        String path = create("RoundTrip");
        File gpr = new File(path);
        assertTrue("path must name the marker file: " + path, gpr.getName().equals("RoundTrip.gpr"));
        assertTrue("returned path must exist on disk: " + path, gpr.isFile());
        assertTrue(new File(gpr.getParentFile(), "RoundTrip.rep").isDirectory());

        // instance_info reports the same path both servers can reopen.
        assertEquals(gpr.getAbsolutePath(), McpHttpServer.projectPath(provider.getProject()));

        ok(service.closeProject());
        Map<String, Object> opened = ok(service.openProject(path));
        assertEquals("RoundTrip", opened.get("project"));
        assertEquals(gpr.getAbsolutePath(), McpHttpServer.projectPath(provider.getProject()));
    }

    @Test
    public void theOldExtensionlessLocatorStillOpens() {
        create("Legacy");
        ok(service.closeProject());
        String locator = new File(tmp.toFile(), "Legacy").getPath();
        assertFalse("the locator form is not a path on disk", new File(locator).exists());
        Map<String, Object> opened = ok(service.openProject(locator));
        assertEquals("Legacy", opened.get("project"));
    }

    @Test
    public void aDirectoryWithOneProjectOpensIt() {
        create("Only");
        ok(service.closeProject());
        assertEquals("Only", ok(service.openProject(tmp.toString())).get("project"));
    }

    @Test
    public void aDirectoryWithSeveralProjectsIsRefusedNotGuessed() {
        String first = create("First");
        String second = create("Second");
        ok(service.closeProject());

        String message = err(service.openProject(tmp.toString()));
        assertTrue(message, message.contains(first));
        assertTrue(message, message.contains(second));
        assertFalse("nothing may be opened on an ambiguous path", provider.hasProject());

        // ...and delete through the same resolver deletes nothing.
        String deleteMessage = err(service.deleteProject(tmp.toString()));
        assertTrue(deleteMessage, deleteMessage.contains("holds 2 Ghidra projects"));
        assertTrue(new File(first).isFile());
        assertTrue(new File(second).isFile());
    }

    @Test
    public void deleteByReturnedPathRemovesBothSiblings() {
        String path = create("Doomed");
        Map<String, Object> deleted = ok(service.deleteProject(path));
        assertEquals(new File(path).getAbsolutePath(), deleted.get("deleted"));
        assertFalse(new File(path).exists());
        assertFalse(new File(tmp.toFile(), "Doomed.rep").exists());
        assertFalse("deleting the open project closes it", provider.hasProject());
    }
}
