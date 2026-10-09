package com.xebyte.core;

import ghidra.GhidraApplicationLayout;
import ghidra.base.project.GhidraProject;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.framework.data.ContentHandler;
import ghidra.framework.data.DomainObjectAdapter;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.program.database.DataTypeArchiveContentHandler;
import ghidra.program.database.DataTypeArchiveDB;
import ghidra.program.database.ProgramContentHandler;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.junit.Assert.*;
import static org.junit.Assume.assumeTrue;

/**
 * {@link ProjectPaths#file} / {@link ProjectPaths#folder} against a real temp project,
 * including folder-scope refusal text (sibling-prefix trap).
 */
public class ProjectPathsGhidraTest {

    private Path tmp;
    private GhidraProject ghidraProject;
    private Project project;
    private String previousScope;

    @BeforeClass
    public static void initializeGhidra() throws Exception {
        String installDir = System.getenv("GHIDRA_INSTALL_DIR");
        assumeTrue("GHIDRA_INSTALL_DIR is required for real Ghidra tests",
            installDir != null && !installDir.isBlank());
        if (!Application.isInitialized()) {
            ApplicationConfiguration configuration = new ApplicationConfiguration();
            configuration.setInitializeLogging(false);
            Application.initializeApplication(new GhidraApplicationLayout(new File(installDir)),
                configuration);
        }
        ghidra.framework.protocol.ghidra.Handler.registerHandler();
        installContentHandlers();
    }

    @SuppressWarnings("unchecked")
    private static void installContentHandlers() throws Exception {
        try {
            DomainObjectAdapter.getContentHandler(DataTypeArchiveDB.class);
            return;
        } catch (IOException notFound) {
            // fall through
        }
        Map<String, ContentHandler<?>> byType = new HashMap<>();
        Map<Class<?>, ContentHandler<?>> byClass = new HashMap<>();
        for (ContentHandler<?> h : List.of(new DataTypeArchiveContentHandler(), new ProgramContentHandler())) {
            byType.put(h.getContentType(), h);
            byClass.put(h.getDomainObjectClass(), h);
        }
        Field type = DomainObjectAdapter.class.getDeclaredField("contentHandlerTypeMap");
        Field cls = DomainObjectAdapter.class.getDeclaredField("contentHandlerClassMap");
        type.setAccessible(true);
        cls.setAccessible(true);
        type.set(null, new HashMap<>(byType));
        cls.set(null, new HashMap<>(byClass));
    }

    @Before
    public void setUp() throws Exception {
        tmp = Files.createTempDirectory("project-paths");
        ghidraProject = GhidraProject.createProject(tmp.toString(), "paths", false);
        project = ghidraProject.getProject();
        previousScope = SecurityConfig.getInstance().getProjectFolderScope();
        clearFolderScope();
    }

    @After
    public void tearDown() throws Exception {
        setFolderScope(previousScope);
        if (ghidraProject != null) {
            ghidraProject.close();
        }
        try (Stream<Path> walk = Files.walk(tmp)) {
            walk.sorted(Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
        }
    }

    @Test
    public void folderCreateMissingAndRoot() throws Exception {
        DomainFolder root = ProjectPaths.folder(project, "/", false);
        assertNotNull(root);
        assertEquals("/", root.getPathname());

        DomainFolder nested = ProjectPaths.folder(project, "Mods/PD2", true);
        assertEquals("/Mods/PD2", nested.getPathname());
        assertNotNull(project.getProjectData().getFolder("/Mods/PD2"));

        DomainFolder again = ProjectPaths.folder(project, "/Mods/PD2", false);
        assertEquals("/Mods/PD2", again.getPathname());
    }

    @Test
    public void missingFileAndFolderRefuse() {
        try {
            ProjectPaths.file(project, "/nope.dll");
            fail("expected Refusal");
        } catch (Refusal r) {
            assertEquals("No file at /nope.dll", r.getMessage());
        }
        try {
            ProjectPaths.folder(project, "/missing", false);
            fail("expected Refusal");
        } catch (Refusal r) {
            assertEquals("No folder at /missing", r.getMessage());
        }
    }

    @Test
    public void scopeInsideOutsideAndSiblingPrefixTrap() throws Exception {
        ProjectPaths.folder(project, "/Mods/PD2", true);
        ProjectPaths.folder(project, "/Mods/PD2-S12", true);

        setFolderScope("/Mods/PD2");
        assertEquals("/Mods/PD2", ProjectPaths.folder(project, "/Mods/PD2", false).getPathname());
        try {
            ProjectPaths.folder(project, "/Mods/PD2-S12", false);
            fail("sibling-prefix must not match scope /Mods/PD2");
        } catch (Refusal r) {
            assertEquals(
                "Path is outside this server's project-folder scope: /Mods/PD2-S12",
                r.getMessage());
        }
        try {
            ProjectPaths.folder(project, "/Mods/Other", true);
            fail("create outside scope must refuse");
        } catch (Refusal r) {
            assertEquals(
                "Path is outside this server's project-folder scope: /Mods/Other",
                r.getMessage());
        }
    }

    @Test
    public void ancestorsOfTheScopeListButOnlyItsBranchIsVisible() throws Exception {
        ProjectPaths.folder(project, "/Mods/PD2", true);
        ProjectPaths.folder(project, "/Mods/PD2-S12", true);
        ProjectPaths.folder(project, "/Other", true);
        setFolderScope("/Mods/PD2");

        assertEquals("/", ProjectPaths.listable(project, "/").getPathname());
        assertEquals("/Mods", ProjectPaths.listable(project, "Mods").getPathname());
        assertTrue(ProjectPaths.visible("/Mods"));
        assertTrue(ProjectPaths.visible("/Mods/PD2/sub"));
        assertFalse(ProjectPaths.visible("/Mods/PD2-S12"));
        assertFalse(ProjectPaths.visible("/Other"));
        try {
            ProjectPaths.listable(project, "/Other");
            fail("a folder off the scope's branch must refuse");
        } catch (Refusal r) {
            assertTrue(r.getMessage(), r.getMessage().contains("project-folder scope"));
        }
    }

    @Test
    public void findFileIsNullWhenMissingAndOperatorBypassesScope() throws Exception {
        assertNull(ProjectPaths.findFile(project, "/nope.dll"));
        setFolderScope("/Mods/PD2");
        try {
            ProjectPaths.findFile(project, "/Other/x.dll");
            fail("an agent's lookup stays scoped");
        } catch (Refusal r) {
            assertTrue(r.getMessage(), r.getMessage().contains("project-folder scope"));
        }
        try {
            ProjectPaths.operatorFile(project, "/Other/x.dll");
            fail("expected Refusal for missing operator file");
        } catch (Refusal r) {
            assertEquals("No file at /Other/x.dll", r.getMessage());
        }
    }

    private void setFolderScope(String scope) {
        SecurityConfig.getInstance().setProjectFolderScopeForTest(scope);
    }

    private void clearFolderScope() {
        setFolderScope(null);
    }
}
