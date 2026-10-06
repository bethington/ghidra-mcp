package com.xebyte.core;

import com.xebyte.core.settings.ProjectStores;
import com.xebyte.headless.DirectThreadingStrategy;
import com.xebyte.core.settings.ScopeStore;
import com.xebyte.core.settings.SettingKey;
import com.xebyte.core.settings.SettingsRegistry;
import ghidra.GhidraApplicationLayout;
import ghidra.base.project.GhidraProject;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.framework.data.ContentHandler;
import ghidra.framework.data.DomainObjectAdapter;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.Project;
import ghidra.program.database.DataTypeArchiveContentHandler;
import ghidra.program.database.DataTypeArchiveDB;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramContentHandler;
import ghidra.program.model.listing.Program;
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
import java.util.Optional;
import java.util.stream.Stream;

import static org.junit.Assert.*;
import static org.junit.Assume.assumeTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/** The settings stores against a real (local, unshared) project and program. */
public class SettingsStoresGhidraTest {

    private static final SettingKey AUTOLOAD = SettingsRegistry.DEFAULT.get("tools.autoload");
    private static final SettingKey LAST = SettingsRegistry.DEFAULT.get("tools.last_loaded");

    private Path tmp;
    private GhidraProject ghidraProject;
    private Project project;

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
        // project locators form ghidra: URLs; a server registers the handler at startup
        ghidra.framework.protocol.ghidra.Handler.registerHandler();
        installContentHandlers();
    }

    /**
     * Creating a project file needs the {@link ContentHandler} for its type. A server finds
     * them through {@code ClassSearcher} under Ghidra's class loader; on Maven's flat test
     * classpath the search finds none, so the two this test needs are installed directly.
     */
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
        tmp = Files.createTempDirectory("settings-stores");
        ghidraProject = GhidraProject.createProject(tmp.toString(), "settings", false);
        project = ghidraProject.getProject();
    }

    @After
    public void tearDown() throws Exception {
        if (ghidraProject != null) {
            ghidraProject.close();
        }
        try (Stream<Path> walk = Files.walk(tmp)) {
            walk.sorted(Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
        }
    }

    @Test
    public void theSharedStoreCreatesItsArchiveOnFirstWriteAndAnotherInstanceReadsIt() {
        ScopeStore first = ProjectStores.shared(project);
        assertEquals(Optional.empty(), first.read(AUTOLOAD));
        assertNull(project.getProjectData().getFile(ProjectStores.ARCHIVE_PATH));

        first.write(AUTOLOAD, "+datatype");
        DomainFile archive = project.getProjectData().getFile(ProjectStores.ARCHIVE_PATH);
        assertNotNull(archive);
        assertTrue(ProjectStores.isSettingsArchive(archive));
        assertEquals(Optional.of("+datatype"), first.read(AUTOLOAD));

        ScopeStore second = ProjectStores.shared(project);
        assertEquals(Optional.of("+datatype"), second.read(AUTOLOAD));

        first.write(AUTOLOAD, "+memory");
        assertEquals("a write through one store is seen by the other",
            Optional.of("+memory"), second.read(AUTOLOAD));
        second.remove(AUTOLOAD);
        assertEquals(Optional.empty(), first.read(AUTOLOAD));
    }

    @Test
    public void theLocalStoreLivesInTheProjectDirectoryAndSurvivesANewInstance() throws Exception {
        ProjectStores.local(project).write(LAST, "memory,datatype");
        Path file = project.getProjectLocator().getProjectDir().toPath()
            .resolve("ghidra-mcp-settings.properties");
        assertTrue(Files.isRegularFile(file));
        assertEquals(Optional.of("memory,datatype"), ProjectStores.local(project).read(LAST));
        assertNull("local values never become a project file",
            project.getProjectData().getFile(ProjectStores.ARCHIVE_PATH));
    }

    @Test
    public void theProgramStoreUsesTheProgramsOptions() throws Exception {
        ProgramBuilder builder = new ProgramBuilder("p", ProgramBuilder._X64, "gcc", this);
        try {
            Program program = builder.getProgram();
            ScopeStore store = ProjectStores.program(program);
            store.write(AUTOLOAD, "+xref");
            assertEquals("+xref", program.getOptions(ProjectStores.OPTIONS_NAME).getString("tools.autoload", null));
            assertEquals(Optional.of("+xref"), store.read(AUTOLOAD));
            store.remove(AUTOLOAD);
            assertEquals(Optional.empty(), store.read(AUTOLOAD));
        } finally {
            builder.dispose();
        }
    }

    @Test
    public void setSettingWritesTheChosenScopeAndGetSettingsReportsIt() {
        ProgramProvider provider = mock(ProgramProvider.class);
        when(provider.getProject()).thenReturn(project);
        SettingsService settings = new SettingsService(provider, Map.of("GHIDRA_MCP_SCRIPTS_ALLOW", "1"));

        Response set = settings.setSetting("tools.autoload", "+datatype", "project", false, "");
        assertTrue(set.toString(), set instanceof Response.Ok);
        Response local = settings.setSetting("tools.autoload", "-program", "local", false, "");
        assertTrue(local.toString(), local instanceof Response.Ok);
        assertEquals(List.of("listing", "function", "datatype"), settings.value("tools.autoload", null));

        // a guardrail the operator allowed can be tightened locally, and not loosened back
        assertTrue(settings.setSetting("scripts.allow", "false", "local", false, "") instanceof Response.Ok);
        assertEquals(false, settings.value("scripts.allow", null));
        Response unset = settings.setSetting("scripts.allow", "", "local", true, "");
        assertTrue(unset.toString(), unset instanceof Response.Err);
        assertTrue(((Response.Err) unset).message().contains("only be made stricter"));

        Response secret = settings.setSetting("auth.token", "x", "local", false, "");
        assertTrue(secret instanceof Response.Err);

        String listing = settings.getSettings("tools", "").toString();
        assertTrue(listing, listing.contains("tools.autoload"));
        assertFalse(listing, listing.contains("scripts.allow"));
    }

    @Test
    public void projectListingsDoNotShowTheArchiveAndFileToolsRefuseIt() {
        ProjectStores.shared(project).write(AUTOLOAD, "+datatype");
        ProgramProvider provider = mock(ProgramProvider.class);
        when(provider.getProject()).thenReturn(project);
        ProgramScriptService scripts = new ProgramScriptService(provider, new DirectThreadingStrategy());

        assertFalse(scripts.listProjectFiles("/").toString().contains(".ghidra-mcp"));
        Response delete = scripts.deleteFile(ProjectStores.ARCHIVE_PATH);
        assertTrue(delete instanceof Response.Err);
        assertTrue(((Response.Err) delete).message().contains("set_setting"));
        assertTrue(scripts.moveFile(ProjectStores.ARCHIVE_PATH, "/elsewhere") instanceof Response.Err);
        assertNotNull(project.getProjectData().getFile(ProjectStores.ARCHIVE_PATH));
    }
}
