package com.xebyte.offline;

import com.xebyte.core.DecompTreeService;
import com.xebyte.core.JsonHelper;
import com.xebyte.core.ProgramProvider;
import com.xebyte.core.Response;
import com.xebyte.core.SettingsService;
import com.xebyte.core.tree.TreeLayout;
import com.xebyte.core.tree.TreeRegistry;
import com.xebyte.core.settings.Scope;
import com.xebyte.core.settings.ScopeStore;
import com.xebyte.core.settings.SettingsRegistry;
import com.xebyte.core.settings.ProjectStores;
import com.xebyte.core.settings.SettingsResolver;
import ghidra.framework.model.DomainFile;
import ghidra.framework.options.Options;
import ghidra.program.model.listing.Program;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.Map;
import java.util.stream.Stream;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/** {@code decompile_tree_create} resolves omitted parameters from tree.* settings. */
public class TreeCreateSettingsTest {

    private static final SettingsRegistry REG = SettingsRegistry.DEFAULT;
    private static final String DOMAIN = "/settings-test/app.exe";
    private static final com.xebyte.core.ThreadingStrategy THREADING =
        new com.xebyte.headless.DirectThreadingStrategy();

    private final TreeRegistry registry = TreeRegistry.getInstance();
    private Path root;

    @Before
    public void setUp() throws Exception {
        registry.clearForTests();
        root = Files.createTempDirectory("tree-settings").toAbsolutePath().normalize();
        com.xebyte.core.settings.ServerSettings.resetForTests();
    }

    @After
    public void tearDown() throws Exception {
        registry.clearForTests();
        com.xebyte.core.settings.ServerSettings.resetForTests();
        if (root != null && Files.exists(root)) {
            try (Stream<Path> walk = Files.walk(root)) {
                for (Path p : walk.sorted(Comparator.reverseOrder()).toList()) {
                    Files.deleteIfExists(p);
                }
            }
        }
    }

    @Test
    public void omittedParamsUseSettingsResolvedValues() throws Exception {
        String bandEnv = REG.get("tree.band_size").envName();
        String disasmEnv = REG.get("tree.disassemble_missing").envName();
        Program program = program();
        ProgramProvider provider = provider(program);
        SettingsService settings = new SettingsService(provider,
            Map.of(bandEnv, "42", disasmEnv, "true"));
        DecompTreeService svc = new DecompTreeService(provider, THREADING, settings);

        Response r = svc.treeCreate(program, root.toString(), null, null, null, null, null,
                null, null, null, null);
        assertTrue(r instanceof Response.Ok);

        Map<String, Object> disk = JsonHelper.parseJson(Files.readString(
                root.resolve(TreeLayout.treeJson()), StandardCharsets.UTF_8));
        assertEquals(42, ((Number) disk.get("band_size")).intValue());
        assertEquals(true, disk.get("disassemble_missing"));
        assertEquals(30, ((Number) disk.get("decompile_timeout_seconds")).intValue());
    }

    @Test
    public void explicitParamBeatsSetting() throws Exception {
        String bandEnv = REG.get("tree.band_size").envName();
        Program program = program();
        ProgramProvider provider = provider(program);
        SettingsService settings = new SettingsService(provider, Map.of(bandEnv, "42"));
        DecompTreeService svc = new DecompTreeService(provider, THREADING, settings);

        Response r = svc.treeCreate(program, root.toString(), null, 7, null, null, null,
                null, null, null, null);
        assertTrue(r instanceof Response.Ok);

        Map<String, Object> disk = JsonHelper.parseJson(Files.readString(
                root.resolve(TreeLayout.treeJson()), StandardCharsets.UTF_8));
        assertEquals(7, ((Number) disk.get("band_size")).intValue());
    }

    @Test
    public void projectScopeOverridesServer() {
        String key = "tree.band_size";
        Map<Scope, ScopeStore> stores = new EnumMap<>(Scope.class);
        stores.put(Scope.SERVER, ScopeStore.server(
            Map.of(REG.get(key).envName(), "15"), Map.of()));
        stores.put(Scope.PROJECT, ScopeStore.memory(Map.of(key, "25")));
        SettingsResolver.Resolution r = SettingsResolver.resolve(REG.get(key), stores);
        assertEquals(25L, r.value());
        assertEquals(Scope.PROJECT, r.source());
    }

    @Test
    public void disassembleMissingFalseWhenUnset() throws Exception {
        Program program = program();
        ProgramProvider provider = provider(program);
        DecompTreeService svc = new DecompTreeService(provider, THREADING, new SettingsService(provider));

        Response r = svc.treeCreate(program, root.toString(), null, null, null, null, null,
                null, null, null, null);
        assertTrue(r instanceof Response.Ok);

        Map<String, Object> disk = JsonHelper.parseJson(Files.readString(
                root.resolve(TreeLayout.treeJson()), StandardCharsets.UTF_8));
        assertEquals(false, disk.get("disassemble_missing"));
    }

    @Test
    public void resolvedConfigIsFrozenOnDiskWhenSettingsChange() throws Exception {
        String bandEnv = REG.get("tree.band_size").envName();
        Program program = program();
        ProgramProvider provider = provider(program);
        SettingsService settings = new SettingsService(provider, Map.of(bandEnv, "33"));
        DecompTreeService svc = new DecompTreeService(provider, THREADING, settings);

        Response r = svc.treeCreate(program, root.toString(), null, null, null, null, null,
                null, null, null, null);
        assertTrue(r instanceof Response.Ok);
        Map<String, Object> first = JsonHelper.parseJson(Files.readString(
                root.resolve(TreeLayout.treeJson()), StandardCharsets.UTF_8));
        assertEquals(33, ((Number) first.get("band_size")).intValue());

        SettingsService later = new SettingsService(provider, Map.of(bandEnv, "99"));
        DecompTreeService laterSvc = new DecompTreeService(provider, THREADING, later);
        Response status = laterSvc.treeStatus(registry.all().iterator().next().id());
        assertTrue(status instanceof Response.Ok);
        Map<String, Object> still = JsonHelper.parseJson(Files.readString(
                root.resolve(TreeLayout.treeJson()), StandardCharsets.UTF_8));
        assertEquals(33, ((Number) still.get("band_size")).intValue());
    }

    private static Program program() {
        DomainFile df = mock(DomainFile.class);
        when(df.getPathname()).thenReturn(DOMAIN);
        Options opts = mock(Options.class);
        when(opts.contains(anyString())).thenReturn(false);
        Program p = mock(Program.class);
        when(p.getDomainFile()).thenReturn(df);
        when(p.getName()).thenReturn("app.exe");
        when(p.isClosed()).thenReturn(false);
        when(p.getModificationNumber()).thenReturn(1L);
        when(p.getOptions(ProjectStores.OPTIONS_NAME)).thenReturn(opts);
        return p;
    }

    private static ProgramProvider provider(Program program) {
        ProgramProvider provider = mock(ProgramProvider.class);
        when(provider.getAllOpenPrograms()).thenReturn(new Program[] {program});
        when(provider.getProgram(anyString())).thenReturn(program);
        when(provider.resolveProgram(anyString())).thenReturn(program);
        when(provider.getProject()).thenReturn(null);
        return provider;
    }
}
