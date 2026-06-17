package com.xebyte.offline.vuln;

import com.xebyte.core.vuln.SinkCatalog;
import com.xebyte.core.vuln.CatalogEntry;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionTag;
import org.junit.Test;
import java.util.List;
import java.util.Set;
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class SinkCatalogTest {

    @Test
    public void load_bakedInResource_parsesAllEntries() {
        SinkCatalog cat = SinkCatalog.load(null);
        assertNull(cat.status());
        assertTrue(cat.sinks().size() >= 5);
        assertTrue(cat.sources().size() >= 4);
        CatalogEntry memcpy = cat.byId("memcpy");
        assertNotNull(memcpy);
        assertEquals("copy", memcpy.vulnClass());
        assertEquals(Integer.valueOf(2), memcpy.arg("size_arg"));
        assertEquals(Integer.valueOf(0), memcpy.arg("dst_arg"));
    }

    @Test
    public void resolve_byImportName_matchesExternal() {
        SinkCatalog cat = SinkCatalog.load(null);
        Function f = mock(Function.class);
        when(f.isExternal()).thenReturn(true);
        when(f.getName()).thenReturn("memcpy");
        when(f.getTags()).thenReturn(Set.of());
        List<CatalogEntry> hits = cat.resolve(f);
        assertTrue(hits.stream().anyMatch(e -> e.id().equals("memcpy")));
    }

    @Test
    public void resolve_byRegex_matchesRenamedInternal() {
        SinkCatalog cat = SinkCatalog.load(null);
        Function f = mock(Function.class);
        when(f.isExternal()).thenReturn(false);
        when(f.getName()).thenReturn("Crt_MemCpy_Fast");
        when(f.getTags()).thenReturn(Set.of());
        List<CatalogEntry> hits = cat.resolve(f);
        assertTrue(hits.stream().anyMatch(e -> e.id().equals("memcpy")));
    }

    @Test
    public void resolve_byTag_matchesTaggedFunction() {
        SinkCatalog cat = SinkCatalog.load(null);
        Function f = mock(Function.class);
        FunctionTag tag = mock(FunctionTag.class);
        when(tag.getName()).thenReturn("SINK_FORMAT");
        when(f.isExternal()).thenReturn(false);
        when(f.getName()).thenReturn("FUN_00401234");
        when(f.getTags()).thenReturn(Set.of(tag));
        List<CatalogEntry> hits = cat.resolve(f);
        assertTrue(hits.stream().anyMatch(e -> e.id().equals("printf")));
    }

    @Test
    public void resolve_noMatch_returnsEmpty() {
        SinkCatalog cat = SinkCatalog.load(null);
        Function f = mock(Function.class);
        when(f.isExternal()).thenReturn(false);
        when(f.getName()).thenReturn("DoBusinessLogic");
        when(f.getTags()).thenReturn(Set.of());
        assertTrue(cat.resolve(f).isEmpty());
    }

    @Test
    public void load_overrideMerges_userEntryWinsOnId() throws Exception {
        java.io.File tmp = java.io.File.createTempFile("vuln_cat_override", ".json");
        tmp.deleteOnExit();
        java.nio.file.Files.writeString(tmp.toPath(),
            "{\"sinks\":[{\"id\":\"memcpy\",\"class\":\"copy\",\"size_arg\":3,\"dst_arg\":1," +
            "\"match\":{\"tag\":[\"MY_MEMCPY\"]}}]}");
        SinkCatalog cat = SinkCatalog.load(tmp.getAbsolutePath());
        CatalogEntry e = cat.byId("memcpy");
        assertEquals(Integer.valueOf(3), e.arg("size_arg"));
        assertNotNull(cat.byId("strcpy"));
    }

    @Test
    public void load_malformedOverride_fallsBackWithStatus() throws Exception {
        java.io.File tmp = java.io.File.createTempFile("vuln_cat_bad", ".json");
        tmp.deleteOnExit();
        java.nio.file.Files.writeString(tmp.toPath(), "{not json");
        SinkCatalog cat = SinkCatalog.load(tmp.getAbsolutePath());
        assertNotNull(cat.byId("memcpy"));
        assertNotNull(cat.status());
        assertTrue(cat.status().contains("override"));
    }

    @Test
    public void resolve_overrideRegex_unanchoredSubstringMatchesViaFind() throws Exception {
        // .find() (not .matches()) so bare substrings in user overrides work.
        java.io.File tmp = java.io.File.createTempFile("vuln_cat_re", ".json");
        tmp.deleteOnExit();
        java.nio.file.Files.writeString(tmp.toPath(),
            "{\"sinks\":[{\"id\":\"custom_copy\",\"class\":\"copy\",\"dst_arg\":0," +
            "\"match\":{\"regex\":[\"FastCopy\"]}}]}");
        SinkCatalog cat = SinkCatalog.load(tmp.getAbsolutePath());
        ghidra.program.model.listing.Function f = mock(ghidra.program.model.listing.Function.class);
        when(f.isExternal()).thenReturn(false);
        when(f.getName()).thenReturn("Rtos_FastCopy_Impl");
        when(f.getTags()).thenReturn(java.util.Set.of());
        assertTrue(cat.resolve(f).stream().anyMatch(e -> e.id().equals("custom_copy")));
    }

    @Test
    public void resolve_internalExactName_importMatchesWithoutExternalFlag() {
        // I3: a non-external function literally named "recv" must import-match.
        SinkCatalog cat = SinkCatalog.load(null);
        Function f = mock(Function.class);
        when(f.isThunk()).thenReturn(false);
        when(f.isExternal()).thenReturn(false);
        when(f.getName()).thenReturn("recv");
        when(f.getTags()).thenReturn(java.util.Set.of());
        assertTrue(cat.resolve(f).stream().anyMatch(e -> e.id().equals("recv")));
    }

    @Test
    public void resolve_thunk_followsToReal() {
        SinkCatalog cat = SinkCatalog.load(null);
        Function real = mock(Function.class);
        when(real.isThunk()).thenReturn(false);
        when(real.getName()).thenReturn("system");
        when(real.getTags()).thenReturn(java.util.Set.of());
        Function thunk = mock(Function.class);
        when(thunk.isThunk()).thenReturn(true);
        when(thunk.getThunkedFunction(true)).thenReturn(real);
        assertTrue(cat.resolve(thunk).stream().anyMatch(e -> e.id().equals("system")));
    }

    @Test
    public void load_overrideWithBadRegex_skipsAndReportsInStatus() throws Exception {
        // I2: invalid regex surfaces at load() time via status(), not at resolve().
        java.io.File tmp = java.io.File.createTempFile("vuln_cat_badre", ".json");
        tmp.deleteOnExit();
        java.nio.file.Files.writeString(tmp.toPath(),
            "{\"sinks\":[{\"id\":\"bad\",\"class\":\"copy\",\"match\":{\"regex\":[\"[\"]}}]}");
        SinkCatalog cat = SinkCatalog.load(tmp.getAbsolutePath());
        assertNotNull(cat.status());
        assertTrue(cat.status().toLowerCase().contains("regex"));
        // resolve must not throw for any name now
        Function f = mock(Function.class);
        when(f.isThunk()).thenReturn(false);
        when(f.getName()).thenReturn("anything");
        when(f.getTags()).thenReturn(java.util.Set.of());
        cat.resolve(f); // no exception
    }

    @Test
    public void all_isUnmodifiable() {
        SinkCatalog cat = SinkCatalog.load(null);
        try { cat.all().clear(); fail("all() must be unmodifiable"); }
        catch (UnsupportedOperationException expected) {}
    }
}
