package com.xebyte.core;

import com.xebyte.headless.DirectThreadingStrategy;
import com.xebyte.headless.HeadlessProgramProvider;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Library;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.util.task.TaskMonitor;
import org.junit.*;

import java.util.*;

import static org.junit.Assert.*;

/** Real disposable Ghidra program only: no server, saved project or target execution. */
public class DataTypeServiceGlobalProvenanceGhidraTest {
    private ProgramBuilder builder;
    private ProgramDB program;
    private DataTypeService service;
    private AnalysisService analysis;

    @BeforeClass public static void initializeGhidra() throws Exception {
        String install = System.getenv("GHIDRA_INSTALL_DIR");
        org.junit.Assume.assumeTrue(install != null && !install.isBlank());
        if (!ghidra.framework.Application.isInitialized()) {
            var config = new ghidra.framework.ApplicationConfiguration();
            config.setInitializeLogging(false);
            ghidra.framework.Application.initializeApplication(
                new ghidra.GhidraApplicationLayout(new java.io.File(install)), config);
        }
        ghidra.util.classfinder.ClassSearcher.search(TaskMonitor.DUMMY);
    }

    @Before public void setUp() throws Exception {
        builder = new ProgramBuilder("global-provenance-fixture", ProgramBuilder._X64, "gcc", this);
        program = builder.getProgram();
        builder.createMemory(".data", "0x10000", 0x1000);
        int tx = program.startTransaction("Fixture uninitialized blocks");
        try {
            program.getMemory().createUninitializedBlock("EXTERNAL", addr(0x80000), 0x1000, false);
            program.getMemory().createUninitializedBlock(".bss", addr(0x20000), 0x1000, false);
        } finally { program.endTransaction(tx, true); }
        HeadlessProgramProvider provider = new HeadlessProgramProvider();
        provider.trackOpenProgram(program);
        var threading = new DirectThreadingStrategy();
        service = new DataTypeService(provider, threading);
        analysis = new AnalysisService(provider, threading, new FunctionService(provider, threading));
    }

    @After public void tearDown() { if (builder != null) builder.dispose(); }

    private Address addr(long value) { return program.getAddressFactory().getDefaultAddressSpace().getAddress(value); }

    private Symbol label(long address, String name, SourceType source) throws Exception {
        int tx = program.startTransaction("Fixture symbol");
        try {
            Symbol result = program.getSymbolTable().createLabel(addr(address), name, source);
            result.setPrimary();
            return result;
        } finally { program.endTransaction(tx, true); }
    }

    private void type(long address, DataType type) throws Exception {
        int tx = program.startTransaction("Fixture data");
        try { program.getListing().createData(addr(address), type); }
        finally { program.endTransaction(tx, true); }
    }

    private Map<String, Object> audit(long address) { return DataTypeService.auditGlobalAt(program, addr(address)); }

    @SuppressWarnings("unchecked") private Map<String, Object> facts(Map<String, Object> audit) {
        return (Map<String, Object>) audit.get("provenance");
    }

    @SuppressWarnings("unchecked") private List<String> issues(Map<String, Object> audit) {
        return (List<String>) audit.get("issues");
    }

    @SuppressWarnings("unchecked") private Map<String, Object> data(Response response) {
        assertTrue(response.toJson(), response instanceof Response.Ok);
        return (Map<String, Object>) ((Response.Ok) response).data();
    }

    private void assertApplicableWithStorageIssues(long address) {
        Map<String, Object> result = audit(address);
        assertEquals(result.toString(), true, result.get("applicable"));
        assertTrue(result.toString(), issues(result).contains("missing_plate_comment"));
        assertEquals(false, facts(result).get("linkage_placeholder"));
    }

    @Test public void importedUninitializedExternalPlaceholderIsEvidenceNotAFreeCompleteScore() throws Exception {
        label(0x80000, "__nativeTypeMetadata", SourceType.IMPORTED);
        Map<String, Object> result = audit(0x80000);
        assertEquals(result.toString(), false, result.get("applicable"));
        assertEquals("external_linkage_placeholder", result.get("reason"));
        assertEquals(false, result.get("fully_documented"));
        assertTrue(issues(result).isEmpty());
        assertEquals(true, facts(result).get("has_imported_identity"));
        assertEquals(false, facts(result).get("defined_data_containing_address"));
        Map<String, Object> score = DataTypeService.scoreGlobalCompletenessAt(program, addr(0x80000));
        assertEquals(false, score.get("applicable"));
        assertNull(score.get("score"));
        assertNull(score.get("effective_score"));
        assertNull(score.get("band"));
    }

    @Test public void separateExternalLocationWithoutRamAssociationDoesNotInventProvenance() throws Exception {
        label(0x80000, "__nativeUnassociated", SourceType.ANALYSIS);
        int tx = program.startTransaction("Fixture loader-style external identity");
        try {
            ExternalLocation external = program.getExternalManager().addExtLocation(
                    Library.UNKNOWN, "__nativeUnassociated", null, SourceType.IMPORTED);
            assertNull(external.getAddress());
        } finally { program.endTransaction(tx, true); }
        assertApplicableWithStorageIssues(0x80000);
        assertEquals(false, facts(audit(0x80000)).get("has_imported_identity"));
        // Match the Mach-O loader's separate imported RAM label explicitly.
        label(0x80000, "_$sNativeUnassociated", SourceType.IMPORTED);
        label(0x80000, "__nativeUnassociated", SourceType.ANALYSIS);
        assertEquals(false, audit(0x80000).get("applicable"));
    }

    @Test public void realGotSlotRetainsBindingAndTypePlateDeductions() throws Exception {
        label(0x80000, "__nativeArrayStorage", SourceType.IMPORTED);
        label(0x10000, "PTR___nativeArrayStorage", SourceType.IMPORTED);
        type(0x10000, new PointerDataType(null, 8));
        int tx = program.startTransaction("Fixture imported binding");
        try {
            program.getReferenceManager().addMemoryReference(addr(0x10000), addr(0x80000),
                    RefType.DATA, SourceType.IMPORTED, 0);
        } finally { program.endTransaction(tx, true); }
        Map<String, Object> result = audit(0x10000);
        assertApplicableWithStorageIssues(0x10000);
        assertTrue(issues(result).contains("untyped"));
        assertFalse(issues(result).contains("name_missing_g_prefix"));
        assertEquals(true, facts(result).get("name_preserved"));
        @SuppressWarnings("unchecked") var references = (List<Map<String, Object>>) facts(result).get("outgoing_references");
        assertEquals(1, references.size());
        assertEquals(addr(0x80000).toString(), references.get(0).get("to"));
        Map<String, Object> score = DataTypeService.scoreGlobalCompletenessAt(program, addr(0x10000));
        assertEquals(true, score.get("applicable"));
        assertTrue(((Number) score.get("effective_score")).doubleValue() < 80);
    }

    @Test public void importedRealStorageStillNeedsExtentAndReaderDocumentation() throws Exception {
        label(0x10000, "__nativeTable", SourceType.IMPORTED);
        type(0x10000, new ArrayDataType(IntegerDataType.dataType, 4, 4));
        int tx = program.startTransaction("Fixture documentation issues");
        try {
            program.getListing().setComment(addr(0x10000), ghidra.program.model.listing.CommentType.PLATE,
                    "[RE] A 19-byte table containing native configuration values.");
            for (int i = 0; i < 7; i++) {
                program.getReferenceManager().addMemoryReference(addr(0x10100 + i), addr(0x10000),
                        RefType.DATA, SourceType.ANALYSIS, 0);
            }
        } finally { program.endTransaction(tx, true); }
        Map<String, Object> result = audit(0x10000);
        assertEquals(true, result.get("applicable"));
        assertEquals(true, facts(result).get("name_preserved"));
        assertTrue(result.toString(), issues(result).contains("plate_extent_mismatch"));
        assertTrue(result.toString(), issues(result).contains("xref_summary_missing"));
        assertEquals(false, result.get("fully_documented"));
    }

    @Test public void bssAndCommonDoNotBecomeImportsBecauseTheyAreUninitialized() throws Exception {
        label(0x20000, "__nativeBss", SourceType.IMPORTED);
        assertApplicableWithStorageIssues(0x20000);
        assertTrue(issues(audit(0x20000)).contains("untyped"));
        int tx = program.startTransaction("Fixture common storage");
        try { program.getMemory().createUninitializedBlock("__common", addr(0x30000), 0x100, false); }
        finally { program.endTransaction(tx, true); }
        label(0x30000, "DAT_00030000", SourceType.ANALYSIS);
        assertApplicableWithStorageIssues(0x30000);
        assertTrue(issues(audit(0x30000)).contains("generic_name"));
    }

    @Test public void initializedExternalIsStillStorage() throws Exception {
        int tx = program.startTransaction("Fixture initialized EXTERNAL");
        try {
            program.getMemory().convertToInitialized(program.getMemory().getBlock(addr(0x80000)), (byte) 0);
        } finally { program.endTransaction(tx, true); }
        label(0x80000, "__nativeInitialized", SourceType.IMPORTED);
        assertApplicableWithStorageIssues(0x80000);
        assertTrue(issues(audit(0x80000)).contains("untyped"));
    }

    @Test public void mappedExternalDoesNotQualify() throws Exception {
        int tx = program.startTransaction("Fixture mapped EXTERNAL");
        try {
            program.getMemory().removeBlock(program.getMemory().getBlock(addr(0x80000)), TaskMonitor.DUMMY);
            program.getMemory().createByteMappedBlock("EXTERNAL", addr(0x80000), addr(0x10000), 0x100, false);
        } finally { program.endTransaction(tx, true); }
        label(0x80000, "__nativeMapped", SourceType.IMPORTED);
        assertApplicableWithStorageIssues(0x80000);
        assertEquals(true, ((Map<?, ?>) facts(audit(0x80000)).get("memory_block")).get("mapped"));
    }

    @Test public void definedAndInteriorExternalDataAreStillAudited() throws Exception {
        label(0x80000, "__nativeStoredValue", SourceType.IMPORTED);
        type(0x80000, new ArrayDataType(IntegerDataType.dataType, 4, 4));
        label(0x80004, "__nativeInterior", SourceType.IMPORTED);
        assertApplicableWithStorageIssues(0x80000);
        assertApplicableWithStorageIssues(0x80004);
        Map<String, Object> interior = audit(0x80004);
        assertTrue(issues(interior).contains("interior_to_data"));
        assertTrue(issues(interior).contains("untyped"));
        assertEquals(true, facts(interior).get("defined_data_containing_address"));
    }

    @Test public void autoAndOrdinalImportedLabelsAreNotIdentityProtection() throws Exception {
        label(0x80000, "DAT_00080000", SourceType.IMPORTED);
        label(0x80100, "Ordinal_7", SourceType.IMPORTED);
        label(0x80200, "PTR_DAT_00080200", SourceType.IMPORTED);
        for (long address : new long[]{0x80000, 0x80100, 0x80200}) {
            assertApplicableWithStorageIssues(address);
            assertEquals(false, facts(audit(address)).get("name_preserved"));
            assertTrue(issues(audit(address)).stream().anyMatch(i -> i.equals("generic_name") || i.startsWith("name_")));
        }
    }

    @Test public void userPrimariesAndAnalysisOnlyNamespacesCannotBorrowImportedIdentity() throws Exception {
        label(0x80000, "__nativeOriginal", SourceType.IMPORTED);
        label(0x80000, "PretendNative", SourceType.USER_DEFINED);
        assertApplicableWithStorageIssues(0x80000);
        assertTrue(issues(audit(0x80000)).contains("name_missing_g_prefix"));
        int tx = program.startTransaction("Fixture native-looking namespaces");
        try {
            var namespace = program.getSymbolTable().createClass(null, "NativeClass", SourceType.IMPORTED);
            program.getSymbolTable().createLabel(addr(0x10000), "_userField", namespace, SourceType.USER_DEFINED).setPrimary();
            program.getSymbolTable().createLabel(addr(0x10008), "_analysisField", namespace, SourceType.ANALYSIS).setPrimary();
        } finally { program.endTransaction(tx, true); }
        for (long address : new long[]{0x10000, 0x10008}) {
            assertEquals(false, facts(audit(address)).get("name_preserved"));
            assertTrue(issues(audit(address)).contains("name_missing_g_prefix"));
        }
    }

    @Test public void analyzedDemanglingRequiresRetainedImportedAlias() throws Exception {
        label(0x80000, "_$sNativeMetadata", SourceType.IMPORTED);
        label(0x80000, "$$type_metadata_for_Native.Type", SourceType.ANALYSIS);
        assertEquals(false, audit(0x80000).get("applicable"));
        assertEquals("analysis_with_imported_alias", facts(audit(0x80000)).get("name_preservation_reason"));
        label(0x80100, "$$type_metadata_for_Unknown.Type", SourceType.ANALYSIS);
        assertApplicableWithStorageIssues(0x80100);
        assertEquals(false, facts(audit(0x80100)).get("name_preserved"));
    }

    @Test public void nativeQualifiedImportedFieldKeepsIdentityButNeedsATypeAndPlate() throws Exception {
        int tx = program.startTransaction("Fixture native field identity");
        try {
            var module = program.getSymbolTable().createNameSpace(null, "NativeModule", SourceType.IMPORTED);
            var owner = program.getSymbolTable().createClass(module, "Settings", SourceType.IMPORTED);
            program.getSymbolTable().createLabel(addr(0x10000), "_enableFeature", owner, SourceType.IMPORTED).setPrimary();
        } finally { program.endTransaction(tx, true); }
        Map<String, Object> result = audit(0x10000);
        assertApplicableWithStorageIssues(0x10000);
        assertTrue(issues(result).contains("untyped"));
        assertFalse(issues(result).contains("name_missing_g_prefix"));
        var primary = (Map<?, ?>) facts(result).get("primary_symbol");
        assertEquals("NativeModule::Settings::_enableFeature", primary.get("qualified_name"));
        assertEquals(2, ((List<?>) primary.get("namespaces")).size());
    }

    private Function referencingFunction() throws Exception {
        builder.createMemory(".text", "0x1000", 0x100);
        // Actual RIP-relative loads of EXTERNAL, GOT and BSS, then arithmetic.
        builder.setBytes("0x1000", "48 8b 05 f9 ef 07 00 48 8b 0d f2 ef 00 00 48 03 05 eb ef 01 00 48 31 c8 48 83 c0 01 c3");
        builder.disassemble("0x1000", 29);
        Function function = builder.createFunction("0x1000");
        int tx = program.startTransaction("Fixture named function");
        try { function.setName("ReadFixtureStorage", SourceType.USER_DEFINED); }
        finally { program.endTransaction(tx, true); }
        return function;
    }

    @Test public void functionInventoryAndQualityExcludeOnlyProvenPlaceholder() throws Exception {
        label(0x80000, "__nativeMetadata", SourceType.IMPORTED);
        label(0x10000, "PTR___nativeMetadata", SourceType.IMPORTED);
        type(0x10000, new PointerDataType(null, 8));
        label(0x20000, "DAT_00020000", SourceType.ANALYSIS);
        referencingFunction();
        Map<String, Object> inventory = data(service.auditGlobalsInFunction(program.getFunctionManager().getFunctionAt(addr(0x1000)), program));
        var summary = (Map<?, ?>) inventory.get("summary");
        assertEquals(inventory.toString(), 3, summary.get("total"));
        assertEquals(1, summary.get("not_applicable"));
        assertEquals(2, summary.get("with_issues"));
        assertEquals(0, summary.get("fully_documented"));
        Map<String, Object> quality = data(analysis.analyzeFunctionCompleteness(program.getFunctionManager().getFunctionAt(addr(0x1000)), false, "", program));
        @SuppressWarnings("unchecked") var breakdown = (List<Map<String, Object>>) quality.get("deduction_breakdown");
        assertNotNull(quality.toString(), breakdown);
        for (Map<String, Object> deduction : breakdown) {
            if (deduction.get("category").equals("untyped_global")) assertEquals(2, deduction.get("count"));
            if (deduction.get("category").equals("generic_global_name")) assertEquals(1, deduction.get("count"));
            if (deduction.get("category").equals("missing_global_plate_comment")) assertEquals(2, deduction.get("count"));
        }
        assertTrue(breakdown.toString(), breakdown.stream().anyMatch(d -> "untyped_global".equals(d.get("category"))));
    }

    @Test public void functionSummaryRetainsSoftFindingsWithoutCallingThemIncomplete() throws Exception {
        label(0x80000, "__nativeMetadata", SourceType.IMPORTED);
        label(0x10000, "PTR___nativeMetadata", SourceType.IMPORTED);
        type(0x10000, new PointerDataType(IntegerDataType.dataType, 8));
        label(0x20000, "g_dwFixtureCount", SourceType.USER_DEFINED);
        type(0x20000, UnsignedIntegerDataType.dataType);
        int tx = program.startTransaction("Fixture complete data with soft warning");
        try {
            program.getListing().setComment(addr(0x10000), ghidra.program.model.listing.CommentType.PLATE,
                    "[RE] Native binding stores a pointer to the imported fixture metadata and deliberately uses a long description for the soft line-wrap warning.");
            program.getListing().setComment(addr(0x20000), ghidra.program.model.listing.CommentType.PLATE,
                    "[RE] Counts fixture operations before arithmetic.");
        } finally { program.endTransaction(tx, true); }
        referencingFunction();
        Map<String, Object> inventory = data(service.auditGlobalsInFunction(program.getFunctionManager().getFunctionAt(addr(0x1000)), program));
        var summary = (Map<?, ?>) inventory.get("summary");
        assertEquals(inventory.toString(), 3, summary.get("total"));
        assertEquals(1, summary.get("not_applicable"));
        assertEquals(2, summary.get("fully_documented"));
        assertEquals(0, summary.get("with_issues"));
        assertEquals(1, ((Map<?, ?>) summary.get("issue_histogram")).get("plate_line_too_long"));
    }

    @Test public void codeAddressGuardStillPrecedesLinkageClassification() throws Exception {
        builder.createMemory(".text", "0x1000", 0x100);
        builder.setBytes("0x1000", "c3");
        builder.disassemble("0x1000", 1);
        builder.createFunction("0x1000");
        Map<String, Object> result = audit(0x1000);
        assertEquals(false, result.get("applicable"));
        assertEquals("code_address", result.get("reason"));
    }
}
