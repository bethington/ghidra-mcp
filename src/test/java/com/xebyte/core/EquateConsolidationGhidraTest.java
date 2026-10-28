package com.xebyte.core;

import com.xebyte.headless.DirectThreadingStrategy;
import ghidra.GhidraApplicationLayout;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.symbol.Equate;
import ghidra.util.task.TaskMonitor;
import org.junit.*;
import java.io.File;
import java.util.*;
import static org.junit.Assert.*;
import static org.junit.Assume.assumeTrue;
import static org.mockito.Mockito.*;
import static org.mockito.ArgumentMatchers.any;

/** Real instruction scalars, equate references, transactions and HTTP binding. */
public class EquateConsolidationGhidraTest {
    private ProgramBuilder builder;
    private ProgramDB program;
    private AnnotationScanner scanner;

    @BeforeClass public static void initializeGhidra() throws Exception {
        String dir = System.getenv("GHIDRA_INSTALL_DIR");
        assumeTrue(dir != null && !dir.isBlank());
        if (!Application.isInitialized()) {
            ApplicationConfiguration config = new ApplicationConfiguration();
            config.setInitializeLogging(false);
            Application.initializeApplication(new GhidraApplicationLayout(new File(dir)), config);
        }
    }

    @Before public void setUp() throws Exception {
        builder = new ProgramBuilder("equates", ProgramBuilder._X64, "gcc", this);
        program = builder.getProgram();
        builder.createMemory(".text", "0x1000", 0x100);
        // PUSH -1 (8-bit scalar); MOV EAX,3; MOV EBX,3; RET.
        builder.setBytes("0x1000", "6a ff b8 03 00 00 00 bb 03 00 00 00 c3");
        builder.withTransaction(() -> assertTrue(new DisassembleCommand(builder.addr("0x1000"),
            new AddressSet(builder.addr("0x1000"), builder.addr("0x100c")), true)
            .applyTo(program, TaskMonitor.DUMMY)));
        builder.createFunction("0x1000");
        ProgramProvider provider = mock(ProgramProvider.class);
        when(provider.getAllOpenPrograms()).thenReturn(new ghidra.program.model.listing.Program[]{program});
        when(provider.getCurrentProgram()).thenReturn(program);
        when(provider.getProgram(any())).thenReturn(program);
        when(provider.resolveProgram(any())).thenReturn(program);
        DirectThreadingStrategy strategy = new DirectThreadingStrategy();
        ListingService listing = new ListingService(provider, strategy);
        scanner = new AnnotationScanner(provider, strategy, listing);
    }

    @After public void tearDown() { if (builder != null) builder.dispose(); }

    private Response write(Map<String,Object> body) throws Exception {
        EndpointDef ep = scanner.getEndpoints().stream().filter(e -> e.path().equals("/set_equate"))
            .findFirst().orElseThrow(() -> new AssertionError("Missing consolidated equate writer"));
        return ep.handler().handle(Map.of(), body);
    }
    private void ok(Response r) { assertTrue(r.toJson(), r instanceof Response.Ok); }
    private void err(Response r) { assertTrue(r.toJson(), r instanceof Response.Err); }
    private void seed(String name, long value, String address, int operand) throws Exception {
        new DirectThreadingStrategy().executeWrite(program, "fixture equate", () -> {
            Equate e = program.getEquateTable().getEquate(name);
            if (e == null) e = program.getEquateTable().createEquate(name, value);
            e.addReference(builder.addr(address), operand);
            return null;
        });
    }
    private List<Equate> at(String address, int operand) {
        return program.getEquateTable().getEquates(builder.addr(address), operand);
    }
    @Test public void signedNegativeScalarMatches() throws Exception {
        ok(write(Map.of("action","apply","name","NEG","value","-1","address","0x1000")));
        assertEquals(-1, program.getEquateTable().getEquate("NEG").getValue());
        assertEquals("NEG", at("0x1000",0).get(0).getName());
        assertNull(program.getCurrentTransactionInfo());
    }
    @Test public void applyReplacesPreviousNameOnSameScalar() throws Exception {
        seed("OLD",3,"0x1002",1);
        ok(write(Map.of("action","apply","name","NEW","address","0x1002","operand_index",1)));
        assertEquals(1, at("0x1002",1).size());
        assertEquals("NEW", at("0x1002",1).get(0).getName());
        assertEquals(0, program.getEquateTable().getEquate("OLD").getReferenceCount());
    }
    @Test public void capRefusalLeavesEveryReferenceIntact() throws Exception {
        seed("OLD",3,"0x1002",1);
        err(write(Map.of("action","apply","name","NEW","value","3","function_address","0x1003","max_hits",1)));
        assertNull(program.getEquateTable().getEquate("NEW"));
        assertEquals("OLD", at("0x1002",1).get(0).getName());
        assertTrue(at("0x1007",1).isEmpty());
    }
    @Test public void conflictingDefinitionDoesNotPartiallyReplace() throws Exception {
        seed("OLD",3,"0x1002",1); seed("NEW",9,"0x1007",1);
        err(write(Map.of("action","apply","name","NEW","value","3","function_address","0x1000")));
        assertEquals("OLD", at("0x1002",1).get(0).getName());
        assertEquals(9, program.getEquateTable().getEquate("NEW").getValue());
    }
    @Test public void invalidOperandAndCapRejectBeforeMutation() throws Exception {
        for (int index : new int[]{-2,2}) {
            err(write(Map.of("action","apply","name","NEW","address","0x1002","operand_index",index)));
        }
        for (int cap : new int[]{0,-1}) {
            err(write(Map.of("action","apply","name","NEW","address","0x1002","max_hits",cap)));
        }
        assertNull(program.getEquateTable().getEquate("NEW"));
    }
    @Test public void removeDefinitionHonorsValueFilter() throws Exception {
        seed("KEEP",3,"0x1002",1);
        err(write(Map.of("action","remove","name","KEEP","value","4","delete_definition",true)));
        assertEquals(1, program.getEquateTable().getEquate("KEEP").getReferenceCount());
    }
    @Test public void scopedDeleteCannotEraseUnselectedReferences() throws Exception {
        seed("KEEP",3,"0x1002",1); seed("KEEP",3,"0x1007",1);
        err(write(Map.of("action","remove","name","KEEP","address","0x1002","delete_definition",true)));
        assertEquals(2, program.getEquateTable().getEquate("KEEP").getReferenceCount());
    }
    @Test public void removeByValueWithoutScopeRetainsUsefulFilter() throws Exception {
        seed("A",3,"0x1002",1); seed("B",3,"0x1007",1);
        ok(write(Map.of("action","remove","value","3")));
        assertTrue(at("0x1002",1).isEmpty()); assertTrue(at("0x1007",1).isEmpty());
    }
    @Test public void renameCollisionIsAtomicAndSameNameIsIdempotent() throws Exception {
        seed("A",3,"0x1002",1); seed("B",3,"0x1007",1);
        err(write(Map.of("action","rename","name","A","new_name","B")));
        assertEquals("A", at("0x1002",1).get(0).getName());
        ok(write(Map.of("action","rename","name","A","new_name","A")));
        ok(write(Map.of("action","rename","old_name","A","new_name","C")));
        assertEquals("C", at("0x1002",1).get(0).getName());
        assertEquals("B", at("0x1007",1).get(0).getName());
    }
    @Test public void ambiguousScopesAndMalformedLiteralDoNotWrite() throws Exception {
        err(write(Map.of("action","apply","name","A","address","0x1002","function_address","0x1000")));
        err(write(Map.of("action","apply","name","A","address","0x1002","value","'ABC'")));
        err(write(Map.of("action","wat","name","A")));
        assertFalse(program.getEquateTable().getEquates().hasNext());
    }
    @Test public void inventoryPreservesFiltersReferencesAndPagination() throws Exception {
        seed("ZZZ",3,"0x1007",1); seed("AAA",3,"0x1002",1);
        EndpointDef ep = scanner.getEndpoints().stream().filter(e -> e.path().equals("/list_program_items"))
            .findFirst().orElseThrow();
        Response r = ep.handler().handle(Map.of("kind","equates","value","3","name_contains","aa",
            "address","0x1002","include_references","true","limit","1"), Map.of());
        ok(r);
        String json = r.toJson();
        assertTrue(json, json.contains("AAA")); assertFalse(json, json.contains("ZZZ"));
        assertTrue(json, json.contains("operand_index")); assertTrue(json, json.contains("items"));
    }
    @Test public void dryRunApplyRollsBackReplacementAndDefinition() throws Exception {
        seed("OLD",3,"0x1002",1);
        ok(write(Map.of("action","apply","name","PREVIEW","address","0x1002","dry_run",true)));
        assertNull(program.getEquateTable().getEquate("PREVIEW"));
        assertEquals("OLD", at("0x1002",1).get(0).getName());
        assertNull(program.getCurrentTransactionInfo());
    }
    @Test public void dryRunRemoveRestoresDefinitionAndEveryReference() throws Exception {
        seed("KEEP",3,"0x1002",1); seed("KEEP",3,"0x1007",1);
        ok(write(Map.of("action","remove","name","KEEP","delete_definition",true,"dry_run",true)));
        assertEquals(2, program.getEquateTable().getEquate("KEEP").getReferenceCount());
        assertEquals("KEEP", at("0x1002",1).get(0).getName());
        assertEquals("KEEP", at("0x1007",1).get(0).getName());
        assertNull(program.getCurrentTransactionInfo());
    }
    @Test public void dryRunRenameRestoresOriginalNameAndReferences() throws Exception {
        seed("KEEP",3,"0x1002",1); seed("KEEP",3,"0x1007",1);
        ok(write(Map.of("action","rename","name","KEEP","new_name","PREVIEW","dry_run",true)));
        assertNull(program.getEquateTable().getEquate("PREVIEW"));
        assertEquals(2, program.getEquateTable().getEquate("KEEP").getReferenceCount());
        assertNull(program.getCurrentTransactionInfo());
    }
    @Test public void enumReferenceMayDetachButDefinitionDeletionIsRefused() throws Exception {
        String enumName = ghidra.program.database.symbol.EquateManager.formatNameForEquate(
            new ghidra.util.UniversalID(123), 3);
        seed(enumName,3,"0x1002",1);
        assertTrue(program.getEquateTable().getEquate(enumName).isEnumBased());
        err(write(Map.of("action","remove","name",enumName,"delete_definition",true)));
        assertEquals(1, program.getEquateTable().getEquate(enumName).getReferenceCount());
        ok(write(Map.of("action","remove","name",enumName,"address","0x1002")));
        assertNotNull(program.getEquateTable().getEquate(enumName));
        assertEquals(0, program.getEquateTable().getEquate(enumName).getReferenceCount());
    }
    @Test public void paginationIsStableAndHandlesUnboundedAndOverflowingPages() throws Exception {
        seed("Z",3,"0x1007",1); seed("A",3,"0x1002",1);
        EndpointDef ep = scanner.getEndpoints().stream().filter(e -> e.path().equals("/list_program_items"))
            .findFirst().orElseThrow();
        Response r = ep.handler().handle(Map.of("kind","equates","offset","1","limit","2147483647"), Map.of());
        ok(r);
        @SuppressWarnings("unchecked") Map<String,Object> data = (Map<String,Object>) ((Response.Ok)r).data();
        assertEquals(2, data.get("total")); assertEquals(1, data.get("count"));
        assertEquals("Z", ((Map<?,?>)((List<?>)data.get("items")).get(0)).get("name"));
        r = ep.handler().handle(Map.of("kind","equates","offset","-2","limit","0"), Map.of());
        ok(r);
        @SuppressWarnings("unchecked") Map<String,Object> unbounded = (Map<String,Object>) ((Response.Ok)r).data();
        assertEquals(2, unbounded.get("count")); assertEquals(0, unbounded.get("offset"));
        assertFalse(unbounded.containsKey("limit"));
    }
    @Test public void removeAndRenameCapsRefuseWithoutMutation() throws Exception {
        seed("KEEP",3,"0x1002",1); seed("KEEP",3,"0x1007",1);
        err(write(Map.of("action","remove","name","KEEP","max_hits",1)));
        err(write(Map.of("action","rename","name","KEEP","new_name","NO","max_hits",1)));
        assertEquals(2, program.getEquateTable().getEquate("KEEP").getReferenceCount());
        assertNull(program.getEquateTable().getEquate("NO"));
    }
    @Test public void oldRoutesAreRemoved() {
        for (EndpointDef ep : scanner.getEndpoints()) {
            assertFalse(ep.path(), Set.of("/apply_equate","/remove_equate","/rename_equate","/list_equates").contains(ep.path()));
        }
    }
}
