package com.xebyte.offline;

import com.xebyte.core.Response;
import com.xebyte.core.SymbolLabelService;
import com.xebyte.core.ThreadingStrategy;
import junit.framework.TestCase;

/**
 * Graceful-degradation coverage for SymbolLabelService (previously no behavioral tests).
 * With no program loaded, the label/rename tools must return a clean "No program loaded"
 * error instead of throwing.
 */
public class SymbolLabelServiceValidationTest extends TestCase {

    private SymbolLabelService symbols;

    @Override
    protected void setUp() {
        ThreadingStrategy ts = new NoopThreadingStrategy();
        symbols = new SymbolLabelService(ServiceFactory.stubProvider(), ts);
    }

    private static void assertNoProgram(Response r) {
        assertNotNull("method returned null instead of an error Response", r);
        assertTrue("expected a graceful 'No program loaded' error, got: " + r.toJson(),
                r.toJson().contains("No program loaded"));
    }

    public void testCreateLabelDegradesGracefully() {
        assertNoProgram(symbols.createLabel("0x401000", "my_label"));
    }

    public void testRenameLabelDegradesGracefully() {
        assertNoProgram(symbols.renameLabel("0x401000", "old", "new_name"));
    }

    public void testRenameOrLabelDegradesGracefully() {
        assertNoProgram(symbols.renameOrLabel("0x401000", "g_someGlobal"));
    }

    public void testDeleteLabelDegradesGracefully() {
        assertNoProgram(symbols.deleteLabel("0x401000", "my_label"));
    }

    public void testRenameDataAtAddressDegradesGracefully() {
        assertNoProgram(symbols.renameDataAtAddress("0x401000", "g_data"));
    }

    public void testRenameGlobalVariableDegradesGracefully() {
        assertNoProgram(symbols.renameGlobalVariable("oldGlobal", "g_newGlobal"));
    }

    public void testGetFunctionLabelsDegradesGracefully() {
        assertNoProgram(symbols.getFunctionLabels("FUN_00401000", 0, 100));
    }

    public void testCanRenameAtAddressDegradesGracefully() {
        assertNoProgram(symbols.canRenameAtAddress("0x401000"));
    }
}
