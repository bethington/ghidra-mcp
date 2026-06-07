package com.xebyte.offline;

import com.xebyte.core.EmulationService;
import com.xebyte.core.Response;
import com.xebyte.core.ThreadingStrategy;
import junit.framework.TestCase;

/**
 * Graceful-degradation coverage for EmulationService (previously no behavioral tests).
 * emulate_function must return a clean "No program loaded" error rather than throw when no
 * binary is loaded.
 */
public class EmulationServiceValidationTest extends TestCase {

    private EmulationService emulation;

    @Override
    protected void setUp() {
        ThreadingStrategy ts = new NoopThreadingStrategy();
        emulation = new EmulationService(ServiceFactory.stubProvider(), ts);
    }

    public void testEmulateFunctionDegradesGracefully() {
        Response r = emulation.emulateFunction("0x401000", "", "", 10000, "", "");
        assertNotNull(r);
        assertTrue("expected 'No program loaded', got: " + r.toJson(),
                r.toJson().contains("No program loaded"));
    }
}
