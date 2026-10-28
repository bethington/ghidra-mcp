package com.xebyte.offline;

import com.xebyte.core.AnnotationScanner;
import com.xebyte.core.EndpointDef;
import com.xebyte.core.McpTool;
import com.xebyte.core.Param;
import com.xebyte.core.ParamSource;
import com.xebyte.core.Response;
import com.xebyte.core.SymbolLabelService;
import junit.framework.TestCase;

import java.util.HashMap;
import java.util.Map;

/**
 * {@code /rename_symbol} used to declare {@code old_name} as a parameter in its
 * own right <em>and</em> as an alias of {@code target}, so a single request value
 * bound to two Java arguments.
 *
 * <p>The first half of this class shows the mechanism with a mock service that
 * still carries the colliding declaration - the resolver has no idea two bindings
 * are feeding on one key, and it fills both. The second half pins the replacement:
 * {@code target} keeps only the address spellings, {@code old_name} is a parameter
 * and nothing else, and the legacy {@code rename_global_variable(old_name,
 * new_name)} call shape keeps working through an explicit fallback that resolves
 * in the same order the alias list produced.
 *
 * <p>{@code SchemaAliasPublicationTest} carries the general guard that no
 * <em>real</em> tool may declare such a collision again.
 */
public class RenameSymbolTargetBindingTest extends TestCase {

    /** The declaration as it stood before the fix, kept only to demonstrate it. */
    public static class CollidingShape {
        @McpTool(path = "/colliding", method = "POST", description = "", category = "test")
        public Response rename(
                @Param(value = "target", source = ParamSource.BODY,
                       aliases = {"address", "function_address", "old_name"}) String target,
                @Param(value = "old_name", source = ParamSource.BODY, defaultValue = "") String oldName) {
            return Response.text("target=" + target + "|old_name=" + oldName);
        }
    }

    /** The declaration after the fix: no parameter name appears in an alias list. */
    public static class SingleBindingShape {
        @McpTool(path = "/single", method = "POST", description = "", category = "test")
        public Response rename(
                @Param(value = "target", source = ParamSource.BODY,
                       aliases = {"address", "function_address"}) String target,
                @Param(value = "old_name", source = ParamSource.BODY, defaultValue = "") String oldName) {
            return Response.text("target=" + SymbolLabelService.resolveRenameTarget(target, oldName)
                + "|old_name=" + oldName);
        }
    }

    private static String post(Object service, String path, Map<String, Object> body) throws Exception {
        AnnotationScanner scanner = new AnnotationScanner(service);
        for (EndpointDef ep : scanner.getEndpoints()) {
            if (ep.path().equals(path)) {
                return ep.handler().handle(new HashMap<>(), body).toJson();
            }
        }
        throw new AssertionError("no endpoint " + path);
    }

    private static Map<String, Object> body(String... kv) {
        Map<String, Object> m = new HashMap<>();
        for (int i = 0; i < kv.length; i += 2) m.put(kv[i], kv[i + 1]);
        return m;
    }

    // ------------------------------------------------------------------
    // The defect, demonstrated
    // ------------------------------------------------------------------

    /**
     * With {@code old_name} declared as both, one request value reaches two
     * parameters. This is what {@code /rename_symbol} did.
     */
    public void testCollidingDeclarationBindsOneValueToTwoParameters() throws Exception {
        String out = post(new CollidingShape(), "/colliding", body("old_name", "gFoo"));
        assertTrue("target should have picked the value up via the old_name alias: " + out,
            out.contains("target=gFoo"));
        assertTrue("old_name should have picked the SAME value up as its own parameter: " + out,
            out.contains("old_name=gFoo"));
    }

    /**
     * The collision is order-dependent in only one direction: the canonical name
     * is tried first, so {@code target} always wins for itself when present, and
     * {@code old_name} is never consulted for {@code target}. That is why a caller
     * sending both was never ambiguous - only a caller sending {@code old_name}
     * alone triggered the double bind.
     */
    public void testCanonicalNameStillWinsWhenBothAreSent() throws Exception {
        String out = post(new CollidingShape(), "/colliding",
            body("target", "0x401000", "old_name", "LAB_00401000"));
        assertTrue(out.contains("target=0x401000"));
        assertTrue(out.contains("old_name=LAB_00401000"));
    }

    // ------------------------------------------------------------------
    // The replacement
    // ------------------------------------------------------------------

    /** Legacy rename_global_variable(old_name, new_name) callers keep working. */
    public void testOldNameOnlyStillSelectsTheTarget() throws Exception {
        String out = post(new SingleBindingShape(), "/single", body("old_name", "gFoo"));
        assertTrue("old_name must still reach target, now explicitly: " + out,
            out.contains("target=gFoo"));
    }

    /** The address spellings that were aliases still are. */
    public void testAddressAliasesStillSelectTheTarget() throws Exception {
        assertTrue(post(new SingleBindingShape(), "/single", body("address", "0x401000"))
            .contains("target=0x401000"));
        assertTrue(post(new SingleBindingShape(), "/single", body("function_address", "0x401000"))
            .contains("target=0x401000"));
    }

    /**
     * A caller sending both gets the documented split: {@code target} names the
     * symbol, {@code old_name} stays the kind=label selector. It is never used as
     * the target while a target is present.
     */
    public void testBothSentKeepsThemSeparate() throws Exception {
        String out = post(new SingleBindingShape(), "/single",
            body("target", "0x401000", "old_name", "LAB_00401000"));
        assertTrue("target must come from target: " + out, out.contains("target=0x401000"));
        assertTrue("old_name must stay the label selector: " + out,
            out.contains("old_name=LAB_00401000"));
    }

    // ------------------------------------------------------------------
    // The fallback itself
    // ------------------------------------------------------------------

    public void testResolveRenameTargetPrefersTarget() {
        assertEquals("0x401000", SymbolLabelService.resolveRenameTarget("0x401000", "LAB_00401000"));
    }

    public void testResolveRenameTargetFallsBackToOldName() {
        assertEquals("gFoo", SymbolLabelService.resolveRenameTarget(null, "gFoo"));
        assertEquals("gFoo", SymbolLabelService.resolveRenameTarget("", "gFoo"));
        assertEquals("gFoo", SymbolLabelService.resolveRenameTarget("   ", "gFoo"));
    }

    public void testResolveRenameTargetKeepsNullWhenNeitherIsUsable() {
        assertNull(SymbolLabelService.resolveRenameTarget(null, null));
        assertNull(SymbolLabelService.resolveRenameTarget(null, ""));
        assertEquals("", SymbolLabelService.resolveRenameTarget("", ""));
    }
}
