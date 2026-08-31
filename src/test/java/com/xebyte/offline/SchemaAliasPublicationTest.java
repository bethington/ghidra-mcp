package com.xebyte.offline;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.xebyte.core.AnnotationScanner;
import com.xebyte.core.McpTool;
import com.xebyte.core.Param;
import com.xebyte.core.ProgramProvider;
import junit.framework.TestCase;

import java.lang.reflect.Method;
import java.lang.reflect.Parameter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Two defects in the published contract, pinned so they cannot come back.
 *
 * <p><b>1. /mcp/schema never emitted {@code @Param} aliases.</b>
 * {@code AnnotationScanner.resolveQueryParam} / {@code resolveBodyParam} try the
 * canonical name and then every declared alias, so the server genuinely serves
 * both spellings. {@code ParamDescriptor.toJson} did not emit them, so the
 * published schema understated what the server accepts, and anything reasoning
 * about "is this a parameter the server accepts?" from the schema alone called a
 * valid spelling unknown. {@code /get_function_labels} accepting {@code address}
 * was reported as a contract breach on exactly that basis.
 *
 * <p><b>2. /rename_symbol bound one request value to two parameters.</b>
 * {@code old_name} was declared BOTH as a parameter in its own right and as an
 * alias of {@code target}, because the two tools it replaced disagree about what
 * the name means. No schema can describe that honestly. The guard here is
 * general: no tool may declare an alias that collides with another parameter's
 * canonical name on the same tool.
 */
public class SchemaAliasPublicationTest extends TestCase {

    private AnnotationScanner scanner;
    private Object[] services;

    @Override
    protected void setUp() {
        ProgramProvider provider = ServiceFactory.stubProvider();
        services = ServiceFactory.buildAllServices();
        scanner = new AnnotationScanner(provider, services);
    }

    // ------------------------------------------------------------------
    // Bug 1 - aliases must reach /mcp/schema
    // ------------------------------------------------------------------

    /**
     * The motivating case: {@code /get_function_labels} declares
     * {@code aliases = {"function", "address", "function_address"}} on its
     * {@code name} parameter. Before the fix the schema showed only {@code name},
     * so {@code address=} looked like an unknown parameter.
     */
    public void testGetFunctionLabelsPublishesItsAliases() {
        AnnotationScanner.ParamDescriptor p = findParam("/get_function_labels", "name");
        assertNotNull("/get_function_labels has no 'name' parameter", p);
        assertEquals("declared aliases must be published verbatim, in declaration order",
            List.of("function", "address", "function_address"), p.aliases());

        String json = p.toJson();
        assertTrue("ParamDescriptor.toJson must emit an aliases array; got: " + json,
            json.contains("\"aliases\": [\"function\", \"address\", \"function_address\"]"));
    }

    /**
     * Every alias declared on any {@code @McpTool} parameter must appear in that
     * parameter's schema entry. One endpoint passing is not the contract; the
     * whole surface is.
     */
    public void testEveryDeclaredAliasIsPublished() {
        Map<String, Map<String, List<String>>> declared = declaredAliases();
        // Sanity: the reflection walk actually found aliases to check, so a
        // silently-empty walk cannot pass this test vacuously.
        assertTrue("expected several tools in this tree to declare aliases, found " + declared.size(),
            declared.size() >= 3);

        List<String> problems = new ArrayList<>();
        for (Map.Entry<String, Map<String, List<String>>> tool : declared.entrySet()) {
            for (Map.Entry<String, List<String>> param : tool.getValue().entrySet()) {
                AnnotationScanner.ParamDescriptor p = findParam(tool.getKey(), param.getKey());
                if (p == null) {
                    problems.add(tool.getKey() + " has no scanned param '" + param.getKey() + "'");
                    continue;
                }
                if (!param.getValue().equals(p.aliases())) {
                    problems.add(tool.getKey() + "." + param.getKey()
                        + " declares " + param.getValue() + " but the schema publishes " + p.aliases());
                }
            }
        }
        assertTrue("Declared aliases missing from /mcp/schema:\n  " + String.join("\n  ", problems),
            problems.isEmpty());
    }

    /**
     * The whole schema document must stay valid JSON with the new key, and the
     * key must be absent - not empty - for the overwhelming majority of
     * parameters that declare no alias. An always-present empty array would bloat
     * every snapshot and every client for no information.
     */
    public void testSchemaStaysValidJsonAndOmitsEmptyAliases() {
        JsonObject root = new Gson().fromJson(scanner.generateSchema(), JsonObject.class);
        JsonArray tools = root.getAsJsonArray("tools");
        assertTrue("scanner found no tools", tools.size() > 100);

        int withAliases = 0;
        int withoutAliasKey = 0;
        for (int i = 0; i < tools.size(); i++) {
            JsonObject tool = tools.get(i).getAsJsonObject();
            JsonArray params = tool.getAsJsonArray("params");
            if (params == null) continue;
            for (int j = 0; j < params.size(); j++) {
                JsonObject p = params.get(j).getAsJsonObject();
                if (!p.has("aliases")) {
                    withoutAliasKey++;
                    continue;
                }
                JsonArray a = p.getAsJsonArray("aliases");
                assertTrue("an emitted aliases array must never be empty: " + tool.get("path"),
                    a.size() > 0);
                withAliases++;
            }
        }
        assertTrue("no parameter published aliases at all", withAliases > 0);
        assertTrue("aliases key should be omitted for params that declare none", withoutAliasKey > 0);
    }

    /** The 8-arg constructor stays source-compatible for callers predating aliases. */
    public void testEightArgConstructorDefaultsToNoAliases() {
        AnnotationScanner.ParamDescriptor p = new AnnotationScanner.ParamDescriptor(
            "x", "string", "body", true, null, "", "", false);
        assertEquals(List.of(), p.aliases());
        assertFalse("no aliases declared => no aliases key", p.toJson().contains("aliases"));
    }

    // ------------------------------------------------------------------
    // Bug 2 - one request value must not bind to two parameters
    // ------------------------------------------------------------------

    /**
     * General guard. An alias equal to another parameter's canonical name on the
     * same tool means one request value resolves into two Java arguments: the
     * alias owner picks it up (canonical absent, alias present) and so does the
     * parameter that owns the name. That is unrepresentable in a schema, and it
     * is how /rename_symbol went wrong.
     */
    public void testNoAliasCollidesWithAnotherParameterOnTheSameTool() {
        List<String> collisions = new ArrayList<>();
        for (AnnotationScanner.ToolDescriptor tool : scanner.getDescriptors()) {
            Set<String> canonical = new HashSet<>();
            for (AnnotationScanner.ParamDescriptor p : tool.params()) {
                canonical.add(p.name());
            }
            for (AnnotationScanner.ParamDescriptor p : tool.params()) {
                for (String alias : p.aliases()) {
                    if (canonical.contains(alias)) {
                        collisions.add(tool.path() + ": '" + alias
                            + "' is both a parameter and an alias of '" + p.name() + "'");
                    }
                }
            }
        }
        assertTrue("A request value would bind to two parameters:\n  "
            + String.join("\n  ", collisions), collisions.isEmpty());
    }

    /**
     * The specific declaration. {@code target} keeps the address spellings; it
     * must not claim {@code old_name}, which is a parameter of its own.
     */
    public void testRenameSymbolTargetNoLongerAliasesOldName() {
        AnnotationScanner.ParamDescriptor target = findParam("/rename_symbol", "target");
        assertNotNull("/rename_symbol lost its 'target' parameter", target);
        assertEquals(List.of("address", "function_address"), target.aliases());

        AnnotationScanner.ParamDescriptor oldName = findParam("/rename_symbol", "old_name");
        assertNotNull("/rename_symbol must keep old_name as a parameter in its own right", oldName);
        assertEquals("old_name declares no aliases of its own", List.of(), oldName.aliases());
    }

    // ------------------------------------------------------------------
    // helpers
    // ------------------------------------------------------------------

    private AnnotationScanner.ParamDescriptor findParam(String path, String name) {
        for (AnnotationScanner.ToolDescriptor tool : scanner.getDescriptors()) {
            if (!tool.path().equals(path)) continue;
            for (AnnotationScanner.ParamDescriptor p : tool.params()) {
                if (p.name().equals(name)) return p;
            }
        }
        return null;
    }

    /** path -&gt; canonical param name -&gt; declared aliases, straight off the annotations. */
    private Map<String, Map<String, List<String>>> declaredAliases() {
        Map<String, Map<String, List<String>>> out = new LinkedHashMap<>();
        for (Object service : services) {
            for (Method m : service.getClass().getMethods()) {
                McpTool tool = m.getAnnotation(McpTool.class);
                if (tool == null) continue;
                Map<String, List<String>> params = new LinkedHashMap<>();
                for (Parameter jp : m.getParameters()) {
                    Param p = jp.getAnnotation(Param.class);
                    if (p == null || p.aliases().length == 0) continue;
                    params.put(p.value(), Arrays.asList(p.aliases()));
                }
                if (!params.isEmpty()) out.put(tool.path(), params);
            }
        }
        return out;
    }
}
