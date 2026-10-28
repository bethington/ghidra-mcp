package com.xebyte.core;

import org.junit.Test;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilderFactory;
import java.io.File;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.junit.Assume.assumeTrue;

/**
 * Guards the classpath that the real-Ghidra test tier runs on.
 *
 * <p>The tier ({@code src/test/java/com/xebyte/core/*GhidraTest.java}) builds a real
 * {@code ProgramDB}, which loads the x86 SLEIGH language and so needs a dozen third-party
 * libraries that Ghidra bundles but that the pom's {@code install-file}'d {@code ghidra:*}
 * module jars carry no transitive record of. The {@code ghidra-runtime-tests} profile in
 * pom.xml names them explicitly.
 *
 * <p>Two failure modes are covered, both of which used to present as an opaque
 * {@code NoClassDefFoundError} thrown from a test that looks unrelated to the classpath:
 *
 * <ul>
 *   <li>a Ghidra upgrade renames a bundled jar (they are version-stamped), so a profile entry
 *       silently points at nothing -- a missing classpath element is ignored by the JVM;</li>
 *   <li>the profile does not activate at all, so the extension never happens.</li>
 * </ul>
 *
 * <p>The jar list is READ FROM pom.xml rather than restated here on purpose: a second
 * hand-maintained copy would drift, and whichever copy was consulted last would decide what
 * "the classpath" means.
 */
public class GhidraRuntimeClasspathGhidraTest {

    private static final String PROFILE_ID = "ghidra-runtime-tests";

    /**
     * Marker classes, one per distinct library in the chain, each paired with the Ghidra class
     * whose initialization actually resolves it. Loading them proves the profile is live -- a
     * file-existence check alone would still pass if the profile never activated.
     */
    private static final String[][] MARKERS = {
        { "org.apache.logging.log4j.LogManager", "ghidra.program.util.DefaultLanguageService" },
        { "org.apache.logging.log4j.core.Logger", "ghidra.program.util.DefaultLanguageService" },
        { "com.google.common.collect.BiMap", "ghidra.app.plugin.processors.sleigh.SleighLanguage" },
        { "org.apache.commons.lang3.ArrayUtils", "db.TableRecord" },
        { "org.apache.commons.collections4.IteratorUtils", "Ghidra listing iteration" },
        { "org.antlr.runtime.RecognitionException",
          "ghidra.app.plugin.processors.sleigh.SleighLanguageProvider" },
        { "org.iso_relax.verifier.VerifierFactory", "SLEIGH language-definition XML validation" },
        { "com.sun.msv.verifier.jarv.TheFactoryImpl", "SLEIGH language-definition XML validation" },
        { "org.relaxng.datatype.Datatype", "SLEIGH language-definition XML validation" },
        { "com.sun.msv.datatype.xsd.XSDatatype", "SLEIGH language-definition XML validation" },
        { "javax.help.UnsupportedOperationException",
          "ghidra.program.database.data.CompositeDBAdapter" },
        { "ghidra.graph.GEdge", "ghidra.program.database.data.CompositeDBAdapter" },
    };

    private static String ghidraInstallDir() {
        String dir = System.getenv("GHIDRA_INSTALL_DIR");
        assumeTrue("GHIDRA_INSTALL_DIR is required for real Ghidra tests",
            dir != null && !dir.isBlank());
        return dir;
    }

    @Test
    public void everyJarNamedByTheProfileExists() throws Exception {
        String installDir = ghidraInstallDir();
        List<String> elements = readProfileClasspathElements(installDir);

        assertFalse("pom.xml profile " + PROFILE_ID + " declares no additionalClasspathElements"
            + " -- the real-Ghidra tier cannot load a SLEIGH language without them",
            elements.isEmpty());

        List<String> missing = new ArrayList<>();
        for (String element : elements) {
            if (!new File(element).isFile()) {
                missing.add(element);
            }
        }
        if (!missing.isEmpty()) {
            fail("pom.xml profile " + PROFILE_ID + " points at " + missing.size()
                + " jar(s) that do not exist under GHIDRA_INSTALL_DIR=" + installDir + ":\n  "
                + String.join("\n  ", missing)
                + "\nThese filenames are version-stamped by Ghidra, so an upgrade renames them."
                + " A missing classpath element is IGNORED by the JVM, so leaving this unfixed"
                + " does not fail there -- it resurfaces as a NoClassDefFoundError from"
                + " whichever *GhidraTest builds a Program first. Update the <element> versions"
                + " in the " + PROFILE_ID + " profile to match the new installation.");
        }
    }

    @Test
    public void everyLibraryInTheChainIsActuallyOnTheTestClasspath() {
        ghidraInstallDir();

        List<String> unresolved = new ArrayList<>();
        for (String[] marker : MARKERS) {
            try {
                Class.forName(marker[0], false, getClass().getClassLoader());
            }
            catch (ClassNotFoundException | NoClassDefFoundError e) {
                unresolved.add(marker[0] + "  (reached from " + marker[1] + ")");
            }
        }
        if (!unresolved.isEmpty()) {
            fail("The real-Ghidra test classpath is incomplete -- " + unresolved.size()
                + " of " + MARKERS.length + " libraries in the SLEIGH-loading chain did not"
                + " resolve:\n  " + String.join("\n  ", unresolved)
                + "\nUnder Maven these come from the " + PROFILE_ID + " profile in pom.xml"
                + " (activated by GHIDRA_INSTALL_DIR being set) plus the ghidra:Graph test"
                + " dependency; under Gradle they come from build.gradle's fileTree over the"
                + " installation. If the profile is present but inert, check that this run"
                + " actually activated it: mvn help:active-profiles.");
        }
    }

    /** Reads the profile's {@code additionalClasspathElements}, resolving its properties. */
    private static List<String> readProfileClasspathElements(String installDir) throws Exception {
        File pom = new File(System.getProperty("basedir", "."), "pom.xml");
        assertTrue("pom.xml not found at " + pom.getAbsolutePath(), pom.isFile());

        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(false);
        Element profile = null;
        NodeList profiles = factory.newDocumentBuilder().parse(pom).getElementsByTagName("profile");
        for (int i = 0; i < profiles.getLength(); i++) {
            Element candidate = (Element) profiles.item(i);
            if (PROFILE_ID.equals(childText(candidate, "id"))) {
                profile = candidate;
                break;
            }
        }
        if (profile == null) {
            fail("pom.xml has no " + PROFILE_ID + " profile -- the real-Ghidra test tier has no"
                + " way to put Ghidra's bundled third-party jars on the Maven test classpath.");
        }

        Map<String, String> properties = new LinkedHashMap<>();
        properties.put("env.GHIDRA_INSTALL_DIR", installDir);
        NodeList propertyBlocks = profile.getElementsByTagName("properties");
        for (int i = 0; i < propertyBlocks.getLength(); i++) {
            NodeList declared = propertyBlocks.item(i).getChildNodes();
            for (int j = 0; j < declared.getLength(); j++) {
                Node node = declared.item(j);
                if (node.getNodeType() == Node.ELEMENT_NODE) {
                    properties.put(node.getNodeName(), expand(node.getTextContent(), properties));
                }
            }
        }

        List<String> elements = new ArrayList<>();
        NodeList declared = profile.getElementsByTagName("element");
        for (int i = 0; i < declared.getLength(); i++) {
            elements.add(expand(declared.item(i).getTextContent(), properties));
        }
        return elements;
    }

    private static String expand(String value, Map<String, String> properties) {
        String expanded = value.trim();
        for (Map.Entry<String, String> property : properties.entrySet()) {
            expanded = expanded.replace("${" + property.getKey() + "}", property.getValue());
        }
        return expanded;
    }

    private static String childText(Element parent, String tag) {
        NodeList children = parent.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            Node node = children.item(i);
            if (node.getNodeType() == Node.ELEMENT_NODE && tag.equals(node.getNodeName())) {
                return node.getTextContent().trim();
            }
        }
        return null;
    }
}
