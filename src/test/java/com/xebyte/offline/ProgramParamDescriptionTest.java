package com.xebyte.offline;

import com.xebyte.core.AnnotationScanner;
import org.junit.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * Every tool's {@code program} parameter gets {@link AnnotationScanner#PROGRAM_PARAM_DESCRIPTION}
 * unless the tool supplies its own description.
 */
public class ProgramParamDescriptionTest {

    private static final AnnotationScanner SCANNER = ServiceFactory.buildGuiScanner();

    @Test
    public void anUndescribedProgramParamGetsTheSharedText() {
        AnnotationScanner.ParamDescriptor program = SCANNER.getDescriptors().stream()
            .filter(t -> t.path().equals("/get_change_token"))
            .flatMap(t -> t.params().stream())
            .filter(p -> p.name().equals("program"))
            .findFirst().orElseThrow();
        assertTrue(program.description(), program.description().startsWith("Target program: its project path"));
    }

    @Test
    public void noToolCarriesItsOwnCopyOfTheBoilerplate() {
        List<String> copies = new ArrayList<>();
        for (AnnotationScanner.ToolDescriptor tool : SCANNER.getDescriptors()) {
            for (AnnotationScanner.ParamDescriptor p : tool.params()) {
                if (p.name().equals("program")
                        && (p.description().startsWith("Target program name")
                            || p.description().startsWith("Target program path"))) {
                    copies.add(tool.path() + ": " + p.description());
                }
            }
        }
        assertEquals("drop the description and let the scanner supply it", List.of(), copies);
    }
}
