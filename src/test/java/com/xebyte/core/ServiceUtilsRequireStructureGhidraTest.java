package com.xebyte.core;

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Structure;
import org.junit.BeforeClass;
import org.junit.Test;

import java.util.List;

import static org.junit.Assert.*;
import static org.junit.Assume.assumeTrue;
import static org.mockito.Mockito.*;

/**
 * {@link ServiceUtils#requireStructure} / {@link ServiceUtils#requireEnum}. Real-Ghidra tier: mocking
 * a data type runs {@code DataType}'s static initializer, which needs the libraries only the
 * installation puts on the classpath.
 */
public class ServiceUtilsRequireStructureGhidraTest {

    @BeforeClass
    public static void requireGhidra() {
        assumeTrue("GHIDRA_INSTALL_DIR is required for real Ghidra tests",
                System.getenv("GHIDRA_INSTALL_DIR") != null);
    }

    @Test
    public void requireStructureReturnsNamedStructure() {
        Structure struct = mock(Structure.class);
        when(struct.getName()).thenReturn("Foo");
        DataTypeManager dtm = dtmWith(struct);

        assertSame(struct, ServiceUtils.requireStructure(dtm, "Foo"));
    }

    @Test
    public void requireStructureNotFoundMessage() {
        DataTypeManager dtm = dtmWith();
        try {
            ServiceUtils.requireStructure(dtm, "Missing");
            fail("expected Refusal");
        } catch (Refusal r) {
            assertEquals("Structure not found: Missing", r.getMessage());
        }
    }

    @Test
    public void requireStructureWrongKindMessageUsesQuotes() {
        DataType other = mock(DataType.class);
        when(other.getName()).thenReturn("NotAStruct");
        DataTypeManager dtm = dtmWith(other);
        try {
            ServiceUtils.requireStructure(dtm, "NotAStruct");
            fail("expected Refusal");
        } catch (Refusal r) {
            assertEquals("Data type 'NotAStruct' is not a structure", r.getMessage());
        }
    }

    @Test
    public void requireEnumReturnsNamedEnum() {
        ghidra.program.model.data.Enum enm = mock(ghidra.program.model.data.Enum.class);
        when(enm.getName()).thenReturn("Color");
        DataTypeManager dtm = dtmWith(enm);

        assertSame(enm, ServiceUtils.requireEnum(dtm, "Color"));
    }

    @Test
    public void requireEnumNotFoundAndWrongKindMessages() {
        DataTypeManager empty = dtmWith();
        try {
            ServiceUtils.requireEnum(empty, "Gone");
            fail("expected Refusal");
        } catch (Refusal r) {
            assertEquals("Enumeration not found: Gone", r.getMessage());
        }

        DataType other = mock(DataType.class);
        when(other.getName()).thenReturn("NotEnum");
        DataTypeManager dtm = dtmWith(other);
        try {
            ServiceUtils.requireEnum(dtm, "NotEnum");
            fail("expected Refusal");
        } catch (Refusal r) {
            assertEquals("Data type 'NotEnum' is not an enumeration", r.getMessage());
        }
    }

    private static DataTypeManager dtmWith(DataType... types) {
        DataTypeManager dtm = mock(DataTypeManager.class);
        when(dtm.getAllDataTypes()).thenAnswer(inv -> List.of(types).iterator());
        return dtm;
    }
}
