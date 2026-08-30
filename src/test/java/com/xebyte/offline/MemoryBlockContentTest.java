package com.xebyte.offline;

import com.xebyte.core.ProgramScriptService;
import com.xebyte.core.ProgramScriptService.BlockContentPlan;
import junit.framework.TestCase;

import java.util.Base64;

/**
 * Offline coverage for {@code /create_memory_block}'s byte-content support (issue #404).
 *
 * <p>Both halves of the feature are pure functions on purpose — decoding the wire
 * payload and reconciling it against the requested block length happen <em>before</em>
 * any transaction opens, so a malformed request can never touch the program database.
 * That also makes them testable with no Ghidra program, which is what this class does.
 *
 * <p>The one rule worth stating out loud: content longer than {@code size} is an error,
 * never a truncation. Silently dropping bytes the caller sent would produce a block that
 * reports success and contains the wrong program.
 */
public class MemoryBlockContentTest extends TestCase {

    // ------------------------------------------------------------------
    // Hex decoding
    // ------------------------------------------------------------------

    public void testDecodePlainHex() {
        byte[] b = ProgramScriptService.decodeBlockContent("deadbeef", "");
        assertEquals(4, b.length);
        assertEquals((byte) 0xDE, b[0]);
        assertEquals((byte) 0xAD, b[1]);
        assertEquals((byte) 0xBE, b[2]);
        assertEquals((byte) 0xEF, b[3]);
    }

    public void testDecodeHexIsCaseInsensitive() {
        assertEquals(
            java.util.Arrays.toString(ProgramScriptService.decodeBlockContent("DEADBEEF", "")),
            java.util.Arrays.toString(ProgramScriptService.decodeBlockContent("deadbeef", "")));
    }

    public void testDecodeHexToleratesSpacingAndPrefix() {
        byte[] spaced = ProgramScriptService.decodeBlockContent("de ad\tbe\nef", "");
        byte[] commas = ProgramScriptService.decodeBlockContent("de,ad,be,ef", "");
        byte[] prefix = ProgramScriptService.decodeBlockContent("0xdeadbeef", "");
        assertEquals(4, spaced.length);
        assertEquals(4, commas.length);
        assertEquals(4, prefix.length);
        assertEquals((byte) 0xEF, spaced[3]);
        assertEquals((byte) 0xEF, commas[3]);
        assertEquals((byte) 0xEF, prefix[3]);
    }

    public void testDecodeHexRejectsOddLength() {
        try {
            ProgramScriptService.decodeBlockContent("abc", "");
            fail("expected rejection of an odd-length hex string");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage(), e.getMessage().contains("even number of hex digits"));
        }
    }

    /**
     * A bad character must be named by position. The precedent implementation in
     * EmulationService lets Integer.parseInt throw, which surfaces to the caller as
     * a bare NumberFormatException naming a two-character substring and nothing else.
     */
    public void testDecodeHexNamesTheOffendingCharacter() {
        try {
            ProgramScriptService.decodeBlockContent("dead" + "zz" + "beef", "");
            fail("expected rejection of a non-hex character");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage(), e.getMessage().contains("non-hex character 'z'"));
            assertTrue(e.getMessage(), e.getMessage().contains("position 4"));
        }
    }

    public void testDecodeHexRejectsNoDigits() {
        // Blank-only input means "not supplied", not "malformed".
        assertEquals(0, ProgramScriptService.decodeBlockContent("   ", "").length);
        // "0x" alone strips to nothing and IS an error: content was clearly intended.
        try {
            ProgramScriptService.decodeBlockContent("0x", "");
            fail("expected rejection of a hex string with no digits");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage(), e.getMessage().contains("no hex digits"));
        }
    }

    // ------------------------------------------------------------------
    // Base64 decoding
    // ------------------------------------------------------------------

    public void testDecodeBase64() {
        byte[] raw = {(byte) 'M', (byte) 'Z', (byte) 0x90, (byte) 0x00};
        String b64 = Base64.getEncoder().encodeToString(raw);
        byte[] b = ProgramScriptService.decodeBlockContent("", b64);
        assertEquals(4, b.length);
        assertEquals((byte) 'M', b[0]);
        assertEquals((byte) 'Z', b[1]);
    }

    public void testDecodeBase64ToleratesWhitespace() {
        String b64 = Base64.getEncoder().encodeToString(new byte[] {1, 2, 3, 4, 5, 6});
        String wrapped = b64.substring(0, 4) + "\n" + b64.substring(4);
        assertEquals(6, ProgramScriptService.decodeBlockContent("", wrapped).length);
    }

    public void testDecodeBase64RejectsGarbage() {
        try {
            ProgramScriptService.decodeBlockContent("", "!!!not base64!!!");
            fail("expected rejection of invalid base64");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage(), e.getMessage().contains("not valid base64"));
        }
    }

    // ------------------------------------------------------------------
    // Encoding selection
    // ------------------------------------------------------------------

    public void testNeitherEncodingYieldsEmptyContent() {
        assertEquals(0, ProgramScriptService.decodeBlockContent(null, null).length);
        assertEquals(0, ProgramScriptService.decodeBlockContent("", "").length);
        assertEquals(0, ProgramScriptService.decodeBlockContent("  ", "  ").length);
    }

    public void testBothEncodingsIsAnError() {
        try {
            ProgramScriptService.decodeBlockContent("dead", "3q0=");
            fail("expected rejection when both encodings are supplied");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage(), e.getMessage().contains("only one of bytes_hex or bytes_base64"));
        }
    }

    // ------------------------------------------------------------------
    // Size caps — an HTTP endpoint taking arbitrary bytes must refuse, not OOM
    // ------------------------------------------------------------------

    /**
     * The cap is checked against the ENCODED length, before any byte[] is allocated.
     * A hex string 2 characters over the limit must be refused without materializing
     * the 16 MB array it describes.
     */
    public void testHexOverCapIsRejectedBeforeAllocation() {
        int overBytes = ProgramScriptService.MAX_BLOCK_CONTENT_BYTES + 1;
        StringBuilder sb = new StringBuilder(overBytes * 2);
        for (int i = 0; i < overBytes; i++) {
            sb.append("00");
        }
        try {
            ProgramScriptService.decodeBlockContent(sb.toString(), "");
            fail("expected rejection of an oversized hex payload");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage(), e.getMessage().contains("over the"));
            assertTrue(e.getMessage(),
                e.getMessage().contains(String.valueOf(ProgramScriptService.MAX_BLOCK_CONTENT_BYTES)));
        }
    }

    public void testBase64OverCapIsRejected() {
        // 4 base64 chars -> 3 bytes; build a string whose estimate clears the cap.
        int chars = ((ProgramScriptService.MAX_BLOCK_CONTENT_BYTES / 3) + 16) * 4;
        StringBuilder sb = new StringBuilder(chars);
        for (int i = 0; i < chars; i++) {
            sb.append('A');
        }
        try {
            ProgramScriptService.decodeBlockContent("", sb.toString());
            fail("expected rejection of an oversized base64 payload");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage(), e.getMessage().contains("over the"));
        }
    }

    public void testContentCapFitsInsideTheRequestBodyCapInBothEncodings() {
        // hex doubles the payload, base64 grows it by a third; both must still fit
        // under SecurityConfig.MAX_REQUEST_BODY_BYTES or the cap is unreachable.
        long hexWire = 2L * ProgramScriptService.MAX_BLOCK_CONTENT_BYTES;
        long b64Wire = (long) Math.ceil(ProgramScriptService.MAX_BLOCK_CONTENT_BYTES / 3.0) * 4;
        assertTrue("hex wire form must fit in the request body cap",
            hexWire < com.xebyte.core.SecurityConfig.MAX_REQUEST_BODY_BYTES);
        assertTrue("base64 wire form must fit in the request body cap",
            b64Wire < com.xebyte.core.SecurityConfig.MAX_REQUEST_BODY_BYTES);
    }

    // ------------------------------------------------------------------
    // Reconciling content against size
    // ------------------------------------------------------------------

    public void testContentWithNoSizeSizesTheBlockToTheContent() {
        BlockContentPlan plan = ProgramScriptService.planBlockContent(
            new byte[] {1, 2, 3, 4}, false, 0, 0);
        assertEquals(4L, plan.size());
        assertEquals(0L, plan.paddedBytes());
        assertTrue("supplying content must force an initialized block", plan.initialized());
    }

    public void testContentShorterThanSizeIsPadded() {
        BlockContentPlan plan = ProgramScriptService.planBlockContent(
            new byte[] {(byte) 0x4D, (byte) 0x5A}, false, 4096, 0xCC);
        assertEquals(4096L, plan.size());
        assertEquals(2, plan.content().length);
        assertEquals(4094L, plan.paddedBytes());
        assertEquals(0xCC, plan.fillByte());
    }

    /** Bytes are never truncated: over-long content is a refusal, not a silent trim. */
    public void testContentLongerThanSizeIsRejected() {
        try {
            ProgramScriptService.planBlockContent(new byte[] {1, 2, 3, 4, 5}, false, 4, 0);
            fail("expected rejection when content exceeds size");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage(), e.getMessage().contains("5 bytes but size is 4"));
            assertTrue(e.getMessage(), e.getMessage().contains("never truncated"));
        }
    }

    public void testContentExactlyFillingSizeIsNotPadded() {
        BlockContentPlan plan = ProgramScriptService.planBlockContent(
            new byte[] {1, 2, 3, 4}, false, 4, 0);
        assertEquals(4L, plan.size());
        assertEquals(0L, plan.paddedBytes());
    }

    public void testNoContentStillRequiresAPositiveSize() {
        try {
            ProgramScriptService.planBlockContent(new byte[0], false, 0, 0);
            fail("expected rejection of a zero-size block with no content");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage(), e.getMessage().contains("size must be positive"));
        }
        try {
            ProgramScriptService.planBlockContent(new byte[0], false, -8, 0);
            fail("expected rejection of a negative size");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage(), e.getMessage().contains("size must be positive"));
        }
    }

    /** The pre-#404 behavior: no content, initialized=false, positive size. */
    public void testUninitializedBlockIsStillTheDefault() {
        BlockContentPlan plan = ProgramScriptService.planBlockContent(new byte[0], false, 0x1000, 0);
        assertFalse(plan.initialized());
        assertEquals(0x1000L, plan.size());
        assertEquals(0, plan.content().length);
    }

    public void testInitializedCanBeRequestedWithoutContent() {
        BlockContentPlan plan = ProgramScriptService.planBlockContent(new byte[0], true, 64, 0xFF);
        assertTrue(plan.initialized());
        assertEquals(64L, plan.size());
        assertEquals(64L, plan.paddedBytes());
    }

    public void testFillByteMustBeAByte() {
        for (int bad : new int[] {-1, 256, 1000}) {
            try {
                ProgramScriptService.planBlockContent(new byte[0], true, 16, bad);
                fail("expected rejection of fill_byte " + bad);
            } catch (IllegalArgumentException e) {
                assertTrue(e.getMessage(), e.getMessage().contains("fill_byte must be between 0 and 255"));
            }
        }
        // Both ends of the range are legal.
        assertEquals(0, ProgramScriptService.planBlockContent(new byte[0], true, 16, 0).fillByte());
        assertEquals(255, ProgramScriptService.planBlockContent(new byte[0], true, 16, 255).fillByte());
    }

    /**
     * An initialized block is real database storage written on the Swing thread, so it
     * gets a ceiling. An uninitialized block costs nothing per byte and keeps the
     * pre-existing unrestricted behavior — mapping a multi-gigabyte MMIO aperture is
     * a legitimate thing this endpoint already supported.
     */
    public void testInitializedBlockSizeIsCappedButUninitializedIsNot() {
        long over = ProgramScriptService.MAX_INITIALIZED_BLOCK_BYTES + 1;
        try {
            ProgramScriptService.planBlockContent(new byte[0], true, over, 0);
            fail("expected rejection of an oversized initialized block");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage(), e.getMessage().contains("initialized=false"));
        }
        BlockContentPlan uninit = ProgramScriptService.planBlockContent(new byte[0], false, over, 0);
        assertEquals(over, uninit.size());
        assertFalse(uninit.initialized());
    }

    public void testTinyContentInsideAHugeBlockIsStillCapped() {
        long over = ProgramScriptService.MAX_INITIALIZED_BLOCK_BYTES + 1;
        try {
            ProgramScriptService.planBlockContent(new byte[] {1}, false, over, 0);
            fail("content implies initialized, so the initialized cap must apply");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage(), e.getMessage().contains("initialized block"));
        }
    }

    public void testNullContentIsTreatedAsNone() {
        BlockContentPlan plan = ProgramScriptService.planBlockContent(null, false, 32, 0);
        assertNotNull(plan.content());
        assertEquals(0, plan.content().length);
        assertFalse(plan.initialized());
    }

    // ------------------------------------------------------------------
    // End-to-end of the two pure stages
    // ------------------------------------------------------------------

    public void testHexAndBase64OfTheSameBytesProduceTheSamePlan() {
        byte[] raw = {(byte) 0x90, (byte) 0x90, (byte) 0xC3};
        BlockContentPlan viaHex = ProgramScriptService.planBlockContent(
            ProgramScriptService.decodeBlockContent("9090c3", ""), false, 16, 0);
        BlockContentPlan viaB64 = ProgramScriptService.planBlockContent(
            ProgramScriptService.decodeBlockContent("", Base64.getEncoder().encodeToString(raw)),
            false, 16, 0);
        assertEquals(viaHex.size(), viaB64.size());
        assertEquals(viaHex.paddedBytes(), viaB64.paddedBytes());
        assertEquals(java.util.Arrays.toString(viaHex.content()),
                     java.util.Arrays.toString(viaB64.content()));
    }
}
