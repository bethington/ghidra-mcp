// SetPerspComments.java
//@category RE - Comment
//@author Claude
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
public class SetPerspComments extends GhidraScript {
    @Override
    public void run() throws Exception {
        long BASE = 0x6fb65510L;
        Address fa = currentProgram.getAddressFactory().getAddress(Long.toHexString(BASE));
        Listing lst = currentProgram.getListing();
        Function func = currentProgram.getFunctionManager().getFunctionAt(fa);
        if (func == null) { println("ERROR: not found at " + fa); return; }
        println("Found: " + func.getName());
        String plate =
            "Allocates and populates five perspective-mode rendering lookup tables used\n" +
            "by the software renderer for isometric perspective correction.\n\n" +
            "Algorithm:\n" +
            "1. Guard: assert all five table pointers are NULL; abort with source\n" +
            "   line numbers 0xca-0xce (202-206) if any is already allocated.\n" +
            "2. Call CopyGlobalRenderBuffer (ECX = render buffer context 0x6fbac3e0).\n" +
            "3. AllocateExtendedLookupTable(32, 8)    -> g_dwViewWidth  (0x6fbcca70)\n" +
            "4. AllocateAndGenerateLookupTable(32,16) -> g_dwViewHeight (0x6fbcca74)\n" +
            "5. AllocateAndGenerateLookupTable(32,32) -> g_dwViewBitDepth (0x6fbcca78)\n" +
            "6. AllocatePerspectiveLookupTable(32,32) -> g_dwViewParam0 (0x6fbcca80)\n" +
            "7. AllocateAndGenerateLookupTable(32,40) -> g_dwViewParam1 (0x6fbcca84)\n\n" +
            "Parameters: none\n" +
            "Returns:    void. Never returns if any table pointer is already non-NULL.\n\n" +
            "Special Cases:\n" +
            "  - 0x20 (32) is the first arg to all five allocators (entry count).\n" +
            "  - Second args 0x08/0x10/0x20/0x28 are stride/type identifiers per table.\n" +
            "  - 0x6fbcca7c is skipped (reserved slot between tables 2 and 3).\n" +
            "  - pContext and nLineNumber are register-only SSA vars (no frame storage).";
        lst.setComment(fa, CodeUnit.PLATE_COMMENT, plate);
        println("Plate comment set.");
        long[] off = {0x09,0x19,0x29,0x39,0x49,0x68,0x72,0x74,0x7b,0x7d,0x89,0x8b,0x97,0x99,0xa5,0xa7};
        String[] eol = {"line 202 (0xca): g_dwViewWidth already allocated","line 203 (0xcb): g_dwViewHeight already allocated","line 204 (0xcc): g_dwViewBitDepth already allocated","line 205 (0xcd): g_dwViewParam0 already allocated","line 206 (0xce): g_dwViewParam1 already allocated","render buf ctx ptr (CopyGlobalRenderBuffer thisptr)","table0: size/type param = 8","table0: entry count = 32 (0x20)","table1: size/type param = 16 (0x10)","table1: entry count = 32 (0x20)","table2: size/type param = 32 (0x20)","table2: entry count = 32 (0x20)","table3 (persp): size/type = 32 (0x20)","table3: entry count = 32 (0x20)","table4: size/type param = 40 (0x28)","table4: entry count = 32 (0x20)"};
        int set = 0;
        for (int i=0;i<off.length;i++) {
            Address a = currentProgram.getAddressFactory().getAddress(Long.toHexString(BASE+off[i]));
            CodeUnit c = lst.getCodeUnitAt(a);
            if (c != null) { c.setComment(CodeUnit.EOL_COMMENT, eol[i]); set+; }
            else { println("WARN: no cu at " + a); }
        }
        println("Done: plate + " + set + "/" + off.length + " EOL comments applied.");
    }
}