// D2Gfx
//
// Batch applies documentation to specific D2Gfx.dll functions related to viewport coordinates, screen dimensions, panel modes, and scroll offsets.
//
// Usage: Run from Script Manager. Opens D2Gfx.dll from project path /Vanilla/1.13c/.
// Output: Renames and documents graphics functions in D2Gfx.dll.
//
// @author Ben Ethington
// @category Diablo 2.Documentation
// @description Document D2Gfx.dll viewport and graphics functions
// @menupath Diablo 2.Documentation.D2Gfx

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.framework.model.*;

public class Document_D2Gfx extends GhidraScript {
    @Override
    public void run() throws Exception {
        // Find D2Gfx in the project
        Project project = state.getProject();
        if (project == null) { println("No project"); return; }
        ProjectData pd = project.getProjectData();
        DomainFile df = pd.getFile("/Vanilla/1.13c/D2Gfx.dll");
        if (df == null) { println("D2Gfx.dll not found in project"); return; }

        Program d2gfx = (Program) df.getDomainObject(this, false, false, monitor);
        println("Opened: " + d2gfx.getName() + " base=0x" + Long.toHexString(d2gfx.getImageBase().getOffset()));

        var fm = d2gfx.getFunctionManager();
        var space = d2gfx.getAddressFactory().getDefaultAddressSpace();
        int txn = d2gfx.startTransaction("Document viewport functions");
        try {
            String[][] funcs = {
                {"6fa88970", "Screen_InitializeViewportCoords", "Viewport coord init. Mode 0=no shift, 1=right panel (halved), 2=left panel (offset). Reads g_nViewportPanelMode."},
                {"6fa8aec0", "Screen_SetDimensionsAndLUT", "Sets screen dims, rebuilds scanline LUT, calls Screen_InitializeViewportCoords if panel mode changed."},
                {"6fa87fd0", "GetDisplaySizeFromMode", "Ord 10025. Mode 0:640x480, 1/2:800x600, 3:1344x700. SGD2FreeRes patches RVA 0x7FD0 (0x24 bytes)."},
                {"6fa8b190", "SetViewportPanelMode", "Ord 11103. Sets g_nViewportPanelMode (0-3). Called from D2Client SetPaletteValue -> D2Common."},
                {"6fa8b800", "GfxSetScrollOffset", "Ord 10057. Sets scroll ref coords, calls gfx vtable 0x60."},
                {"6fa8b920", "GfxIsPointInViewport", "Ord 10012. True if within 0x320000 units of scroll ref."},
                {"6fa8aee0", "DisplaySettings_LoadAndApply", "Loads Contrast+Gamma from registry, applies via gfx vtable 0x30 and 0x58."},
                {"6fa8b1e0", "GfxInterface_SetGamma", "Ord 10034. Sets gamma (NOT screen shift). Calls gfx vtable 0x58."},
                {"6fa8b320", "GetResolutionWindowHandle", "Ord 10031. Returns g_nWindowState."},
                {"6fa8b340", "GetVideoMode", "Returns g_nVideoMode (1=SW,2=DDraw,3=Glide,4=OGL,5=D3D)."},
                {"6fa8b330", "GetFullscreenFlag", "Ord 10004. Returns g_bFullscreenEnabled."},
                {"6fa87fb0", "GetGameWindowHandle", "Returns g_hGameWindow (HWND)."},
                {"6fa8af80", "InitializeGame_GfxEntry", "Calls InitializeTileBlendLookup, resets init counter."},
                {"6fa8b9f0", "GfxSetClipRectangle", "Ord 10056. Validates rect, calls gfx vtable 0xBC."},
                {"6fa8ba30", "GfxValidateClipCoordinates", "Ord 10055. Validates rect, calls gfx vtable 0xB8."},
                {"6fa88650", "InitializeMainGameWindow", "Creates D2 game window. Sets g_hGameWindow, g_bFullscreenEnabled, g_nWindowState."},
                {"6fa88100", "CenterWindowAndStoreRect", "Centers window on screen, stores initial rect to rInitialWindowRect."},
                {"6fa884d0", "SynchronizeDisplayMode", "Syncs display mode with window state."},
                {"6fa8b650", "InitializeGraphicsAndWindow", "Main graphics init. Sets g_nVideoMode, g_bFullscreenEnabled, loads renderer DLL."},
            };
            for (String[] f : funcs) {
                var func = fm.getFunctionAt(space.getAddress(Long.parseLong(f[0], 16)));
                if (func != null) {
                    func.setName(f[1], SourceType.USER_DEFINED);
                    func.setComment(f[2]);
                    println("  OK: " + f[1]);
                } else {
                    println("  MISS: 0x" + f[0] + " " + f[1]);
                }
            }

            var listing = d2gfx.getListing();
            var sym = d2gfx.getSymbolTable();
            String[][] globals = {
                {"6fa91270", "g_nViewportPanelMode", "Panel mode 0-3. Set by ord 11103."},
                {"6fa95440", "g_nViewportXOffset", "Viewport X offset. 0=no panels, width/2=left panel."},
                {"6fa91264", "g_hGameWindow", "HWND game window."},
                {"6fa91258", "g_nVideoMode", "1=SW,2=DDraw,3=Glide,4=OGL,5=D3D."},
                {"6fa9125c", "g_bFullscreenEnabled", "0=windowed, non-zero=fullscreen."},
                {"6fa91260", "g_nWindowState", "Window state for InitializeMainGameWindow."},
                {"6fa90bec", "g_nGammaValue", "Gamma value. Set by GfxInterface_SetGamma."},
                {"6fa9d470", "rInitialWindowRect", "RECT stored by CenterWindowAndStoreRect. Exported as ord 10087."},
            };
            for (String[] g : globals) {
                var addr = space.getAddress(Long.parseLong(g[0], 16));
                try { sym.createLabel(addr, g[1], SourceType.USER_DEFINED); } catch (Exception e) {}
                listing.setComment(addr, CodeUnit.EOL_COMMENT, g[2]);
                println("  Label: " + g[1]);
            }
        } finally {
            d2gfx.endTransaction(txn, true);
        }
        d2gfx.release(this);
        println("D2Gfx documentation complete.");
    }
}
