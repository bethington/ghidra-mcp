// D2Client
//
// Batch applies documentation to specific D2Client.dll functions related to viewport management, resolution switching, screen shifting, and UI panel toggling.
//
// Usage: Run from Script Manager. Opens D2Client.dll from project path /Vanilla/1.13c/.
// Output: Renames and documents viewport/resolution functions in D2Client.dll.
//
// @author Ben Ethington
// @category Diablo 2.Documentation
// @description Document D2Client.dll viewport and resolution functions
// @menupath Diablo 2.Documentation.D2Client

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.framework.model.*;

public class Document_D2Client extends GhidraScript {
    @Override
    public void run() throws Exception {
        Project project = state.getProject();
        ProjectData pd = project.getProjectData();
        DomainFile df = pd.getFile("/Vanilla/1.13c/D2Client.dll");
        if (df == null) { println("D2Client.dll not found"); return; }
        Program prog = (Program) df.getDomainObject(this, false, false, monitor);
        println("Opened: " + prog.getName() + " base=0x" + Long.toHexString(prog.getImageBase().getOffset()));

        var fm = prog.getFunctionManager();
        var space = prog.getAddressFactory().getDefaultAddressSpace();
        int txn = prog.startTransaction("Document D2Client viewport/resolution functions");
        try {
            // Resolution and viewport functions
            String[][] funcs = {
                // Viewport/Panel
                {"6faeff90", "SetViewportModeAndFadeState", "Sets viewport offset by panel mode. Mode 0=no shift, 1=-(W/4) right panel, 2=+(W/4) left panel, 3=full reset. Calls SetPaletteValue+ConfigureViewportClippingRectangle."},
                {"6fb3a4d0", "ConfigureViewportClippingRectangle", "Sets viewport clip rect with 80px padding. SGD2FreeRes JMP hook at RVA 0x8A4D0 (5 bytes). Uses g_dwScreenWidth/Height for outer bounds. Perspective mode adds +/-30px."},
                {"6fb15e70", "ProcessPanelToggleCommand", "Central UI panel toggle. Cmd 0=main/inv, 1=char, 2=skill, 3=party, 4=hireling, 5=chat, 6=quest, 7=reinit display. Manages viewport offset via SetPaletteValue."},
                {"6fb2f260", "HandleUIEventAndUpdateViewportMode", "Updates viewport/trade state on UI events. Validates mouse coords, manages SystemModeFlag transitions, sets GlobalTradeWindowXOffset."},
                // Resolution setter
                {"6fac0df0", "SetResolutionAndInitGraphics", "Resolution mode setter. Mode 0=640x480, 2=800x600. Sets g_dwScreenWidth/Height, viewportHeight=H-40. Calls InitializeGame+SetViewportModeAndFadeState. SGD2FreeRes CALL hook at RVA 0x10DFD."},
                // Screen shift
                {"6fb739e0", "ProcessCompleteGameUIRenderingPipeline", "Main UI render pipeline. SGD2FreeRes CALL hook at RVA 0xC39F6 for set_screen_shift (screen centering offsets). patch_resolution_v2.py rewrites 0x27 bytes at 0xC39F6."},
                // Menu positioning
                {"6fb7daa0", "CalculateScreenLeftBoundaryForCentering", "ScreenLeftBoundary = (g_dwScreenWidth - 325) / 2. Called on resolution change. Used to center 325px-wide UI elements."},
                {"6fb7dca0", "CalculateUIElementCoordinatesFromScreenDimensions", "Computes 12 UI element coords from screenW/H. Y offsets: -105,-140,-160,-195,-143,-198 from bottom. X offsets: W/2+40, W/2+75."},
                {"6fb7dd90", "CalculateMenuPanelYPosition", "Y = (viewportHeight - 420) / 2 + 47. Centers 420px-tall menu panel vertically."},
                // Button bounds (SGD2FreeRes JMP hooks)
                {"6faffe70", "CheckMouseInButtonBounds", "Interface bar right-side button hit test. Reads g_dwScreenWidth, divides by 2. SGD2FreeRes JMP at RVA 0x4FE70 (68 bytes) for enable_800_new_skill_button."},
                {"6fafff10", "CheckMouseInLeftPanelButtonBounds", "Interface bar left-side button hit test. Same pattern. SGD2FreeRes JMP at RVA 0x4FF10 (69 bytes) for enable_800_new_stats_button."},
                // Game state transitions
                {"6face7e0", "ProcessSystemTransitionWithScreenFade", "System state transition. Resets viewport (SetPaletteValue(0)) when no player slots active. Handles split-screen offset for trade."},
                {"6faec5b0", "UpdateViewportAndSecurityState", "Viewport update with security validation. Calls SetPaletteValue with quarter-screen offsets based on player slot state."},
                // Rendering
                {"6fae62e0", "RenderGameScreenBorders", "Draws 8 border elements around game screen."},
                {"6fb3a090", "CreateGameViewportContext", "Allocates 0xEABC-byte viewport context struct from View.cpp. Requires audio init."},
                {"6fb14910", "SetPerspectiveModeAndConfigureViewportClipping", "Saves perspective to registry, applies via ConfigureViewportClippingRectangle with full screen dims."},
                // SetPaletteValue wrapper
                {"6fabd1b0", "SetPaletteValue", "Thin wrapper: calls D2Common_SetViewportPanelOffset (IAT). Forwards panel offset to D2Gfx SetViewportPanelMode (ord 11103). ~80 call sites in D2Client."},
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

            // Globals
            var listing = prog.getListing();
            var sym = prog.getSymbolTable();
            String[][] globals = {
                {"6fb8bc48", "g_dwScreenWidth", "Screen width in pixels. 640 or 800 vanilla. Patched by SGD2FreeRes and patch_resolution_v2.py."},
                {"6fb8bc4c", "g_dwScreenHeight", "Screen height in pixels. 480 or 600 vanilla."},
                {"6fba9e18", "g_dwViewportHeight", "Viewport height = screenHeight - 40. Used by CalculateMenuPanelYPosition."},
                {"6fbcec38", "g_dwScreenLeftBoundary", "Computed (screenWidth-325)/2. Written by CalculateScreenLeftBoundaryForCentering."},
                {"6fbdc010", "g_dwViewportHeightForMenu", "Read by CalculateMenuPanelYPosition for menu centering."},
                {"6fbf8f28", "g_dwMenuPositionY", "Computed menu Y position. Written by CalculateMenuPanelYPosition."},
            };
            for (String[] g : globals) {
                var addr = space.getAddress(Long.parseLong(g[0], 16));
                try { sym.createLabel(addr, g[1], SourceType.USER_DEFINED); } catch (Exception e) {}
                listing.setComment(addr, CodeUnit.EOL_COMMENT, g[2]);
                println("  Label: " + g[1]);
            }
        } finally {
            prog.endTransaction(txn, true);
        }
        prog.release(this);
        println("D2Client documentation complete.");
    }
}
