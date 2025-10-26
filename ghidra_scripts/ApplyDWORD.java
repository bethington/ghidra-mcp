//Apply DWORD from windows.h
//@category Data
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Data;

public class ApplyDWORD extends GhidraScript {
    
    @Override
    public void run() throws Exception {
        // Validate we have a program loaded
        if (currentProgram == null) {
            printerr("No program is currently open.");
            return;
        }
        
        // Validate we have a current location
        if (currentLocation == null) {
            printerr("No location selected. Please position cursor at desired address.");
            return;
        }
        
        // Get current location
        Address currentAddress = currentLocation.getAddress();
        if (currentAddress == null) {
            printerr("No valid address at current location.");
            return;
        }
        
        // Get data type manager
        DataTypeManager dtm = currentProgram.getDataTypeManager();
        
        // Find DWORD from windows data types - try multiple common paths
        DataType dwordType = null;
        
        // Try various common locations for DWORD (note: case-sensitive!)
        String[] possiblePaths = {
            "/WinDef.h/DWORD",      // Standard location (case-sensitive!)
            "/windef.h/DWORD",      // Lowercase variant
            "/windows.h/DWORD",     // Alternative location
            "/DWORD",               // Root level
            "DWORD"                 // Simple name
        };
        
        for (String path : possiblePaths) {
            dwordType = dtm.getDataType(path);
            if (dwordType != null) {
                println("Found DWORD at: " + path);
                break;
            }
        }
        
        // If still not found, create a simple DWORD as unsigned 4-byte integer
        if (dwordType == null) {
            println("DWORD type not found in data type manager.");
            println("Using built-in unsigned int (4 bytes) as fallback.");
            
            // Use the built-in unsigned int (dword) type
            dwordType = dtm.getDataType("/dword");
            
            if (dwordType == null) {
                // Last resort: use ulong which is typically 4 bytes on Windows
                dwordType = dtm.getDataType("/ulong");
            }
            
            if (dwordType == null) {
                printerr("ERROR: Could not find any suitable 4-byte integer type.");
                printerr("Try: Window -> Data Type Manager -> Open File Archive -> windows_vs12_32");
                return;
            }
        }
        
        try {
            // Clear any existing data at this location
            clearListing(currentAddress, currentAddress.add(dwordType.getLength() - 1));
            
            // Apply the DWORD data type
            Data data = createData(currentAddress, dwordType);
            
            if (data != null) {
                println("SUCCESS: Applied DWORD (" + dwordType.getLength() + " bytes) at " + currentAddress);
            } else {
                printerr("FAILED: Could not apply DWORD at " + currentAddress);
            }
        } catch (Exception e) {
            printerr("ERROR: Failed to apply DWORD at " + currentAddress);
            printerr("Reason: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
