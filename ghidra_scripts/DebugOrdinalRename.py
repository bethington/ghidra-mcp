#Debug Ordinal Rename
#
#Shows detailed information about the rename process for ordinal symbol rename operations.
#Useful for troubleshooting ordinal linkage issues and verifying rename success.
#
#@author Ben Ethington
#@category Diablo 2
#@description Shows detailed information and debugging output for ordinal symbol rename operations
#@keybinding
#@menupath Diablo II.Ordinal Linkage.Debug Ordinal Rename

from ghidra.program.model.symbol import SourceType

def debugOrdinalRename():
    print("=== DEBUG ORDINAL RENAME ===")
    
    extManager = currentProgram.getExternalManager()
    
    print("External Manager: {}".format(extManager))
    
    # Get all external libraries
    libs = list(extManager.getExternalLibraries())
    print("Found {} external libraries:".format(len(libs)))
    
    for lib in libs:
        libName = lib.getName()
        print("  Library: {}".format(libName))
        
        if "D2COMMON" in libName:
            print("  --> Processing D2COMMON library")
            
            # Get all locations in this library
            locations = list(extManager.getExternalLocations(lib))
            print("  --> Total locations: {}".format(len(locations)))
            
            ordinal_count = 0
            for location in locations:
                label = location.getLabel()
                if "Ordinal_" in label:
                    ordinal_count += 1
                    if label in ["Ordinal_10078", "Ordinal_11020"]:
                        address = location.getAddress()
                        print("  --> Found TARGET: {} @ {}".format(label, address))
                        
                        # Try to rename
                        if label == "Ordinal_10078":
                            newName = "FindNearestValidRoomWrapper"
                        elif label == "Ordinal_11020":
                            newName = "GetUnitPropertyValue"
                        
                        print("      Attempting rename: {} -> {}".format(label, newName))
                        
                        try:
                            # Method 1: Direct setName
                            location.setName(newName, SourceType.USER_DEFINED)
                            verifyLabel = location.getLabel()
                            print("      Method 1 result: '{}'".format(verifyLabel))
                            
                        except Exception as e:
                            print("      Method 1 failed: {}".format(str(e)))
                            
                            # Method 2: Try recreating the external location
                            try:
                                print("      Trying Method 2: Recreation...")
                                oldAddr = location.getAddress()
                                
                                # Remove old and create new
                                extManager.removeExternalLocation(location)
                                newLoc = extManager.addExtFunction(libName, newName, oldAddr, SourceType.USER_DEFINED)
                                print("      Method 2 success: Created {}".format(newName))
                                
                            except Exception as e2:
                                print("      Method 2 also failed: {}".format(str(e2)))
            
            print("  --> Total ordinals found: {}".format(ordinal_count))
    
    print("=== DEBUG COMPLETED ===")

if __name__ == "__main__":
    debugOrdinalRename()