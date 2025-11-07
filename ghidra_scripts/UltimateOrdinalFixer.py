#Ultimate Ordinal Fixer
#
#Updates all ordinal symbol references throughout the program using batch rename operations.
#Processes all symbols, labels, pointers, and external locations containing ordinal references
#and renames them to match their real function names from the DLL export mappings.
#
#@author Ben Ethington
#@category Diablo 2
#@description Updates all ordinal symbol references throughout the program using batch rename operations
#@keybinding
#@menupath Diablo II.Ordinal Linkage.Ultimate Ordinal Fixer

from ghidra.program.model.symbol import SourceType

print("="*80)
print("ULTIMATE ORDINAL NAME FIXER")
print("Updating ALL symbols, labels, and references to use proper function names")
print("="*80)

# Function name mappings
ORDINAL_NAMES = {
    10084: "ProcessUnitCoordinatesAndPath",
    10092: "ProcessUnitMovement", 
    10123: "GetUnitPosition",
    10259: "CreateUnitStruct",
    10338: "ProcessUnitAI",
    10527: "UpdateUnitAnimation", 
    10770: "ProcessUnitCollision",
    10817: "GetUnitStats",
}

def updateAllOrdinalReferences():
    """Update all symbols, labels, and references containing ordinal patterns"""
    
    symbolTable = currentProgram.getSymbolTable()
    
    total_updated = 0
    
    for ordinal_num, function_name in ORDINAL_NAMES.items():
        print("\nProcessing Ordinal_{} -> {}:".format(ordinal_num, function_name))
        
        # Find all symbols containing this ordinal number
        ordinal_pattern = "Ordinal_{}".format(ordinal_num)
        
        # Get all symbols in the program
        all_symbols = symbolTable.getAllSymbols(True)  # Include dynamic symbols
        
        updated_count = 0
        
        for symbol in all_symbols:
            symbol_name = symbol.getName()
            
            # Check if this symbol refers to our target ordinal
            if ordinal_pattern in symbol_name:
                old_name = symbol_name
                
                # Determine new name based on symbol type
                if symbol_name.startswith("PTR_"):
                    # This is a pointer symbol like PTR_Ordinal_10084_6fb7e220
                    addr_suffix = ""
                    if "_" in symbol_name:
                        parts = symbol_name.split("_")
                        if len(parts) >= 3:
                            addr_suffix = "_{}".format(parts[-1])
                    
                    new_name = "PTR_{}{}".format(function_name, addr_suffix)
                
                elif symbol_name.startswith("LAB_"):
                    # This is a label
                    new_name = "LAB_{}".format(function_name)
                
                elif symbol_name == ordinal_pattern:
                    # Direct ordinal reference
                    new_name = function_name
                
                else:
                    # Other symbol types - replace the ordinal part
                    new_name = symbol_name.replace(ordinal_pattern, function_name)
                
                # Attempt to rename the symbol
                try:
                    print("  Renaming: {} -> {}".format(old_name, new_name))
                    symbol.setName(new_name, SourceType.USER_DEFINED)
                    updated_count += 1
                    print("    SUCCESS!")
                    
                except Exception as e:
                    print("    FAILED: {}".format(str(e)))
                    
                    # Try alternative approach - delete and recreate
                    try:
                        symbol_addr = symbol.getAddress()
                        symbol_namespace = symbol.getParentNamespace()
                        
                        # Delete old symbol
                        symbolTable.removeSymbolSpecial(symbol)
                        
                        # Create new symbol
                        new_symbol = symbolTable.createLabel(symbol_addr, new_name, symbol_namespace, SourceType.USER_DEFINED)
                        
                        if new_symbol:
                            updated_count += 1
                            print("    SUCCESS (recreated)!")
                        else:
                            print("    FAILED (recreation failed)")
                            
                    except Exception as e2:
                        print("    FAILED (recreation): {}".format(str(e2)))
        
        print("  Updated {} symbols for Ordinal_{}".format(updated_count, ordinal_num))
        total_updated += updated_count
    
    return total_updated

def updateExternalLocationNames():
    """Also update external location names as backup"""
    
    extManager = currentProgram.getExternalManager()
    updated_external = 0
    
    print("\nUpdating external location names...")
    
    for libName in extManager.getExternalLibraryNames():
        if "D2COMMON" in libName.upper():
            locations = extManager.getExternalLocations(libName)
            
            while locations.hasNext():
                extLocation = locations.next()
                current_name = extLocation.getLabel()
                
                for ordinal_num, function_name in ORDINAL_NAMES.items():
                    if "Ordinal_{}".format(ordinal_num) == current_name:
                        try:
                            print("  External: {} -> {}".format(current_name, function_name))
                            extLocation.setName(function_name, SourceType.USER_DEFINED)
                            updated_external += 1
                            print("    SUCCESS!")
                        except Exception as e:
                            print("    FAILED: {}".format(str(e)))
                        break
            break
    
    return updated_external

def main():
    print("1. Updating symbol table references...")
    symbol_updates = updateAllOrdinalReferences()
    
    print("\n2. Updating external location names...")
    external_updates = updateExternalLocationNames()
    
    print("\n" + "="*80)
    print("ULTIMATE ORDINAL FIXING COMPLETE!")
    print("Updated {} symbols in symbol table".format(symbol_updates))
    print("Updated {} external locations".format(external_updates))
    print("Total updates: {}".format(symbol_updates + external_updates))
    print("")
    print("Check your function pointer at 0x6fb7e220 - it should now show:")
    print("PTR_ProcessUnitCoordinatesAndPath_6fb7e220")
    print("="*80)

if __name__ == "__main__":
    main()