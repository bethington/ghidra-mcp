#Export Ordinal Lister
#
#This script parses the PE export table to extract ordinal numbers and maps them
#to the current function names in Ghidra. Outputs a CSV-formatted list showing:
#Ordinal Number, Address, Current Function Name
#Useful for tracking which ordinals have been renamed vs still using default names.
#
#@author Ben Ethington
#@category Diablo 2
#@description Lists all exported functions with ordinal numbers and current Ghidra function names in CSV format
#@keybinding
#@menupath Diablo II.Ordinal Linkage.Export Ordinal Lister

from ghidra.util.exception import CancelledException

def getExportsWithOrdinals():
    """Parse PE export table and list all functions with their ordinals"""
    base = currentProgram.getImageBase()
    
    # Parse PE header to find export table
    # Offset 0x3C points to PE header
    peHeaderOffset = currentProgram.getMemory().getInt(base.add(0x3c))
    peHeader = base.add(peHeaderOffset)
    
    # Export table RVA is at PE+0x78 (0x18 optional header start + 0x60 data directory)
    exportTableRVA = currentProgram.getMemory().getInt(peHeader.add(0x18 + 0x60))
    exportTable = base.add(exportTableRVA)
    
    # Parse export directory structure
    # +0x10: Base ordinal (starting ordinal number)
    # +0x14: Number of functions
    # +0x18: Number of names
    # +0x1C: Address of functions array (RVA)
    # +0x20: Address of names array (RVA)
    # +0x24: Address of name ordinals array (RVA)
    
    baseOrdinal = currentProgram.getMemory().getInt(exportTable.add(0x10))
    numFunctions = currentProgram.getMemory().getInt(exportTable.add(0x14))
    numNames = currentProgram.getMemory().getInt(exportTable.add(0x18))
    
    functionsArrayRVA = currentProgram.getMemory().getInt(exportTable.add(0x1C))
    namesArrayRVA = currentProgram.getMemory().getInt(exportTable.add(0x20))
    nameOrdinalsArrayRVA = currentProgram.getMemory().getInt(exportTable.add(0x24))
    
    functionsArray = base.add(functionsArrayRVA)
    namesArray = base.add(namesArrayRVA)
    nameOrdinalsArray = base.add(nameOrdinalsArrayRVA)
    
    print("Export Table Analysis")
    print("=" * 80)
    print("Base Ordinal: {}".format(baseOrdinal))
    print("Number of Functions: {}".format(numFunctions))
    print("Number of Named Exports: {}".format(numNames))
    print("=" * 80)
    print("")
    print("Ordinal,Address,CurrentName,ExportedName")
    print("-" * 80)
    
    # Build a map of ordinal index -> exported name
    exportedNames = {}
    for i in range(numNames):
        # Get the ordinal index for this name
        ordinalIndex = currentProgram.getMemory().getShort(nameOrdinalsArray.add(i * 2)) & 0xFFFF
        
        # Get the name RVA
        nameRVA = currentProgram.getMemory().getInt(namesArray.add(i * 4))
        nameAddr = base.add(nameRVA)
        
        # Read the null-terminated string
        exportedName = ""
        offset = 0
        while True:
            b = currentProgram.getMemory().getByte(nameAddr.add(offset))
            if b == 0:
                break
            exportedName += chr(b & 0xFF)
            offset += 1
        
        exportedNames[ordinalIndex] = exportedName
    
    # Iterate through all function slots
    results = []
    for i in range(numFunctions):
        # Get function RVA
        functionRVA = currentProgram.getMemory().getInt(functionsArray.add(i * 4))
        
        if functionRVA == 0:
            # Empty slot
            continue
            
        functionAddr = base.add(functionRVA)
        ordinalNumber = baseOrdinal + i
        
        # Get the current function name in Ghidra
        func = currentProgram.getFunctionManager().getFunctionAt(functionAddr)
        if func:
            currentName = func.getName()
        else:
            currentName = "<no function>"
        
        # Get exported name if it exists
        exportedName = exportedNames.get(i, "<ordinal only>")
        
        result = {
            'ordinal': ordinalNumber,
            'address': "0x{}".format(functionAddr),
            'currentName': currentName,
            'exportedName': exportedName
        }
        results.append(result)
        
        print("{},{},{},{}".format(ordinalNumber, result['address'], currentName, exportedName))
    
    print("")
    print("=" * 80)
    print("Total exported functions: {}".format(len(results)))
    print("Functions with names: {}".format(numNames))
    print("Functions with ordinal only: {}".format(len(results) - numNames))
    
    # Summary of functions still using default names
    defaultNames = [r for r in results if r['currentName'].startswith('FUN_') or r['currentName'].startswith('Ordinal_')]
    if defaultNames:
        print("")
        print("Functions still using default names: {}".format(len(defaultNames)))
        print("-" * 80)
        for r in defaultNames:
            print("  Ordinal {} @ {} : {}".format(r['ordinal'], r['address'], r['currentName']))

try:
    getExportsWithOrdinals()
except CancelledException:
    pass
