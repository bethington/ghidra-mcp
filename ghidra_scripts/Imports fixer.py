#Fix D2Common imports
#This script analyzes Diablo 2 DLL imports and exports by parsing the PE header structure.
#It counts imported functions from key DLLs (D2COMMON, D2CMP, D2LANG, D2NET, FOG, STORM)
#and processes the export table to create functions at all exported addresses.
#Useful for ensuring all exported ordinals have proper function definitions.
#
#@author dzik
#@category Diablo 2
#@keybinding 
#@menupath 
#@toolbar

import json
import os
import platform

from ghidra.util.exception import CancelledException, InvalidInputException
from ghidra.app.cmd.function import CreateFunctionCmd
from ghidra.app.cmd.disassemble import DisassembleCommand

def getExports():
    base = currentProgram.getImageBase()
    a = base.add(0x3c)
    b = currentProgram.getMemory().getInt(a)
    PE = base.add(b)
    c = PE.add(0x18 + 0x60)
    d = currentProgram.getMemory().getInt(c)
    export = base.add(d)
    print("Export header {}".format(export))
    e = export.add(0x10)
    f = currentProgram.getMemory().getInt(e)
    g = export.add(0x14)
    h = currentProgram.getMemory().getInt(g)
    i = export.add(0x14 + 4 + 4)
    j = currentProgram.getMemory().getInt(i)
    k = base.add(j)
    print("Numer of exported functions is equal to {} and first ordinal number is {}".format(h, f))
    print("Ordinal table is located at address {}".format(k))
    for u in range(h):
        x = k.add(u * 4)
        y = currentProgram.getMemory().getInt(x)
        if y != 0:
            z = base.add(y)
            p = currentProgram.functionManager.getFunctionAt(z)
            if not p:
                cmd = CreateFunctionCmd(z)
                cmd.applyTo(currentProgram)
                cmd = DisassembleCommand(z, None, False)
                cmd.applyTo(currentProgram, monitor)
        
    

def findImports(name):
    i = 0
    monitor.setMessage("Finding imported functions")
    for func in currentProgram.functionManager.getExternalFunctions():
        if name in func.getExternalLocation().getParentName():
            i = i + 1
            
    print("Found {} imported functions from {}".format(i, name))

try:
    findImports(u"D2COMMON.DLL")
    findImports(u"D2CMP.DLL")
    findImports(u"D2LANG.DLL")
    findImports(u"D2NET.DLL")
    findImports(u"FOG.DLL")
    findImports(u"STORM.DLL")
    
    getExports()
except CancelledException:
    pass