#Add custom registers to function arguments
#This script identifies functions in Diablo 2 that use non-standard registers (in_* or unaff_*)
#as parameters and promotes them to explicit function arguments. It enables custom variable storage,
#adds the register parameters to the function signature, and sets the calling convention to "unknown".
#Useful for fixing functions with unusual register usage patterns that Ghidra doesn't detect automatically.
#
#@author dzik
#@category Diablo 2
#@keybinding 
#@menupath 
#@toolbar

import json
import os
import platform
import time

from ghidra.util.exception import CancelledException, InvalidInputException
from ghidra.program.model.symbol import SourceType
from ghidra.app.cmd.label import AddLabelCmd
from ghidra.app.cmd.label import RenameLabelCmd
from ghidra.app.cmd.label import CreateNamespacesCmd
from ghidra.app.cmd.function import CreateFunctionCmd
from ghidra.app.util import NamespaceUtils
from ghidra.app.cmd.disassemble import DisassembleCommand
from ghidra.app.decompiler import DecompileOptions
from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.listing import ParameterImpl
from ghidra.program.model.pcode import HighFunctionDBUtil
from ghidra.app.services import DataTypeManagerService

def stepFindCustomRegisters(s):
    c = 0
    monitor.setMessage(s)
    print(s)
    monitor.initialize(currentProgram.getFunctionManager().getFunctionCount())
    # decompiler setup
    options = DecompileOptions()
    ifc = DecompInterface()
    ifc.setOptions(options)
    ifc.openProgram(currentProgram)
    for func in currentProgram.functionManager.getFunctions(1): 
        monitor.incrementProgress(1)
        monitor.setShowProgressValue(True)
        
        # stop on this address - after that we have standard garbage code we dont care about
        if "{}".format(func.getEntryPoint()) == "00681a48":
            break
            
        monitor.setMessage("Analyzing 0x{}".format(func.getEntryPoint()))
        res = ifc.decompileFunction(func, 60, monitor)
        high_func = res.getHighFunction()
        if high_func:
            lsm = high_func.getLocalSymbolMap()
            
            hfdb = HighFunctionDBUtil()
            hfdb.commitParamsToDatabase(high_func, True, SourceType.USER_DEFINED)
            hfdb.commitReturnToDatabase(high_func, SourceType.USER_DEFINED)
            hfdb.commitLocalNamesToDatabase(high_func, SourceType.USER_DEFINED)
            
            symbols = lsm.getSymbols()
            update = False
            for i, symbol in enumerate(symbols):
                if (symbol.name.startswith("in_") or symbol.name.startswith("unaff_")) and not symbol.name.startswith("in_register") and not symbol.name.startswith("in_FS") and symbol.parameter == False and not "{}".format(symbol.storage).startswith("unique") and not "{}".format(symbol.storage).startswith("Stack") and not "{}".format(symbol.storage).startswith("HASH"):
                    func.setCustomVariableStorage(True)
                    p = ParameterImpl(None, symbol.dataType, symbol.storage, currentProgram)
                    print("Adding {} as param for 0x{}".format(symbol.storage, func.getEntryPoint()))
                    func.addParameter(p, SourceType.USER_DEFINED)
                    update = True
                else:
                    if symbol.name.startswith("in_stack_000000"):
                        print("0x{} require stack param {}".format(func.getEntryPoint(), symbol))
            
            if update:
                #print("Function 0x{} uses custom registers!".format(func.getEntryPoint()))
                func.setCallingConvention("unknown")
                c = c + 1
        monitor.checkCanceled()
    print("Found {} functions using custom registers!".format(c))
    
def main():
    start = time.time()
    stepFindCustomRegisters("Find functions what uses custom registers as arguments and fix them")
    end = time.time()
    print(end - start)
        
try:
    main()
except CancelledException:
    pass