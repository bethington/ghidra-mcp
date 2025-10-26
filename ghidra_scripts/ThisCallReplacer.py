#Replace __thiscall with unknown calling convention
#This script finds all functions using the __thiscall calling convention and changes them
#to "unknown" calling convention. Useful when __thiscall is incorrectly applied in Diablo 2
#or when you need to force Ghidra to re-analyze calling conventions for C++ member functions.
#Reports the total count of modified functions.
#
#@author dzik
#@category Diablo 2
#@keybinding 
#@menupath 
#@toolbar

import json

from ghidra.util.exception import CancelledException, InvalidInputException

try:
    i = 0
    for func in currentProgram.functionManager.getFunctions(1):
        if func.getCallingConventionName() == "__thiscall":
            i = i + 1
            func.setCallingConvention("unknown")
            
    print("Found {} functions with __thiscall calling convention".format(i))
        
except CancelledException:
    pass