#Namespacer
#
#This script assigns all functions after the current address to the same namespace
#as the currently selected function. It continues until it encounters two consecutive
#functions that already belong to the target namespace, indicating the end of the range.
#Useful for bulk namespace organization when functions are grouped by memory region.
#
#@author Ben Ethington
#@category Diablo 2
#@description Bulk assigns functions to the same namespace as the currently selected function
#@keybinding
#@menupath Diablo II.Namespacer

c = 0
n = currentProgram.functionManager.getFunctionAt(currentAddress).getParentNamespace()

for f in currentProgram.functionManager.getFunctions(currentAddress, True):
    cn = f.getParentNamespace()
    if cn == n:
        c = c + 1
        print(f.getName())
        if c == 2:
            break
    else:
        f.setParentNamespace(n)
    