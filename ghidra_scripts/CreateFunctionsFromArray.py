#Create Functions From Array
#
#This script reads an array of function pointers starting at the current address,
#disassembles each target address, and creates a function at each location.
#Useful for processing function pointer tables or vtables in Diablo 2.
#Place cursor at the start of the array before running.
#
#@author Ben Ethington
#@category Diablo 2
#@description Creates functions at addresses stored in function pointer arrays and vtables
#@keybinding
#@menupath Diablo II.Create Functions From Array

from ghidra.app.cmd.function import CreateFunctionCmd
from ghidra.app.cmd.disassemble import DisassembleCommand



# helper function to get a Ghidra Address type
# accepts hexstring
def getAddress(addr):
    # Address getAddress(java.lang.String addrString)
    return currentProgram.getAddressFactory().getAddress(addr)

base = currentAddress
for i in range(52):
    number = currentProgram.getMemory().getInt(base.add(i*4))
    addr = getAddress("{:08X}".format(number))

    cmd = DisassembleCommand(addr, None, False)
    cmd.applyTo(currentProgram, monitor)

    cmd = CreateFunctionCmd(addr)
    cmd.applyTo(currentProgram)