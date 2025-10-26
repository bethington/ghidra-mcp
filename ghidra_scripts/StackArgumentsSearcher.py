#Stack arguments searcher
#This script identifies Diablo 2 functions with incorrect stack parameter counts by analyzing
#RET instructions (opcode C2). It compares the stack cleanup size in RET with the declared
#parameter size and automatically adds missing undefined4 parameters to match the actual count.
#Essential for fixing __stdcall and __fastcall functions where Ghidra misidentifies parameter counts.
#Also ensures functions with custom variable storage use "unknown" calling convention.
#
#@author dzik
#@category Diablo 2
#@keybinding 
#@menupath 
#@toolbar

import json
import time

from ghidra.util.exception import CancelledException, InvalidInputException
from ghidra.program.model.listing import VariableFilter
from ghidra.program.model.listing import ParameterImpl
from ghidra.program.model.symbol import SourceType
from ghidra.app.services import DataTypeManagerService
    
# thanks weiry6922
def getDataTypeManagerByName(name):
    tool = state.getTool()
    service = tool.getService(DataTypeManagerService)
    dataTypeManagers = service.getDataTypeManagers()
    for manager in dataTypeManagers:
        managerName = manager.getName()
        if name in managerName:
            return manager
    return None

# thanks weiry6922
def findDataTypeByNameInDataManager(nameDT, nameDTM):
    manager = getDataTypeManagerByName(nameDTM)
    allDataTypes = manager.getAllDataTypes()
    while allDataTypes.hasNext():
        dataType = allDataTypes.next()
        dataTypeName = dataType.getName()
        if dataTypeName.startswith(nameDT):
            return dataType
    return None

# thanks weiry6922
def findDataTypeByName(name):
    dt = findDataTypeByNameInDataManager(name, currentProgram.name)
    if dt == None:
        dt = findDataTypeByNameInDataManager(name, u"BuiltInTypes")
    if dt == None:
        dt = findDataTypeByNameInDataManager(name, u"windows_vs12_32")
    return dt
    
def main():
    start = time.time()
    monitor.initialize(currentProgram.getFunctionManager().getFunctionCount())
    c = 0
    for func in currentProgram.functionManager.getFunctions(1): 
        if "{}".format(func.getEntryPoint()) == "00681a48":
            break
            
        if func.hasCustomVariableStorage():
            func.setCallingConvention("unknown")
            
        monitor.incrementProgress(1)
        monitor.setShowProgressValue(True)
        
        found = False
        
        args = func.getParameters(VariableFilter.STACK_VARIABLE_FILTER)
        
        argsSize = 0
        for arg in args:
            a = arg.getLength()
            if a < 4:
                a = 4
            argsSize = argsSize + a
            
        argcount = len(args)
        retcount = 0
        retSize = 0
        
        for inst in currentProgram.listing.getInstructions(func.getBody(), True):
            if '{:02X}'.format(inst.getUnsignedByte(0)) == "C2":
                retSize = inst.getUnsignedShort(1)
                retcount = retSize / 4
                found = True
                break;
        
        if found:
            if argsSize != retSize:
                if argsSize < retSize:
                    if not func.hasCustomVariableStorage():
                        for i in range(retcount - argcount):
                            dt = findDataTypeByName("undefined4")
                            p = ParameterImpl(None, dt, currentProgram)
                            func.addParameter(p, SourceType.USER_DEFINED)
                c = c + 1
                print("Function 0x{} has defined {}/{} stack arguments".format(func.getEntryPoint(), argcount, retcount))
                
    print("Found {} functions with wrong stack arguments count".format(c))
    end = time.time()
    print(end - start)
try:
    main()
except CancelledException:
    pass