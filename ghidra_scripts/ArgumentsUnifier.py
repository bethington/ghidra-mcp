#Arguments unifier - Standardizes function parameter and return types to fixed-width types
#Converts variable-sized types to explicit fixed-width equivalents:
#  - int → int32_t, uint → uint32_t
#  - short → int16_t, ushort → uint16_t
#  - BYTE → int8_t
#Applies to both function parameters and return types across all functions.
#Ensures consistent type sizes regardless of platform or compiler settings.
#@author dzik
#@category Diablo 2
#@keybinding 
#@menupath 
#@toolbar

import json

from ghidra.util.exception import CancelledException, InvalidInputException
from ghidra.program.model.listing import VariableFilter
from ghidra.program.model.symbol import SourceType
from ghidra.util.exception import DuplicateNameException
from ghidra.app.services import DataTypeManagerService

# thanks weiry6922
def exportParamName(param):
    if "(" in param:
        #print("Skippping function parameter")
        return None, None
    elif not " " in param:
        #print("Skipping function pointer")
        return None, None
    elif "unsigned" in param:
        sig, strc, name = param.split(" ")
    elif "signed" in param:
        sig, strc, name = param.split(" ")
    elif "const" in param:
        sig, strc, name = param.split(" ")
    else:
        strc, name = param.split(" ")
    
    return strc, name

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
    
def retypeArgs(args):
    c = 0
    for arg in args:
        if "{}".format(arg.getDataType()) == "int":
            arg.setDataType(findDataTypeByName("int32_t"), SourceType.USER_DEFINED)
            c = c + 1
        if "{}".format(arg.getDataType()) == "uint":
            arg.setDataType(findDataTypeByName("uint32_t"), SourceType.USER_DEFINED)
            c = c + 1
        if "{}".format(arg.getDataType()) == "short":
            arg.setDataType(findDataTypeByName("int16_t"), SourceType.USER_DEFINED)
            c = c + 1
        if "{}".format(arg.getDataType()) == "ushort":
            arg.setDataType(findDataTypeByName("uint16_t"), SourceType.USER_DEFINED)
            c = c + 1
        if "{}".format(arg.getDataType()) == "BYTE":
            arg.setDataType(findDataTypeByName("int8_t"), SourceType.USER_DEFINED)
            c = c + 1
    return c
    
def main():
    monitor.initialize(currentProgram.getFunctionManager().getFunctionCount())
    c = 0
    for func in currentProgram.functionManager.getFunctions(1): 
        if "{}".format(func.getEntryPoint()) == "00681a48":
            break
            
        monitor.incrementProgress(1)
        monitor.setShowProgressValue(True)
        
        # retype function arguments
        args = func.getParameters()
        c = c + retypeArgs(args)
        
        # retype function return
        retu = func.getReturn()
        c = c + retypeArgs([retu])

    print("Fixed {} argument types".format(c))         
try:
    main()
except CancelledException:
    pass