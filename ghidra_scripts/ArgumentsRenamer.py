#Arguments renamer - Automatically renames function parameters based on Diablo 2 data types
#Iterates through all functions and renames parameters to follow Hungarian notation:
#  - Pointer types: prefix 'p' (pGame, pClient, pUnit)
#  - Double pointers: prefix 'pp' (ppMonsterRegion)
#  - Enum types: prefix 'e' (eUnitType, eSkill, eState)
#Handles duplicate names gracefully and tracks successful renames.
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
    
    
def main():
    monitor.initialize(currentProgram.getFunctionManager().getFunctionCount())
    c = 0
    for func in currentProgram.functionManager.getFunctions(1): 
        if "{}".format(func.getEntryPoint()) == "00681a48":
            break
            
        monitor.incrementProgress(1)
        monitor.setShowProgressValue(True)
        
        args = func.getParameters()
        
        for arg in args:
            if "{}".format(arg.getDataType()) == "D2GameStrc *":
                try:
                    arg.setName("pGame", SourceType.USER_DEFINED)
                except DuplicateNameException:
                    c = c - 1
                c = c + 1
            if "{}".format(arg.getDataType()) == "D2ClientStrc *":
                try:
                    arg.setName("pClient", SourceType.USER_DEFINED)
                except DuplicateNameException:
                    c = c - 1
                c = c + 1
            if "{}".format(arg.getDataType()) == "D2PoolManagerStrc *":
                try:
                    arg.setName("pMemory", SourceType.USER_DEFINED)
                except DuplicateNameException:
                    c = c - 1
                c = c + 1
            if "{}".format(arg.getDataType()) == "D2RoomStrc *":
                try:
                    arg.setName("pRoom", SourceType.USER_DEFINED)
                except DuplicateNameException:
                    c = c - 1
                c = c + 1
            if "{}".format(arg.getDataType()) == "D2RoomExStrc *":
                try:
                    arg.setName("pRoomEx", SourceType.USER_DEFINED)
                except DuplicateNameException:
                    c = c - 1
                c = c + 1
            if "{}".format(arg.getDataType()) == "D2DrlgLevelStrc *":
                try:
                    arg.setName("pLevel", SourceType.USER_DEFINED)
                except DuplicateNameException:
                    c = c - 1
                c = c + 1
            if "{}".format(arg.getDataType()) == "D2PresetUnitStrc *":
                try:
                    arg.setName("pPresetUnit", SourceType.USER_DEFINED)
                except DuplicateNameException:
                    c = c - 1
                c = c + 1
            if "{}".format(arg.getDataType()) == "eD2UnitType":
                try:
                    arg.setName("eUnitType", SourceType.USER_DEFINED)
                except DuplicateNameException:
                    c = c - 1
                c = c + 1
            if "{}".format(arg.getDataType()) == "D2RosterStrc *":
                try:
                    arg.setName("pRoster", SourceType.USER_DEFINED)
                except DuplicateNameException:
                    c = c - 1
                c = c + 1
            if "{}".format(arg.getDataType()) == "eD2Skills":
                try:
                    arg.setName("eSkill", SourceType.USER_DEFINED)
                except DuplicateNameException:
                    c = c - 1
                c = c + 1
            if "{}".format(arg.getDataType()) == "eD2States":
                try:
                    arg.setName("eState", SourceType.USER_DEFINED)
                except DuplicateNameException:
                    c = c - 1
                c = c + 1
            if "{}".format(arg.getDataType()) == "eD2UnitStat":
                try:
                    arg.setName("eUnitStat", SourceType.USER_DEFINED)
                except DuplicateNameException:
                    c = c - 1
                c = c + 1
            if "{}".format(arg.getDataType()) == "eD2PlayerClassID":
                try:
                    arg.setName("ePlayerClass", SourceType.USER_DEFINED)
                except DuplicateNameException:
                    c = c - 1
                c = c + 1
            if "{}".format(arg.getDataType()) == "D2InventoryStrc *":
                try:
                    arg.setName("pInventory", SourceType.USER_DEFINED)
                except DuplicateNameException:
                    c = c - 1
                c = c + 1
            if "{}".format(arg.getDataType()) == "DC6 *":
                try:
                    arg.setName("pDC6", SourceType.USER_DEFINED)
                except DuplicateNameException:
                    c = c - 1
                c = c + 1
            if "{}".format(arg.getDataType()) == "D2SkillStrc *":
                try:
                    arg.setName("pSkill", SourceType.USER_DEFINED)
                except DuplicateNameException:
                    c = c - 1
                c = c + 1
            if "{}".format(arg.getDataType()) == "D2DynamicPathStrc *":
                try:
                    arg.setName("pDynamicPath", SourceType.USER_DEFINED)
                except DuplicateNameException:
                    c = c - 1
                c = c + 1
            if "{}".format(arg.getDataType()) == "D2PlayerListStrc *":
                try:
                    arg.setName("pPlayerList", SourceType.USER_DEFINED)
                except DuplicateNameException:
                    c = c - 1
                c = c + 1
            if "{}".format(arg.getDataType()) == "D2ParticleStrc *":
                try:
                    arg.setName("pParticle", SourceType.USER_DEFINED)
                except DuplicateNameException:
                    c = c - 1
                c = c + 1
            if "{}".format(arg.getDataType()) == "D2DrlgStrc *":
                try:
                    arg.setName("pDrlg", SourceType.USER_DEFINED)
                except DuplicateNameException:
                    c = c - 1
                c = c + 1
            if "{}".format(arg.getDataType()) == "D2DrlgActStrc *":
                try:
                    arg.setName("pDrlgAct", SourceType.USER_DEFINED)
                except DuplicateNameException:
                    c = c - 1
                c = c + 1
            if "{}".format(arg.getDataType()) == "D2DrlgEnvironmentStrc *":
                try:
                    arg.setName("pDrlgEnvironment", SourceType.USER_DEFINED)
                except DuplicateNameException:
                    c = c - 1
                c = c + 1
            if "{}".format(arg.getDataType()) == "D2DrlgMapStrc *":
                try:
                    arg.setName("pDrlgMap", SourceType.USER_DEFINED)
                except DuplicateNameException:
                    c = c - 1
                c = c + 1
            if "{}".format(arg.getDataType()) == "D2TimerQueueStrc *":
                try:
                    arg.setName("pTimerQueue", SourceType.USER_DEFINED)
                except DuplicateNameException:
                    c = c - 1
                c = c + 1
            if "{}".format(arg.getDataType()) == "D2TimerListStrc *":
                try:
                    arg.setName("pTimerList", SourceType.USER_DEFINED)
                except DuplicateNameException:
                    c = c - 1
                c = c + 1
            if "{}".format(arg.getDataType()) == "D2BitBufferStrc *":
                try:
                    arg.setName("pBitBuffer", SourceType.USER_DEFINED)
                except DuplicateNameException:
                    c = c - 1
                c = c + 1
            if "{}".format(arg.getDataType()) == "D2QuestDataStrc *":
                try:
                    arg.setName("pQuestData", SourceType.USER_DEFINED)
                except DuplicateNameException:
                    c = c - 1
                c = c + 1
            if "{}".format(arg.getDataType()) == "D2SeedStrc *":
                try:
                    arg.setName("pSeed", SourceType.USER_DEFINED)
                except DuplicateNameException:
                    c = c - 1
                c = c + 1
            if "{}".format(arg.getDataType()) == "D2MonsterRegionStrc *":
                try:
                    arg.setName("pMonsterRegion", SourceType.USER_DEFINED)
                except DuplicateNameException:
                    c = c - 1
                c = c + 1
            if "{}".format(arg.getDataType()) == "D2MonsterRegionStrc * *":
                try:
                    arg.setName("ppMonsterRegion", SourceType.USER_DEFINED)
                except DuplicateNameException:
                    c = c - 1
                c = c + 1
            if "{}".format(arg.getDataType()) == "eD2ItemTypes":
                try:
                    arg.setName("eItemType", SourceType.USER_DEFINED)
                except DuplicateNameException:
                    c = c - 1
                c = c + 1
            if "{}".format(arg.getDataType()) == "D2UnitStrc *":
                try:
                    arg.setName("pUnit", SourceType.USER_DEFINED)
                except DuplicateNameException:
                    c = c - 1
                c = c + 1
            if "{}".format(arg.getDataType()) == "D2NetDataStrc *":
                try:
                    arg.setName("pNetData", SourceType.USER_DEFINED)
                except DuplicateNameException:
                    c = c - 1
                c = c + 1
            if "{}".format(arg.getDataType()) == "eD2LevelId":
                try:
                    arg.setName("eLevel", SourceType.USER_DEFINED)
                except DuplicateNameException:
                    c = c - 1
                c = c + 1
            if "{}".format(arg.getDataType()) == "eD2UIvars":
                try:
                    arg.setName("eUI", SourceType.USER_DEFINED)
                except DuplicateNameException:
                    c = c - 1
                c = c + 1
            if "{}".format(arg.getDataType()) == "D2GfxInfoStrc *":
                try:
                    arg.setName("pGfxInfo", SourceType.USER_DEFINED)
                except DuplicateNameException:
                    c = c - 1
                c = c + 1
            if "{}".format(arg.getDataType()) == "eOverlayId":
                try:
                    arg.setName("eOverlay", SourceType.USER_DEFINED)
                except DuplicateNameException:
                    c = c - 1
                c = c + 1
    print("Renamed {} arguments".format(c))         
try:
    main()
except CancelledException:
    pass