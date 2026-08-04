// Arguments Renamer
//
// Iterates through all functions and renames parameters based on Diablo 2 data types following Hungarian notation: 'p' for pointers, 'pp' for double pointers, 'e' for enums.
//
// Usage: Run from Script Manager on any D2 binary.
// Output: Renames function parameters to follow Hungarian conventions.
//
// @author Ben Ethington
// @category Diablo 2.Repair
// @description Rename function parameters using Hungarian notation
// @menupath Diablo 2.Repair.Arguments Renamer

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import java.util.*;

public class Repair_ArgumentsRenamer extends GhidraScript {

    private static final Map<String, String> TYPE_TO_NAME = new LinkedHashMap<>();
    static {
        TYPE_TO_NAME.put("D2GameStrc *", "pGame");
        TYPE_TO_NAME.put("D2ClientStrc *", "pClient");
        TYPE_TO_NAME.put("D2PoolManagerStrc *", "pMemory");
        TYPE_TO_NAME.put("D2RoomStrc *", "pRoom");
        TYPE_TO_NAME.put("D2RoomExStrc *", "pRoomEx");
        TYPE_TO_NAME.put("D2DrlgLevelStrc *", "pLevel");
        TYPE_TO_NAME.put("D2PresetUnitStrc *", "pPresetUnit");
        TYPE_TO_NAME.put("eD2UnitType", "eUnitType");
        TYPE_TO_NAME.put("D2RosterStrc *", "pRoster");
        TYPE_TO_NAME.put("eD2Skills", "eSkill");
        TYPE_TO_NAME.put("eD2States", "eState");
        TYPE_TO_NAME.put("eD2UnitStat", "eUnitStat");
        TYPE_TO_NAME.put("eD2PlayerClassID", "ePlayerClass");
        TYPE_TO_NAME.put("D2InventoryStrc *", "pInventory");
        TYPE_TO_NAME.put("DC6 *", "pDC6");
        TYPE_TO_NAME.put("D2SkillStrc *", "pSkill");
        TYPE_TO_NAME.put("D2DynamicPathStrc *", "pDynamicPath");
        TYPE_TO_NAME.put("D2PlayerListStrc *", "pPlayerList");
        TYPE_TO_NAME.put("D2ParticleStrc *", "pParticle");
        TYPE_TO_NAME.put("D2DrlgStrc *", "pDrlg");
        TYPE_TO_NAME.put("D2DrlgActStrc *", "pDrlgAct");
        TYPE_TO_NAME.put("D2DrlgEnvironmentStrc *", "pDrlgEnvironment");
        TYPE_TO_NAME.put("D2DrlgMapStrc *", "pDrlgMap");
        TYPE_TO_NAME.put("D2TimerQueueStrc *", "pTimerQueue");
        TYPE_TO_NAME.put("D2TimerListStrc *", "pTimerList");
        TYPE_TO_NAME.put("D2BitBufferStrc *", "pBitBuffer");
        TYPE_TO_NAME.put("D2QuestDataStrc *", "pQuestData");
        TYPE_TO_NAME.put("D2SeedStrc *", "pSeed");
        TYPE_TO_NAME.put("D2MonsterRegionStrc *", "pMonsterRegion");
        TYPE_TO_NAME.put("D2MonsterRegionStrc * *", "ppMonsterRegion");
        TYPE_TO_NAME.put("eD2ItemTypes", "eItemType");
        TYPE_TO_NAME.put("D2UnitStrc *", "pUnit");
        TYPE_TO_NAME.put("D2NetDataStrc *", "pNetData");
        TYPE_TO_NAME.put("eD2LevelId", "eLevel");
        TYPE_TO_NAME.put("eD2UIvars", "eUI");
        TYPE_TO_NAME.put("D2GfxInfoStrc *", "pGfxInfo");
        TYPE_TO_NAME.put("eOverlayId", "eOverlay");
    }

    @Override
    public void run() throws Exception {
        monitor.initialize(currentProgram.getFunctionManager().getFunctionCount());
        int c = 0;

        try {
            FunctionIterator funcIter = currentProgram.getFunctionManager().getFunctions(true);
            while (funcIter.hasNext()) {
                monitor.checkCanceled();
                Function func = funcIter.next();

                if (func.getEntryPoint().toString().equals("00681a48")) break;

                monitor.incrementProgress(1);
                monitor.setShowProgressValue(true);

                Parameter[] args = func.getParameters();
                for (Parameter arg : args) {
                    String typeName = arg.getDataType().toString();
                    String newName = TYPE_TO_NAME.get(typeName);
                    if (newName != null) {
                        try {
                            arg.setName(newName, SourceType.USER_DEFINED);
                        } catch (DuplicateNameException e) {
                            c--;
                        }
                        c++;
                    }
                }
            }
        } catch (CancelledException e) {
            // cancelled
        }

        println("Renamed " + c + " arguments");
    }
}
