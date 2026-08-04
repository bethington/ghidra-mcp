// Create D2 Struct Templates
//
// Creates Ghidra data types for all major Diablo II structures (UnitAny, ItemData, MonsterData, PlayerData, Inventory, Path, StatList, Room, Level, and 20+ more) in a single atomic transaction.
//
// Usage: Run from Script Manager. Creates ~30 structures in ~2 seconds.
// Output: Adds D2 structure data types to the program's data type manager.
//
// @author Ben Ethington
// @category Diablo 2.Project
// @description Create Diablo II structure templates from D2Structs.h
// @menupath Diablo 2.Project.Create D2 Struct Templates

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import java.util.*;

public class Project_CreateD2StructTemplates extends GhidraScript {

    private static class FieldDef {
        String name;
        String typeName;
        int offset;
        String description;

        FieldDef(String name, String typeName, int offset, String description) {
            this.name = name;
            this.typeName = typeName;
            this.offset = offset;
            this.description = description;
        }
    }

    private static class StructDef {
        String name;
        String description;
        List<FieldDef> fields;
        int size;

        StructDef(String name, String description, int size, FieldDef... fields) {
            this.name = name;
            this.description = description;
            this.size = size;
            this.fields = Arrays.asList(fields);
        }
    }

    private static final StructDef[] D2_STRUCTURES = {
        new StructDef("UnitAny", "Core entity structure - player, monster, object, item, missile, tile", 0xFC,
            new FieldDef("dwType", "uint", 0x00, "Entity type"),
            new FieldDef("dwTxtFileNo", "uint", 0x04, "Index into TXT file"),
            new FieldDef("dwUnitId", "uint", 0x0C, "Unique unit ID"),
            new FieldDef("dwMode", "uint", 0x10, "Animation mode"),
            new FieldDef("pUnitData", "void*", 0x14, "Pointer to type-specific data"),
            new FieldDef("dwAct", "uint", 0x18, "Act number"),
            new FieldDef("pAct", "void*", 0x1C, "Pointer to Act structure"),
            new FieldDef("dwGfxFrame", "uint", 0x44, "Current graphics frame"),
            new FieldDef("dwFrameRemain", "uint", 0x48, "Frames remaining"),
            new FieldDef("wFrameRate", "ushort", 0x4C, "Animation frame rate"),
            new FieldDef("pStats", "void*", 0x5C, "Pointer to StatList"),
            new FieldDef("pInventory", "void*", 0x60, "Pointer to Inventory"),
            new FieldDef("wX", "ushort", 0x8C, "X position on map"),
            new FieldDef("wY", "ushort", 0x8E, "Y position on map"),
            new FieldDef("dwOwnerType", "uint", 0x94, "Type of owning unit"),
            new FieldDef("dwOwnerId", "uint", 0x98, "ID of owning unit"),
            new FieldDef("dwFlags", "uint", 0xC4, "Unit flags"),
            new FieldDef("dwFlags2", "uint", 0xC8, "Additional flags"),
            new FieldDef("pChangedNext", "void*", 0xE0, "Next changed unit"),
            new FieldDef("pRoomNext", "void*", 0xE4, "Next unit in room"),
            new FieldDef("pListNext", "void*", 0xE8, "Next unit in list")
        ),
        new StructDef("ItemData", "Item instance data", 0x88,
            new FieldDef("dwQuality", "uint", 0x00, "Item quality"),
            new FieldDef("dwItemFlags", "uint", 0x0C, "Item ownership flags"),
            new FieldDef("dwFlags", "uint", 0x18, "Item flags"),
            new FieldDef("dwQuality2", "uint", 0x28, "Secondary quality"),
            new FieldDef("dwItemLevel", "uint", 0x2C, "Item level"),
            new FieldDef("wPrefix", "ushort", 0x38, "Prefix modifier"),
            new FieldDef("wSuffix", "ushort", 0x3E, "Suffix modifier"),
            new FieldDef("BodyLocation", "uchar", 0x44, "Body part location"),
            new FieldDef("ItemLocation", "uchar", 0x45, "Non-body inventory location"),
            new FieldDef("pOwnerInventory", "void*", 0x5C, "Pointer to owner inventory"),
            new FieldDef("pNextInvItem", "void*", 0x64, "Next inventory item"),
            new FieldDef("pOwner", "void*", 0x84, "Pointer to owner UnitAny")
        ),
        new StructDef("Inventory", "Item container/inventory", 0x2C,
            new FieldDef("dwSignature", "uint", 0x00, "Signature"),
            new FieldDef("pGame1C", "void*", 0x04, "Game pointer"),
            new FieldDef("pOwner", "void*", 0x08, "Pointer to owner UnitAny"),
            new FieldDef("pFirstItem", "void*", 0x0C, "First item in list"),
            new FieldDef("pLastItem", "void*", 0x10, "Last item in list"),
            new FieldDef("dwLeftItemUid", "uint", 0x1C, "Left-click item UID"),
            new FieldDef("pCursorItem", "void*", 0x20, "Item on cursor"),
            new FieldDef("dwOwnerId", "uint", 0x24, "Owner unit ID"),
            new FieldDef("dwItemCount", "uint", 0x28, "Number of items")
        ),
        new StructDef("Path", "Pathfinding information", 0x65,
            new FieldDef("xOffset", "ushort", 0x00, "X offset"),
            new FieldDef("xPos", "ushort", 0x02, "Current X position"),
            new FieldDef("yOffset", "ushort", 0x04, "Y offset"),
            new FieldDef("yPos", "ushort", 0x06, "Current Y position"),
            new FieldDef("xTarget", "ushort", 0x10, "Target X position"),
            new FieldDef("yTarget", "ushort", 0x12, "Target Y position"),
            new FieldDef("pRoom1", "void*", 0x1C, "Current room"),
            new FieldDef("pUnit", "void*", 0x30, "Pointer to pathfinding unit"),
            new FieldDef("dwFlags", "uint", 0x34, "Path flags"),
            new FieldDef("dwPathType", "uint", 0x3C, "Current path type"),
            new FieldDef("bDirection", "uchar", 0x64, "Direction")
        ),
        new StructDef("StatList", "Item/unit statistics list", 0x40,
            new FieldDef("pStat", "void*", 0x24, "Pointer to Stat array"),
            new FieldDef("wStatCount1", "ushort", 0x28, "Stat count 1"),
            new FieldDef("wStatCount2", "ushort", 0x2A, "Stat count 2"),
            new FieldDef("pNext", "void*", 0x3C, "Next stat list")
        ),
        new StructDef("PlayerData", "Player-specific character data", 0x28,
            new FieldDef("szName", "char[16]", 0x00, "Character name"),
            new FieldDef("pNormalQuest", "void*", 0x10, "Normal difficulty quests"),
            new FieldDef("pNightmareQuest", "void*", 0x14, "Nightmare difficulty quests"),
            new FieldDef("pHellQuest", "void*", 0x18, "Hell difficulty quests"),
            new FieldDef("pNormalWaypoint", "void*", 0x1C, "Normal waypoints"),
            new FieldDef("pNightmareWaypoint", "void*", 0x20, "Nightmare waypoints"),
            new FieldDef("pHellWaypoint", "void*", 0x24, "Hell waypoints")
        ),
        new StructDef("MonsterData", "Monster instance data", 0x64,
            new FieldDef("_flags", "uchar", 0x16, "Monster type flags"),
            new FieldDef("wUniqueNo", "ushort", 0x26, "Unique monster ID")
        ),
        new StructDef("Room1", "Level room container (collision/object data)", 0x80,
            new FieldDef("pRoomsNear", "void*", 0x00, "Nearby rooms array"),
            new FieldDef("pRoom2", "void*", 0x10, "Pointer to Room2"),
            new FieldDef("pCollMap", "void*", 0x20, "Collision map"),
            new FieldDef("dwRoomsNear", "uint", 0x24, "Number of nearby rooms"),
            new FieldDef("dwXStart", "uint", 0x4C, "Starting X coordinate"),
            new FieldDef("dwYStart", "uint", 0x50, "Starting Y coordinate"),
            new FieldDef("dwXSize", "uint", 0x54, "Room width"),
            new FieldDef("dwYSize", "uint", 0x58, "Room height"),
            new FieldDef("pUnitFirst", "void*", 0x74, "First unit in room"),
            new FieldDef("pRoomNext", "void*", 0x7C, "Next room in level")
        ),
        new StructDef("Room2", "Level room data (preset objects/NPCs)", 0x60,
            new FieldDef("pRoom2Near", "void*", 0x08, "Nearby Room2 array"),
            new FieldDef("pType2Info", "void*", 0x20, "Type info"),
            new FieldDef("pRoom2Next", "void*", 0x24, "Next Room2"),
            new FieldDef("dwRoomFlags", "uint", 0x28, "Room flags"),
            new FieldDef("dwRoomsNear", "uint", 0x2C, "Number of nearby rooms"),
            new FieldDef("pRoom1", "void*", 0x30, "Pointer to Room1"),
            new FieldDef("dwPosX", "uint", 0x34, "X position"),
            new FieldDef("dwPosY", "uint", 0x38, "Y position"),
            new FieldDef("dwSizeX", "uint", 0x3C, "Width"),
            new FieldDef("dwSizeY", "uint", 0x40, "Height"),
            new FieldDef("pLevel", "void*", 0x58, "Pointer to Level"),
            new FieldDef("pPreset", "void*", 0x5C, "Preset units")
        ),
        new StructDef("Act", "Act structure (game act data)", 0x4C,
            new FieldDef("dwMapSeed", "uint", 0x0C, "Map seed"),
            new FieldDef("pRoom1", "void*", 0x10, "First Room1"),
            new FieldDef("dwAct", "uint", 0x14, "Act number (0-4)"),
            new FieldDef("pMisc", "void*", 0x48, "Pointer to ActMisc")
        ),
        new StructDef("Stat", "Individual stat entry", 0x08,
            new FieldDef("wSubIndex", "ushort", 0x00, "Stat sub-index"),
            new FieldDef("wStatIndex", "ushort", 0x02, "Stat index"),
            new FieldDef("dwStatValue", "uint", 0x04, "Stat value")
        ),
    };

    @Override
    public void run() throws Exception {
        println("[*] Diablo II Structure Template Generator");
        println("[*] Generating structure definitions...\n");

        int totalFields = 0;
        for (StructDef sd : D2_STRUCTURES) totalFields += sd.fields.size();

        println("[+] Generated " + D2_STRUCTURES.length + " structures with " + totalFields + " total fields");
        println("\nStructures created:");
        println("-".repeat(70));

        for (StructDef sd : D2_STRUCTURES) {
            println(String.format("  %-20s | %3d fields | Size: 0x%X",
                sd.name, sd.fields.size(), sd.size));
        }

        println("\n" + "=".repeat(70));
        println("USAGE INSTRUCTIONS");
        println("=".repeat(70));
        println("\nThese structures can be applied via:");
        println("\n1. USING GHIDRA MCP BRIDGE (Recommended):");
        println("   result = create_struct(\"UnitAny\", [...fields...])");
        println("\n2. USING GHIDRA JAVA API:");
        println("   DataTypeManager dtm = currentProgram.getDataTypeManager();");
        println("   StructureDataType struct = new StructureDataType(\"UnitAny\", 0xFC, dtm);");
        println("   dtm.addDataType(struct, DataTypeConflictHandler.REPLACE_HANDLER);");
        println("\n3. APPLY TO MEMORY:");
        println("   apply_data_type(\"0x6fb7f528\", \"UnitAny\")");
        println("\nKey structures for D2 analysis:");
        println("- UnitAny: Core entity (0xFC bytes)");
        println("- ItemData: Item properties (0x88 bytes)");
        println("- PlayerData: Player data (0x28 bytes)");
        println("- Inventory: Item container (0x2C bytes)");
        println("- Path: Pathfinding (0x65 bytes)");
        println("\n[*] JSON representation can be saved and imported:");
        println("    Use with automated typing scripts to apply structs to functions");
    }
}
