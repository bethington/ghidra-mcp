// Auto Tag Functions
//
// Comprehensive auto-tagging using source files, data tables, units, quests, AI, network, UI, APIs, and structures. Tags use prefixes: SRC_, MOD_, TBL_ for organized categorization.
//
// Usage: Run from Script Manager or via Ctrl+Shift+A.
// Output: Applies plate comment tags to functions in the current program.
//
// @author Ben Ethington
// @category Diablo 2.Documentation
// @description Auto-tag functions using multiple detection methods
// @menupath Diablo 2.Documentation.Auto Tag Functions

import ghidra.app.script.GhidraScript;
import ghidra.framework.model.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.mem.*;
import ghidra.program.model.block.*;
import ghidra.program.model.scalar.*;
import java.io.*;
import java.util.*;
import java.util.regex.*;

/**
 * Comprehensive auto-tagging script for D2 binaries.
 *
 * TAG PREFIX ORGANIZATION:
 * ========================
 * SRC_      - Source file name (e.g., SRC_Waypoint.cpp)
 * MOD_      - Module/subsystem from path (e.g., MOD_COLLISION, MOD_INVENTORY)
 * TBL_      - Data table access (e.g., TBL_skills, TBL_monstats)
 * UNIT_     - Unit type handling (e.g., UNIT_PLAYER, UNIT_MONSTER)
 * MODE_     - Game mode handling (e.g., MODE_MONSTER, MODE_OBJECT)
 * QUEST_    - Quest system (e.g., QUEST_A1Q1, QUEST_A5Q6)
 * AI_       - AI system (e.g., AI_BAAL, AI_GENERAL)
 * NET_      - Network/Protocol (e.g., NET_SCMD, NET_PACKET)
 * UI_       - User interface (e.g., UI_PANEL, UI_AUTOMAP)
 * GFX_      - Graphics/Video (e.g., GFX_DIRECT3D, GFX_CACHE)
 * SND_      - Sound system (e.g., SND_CHANNEL, SND_ENVIRON)
 * CLASS_    - Character class (e.g., CLASS_AMAZON, CLASS_NECRO)
 * API_      - Win32 API category (e.g., API_NETWORK, API_FILE_IO)
 * STRUCT_   - D2 structure usage (e.g., STRUCT_Unit, STRUCT_Inventory)
 * RET_      - Return type structure (e.g., RET_Unit, RET_Inventory)
 * PARAM_    - Parameter count (e.g., PARAM_0, PARAM_1, PARAM_5)
 * CALLEE_   - Callee count (e.g., CALLEE_0, CALLEE_5, CALLEE_10)
 * CALLER_   - Caller count (e.g., CALLER_0, CALLER_3, CALLER_15)
 * PROP_     - Structural properties (e.g., PROP_LEAF, PROP_LARGE)
 * LIB_      - Library component (e.g., LIB_STORM_COMP, LIB_FOG_MEM)
 *
 * Can run on single program or all programs in project.
 * CLEARS ALL EXISTING TAGS before applying new ones.
 */
public class Document_AutoTagFunctions extends GhidraScript {

    // Mode
    private boolean batchMode = false;
    private boolean clearExistingTags = true;
    private Program activeProgram;

    // Statistics
    private int totalPrograms = 0;
    private int totalFunctions = 0;
    private int totalTagsApplied = 0;
    private int totalTagsCleared = 0;
    private Map<String, Integer> globalTagCounts = new TreeMap<>();

    // Tagging method flags
    private boolean tagSourceFiles = true;
    private boolean tagModules = true;
    private boolean tagDataTables = true;
    private boolean tagUnitTypes = true;
    private boolean tagQuests = true;
    private boolean tagAI = true;
    private boolean tagNetwork = true;
    private boolean tagUI = true;
    private boolean tagGraphics = true;
    private boolean tagSound = true;
    private boolean tagClasses = true;
    private boolean tagApiCategories = true;
    private boolean tagStructural = true;
    private boolean tagD2Structures = true;
    private boolean tagLibraries = true;

    //==========================================================================
    // DATA TABLE PATTERNS
    //==========================================================================
    private static final String[] DATA_TABLES = {
        "skills", "skilldesc", "monstats", "monstats2", "monprop", "monsounds",
        "levels", "leveldefs", "levelgroups", "lvlmaze", "lvlprest", "lvlsub", "lvltypes", "lvlwarp",
        "charstats", "experience", "plrmode", "plrtype",
        "itemtypes", "items", "armor", "weapons", "misc", "gems", "runes",
        "setitems", "sets", "uniqueitems", "magicprefix", "magicsuffix", "rareprefix", "raresuffix",
        "automagic", "properties", "itemstatcost",
        "objects", "objgroup", "objmode", "objpreset", "objtype",
        "missiles", "misscalc",
        "overlay", "states", "events", "compcode",
        "sounds", "soundenviron", "music",
        "cubemain", "cubemod", "recipes",
        "superuniques", "hirelings", "hireling", "npc",
        "pettype", "shrines", "belts", "inventory", "storepage",
        "elemtypes", "hitclass", "monai", "monmode", "monseq", "monplace",
        "treasureclassex", "qualityitems", "lowqualityitems",
        "difficultylevels", "automap", "colors"
    };

    //==========================================================================
    // UNIT TYPE PATTERNS
    //==========================================================================
    private static final Map<String, String> UNIT_TYPE_PATTERNS = new LinkedHashMap<>();
    static {
        UNIT_TYPE_PATTERNS.put("UNIT_PLAYER", "UNIT_PLAYER");
        UNIT_TYPE_PATTERNS.put("UNIT_MONSTER", "UNIT_MONSTER");
        UNIT_TYPE_PATTERNS.put("UNIT_OBJECT", "UNIT_OBJECT");
        UNIT_TYPE_PATTERNS.put("UNIT_MISSILE", "UNIT_MISSILE");
        UNIT_TYPE_PATTERNS.put("UNIT_ITEM", "UNIT_ITEM");
        UNIT_TYPE_PATTERNS.put("UNIT_ROOMTILE", "UNIT_ROOMTILE");
    }

    //==========================================================================
    // QUEST PATTERNS (Act/Quest from source paths)
    //==========================================================================
    private static final Pattern QUEST_PATTERN = Pattern.compile(
        "a(\\d)q(\\d)", Pattern.CASE_INSENSITIVE
    );

    //==========================================================================
    // AI PATTERNS
    //==========================================================================
    private static final String[] AI_KEYWORDS = {
        "AiBaal", "AiGeneral", "AiTatics", "AiThink", "AiUtil",
        "MonsterAI", "ptAi", "pfnAi", "AI_MODE"
    };

    //==========================================================================
    // NETWORK/PROTOCOL PATTERNS
    //==========================================================================
    private static final String[] NET_SCMD_PATTERNS = {"SCMD_", "scmd_", "ptCmd->", "bCmd"};
    private static final String[] NET_SERVER_PATTERNS = {"[SERVER]", "Srv", "SERVER_"};
    private static final String[] NET_CLIENT_PATTERNS = {"[D2CLIENT]", "[CLIENT]", "CLIENT_"};
    private static final String[] NET_PACKET_PATTERNS = {"ptPacket", "packetSize", "nCmdSize"};

    //==========================================================================
    // UI PATTERNS
    //==========================================================================
    private static final Map<String, String> UI_PATTERNS = new LinkedHashMap<>();
    static {
        UI_PATTERNS.put("UI_PANEL", "Panel\\");
        UI_PATTERNS.put("UI_MENU", "Menu\\");
        UI_PATTERNS.put("UI_AUTOMAP", "AutoMap");
        UI_PATTERNS.put("UI_INVENTORY", "\\inv");
        UI_PATTERNS.put("UI_QUEST", "Quest");
        UI_PATTERNS.put("UI_PARTY", "Party");
        UI_PATTERNS.put("UI_TRADE", "Trade");
        UI_PATTERNS.put("UI_CHAT", "chat.cpp");
        UI_PATTERNS.put("UI_DIALOG", "dialog");
        UI_PATTERNS.put("UI_SKILLS", "skill");
        UI_PATTERNS.put("UI_CHAR", "\\char.cpp");
    }

    //==========================================================================
    // GRAPHICS PATTERNS
    //==========================================================================
    private static final String[] GFX_VIDEO_MODES = {"Direct3D", "OpenGL", "Glide", "DirectDraw", "Software"};
    private static final String[] GFX_CACHE_PATTERNS = {"Sprite Cache", "Tile Cache", "Floor Cache", "COF Memory", "GFX Memory"};
    private static final String[] GFX_DRAW_PATTERNS = {"dFloor", "dWall", "dLightMap", "Draw\\"};

    //==========================================================================
    // SOUND PATTERNS
    //==========================================================================
    private static final String[] SND_PATTERNS = {
        "Sound\\", "SoundChan", "soundenviron", "sounds.txt", "SND_", "D2Sound"
    };

    //==========================================================================
    // CHARACTER CLASS PATTERNS
    //==========================================================================
    private static final Map<String, String> CLASS_PATTERNS = new LinkedHashMap<>();
    static {
        CLASS_PATTERNS.put("CLASS_AMAZON", "Amazon");
        CLASS_PATTERNS.put("CLASS_NECRO", "Necromancer");
        CLASS_PATTERNS.put("CLASS_SORC", "Sorceress");
        CLASS_PATTERNS.put("CLASS_PALADIN", "Paladin");
        CLASS_PATTERNS.put("CLASS_BARB", "Barbarian");
        CLASS_PATTERNS.put("CLASS_DRUID", "Druid");
        CLASS_PATTERNS.put("CLASS_ASSASSIN", "Assassin");
    }

    //==========================================================================
    // MODULE/SUBSYSTEM PATTERNS (from source paths)
    //==========================================================================
    private static final Map<String, String> MODULE_PATTERNS = new LinkedHashMap<>();
    static {
        // D2Common subsystems
        MODULE_PATTERNS.put("MOD_COLLISION", "COLLISN");
        MODULE_PATTERNS.put("MOD_DATATABLES", "DATATBLS");
        MODULE_PATTERNS.put("MOD_INVENTORY", "INVENTORY");
        MODULE_PATTERNS.put("MOD_ITEMS", "ITEMS");
        MODULE_PATTERNS.put("MOD_PATH", "PATH");
        MODULE_PATTERNS.put("MOD_SKILLS", "SKILLS");
        MODULE_PATTERNS.put("MOD_STATS", "STATS");
        MODULE_PATTERNS.put("MOD_UNIT", "UNIT");
        MODULE_PATTERNS.put("MOD_WAYPOINT", "Waypoint");
        // D2Client subsystems
        MODULE_PATTERNS.put("MOD_CORE", "\\CORE\\");
        MODULE_PATTERNS.put("MOD_DRAW", "\\Draw\\");
        MODULE_PATTERNS.put("MOD_GAME", "\\GAME\\");
        MODULE_PATTERNS.put("MOD_QUEST", "\\QUEST");
        MODULE_PATTERNS.put("MOD_UI", "\\UI\\");
        MODULE_PATTERNS.put("MOD_SOUND", "\\Sound\\");
        // D2Game subsystems
        MODULE_PATTERNS.put("MOD_MONSTER", "\\MONSTER\\");
        MODULE_PATTERNS.put("MOD_MISSILES", "\\MISSILES\\");
        MODULE_PATTERNS.put("MOD_OBJECTS", "\\OBJECTS\\");
        MODULE_PATTERNS.put("MOD_PLAYER", "\\PLAYER\\");
        MODULE_PATTERNS.put("MOD_AI", "\\Ai\\");
        MODULE_PATTERNS.put("MOD_DEBUG", "\\DEBUG\\");
    }

    //==========================================================================
    // LIBRARY COMPONENT PATTERNS
    //==========================================================================
    private static final Map<String, String> LIBRARY_PATTERNS = new LinkedHashMap<>();
    static {
        // Storm library
        LIBRARY_PATTERNS.put("LIB_STORM_BIG", "SBig.cpp");
        LIBRARY_PATTERNS.put("LIB_STORM_BLT", "SBLT.CPP");
        LIBRARY_PATTERNS.put("LIB_STORM_BMP", "SBMP.CPP");
        LIBRARY_PATTERNS.put("LIB_STORM_CMD", "SCMD.CPP");
        LIBRARY_PATTERNS.put("LIB_STORM_CODE", "SCODE.CPP");
        LIBRARY_PATTERNS.put("LIB_STORM_COMP", "SCOMP.CPP");
        LIBRARY_PATTERNS.put("LIB_STORM_DLG", "SDLG.CPP");
        // Fog library
        LIBRARY_PATTERNS.put("LIB_FOG_MEM", "Fog\\Src\\Mem");
        LIBRARY_PATTERNS.put("LIB_FOG_EXCEL", "Fog\\Src\\Excel");
        LIBRARY_PATTERNS.put("LIB_FOG_NET", "QServer");
        LIBRARY_PATTERNS.put("LIB_FOG_STRING", "FogString");
        LIBRARY_PATTERNS.put("LIB_FOG_ERROR", "ErrorManager");
        LIBRARY_PATTERNS.put("LIB_FOG_LOG", "LogManager");
        LIBRARY_PATTERNS.put("LIB_FOG_ASYNC", "AsyncData");
    }

    //==========================================================================
    // API CATEGORIES
    //==========================================================================
    private static final Map<String, String[]> API_CATEGORIES = new LinkedHashMap<>();
    static {
        API_CATEGORIES.put("NETWORK", new String[]{
            "WSAStartup", "WSACleanup", "socket", "connect", "send", "recv",
            "sendto", "recvfrom", "bind", "listen", "accept", "closesocket",
            "gethostbyname", "inet_addr", "htons", "ntohs", "select"
        });
        API_CATEGORIES.put("FILE_IO", new String[]{
            "CreateFileA", "CreateFileW", "ReadFile", "WriteFile", "CloseHandle",
            "SetFilePointer", "GetFileSize", "DeleteFileA", "FindFirstFileA"
        });
        API_CATEGORIES.put("REGISTRY", new String[]{
            "RegOpenKeyExA", "RegQueryValueExA", "RegSetValueExA", "RegCloseKey", "RegCreateKeyExA"
        });
        API_CATEGORIES.put("THREADING", new String[]{
            "CreateThread", "WaitForSingleObject", "Sleep", "CreateMutexA",
            "CreateEventA", "SetEvent", "EnterCriticalSection", "LeaveCriticalSection"
        });
        API_CATEGORIES.put("MEMORY", new String[]{
            "VirtualAlloc", "VirtualFree", "HeapAlloc", "HeapFree", "GlobalAlloc", "GlobalFree"
        });
        API_CATEGORIES.put("GDI", new String[]{
            "GetDC", "ReleaseDC", "CreateCompatibleDC", "BitBlt", "SelectObject", "DeleteObject"
        });
        API_CATEGORIES.put("DIRECTX", new String[]{
            "DirectDrawCreate", "Direct3DCreate8", "DirectSoundCreate", "DirectInputCreate"
        });
        API_CATEGORIES.put("WINDOW", new String[]{
            "CreateWindowExA", "DestroyWindow", "ShowWindow", "GetMessage", "DispatchMessage",
            "SendMessageA", "PostMessageA", "DefWindowProcA", "MessageBoxA"
        });
    }

    //==========================================================================
    // D2 STRUCTURE NAME PATTERNS (for string-based detection)
    // Catches Hungarian notation like pUnit, ptInventory, etc.
    //==========================================================================
    private static final Map<String, String[]> STRUCT_NAME_PATTERNS = new LinkedHashMap<>();
    static {
        // Unit-related
        STRUCT_NAME_PATTERNS.put("STRUCT_Unit", new String[]{
            "pUnit", "ptUnit", "pUnitAny", "ptUnitAny", "pSourceUnit", "pTargetUnit",
            "pOwnerUnit", "pAttacker", "pDefender", "pSrcUnit", "pDstUnit"
        });
        // Inventory
        STRUCT_NAME_PATTERNS.put("STRUCT_Inventory", new String[]{
            "pInventory", "ptInventory", "pInv", "pOwnerInventory"
        });
        // Stats
        STRUCT_NAME_PATTERNS.put("STRUCT_StatList", new String[]{
            "pStatList", "ptStatList", "pStats", "pStat", "ptStat", "pStatEx"
        });
        // Skills
        STRUCT_NAME_PATTERNS.put("STRUCT_Skill", new String[]{
            "pSkill", "ptSkill", "pSkillInfo", "pSkillData", "pLeftSkill", "pRightSkill"
        });
        // Path/Movement
        STRUCT_NAME_PATTERNS.put("STRUCT_Path", new String[]{
            "pPath", "ptPath", "pUnitPath", "pPathInfo"
        });
        // Room structures
        STRUCT_NAME_PATTERNS.put("STRUCT_Room", new String[]{
            "pRoom", "pRoom1", "pRoom2", "ptRoom", "pRoomEx", "pRoomData"
        });
        // Level
        STRUCT_NAME_PATTERNS.put("STRUCT_Level", new String[]{
            "pLevel", "ptLevel", "pLevelData", "pCurrentLevel"
        });
        // Act
        STRUCT_NAME_PATTERNS.put("STRUCT_Act", new String[]{
            "pAct", "ptAct", "pActData", "pCurrentAct"
        });
        // Game
        STRUCT_NAME_PATTERNS.put("STRUCT_Game", new String[]{
            "pGame", "ptGame", "pGameData", "gpGame"
        });
        // Client/Player
        STRUCT_NAME_PATTERNS.put("STRUCT_Client", new String[]{
            "pClient", "ptClient", "pClientData", "pPlayerClient"
        });
        // Item
        STRUCT_NAME_PATTERNS.put("STRUCT_Item", new String[]{
            "pItem", "ptItem", "pItemData", "pCursorItem", "pEquipItem"
        });
        // Monster
        STRUCT_NAME_PATTERNS.put("STRUCT_MonsterData", new String[]{
            "pMonsterData", "ptMonsterData", "pMonData", "pMonStats"
        });
        // Player data
        STRUCT_NAME_PATTERNS.put("STRUCT_PlayerData", new String[]{
            "pPlayerData", "ptPlayerData", "pPlrData"
        });
        // Object data
        STRUCT_NAME_PATTERNS.put("STRUCT_ObjectData", new String[]{
            "pObjectData", "ptObjectData", "pObjData"
        });
        // Quest
        STRUCT_NAME_PATTERNS.put("STRUCT_Quest", new String[]{
            "pQuest", "ptQuest", "pQuestData", "pQuestInfo"
        });
        // Waypoint
        STRUCT_NAME_PATTERNS.put("STRUCT_Waypoint", new String[]{
            "pWaypoint", "ptWaypoint", "pWaypointData"
        });
        // Control (UI)
        STRUCT_NAME_PATTERNS.put("STRUCT_Control", new String[]{
            "pControl", "ptControl", "pCtrl", "pEditBox", "pButton", "pTextBox"
        });
        // Collision
        STRUCT_NAME_PATTERNS.put("STRUCT_Collision", new String[]{
            "pColl", "pCollision", "ptColl", "pCollMap"
        });
        // Automap
        STRUCT_NAME_PATTERNS.put("STRUCT_Automap", new String[]{
            "pAutomap", "ptAutomap", "pAutomapCell", "pAutomapLayer"
        });
        // Data tables (txt records)
        STRUCT_NAME_PATTERNS.put("STRUCT_TxtRecord", new String[]{
            "pTxt", "ptTxt", "pSkillsTxt", "pMonStatsTxt", "pItemsTxt", "pLevelsTxt",
            "pMissilesTxt", "pObjectsTxt", "pSuperUniquesTxt"
        });
        // Tile/Preset
        STRUCT_NAME_PATTERNS.put("STRUCT_Preset", new String[]{
            "pPreset", "ptPreset", "pTile", "pRoomTile", "pPresetUnit"
        });
        // Light
        STRUCT_NAME_PATTERNS.put("STRUCT_Light", new String[]{
            "pLight", "ptLight", "pLightMap", "pLightInfo"
        });
        // Particle/GFX
        STRUCT_NAME_PATTERNS.put("STRUCT_Particle", new String[]{
            "pParticle", "pGfxData", "pCOF", "pDCC", "pDC6", "pSprite"
        });
        // Arena/PvP
        STRUCT_NAME_PATTERNS.put("STRUCT_Arena", new String[]{
            "pArena", "ptArena", "pArenaUnit"
        });
        // Trade
        STRUCT_NAME_PATTERNS.put("STRUCT_Trade", new String[]{
            "pTrade", "ptTrade", "pTradeData"
        });
        // Party
        STRUCT_NAME_PATTERNS.put("STRUCT_Party", new String[]{
            "pParty", "ptParty", "pPartyData", "pRoster"
        });
        // Packet/Net
        STRUCT_NAME_PATTERNS.put("STRUCT_Packet", new String[]{
            "pPacket", "ptPacket", "pNetData", "pBitStream"
        });
        // Timer
        STRUCT_NAME_PATTERNS.put("STRUCT_Timer", new String[]{
            "pTimer", "ptTimer", "pTimerQueue"
        });
        // Overlay/State
        STRUCT_NAME_PATTERNS.put("STRUCT_Overlay", new String[]{
            "pOverlay", "ptOverlay", "pStateData", "pState"
        });
        // Aura
        STRUCT_NAME_PATTERNS.put("STRUCT_Aura", new String[]{
            "pAura", "ptAura", "pAuraState"
        });
        // Summon/Pet
        STRUCT_NAME_PATTERNS.put("STRUCT_Pet", new String[]{
            "pPet", "ptPet", "pSummon", "pMinion"
        });
        // Corpse
        STRUCT_NAME_PATTERNS.put("STRUCT_Corpse", new String[]{
            "pCorpse", "ptCorpse", "pCorpseData"
        });
        // Mercenary
        STRUCT_NAME_PATTERNS.put("STRUCT_Merc", new String[]{
            "pMerc", "ptMerc", "pMercData", "pHireling"
        });
    }

    //==========================================================================
    // RETURN TYPE STRUCTURE PATTERNS
    // Maps return type substrings to tag names
    //==========================================================================
    private static final Map<String, String> RETURN_TYPE_PATTERNS = new LinkedHashMap<>();
    static {
        // Core game structures
        RETURN_TYPE_PATTERNS.put("RET_Unit", "Unit");
        RETURN_TYPE_PATTERNS.put("RET_UnitAny", "UnitAny");
        RETURN_TYPE_PATTERNS.put("RET_Inventory", "Inventory");
        RETURN_TYPE_PATTERNS.put("RET_StatList", "StatList");
        RETURN_TYPE_PATTERNS.put("RET_Skill", "Skill");
        RETURN_TYPE_PATTERNS.put("RET_SkillInfo", "SkillInfo");
        RETURN_TYPE_PATTERNS.put("RET_Path", "Path");
        RETURN_TYPE_PATTERNS.put("RET_Room", "Room");
        RETURN_TYPE_PATTERNS.put("RET_Room1", "Room1");
        RETURN_TYPE_PATTERNS.put("RET_Room2", "Room2");
        RETURN_TYPE_PATTERNS.put("RET_Level", "Level");
        RETURN_TYPE_PATTERNS.put("RET_Act", "Act");
        RETURN_TYPE_PATTERNS.put("RET_Game", "Game");
        RETURN_TYPE_PATTERNS.put("RET_Client", "Client");
        RETURN_TYPE_PATTERNS.put("RET_Item", "Item");
        RETURN_TYPE_PATTERNS.put("RET_ItemData", "ItemData");
        RETURN_TYPE_PATTERNS.put("RET_MonsterData", "MonsterData");
        RETURN_TYPE_PATTERNS.put("RET_PlayerData", "PlayerData");
        RETURN_TYPE_PATTERNS.put("RET_ObjectData", "ObjectData");
        RETURN_TYPE_PATTERNS.put("RET_Quest", "Quest");
        RETURN_TYPE_PATTERNS.put("RET_QuestData", "QuestData");
        RETURN_TYPE_PATTERNS.put("RET_Waypoint", "Waypoint");
        RETURN_TYPE_PATTERNS.put("RET_Control", "Control");
        RETURN_TYPE_PATTERNS.put("RET_Collision", "Collision");
        RETURN_TYPE_PATTERNS.put("RET_Coll", "Coll");
        RETURN_TYPE_PATTERNS.put("RET_Automap", "Automap");
        RETURN_TYPE_PATTERNS.put("RET_AutomapCell", "AutomapCell");
        RETURN_TYPE_PATTERNS.put("RET_Preset", "Preset");
        RETURN_TYPE_PATTERNS.put("RET_PresetUnit", "PresetUnit");
        RETURN_TYPE_PATTERNS.put("RET_Tile", "Tile");
        RETURN_TYPE_PATTERNS.put("RET_Light", "Light");
        RETURN_TYPE_PATTERNS.put("RET_Particle", "Particle");
        RETURN_TYPE_PATTERNS.put("RET_Arena", "Arena");
        RETURN_TYPE_PATTERNS.put("RET_Trade", "Trade");
        RETURN_TYPE_PATTERNS.put("RET_Party", "Party");
        RETURN_TYPE_PATTERNS.put("RET_Roster", "Roster");
        RETURN_TYPE_PATTERNS.put("RET_Packet", "Packet");
        RETURN_TYPE_PATTERNS.put("RET_Timer", "Timer");
        RETURN_TYPE_PATTERNS.put("RET_Overlay", "Overlay");
        RETURN_TYPE_PATTERNS.put("RET_State", "State");
        RETURN_TYPE_PATTERNS.put("RET_Aura", "Aura");
        RETURN_TYPE_PATTERNS.put("RET_Pet", "Pet");
        RETURN_TYPE_PATTERNS.put("RET_Summon", "Summon");
        RETURN_TYPE_PATTERNS.put("RET_Corpse", "Corpse");
        RETURN_TYPE_PATTERNS.put("RET_Merc", "Merc");
        RETURN_TYPE_PATTERNS.put("RET_Hireling", "Hireling");
        // Data table records
        RETURN_TYPE_PATTERNS.put("RET_SkillsTxt", "SkillsTxt");
        RETURN_TYPE_PATTERNS.put("RET_MonStatsTxt", "MonStatsTxt");
        RETURN_TYPE_PATTERNS.put("RET_ItemsTxt", "ItemsTxt");
        RETURN_TYPE_PATTERNS.put("RET_LevelsTxt", "LevelsTxt");
        RETURN_TYPE_PATTERNS.put("RET_MissilesTxt", "MissilesTxt");
        RETURN_TYPE_PATTERNS.put("RET_ObjectsTxt", "ObjectsTxt");
        RETURN_TYPE_PATTERNS.put("RET_SetItemsTxt", "SetItemsTxt");
        RETURN_TYPE_PATTERNS.put("RET_UniqueItemsTxt", "UniqueItemsTxt");
        // Graphics structures
        RETURN_TYPE_PATTERNS.put("RET_GfxData", "GfxData");
        RETURN_TYPE_PATTERNS.put("RET_COF", "COF");
        RETURN_TYPE_PATTERNS.put("RET_DCC", "DCC");
        RETURN_TYPE_PATTERNS.put("RET_DC6", "DC6");
        RETURN_TYPE_PATTERNS.put("RET_Sprite", "Sprite");
        RETURN_TYPE_PATTERNS.put("RET_CellFile", "CellFile");
        RETURN_TYPE_PATTERNS.put("RET_CellContext", "CellContext");
        // Network
        RETURN_TYPE_PATTERNS.put("RET_NetData", "NetData");
        RETURN_TYPE_PATTERNS.put("RET_BitStream", "BitStream");
    }

    //==========================================================================
    // D2 DATA STRUCTURE SIGNATURES (offset-based detection)
    //==========================================================================
    private static final Map<String, StructureSignature> D2_STRUCTURES = new LinkedHashMap<>();
    static {
        D2_STRUCTURES.put("STRUCT_UnitAny", new StructureSignature(
            new int[]{0x00, 0x04, 0x0C, 0x10, 0x14, 0x2C, 0x5C, 0x60},
            "dwType|dwTxtFileNo|dwUnitId|dwMode|pTypeData|pPath|pStats|pInventory"
        ));
        D2_STRUCTURES.put("STRUCT_Inventory", new StructureSignature(
            new int[]{0x00, 0x08, 0x0C, 0x10, 0x20, 0x28},
            "dwSignature|pOwner|pFirstItem|pLastItem|pCursorItem|dwItemCount"
        ));
        D2_STRUCTURES.put("STRUCT_StatList", new StructureSignature(
            new int[]{0x24, 0x28, 0x3C}, "pStat|wStatCount|pNext"
        ));
        D2_STRUCTURES.put("STRUCT_Skill", new StructureSignature(
            new int[]{0x00, 0x04, 0x28, 0x30}, "pSkillInfo|pNextSkill|dwSkillLevel|dwFlags"
        ));
        D2_STRUCTURES.put("STRUCT_Path", new StructureSignature(
            new int[]{0x1C, 0x30, 0x34, 0x3C, 0x58}, "pRoom1|pUnit|dwFlags|dwPathType|pTargetUnit"
        ));
        D2_STRUCTURES.put("STRUCT_Room1", new StructureSignature(
            new int[]{0x10, 0x20, 0x74, 0x7C}, "pRoom2|Coll|pUnitFirst|pRoomNext"
        ));
        D2_STRUCTURES.put("STRUCT_Room2", new StructureSignature(
            new int[]{0x24, 0x30, 0x4C, 0x58, 0x5C}, "pRoom2Next|pRoom1|pRoomTiles|pLevel|pPreset"
        ));
        D2_STRUCTURES.put("STRUCT_Level", new StructureSignature(
            new int[]{0x10, 0x1AC, 0x1B4, 0x1D0}, "pRoom2First|pNextLevel|pMisc|dwLevelNo"
        ));
        D2_STRUCTURES.put("STRUCT_Act", new StructureSignature(
            new int[]{0x0C, 0x10, 0x14, 0x48}, "dwMapSeed|pRoom1|dwAct|pMisc"
        ));
        D2_STRUCTURES.put("STRUCT_Control", new StructureSignature(
            new int[]{0x00, 0x0C, 0x10, 0x14, 0x18, 0x3C}, "dwType|dwPosX|dwPosY|dwSizeX|dwSizeY|pNext"
        ));
        D2_STRUCTURES.put("STRUCT_ItemData", new StructureSignature(
            new int[]{0x00, 0x0C, 0x2C, 0x44}, "dwQuality|dwItemFlags|dwItemLevel|BodyLocation"
        ));
        D2_STRUCTURES.put("STRUCT_PlayerData", new StructureSignature(
            new int[]{0x00, 0x10, 0x14, 0x18, 0x1C}, "szName|pNormalQuest|pNightmareQuest|pHellQuest|pWaypoint"
        ));
        D2_STRUCTURES.put("STRUCT_MonsterData", new StructureSignature(
            new int[]{0x16, 0x1C, 0x26, 0x2C}, "fFlags|anEnchants|wUniqueNo|wName"
        ));
    }

    // Source file pattern
    private static final Pattern SOURCE_FILE_PATTERN = Pattern.compile(
        ".*[/\\\\]([^/\\\\]+\\.(cpp|c|h|hpp|cxx|cc|inl))\"?$",
        Pattern.CASE_INSENSITIVE
    );

    @Override
    public void run() throws Exception {
        println("=".repeat(70));
        println("AUTO-TAG FUNCTIONS (Organized Prefix System)");
        println("=".repeat(70));

        // Ask for mode
        String modeChoice = askChoice("Tagging Mode",
            "Choose which programs to tag:",
            Arrays.asList("Current Program Only", "All Programs in Project"),
            "Current Program Only");

        batchMode = modeChoice.equals("All Programs in Project");

        // Ask about clearing tags
        clearExistingTags = askYesNo("Clear Existing Tags",
            "Clear ALL existing function tags before applying new ones?\n\n" +
            "Recommended: Yes (ensures clean, consistent tagging)");

        // Show tag prefix info
        println("\nTag Prefix System:");
        println("  SRC_    - Source file    MOD_    - Module/subsystem");
        println("  TBL_    - Data tables    UNIT_   - Unit types");
        println("  QUEST_  - Quests         AI_     - AI system");
        println("  NET_    - Network        UI_     - User interface");
        println("  GFX_    - Graphics       SND_    - Sound");
        println("  CLASS_  - Character      API_    - Win32 API");
        println("  STRUCT_ - D2 structs     RET_    - Return types");
        println("  PARAM_  - Param count    CALLEE_ - Callee count");
        println("  CALLER_ - Caller count   PROP_   - Properties");
        println("  LIB_    - Libraries");

        if (batchMode) {
            runBatchMode();
        } else {
            runSingleMode();
        }

        // Final summary
        println("\n" + "=".repeat(70));
        println("AUTO-TAGGING COMPLETE");
        println("=".repeat(70));
        println("Programs processed: " + totalPrograms);
        println("Functions analyzed: " + totalFunctions);
        if (clearExistingTags) {
            println("Tags cleared: " + totalTagsCleared);
        }
        println("Tags applied: " + totalTagsApplied);

        if (!globalTagCounts.isEmpty()) {
            println("\nTag distribution by prefix:");
            Map<String, Integer> prefixCounts = new TreeMap<>();
            for (Map.Entry<String, Integer> entry : globalTagCounts.entrySet()) {
                String tag = entry.getKey();
                String prefix = tag.contains("_") ? tag.substring(0, tag.indexOf('_') + 1) : tag;
                prefixCounts.merge(prefix, entry.getValue(), Integer::sum);
            }
            for (Map.Entry<String, Integer> entry : prefixCounts.entrySet()) {
                println(String.format("  %-10s %d tags", entry.getKey(), entry.getValue()));
            }
        }
    }

    //==========================================================================
    // SINGLE PROGRAM MODE
    //==========================================================================

    private void runSingleMode() throws Exception {
        activeProgram = currentProgram;
        println("\nMode: Single Program");
        println("Program: " + activeProgram.getName());
        processProgram();
        totalPrograms = 1;
    }

    //==========================================================================
    // BATCH MODE
    //==========================================================================

    private void runBatchMode() throws Exception {
        println("\nMode: Batch (All Programs)");
        Project project = state.getProject();
        if (project == null) {
            printerr("No project is open!");
            return;
        }

        ProjectData projectData = project.getProjectData();
        DomainFolder rootFolder = projectData.getRootFolder();
        int fileCount = countProgramFiles(rootFolder);
        println("Total program files: " + fileCount);

        if (!askYesNo("Confirm Batch Tagging",
                "This will process " + fileCount + " programs.\nContinue?")) {
            println("Cancelled.");
            return;
        }

        long startTime = System.currentTimeMillis();
        processFolder(rootFolder, "");
        long elapsed = (System.currentTimeMillis() - startTime) / 1000;
        println("\nElapsed time: " + elapsed + " seconds");
    }

    private int countProgramFiles(DomainFolder folder) throws Exception {
        int count = 0;
        for (DomainFile file : folder.getFiles()) {
            if (file.getContentType().equals("Program")) count++;
        }
        for (DomainFolder subfolder : folder.getFolders()) {
            count += countProgramFiles(subfolder);
        }
        return count;
    }

    private void processFolder(DomainFolder folder, String path) throws Exception {
        String currentPath = path.isEmpty() ? folder.getName() : path + "/" + folder.getName();
        if (folder.getParent() == null) currentPath = "";

        for (DomainFile file : folder.getFiles()) {
            if (monitor.isCancelled()) return;
            if (!file.getContentType().equals("Program")) continue;

            String filePath = currentPath.isEmpty() ? file.getName() : currentPath + "/" + file.getName();
            if (filePath.contains("PD2")) {
                println("Skipping PD2: " + filePath);
                continue;
            }
            processBatchProgram(file, filePath);
        }

        for (DomainFolder subfolder : folder.getFolders()) {
            if (monitor.isCancelled()) return;
            if (!subfolder.getName().equals("PD2")) {
                processFolder(subfolder, currentPath);
            }
        }
    }

    private void processBatchProgram(DomainFile file, String projectPath) {
        activeProgram = null;
        int transactionId = -1;
        try {
            println("\n" + "-".repeat(50));
            println("Processing: " + projectPath);

            // Open program with write access (true = upgrade, false = not read-only)
            activeProgram = (Program) file.getDomainObject(this, true, false, monitor);
            if (activeProgram == null) throw new Exception("Failed to open program");

            // Start a transaction for modifications
            transactionId = activeProgram.startTransaction("AutoTagFunctions");

            int startTags = totalTagsApplied;
            int startCleared = totalTagsCleared;
            processProgram();
            totalPrograms++;

            println("  Cleared: " + (totalTagsCleared - startCleared) + ", Applied: " + (totalTagsApplied - startTags));

            // Commit the transaction
            activeProgram.endTransaction(transactionId, true);
            transactionId = -1;

            // Save the program
            activeProgram.save("AutoTagFunctions", monitor);

        } catch (Exception e) {
            printerr("  ERROR: " + e.getMessage());
            // Abort transaction if it was started
            if (transactionId != -1 && activeProgram != null) {
                activeProgram.endTransaction(transactionId, false);
            }
        } finally {
            if (activeProgram != null) {
                activeProgram.release(this);
                activeProgram = null;
            }
        }
    }

    //==========================================================================
    // MAIN PROCESSING LOGIC
    //==========================================================================

    private void processProgram() throws Exception {
        FunctionManager funcMgr = activeProgram.getFunctionManager();
        FunctionTagManager tagMgr = funcMgr.getFunctionTagManager();

        // Phase 0: Clear existing tags if requested
        if (clearExistingTags) {
            println("  Clearing existing tags...");
            clearAllFunctionTags(funcMgr);
        }

        // Collect all strings for pattern matching
        println("  Building string index...");
        Map<Address, String> stringIndex = buildStringIndex();

        // Pre-compute tags for all functions
        Map<Address, Set<String>> functionTags = new HashMap<>();

        // Phase 1: Source files and modules
        println("  Analyzing source paths...");
        tagBySourcePaths(functionTags, stringIndex);

        // Phase 2: Data tables
        println("  Detecting data table access...");
        tagByDataTables(functionTags, stringIndex);

        // Phase 3: Unit types
        println("  Detecting unit type handling...");
        tagByUnitTypes(functionTags, stringIndex);

        // Phase 4: Quests
        println("  Detecting quest handlers...");
        tagByQuests(functionTags, stringIndex);

        // Phase 5: AI
        println("  Detecting AI functions...");
        tagByAI(functionTags, stringIndex);

        // Phase 6: Network
        println("  Detecting network/protocol...");
        tagByNetwork(functionTags, stringIndex);

        // Phase 7: UI
        println("  Detecting UI components...");
        tagByUI(functionTags, stringIndex);

        // Phase 8: Graphics
        println("  Detecting graphics...");
        tagByGraphics(functionTags, stringIndex);

        // Phase 9: Sound
        println("  Detecting sound...");
        tagBySound(functionTags, stringIndex);

        // Phase 10: Character classes
        println("  Detecting character classes...");
        tagByClasses(functionTags, stringIndex);

        // Phase 11: Library components
        println("  Detecting library components...");
        tagByLibraries(functionTags, stringIndex);

        // Phase 12: API categories
        println("  Analyzing API calls...");
        tagByApiCategories(functionTags);

        // Phase 13: Structural properties
        println("  Analyzing structural properties...");
        tagByStructure(functionTags);

        // Phase 14: D2 data structures (offset-based)
        println("  Detecting D2 structure usage (offsets)...");
        tagByD2Structures(functionTags);

        // Phase 15: D2 structure names (string-based, catches Hungarian notation)
        println("  Detecting D2 structure names (strings)...");
        tagByStructNames(functionTags, stringIndex);

        // Phase 16: Parameter counts
        println("  Tagging by parameter count...");
        tagByParamCount(functionTags);

        // Phase 17: Callee/Caller counts
        println("  Tagging by callee/caller count...");
        tagByCallCounts(functionTags);

        // Phase 18: Return type structures
        println("  Detecting return type structures...");
        tagByReturnType(functionTags);

        // Apply all collected tags
        println("  Applying tags...");
        int applied = 0;
        for (Map.Entry<Address, Set<String>> entry : functionTags.entrySet()) {
            Function func = funcMgr.getFunctionAt(entry.getKey());
            if (func == null) continue;

            for (String tagName : entry.getValue()) {
                FunctionTag tag = tagMgr.getFunctionTag(tagName);
                if (tag == null) {
                    tag = tagMgr.createFunctionTag(tagName, "Auto-generated");
                }
                func.addTag(tagName);
                applied++;
                globalTagCounts.merge(tagName, 1, Integer::sum);
            }
            totalFunctions++;
        }
        totalTagsApplied += applied;
    }

    //==========================================================================
    // CLEAR ALL TAGS
    //==========================================================================

    private void clearAllFunctionTags(FunctionManager funcMgr) throws Exception {
        int cleared = 0;
        FunctionIterator funcIter = funcMgr.getFunctions(true);
        while (funcIter.hasNext()) {
            if (monitor.isCancelled()) break;
            Function func = funcIter.next();
            Set<FunctionTag> tags = func.getTags();
            for (FunctionTag tag : new HashSet<>(tags)) {
                func.removeTag(tag.getName());
                cleared++;
            }
        }
        totalTagsCleared += cleared;
    }

    //==========================================================================
    // BUILD STRING INDEX
    //==========================================================================

    private Map<Address, String> buildStringIndex() throws Exception {
        Map<Address, String> index = new HashMap<>();
        Listing listing = activeProgram.getListing();
        DataIterator dataIter = listing.getDefinedData(true);

        while (dataIter.hasNext()) {
            if (monitor.isCancelled()) break;
            Data data = dataIter.next();
            if (!data.hasStringValue()) continue;

            String value = data.getDefaultValueRepresentation();
            if (value == null || value.length() < 3) continue;

            // Remove quotes
            if (value.startsWith("\"") && value.endsWith("\"") && value.length() > 2) {
                value = value.substring(1, value.length() - 1);
            }
            index.put(data.getAddress(), value);
        }
        return index;
    }

    //==========================================================================
    // TAG BY SOURCE PATHS (SRC_ and MOD_)
    //==========================================================================

    private void tagBySourcePaths(Map<Address, Set<String>> functionTags, Map<Address, String> stringIndex) throws Exception {
        FunctionManager funcMgr = activeProgram.getFunctionManager();
        ReferenceManager refMgr = activeProgram.getReferenceManager();

        for (Map.Entry<Address, String> entry : stringIndex.entrySet()) {
            String value = entry.getValue();

            // Extract source filename
            String filename = extractSourceFilename(value);
            if (filename != null) {
                ReferenceIterator refIter = refMgr.getReferencesTo(entry.getKey());
                while (refIter.hasNext()) {
                    Reference ref = refIter.next();
                    Function func = funcMgr.getFunctionContaining(ref.getFromAddress());
                    if (func != null) {
                        Set<String> tags = functionTags.computeIfAbsent(func.getEntryPoint(), k -> new HashSet<>());
                        tags.add("SRC_" + filename);

                        // Also add module tag
                        for (Map.Entry<String, String> modEntry : MODULE_PATTERNS.entrySet()) {
                            if (value.contains(modEntry.getValue())) {
                                tags.add(modEntry.getKey());
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    private String extractSourceFilename(String path) {
        if (path == null) return null;
        Matcher matcher = SOURCE_FILE_PATTERN.matcher(path);
        if (matcher.matches()) return matcher.group(1);

        String lower = path.toLowerCase();
        if (lower.endsWith(".cpp") || lower.endsWith(".c") || lower.endsWith(".h")) {
            int lastSlash = Math.max(path.lastIndexOf('/'), path.lastIndexOf('\\'));
            if (lastSlash >= 0) return path.substring(lastSlash + 1);
        }
        return null;
    }

    //==========================================================================
    // TAG BY DATA TABLES (TBL_)
    //==========================================================================

    private void tagByDataTables(Map<Address, Set<String>> functionTags, Map<Address, String> stringIndex) throws Exception {
        FunctionManager funcMgr = activeProgram.getFunctionManager();
        ReferenceManager refMgr = activeProgram.getReferenceManager();

        for (Map.Entry<Address, String> entry : stringIndex.entrySet()) {
            String value = entry.getValue().toLowerCase();

            for (String table : DATA_TABLES) {
                // Match table name (whole word or with .txt/.bin suffix)
                if (value.equals(table) || value.equals(table + ".txt") || value.equals(table + ".bin") ||
                    value.contains("\\" + table + ".") || value.contains("/" + table + ".")) {

                    ReferenceIterator refIter = refMgr.getReferencesTo(entry.getKey());
                    while (refIter.hasNext()) {
                        Reference ref = refIter.next();
                        Function func = funcMgr.getFunctionContaining(ref.getFromAddress());
                        if (func != null) {
                            functionTags.computeIfAbsent(func.getEntryPoint(), k -> new HashSet<>())
                                .add("TBL_" + table);
                        }
                    }
                    break;
                }
            }
        }
    }

    //==========================================================================
    // TAG BY UNIT TYPES (UNIT_)
    //==========================================================================

    private void tagByUnitTypes(Map<Address, Set<String>> functionTags, Map<Address, String> stringIndex) throws Exception {
        FunctionManager funcMgr = activeProgram.getFunctionManager();
        ReferenceManager refMgr = activeProgram.getReferenceManager();

        for (Map.Entry<Address, String> entry : stringIndex.entrySet()) {
            String value = entry.getValue();

            for (Map.Entry<String, String> unitEntry : UNIT_TYPE_PATTERNS.entrySet()) {
                if (value.contains(unitEntry.getValue())) {
                    ReferenceIterator refIter = refMgr.getReferencesTo(entry.getKey());
                    while (refIter.hasNext()) {
                        Reference ref = refIter.next();
                        Function func = funcMgr.getFunctionContaining(ref.getFromAddress());
                        if (func != null) {
                            functionTags.computeIfAbsent(func.getEntryPoint(), k -> new HashSet<>())
                                .add(unitEntry.getKey());
                        }
                    }
                }
            }
        }
    }

    //==========================================================================
    // TAG BY QUESTS (QUEST_)
    //==========================================================================

    private void tagByQuests(Map<Address, Set<String>> functionTags, Map<Address, String> stringIndex) throws Exception {
        FunctionManager funcMgr = activeProgram.getFunctionManager();
        ReferenceManager refMgr = activeProgram.getReferenceManager();

        for (Map.Entry<Address, String> entry : stringIndex.entrySet()) {
            String value = entry.getValue();
            Matcher matcher = QUEST_PATTERN.matcher(value);

            if (matcher.find()) {
                String act = matcher.group(1);
                String quest = matcher.group(2);
                String tagName = "QUEST_A" + act + "Q" + quest;

                ReferenceIterator refIter = refMgr.getReferencesTo(entry.getKey());
                while (refIter.hasNext()) {
                    Reference ref = refIter.next();
                    Function func = funcMgr.getFunctionContaining(ref.getFromAddress());
                    if (func != null) {
                        functionTags.computeIfAbsent(func.getEntryPoint(), k -> new HashSet<>())
                            .add(tagName);
                    }
                }
            }
        }
    }

    //==========================================================================
    // TAG BY AI (AI_)
    //==========================================================================

    private void tagByAI(Map<Address, Set<String>> functionTags, Map<Address, String> stringIndex) throws Exception {
        FunctionManager funcMgr = activeProgram.getFunctionManager();
        ReferenceManager refMgr = activeProgram.getReferenceManager();

        for (Map.Entry<Address, String> entry : stringIndex.entrySet()) {
            String value = entry.getValue();

            for (String aiKeyword : AI_KEYWORDS) {
                if (value.contains(aiKeyword)) {
                    String tagName = "AI_SYSTEM";
                    if (aiKeyword.equals("AiBaal")) tagName = "AI_BAAL";
                    else if (aiKeyword.equals("AiGeneral")) tagName = "AI_GENERAL";
                    else if (aiKeyword.equals("AiTatics")) tagName = "AI_TACTICS";
                    else if (aiKeyword.equals("AiThink")) tagName = "AI_THINK";
                    else if (aiKeyword.equals("AiUtil")) tagName = "AI_UTIL";
                    else if (aiKeyword.equals("MonsterAI")) tagName = "AI_MONSTER";

                    ReferenceIterator refIter = refMgr.getReferencesTo(entry.getKey());
                    while (refIter.hasNext()) {
                        Reference ref = refIter.next();
                        Function func = funcMgr.getFunctionContaining(ref.getFromAddress());
                        if (func != null) {
                            functionTags.computeIfAbsent(func.getEntryPoint(), k -> new HashSet<>())
                                .add(tagName);
                        }
                    }
                    break;
                }
            }
        }
    }

    //==========================================================================
    // TAG BY NETWORK (NET_)
    //==========================================================================

    private void tagByNetwork(Map<Address, Set<String>> functionTags, Map<Address, String> stringIndex) throws Exception {
        FunctionManager funcMgr = activeProgram.getFunctionManager();
        ReferenceManager refMgr = activeProgram.getReferenceManager();

        for (Map.Entry<Address, String> entry : stringIndex.entrySet()) {
            String value = entry.getValue();
            Set<String> netTags = new HashSet<>();

            for (String pattern : NET_SCMD_PATTERNS) {
                if (value.contains(pattern)) { netTags.add("NET_SCMD"); break; }
            }
            for (String pattern : NET_SERVER_PATTERNS) {
                if (value.contains(pattern)) { netTags.add("NET_SERVER"); break; }
            }
            for (String pattern : NET_CLIENT_PATTERNS) {
                if (value.contains(pattern)) { netTags.add("NET_CLIENT"); break; }
            }
            for (String pattern : NET_PACKET_PATTERNS) {
                if (value.contains(pattern)) { netTags.add("NET_PACKET"); break; }
            }

            if (!netTags.isEmpty()) {
                ReferenceIterator refIter = refMgr.getReferencesTo(entry.getKey());
                while (refIter.hasNext()) {
                    Reference ref = refIter.next();
                    Function func = funcMgr.getFunctionContaining(ref.getFromAddress());
                    if (func != null) {
                        functionTags.computeIfAbsent(func.getEntryPoint(), k -> new HashSet<>())
                            .addAll(netTags);
                    }
                }
            }
        }
    }

    //==========================================================================
    // TAG BY UI (UI_)
    //==========================================================================

    private void tagByUI(Map<Address, Set<String>> functionTags, Map<Address, String> stringIndex) throws Exception {
        FunctionManager funcMgr = activeProgram.getFunctionManager();
        ReferenceManager refMgr = activeProgram.getReferenceManager();

        for (Map.Entry<Address, String> entry : stringIndex.entrySet()) {
            String value = entry.getValue();

            for (Map.Entry<String, String> uiEntry : UI_PATTERNS.entrySet()) {
                if (value.toLowerCase().contains(uiEntry.getValue().toLowerCase())) {
                    ReferenceIterator refIter = refMgr.getReferencesTo(entry.getKey());
                    while (refIter.hasNext()) {
                        Reference ref = refIter.next();
                        Function func = funcMgr.getFunctionContaining(ref.getFromAddress());
                        if (func != null) {
                            functionTags.computeIfAbsent(func.getEntryPoint(), k -> new HashSet<>())
                                .add(uiEntry.getKey());
                        }
                    }
                }
            }
        }
    }

    //==========================================================================
    // TAG BY GRAPHICS (GFX_)
    //==========================================================================

    private void tagByGraphics(Map<Address, Set<String>> functionTags, Map<Address, String> stringIndex) throws Exception {
        FunctionManager funcMgr = activeProgram.getFunctionManager();
        ReferenceManager refMgr = activeProgram.getReferenceManager();

        for (Map.Entry<Address, String> entry : stringIndex.entrySet()) {
            String value = entry.getValue();
            Set<String> gfxTags = new HashSet<>();

            for (String mode : GFX_VIDEO_MODES) {
                if (value.contains(mode)) { gfxTags.add("GFX_VIDEO"); break; }
            }
            for (String cache : GFX_CACHE_PATTERNS) {
                if (value.contains(cache)) { gfxTags.add("GFX_CACHE"); break; }
            }
            for (String draw : GFX_DRAW_PATTERNS) {
                if (value.contains(draw)) { gfxTags.add("GFX_DRAW"); break; }
            }

            if (!gfxTags.isEmpty()) {
                ReferenceIterator refIter = refMgr.getReferencesTo(entry.getKey());
                while (refIter.hasNext()) {
                    Reference ref = refIter.next();
                    Function func = funcMgr.getFunctionContaining(ref.getFromAddress());
                    if (func != null) {
                        functionTags.computeIfAbsent(func.getEntryPoint(), k -> new HashSet<>())
                            .addAll(gfxTags);
                    }
                }
            }
        }
    }

    //==========================================================================
    // TAG BY SOUND (SND_)
    //==========================================================================

    private void tagBySound(Map<Address, Set<String>> functionTags, Map<Address, String> stringIndex) throws Exception {
        FunctionManager funcMgr = activeProgram.getFunctionManager();
        ReferenceManager refMgr = activeProgram.getReferenceManager();

        for (Map.Entry<Address, String> entry : stringIndex.entrySet()) {
            String value = entry.getValue();

            for (String snd : SND_PATTERNS) {
                if (value.contains(snd)) {
                    ReferenceIterator refIter = refMgr.getReferencesTo(entry.getKey());
                    while (refIter.hasNext()) {
                        Reference ref = refIter.next();
                        Function func = funcMgr.getFunctionContaining(ref.getFromAddress());
                        if (func != null) {
                            functionTags.computeIfAbsent(func.getEntryPoint(), k -> new HashSet<>())
                                .add("SND_SYSTEM");
                        }
                    }
                    break;
                }
            }
        }
    }

    //==========================================================================
    // TAG BY CHARACTER CLASSES (CLASS_)
    //==========================================================================

    private void tagByClasses(Map<Address, Set<String>> functionTags, Map<Address, String> stringIndex) throws Exception {
        FunctionManager funcMgr = activeProgram.getFunctionManager();
        ReferenceManager refMgr = activeProgram.getReferenceManager();

        for (Map.Entry<Address, String> entry : stringIndex.entrySet()) {
            String value = entry.getValue();

            for (Map.Entry<String, String> classEntry : CLASS_PATTERNS.entrySet()) {
                if (value.contains(classEntry.getValue())) {
                    ReferenceIterator refIter = refMgr.getReferencesTo(entry.getKey());
                    while (refIter.hasNext()) {
                        Reference ref = refIter.next();
                        Function func = funcMgr.getFunctionContaining(ref.getFromAddress());
                        if (func != null) {
                            functionTags.computeIfAbsent(func.getEntryPoint(), k -> new HashSet<>())
                                .add(classEntry.getKey());
                        }
                    }
                }
            }
        }
    }

    //==========================================================================
    // TAG BY LIBRARIES (LIB_)
    //==========================================================================

    private void tagByLibraries(Map<Address, Set<String>> functionTags, Map<Address, String> stringIndex) throws Exception {
        FunctionManager funcMgr = activeProgram.getFunctionManager();
        ReferenceManager refMgr = activeProgram.getReferenceManager();

        for (Map.Entry<Address, String> entry : stringIndex.entrySet()) {
            String value = entry.getValue();

            for (Map.Entry<String, String> libEntry : LIBRARY_PATTERNS.entrySet()) {
                if (value.contains(libEntry.getValue())) {
                    ReferenceIterator refIter = refMgr.getReferencesTo(entry.getKey());
                    while (refIter.hasNext()) {
                        Reference ref = refIter.next();
                        Function func = funcMgr.getFunctionContaining(ref.getFromAddress());
                        if (func != null) {
                            functionTags.computeIfAbsent(func.getEntryPoint(), k -> new HashSet<>())
                                .add(libEntry.getKey());
                        }
                    }
                    break;
                }
            }
        }
    }

    //==========================================================================
    // TAG BY API CATEGORIES (API_)
    //==========================================================================

    private void tagByApiCategories(Map<Address, Set<String>> functionTags) throws Exception {
        FunctionManager funcMgr = activeProgram.getFunctionManager();
        Map<Address, String> importMap = buildImportMap();

        FunctionIterator funcIter = funcMgr.getFunctions(true);
        while (funcIter.hasNext()) {
            if (monitor.isCancelled()) break;

            Function func = funcIter.next();
            Set<String> calledApis = getCalledApis(func, importMap);

            for (Map.Entry<String, String[]> category : API_CATEGORIES.entrySet()) {
                for (String api : category.getValue()) {
                    if (calledApis.contains(api)) {
                        functionTags.computeIfAbsent(func.getEntryPoint(), k -> new HashSet<>())
                            .add("API_" + category.getKey());
                        break;
                    }
                }
            }
        }
    }

    private Map<Address, String> buildImportMap() {
        Map<Address, String> importMap = new HashMap<>();
        SymbolTable symTable = activeProgram.getSymbolTable();
        ReferenceManager refMgr = activeProgram.getReferenceManager();

        SymbolIterator extSymbols = symTable.getExternalSymbols();
        while (extSymbols.hasNext()) {
            Symbol sym = extSymbols.next();
            if (sym.getSymbolType() == SymbolType.FUNCTION) {
                ReferenceIterator refIter = refMgr.getReferencesTo(sym.getAddress());
                while (refIter.hasNext()) {
                    importMap.put(refIter.next().getFromAddress(), sym.getName());
                }
            }
        }
        return importMap;
    }

    private Set<String> getCalledApis(Function func, Map<Address, String> importMap) {
        Set<String> apis = new HashSet<>();
        ReferenceManager refMgr = activeProgram.getReferenceManager();

        AddressIterator addrIter = func.getBody().getAddresses(true);
        while (addrIter.hasNext()) {
            Address addr = addrIter.next();
            for (Reference ref : refMgr.getReferencesFrom(addr)) {
                if (ref.getReferenceType().isCall()) {
                    String name = importMap.get(ref.getToAddress());
                    if (name != null) apis.add(name);
                    else {
                        Function called = activeProgram.getFunctionManager().getFunctionAt(ref.getToAddress());
                        if (called != null && called.isThunk()) {
                            Function thunked = called.getThunkedFunction(false);
                            if (thunked != null && thunked.isExternal()) {
                                apis.add(thunked.getName());
                            }
                        }
                    }
                }
            }
        }
        return apis;
    }

    //==========================================================================
    // TAG BY STRUCTURE (PROP_)
    //==========================================================================

    private void tagByStructure(Map<Address, Set<String>> functionTags) throws Exception {
        FunctionManager funcMgr = activeProgram.getFunctionManager();
        BasicBlockModel bbModel = new BasicBlockModel(activeProgram);

        FunctionIterator funcIter = funcMgr.getFunctions(true);
        while (funcIter.hasNext()) {
            if (monitor.isCancelled()) break;

            Function func = funcIter.next();
            int size = (int) func.getBody().getNumAddresses();
            Set<String> tags = functionTags.computeIfAbsent(func.getEntryPoint(), k -> new HashSet<>());

            // Size tags
            if (size <= 10) tags.add("PROP_TINY");
            else if (size <= 50) tags.add("PROP_SMALL");
            else if (size >= 500) tags.add("PROP_LARGE");
            else if (size >= 2000) tags.add("PROP_HUGE");

            // Leaf function
            if (func.getCalledFunctions(monitor).isEmpty()) tags.add("PROP_LEAF");

            // No callers
            if (func.getCallingFunctions(monitor).isEmpty()) tags.add("PROP_NOCALLER");

            // Thunk
            if (func.isThunk()) tags.add("PROP_THUNK");

            // Loop count
            int loops = countLoops(func);
            if (loops >= 3) tags.add("PROP_LOOPHEAVY");
        }
    }

    private int countLoops(Function func) {
        int loops = 0;
        Listing listing = activeProgram.getListing();
        AddressSetView body = func.getBody();

        InstructionIterator instrIter = listing.getInstructions(body, true);
        while (instrIter.hasNext()) {
            Instruction instr = instrIter.next();
            String mnemonic = instr.getMnemonicString();

            if (mnemonic.startsWith("J") || mnemonic.equals("LOOP")) {
                for (Reference ref : instr.getReferencesFrom()) {
                    if (ref.getReferenceType().isJump() &&
                        ref.getToAddress().compareTo(instr.getAddress()) < 0 &&
                        body.contains(ref.getToAddress())) {
                        loops++;
                    }
                }
            }
        }
        return loops;
    }

    //==========================================================================
    // TAG BY D2 STRUCTURES (STRUCT_)
    //==========================================================================

    private void tagByD2Structures(Map<Address, Set<String>> functionTags) throws Exception {
        FunctionManager funcMgr = activeProgram.getFunctionManager();
        Listing listing = activeProgram.getListing();

        FunctionIterator funcIter = funcMgr.getFunctions(true);
        while (funcIter.hasNext()) {
            if (monitor.isCancelled()) break;

            Function func = funcIter.next();
            Set<Integer> accessedOffsets = new HashSet<>();

            InstructionIterator instrIter = listing.getInstructions(func.getBody(), true);
            while (instrIter.hasNext()) {
                Instruction instr = instrIter.next();
                for (int i = 0; i < instr.getNumOperands(); i++) {
                    for (Object obj : instr.getOpObjects(i)) {
                        if (obj instanceof Scalar) {
                            int val = (int) ((Scalar) obj).getValue();
                            if (val >= 0 && val < 0x1000) accessedOffsets.add(val);
                        }
                    }
                }
            }

            for (Map.Entry<String, StructureSignature> entry : D2_STRUCTURES.entrySet()) {
                StructureSignature sig = entry.getValue();
                int matchCount = 0;
                for (int offset : sig.offsets) {
                    if (accessedOffsets.contains(offset)) matchCount++;
                }

                int threshold = Math.max(3, (int)(sig.offsets.length * 0.6));
                if (matchCount >= threshold) {
                    functionTags.computeIfAbsent(func.getEntryPoint(), k -> new HashSet<>())
                        .add(entry.getKey());
                }
            }
        }
    }

    //==========================================================================
    // TAG BY STRUCTURE NAMES (STRUCT_ from strings with Hungarian notation)
    //==========================================================================

    // Pattern to match Hungarian notation pointers: pSomething, ptSomething, ppSomething
    // Must start with p/pt/pp followed by uppercase letter
    private static final Pattern HUNGARIAN_POINTER_PATTERN = Pattern.compile(
        "\\b(p{1,2}t?[A-Z][a-zA-Z0-9_]*)\\b"
    );

    // Set of all known patterns to exclude from STRUCT_Other
    private static Set<String> ALL_KNOWN_PATTERNS = null;

    private void buildKnownPatternsSet() {
        if (ALL_KNOWN_PATTERNS != null) return;
        ALL_KNOWN_PATTERNS = new HashSet<>();
        for (String[] patterns : STRUCT_NAME_PATTERNS.values()) {
            for (String pattern : patterns) {
                ALL_KNOWN_PATTERNS.add(pattern);
            }
        }
    }

    private void tagByStructNames(Map<Address, Set<String>> functionTags, Map<Address, String> stringIndex) throws Exception {
        FunctionManager funcMgr = activeProgram.getFunctionManager();
        ReferenceManager refMgr = activeProgram.getReferenceManager();

        // Build the set of known patterns for STRUCT_Other detection
        buildKnownPatternsSet();

        int otherStructCount = 0;

        for (Map.Entry<Address, String> entry : stringIndex.entrySet()) {
            String value = entry.getValue();
            Set<String> matchedTags = new HashSet<>();
            boolean foundKnownStruct = false;

            // Check each structure name pattern
            for (Map.Entry<String, String[]> structEntry : STRUCT_NAME_PATTERNS.entrySet()) {
                String tagName = structEntry.getKey();

                for (String pattern : structEntry.getValue()) {
                    // Match as whole word to avoid false positives
                    // Check for: pattern at word boundary (not part of larger word)
                    if (containsWordBoundary(value, pattern)) {
                        matchedTags.add(tagName);
                        foundKnownStruct = true;
                        break;
                    }
                }
            }

            // Check for STRUCT_Other: any Hungarian notation pointer not already matched
            if (!foundKnownStruct) {
                Matcher matcher = HUNGARIAN_POINTER_PATTERN.matcher(value);
                while (matcher.find()) {
                    String match = matcher.group(1);
                    // Only tag as Other if not in known patterns
                    if (!ALL_KNOWN_PATTERNS.contains(match)) {
                        matchedTags.add("STRUCT_Other");
                        otherStructCount++;
                        break; // One STRUCT_Other per string is enough
                    }
                }
            }

            // Apply all matched tags to referencing functions
            if (!matchedTags.isEmpty()) {
                ReferenceIterator refIter = refMgr.getReferencesTo(entry.getKey());
                while (refIter.hasNext()) {
                    Reference ref = refIter.next();
                    Function func = funcMgr.getFunctionContaining(ref.getFromAddress());
                    if (func != null) {
                        functionTags.computeIfAbsent(func.getEntryPoint(), k -> new HashSet<>())
                            .addAll(matchedTags);
                    }
                }
            }
        }

        if (otherStructCount > 0) {
            println("    STRUCT_Other matches: " + otherStructCount);
        }
    }

    /**
     * Check if a string contains the pattern at a word boundary.
     * This prevents matching "pUnit" inside "DisplayUnit" or "ComputeUnit".
     * Matches: "pUnit", "pUnit->", "pUnit,", "(pUnit)", " pUnit "
     * Does not match: "DisplayUnit", "ComputeUnitValue"
     */
    private boolean containsWordBoundary(String text, String pattern) {
        int idx = 0;
        while ((idx = text.indexOf(pattern, idx)) != -1) {
            // Check character before pattern (should be non-alphanumeric or start)
            boolean validStart = (idx == 0) || !Character.isLetterOrDigit(text.charAt(idx - 1));

            // Check character after pattern (should be non-alphanumeric or end)
            int endIdx = idx + pattern.length();
            boolean validEnd = (endIdx >= text.length()) || !Character.isLetterOrDigit(text.charAt(endIdx));

            if (validStart && validEnd) {
                return true;
            }
            idx++;
        }
        return false;
    }

    //==========================================================================
    // TAG BY PARAMETER COUNT (PARAM_)
    //==========================================================================

    private void tagByParamCount(Map<Address, Set<String>> functionTags) throws Exception {
        FunctionManager funcMgr = activeProgram.getFunctionManager();
        Map<Integer, Integer> paramDistribution = new TreeMap<>();

        FunctionIterator funcIter = funcMgr.getFunctions(true);
        while (funcIter.hasNext()) {
            if (monitor.isCancelled()) break;

            Function func = funcIter.next();
            int paramCount = func.getParameterCount();

            // Track distribution
            paramDistribution.merge(paramCount, 1, Integer::sum);

            // Add tag
            String tagName = "PARAM_" + paramCount;
            functionTags.computeIfAbsent(func.getEntryPoint(), k -> new HashSet<>())
                .add(tagName);
        }

        // Log distribution summary
        int maxParams = paramDistribution.isEmpty() ? 0 :
            paramDistribution.keySet().stream().max(Integer::compare).orElse(0);
        println("    Parameter count range: 0 to " + maxParams);
    }

    //==========================================================================
    // TAG BY CALLEE/CALLER COUNT (CALLEE_, CALLER_)
    //==========================================================================

    private void tagByCallCounts(Map<Address, Set<String>> functionTags) throws Exception {
        FunctionManager funcMgr = activeProgram.getFunctionManager();
        Map<Integer, Integer> calleeDistribution = new TreeMap<>();
        Map<Integer, Integer> callerDistribution = new TreeMap<>();

        FunctionIterator funcIter = funcMgr.getFunctions(true);
        while (funcIter.hasNext()) {
            if (monitor.isCancelled()) break;

            Function func = funcIter.next();

            // Get callee count (functions this function calls)
            Set<Function> callees = func.getCalledFunctions(monitor);
            int calleeCount = callees.size();

            // Get caller count (functions that call this function)
            Set<Function> callers = func.getCallingFunctions(monitor);
            int callerCount = callers.size();

            // Track distribution
            calleeDistribution.merge(calleeCount, 1, Integer::sum);
            callerDistribution.merge(callerCount, 1, Integer::sum);

            // Add tags
            Set<String> tags = functionTags.computeIfAbsent(func.getEntryPoint(), k -> new HashSet<>());
            tags.add("CALLEE_" + calleeCount);
            tags.add("CALLER_" + callerCount);
        }

        // Log distribution summary
        int maxCallees = calleeDistribution.isEmpty() ? 0 :
            calleeDistribution.keySet().stream().max(Integer::compare).orElse(0);
        int maxCallers = callerDistribution.isEmpty() ? 0 :
            callerDistribution.keySet().stream().max(Integer::compare).orElse(0);
        println("    Callee count range: 0 to " + maxCallees);
        println("    Caller count range: 0 to " + maxCallers);
    }

    //==========================================================================
    // TAG BY RETURN TYPE (RET_)
    //==========================================================================

    private void tagByReturnType(Map<Address, Set<String>> functionTags) throws Exception {
        FunctionManager funcMgr = activeProgram.getFunctionManager();
        int structReturns = 0;

        FunctionIterator funcIter = funcMgr.getFunctions(true);
        while (funcIter.hasNext()) {
            if (monitor.isCancelled()) break;

            Function func = funcIter.next();
            DataType returnType = func.getReturnType();
            if (returnType == null) continue;

            String returnTypeName = returnType.getName();
            String displayName = returnType.getDisplayName();

            // Check against known structure patterns
            for (Map.Entry<String, String> entry : RETURN_TYPE_PATTERNS.entrySet()) {
                String tagName = entry.getKey();
                String pattern = entry.getValue();

                // Check if return type contains the structure name
                // Handles: "Unit *", "UnitAny *", "struct Unit *", "D2UnitStrc *"
                if (returnTypeName.contains(pattern) || displayName.contains(pattern)) {
                    functionTags.computeIfAbsent(func.getEntryPoint(), k -> new HashSet<>())
                        .add(tagName);
                    structReturns++;
                    break; // Only tag with first match to avoid duplicates
                }
            }

            // Also detect pointer returns to any struct (generic)
            if (isPointerToStruct(returnType)) {
                functionTags.computeIfAbsent(func.getEntryPoint(), k -> new HashSet<>())
                    .add("RET_STRUCT_PTR");
            }
        }

        println("    Functions returning structures: " + structReturns);
    }

    /**
     * Check if a data type is a pointer to a structure.
     */
    private boolean isPointerToStruct(DataType dt) {
        if (dt instanceof Pointer) {
            DataType pointedTo = ((Pointer) dt).getDataType();
            if (pointedTo instanceof Structure || pointedTo instanceof TypeDef) {
                // Check if it's not void* or primitive*
                String name = pointedTo.getName().toLowerCase();
                if (!name.equals("void") && !name.equals("undefined") &&
                    !name.equals("int") && !name.equals("char") &&
                    !name.equals("byte") && !name.equals("short") &&
                    !name.equals("long") && !name.equals("dword") &&
                    !name.equals("qword") && !name.equals("float") &&
                    !name.equals("double")) {
                    return true;
                }
            }
        }
        return false;
    }

    //==========================================================================
    // HELPER CLASS
    //==========================================================================

    static class StructureSignature {
        int[] offsets;
        String description;
        StructureSignature(int[] offsets, String description) {
            this.offsets = offsets;
            this.description = description;
        }
    }
}
