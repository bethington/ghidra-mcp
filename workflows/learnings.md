# RE Loop Learnings

> Maintained by /re-loop. Manual edits welcome.
> Last updated: iteration 20

## Binary Context
- [D2Common.dll@1.00] x86 32-bit PE, __stdcall ordinal exports. 3,654 functions, 332 data types, image base 0x10000000. All undocumented ordinals are single-JMP thunks.
- [D2Common.dll@1.13d] x86 32-bit PE, __stdcall ordinal exports. 2,961 functions, 488 data types, image base 0x6fd50000. Core game data: items, stats, skills, levels. 1,054 undocumented (35.6%). Source paths: `..\\Source\\D2Common\\DATATBLS\\DataTbls.cpp`. **CRITICAL**: Duplicate function names exist (e.g., two "Ordinal_10600" at different addresses). Always use address-based operations. Ordinals are NOT stable across versions (ordinal N in 1.13d ≠ ordinal N in 1.10).
- [Fog.dll@1.13d] x86 32-bit PE, mixed calling conventions (__cdecl, __fastcall). 1,069 functions, 441 data types, image base 0x6ff50000. Foundation utility DLL — networking, memory management, file I/O, bit manipulation.
- [Storm.dll@1.13d] x86 32-bit PE, __stdcall ordinal exports. 1,675 functions, 602 data types, image base 0x6fbf0000. Blizzard platform library — file I/O (MPQ), networking, audio, image formats, memory, events, registry, error handling. 99.5% pre-named, only 8 ordinals undocumented. Source paths: `..\3rdParty\STORM\SOURCE\*.CPP`.

## Naming Conventions
- [D2Common.dll] Ordinal exports mostly use __stdcall; exception: FreeTrackedPoolArray (10954) uses __fastcall (ECX/EDX)
- [Fog.dll] Mixed calling conventions: __cdecl for simple/logging, __fastcall (ECX/EDX) for path and init functions
- [Fog.dll] BITMANIP_ prefix family: ordinals 10118-10136 (CE_Database). BITMANIP_WriteBits (10128), BITMANIP_SetBitState (10118)
- [Fog.dll] Handle[Event]Shutdown pattern: HandleDeadlockShutdown (10027) — WSACleanup + error log + exit
- [Fog.dll] System init: InitializeSystem (10019) — OS detection, critical sections, memory pool, exception handler
- [Fog.dll] Path getters: Get[Install/Save]Path (10116/10115) — registry-first with fallback, __fastcall(lpszBuffer, dwBufferSize)
- [Storm.dll] Canonical S-prefix API naming: SErr*, SReg*, SEvt*, SFile*, SNet*, SBmp*, SDraw*, SMem*, SVid*, SStr*. Community names from Liquipedia/storm.h — always preferred over generated names.
- [Storm.dll] Pre-documented functions: all 8 undocumented ordinals already had plate comments, variable renames, and prototypes from previous analysis. Only needed function name assignment.
- Functions: PascalCase verb-first (SetUnitUpdateFlag, GetAnimDataRecord, LogArchiveError)
- Error/logging functions: Log[Context]Error pattern (LogArchiveError, LogSaveParseError)
- Position functions: Get[Unit]Position pattern
- Stat list functions: [Verb]Stat[From/To]StatList pattern (ClearStatFromStatList, SetOrAddStatToStatList)
- Item comparison: AreItems[Adjective] pattern (AreItemsInSameStatGroup)
- Linked list ops: Remove[Unit]From[List] pattern (RemoveUnitFromChangedList)
- Boolean state checks: Is[Unit][State]Active pattern (IsUnitStateActive)
- Trivial getters: Get[Node][Property] pattern (GetNodeDirection)
- Exchange operations: Exchange[Entity][Field] pattern (ExchangeUnitTypeField) — set new, return old
- Stat accessors: GetStatRecord[Entry] pattern (GetStatRecordEntry) — array indexing with GetStatRecord
- Multi-flag boolean: Has[Active][Condition]Flags pattern (HasActiveEffectFlags) — OR'd bit checks
- Monster compute: Compute[Monster][Params] pattern (ComputeMonsterSkillParams) — multi-branch class switch
- Missile accessors: Get/SetMissileDataField pattern — assert UNIT_MISSILE, access pMissileData offsets
- Pool memory: Free[Tracked]Pool[Array] pattern (FreeTrackedPoolArray) — batch deallocation
- Effect flag family: Has[Type]EffectFlag pattern (HasOverlayEffectFlag, HasAuraEffectFlag, HasActiveEffectFlags) — ordinals 10526/10533/10535

## Structure Layouts
### UnitAny (partial)
- Offset +0x00 (pUnit[0x00]): dwType (uint) — unit type enum. 0 = Player (confirmed by AdjustValueByPlayerClass)
- Offset +0x04 (pUnit[0x01]): dwClassId (uint) — class ID (0=Amazon?, 3=Paladin?, 4=Barbarian? — speculative from AdjustValueByPlayerClass)
- Offset +0x0C (pUnit[0x03]): dwPathIndex (uint) — index into path Y position array
- Offset +0x4C (pUnit[0x13]): nPosX (int) — unit X coordinate
- Offset +0x50 (pUnit[0x14]): nPosY (int) — unit Y coordinate (non-player)
- Offset +0x68 (pUnit[0x1a]): pSubData (void*) — sub-struct pointer with effect flags (+0xD8 bit 1, +0xDC bit 31, +0xE4 bits 3,11)
- Offset +0x6C (pUnit[0x1b]): pPathData/pMissileData (void*) — path data for units, missile data for type 3 (confirmed by ptMissileData assert)
- Offset +0xC8 (pUnit[0x32]): pTypeData (void*) — type-specific data union (Player/Monster/Item/Object/Missile). Field at +0x14 is exchangeable mode/state.
- Offset +0xDC (pUnit[0x37]): dwStateFlags1 (uint) — bit 31: state overlay active flag
- Offset +0xE0 (pUnit[0x38]): dwStateFlags2 (uint) — bit 29: state active continuation flag
- Offset +0xE8 (pUnit[0x3a]): dwFlags (uint) — bit 0: needs room update, bit 1: player-specific update flag
- Offset +0x100 (pUnit[0x40]): ptChangedNext (void*) — linked list pointer for room "changed" units list
- Player Y position: *(pPathData + 0xD8 + dwPathIndex * 4)

### AnimDataRecord (16 bytes, from iteration 2)
- Offset +0x00: dwField0 (uint)
- Offset +0x04: dwField1 (uint)
- Offset +0x08: dwField2 (uint)
- Offset +0x0C: dwField3 (uint)
- Indexed by (nAnimIndex >> 8), stride = 0x10 bytes
- Used by InitializeUnitAnimation, GetUnitAnimFrameEvent, InitializeMonsterItemData

### ItemStatsDataEntry (partial, from iteration 3)
- Offset +0x68: dwGroupId (uint) — stat group identifier, used for group membership comparison

### StatRecord (partial, from iteration 5)
- Offset +0x190 (400 decimal): pBase (void*) — base pointer of stat entry array
- Offset +0x198: dwStride (uint) — element size for array indexing
- Entry address = pBase + dwStride * (nIndex - 1), 1-based indexing
- Used by GetStatRecordEntry

### Stat Encoding
- Combined key = nLayer * 256 + nSubStat (layer in high bits, substat in low byte)
- Used by ClearStatFromStatList, SetOrAddStatToStatList

## Ordinal Mappings
- Ordinal 10024: LogArchiveError — logs error during archive/file I/O
- Ordinal 10098: LogSaveParseError — logs error during character save parsing
- Ordinal 10352: SetUnitUpdateFlag — sets/clears room update flag on a unit
- Ordinal 10375: GetUnitPosition — retrieves unit X/Y position (player uses path-based Y)
- Ordinal 10509: ClearStatFromStatList — clears stat by setting value to 0 via SetOrAddStatToStatList
- Ordinal 10645: GetAnimDataRecord — extracts 16-byte animation data record by index
- Ordinal 10207: GetNodeDirection — trivial getter reading direction from node sub-struct at *(*(pNode+0x34)+0x48)
- Ordinal 10382: RemoveUnitFromChangedList — removes unit from room's "changed" linked list via ptChangedNext at +0x100
- Ordinal 10529: IsUnitStateActive — checks state overlay flags at UnitAny +0xDC (bit 31) and +0xE0 (bit 29)
- Ordinal 10729: AreItemsInSameStatGroup — checks if two items share a stat group via 3 global arrays
- Ordinal 10853: ExchangeUnitTypeField — exchanges field at +0x14 in unit type-specific data (+0xC8)
- Ordinal 10899: GetStatRecordEntry — computes stat record array entry by 1-based index (base +0x190, stride +0x198)
- Ordinal 10535: HasActiveEffectFlags — multi-flag boolean check on sub-struct at +0x68
- Ordinal 10944: ComputeMonsterSkillParams — class-switch computing overlay/target params for monster skills
- Ordinal 11000: GetMissileDataField — reads pMissileData+0x28 (asserts UNIT_MISSILE)
- Ordinal 11012: SetMissileDataField — writes pMissileData+0x34 (asserts UNIT_MISSILE, ptMissileData)
- Ordinal 10954: FreeTrackedPoolArray — __fastcall, frees 108 tracked pool entries from array
- Ordinal 10533: HasOverlayEffectFlag — checks pSubData+0xD8 bit 1 and +0xE4 bit 11
- Ordinal 10526: HasAuraEffectFlag — checks pSubData+0xD8 bit 29 and +0xDC bit 29
- Ordinal 10772: AdjustValueByPlayerClass — class-based value multiplier (1.5x class 0/3, 2x class 4)
- Ordinal 10483: TestStateTargetOverlay — state bit property tester (body already named)
- Ordinal 11093: GetDataTableValue — 2D table lookup, stride 135, base g_adwDataTable135
- Ordinal 10843: GetLinkedFieldByte — null-safe read byte at *(pStruct[0]+0x7E)
- Ordinal 10211: ResetUnitTileAttributes — clear collision, lookup preset, apply tile attrs. Unit+0x34 = tile data ptr
- Ordinal 10370: AdvanceFrameAccumulator — 8.8 fixed-point frame counter with wrap. pAnimData+0x4C=accum, +0x54=rate
- [D2Common.dll@1.13d] Ordinal 10600: GetItemDataRecord — bounds-checked item data lookup, stride 0x1a8 (424 bytes). Community: D2GetItemsBIN
- [D2Common.dll@1.13d] Ordinal 10731: CheckItemType — bitmask item type checker using sgptDataTables type matrix + parent type inheritance at +0x120. Community: D2CheckItemType
- [D2Common.dll@1.13d] Ordinal 10550: GetUnitBaseStat — stat value getter from ItemStatCost table, stride 0x144 (324 bytes), calls GetStatValueWithMinCheck. Community: D2GetPlayerBaseStat
- [D2Common.dll@1.13d] Ordinal 10463: SetStatInList — binary search + insert/remove/update stat in sorted list, propagates delta to modifier chain. Community: STATLIST_SetStat
- [D2Common.dll@1.13d] Ordinal 10037: CompileTextDataTable — loads tab-delimited .txt from DATA\GLOBAL\EXCEL, compiles to binary via format descriptors. Source: DataTbls.cpp. Community: DATATBLS_CompileTxt
- [D2Common.dll@1.13d] Ordinal 10590: SetUnitStat — wrapper: validates unit, calls SetStatInList on unit's stat list. Community: STATLIST_SetUnitStat
- [D2Common.dll@1.13d] Ordinal 10953: CheckCollisionMask — multi-mode collision checker. Mode 0=point, 1/3/5=edge_wrap, 2/4=3x3 area. Calls GetMaskFlagAtCoordinate, CheckMaskFlagsWithEdgeWrap, CheckMaskFlagsRecursive
- [D2Common.dll@1.13d] Ordinal 11158: AddStatToList — accumulator variant of stat list update (adds to existing value). Community: STATLIST_AddStat
- [D2Common.dll@1.13d] Ordinal 10846: GetUnitClassData — returns class-specific data pointer from unit, 31 xrefs
- [D2Common.dll@1.13d] Ordinal 10121: GetItemType — item type lookup via code→type mapping. Calls undocumented Ordinal_10850 (GetItemTypeFromClassId)
- [D2Common.dll@1.13d] Ordinal 10780: GetUnitSizeModifier — per-type switch: Player=2, Monster=table+8, Object=sub+0xD0, Missile=table+0x18A, Item=1
- [D2Common.dll@1.13d] Ordinal 10075: GetItemProperty — item-only accessor: reads item_data+0x28, asserts type==4
- [D2Common.dll@1.13d] Ordinal 10283: AllocateDrlgLevel — __fastcall(pDrlg, nLevelId). DRLG level struct 0x230 bytes. Source: Drlg.cpp. Level types: 1=Maze, 2=Preset, 3=Outdoors
- [D2Common.dll@1.13d] Ordinal 10190: GetStatCostTableValue — reads from ItemStatCost table (sgptDataTables+0xBCC, stride 0x144) via GetBaseStatValueWithMinCheck
- [D2Common.dll@1.13d] Ordinal 10229: AddUnitToClassQueue — links unit into class_data+0x1C queue, sets bit 0x2000 at unit+0xC4, marks dirty
- [D2Common.dll@1.13d] Ordinal 10216: GetStatCostValueChecked — like GetStatCostTableValue but also checks unit+0x5C != 0 (stat list/active flag)
- [D2Common.dll@1.13d] Ordinal 11090: GetItemTypeProperty — reads byte at +0x10 from ItemTypes table (sgptDataTables+0xBF8, stride 0xE4, count +0xBFC)
- [D2Common.dll@1.13d] Ordinal 10955: IsItemNotRestricted — returns 1 unless item has flags 0x100 or 0x4000 at item_data+0x18
- [D2Common.dll@1.13d] Ordinal 10709: GetItemFlags — returns dword at item_data+0x18 (item status/restriction flags)
- [D2Common.dll@1.13d] Ordinal 10174: GetGlobalRecordById — 1-based index into global table at DWORD_6fdf4cd8, stride 0x90 (144 bytes), count DWORD_6fdf4cd4. 100% score.
- [D2Common.dll@1.13d] Ordinal 10808: InsertAndApplyStatList — dual-chain stat list insertion (+0x3C primary, +0x40 secondary with modifier apply)
- [D2Common.dll@1.13d] Ordinal 10000: FindItemDataRecord — binary search item data by 4-byte code, sorted table stride 0x1a8
- [D2Common.dll@1.13d] Ordinal 10374: ApplySkillItemStats — skill→item stat application (up to 5 entries), tracking stats 0x15E/0x15F
- [D2Common.dll@1.13d] Ordinal 10850: GetItemTypeFromClassId — item_data+0x50 → ItemTypes table index. Called by GetItemType (10121)
- [D2Common.dll@1.13d] Ordinal 10886: LookupGlobalPairTable — 13-element key-value scan at DWORD_6fdf4cd8
- [D2Common.dll@1.13d] Ordinal 10706: IsUnitAutoMapRevealed — validates unit type (Player/Monster/Missile), delegates to IsAutoMapCellRevealed
- [D2Common.dll@1.13d] Ordinal 11152: SetUnitItemTypeBitFlag — set/clear bit in bitmask at unit[0x17]+0x58, uses gdwBitMasks_exref/gdwInvBitMasks_exref
- [D2Common.dll@1.13d] Ordinal 10007: GetEffectiveItemLevel — item_data+0x28 base + optional skill bonus, clamped to [0, g_pdwMaxItemLevel]
- [D2Common.dll@1.13d] Ordinal 11081: EvaluateSkillCalcExpression — bytecode interpreter for skill calcs. Table: sgptDataTables+0x40/+0x44. Uses GetSkillCalcParameter callback.
- [D2Common.dll@1.13d] Ordinal 10399: ApplyUnitItemTypeStatList — creates stat list (flags 0x80), writes stat 0xB2 (item type), sets bit 0x100 at unit[0x17]+0x10
- [D2Common.dll@1.13d] Ordinal 11146: CalcLevelScaledValue — diminishing returns formula: level*110/(level+6) * (max-min)/100 + min. Pure math, 95%/100%eff.
- [D2Common.dll@1.13d] Ordinal 10157: GetUnitCollisionFlags — __fastcall, returns collision bitmask per unit type. Type 2 (Object) checks +0x13A/+0x13B/+0x167/+0x1B6. Type 4=0x200, Type 5=1.
- [D2Common.dll@1.13d] Ordinal 10058: FindBestEquippedWeapon — inventory weapon selection. Reads unit[0x18] (inventory), switch on item sub-type at +0x168. Type 0x2D = weapon class. Slots 5/6 = left/right hand.
- [D2Common.dll@1.13d] Ordinal 10977: TransferStatListOwnership — transfers stat list between owners. Special case: items with Ordinal_10689 result 0x0B/0x0C get removed. Bit 0x40000000 at sub_struct+0x10 = modifier state.
- [D2Common.dll@1.13d] Ordinal 10964: GetLevelPresetData — reads 24 bytes from preset table. DWORD_6fdf4cac (base), stride 0xF0 (240 bytes), compound index = levelId + presetIndex*16.
- [Fog.dll@1.13d] Ordinal 10019: InitializeSystem — __fastcall, OS detection + crit sections + memory pool + exception handler. Absent in 1.06b.
- [Fog.dll@1.13d] Ordinal 10027: HandleDeadlockShutdown — __cdecl, WSACleanup + LogErrorAndInitiateShutdown + ShutdownResourcesAndExit
- [Fog.dll@1.13d] Ordinal 10115: GetSavePath — __fastcall(lpszBuffer, dwBufferSize), registry "Save Path" + fallback to InstallPath\Save\
- [Fog.dll@1.13d] Ordinal 10116: GetInstallPath — __fastcall(lpszBuffer, dwBufferSize), registry "InstallPath" + fallback to module path
- [Fog.dll@1.13d] Ordinal 10128: BITMANIP_WriteBits — __cdecl, bit-packing encoder into bitstream buffer
- [Fog.dll@1.13d] Ordinal 10263: ReadAndMergeCrashdumpRecords — __fastcall, reads+deduplicates crash records from Crashdump file. Absent in 1.06b.
- [Fog.dll@1.13d] Ordinal 10033: DumpStackAndShutdown — __stdcall, deadlock stack dump + shutdown. WARNING: ordinal 10033 = different function in 1.06b (AllocClientMemory).
- [Storm.dll@1.13d] Ordinal 466: SErrReportNamedResourceLeak — debug resource leak logger with lazy init, OutputDebugStringA
- [Storm.dll@1.13d] Ordinal 423: SRegLoadValue — registry value loader (RegQueryValueExA)
- [Storm.dll@1.13d] Ordinal 376: SEvtPopState — event hash table entry pop/removal with critical section
- [Storm.dll@1.13d] Ordinal 377: SEvtPushState — event hash table entry push/insertion with critical section
- [Storm.dll@1.13d] Ordinal 290: SFileReadFileEx — file data allocation and reading with MPQ archive support
- [Storm.dll@1.13d] Ordinal 138: SNetCreateLadderGame — ladder game creation with player config and broadcast
- [Storm.dll@1.13d] Ordinal 326: SBmpSaveImageEx — multi-format image writer (BMP, PCX, TGA, GIF)
- [Storm.dll@1.13d] Ordinal 255: SFileDdaBeginEx — WAV/DDA audio stream initialization and playback setup

## Function Families
- **Logging**: LogArchiveError (10024), LogSaveParseError (10098) — adjacent at 0x10077dXX, file I/O error subsystem
- **Unit State**: SetUnitUpdateFlag (10352), IsUnitStateActive (10529), RemoveUnitFromChangedList (10382), ExchangeUnitTypeField (10853), HasActiveEffectFlags (10535) — UnitAny flags/linked lists/type data
- **Position/Movement**: GetUnitPosition (10375), GetNodeDirection (10207) — coordinate and path data
- **Animation**: GetAnimDataRecord (10645) — AnimDataRecord lookup by index
- **Item Stats**: AreItemsInSameStatGroup (10729), ClearStatFromStatList (10509), GetStatRecordEntry (10899) — stat encoding, group comparison, array access
- **Missile**: GetMissileDataField (11000), SetMissileDataField (11012) — missile-specific data access with type assertions
- **Monster Skills**: ComputeMonsterSkillParams (10944) — class-relative skill overlay/targeting
- **Effect Flags**: HasAuraEffectFlag (10526), HasOverlayEffectFlag (10533), HasActiveEffectFlags (10535) — family of flag checkers on sub-struct at +0x68
- **Memory Management**: FreeTrackedPoolArray (10954) — tracked pool deallocation, 108 entries, __fastcall
- **Player Class Scaling**: AdjustValueByPlayerClass (10772) — class-based multiplier, UnitAny+0x04 = classId
- **State Bit Testers**: TestStateTargetOverlay (10483) — thin wrappers around TestStateBit with hardcoded bitmask constants
- **Data Table Accessors**: GetDataTableValue (11093) — 2D table[row][col], stride 135, global base at 0x1009c388
- **Tile/Collision**: ResetUnitTileAttributes (10211) — ClearUnitCollisionFlags + ApplyPresetUnitTileAttributes, preset lookup via g_adwPresetTileValues
- **Animation**: AdvanceFrameAccumulator (10370) — 8.8 fixed-point frame counter, accumulator+rate at +0x4C/+0x54
- **Struct Getters**: GetLinkedFieldByte (10843) — indirection-based byte getter (pStruct→sub→field)
- [Fog.dll] **System Init**: InitializeSystem (10019) — OS detection, critical sections, memory pool, bitmask validation, exception handler
- [Fog.dll] **File Paths**: GetInstallPath (10116), GetSavePath (10115) — registry-first path resolution with fallbacks
- [Fog.dll] **Bit Manipulation**: BITMANIP_WriteBits (10128) — part of BITMANIP_ family (ordinals 10118-10136)
- [Fog.dll] **Error Handling**: HandleDeadlockShutdown (10027), DumpStackAndShutdown (10033) — deadlock detection + graceful shutdown
- [Fog.dll] **Crash Diagnostics**: ReadAndMergeCrashdumpRecords (10263) — crashdump file reader with record deduplication
- [Storm.dll] **Error/Debug**: SErrReportNamedResourceLeak (466) — debug leak logging with lazy init
- [Storm.dll] **Registry**: SRegLoadValue (423) — config value loading from Windows registry
- [Storm.dll] **Events**: SEvtPopState (376), SEvtPushState (377) — hash table-backed event state management with critical section
- [Storm.dll] **File I/O**: SFileReadFileEx (290) — MPQ archive-aware file reader
- [Storm.dll] **Networking**: SNetCreateLadderGame (138) — ladder game session creation
- [Storm.dll] **Image Export**: SBmpSaveImageEx (326) — multi-format image writer (BMP, PCX, TGA, GIF)
- [Storm.dll] **Audio**: SFileDdaBeginEx (255) — WAV/DDA audio stream initialization
- [D2Common.dll@1.13d] **Item Data**: GetItemDataRecord (10600) — array lookup by item code, stride 0x1a8
- [D2Common.dll@1.13d] **Item Types**: CheckItemType (10731) — bitmask type check with parent inheritance, 111 xrefs (most-called undocumented)
- [D2Common.dll@1.13d] **Stat System**: GetUnitBaseStat (10550), SetStatInList (10463) — stat value read/write via sorted lists with binary search
- [D2Common.dll@1.13d] **Data Tables**: CompileTextDataTable (10037) — generic DATA\GLOBAL\EXCEL .txt→binary compiler, 94 xrefs
- [D2Common.dll@1.13d] **Stat System Extended**: SetUnitStat (10590) wraps SetStatInList (10463), AddStatToList (11158) accumulates. Three-layer architecture: unit wrapper → sorted list op → delta propagation
- [D2Common.dll@1.13d] **Collision**: CheckCollisionMask (10953) — multi-mode point/edge/area collision. Subfamily: GetMaskFlagAtCoordinate, CheckMaskFlagsWithEdgeWrap, CheckMaskFlagsRecursive
- [D2Common.dll@1.13d] **Unit Data Access**: GetUnitClassData (10846) — class data pointer getter. GetItemType (10121) → GetItemTypeFromClassId (10850)
- [D2Common.dll@1.13d] **Unit Properties**: GetUnitSizeModifier (10780) — per-type property switch. GetItemProperty (10075) — item data field at +0x28
- [D2Common.dll@1.13d] **DRLG (Level Generation)**: AllocateDrlgLevel (10283) — level struct allocator from Drlg.cpp. Level types: 1=Maze (FindLevelWarpEntryById), 2=Preset (AllocatePresetWithRandomSubEntry), 3=Outdoors (Outdoors.cpp). LevelsDef table: sgptDataTables+0xC5C (count), base DWORD_6fdf64b8, stride 0x9C
- [D2Common.dll@1.13d] **Unit Queue Management**: AddUnitToClassQueue (10229) — linked list insertion at class_data+0x1C, membership flag bit 0x2000 at unit+0xC4
- [D2Common.dll@1.13d] **Item Flags**: GetItemFlags (10709) — item_data+0x18 dword. IsItemNotRestricted (10955) checks bits 0x100 and 0x4000 of this. Related to item restrictions.
- [D2Common.dll@1.13d] **Item Type Table**: GetItemTypeProperty (11090) — ItemTypes.txt lookup. Table: sgptDataTables+0xBF8 (base), +0xBFC (count), stride 0xE4 (228 bytes). Property at +0x10.
- [D2Common.dll@1.13d] **Global Record Accessors**: GetGlobalRecordById (10174) — stride 0x90 table at DWORD_6fdf4cd8, 1-based indexing. First 100% score function in 1.13d.
- [D2Common.dll@1.13d] **Stat List Operations**: InsertAndApplyStatList (10808) — dual chain insertion: primary at +0x3C, secondary at +0x40 with modifier application. Complex 66-line function with 12 register-only SSA vars.
- [D2Common.dll@1.13d] **Item Data Search**: FindItemDataRecord (10000) — binary search by 4-byte item code in sorted table (sgptDataTables+0xB7C base, +0xB80 count, stride 0x1a8). Returns pointer or NULL. 95% score.
- [D2Common.dll@1.13d] **Skill Item Stats**: ApplySkillItemStats (10374) — applies up to 5 stat entries from skill data (+0x98 stat IDs, +0xA4 params, stride 4). Skills table: +0xB98/+0xBA0, stride 0x23C. Tracking stats: 0x15E=skillId, 0x15F=target. 4 undocumented callees: Ordinal_10706 (check skill target), Ordinal_10007 (create item link), Ordinal_11081 (calc stat value), Ordinal_11152 (finalize effect).
- [D2Common.dll@1.13d] **Item Type Lookup**: GetItemTypeFromClassId (10850) — reads uint at item_data+0x50, bounds-checks against ItemTypes count. Called by GetItemType (10121).
- [D2Common.dll@1.13d] **Global Pair Table**: LookupGlobalPairTable (10886) — 13-element key-value table at DWORD_6fdf4cd8, scans key array then returns value at matching offset. 0-based indexing, returns 0 on miss.
- [D2Common.dll@1.13d] **Automap**: IsUnitAutoMapRevealed (10706) — unit type filter (Player/Monster/Missile only) → IsAutoMapCellRevealed delegate
- [D2Common.dll@1.13d] **Item Type Bitmask**: SetUnitItemTypeBitFlag (11152) — bit manipulation on bitmask array at unit[0x17]+0x58. Uses gdwBitMasks_exref/gdwInvBitMasks_exref globals. Marks unit dirty via AddUnitToClassQueue. ApplyUnitItemTypeStatList (10399) creates stat lists with flag 0x80, writes stat 0xB2.
- [D2Common.dll@1.13d] **Skill Calculations**: EvaluateSkillCalcExpression (11081) — bytecode evaluator. Calc table: sgptDataTables+0x40 (base), +0x44 (size). Callback: GetSkillCalcParameter. Related: ApplySkillItemStats (10374) calls this per stat entry.
- [D2Common.dll@1.13d] **Item Level**: GetEffectiveItemLevel (10007) — base from item_data+0x28 + optional CalculateTotalSkillDamageBonus, clamped to g_pdwMaxItemLevel. Same base field as GetItemProperty (10075).
- [D2Common.dll@1.13d] **Level Scaling**: CalcLevelScaledValue (11146) — diminishing returns curve: level*110/(level+6). At level 99: ~103.7% of range. Used for stat/damage/defense scaling across 13 callers.
- [D2Common.dll@1.13d] **Unit Collision**: GetUnitCollisionFlags (10157) — __fastcall flag bitmask. Object sub-struct offsets: +0x13A (blocking), +0x13B (solid), +0x167 bit 4 (special), +0x1B6 (dynamic). Default reads from pPath+0x4C.
- [D2Common.dll@1.13d] **Weapon Selection**: FindBestEquippedWeapon (10058) — inventory scan by unit[0x18]. Equipment slots via Ordinal_10286. Type 0x2D = weapon check. Flag 0x2000 = dual-wield pref. Sub-type switch at +0x168.
- [D2Common.dll@1.13d] **Stat List Transfer**: TransferStatListOwnership (10977) — handles ownership migration with item special cases. Bit 0x40000000 = modifier applied state. Ordinal_10333 = unapply, Ordinal_10431 = reapply.
- [D2Common.dll@1.13d] **Level Presets**: GetLevelPresetData (10964) — table at DWORD_6fdf4cac, stride 0xF0, compound 2D index (16 levels per preset). Copies 6 DWORDs from +0x10 to +0x24.

## String Anchors
- [D2Common.dll@1.13d] `..\\Source\\D2Common\\DATATBLS\\DataTbls.cpp` — CompileTextDataTable and related data table functions

## Known Limitations
- Hungarian `fEnable` false positive: int used as boolean gets `p` prefix flagged. Accept `f` prefix for int-as-boolean.
- Hungarian `pX` false positive: int used as pointer (e.g., pUnit, pStatEntry). Countermeasure: set type to `void*` or proper pointer type. Occurs in ~50% of functions with pointer-semantics params.
- Thunk functions (single JMP) have no body variables of their own; skip type audit and variable renaming on the thunk. Document the body instead.
- Register-only SSA variables (bVar*, iVar*, piVar*, uVar*) in worker bodies cannot be renamed or retyped. Document in plate comment Special Cases.
- Decompiler fails to recover jumptables for some error logging functions (0x10077d16, 0x10077d22).
- CONCAT22 phantom variables (extraout_var*) appear when 16-bit path position functions return ushort but caller uses uint. Cannot fix.
- DAT_* globals renamed via create_label/rename_or_label may not reflect in decompiler output until cache refresh. Deduction persists at 97% — accept as near-unfixable.
- [FrontEnd] propagate_documentation fails: "FunctionService is null". Must propagate manually via switch_program + rename + set_prototype per version.

## Strategy Performance
- [D2Common.dll@1.00] callee_first: 25 functions, avg 94.4% — all ordinal exports are thunks with no callees, degrades to sequential.
- [D2Common.dll@1.13d] callee_first (exploration): 5 functions, avg 77.4% raw / 100% effective. All callees pre-named (1900+ functions already named). Strategy degenerates to sequential in this binary since undocumented Ordinal_* functions mostly call already-named functions.
- [Fog.dll@1.13d] callee_first: 7 functions across 2 iterations, avg 84.6% raw / 98.6% effective. Binary COMPLETE (0 undocumented). Register-only SSA is primary deduction source. Propagation: 11 total (7 to 1.10, 4 to 1.06b).
- [D2Common.dll] All 269 remaining undocumented are Ordinal_* thunks. Worker-body thunks still yield rich analysis.
- [D2Common.dll] Best batch: iteration 7 (3 thunks, all 100%). Worst: iteration 9 (85% raw, void* deductions).
- [D2Common.dll@1.13d] neighborhood (exploration): 5 functions, avg 59.4% raw / 91.0% effective. Low raw scores due to many register-only SSA variables in complex functions. Good for contextual documentation — 4/5 were callees of ApplySkillItemStats with shared skill/item context.
- [Storm.dll@1.13d] callee_first: 8 functions in 1 iteration, avg 56.1% raw / 85.9% effective. Binary COMPLETE (0 undocumented). Low raw scores due to register-only SSA and pre-existing docs with unfixable deductions. All community-named. Propagation: 8 to 1.10, 0 to 1.06b.

## Common Mistakes
- Typing parameters as `int` when they're semantically pointers (e.g., pAnimDataTable). Set type to `void*` or a proper pointer type to avoid Hungarian notation false positives and improve decompiler output.

## Cross-Binary Notes
- LogArchiveError and LogSaveParseError are adjacent (0x10077d16, 0x10077d22) — part of a file I/O error logging subsystem. Likely more error logging thunks in the 0x10077dXX range.

## Cross-Version Notes
- [D2Common.dll@1.00] 25 functions documented (iteration 1-9). Classic cluster head start.
- Version clusters: Modern LoD (1.11-1.13d, 50-70% hash), Early LoD (1.07-1.10, 40-60% hash), Classic (1.00-1.06b, high hash), Monolithic (1.14a-1.14d), PD2
- 1.10->1.11 boundary: major DLL refactor — functions migrated between D2Client, D2Game, D2Common.
- Monolithic 1.14x: Game.exe contains all DLLs merged. String anchors identify virtual DLL boundaries.
- PD2: based on 1.13c layout. PD2-specific DLLs need full manual docs.
- [Fog.dll] 1.13d↔1.10: identical function addresses (5/5 hash match at same addresses). Very high stability.
- [Fog.dll] 1.13d↔1.06b: 4/5 hash match. HandleDeadlockShutdown at different address (0x6ff6ef10 vs 0x6ff5e3b0). Ordinal_10019 (InitializeSystem) absent in Classic-era — newer system init function.
- [Fog.dll] propagate_documentation fails in FrontEnd mode ("FunctionService is null"). Workaround: manual switch_program + rename_function_by_address + set_function_prototype per secondary version.
- [Fog.dll] CRITICAL: Ordinal numbers are NOT stable across Classic↔LoD versions. Ordinal 10033 = DumpStackAndShutdown in 1.13d but AllocClientMemory in 1.06b. Always verify by decompiling before propagating by ordinal name.
- [Fog.dll] Ordinal_10263 (ReadAndMergeCrashdumpRecords) absent in 1.06b — newer crash diagnostics feature added post-Classic.
- [Storm.dll] 1.13d→1.10: different image bases (0x6fbf0000 vs 0x6ffb0000) so addresses differ, but ordinal numbers stable within LoD era. All 8 ordinals found. Hash matches failed (code changed between versions) but ordinal-based rename works.
- [Storm.dll] 1.13d→1.06b: Classic-era Storm.dll has completely different export table. 0/8 ordinals found. Storm.dll export table is NOT stable across Classic↔LoD boundary (same as Fog.dll).
- [Storm.dll] Propagation approach for Storm: ordinal-name matching (not hash matching) works for LoD→LoD versions. For Classic→LoD, ordinal tables are incompatible.
- [D2Common.dll] **CRITICAL**: D2Common.dll ordinals are shuffled between ALL versions — ordinal N in 1.13d maps to a completely DIFFERENT function than ordinal N in 1.10. Ordinal 10600 has 84 xrefs in 1.13d but 169 in 1.10 (different function). Neither hash matching (0/5) nor ordinal matching works for cross-version propagation. Need semantic matching via string anchors, fuzzy comparison, or source file correlation.
- [D2Common.dll] Duplicate function names: Ghidra assigns the same ordinal name to multiple addresses (e.g., two "Ordinal_10600" at 0x6fd88130 and 0x6fdb2c70). Always use address-based operations (rename_function_by_address, decompile_function(address=), etc.) — never name-based.
- [D2Common.dll] Propagation strategy for D2Common: (1) Within modern_lod cluster (1.11-1.13d): try hash first, then fuzzy. (2) Across clusters: use source file string anchors (DataTbls.cpp path, format strings) to identify equivalent functions. (3) Community ordinal tables (PlugY/D2Funcs.h) have per-version mappings that can help correlate.

## Community References
- **CE_Database (GitHub)**: ThePhrozenKeep/CE_Database — complete export tables for all D2 DLLs. Used for Fog.dll ordinal names (GetSavePath, BITMANIP_ family).
- **d2mods.info / PhrozenKeep**: Ordinal tables, function signatures, struct definitions, modding docs. Primary for D2Common, also covers Fog.dll.
- **d2bs (GitHub)**: JavaScript bindings for D2 function names/params. Kolton/d2bot-with-kolbot.
- **GitHub repos**: blizzhackers, d2mods — community RE work with struct layouts and constant enums.
- Community names preferred over generated names when well-established.
- **Liquipedia StarCraft Brood War Wiki**: Comprehensive Storm.dll ordinal table with function signatures. Best source for Storm.dll API names.
- **storm.h (danyim/notes GitHub)**: C header with Storm.dll ordinal-to-name mappings. Partial but reliable for SFile*, SReg*, SNet*, SDraw*, SVid*, SMem*, SErr*, SStr* families.
- **PlugY/D2Funcs.h (GitHub haxifix/PlugY)**: D2Common ordinal→name mappings across versions (1.10–1.14d). Best for D2Common function identification.
- **D2MOO (GitHub ThePhrozenKeep/D2MOO)**: Reimplementation of D2 with DATATBLS_, STATLIST_, ITEMS_ prefix conventions. Source at `source/D2Common/src/`. Key files: D2StatList.cpp, DataTbls/, Items/.
- **Diablo-II-Address-Table (GitHub mir-diablo-ii-tools)**: Per-version address tables (1.13D.txt, etc.). Partial D2Common coverage.
