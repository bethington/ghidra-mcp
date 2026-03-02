# RE Loop Learnings

> Maintained by /re-loop. Manual edits welcome.
> Last updated: iteration 158

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
- Offset +0x10 (pUnit[0x04]): dwAnimMode (uint) — animation mode. Set by SetUnitAnimMode. Type 5 (Warp) excluded from mode changes.
- Offset +0x14 (pUnit[0x05]): pTypeData (void*) — type-specific data union: pPlayerData (type 0), pMonsterData (type 1), pObjectData (type 2), pItemData (type 4). Confirmed by GetPlayerData (11103), GetPlayerDataField2C (10910), GetObjectRecordField168 (10828).
- Offset +0x4C (pUnit[0x13]): nPosX (int) — unit X coordinate
- Offset +0x4E: bAnimFlag (byte) — animation flag, cleared by InitializeUnitAnimation
- Offset +0x50 (pUnit[0x14]): nPosY (int) — unit Y coordinate (non-player)
- Offset +0x5C (pUnit[0x17]): pStatList (void*) — stat list pointer. Stat list has: +0x10 flags (bit 1=needs cleanup), +0x3C linked list head, +0x58 item type bitmask
- Offset +0x68 (pUnit[0x1a]): pSubData (void*) — sub-struct pointer with effect flags (+0xD8 bit 1, +0xDC bit 31, +0xE4 bits 3,11)
- Offset +0x6C (pUnit[0x1b]): pPathData/pMissileData (void*) — path data for units, missile data for type 3 (confirmed by ptMissileData assert)
- Offset +0xC8 (pUnit[0x32]): pTypeData (void*) — type-specific data union (Player/Monster/Item/Object/Missile). Field at +0x14 is exchangeable mode/state.
- Offset +0xDC (pUnit[0x37]): dwStateFlags1 (uint) — bit 31: state overlay active flag
- Offset +0xE0 (pUnit[0x38]): dwStateFlags2 (uint) — bit 29: state active continuation flag
- Offset +0xC4 (pUnit[0x31]): dwUpdateFlags (uint) — bit 0: needs update (set by SetUnitAnimMode, AddUnitToRoom)
- Offset +0xE8 (pUnit[0x3a]): ptRoomNext (void*) — next unit in room linked list (head at room+0x74). Confirmed by AddUnitToRoom and FindUnitsInRooms.
- Offset +0x100 (pUnit[0x40]): ptChangedNext (void*) — linked list pointer for room "changed" units list
- Player Y position: *(pPathData + 0xD8 + dwPathIndex * 4)

### AnimDataRecord (16 bytes, from iteration 2)
- Offset +0x00: dwField0 (uint)
- Offset +0x04: dwField1 (uint)
- Offset +0x08: dwField2 (uint)
- Offset +0x0C: dwField3 (uint)
- Indexed by (nAnimIndex >> 8), stride = 0x10 bytes
- Used by InitializeUnitAnimation, GetUnitAnimFrameEvent, InitializeMonsterItemData

### Missiles Table (sgptDataTables+0xB64, stride 0x1A4 = 420 bytes)
- Base: sgptDataTables+0xB64, count: sgptDataTables+0xB6C
- Field +0x04: byte, bitmask flags (checked by SetMissileSourceData 11091)
- Field +0x94: byte (GetMissileRecordField94, 11164)
- Field +0xEC: base value (int), used by CalcMissileParam
- Field +0x104: level breakpoints (passed to CalculateStatByLevelBreakpoints)
- Field +0x118: calc expression index (uint, -1 = none)
- Field +0x196: fixed-point shift (byte)

### ItemStatCost Table (sgptDataTables+0xBCC, stride 0x144 = 324 bytes)
- Base: sgptDataTables+0xBCC, count: sgptDataTables+0xBD4
- Field +0x54: byte — stat category (6-7 = derived stat with dependency chain)
- Field +0x58: 3 x ushort — dependency stat IDs (0xFFFF = terminator)
- Used by RecalculateDerivedStats (11002), GetItemStatCostValue (10889)

### Missile Data Struct (unit[5] for type 3, 52 bytes = 13 dwords, Source: Missile.cpp:0x22)
- +0x08: short (GetMissileDataField08, 11137)
- +0x0C: short (SetMissileDataField0C, 11119)
- +0x0E: short — total frames/range (GetMissileDataField0E, 11122)
- +0x10: short — elapsed frames/distance (GetMissileDataField10, 11124). Diff = remaining (11125)
- +0x18: dword — source data field 1 (SetMissileSourceData 11091, from pSourceData[0])
- +0x1C: dword — source data field 2 (SetMissileSourceData 11091, from pSourceData[3], -1=none)
- +0x20: dword — target data field 1 (GetMissileTargetData 11138)
- +0x24: dword — target data field 2 (GetMissileTargetData 11138, default -1)
- +0x28: dword — get/set (GetMissileDataField28 11141, SetMissileDataField28 11140)
- +0x2C: dword (GetMissileDataField2C, 11143)

### State Flags Bitfield (16 bytes + version tag, from iteration 113)
- Offset +0x00: wVersion (short) — version tag: 0=legacy, 0x101=v1, 0x102=current
- Offset +0x02: 16 bytes of packed flag data (8 shorts)
- Lookup tables: WORD_6fdef450 (offsets), WORD_6fdef452 (bitmasks) — 112 state flags
- DWORD_6fdef610 = 0x70 (112 flag count)
- API: GetStateFlagBit (11029), ExportStateFlagsToBuffer (10334), ImportStateFlagsFromBuffer (10599), DeallocateStateFlags (10468)
- Version auto-upgrade: 0 and 0x101 upgraded to 0x102 on access. Unrecognized versions abort.

### Skills Table (sgptDataTables+0xC58, stride 0x220 = 544 bytes, from iteration 113)
- Base: sgptDataTables+0xC58, Count: sgptDataTables+0xC5C
- Field +0xE4: overlay index byte (0xFF = none)
- 1-based indexing (nSkillId > 0)
- Used by TryGetSkillRecordOverlay (10978)

### DifficultyLevels Table (DWORD_6fdf64d8, stride 0x58 = 88 bytes, from iteration 158)
- Base: DWORD_6fdf64d8, Count: DWORD_6fdf64d4
- Community: D2GetDifficultyLevelsBIN (PlugY/D2Funcs.h)
- Used by GetDifficultyLevelsBIN (10694)

### QualityLevel Table (g_pQualityLevelTable 0x6fdf64d0, stride 0x20 = 32 bytes, from iteration 158)
- Threshold-based bracket lookup (iterate until nItemLevel < threshold)
- Used by GetItemQualityBracket (11171)

### SkillDesc Table (DWORD_6fdf64b8, stride 0x9C = 156 bytes, from iteration 115)
- Base: DWORD_6fdf64b8, Count: sgptDataTables+0xC5C (shared with Skills table)
- Field +0x34: dword (GetSkillDescField0x34, 10918)
- Field +0x94: dword (GetSkillDescField0x94, 10702)
- Field +0x98: dword (GetSkillDescField0x98, 10557)
- 0-based indexing

### Grid Record Table (DWORD_6fdf4cac, stride 0xF0 = 240 bytes, from iteration 115)
- Base: DWORD_6fdf4cac, Max index: DWORD_6fdf4ca8
- 2D indexing: flat = nRow * 16 + nCol (16-column grid)
- Header: 4 dwords at offset 0 (GetGridRecordHeader, 10770)
- Sub-entries: 5 dwords each, starting at offset 40 (GetGridRecordSubEntry, 10441)

### Path Data (unit+0x2C sub-structure, 512 bytes)
**Position layout (type-dispatched):**
- Types 0/1/3 (Player/Monster/Missile): +0x00=X 16.16 fixed, +0x02=X ushort (integer part), +0x04=Y 16.16 fixed, +0x06=Y ushort, +0x08=target X (tile), +0x0C=target Y (tile)
- Types 2/4/5 (Object/Item/Tile): +0x04=X (tile), +0x08=Y (tile), +0x0C=X2 (integer, <<16 for fixed), +0x10=Y2 (integer, <<16 for fixed)
- Offset +0x10: current position
- Offset +0x24: velocity (int, subtracted per step)
- Offset +0x30: sub-struct pointer (validated for mode 2 transitions)
- Offset +0x34: mode flags (uint, bits 8-18 = mode-specific flags, bit 4 = at destination)
- Offset +0x3C: current mode (int: 2=normal, 4=special, 0xB/8=invalid backup, 0xD=alternate, 0xF=retry)
- Offset +0x40: backup mode (int, saved from +0x3C on flag 0x2000 transitions)
- Offset +0x7C: secondary field (backed up to +0x80 on flag bit 15 transitions)
- Offset +0x80: backup of +0x7C
- Offset +0x91: byte value (validated < 0x4E for mode 4)
- Offset +0x94: distance accumulator (byte, [0-255])
- Offset +0x98: mode data (from g_adwData_6fde02d8[mode + 0x0E])
- Used by AdvanceUnitPathStep (10251), SetPathMode (10325), CopyUnitPathBlock (10881), ComputeUnitPath (10474)

### Room (partial)
- Offset +0x28: player/NPC count (incremented by AddUnitToRoom for type 0 and Monster stat==2)
- Offset +0x74: unit list head (linked list, next at unit+0xE8)
- Offset [8]+0x08: collision map stride
- Offset [8]+0x20: collision map data pointer (ushort array)
- Offset [0x13]: X origin, [0x14]: Y origin, [0x15]: width, [0x16]: height
- Used by TraceLineForCollision (10505), AddUnitToRoom (11279), FindUnitsInRooms (10181)

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
- [D2Common.dll@1.13d] Core ordinals (high-xref, community names): 10600: GetItemDataRecord (D2GetItemsBIN, stride 0x1a8), 10731: CheckItemType (D2CheckItemType, bitmask+inheritance), 10550: GetUnitBaseStat (D2GetPlayerBaseStat, ItemStatCost stride 0x144), 10463: SetStatInList (STATLIST_SetStat, binary search+modifier chain), 10037: CompileTextDataTable (DATATBLS_CompileTxt, DataTbls.cpp), 10590: SetUnitStat (STATLIST_SetUnitStat, wrapper), 11158: AddStatToList (STATLIST_AddStat, accumulator)
- [D2Common.dll@1.13d] Collision/spatial: 10953: CheckCollisionMask (multi-mode 0-4), 10780: GetUnitSizeModifier (per-type switch), 10246: ComputeUnitDistance (size-adjusted distance)
- [D2Common.dll@1.13d] Item accessors: 10075: GetItemProperty (+0x28), 10709: GetItemFlags (+0x18), 10955: IsItemNotRestricted (flags 0x100/0x4000), 10121: GetItemType (→10850 GetItemTypeFromClassId, +0x50), 11090: GetItemTypeProperty (ItemTypes +0x10, stride 0xE4), 10000: FindItemDataRecord (binary search by 4-byte code)
- [D2Common.dll@1.13d] Stat system: 10190: GetStatCostTableValue (ItemStatCost +0xBCC, stride 0x144), 10216: GetStatCostValueChecked (requires unit+0x5C), 10808: InsertAndApplyStatList (+0x3C/+0x40 dual-chain), 10846: GetUnitClassData (31 xrefs)
- [D2Common.dll@1.13d] DRLG/units: 10283: AllocateDrlgLevel (__fastcall, struct 0x230, Source: Drlg.cpp), 10229: AddUnitToClassQueue (+0x1C queue, bit 0x2000), 10174: GetGlobalRecordById (stride 0x90, 100% score), 10374: ApplySkillItemStats (5 entries, stats 0x15E/0x15F), 10850: GetItemTypeFromClassId (+0x50→ItemTypes)
- [D2Common.dll@1.13d] Item record field getters: 10569: GetItemRecordFlagDC (+0xDC bit 0), 10390: GetItemRecordField13E (+0x13E byte), 10661: GetItemRecordFieldE4 (+0xE4 DWORD), 10761: GetItemRecordField104 (+0x104 byte), 10884: GetItemRecordGfxField (+0x138, gfx cap), 10209: GetItemRecordByte11C (+0x11C strict), 10143: GetItemDimensions (+0x10F/+0x110). All stride 0x1a8.
- [D2Common.dll@1.13d] Item properties: 10360: SetItemProperty (+0x28, mirror of 10075), 10717: GetItemQuantity (+0x2C, min 1), 10458: TestItemFlags (+0x18 bitmask), 10695: GetItemQuality (+0x00, enum 1-8), 10880: IsItemEthereal (bit 22 in +0x18), 10007: GetEffectiveItemLevel (+0x28 base+bonus), 10185: GetItemStackGfxTier (quantity→tier), 10976: GetItemStatValueCapped (capped 0x1FF)
- [D2Common.dll@1.13d] Spatial/transforms: 10720: TransformIsometricCoords ((2Y+X)>>5, (2Y-X)>>5), 10697: CalcDirectionToCoords (type-branched), 10881: CopyUnitPathBlock (32 bytes from +0x4C)
- [D2Common.dll@1.13d] Set items: 10189: GetSetItemRecordField2E (+0x2E), 10346: GetSetItemRecord (SetItems +0xC18, stride 0x1B8), 10233: GetItemStorePage (ItemTypes +0x21)
- [D2Common.dll@1.13d] COF/anim: 11169: GetCofComponentByte (switch remap), 10856: BuildUnitCofPath (equip+mode), 10743: IsUnitWeaponAnimMelee (token 1/7), 10840: SetAnimFieldPair (DWORD pair), 10484: GetUnitOverlayComponent (type+mode→index), 11127: GetObjectDataField0A (+0xA short)
- [D2Common.dll@1.13d] Stat cost: 10341: GetStatFromListByLayerChecked (unit+0x5C check), 10952/10790: min/maxDamageStatCost (stats 21-24), 10943/10084: maxStamina/maxMana (stats 11/9), 10518: GetUnitStatCostValue (stride 0x144), 10219: AllocateStatList (60-byte, StatsEx.cpp:1386), 10399: ApplyUnitItemTypeStatList (stat 0xB2)
- [D2Common.dll@1.13d] Collision pair: 10444: ClearCollisionMask (mode 1/2/3), 10446: SetCollisionMask (mode 1/2/3 OR), 10152: GetCollisionMaskFlags (mode 0-3), 10223: ClearUnitCollisionArea (type dispatch), 10222: SetUnitCollisionArea (mirror), 10157: GetUnitCollisionFlags (__fastcall), 11081: EvaluateSkillCalcExpression (bytecode +0x40/+0x44)
- [D2Common.dll@1.13d] Equipment: 10058: FindBestEquippedWeapon (slots 5/6), 10627: FindEquippedWeaponByClassId (type 0x2D), 10721: FindWeaponInEquipSlots (slots 4/5), 10286: GetEquippedItemByBodyLoc (11 slots), 10987: GetItemEquipBodyType (+0xC0 lookup), 10171: IsUnitDualWieldClass (Barbarian/Assassin), 11012: ResolveItemEquipSlotType (bitmask scan)
- [D2Common.dll@1.13d] DRLG/units: 10736: GenerateDrlgLevel (1=Maze/2=Preset/3=Outdoors), 10964: GetLevelPresetData (stride 0xF0), 10992: RemoveUnitFromClassList (+0x74 list), 10292: GetInventorySlotItem (0-12), 11146: CalcLevelScaledValue (diminishing returns), 10977: TransferStatListOwnership, 10435: AssignSkillToUnit (Skills.cpp), 10886: LookupGlobalPairTable (13 elements), 10706/11152: automap/bitmask flag ops
- [D2Common.dll@1.13d] Ordinal 10361: TestItemTypeBitMatrix — 2D bit matrix test, sgptDataTables+0xC04 (120x120 table)
- [D2Common.dll@1.13d] Ordinal 10526: ResolveWeaponAnimToken — complex 175-line animation resolver. 4-byte ASCII codes: "hth "=hand-to-hand, "1ss "=single swing, "1js "=jab swing, "1jt "=jab thrust, "1st "=stab, "ht2 "=assassin. Skills table: sgptDataTables+0xBC4, stride 0xC4.
- [D2Common.dll@1.13d] Ordinal 11021: GetSkillRangeValue — skills table short at +0x174. Default 0x7FFFFFFF (range/distance). Skills: base +0xB98, count +0xBA0, stride 0x23C.
- [D2Common.dll@1.13d] Ordinal 10984: FindSkillListNode — __fastcall linked list search at pSkillData+0xA8. Matches skillId (short at +0) AND param (at +0x34). Node stride: +0 id, +4 next, +0x34 param.
- [D2Common.dll@1.13d] Ordinal 11013: GetUnitBlockingSize — per-type collision size. Player=2, Monster=table+9, Object=record+0xD4, Missile=table+0x18A, Item=1. NULL aborts.
- [D2Common.dll@1.13d] Ordinal 10820: UnpackAnimComponentFields — packed uint decoder: low5/3, low5%3, bits[9:5]. Leaf, 90%.
- [D2Common.dll@1.13d] Ordinal 10520: FindItemSkillStatInList — recursive stat 0xCC (204) searcher on item stat lists + inventory. Calls Ordinal_10027 for flag 0x40 nodes.
- [D2Common.dll@1.13d] Ordinal 10085: ApplySkillStatToRoomUnits — recursive stat 0xCC applier via FindRoomUnitByTypeFlags(0x40) + Ordinal_10709. Encodes level+param. 43% raw (10 SSA).
- [D2Common.dll@1.13d] Ordinal 10619: GetOverlayRecord — Overlay table at DWORD_6fdf4cec, count DWORD_6fdf4ce8, stride 0xC0 (192). Bounds-checked, 90%.
- [D2Common.dll@1.13d] Ordinal 10423: FreeDrlgStructure — __fastcall DRLG destructor. Frees levels (+0x47C, next +0x1AC) and sub-resources (+0x90, next +0x44). Pool at +0x478.
- [D2Common.dll@1.13d] Ordinal 11112: FreeResourcePair — frees *(DWORD*)pResource then pResource itself via DeallocateResourceBuffer
- [D2Common.dll@1.13d] Ordinal 10046: CalcSkillManaCost — Skills +0x148/+0x14C min/max via CalcLevelScaledValue
- [D2Common.dll@1.13d] Ordinal 10947: IsLineOfSightClear — wrapper around TraceLineForCollision, inverts result (true=clear)
- [D2Common.dll@1.13d] Ordinal 10648: EvaluateSkillCalcValue — Skills +0x198/+0x19C/+0x1A0 linear or bytecode calc
- [D2Common.dll@1.13d] Ordinal 10906: IsUnitAutoMapStateRevealed — checks state 0x86 (134) for Player/Monster/Missile, returns 2 if revealed
- [D2Common.dll@1.13d] Ordinal 10289: CalcPlayerAttackFrames — (unit+0x48>>8) / weapon speed. Default 0x13 (hand-to-hand). Uses FindBestEquippedWeapon + Ordinal_10564.
- [D2Common.dll@1.13d] Ordinal 10196: CalcSkillMaxDamage — skill +0x1AC base, +0x1C4 breakpoints, +0x1A5 weapon factor, +0x1D8 bytecode calc. Mirror of CalcSkillMinDamage.
- [D2Common.dll@1.13d] Ordinal 10687: CalcSkillMinDamage — skill +0x1A8 base, +0x1B0 breakpoints. Uses stat 0x15 (mindamage) or GetMinDamageStatCost.
- [D2Common.dll@1.13d] Ordinal 10030: GetLevelRecordField06 — short at record+6
- [D2Common.dll@1.13d] Ordinal 10465: GetLevelRecordField02 — short at record+2
- [D2Common.dll@1.13d] Ordinal 10203: SetSkillRecordDisabledFlag — toggles bit 0x40 at record+0x34. fEnable=0 sets, non-zero clears.
- [D2Common.dll@1.13d] Ordinal 10556: ResetProfilingCounters — DumpProfilingStats + zero static array (stride 0x78, ~12 entries)
- [D2Common.dll@1.13d] Ordinal 10629: GetMaxItemLevelByDifficulty — g_pdwMaxItemLevel[nDifficulty], clamp 0-6
- [D2Common.dll@1.13d] Ordinal 10628: GetMaxItemLevelByQualityTier — g_pdwMaxItemLevel[diff + 8 + quality*8]
- [D2Common.dll@1.13d] Ordinal 10746: GetItemLevelCapByIndex — secondary table stride 0x20, record +0x3C, bounds-checked
- [D2Common.dll@1.13d] Ordinal 10993: GetItemRecordBodyLoc — byte at item record +0x115. Equipment body location slot. Strict validation (aborts on NULL/non-item/no record).
- [D2Common.dll@1.13d] Ordinal 10715: GetItemRecordByte132 — byte at item record +0x132. **Stackability flag** (0=not stackable). Used by AreItemsIdentical (10613) to gate deep comparison. Lenient (returns 0 for NULL/non-item).
- [D2Common.dll@1.13d] Ordinal 11168: ApplyCollisionPatternAtCoords — delegates to Ordinal_10144 with unit size/flags. NULL aborts.
- [D2Common.dll@1.13d] Ordinal 10254: ApplyUnitSizedCollision — extracts position from path data, delegates to Ordinal_11104 with collision properties.
- [D2Common.dll@1.13d] Ordinal 10335: UpdateUnitSkillLevel — find/create skill node, set level, reapply stats. Skill node: +0x28=level.
- [D2Common.dll@1.13d] Ordinal 10613: AreItemsIdentical — deep item comparison for stacking: classId, quality, property, +0x132 flag, ethereal, 6 stats (0x15-0x18, 0x9F, 0xA0), Ordinal_10275 check. Returns 1 if all match.
- [D2Common.dll@1.13d] Ordinal 10236: CheckUnitCollisionOverlap — bounding box overlap test between units. Only checks against Object type. Uses path data position (type-dependent 16/32-bit coords).
- [D2Common.dll@1.13d] Ordinal 10604: GetItemRecordCode — dword at item data record +0x80. Used by item encode/decode serialization.
- [D2Common.dll@1.13d] Ordinal 10701: GetItemDataShortByIndex — ushort at item_data+0x3E + nIndex*2. Lenient (returns 0 on failure).
- [D2Common.dll@1.13d] Ordinal 10348: IsClassRestrictedItem — checks item record +0x13D for Barbarian (class 4) owners. Likely "2-handed" flag. Used by weapon swap validation.
- [D2Common.dll@1.13d] Ordinal 10246: ComputeUnitDistance — approximate distance between units using size-adjusted positions. Lookup table for near (<8 tiles), weighted sum for far. Used by collision system.
- [D2Common.dll@1.13d] Ordinal 10443: GetWeaponSlotRestriction — weapon slot compatibility checker. Returns -1 (no issue), 1 (class restricted), 2 (special property). Calls IsClassRestrictedItem and HasItemRecordFlag11C.
- [D2Common.dll@1.13d] Ordinal 10004: GetItemRecordByte137 — byte at item record +0x137 by classId. Lenient (0 on out-of-bounds).
- [D2Common.dll@1.13d] Ordinal 10672: HasItemRecordFlag11C — unit-validated wrapper around GetItemRecordByte11C. Returns 0 for non-items.
- [D2Common.dll@1.13d] **ItemTypes Table Field Map** (sgptDataTables+0xBF8, stride 0xE4): +0x0C=short equiv1 (10215 by-unit, 10222 by-index), +0x0E=short equiv2 (10869 by-unit, 10658 by-index), +0x10=byte (10882), +0x11=byte (10299 by-unit), +0x12=byte (11017 by-unit), +0x13=byte (10183 by-index), +0x19=byte property19 (10306), +0x21=byte storagePage (11108). Two accessor patterns: by-unit (validates type==4, calls GetItemType) and by-index (direct bounds-check).
- [D2Common.dll@1.13d] Ordinal 10149: IsItemDurabilityDepleted — multi-condition: has durability (+0x112), not indestructible (+0x113), Ordinal_10314 check, stat 0x98 < 1.
- [D2Common.dll@1.13d] Ordinal 10314: GetMaxDurabilityStat — checks ItemStatCost[73] (maxdurability), reads unit+0x5C stat list. Gate for durability depletion.
- [D2Common.dll@1.13d] Ordinal 10821: CalcMissileParam — missiles table calc (base+0xB64, stride 0x1A4). Fields: +0xEC base, +0x104 breakpoints, +0x118 calc, +0x196 shift. Requires type 3 (Missile).
- [D2Common.dll@1.13d] Ordinal 10728: CalcSkillElemMin — skill elemental min damage. Skills table +0x1E0 (base), +0x1E8 (breakpoints), +0x1A4 (shift), +0x210 (calc), +0x1DC (bonus type).
- [D2Common.dll@1.13d] Ordinal 10662: CalcSkillElemMax — skill elemental max damage. Skills table +0x1E4 (base), +0x1FC (breakpoints). Paired with CalcSkillElemMin.
- [D2Common.dll@1.13d] Ordinal 10251: AdvanceUnitPathStep — path stepping with mode transitions (2/0xD/0xF). Distance accumulator byte at path+0x94, velocity at path+0x24.
- [D2Common.dll@1.13d] Ordinal 10275: GetItemStatCostEntryC2 — reads ItemStatCost[194] (0xC2) value. Used by AreItemsIdentical for identity comparison.
- [D2Common.dll@1.13d] Ordinal 10536: EvaluateMissileCalcExpression — missile bytecode evaluator. Table: sgptDataTables+0x60/+0x64. Called by CalcMissileParam (10821).
- [D2Common.dll@1.13d] Ordinal 10001: GetItemDataShort30 — reads short at item_data+0x30. Type 4 only. CONCAT22 artifact.
- [D2Common.dll@1.13d] Ordinal 10739: SetUnitPathField10 — writes pathData+0x10 for Object/Item/Tile (types 2/4/5). Paired with 10892.
- [D2Common.dll@1.13d] Ordinal 10892: SetUnitPathField0C — writes pathData+0x0C for Object/Item/Tile (types 2/4/5). Paired with 10739. Likely X/Y coordinate pair at +0x0C/+0x10.
- [D2Common.dll@1.13d] Ordinal 10864: GetMaxGoldBank — gold stash tier by level thresholds (g_dwPad_6fde3418[1..5]). Community: D2GetMaxGoldBank.
- [D2Common.dll@1.13d] Ordinal 10796: CheckItemTypeByClassId — bitmask type check by class ID with parent inheritance at +0x120. Similar to CheckItemType (10731) but raw class ID input.
- [D2Common.dll@1.13d] Ordinal 11035: GetUnitModifierStatValue — stat from modifier 0x69 (105) via Ordinal_10429. Player/Monster only, default 2 for other types.
- [D2Common.dll@1.13d] Ordinal 10395: GetPositionPair — reads struct[0] and struct[9] (offsets +0x00, +0x24) into output pointers. Adjacent to CopyUnitPathBlock.
- [D2Common.dll@1.13d] Ordinal 10325: SetPathMode — path mode setter with flag backup, mode table g_adwData_6fde02d8. Updates +0x3C mode, +0x34 flags, +0x98 mode data.
- [D2Common.dll@1.13d] Ordinal 10032: ResolvePathModeAfterStep — resolves mode after step: backup +0x7C/+0x80, set mode 7 (idle) or restore from +0x40. Caller of SetPathMode.
- [D2Common.dll@1.13d] Ordinal 10579: AllocateUnitPath — allocates 512-byte path data from pool. Source: Path.cpp:1107. Type dispatch: Player=mode 7/collision 0x1C09, Monster=mode 2, Missile=mode 4.
- [D2Common.dll@1.13d] Ordinal 11131: InitializeUnitDefaultState — initializes unit sub-struct fields + animation. Community D2GetMaxGold is MISATTRIBUTED (ordinal shuffle).
- [D2Common.dll@1.13d] Ordinal 10587: IsItemAtBaseTier — weapon/armor tier check: normcode(+0x88) or ubercode(+0x8C) == code(+0x80), not type 0x26, flag +0x12A==0.
- [D2Common.dll@1.13d] Ordinal 10181: FindUnitsInRooms — callback-based unit search across adjacent rooms. UnitFindContext struct. Room+0x74=unit list, unit+0xE8=next.
- [D2Common.dll@1.13d] Ordinal 10594: StepExplorationField — reads exploration grid cell, steps position via delta lookup tables. Returns true if next cell passable (!=8).
- [D2Common.dll@1.13d] Ordinal 10517: GetItemDropQualityByDifficulty — __thiscall, difficulty→quality tier from table[+0x67]. Upgrades identifiable monsters: tier 1→3, 2→4 if bit flag 9 unset.
- [D2Common.dll@1.13d] Ordinal 10474: ComputeUnitPath — main pathfinding: validates target, clears collision, dispatches to handler via function pointer table[path+0x3C], validates waypoints. 100-line worker.
- [D2Common.dll@1.13d] Ordinal 11279 (actual 10748): AddUnitToRoom — inserts unit at head of room+0x74 linked list. Increments room+0x28 counter for Player/NPC(Monster with stat==2).
- [D2Common.dll@1.13d] Ordinal 10193: SetUnitAnimMode — sets unit+0x10 animation mode, flags unit+0xC4 for update. Skips Warp (type 5). Monster walk mode optimization.
- [D2Common.dll@1.13d] Ordinal 10551: WriteLogEntry — __cdecl thread-safe log writer. Critical section + WriteTimestampedLogEntry. 6 int params + format + varargs.
- [D2Common.dll@1.13d] Ordinal 10505: TraceLineForCollision — Bresenham ray cast through collision map. Room collision: room[8]+0x20=data, room[8]+8=stride. Room bounds: [0x13]=X, [0x14]=Y, [0x15]=W, [0x16]=H.
- [D2Common.dll@1.13d] Ordinal 11087: FindItemInventorySlot — inventory placement dispatcher by item height. 4 modes: 1=reverse, 2+2=alt, 3=mode2, default=standard. Magic 0x1020304.
- [D2Common.dll@1.13d] Ordinal 10762: SetItemDataField0C — strict item data setter at +0x0C. Asserts type 4 + data.
- [D2Common.dll@1.13d] Ordinal 10741: CompareItemRecordFieldC0 — item record +0xC0 equality check by classId. Stride 0x1A8.
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
- [D2Common.dll@1.13d] State flags API: 11029: GetStateFlagBit (offset/mask lookup), 10334: ExportStateFlagsToBuffer, 10599: ImportStateFlagsFromBuffer, 10468: DeallocateStateFlags. Version tag: 0/0x101→0x102 auto-upgrade. Globals: WORD_6fdef450 (offsets), WORD_6fdef452 (masks), DWORD_6fdef610=0x70 (112 flags).
- [D2Common.dll@1.13d] Ordinal 10978: TryGetSkillRecordOverlay — Skills table +0xC58, stride 0x220, field +0xE4 byte (overlay index, 0xFF=none). TryGet pattern (returns BOOL + out-param).
- [D2Common.dll@1.13d] Ordinal 10628: GetItemEffectiveCode — item effective code getter (item_data+0x84, or +0x88/+0x8C for upgraded tiers). Stride 0x1A8.
- [D2Common.dll@1.13d] Ordinal 10702: SetItemDataShortByIndex — writes ushort at item_data+0x3E + nIndex*2. Counterpart of GetItemDataShortByIndex (10701) at +0x3E (vs +0x3E read offset).
- [D2Common.dll@1.13d] Ordinal 10114: CleanupUnitStatListEntries — walks stat list at unit+0x5C, frees flagged entries (bit 2), reveals automap, clears cleanup flag (bit 1).
- [D2Common.dll@1.13d] Ordinal 10095: InitializeUnitAnimation — 5-way type switch: Player/Monster (equip slots, anim speed), Object (record data+random frame), Missile (64-bit scaled rate), Item (hardcoded). LOW SCORE: 42% due to 10 SSA undefined + 4 undocumented callees (10116, 10551, 11050, 10319).
- [D2Common.dll@1.13d] Ordinal 10699: GetItemDataField38ByIndex — reads ushort at item_data+0x38 + nIndex*2. Distinct from GetItemDataShortByIndex (10701, +0x3E offset).
- [D2Common.dll@1.13d] Ordinal 10689: GetItemDataByte44 — byte at item_data+0x44. CONCAT31 artifact. 5 xrefs.
- [D2Common.dll@1.13d] Ordinal 10306: GetItemTypeProperty19 — ItemTypes table byte at +0x19 (sgptDataTables+0xBF8, stride 0xE4). Community "D2GetSkillLevel" is ordinal mismatch.
- [D2Common.dll@1.13d] Ordinal 10679: CanItemBeRepaired — multi-check: flag 0x10, not ethereal, type repairable, tradeable or depleted. Calls 10499, IsItemDurabilityDepleted.
- [D2Common.dll@1.13d] Ordinal 10132: CalcMissileBreakpointValue — 3-tier piecewise linear (breakpoints 8, 16). Entry offsets: +0x11C base, +0x120/+0x124/+0x128 rates.
- [D2Common.dll@1.13d] Ordinal 10624: CalcMissileVelocityParam — velocity with CalculateStatByLevelBreakpoints (+0xCC) + base (+0xB4) + calc expression (+0xE0) + shift (+0x196).
- [D2Common.dll@1.13d] Ordinal 10302: CalcMissileAccelParam — acceleration with CalculateStatByLevelBreakpoints (+0xD8) + base (+0xB0) + calc expression (+0xEC) + shift (+0x196). Paired with CalcMissileVelocityParam.
- [D2Common.dll@1.13d] Ordinal 10975: StepExplorationToCollision — exploration stepper that walks delta array until collision flag (cell != 8). Calls StepExplorationField (10594).
- [D2Common.dll@1.13d] Ordinal 11113: DecodePackedPositionDelta — unpacks packed position delta into x/y components. Bit-level decoding of compact position format.
- [D2Common.dll@1.13d] Ordinal 11154: EvaluateSkillElementalCalc — elemental calc expression evaluator for skills. Calls EvaluateSkillCalcExpression (11081). Many SSA intermediates (35%/45%).
- [D2Common.dll@1.13d] Ordinal 10167: CalcSkillPassiveValue — passive skill value calculator using CalculateStatByLevelBreakpoints + calc expression. Similar pattern to missile calcs but for passive skills.
- [D2Common.dll@1.13d] Ordinal 10116: GetEquipSlotAnimComponent — equip slot→anim component resolver. Player hand/weapon slots (7,8,0xF,0x10) use g_awData_6fde96b6 lookup. Dual-wield check for weapon slots.
- [D2Common.dll@1.13d] Ordinal 11050: InitializeAnimFromGraphicsMode — writes +0x30 (base), +0x34 (frame count 8.8), +0x38 (accum), +0x3C (rate 0x100), +0x48 (scaled field), sets 0x4000 at +0xC4.
- [D2Common.dll@1.13d] Ordinal 10319: GetAnimSequenceRecord — table accessor, base DWORD_6fdf5830, count DWORD_6fdf5834, stride 0x1C0 (448 bytes). Bounds-checked with abort.
- [D2Common.dll@1.13d] Ordinal 10942: GetActiveSkillFieldC — reads *(pSkillData+0xA8)+0x0C. Skill node field getter.
- [D2Common.dll@1.13d] Ordinal 10909: GetActiveSkillField8 — reads *(pSkillData+0xA8)+0x08. Paired with GetActiveSkillFieldC (10942).
- [D2Common.dll@1.13d] Ordinal 10144: ApplyCollisionMaskArea — OR flags into collision map area. 1x1=direct cell, larger=SetMaskFlagsRecursive. Used by SetUnitCollisionArea (10222).
- [D2Common.dll@1.13d] Ordinal 11104: ClearCollisionMaskArea — clear flags from collision map area. 1x1=ClearMaskFlagAtPoint, larger=ClearMaskFlagsRecursive. Used by ClearUnitCollisionArea (10223).
- [D2Common.dll@1.13d] Ordinal 10622: CalcDistanceToPoint — octagonal distance approx from unit to (x,y). Type dispatch for 16/32-bit coords. Formula: (min+max*2)/2.
- [D2Common.dll@1.13d] Ordinal 11040: GetInventoryFieldC — inventory struct +0x0C getter. Magic header 0x1020304 validated. 4 xrefs.
- [D2Common.dll@1.13d] Ordinal 10305: SetSkillDataHighField38 — packs value into bits 8-31 of +0x38, preserves low byte. Line 0xACE (Skills.cpp).
- [D2Common.dll@1.13d] Ordinal 10879: GetItemDataField64 — reads item_data+0x64. Leaf getter.
- [D2Common.dll@1.13d] Ordinal 11114: FindEquippedType33Item — scans equipment for type 0x33 item (charm/jewel?). Worker with SSA.
- [D2Common.dll@1.13d] Ordinal 11058: GetItemDataPosition — reads item_data position fields. Leaf getter.
- [D2Common.dll@1.13d] Ordinal 10819: AreItemsInSameCodeGroup — compares item code groups via item record lookup. 5 SSA vars (40%/70%).
- [D2Common.dll@1.13d] Ordinal 11108: GetItemTypeStorageSize — storage page/size from ItemTypes table.
- [D2Common.dll@1.13d] Ordinal 10593: SetActiveSkillFieldC — sets skill header +0x0C to matching node (linked list search by id+param). Paired with GetActiveSkillFieldC (10942).
- [D2Common.dll@1.13d] Ordinal 10161: SetActiveSkillField8 — sets skill header +0x08 to matching node. Paired with GetActiveSkillField8 (10909).
- [D2Common.dll@1.13d] Ordinal 10437: GetEffectiveSkillRange — base range (+0x174) + node level bonus (+0x28). Extends GetSkillRangeValue (11021).
- [D2Common.dll@1.13d] Ordinal 10966: GetSkillNodeRecord — __fastcall null-safe first dword getter from skill node. 5 xrefs.
- [D2Common.dll@1.13d] Ordinal 10300: CalcCombatStatBonus — __thiscall, ItemStatCost entries + skill table formula. stat2*5+stat1-35+skills[classId]+0x3C.
- [D2Common.dll@1.13d] Ordinal 10900: GetUnitWeaponStyle — type dispatch: Player→weapon slot scan, Monster→table entry+0xE. Returns 0-2.
- [D2Common.dll@1.13d] Ordinal 10156: TestBitInTable — bit matrix tester (row*16+col indexing). GetBitValue wrapper.
- [D2Common.dll@1.13d] Ordinal 11070: DestroyInventory — __thiscall inventory destructor. Removes items, frees pages, clears owner, frees linked lists.
- [D2Common.dll@1.13d] Ordinal 10096: ExtractAnimFrameData — 6-byte stride records, 8.8 fixed-point index. 4 output bytes with range scan.
- [D2Common.dll@1.13d] Ordinal 10808: GetItemRecordField108 — short at item record +0x108. Speed-related, default 100. Stride 0x1a8.
- [D2Common.dll@1.13d] Ordinal 10807: GetItemRecordField106 — short at item record +0x106. Speed-related, default 100. Paired with 10808.
- [D2Common.dll@1.13d] Ordinal 10706: SetItemDataField34 — writes item_data+0x34. Strict type 4 assert.
- [D2Common.dll@1.13d] Ordinal 10941: GetEquippedSetBonusMask — inventory scan for Quality==5 (Set) items matching set ID, flag 0x4000000 check, returns bitmask.
- [D2Common.dll@1.13d] Ordinal 10826: GetAnimDataFrameInfo — FindAnimDataByName wrapper, outputs frame count/speed/first active frame. Falls back to g_dwLastError.
- [D2Common.dll@1.13d] Ordinal 10966: UpdatePathCollisionFlags — clear old+apply new collision on path data. Mode 3=tile-based, else radius-based. Fields: +0x1C room, +0x02/+0x06 pos, +0x4C flags.
- [D2Common.dll@1.13d] Ordinal 11098: GetItemRecordFields4A4B — reads bytes at item record +0x4A/+0x4B via output pointers. Stride 0x1A8. Lenient (0 on OOB).
- [D2Common.dll@1.13d] Ordinal 11008: FreeResourceBuffer — conditional dealloc, -4 header adjust when DWORD_6fdf33f4 set. Delegates to DeallocateResourceBuffer.
- [D2Common.dll@1.13d] Ordinal 11019: GetAnimFrameDataByMode — type/mode dispatch. Modes 0x0E/0x12 → ExtractAnimFrameData. Default → byte at unit[0x14]+0x10+index. Bounds: index<0x90.
- [D2Common.dll@1.13d] Ordinal 10105: UpdateDualWieldStatOwnership — dual-wield weapon stat list transfer. 3 cases: no best, best==equipped, best!=equipped. Validates modifier chain.
- [D2Common.dll@1.13d] Ordinal 10150: GetMissileFieldByIndex — master missile property getter, 43-case switch. Direct reads +0x38-0x7C, calcs via CalcMissileParam/CalcLevelScaledValue. Missiles: +0xB64, stride 0x1A4.
- [D2Common.dll@1.13d] Ordinal 10429: FindStatListEntryByGuid — stat list entry lookup via FindRoomUnitByGuid. Unit+0x5C stat list, flag +0x10 < 0 = active.
- [D2Common.dll@1.13d] Ordinal 10053: ClearAllStatsFromList — binary search + removal loop. Negates values via ApplyStatModifierToChain. NPC list insertion on flag 0x2000.
- [D2Common.dll@1.13d] Ordinal 10650: ToggleStatListActiveFlag — toggles 0x2000 flag at entry+0x10. RemoveItemAndUnapplyStats→InsertAndApplyStatList cycle.
- [D2Common.dll@1.13d] Ordinal 10206: DispatchPropertyEffects — 7-entry function pointer dispatch from property table (+0xA4, stride 0x2E). Handler index at +0x18+i. Has phantom stack params.
- [D2Common.dll@1.13d] Ordinal 10050: GetMonsterTypeRecord — bounds-checked table access, stride 0x20. MonTypes table (+0xB50).
- [D2Common.dll@1.13d] Ordinal 10122: FindOrAllocateDrlgLevel — DRLG level linked list search + allocate. pDrlg+0x24 list head, stride via AllocateDrlgLevel.
- [D2Common.dll@1.13d] Ordinal 11162: GetSkillRecordField94 — short at skill record +0x94. Skills table (+0xB98, stride 0x23C).
- [D2Common.dll@1.13d] Ordinal 10017: CalcMaxItemTypeBonus — item type bonus calculator with stat layer lookup. Complex worker, many SSA vars.
- [D2Common.dll@1.13d] Ordinal 10668: FindAutoMapCellEntry — automap cell table linear search, stride 0x118.
- [D2Common.dll@1.13d] Ordinal 10731: DumpProfilingStats — iterates profiling array at 0x6fdf3460 (stride 0x78), logs name/time/count.
- [D2Common.dll@1.13d] Ordinal 10043: GetRoomDimensions — width at pRoom[0x11], height at pRoom[0x12] or DRLG indirect for type 2.
- [D2Common.dll@1.13d] Ordinal 10958: GetPlayerEquippedWeapon — FindWeaponInEquipSlots on inventory, player-only.
- [D2Common.dll@1.13d] Ordinal 11111: FreeRoomResourceList — walks linked list at pRoom+0x18, DeallocateResourceBuffer each. Dungeon.cpp.
- [D2Common.dll@1.13d] Ordinal 10130: AddRoomResourceEntry — alloc slot, push onto pRoom+0x18 list, set dirty flag +0x58. Dungeon.cpp:900.
- [D2Common.dll@1.13d] Ordinal 10675: DecrementRoomRefCount — refcount at pRoom+0x28, asserts >=1. Dungeon.cpp:636.
- [D2Common.dll@1.13d] Ordinal 10147: IsCoordinateInRoomBounds — X: +0x5C/+0x64, Y: +0x60/+0x68. Dungeon.cpp:360.
- [D2Common.dll@1.13d] Ordinal 10803: CheckSpecialBodyLocation — null-safe wrapper around IsSpecialBodyLocation.
- [D2Common.dll@1.13d] Ordinal 10561: GetCollisionFlagAtPosition — room grid at room[8]->grid[8], stride 2 bytes. Default 0x27.
- [D2Common.dll@1.13d] Ordinal 10502: TestClassFlagBit — bit test on class flag table. Player: +0x104, others: +0x100. Max index: +0xC4.
- [D2Common.dll@1.13d] Ordinal 10551: GetUnitClassFlagBit3 — bit 3 of unit+0xC8 flags field.
- [D2Common.dll@1.13d] Ordinal 11059: ValidateObjectBitMasks — wrapper, calls CheckObjectBitMaskOverlap on sgptDataTables+0x150.
- [D2Common.dll@1.13d] Ordinal 10759: FindNearbyUnitByProximity — room+0x74 unit list, 9-case proximity matrix (size*level), callback filter. 153 lines, 0% raw.
- [D2Common.dll@1.13d] Ordinal 10478: IsItemTypeInInventory — inventory magic 0x1020304, linked list at [0xB], match entry[0]==type.
- [D2Common.dll@1.13d] Ordinal 10332: HasMatchingItemInCodeGroup — excludes scrolls (isc/tsc), searches 4 inventory page slots via AreItemsInSameCodeGroup.
- [D2Common.dll@1.13d] Ordinal 10532: FindBeltSlotForItem — belt slot finder. 1x1 items only, type property 19, code group matching + fallback.
- [D2Common.dll@1.13d] Ordinal 10584: UpdateWeaponCursorState — sets/clears inventory[7] (cursor GUID) based on weapon equip/type checks.
- [D2Common.dll@1.13d] Ordinal 10914: CanItemFitInEquipSlot — slot [0-12], delegates to FindItemInventorySlot.
- [D2Common.dll@1.13d] Ordinal 11052: GetItemRecordField13C — byte at item record +0x13C. Assert-validated.
- [D2Common.dll@1.13d] Ordinal 10070: IsItemRecordFlag139Set — bool at item record +0x139. Stride 0x1A8, g_pItemDataTable.
- [D2Common.dll@1.13d] Ordinal 10682: FreeAllDataTables — 253-line master cleanup, frees ALL game data tables via 17+ Free* calls. DWORD_6fdf33f4 debug header flag. Source: DataTbls.cpp.
- [D2Common.dll@1.13d] Ordinal 10081: LoadAllDataTables — master data table loader, 50+ Load*/Parse* calls. Counterpart of FreeAllDataTables. Source: DataTbls.cpp. 47% raw (4 phantom, SSA).
- [D2Common.dll@1.13d] Ordinal 10925: DestroyIgnoreListManager — vtable +0x2C destructor, clears DWORD_6fdf6564. Source: Ignorelist.cpp. Struct size 0x188.
- [D2Common.dll@1.13d] Ordinal 10735: CreateIgnoreListManager — SEH + AllocateMemoryFromArena(0x188) + InitializeIgnoreListManager. Source: Ignorelist.cpp.
- [D2Common.dll@1.13d] Ordinal 10828: GetObjectRecordField168 — Object type 2, reads *(*(pObjectData) + 0x168). Object record sub-field.
- [D2Common.dll@1.13d] Ordinal 10910: GetPlayerDataField2C — Player type 0, reads pPlayerData+0x2C. Getter.
- [D2Common.dll@1.13d] Ordinal 10271: SetPlayerDataField2C — Player type 0, writes pPlayerData+0x2C. Setter.
- [D2Common.dll@1.13d] Ordinal 11103: GetPlayerData — Player type 0, returns pPlayerData pointer (unit+0x14).
- [D2Common.dll@1.13d] Ordinal 10308: AssertValidPlayerUnit — validates non-NULL Player with valid pPlayerData.
- [D2Common.dll@1.13d] Ordinal 10434: GetObjectAnimModeRecordByte — Object record +0x120+animMode byte. Default 1 for non-Objects.
- [D2Common.dll@1.13d] Ordinal 10885: SetAnimEventFromFrameData — reads frame data +0x10+index, sets +0x4E event (1-4). Index < 0x90.
- [D2Common.dll@1.13d] Ordinal 10397: GetUnitAnimFramePair — type-dispatched: Object record +0xD8+mode*4, others +0x48>>8. Both return +0x44>>8.
- [D2Common.dll@1.13d] Ordinal 10537: IsAnimationComplete — reverse mode: +0x48<1, forward: +0x48 <= +0x4C + +0x44.
- [D2Common.dll@1.13d] Ordinal 10754: AdvanceAnimFrameWithWrap — 8.8 fixed-point frame advance. Wraps from end to start.
- [D2Common.dll@1.13d] Ordinal 10630: FreeUnitSubAllocation — frees +0x2C sub-resource from pool +0x08. Paired with 10598.
- [D2Common.dll@1.13d] Ordinal 10598: AllocateUnitSubResource — alloc 32 bytes at +0x2C, zeros 8 DWORDs. Source: Units.cpp:5406.
- [D2Common.dll@1.13d] Ordinal 10177: GetPlayerDataField90 — Player data +0x90 getter. Paired with 10342.
- [D2Common.dll@1.13d] Ordinal 10342: SetPlayerItemField90 — sets pPlayerData+0x90 from item[3] or clears to 0.
- [D2Common.dll@1.13d] Ordinal 10991: SetPlayerDataFieldPair8088 — writes pPlayerData+0x80 and +0x88.
- [D2Common.dll@1.13d] Ordinal 10173: GetPlayerDataFieldPair747C — reads pPlayerData+0x74/+0x7C via output pointers.
- [D2Common.dll@1.13d] Ordinal 10611: GetPlayerDataFieldPair7078 — reads pPlayerData+0x70/+0x78 via output pointers.
- [D2Common.dll@1.13d] Ordinal 10813: SetUnitTargetInfo — writes target position to unit path data, type-dispatched (+0x18/+0x1C for Obj/Item, +0x34 flags for Player/Monster).
- [D2Common.dll@1.13d] Ordinal 10061: SetUnitRunningFlag — sets/clears running flag: Player/Monster bit 2 at pathData+0x34, Object/Item byte at pathData+0x1D.
- [D2Common.dll@1.13d] Ordinal 10270: GetUnitRunningFlag — reads running flag: Player/Monster bit 2 at pathData+0x34, Object/Item byte at pathData+0x1D.
- [D2Common.dll@1.13d] Ordinal 10305: GetUnitIfItem — branchless return: unit pointer if type==4 (Item), else NULL. Bitmask trick.
- [D2Common.dll@1.13d] Ordinal 10600: GetItemDataByte69 — byte at item_data+0x69. Sentinel check (pTypeData != -0x5C).
- [D2Common.dll@1.13d] Ordinal 10705: GetItemDataField34 — short at item_data+0x34 (getter). Pairs with SetItemDataField34 (10706).
- [D2Common.dll@1.13d] Ordinal 10704: SetItemDataField32 — writes ushort at item_data+0x32. Pairs with 10703.
- [D2Common.dll@1.13d] Ordinal 10703: GetItemDataField32 — reads short at item_data+0x32. Pairs with 10704.
- [D2Common.dll@1.13d] Ordinal 10948: FindMatchingCubeRecipe — cube recipe table scan. Table: DWORD_6fdf4cf4, stride 0x120, count DWORD_6fdf4cf0. Fields: +0x80 enabled, +0x86 inclusion types (6), +0x92 exclusion types (3), +0x98 input classIds (6).
- [D2Common.dll@1.13d] Ordinal 11072: CheckItemEquipRequirements — str (stat 0, record +0x10A), dex (stat 2, +0x10C), level (stat 0xC). Ethereal -10 penalty. Socket deduction. 9% raw (13 SSA).
- [D2Common.dll@1.13d] Ordinal 10241: SetItemInventoryDisplayTier — clamps tier to [1, min(cells, gfxTier)], sets stat 0xC2 (194), flags 0x800.
- [D2Common.dll@1.13d] Ordinal 10387: GetSubStructDimension — reads sub[+4] (return) and computes sub[+8]/sub[+0x28] (output). Assert non-null.
- [D2Common.dll@1.13d] Ordinal 10355: GetUnitWeaponAnimToken — dual-wield + mode dispatch → ResolveWeaponAnimToken. Default "hth " (0x20687468).
- [D2Common.dll@1.13d] Ordinal 10064: AccumulateProfilingTime — __thiscall, QPC delta → profiling array (DWORD_6fdf3460, stride 0x78). Entry: [0]=elapsed_lo, [1]=elapsed_hi, [2]=count.
- [D2Common.dll@1.13d] Ordinal 10711: ReadExcelDataFile — reads DATA\GLOBAL\EXCEL\<name>, skips 4-byte header, fills buffer.
- [D2Common.dll@1.13d] Ordinal 10422: GetGlobalTableEntry — bounds-checked DWORD lookup. Base DWORD_6fdf58d4, count DWORD_6fdf58dc.
- [D2Common.dll@1.13d] Ordinal 10789: GetObjectRecordByte13A — Object type 2 record +0x13A. Assert non-null. Collision-related.
- [D2Common.dll@1.13d] Ordinal 10372: GetItemRecordByte130 — item record +0x130. Strict validation. Stride 0x1A8, g_pItemDataTable.
- [D2Common.dll@1.13d] Ordinal 11023: IsUnitInAttackRange — melee range check: ComputeUnitDistance + weapon style + collision (0x804). Monster codes 0x102/0x105 get distance bonus.
- [D2Common.dll@1.13d] Ordinal 10603: FilterUnitByProximityAndFlags — type-dispatched (5 types) unit filter callback for area search. Position from path data, radius at params[5], flags per type. 164 lines, 34% raw/93% eff.
- [D2Common.dll@1.13d] Ordinal 10691: GetNestedStructFieldValue — triple indirection: pStruct+0x10→+0x58→+0x1D0. Null-safe, returns 0. 97%/100%.
- [D2Common.dll@1.13d] Ordinal 11045: RemoveRoomFromDrlgList — DRLG room linked list removal. Unlinks from pDrlgLevel+0x10, clears adjacency, frees tile data. 68 lines.
- [D2Common.dll@1.13d] Ordinal 10409: GetCollisionMaskFlagsMultiMode — 6-mode collision flag collector. Mode 0=point, 1/3/5=cross-OR, 2/4=3x3 recursive. Returns 0xFFFF invalid.
- [D2Common.dll@1.13d] Ordinal 10234: GetItemIfStatListOwner — returns Item unit if stat list ID matches (branchless AND trick). 92%/100%.
- [D2Common.dll@1.13d] Ordinal 10375: IsItemStatListOwner — boolean: item stat list at pTypeData+0x5C matches nOwnerId. Paired with 10234.
- [D2Common.dll@1.13d] Ordinal 11016: GetAlternateEquippedWeapon — finds the OTHER weapon in dual equip slots (+0x14/+0x10) by GUID at inventory[7]. Type 0x2D filter.
- [D2Common.dll@1.13d] Ordinal 10690: IsMonsterRecordRangedType — checks monster record byte +0xD bits 3/4 via gdwBitMasks_exref. Type 1 only, record stride 0x1A8 at sgptDataTables+0xA78.
- [D2Common.dll@1.13d] Ordinal 11033: GetItemRecordFieldE8 — DWORD at item record +0xE8. Aborts on null/OOB. Stride 0x1A8, g_pItemDataTable.
- [D2Common.dll@1.13d] Ordinal 10744: GetItemRecordFieldC0 — DWORD at item record +0xC0 via GetItemDataRecord. 92%/100%.
- [D2Common.dll@1.13d] Ordinal 10725: GetItemDataByte48 — byte at item_data+0x48. Default 1. 97%/100%.
- [D2Common.dll@1.13d] Ordinal 10720: SetItemDataByte45 — writes byte to item_data+0x45. Paired setter. 97%/100%.
- [D2Common.dll@1.13d] Ordinal 10697: GetItemDataShort36 — ushort at item_data+0x36. CONCAT22 artifact. 97%/100%.
- [D2Common.dll@1.13d] Ordinal 11095: IsItemStorable — checks item record +0x11E → ItemTypes +0x21 store page < 7. TRUE=can be sold.
- [D2Common.dll@1.13d] Ordinal 10659: CopyPresetDataArray — __fastcall(pMemPool, pSource), DRLG/Preset.cpp:0x57A. Allocs and copies preset data (count + triplet DWORDs). Source: Preset.cpp.
- [D2Common.dll@1.13d] Ordinal 10322: CopyStatListEntries — copies stat entries (8-byte pairs) from unit+0x5C stat list (+0x48 array, +0x4C count) into output buffer. Returns count copied.
- [D2Common.dll@1.13d] Ordinal 10027 (D2Common): FindRoomUnitByTypeFlagsValidated — validated wrapper for FindRoomUnitByTypeFlags. Checks stat list active flag first. NOTE: 10027 in Fog.dll = HandleDeadlockShutdown.
- [D2Common.dll@1.13d] Ordinal 10574: GetDataTablePropertyStat — reads stat from sgptDataTables+0xBCC (property table) at fixed offset +0x8DC. Count check at +0xBD4 > 7.
- [D2Common.dll@1.13d] Ordinal 10333: UnapplyStatModifiers — reverse stat bonuses between units. Ownership transfer if mismatched, sets flag 0x40000000, negates matching entries via ApplyStatModifierToChain. Uses gdwBitMasks_exref[8] filter.
- [D2Common.dll@1.13d] Ordinal 10288: HasReachedPathTarget — path target check. unit[0x0B] path data: +0x58=target unit, +0x93=range byte, +0x02/+0x06=cur pos, +0x10/+0x12=target pos.
- [D2Common.dll@1.13d] Ordinal 10370: CopyLevelTileRecord — 2D table copy, base DWORD_6fdf4ba0, stride 0x108, 7 rows/column. 0x42 DWORDs per record.
- [D2Common.dll@1.13d] Ordinal 10249/11112: CalcSkillScaledValue158/150 — paired skill calculators via CalcLevelScaledValue. Skills table +0x150/+0x154 and +0x158/+0x15C.
- [D2Common.dll@1.13d] Ordinal 10432: GetMonsterSkillLevel — __fastcall, monster record +0x170 (8-entry skill ID array), +0x188 (skill levels). Class 199=skip.
- [D2Common.dll@1.13d] Ordinal 11150/10612: FindLevelDatRecordById/ByRange — table base DWORD_6fdf59f8, count DWORD_6fdf59fc, stride 0x118. Id match at +8, range at +0x114/+0x116. Expansion flag: value 100 at +0.
- [D2Common.dll@1.13d] Ordinal 10597: RemoveUnitFromClassDataList — classData+0x1C linked list, next at unit[0x38]. Paired with AddUnitToClassQueue (10229).
- [D2Common.dll@1.13d] Ordinal 10203: SortRoomUnitListByPosition — bubble sort on room+0x74 list via unit[0x3A]. Sort key: pathData+0x08 (type 2/4/5) or +0x0C (type 0/1/3).
- [D2Common.dll@1.13d] Ordinal 10896: GetUnitTypeName — __thiscall, type switch → name string (Player/Monster/Object/Missile/Item). Default "Invalid Unit Type".
- [D2Common.dll@1.13d] Ordinal 10097: InitializeGlobalIgnoreList — initializes global ignore list structures. 8 SSA undefined vars (55%/60%). Source: Ignorelist.cpp.
- [D2Common.dll@1.13d] Ordinal 11092: SetStructField7C — writes DWORD to struct field at +0x7C. Leaf setter. 82%/90%.
- [D2Common.dll@1.13d] Ordinal 11025: GetDefaultArenaSize — returns constant arena size value (stub). 85%.
- [D2Common.dll@1.13d] Ordinal 10755: TestObjectDataByte5Flag — tests bit flag in pObjectData+5 byte. 95%. Paired with 10033.
- [D2Common.dll@1.13d] Ordinal 10033 (D2Common): SetObjectDataByte5 — writes byte to pObjectData+5. 85%/90%. NOTE: 10033 in Fog.dll = DumpStackAndShutdown.
- [D2Common.dll@1.13d] Ordinal 11009: IsObjectRecordFlag167Set — bit 0 of object record byte +0x167. Object type 2 only. 92%/100%.
- [D2Common.dll@1.13d] Ordinal 10634: AdvanceAnimSubAccumulator — increments +0x44 by short(+0x4C), wraps at +0x48. Anim sub-accumulator.
- [D2Common.dll@1.13d] Ordinal 10365/10369: SetPathFieldByUnitType/GetPathFieldByUnitType — type-dispatched field pair. Player/Monster with +0x30 sub-struct: use +0x40. Others: use +0x10. Setter aborts on NULL; getter returns 0.
- [D2Common.dll@1.13d] Ordinal 11133: ConsumeAndClearField64 — read-and-clear DWORD at +0x64 (decimal 100). Returns old value.
- [D2Common.dll@1.13d] Ordinal 10424: ConsumePlayerFieldPair8088 — reads pPlayerData+0x80/+0x88 into outputs, resets +0x70/+0x78/+0x90/+0x94. Paired with SetPlayerDataFieldPair8088 (10991).
- [D2Common.dll@1.13d] Ordinal 10165: GetSkillDescFieldPair4041 — skill desc table (sgptDataTables+0xBC4, stride 0xC4). Outputs bytes +0x40/+0x41.
- [D2Common.dll@1.13d] Ordinal 10124/10389: GetPathTargetField60/GetPathTargetField5C — path data +0x60/+0x5C getters. Require target at +0x58. Player/Monster/Missile only.
- [D2Common.dll@1.13d] Ordinal 10727: InitializeSubStructBounds — sets up bounds sub-struct at +0x2C. Fields: identifier, center, radius, scaled bounds ((c-r)*16, (c+r)*8).
- [D2Common.dll@1.13d] Ordinal 10768: CalcAbsUnitXDifference — abs X diff between two units. Types 2/4/5: pathData+0x0C (32-bit), types 0/1/3: pathData+0x02 (16-bit ushort).
- [D2Common.dll@1.13d] Ordinal 10057/10641: GetUnitPathCoordY/X — tile-precision position getters. Y: 0/1/3→+0x0C, 2/4/5→+0x08. X: 0/1/3→+0x08, 2/4/5→+0x04.
- [D2Common.dll@1.13d] Ordinal 10607/10321: GetUnitFixedPointY/X — 16.16 fixed-point position. Types 0/1/3: +0x04/+0x00 direct. Types 2/4/5: +0x10/+0x0C << 16.
- [D2Common.dll@1.13d] Ordinal 10969: UpdatePlayerSkillAnimData8 — writes pPlayerData+0x74 (anim ID from skill node short[0]) and +0x7C (node[0xD]). Calls GetActiveSkillField8. Player only.
- [D2Common.dll@1.13d] Ordinal 10248: UpdatePlayerSkillAnimDataC — writes pPlayerData+0x70 (anim ID) and +0x78 (node[0xD]). Calls GetActiveSkillFieldC. Paired with 10969.
- [D2Common.dll@1.13d] Ordinal 10247: GetUnitEquipSlotCount — Player=1, Monster=(table byte+0xC)-1, others=0. Type dispatch via GetLinkedDataTableEntry.
- [D2Common.dll@1.13d] Ordinal 10135: FreePlayerQuestWaypointData — frees 4 difficulty slots of quest+waypoint records from pPlayerExtData+0x14. Marker 0x102=freed, 0x0=empty, 0x101=active.
- [D2Common.dll@1.13d] Ordinal 10404: InitializePlayerQuestWaypointData — allocates 0x16C byte sub-struct + 4 difficulty slots of quest records (QuestRecord.cpp) + waypoint states (Waypoint.cpp). Expansion bitmask from g_dwGameResult.
- [D2Common.dll@1.13d] Ordinal 10129: SetUnitPathTarget — sets pathData+0x58 (target unit ptr), +0x5C (target[0]), +0x60 (target[3]). Types 0/1/3 only.
- [D2Common.dll@1.13d] Ordinal 11094: IsMonsterInSpecialDeathMode — Monster type 1, animMode 0xC (death). Checks linked table flags + ValidateObjectBitMasks.
- [D2Common.dll@1.13d] Ordinal 10451: IsMonsterRecordExpansionOnly — __fastcall, MonsterTypes stride 0x1A8, expansion bit at record+0xE. Checks expansion flag via GetLinkedTableBitFlag.
- [D2Common.dll@1.13d] Ordinal 11065: CalcPathBetweenUnits — path between two units. Temporarily clears collision areas, calls CalculatePathWithOffset. 81 lines, 20% raw (12 SSA undefined).
- [D2Common.dll@1.13d] Ordinal 10841: CalcPathToCoords — path from unit to coordinates. Same position pattern, CalculatePathWithOffset. 43 lines, 30% raw (10 SSA undefined).
- [D2Common.dll@1.13d] Ordinal 10345: CalcUnitBlockChance — Player: shield+stat21+skill desc+0x49, dex/level scaling. Monster: record bit 8 or special condition. Capped 75.
- [D2Common.dll@1.13d] Ordinal 10683: CalcLifePercentage — (stat7>>8)*100/(stat8>>8). Stat 7=hitpoints (ItemStatCost+0x798), stat 8=maxhp (+0x8DC). 8.8 fixed-point.
- [D2Common.dll@1.13d] Ordinal 10998: GetBestWeaponBodyType — __fastcall wrapper: FindBestEquippedWeapon(1) → GetItemEquipBodyType. Returns ushort.
- [D2Common.dll@1.13d] Ordinal 10088: GetUnitWeaponRange — __fastcall. Player: best weapon record +0x13C (default 1). Monster: linked table +0x14. Others: 0.
- [D2Common.dll@1.13d] Ordinal 10048: AdvanceAnimFrameWithEvents — forward: 8.8 frame accum + event scan (1-4) at frameData+0x10+index, wrap with equip anim offset. Reverse: stream rate + flag 0x4000. 72 lines.
- [D2Common.dll@1.13d] Ordinal 11148: ToggleGlobalLogFile — __fastcall, sets DWORD_6fdf655c, opens/closes "d2log.txt". 94%/97%.
- [D2Common.dll@1.13d] Ordinal 10926: CopySkillListToBuffer — copies up to 8 skill list linked entries into 34-byte flat buffer. Entry: short[0]=value, byte[4]=type, ptr[8]=next. 62%/70%.
- [D2Common.dll@1.13d] Ordinal 10103: GetSkillListEntryByTypeIndex1 — linked list search for type==1, returns Nth match short value. 62%/65%.
- [D2Common.dll@1.13d] Ordinal 10012: GetSkillListEntryByTypeIndex0 — linked list search for type==0, returns Nth match short value. 62%/65%.
- [D2Common.dll@1.13d] Ordinal 10996: GetSkillListEntryByTypeIndex2 — linked list search for type==2, returns Nth match short value, default 0xE8C. 62%/65%.
- [D2Common.dll@1.13d] Ordinal 11142: FreeLinkedResourceList — walks linked list at struct[2] (next at +8), frees each node + container via DeallocateResourceBuffer. 85%/90%.
- [D2Common.dll@1.13d] Ordinal 10447: GetDataRecordStrideB8 — bounds-checked table accessor, stride 0xB8 (184). Base DWORD_6fdf5828, count g_dwLastError. Aborts OOB. 85%.
- [D2Common.dll@1.13d] Ordinal 10707: GetDataRecordStride34 — lenient table accessor, stride 0x34 (52). Base DWORD_6fdf5838, count DWORD_6fdf583c. Returns 0 on OOB. 100%.
- [D2Common.dll@1.13d] Ordinal 10101: InitializeUnitFindContext — allocs 60-byte results buffer, fills 11 context fields. Source: UnitFinds.cpp:228. Capacity 15. 0%/100% (all unfixable).
- [D2Common.dll@1.13d] Ordinal 10725: CollectFilteredRoomUnits — room+0x74 unit list walk, callback filter, output array. Max 15. IsBadCodePtr validation. 43%/64%.
- [D2Common.dll@1.13d] Ordinal 10772 (0x6fd72bd0): AppendToRingBuffer4 — 4-entry circular buffer at struct+0x38, index byte at +0x14, wraps mod 4. NOT AdjustValueByPlayerClass (duplicate ordinal). 91%/97%.
- [D2Common.dll@1.13d] Ordinal 10045: SetStructField4C — strict setter at +0x4C. 76%/82%.
- [D2Common.dll@1.13d] Ordinal 10845: GetStructField8 — strict getter at +0x08. 82%/85%.
- [D2Common.dll@1.13d] Ordinal 10310/10742: UpdateForwardListFlags/UpdateReverseListFlags — paired wrappers, delegate to UpdateLinkedListFlagsForward/Reverse on list at +0x10. 82%/85% each.
- [D2Common.dll@1.13d] Ordinal 11039: GetStructField18 — strict getter at +0x18. 82%/85%.
- [D2Common.dll@1.13d] Ordinal 10806: GetStructField10 — strict getter at +0x10. 82%/85%.
- [D2Common.dll@1.13d] Ordinal 10220: IncrementStructField28 — lenient counter increment at +0x28. Returns 0 on null. 97%/100%.
- [D2Common.dll@1.13d] Ordinal 11056: FindRoomContainingCoords — DRLG room linked list search. Bounds: +0x4C/+0x50 origin, +0x54/+0x58 size. Next at +0x7C. 84%/87%.
- [D2Common.dll@1.13d] Ordinal 10414: GetRoomBoundsRect — computes xMin/yMin/xMax/yMax from origin+size. Fields: +0x4C/+0x50/+0x54/+0x58. 82%/85%.
- [D2Common.dll@1.13d] Ordinal 10014: GetSubStructPairedFields — strict getter, reads 2 DWORDs from sub-struct at +0x08. Aborts on null. 55%/75%.
- [D2Common.dll@1.13d] Ordinal 10513: GetSubStructPairedFields2 — lenient getter, reads +0x08 and +0x0C from sub-struct at +0x08. Returns 0 on null. 60%/80%.
- [D2Common.dll@1.13d] Ordinal 10792: BroadcastValueToLinkedList — sets +0x08 on all nodes in list at *(struct+0x10)+0x4C, next at +0x04. 65%/90%.
- [D2Common.dll@1.13d] Ordinal 10454: PropagateRoomConnectionFromPair — finds room in DRLG list (+0x10, next +0x7C), delegates to PropagateRoomConnectionValue. 61%/95%.
- [D2Common.dll@1.13d] Ordinal 10907: SetRoomSubStructFlag22 — toggles bit 0x400000 at sub-struct(+0x10)+0x28. 74%/97%.
- [D2Common.dll@1.13d] Ordinal 10180: GetRoomExtendedBound — returns sub-struct(+0x10)+0x58 + 0x1E0 (480). 80%/95%.
- [D2Common.dll@1.13d] Ordinal 10268: GetRoomTypeBasedFlag — type dispatch on +0x48: type 1→1, type 2→bit 19 of flags(+0x28). 75%/95%.
- [D2Common.dll@1.13d] Ordinal 10500: AreAllArrayEntryFlagsSet — validates all array entries have bit 0 at +0x34. Count check vs [4]+0x2C. 40%/80%.
- [D2Common.dll@1.13d] Ordinal 10098: IsRoomFieldAboveThreshold — byte at sub-struct(+0x10)+0x44 >= 3. 85%/100%.
- [D2Common.dll@1.13d] Ordinal 10626: HasRoomConnectionFlags — bits 16-17 (0x30000) of flags at sub-struct(+0x10)+0x28. 80%/95%.
- [D2Common.dll@1.13d] Ordinal 10767: FindLinkedListNodeByKey — list at sub(+0x10)+0x4C, matches *(node+0x10)->byte[0] vs key byte. 40%/80%.
- [D2Common.dll@1.13d] Ordinal 10188: UpdateAllAnimationFrames — calls UpdateAnimationFrameIndices in loop, count from sub(+0x10)+0x2C. 70%/95%.
- [D2Common.dll@1.13d] Ordinal 11109: ProcessLightingAtPosition — wrapper, delegates to ProcessRoomLightingByPosition with sub(+0x10). 65%/80%.
- [D2Common.dll@1.13d] Ordinal 11163: GetRoomType1SubFlag7 — type 1 only, bit 7 of *(sub(+0x10)+0x20)+0x54. 80%/95%.
- [D2Common.dll@1.13d] Ordinal 10701: RemoveFromRoomArray — search+swap-last in array at +0x48, count at +0x78, then SortRoomArray. 52%/95%.
- [D2Common.dll@1.13d] Ordinal 10898: CheckRoomDrawVisibility — validates +0x50==0, delegates to CheckRoomVisibilityForDrawing. 65%/95%.
- [D2Common.dll@1.13d] Ordinal 10400: GetLevelColorBytes — wrapper for GetRoomLevelColorBytes, 4 output byte pointers. 45%/70%.
- [D2Common.dll@1.13d] Ordinal 10463: LookupLogicalRoomAtTile — wrapper for LookupLogicalRoomByTile(tileX, tileY). 85%/90%.
- [D2Common.dll@1.13d] Ordinal 10793: GetRoomConnectionAtCoords — FindRoomByCoordinates + GetLogicalRoomConnectionId, coords/5 for tile. 80%/90%.
- [D2Common.dll@1.13d] Ordinal 10555: CountVisibleRooms — wrapper for CountVisibleRoomsInLevel(struct+0x48, param). 80%/95%.
- [D2Common.dll@1.13d] Ordinal 10024: AllocateDrlgRoom — 96-byte room alloc+init, Dungeon.cpp:25. Calls Ordinal_10871, AllocateEnvironmentContext, InitializeDrlgRoomData. 0%/70%.
- [D2Common.dll@1.13d] Ordinal 11100: GetConnectedRoomLevel — lenient wrapper for GetConnectedRoomLevelId(param, sub+0x10, param). 75%/95%.
- [D2Common.dll@1.13d] Ordinal 10501: FindRoomAndLoadTiles — FindRoomForPathCoordinates + LoadRoomTilesAndGetCacheHandle. 50%/80%.
- [D2Common.dll@1.13d] Ordinal 10208/10890: DecrementRoomRefAtCoords/IncrementRoomRefAtCoords — paired ref count wrappers at coordinates. 70%/90% and 65%/95%.
- [D2Common.dll@1.13d] Ordinal 10079/10880: ClearCollisionFlagAtCoords/SetCollisionFlagAtCoords — paired grid cell flag ops. room[8]->grid, cell index = ((y-grid[1])*grid[2]-grid[0]+x)*2, ushort per cell. AND-NOT to clear, OR to set. 75%/90%.
- [D2Common.dll@1.13d] Ordinal 10937: SpiralSearchFreePosition — __fastcall expanding spiral search for collision-free position. Max radius 49, step 2. 95 lines. 0%/70% (18 SSA).
- [D2Common.dll@1.13d] Ordinal 10716: FindNearestValidPositionDefault — wrapper for SpiralSearchFreePosition with radius 50, flag 1. 55%/75%.
- [D2Common.dll@1.13d] Ordinal 11048: FindNearestValidPositionSimple — simplified spiral search wrapper, NULL output room, duplicated flag mask. 75%/85%.
- [D2Common.dll@1.13d] Ordinal 10269/10595: ClearMatrixBit/SetMatrixBit — paired bit ops on 16-column bit matrix. Index = row*16+col. 90%.
- [D2Common.dll@1.13d] Ordinal 11080: CopyAndReprocessBitfieldArray — copies 96 bytes + reprocesses activation flags (stride 16, 43 groups). 58%/61%.
- [D2Common.dll@1.13d] Ordinal 11037: TestGlobalBitfieldD4 — bit test on sgptDataTables+0xD4. 94%/97%.
- [D2Common.dll@1.13d] Ordinal 10239: TestGlobalBitfield148 — bit test on sgptDataTables+0x148, bounds-checked vs +0xC4. 94%/97%.
- [D2Common.dll@1.13d] Ordinal 10495: GetBitfieldArraySize — ceil(sgptDataTables+0xC4 / 32) DWORD count. 90%.
- [D2Common.dll@1.13d] Ordinal 10259: GetUnitStatListField58 — reads stat list +0x58 when +0x10 has high bit set. 89%/92%.
- [D2Common.dll@1.13d] Ordinal 10699: TestTableBitfieldByIndex — indexed bitfield test, 40 entries at +0xCC array. 92%/100%.
- [D2Common.dll@1.13d] Fixed bitfield tester family (offsets 0xD4-0x154): 10588:D4, 11134:E0, 10080:E4, 11083:E8, 10787:EC, 10023:120, 10213:124, 10837:128, 10295:130, 10290:134, 10671:14C, 11074:154. All call CheckObjectBitMaskOverlap on sgptDataTables+offset. 80-85%. Array base at +0xCC, 40 entries (stride 4).
- [D2Common.dll@1.13d] Ordinal 10318: ClearUnitStatBitfield2 — zeros second bitfield in stat list (+0x58 + dwordCount*4). 61%/64%.
- [D2Common.dll@1.13d] Ordinal 10620: TestUnitStatBitfield2 — bit test on second stat bitfield. 73%/79%.
- [D2Common.dll@1.13d] Ordinal 10051: TransferBitMaskFlagsDC — wrapper for table+0xDC bit mask transfer. 85%.
- [D2Common.dll@1.13d] Ordinal 10515: ProcessItemSetBonusAndPlacement — set item bonus + placement logic. 71%/77%.
- [D2Common.dll@1.13d] Ordinal 10570: FreeObjectResourcePair — 2-level object resource free (struct + sub-struct). 85%.
- [D2Common.dll@1.13d] Ordinal 10853: IsDataRecord788FieldEqual — checks byte at +0x780 in stride-0x788 table (DWORD_6fdf6514). 85%.
- [D2Common.dll@1.13d] Ordinal 10087: GetDataRecord9CPtr — __fastcall record ptr getter, stride 0x9C, bounds sgptDataTables+0xC5C. 100%.
- [D2Common.dll@1.13d] Ordinal 10542: HaveLightResBonus — byte at offset 7 in stride-0x220 table at +0xC58 (community: D2haveLightResBonus). 94%.
- [D2Common.dll@1.13d] Ordinal 10041: HaveColdResBonus — byte at offset 6 in same table (speculative element). 94%.
- [D2Common.dll@1.13d] Ordinal 10930: HaveFireResBonus — byte at offset 5 in same table (speculative element). 94%.
- [D2Common.dll@1.13d] Ordinal 10460: GameToTileCoords — isometric (2Y+X)/32, (2Y-X)/32 with signed floor division. 85%.
- [D2Common.dll@1.13d] Ordinal 10644: TileToScreenCoords — (X-Y)*80-80, (X+Y)*40+80. Tile = 80x40 px. 95%.
- [D2Common.dll@1.13d] Ordinal 10141: GameToRoomCoords — (2Y+X)/160, (2Y-X)/160. Room = 5 tiles = 160 sub-tile. 80%.
- [D2Common.dll@1.13d] Ordinal 11032: TileToScreenCoordsInPlace — in-place (X-Y)*80, (X+Y)*40 (no centering offset). 85%.
- [D2Common.dll@1.13d] Ordinal 11027: GameToRoomCoordsInPlace — in-place (2Y+X)/160, (2Y-X)/160. 90%.
- [D2Common.dll@1.13d] Ordinal 10385: CalcUnitProximityDistance — octagonal distance estimate between units with size modifier. 48%.
- [D2Common.dll@1.13d] Ordinal 11084: CalcCubicScaledValue — (n+1)*n^2*m polynomial formula. 100%.
- [D2Common.dll@1.13d] Ordinal 10244: GetLevelDatRecordField — level record lookup with ID/range fallback, returns +0xC - 1. 87%.
- [D2Common.dll@1.13d] Ordinal 10068: GenerateRandomAttributes — 4-stage random attribute gen with difficulty (stride 4/4/6/5/7 tables). 59%.
- [D2Common.dll@1.13d] Ordinal 10243: CalcQuadraticStatBonus — (value^2/2)*15, capped 50000, from sgptDataTables+0xBCC+0xF30. 79%.
- [D2Common.dll@1.13d] Ordinal 10487: AppendInventoryRecord — linked list append from Inventory.cpp. Magic 0x1020304 validated. 77%.
- [D2Common.dll@1.13d] Ordinal 10545: GetInventoryField24 — inventory struct +0x24 getter. Magic header validated. 100%.
- [D2Common.dll@1.13d] Ordinal 10292: SetInventoryField24 — inventory struct +0x24 setter. Magic header validated. 95%.
- [D2Common.dll@1.13d] Ordinal 10264: GetInventoryField28 — inventory struct +0x28 getter. Magic header validated. 100%.
- [D2Common.dll@1.13d] Ordinal 10311: GetStructField4 — thunk to shared getter at +0x04. Multi-ordinal (4 ordinals). 97%.
- [D2Common.dll@1.13d] Ordinal 10695: GetItemUnitFieldC — safe unit[3] getter for Items (type 4). Returns 0 for non-items. 80%.
- [D2Common.dll@1.13d] Ordinal 10044: AddUniqueItemTypeToInventory — adds item type to tracking linked list. Source: Inventory.cpp:0xD0A. 67%.
- [D2Common.dll@1.13d] Ordinal 10899: GetInventoryItemDataField — inventory-validated wrapper for GetUnitDataFieldOffset2. 72%.
- [D2Common.dll@1.13d] Ordinal 10127: GetUnitNameString — worker, switch on unit type (0-4) for type-specific name getters. Returns char*. __stdcall. 100%.
- [D2Common.dll@1.13d] Ordinal 10694: GetDifficultyLevelsBIN — DifficultyLevels table accessor, stride 0x58. Community: D2GetDifficultyLevelsBIN (PlugY/D2Funcs.h). Globals: DWORD_6fdf64d8 (base), DWORD_6fdf64d4 (count). 90%.
- [D2Common.dll@1.13d] Ordinal 11171: GetItemQualityBracket — quality level threshold table iterator, stride 0x20. Global: g_pQualityLevelTable (0x6fdf64d0). Returns bracket index (0-based). 75% (4 SSA unfixable).
- [D2Common.dll@1.13d] Ordinal 11053: GetInventoryItemDataFieldCapped — same as 10899 but caps value at 10 (branchless zero-on-overflow). 72%.
- [D2Common.dll@1.13d] Ordinal 11011: CreateInventory — allocates 64-byte inventory struct, magic 0x1020304, links to owner+0x60. Source: Inventory.cpp:0x22E. 22%.
- [D2Common.dll@1.13d] Ordinal 10031: CheckItemFitsInInventoryGrid — scans grid cells in item bounding rect, counts conflicts. 19%.
- [D2Common.dll@1.13d] Ordinal 10696: UpdateWeaponCursorAfterRemoval — clears/replaces weapon cursor (inv[7]) on type 0x2D removal. Byte 0x44 selects page slot. 62%.
- [D2Common.dll@1.13d] Ordinal 10547: FindNextItemByTypeInPage — walks item list via pTypeData+0x70, CheckItemType match, bounds <11. 46%.
- [D2Common.dll@1.13d] Ordinal 10067: FindNextItemByTypeWithOverlay — same as 10547 but resolves page from owner overlay component. 43%.
- [D2Common.dll@1.13d] Ordinal 10849: HasItemType3InInventory — checks grid slot +0x0C for type 3 (armor/body). 47%.
- [D2Common.dll@1.13d] Ordinal 10786: FindBetterMatchingItem — identity match + stat value comparison in inventory. Threshold from +0x5898. 37%.
- [D2Common.dll@1.13d] Ordinal 10722: CheckEquipSlotAvailability — __thiscall slot checker. Switch: 0=deny, 4/5=weapon swap, 0xB/0xC=ring swap. Returns 0-5. 32%.
- [D2Common.dll@1.13d] Ordinal 11064: RebuildEquipmentVisualComponents — COF component rebuild on equip change. 16-slot scan, placement byte dispatch. 17%.
- [D2Common.dll@1.13d] Ordinal 10351: ClearInventoryAndRemoveAllItems — __thiscall, resets cursor, loops RemoveItemFromInventory. 39%.
- [D2Common.dll@1.13d] Ordinal 10640: RemoveAllItemsFromInventory — __thiscall, simpler loop variant (no cursor reset). 49%.

## Function Families
- **Logging**: LogArchiveError (10024), LogSaveParseError (10098), ToggleGlobalLogFile (11148, "d2log.txt" open/close), WriteLogEntry (10551, __cdecl thread-safe) — file I/O error subsystem + global log
- **Unit State**: SetUnitUpdateFlag (10352), IsUnitStateActive (10529), RemoveUnitFromChangedList (10382), ExchangeUnitTypeField (10853), HasActiveEffectFlags (10535) — UnitAny flags/linked lists/type data
- **Position/Movement**: GetUnitPosition (10375), GetNodeDirection (10207), ComputeUnitPath (10474), AdvanceUnitPathStep (10251), AllocateUnitPath (10579), ResolvePathModeAfterStep (10032), SetPathMode (10325), StepExplorationField (10594) — path data, navigation, collision avoidance
- **Animation**: GetAnimDataRecord (10645), SetUnitAnimMode (10193) — AnimDataRecord lookup, mode transitions
- **Room Management**: AddUnitToRoom (11279/10748), FindUnitsInRooms (10181) — room unit linked list at room+0x74, unit+0xE8=next
- **DRLG Room Bounds**: FindRoomContainingCoords (11056), GetRoomBoundsRect (10414), IsCoordinateInRoomBounds (10147) — bounds layout: +0x4C X origin, +0x50 Y origin, +0x54 width, +0x58 height, +0x7C next room
- **DRLG Room Lifecycle**: AllocateDrlgRoom (10024, alloc 96B), FindRoomAndLoadTiles (10501), DecrementRoomRefAtCoords (10208), IncrementRoomRefAtCoords (10890), RemoveFromRoomArray (10701), CountVisibleRooms (10555) — Dungeon.cpp room management
- **Collision Grid Flags**: ClearCollisionFlagAtCoords (10079), SetCollisionFlagAtCoords (10880) — paired AND-NOT/OR on collision grid cells. Grid: room[8]->grid struct [0]=Xoff, [1]=Yoff, [2]=stride, [8]=data.
- **Spiral Position Search**: SpiralSearchFreePosition (10937, __fastcall core), FindNearestValidPositionDefault (10716, radius 50), FindNearestValidPositionSimple (11048, simplified) — expanding spiral for collision-free positions
- **Bit Matrix Ops**: ClearMatrixBit (10269), SetMatrixBit (10595) — paired clear/set on 16-column bit matrices. CopyAndReprocessBitfieldArray (11080) — bulk copy + flag reprocessing.
- **Global Bitfield Tests**: TestGlobalBitfieldD4 (11037, sgptDataTables+0xD4), TestGlobalBitfield148 (10239, +0x148 with bounds +0xC4) — standard bit-test pattern using gdwBitMasks_exref. **Fixed-offset family** (0x120-0x154): 10023, 10213, 10837, 10295, 10290, 10671, 11074 — all via CheckObjectBitMaskOverlap. TestTableBitfieldByIndex (10699) is the indexed variant (40 entries at +0xCC). GetBitfieldArraySize (10495) returns DWORD count.
- **Unit Stat Bitfield2**: ClearUnitStatBitfield2 (10318), TestUnitStatBitfield2 (10620) — second bitfield in stat list, located at +0x58 + dwordCount*4 (where dwordCount = ceil(sgptDataTables+0xC4 / 32)). Paired clear/test ops on secondary bit array.
- **Resistance Bonus Getters**: HaveFireResBonus (10930, offset 5), HaveColdResBonus (10041, offset 6), HaveLightResBonus (10542, offset 7, community confirmed) — byte flags from stride-0x220 table at sgptDataTables+0xC58, bounds at +0xC5C. GetDataRecord9CPtr (10087, __fastcall) returns ptr to stride-0x9C record from same index space.
- **Isometric Coordinate Transforms**: GameToTileCoords (10460, div 32), GameToRoomCoords (10141, div 160), TileToScreenCoords (10644, *80/*40 + offset), TileToScreenCoordsInPlace (11032, no offset), GameToRoomCoordsInPlace (11027). D2 isometric: tiles 80x40 px, rooms 5 tiles wide, sub-tile unit = 1/32 tile.
- **Item Stats**: AreItemsInSameStatGroup (10729), ClearStatFromStatList (10509), GetStatRecordEntry (10899) — stat encoding, group comparison, array access
- **Missile Record Accessors**: Table at sgptDataTables+0xBBC, stride 0x84 (132 bytes), count at +0xBC0. GetMissileRecordField44 (10391), GetMissileRecordByte48 (10015), GetMissileRecordField54 (10020), GetMissileRecordField58 (11000), GetMissileRecordByte7C (10471) — all 92%. SetMissileDataField (11012) — setter variant.
- **Monster Skills**: ComputeMonsterSkillParams (10944) — class-relative skill overlay/targeting
- **Effect Flags**: HasAuraEffectFlag (10526), HasOverlayEffectFlag (10533), HasActiveEffectFlags (10535) — family of flag checkers on sub-struct at +0x68
- **Memory Management**: FreeTrackedPoolArray (10954) — tracked pool deallocation, 108 entries, __fastcall
- **Player Class Scaling**: AdjustValueByPlayerClass (10772) — class-based multiplier, UnitAny+0x04 = classId
- **State Bit Testers**: TestStateTargetOverlay (10483) — thin wrappers around TestStateBit with hardcoded bitmask constants
- **Inventory System**: CreateInventory (11011), GetInventoryFieldC (11040), GetInventoryField24 (10545), SetInventoryField24 (10292), GetInventoryField28 (10264), AppendInventoryRecord (10487), IsItemTypeInInventory (10478), AddUniqueItemTypeToInventory (10044), GetInventoryItemDataField (10899/11053), CheckItemFitsInInventoryGrid (10031), FindNextItemByTypeInPage (10547), FindNextItemByTypeWithOverlay (10067), HasItemType3InInventory (10849), UpdateWeaponCursorAfterRemoval (10696), PlaceItemInStoragePage (10963), AutoPlaceItemInInventory (10402), AutoPlaceItemInBelt (10903), PlaceBeltableItemInSlot (10052), GetInventoryPageDimensions (10901). All validate magic 0x1020304. Struct: 64B, [0]=magic, [1]=pool, [2]=owner, [7]=cursor GUID, [9]=classId, [0xB]=list head, [0xC]=list tail. Item traversal: pTypeData+0x70 = next item. Sentinel: pTypeData == -0x5C. Owner at unit+0x60. ExpandOrInitInventoryPage resolves page grid; grid cell = width*Y+X index. Page dimensions: g_abData[nPage+0x23]=width, g_abData[nPage+3]=height. Pages: 0=equipment, 1=belt (slots 0-15), 2+=storage. PlaceItemInStoragePage adds +2 to page index. Belt items must be 1x1 (record +0x10F/+0x110). FindItemInventorySlot finds free grid position; FindBeltSlotForItem finds free belt slot (0-15).
- **Data Table Accessors**: GetDataTableValue (11093) — 2D table[row][col], stride 135, global base at 0x1009c388
- **Tile/Collision**: ResetUnitTileAttributes (10211) — ClearUnitCollisionFlags + ApplyPresetUnitTileAttributes, preset lookup via g_adwPresetTileValues
- **Animation**: AdvanceFrameAccumulator (10370) — 8.8 fixed-point frame counter, accumulator+rate at +0x4C/+0x54. GetAnimOverlayByteAtFrame (10072, stride 6, byte +5 at frame>>8). **Graphics Mode**: GetUnitGraphicsMode returns struct, field accessors: GetGraphicsModeField0 (10364, +0), GetGraphicsModeFrameFixed (10664, +4 <<8), GetGraphicsModeField8 (10362, +8). SetOrClearBitFlags (10388, generic bit OR/AND-NOT utility).
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
- [D2Common.dll@1.13d] **Monster System**: Monstats table at sgptDataTables+0xA78 (base), +0xA80 (count), stride 0x1A8 (424 bytes). Property flags at record+0xC/+0xD via gdwBitMasks bit indexing. IsMonsterInNeutralMode (10971, mode 0 or 0xC). GetMonsterDataProperty6 (10184, +0xC bit 6), GetMonsterDataProperty7 (10368, +0xC bit 7), IsMonsterDataProperty20Set (11156, +0xD bit 4). SetMonsterUnicodeName (10304, __fastcall, monsterData+0x2C alloc, MONSTERS.CPP). Unit type 1=Monster, unit[1]=classId, unit[4]=animMode, unit[5]=monsterData.
- [D2Common.dll@1.13d] **Item System**: GetItemDataRecord (10600, stride 0x1a8), FindItemDataRecord (10000, binary search), CheckItemType (10731, 111 xrefs). GetItemType (10121) → GetItemTypeFromClassId (10850, item_data+0x50). GetItemTypeProperty (11090, ItemTypes +0xBF8, stride 0xE4). GetItemTypeEquiv1 (10215, +0xC)/GetItemTypeEquiv2 (10869, +0xE) — type equivalence hierarchy.
- [D2Common.dll@1.13d] **Item Record Fields**: +0x4A/+0x4B=fieldPair (11098), +0x80=itemCode (10604), +0x88=normcode, +0x8C=ubercode (10587 tier check), +0xC0=bodyType (10987), +0xDC=flagByte (10569), +0xE4=fieldE4_dword (10661), +0xE8=fieldE8_dword (11033), +0x104=field104 (10761), +0x106/+0x108=speed (10807/10808), +0x10A=strReq, +0x10C=dexReq (11072), +0x10F/+0x110=invW/H (10143), +0x112/+0x113=durability/indestructible (10149), +0x115=bodyLoc (10993), +0x11C=unknown (10209), +0x12A=tierFlag (10587), +0x130=byte (10372), +0x132=stackability (10715), +0x137=byte (10004), +0x138=gfxVariants (10884), +0x13A=collision (10789), +0x13D=classRestrict (10348), +0x13E=byte (10390). All stride 0x1a8. **Flag byte +0xDC bit accessors**: bit1 (11043), bit2 (10931) via g_pItemDataTable. **Item data struct (unit[5])**: +0x00=dword (10696 setter), +0x04/+0x08=dword pair init 1/0x29A (10756), +0x0C=fieldC (10466, abort), +0x10=dword get/set (10693/10950, setter aborts), +0x1C/+0x20=paired fields (11245, setter), +0x36=short (10698 setter), +0x45=byte get (10719), +0x46=byte get/set (10721/10722), +0x47=byte get/set (10853/10854). Abort pattern: GetReturnAddress→CleanupAndAbort(sourceFile, retAddr, lineNum)→ReportError(-1). Byte getters return 0xFF on invalid unit. **Additional accessors**: +0xFA=ushort (11006), +0xFD=byte (11031), +0x11D=byte (10514), +0x90=ultracode fallback to +0x80 base code (10336). **ItemTypes table**: +0x10 byte accessor (10882, __stdcall, stride via sgptDataTables).
- [D2Common.dll@1.13d] **Item Properties**: GetItemProperty (10075)/SetItemProperty (10360) at item_data+0x28. GetItemQuality (10695) at +0x00. GetItemFlags (10709)/TestItemFlags (10458)/IsItemNotRestricted (10955)/IsItemEthereal (10880) at +0x18. GetItemQuantity (10717) at +0x2C. GetEffectiveItemLevel (10007) base+bonus. GetItemStackGfxTier (10185) quantity→tier. GetItemStatValueCapped (10976) capped to 511. GetItemDataShortByIndex (10701, item_data+0x3E array). GetItemRecordCode (10604, record+0x80 dword). GetItemStorePage (10233, ItemTypes+0x21 byte, 0-6 valid).
- [D2Common.dll@1.13d] **Set Items**: SetItems table: sgptDataTables+0xC18 (base), +0xC1C (count), stride 0x1B8 (440 bytes). GetSetItemRecord (10346, record pointer). GetSetItemRecordField2E (10189, short at +0x2E). Quality 5 = Set.
- [D2Common.dll@1.13d] **Stat System**: SetStatInList (10463) binary search insert, SetUnitStat (10590) wrapper, AddStatToList (11158) accumulator, GetUnitBaseStat (10550) reader. GetStatCostTableValue (10190)/GetStatCostValueChecked (10216) from ItemStatCost (+0xBCC, stride 0x144). InsertAndApplyStatList (10808) dual-chain. TransferStatListOwnership (10977). AllocateStatList (10219) 60-byte from pool. FindStatListEntryByGuid (10429, unit+0x5C lookup). ClearAllStatsFromList (10053, removal loop). ToggleStatListActiveFlag (10650, 0x2000 toggle+re-apply). GetStatFromListByLayerChecked (10341, conditional layer lookup). Damage stat cost family: GetMinDamageStatCost (10952, stat 21/23), GetMaxDamageStatCost (10790, stat 22/24). Resource stat cost: GetMaxManaStatCost (10084, stat 9), GetMaxStaminaStatCost (10943, stat 11). D2 stat IDs: 9=maxmana, 11=maxstamina, 21=mindamage, 22=maxdamage, 23=secondary_mindamage, 24=secondary_maxdamage. CopyStatListEntries (10322, +0x48 array copy into buffer). UnapplyStatModifiers (10333, reverse stat bonuses, flag 0x40000000, gdwBitMasks_exref[8] filter).
- [D2Common.dll@1.13d] **Collision System**: Low: ClearCollisionMask (10444), GetCollisionMaskFlags (10152), GetCollisionMaskFlagsMultiMode (10409, 6-mode), CheckCollisionMask (10953), SetCollisionMask (10446). Mid: ApplyCollisionMaskArea (10144, OR flags), ClearCollisionMaskArea (11104, clear flags), ClearUnitCollisionArea (10223), SetUnitCollisionArea (10222), ApplyUnitSizedCollision (10254), ApplyCollisionPatternAtCoords (11168), UpdatePathCollisionFlags (10966, clear+apply path collision). High: GetUnitCollisionFlags (10157, __fastcall), GetUnitSizeModifier (10780), GetUnitBlockingSize (11013), CheckUnitCollisionOverlap (10236), ComputeUnitDistance (10246), CalcDistanceToPoint (10622, octagonal approx), IsUnitInAttackRange (11023, melee range check). CopyUnitPathBlock (10881).
- [D2Common.dll@1.13d] **Skill System**: GetSkillRangeValue (11021, +0x174), FindSkillListNode (10984, __fastcall linked list), AssignSkillToUnit (10435), UpdateUnitSkillLevel (10335, level set+reapply), ApplySkillItemStats (10374, 5 stat entries), EvaluateSkillCalcExpression (11081, bytecode), CalcSkillElemMin (10728, +0x1E0/+0x1E8), CalcSkillElemMax (10662, +0x1E4/+0x1FC) — paired elem damage calc. Skills table: +0xB98/+0xBA0, stride 0x23C. Skill ElemMin: +0x1E0 base, +0x1E8 breakpoints. ElemMax: +0x1E4 base, +0x1FC breakpoints. Shared: +0x1A4 shift, +0x210 calc, +0x1DC bonus type.
- [D2Common.dll@1.13d] **Missile System**: CalcMissileParam (10821, Missiles table +0xB64, stride 0x1A4). EvaluateMissileCalcExpression (10536, bytecode at +0x60/+0x64). GetMissileFieldByIndex (10150, master 43-case property getter). Fields: +0xEC base, +0x104 breakpoints, +0x118 calc, +0x196 shift. Requires unit type 3 (Missile).
- [D2Common.dll@1.13d] **Path/Movement**: AllocateUnitPath (10579, Source: Path.cpp, 512-byte path alloc, type dispatch). ResolvePathModeAfterStep (10032, restore/idle). AdvanceUnitPathStep (10251) — path step with mode transitions. SetPathMode (10325) — mode setter with flag backup and mode table. SetUnitPathField0C (10892)/SetUnitPathField10 (10739) — coordinate pair setters. GetPositionPair (10395) — dual-field getter from struct. CalcDirectionToCoords (10697, type-branched position+CalculateDirectionFromDelta). TransformIsometricCoords (10720, isometric rotation). SetPathFieldByUnitType (10365)/GetPathFieldByUnitType (10369) — type-dispatched: +0x40 (Player/Monster w/ +0x30 sub-struct) or +0x10 (others). SetUnitPathTarget (10129, +0x58/+0x5C/+0x60 target). CalcPathBetweenUnits (11065, dual-unit path with collision clear/restore). CalcPathToCoords (10841, single-unit path to coords). HasReachedPathTarget (10288, path target check). **Position accessors**: GetUnitPathCoordX (10641)/Y (10057) — tile precision. GetUnitFixedPointX (10321)/Y (10607) — 16.16 fixed-point. CalcAbsUnitXDifference (10768) — abs X distance. Path data at unit[0x0B], 512 bytes. Modes: 2=normal, 4=special, 7=idle, 0xD=alt, 0xF=retry.
- [D2Common.dll@1.13d] **Unit Search**: InitializeUnitFindContext (10101, UnitFinds.cpp:228, allocs 60-byte buffer, 15 capacity), CollectFilteredRoomUnits (10725, callback-filtered unit collection, max 15), FindUnitsInRooms (10181, multi-room callback search), FilterUnitByProximityAndFlags (10603, type-dispatched radius+flag filter). UnitFindContext: [0]=pool, [1]=results, [2]=room, [3]=filterParam, [4]=userData, [6]=count, [7]=capacity(15), [8-10]=extra params. Room unit list at room+0x74, next at unit+0xE8.
- [D2Common.dll@1.13d] **Item Identity**: AreItemsIdentical (10613) — deep comparison for stacking. Checks classId, quality, property (+0x28), stackability flag (+0x132), ethereal, 6 stats (0x15-0x18, 0x9F, 0xA0).
- [D2Common.dll@1.13d] **Equipment System**: GetUnitEquipSlotCount (10247, type-dispatch Player=1/Monster=table-1/other=0), GetBestWeaponBodyType (10998, __fastcall weapon→body type), GetUnitWeaponRange (10088, __fastcall Player record+0x13C/Monster+0x14), IsUnitDualWieldClass (10171), FindEquippedWeaponByClassId (10627), FindWeaponInEquipSlots (10721), GetEquippedItemByBodyLoc (10286), GetItemEquipBodyType (10987), FindBestEquippedWeapon (10058), GetAlternateEquippedWeapon (11016, dual-slot swap by GUID), ResolveItemEquipSlotType (11012), IsClassRestrictedItem (10348), GetWeaponSlotRestriction (10443), FindEquippedType33Item (11114), GetEquippedSetBonusMask (10941), UpdateDualWieldStatOwnership (10105), GetPlayerEquippedWeapon (10958). 11 slots.
- [D2Common.dll@1.13d] **Room/Dungeon**: GetRoomDimensions (10043, width [0x11], height [0x12]), FreeRoomResourceList (11111, +0x18 list free), AddRoomResourceEntry (10130, Dungeon.cpp:900), DecrementRoomRefCount (10675, +0x28 refcount), IsCoordinateInRoomBounds (10147, X:+0x5C/+0x64, Y:+0x60/+0x68), SortRoomUnitListByPosition (10203, bubble sort by pathData Y). Pool at +0x2C->+0x5C.
- [D2Common.dll@1.13d] **Collision System**: GetCollisionFlagAtPosition (10561, room grid at room[8]->grid[8], 2-byte stride, default 0x27), UpdatePathCollisionFlags (10966, mode 3=tile-based).
- [D2Common.dll@1.13d] **Profiling**: DumpProfilingStats (10731, dump), AccumulateProfilingTime (10064, __thiscall QPC accumulator), ResetProfilingCounters (10556, zero+dump). Array: 0x6fdf3460, stride 0x78, ~11 entries. Entry: [0]=elapsed_lo, [1]=elapsed_hi, [2]=call_count.
- [D2Common.dll@1.13d] **Data Table I/O**: ReadExcelDataFile (10711, DATA\GLOBAL\EXCEL reader). CompileTextDataTable (10037, txt→binary compiler).
- [D2Common.dll@1.13d] **Inventory Operations**: GetInventorySlotItem (10292), FindItemInventorySlot (11087), GetInventoryFieldC (11040), DestroyInventory (11070), IsItemTypeInInventory (10478, linked list [0xB]), HasMatchingItemInCodeGroup (10332, excludes scrolls), FindBeltSlotForItem (10532, 1x1 belt placement), UpdateWeaponCursorState (10584, cursor GUID management), CanItemFitInEquipSlot (10914, slot 0-12). Magic header 0x1020304.
- [D2Common.dll@1.13d] **Spatial Queries**: FindNearbyUnitByProximity (10759, room+0x74 unit list, 9-case proximity matrix, callback filter — 153 lines, 0% raw due to SSA).
- [D2Common.dll@1.13d] **DRLG**: AllocateDrlgLevel (10283, types 1=Maze/2=Preset/3=Outdoors), GenerateDrlgLevel (10736), GetLevelPresetData (10964, stride 0xF0), FindOrAllocateDrlgLevel (10122, pDrlg+0x24 linked list), FreeDrlgStructure (10423, __fastcall destructor), RemoveRoomFromDrlgList (11045, room unlink+adjacency cleanup), CopyPresetDataArray (10659, __fastcall pool alloc+copy triplets, Preset.cpp). LevelsDef: +0xC5C, stride 0x9C.
- [D2Common.dll@1.13d] **Overlay Data**: GetOverlayRecord (10619, DWORD_6fdf4cec base, DWORD_6fdf4ce8 count, stride 0xC0=192).
- [D2Common.dll@1.13d] **Skill Stat 0xCC**: FindItemSkillStatInList (10520, recursive stat list + inventory search), ApplySkillStatToRoomUnits (10085, recursive room unit + inventory application via Ordinal_10709). Both use flag 0x40 stat nodes, ItemStatCost bounds check at +0xBD4/+0xBCC+0x10230.
- [D2Common.dll@1.13d] **Monster Types**: GetMonsterTypeRecord (10050, MonTypes +0xB50, stride 0x20, bounds-checked). IsMonsterRecordExpansionOnly (10451, __fastcall, record+0xE expansion bit). IsMonsterInSpecialDeathMode (11094, animMode 0xC + linked table flags).
- [D2Common.dll@1.13d] **AutoMap**: IsUnitAutoMapRevealed (10706), FindAutoMapCellEntry (10668, linear search, stride 0x118).
- [D2Common.dll@1.13d] **Combat**: CalcUnitBlockChance (10345, shield+stat21+skill desc, dex/level scaling, cap 75). CalcLifePercentage (10683, stat7*100/stat8, 8.8 fixed). IsUnitInAttackRange (11023, melee range). CalcCombatStatBonus (10300, __thiscall, stat formula).
- [D2Common.dll@1.13d] **COF/Animation**: AdvanceAnimFrameWithEvents (10048, frame advance+event scan 1-4, forward/reverse modes). GetCofComponentByte (11169, switch remap), BuildUnitCofPath (10856, equip+mode resolve→BuildAnimCofPath), IsUnitWeaponAnimMelee (10743, token 1/7=melee), SetAnimFieldPair (10840, DWORD pair setter). Component IDs: 1=Head, 2=Torso, 3=Legs, 4=RArm, 8=Shield, 9=Special. **Frame Control**: IsAnimationComplete (10537, boundary test reverse/forward), AdvanceAnimFrameWithWrap (10754, 8.8 modular loop), SetAnimEventFromFrameData (10885, +0x4E event from frame array), GetUnitAnimFramePair (10397, type-dispatched frame pair), GetObjectAnimModeRecordByte (10434, record +0x120+mode).
- [D2Common.dll@1.13d] **Object Data**: GetObjectDataField0A (11127, short at pObjectData+0xA, type 3 only). TestObjectDataByte5Flag (10755)/SetObjectDataByte5 (10033) — flag getter/setter pair at pObjectData+5.
- [D2Common.dll@1.13d] **Data Tables**: CompileTextDataTable (10037, 94 xrefs). GetGlobalRecordById (10174, stride 0x90). LookupGlobalPairTable (10886, 13 elements). GetDataTableValue (11093, stride 135).
- [D2Common.dll@1.13d] **Unit Access**: GetUnitClassData (10846, 31 xrefs). AddUnitToClassQueue (10229)/RemoveUnitFromClassList (10992)/RemoveUnitFromClassDataList (10597). GetUnitTypeName (10896, __thiscall type switch). SetUnitItemTypeBitFlag (11152)/ApplyUnitItemTypeStatList (10399). IsUnitAutoMapRevealed (10706).
- [D2Common.dll@1.13d] **Animation**: ResolveWeaponAnimToken (10526, 4-byte ASCII codes). GetUnitOverlayComponent (10484, type+mode→index). CalcLevelScaledValue (11146, diminishing returns). InitializeUnitAnimation (10095, 5-way type switch, callees: 10116/10551/11050/10319). GetEquipSlotAnimComponent (10116, equip→anim lookup). InitializeAnimFromGraphicsMode (11050, graphics mode init). GetAnimSequenceRecord (10319, stride 0x1C0 table). GetAnimDataFrameInfo (10826, FindAnimDataByName wrapper, g_dwLastError fallback). GetAnimFrameDataByMode (11019, type/mode dispatch to ExtractAnimFrameData or direct byte).
- [D2Common.dll@1.13d] **Skill Node Accessors**: GetActiveSkillFieldC (10942)/SetActiveSkillFieldC (10593) at +0x0C, GetActiveSkillField8 (10909)/SetActiveSkillField8 (10161) at +0x08. GetEffectiveSkillRange (10437, base+0x174+node level). GetSkillNodeRecord (10966, __fastcall). Skill header at pSkillData+0xA8: +0x04=first node, +0x08=left active, +0x0C=right active.
- [D2Common.dll@1.13d] **Skill List Linked List**: CopySkillListToBuffer (10926, flattens 8 entries into 34-byte buffer), GetSkillListEntryByTypeIndex0/1/2 (10012/10103/10996, typed searches). Entry layout: short[+0]=value, byte[+4]=type (0/1/2), ptr[+8]=next. Type 2 default: 0xE8C. Three nearly identical functions forming a type-filtered family.
- [D2Common.dll@1.13d] **Item Data Access (field-based)**: GetItemDataShortByIndex (10701, +0x3E), SetItemDataShortByIndex (10702, +0x3E), GetItemDataField38ByIndex (10699, +0x38), GetItemDataField32 (10703)/SetItemDataField32 (10704, +0x32), GetItemDataField34 (10705)/SetItemDataField34 (10706, +0x34), GetItemDataShort36 (10697, +0x36), SetItemDataByte45 (10720, +0x45)/GetItemDataByte48 (10725, +0x48), GetItemEffectiveCode (10628, +0x84/+0x88/+0x8C), SetItemDataField0C (10762, +0x0C), GetItemDataField64 (10879, +0x64), GetItemDataByte69 (10600, +0x69), GetItemDataPosition (11058). GetUnitIfItem (10305) = branchless item type filter.
- [D2Common.dll@1.13d] **Stat List Maintenance**: CleanupUnitStatListEntries (10114, unit+0x5C stat list, automap reveal+free), InsertAndApplyStatList (10808), TransferStatListOwnership (10977).
- [D2Common.dll@1.13d] **Missile Calculations**: CalcMissileParam (10821, +0xEC/+0x104/+0x118), CalcMissileBreakpointValue (10132, +0x11C/+0x120-128 3-tier piecewise), CalcMissileVelocityParam (10624, +0xB4/+0xCC/+0xE0), CalcMissileAccelParam (10302, +0xB0/+0xD8/+0xEC), EvaluateMissileCalcExpression (10536, bytecode). Velocity and Accel are paired (same structure, different offsets).
- [D2Common.dll@1.13d] **Item Repair/Quality**: CanItemBeRepaired (10679), IsItemDurabilityDepleted (10149), GetItemDropQualityByDifficulty (10517). CheckItemEquipRequirements (11072, str/dex/lvl). SetItemInventoryDisplayTier (10241, stat 0xC2).
- [D2Common.dll@1.13d] **Cube Recipes**: FindMatchingCubeRecipe (10948). CubeMain table: DWORD_6fdf4cf4, stride 0x120, count DWORD_6fdf4cf0. Fields: +0x80=enabled, +0x86=include types, +0x92=exclude types, +0x98=input classIds.
- [D2Common.dll@1.13d] **Exploration/Pathing**: StepExplorationField (10594), StepExplorationToCollision (10975, walks until collision), DecodePackedPositionDelta (11113, bit-level position unpacking). Used by pathfinding subsystem.
- [D2Common.dll@1.13d] **Skill Calculations (extended)**: EvaluateSkillElementalCalc (11154, calls 11081 bytecode), CalcSkillPassiveValue (10167, passive breakpoint+calc), CalcSkillManaCost (10046, +0x148/+0x14C via CalcLevelScaledValue), EvaluateSkillCalcValue (10648, +0x198/+0x19C linear or +0x1A0 bytecode), CalcSkillMaxDamage (10196, +0x1AC/+0x1C4 + weapon stat 22), CalcSkillMinDamage (10687, +0x1A8/+0x1B0 + weapon stat 21). Same CalculateStatByLevelBreakpoints pattern as missiles. Low raw scores (35-45%) due to SSA intermediates.
- [D2Common.dll@1.13d] **Level Record Fields**: GetLevelRecordField02 (10465, +2 short), GetLevelRecordField06 (10030, +6 short). Both null-abort pattern.
- [D2Common.dll@1.13d] **Item Level Caps**: g_pdwMaxItemLevel global table. GetMaxItemLevelByDifficulty (10629, [0-6] index), GetMaxItemLevelByQualityTier (10628, compound diff+quality*8+8), GetItemLevelCapByIndex (10746, stride 0x20, +0x3C), GetEffectiveItemLevel (10007, clamped to cap).
- [D2Common.dll@1.13d] **Data Table Init/Cleanup**: LoadAllDataTables (10081, master loader, 50+ table calls) / FreeAllDataTables (10682, master cleanup, 17+ Free* calls). Source: DataTbls.cpp. DWORD_6fdf33f4 = debug allocation flag.
- [D2Common.dll@1.13d] **Ignore List Manager**: CreateIgnoreListManager (10735, SEH+arena alloc 0x188) / DestroyIgnoreListManager (10925, vtable +0x2C destructor). Global: DWORD_6fdf6564. Source: Ignorelist.cpp.
- [D2Common.dll@1.13d] **Player Data Accessors**: GetPlayerData (11103, unit+0x14 pointer), GetPlayerDataField2C (10910)/SetPlayerDataField2C (10271, +0x2C), GetPlayerDataField90 (10177)/SetPlayerItemField90 (10342, +0x90 from item[3]), SetPlayerDataFieldPair8088 (10991, +0x80/+0x88), AssertValidPlayerUnit (10308, validation). UpdatePlayerSkillAnimData8 (10969, +0x74/+0x7C from skill field 8), UpdatePlayerSkillAnimDataC (10248, +0x70/+0x78 from skill field C). All Player type 0 only.
- [D2Common.dll@1.13d] **Quest/Waypoint**: InitializePlayerQuestWaypointData (10404, alloc 0x16C+4 difficulty slots) / FreePlayerQuestWaypointData (10135, free 4 slots). Sub-struct at pPlayerExtData+0x14. QuestRecord.cpp, Waypoint.cpp source. Marker: 0x102=freed, 0x101=active, 0x0=empty. Expansion bitmask at sub_struct+0x2C from g_dwGameResult.
- [D2Common.dll@1.13d] **Unit Sub-Resource**: AllocateUnitSubResource (10598) / FreeUnitSubAllocation (10630). 32-byte alloc at +0x2C from pool +0x08. Source: Units.cpp.
- [D2Common.dll@1.13d] **Unit Running Flag**: SetUnitRunningFlag (10061) / GetUnitRunningFlag (10270) — type-dispatched: Player/Monster use bit 2 at pathData+0x34, Object/Item use byte at pathData+0x1D. SetUnitTargetInfo (10813) — writes target position to path data.
- [D2Common.dll@1.13d] **Player Data Field Pairs**: GetPlayerDataFieldPair747C (10173, +0x74/+0x7C), GetPlayerDataFieldPair7078 (10611, +0x70/+0x78), SetPlayerDataFieldPair8088 (10991, +0x80/+0x88), ConsumePlayerFieldPair8088 (10424, read+reset +0x70/+0x78/+0x80/+0x88/+0x90/+0x94). Paired field accessors on pPlayerData.

## String Anchors
- [D2Common.dll@1.13d] `..\\Source\\D2Common\\DATATBLS\\DataTbls.cpp` — CompileTextDataTable and related data table functions
- [D2Common.dll@1.13d] `..\\Source\\D2Common\\PATH\\Path.cpp` — AllocateUnitPath and path system functions
- [D2Common.dll@1.13d] `..\\Source\\D2Common\\UNITS\\Units.cpp` — AllocateUnitSubResource (10598) and unit lifecycle

## Known Limitations
- Hungarian `fEnable` false positive: int used as boolean gets `p` prefix flagged. Accept `f` prefix for int-as-boolean.
- Hungarian `pX` false positive: int used as pointer (e.g., pUnit, pStatEntry). Countermeasure: set type to `void*` or proper pointer type. Occurs in ~50% of functions with pointer-semantics params.
- Thunk functions (single JMP) have no body variables of their own; skip type audit and variable renaming on the thunk. Document the body instead.
- Register-only SSA variables (bVar*, iVar*, piVar*, uVar*) in worker bodies cannot be renamed or retyped. Document in plate comment Special Cases.
- Decompiler fails to recover jumptables for some error logging functions (0x10077d16, 0x10077d22).
- [D2Common.dll@1.13d] Ordinals 10005/10009/10022/10056 at 0x6fd5afba-afd2: jumptable dispatchers, decompiler can't recover ("Too many branches"). 6-12 xrefs each but undocumentable.
- CONCAT22 phantom variables (extraout_var*) appear when 16-bit path position functions return ushort but caller uses uint. Cannot fix.
- DAT_* globals renamed via create_label/rename_or_label may not reflect in decompiler output until cache refresh. Deduction persists at 97% — accept as near-unfixable.
- [FrontEnd] propagate_documentation fails: "FunctionService is null". Must propagate manually via switch_program + rename + set_prototype per version.

## Strategy Performance
- [D2Common.dll@1.00] callee_first: 25 functions, avg 94.4% — all ordinal exports are thunks with no callees, degrades to sequential.
- [D2Common.dll@1.13d] callee_first (exploration x3): 15 functions, avg 77.2% raw. Degenerates — all callees pre-named. Complex functions (skill/missile calc) drop raw scores due to SSA/undefined storage.
- [D2Common.dll@1.13d] high_xref: 65 functions, avg 75.6% raw. Primary strategy. Consistent results across item/skill/collision/equipment/path domains.
- [Fog.dll@1.13d] callee_first: 7 functions across 2 iterations, avg 84.6% raw / 98.6% effective. Binary COMPLETE (0 undocumented). Register-only SSA is primary deduction source. Propagation: 11 total (7 to 1.10, 4 to 1.06b).
- [D2Common.dll] All 269 remaining undocumented are Ordinal_* thunks. Worker-body thunks still yield rich analysis.
- [D2Common.dll] Best batch: iteration 7 (3 thunks, all 100%). Worst: iteration 9 (85% raw, void* deductions).
- [D2Common.dll@1.13d] neighborhood (exploration): 5 functions, avg 59.4% raw / 91.0% effective. Low raw scores due to many register-only SSA variables in complex functions. Good for contextual documentation — 4/5 were callees of ApplySkillItemStats with shared skill/item context.
- [Storm.dll@1.13d] callee_first: 8 functions in 1 iteration, avg 56.1% raw / 85.9% effective. Binary COMPLETE (0 undocumented). Low raw scores due to register-only SSA and pre-existing docs with unfixable deductions. All community-named. Propagation: 8 to 1.10, 0 to 1.06b.

## Common Mistakes
- Typing parameters as `int` when they're semantically pointers (e.g., pAnimDataTable). Set type to `void*` or a proper pointer type to avoid Hungarian notation false positives and improve decompiler output.
- **CRITICAL: Plate comment `\n` escape sequences**: Using `\n` in batch_apply_documentation plate_comment parameter creates LITERAL backslash-n text, NOT newlines. The completeness checker sees 1 line and flags 4 plate_issues (-12 to -20 raw score). FIX: Use actual multi-line text in the plate_comment parameter. Discovered iteration 44, affected 9 functions across 2 iterations (+20 score each after fix).
- **CRITICAL: Plate comment REQUIRED SECTIONS** (discovered iter 72): The completeness checker (`validatePlateCommentStructure`) requires 4 elements: (1) minimum 10 lines, (2) "Algorithm:" section with numbered steps (1. 2. 3.), (3) "Parameters:" section, (4) "Returns:" section. Missing ANY element = -1 per missing. All 10 functions in iters 59-60 had -4 (all missing). FIX: Use this template:
  ```
  Brief one-line summary.
  [Additional context lines as needed]

  Algorithm:
  1. First step
  2. Second step
  3. Third step

  Parameters:
  - param1: description
  - param2: description

  Returns:
  - Return value description

  Special Cases:
  - Any edge cases or limitations
  ```
  Must total >= 10 lines. Expected impact: +4 raw score per function.

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
