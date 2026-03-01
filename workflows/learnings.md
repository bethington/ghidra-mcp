# RE Loop Learnings

> Maintained by /re-loop. Manual edits welcome.
> Last updated: iteration 7

## Binary Context
- Program: D2Common.dll 1.00 (Classic/LoD)
- Architecture: x86 32-bit PE, __stdcall for ordinal exports
- Total functions: 3,654
- Data types: 332
- Image base: 0x10000000
- All undocumented ordinal exports are single-JMP thunks — body is at the jump target

## Naming Conventions
- Ordinal exports mostly use __stdcall; exception: FreeTrackedPoolArray (10954) uses __fastcall (ECX/EDX)
- Existing named functions: MarkUnitForRoomUpdate, InitializeUnitAnimation, GetUnitAnimFrameEvent, InitializeMonsterItemData, ParseCharacterSaveData, ValidateAndSetAsyncFileHandle, ValidateFileOperationResult, ReadFileToBuffer, ReadFileWithRetry, ValidateFileReadResult, ValidateFileSeekResult
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
- Offset +0x00 (pUnit[0x00]): dwType (uint) — unit type enum. 2 = Player
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

## String Anchors

## Known Limitations
- Hungarian `fEnable` false positive: int used as boolean gets `p` prefix flagged. Accept `f` prefix for int-as-boolean.
- Hungarian `pX` false positive: int used as pointer (e.g., pUnit, pStatEntry). Countermeasure: set type to `void*` or proper pointer type. Occurs in ~50% of functions with pointer-semantics params.
- Thunk functions (single JMP) have no body variables of their own; skip type audit and variable renaming on the thunk. Document the body instead.
- Register-only SSA variables (bVar*, iVar*, piVar*, uVar*) in worker bodies cannot be renamed or retyped. Document in plate comment Special Cases.
- Decompiler fails to recover jumptables for some error logging functions (0x10077d16, 0x10077d22).
- CONCAT22 phantom variables (extraout_var*) appear when 16-bit path position functions return ushort but caller uses uint. Cannot fix.

## Strategy Performance
- callee_first: 7 functions, avg 95% — all ordinal exports are thunks with no callees, degrades to sequential. No FUN_* functions remain in D2Common.dll 1.00.
- All 269 remaining undocumented functions are Ordinal_* thunks. callee_first is equivalent to high_xref for this binary since all targets are leaf thunks.
- Worker-body thunks (Ordinal_10729) can still yield rich analysis — the body at the JMP target has full logic.
- Iteration 4 (callee_first): 3 thunks, avg 94% raw / 97% effective. All 3 had p-prefix Hungarian false positive. One body (RemoveUnitFromChangedList) had register-only SSA — only 69% raw but 97% effective.
- Iteration 5 (callee_first): 3 thunks, avg 98% raw / 100% effective. 1 perfect (GetStatRecordEntry), 2 with p-prefix only.
- Iteration 6 (callee_first): 3 thunks, avg 97% raw / 100% effective. 2 perfect (missile pair), 1 complex worker with phantoms (ComputeMonsterSkillParams).
- Iteration 7 (callee_first): 3 thunks, all 100% raw/effective. Triple perfect — best batch ever. First __fastcall ordinal (10954).

## Common Mistakes
- Typing parameters as `int` when they're semantically pointers (e.g., pAnimDataTable). Set type to `void*` or a proper pointer type to avoid Hungarian notation false positives and improve decompiler output.

## Cross-Binary Notes
- LogArchiveError and LogSaveParseError are adjacent (0x10077d16, 0x10077d22) — part of a file I/O error logging subsystem. Likely more error logging thunks in the 0x10077dXX range.
