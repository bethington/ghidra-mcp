/*
 * get_stat_list_flags.c — fun-doc benchmark core-tier function.
 *
 * D2-derived reconstruction: /Mods/PD2-S12/D2Common.dll @ 6fd6e170
 * (ordinal 10198 per memory/structs.md; MSVC 6.0 SP6-compiled original)
 *
 * The real D2 StatList magic is 0x01020304 and flags live at offset
 * 0x10. This reconstruction matches that layout. Deliberately kept as
 * raw int-pointer arithmetic (pStatList[4]) to mirror the decompile
 * rather than introducing a StatList struct — the D2 original was
 * written before struct definitions existed, and Ghidra's decompile
 * of the real function produces the same pattern.
 *
 * === REFERENCE: decompilation from Ghidra ===
 *
 *   int GetStatListFlags(int *pStatList) {
 *     if ((pStatList != (int *)0x0) && (*pStatList == 0x1020304)) {
 *       return pStatList[4];
 *     }
 *     return 0;
 *   }
 *
 * === REFERENCE: existing plate comment ===
 *
 *   Returns the flags field (offset 0x10) from a stat list structure.
 *   Validates the stat list magic signature (0x1020304) before access.
 *   stat list +0x10 holds the flags bitfield.
 *
 *   Algorithm:
 *     1. Check if pStatList is null
 *     2. Validate magic: pStatList[0] must equal 0x1020304
 *     3. Return pStatList[4] (offset 0x10)
 *     4. Return 0 if null or invalid magic
 */

#include <windows.h>

#define STAT_LIST_MAGIC_D2   0x01020304

/**
 * Read the flags bitfield from a D2 StatList structure.
 *
 * Returns the 32-bit flags value at offset 0x10 after validating the
 * pointer is non-null and the magic signature at offset 0x00 matches
 * the StatList tag 0x01020304. Returns 0 on null-pointer or magic-
 * mismatch (corruption guard).
 *
 * @param pStatList  pointer to a StatList structure
 * @return the flags at offset 0x10, or 0 if invalid
 */
__declspec(dllexport)
int __stdcall get_stat_list_flags(int *pStatList)
{
    if (pStatList == NULL) {
        return 0;
    }
    if (*pStatList != STAT_LIST_MAGIC_D2) {
        return 0;
    }
    return pStatList[4];
}
