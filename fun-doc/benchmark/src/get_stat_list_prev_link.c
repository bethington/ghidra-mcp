/*
 * get_stat_list_prev_link.c — fun-doc benchmark core-tier function.
 *
 * D2-derived reconstruction: /Mods/PD2-S12/D2Common.dll @ 6fd6dd20
 * (ordinal 10284; same validated-accessor pattern as the other
 * StatList getters but reads the prev_link pointer at offset +0x34.
 * Semantically distinct from flags / owner_guid — this is a linked-
 * list next-pointer, which fun-doc should ideally recognize in the
 * plate as part of a linked-list traversal pattern.)
 *
 * === REFERENCE: decompilation from Ghidra ===
 *
 *   int GetStatListPrevLink(int *pStatList) {
 *     if ((pStatList != (int *)0x0) && (*pStatList == 0x1020304)) {
 *       return pStatList[0xd];
 *     }
 *     return 0;
 *   }
 *
 * === REFERENCE: existing plate comment ===
 *
 *   Returns the previous link field (offset 0x34) from a stat list
 *   structure. Validates the stat list magic signature (0x1020304)
 *   before access. Null-safe: returns 0 if pointer is null or magic
 *   is invalid.
 *   DWORD at offset 0x34 is the previous link pointer.
 */

#include <windows.h>

#define STAT_LIST_MAGIC_D2   0x01020304

/**
 * Read the prev_link pointer from a D2 StatList structure.
 *
 * Returns the 32-bit pointer at offset +0x34 after validating
 * pStatList is non-null and its magic signature at offset 0
 * matches 0x01020304. Part of a linked-list traversal: following
 * this pointer repeatedly walks backwards through the stat list
 * chain. Returns 0 on null or corruption.
 *
 * @param pStatList  pointer to a StatList structure
 * @return the prev-link pointer at +0x34, or 0 if invalid
 */
__declspec(dllexport)
int __stdcall get_stat_list_prev_link(int *pStatList)
{
    if (pStatList == NULL) {
        return 0;
    }
    if (*pStatList != STAT_LIST_MAGIC_D2) {
        return 0;
    }
    return pStatList[0xd];
}
