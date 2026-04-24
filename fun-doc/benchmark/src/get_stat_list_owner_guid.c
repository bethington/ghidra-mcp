/*
 * get_stat_list_owner_guid.c — fun-doc benchmark core-tier function.
 *
 * D2-derived reconstruction: /Mods/PD2-S12/D2Common.dll @ 6fd6dfb0
 * (ordinal 11017; same validated-accessor pattern as
 * get_stat_list_flags, different offset — exercises suite-level
 * state bleed since the StatList magic is shared context.)
 *
 * === REFERENCE: decompilation from Ghidra ===
 *
 *   int GetStatListOwnerGuid(int *pStatList) {
 *     if ((pStatList != (int *)0x0) && (*pStatList == 0x1020304)) {
 *       return pStatList[8];
 *     }
 *     return 0;
 *   }
 *
 * === REFERENCE: existing plate comment ===
 *
 *   Returns the owner GUID field (offset 0x20) from a stat list
 *   structure. Validates the stat list magic signature (0x1020304)
 *   before access. Null-safe: returns 0 if pointer is null or magic
 *   is invalid.
 *   DWORD at offset 0x20 is the owner GUID.
 */

#include <windows.h>

#define STAT_LIST_MAGIC_D2   0x01020304

/**
 * Read the owner GUID from a D2 StatList structure.
 *
 * Returns the 32-bit GUID at offset +0x20 after validating the
 * pointer is non-null and the magic signature at offset 0 matches
 * the StatList tag 0x01020304. Returns 0 on null-pointer or
 * magic-mismatch (corruption guard).
 *
 * @param pStatList  pointer to a StatList structure
 * @return the GUID at offset +0x20, or 0 if invalid
 */
__declspec(dllexport)
int __stdcall get_stat_list_owner_guid(int *pStatList)
{
    if (pStatList == NULL) {
        return 0;
    }
    if (*pStatList != STAT_LIST_MAGIC_D2) {
        return 0;
    }
    return pStatList[8];
}
