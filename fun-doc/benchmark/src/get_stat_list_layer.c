/*
 * get_stat_list_layer.c — fun-doc benchmark core-tier function.
 *
 * D2-derived reconstruction: /Mods/PD2-S12/D2Common.dll @ 6fd68240
 * (Ghidra names this function GetStatListOwnerType in PD2-S12; the
 * decompile reads offset +0x04 which is actually the layer field per
 * memory/structs.md. This reconstruction treats the function as the
 * layer accessor based on what it ACTUALLY reads, not what Ghidra
 * calls it — the benchmark scores against our C, not Ghidra's name.)
 *
 * Structural variety: unlike the other StatList accessors in this
 * suite, this one has NO null-check and NO magic validation. It
 * directly dereferences pStatList+4 and returns the DWORD. This is
 * the raw-read pattern and exercises whether fun-doc can distinguish
 * validated from unvalidated accessors in its generated plate.
 *
 * === REFERENCE: decompilation from Ghidra ===
 *
 *   dword GetStatListOwnerType(int pStatList) {
 *     return *(dword *)(pStatList + 4);
 *   }
 *
 * === REFERENCE: existing plate comment ===
 *
 *   Returns the owner type field from a StatList structure.
 *   Algorithm:
 *     1. Read DWORD at offset +4 from StatList
 *     2. Return value directly
 */

#include <windows.h>

/**
 * Read the layer field from a D2 StatList structure.
 *
 * Returns the 32-bit DWORD at offset +0x04 (the StatList's layer
 * index). Performs NO validation — assumes the caller has already
 * verified pStatList is non-null and points at a well-formed
 * StatList. Callers that want the safety of magic-number validation
 * should use a validated variant instead.
 *
 * @param pStatList  pointer to a StatList structure
 * @return the DWORD at offset +0x04 (layer index)
 */
__declspec(dllexport)
unsigned int __stdcall get_stat_list_layer(const unsigned char *pStatList)
{
    return *(const unsigned int *)(pStatList + 4);
}
