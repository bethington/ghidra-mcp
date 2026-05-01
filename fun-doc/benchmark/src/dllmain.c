/*
 * dllmain.c — Boilerplate DLL entry point, isolated here so the
 * archetype .c files (crc16.c, state_machine.c, etc.) contain only
 * the function they're meant to exercise. DllMain is deliberately
 * trivial; it carries no ground-truth yaml and is excluded from
 * scoring.
 */

#include <windows.h>

BOOL WINAPI DllMain(HINSTANCE hinstance, DWORD reason, LPVOID reserved)
{
    (void)hinstance;
    (void)reason;
    (void)reserved;
    return TRUE;
}
