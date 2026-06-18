/*
 * vuln_alloc.c — VulnAnalysisService benchmark fixture: integer overflow
 * into allocator size.
 *
 * Vuln_* functions plant patterns the Phase-1 IntegerOverflowAllocDetector
 * must flag: an unchecked attacker-influenced integer feeding a multiply
 * or add expression whose result becomes the size argument of malloc().
 * Safe_AllocConst passes a compile-time constant and MUST NOT be flagged.
 * Compiled into Benchmark.dll; graded against truth/vuln_alloc.truth.yaml.
 */

#include <windows.h>
#include <stdlib.h>

__declspec(dllexport)
void * __stdcall Vuln_AllocMul(unsigned int count)
{
    return malloc(count * 16);
}

__declspec(dllexport)
void * __stdcall Vuln_AllocAdd(unsigned int len)
{
    return malloc(len + 32);
}

__declspec(dllexport)
void * __stdcall Safe_AllocConst(void)
{
    return malloc(128);
}
