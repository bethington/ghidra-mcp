/*
 * vuln_copy.c — VulnAnalysisService benchmark fixture: unbounded copy sinks.
 *
 * Vuln_* functions plant patterns the Phase-1 UnboundedCopyDetector must
 * flag: an attacker-influenced source flowing into a fixed-size stack
 * buffer via strcpy / memcpy with no bound (or an unchecked bound). Safe_*
 * twins apply a correct bound and MUST NOT be flagged. Compiled into
 * Benchmark.dll; graded against truth/vuln_copy.truth.yaml.
 */

#include <windows.h>
#include <string.h>

/* VC6 /O2 implies /Oi which inlines strcpy/memcpy as rep movs* — that defeats
 * the SinkCatalog (no CALL → no SinkCallSite). Force the function-call form. */
#pragma function(strcpy, memcpy)

volatile char g_vuln_copy_sink;

__declspec(dllexport)
void __stdcall Vuln_CopyToStack(const char *src)
{
    char buf[32];
    strcpy(buf, src);
    g_vuln_copy_sink = buf[0];
}

__declspec(dllexport)
void __stdcall Safe_CopyBounded(const char *src)
{
    char buf[32];
    strncpy(buf, src, sizeof buf - 1);
    buf[31] = 0;
    g_vuln_copy_sink = buf[0];
}

__declspec(dllexport)
void __stdcall Vuln_MemcpyUnchecked(const char *src, unsigned int n)
{
    char buf[64];
    memcpy(buf, src, n);
    g_vuln_copy_sink = buf[0];
}

__declspec(dllexport)
void __stdcall Safe_MemcpyChecked(const char *src, unsigned int n)
{
    char buf[64];
    if (n < sizeof buf) {
        memcpy(buf, src, n);
    }
    g_vuln_copy_sink = buf[0];
}
