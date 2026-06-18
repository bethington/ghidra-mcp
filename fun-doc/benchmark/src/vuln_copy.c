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

__declspec(dllexport)
void __stdcall Vuln_CopyToStack(const char *src)
{
    char buf[32];
    strcpy(buf, src);
}

__declspec(dllexport)
void __stdcall Safe_CopyBounded(const char *src)
{
    char buf[32];
    strncpy(buf, src, sizeof buf - 1);
    buf[31] = 0;
}

__declspec(dllexport)
void __stdcall Vuln_MemcpyUnchecked(const char *src, unsigned int n)
{
    char buf[64];
    memcpy(buf, src, n);
}

__declspec(dllexport)
void __stdcall Safe_MemcpyChecked(const char *src, unsigned int n)
{
    char buf[64];
    if (n < sizeof buf) {
        memcpy(buf, src, n);
    }
}
