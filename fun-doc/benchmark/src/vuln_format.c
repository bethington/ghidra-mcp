/*
 * vuln_format.c — VulnAnalysisService benchmark fixture: format-string sink.
 *
 * Each Vuln_* function plants exactly one pattern that the Phase-1
 * FormatStringDetector must flag (non-literal format argument reaching a
 * printf-family sink). Each Safe_* twin is the corrected form and MUST NOT
 * be flagged. Compiled into Benchmark.dll alongside the fun-doc archetype
 * functions; the vuln benchmark scorer reads truth/vuln_format.truth.yaml
 * to grade detector output.
 */

#include <windows.h>
#include <stdio.h>

__declspec(dllexport)
void __stdcall Vuln_FormatFromArg(const char *user)
{
    printf(user);
}

__declspec(dllexport)
void __stdcall Safe_FormatLiteral(const char *user)
{
    printf("%s", user);
}
