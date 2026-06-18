/*
 * vuln_exec.c — VulnAnalysisService benchmark fixture: command-injection sink.
 *
 * Vuln_ExecArg plants the pattern the Phase-1 CommandInjectionDetector must
 * flag: an attacker-influenced string reaching system() unmodified.
 * Safe_ExecLiteral passes a string literal and MUST NOT be flagged.
 * Compiled into Benchmark.dll; graded against truth/vuln_exec.truth.yaml.
 */

#include <windows.h>
#include <stdlib.h>

__declspec(dllexport)
int __stdcall Vuln_ExecArg(const char *cmd)
{
    return system(cmd);
}

__declspec(dllexport)
int __stdcall Safe_ExecLiteral(void)
{
    return system("/bin/true");
}
