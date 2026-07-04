# ScyllaHide (third-party) — for the PD2-S12 conformance oracle

`start-oracle.ps1` injects ScyllaHide into PD2's `Game.exe` so the game's
**API-based anti-debug** (`IsDebuggerPresent`, `NtQueryInformationProcess`,
`ThreadHideFromDebugger`, code-checksum breakpoint detection, …) is neutralized
and **software breakpoints actually stick** — which the debugger (and
`call_function`, which sets a return-catch breakpoint) depends on.

The binaries are **not committed** (third-party, gitignored). Drop these files here
(32-bit target = PD2 `Game.exe` is x86):

    InjectorCLIx86.exe
    HookLibraryx86.dll
    scylla_hide.ini

Get them from the official release: https://github.com/x64dbg/ScyllaHide/releases
(the "Generic"/root injector build). `start-oracle.ps1` defaults `SCYLLAHIDE_DIR`
to this folder; override via `.env` (`SCYLLAHIDE_DIR=...`) if you keep them elsewhere.

Note: ScyllaHide handles the API/breakpoint anti-debug; the debugger's
`/debugger/pass_exceptions` handles the separate `INT3` exception flood. Both are
needed — they defend different tricks.
