# Ghidra scripts

User-installable Ghidra scripts that pair with GhidraMCP workflows.

## Installation

Copy any `.java` file in this directory into your Ghidra user scripts
directory:

| Platform | Path |
|---|---|
| Windows | `%USERPROFILE%\ghidra_scripts\` |
| macOS / Linux | `~/ghidra_scripts/` |

In Ghidra: `Window > Script Manager > refresh`. The script appears under
the category in its `@category` annotation.

## Scripts

### `ImportMSDLPDB.java`

Downloads the matching PDB for the current program from Microsoft's symbol
server and applies it via Ghidra's PDB Universal Analyzer. Pairs with
`fun-doc/library_code_detector.py` — PDB handles symbols Microsoft
published (CRT / MSVCRT / MFC), the heuristic detector catches the rest.

One-time Ghidra setup: `Edit > Symbol Server Config` → point at
`https://msdl.microsoft.com/download/symbols` with a local cache dir.

Skips gracefully (returns an empty JSON result) when the binary has no
`PdbInformation` header (no `/DEBUG` link flag, common for third-party
DLLs).
