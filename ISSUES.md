# GhidraMCP Issues

## 1. ~~`run_ghidra_script` does not support passing script arguments~~ **FIXED**

**Fix**: Added `args` parameter to `run_ghidra_script` endpoint and Python bridge.
Args are passed via `script.setScriptArgs()` before execution, so `getScriptArgs()`
returns them instead of falling through to `askString()`.

---

## 2. ~~`run_script` cannot find scripts by path~~ **FIXED**

**Fix**: `runGhidraScript()` now auto-copies scripts from arbitrary paths to
`~/ghidra_scripts/` before execution, so Ghidra's OSGi class loader can find the
source bundle. The copy is cleaned up after execution.

---

## 3. ~~`save_ghidra_script` and `run_ghidra_script` use different directories~~ **FIXED**

**Fix**: `save_ghidra_script` and `list_ghidra_scripts` now use `~/ghidra_scripts/`
(via `os.path.expanduser("~")`) instead of a CWD-relative `ghidra_scripts/` path.
All script tools now agree on `~/ghidra_scripts/` as the canonical directory.

---

## 4. ~~`list_scripts` returns invalid output (Pydantic validation error)~~ **FIXED**

**Fix**: Changed `list_scripts` to use `safe_get_json()` (returns `str`) instead of
`safe_get()` (returns `list`), matching the `-> str` return type annotation.

---

## 5. `run_ghidra_script` blocks on GUI-prompting scripts with no timeout recovery

**Status**: Partially mitigated.

**Mitigation**: Issue #1 fix (args support) prevents the most common trigger — scripts
calling `askString()` / `askFile()` because they didn't receive arguments. With args
properly passed via `setScriptArgs()`, these scripts no longer fall through to GUI prompts.

**Remaining risk**: Scripts that unconditionally call `askString()` (ignoring args) or
use other interactive Ghidra APIs will still block. A full fix would require either:
- Running scripts on a separate thread with a timeout + `monitor.cancel()`
- Overriding `GhidraScript`'s ask methods to throw instead of showing dialogs

**Workaround**: Always pass args to scripts that expect input. If a dialog appears,
dismiss it manually in the Ghidra GUI.

---

## 6. `run_script_inline` previously wrote corrupted scripts (FIXED)

**Problem**: `parseJsonParams()` did not unescape JSON string escapes (`\n`, `\"`, `\\`),
so inline script code was written with literal backslash-n instead of newlines. Every
inline script failed Java compilation.

**Fix**: Added `unescapeJsonString()` to properly convert JSON escape sequences. Also:
- Inline scripts now use `_mcp_inline_` prefix to avoid collisions with user scripts
- Scripts are written to `~/ghidra_scripts/` (not `/tmp/`) for OSGi compatibility
- Cleanup deletes both `.java` and `.class` files, with `deleteOnExit()` fallback
