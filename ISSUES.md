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

## 6. ~~`run_script_inline` previously wrote corrupted scripts~~ **FIXED**

**Fix**: Added `unescapeJsonString()` to properly convert JSON escape sequences. Also
switched to `_mcp_inline_` prefix, `~/ghidra_scripts/` for OSGi compat, and `.class` cleanup.

---

## 7. ~~`bulk_fuzzy_match` returns list instead of string (Pydantic validation error)~~ **FIXED**

**Fix**: Changed `safe_get()` to `safe_get_json()` in `bridge_mcp_ghidra.py`.

**Problem**: `bulk_fuzzy_match()` returns a Python `list` but the Pydantic output model
expects `str`. This causes a validation error:

```
1 validation error for bulk_fuzzy_matchOutput
result
  Input should be a valid string [type=string_type, input_value=['{"source_program": "fir...}]}'], input_type=list
```

**Reproduction**: Any call to `bulk_fuzzy_match()` with two open programs fails:
```python
bulk_fuzzy_match("firmware_reconstructed.bin", "dongle_working_256k.bin", filter="named", threshold=0.7)
```

**Likely fix**: Same pattern as issue #4 — the endpoint function returns a `list` but needs
to return `str` (JSON string). Use `safe_get_json()` instead of `safe_get()`, or
`json.dumps()` the result before returning.

---

## 8. ~~`find_similar_functions_fuzzy` same list-vs-string validation error~~ **FIXED**

**Fix**: Changed `safe_get()` to `safe_get_json()` in `bridge_mcp_ghidra.py`.

**Problem**: Identical to issue #7 — `find_similar_functions_fuzzy()` returns a `list`
but Pydantic expects `str`.

```
1 validation error for find_similar_functions_fuzzyOutput
result
  Input should be a valid string [type=string_type, input_value=['{"source": {"name": "ve...es": 0, "matches": []}'], input_type=list
```

**Likely fix**: Same as #7 — wrap result with `json.dumps()` or use `safe_get_json()`.

---

## 9. `run_script_inline` OSGi class loading fails for complex scripts

**Status**: Open / intermittent.

**Problem**: Inline scripts that reference service classes (e.g., `ProgramManager`,
`ProjectDataService`) sometimes fail with OSGi `ClassNotFoundException` even though
the same code works fine when saved as a named script via `save_ghidra_script` +
`run_ghidra_script`.

```
GhidraScriptLoadException: The class could not be found.
_mcp_inline_CrossMatchByBytes not found by 38876517 [5]
```

**Workaround**: Save complex scripts with `save_ghidra_script` and run them with
`run_ghidra_script` instead of using `run_script_inline`.

**Likely cause**: The `_mcp_inline_` prefix or the temporary compilation context may
interfere with OSGi bundle resolution for imported packages.

---

## 10. ~~Multi-program tools fail with "Endpoint not found: //switch_program"~~ **FIXED**

**Fix**: Removed trailing `/` from `DEFAULT_GHIDRA_SERVER` (`"http://127.0.0.1:8089/"` →
`"http://127.0.0.1:8089"`). The f-string URLs now produce correct single-slash paths.

---

## 11. ~~Instance not discoverable until a program is opened in CodeBrowser~~ **FIXED**

**Fix**: Made `GhidraMCPPlugin` implement `ApplicationLevelPlugin` (marker interface).
The FrontEndTool now auto-loads the plugin when the project window opens, starting the
MCP server before any program is opened in CodeBrowser.

---

## 12. ~~`add_struct_field` ignores `offset` parameter — always appends~~ **FIXED**

**Fix**: Changed `insertAtOffset` to `replaceAtOffset` (matching `create_struct` pattern).
Struct is grown with padding bytes if needed before replacing at the target offset.

---

## 13. ~~`save_program` fails with "Unable to lock due to active transaction"~~ **FIXED**

**Fix**: Moved `df.save()` out of the `executeWrite` transaction wrapper. Save needs an
exclusive lock which cannot be acquired while a transaction is active — it doesn't need
a transaction of its own since it's a read-only persistence operation.
