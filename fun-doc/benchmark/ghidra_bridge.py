"""Thin Ghidra HTTP client for the benchmark runner.

Wraps the endpoints the benchmark needs: scrape a function's current
state (name / prototype / plate / locals) and restore it to a pristine
snapshot. Separate from fun_doc.py's ghidra_get/ghidra_post because
we don't want the full observability machinery (HTTP event logging,
call-state tracking, worker thread context) for a short synchronous
benchmark run.

No retries, no watchdog — this layer assumes Ghidra is reachable and
bails loudly if it isn't. The benchmark is a short interactive script;
a stuck Ghidra call should surface immediately, not be hidden behind
a 10-second exponential backoff.
"""

from __future__ import annotations

import os
from typing import Any, Optional

import requests


GHIDRA_URL = os.environ.get("GHIDRA_SERVER_URL", "http://127.0.0.1:8089").rstrip("/")


class GhidraBridgeError(RuntimeError):
    """Raised when Ghidra returns an error or is unreachable."""


def _get(path: str, params: Optional[dict] = None, timeout: int = 30) -> Any:
    try:
        r = requests.get(f"{GHIDRA_URL}{path}", params=params or {}, timeout=timeout)
    except requests.exceptions.ConnectionError as e:
        raise GhidraBridgeError(
            f"Ghidra unreachable at {GHIDRA_URL}{path}. "
            f"Is the Ghidra MCP plugin running? ({e})"
        )
    if not r.ok:
        raise GhidraBridgeError(
            f"Ghidra GET {path} -> {r.status_code}: {r.text[:200]}"
        )
    try:
        return r.json()
    except ValueError:
        # Some endpoints return text
        return r.text


def _post(path: str, data: Optional[dict] = None, params: Optional[dict] = None, timeout: int = 30) -> Any:
    try:
        r = requests.post(
            f"{GHIDRA_URL}{path}", json=data or {}, params=params or {}, timeout=timeout
        )
    except requests.exceptions.ConnectionError as e:
        raise GhidraBridgeError(
            f"Ghidra unreachable at {GHIDRA_URL}{path} ({e})"
        )
    if not r.ok:
        raise GhidraBridgeError(
            f"Ghidra POST {path} -> {r.status_code}: {r.text[:200]}"
        )
    try:
        return r.json()
    except ValueError:
        return r.text


# ---------- Discovery ----------


def find_function_by_name(program: str, name: str) -> Optional[str]:
    """Locate a function in the given program by symbol name.

    Returns the hex address string (without 0x prefix), or None if not
    found. Uses /search_functions with an exact name_pattern match.
    """
    resp = _get(
        "/search_functions",
        params={"program": program, "name_pattern": name, "limit": 10},
    )
    if not isinstance(resp, dict):
        return None
    for fn in resp.get("results") or resp.get("functions") or []:
        if fn.get("name") == name:
            addr = fn.get("address") or fn.get("entry_point")
            if addr:
                return str(addr).lower().replace("0x", "")
    return None


# ---------- Scrape ----------


def scrape_function_state(program: str, address: str) -> dict:
    """Capture the current state of a function as a dict suitable for
    scoring against ground truth.

    Returns keys:
      name          — current function name
      return_type   — return type per the function prototype
      parameters    — [{name, type}, ...]
      locals        — [{name, type}, ...]
      plate         — plate comment text (may be "")
      raw           — the raw signature/variables/plate responses for debugging
    """
    sig = _get("/get_function_signature", params={"program": program, "address": address})
    vars_resp = _get(
        "/get_function_variables",
        params={"program": program, "address": address, "limit": 64},
    )
    plate = _get("/get_plate_comment", params={"program": program, "address": address})

    # Normalize signature. Ghidra returns a structured dict; extract
    # name + return + params.
    name = ""
    return_type = ""
    parameters: list[dict] = []
    if isinstance(sig, dict):
        name = sig.get("name", "") or sig.get("function_name", "")
        return_type = sig.get("return_type", "") or sig.get("returnType", "")
        params_raw = sig.get("parameters") or sig.get("params") or []
        for p in params_raw:
            if isinstance(p, dict):
                parameters.append(
                    {
                        "name": p.get("name", ""),
                        "type": p.get("type", "") or p.get("data_type", ""),
                    }
                )

    # Normalize locals. Variables come back as a list; filter to non-
    # parameters (params are already in parameters).
    locals_out: list[dict] = []
    if isinstance(vars_resp, dict):
        for v in vars_resp.get("variables") or vars_resp.get("results") or []:
            if not isinstance(v, dict):
                continue
            # Skip parameters — they're in the signature already
            if v.get("is_parameter") or v.get("storage", "").startswith("Stack[+"):
                # Heuristic: positive stack offsets are parameters on x86 stdcall.
                # Different Ghidra versions mark this differently; tolerate both.
                if v.get("is_parameter"):
                    continue
            locals_out.append(
                {
                    "name": v.get("name", ""),
                    "type": v.get("type", "") or v.get("data_type", ""),
                }
            )

    plate_text = ""
    if isinstance(plate, dict):
        plate_text = plate.get("comment", "") or plate.get("plate", "") or ""
    elif isinstance(plate, str):
        plate_text = plate

    return {
        "name": name,
        "return_type": return_type,
        "parameters": parameters,
        "locals": locals_out,
        "plate": plate_text,
        "raw": {"signature": sig, "variables": vars_resp, "plate": plate},
    }


# ---------- Restore ----------


def capture_pristine(program: str, address: str) -> dict:
    """Capture a pristine snapshot of a function's user-editable state.

    Same shape as scrape_function_state but the snapshot is meant to be
    re-applied via restore_pristine later. Keeps the raw responses so
    we can diff what changed during a benchmark run.
    """
    return scrape_function_state(program, address)


def restore_pristine(program: str, address: str, snapshot: dict) -> None:
    """Re-apply a pristine snapshot to a function in Ghidra.

    Resets: function name, plate comment, function prototype (return
    type + parameter types + parameter names), and local variable
    types. Does NOT attempt to undo struct definitions created during
    the run — those persist across benchmark runs unless manually
    cleaned up. That's a known limitation of the non-.gzf reset path;
    the tradeoff is a dramatically simpler reset mechanism.

    All writes are best-effort: a failure on one restore step prints a
    warning but does not abort the restore of the others.
    """
    # 1. Rename back to pristine name
    pristine_name = snapshot.get("name") or f"FUN_{address}"
    try:
        _post(
            "/rename_function_by_address",
            params={"program": program},
            data={"function_address": address, "new_name": pristine_name},
        )
    except GhidraBridgeError as e:
        print(f"  [restore] rename failed: {e}")

    # 2. Reset plate comment. Ghidra's set_plate_comment with empty
    # string clears the comment. (Confirmed behavior — not the per-
    # function set_comments which needs "" to preserve vs explicit null.)
    try:
        _post(
            "/set_plate_comment",
            params={"program": program},
            data={"address": address, "comment": snapshot.get("plate") or ""},
        )
    except GhidraBridgeError as e:
        print(f"  [restore] plate reset failed: {e}")

    # 3. Restore function prototype. If the snapshot has a return type
    # and parameters, reconstruct the prototype string and apply.
    proto = _build_prototype(snapshot)
    if proto:
        try:
            _post(
                "/set_function_prototype",
                params={"program": program},
                data={"function_address": address, "prototype": proto},
            )
        except GhidraBridgeError as e:
            print(f"  [restore] prototype reset failed: {e}")

    # 4. Restore local variable names + types. We can only set types
    # individually (no batch). rename_variables handles names in bulk.
    if snapshot.get("locals"):
        renames = {
            # Can't roundtrip names without knowing the current names;
            # skip name restoration for this first-pass reset. Ghidra
            # will auto-regenerate names (local_4, local_8, ...) once
            # the types are reset to undefined, which is close enough
            # to pristine for benchmark purposes.
        }
        if renames:
            try:
                _post(
                    "/rename_variables",
                    params={"program": program},
                    data={"function_address": address, "variable_renames": renames},
                )
            except GhidraBridgeError as e:
                print(f"  [restore] variable rename failed: {e}")

        for var in snapshot["locals"]:
            var_name = var.get("name")
            var_type = var.get("type")
            if not var_name or not var_type:
                continue
            try:
                _post(
                    "/set_local_variable_type",
                    params={"program": program},
                    data={
                        "function_address": address,
                        "variable_name": var_name,
                        "new_type": var_type,
                    },
                )
            except GhidraBridgeError as e:
                print(f"  [restore] local type reset failed ({var_name}): {e}")


def _build_prototype(snapshot: dict) -> str:
    """Reconstruct a C-style prototype string from a snapshot."""
    ret = snapshot.get("return_type") or "undefined4"
    name = snapshot.get("name") or "FUN_unknown"
    params = snapshot.get("parameters") or []
    if not params:
        param_str = "void"
    else:
        param_str = ", ".join(
            f"{p.get('type', 'undefined4')} {p.get('name', '')}".strip()
            for p in params
        )
    return f"{ret} {name}({param_str})"
