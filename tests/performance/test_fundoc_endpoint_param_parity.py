"""Parity test: fun_doc.py's Ghidra HTTP calls vs the endpoint catalog.

Issue #207: fun-doc was calling Ghidra endpoints with parameter names
the endpoints don't accept — `address` where the endpoint wanted
`function_address`, `function_address` where it wanted `address`, and a
`batch_set_comments` payload shape (`items=[{address,type,text}]`) that
endpoint never had. Those calls silently no-op'd (the archive-apply and
library-code-plate paths), and the LLM workers burned retries on the
same class of mismatch.

This test parses every `ghidra_get(...)` / `ghidra_post(...)` call in
`fun_doc.py` whose path and param dicts are static literals, and asserts
each param name is one the endpoint actually accepts per
`tests/endpoints.json` (the authoritative catalog, regenerated from the
Java `@McpTool` annotations). A mismatch fails the test — param drift
becomes a CI failure instead of a silent worker no-op.

Limitations (deliberate — keeps the test reliable, not clever):
  * Calls with a non-literal path (`ghidra_get(path, ...)`) are skipped.
  * Calls whose `params=` / `data=` is a variable, not a dict literal,
    are skipped (can't introspect statically).
  * Prompt markdown (`fun-doc/prompts/*.md`) is NOT scanned — too much
    prose to parse reliably. The fun_doc.py call sites are the surface
    that matters for fun-doc's own correctness.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest


_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_FUN_DOC = _REPO_ROOT / "fun-doc" / "fun_doc.py"
_ENDPOINTS_JSON = _REPO_ROOT / "tests" / "endpoints.json"

# Params accepted on (almost) every endpoint or supplied by the bridge,
# never declared per-endpoint in the catalog. `program` is the universal
# multi-binary selector; the rest are fun-doc-side niceties.
_UNIVERSAL_PARAMS = {"program"}


def _load_endpoint_params() -> dict[str, set[str]]:
    """path -> set of accepted param names, from the endpoint catalog."""
    data = json.loads(_ENDPOINTS_JSON.read_text(encoding="utf-8"))
    return {
        e["path"]: set(e.get("params", [])) | _UNIVERSAL_PARAMS
        for e in data["endpoints"]
    }


def _dict_literal_keys(node: ast.AST) -> set[str] | None:
    """Return the string keys of a dict literal, or None if not a static
    dict-of-string-keys (variable, **spread, non-str key, etc.)."""
    if not isinstance(node, ast.Dict):
        return None
    keys: set[str] = set()
    for k in node.keys:
        if k is None:  # {**spread}
            return None
        if isinstance(k, ast.Constant) and isinstance(k.value, str):
            keys.add(k.value)
        else:
            return None
    return keys


def _collect_ghidra_calls() -> list[tuple[int, str, set[str]]]:
    """Parse fun_doc.py; return (lineno, path, param_keys) for every
    ghidra_get/ghidra_post call with a literal path and literal param/data
    dicts. param_keys is the union of `params=` and `data=` dict keys.

    Calls that can't be statically introspected are omitted (not failed).
    """
    tree = ast.parse(_FUN_DOC.read_text(encoding="utf-8"))
    out: list[tuple[int, str, set[str]]] = []

    for call in ast.walk(tree):
        if not isinstance(call, ast.Call):
            continue
        fn = call.func
        if not (isinstance(fn, ast.Name) and fn.id in ("ghidra_get", "ghidra_post")):
            continue

        # First positional arg must be a string-literal path.
        if not call.args:
            continue
        path_node = call.args[0]
        if not (isinstance(path_node, ast.Constant) and isinstance(path_node.value, str)):
            continue
        path = path_node.value

        keys: set[str] = set()
        introspectable = False
        for kw in call.keywords:
            if kw.arg in ("params", "data"):
                k = _dict_literal_keys(kw.value)
                if k is not None:
                    keys |= k
                    introspectable = True
                # else: dynamic dict — leave introspectable as-is for the
                # other kw; if neither is literal we just record empty keys.
        # `data=` second positional (ghidra_post(path, data_dict)) — rare,
        # but handle it.
        if len(call.args) >= 2:
            k = _dict_literal_keys(call.args[1])
            if k is not None:
                keys |= k
                introspectable = True

        if introspectable or not call.keywords:
            out.append((path_node.lineno, path, keys))

    return out


def test_fun_doc_py_exists():
    assert _FUN_DOC.is_file(), f"fun_doc.py not found at {_FUN_DOC}"
    assert _ENDPOINTS_JSON.is_file(), f"endpoints.json not found at {_ENDPOINTS_JSON}"


def test_fundoc_calls_use_known_endpoint_params():
    """Every statically-introspectable ghidra_get/ghidra_post call in
    fun_doc.py must use parameter names the target endpoint accepts."""
    endpoint_params = _load_endpoint_params()
    calls = _collect_ghidra_calls()
    assert calls, "no ghidra_get/ghidra_post calls found — parser broke?"

    violations: list[str] = []
    for lineno, path, keys in calls:
        # Endpoints not in the catalog (e.g. /mcp/schema) — can't check.
        if path not in endpoint_params:
            continue
        allowed = endpoint_params[path]
        unknown = keys - allowed
        if unknown:
            violations.append(
                f"  fun_doc.py:{lineno}  {path}  "
                f"uses unknown param(s): {sorted(unknown)}  "
                f"(endpoint accepts: {sorted(allowed)})"
            )

    assert not violations, (
        "fun_doc.py calls Ghidra endpoints with parameter names they don't "
        "accept (#207). Each line below is a silent-no-op waiting to "
        "happen — fix the param name to match tests/endpoints.json:\n"
        + "\n".join(violations)
    )


def test_rename_function_by_address_uses_function_address():
    """Spot-check the specific #207 regression: the archive-apply path
    must call /rename_function_by_address with `function_address`, never
    `address`."""
    calls = _collect_ghidra_calls()
    rename_calls = [(ln, keys) for ln, p, keys in calls
                    if p == "/rename_function_by_address"]
    assert rename_calls, "expected at least one /rename_function_by_address call"
    for lineno, keys in rename_calls:
        assert "address" not in keys, (
            f"fun_doc.py:{lineno} — /rename_function_by_address still uses "
            f"`address`; the endpoint param is `function_address` (#207)"
        )


def test_batch_set_comments_uses_address_not_function_address():
    """The mirror check: /batch_set_comments' address param is `address`,
    NOT `function_address`. fun-doc had the library-code-plate call
    wrong in the opposite direction (#207)."""
    calls = _collect_ghidra_calls()
    bsc_calls = [(ln, keys) for ln, p, keys in calls
                 if p == "/batch_set_comments"]
    assert bsc_calls, "expected at least one /batch_set_comments call"
    for lineno, keys in bsc_calls:
        assert "function_address" not in keys, (
            f"fun_doc.py:{lineno} — /batch_set_comments uses "
            f"`function_address`; the endpoint param is `address` (#207)"
        )
        # The dead `items=[...]` shape must not come back either.
        assert "items" not in keys, (
            f"fun_doc.py:{lineno} — /batch_set_comments uses `items`, an "
            f"API shape this endpoint never had (#207)"
        )
