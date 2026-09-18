"""Back-compat parameter spellings, read from the `@Param` annotations.

Why this file has to exist
--------------------------
``@Param`` carries an ``aliases`` array: alternative spellings the runtime
resolver accepts for the same parameter (``AnnotationScanner`` tries the
canonical name first, then each alias, for both query and body values). It is
how the 7.0.0 consolidation kept older callers working while the canonical
names were standardised.

``AnnotationScanner.ParamDescriptor.toJson`` does **not** emit them. So
``/mcp/schema`` -- and therefore ``tests/conformance/snapshots/mcp_schema.snap``,
which is what the offline tier checks calls against -- advertises only the
canonical name. Anything reasoning about "is this a parameter the server
accepts?" from the schema alone will call a perfectly valid alias an unknown
parameter.

That matters here in exactly one direction: it would manufacture false
contract breaches. ``/get_function_labels`` declares
``@Param(value = "name", aliases = {"function", "address", "function_address"})``,
so a caller sending ``address=`` is served correctly by the real plugin, and
recording it as a breach would be wrong.

So the annotations are read directly. They are the source of truth -- PR #459
settled that, and made ``RegenerateEndpointsJson`` stop copying stale catalog
values forward -- and reading them is what the Java scanner does too. This is a
narrower read than the scanner's: only ``@McpTool`` paths, only ``@Param``
names and their ``aliases``.

Failure mode is deliberately loud. If the parse breaks, it returns *fewer*
aliases, every alias becomes an unknown parameter again, and the contract
ratchet goes red. It cannot fail in the direction of excusing a real breach --
except by inventing an alias, which
``tests/offline/test_param_aliases.py`` pins against known-good expectations.

The real fix is upstream: emit ``aliases`` in the schema so every consumer --
the bridge, the docs, this tier -- can see them. Until then, this module is the
seam.
"""

from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
JAVA_ROOT = REPO_ROOT / "src" / "main" / "java" / "com" / "xebyte"

# `@McpTool(` ... capture through the annotation's own closing paren is done by
# brace balancing below; this only finds where one starts.
_MCP_TOOL = re.compile(r"@McpTool\s*\(")
_PATH_ATTR = re.compile(r'path\s*=\s*"([^"]+)"')
_METHOD_ATTR = re.compile(r'method\s*=\s*"([^"]+)"')
_PARAM = re.compile(r"@Param\s*\(")
_VALUE_ATTR = re.compile(r'value\s*=\s*"([^"]+)"')
_ALIASES_ATTR = re.compile(r"aliases\s*=\s*\{([^}]*)\}")
_QUOTED = re.compile(r'"([^"]*)"')


def _balanced(text: str, open_at: int) -> tuple[str, int]:
    """Return the text inside the parens opening at ``open_at``, and the index
    just past the matching close paren.

    String literals are skipped so a ``)`` inside a description does not end
    the block early -- several descriptions contain them.
    """
    depth = 0
    i = open_at
    start = open_at + 1
    in_string = False
    while i < len(text):
        ch = text[i]
        if in_string:
            if ch == "\\":
                i += 2
                continue
            if ch == '"':
                in_string = False
        elif ch == '"':
            in_string = True
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return text[start:i], i + 1
        i += 1
    return text[start:], len(text)


def _params_of_signature(signature: str) -> dict[str, tuple[str, ...]]:
    """Map canonical parameter name -> aliases, for one method signature."""
    out: dict[str, tuple[str, ...]] = {}
    for match in _PARAM.finditer(signature):
        block, _ = _balanced(signature, match.end() - 1)
        name_match = _VALUE_ATTR.search(block)
        if name_match is None:
            # `@Param("x")` positional form.
            positional = _QUOTED.search(block)
            if positional is None:
                continue
            name = positional.group(1)
        else:
            name = name_match.group(1)
        aliases_match = _ALIASES_ATTR.search(block)
        aliases = (
            tuple(_QUOTED.findall(aliases_match.group(1))) if aliases_match else ()
        )
        out[name] = aliases
    return out


def _scan_source(text: str) -> dict[tuple[str, str], dict[str, tuple[str, ...]]]:
    routes: dict[tuple[str, str], dict[str, tuple[str, ...]]] = {}
    for match in _MCP_TOOL.finditer(text):
        annotation, after = _balanced(text, match.end() - 1)
        path_match = _PATH_ATTR.search(annotation)
        if path_match is None:
            continue
        method_match = _METHOD_ATTR.search(annotation)
        method = (method_match.group(1) if method_match else "GET").upper()

        # The method signature is the next paren group after the annotation.
        open_paren = text.find("(", after)
        if open_paren == -1:
            continue
        # Guard against running into the following annotation or a stray paren
        # in a comment: the signature must start before the method body does.
        brace = text.find("{", after)
        if brace != -1 and brace < open_paren:
            continue
        signature, _ = _balanced(text, open_paren)
        routes[(path_match.group(1), method)] = _params_of_signature(signature)
    return routes


@lru_cache(maxsize=1)
def load_param_aliases() -> dict[tuple[str, str], dict[str, str]]:
    """``(path, METHOD) -> {alias: canonical name}`` for every ``@McpTool``.

    Only routes that actually declare an alias appear with a non-empty map.
    """
    result: dict[tuple[str, str], dict[str, str]] = {}
    for java in sorted(JAVA_ROOT.rglob("*.java")):
        text = java.read_text(encoding="utf-8")
        if "@McpTool" not in text:
            continue
        for route, params in _scan_source(text).items():
            mapping = result.setdefault(route, {})
            for canonical, aliases in params.items():
                for alias in aliases:
                    mapping[alias] = canonical
    return result


def aliases_for(path: str, method: str) -> dict[str, str]:
    """``{alias: canonical}`` accepted by ``METHOD path``. Empty when none."""
    return load_param_aliases().get((path, method.upper()), {})
