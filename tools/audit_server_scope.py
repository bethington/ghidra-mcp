"""Derive which server(s) serve each endpoint: the GUI plugin, the headless one, or both.

GhidraMCP ships two HTTP servers built from the same service layer:

* ``com.xebyte.GhidraMCPPlugin`` — the Ghidra GUI plugin (FrontEnd tool)
* ``com.xebyte.headless.GhidraMCPHeadlessServer`` — the standalone headless server

They do **not** expose the same routes. Each builds its own ``AnnotationScanner``
from a different list of service instances, and each hand-registers a different
list of legacy routes via ``ManualToolDescriptors.addAll(...)``. So a tool that
works in the GUI can 404 headless, and vice versa — which is exactly the question
a headless user asks first (see issue #441, and the connection-triage guide in
#442 that pointed headless users at ``/mcp/health`` and ``/mcp/instance_info``,
neither of which the headless server registers).

Nothing measured that split. ``tests/endpoints.json`` recorded one flat list, and
``.github/workflows/release.yml`` "derived" GUI/headless counts by grepping
``EndpointRegistry.java`` — a file deleted on 2026-07-25 — which is why v6.0.0's
release notes claim ``Headless Endpoints: 1``.

This script reproduces both servers' registration from the Java sources
directly (no Maven, no Ghidra, no JVM), so the split is measurable from a clean
checkout and re-derivable by anyone::

    python -m tools.audit_server_scope            # human-readable report
    python -m tools.audit_server_scope --json     # machine-readable
    python -m tools.audit_server_scope --check    # exit 1 if the catalog drifts
    python -m tools.audit_server_scope --write    # stamp `servers` onto the catalog

Exit code is 0 when the catalog's ``servers`` field agrees with the sources, 1
when it drifts (``--check``) or when an endpoint reaches neither server.

Derivation, mirroring what each server does at startup
------------------------------------------------------

1. **Annotation-scanned routes.** Parse the ``new AnnotationScanner(...)``
   argument list in each server, resolve every argument expression to the
   declared type of the field or getter it names, and treat that set of service
   classes as the server's scanned surface. Every ``@McpTool`` method on a class
   in that set is served by that server.
2. **Hand-registered routes.** Parse each server's
   ``ManualToolDescriptors.addAll(scanner, ...)`` path list. Those routes are
   registered directly via ``createContext``/``safeContext``.

A route's scope is the union of both mechanisms — ``/open_project`` and
``/server/status`` are GUI-hand-registered *and* ``@McpTool`` methods on
``HeadlessManagementService``, so they are correctly ``both`` even though no
single mechanism covers both servers.

Nothing here is hand-declared per endpoint. Adding a service to a server, or a
path to an ``addAll`` call, moves the catalog on the next run — the scanner
always wins, the same rule ``RegenerateEndpointsJson`` follows for category.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

GUI_SERVER = "src/main/java/com/xebyte/GhidraMCPPlugin.java"
HEADLESS_SERVER = "src/main/java/com/xebyte/headless/GhidraMCPHeadlessServer.java"
HEADLESS_HANDLER = "src/main/java/com/xebyte/headless/HeadlessEndpointHandler.java"

#: Scope values written into ``tests/endpoints.json``. Ordered so the emitted
#: array is stable regardless of discovery order.
SERVERS = ("gui", "headless")

# --- Java source parsing -------------------------------------------------

_TOOL_START_RE = re.compile(r"@McpTool\s*\(")
_PATH_RE = re.compile(r"\bpath\s*=\s*\"([^\"]*)\"")
_METHOD_RE = re.compile(r"\bmethod\s*=\s*\"([^\"]*)\"")

# `new AnnotationScanner(` ... `)` — the argument list each server hands the scanner.
_SCANNER_NEW_RE = re.compile(r"new\s+AnnotationScanner\s*\(")

# `ManualToolDescriptors.addAll(scanner, "/a", "/b", ...)`, possibly package-qualified.
_ADD_ALL_RE = re.compile(
    r"(?:com\.xebyte\.core\.)?ManualToolDescriptors\.addAll\s*\("
)

# Literal route registration, for the "registered but not catalogued" report.
# The GUI uses `server.createContext("/x", ...)`; headless wraps it in
# `safeContext("/x", ...)`. Mirrors ManualToolDescriptorsParityTest's patterns.
_LITERAL_CONTEXT_RE = re.compile(
    r"(?:(?:server|httpServer)\.createContext|safeContext)\s*\(\s*\"([^\"]+)\""
)

# A field declaration: `private final com.xebyte.core.ListingService listingService;`
# or `private HeadlessManagementService managementService;`
_FIELD_RE = re.compile(
    r"\bprivate\s+(?:static\s+)?(?:final\s+)?"
    r"([A-Za-z_][\w.]*)\s+([A-Za-z_]\w*)\s*[;=]"
)

# A getter: `public com.xebyte.core.ListingService getListingService() {`
_GETTER_RE = re.compile(
    r"\bpublic\s+([A-Za-z_][\w.]*)\s+(get[A-Za-z_]\w*)\s*\(\s*\)"
)

#: `class FrontEndProgramProvider implements ProgramProvider` / `... extends X`.
_IMPLEMENTS_PROVIDER_RE = re.compile(
    r"\bclass\s+\w+[^{]*?\b(?:implements|extends)\b[^{]*?\bProgramProvider\b",
    re.DOTALL,
)


def _repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _strip_comments(text: str) -> str:
    """Blank out comment lines so documented code is not parsed as real code.

    Covers ``//`` and javadoc continuation lines (``*``). Both matter here:
    ``McpTool.java``'s javadoc contains a worked ``@McpTool(path = ...)``
    example, and both servers carry long ``//`` comments immediately above
    their ``addAll(...)`` calls that quote route names.
    """
    out = []
    for line in text.splitlines():
        stripped = line.lstrip()
        if stripped.startswith("//") or stripped.startswith("*") or stripped.startswith("/*"):
            out.append("")
        else:
            # Trailing `// ...` on a code line.
            out.append(_strip_trailing_comment(line))
    return "\n".join(out)


def _strip_trailing_comment(line: str) -> str:
    in_str = False
    escaped = False
    for i, ch in enumerate(line):
        if in_str:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_str = False
        elif ch == '"':
            in_str = True
        elif ch == "/" and line[i + 1 : i + 2] == "/":
            return line[:i]
    return line


def _balanced(text: str, open_paren: int) -> tuple[str, int]:
    """Return the text inside the parens starting at ``open_paren``, and the index past them."""
    depth = 0
    i = open_paren
    in_str = False
    escaped = False
    while i < len(text):
        ch = text[i]
        if in_str:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_str = False
        elif ch == '"':
            in_str = True
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return text[open_paren + 1 : i], i + 1
        i += 1
    raise ValueError("unterminated paren group")


def _split_args(body: str) -> list[str]:
    """Split a Java argument list on top-level commas."""
    args: list[str] = []
    depth = 0
    in_str = False
    escaped = False
    current: list[str] = []
    for ch in body:
        if in_str:
            current.append(ch)
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
            current.append(ch)
        elif ch in "([{":
            depth += 1
            current.append(ch)
        elif ch in ")]}":
            depth -= 1
            current.append(ch)
        elif ch == "," and depth == 0:
            args.append("".join(current).strip())
            current = []
        else:
            current.append(ch)
    tail = "".join(current).strip()
    if tail:
        args.append(tail)
    return args


def _simple(type_name: str) -> str:
    """`com.xebyte.core.ListingService` -> `ListingService`."""
    return type_name.rsplit(".", 1)[-1]


def scan_annotations(src_root: Path) -> dict[str, dict]:
    """Map endpoint path -> ``{class, method, source}`` for every ``@McpTool``.

    Covers every Java source under ``src/main/java/com/xebyte``, scanned or not;
    whether a class is actually registered is decided later by
    :func:`server_service_classes`.
    """
    found: dict[str, dict] = {}
    for java in sorted(src_root.rglob("*.java")):
        raw = java.read_text(encoding="utf-8")
        if "@McpTool(" not in raw:
            continue
        text = _strip_comments(raw)
        simple_name = java.stem
        pos = 0
        while True:
            m = _TOOL_START_RE.search(text, pos)
            if m is None:
                break
            body, pos = _balanced(text, m.end() - 1)
            path_m = _PATH_RE.search(body)
            if path_m is None:
                # @McpTool with no path= is the annotation's own javadoc example.
                continue
            method_m = _METHOD_RE.search(body)
            found[path_m.group(1)] = {
                "path": path_m.group(1),
                "method": method_m.group(1) if method_m else "GET",
                "class": simple_name,
                "source": java.as_posix(),
            }
    return found


def _declared_types(text: str) -> tuple[dict[str, str], dict[str, str]]:
    """Return ``(field_name -> type, getter_name -> return type)`` for one source file."""
    fields = {m.group(2): _simple(m.group(1)) for m in _FIELD_RE.finditer(text)}
    getters = {m.group(2): _simple(m.group(1)) for m in _GETTER_RE.finditer(text)}
    return fields, getters


def _provider_classes(src_root: Path) -> set[str]:
    """Class names that are ``ProgramProvider`` implementations, read from source.

    The scanner's leading argument is a provider, not a service — but the servers
    pass it as its concrete type (``FrontEndProgramProvider``), so excluding the
    literal name ``ProgramProvider`` is not enough. Derived rather than listed so a
    renamed or added provider needs no edit here.
    """
    providers = {"ProgramProvider"}
    for java in sorted(src_root.rglob("*.java")):
        text = java.read_text(encoding="utf-8")
        if "ProgramProvider" not in text:
            continue
        if _IMPLEMENTS_PROVIDER_RE.search(_strip_comments(text)):
            providers.add(java.stem)
    return providers


def server_service_classes(repo: Path, server_rel: str) -> list[str]:
    """Resolve one server's ``new AnnotationScanner(...)`` arguments to service class names.

    Argument expressions come in two shapes in practice:

    * a bare field reference (``listingService``, ``managementService``) — resolved
      against the server class's own field declarations;
    * a delegating getter (``endpointHandler.getListingService()``) — resolved
      against the return type declared on ``HeadlessEndpointHandler``.

    The scanner's leading ``ProgramProvider`` argument is dropped: it is the
    constructor's provider parameter, not a service to reflect over.
    """
    text = _strip_comments((repo / server_rel).read_text(encoding="utf-8"))
    m = _SCANNER_NEW_RE.search(text)
    if m is None:
        raise ValueError(f"no `new AnnotationScanner(` found in {server_rel}")
    body, _ = _balanced(text, m.end() - 1)

    own_fields, own_getters = _declared_types(text)
    handler_text = _strip_comments((repo / HEADLESS_HANDLER).read_text(encoding="utf-8"))
    _, handler_getters = _declared_types(handler_text)
    providers = _provider_classes(repo / "src" / "main" / "java" / "com" / "xebyte")

    classes: list[str] = []
    for arg in _split_args(body):
        resolved = _resolve_arg(arg, own_fields, own_getters, handler_getters)
        if resolved is None:
            raise ValueError(
                f"{server_rel}: cannot resolve AnnotationScanner argument {arg!r} to a "
                "declared type. Teach tools/audit_server_scope._resolve_arg about it "
                "rather than hand-listing the service."
            )
        if resolved in providers:
            continue
        classes.append(resolved)
    return classes


def _resolve_arg(
    arg: str,
    own_fields: dict[str, str],
    own_getters: dict[str, str],
    handler_getters: dict[str, str],
) -> str | None:
    arg = arg.strip()
    if arg in own_fields:
        return own_fields[arg]
    if arg in own_getters:
        return own_getters[arg]
    call = re.fullmatch(r"(?:\w+\.)?(get[A-Za-z_]\w*)\s*\(\s*\)", arg)
    if call:
        name = call.group(1)
        return handler_getters.get(name) or own_getters.get(name)
    new = re.fullmatch(r"new\s+([A-Za-z_][\w.]*)\s*\(.*\)", arg, re.DOTALL)
    if new:
        return _simple(new.group(1))
    return None


def server_manual_paths(repo: Path, server_rel: str) -> list[str]:
    """The literal path list one server passes to ``ManualToolDescriptors.addAll``."""
    text = _strip_comments((repo / server_rel).read_text(encoding="utf-8"))
    m = _ADD_ALL_RE.search(text)
    if m is None:
        return []
    body, _ = _balanced(text, m.end() - 1)
    # First argument is the scanner; the rest are string literals.
    return [
        a[1:-1]
        for a in _split_args(body)[1:]
        if len(a) >= 2 and a.startswith('"') and a.endswith('"')
    ]


def server_literal_contexts(repo: Path, server_rel: str) -> list[str]:
    """Routes one server registers with a literal path via createContext/safeContext.

    Not the same question as :func:`server_manual_paths`: ``addAll`` says what the
    server *publishes in /mcp/schema*, this says what it will actually *answer*.
    The two agree today except for ``/mcp/instance_info``, which the GUI answers
    but deliberately keeps out of the schema (it is discovery metadata, not a
    tool) -- and which the connection-triage guide nonetheless tells headless
    users to curl.
    """
    text = _strip_comments((repo / server_rel).read_text(encoding="utf-8"))
    seen = dict.fromkeys(m.group(1) for m in _LITERAL_CONTEXT_RE.finditer(text))
    return list(seen)


# --- Scope computation ---------------------------------------------------


def derive_scope(repo: Path | None = None) -> dict:
    """Compute ``path -> ["gui"], ["headless"], or ["gui", "headless"]`` from the sources."""
    repo = repo or _repo_root()
    src_root = repo / "src" / "main" / "java" / "com" / "xebyte"

    annotations = scan_annotations(src_root)

    gui_classes = server_service_classes(repo, GUI_SERVER)
    headless_classes = server_service_classes(repo, HEADLESS_SERVER)
    gui_manual = server_manual_paths(repo, GUI_SERVER)
    headless_manual = server_manual_paths(repo, HEADLESS_SERVER)

    per_server_classes = {"gui": set(gui_classes), "headless": set(headless_classes)}
    per_server_manual = {"gui": set(gui_manual), "headless": set(headless_manual)}

    scope: dict[str, list[str]] = {}
    mechanism: dict[str, dict[str, str]] = {}
    for name in SERVERS:
        for path, ann in annotations.items():
            if ann["class"] in per_server_classes[name]:
                scope.setdefault(path, []).append(name)
                mechanism.setdefault(path, {})[name] = f"@McpTool on {ann['class']}"
        for path in per_server_manual[name]:
            if name not in scope.setdefault(path, []):
                scope[path].append(name)
            mechanism.setdefault(path, {})[name] = "hand-registered"

    # Keep the emitted array in SERVERS order for a stable diff.
    scope = {p: [s for s in SERVERS if s in v] for p, v in scope.items()}

    unreachable = sorted(
        p for p, ann in annotations.items() if not scope.get(p)
    )
    # A class carrying @McpTool that no server hands to a scanner.
    scanned_classes = per_server_classes["gui"] | per_server_classes["headless"]
    orphan_classes = sorted(
        {a["class"] for a in annotations.values()} - scanned_classes
    )

    # Answered by a server but absent from /mcp/schema (and so from the catalog
    # and the bridge's tool discovery). Reported, not stamped.
    literal = {
        name: set(server_literal_contexts(repo, rel))
        for name, rel in (("gui", GUI_SERVER), ("headless", HEADLESS_SERVER))
    }
    undeclared = {
        name: sorted(paths - set(scope) - per_server_manual[name])
        for name, paths in literal.items()
    }

    return {
        "gui_service_classes": sorted(per_server_classes["gui"]),
        "headless_service_classes": sorted(per_server_classes["headless"]),
        "gui_manual_paths": sorted(per_server_manual["gui"]),
        "headless_manual_paths": sorted(per_server_manual["headless"]),
        "gui_literal_contexts": sorted(literal["gui"]),
        "headless_literal_contexts": sorted(literal["headless"]),
        "undeclared_routes": undeclared,
        "annotation_endpoints": len(annotations),
        "scope": dict(sorted(scope.items())),
        "mechanism": mechanism,
        "unreachable": unreachable,
        "orphan_classes": orphan_classes,
    }


def catalog_path(repo: Path) -> Path:
    return repo / "tests" / "endpoints.json"


def load_catalog(repo: Path) -> dict:
    return json.loads(catalog_path(repo).read_text(encoding="utf-8"))


def audit(repo: Path | None = None) -> dict:
    repo = repo or _repo_root()
    derived = derive_scope(repo)
    catalog = load_catalog(repo)
    scope = derived["scope"]

    missing: list[str] = []        # in the catalog, no derivable scope
    unstamped: list[str] = []      # in the catalog, no `servers` field yet
    drift: list[dict] = []         # `servers` disagrees with the sources
    for entry in catalog["endpoints"]:
        path = entry["path"]
        want = scope.get(path)
        if want is None:
            missing.append(path)
            continue
        have = entry.get("servers")
        if have is None:
            unstamped.append(path)
        elif list(have) != want:
            drift.append({"path": path, "catalog": list(have), "derived": want})

    catalog_paths = {e["path"] for e in catalog["endpoints"]}
    uncatalogued = sorted(p for p in scope if p not in catalog_paths)

    counts = Counter()
    for want in scope.values():
        counts["+".join(want)] += 1
    return {
        **derived,
        "catalog_endpoints": len(catalog["endpoints"]),
        "gui_endpoints": sum(1 for v in scope.values() if "gui" in v),
        "headless_endpoints": sum(1 for v in scope.values() if "headless" in v),
        "by_scope": dict(sorted(counts.items())),
        "missing_from_derivation": missing,
        "unstamped": unstamped,
        "drift": drift,
        "uncatalogued": uncatalogued,
    }


def write_catalog(repo: Path | None = None) -> dict:
    """Stamp the derived ``servers`` array onto every catalog entry, in place.

    Emitted immediately after ``params`` so an entry reads path/method/category/
    params/servers/description. Entries the derivation cannot see (none today)
    are left untouched rather than guessed at.
    """
    repo = repo or _repo_root()
    result = audit(repo)
    scope = result["scope"]
    catalog = load_catalog(repo)

    changed = 0
    rebuilt = []
    for entry in catalog["endpoints"]:
        want = scope.get(entry["path"])
        if want is None:
            rebuilt.append(entry)
            continue
        if entry.get("servers") != want:
            changed += 1
        out = {}
        for key in ("path", "method", "category", "params"):
            if key in entry:
                out[key] = entry[key]
        out["servers"] = want
        for key, value in entry.items():
            if key not in out:
                out[key] = value
        rebuilt.append(out)
    catalog["endpoints"] = rebuilt

    text = json.dumps(catalog, indent=2, ensure_ascii=False)
    catalog_path(repo).write_text(text + "\n", encoding="utf-8", newline="\n")
    result["written"] = changed
    return result


def release_counts(repo: Path | None = None) -> tuple[int, int, int]:
    """``(mcp_tools, gui_endpoints, headless_endpoints)`` straight from the catalog.

    Read from ``tests/endpoints.json`` rather than re-derived from the Java
    sources: the release notes describe the artifact being shipped, and the
    catalog is that artifact's authoritative snapshot. The two agree because
    ``tests/unit/test_audit_server_scope.py`` fails when they don't.

    Raises ``KeyError`` if an entry has no ``servers`` field, so a release cannot
    quietly publish a number derived from a partially stamped catalog. The
    previous release-notes code used ``|| echo "0"`` defaults and published
    ``Headless Endpoints: 1`` for two releases running.
    """
    endpoints = load_catalog(repo or _repo_root())["endpoints"]
    scopes = [e["servers"] for e in endpoints]
    return (
        len(endpoints),
        sum(1 for s in scopes if "gui" in s),
        sum(1 for s in scopes if "headless" in s),
    )


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--json", action="store_true", help="emit the raw audit as JSON")
    ap.add_argument("--check", action="store_true", help="exit 1 if the catalog drifts")
    ap.add_argument(
        "--write", action="store_true", help="stamp `servers` onto tests/endpoints.json"
    )
    ap.add_argument("--quiet", action="store_true", help="exit code only, no output")
    ap.add_argument(
        "--release-counts",
        action="store_true",
        help="print `<mcp_tools> <gui> <headless>` for release notes, nothing else",
    )
    args = ap.parse_args(argv)

    if args.release_counts:
        print("%d %d %d" % release_counts())
        return 0

    result = write_catalog() if args.write else audit()

    if args.json:
        printable = {k: v for k, v in result.items() if k != "mechanism"}
        json.dump(printable, sys.stdout, indent=2)
        sys.stdout.write("\n")
    elif not args.quiet:
        print("Service classes handed to each server's AnnotationScanner")
        print(f"  GUI      ({len(result['gui_service_classes']):>2}): "
              f"{', '.join(result['gui_service_classes'])}")
        print(f"  headless ({len(result['headless_service_classes']):>2}): "
              f"{', '.join(result['headless_service_classes'])}")
        gui_only = sorted(set(result["gui_service_classes"])
                          - set(result["headless_service_classes"]))
        hl_only = sorted(set(result["headless_service_classes"])
                         - set(result["gui_service_classes"]))
        print(f"  GUI-only     : {', '.join(gui_only) or '(none)'}")
        print(f"  headless-only: {', '.join(hl_only) or '(none)'}")
        print()
        print("Hand-registered routes (ManualToolDescriptors.addAll)")
        print(f"  GUI      : {len(result['gui_manual_paths'])}")
        print(f"  headless : {len(result['headless_manual_paths'])}")
        gm = set(result["gui_manual_paths"])
        hm = set(result["headless_manual_paths"])
        print(f"  GUI-only     : {', '.join(sorted(gm - hm)) or '(none)'}")
        print(f"  headless-only: {', '.join(sorted(hm - gm)) or '(none)'}")
        print()
        print(f"@McpTool endpoints in tree : {result['annotation_endpoints']}")
        print(f"catalog entries            : {result['catalog_endpoints']}")
        print(f"GUI endpoints              : {result['gui_endpoints']}")
        print(f"headless endpoints         : {result['headless_endpoints']}")
        print(f"by scope                   : {result['by_scope']}")
        for name in SERVERS:
            extra = result["undeclared_routes"][name]
            if extra:
                print(f"\n{name}: answered but NOT in /mcp/schema or the catalog "
                      f"({len(extra)}): {', '.join(extra)}")
        if result["orphan_classes"]:
            print(f"\n@McpTool classes no server scans: "
                  f"{', '.join(result['orphan_classes'])}")
        if result["unreachable"]:
            print(f"\nUNREACHABLE (@McpTool but served by no server): "
                  f"{', '.join(result['unreachable'])}")
        if result["uncatalogued"]:
            print(f"\nDerived but absent from the catalog ({len(result['uncatalogued'])}): "
                  f"{', '.join(result['uncatalogued'])}")
        if result["missing_from_derivation"]:
            print(f"\nIn the catalog but no server registers them "
                  f"({len(result['missing_from_derivation'])}): "
                  f"{', '.join(result['missing_from_derivation'])}")
        if result.get("written") is not None:
            print(f"\nwrote tests/endpoints.json: {result['written']} entries changed")
        else:
            if result["unstamped"]:
                print(f"\nUNSTAMPED (no `servers` field): {len(result['unstamped'])}")
            if result["drift"]:
                print(f"\nDRIFT ({len(result['drift'])}):")
                for d in result["drift"]:
                    print(f"    {d['path']:<44} catalog={d['catalog']} derived={d['derived']}")

    if args.check:
        bad = (
            result["unstamped"]
            or result["drift"]
            or result["unreachable"]
            or result["uncatalogued"]
            or result["missing_from_derivation"]
        )
        return 1 if bad else 0
    return 1 if result["unreachable"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
