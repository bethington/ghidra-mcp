"""Ghidra functions exposed as MCP resources.

Why resources and not just tools: a client caches a `resources/read` by URI and drops
that cache entry when the server sends `notifications/resources/updated` for it. So a
re-read after a write costs nothing until the server says the content moved — which is
what removes the write→re-read churn. Reads also arrive through the client's own built-in
read-only resource tool, so one permission grant covers reading every function instead of
a rule per Ghidra tool.

Shape, and why it is not symmetrical:

* ``resources/list`` carries exactly one entry, ``ghidra://programs``. It is the discovery
  root: it names every open program and spells out how to build the other URIs.
* everything else is a **template**. Templates never appear in ``resources/list`` (the SDK
  lists them only under ``resources/templates/list``) and ``list_resources`` has no cursor,
  so enumerating one resource per function is not merely impractical at 25k+ functions,
  it is unreachable. Per-function labels therefore live in the ``functions`` index rows and
  in the bundle body — a ``resources/read`` result carries only uri/mimeType/text, with no
  name field to put them in.

Bodies are shaped for the thing that reads them, not for symmetry: the function bundle
is **Markdown** (a resource body travels inside a JSON string, so JSON there arrives at the
model doubly escaped — see ``render.py`` for the measurement), while the row-shaped index
and search bodies stay JSON but compact and without a per-row ``uri``, which was a third of
the index payload and is derivable from the ``uri_template`` they carry.

URI keys are **addresses, never names**. Renaming is the most common write, and a
name-keyed URI would die exactly when its content changes: the client's cached body would
be stranded at the old name with no notification able to reach it, since
``resources/list_changed`` evicts only listings and MCP has no rename notification.
"""

import json
from urllib.parse import quote, unquote

from . import dispatch
from . import render
from . import state
from . import subscriptions
from .config import logger
from .server import mcp

# Caps chosen so a single read stays a reasonable size for a model to consume.
_MAX_INDEX_FUNCTIONS = 2000
_MAX_SEARCH_HITS = 200

_JSON = "application/json"
_MARKDOWN = "text/markdown"


def canonical_function_uri(program: str, address: str) -> str:
    """The one place a function's resource URI is constructed.

    Every producer — the index rows, the bundle body's own ``canonical_uri``, search
    results and the invalidation emitter — goes through this, so the client's cache key
    and the key we later invalidate are the same string by construction.

    The address is used exactly as Ghidra emits it (lowercase hex, no ``0x``, optionally
    ``space:hex``), matching ``ServiceUtils.addressToJson`` so the URI and the payload can
    never disagree.
    """
    return f"ghidra://function/{quote(program, safe='')}/{quote(address, safe=':')}"


def _read(endpoint: str, **params) -> str:
    """One upstream GET, off the event loop, with failures surfaced as errors."""
    query = {k: str(v) for k, v in params.items() if v is not None and v != ""}
    text = dispatch.dispatch_get(endpoint, params=query or None)
    return dispatch.raise_on_failure(text)


async def _read_async(endpoint: str, **params) -> str:
    return await state.run_blocking_ghidra_call(_read, endpoint, **params)


def _json(payload) -> str:
    return json.dumps(payload, indent=2)


def _compact(payload) -> str:
    """For row-shaped bodies: indentation is pure escaped whitespace in transit."""
    return json.dumps(payload, separators=(",", ":"))


def parse_function_hit(item) -> tuple[str | None, str | None]:
    """Normalise a ``find_functions`` row into ``(name, address)``.

    One parser keeps every resource that builds a ``uri`` from producing a different
    address spelling than ``canonical_function_uri``. The string form is still accepted
    because ``search_functions`` used to answer ``"name @ address"`` — a shape the 7.0.0
    response contract disallows, and one reason the four listing tools were merged.
    """
    if isinstance(item, dict):
        address = item.get("address")
        name = item.get("name")
        if address:
            return (str(name) if name is not None else None, str(address))
        return None, None
    if isinstance(item, str) and " @ " in item:
        name, address = item.rsplit(" @ ", 1)
        name, address = name.strip(), address.strip()
        if name and address:
            return name, address
    return None, None


# ---------------------------------------------------------------------------
# The discovery root — the only entry in resources/list
# ---------------------------------------------------------------------------
@mcp.resource(
    "ghidra://programs",
    name="Ghidra programs",
    title="Open Ghidra programs and how to address them",
    description="Every program open in the connected Ghidra, plus the URI contract for "
                "reading a function bundle. Start here.",
    mime_type=_JSON,
)
async def programs_resource() -> str:
    """List open programs and document how to build the other URIs."""
    subscriptions.note_resource_read("ghidra://programs")
    try:
        raw = await _read_async("/list_open_programs")
        programs = json.loads(raw)
    except Exception as e:
        return _json({"connected": False, "error": str(e)})

    entries = programs if isinstance(programs, list) else programs.get("programs", programs)
    listed = []
    if isinstance(entries, list):
        for item in entries:
            name = item.get("name") if isinstance(item, dict) else str(item)
            if not name:
                continue
            encoded = quote(name, safe="")
            listed.append({
                "program": name,
                "index": f"ghidra://program/{encoded}/index",
                "functions": f"ghidra://program/{encoded}/functions",
                "search": f"ghidra://search/{encoded}/functions/{{pattern}}",
                "changes": f"ghidra://program/{encoded}/changes",
            })

    return _json({
        "connected": True,
        "programs": listed,
        "uri_contract": {
            "function_by_address": "ghidra://function/{program}/{address}",
            "function_by_name": "ghidra://function/{program}/by-name/{name}",
            "search": "ghidra://search/{program}/functions/{pattern}",
            "changes": "ghidra://program/{program}/changes",
            # Templates never appear in resources/list — this is how an agent
            # learns the tree URI exists at all.
            "trees": "ghidra://decompile-tree/{tree_id}",
            "notes": [
                "Addresses are lowercase hex without 0x, exactly as Ghidra reports them "
                "(use space:hex on programs with several address spaces).",
                "The address form is canonical and stable across renames; the by-name form "
                "is a redirect that returns the canonical URI.",
                "Percent-encode a program name that contains / or spaces.",
                "A decompilation tree lives on the host filesystem; read its resource for "
                "status/config, then Glob/Grep the root it names.",
            ],
        },
    })


# ---------------------------------------------------------------------------
# Templates
# ---------------------------------------------------------------------------
@mcp.resource(
    "ghidra://program/{program}/index",
    name="Ghidra program summary",
    description="Metadata for one program: language, image base, function count.",
    mime_type=_JSON,
)
async def program_index_resource(program: str) -> str:
    name = unquote(program)
    uri = f"ghidra://program/{quote(name, safe='')}/index"
    subscriptions.note_resource_read(uri)
    return await _read_async("/get_ui_cursor", type="program", program=name)


@mcp.resource(
    "ghidra://program/{program}/functions",
    name="Ghidra function index",
    description="Every function as {name, address}, plus the uri_template that turns an "
                "address into its bundle URI. This is where a function's current descriptive "
                "name is visible — a resource read result has no name field of its own.",
    mime_type=_JSON,
)
async def function_index_resource(program: str) -> str:
    name = unquote(program)
    subscriptions.note_resource_read(f"ghidra://program/{quote(name, safe='')}/functions")
    raw = await _read_async(
        "/find_functions",
        program=name,
        offset=0,
        limit=_MAX_INDEX_FUNCTIONS,
    )
    payload = json.loads(raw)
    items = payload.get("functions", payload) if isinstance(payload, dict) else payload
    rows = []
    if isinstance(items, list):
        for item in items:
            fname, address = parse_function_hit(item)
            if not address:
                continue
            # No per-row uri: it is address plus a fixed prefix, and repeating it
            # cost ~a third of this payload (measured 234KB for 2000 rows). The
            # template is in `uri_template` below and in ghidra://programs.
            rows.append({"name": fname, "address": address})
    truncated = len(rows) >= _MAX_INDEX_FUNCTIONS
    total = len(rows)
    if truncated:
        try:
            info = json.loads(await _read_async("/get_ui_cursor", type="program", program=name))
            if isinstance(info, dict) and info.get("function_count") is not None:
                total = int(info["function_count"])
        except Exception:
            total = len(rows)
    return _compact({
        "program": name,
        "uri_template": f"ghidra://function/{quote(name, safe='')}/{{address}}",
        "functions": rows,
        "count": len(rows),
        "total": total,
        "truncated": truncated,
    })


@mcp.resource(
    "ghidra://program/{program}/changes",
    name="Ghidra change token",
    description="The program's change token plus what this session can expect in the way "
                "of change notifications. Read this when a cached bundle might be stale: "
                "compare its token with the bundle's own revision.token.",
    mime_type=_JSON,
)
async def program_changes_resource(program: str) -> str:
    """Expose the coarse change token and the delivery caveats that go with it.

    Notifications can be lost (a transport with no stream open, a session that
    reconnected), and a stale read is worse than churn — an agent that re-reads
    pre-write code concludes its own write did not land. So the token is
    published as well as polled: comparing it to a bundle's ``revision.token``
    detects staleness without any notification at all. The token, not the bare
    modification number: that number starts over each time the program opens.
    """
    name = unquote(program)
    uri = f"ghidra://program/{quote(name, safe='')}/changes"
    subscriptions.note_resource_read(uri)
    payload: dict = {"program": name}
    try:
        payload.update(json.loads(await _read_async("/get_change_token", program=name)))
    except Exception as e:
        payload["error"] = str(e)
    stateless = bool(getattr(mcp.settings, "stateless_http", False))
    payload["notifications"] = {
        "subscribe_supported": not stateless,
        "staleness_check": "Re-read this resource and compare token with the "
                           "revision.token in a cached function bundle; they diverge "
                           "whenever the program was written to, saved, or reopened.",
        "granularity": "Per program, not per function. It counts writes rather than "
                       "changed content, so re-setting an identical comment still moves it.",
        "caveats": [
            "stdio: notifications are delivered on the single stream.",
            "streamable-http: resources/updated for a write rides that call's own "
            "response stream; out-of-band edits (GUI, undo/redo, scripts) arrive on the "
            "standalone GET stream, so open one to see them.",
            "--json-response: no notification can be delivered at all; poll this resource.",
            "--stateless-http: resources/subscribe is refused; poll this resource.",
        ],
    }
    return _json(payload)


@mcp.resource(
    "ghidra://function/{program}/{address}",
    name="Ghidra function bundle",
    title="Decompilation, documentation, callers and call-site context for one function",
    description="Everything about one function from a single decompilation: decompiled C, "
                "signature, plate and inline comments, parameters, locals, labels, callers "
                "with their actual call-site source lines, callees and xrefs. Replaces the "
                "decompile_function + get_function_variables + get_function_callers + "
                "get_comment + get_function_xrefs sequence.",
    mime_type=_MARKDOWN,
)
async def function_bundle_resource(program: str, address: str) -> str:
    """Markdown, not JSON — see render.py for the measurement.

    A resource body travels inside a JSON string, so JSON here would reach the
    model doubly escaped: every key re-quoted, every line of C as a literal
    \\n. The tool /get_functions still answers JSON for anything that
    parses it.
    """
    program_name, addr = unquote(program), unquote(address)
    uri = canonical_function_uri(program_name, addr)
    subscriptions.note_resource_read(uri)
    raw = await _read_async("/get_functions", name=addr, program=program_name)
    payload = json.loads(raw)
    if isinstance(payload, dict):
        # Stamp the cache key into the body so a client that only kept the text
        # still knows which URI to re-read after resources/updated.
        payload.setdefault("canonical_uri", uri)
        return render.function_bundle_markdown(payload)
    return raw


@mcp.resource(
    "ghidra://function/{program}/by-name/{name}",
    name="Ghidra function by name",
    description="Resolve a function name to its canonical address URI. Deliberately tiny: "
                "names change, so the address URI is what should be cached and read.",
    mime_type=_JSON,
)
async def function_by_name_resource(program: str, name: str) -> str:
    program_name, function_name = unquote(program), unquote(name)
    subscriptions.note_resource_read(
        f"ghidra://function/{quote(program_name, safe='')}/by-name/{quote(function_name, safe='')}"
    )
    # ServiceUtils.resolveFunction accepts a function name in the function= param.
    raw = await _read_async(
        "/get_functions",
        address=function_name,
        program=program_name,
        fields="entry_point,signature",
    )
    payload = json.loads(raw)
    address = payload.get("address") if isinstance(payload, dict) else None
    if not address:
        return _json({"name": function_name, "resolved": False, "detail": payload})
    return _json({
        "name": payload.get("name", function_name),
        "address": address,
        "resolved": True,
        "canonical_uri": canonical_function_uri(program_name, address),
    })


@mcp.resource(
    "ghidra://decompile-tree/{tree_id}",
    name="Ghidra decompilation tree",
    title="Checkout status, config, and how to Grep the on-disk tree",
    description="Status and configuration for one decompilation tree. The tree itself "
                "lives on disk under the root this document names — Glob/Grep that; read "
                "this resource to learn whether the tree is still trustworthy.",
    mime_type=_MARKDOWN,
)
async def tree_resource(tree_id: str) -> str:
    """STATUS-shaped: never raise. An agent polls this while a sweep runs."""
    cid = unquote(tree_id)
    uri = f"ghidra://decompile-tree/{quote(cid, safe='')}"
    subscriptions.note_resource_read(uri)
    payload: dict = {"tree_id": cid}
    try:
        raw = await _read_async("/decompile_tree_status", tree=cid)
        data = json.loads(raw)
        if isinstance(data, dict):
            payload = data
        else:
            payload["detail"] = data
    except Exception as e:
        # Transient upstream failure must land in the body, not as a broken
        # resource — the client is often mid-sweep when this fires.
        payload["error"] = str(e)
    return render.tree_markdown(payload)


@mcp.resource(
    "ghidra://search/{program}/functions/{pattern}",
    name="Ghidra function search",
    description="Functions whose name matches a pattern, as {name, address} plus a "
                "uri_template. A filtered result set has no stable identity, so this is not "
                "cached against per-function invalidation — re-read it when the program "
                "changes.",
    mime_type=_JSON,
)
async def function_search_resource(program: str, pattern: str) -> str:
    program_name, needle = unquote(program), unquote(pattern)
    subscriptions.note_resource_read(
        f"ghidra://search/{quote(program_name, safe='')}/functions/{quote(needle, safe='')}"
    )
    raw = await _read_async(
        "/find_functions", name_pattern=needle, program=program_name, limit=_MAX_SEARCH_HITS
    )
    payload = json.loads(raw)
    items = payload.get("functions", payload) if isinstance(payload, dict) else payload
    hits = []
    if isinstance(items, list):
        for item in items:
            fname, address = parse_function_hit(item)
            if not address:
                continue
            hits.append({"name": fname, "address": address})
    total = payload.get("total", len(hits)) if isinstance(payload, dict) else len(hits)
    return _compact({
        "program": program_name,
        "pattern": needle,
        "uri_template": f"ghidra://function/{quote(program_name, safe='')}/{{address}}",
        "matches": hits,
        "count": len(hits),
        "total": total,
        "truncated": bool(total and total > len(hits)),
    })


# ---------------------------------------------------------------------------
# Argument completion
# ---------------------------------------------------------------------------
# Templates are invisible in resources/list, so without completion an agent has to guess
# a URI. This is the main mitigation for resources being less discoverable than tools.
_COMPLETION_LIMIT = 40


@mcp.completion()
async def complete_resource_argument(ref, argument, context):
    """Offer candidate values for {program}, {name}, {pattern} and {tree_id}."""
    from mcp.types import Completion, ResourceTemplateReference

    if not isinstance(ref, ResourceTemplateReference):
        return None
    try:
        if argument.name == "program":
            raw = await _read_async("/list_open_programs")
            payload = json.loads(raw)
            entries = payload if isinstance(payload, list) else payload.get("programs", [])
            names = [e.get("name") for e in entries if isinstance(e, dict) and e.get("name")]
            return Completion(values=_prefixed(names, argument.value))

        if argument.name == "tree_id":
            # No-selector /decompile_tree_status is the live registry; templates are
            # invisible in resources/list so this is the only discovery path.
            raw = await _read_async("/decompile_tree_status")
            payload = json.loads(raw)
            ids = []
            if isinstance(payload, dict):
                for row in payload.get("trees") or []:
                    if isinstance(row, dict) and row.get("tree_id"):
                        ids.append(str(row["tree_id"]))
            return Completion(values=_prefixed(ids, argument.value))

        if argument.name in ("name", "pattern"):
            program = (context.arguments or {}).get("program") if context else None
            partial = argument.value or ""
            if not partial:
                return Completion(values=[])
            raw = await _read_async(
                "/find_functions",
                name_pattern=partial,
                program=unquote(program) if program else None,
                limit=_COMPLETION_LIMIT,
            )
            payload = json.loads(raw)
            items = payload.get("functions", payload) if isinstance(payload, dict) else payload
            names = []
            if isinstance(items, list):
                for item in items:
                    fname, _address = parse_function_hit(item)
                    if fname:
                        names.append(fname)
            return Completion(values=names[:_COMPLETION_LIMIT])
    except Exception as e:
        # Completion is a convenience; a failure here must never break the session.
        logger.debug("Resource completion for %r failed: %s", argument.name, e)
    return None


def _prefixed(values, partial):
    partial = (partial or "").lower()
    matches = [v for v in values if not partial or v.lower().startswith(partial)]
    return matches[:_COMPLETION_LIMIT]
