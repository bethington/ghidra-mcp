"""Render a function bundle as Markdown instead of JSON-inside-JSON.

A ``resources/read`` result carries its body in a JSON *string*, so a JSON body
arrives at the model doubly escaped: every key quoted and re-quoted, every line
of decompiled C as a literal ``\\n``. Measured on one real bundle, all fields
present, counting the bytes as they reach the model:

    JSON, indent=2   18,233 chars   2,746 quote/backslash chars
    JSON, compact    15,026 chars   2,336
    Markdown         10,131 chars     336

56% of the payload for the same facts, and 8x fewer escapes, because the code
sits in a fence with one level of escaping rather than two.

The **tool** ``/get_functions`` still answers JSON — that is the machine
contract, it is in ``/mcp/schema`` and ``tests/endpoints.json``, and anything
parsing it keeps working. This rendering is only for the resource read, whose
sole consumer is a model reading prose.
"""

from __future__ import annotations

import re

_MAX_LOCALS = 80

# Ghidra's own naming, i.e. nobody has looked at this variable yet. The stack
# forms encode their own offset (local_f0 is Stack[-0xf0]), which is why an
# auto-named stack local adds nothing to what the declaration already said.
_AUTO_NAMED = re.compile(
    r"""^(
        local_[0-9a-fA-F]+          # local_f0
      | local_res[0-9a-fA-F]+       # positive-offset (caller frame) slot
      | [a-z]{0,3}Stack_[0-9a-fA-F]+  # auStack_110, uStack_120
      | [a-z]{1,4}Var\d+            # uVar1, pcVar5, puVar1
      | param_\d+                   # unnamed parameter
      | in_\w+                      # in_AL, in_FS_OFFSET (decompiler-invented)
      | extraout_\w+
      | unaff_\w+
    )$""",
    re.VERBOSE,
)


def _fence(code: str, lang: str = "c") -> list[str]:
    return [f"```{lang}", code.rstrip(), "```"]


def _kv_line(bundle: dict) -> list[str]:
    out = [f"# {bundle.get('name', '?')}  `{bundle.get('address', '?')}`"]
    program = bundle.get("program")
    if program:
        out[0] += f"  ({program})"
    signature = bundle.get("signature")
    if signature:
        out.append(f"signature: `{signature}`")
    bits = []
    if bundle.get("classification"):
        bits.append(f"classification: {bundle['classification']}")
    revision = bundle.get("revision") or {}
    if revision.get("token"):
        bits.append(f"revision: {revision['token']}")
    if bits:
        out.append(" · ".join(bits))
    extent = []
    if bundle.get("body_start") and bundle.get("body_end"):
        extent.append(f"body `{bundle['body_start']}..{bundle['body_end']}`")
    if bundle.get("size") is not None:
        extent.append(f"size {bundle['size']}")
    if extent:
        out.append(" · ".join(extent))
    if bundle.get("tags"):
        out.append("tags: " + ", ".join(f"`{t}`" for t in bundle["tags"]))
    # A wrong return type silently poisons every caller's reading of the code,
    # so the warning goes above the fold rather than into a field nobody reads.
    if bundle.get("return_type") and not bundle.get("return_type_resolved", True):
        out.append(f"> ⚠ return type `{bundle['return_type']}` is unresolved — "
                   "verify the return register at RET; do not trust a decompiler 'void'.")
    return out


def _row(var: dict) -> str:
    line = f"- `{var.get('name')}` : {var.get('type')}"
    if var.get("storage"):
        line += f" @ {var['storage']}"
    notes = []
    if var.get("is_phantom"):
        notes.append("phantom")
    if var.get("in_decompiled_code") is False:
        notes.append("not in decompiled code")
    if notes:
        line += f"  ({', '.join(notes)})"
    return line


def _variables(bundle: dict) -> list[str]:
    """Parameters, and only the locals that say something the C does not.

    The decompiled code above already declares every local with its name and its
    type, so repeating all 48 of them is the single largest redundancy in a
    bundle. What the C text cannot carry is: which register a value lives in,
    the stack offset of a local that has been *renamed* away from Ghidra's
    offset-derived auto-name, and variables Ghidra knows about that the
    decompiler dropped. Those survive; the rest are counted, not listed.

    Parameters always survive — there are few of them and their storage is the
    calling convention, which is exactly what a wrong signature hides.
    """
    params = list(bundle.get("parameters") or [])
    locals_ = list(bundle.get("locals") or [])
    keep = [v for v in locals_ if _says_something(v)]
    omitted = len(locals_) - len(keep)
    rows = params + keep
    if not rows and not omitted:
        return []

    out = ["", "## Parameters and notable locals"]
    for var in rows[:_MAX_LOCALS]:
        out.append(_row(var))
    if len(rows) > _MAX_LOCALS:
        out.append(f"- … {len(rows) - _MAX_LOCALS} more")
    if omitted:
        out.append(f"- _{omitted} auto-named locals omitted — the declarations above "
                   "carry their names and types, and their stack offsets are in their names._")
    return out


def _says_something(var: dict) -> bool:
    """True when a local carries a fact the decompiled declarations do not.

    An auto-named local never does: the name IS the storage. ``local_f0`` is
    Stack[-0xf0]; ``in_AL``, ``extraout_EAX`` and ``unaff_EBX`` name their
    register; and ``uVar7``'s register is a register-allocation artifact nobody
    acts on. Rename it to ``bytesRead`` and the offset lives nowhere else — which
    is when the row starts earning its place.
    """
    if var.get("in_decompiled_code") is False:
        return True  # Ghidra knows it; the decompiler dropped it
    return not _AUTO_NAMED.match(var.get("name") or "")


def _call_context(bundle: dict) -> list[str]:
    sites = bundle.get("call_context") or []
    if not sites:
        return []
    out = ["", "## Call context — who calls this, and how"]
    for site in sites:
        head = f"- **{site.get('caller')}** `{site.get('caller_address')}`"
        if site.get("site_address"):
            head += f" · call site `{site['site_address']}`"
        out.append(head)
        text = site.get("text")
        if text:
            # The window is several physical lines and each one needs the list
            # indent, so this cannot go through _fence's single-string form.
            out.append("  ```c")
            out.extend("  " + line for line in text.splitlines())
            out.append("  ```")
    return out


def _named_addresses(title: str, rows, count=None) -> list[str]:
    rows = rows or []
    if not rows and count in (None, 0):
        return []
    heading = f"## {title}" + (f" ({count})" if count is not None else f" ({len(rows)})")
    out = ["", heading]
    out.extend(f"- {row.get('name')} `{row.get('address')}`" for row in rows)
    if count is not None and count > len(rows):
        out.append(f"- … {count - len(rows)} more")
    return out


def function_bundle_markdown(bundle: dict) -> str:
    """Render ``/get_functions``'s JSON as Markdown."""
    out = _kv_line(bundle)

    code = bundle.get("decompiled_code")
    if code:
        out += ["", "## Decompiled"] + _fence(code)
    elif bundle.get("decompile_failed"):
        why = bundle.get("decompile_error")
        out += ["", "## Decompiled", f"_Decompilation failed{': ' + why if why else ''}._"]
    if bundle.get("decompiled_code_note"):
        out.append(f"_{bundle['decompiled_code_note']}_")

    plate = bundle.get("plate_comment")
    if plate:
        out += ["", "## Plate comment", plate]
    for issue in bundle.get("plate_comment_issues") or []:
        out.append(f"- ⚠ {issue}")

    comments = [c for c in (bundle.get("comments") or []) if c.get("kind") != "plate"]
    if comments:
        out += ["", "## Inline comments"]
        for c in comments:
            offset = c.get("relative_offset")
            where = f"+{offset:#x}" if isinstance(offset, int) else c.get("address", "?")
            out.append(f"- `{where}` {c.get('kind')}: {c.get('text')}")

    out += _variables(bundle)

    labels = bundle.get("labels") or []
    if labels:
        out += ["", f"## Labels ({len(labels)})"]
        for label in labels:
            offset = label.get("relative_offset")
            where = f"+{offset:#x}" if isinstance(offset, int) else label.get("address", "?")
            out.append(f"- {label.get('name')} `{where}` ({label.get('source')})")

    refs = bundle.get("refs") or []
    if refs:
        out += ["", f"## Data addresses used ({len(refs)})", " ".join(f"`{r}`" for r in refs)]

    jumps = bundle.get("jump_targets") or []
    if jumps:
        out += ["", f"## Jump targets ({len(jumps)})", " ".join(f"`{j}`" for j in jumps)]

    out += _call_context(bundle)
    out += _named_addresses("Callers", bundle.get("callers"), bundle.get("caller_count"))
    out += _named_addresses("Callees", bundle.get("callees"), bundle.get("callee_count"))

    xrefs = bundle.get("xrefs") or []
    if xrefs:
        out += ["", f"## Xrefs ({len(xrefs)})"]
        for xref in xrefs:
            line = f"- `{xref.get('from')}` {xref.get('type')}"
            if xref.get("from_function"):
                line += f" in {xref['from_function']}"
            out.append(line)

    if bundle.get("disassembly"):
        out += ["", "## Disassembly"] + _fence(
            "\n".join(
                f"{i.get('address')}  {i.get('mnemonic', '')} {i.get('operands', '')}".rstrip()
                for i in bundle["disassembly"]
            ),
            "asm",
        )

    truncated = [k for k, v in (bundle.get("truncation") or {}).items() if v]
    if truncated:
        out += ["", f"_Truncated sections: {', '.join(sorted(truncated))}._"]

    # The URI is the cache key: a client that kept only this text still knows
    # what to re-read when resources/updated names it.
    if bundle.get("canonical_uri"):
        out += ["", f"_Resource: {bundle['canonical_uri']}_"]
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------------------
# Checkout status — same Markdown-not-JSON reason as the function bundle
# ---------------------------------------------------------------------------

def tree_markdown(payload: dict | object) -> str:
    """Render ``/decompile_tree_status`` JSON as Markdown.

    Markdown here is **not** the size win it is for the function bundle, and the
    module docstring's 56% measurement must not be read as applying to this
    payload. Measured on a real completed tree, as delivered inside a JSON
    string: markdown 988 chars / 0 escape chars, compact JSON 830 / 72. The
    bundle saves because it is mostly C code, where every quote and newline is
    escaped twice; a status payload is small scalars with almost nothing to
    escape, so prose framing costs slightly more than escaping saves.

    It is still Markdown, for the reasons that survive: zero escapes is readable
    rather than a wall of ``\\"``, and the body can carry the "How to read this
    checkout" guidance — the Glob/Grep incantations and the per-file
    ``ghidra://function`` pointer — which is the whole reason an agent reads this
    instead of the raw endpoint.

    Handles both shapes: a single tree (has ``tree_id``) and the
    no-selector list (has ``trees``). Missing optional keys never raise —
    a mid-sweep poll can arrive before every field is populated.
    """
    if not isinstance(payload, dict):
        return f"_Unexpected tree payload: {payload!r}_\n"
    # List shape is the no-selector response; a single status always carries
    # tree_id even when it also nests config.
    if "trees" in payload and "tree_id" not in payload:
        return _tree_list_markdown(payload)
    return _tree_single_markdown(payload)


def _tree_single_markdown(payload: dict) -> str:
    cid = payload.get("tree_id") or "?"
    program = payload.get("program_name") or payload.get("program") or "?"
    out = [f"# Tree {cid} — {program}", _tree_headline(payload)]

    if payload.get("error"):
        out += ["", f"**error:** {payload['error']}"]

    out += ["", "## Status"]
    program_field = payload.get("program")
    if program_field == "closed":
        out.append("- program: closed")
    elif program_field is not None:
        out.append(f"- program: open (`{program_field}`)")
    else:
        out.append("- program: unknown")

    root_present = payload.get("root_present")
    root = payload.get("root")
    recreated = payload.get("root_recreated") or 0
    root_line = f"- root present: {root_present}"
    if root:
        root_line += f" (`{root}`)"
    if recreated:
        # Non-zero means /tmp vanished mid-flight and was healed — silent
        # healing of a vanishing temp dir is worse than saying so.
        root_line += f" · recreated {recreated}×"
    out.append(root_line)

    if payload.get("phase") is not None:
        out.append(f"- phase: {payload['phase']}")
    failed = payload.get("functions_failed")
    if failed is not None:
        out.append(f"- failures: {failed}")
    out.append(f"- freshness: {_tree_freshness(payload)}")
    if payload.get("status_state") is not None:
        out.append(f"- status_state: {payload['status_state']}")
    if payload.get("last_error"):
        out.append(f"- last error: {payload['last_error']}")
    elif "last_error" in payload:
        out.append("- last error: _(none)_")

    out += ["", "## Configuration"]
    cfg = payload.get("config") if isinstance(payload.get("config"), dict) else {}
    strategies = cfg.get("enabled_strategies") if cfg else None
    if strategies is None:
        out.append("- strategies: _(cascade default)_")
    elif not strategies:
        out.append("- strategies: [] (full cascade)")
    else:
        out.append(f"- strategies: {', '.join(str(s) for s in strategies)}")
    if cfg.get("band_size") is not None:
        out.append(f"- band size: {cfg['band_size']}")
    if cfg.get("max_file_bytes") is not None:
        out.append(f"- max file bytes: {cfg['max_file_bytes']}")
    if cfg.get("throttle_percent") is not None:
        out.append(f"- throttle: {cfg['throttle_percent']}%")
    timeouts = []
    if cfg.get("decompile_timeout_seconds") is not None:
        timeouts.append(f"decompile {cfg['decompile_timeout_seconds']}s")
    if cfg.get("analysis_wait_seconds") is not None:
        timeouts.append(f"analysis wait {cfg['analysis_wait_seconds']}s")
    if timeouts:
        out.append(f"- timeouts: {', '.join(timeouts)}")
    exclusions = cfg.get("exclusions") or []
    include_only = cfg.get("include_only") or []
    out.append(f"- exclusions: {exclusions if exclusions else '[]'}")
    out.append(f"- include_only: {include_only if include_only else '[]'}")

    root_path = payload.get("root") or "<root>"
    out += [
        "",
        "## How to read this tree",
        "The tree is the corpus; this resource is the microscope.",
        "",
        f"- Glob the decompilations: `Glob {root_path}/modules/*/*.c`",
        f"- Grep across them: `Grep <pattern> {root_path}/modules`",
        "- Every file header carries `uri: ghidra://function/<program>/<address>` — "
        "readable as an MCP resource for callers and call-site context once Grep "
        "finds the hit.",
    ]
    if payload.get("resource_uri"):
        out += ["", f"_Resource: {payload['resource_uri']}_"]
    return "\n".join(out) + "\n"


def _tree_list_markdown(payload: dict) -> str:
    rows = payload.get("trees") or []
    adoptable = payload.get("adoptable_on_disk") or []
    out = [
        "# Trees",
        f"{payload.get('tree_count', len(rows))} registered · "
        f"{payload.get('adoptable_count', len(adoptable))} adoptable on disk",
        "",
        "| id | program | phase | done/total | root |",
        "| --- | --- | --- | --- | --- |",
    ]
    if isinstance(rows, list):
        for row in rows:
            if not isinstance(row, dict):
                continue
            done = row.get("functions_done", "?")
            total = row.get("functions_total", "?")
            out.append(
                f"| {row.get('tree_id', '?')} "
                f"| {row.get('program_name') or row.get('program') or '?'} "
                f"| {row.get('phase', '?')} "
                f"| {done}/{total} "
                f"| `{row.get('root', '')}` |"
            )
    if not rows:
        out.append("| _(none)_ | | | | |")
    if isinstance(adoptable, list) and adoptable:
        out += ["", "## Adoptable on disk",
                "| id | program | status | files | root |",
                "| --- | --- | --- | --- | --- |"]
        for row in adoptable:
            if not isinstance(row, dict):
                continue
            out.append(
                f"| {row.get('tree_id', '?')} "
                f"| {row.get('program_name', '?')} "
                f"| {row.get('status_state', '?')} "
                f"| {row.get('files_on_disk', '?')} "
                f"| `{row.get('root', '')}` |"
            )
    if payload.get("error"):
        out += ["", f"**error:** {payload['error']}"]
    return "\n".join(out) + "\n"


def _tree_headline(payload: dict) -> str:
    bits: list[str] = []
    if payload.get("phase") is not None:
        bits.append(str(payload["phase"]))
    done, total = payload.get("functions_done"), payload.get("functions_total")
    if done is not None or total is not None:
        bits.append(f"{_q(done)}/{_q(total)}")
    comps = payload.get("compartment_count", payload.get("compartments"))
    if isinstance(comps, list):
        bits.append(f"{len(comps)} compartments")
    elif comps is not None:
        bits.append(f"{comps} compartments")
    if payload.get("bytes_written") is not None:
        bits.append(_human_bytes(payload["bytes_written"]))
    if payload.get("eta_seconds") is not None:
        bits.append(f"eta {payload['eta_seconds']}s")
    return " · ".join(bits) if bits else "(no status yet)"


def _tree_freshness(payload: dict) -> str:
    """Does the tree describe the program as it is now? ``in_sync`` answers it: swept, not
    stale, nothing queued. Modification numbers cannot (they start over on every open)."""
    pending = payload.get("pending_dirty")
    if payload.get("phase") == "stale":
        return f"stale ({payload.get('last_error') or 'resweep needed'})"
    if pending:
        return f"catching up ({pending} pending)"
    if payload.get("in_sync") is True:
        spliced = payload.get("spliced_since_sweep") or 0
        return "fresh" + (f", {spliced} blocks spliced since sweep" if spliced else "")
    if payload.get("in_sync") is False:
        return "not in sync"
    return "unknown (program not open)"


def _human_bytes(n) -> str:
    try:
        n = int(n)
    except (TypeError, ValueError):
        return str(n)
    if n < 1024:
        return f"{n} B"
    if n < 1024 ** 2:
        return f"{n / 1024:.1f} KB"
    if n < 1024 ** 3:
        return f"{n / 1024 ** 2:.1f} MB"
    return f"{n / 1024 ** 3:.1f} GB"


def _q(value) -> str:
    return "?" if value is None else str(value)
