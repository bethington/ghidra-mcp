#!/usr/bin/env python3
"""Inventory @Param annotations that carry no description.

Parses the Java sources under src/main/java/com/xebyte/ (no compilation, no
running Ghidra), pairs every @Param with its enclosing @McpTool method, and
reports which ones lack a non-empty `description = "..."` element.

This is the measurement behind "294 undescribed parameters went to 0": the Java
side has `ParamDescriptionCoverageTest` as the build-time gate, and this script
is the reproducible count, runnable against any checkout including an old one::

    git archive <sha> src/main/java | tar -x -C /tmp/base
    cp tools/param_description_inventory.py /tmp/base/tools/
    cd /tmp/base && python tools/param_description_inventory.py

Usage:
    python tools/param_description_inventory.py            # summary
    python tools/param_description_inventory.py --list      # every undocumented param
    python tools/param_description_inventory.py --json      # machine-readable
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import IO, Iterable, Iterator

REPO = Path(__file__).resolve().parent.parent
SRC = REPO / "src" / "main" / "java" / "com" / "xebyte"

#: Annotation declarations, not tool definitions -- they carry `@Param` only in
#: their own javadoc, so scanning them would invent parameters that don't exist.
SKIP_FILES = frozenset({"Param.java", "McpTool.java"})


def strip_comments(text: str) -> str:
    """Blank out // and /* */ comments, preserving offsets and line count.

    Offsets must survive because the caller reports line numbers against the
    ORIGINAL text; newlines inside block comments are kept for the same reason.
    String and char literals are respected, so a "//" inside a description
    string is not mistaken for a comment.
    """
    out = list(text)
    i, n = 0, len(text)
    in_line = in_block = in_str = in_chr = False
    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if in_line:
            if c == "\n":
                in_line = False
            else:
                out[i] = " "
        elif in_block:
            if c == "*" and nxt == "/":
                out[i] = out[i + 1] = " "
                i += 2
                in_block = False
                continue
            if c != "\n":
                out[i] = " "
        elif in_str:
            if c == "\\":
                i += 2
                continue
            if c == '"':
                in_str = False
        elif in_chr:
            if c == "\\":
                i += 2
                continue
            if c == "'":
                in_chr = False
        else:
            if c == "/" and nxt == "/":
                in_line = True
                out[i] = " "
            elif c == "/" and nxt == "*":
                in_block = True
                out[i] = " "
            elif c == '"':
                in_str = True
            elif c == "'":
                in_chr = True
        i += 1
    return "".join(out)


def match_paren(text: str, open_idx: int) -> int:
    """Index of the ')' matching the '(' at open_idx, skipping string literals."""
    depth = 0
    i = open_idx
    n = len(text)
    while i < n:
        c = text[i]
        if c == '"':
            i += 1
            while i < n:
                if text[i] == "\\":
                    i += 2
                    continue
                if text[i] == '"':
                    break
                i += 1
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    raise ValueError("unbalanced parens")


def split_top_level(text: str) -> list[str]:
    """Split on commas that are not nested in (), {}, [], <> or strings.

    The angle brackets matter: a parameter typed `Map<String, String>` carries a
    comma that is not a parameter separator.
    """
    parts: list[str] = []
    buf: list[str] = []
    depth = 0
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c == '"':
            buf.append(c)
            i += 1
            while i < n:
                buf.append(text[i])
                if text[i] == "\\":
                    i += 1
                    if i < n:
                        buf.append(text[i])
                    i += 1
                    continue
                if text[i] == '"':
                    i += 1
                    break
                i += 1
            continue
        if c in "({[<":
            depth += 1
        elif c in ")}]>":
            depth -= 1
        elif c == "," and depth == 0:
            parts.append("".join(buf))
            buf = []
            i += 1
            continue
        buf.append(c)
        i += 1
    if "".join(buf).strip():
        parts.append("".join(buf))
    return parts


_LIT = r'"(?:[^"\\]|\\.)*"'
#: One annotation element. The value alternative accepts a Java `"a" + "b"`
#: concatenation, not just a lone literal: every long description in the tree is
#: written that way, and matching only the first segment silently truncated them.
ANNO_ELEM = re.compile(r'(\w+)\s*=\s*(' + _LIT + r'(?:\s*\+\s*' + _LIT + r')*'
                       r'|\{[^}]*\}|[\w.]+)')
STR_LIT = re.compile(r'"((?:[^"\\]|\\.)*)"')

#: Java escapes that appear inside the description literals we extract. Applied
#: in one left-to-right pass, so a `\\` before a quote cannot be re-consumed.
_ESCAPES = {"\\": "\\", '"': '"', "'": "'", "n": "\n", "t": "\t", "r": "\r"}
_ESCAPE_RE = re.compile(r"\\(.)")


def unescape_java(s: str) -> str:
    """Resolve Java string escapes; leave anything unrecognised alone."""
    return _ESCAPE_RE.sub(lambda m: _ESCAPES.get(m.group(1), m.group(0)), s)


NON_SPACE = re.compile(r"\S")
ANNO_NAME = re.compile(r"@\s*[\w.]+")


def parse_param_anno(anno_body: str) -> dict[str, str]:
    """Parse the inside of an annotation's parens into element -> raw value."""
    elems = dict(ANNO_ELEM.findall(anno_body))
    if "value" not in elems:
        # Positional form: @Param("name") rather than @Param(value = "name").
        m = STR_LIT.search(anno_body)
        if m:
            elems["value"] = '"%s"' % m.group(1)
    return elems


def unquote(v: str | None) -> str | None:
    """Resolve a Java string-literal value; pass anything else through.

    Handles the concatenated form too, so `value` and `path` behave the same way
    `description` does rather than losing everything after the first `+`.
    """
    if v is None:
        return None
    v = v.strip()
    if v.startswith('"') and v.endswith('"'):
        return concat_string_literals(v)
    return v


def concat_string_literals(raw: str) -> str:
    """Join a Java `"a" + "b"` concatenation into the string it produces."""
    lits = STR_LIT.findall(raw)
    return unescape_java("".join(lits)) if lits else raw


def _display_path(path: Path, repo: Path) -> str:
    """Repo-relative POSIX path, falling back to the bare name off-tree."""
    try:
        return str(path.relative_to(repo)).replace("\\", "/")
    except ValueError:
        return path.name


def _skip_annotations(code: str, start: int) -> int:
    """Advance past any further annotations stacked on the method.

    A method may carry `@McpTool(...)` plus e.g. `@SuppressWarnings("unchecked")`
    before its signature; without this the scanner would mistake the second
    annotation's parens for the parameter list and find no parameters at all.

    Returns the offset of the first character that is not part of an annotation.
    """
    j = start
    while True:
        mm = NON_SPACE.search(code, j)
        if not mm:
            return j
        if code[mm.start()] != "@":
            return mm.start()
        name = ANNO_NAME.match(code, mm.start())
        after_name = name.end() if name else mm.start() + 1
        lparen = code.find("(", after_name)
        nl = code.find("\n", after_name)
        if lparen != -1 and (nl == -1 or lparen < nl):
            j = match_paren(code, lparen) + 1
        else:
            # Marker annotation with no parens, e.g. @Override.
            j = after_name


def scan_file(path: Path, repo: Path = REPO) -> list[dict]:
    """Every @Param on an @McpTool method in one Java source file."""
    raw = path.read_text(encoding="utf-8", errors="replace")
    code = strip_comments(raw)
    results: list[dict] = []
    for m in re.finditer(r"@McpTool\s*\(", code):
        anno_open = m.end() - 1
        anno_close = match_paren(code, anno_open)
        tool_elems = parse_param_anno(code[anno_open + 1: anno_close])
        tool_name = unquote(tool_elems.get("name")) or unquote(tool_elems.get("value")) or "?"
        tool_path = unquote(tool_elems.get("path")) or ""

        sig_open = code.find("(", _skip_annotations(code, anno_close + 1))
        if sig_open == -1:
            continue
        sig_close = match_paren(code, sig_open)
        line = raw[:sig_open].count("\n") + 1

        for piece in split_top_level(code[sig_open + 1: sig_close]):
            piece = piece.strip()
            if "@Param" not in piece:
                continue
            p_open = piece.index("(", piece.index("@Param"))
            p_close = match_paren(piece, p_open)
            elems = parse_param_anno(piece[p_open + 1: p_close])
            desc_raw = elems.get("description")
            desc = concat_string_literals(desc_raw) if desc_raw else ""
            java_decl = piece[p_close + 1:].strip()
            results.append({
                "file": _display_path(path, repo),
                "service": path.stem,
                "tool": tool_name,
                "path": tool_path,
                "line": line,
                "param": unquote(elems.get("value")) or "?",
                "java_type": java_decl.rsplit(" ", 1)[0].strip() if " " in java_decl else java_decl,
                "source": unquote(elems.get("source")) or "QUERY(default)",
                "default": unquote(elems.get("defaultValue")),
                "documented": bool(desc.strip()),
                "description": desc,
            })
    return results


def iter_sources(src_root: Path) -> Iterator[Path]:
    """Java files worth scanning, in a stable order."""
    for path in sorted(src_root.rglob("*.java")):
        if path.name not in SKIP_FILES:
            yield path


def collect(src_root: Path = SRC, repo: Path = REPO) -> list[dict]:
    """Scan a whole source tree."""
    rows: list[dict] = []
    for path in iter_sources(src_root):
        rows.extend(scan_file(path, repo))
    return rows


def summarize(rows: Iterable[dict]) -> dict[str, tuple[int, int]]:
    """service -> (total params, undocumented params)."""
    out: dict[str, tuple[int, int]] = {}
    for row in rows:
        total, undoc = out.get(row["service"], (0, 0))
        out[row["service"]] = (total + 1, undoc + (0 if row["documented"] else 1))
    return out


def render(rows: list[dict], show_list: bool, out: IO[str]) -> None:
    """Print the human-readable report."""
    undoc = [r for r in rows if not r["documented"]]
    by_service = summarize(rows)

    print(f"{'service':<32} {'params':>7} {'undoc':>7}", file=out)
    print("-" * 50, file=out)
    for svc in sorted(by_service):
        total, missing = by_service[svc]
        print(f"{svc:<32} {total:>7} {missing:>7}", file=out)
    print("-" * 50, file=out)
    print(f"{'TOTAL':<32} {len(rows):>7} {len(undoc):>7}", file=out)
    tools = {(r["file"], r["tool"]) for r in rows}
    print(f"\n@McpTool methods with params: {len(tools)}", file=out)

    if show_list:
        print("\nUndocumented parameters:", file=out)
        for r in sorted(undoc, key=lambda x: (x["service"], x["tool"], x["param"])):
            print(f"  {r['service']}.{r['tool']}({r['param']})  [{r['java_type']}]"
                  f" src={r['source']} default={r['default']}", file=out)


def main(argv: list[str] | None = None, src_root: Path = SRC,
         repo: Path = REPO, out: IO[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--list", action="store_true", help="print every undocumented param")
    ap.add_argument("--json", action="store_true", help="dump all params as JSON")
    args = ap.parse_args(argv)
    stream = out if out is not None else sys.stdout

    rows = collect(src_root, repo)
    if args.json:
        json.dump(rows, stream, indent=2)
        print(file=stream)
        return 0

    render(rows, args.list, stream)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
