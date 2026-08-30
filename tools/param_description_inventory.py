#!/usr/bin/env python3
"""Inventory @Param annotations that carry no description.

Parses the Java sources under src/main/java/com/xebyte/ (no compilation, no
running Ghidra), pairs every @Param with its enclosing @McpTool method, and
reports which ones lack a non-empty `description = "..."` element.

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

REPO = Path(__file__).resolve().parent.parent
SRC = REPO / "src" / "main" / "java" / "com" / "xebyte"


def strip_comments(text: str) -> str:
    """Blank out // and /* */ comments, preserving offsets and line count."""
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
    """Index of the ')' matching the '(' at open_idx, skipping strings."""
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
    """Split on commas that are not nested in (), {}, <> or strings."""
    parts, buf = [], []
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


ANNO_ELEM = re.compile(r'(\w+)\s*=\s*("(?:[^"\\]|\\.)*"|\{[^}]*\}|[\w.]+)')
STR_LIT = re.compile(r'"((?:[^"\\]|\\.)*)"')


def parse_param_anno(anno_body: str) -> dict:
    """Parse the inside of @Param(...) into a dict of element -> raw value."""
    elems = dict(ANNO_ELEM.findall(anno_body))
    if "value" not in elems:
        # positional form: @Param("name")
        m = STR_LIT.search(anno_body)
        if m:
            elems["value"] = '"%s"' % m.group(1)
    return elems


def unquote(v: str | None) -> str | None:
    if v is None:
        return None
    v = v.strip()
    if v.startswith('"') and v.endswith('"'):
        return v[1:-1]
    return v


def concat_string_literals(raw: str) -> str:
    """Java allows "a" + "b"; join the literals."""
    lits = STR_LIT.findall(raw)
    return "".join(lits) if lits else raw


def scan_file(path: Path) -> list[dict]:
    raw = path.read_text(encoding="utf-8", errors="replace")
    code = strip_comments(raw)
    results = []
    for m in re.finditer(r"@McpTool\s*\(", code):
        anno_open = m.end() - 1
        anno_close = match_paren(code, anno_open)
        anno_body = code[anno_open + 1: anno_close]
        tool_elems = parse_param_anno(anno_body)
        tool_name = unquote(tool_elems.get("name")) or unquote(tool_elems.get("value")) or "?"
        tool_path = unquote(tool_elems.get("path")) or ""
        # Find the method signature's parameter list: the first '(' after the
        # annotation block that is preceded by an identifier at statement level.
        j = anno_close + 1
        # skip further annotations on the method
        while True:
            mm = re.compile(r"\S").search(code, j)
            if not mm:
                break
            if code[mm.start()] == "@":
                a_open = code.index("(", mm.start()) if "(" in code[mm.start(): mm.start() + 200] else -1
                nxt_at = code.find("@", mm.start() + 1)
                # annotation may have no parens
                lparen = code.find("(", mm.start())
                nl = code.find("\n", mm.start())
                if lparen != -1 and (nl == -1 or lparen < nl):
                    j = match_paren(code, lparen) + 1
                else:
                    j = mm.start() + 1
                continue
            break
        sig_open = code.find("(", j)
        if sig_open == -1:
            continue
        sig_close = match_paren(code, sig_open)
        params_src = code[sig_open + 1: sig_close]
        line = raw[:sig_open].count("\n") + 1
        for piece in split_top_level(params_src):
            piece = piece.strip()
            if "@Param" not in piece:
                continue
            p_at = piece.index("@Param")
            p_open = piece.index("(", p_at)
            p_close = match_paren(piece, p_open)
            body = piece[p_open + 1: p_close]
            elems = parse_param_anno(body)
            name = unquote(elems.get("value")) or "?"
            desc_raw = elems.get("description")
            desc = concat_string_literals(desc_raw) if desc_raw else ""
            java_decl = piece[p_close + 1:].strip()
            results.append({
                "file": str(path.relative_to(REPO)).replace("\\", "/"),
                "service": path.stem,
                "tool": tool_name,
                "path": tool_path,
                "line": line,
                "param": name,
                "java_type": java_decl.rsplit(" ", 1)[0].strip() if " " in java_decl else java_decl,
                "source": unquote(elems.get("source")) or "QUERY(default)",
                "default": unquote(elems.get("defaultValue")),
                "documented": bool(desc.strip()),
                "description": desc,
            })
    return results


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--list", action="store_true", help="print every undocumented param")
    ap.add_argument("--json", action="store_true", help="dump all params as JSON")
    args = ap.parse_args()

    rows = []
    for path in sorted(SRC.rglob("*.java")):
        if path.name in {"Param.java", "McpTool.java"}:
            continue
        rows.extend(scan_file(path))

    if args.json:
        json.dump(rows, sys.stdout, indent=2)
        print()
        return 0

    undoc = [r for r in rows if not r["documented"]]
    by_service: dict[str, list[dict]] = {}
    for r in rows:
        by_service.setdefault(r["service"], []).append(r)

    print(f"{'service':<32} {'params':>7} {'undoc':>7}")
    print("-" * 50)
    for svc in sorted(by_service):
        svc_rows = by_service[svc]
        u = sum(1 for r in svc_rows if not r["documented"])
        if u or True:
            print(f"{svc:<32} {len(svc_rows):>7} {u:>7}")
    print("-" * 50)
    print(f"{'TOTAL':<32} {len(rows):>7} {len(undoc):>7}")
    tools = {(r['file'], r['tool']) for r in rows}
    print(f"\n@McpTool methods with params: {len(tools)}")

    if args.list:
        print("\nUndocumented parameters:")
        for r in sorted(undoc, key=lambda x: (x["service"], x["tool"], x["param"])):
            print(f"  {r['service']}.{r['tool']}({r['param']})  [{r['java_type']}]"
                  f" src={r['source']} default={r['default']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
