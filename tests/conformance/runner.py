"""Conformance runner: executes YAML tool-cases against an MCP transport.

Two assertion layers, per the agreed design:

1. **Semantic assertions** -- declared per case (`assert:`). Encode intent:
   this key exists, this write actually took effect, this bad input is refused.
2. **Golden snapshots** -- the normalized response recorded per case. Catches
   field-level drift nobody thought to assert, which is precisely what a
   reimplementation breaks.

Snapshots are normalized before comparison because raw responses embed values
that legitimately change between runs (elapsed times, session ids, absolute
paths, analysis timestamps). Normalization is deliberately conservative: it
masks only patterns known to be volatile, so a real behavioral change cannot be
masked away as noise.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .mcp_client import McpError, McpTransport, ToolResult

# ---------------------------------------------------------------- normalizing

# Ordered, conservative. Each entry must be something that varies run-to-run
# for reasons unrelated to behavior.
_VOLATILE = [
    (re.compile(r'"elapsed_ms"\s*:\s*\d+'), '"elapsed_ms":<MS>'),
    (re.compile(r'"duration_ms"\s*:\s*\d+'), '"duration_ms":<MS>'),
    (re.compile(r'"timestamp"\s*:\s*"[^"]*"'), '"timestamp":"<TS>"'),
    # get_version's build_timestamp/build_number/full_version all embed the
    # Maven build timestamp (yyyyMMdd-HHmmss), which changes on every rebuild
    # by design (pom.xml's maven.build.timestamp) -- not a behavioral change.
    (re.compile(r'\b\d{8}-\d{6}\b'), '<BUILDSTAMP>'),
    (re.compile(r'"uptime[^"]*"\s*:\s*[\d.]+'), '"uptime":<UPTIME>'),
    (re.compile(r'"(?:used|free|total|max)_memory[^"]*"\s*:\s*\d+'), '"memory":<MEM>'),
    (re.compile(r'"pid"\s*:\s*\d+'), '"pid":<PID>'),
    (re.compile(r'"session_id"\s*:\s*"[^"]*"'), '"session_id":"<SID>"'),
    (re.compile(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?'), '<DATETIME>'),
    # Network locations are operator infrastructure. They must never reach a
    # committed snapshot -- this is a public repo, and the repo's own
    # test_no_default_data_egress guard exists precisely to catch that.
    # (It did catch it: the first recording pass captured a private Ghidra
    # Server address via project_info.)
    (re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?'), '<HOST>'),
    (re.compile(r'\b(?:localhost|127\.0\.0\.1)(?::\d+)?'), '<HOST>'),
    # Absolute host paths differ per machine; the trailing filename is what matters.
    (re.compile(r'[A-Za-z]:[\\/](?:[^"\\/:*?<>|\r\n]+[\\/])*'), '<PATH>/'),
]


def is_error_payload(text: str) -> bool:
    """True when a response body is nothing but a server-side refusal.

    The MCP protocol flag `isError` is NOT set for these: the tool call
    succeeded, the tool said no. So `assert: is_error: false` passes on them,
    `nonempty: true` passes on them, and `--record` used to write them out as
    the golden -- which turns the suite into an assertion that the endpoint
    stays broken. Measured on the first recording pass: 20 of 124 committed
    goldens were bodies like
    `{"error": "At least one of 'mnemonic' or 'operand_pattern' must be
    non-empty"}` -- the case's own arguments were wrong, and every one of those
    cases reported PASS.
    """
    try:
        parsed = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return False
    return isinstance(parsed, dict) and set(parsed) == {"error"}


def normalize(text: str, extra: list[tuple[str, str]] | None = None) -> str:
    """Mask volatile substrings so snapshots compare meaningfully."""
    out = text.replace("\r\n", "\n")
    for pattern, repl in _VOLATILE:
        out = pattern.sub(repl, out)
    for pat, repl in extra or []:
        out = re.sub(pat, repl, out)
    # Canonicalize JSON so key order / spacing can't cause false diffs.
    try:
        parsed = json.loads(out)
        out = json.dumps(parsed, indent=2, sort_keys=True, ensure_ascii=False)
    except (json.JSONDecodeError, TypeError):
        pass
    return out.strip()


# ------------------------------------------------------------------ case model


@dataclass
class Case:
    tool: str
    args: dict[str, Any] = field(default_factory=dict)
    asserts: dict[str, Any] = field(default_factory=dict)
    snapshot: bool = True
    timeout: float = 60.0
    skip: str | None = None          # non-None => skipped, value is the reason
    tier: str = "read"               # read | write | destructive
    # Opt in to recording an `{"error": ...}` body as this case's golden. Only
    # true for cases whose POINT is the refusal (a bad-input negative test).
    expect_error_payload: bool = False
    normalize_extra: list[tuple[str, str]] = field(default_factory=list)
    name: str | None = None          # disambiguates multiple cases per tool
    extract: dict[str, str] = field(default_factory=dict)  # capture_name -> dot.path into response JSON

    @property
    def case_id(self) -> str:
        return f"{self.tool}::{self.name}" if self.name else self.tool


@dataclass
class CaseOutcome:
    case_id: str
    tool: str
    status: str                       # pass | fail | skip | error
    detail: str = ""
    elapsed_ms: int = 0
    snapshot_status: str = "n/a"      # match | new | drift | refused | n/a
    response_preview: str = ""


# ------------------------------------------------------------------ assertions


def _check(case: Case, result: ToolResult) -> list[str]:
    """Return a list of assertion failures (empty == passed)."""
    a = case.asserts
    fails: list[str] = []
    text = result.text
    parsed = result.json()

    if a.get("is_error") is True and not result.is_error:
        fails.append("expected an MCP-level error, got a normal result")
    if a.get("is_error") is False and result.is_error:
        fails.append(f"unexpected MCP-level error: {text[:200]}")

    if a.get("nonempty") and not text.strip():
        fails.append("expected a non-empty response")

    for needle in a.get("contains", []) or []:
        if needle not in text:
            fails.append(f"expected substring {needle!r} in response")

    for needle in a.get("not_contains", []) or []:
        if needle in text:
            fails.append(f"did not expect substring {needle!r} in response")

    if "json_keys" in a:
        if parsed is None:
            fails.append(f"expected JSON, got non-JSON: {text[:160]!r}")
        elif not isinstance(parsed, dict):
            fails.append(f"expected a JSON object, got {type(parsed).__name__}")
        else:
            missing = [k for k in a["json_keys"] if k not in parsed]
            if missing:
                fails.append(f"JSON missing key(s): {missing}")

    for path, expected in (a.get("json_equals") or {}).items():
        cur: Any = parsed
        for part in path.split("."):
            cur = cur.get(part) if isinstance(cur, dict) else None
        if cur != expected:
            fails.append(f"{path}: expected {expected!r}, got {cur!r}")

    # In-band errors: many tools signal failure inside a 200 response.
    if a.get("error_contains"):
        haystack = text.lower()
        for needle in a["error_contains"]:
            if needle.lower() not in haystack:
                fails.append(f"expected error text {needle!r} in response")
    if a.get("no_error") and parsed is not None and isinstance(parsed, dict):
        if "error" in parsed:
            fails.append(f"unexpected in-band error: {parsed['error']!r}")

    return fails


# --------------------------------------------------------------------- runner


class ExtractError(Exception):
    """Raised when a case's `extract:` path can't be resolved against its
    own response, or a later case references a capture that was never set
    (e.g. its producing case was skipped or failed)."""


def _resolve_path(obj: Any, path: str) -> Any:
    """Walk a dot-separated path into parsed JSON. `foo.bar` is a dict key
    lookup; a purely-numeric segment (`foo.0.bar`) indexes a list."""
    cur = obj
    for part in path.split("."):
        if isinstance(cur, dict):
            if part not in cur:
                raise ExtractError(f"path segment {part!r} not found in response (path={path!r})")
            cur = cur[part]
        elif isinstance(cur, list):
            try:
                idx = int(part)
            except ValueError:
                raise ExtractError(f"expected a list index, got {part!r} (path={path!r})") from None
            if idx >= len(cur):
                raise ExtractError(f"index {idx} out of range for list of {len(cur)} (path={path!r})")
            cur = cur[idx]
        else:
            raise ExtractError(f"cannot descend into {type(cur).__name__} at {part!r} (path={path!r})")
    return cur


class ConformanceRunner:
    def __init__(self, transport: McpTransport, snapshot_dir: Path,
                 record: bool = False, update: bool = False):
        self.transport = transport
        self.snapshot_dir = snapshot_dir
        self.record = record          # write snapshots for cases that have none
        self.update = update          # overwrite existing snapshots
        self.outcomes: list[CaseOutcome] = []
        # Values captured from earlier cases' responses via `extract:`, for
        # substitution into later cases' args via "${name}" placeholders.
        # Exists because some tools (debugger breakpoint/memory/address-
        # translation tools) need a value that only exists once a prior case
        # (e.g. debugger_launch) has run -- a post-ASLR runtime address, a
        # freshly-created ID, etc. -- and can't be hardcoded in YAML.
        self.captures: dict[str, Any] = {}

    def _substitute_args(self, args: dict[str, Any]) -> dict[str, Any]:
        """Replace any string arg value that is exactly "${name}" with the
        captured value from an earlier case's `extract:`. Values embedded in
        a larger string (e.g. "prefix-${name}") are intentionally NOT
        supported -- keep this simple; a case needing that can extract a
        pre-formatted value instead."""
        out = dict(args)
        for key, value in args.items():
            if isinstance(value, str) and value.startswith("${") and value.endswith("}"):
                name = value[2:-1]
                if name not in self.captures:
                    raise ExtractError(
                        f"arg {key!r} references capture {name!r}, which was never set "
                        "(its producing case may have been skipped, failed, or run later)")
                out[key] = self.captures[name]
        return out

    def _snapshot_path(self, case: Case) -> Path:
        safe = re.sub(r"[^A-Za-z0-9_.-]", "_", case.case_id)
        return self.snapshot_dir / f"{safe}.snap"

    def _handle_snapshot(self, case: Case, result: ToolResult) -> tuple[str, str]:
        if not case.snapshot:
            return "n/a", ""
        path = self._snapshot_path(case)
        current = normalize(result.text, case.normalize_extra)
        # A refusal is never a golden unless the case says its point IS the
        # refusal. Recording one silently converts a wrong CASE into a
        # permanent claim about the SERVER.
        if (self.record or self.update) and not case.expect_error_payload \
                and is_error_payload(current):
            return "refused", (
                "refusing to record an error payload as a golden -- fix the "
                f"case's arguments, or set expect_error_payload: true if the "
                f"refusal is the point. Body: {current[:200]}"
            )
        if not path.exists():
            if self.record or self.update:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(current, encoding="utf-8")
                return "new", ""
            return "new", "no golden snapshot recorded yet (run with --record)"
        previous = path.read_text(encoding="utf-8").strip()
        if previous == current:
            return "match", ""
        if self.update:
            path.write_text(current, encoding="utf-8")
            return "new", ""
        diff = _first_diff(previous, current)
        return "drift", f"snapshot drift: {diff}"

    def run_case(self, case: Case) -> CaseOutcome:
        if case.skip:
            outcome = CaseOutcome(case.case_id, case.tool, "skip", case.skip)
            self.outcomes.append(outcome)
            return outcome
        try:
            args = self._substitute_args(case.args)
        except ExtractError as exc:
            outcome = CaseOutcome(case.case_id, case.tool, "error", f"arg substitution: {exc}")
            self.outcomes.append(outcome)
            return outcome
        try:
            result = self.transport.call_tool(case.tool, args, timeout=case.timeout)
        except McpError as exc:
            outcome = CaseOutcome(case.case_id, case.tool, "error", str(exc))
            self.outcomes.append(outcome)
            return outcome

        fails = _check(case, result)

        if case.extract and not result.is_error:
            parsed = result.json()
            for capture_name, path in case.extract.items():
                try:
                    self.captures[capture_name] = _resolve_path(parsed, path)
                except ExtractError as exc:
                    fails.append(f"extract {capture_name!r}: {exc}")

        snap_status, snap_detail = self._handle_snapshot(case, result)
        if snap_detail and snap_status in ("drift", "refused"):
            fails.append(snap_detail)

        outcome = CaseOutcome(
            case_id=case.case_id,
            tool=case.tool,
            status="fail" if fails else "pass",
            detail="; ".join(fails),
            elapsed_ms=result.elapsed_ms,
            snapshot_status=snap_status,
            response_preview=result.text[:300],
        )
        self.outcomes.append(outcome)
        return outcome

    def run(self, cases: list[Case], progress=None) -> list[CaseOutcome]:
        for i, case in enumerate(cases, 1):
            outcome = self.run_case(case)
            if progress:
                progress(i, len(cases), outcome)
        return self.outcomes

    def summary(self) -> dict[str, Any]:
        counts: dict[str, int] = {}
        for o in self.outcomes:
            counts[o.status] = counts.get(o.status, 0) + 1
        snaps: dict[str, int] = {}
        for o in self.outcomes:
            snaps[o.snapshot_status] = snaps.get(o.snapshot_status, 0) + 1
        return {
            "total": len(self.outcomes),
            "by_status": counts,
            "by_snapshot": snaps,
            "failures": [
                {"case": o.case_id, "detail": o.detail, "preview": o.response_preview}
                for o in self.outcomes if o.status in ("fail", "error")
            ],
        }


def _first_diff(a: str, b: str) -> str:
    a_lines, b_lines = a.split("\n"), b.split("\n")
    for i in range(max(len(a_lines), len(b_lines))):
        old = a_lines[i] if i < len(a_lines) else "<missing>"
        new = b_lines[i] if i < len(b_lines) else "<missing>"
        if old != new:
            return f"line {i + 1}: golden={old[:110]!r} current={new[:110]!r}"
    return "content differs"
