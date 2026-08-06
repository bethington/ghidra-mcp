"""Score a generated plate comment against the ORIGINAL SOURCE it describes.

The name score (`ground_truth_review`) is mechanical and cheap, but a name is
four or five tokens. The plate is where most of the documentation's value and
most of its risk live -- and the measured failure was a plate that was coherent,
well-structured, correct in every mechanical particular, honestly hedged, and
about a function that does not exist.

    documented : "Tests whether the current viewport is visible."
    actually   : a mouse-over hit test for the 800x600 new-stats button

Nothing mechanical can catch that. `analyze_function_completeness` is computed
FROM the documentation, so no fact about the binary can lower it. `falsify`
finds contradictions against the DISASSEMBLY, and there was none -- the plate
agreed with every instruction it described. Only the original source disagrees,
and only a reader can see it.

WHY A DIFFERENT MODEL JUDGES. minimax writes the documentation, so minimax must
not grade it: a model that invented `CLIENT_CheckViewportVisible` is not the one
to ask whether `CLIENT_CheckViewportVisible` is right. This project already
pairs complementary families for exactly that reason. The judge is a measuring
instrument, not part of the pipeline under test.

WHAT IT IS ASKED. Semantics, not wording -- a plate that says "computes the
visible tile bounds" where the source says "sets the tile culling window" has
understood the function, and scoring it down would teach the workflow to copy
vocabulary. The judge is asked for three separable things, because "is this
good" produces mush:

    describes_right_function   the load-bearing one; everything else is moot
    supported_claims           statements the source bears out
    unsupported_claims         statements the source contradicts or does not
                               mention -- INVENTION, the measured failure

Prompt building and response parsing live here, apart from the invocation, so
the whole thing is testable offline with no provider and no network.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

# Long enough to judge, short enough not to turn one review into a novel. The
# measured functions run 3-120 lines; this holds all but the largest whole.
_MAX_SOURCE_LINES = 200


def read_source(source_file: str, line_start: int, line_end: int,
                context: int = 2) -> str:
    """The original function's text, with a couple of lines of lead-in.

    Returns "" when the file is unreadable rather than raising: a missing source
    file means this function cannot be judged, which the caller reports as
    unscorable. It must never be confused with a bad plate.
    """
    try:
        lines = Path(source_file).read_text(encoding="utf-8",
                                            errors="replace").splitlines()
    except Exception:
        return ""
    if not lines:
        return ""
    lo = max(0, int(line_start) - 1 - context)
    hi = min(len(lines), int(line_end))
    if hi <= lo:
        return ""
    body = lines[lo:hi][:_MAX_SOURCE_LINES]
    out = "\n".join(f"{lo + i + 1:5d}| {ln}" for i, ln in enumerate(body))
    if hi - lo > _MAX_SOURCE_LINES:
        out += f"\n     | ... ({hi - lo - _MAX_SOURCE_LINES} more lines)"
    return out


def build_judge_prompt(documented_name: str, plate: str, source: str,
                       truth_name: str = "") -> str:
    """The judging prompt. Separate from invocation so it is testable offline."""
    return f"""You are scoring reverse-engineering documentation against the ORIGINAL
SOURCE CODE the binary was compiled from. The source is the authority. The
documentation was written by a different model that never saw it.

Judge MEANING, not wording. Different vocabulary for the same behaviour is
CORRECT: "computes the visible tile bounds" and "sets the tile culling window"
describe the same thing. Do not reward or penalise style, formatting, or
whether the documentation uses the same words as the source.

The failure that matters most is documentation that is coherent, confident and
about a DIFFERENT FUNCTION than the one shown. Judge that first.

DOCUMENTED NAME:
{documented_name}

DOCUMENTATION (plate comment) UNDER REVIEW:
{plate}

ORIGINAL SOURCE (the authority):
```c
{source}
```

Answer with ONLY a JSON object, no prose around it:

{{
  "describes_right_function": true|false,
  "confidence": 0.0-1.0,
  "supported_claims": ["statements the source bears out"],
  "unsupported_claims": ["statements the source contradicts or never mentions"],
  "missing_key_behaviour": ["what the source does that the documentation omits"],
  "summary": "one sentence"
}}"""


@dataclass
class PlateVerdict:
    right_function: Optional[bool] = None
    confidence: float = 0.0
    supported: List[str] = field(default_factory=list)
    unsupported: List[str] = field(default_factory=list)
    missing: List[str] = field(default_factory=list)
    summary: str = ""
    unscorable_reason: str = ""

    @property
    def scorable(self) -> bool:
        return self.right_function is not None

    @property
    def verdict(self) -> str:
        if not self.scorable:
            return "unscorable"
        if not self.right_function:
            return "wrong_function"
        return "accurate" if not self.unsupported else "accurate_with_invention"


# A GREEDY `\{.*\}` spans from the FIRST brace anywhere in the reply to the
# LAST one, so any prose containing a brace -- or a fenced block preceded by an
# explanation -- yields text that is not valid JSON. Measured 2026-08-06: the
# judge answered correctly for all 8 functions and every row came back
# `unscorable`, because the model wrapped its object in a ```json fence with a
# sentence before it. The verdicts were real; the parser threw them away.
_FENCE_RE = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.S)
_JSON_RE = re.compile(r"\{.*\}", re.S)


def _json_candidates(raw: str):
    """Plausible JSON objects in a reply, best first.

    Fenced blocks are tried before the greedy span, and the greedy span before
    a brace-balanced scan from each opening brace -- so a correct answer is not
    discarded because of the prose around it.
    """
    for m in _FENCE_RE.finditer(raw):
        yield m.group(1)
    m = _JSON_RE.search(raw)
    if m:
        yield m.group(0)
    depth = 0
    start = -1
    for i, ch in enumerate(raw):
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}" and depth:
            depth -= 1
            if depth == 0 and start >= 0:
                yield raw[start:i + 1]


def parse_judge_response(text) -> PlateVerdict:
    """Parse the judge's answer.

    An unparseable response is UNSCORABLE, never a pass and never a failure.
    A judge that returned prose tells us nothing about the documentation, and
    recording that as either verdict would put noise into the one number this
    whole corpus exists to produce -- the same "cannot tell is not passed" rule
    that falsify's CONF_BLOCKED and the port classifier's `unknown` follow.
    """
    if isinstance(text, dict):
        payload = text
    else:
        raw = str(text or "")
        payload, err = None, "no JSON object in response"
        for cand in _json_candidates(raw):
            try:
                parsed = json.loads(cand)
            except Exception as exc:
                err = f"unparseable JSON: {exc}"
                continue
            if isinstance(parsed, dict) and "describes_right_function" in parsed:
                payload = parsed
                break
            payload = payload or parsed
        if payload is None:
            return PlateVerdict(unscorable_reason=err)
    if not isinstance(payload, dict) or "describes_right_function" not in payload:
        return PlateVerdict(unscorable_reason="missing describes_right_function")

    rf = payload.get("describes_right_function")
    if not isinstance(rf, bool):
        return PlateVerdict(unscorable_reason="describes_right_function not boolean")

    def _lst(key):
        v = payload.get(key) or []
        return [str(x) for x in v] if isinstance(v, list) else []

    try:
        conf = float(payload.get("confidence") or 0.0)
    except (TypeError, ValueError):
        conf = 0.0
    return PlateVerdict(
        right_function=rf, confidence=max(0.0, min(1.0, conf)),
        supported=_lst("supported_claims"),
        unsupported=_lst("unsupported_claims"),
        missing=_lst("missing_key_behaviour"),
        summary=str(payload.get("summary") or ""))


def judge_plate(documented_name, plate, source_file, line_start, line_end,
                truth_name="", invoke=None, provider="claude") -> PlateVerdict:
    """Score one plate. `invoke` is injected so tests never call a provider."""
    if not plate or not str(plate).strip():
        return PlateVerdict(unscorable_reason="no plate comment")
    source = read_source(source_file, line_start, line_end)
    if not source:
        return PlateVerdict(unscorable_reason="original source unreadable")
    prompt = build_judge_prompt(documented_name, plate, source, truth_name)
    if invoke is None:                                   # pragma: no cover
        import fun_doc as fd
        invoke = lambda p: fd.invoke_claude(p, provider=provider, use_tools=False)
    try:
        return parse_judge_response(invoke(prompt))
    except Exception as exc:
        return PlateVerdict(unscorable_reason=f"judge invocation failed: {exc}")


def summarise(verdicts) -> dict:
    """Aggregate, with unscorable rows kept OUT of the rates.

    Same rule the name measurement uses for deferrals: a row nobody could judge
    is not evidence in either direction, and folding it into a rate hides how
    much of the sample was actually measured.
    """
    vs = list(verdicts or [])
    scorable = [v for v in vs if v.scorable]
    right = [v for v in scorable if v.right_function]
    clean = [v for v in right if not v.unsupported]
    n = len(scorable) or 1
    return {
        "reviewed": len(vs),
        "scorable": len(scorable),
        "unscorable": len(vs) - len(scorable),
        "right_function": len(right),
        "right_function_rate": round(len(right) / n, 3),
        "free_of_invention": len(clean),
        "invention_rate": round((len(right) - len(clean)) / (len(right) or 1), 3),
    }
