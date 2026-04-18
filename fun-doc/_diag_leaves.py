"""Diagnose why leaf functions aren't being picked by the selector."""

import json
from collections import Counter

s = json.load(open("state.json"))
funcs = s.get("functions", {})
good_enough = 80
leaf_below = []
leaf_excluded = []

for key, func in funcs.items():
    if func.get("is_thunk") or func.get("is_external"):
        continue
    callees = func.get("callees")
    is_leaf = not callees
    score = func.get("score", 0)
    if not is_leaf or score >= good_enough:
        continue
    # This is a leaf below good_enough — why might it be excluded?
    reasons = []
    if func.get("consecutive_fails", 0) >= 3:
        reasons.append("consecutive_fails>=3")
    if func.get("recovery_pass_done"):
        reasons.append("recovery_pass_done")
    if func.get("decompile_timeout"):
        reasons.append("decompile_timeout")
    if func.get("stagnation_runs", 0) >= 3:
        reasons.append("stagnation_runs>=3")
    fixable = func.get("fixable", 0)
    last_processed = func.get("last_processed")
    if fixable <= 0 and last_processed is not None:
        reasons.append("fixable<=0")
    if reasons:
        leaf_excluded.append((key, score, fixable, reasons))
    else:
        leaf_below.append((key, score, fixable, last_processed))

print(
    f"Leaf functions below {good_enough}: {len(leaf_below) + len(leaf_excluded)} total"
)
print(f"  Eligible (should be picked): {len(leaf_below)}")
print(f"  Excluded by filters: {len(leaf_excluded)}")
print()

reason_counts = Counter()
for _, _, _, reasons in leaf_excluded:
    for r in reasons:
        reason_counts[r] += 1
print("=== Exclusion reason breakdown ===")
for r, c in reason_counts.most_common():
    print(f"  {r}: {c}")
print()

print("=== Top 15 eligible leaf functions ===")
leaf_below.sort(key=lambda x: -x[2])  # by fixable desc
for key, score, fixable, lp in leaf_below[:15]:
    fn = key.split("::")[-1] if "::" in key else key
    status = "processed" if lp else "unscored"
    print(f"  {fn[:40]:40s} | score={score:3.0f} | fixable={fixable:5.1f} | {status}")
print()

print("=== Sample excluded leaves (first 15) ===")
for key, score, fixable, reasons in leaf_excluded[:15]:
    fn = key.split("::")[-1] if "::" in key else key
    print(f"  {fn[:40]:40s} | score={score:3.0f} | fixable={fixable:5.1f} | {reasons}")
print()

# Also check: are there leaves with score=0 and no last_processed that should be cold-start?
unscored_leaves = [x for x in leaf_below if x[3] is None]
print(f"=== Unscored leaves (never processed, score=0): {len(unscored_leaves)} ===")
for key, score, fixable, lp in unscored_leaves[:10]:
    fn = key.split("::")[-1] if "::" in key else key
    print(f"  {fn[:40]:40s} | score={score:3.0f} | fixable={fixable:5.1f}")
print()

# Check require_scored setting
pq = (
    json.load(open("priority_queue.json"))
    if __import__("os").path.exists("priority_queue.json")
    else {}
)
cfg = pq.get("config", {})
print(f"=== Queue config ===")
print(f"  require_scored: {cfg.get('require_scored', False)}")
print(f"  good_enough_score: {cfg.get('good_enough_score', 80)}")
print(f"  active_binary: {s.get('active_binary', 'NOT SET')}")
