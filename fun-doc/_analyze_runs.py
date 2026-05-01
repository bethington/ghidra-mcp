import json
from collections import Counter, defaultdict

errors = []
all_runs = []
with open("logs/runs.jsonl") as f:
    for line in f:
        if not line.strip():
            continue
        try:
            r = json.loads(line)
            all_runs.append(r)
            res = r.get("result", "")
            if res in ("failed", "rate_limited", "partial"):
                errors.append(r)
        except:
            pass

print("=== Result summary ===")
counts = Counter(r.get("result", "?") for r in all_runs)
for k, v in sorted(counts.items(), key=lambda x: -x[1]):
    print(f"  {k}: {v}")

print("\n=== Last 20 failed/rate_limited/partial ===")
for e in errors[-20:]:
    ts = e.get("timestamp", "")[:19]
    res = e.get("result", "")
    model = e.get("model", "")
    fn = str(e.get("function", ""))[:40]
    out = str(e.get("output", ""))[:120]
    print(f"  {ts} [{res}] {model}  {fn}")
    if out:
        print(f"    -> {out}")

print("\n=== Rate limited entries ===")
rl = [e for e in errors if e.get("result") == "rate_limited"]
print(f"Total rate_limited: {len(rl)}")
for e in rl[-10:]:
    ts = e.get("timestamp", "")[:19]
    model = e.get("model", "")
    fn = str(e.get("function", ""))[:40]
    out = str(e.get("output", ""))[:120]
    print(f"  {ts} {model}  {fn}")
    if out:
        print(f"    -> {out}")

print("\n=== Failed breakdown by model ===")
failed = [e for e in errors if e.get("result") == "failed"]
model_counts = Counter(e.get("model", "?") for e in failed)
for k, v in sorted(model_counts.items(), key=lambda x: -x[1]):
    print(f"  {k}: {v}")

print("\n=== Failed breakdown by output pattern ===")
output_patterns = Counter()
for e in failed:
    out = str(e.get("output", ""))[:80].lower()
    if "overload" in out or "overloaded" in out:
        output_patterns["overloaded"] += 1
    elif "rate limit" in out or "rate_limit" in out:
        output_patterns["rate_limit"] += 1
    elif "timeout" in out:
        output_patterns["timeout"] += 1
    elif "token" in out:
        output_patterns["token_limit"] += 1
    elif "context" in out:
        output_patterns["context"] += 1
    elif "error" in out:
        output_patterns["api_error"] += 1
    else:
        output_patterns["other"] += 1
for k, v in sorted(output_patterns.items(), key=lambda x: -x[1]):
    print(f"  {k}: {v}")

print('\n=== Sample "failed" outputs ===')
for e in failed[-10:]:
    ts = e.get("timestamp", "")[:19]
    model = e.get("model", "")
    fn = str(e.get("function", ""))[:40]
    out = str(e.get("output", ""))[:200]
    print(f"  [{ts}] {model}  {fn}")
    print(f"    {out}")
    print()
