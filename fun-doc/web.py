"""
Fun-Doc Web Dashboard: Control panel for RE documentation progress.

Features:
- Real-time progress monitoring (auto-refresh 5s)
- Deduction breakdown: where are the points hiding?
- ROI-ranked work queue: highest-impact functions first
- Run log stats: model performance, stuck functions
- Priority queue: reorder/pin/skip functions from the browser
- Per-folder state switching
"""

import json
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

from flask import Flask, render_template, jsonify, request


def create_app(state_file):
    app = Flask(__name__, template_folder=str(Path(__file__).parent / "templates"))
    app.config["STATE_FILE"] = Path(state_file)
    app.config["LOG_FILE"] = Path(__file__).parent / "logs" / "runs.jsonl"
    app.config["QUEUE_FILE"] = Path(__file__).parent / "priority_queue.json"

    def load_state():
        sf = app.config["STATE_FILE"]
        if sf.exists():
            with open(sf, "r") as f:
                return json.load(f)
        return {"functions": {}, "sessions": [], "project_folder": "unknown", "last_scan": None}

    def load_queue():
        qf = app.config["QUEUE_FILE"]
        if qf.exists():
            with open(qf, "r") as f:
                return json.load(f)
        return {"pinned": [], "skipped": [], "order": []}

    def save_queue(queue):
        qf = app.config["QUEUE_FILE"]
        with open(qf, "w") as f:
            json.dump(queue, f, indent=2)

    def load_run_logs(max_lines=500):
        lf = app.config["LOG_FILE"]
        if not lf.exists():
            return []
        lines = []
        try:
            with open(lf, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            lines.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
            return lines[-max_lines:]
        except Exception:
            return []

    def compute_deduction_breakdown(funcs):
        """Aggregate deduction categories across all functions."""
        cats = defaultdict(lambda: {"count": 0, "total_pts": 0.0, "functions": 0})
        for f in funcs.values():
            seen = set()
            for d in f.get("deductions", []):
                cat = d.get("category", "unknown")
                pts = d.get("points", 0)
                fixable = d.get("fixable", False)
                if not fixable:
                    continue
                cats[cat]["count"] += d.get("count", 1)
                cats[cat]["total_pts"] += pts
                if cat not in seen:
                    cats[cat]["functions"] += 1
                    seen.add(cat)
        # Sort by total points descending
        return sorted(
            [{"category": k, **v} for k, v in cats.items()],
            key=lambda x: x["total_pts"],
            reverse=True,
        )

    def compute_roi_queue(funcs, queue):
        """Rank functions by ROI: fixable_pts * (1 + caller_count/10)."""
        pinned = set(queue.get("pinned", []))
        skipped = set(queue.get("skipped", []))
        candidates = []
        for key, func in funcs.items():
            if func.get("is_thunk") or func.get("is_external"):
                continue
            if func.get("score", 0) >= 95 and func.get("fixable", 0) == 0:
                continue
            if key in skipped:
                continue
            fixable = func.get("fixable", 0)
            callers = func.get("caller_count", 0)
            roi = fixable * (1 + callers / 10)
            candidates.append({
                "key": key,
                "name": func["name"],
                "address": func["address"],
                "program": func.get("program_name", ""),
                "score": func.get("score", 0),
                "fixable": round(fixable, 1),
                "callers": callers,
                "roi": round(roi, 1),
                "is_leaf": func.get("is_leaf", False),
                "last_result": func.get("last_result"),
                "last_processed": func.get("last_processed"),
                "pinned": key in pinned,
                "classification": func.get("classification", ""),
            })
        # Pinned first, then by ROI
        candidates.sort(key=lambda x: (not x["pinned"], -x["roi"]))
        return candidates

    def compute_run_stats(logs):
        """Compute stats from run logs."""
        if not logs:
            return {
                "total_runs": 0, "today_runs": 0, "avg_delta": 0,
                "success_rate": 0, "by_provider": {}, "stuck_functions": [],
            }
        today = datetime.now().date().isoformat()
        today_logs = [l for l in logs if l.get("timestamp", "").startswith(today)]

        deltas = []
        success = 0
        by_provider = defaultdict(lambda: {"runs": 0, "avg_delta": 0, "deltas": []})
        func_results = defaultdict(lambda: {"fails": 0, "last_result": "", "name": "", "address": ""})

        for l in logs:
            before = l.get("score_before")
            after = l.get("score_after")
            result = l.get("result", "")
            provider = l.get("provider", "unknown")

            if before is not None and after is not None:
                delta = after - before
                deltas.append(delta)
                by_provider[provider]["deltas"].append(delta)

            by_provider[provider]["runs"] += 1
            if result == "completed":
                success += 1

            fkey = f"{l.get('program', '')}::{l.get('address', '')}"
            func_results[fkey]["name"] = l.get("function", "")
            func_results[fkey]["address"] = l.get("address", "")
            func_results[fkey]["last_result"] = result
            if result in ("failed", "needs_redo"):
                func_results[fkey]["fails"] += 1

        # Provider averages
        provider_stats = {}
        for p, data in by_provider.items():
            d = data["deltas"]
            provider_stats[p] = {
                "runs": data["runs"],
                "avg_delta": round(sum(d) / len(d), 1) if d else 0,
            }

        # Stuck functions (3+ failures)
        stuck = sorted(
            [{"name": v["name"], "address": v["address"], "fails": v["fails"]}
             for v in func_results.values() if v["fails"] >= 3],
            key=lambda x: x["fails"], reverse=True,
        )[:10]

        return {
            "total_runs": len(logs),
            "today_runs": len(today_logs),
            "avg_delta": round(sum(deltas) / len(deltas), 1) if deltas else 0,
            "success_rate": round(success / len(logs) * 100, 1) if logs else 0,
            "by_provider": provider_stats,
            "stuck_functions": stuck,
        }

    def compute_stats(state):
        funcs = state.get("functions", {})
        total = len(funcs)
        queue = load_queue()

        if total == 0:
            return {
                "total": 0, "done": 0, "fixable": 0, "needs_work": 0,
                "pct": 0, "buckets": {}, "by_program": {}, "sessions": [],
                "next_targets": [], "all_functions": [],
                "deduction_breakdown": [], "roi_queue": [],
                "run_stats": compute_run_stats([]),
                "project_folder": state.get("project_folder", "unknown"),
                "last_scan": state.get("last_scan"),
            }

        done = sum(1 for f in funcs.values() if f["score"] >= 90)
        fixable_count = sum(1 for f in funcs.values() if 70 <= f["score"] < 90)
        needs_work = sum(1 for f in funcs.values() if f["score"] < 70)
        pct = (done / total * 100) if total > 0 else 0

        # Score buckets
        buckets = {"100": 0, "90-99": 0, "80-89": 0, "70-79": 0, "60-69": 0,
                   "50-59": 0, "40-49": 0, "30-39": 0, "20-29": 0, "10-19": 0, "0-9": 0}
        for f in funcs.values():
            s = f["score"]
            if s >= 100: buckets["100"] += 1
            elif s >= 90: buckets["90-99"] += 1
            elif s >= 80: buckets["80-89"] += 1
            elif s >= 70: buckets["70-79"] += 1
            elif s >= 60: buckets["60-69"] += 1
            elif s >= 50: buckets["50-59"] += 1
            elif s >= 40: buckets["40-49"] += 1
            elif s >= 30: buckets["30-39"] += 1
            elif s >= 20: buckets["20-29"] += 1
            elif s >= 10: buckets["10-19"] += 1
            else: buckets["0-9"] += 1

        # Per program
        by_program = defaultdict(lambda: {"total": 0, "done": 0, "remaining": 0})
        for f in funcs.values():
            prog = f.get("program_name", "unknown")
            by_program[prog]["total"] += 1
            if f["score"] >= 90:
                by_program[prog]["done"] += 1
            else:
                by_program[prog]["remaining"] += 1

        # Deduction breakdown
        deduction_breakdown = compute_deduction_breakdown(funcs)

        # ROI queue
        roi_queue = compute_roi_queue(funcs, queue)

        # Run log stats
        logs = load_run_logs()
        run_stats = compute_run_stats(logs)

        # Function list for table (all functions, sorted by score asc)
        func_list = []
        for key, func in funcs.items():
            if func.get("is_thunk") or func.get("is_external"):
                continue
            func_list.append({
                "key": key,
                "name": func["name"],
                "address": func["address"],
                "program": func.get("program_name", ""),
                "score": func["score"],
                "fixable": round(func.get("fixable", 0), 1),
                "callers": func.get("caller_count", 0),
                "is_leaf": func.get("is_leaf", False),
                "last_result": func.get("last_result"),
                "last_processed": func.get("last_processed"),
            })
        func_list.sort(key=lambda x: x["score"])

        return {
            "total": total,
            "done": done,
            "fixable": fixable_count,
            "needs_work": needs_work,
            "pct": round(pct, 1),
            "buckets": buckets,
            "by_program": dict(by_program),
            "sessions": state.get("sessions", [])[-10:],
            "next_targets": roi_queue[:10],
            "roi_queue": roi_queue[:50],
            "all_functions": func_list,
            "deduction_breakdown": deduction_breakdown,
            "run_stats": run_stats,
            "project_folder": state.get("project_folder", "unknown"),
            "last_scan": state.get("last_scan"),
        }

    @app.route("/")
    def dashboard():
        state = load_state()
        stats = compute_stats(state)
        return render_template("dashboard.html", stats=stats)

    @app.route("/api/stats")
    def api_stats():
        state = load_state()
        stats = compute_stats(state)
        stats.pop("all_functions", None)
        return jsonify(stats)

    @app.route("/api/queue", methods=["GET"])
    def get_queue():
        return jsonify(load_queue())

    @app.route("/api/queue/pin", methods=["POST"])
    def pin_function():
        data = request.json
        key = data.get("key")
        if not key:
            return jsonify({"error": "key required"}), 400
        queue = load_queue()
        if key not in queue["pinned"]:
            queue["pinned"].append(key)
        queue["skipped"] = [k for k in queue["skipped"] if k != key]
        save_queue(queue)
        return jsonify({"ok": True, "queue": queue})

    @app.route("/api/queue/unpin", methods=["POST"])
    def unpin_function():
        data = request.json
        key = data.get("key")
        if not key:
            return jsonify({"error": "key required"}), 400
        queue = load_queue()
        queue["pinned"] = [k for k in queue["pinned"] if k != key]
        save_queue(queue)
        return jsonify({"ok": True, "queue": queue})

    @app.route("/api/queue/skip", methods=["POST"])
    def skip_function():
        data = request.json
        key = data.get("key")
        if not key:
            return jsonify({"error": "key required"}), 400
        queue = load_queue()
        if key not in queue["skipped"]:
            queue["skipped"].append(key)
        queue["pinned"] = [k for k in queue["pinned"] if k != key]
        save_queue(queue)
        return jsonify({"ok": True, "queue": queue})

    @app.route("/api/queue/unskip", methods=["POST"])
    def unskip_function():
        data = request.json
        key = data.get("key")
        if not key:
            return jsonify({"error": "key required"}), 400
        queue = load_queue()
        queue["skipped"] = [k for k in queue["skipped"] if k != key]
        save_queue(queue)
        return jsonify({"ok": True, "queue": queue})

    @app.route("/api/queue/reorder", methods=["POST"])
    def reorder_queue():
        """Set explicit ordering for the work queue."""
        data = request.json
        order = data.get("order", [])
        queue = load_queue()
        queue["order"] = order
        save_queue(queue)
        return jsonify({"ok": True, "queue": queue})

    return app
