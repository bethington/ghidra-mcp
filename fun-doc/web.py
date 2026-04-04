"""
Fun-Doc Web Dashboard: Minimal Flask viewer for state.json.

Auto-refreshes every 5 seconds. Read-only view of documentation progress.
"""

import json
from pathlib import Path
from flask import Flask, render_template, jsonify
from collections import defaultdict


def create_app(state_file):
    app = Flask(__name__, template_folder=str(Path(__file__).parent / "templates"))
    app.config["STATE_FILE"] = Path(state_file)

    def load_state():
        sf = app.config["STATE_FILE"]
        if sf.exists():
            with open(sf, "r") as f:
                return json.load(f)
        return {"functions": {}, "sessions": [], "project_folder": "unknown", "last_scan": None}

    def compute_stats(state):
        funcs = state.get("functions", {})
        total = len(funcs)

        if total == 0:
            return {
                "total": 0, "done": 0, "fixable": 0, "needs_work": 0,
                "pct": 0, "buckets": {}, "by_program": {}, "sessions": [],
                "next_targets": [], "project_folder": state.get("project_folder", "unknown"),
                "last_scan": state.get("last_scan"),
            }

        done = sum(1 for f in funcs.values() if f["score"] >= 90)
        fixable = sum(1 for f in funcs.values() if 70 <= f["score"] < 90)
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

        # Next targets (top 10 by priority)
        candidates = []
        for key, func in funcs.items():
            if func.get("is_thunk") or func.get("is_external"):
                continue
            if func["score"] >= 90:
                continue
            caller_count = func.get("caller_count", 0)
            is_leaf = func.get("is_leaf", False)
            base = 10000 if is_leaf else 1000
            impact = caller_count * 10
            effort_bonus = 500 if func["score"] >= 70 else (200 if func["score"] >= 50 else 0)
            priority = base + impact + effort_bonus
            candidates.append({
                "name": func["name"],
                "address": func["address"],
                "program": func.get("program_name", ""),
                "score": func["score"],
                "callers": caller_count,
                "is_leaf": is_leaf,
                "priority": priority,
                "last_result": func.get("last_result"),
            })

        candidates.sort(key=lambda x: x["priority"], reverse=True)

        # Function list for table (all functions, sorted by score asc)
        func_list = []
        for key, func in funcs.items():
            if func.get("is_thunk") or func.get("is_external"):
                continue
            func_list.append({
                "name": func["name"],
                "address": func["address"],
                "program": func.get("program_name", ""),
                "score": func["score"],
                "callers": func.get("caller_count", 0),
                "is_leaf": func.get("is_leaf", False),
                "last_result": func.get("last_result"),
                "last_processed": func.get("last_processed"),
            })
        func_list.sort(key=lambda x: x["score"])

        return {
            "total": total,
            "done": done,
            "fixable": fixable,
            "needs_work": needs_work,
            "pct": round(pct, 1),
            "buckets": buckets,
            "by_program": dict(by_program),
            "sessions": state.get("sessions", [])[-10:],
            "next_targets": candidates[:10],
            "all_functions": func_list,
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
        # Don't send all_functions in the API (too large for polling)
        stats.pop("all_functions", None)
        return jsonify(stats)

    return app
